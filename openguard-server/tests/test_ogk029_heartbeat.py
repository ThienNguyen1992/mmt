from datetime import datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.config import settings
from app.core.security import generate_device_access_token
from app.database import Base, get_db
from app.main import app
from app.models import Child, Device, Parent
from app.schemas.policy import PolicyContent
from app.services.policy_service import create_new_policy_version


@pytest.fixture
def hb_env(tmp_path, monkeypatch):
    monkeypatch.setattr(
        settings, "policy_signing_private_key_pem_path", str(tmp_path / "certs" / "priv.pem")
    )
    monkeypatch.setattr(
        settings, "policy_signing_public_key_pem_path", str(tmp_path / "certs" / "pub.pem")
    )

    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=test_engine)

    db = TestingSessionLocal()
    parent = Parent(email="p029@example.com", password_hash="$argon2id$dummy")
    db.add(parent)
    db.flush()
    child = Child(parent_id=parent.id, name="Bé An")
    db.add(child)
    db.flush()
    device = Device(child_id=child.id, fingerprint="FP-029")
    db.add(device)
    db.commit()
    create_new_policy_version(db, device.id, PolicyContent())
    device_id = device.id
    db.close()

    def override_get_db():
        s = TestingSessionLocal()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, base_url="https://testserver") as client:
        yield client, TestingSessionLocal, device_id, generate_device_access_token(device_id)
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()


def test_heartbeat_updates_last_seen_and_signals_policy_version_mismatch(hb_env):
    client, session_factory, device_id, token = hb_env
    headers = {"Authorization": f"Bearer {token}"}

    # Missing token -> 401; wrong device_id -> 403
    assert (
        client.post(
            f"/policy/heartbeat/{device_id}",
            json={"policy_version": 0, "quota_used_min": 5},
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/policy/heartbeat/other-device-id",
            json={"policy_version": 0, "quota_used_min": 5},
            headers=headers,
        ).status_code
        == 403
    )

    # Version mismatch (agent=0, server=1) -> policy_update_available=True
    r1 = client.post(
        f"/policy/heartbeat/{device_id}",
        json={"policy_version": 0, "quota_used_min": 10, "is_locked": False},
        headers=headers,
    )
    assert r1.status_code == 200
    d1 = r1.json()
    assert d1["server_policy_version"] == 1
    assert d1["policy_update_available"] is True
    assert datetime.fromisoformat(d1["server_utc"])

    db = session_factory()
    try:
        dev = db.query(Device).filter(Device.id == device_id).one()
        assert dev.last_seen_at is not None
    finally:
        db.close()

    # Matching version -> policy_update_available=False
    r2 = client.post(
        f"/policy/heartbeat/{device_id}",
        json={"policy_version": 1, "quota_used_min": 11, "is_locked": False},
        headers=headers,
    )
    assert r2.status_code == 200
    assert r2.json()["policy_update_available"] is False
