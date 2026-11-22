from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.config import settings
from app.core.security import decode_access_token, hash_password, hash_refresh_token
from app.database import Base, get_db
from app.main import app
from app.models import AuditLog, Child, Device, Parent, RefreshToken


@pytest.fixture
def revoke_env(tmp_path, monkeypatch):
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
    pa = Parent(email="pa023@example.com", password_hash=hash_password("StrongPass123!"))
    pb = Parent(email="pb023@example.com", password_hash=hash_password("StrongPass123!"))
    db.add_all([pa, pb])
    db.flush()

    child_a = Child(parent_id=pa.id, name="Bé An")
    db.add(child_a)
    db.commit()
    child_a_id = child_a.id
    db.close()

    def override_get_db():
        s = TestingSessionLocal()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, base_url="https://testserver") as client:
        yield client, TestingSessionLocal, child_a_id
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()


def _login_and_enroll(client, child_id: str) -> tuple[dict, dict]:
    login_res = client.post(
        "/auth/login",
        json={"email": "pa023@example.com", "password": "StrongPass123!"},
    )
    csrf_headers = {"X-CSRF-Token": login_res.json()["csrf_token"]}
    code_res = client.post(
        "/enroll/create-code",
        json={"child_id": child_id, "consent_confirmed": True},
        headers=csrf_headers,
    )
    enroll_res = client.post(
        "/enroll/device",
        json={"code": code_res.json()["code"], "fingerprint": "FP-023"},
    )
    assert enroll_res.status_code == 200
    return enroll_res.json(), csrf_headers


def test_refresh_token_issues_new_access_token_and_rejects_expired(revoke_env):
    client, session_factory, child_id = revoke_env
    enrolled, _ = _login_and_enroll(client, child_id)

    ref_res = client.post("/enroll/refresh", json={"refresh_token": enrolled["refresh_token"]})
    assert ref_res.status_code == 200
    new_access = ref_res.json()["access_token"]
    assert decode_access_token(new_access)["sub"] == enrolled["device_id"]

    # Unknown refresh token -> 401
    assert client.post("/enroll/refresh", json={"refresh_token": "bogus"}).status_code == 401

    # Expired refresh token -> 401
    db = session_factory()
    try:
        rt = (
            db.query(RefreshToken)
            .filter(RefreshToken.token_hash == hash_refresh_token(enrolled["refresh_token"]))
            .one()
        )
        rt.expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
        db.commit()
    finally:
        db.close()

    assert (
        client.post(
            "/enroll/refresh", json={"refresh_token": enrolled["refresh_token"]}
        ).status_code
        == 401
    )


def test_revoke_device_blocks_sync_and_refresh_with_idor_protection(revoke_env):
    client, session_factory, child_id = revoke_env
    enrolled, csrf_a = _login_and_enroll(client, child_id)
    device_id = enrolled["device_id"]

    # Parent B tries to revoke Parent A's device -> 404 (anti-IDOR)
    login_b = client.post(
        "/auth/login",
        json={"email": "pb023@example.com", "password": "StrongPass123!"},
    )
    csrf_b = {"X-CSRF-Token": login_b.json()["csrf_token"]}
    assert client.post(f"/enroll/revoke/{device_id}", headers=csrf_b).status_code == 404

    # Re-login as Parent A and revoke
    login_a = client.post(
        "/auth/login",
        json={"email": "pa023@example.com", "password": "StrongPass123!"},
    )
    csrf_a = {"X-CSRF-Token": login_a.json()["csrf_token"]}

    # Missing CSRF -> 403
    assert client.post(f"/enroll/revoke/{device_id}").status_code == 403

    rev_res = client.post(f"/enroll/revoke/{device_id}", headers=csrf_a)
    assert rev_res.status_code == 200

    db = session_factory()
    try:
        dev = db.query(Device).filter(Device.id == device_id).one()
        assert dev.is_active is False
        rt = db.query(RefreshToken).filter(RefreshToken.device_id == device_id).one()
        assert rt.revoked is True
        audit = db.query(AuditLog).filter(AuditLog.action == "revoke_device").one()
        assert f"device_id={device_id}" in (audit.new_value or "")
    finally:
        db.close()

    # Subsequent refresh and event sync are both rejected (401)
    assert (
        client.post(
            "/enroll/refresh", json={"refresh_token": enrolled["refresh_token"]}
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/events/batch",
            json={"events": []},
            headers={"Authorization": f"Bearer {enrolled['access_token']}"},
        ).status_code
        == 401
    )
