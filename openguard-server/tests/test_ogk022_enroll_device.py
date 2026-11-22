from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.config import settings
from app.core.crypto import decrypt_aes_gcm
from app.core.security import decode_access_token, hash_password, hash_refresh_token
from app.database import Base, get_db
from app.main import app
from app.models import Child, Device, EnrollmentCode, Parent, RefreshToken


@pytest.fixture
def enroll_device_env(tmp_path, monkeypatch):
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
    parent = Parent(email="pa022@example.com", password_hash=hash_password("StrongPass123!"))
    db.add(parent)
    db.flush()

    child = Child(parent_id=parent.id, name="Bé An")
    db.add(child)
    db.commit()
    child_id = child.id
    db.close()

    def override_get_db():
        s = TestingSessionLocal()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, base_url="https://testserver") as client:
        yield client, TestingSessionLocal, child_id
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()


def _create_code(client, child_id: str) -> str:
    login_res = client.post(
        "/auth/login",
        json={"email": "pa022@example.com", "password": "StrongPass123!"},
    )
    csrf_headers = {"X-CSRF-Token": login_res.json()["csrf_token"]}
    res = client.post(
        "/enroll/create-code",
        json={"child_id": child_id, "consent_confirmed": True},
        headers=csrf_headers,
    )
    assert res.status_code == 200
    return res.json()["code"]


def test_enroll_device_success_encrypts_fingerprint_and_returns_tokens(enroll_device_env):
    client, session_factory, child_id = enroll_device_env
    code = _create_code(client, child_id)

    res = client.post(
        "/enroll/device",
        json={
            "code": code.lower(),
            "fingerprint": "WIN11-HW-FP-001",
            "device_name": "PC Học Tập",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["child_id"] == child_id
    assert "BEGIN PUBLIC KEY" in data["policy_public_key_pem"]

    claims = decode_access_token(data["access_token"])
    assert claims["sub"] == data["device_id"]
    assert claims["type"] == "access"

    db = session_factory()
    try:
        device = db.query(Device).filter(Device.id == data["device_id"]).one()
        assert device.fingerprint_enc != "WIN11-HW-FP-001"
        assert decrypt_aes_gcm(device.fingerprint_enc) == "WIN11-HW-FP-001"
        assert device.device_secret_hash is not None
        assert len(device.device_secret_hash) == 64

        rt = db.query(RefreshToken).filter(RefreshToken.device_id == device.id).one()
        assert rt.token_hash == hash_refresh_token(data["refresh_token"])
        assert rt.revoked is False

        enr = db.query(EnrollmentCode).filter(EnrollmentCode.code == code).one()
        assert enr.used is True
        assert enr.used_at is not None
    finally:
        db.close()

    # Reusing used code -> 410 Gone
    reuse = client.post(
        "/enroll/device",
        json={"code": code, "fingerprint": "WIN11-HW-FP-002"},
    )
    assert reuse.status_code == 410


def test_enroll_device_rejects_missing_or_expired_code(enroll_device_env):
    client, session_factory, child_id = enroll_device_env

    assert (
        client.post(
            "/enroll/device",
            json={"code": "ZZZZ9999", "fingerprint": "FP-X"},
        ).status_code
        == 404
    )

    code = _create_code(client, child_id)
    db = session_factory()
    try:
        enr = db.query(EnrollmentCode).filter(EnrollmentCode.code == code).one()
        enr.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.commit()
    finally:
        db.close()

    expired_res = client.post(
        "/enroll/device",
        json={"code": code, "fingerprint": "FP-EXPIRED"},
    )
    assert expired_res.status_code == 410
