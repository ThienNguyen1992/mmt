import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.config import settings
from app.core.security import (
    generate_device_access_token,
    hash_password,
    verify_policy_signature,
)
from app.database import Base, get_db
from app.main import app
from app.models import AuditLog, Child, Device, Parent, Policy
from app.schemas.policy import PolicyContent
from app.services.policy_service import canonical_policy_json


@pytest.fixture
def policy_env(tmp_path, monkeypatch):
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
    pa = Parent(email="pa027@example.com", password_hash=hash_password("StrongPass123!"))
    pb = Parent(email="pb027@example.com", password_hash=hash_password("StrongPass123!"))
    db.add_all([pa, pb])
    db.flush()

    ca = Child(parent_id=pa.id, name="Bé An")
    cb = Child(parent_id=pb.id, name="Bé Bình")
    db.add_all([ca, cb])
    db.flush()

    da = Device(child_id=ca.id, fingerprint="FP-027-A")
    db_dev = Device(child_id=cb.id, fingerprint="FP-027-B")
    db.add_all([da, db_dev])
    db.commit()

    ids = {
        "child_a": ca.id,
        "dev_a": da.id,
        "dev_b": db_dev.id,
        "tok_a": generate_device_access_token(da.id),
        "tok_b": generate_device_access_token(db_dev.id),
    }
    db.close()

    def override_get_db():
        s = TestingSessionLocal()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, base_url="https://testserver") as client:
        yield client, TestingSessionLocal, ids
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()


def test_post_policy_signs_ed25519_audits_ip_and_detects_1byte_tamper(policy_env):
    client, session_factory, ids = policy_env
    dev_a = ids["dev_a"]

    # Device has no policy yet -> 404
    assert (
        client.get(
            f"/policy/{dev_a}", headers={"Authorization": f"Bearer {ids['tok_a']}"}
        ).status_code
        == 404
    )

    login_a = client.post(
        "/auth/login",
        json={"email": "pa027@example.com", "password": "StrongPass123!"},
    )
    csrf_a = {"X-CSRF-Token": login_a.json()["csrf_token"]}

    # Missing CSRF -> 403
    assert (
        client.post(
            f"/policy/{dev_a}",
            json={"content": PolicyContent(quota_weekday_min=60).model_dump()},
        ).status_code
        == 403
    )

    # Create v1
    r1 = client.post(
        f"/policy/{dev_a}",
        json={"content": PolicyContent(quota_weekday_min=60).model_dump()},
        headers=csrf_a,
    )
    assert r1.status_code == 200
    d1 = r1.json()
    assert d1["version"] == 1
    assert verify_policy_signature(canonical_policy_json(d1["content"]), d1["signature"])

    # Update to v2
    r2 = client.post(
        f"/policy/{dev_a}",
        json={"content": PolicyContent(quota_weekday_min=90).model_dump()},
        headers=csrf_a,
    )
    assert r2.status_code == 200
    assert r2.json()["version"] == 2

    # Check AuditLog recorded old_value, new_value, and real IP
    db = session_factory()
    try:
        audits = (
            db.query(AuditLog)
            .filter(AuditLog.action == "update_policy")
            .order_by(AuditLog.created_at.asc())
            .all()
        )
        assert len(audits) == 2
        assert audits[0].old_value is None
        assert audits[1].old_value is not None
        assert audits[1].ip_address != ""

        # Modify 1 byte in DB -> signature verification must fail
        pol_v2 = db.query(Policy).filter(Policy.device_id == dev_a, Policy.version == 2).one()
        tampered_json = pol_v2.content_json.replace(
            '"quota_weekday_min":90', '"quota_weekday_min":91'
        )
        assert tampered_json != pol_v2.content_json
        assert verify_policy_signature(tampered_json, pol_v2.signature) is False
    finally:
        db.close()

    # Device GET /policy/{device_id} succeeds for own token, 403 for other device token
    get_res = client.get(f"/policy/{dev_a}", headers={"Authorization": f"Bearer {ids['tok_a']}"})
    assert get_res.status_code == 200
    assert get_res.json()["version"] == 2

    other_res = client.get(f"/policy/{dev_a}", headers={"Authorization": f"Bearer {ids['tok_b']}"})
    assert other_res.status_code == 403


def test_post_policy_idor_and_child_view_blocked(policy_env):
    client, _, ids = policy_env

    # Parent B tries to update Parent A's device -> 404
    login_b = client.post(
        "/auth/login",
        json={"email": "pb027@example.com", "password": "StrongPass123!"},
    )
    csrf_b = {"X-CSRF-Token": login_b.json()["csrf_token"]}
    assert (
        client.post(
            f"/policy/{ids['dev_a']}",
            json={"content": PolicyContent().model_dump()},
            headers=csrf_b,
        ).status_code
        == 404
    )

    # child-view blocked -> 403
    login_a = client.post(
        "/auth/login",
        json={"email": "pa027@example.com", "password": "StrongPass123!"},
    )
    csrf_a = {"X-CSRF-Token": login_a.json()["csrf_token"]}
    cv = client.post(
        "/auth/child-view",
        json={"child_id": ids["child_a"]},
        headers=csrf_a,
    )
    csrf_cv = {"X-CSRF-Token": cv.json()["csrf_token"]}
    assert (
        client.post(
            f"/policy/{ids['dev_a']}",
            json={"content": PolicyContent().model_dump()},
            headers=csrf_cv,
        ).status_code
        == 403
    )
