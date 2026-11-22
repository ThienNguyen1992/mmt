from datetime import datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.core.security import hash_password
from app.database import Base, get_db
from app.main import app
from app.models import AuditLog, Child, EnrollmentCode, Parent


@pytest.fixture
def enroll_code_env():
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=test_engine)

    db = TestingSessionLocal()
    pa = Parent(email="pa021@example.com", password_hash=hash_password("StrongPass123!"))
    pb = Parent(email="pb021@example.com", password_hash=hash_password("StrongPass123!"))
    db.add_all([pa, pb])
    db.flush()

    child_a = Child(parent_id=pa.id, name="Bé An")
    child_b = Child(parent_id=pb.id, name="Bé Bình")
    db.add_all([child_a, child_b])
    db.commit()
    ids = {"child_a": child_a.id, "child_b": child_b.id}
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


def test_create_enrollment_code_records_consent_and_audit(enroll_code_env):
    client, session_factory, ids = enroll_code_env

    login_res = client.post(
        "/auth/login",
        json={"email": "pa021@example.com", "password": "StrongPass123!"},
    )
    csrf_headers = {"X-CSRF-Token": login_res.json()["csrf_token"]}

    res = client.post(
        "/enroll/create-code",
        json={"child_id": ids["child_a"], "consent_confirmed": True},
        headers=csrf_headers,
    )
    assert res.status_code == 200
    data = res.json()
    code = data["code"]
    assert len(code) == 8
    assert not any(ch in code for ch in ("0", "O", "1", "I"))
    assert datetime.fromisoformat(data["expires_at"])

    db = session_factory()
    try:
        row = db.query(EnrollmentCode).filter(EnrollmentCode.code == code).one()
        assert row.consent_confirmed is True
        assert row.consent_ip is not None
        assert row.used is False
        delta_sec = (row.expires_at - row.created_at).total_seconds()
        assert 590 <= delta_sec <= 610

        audit = db.query(AuditLog).filter(AuditLog.action == "create_enrollment_code").one()
        assert audit.child_id == ids["child_a"]
        assert audit.ip_address == row.consent_ip
    finally:
        db.close()


def test_create_enrollment_code_validation_idor_csrf_and_rbac(enroll_code_env):
    client, _, ids = enroll_code_env

    login_res = client.post(
        "/auth/login",
        json={"email": "pa021@example.com", "password": "StrongPass123!"},
    )
    csrf_headers = {"X-CSRF-Token": login_res.json()["csrf_token"]}

    # Missing CSRF -> 403
    assert (
        client.post(
            "/enroll/create-code",
            json={"child_id": ids["child_a"], "consent_confirmed": True},
        ).status_code
        == 403
    )

    # consent_confirmed=False -> 422
    assert (
        client.post(
            "/enroll/create-code",
            json={"child_id": ids["child_a"], "consent_confirmed": False},
            headers=csrf_headers,
        ).status_code
        == 422
    )

    # Another parent's child -> 404 (IDOR)
    assert (
        client.post(
            "/enroll/create-code",
            json={"child_id": ids["child_b"], "consent_confirmed": True},
            headers=csrf_headers,
        ).status_code
        == 404
    )

    # Switch to child-view -> blocked 403
    cv_res = client.post(
        "/auth/child-view",
        json={"child_id": ids["child_a"]},
        headers=csrf_headers,
    )
    cv_headers = {"X-CSRF-Token": cv_res.json()["csrf_token"]}
    assert (
        client.post(
            "/enroll/create-code",
            json={"child_id": ids["child_a"], "consent_confirmed": True},
            headers=cv_headers,
        ).status_code
        == 403
    )
