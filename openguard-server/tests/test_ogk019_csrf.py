import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.core.csrf import generate_csrf_token, validate_csrf_value
from app.core.security import hash_password
from app.database import Base, get_db
from app.main import app
from app.models import Child, Parent


@pytest.fixture
def csrf_env():
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=test_engine)

    db = TestingSessionLocal()
    parent = Parent(
        email="csrf@example.com",
        password_hash=hash_password("StrongPass123!"),
        role="parent",
    )
    db.add(parent)
    db.flush()
    child = Child(parent_id=parent.id, name="Bé Lan")
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
        yield client, child_id
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()


def test_validate_csrf_value_unit():
    token = generate_csrf_token("sess-abc")
    assert validate_csrf_value(token, "sess-abc") is True
    assert validate_csrf_value(token, "sess-other") is False
    assert validate_csrf_value(None, "sess-abc") is False
    assert validate_csrf_value("", "sess-abc") is False
    assert validate_csrf_value(token + "tamper", "sess-abc") is False


def test_csrf_protect_blocks_missing_or_wrong_header_and_allows_valid(csrf_env):
    client, child_id = csrf_env

    # No session cookie -> 401
    assert client.post("/auth/child-view", json={"child_id": child_id}).status_code == 401

    login_res = client.post(
        "/auth/login",
        json={"email": "csrf@example.com", "password": "StrongPass123!"},
    )
    assert login_res.status_code == 200
    csrf_token = login_res.json()["csrf_token"]

    # Missing X-CSRF-Token -> 403
    assert client.post("/auth/child-view", json={"child_id": child_id}).status_code == 403

    # Wrong X-CSRF-Token -> 403
    assert (
        client.post(
            "/auth/child-view",
            json={"child_id": child_id},
            headers={"X-CSRF-Token": "forged-token"},
        ).status_code
        == 403
    )

    # Valid X-CSRF-Token -> 200
    ok_res = client.post(
        "/auth/child-view",
        json={"child_id": child_id},
        headers={"X-CSRF-Token": csrf_token},
    )
    assert ok_res.status_code == 200
