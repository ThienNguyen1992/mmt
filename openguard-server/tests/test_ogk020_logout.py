import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.core.security import hash_password
from app.database import Base, get_db
from app.main import app
from app.models import Parent
from app.models.misc import Session as SessionModel


@pytest.fixture
def logout_env():
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=test_engine)

    db = TestingSessionLocal()
    db.add(
        Parent(
            email="logout@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="parent",
        )
    )
    db.commit()
    db.close()

    def override_get_db():
        s = TestingSessionLocal()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, base_url="https://testserver") as client:
        yield client, TestingSessionLocal
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()


def test_logout_revokes_server_session_and_rejects_replayed_cookie(logout_env):
    client, session_factory = logout_env

    login_res = client.post(
        "/auth/login",
        json={"email": "logout@example.com", "password": "StrongPass123!"},
    )
    assert login_res.status_code == 200
    csrf_token = login_res.json()["csrf_token"]
    old_cookie = client.cookies.get("ogk_session")
    assert old_cookie

    # Missing CSRF -> 403
    assert client.post("/auth/logout").status_code == 403

    # Valid logout -> 200 & revokes session in DB + deletes cookie
    logout_res = client.post("/auth/logout", headers={"X-CSRF-Token": csrf_token})
    assert logout_res.status_code == 200
    assert "Max-Age=0" in logout_res.headers.get("set-cookie", "")

    db = session_factory()
    try:
        sess = db.query(SessionModel).filter(SessionModel.session_token == old_cookie).one()
        assert sess.revoked is True
    finally:
        db.close()

    # Replaying old cookie after logout -> 401
    client.cookies.set("ogk_session", old_cookie)
    replay_res = client.post(
        "/auth/logout",
        headers={"X-CSRF-Token": csrf_token},
    )
    assert replay_res.status_code == 401
