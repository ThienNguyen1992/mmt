from datetime import datetime, timedelta, timezone

import pytest
from fastapi import APIRouter, Depends
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.config import settings
from app.core.deps import get_current_admin, get_current_parent, get_current_viewer
from app.core.security import hash_password
from app.database import Base, get_db
from app.main import app
from app.models import Child, Parent
from app.models.misc import Session as SessionModel


@pytest.fixture
def rbac_env():
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=test_engine)

    probe_router = APIRouter(prefix="/_test_rbac")

    @probe_router.post("/parent-write")
    def _parent_write(parent: Parent = Depends(get_current_parent)):
        return {"ok": True, "role": parent.role}

    @probe_router.get("/admin-only")
    def _admin_only(admin: Parent = Depends(get_current_admin)):
        return {"ok": True, "role": admin.role}

    @probe_router.get("/viewer-read")
    def _viewer_read(sess: SessionModel = Depends(get_current_viewer)):
        return {"ok": True, "role": sess.role, "child_id": sess.child_id}

    app.include_router(probe_router)

    db = TestingSessionLocal()
    parent_a = Parent(
        email="parenta@example.com",
        password_hash=hash_password("StrongPass123!"),
        role="parent",
    )
    parent_b = Parent(
        email="parentb@example.com",
        password_hash=hash_password("StrongPass123!"),
        role="parent",
    )
    admin = Parent(
        email="admin@example.com",
        password_hash=hash_password("StrongPass123!"),
        role="admin",
    )
    db.add_all([parent_a, parent_b, admin])
    db.flush()

    child_a = Child(parent_id=parent_a.id, name="Bé An")
    child_b = Child(parent_id=parent_b.id, name="Bé Bình")
    db.add_all([child_a, child_b])
    db.commit()

    ids = {
        "child_a_id": child_a.id,
        "child_b_id": child_b.id,
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

    app.router.routes = [
        r for r in app.router.routes if not getattr(r, "path", "").startswith("/_test_rbac")
    ]
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()


def test_login_sets_secure_httponly_samesite_lax_cookie_12h(rbac_env, monkeypatch):
    monkeypatch.setattr(settings, "cookie_secure", True)
    client, session_factory, _ = rbac_env
    res = client.post(
        "/auth/login",
        json={"email": "parenta@example.com", "password": "StrongPass123!"},
    )
    assert res.status_code == 200
    assert res.json()["role"] == "parent"

    set_cookie = res.headers.get("set-cookie", "")
    assert "ogk_session=" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "Secure" in set_cookie
    assert (
        "SameSite=lax" in set_cookie.lower().replace("samesite=lax", "SameSite=lax")
        or "samesite=lax" in set_cookie.lower()
    )
    assert "Max-Age=43200" in set_cookie

    db = session_factory()
    try:
        sess = db.query(SessionModel).one()
        assert sess.role == "parent"
        assert sess.revoked is False
        delta = sess.expires_at - sess.created_at
        assert 43190 <= delta.total_seconds() <= 43210
    finally:
        db.close()


def test_login_invalid_credentials_returns_401(rbac_env):
    client, _, _ = rbac_env
    res = client.post(
        "/auth/login",
        json={"email": "parenta@example.com", "password": "WrongPassword!"},
    )
    assert res.status_code == 401


def test_rbac_three_roles_parent_child_view_admin(rbac_env):
    client, _, ids = rbac_env

    # Unauthenticated -> 401
    assert client.post("/_test_rbac/parent-write").status_code == 401

    # Login as parent
    assert (
        client.post(
            "/auth/login",
            json={"email": "parenta@example.com", "password": "StrongPass123!"},
        ).status_code
        == 200
    )
    assert client.post("/_test_rbac/parent-write").status_code == 200
    assert client.get("/_test_rbac/viewer-read").status_code == 200
    assert client.get("/_test_rbac/admin-only").status_code == 403

    # Parent cannot switch to another parent's child (IDOR -> 404)
    assert client.post("/auth/child-view", json={"child_id": ids["child_b_id"]}).status_code == 404

    # Switch to child-view for own child -> 200
    cv_res = client.post("/auth/child-view", json={"child_id": ids["child_a_id"]})
    assert cv_res.status_code == 200
    assert cv_res.json()["role"] == "child-view"
    assert cv_res.json()["child_id"] == ids["child_a_id"]

    # child-view blocked on parent write routes (403), allowed on viewer read (200)
    assert client.post("/_test_rbac/parent-write").status_code == 403
    assert client.post("/auth/child-view", json={"child_id": ids["child_a_id"]}).status_code == 403
    viewer_res = client.get("/_test_rbac/viewer-read")
    assert viewer_res.status_code == 200
    assert viewer_res.json() == {"ok": True, "role": "child-view", "child_id": ids["child_a_id"]}

    # Login as admin -> allowed on all 3
    assert (
        client.post(
            "/auth/login",
            json={"email": "admin@example.com", "password": "StrongPass123!"},
        ).status_code
        == 200
    )
    assert client.post("/_test_rbac/parent-write").status_code == 200
    assert client.get("/_test_rbac/admin-only").status_code == 200
    assert client.get("/_test_rbac/viewer-read").status_code == 200


def test_expired_session_rejected_401(rbac_env):
    client, session_factory, _ = rbac_env
    client.post(
        "/auth/login",
        json={"email": "parenta@example.com", "password": "StrongPass123!"},
    )
    db = session_factory()
    try:
        sess = db.query(SessionModel).one()
        sess.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.commit()
    finally:
        db.close()

    assert client.get("/_test_rbac/viewer-read").status_code == 401
