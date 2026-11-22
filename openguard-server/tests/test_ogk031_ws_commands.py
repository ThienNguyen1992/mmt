import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.websockets import WebSocketDisconnect

import app.models  # noqa: F401
from app.core.security import generate_device_access_token, hash_password
from app.database import Base, get_db
from app.main import app
from app.models import AuditLog, Child, Device, Parent


@pytest.fixture
def ws_env():
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=test_engine)

    db = TestingSessionLocal()
    pa = Parent(email="pa031@example.com", password_hash=hash_password("StrongPass123!"))
    pb = Parent(email="pb031@example.com", password_hash=hash_password("StrongPass123!"))
    db.add_all([pa, pb])
    db.flush()

    ca = Child(parent_id=pa.id, name="Bé An")
    db.add(ca)
    db.flush()

    da = Device(child_id=ca.id, fingerprint="FP-031-A", is_active=True)
    da_revoked = Device(child_id=ca.id, fingerprint="FP-031-REV", is_active=False)
    db.add_all([da, da_revoked])
    db.commit()

    ids = {
        "dev_a": da.id,
        "tok_a": generate_device_access_token(da.id),
        "tok_revoked": generate_device_access_token(da_revoked.id),
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


def test_ws_rejects_missing_invalid_mismatched_and_revoked_tokens_with_4401(ws_env):
    client, _, ids = ws_env
    dev_a = ids["dev_a"]

    # Missing token
    with pytest.raises(WebSocketDisconnect) as exc1:
        with client.websocket_connect(f"/commands/ws/{dev_a}"):
            pass
    assert exc1.value.code == 4401

    # Invalid JWT
    with pytest.raises(WebSocketDisconnect) as exc2:
        with client.websocket_connect(
            f"/commands/ws/{dev_a}",
            headers={"Authorization": "Bearer invalid.jwt"},
        ):
            pass
    assert exc2.value.code == 4401

    # Token belongs to dev_a, trying to connect as other device_id
    with pytest.raises(WebSocketDisconnect) as exc3:
        with client.websocket_connect(
            "/commands/ws/other-device",
            headers={"Authorization": f"Bearer {ids['tok_a']}"},
        ):
            pass
    assert exc3.value.code == 4401

    # Revoked device token
    with pytest.raises(WebSocketDisconnect) as exc4:
        with client.websocket_connect(
            f"/commands/ws/{dev_a}",
            headers={"Authorization": f"Bearer {ids['tok_revoked']}"},
        ):
            pass
    assert exc4.value.code == 4401


def test_ws_header_auth_ping_pong_and_send_emergency_commands(ws_env):
    client, session_factory, ids = ws_env
    dev_a = ids["dev_a"]

    login_a = client.post(
        "/auth/login",
        json={"email": "pa031@example.com", "password": "StrongPass123!"},
    )
    csrf_a = {"X-CSRF-Token": login_a.json()["csrf_token"]}

    with client.websocket_connect(
        f"/commands/ws/{dev_a}",
        headers={"Authorization": f"Bearer {ids['tok_a']}"},
    ) as ws:
        ws.send_text(json.dumps({"type": "ping"}))
        assert json.loads(ws.receive_text()) == {"type": "pong"}

        # Send valid emergency command over HTTP -> pushed immediately to WS
        send_res = client.post(
            f"/commands/send/{dev_a}",
            json={"type": "add_minutes", "minutes": 15},
            headers=csrf_a,
        )
        assert send_res.status_code == 200
        assert send_res.json()["delivered"] is True

        pushed = json.loads(ws.receive_text())
        assert pushed["type"] == "add_minutes"
        assert pushed["minutes"] == 15
        assert "issued_at" in pushed

    # Invalid command type -> 422
    assert (
        client.post(
            f"/commands/send/{dev_a}",
            json={"type": "rm_rf"},
            headers=csrf_a,
        ).status_code
        == 422
    )

    # Anti-IDOR: Parent B cannot send command to Parent A's device -> 404
    login_b = client.post(
        "/auth/login",
        json={"email": "pb031@example.com", "password": "StrongPass123!"},
    )
    csrf_b = {"X-CSRF-Token": login_b.json()["csrf_token"]}
    assert (
        client.post(
            f"/commands/send/{dev_a}",
            json={"type": "lock_now"},
            headers=csrf_b,
        ).status_code
        == 404
    )

    db = session_factory()
    try:
        audit = db.query(AuditLog).filter(AuditLog.action == "send_emergency_command").one()
        assert "add_minutes" in (audit.new_value or "")
    finally:
        db.close()
