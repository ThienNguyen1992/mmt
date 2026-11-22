from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.core.security import generate_device_access_token
from app.database import Base, get_db
from app.main import app
from app.models import Child, ChildRequest, Device, Event, Parent


@pytest.fixture
def env():
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(test_engine, "connect")
    def _fk(dbapi_conn, _rec):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON;")
        cur.close()

    TestingSessionLocal = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=test_engine)

    db = TestingSessionLocal()
    parent = Parent(email="p011@example.com", password_hash="$argon2id$dummy", role="parent")
    db.add(parent)
    db.flush()

    child = Child(parent_id=parent.id, name="Bé Minh")
    db.add(child)
    db.flush()

    device = Device(child_id=child.id, fingerprint="FP-011", is_active=True)
    inactive_device = Device(child_id=child.id, fingerprint="FP-011-REVOKED", is_active=False)
    db.add_all([device, inactive_device])
    db.commit()

    device_id = device.id
    child_id = child.id
    revoked_id = inactive_device.id
    db.close()

    def override_get_db():
        s = TestingSessionLocal()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as client:
        yield {
            "client": client,
            "session_factory": TestingSessionLocal,
            "device_id": device_id,
            "child_id": child_id,
            "revoked_id": revoked_id,
            "token": generate_device_access_token(device_id),
            "revoked_token": generate_device_access_token(revoked_id),
        }
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()


def _make_event_payload(device_id: str, child_id: str, **overrides) -> dict:
    base = {
        "idempotency_key": "idem-1",
        "ts": datetime.now(timezone.utc).isoformat(),
        "device_id": device_id,
        "child_id": child_id,
        "type": "app_stop",
        "subject": "word.exe",
        "duration_sec": 300,
        "policy_id": "v1",
    }
    base.update(overrides)
    return base


def test_events_batch_requires_active_device_token(env):
    client = env["client"]
    payload = {"events": [_make_event_payload(env["device_id"], env["child_id"])]}

    assert client.post("/events/batch", json=payload).status_code == 401
    assert (
        client.post(
            "/events/batch",
            json=payload,
            headers={"Authorization": "Bearer invalid.jwt.token"},
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/events/batch",
            json=payload,
            headers={"Authorization": f"Bearer {env['revoked_token']}"},
        ).status_code
        == 401
    )


def test_events_batch_rejects_full_url_and_unknown_type_422(env):
    client = env["client"]
    headers = {"Authorization": f"Bearer {env['token']}"}

    bad_url = _make_event_payload(
        env["device_id"],
        env["child_id"],
        idempotency_key="k-url",
        type="domain_query",
        subject="https://example.com/a?b=1",
    )
    assert (
        client.post("/events/batch", json={"events": [bad_url]}, headers=headers).status_code == 422
    )

    bad_type = _make_event_payload(
        env["device_id"],
        env["child_id"],
        idempotency_key="k-type",
        type="unknown_event_type",
    )
    assert (
        client.post("/events/batch", json={"events": [bad_type]}, headers=headers).status_code
        == 422
    )


def test_events_batch_rejects_device_or_child_mismatch_403(env):
    client = env["client"]
    headers = {"Authorization": f"Bearer {env['token']}"}

    valid_item = _make_event_payload(env["device_id"], env["child_id"], idempotency_key="k-valid")
    spoofed_device = _make_event_payload(
        "other-device-id", env["child_id"], idempotency_key="k-spoof-dev"
    )
    res1 = client.post(
        "/events/batch",
        json={"events": [valid_item, spoofed_device]},
        headers=headers,
    )
    assert res1.status_code == 403

    spoofed_child = _make_event_payload(
        env["device_id"], "other-child-id", idempotency_key="k-spoof-child"
    )
    res2 = client.post("/events/batch", json={"events": [spoofed_child]}, headers=headers)
    assert res2.status_code == 403

    db = env["session_factory"]()
    try:
        assert db.query(Event).count() == 0
    finally:
        db.close()


def test_events_batch_inserts_and_skips_duplicate_idempotency_keys(env):
    client = env["client"]
    headers = {"Authorization": f"Bearer {env['token']}"}

    ev1 = _make_event_payload(
        env["device_id"],
        env["child_id"],
        idempotency_key="idem-dup-1",
        type="app_stop",
        subject="word.exe",
        duration_sec=180,
    )
    ev2 = _make_event_payload(
        env["device_id"],
        env["child_id"],
        idempotency_key="idem-dup-2",
        type="domain_query",
        subject="hcmus.edu.vn",
        duration_sec=0,
    )

    # First batch (includes an intra-batch duplicate of idem-dup-1)
    res1 = client.post("/events/batch", json={"events": [ev1, ev2, ev1]}, headers=headers)
    assert res1.status_code == 200
    assert res1.json() == {"inserted": 2, "skipped_duplicates": 1}

    # Retry identical batch -> both skipped, no 500 error, duration not doubled
    res2 = client.post("/events/batch", json={"events": [ev1, ev2]}, headers=headers)
    assert res2.status_code == 200
    assert res2.json() == {"inserted": 0, "skipped_duplicates": 2}

    db = env["session_factory"]()
    try:
        assert db.query(Event).count() == 2
        stored = db.query(Event).filter(Event.idempotency_key == "idem-dup-1").one()
        assert stored.duration_sec == 180
    finally:
        db.close()


def test_events_batch_unlock_request_creates_child_request(env):
    client = env["client"]
    headers = {"Authorization": f"Bearer {env['token']}"}

    req_extra = _make_event_payload(
        env["device_id"],
        env["child_id"],
        idempotency_key="idem-req-1",
        type="unlock_request",
        subject="extra_time_15min",
        duration_sec=0,
    )
    req_wrong_block = _make_event_payload(
        env["device_id"],
        env["child_id"],
        idempotency_key="idem-req-2",
        type="unlock_request",
        subject="wrong_block:hocmai.vn",
        duration_sec=0,
    )

    res = client.post(
        "/events/batch", json={"events": [req_extra, req_wrong_block]}, headers=headers
    )
    assert res.status_code == 200
    assert res.json() == {"inserted": 2, "skipped_duplicates": 0}

    db = env["session_factory"]()
    try:
        requests = db.query(ChildRequest).order_by(ChildRequest.request_type.asc()).all()
        assert len(requests) == 2
        extra_row, wrong_row = requests
        assert extra_row.request_type == "extra_time"
        assert extra_row.subject == "extra_time_15min"
        assert extra_row.requested_minutes == 15
        assert wrong_row.request_type == "wrong_block"
        assert wrong_row.subject == "hocmai.vn"
        assert wrong_row.requested_minutes is None
    finally:
        db.close()
