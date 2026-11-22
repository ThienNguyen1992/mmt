import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.core.security import generate_device_access_token
from app.database import Base, get_db
from app.main import app
from app.models import Child, Device, Event, Parent


@pytest.fixture
def pipeline_env():
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=test_engine)

    db = TestingSessionLocal()
    parent = Parent(email="p033@example.com", password_hash="$argon2id$dummy")
    db.add(parent)
    db.flush()
    child = Child(parent_id=parent.id, name="Bé An")
    db.add(child)
    db.flush()
    device = Device(child_id=child.id, fingerprint="FP-033", is_active=True)
    db.add(device)
    db.commit()
    ids = {
        "device_id": device.id,
        "child_id": child.id,
        "token": generate_device_access_token(device.id),
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


def test_retrying_same_event_batch_never_doubles_duration(pipeline_env):
    client, session_factory, ids = pipeline_env
    headers = {"Authorization": f"Bearer {ids['token']}"}
    now_iso = datetime.now(timezone.utc).isoformat()

    batch = {
        "events": [
            {
                "idempotency_key": str(uuid.uuid4()),
                "ts": now_iso,
                "device_id": ids["device_id"],
                "child_id": ids["child_id"],
                "type": "app_stop",
                "subject": "word.exe",
                "duration_sec": 600,
                "policy_id": "v1",
            },
            {
                "idempotency_key": str(uuid.uuid4()),
                "ts": now_iso,
                "device_id": ids["device_id"],
                "child_id": ids["child_id"],
                "type": "domain_query",
                "subject": "hocmai.vn",
                "duration_sec": 0,
                "policy_id": "v1",
            },
        ]
    }

    r1 = client.post("/events/batch", json=batch, headers=headers)
    assert r1.status_code == 200
    assert r1.json() == {"inserted": 2, "skipped_duplicates": 0}

    r2 = client.post("/events/batch", json=batch, headers=headers)
    assert r2.status_code == 200
    assert r2.json() == {"inserted": 0, "skipped_duplicates": 2}

    db = session_factory()
    try:
        total_duration = db.query(func.sum(Event.duration_sec)).scalar()
        assert total_duration == 600
        assert db.query(Event).count() == 2
    finally:
        db.close()
