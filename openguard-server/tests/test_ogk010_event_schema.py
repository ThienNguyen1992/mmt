from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import create_engine, inspect

import app.models  # noqa: F401
from app.database import Base
from app.models.event import Event, EventType
from app.schemas.event import EventBatchRequest, EventItem


def test_event_table_columns_match_7_business_fields(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'ogk010.db'}", future=True)
    try:
        Base.metadata.create_all(bind=engine)
        cols = {col["name"] for col in inspect(engine).get_columns("events")}
        assert cols == {
            "id",
            "idempotency_key",
            "ts",
            "device_id",
            "child_id",
            "type",
            "subject",
            "duration_sec",
            "policy_id",
        }
        assert Event.__tablename__ == "events"
    finally:
        engine.dispose()


def test_event_type_enum_has_exact_9_values():
    expected = {
        "app_start",
        "app_stop",
        "domain_query",
        "blocked_app",
        "blocked_domain",
        "quota_warning",
        "locked",
        "unlock_request",
        "override_granted",
    }
    assert {e.value for e in EventType} == expected
    assert len(EventType) == 9


@pytest.mark.parametrize(
    "valid_subject",
    [
        None,
        "word.exe",
        "youtube.com",
        "hcmus.edu.vn",
        "extra_time_15min",
        "wrong_block:hocmai.vn",
    ],
)
def test_event_item_accepts_valid_subjects(valid_subject):
    item = EventItem(
        idempotency_key="key-123",
        ts=datetime.now(timezone.utc),
        device_id="dev-1",
        child_id="child-1",
        type=EventType.domain_query,
        subject=valid_subject,
        duration_sec=120,
        policy_id="v1",
    )
    assert item.subject == valid_subject


@pytest.mark.parametrize(
    "bad_subject",
    [
        "https://example.com/a?b=1",
        "http://example.com",
        "example.com/path/to/page",
        "example.com?search=abc",
        "param=value",
        "example.com#section",
    ],
)
def test_event_item_forbids_full_url_path_or_query(bad_subject):
    with pytest.raises(ValidationError, match="NT2"):
        EventItem(
            idempotency_key="key-bad",
            ts=datetime.now(timezone.utc),
            device_id="dev-1",
            child_id="child-1",
            type=EventType.domain_query,
            subject=bad_subject,
        )


def test_event_item_forbids_unknown_type_negative_duration_and_extra_fields():
    base_kwargs = {
        "idempotency_key": "key-1",
        "ts": datetime.now(timezone.utc),
        "device_id": "dev-1",
        "child_id": "child-1",
        "type": "app_start",
    }

    with pytest.raises(ValidationError):
        EventItem(**{**base_kwargs, "type": "keystroke_capture"})

    with pytest.raises(ValidationError):
        EventItem(**{**base_kwargs, "duration_sec": -5})

    with pytest.raises(ValidationError):
        EventItem(**{**base_kwargs, "window_title": "Private Document.docx"})


def test_event_batch_request_max_200_and_fastapi_422_on_full_url():
    sample = EventItem(
        idempotency_key="k1",
        ts=datetime.now(timezone.utc),
        device_id="dev-1",
        child_id="child-1",
        type=EventType.app_stop,
        subject="notepad.exe",
        duration_sec=60,
    )
    with pytest.raises(ValidationError):
        EventBatchRequest(events=[sample] * 201)

    probe_app = FastAPI()

    @probe_app.post("/probe-events")
    def _probe(payload: EventBatchRequest):
        return {"count": len(payload.events)}

    client = TestClient(probe_app)
    res = client.post(
        "/probe-events",
        json={
            "events": [
                {
                    "idempotency_key": "k-url",
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "device_id": "dev-1",
                    "child_id": "child-1",
                    "type": "domain_query",
                    "subject": "https://example.com/a?b=1",
                    "duration_sec": 10,
                    "policy_id": "v1",
                }
            ]
        },
    )
    assert res.status_code == 422
