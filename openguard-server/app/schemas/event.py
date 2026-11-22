from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.event import EventType

_FORBIDDEN_SUBJECT_TOKENS = ("://", "/", "?", "=", "#")


class EventItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    idempotency_key: str = Field(min_length=1, max_length=128)
    ts: datetime
    device_id: str = Field(min_length=1)
    child_id: str = Field(min_length=1)
    type: EventType
    subject: str | None = Field(default=None, max_length=255)
    duration_sec: int = Field(default=0, ge=0)
    policy_id: str | None = None

    @field_validator("subject")
    @classmethod
    def forbid_full_url(cls, v: str | None) -> str | None:
        if v is None:
            return None
        cleaned = v.strip()
        if not cleaned:
            return None
        if any(token in cleaned for token in _FORBIDDEN_SUBJECT_TOKENS):
            raise ValueError(
                "NT2: subject chỉ được chứa tên app hoặc tên miền cấp hai, cấm lưu URL đầy đủ"
            )
        return cleaned


class EventBatchRequest(BaseModel):
    events: list[EventItem] = Field(max_length=200)


class EventBatchResponse(BaseModel):
    inserted: int
    skipped_duplicates: int
