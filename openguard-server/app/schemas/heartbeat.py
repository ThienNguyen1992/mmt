from pydantic import BaseModel, Field


class HeartbeatRequest(BaseModel):
    policy_version: int
    quota_used_min: int
    is_locked: bool = False
    offline_since_iso: str | None = None


class HeartbeatResponse(BaseModel):
    server_policy_version: int
    policy_update_available: bool
    server_utc: str
    pending_commands: list[dict] = Field(default_factory=list)
