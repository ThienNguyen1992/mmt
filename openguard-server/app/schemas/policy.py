from typing import Dict, List, Literal

from pydantic import BaseModel, Field, field_validator
from shared.schedule_utils import WEEKLY_SLOTS


class AppRule(BaseModel):
    match_type: Literal["name", "path", "hash"] = "name"
    value: str
    action: Literal["allow", "block"]
    group: Literal["study", "game", "entertainment", "other"] = "other"


class AppRulesConfig(BaseModel):
    mode: Literal["blacklist", "whitelist"] = "blacklist"
    rules: List[AppRule] = Field(default_factory=list)
    # Ngân sách riêng theo nhóm (phút/ngày). Vd: {"game": 45}
    group_quotas_min: Dict[str, int] = Field(default_factory=dict)

    @field_validator("rules")
    @classmethod
    def no_duplicate_rules(cls, rules: List[AppRule]) -> List[AppRule]:
        seen = set()
        for r in rules:
            key = (r.match_type, r.value.lower())
            if key in seen:
                raise ValueError(f"Rule ứng dụng trùng lặp: {r.match_type}={r.value}")
            seen.add(key)
        return rules


class DomainRulesConfig(BaseModel):
    # 6 nhóm: education, entertainment, social_media, gaming, inappropriate, uncategorized
    blocked_categories: List[str] = Field(default_factory=lambda: ["social_media", "inappropriate"])
    custom_blocked_domains: List[str] = Field(default_factory=list)
    custom_allowed_domains: List[str] = Field(default_factory=list)
    safesearch_enforce: bool = True
    age_preset: Literal["6-11", "12-15", "custom"] = "6-11"


class PolicyContent(BaseModel):
    quota_weekday_min: int = Field(default=90, ge=0, le=1440)
    quota_weekend_min: int = Field(default=120, ge=0, le=1440)
    weekly_schedule: str = Field(
        default="A" * WEEKLY_SLOTS,
        min_length=WEEKLY_SLOTS,
        max_length=WEEKLY_SLOTS,
    )
    app_rules: AppRulesConfig = Field(default_factory=AppRulesConfig)
    domain_rules: DomainRulesConfig = Field(default_factory=DomainRulesConfig)

    @field_validator("weekly_schedule")
    @classmethod
    def validate_schedule_chars(cls, v: str) -> str:
        if not all(c in ("A", "B") for c in v):
            raise ValueError("weekly_schedule chỉ được chứa 'A' hoặc 'B'")
        return v


class PolicyUpdateRequest(BaseModel):
    content: PolicyContent


class PolicyResponse(BaseModel):
    policy_id: str
    device_id: str
    version: int
    content: dict
    signature: str
    created_at: str
