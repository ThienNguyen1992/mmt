import pytest
from pydantic import ValidationError

from app.schemas.policy import AppRule, AppRulesConfig, PolicyContent


def test_policy_content_defaults_valid():
    policy = PolicyContent()
    assert policy.quota_weekday_min == 90
    assert policy.quota_weekend_min == 120
    assert len(policy.weekly_schedule) == 336
    assert policy.app_rules.mode == "blacklist"
    assert policy.domain_rules.age_preset == "6-11"
    assert policy.domain_rules.safesearch_enforce is True


def test_policy_content_rejects_invalid_schedule_length_or_chars():
    with pytest.raises(ValidationError):
        PolicyContent(weekly_schedule="A" * 335)

    with pytest.raises(ValidationError, match="A.*B"):
        PolicyContent(weekly_schedule="C" * 336)


def test_app_rules_rejects_duplicate_rules_case_insensitive():
    with pytest.raises(ValidationError, match="trùng lặp"):
        AppRulesConfig(
            mode="blacklist",
            rules=[
                AppRule(match_type="name", value="Game.exe", action="block", group="game"),
                AppRule(match_type="name", value="game.exe", action="block", group="game"),
            ],
        )
