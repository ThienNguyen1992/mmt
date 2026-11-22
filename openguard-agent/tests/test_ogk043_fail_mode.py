from datetime import datetime, timedelta, timezone

from agent.core import config as agent_config
from agent.core.fail_mode import FailModeEvaluator, is_emergency_domain
from agent.core.offline_tracker import OfflineTracker
from agent.service.agent_runtime import AgentRuntime


def test_is_emergency_domain_matches_nt6_without_false_suffix_match():
    assert is_emergency_domain("tongdai111.vn") is True
    assert is_emergency_domain("portal.tongdai111.vn.") is True
    assert is_emergency_domain("moet.gov.vn") is True
    assert is_emergency_domain("portal.hcmus.edu.vn") is True
    assert is_emergency_domain("notmoet.gov.vn") is False
    assert is_emergency_domain("gaming.com") is False


def test_fail_mode_grace_period_and_4_days_offline_tightening(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_config, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(agent_config, "IPC_DIR", str(tmp_path / "ipc"))

    tracker = OfflineTracker(failure_threshold=3)
    evaluator = FailModeEvaluator(tracker, grace_days=3)

    t0 = datetime(2026, 11, 18, 8, 0, tzinfo=timezone.utc)
    for step in range(3):
        tracker.record_failure(now=t0 + timedelta(minutes=step))

    base_policy = {
        "quota_weekday_min": 90,
        "quota_weekend_min": 40,
        "domain_rules": {
            "blocked_categories": ["inappropriate"],
            "custom_allowed_domains": ["khanacademy.org"],
        },
    }

    # Day 2 offline (< 3 days) -> normal policy unchanged
    day2 = evaluator.evaluate(base_policy, now=t0 + timedelta(days=2))
    assert day2["fail_mode_active"] is False
    assert day2["quota_weekday_min"] == 90
    assert day2["quota_weekend_min"] == 40
    assert day2["reason"] == ""

    # Day 4 offline (>= 3 days) -> 50% quota (min 30 min), education-only + NT6, transparent reason
    day4 = evaluator.evaluate(base_policy, now=t0 + timedelta(days=4))
    assert day4["fail_mode_active"] is True
    assert day4["education_only"] is True
    assert day4["quota_weekday_min"] == 45
    assert day4["quota_weekend_min"] == 30  # max(30, 40 // 2)
    assert "education" not in day4["domain_rules"]["blocked_categories"]
    assert "social_media" in day4["domain_rules"]["blocked_categories"]
    assert "tongdai111.vn" in day4["domain_rules"]["custom_allowed_domains"]
    assert "NT6" in day4["reason"]

    # Integrated into AgentRuntime status snapshot
    rt = AgentRuntime(start_network=False)
    monkeypatch.setattr(
        rt.offline_tracker,
        "get_offline_duration_days",
        lambda now=None: 4.0,
    )
    snap = rt.get_status_snapshot()
    assert snap["fail_mode_active"] is True
    assert "NT6" in snap["fail_mode_reason"]
