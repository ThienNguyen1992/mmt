"""Tests for OGK-044: daily weekday/weekend quota and 3-minute quota exhaustion."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from agent.core import config as cfg
from agent.core import local_store
from agent.core.screen_time import ScreenTimeCounter


class _DummyRuntime:
    def __init__(self, policy: dict[str, Any]) -> None:
        self.policy = policy
        self._extra_minutes_today = 0
        self.locked_reasons: list[str] = []

    def get_effective_policy(self) -> dict[str, Any]:
        return self.policy

    def lock_device(self, reason: str) -> None:
        self.locked_reasons.append(reason)


@pytest.fixture()
def isolated_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(cfg, "DATA_DIR", str(tmp_path))
    local_store.init_schema()
    return tmp_path / "ogk_agent.db"


def test_weekday_vs_weekend_quota_limits(isolated_db: Path) -> None:
    runtime = _DummyRuntime({"quota_weekday_min": 120, "quota_weekend_min": 180})
    counter = ScreenTimeCounter(runtime)

    monday = datetime(2026, 4, 13, 10, 0)  # weekday() == 0
    saturday = datetime(2026, 4, 18, 10, 0)  # weekday() == 5

    assert counter._get_quota_limit_sec(runtime.policy, monday) == 120 * 60
    assert counter._get_quota_limit_sec(runtime.policy, saturday) == 180 * 60

    runtime._extra_minutes_today = 15
    assert counter._get_quota_limit_sec(runtime.policy, monday) == 135 * 60


def test_3min_quota_expires_within_180_seconds(isolated_db: Path) -> None:
    runtime = _DummyRuntime({"quota_weekday_min": 3, "quota_weekend_min": 3})
    monday = datetime(2026, 4, 13, 14, 0)
    counter = ScreenTimeCounter(runtime, grace_period_sec=0)
    counter._safe_now = lambda: monday  # type: ignore[method-assign]

    assert counter.get_quota_remaining_sec() == 180

    # Tick 35 times (175s) -> still 5s left, not locked yet
    for _ in range(35):
        counter._tick(5, now=monday)
    assert counter.get_quota_remaining_sec() == 5
    assert runtime.locked_reasons == []

    # One more 5s tick (180s total) -> exhausted and locked
    counter._tick(5, now=monday)
    assert counter.get_quota_remaining_sec() == 0
    assert runtime.locked_reasons == ["quota_exceeded"]
