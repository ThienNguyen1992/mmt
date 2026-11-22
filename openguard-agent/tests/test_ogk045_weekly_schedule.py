"""Tests for OGK-045: weekly schedule 336-slot enforcement."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from shared.schedule_utils import get_current_slot_index

from agent.core import config as cfg
from agent.core import local_store
from agent.core.screen_time import TICK_INTERVAL_SEC, ScreenTimeCounter


class _DummyRuntime:
    def __init__(self, policy: dict[str, Any]) -> None:
        self.policy = policy
        self._extra_minutes_today = 0
        self._lock_flag = False
        self._lock_reason = ""
        self.lock_calls: list[str] = []
        self.unlock_calls = 0

    def get_effective_policy(self) -> dict[str, Any]:
        return self.policy

    def lock_device(self, reason: str) -> None:
        self._lock_flag = True
        self._lock_reason = reason
        self.lock_calls.append(reason)

    def unlock_device(self) -> None:
        self._lock_flag = False
        self._lock_reason = ""
        self.unlock_calls += 1


@pytest.fixture()
def isolated_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(cfg, "DATA_DIR", str(tmp_path))
    local_store.init_schema()
    return tmp_path / "ogk_agent.db"


def test_blocked_slot_locks_within_one_tick_and_does_not_burn_quota(isolated_db: Path) -> None:
    monday_evening = datetime(2026, 4, 13, 21, 0)  # blocked slot
    slot_idx = get_current_slot_index(monday_evening)
    slots = ["A"] * 336
    slots[slot_idx] = "B"

    runtime = _DummyRuntime({"weekly_schedule": "".join(slots), "quota_weekday_min": 60})
    counter = ScreenTimeCounter(runtime)

    assert TICK_INTERVAL_SEC <= 5
    counter._tick(TICK_INTERVAL_SEC, now=monday_evening)

    assert runtime._lock_flag is True
    assert runtime._lock_reason == "outside_weekly_schedule"
    assert runtime.lock_calls == ["outside_weekly_schedule"]
    assert counter._quota_used_sec == 0

    # Subsequent ticks in same blocked slot do not spam duplicate lock calls
    counter._tick(TICK_INTERVAL_SEC, now=monday_evening)
    assert runtime.lock_calls == ["outside_weekly_schedule"]

    # Transitioning back to an allowed slot unlocks automatically
    monday_morning = datetime(2026, 4, 13, 10, 0)
    counter._tick(TICK_INTERVAL_SEC, now=monday_morning)
    assert runtime._lock_flag is False
    assert runtime.unlock_calls == 1
    assert counter._quota_used_sec == TICK_INTERVAL_SEC
