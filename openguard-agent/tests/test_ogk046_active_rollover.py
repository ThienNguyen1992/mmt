"""Tests for OGK-046: active usage increment, midnight rollover, and deduped locked events."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from shared.schedule_utils import get_current_slot_index

from agent.core import config as cfg
from agent.core import event_queue, local_store
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

    def is_locked(self) -> bool:
        return self._lock_flag

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


def test_duplicate_locked_event_suppressed_within_same_reason(isolated_db: Path) -> None:
    day1 = datetime(2026, 4, 13, 12, 0)
    runtime = _DummyRuntime({"quota_weekday_min": 1, "quota_weekend_min": 1})
    counter = ScreenTimeCounter(runtime)
    counter._safe_now = lambda: day1  # type: ignore[method-assign]

    # Burn full 60s quota -> triggers locked
    for _ in range(12):
        counter._tick(TICK_INTERVAL_SEC, now=day1)

    # Simulate additional tick while schedule flips to blocked; schedule lock runs, then flips back
    # First verify repeated quota lock or schedule lock doesn't emit duplicate locked events
    idx = get_current_slot_index(day1)
    blocked = ["A"] * 336
    blocked[idx] = "B"
    runtime.policy["weekly_schedule"] = "".join(blocked)
    counter._tick(TICK_INTERVAL_SEC, now=day1)
    counter._tick(TICK_INTERVAL_SEC, now=day1)

    events = event_queue.get_pending_batch(50)
    locked_subjects = [e["subject"] for e in events if e["type"] == "locked"]
    assert locked_subjects == ["quota_exceeded", "outside_weekly_schedule"]


def test_midnight_rollover_resets_counters_and_unlocks_quota_lock(isolated_db: Path) -> None:
    day1 = datetime(2026, 4, 13, 23, 59)
    day2 = datetime(2026, 4, 14, 0, 1)

    runtime = _DummyRuntime({"quota_weekday_min": 1, "quota_weekend_min": 1})
    counter = ScreenTimeCounter(runtime)
    counter._safe_now = lambda: day1  # type: ignore[method-assign]

    for _ in range(12):
        counter._tick(TICK_INTERVAL_SEC, now=day1)
    assert counter._quota_used_sec == 60
    assert runtime.is_locked() is True

    # Cross midnight
    counter._safe_now = lambda: day2  # type: ignore[method-assign]
    counter._tick(TICK_INTERVAL_SEC, now=day2)

    assert counter._current_date == "2026-04-14"
    assert runtime.unlock_calls == 1
    assert counter._quota_used_sec == TICK_INTERVAL_SEC
    assert counter.get_quota_remaining_sec() == 60 - TICK_INTERVAL_SEC
