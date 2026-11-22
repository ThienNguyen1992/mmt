"""Tests for OGK-049: quota warning marks at 10, 5, and 1 minute remaining."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from agent.core import config as cfg
from agent.core import event_queue, local_store, notifier
from agent.core.screen_time import TICK_INTERVAL_SEC, ScreenTimeCounter


class _DummyRuntime:
    def __init__(self, policy: dict[str, Any]) -> None:
        self.policy = policy
        self._extra_minutes_today = 0
        self._user_idle_sec = 0.0
        self._user_session_locked = False
        self._lock_flag = False
        self._lock_reason = ""

    def get_effective_policy(self) -> dict[str, Any]:
        return self.policy

    def is_locked(self) -> bool:
        return self._lock_flag

    def lock_device(self, reason: str) -> None:
        self._lock_flag = True
        self._lock_reason = reason

    def unlock_device(self) -> None:
        self._lock_flag = False
        self._lock_reason = ""


@pytest.fixture()
def isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(cfg, "DATA_DIR", str(tmp_path))
    local_store.init_schema()
    notifier.pop_pending_notifications()
    return tmp_path / "ogk_agent.db"


def test_warnings_triggered_once_at_10_5_1_minutes(isolated_env: Path) -> None:
    day = datetime(2026, 4, 13, 15, 0)
    runtime = _DummyRuntime({"quota_weekday_min": 12, "quota_weekend_min": 12})
    counter = ScreenTimeCounter(runtime)
    counter._safe_now = lambda: day  # type: ignore[method-assign]

    # Run 11 minutes + 55 seconds (remaining goes from 12m -> 5s), 1 tick at a time
    for _ in range(143):
        counter._tick(TICK_INTERVAL_SEC, now=day)

    notifs = [n for n in notifier.pop_pending_notifications() if n["type"] == "quota_warning"]
    assert [n["minutes_left"] for n in notifs] == [10, 5, 1]

    events = [e for e in event_queue.get_pending_batch(50) if e["type"] == "quota_warning"]
    assert [e["subject"] for e in events] == ["10_min_left", "5_min_left", "1_min_left"]
