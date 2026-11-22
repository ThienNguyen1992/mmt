"""Tests for OGK-050: 60-second grace period countdown before quota lock."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from agent.core import config as cfg
from agent.core import local_store, notifier
from agent.core.screen_time import GRACE_PERIOD_SEC, TICK_INTERVAL_SEC, ScreenTimeCounter


class _DummyRuntime:
    def __init__(self, policy: dict[str, Any]) -> None:
        self.policy = policy
        self._extra_minutes_today = 0
        self._user_idle_sec = 0.0
        self._user_session_locked = False
        self._lock_flag = False
        self._lock_reason = ""
        self.lock_calls: list[str] = []

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


@pytest.fixture()
def isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(cfg, "DATA_DIR", str(tmp_path))
    local_store.init_schema()
    notifier.pop_pending_notifications()
    return tmp_path / "ogk_agent.db"


def test_grace_period_60s_delays_lock_and_notifies_child(isolated_env: Path) -> None:
    assert GRACE_PERIOD_SEC == 60
    day = datetime(2026, 4, 13, 15, 0)
    runtime = _DummyRuntime({"quota_weekday_min": 1, "quota_weekend_min": 1})
    grace_callbacks: list[int] = []
    counter = ScreenTimeCounter(runtime, on_grace_start=grace_callbacks.append)
    counter._safe_now = lambda: day  # type: ignore[method-assign]

    # Exhaust 60s quota -> triggers grace period instead of immediate lock
    for _ in range(12):
        counter._tick(TICK_INTERVAL_SEC, now=day)

    assert runtime.is_locked() is False
    assert counter._in_grace is True
    assert grace_callbacks == [60]
    grace_notifs = [n for n in notifier.pop_pending_notifications() if n["type"] == "grace_period"]
    assert len(grace_notifs) == 1
    assert grace_notifs[0]["seconds"] == 60

    # Tick 55s inside grace -> still unlocked
    for _ in range(11):
        counter._tick(TICK_INTERVAL_SEC, now=day)
    assert runtime.is_locked() is False

    # Tick remaining 5s (60s total grace elapsed) -> device locks!
    counter._tick(TICK_INTERVAL_SEC, now=day)
    assert runtime.is_locked() is True
    assert runtime._lock_reason == "quota_exceeded"
