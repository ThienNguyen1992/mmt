"""Tests for OGK-048: session lock (Win+L / WTS_SESSION_LOCK) pauses quota immediately."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from agent.core import config as cfg
from agent.core import local_store
from agent.core.screen_time import TICK_INTERVAL_SEC, ScreenTimeCounter
from agent.core.session_lock_monitor import (
    NOTIFY_FOR_ALL_SESSIONS,
    WTS_SESSION_LOCK,
    WTS_SESSION_UNLOCK,
    SessionLockMonitor,
)


class _DummyRuntime:
    def __init__(self, policy: dict[str, Any]) -> None:
        self.policy = policy
        self._extra_minutes_today = 0
        self._user_idle_sec: float | None = 0.0
        self._user_session_locked: bool | None = None
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
def isolated_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(cfg, "DATA_DIR", str(tmp_path))
    local_store.init_schema()
    return tmp_path / "ogk_agent.db"


def test_wts_session_lock_and_unlock_events_update_state() -> None:
    assert NOTIFY_FOR_ALL_SESSIONS == 1
    mon = SessionLockMonitor(hook_os=False)
    assert mon.is_locked() is False

    mon.handle_wts_event(WTS_SESSION_LOCK)
    assert mon.is_locked() is True

    mon.handle_wts_event(WTS_SESSION_UNLOCK)
    assert mon.is_locked() is False


def test_session_lock_pauses_screen_time_immediately(isolated_db: Path) -> None:
    day = datetime(2026, 4, 13, 15, 0)
    runtime = _DummyRuntime({"quota_weekday_min": 60})
    counter = ScreenTimeCounter(runtime)
    counter.session_lock_monitor = SessionLockMonitor(hook_os=False)
    counter._safe_now = lambda: day  # type: ignore[method-assign]

    # Active tick -> 5s burned
    counter._tick(TICK_INTERVAL_SEC, now=day)
    assert counter._quota_used_sec == TICK_INTERVAL_SEC

    # Simulate Win+L via WTS_SESSION_LOCK -> 0 additional seconds deducted
    counter.session_lock_monitor.handle_wts_event(WTS_SESSION_LOCK)
    for _ in range(10):
        counter._tick(TICK_INTERVAL_SEC, now=day)
    assert counter._quota_used_sec == TICK_INTERVAL_SEC

    # Unlock session -> resumes counting
    counter.session_lock_monitor.handle_wts_event(WTS_SESSION_UNLOCK)
    counter._tick(TICK_INTERVAL_SEC, now=day)
    assert counter._quota_used_sec == 2 * TICK_INTERVAL_SEC

    # IPC telemetry override _user_session_locked=True also pauses counting
    runtime._user_session_locked = True
    counter._tick(TICK_INTERVAL_SEC, now=day)
    assert counter._quota_used_sec == 2 * TICK_INTERVAL_SEC
