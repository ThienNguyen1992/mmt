"""Comprehensive E5 ScreenTimeCounter suite: per-group app budgets, schedule, grace."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from agent.core import config as cfg
from agent.core import event_queue, local_store, notifier
from agent.core.foreground_app import get_foreground_app_group
from agent.core.screen_time import TICK_INTERVAL_SEC, ScreenTimeCounter
from agent.core.session_lock_monitor import SessionLockMonitor


class _DummyRuntime:
    def __init__(self, policy: dict[str, Any]) -> None:
        self.policy = policy
        self._extra_minutes_today = 0
        self._user_idle_sec = 0.0
        self._user_fg_process: str | None = None
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


def test_foreground_app_maps_to_policy_group() -> None:
    policy = {
        "app_rules": {
            "mode": "blacklist",
            "rules": [
                {"match_type": "name", "value": "roblox.exe", "action": "allow", "group": "game"},
                {"match_type": "name", "value": "winword.exe", "action": "allow", "group": "study"},
            ],
            "group_quotas_min": {"game": 1, "study": 10},
        }
    }
    assert get_foreground_app_group(policy, override_process_name="Roblox.exe") == (
        "roblox.exe",
        "game",
    )
    assert get_foreground_app_group(policy, override_process_name="WINWORD.EXE") == (
        "winword.exe",
        "study",
    )
    assert get_foreground_app_group(policy, override_process_name="notepad.exe") == (
        "notepad.exe",
        "other",
    )


def test_study_and_game_have_independent_group_budgets(isolated_env: Path) -> None:
    day = datetime(2026, 4, 13, 15, 0)
    policy = {
        "quota_weekday_min": 60,
        "quota_weekend_min": 60,
        "app_rules": {
            "mode": "blacklist",
            "rules": [
                {"match_type": "name", "value": "roblox.exe", "action": "allow", "group": "game"},
                {"match_type": "name", "value": "winword.exe", "action": "allow", "group": "study"},
            ],
            "group_quotas_min": {"game": 1, "study": 5},
        },
    }
    runtime = _DummyRuntime(policy)
    counter = ScreenTimeCounter(runtime)
    counter.session_lock_monitor = SessionLockMonitor(hook_os=False)
    counter._safe_now = lambda: day  # type: ignore[method-assign]

    # Child plays game for 60s -> exhausts 'game' budget (1 min), emits group_quota_exhausted
    runtime._user_fg_process = "roblox.exe"
    for _ in range(12):
        counter._tick(TICK_INTERVAL_SEC, now=day)

    assert counter.get_group_remaining_sec("game") == 0
    assert counter.is_group_exhausted("game") is True
    assert counter.get_exhausted_groups() == {"game"}

    # Study budget was NEVER consumed & device stays unlocked!
    assert counter.get_group_remaining_sec("study") == 5 * 60
    assert counter.is_group_exhausted("study") is False
    assert runtime.is_locked() is False

    # Notifications & events recorded once for game exhaustion
    notifs = [
        n for n in notifier.pop_pending_notifications() if n["type"] == "group_quota_exhausted"
    ]
    assert [n["group"] for n in notifs] == ["game"]
    events = [e for e in event_queue.get_pending_batch(50) if e["type"] == "group_quota_exhausted"]
    assert [e["subject"] for e in events] == ["game"]

    # Child switches to Word (study) -> study ticks independently!
    runtime._user_fg_process = "winword.exe"
    counter._tick(TICK_INTERVAL_SEC, now=day)
    assert counter.get_group_remaining_sec("study") == 5 * 60 - TICK_INTERVAL_SEC

    # Midnight rollover clears both global & group usage
    next_day = datetime(2026, 4, 14, 0, 5)
    counter._safe_now = lambda: next_day  # type: ignore[method-assign]
    counter._tick(TICK_INTERVAL_SEC, now=next_day)
    assert counter.is_group_exhausted("game") is False
    assert counter.get_group_remaining_sec("game") == 60
