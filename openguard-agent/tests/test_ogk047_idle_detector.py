"""Tests for OGK-047: idle detection, 32-bit wrap-around, and Session 0 override."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from agent.core import config as cfg
from agent.core import local_store
from agent.core.idle_detector import IDLE_THRESHOLD_SEC, compute_idle_seconds_32bit
from agent.core.screen_time import TICK_INTERVAL_SEC, ScreenTimeCounter


class _DummyRuntime:
    def __init__(self, policy: dict[str, Any]) -> None:
        self.policy = policy
        self._extra_minutes_today = 0
        self._user_idle_sec: float | None = 0.0
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


def test_32bit_tick_wrap_around_is_non_negative() -> None:
    # Wrap from 0xFFFFFF00 (4294967040) to 5000 ms -> elapsed 256 + 5000 = 5256 ms
    elapsed = compute_idle_seconds_32bit(5000, 0xFFFFFF00)
    assert elapsed == pytest.approx(5.256, abs=0.001)


def test_idle_over_180s_pauses_quota_counting_via_ipc_telemetry(isolated_db: Path) -> None:
    day = datetime(2026, 4, 13, 15, 0)
    runtime = _DummyRuntime({"quota_weekday_min": 60})
    counter = ScreenTimeCounter(runtime)
    counter._safe_now = lambda: day  # type: ignore[method-assign]

    runtime._user_idle_sec = 10.0
    counter._tick(TICK_INTERVAL_SEC, now=day)
    assert counter._quota_used_sec == TICK_INTERVAL_SEC

    # Idle >= 180s -> pause quota deduction
    runtime._user_idle_sec = float(IDLE_THRESHOLD_SEC)
    for _ in range(5):
        counter._tick(TICK_INTERVAL_SEC, now=day)
    assert counter._quota_used_sec == TICK_INTERVAL_SEC

    # User moves mouse -> resumes counting
    runtime._user_idle_sec = 0.0
    counter._tick(TICK_INTERVAL_SEC, now=day)
    assert counter._quota_used_sec == 2 * TICK_INTERVAL_SEC
