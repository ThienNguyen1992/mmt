"""Tests for OGK-051 (ClockGuard anti-tamper & reboot resilience) and 32-bit idle wrap."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from agent.core import config as cfg
from agent.core import local_store
from agent.core.clock_guard import ClockGuard
from agent.core.idle_detector import compute_idle_seconds_32bit


@pytest.fixture()
def isolated_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(cfg, "DATA_DIR", str(tmp_path))
    local_store.init_schema()
    return tmp_path / "ogk_agent.db"


def test_clock_rollback_3_hours_same_boot_detected_and_safe_now_immune(isolated_db: Path) -> None:
    fake_wall = datetime(2026, 4, 13, 15, 0).timestamp()
    fake_uptime = 1000.0
    events: list[dict] = []

    guard = ClockGuard(
        wall_fn=lambda: fake_wall,
        uptime_fn=lambda: fake_uptime,
        on_tamper_event=events.append,
    )
    assert events == []

    # 10s normal elapsed -> no tamper
    fake_wall += 10.0
    fake_uptime += 10.0
    assert guard.check() is False
    assert guard.get_safe_now() == datetime.fromtimestamp(fake_wall)

    # Child winds Windows clock back 3 hours while uptime moves +5s
    tampered_wall = fake_wall - 3 * 3600 + 5.0
    expected_true_ts = fake_wall + 5.0
    fake_wall = tampered_wall
    fake_uptime += 5.0

    assert guard.check() is True
    assert len(events) == 1
    assert events[0]["kind"] == "same_boot_drift"
    # Safe now stays on real monotonic timeline (~15:00:15), ignoring -3h rollback!
    assert guard.get_safe_now().timestamp() == pytest.approx(expected_true_ts, abs=0.5)

    # Subsequent tick does not spam duplicate tamper events
    fake_wall += 5.0
    fake_uptime += 5.0
    assert guard.check() is False
    assert len(events) == 1


def test_normal_reboot_has_no_false_positive_and_cross_reboot_rollback_is_caught(
    isolated_db: Path,
) -> None:
    wall_1 = datetime(2026, 4, 13, 15, 0).timestamp()
    uptime_1 = 7200.0
    events: list[dict] = []

    # Run 1: persist anchors before shutdown
    ClockGuard(wall_fn=lambda: wall_1, uptime_fn=lambda: uptime_1, on_tamper_event=events.append)
    assert events == []

    # Run 2: Normal reboot 1 hour later -> uptime resets from 7200s to 20s, wall moves +3600s
    wall_2 = wall_1 + 3600.0
    uptime_2 = 20.0
    guard2 = ClockGuard(
        wall_fn=lambda: wall_2, uptime_fn=lambda: uptime_2, on_tamper_event=events.append
    )
    assert events == []
    assert guard2.get_safe_now().timestamp() == pytest.approx(wall_2, abs=0.5)

    # Run 3: Malicious reboot where BIOS/OS clock was rolled back 3 hours below persisted anchor
    wall_3 = wall_2 - 3 * 3600
    uptime_3 = 10.0
    guard3 = ClockGuard(
        wall_fn=lambda: wall_3, uptime_fn=lambda: uptime_3, on_tamper_event=events.append
    )
    assert len(events) == 1
    assert events[0]["kind"] == "cross_reboot_rollback"
    # Monotonic safe time never goes backward past persisted wall_2
    assert guard3.get_safe_now().timestamp() >= wall_2


def test_32bit_idle_wrap_around_around_day49_7() -> None:
    idle_sec = compute_idle_seconds_32bit(now_tick32=1000, last_input_tick32=0xFFFFFF80)
    # 0x100000000 - 0xFFFFFF80 = 128 ms; + 1000 ms = 1.128s
    assert idle_sec == pytest.approx(1.128, abs=0.001)
