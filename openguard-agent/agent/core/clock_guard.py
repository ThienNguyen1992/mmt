"""Anti-tamper ClockGuard: detects same-boot clock rollback and cross-reboot tampering."""

from __future__ import annotations

import ctypes
import sys
import time
from datetime import datetime
from typing import Any, Callable

from agent.core.local_store import get_state, init_schema, set_state

CLOCK_DRIFT_THRESHOLD_SEC = 120


def get_system_uptime_sec() -> float:
    """Return OS uptime in seconds (64-bit monotonic tick on Windows)."""
    if sys.platform == "win32":
        try:
            ms = ctypes.windll.kernel32.GetTickCount64()
            return float(ms) / 1000.0
        except Exception:
            pass
    return time.monotonic()


class ClockGuard:
    """Guards screen-time and schedule checks against manual system clock tampering."""

    def __init__(
        self,
        drift_threshold_sec: float = CLOCK_DRIFT_THRESHOLD_SEC,
        wall_fn: Callable[[], float] | None = None,
        uptime_fn: Callable[[], float] | None = None,
        on_tamper_event: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        init_schema()
        self.drift_threshold_sec = float(drift_threshold_sec)
        self._wall_fn = wall_fn or time.time
        self._uptime_fn = uptime_fn or get_system_uptime_sec
        self._on_tamper_event = on_tamper_event

        now_wall = float(self._wall_fn())
        now_uptime = float(self._uptime_fn())

        self._anchor_wall = now_wall
        self._anchor_uptime = now_uptime
        self._safe_anchor_wall = now_wall
        self._safe_anchor_uptime = now_uptime
        self.tamper_count = 0

        self._check_startup_against_persisted(now_wall, now_uptime)
        self._persist_anchors(self.get_safe_timestamp(), now_uptime)

    def _emit_tamper(self, kind: str, drift_sec: float, now_wall: float, expected: float) -> None:
        self.tamper_count += 1
        if self._on_tamper_event:
            self._on_tamper_event(
                {
                    "kind": kind,
                    "drift_sec": drift_sec,
                    "observed_wall": now_wall,
                    "expected_wall": expected,
                }
            )

    def _check_startup_against_persisted(self, now_wall: float, now_uptime: float) -> None:
        prev_wall_raw = get_state("clock_last_wall_utc")
        prev_uptime_raw = get_state("clock_last_uptime_sec")
        if prev_wall_raw is None or prev_uptime_raw is None:
            return
        try:
            prev_wall = float(prev_wall_raw)
            prev_uptime = float(prev_uptime_raw)
        except (ValueError, TypeError):
            return

        rebooted = now_uptime < prev_uptime
        if rebooted:
            # Across a reboot, wall time can advance arbitrarily; backward jumps > threshold tamper.
            if now_wall < prev_wall - self.drift_threshold_sec:
                drift = now_wall - prev_wall
                self._safe_anchor_wall = prev_wall
                self._safe_anchor_uptime = now_uptime
                self._emit_tamper("cross_reboot_rollback", drift, now_wall, prev_wall)
            return

        # Same boot: wall clock elapsed must stay consistent with uptime elapsed
        expected_wall = prev_wall + (now_uptime - prev_uptime)
        drift = now_wall - expected_wall
        if abs(drift) > self.drift_threshold_sec:
            self._safe_anchor_wall = expected_wall
            self._safe_anchor_uptime = now_uptime
            self._emit_tamper("same_boot_drift", drift, now_wall, expected_wall)

    def _persist_anchors(self, wall_ts: float, uptime_sec: float) -> None:
        set_state("clock_last_wall_utc", f"{wall_ts:.3f}")
        set_state("clock_last_uptime_sec", f"{uptime_sec:.3f}")

    def check(self) -> bool:
        """Check whether wall clock drifted abnormally since the last check."""
        now_wall = float(self._wall_fn())
        now_uptime = float(self._uptime_fn())
        expected_wall = self._anchor_wall + (now_uptime - self._anchor_uptime)
        drift = now_wall - expected_wall

        tampered = False
        if abs(drift) > self.drift_threshold_sec:
            safe_now_ts = self.get_safe_timestamp(now_uptime=now_uptime)
            # Only flag if the jump doesn't simply restore real monotonic time (e.g. NTP recovery)
            if abs(now_wall - safe_now_ts) > self.drift_threshold_sec:
                tampered = True
                self._emit_tamper("same_boot_drift", drift, now_wall, safe_now_ts)
            self._anchor_wall = now_wall
            self._anchor_uptime = now_uptime

        self._persist_anchors(self.get_safe_timestamp(now_uptime=now_uptime), now_uptime)
        return tampered

    def get_safe_timestamp(self, now_uptime: float | None = None) -> float:
        uptime = float(self._uptime_fn()) if now_uptime is None else float(now_uptime)
        return self._safe_anchor_wall + max(0.0, uptime - self._safe_anchor_uptime)

    def get_safe_now(self) -> datetime:
        return datetime.fromtimestamp(self.get_safe_timestamp())
