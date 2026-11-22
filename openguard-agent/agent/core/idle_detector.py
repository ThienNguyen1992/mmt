"""Windows user idle detection with 32-bit tick wrap-around & Session 0 support."""

from __future__ import annotations

import ctypes
import sys

IDLE_THRESHOLD_SEC = 180


class _LastInputInfo(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_uint),
        ("dwTime", ctypes.c_uint),
    ]


def compute_idle_seconds_32bit(now_tick32: int, last_input_tick32: int) -> float:
    """Compute idle duration handling 32-bit GetTickCount wrap-around every ~49.7 days."""
    diff_ms = (int(now_tick32) - int(last_input_tick32)) & 0xFFFFFFFF
    return diff_ms / 1000.0


def get_os_idle_seconds() -> float:
    """Return idle seconds via Win32 GetLastInputInfo; safely returns 0.0 in Session 0."""
    if sys.platform != "win32":
        return 0.0
    try:
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        lii = _LastInputInfo()
        lii.cbSize = ctypes.sizeof(_LastInputInfo)
        if not user32.GetLastInputInfo(ctypes.byref(lii)):
            return 0.0
        now_tick = int(kernel32.GetTickCount()) & 0xFFFFFFFF
        return compute_idle_seconds_32bit(now_tick, int(lii.dwTime))
    except Exception:
        return 0.0


class IdleDetector:
    """Detects user inactivity using IPC telemetry override first, then Win32 API."""

    def __init__(self, threshold_sec: int = IDLE_THRESHOLD_SEC) -> None:
        self.threshold_sec = int(threshold_sec)

    def get_idle_seconds(self, override_idle_sec: float | None = None) -> float:
        if override_idle_sec is not None:
            return max(0.0, float(override_idle_sec))
        return get_os_idle_seconds()

    def is_idle(self, override_idle_sec: float | None = None) -> bool:
        return self.get_idle_seconds(override_idle_sec) >= self.threshold_sec
