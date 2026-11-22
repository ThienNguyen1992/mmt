"""Screen-time & quota counter for OpenGuard Kids agent."""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime
from typing import Any

from shared.schedule_utils import is_allowed_now

from agent.core.config import load_config
from agent.core.event_queue import enqueue_event
from agent.core.local_store import get_state, init_schema, set_state

TICK_INTERVAL_SEC = 5


class ScreenTimeCounter:
    """Tracks daily screen time against weekday/weekend quotas and weekly schedule."""

    def __init__(self, runtime: Any) -> None:
        self.runtime = runtime
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.RLock()

        init_schema()
        self._current_date = self._safe_today_str()
        self._quota_used_sec: int = 0
        self._quota_used_sec_by_group: dict[str, int] = {}
        self._schedule_locked: bool = False
        self._locked_emitted_reason: str | None = None
        self._sent_warnings: set[int] = set()
        self._load_today_usage()

    def _safe_now(self) -> datetime:
        return datetime.now()

    def _safe_today_str(self) -> str:
        return self._safe_now().strftime("%Y-%m-%d")

    def _get_effective_content(self) -> dict[str, Any]:
        raw = self.runtime.get_effective_policy() or {}
        if isinstance(raw.get("policy"), dict):
            return raw["policy"]
        return raw

    def _get_quota_limit_sec(self, content: dict[str, Any], now: datetime) -> int:
        is_weekend = now.weekday() >= 5
        base_min = int(
            content.get("quota_weekend_min", 180)
            if is_weekend
            else content.get("quota_weekday_min", 120)
        )
        extra_min = max(0, int(getattr(self.runtime, "_extra_minutes_today", 0) or 0))
        return max(0, (base_min + extra_min) * 60)

    def get_quota_remaining_sec(self) -> int:
        with self._lock:
            now = self._safe_now()
            content = self._get_effective_content()
            limit = self._get_quota_limit_sec(content, now)
            return max(0, limit - self._quota_used_sec)

    def _load_today_usage(self) -> None:
        saved_date = get_state("usage_date", "")
        if saved_date == self._current_date:
            self._quota_used_sec = int(get_state("quota_used_sec", "0") or 0)
            raw_groups = get_state("quota_used_sec_by_group", "{}") or "{}"
            try:
                parsed = json.loads(raw_groups)
                if isinstance(parsed, dict):
                    self._quota_used_sec_by_group = {str(k): int(v) for k, v in parsed.items()}
                else:
                    self._quota_used_sec_by_group = {}
            except (ValueError, TypeError):
                self._quota_used_sec_by_group = {}
        else:
            self._quota_used_sec = 0
            self._quota_used_sec_by_group = {}
            self._save_today_usage()

    def _save_today_usage(self) -> None:
        set_state("usage_date", self._current_date)
        set_state("quota_used_sec", str(self._quota_used_sec))
        set_state("quota_used_sec_by_group", json.dumps(self._quota_used_sec_by_group))

    def reset_counters(self) -> None:
        with self._lock:
            self._current_date = self._safe_today_str()
            self._quota_used_sec = 0
            self._quota_used_sec_by_group = {}
            self._sent_warnings.clear()
            self._locked_emitted_reason = None
            self._schedule_locked = False
            self._save_today_usage()

    def _rollover_if_new_day(self, today_str: str) -> None:
        if today_str == self._current_date:
            return
        self._current_date = today_str
        self._quota_used_sec = 0
        self._quota_used_sec_by_group = {}
        self._sent_warnings.clear()
        self._locked_emitted_reason = None
        if hasattr(self.runtime, "_extra_minutes_today"):
            self.runtime._extra_minutes_today = 0
        if getattr(self.runtime, "_lock_reason", "") == "quota_exceeded" and hasattr(
            self.runtime, "unlock_device"
        ):
            self.runtime.unlock_device()
        self._save_today_usage()

    def _emit_lock(self, reason: str, policy_id: str | None = None) -> None:
        if self._locked_emitted_reason == reason:
            return
        self.runtime.lock_device(reason)
        self._locked_emitted_reason = reason
        cfg = load_config()
        enqueue_event(
            event_type="locked",
            subject=reason,
            policy_id=policy_id,
            device_id=cfg.get("device_id") or None,
            child_id=cfg.get("child_id") or None,
        )

    def _tick(self, elapsed_sec: int = TICK_INTERVAL_SEC, now: datetime | None = None) -> None:
        with self._lock:
            current_now = now or self._safe_now()
            self._rollover_if_new_day(current_now.strftime("%Y-%m-%d"))

            is_locked_fn = getattr(self.runtime, "is_locked", None)
            if callable(is_locked_fn) and not is_locked_fn():
                self._locked_emitted_reason = None

            content = self._get_effective_content()
            policy_id = str(content.get("policy_id")) if content.get("policy_id") else None

            weekly_schedule = content.get("weekly_schedule") or ("A" * 336)
            if not is_allowed_now(weekly_schedule, current_now):
                self._schedule_locked = True
                self._emit_lock("outside_weekly_schedule", policy_id=policy_id)
                return

            if self._schedule_locked:
                self._schedule_locked = False
                if getattr(self.runtime, "_lock_reason", "") == "outside_weekly_schedule":
                    self.runtime.unlock_device()
                    self._locked_emitted_reason = None

            if callable(is_locked_fn) and is_locked_fn():
                return

            self._quota_used_sec += max(0, int(elapsed_sec))
            limit_sec = self._get_quota_limit_sec(content, current_now)
            self._save_today_usage()
            if self._quota_used_sec >= limit_sec:
                self._emit_lock("quota_exceeded", policy_id=policy_id)

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, name="screen-time", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def _run_loop(self) -> None:
        while not self._stop_event.wait(TICK_INTERVAL_SEC):
            try:
                self._tick(TICK_INTERVAL_SEC)
            except Exception:
                time.sleep(0.1)
