"""Screen-time & quota counter for OpenGuard Kids agent."""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime
from typing import Any, Callable

from shared.schedule_utils import is_allowed_now

from agent.core.clock_guard import ClockGuard
from agent.core.config import load_config
from agent.core.event_queue import enqueue_event
from agent.core.foreground_app import get_foreground_app_group
from agent.core.idle_detector import IdleDetector
from agent.core.local_store import get_state, init_schema, set_state
from agent.core.notifier import push_notification
from agent.core.session_lock_monitor import SessionLockMonitor

TICK_INTERVAL_SEC = 5
WARNING_MARKS_MIN = [10, 5, 1]
GRACE_PERIOD_SEC = 60


class ScreenTimeCounter:
    """Tracks daily screen time against weekday/weekend quotas and weekly schedule."""

    def __init__(
        self,
        runtime: Any,
        grace_period_sec: int = GRACE_PERIOD_SEC,
        on_grace_start: Callable[[int], None] | None = None,
    ) -> None:
        self.runtime = runtime
        self.grace_period_sec = max(0, int(grace_period_sec))
        self.on_grace_start = on_grace_start
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.RLock()

        init_schema()
        self.clock_guard = ClockGuard(on_tamper_event=self._on_clock_tamper)
        self.idle_detector = IdleDetector()
        self.session_lock_monitor = SessionLockMonitor()
        self._current_date = self._safe_today_str()
        self._quota_used_sec: int = 0
        self._quota_used_sec_by_group: dict[str, int] = {}
        self._schedule_locked: bool = False
        self._locked_emitted_reason: str | None = None
        self._sent_warnings: set[int] = set()
        self._in_grace: bool = False
        self._grace_elapsed_sec: int = 0
        self._exhausted_groups_notified: set[str] = set()
        self._load_today_usage()

    def _on_clock_tamper(self, info: dict[str, Any]) -> None:
        cfg = load_config()
        drift_sec = int(info.get("drift_sec", 0))
        push_notification(
            "clock_tamper",
            {"drift_sec": drift_sec, "message": "Phát hiện thay đổi giờ hệ thống bất thường!"},
        )
        enqueue_event(
            event_type="clock_tamper_detected",
            subject=f"{info.get('kind', 'drift')}:{drift_sec}s",
            device_id=cfg.get("device_id") or None,
            child_id=cfg.get("child_id") or None,
        )

    def _safe_now(self) -> datetime:
        return self.clock_guard.get_safe_now()

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

    def get_group_remaining_sec(self, group: str) -> int | None:
        """Return remaining seconds for an app group, or None if uncapped."""
        with self._lock:
            content = self._get_effective_content()
            group_quotas = (content.get("app_rules") or {}).get("group_quotas_min") or {}
            if group not in group_quotas:
                return None
            limit_sec = max(0, int(group_quotas[group]) * 60)
            used_sec = self._quota_used_sec_by_group.get(group, 0)
            return max(0, limit_sec - used_sec)

    def is_group_exhausted(self, group: str) -> bool:
        rem = self.get_group_remaining_sec(group)
        return rem is not None and rem <= 0

    def get_exhausted_groups(self) -> set[str]:
        with self._lock:
            content = self._get_effective_content()
            group_quotas = (content.get("app_rules") or {}).get("group_quotas_min") or {}
            exhausted: set[str] = set()
            for grp, mins in group_quotas.items():
                limit_sec = max(0, int(mins) * 60)
                if self._quota_used_sec_by_group.get(grp, 0) >= limit_sec:
                    exhausted.add(str(grp))
            return exhausted

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
            self._in_grace = False
            self._grace_elapsed_sec = 0
            self._exhausted_groups_notified.clear()
            self._save_today_usage()

    def _rollover_if_new_day(self, today_str: str) -> None:
        if today_str == self._current_date:
            return
        self._current_date = today_str
        self._quota_used_sec = 0
        self._quota_used_sec_by_group = {}
        self._sent_warnings.clear()
        self._locked_emitted_reason = None
        self._in_grace = False
        self._grace_elapsed_sec = 0
        self._exhausted_groups_notified.clear()
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

    def _check_warnings_and_lock(
        self,
        remaining_sec: int,
        limit_sec: int,
        elapsed_sec: int = TICK_INTERVAL_SEC,
        policy_id: str | None = None,
    ) -> None:
        cfg = load_config()
        for mark_min in WARNING_MARKS_MIN:
            threshold_sec = mark_min * 60
            if remaining_sec > threshold_sec:
                self._sent_warnings.discard(mark_min)
                continue
            if (
                0 < remaining_sec <= threshold_sec
                and limit_sec >= threshold_sec
                and mark_min not in self._sent_warnings
            ):
                self._sent_warnings.add(mark_min)
                push_notification(
                    "quota_warning",
                    {
                        "minutes_left": mark_min,
                        "message": f"Còn {mark_min} phút sử dụng máy hôm nay!",
                    },
                )
                enqueue_event(
                    event_type="quota_warning",
                    subject=f"{mark_min}_min_left",
                    policy_id=policy_id,
                    device_id=cfg.get("device_id") or None,
                    child_id=cfg.get("child_id") or None,
                )

        if remaining_sec > 0:
            self._in_grace = False
            self._grace_elapsed_sec = 0
            return

        if self.grace_period_sec <= 0:
            self._emit_lock("quota_exceeded", policy_id=policy_id)
            return

        if not self._in_grace:
            self._in_grace = True
            self._grace_elapsed_sec = 0
            push_notification(
                "grace_period",
                {
                    "seconds": self.grace_period_sec,
                    "message": (
                        f"Hết giờ! Máy sẽ khóa sau {self.grace_period_sec} giây, "
                        "hãy lưu bài làm."
                    ),
                },
            )
            if self.on_grace_start:
                self.on_grace_start(self.grace_period_sec)
            return

        self._grace_elapsed_sec += max(0, int(elapsed_sec))
        if self._grace_elapsed_sec >= self.grace_period_sec:
            self._emit_lock("quota_exceeded", policy_id=policy_id)

    def _tick(self, elapsed_sec: int = TICK_INTERVAL_SEC, now: datetime | None = None) -> None:
        with self._lock:
            self.clock_guard.check()
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

            override_session = getattr(self.runtime, "_user_session_locked", None)
            if self.session_lock_monitor.is_locked(override_session):
                return

            override_idle = getattr(self.runtime, "_user_idle_sec", None)
            if self.idle_detector.is_idle(override_idle_sec=override_idle):
                return

            inc = max(0, int(elapsed_sec))
            self._quota_used_sec += inc

            override_fg = getattr(self.runtime, "_user_fg_process", None)
            _, fg_group = get_foreground_app_group(content, override_process_name=override_fg)
            if fg_group:
                self._quota_used_sec_by_group[fg_group] = (
                    self._quota_used_sec_by_group.get(fg_group, 0) + inc
                )
                self._check_group_quota(content, fg_group, policy_id=policy_id)

            limit_sec = self._get_quota_limit_sec(content, current_now)
            self._save_today_usage()
            remaining_sec = max(0, limit_sec - self._quota_used_sec)
            self._check_warnings_and_lock(
                remaining_sec, limit_sec, elapsed_sec=elapsed_sec, policy_id=policy_id
            )

    def _check_group_quota(
        self, content: dict[str, Any], group: str, policy_id: str | None = None
    ) -> None:
        group_quotas = (content.get("app_rules") or {}).get("group_quotas_min") or {}
        if group not in group_quotas:
            return
        limit_sec = max(0, int(group_quotas[group]) * 60)
        used_sec = self._quota_used_sec_by_group.get(group, 0)
        if used_sec >= limit_sec and group not in self._exhausted_groups_notified:
            self._exhausted_groups_notified.add(group)
            cfg = load_config()
            push_notification(
                "group_quota_exhausted",
                {
                    "group": group,
                    "message": f"Nhóm ứng dụng '{group}' đã hết ngân sách hôm nay!",
                },
            )
            enqueue_event(
                event_type="group_quota_exhausted",
                subject=group,
                policy_id=policy_id,
                device_id=cfg.get("device_id") or None,
                child_id=cfg.get("child_id") or None,
            )

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self.session_lock_monitor.start()
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, name="screen-time", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        self.session_lock_monitor.stop()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def _run_loop(self) -> None:
        while not self._stop_event.wait(TICK_INTERVAL_SEC):
            try:
                self._tick(TICK_INTERVAL_SEC)
            except Exception:
                time.sleep(0.1)
