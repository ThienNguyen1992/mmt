import threading
from datetime import datetime, timezone

from agent.core.local_store import get_state, get_state_int, init_schema, set_state
from agent.core.logger import get_logger

logger = get_logger("offline_tracker")

STATE_KEY_OFFLINE_SINCE = "offline_since_iso"
STATE_KEY_FAIL_COUNT = "offline_failure_count"


class OfflineTracker:
    """Theo dõi mất kết nối liên tiếp & thời điểm offline_since_iso trong ogk_agent.db."""

    def __init__(self, failure_threshold: int = 3):
        self.failure_threshold = failure_threshold
        self._lock = threading.Lock()
        init_schema()

    def record_failure(self, now: datetime | None = None) -> bool:
        current = now or datetime.now(timezone.utc)
        with self._lock:
            fails = get_state_int(STATE_KEY_FAIL_COUNT, 0) + 1
            set_state(STATE_KEY_FAIL_COUNT, str(fails))
            existing_since = self.get_offline_since_iso()
            if fails >= self.failure_threshold and not existing_since:
                set_state(STATE_KEY_OFFLINE_SINCE, current.isoformat())
                logger.warning(
                    "Agent chuyển sang OFFLINE MODE sau %s lần lỗi liên tiếp (%s)",
                    fails,
                    current.isoformat(),
                )
            return self.is_offline()

    def record_success(self) -> None:
        with self._lock:
            was_offline = self.is_offline()
            set_state(STATE_KEY_FAIL_COUNT, "0")
            set_state(STATE_KEY_OFFLINE_SINCE, "")
            if was_offline:
                logger.info("Kết nối Server khôi phục — thoát OFFLINE MODE")

    def get_offline_since_iso(self) -> str | None:
        raw = get_state(STATE_KEY_OFFLINE_SINCE)
        return raw if raw else None

    def is_offline(self) -> bool:
        return self.get_offline_since_iso() is not None

    def get_offline_duration_days(self, now: datetime | None = None) -> float:
        since_iso = self.get_offline_since_iso()
        if not since_iso:
            return 0.0
        since = datetime.fromisoformat(since_iso)
        if since.tzinfo is None:
            since = since.replace(tzinfo=timezone.utc)
        current = now or datetime.now(timezone.utc)
        return max(0.0, (current - since).total_seconds() / 86400.0)
