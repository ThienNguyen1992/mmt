from datetime import datetime

WEEKLY_SLOTS = 7 * 48  # 336 slot 30 phút trong 1 tuần


def get_current_slot_index(now: datetime | None = None) -> int:
    """Tính chỉ số slot 30 phút (0..335) theo thứ (0=Mon..6=Sun) và giờ phút."""
    current = now or datetime.now()
    minutes_since_midnight = current.hour * 60 + current.minute
    return current.weekday() * 48 + (minutes_since_midnight // 30)


def is_allowed_now(weekly_schedule: str, now: datetime | None = None) -> bool:
    """Kiểm tra slot hiện tại có được phép ('A') hay bị khóa ('B')."""
    if not weekly_schedule or len(weekly_schedule) != WEEKLY_SLOTS:
        return True
    return weekly_schedule[get_current_slot_index(now)] == "A"
