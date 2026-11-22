from datetime import datetime

from shared.schedule_utils import WEEKLY_SLOTS, get_current_slot_index, is_allowed_now


def test_get_current_slot_index_boundaries():
    # Monday 00:00 -> slot 0; Monday 00:30 -> slot 1
    assert get_current_slot_index(datetime(2026, 11, 23, 0, 0)) == 0
    assert get_current_slot_index(datetime(2026, 11, 23, 0, 29)) == 0
    assert get_current_slot_index(datetime(2026, 11, 23, 0, 30)) == 1
    # Sunday 23:59 -> slot 335
    assert get_current_slot_index(datetime(2026, 11, 29, 23, 59)) == 335


def test_is_allowed_now_maps_336_slots_correctly():
    assert WEEKLY_SLOTS == 336
    schedule = ["A"] * WEEKLY_SLOTS
    # Block Tuesday 14:00..14:29 -> weekday=1, slot 48 + 28 = 76
    tue_14_15 = datetime(2026, 11, 24, 14, 15)
    slot = get_current_slot_index(tue_14_15)
    assert slot == 76
    schedule[slot] = "B"
    sched_str = "".join(schedule)

    assert is_allowed_now(sched_str, tue_14_15) is False
    assert is_allowed_now(sched_str, datetime(2026, 11, 24, 14, 30)) is True
    assert is_allowed_now("", tue_14_15) is True
