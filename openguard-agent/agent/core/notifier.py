import json
from datetime import datetime, timezone

from agent.core.local_store import _write_lock, get_connection, init_schema
from agent.core.logger import get_logger

logger = get_logger("notifier")


def push_notification(notif_type: str, payload: dict) -> None:
    """Lưu thông báo minh bạch (NT1/NT4) vào hàng đợi notifications trong ogk_agent.db."""
    init_schema()
    with _write_lock, get_connection() as conn:
        conn.execute(
            "INSERT INTO notifications (notif_type, payload, created_at) VALUES (?, ?, ?)",
            (
                notif_type,
                json.dumps(payload, ensure_ascii=False),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()
    logger.info("Push notification '%s': %s", notif_type, payload)


def pop_pending_notifications() -> list[dict]:
    """Lấy và xóa các thông báo đang chờ để Tray UI hiển thị cho trẻ."""
    init_schema()
    with _write_lock, get_connection() as conn:
        rows = conn.execute(
            "SELECT id, notif_type, payload, created_at FROM notifications ORDER BY id ASC"
        ).fetchall()
        if rows:
            ids = [r["id"] for r in rows]
            placeholders = ",".join("?" for _ in ids)
            conn.execute(f"DELETE FROM notifications WHERE id IN ({placeholders})", ids)
            conn.commit()
    return [
        {"type": r["notif_type"], **json.loads(r["payload"]), "created_at": r["created_at"]}
        for r in rows
    ]
