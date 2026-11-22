import uuid
from datetime import datetime, timezone

from agent.core.config import load_config
from agent.core.local_store import _write_lock, get_connection, init_schema
from agent.core.logger import get_logger

logger = get_logger("event_queue")


def enqueue_event(
    event_type: str,
    subject: str | None = None,
    duration_sec: int = 0,
    policy_id: str | None = None,
    ts: str | None = None,
    device_id: str | None = None,
    child_id: str | None = None,
    idempotency_key: str | None = None,
) -> str:
    """Đưa sự kiện vào hàng đợi pending_events trong ogk_agent.db kèm idempotency_key UUIDv4."""
    init_schema()
    cfg = load_config()
    dev_id = device_id or cfg.get("device_id") or ""
    ch_id = child_id or cfg.get("child_id") or ""
    key = idempotency_key or str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()
    ts_iso = ts or now_iso

    with _write_lock, get_connection() as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO pending_events (
                idempotency_key, ts, device_id, child_id, type,
                subject, duration_sec, policy_id, synced, retry_count, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?)
            """,
            (
                key,
                ts_iso,
                dev_id,
                ch_id,
                event_type,
                subject,
                max(0, int(duration_sec)),
                policy_id,
                now_iso,
            ),
        )
        conn.commit()
    return key


def get_pending_batch(limit: int = 50, max_retries: int = 10) -> list[dict]:
    """Lấy lô tối đa `limit` sự kiện chưa đồng bộ và chưa vượt quá max_retries."""
    init_schema()
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT idempotency_key, ts, device_id, child_id, type, subject, duration_sec, policy_id
            FROM pending_events
            WHERE synced = 0 AND retry_count < ?
            ORDER BY created_at ASC, rowid ASC
            LIMIT ?
            """,
            (max_retries, limit),
        ).fetchall()
    return [
        {
            "idempotency_key": r["idempotency_key"],
            "ts": r["ts"],
            "device_id": r["device_id"],
            "child_id": r["child_id"],
            "type": r["type"],
            "subject": r["subject"],
            "duration_sec": r["duration_sec"],
            "policy_id": r["policy_id"],
        }
        for r in rows
    ]


def mark_synced(idempotency_keys: list[str]) -> int:
    if not idempotency_keys:
        return 0
    init_schema()
    placeholders = ",".join("?" for _ in idempotency_keys)
    with _write_lock, get_connection() as conn:
        cur = conn.execute(
            f"UPDATE pending_events SET synced = 1 WHERE idempotency_key IN ({placeholders})",
            idempotency_keys,
        )
        conn.commit()
        return cur.rowcount


def increment_retry(idempotency_keys: list[str]) -> int:
    if not idempotency_keys:
        return 0
    init_schema()
    placeholders = ",".join("?" for _ in idempotency_keys)
    with _write_lock, get_connection() as conn:
        cur = conn.execute(
            "UPDATE pending_events SET retry_count = retry_count + 1 "
            f"WHERE idempotency_key IN ({placeholders})",
            idempotency_keys,
        )
        conn.commit()
        return cur.rowcount


def count_pending(max_retries: int = 10) -> int:
    init_schema()
    with get_connection() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM pending_events WHERE synced = 0 AND retry_count < ?",
            (max_retries,),
        ).fetchone()
    return int(row["cnt"]) if row else 0
