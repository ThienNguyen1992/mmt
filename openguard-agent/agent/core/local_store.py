import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone

from agent.core.config import ensure_app_data_dir
from agent.core.logger import get_logger

logger = get_logger("local_store")
_write_lock = threading.Lock()


def get_db_path() -> str:
    # Đọc động từ config để pytest monkeypatch DATA_DIR hoạt động sạch sẽ
    from agent.core import config as cfg

    return os.path.join(cfg.DATA_DIR, "ogk_agent.db")


@contextmanager
def get_connection():
    ensure_app_data_dir()
    conn = sqlite3.connect(get_db_path(), timeout=15, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    try:
        yield conn
    finally:
        conn.close()


def init_schema() -> None:
    with _write_lock, get_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS policy_cache (
                device_id     TEXT PRIMARY KEY,
                policy_id     TEXT NOT NULL DEFAULT '0',
                version       INTEGER NOT NULL,
                content_json  TEXT NOT NULL,
                signature     TEXT NOT NULL,
                cached_at     TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pending_events (
                idempotency_key TEXT PRIMARY KEY,
                ts              TEXT NOT NULL,
                device_id       TEXT NOT NULL,
                child_id        TEXT NOT NULL,
                type            TEXT NOT NULL,
                subject         TEXT,
                duration_sec    INTEGER DEFAULT 0,
                policy_id       TEXT,
                synced          INTEGER DEFAULT 0,
                retry_count     INTEGER DEFAULT 0,
                created_at      TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_pending_unsynced
                ON pending_events(synced, created_at);

            CREATE TABLE IF NOT EXISTS agent_state (
                key        TEXT PRIMARY KEY,
                value      TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS notifications (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                notif_type TEXT NOT NULL,
                payload    TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """)
        conn.commit()


def set_state(key: str, value: str) -> None:
    with _write_lock, get_connection() as conn:
        conn.execute(
            """
            INSERT INTO agent_state (key, value, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
            """,
            (key, str(value), datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()


def get_state(key: str, default: str | None = None) -> str | None:
    with get_connection() as conn:
        row = conn.execute("SELECT value FROM agent_state WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def get_state_int(key: str, default: int = 0) -> int:
    raw = get_state(key)
    try:
        return int(raw) if raw is not None else default
    except ValueError:
        return default


def purge_synced_events(older_than_days: int = 7) -> int:
    with _write_lock, get_connection() as conn:
        cur = conn.execute(
            "DELETE FROM pending_events WHERE synced=1 AND created_at < datetime('now', ?)",
            (f"-{older_than_days} days",),
        )
        conn.commit()
        return cur.rowcount


def clear_all_local_data() -> None:
    """F3: Thực thi khi phụ huynh bấm 'Xóa toàn bộ dữ liệu của con tôi'."""
    with _write_lock, get_connection() as conn:
        conn.executescript("""
            DELETE FROM pending_events;
            DELETE FROM notifications;
            DELETE FROM agent_state WHERE key LIKE 'usage_%' OR key LIKE 'group_exhausted_%';
            """)
        conn.commit()
    logger.info("Đã xóa sạch dữ liệu sử dụng và hàng đợi event trong bộ đệm Agent")
