from agent.core import config as agent_config
from agent.core import event_queue, local_store, notifier


def test_local_store_wal_4_tables_and_clear_all_preserves_enrollment(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_config, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(agent_config, "IPC_DIR", str(tmp_path / "ipc"))
    agent_config.save_config({"device_id": "dev-036", "child_id": "child-036", "enrolled": True})

    local_store.init_schema()

    with local_store.get_connection() as conn:
        mode = conn.execute("PRAGMA journal_mode;").scalar() if hasattr(conn, "scalar") else None
        if mode is None:
            mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        assert str(mode).lower() == "wal"

        tables = {
            row["name"]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        assert {"policy_cache", "pending_events", "agent_state", "notifications"}.issubset(tables)

    local_store.set_state("quota_used_sec", "1200")
    local_store.set_state("usage_2026_11_22", "1200")
    local_store.set_state("group_exhausted_game", "1")
    local_store.set_state("offline_since_iso", "2026-11-20T00:00:00+00:00")
    assert local_store.get_state_int("quota_used_sec") == 1200

    event_queue.enqueue_event("app_stop", subject="word.exe", duration_sec=60)
    notifier.push_notification("blocked_domain", {"subject": "example.com"})

    local_store.clear_all_local_data()

    assert event_queue.count_pending() == 0
    assert notifier.pop_pending_notifications() == []
    assert local_store.get_state("usage_2026_11_22") is None
    assert local_store.get_state("group_exhausted_game") is None
    # Non-usage state & enrollment config stay intact
    assert local_store.get_state("offline_since_iso") == "2026-11-20T00:00:00+00:00"
    assert agent_config.load_config()["enrolled"] is True
