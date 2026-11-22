from unittest.mock import MagicMock

from agent.core import config as agent_config
from agent.core import event_queue, sync_client
from agent.core.offline_tracker import OfflineTracker


def test_event_sync_worker_flushes_200_events_in_batches_of_50(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_config, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(agent_config, "IPC_DIR", str(tmp_path / "ipc"))
    agent_config.save_config(
        {
            "device_id": "dev-042",
            "child_id": "child-042",
            "access_token": "jwt-042",
            "refresh_token": "ref-042",
            "enrolled": True,
        }
    )

    for i in range(200):
        event_queue.enqueue_event("domain_query", subject=f"site{i}.edu.vn", duration_sec=10)
    assert event_queue.count_pending() == 200

    sent_batches = []

    def fake_post(url, json=None, headers=None, timeout=15):
        sent_batches.append(json["events"])
        resp = MagicMock(status_code=200)
        resp.json.return_value = {"inserted": len(json["events"]), "skipped_duplicates": 0}
        return resp

    mock_session = MagicMock()
    mock_session.post.side_effect = fake_post

    tracker = OfflineTracker(failure_threshold=3)
    worker = sync_client.EventSyncWorker(
        "https://127.0.0.1:8443",
        batch_size=50,
        session=mock_session,
        offline_tracker=tracker,
    )

    synced = worker.sync_once()
    assert synced == 200
    assert len(sent_batches) == 4
    assert [len(b) for b in sent_batches] == [50, 50, 50, 50]
    all_keys = [ev["idempotency_key"] for b in sent_batches for ev in b]
    assert len(set(all_keys)) == 200
    assert event_queue.count_pending() == 0


def test_event_sync_worker_backoff_capped_600s_and_quarantines_after_10_retries(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(agent_config, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(agent_config, "IPC_DIR", str(tmp_path / "ipc"))
    agent_config.save_config({"device_id": "dev-042", "access_token": "jwt", "enrolled": True})

    event_queue.enqueue_event("app_stop", subject="bad.exe", duration_sec=5)
    mock_session = MagicMock()
    mock_session.post.side_effect = RuntimeError("server unreachable")

    worker = sync_client.EventSyncWorker(
        "https://127.0.0.1:8443",
        batch_size=50,
        max_retries=10,
        max_backoff_sec=600.0,
        session=mock_session,
    )

    for _ in range(10):
        assert worker.sync_once() == 0

    # Poisoned event quarantined after 10 failures
    assert event_queue.count_pending(max_retries=10) == 0
    # Backoff capped at 600s (+ up to 20% jitter = 720s max)
    delay = worker.next_wait_seconds()
    assert 600.0 <= delay <= 720.0
