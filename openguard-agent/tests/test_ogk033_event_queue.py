import uuid

from agent.core import config as agent_config
from agent.core import event_queue


def test_event_queue_enqueue_batch_mark_synced_and_retry_quarantine(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_config, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(agent_config, "IPC_DIR", str(tmp_path / "ipc"))
    agent_config.save_config({"device_id": "dev-033", "child_id": "child-033", "enrolled": True})

    k1 = event_queue.enqueue_event("app_start", subject="word.exe", duration_sec=0, policy_id="v1")
    k2 = event_queue.enqueue_event("app_stop", subject="word.exe", duration_sec=300, policy_id="v1")

    assert uuid.UUID(k1).version == 4
    assert uuid.UUID(k2).version == 4
    assert k1 != k2
    assert event_queue.count_pending() == 2

    batch = event_queue.get_pending_batch(limit=50)
    assert len(batch) == 2
    assert [ev["idempotency_key"] for ev in batch] == [k1, k2]
    assert batch[1]["duration_sec"] == 300
    assert batch[1]["device_id"] == "dev-033"

    # Mark first event synced; quarantine second after 10 failed retries
    assert event_queue.mark_synced([k1]) == 1
    assert event_queue.count_pending() == 1

    for _ in range(10):
        event_queue.increment_retry([k2])
    assert event_queue.count_pending(max_retries=10) == 0
    assert event_queue.get_pending_batch(limit=50, max_retries=10) == []
