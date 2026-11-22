from unittest.mock import MagicMock

from agent.core import config as agent_config
from agent.core import sync_client


def test_heartbeat_worker_tick_success_and_backoff_on_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_config, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(agent_config, "IPC_DIR", str(tmp_path / "ipc"))
    agent_config.save_config(
        {
            "device_id": "dev-029",
            "child_id": "child-029",
            "access_token": "jwt-029",
            "refresh_token": "ref-029",
            "enrolled": True,
        }
    )

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "server_policy_version": 2,
        "policy_update_available": True,
        "server_utc": "2026-11-22T14:00:00+00:00",
        "pending_commands": [],
    }
    mock_session = MagicMock()
    mock_session.post.return_value = mock_resp

    worker = sync_client.HeartbeatWorker(
        "https://127.0.0.1:8443",
        state_provider=lambda: {"policy_version": 1, "quota_used_min": 15, "is_locked": False},
        interval_sec=60.0,
        session=mock_session,
    )

    res = worker.tick_once()
    assert res["server_policy_version"] == 2
    assert res["policy_update_available"] is True
    assert worker.last_rtt_ms is not None
    assert worker.consecutive_failures == 0
    assert worker.next_wait_seconds() == 60.0

    # Simulate network failure -> backoff kicks in
    mock_session.post.side_effect = RuntimeError("network down")
    assert worker.tick_once() is None
    assert worker.consecutive_failures == 1
    wait_1 = worker.next_wait_seconds()
    assert 5.0 <= wait_1 <= 6.0
