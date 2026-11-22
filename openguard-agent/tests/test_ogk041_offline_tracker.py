from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from agent.core import config as agent_config
from agent.core import sync_client
from agent.core.offline_tracker import OfflineTracker


def test_offline_tracker_persists_since_iso_after_threshold_and_resets(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_config, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(agent_config, "IPC_DIR", str(tmp_path / "ipc"))

    tracker = OfflineTracker(failure_threshold=3)
    t0 = datetime(2026, 11, 18, 10, 0, tzinfo=timezone.utc)

    assert tracker.record_failure(now=t0) is False
    assert tracker.record_failure(now=t0 + timedelta(minutes=1)) is False
    assert tracker.is_offline() is False

    t_offline = t0 + timedelta(minutes=2)
    assert tracker.record_failure(now=t_offline) is True
    assert tracker.is_offline() is True
    assert tracker.get_offline_since_iso() == t_offline.isoformat()

    # Subsequent failure preserves original offline_since_iso & survives restart
    tracker.record_failure(now=t_offline + timedelta(days=2))
    reloaded = OfflineTracker(failure_threshold=3)
    assert reloaded.is_offline() is True
    assert reloaded.get_offline_since_iso() == t_offline.isoformat()
    days = reloaded.get_offline_duration_days(now=t_offline + timedelta(days=4))
    assert round(days, 2) == 4.0

    reloaded.record_success()
    assert reloaded.is_offline() is False
    assert reloaded.get_offline_since_iso() is None
    assert reloaded.get_offline_duration_days() == 0.0


def test_heartbeat_worker_drives_offline_tracker(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_config, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(agent_config, "IPC_DIR", str(tmp_path / "ipc"))
    agent_config.save_config({"device_id": "dev-041", "access_token": "jwt", "enrolled": True})

    tracker = OfflineTracker(failure_threshold=3)
    mock_session = MagicMock()
    mock_session.post.side_effect = RuntimeError("offline")

    worker = sync_client.HeartbeatWorker(
        "https://127.0.0.1:8443",
        state_provider=lambda: {"policy_version": 1, "quota_used_min": 5},
        session=mock_session,
        offline_tracker=tracker,
    )

    for _ in range(3):
        worker.tick_once()
    assert tracker.is_offline() is True

    ok_resp = MagicMock(status_code=200)
    ok_resp.json.return_value = {
        "server_policy_version": 1,
        "policy_update_available": False,
        "server_utc": "2026-11-22T14:00:00+00:00",
        "pending_commands": [],
    }
    mock_session.post.side_effect = None
    mock_session.post.return_value = ok_resp
    worker.tick_once()
    assert tracker.is_offline() is False
