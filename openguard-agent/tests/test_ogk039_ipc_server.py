import requests

from agent.core import config as agent_config
from agent.core import event_queue, local_store, notifier
from agent.core.ipc_server import IPCServer, get_last_tray_heartbeat
from agent.service.agent_runtime import AgentRuntime
from agent.tray.ipc_client import IPCClient


def test_ipc_server_and_client_routes(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_config, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(agent_config, "IPC_DIR", str(tmp_path / "ipc"))
    agent_config.save_config({"device_id": "dev-039", "child_id": "child-039", "enrolled": True})
    local_store.init_schema()

    rt = AgentRuntime(start_network=False)
    srv = IPCServer(runtime=rt, port=0)
    srv.start()
    try:
        client = IPCClient(base_url=f"http://127.0.0.1:{srv.port}")

        # /status
        status = client.get_status()
        assert status["device_id"] == "dev-039"

        # /tray/heartbeat passes user-session telemetry across Session 0 boundary
        hb = client.send_tray_heartbeat(
            idle_sec=42.0,
            foreground_process="chrome.exe",
            session_locked=False,
        )
        assert hb["ok"] is True
        assert rt._user_idle_sec == 42.0
        assert rt._user_fg_process == "chrome.exe"
        assert rt._user_session_locked is False
        assert get_last_tray_heartbeat() > 0

        # /notifications
        notifier.push_notification("quota_warning", {"remaining_min": 10})
        notifs = client.pop_notifications()
        assert len(notifs) == 1
        assert notifs[0]["type"] == "quota_warning"

        # /request-extra-time & /report-wrong-block enqueue unlock_request events
        assert client.request_extra_time(15)["submitted"] is True
        assert client.report_wrong_block("hocmai.vn")["submitted"] is True
        batch = event_queue.get_pending_batch(limit=10)
        assert [b["subject"] for b in batch] == ["extra_time_15min", "wrong_block:hocmai.vn"]

        # /today-usage & /diagnostics
        event_queue.enqueue_event("app_stop", subject="<script>word.exe</script>", duration_sec=120)
        usage = client.get_today_usage()
        assert len(usage["items"]) >= 1

        diag_resp = requests.get(f"http://127.0.0.1:{srv.port}/diagnostics", timeout=3)
        assert diag_resp.status_code == 200

        # /transparency escapes HTML safely
        trans_resp = requests.get(f"http://127.0.0.1:{srv.port}/transparency", timeout=3)
        assert trans_resp.status_code == 200
        assert "&lt;script&gt;word.exe&lt;/script&gt;" in trans_resp.text
    finally:
        srv.stop()
