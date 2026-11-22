from unittest.mock import MagicMock

from agent.core import config as agent_config
from agent.service import windows_service
from agent.service.agent_runtime import AgentRuntime


def test_agent_runtime_lifecycle_lock_unlock_and_telemetry(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_config, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(agent_config, "IPC_DIR", str(tmp_path / "ipc"))
    agent_config.save_config({"device_id": "dev-034", "child_id": "child-034", "enrolled": True})

    rt = AgentRuntime(start_network=False)
    rt.start()
    try:
        assert rt.is_locked() is False

        rt.update_tray_telemetry(idle_sec=12.5, fg_process="word.exe", session_locked=False)
        assert rt._user_idle_sec == 12.5
        assert rt._user_fg_process == "word.exe"
        assert rt._user_session_locked is False

        rt.lock_device("quota_exceeded")
        assert rt.is_locked() is True

        # Adding minutes while quota_exceeded unlocks automatically
        rt.add_extra_minutes(15)
        assert rt._extra_minutes_today == 15
        assert rt.is_locked() is False

        snap = rt.get_status_snapshot()
        assert snap["device_id"] == "dev-034"
        assert snap["is_locked"] is False
    finally:
        rt.stop()
        assert rt.wait(timeout=0.1) is True


def test_windows_service_metadata_and_cli_flags(monkeypatch):
    assert windows_service.OGKAgentService._svc_name_ == "OGKAgent"

    called = []
    monkeypatch.setattr(windows_service, "_handle_setup_acl", lambda: called.append("setup-acl"))
    monkeypatch.setattr(windows_service, "_handle_install", lambda: called.append("install"))
    monkeypatch.setattr(windows_service, "_handle_uninstall", lambda: called.append("uninstall"))
    monkeypatch.setattr(windows_service, "run_console", lambda: called.append("console"))

    assert windows_service.main(["--setup-acl"]) == 0
    assert windows_service.main(["--install"]) == 0
    assert windows_service.main(["--uninstall"]) == 0
    assert windows_service.main(["console"]) == 0
    assert called == ["setup-acl", "install", "uninstall", "console"]

    if windows_service.HAS_PYWIN32:
        mock_hcl = MagicMock()
        monkeypatch.setattr(windows_service.win32serviceutil, "HandleCommandLine", mock_hcl)
        assert windows_service.main(["start"]) == 0
        mock_hcl.assert_called_once()
