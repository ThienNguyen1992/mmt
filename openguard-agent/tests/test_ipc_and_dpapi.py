import pytest
import requests

from agent.core import config as agent_config
from agent.core import local_store, secure_storage
from agent.core.ipc_server import IPCServer
from agent.core.ipc_token import read_ipc_token, rotate_ipc_token, verify_ipc_token
from agent.service.agent_runtime import AgentRuntime
from agent.tray.ipc_client import IPCClient


def test_ipc_token_auth_401_and_rotation_invalidates_old_token(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_config, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(agent_config, "IPC_DIR", str(tmp_path / "ipc"))
    agent_config.save_config({"device_id": "dev-040", "child_id": "child-040", "enrolled": True})
    local_store.init_schema()

    rt = AgentRuntime(start_network=False)
    srv = IPCServer(runtime=rt, port=0)
    srv.start()
    try:
        tok1 = rotate_ipc_token()
        assert read_ipc_token() == tok1
        assert verify_ipc_token(tok1) is True
        assert verify_ipc_token("wrong-token") is False

        base = f"http://127.0.0.1:{srv.port}"

        # Missing or wrong X-IPC-Token -> 401
        assert requests.get(f"{base}/status", timeout=3).status_code == 401
        assert (
            requests.get(f"{base}/status", headers={"X-IPC-Token": "bad"}, timeout=3).status_code
            == 401
        )
        assert (
            requests.post(
                f"{base}/tray/heartbeat",
                json={"idle_sec": 0},
                headers={"X-IPC-Token": "bad"},
                timeout=3,
            ).status_code
            == 401
        )
        assert requests.get(f"{base}/transparency", timeout=3).status_code == 401

        # Valid token -> 200
        client = IPCClient(base_url=base)
        assert client.get_status()["device_id"] == "dev-040"
        assert requests.get(f"{base}/transparency?token={tok1}", timeout=3).status_code == 200

        # Simulate service restart: rotate token -> old token becomes 401
        tok2 = rotate_ipc_token()
        assert tok2 != tok1
        assert (
            requests.get(f"{base}/status", headers={"X-IPC-Token": tok1}, timeout=3).status_code
            == 401
        )
        assert (
            requests.get(f"{base}/status", headers={"X-IPC-Token": tok2}, timeout=3).status_code
            == 200
        )
    finally:
        srv.stop()


def test_dpapi_and_ipc_integration(tmp_path, monkeypatch):
    if not secure_storage.HAS_WIN32CRYPT:
        pytest.skip("win32crypt required on Windows")

    enc = secure_storage.protect_secret("token-040", "OGK IPC test")
    assert secure_storage.unprotect_secret(enc) == "token-040"
