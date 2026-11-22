from unittest.mock import MagicMock

from agent.core import config as agent_config
from agent.core import sync_client


def test_get_device_fingerprint_returns_32_hex_chars():
    fp = sync_client.get_device_fingerprint()
    assert len(fp) == 32
    int(fp, 16)


def test_agent_enroll_saves_tokens_and_public_key(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_config, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(agent_config, "IPC_DIR", str(tmp_path / "ipc"))

    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "device_id": "dev-uuid-123",
        "child_id": "child-uuid-456",
        "access_token": "jwt-access-abc",
        "refresh_token": "raw-refresh-xyz",
        "policy_public_key_pem": "-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----\n",
    }
    mock_session = MagicMock()
    mock_session.post.return_value = mock_resp

    data = sync_client.enroll(
        "https://127.0.0.1:8443",
        code="AB23CD45",
        device_name="TestWinPC",
        session=mock_session,
    )
    assert data["device_id"] == "dev-uuid-123"
    mock_session.post.assert_called_once()
    call_kwargs = mock_session.post.call_args.kwargs
    assert call_kwargs["json"]["code"] == "AB23CD45"
    assert call_kwargs["json"]["device_name"] == "TestWinPC"

    saved = agent_config.load_config()
    assert saved["enrolled"] is True
    assert saved["device_id"] == "dev-uuid-123"
    assert saved["child_id"] == "child-uuid-456"
    assert saved["access_token"] == "jwt-access-abc"
    assert saved["refresh_token"] == "raw-refresh-xyz"
    assert "BEGIN PUBLIC KEY" in saved["policy_public_key_pem"]
