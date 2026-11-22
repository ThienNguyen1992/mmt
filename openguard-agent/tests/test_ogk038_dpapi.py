import json

import pytest

from agent.core import config as agent_config
from agent.core import secure_storage


def test_dpapi_protect_and_unprotect_roundtrip():
    if not secure_storage.HAS_WIN32CRYPT:
        pytest.skip("win32crypt required on Windows")

    secret = "refresh-token-bi-mat-12345"
    enc = secure_storage.protect_secret(secret, "OGK test")
    assert enc != secret
    assert secret not in enc
    assert secure_storage.unprotect_secret(enc) == secret


def test_agent_config_stores_dpapi_ciphertext_and_no_plaintext_tokens(tmp_path, monkeypatch):
    if not secure_storage.HAS_WIN32CRYPT:
        pytest.skip("win32crypt required on Windows")

    monkeypatch.setattr(agent_config, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(agent_config, "IPC_DIR", str(tmp_path / "ipc"))

    agent_config.save_config(
        {
            "device_id": "dev-038",
            "access_token": "jwt-plaintext-access",
            "refresh_token": "raw-plaintext-refresh",
            "enrolled": True,
        }
    )

    raw_text = (tmp_path / "data" / "agent_config.json").read_text(encoding="utf-8")
    assert "jwt-plaintext-access" not in raw_text
    assert "raw-plaintext-refresh" not in raw_text

    raw_json = json.loads(raw_text)
    assert "access_token" not in raw_json
    assert "refresh_token" not in raw_json
    assert "access_token_enc" in raw_json
    assert "refresh_token_enc" in raw_json

    loaded = agent_config.load_config()
    assert loaded["access_token"] == "jwt-plaintext-access"
    assert loaded["refresh_token"] == "raw-plaintext-refresh"
