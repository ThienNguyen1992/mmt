import pytest
from fastapi.testclient import TestClient
from shared.network_constants import HTTPS_API_PORT

from app.config import Settings, settings
from app.main import app


def test_health_endpoint():
    client = TestClient(app)
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}


def test_server_settings_defaults():
    cfg = Settings(_env_file=None)
    assert cfg.access_token_expire_minutes == 15
    assert cfg.refresh_token_expire_days == 30
    assert cfg.session_expire_hours == 12
    assert cfg.enrollment_code_expire_minutes == 10
    assert cfg.login_max_attempts == 5
    assert cfg.login_lockout_minutes == 15
    assert cfg.retention_days == 90
    assert cfg.offline_grace_days == 3
    assert cfg.offline_fail_mode == "fail-closed"
    assert cfg.cookie_secure is True
    assert HTTPS_API_PORT == 8443


def test_dev_env_loaded_with_valid_keys():
    assert settings.app_env == "dev"
    assert not settings.secret_key.startswith("CHANGE_ME")
    assert len(settings.secret_key) >= 64
    assert settings.aes_gcm_key_b64 != ""
    assert len(settings.device_secret_pepper) >= 64


def test_invalid_aes_key_rejected():
    with pytest.raises(ValueError):
        Settings(_env_file=None, aes_gcm_key_b64="CHANGE_ME_BASE64_32_BYTES_KEY")


def test_lab_mode_rejects_dev_defaults():
    with pytest.raises(ValueError):
        Settings(_env_file=None, app_env="lab")
