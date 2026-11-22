import json
import os
import threading

APP_ROOT_DIR = os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"), "OpenGuardKids")
# Tách 2 thư mục con để siết ACL:
# - DATA_DIR: CHỈ SYSTEM & Administrators (chứa DB, config DPAPI, logs)
# - IPC_DIR:  SYSTEM & Admins Full, Users Read-Only (chỉ chứa ipc_token.txt cho Tray UI)
DATA_DIR = os.path.join(APP_ROOT_DIR, "data")
IPC_DIR = os.path.join(APP_ROOT_DIR, "ipc")
APP_DATA_DIR = DATA_DIR  # alias tương thích ngược trong test
CONFIG_PATH = os.path.join(DATA_DIR, "agent_config.json")

SECRET_FIELDS = ("refresh_token", "access_token")
_config_lock = threading.Lock()

DEFAULT_CONFIG = {
    "server_host": "127.0.0.1",
    "server_port": 8443,
    "heartbeat_interval_sec": 60,
    "device_id": None,
    "child_id": None,
    "enrolled": False,
    "policy_public_key_pem": None,
    "pinned_cert_sha256": None,
}


def get_config_path() -> str:
    return os.path.join(DATA_DIR, "agent_config.json")


def ensure_app_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(IPC_DIR, exist_ok=True)


def load_config() -> dict:
    with _config_lock:
        ensure_app_data_dir()
        cfg_path = get_config_path()
        if not os.path.exists(cfg_path):
            cfg = dict(DEFAULT_CONFIG)
            with open(cfg_path, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
            return cfg
        with open(cfg_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        # Phần giải mã DPAPI được gắn vào từ OGK-038 (E4)
        for field in SECRET_FIELDS:
            enc_key = f"{field}_enc"
            if raw.get(enc_key):
                try:
                    from agent.core.secure_storage import unprotect_secret

                    raw[field] = unprotect_secret(raw[enc_key])
                except Exception:
                    raw[field] = None
        return raw


def save_config(config: dict):
    with _config_lock:
        ensure_app_data_dir()
        cfg_path = get_config_path()
        to_write = dict(config)
        for field in SECRET_FIELDS:
            if to_write.get(field):
                try:
                    from agent.core.secure_storage import protect_secret

                    to_write[f"{field}_enc"] = protect_secret(to_write[field], f"OGK {field}")
                    to_write.pop(field, None)
                except ImportError:
                    pass  # trước khi cài đặt OGK-038 hoặc khi test non-Windows
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(to_write, f, indent=2)
