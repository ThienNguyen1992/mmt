import hmac
import os
import secrets

from agent.core import config as agent_config


def get_ipc_token_path() -> str:
    return os.path.join(agent_config.IPC_DIR, "ipc_token.txt")


def rotate_ipc_token() -> str:
    """Sinh mới IPC token mỗi lần Service khởi động và lưu vào IPC_DIR/ipc_token.txt."""
    agent_config.ensure_app_data_dir()
    token = secrets.token_urlsafe(32)
    with open(get_ipc_token_path(), "w", encoding="utf-8") as f:
        f.write(token)
    return token


def read_ipc_token() -> str:
    path = get_ipc_token_path()
    if not os.path.exists(path):
        return ""
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


def verify_ipc_token(candidate: str | None) -> bool:
    """So sánh X-IPC-Token bằng hmac.compare_digest chống timing attack."""
    if not candidate:
        return False
    expected = read_ipc_token()
    if not expected:
        return False
    return hmac.compare_digest(candidate, expected)
