import hashlib
import platform

import requests

from agent.core.config import load_config, save_config
from agent.core.logger import get_logger

logger = get_logger("sync_client")


def get_device_fingerprint() -> str:
    """Sinh hardware fingerprint 32 ký tự hex ổn định cho thiết bị."""
    raw = f"{platform.node()}-{platform.machine()}-{platform.processor()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _build_session(verify_cert_path: str | None = None) -> requests.Session:
    session = requests.Session()
    if verify_cert_path:
        session.verify = verify_cert_path
    return session


def enroll(
    server_base_url: str,
    code: str,
    verify_cert_path: str | None = None,
    device_name: str | None = None,
    session: requests.Session | None = None,
) -> dict:
    """Ghép đôi Agent với Server bằng mã 8 ký tự và lưu tokens + public key Ed25519."""
    http = session or _build_session(verify_cert_path)
    resp = http.post(
        f"{server_base_url.rstrip('/')}/enroll/device",
        json={
            "code": code,
            "fingerprint": get_device_fingerprint(),
            "device_name": device_name or platform.node(),
        },
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()

    cfg = load_config()
    cfg.update(
        {
            "device_id": data["device_id"],
            "child_id": data["child_id"],
            "access_token": data["access_token"],
            "refresh_token": data["refresh_token"],
            "policy_public_key_pem": data["policy_public_key_pem"],
            "enrolled": True,
        }
    )
    save_config(cfg)
    logger.info("Enroll thành công device_id=%s child_id=%s", data["device_id"], data["child_id"])
    return data
