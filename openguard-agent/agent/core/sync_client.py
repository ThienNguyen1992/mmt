import hashlib
import platform
import threading

import requests

from agent.core.cert_pinning import build_pinned_session, load_expected_fingerprint
from agent.core.config import load_config, save_config
from agent.core.logger import get_logger

logger = get_logger("sync_client")
_refresh_lock = threading.Lock()


def get_device_fingerprint() -> str:
    """Sinh hardware fingerprint 32 ký tự hex ổn định cho thiết bị."""
    raw = f"{platform.node()}-{platform.machine()}-{platform.processor()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _get_session(
    verify_cert_path: str | None = None,
    pinned_cert_path: str | None = None,
    session: requests.Session | None = None,
) -> requests.Session:
    if session is not None:
        return session
    pinned_fp = None if pinned_cert_path else load_config().get("pinned_cert_sha256")
    return build_pinned_session(
        pinned_cert_path=pinned_cert_path,
        ca_cert_path=verify_cert_path,
        expected_fingerprint=pinned_fp,
    )


def enroll(
    server_base_url: str,
    code: str,
    verify_cert_path: str | None = None,
    pinned_cert_path: str | None = None,
    device_name: str | None = None,
    session: requests.Session | None = None,
) -> dict:
    """Ghép đôi Agent với Server bằng mã 8 ký tự và lưu tokens + public key Ed25519."""
    http = _get_session(verify_cert_path, pinned_cert_path, session)
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
    if pinned_cert_path:
        cfg["pinned_cert_sha256"] = load_expected_fingerprint(pinned_cert_path)
    save_config(cfg)
    logger.info("Enroll thành công device_id=%s child_id=%s", data["device_id"], data["child_id"])
    return data


def refresh_access_token(
    server_base_url: str,
    verify_cert_path: str | None = None,
    pinned_cert_path: str | None = None,
    session: requests.Session | None = None,
    expected_old_token: str | None = None,
) -> str:
    """Làm mới access token an toàn đa luồng dưới Lock, tránh 2 worker refresh đè nhau."""
    with _refresh_lock:
        cfg = load_config()
        current_token = cfg.get("access_token")
        if expected_old_token is not None and current_token and current_token != expected_old_token:
            return current_token

        http = _get_session(verify_cert_path, pinned_cert_path, session)
        resp = http.post(
            f"{server_base_url.rstrip('/')}/enroll/refresh",
            json={"refresh_token": cfg["refresh_token"]},
            timeout=10,
        )
        resp.raise_for_status()
        new_token = resp.json()["access_token"]
        cfg["access_token"] = new_token
        save_config(cfg)
        return new_token


def call_with_auto_refresh(
    method_name: str,
    url: str,
    server_base_url: str,
    verify_cert_path: str | None = None,
    pinned_cert_path: str | None = None,
    session: requests.Session | None = None,
    **kwargs,
) -> requests.Response:
    """Gửi HTTP request với Bearer token; tự refresh và retry 1 lần nếu gặp 401."""
    http = _get_session(verify_cert_path, pinned_cert_path, session)
    cfg = load_config()
    current_token = cfg.get("access_token", "")
    headers = dict(kwargs.pop("headers", {}))
    headers["Authorization"] = f"Bearer {current_token}"

    req_fn = getattr(http, method_name.lower())
    resp = req_fn(url, headers=headers, **kwargs)
    if resp.status_code == 401:
        new_token = refresh_access_token(
            server_base_url,
            verify_cert_path=verify_cert_path,
            pinned_cert_path=pinned_cert_path,
            session=http,
            expected_old_token=current_token,
        )
        headers["Authorization"] = f"Bearer {new_token}"
        resp = req_fn(url, headers=headers, **kwargs)
    return resp
