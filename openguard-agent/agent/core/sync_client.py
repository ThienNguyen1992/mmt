import hashlib
import platform
import random
import threading
import time
from collections.abc import Callable

import requests

from agent.core.cert_pinning import build_pinned_session, load_expected_fingerprint
from agent.core.config import load_config, save_config
from agent.core.event_queue import get_pending_batch, increment_retry, mark_synced
from agent.core.logger import get_logger
from agent.core.policy_enforcer import PolicyEnforcer

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


def send_heartbeat(
    server_base_url: str,
    policy_version: int,
    quota_used_min: int,
    is_locked: bool = False,
    offline_since_iso: str | None = None,
    verify_cert_path: str | None = None,
    pinned_cert_path: str | None = None,
    session: requests.Session | None = None,
) -> dict:
    """Gửi heartbeat 60s kèm trạng thái hiện tại lên Server."""
    cfg = load_config()
    device_id = cfg.get("device_id")
    if not device_id:
        raise ValueError("Thiết bị chưa được enroll (thiếu device_id)")

    url = f"{server_base_url.rstrip('/')}/policy/heartbeat/{device_id}"
    payload = {
        "policy_version": policy_version,
        "quota_used_min": quota_used_min,
        "is_locked": is_locked,
        "offline_since_iso": offline_since_iso,
    }
    resp = call_with_auto_refresh(
        "post",
        url,
        server_base_url,
        verify_cert_path=verify_cert_path,
        pinned_cert_path=pinned_cert_path,
        session=session,
        json=payload,
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def fetch_and_apply_latest_policy(
    server_base_url: str,
    policy_enforcer: PolicyEnforcer,
    verify_cert_path: str | None = None,
    pinned_cert_path: str | None = None,
    session: requests.Session | None = None,
) -> bool:
    """Tải GET /policy/{device_id}, xác thực chữ ký Ed25519 và áp dụng ngay."""
    cfg = load_config()
    device_id = cfg.get("device_id") or policy_enforcer.device_id
    if not device_id:
        raise ValueError("Thiết bị chưa được enroll (thiếu device_id)")

    url = f"{server_base_url.rstrip('/')}/policy/{device_id}"
    resp = call_with_auto_refresh(
        "get",
        url,
        server_base_url,
        verify_cert_path=verify_cert_path,
        pinned_cert_path=pinned_cert_path,
        session=session,
        timeout=10,
    )
    resp.raise_for_status()
    payload = resp.json()
    return policy_enforcer.apply_new_policy(
        version=payload["version"],
        content=payload["content"],
        signature=payload["signature"],
        policy_id=payload.get("policy_id", ""),
    )


class HeartbeatWorker(threading.Thread):
    """Worker gửi heartbeat định kỳ mỗi 60s với exponential backoff + jitter khi lỗi."""

    def __init__(
        self,
        server_base_url: str,
        state_provider: Callable[[], dict],
        interval_sec: float = 60.0,
        max_backoff_sec: float = 300.0,
        verify_cert_path: str | None = None,
        pinned_cert_path: str | None = None,
        session: requests.Session | None = None,
        policy_enforcer: PolicyEnforcer | None = None,
        on_policy_updated: Callable[[dict | None], None] | None = None,
        offline_tracker=None,
    ):
        super().__init__(daemon=True, name="OGK-HeartbeatWorker")
        self.server_base_url = server_base_url
        self.state_provider = state_provider
        self.interval_sec = interval_sec
        self.max_backoff_sec = max_backoff_sec
        self.verify_cert_path = verify_cert_path
        self.pinned_cert_path = pinned_cert_path
        self.session = session
        self.policy_enforcer = policy_enforcer
        self.on_policy_updated = on_policy_updated
        self.offline_tracker = offline_tracker
        self.stop_event = threading.Event()
        self.last_rtt_ms: float | None = None
        self.consecutive_failures = 0

    def tick_once(self) -> dict | None:
        state = self.state_provider()
        offline_since = state.get("offline_since_iso")
        if offline_since is None and self.offline_tracker is not None:
            offline_since = self.offline_tracker.get_offline_since_iso()
        started = time.perf_counter()
        try:
            data = send_heartbeat(
                self.server_base_url,
                policy_version=state.get("policy_version", 0),
                quota_used_min=state.get("quota_used_min", 0),
                is_locked=state.get("is_locked", False),
                offline_since_iso=offline_since,
                verify_cert_path=self.verify_cert_path,
                pinned_cert_path=self.pinned_cert_path,
                session=self.session,
            )
            self.last_rtt_ms = (time.perf_counter() - started) * 1000.0
            self.consecutive_failures = 0
            if self.offline_tracker is not None:
                self.offline_tracker.record_success()

            if self.policy_enforcer is not None:
                server_ver = data.get("server_policy_version", 0)
                needs_sync = bool(data.get("policy_update_available")) or (
                    server_ver != self.policy_enforcer.get_current_version()
                )
                if needs_sync and server_ver > 0:
                    applied = fetch_and_apply_latest_policy(
                        self.server_base_url,
                        self.policy_enforcer,
                        verify_cert_path=self.verify_cert_path,
                        pinned_cert_path=self.pinned_cert_path,
                        session=self.session,
                    )
                    if applied and self.on_policy_updated is not None:
                        self.on_policy_updated(self.policy_enforcer.get_content())

            return data
        except Exception as exc:
            self.consecutive_failures += 1
            if self.offline_tracker is not None:
                self.offline_tracker.record_failure()
            logger.warning("Heartbeat lỗi (lần %s): %s", self.consecutive_failures, exc)
            return None

    def next_wait_seconds(self) -> float:
        if self.consecutive_failures == 0:
            return self.interval_sec
        base = min(self.max_backoff_sec, 5.0 * (2 ** (self.consecutive_failures - 1)))
        return base + random.uniform(0.0, base * 0.2)

    def run(self) -> None:
        while not self.stop_event.is_set():
            self.tick_once()
            self.stop_event.wait(timeout=self.next_wait_seconds())

    def stop(self) -> None:
        self.stop_event.set()


class EventSyncWorker(threading.Thread):
    """Đồng bộ lô 50 event kèm idempotency_key, backoff + jitter (tối đa 600s)."""

    def __init__(
        self,
        server_base_url: str,
        interval_sec: float = 30.0,
        batch_size: int = 50,
        max_retries: int = 10,
        max_backoff_sec: float = 600.0,
        verify_cert_path: str | None = None,
        pinned_cert_path: str | None = None,
        session: requests.Session | None = None,
        offline_tracker=None,
    ):
        super().__init__(daemon=True, name="OGK-EventSyncWorker")
        self.server_base_url = server_base_url
        self.interval_sec = interval_sec
        self.batch_size = batch_size
        self.max_retries = max_retries
        self.max_backoff_sec = max_backoff_sec
        self.verify_cert_path = verify_cert_path
        self.pinned_cert_path = pinned_cert_path
        self.session = session
        self.offline_tracker = offline_tracker
        self.stop_event = threading.Event()
        self.consecutive_failures = 0

    def sync_once(self) -> int:
        """Đẩy lần lượt từng lô tối đa `batch_size` event chưa đồng bộ lên Server."""
        total_synced = 0
        url = f"{self.server_base_url.rstrip('/')}/events/batch"

        while not self.stop_event.is_set():
            batch = get_pending_batch(limit=self.batch_size, max_retries=self.max_retries)
            if not batch:
                break

            keys = [item["idempotency_key"] for item in batch]
            try:
                resp = call_with_auto_refresh(
                    "post",
                    url,
                    self.server_base_url,
                    verify_cert_path=self.verify_cert_path,
                    pinned_cert_path=self.pinned_cert_path,
                    session=self.session,
                    json={"events": batch},
                    timeout=15,
                )
                resp.raise_for_status()
                mark_synced(keys)
                total_synced += len(keys)
                self.consecutive_failures = 0
                if self.offline_tracker is not None:
                    self.offline_tracker.record_success()
            except Exception as exc:
                self.consecutive_failures += 1
                increment_retry(keys)
                if self.offline_tracker is not None:
                    self.offline_tracker.record_failure()
                logger.warning("EventSync lỗi (lần %s): %s", self.consecutive_failures, exc)
                break

        return total_synced

    def next_wait_seconds(self) -> float:
        if self.consecutive_failures == 0:
            return self.interval_sec
        base = min(self.max_backoff_sec, 10.0 * (2 ** (self.consecutive_failures - 1)))
        return base + random.uniform(0.0, base * 0.2)

    def run(self) -> None:
        while not self.stop_event.is_set():
            self.sync_once()
            self.stop_event.wait(timeout=self.next_wait_seconds())

    def stop(self) -> None:
        self.stop_event.set()
