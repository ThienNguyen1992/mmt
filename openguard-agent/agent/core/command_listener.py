import json
import random
import ssl
import threading
from collections.abc import Callable
from urllib.parse import urlparse

import websocket

from agent.core.cert_pinning import (
    compute_cert_fingerprint,
    create_pinned_ssl_context,
    load_expected_fingerprint,
)
from agent.core.config import load_config
from agent.core.logger import get_logger

logger = get_logger("command_listener")


class CommandListener(threading.Thread):
    """WebSocket listener nhận lệnh khẩn (< 5s), tự refresh JWT khi 4401 & TLS 1.2+."""

    def __init__(
        self,
        ws_url: str,
        token_provider: Callable[[], str] | None = None,
        refresh_token_fn: Callable[[], str] | None = None,
        ca_cert_path: str | None = None,
        pinned_cert_path: str | None = None,
        expected_fingerprint: str | None = None,
        on_lock_now: Callable[[dict], None] | None = None,
        on_unlock: Callable[[dict], None] | None = None,
        on_add_minutes: Callable[[int, dict], None] | None = None,
        on_wipe_local_cache: Callable[[dict], None] | None = None,
        initial_backoff_sec: float = 2.0,
        max_backoff_sec: float = 60.0,
        ping_interval: int = 25,
        ping_timeout: int = 10,
    ):
        super().__init__(daemon=True, name="OGK-CommandListener")
        self.ws_url = ws_url
        self.token_provider = token_provider or (lambda: load_config().get("access_token", ""))
        self.refresh_token_fn = refresh_token_fn
        self.ca_cert_path = ca_cert_path
        self.expected_fingerprint = (
            expected_fingerprint.lower()
            if expected_fingerprint
            else (load_expected_fingerprint(pinned_cert_path) if pinned_cert_path else None)
        )
        self.on_lock_now = on_lock_now
        self.on_unlock = on_unlock
        self.on_add_minutes = on_add_minutes
        self.on_wipe_local_cache = on_wipe_local_cache
        self.initial_backoff_sec = initial_backoff_sec
        self.max_backoff_sec = max_backoff_sec
        self.ping_interval = ping_interval
        self.ping_timeout = ping_timeout

        self.stop_event = threading.Event()
        self._current_ws: websocket.WebSocketApp | None = None
        self._last_close_code: int | None = None
        self._backoff = initial_backoff_sec

    def _build_sslopt(self) -> dict | None:
        if not self.ws_url.startswith("wss://"):
            return None
        ctx = create_pinned_ssl_context(self.ca_cert_path)
        sslopt: dict = {
            "context": ctx,
            "cert_reqs": ssl.CERT_REQUIRED,
        }
        if self.ca_cert_path:
            sslopt["ca_certs"] = self.ca_cert_path
        return sslopt

    def _verify_pinned_peer_cert(self, ws) -> bool:
        if not self.expected_fingerprint:
            return True
        sock = getattr(ws, "sock", None)
        inner_sock = getattr(sock, "sock", None) if sock is not None else None
        if inner_sock is None or not hasattr(inner_sock, "getpeercert"):
            return True
        cert_der = inner_sock.getpeercert(binary_form=True)
        if not cert_der:
            return False
        live_fp = compute_cert_fingerprint(cert_der)
        if live_fp != self.expected_fingerprint:
            logger.error(
                "CẢNH BÁO MITM WebSocket (%s): cert %s != pinned %s",
                urlparse(self.ws_url).netloc,
                live_fp,
                self.expected_fingerprint,
            )
            return False
        return True

    def dispatch_command(self, raw_message: str) -> bool:
        """Giải mã JSON và gọi callback tương ứng với loại lệnh khẩn."""
        try:
            cmd = json.loads(raw_message)
        except json.JSONDecodeError:
            logger.warning("Bỏ qua message WebSocket không phải JSON hợp lệ")
            return False

        if not isinstance(cmd, dict):
            return False

        cmd_type = cmd.get("type")
        if cmd_type == "pong":
            return True
        if cmd_type == "lock_now":
            if self.on_lock_now:
                self.on_lock_now(cmd)
            return True
        if cmd_type == "unlock":
            if self.on_unlock:
                self.on_unlock(cmd)
            return True
        if cmd_type == "add_minutes":
            minutes = int(cmd.get("minutes", 15))
            if self.on_add_minutes:
                self.on_add_minutes(minutes, cmd)
            return True
        if cmd_type == "wipe_local_cache":
            if self.on_wipe_local_cache:
                self.on_wipe_local_cache(cmd)
            return True

        logger.warning("Nhận loại lệnh WebSocket không hỗ trợ: %s", cmd_type)
        return False

    def next_reconnect_delay(self) -> float:
        """Tính thời gian chờ reconnect kèm jitter [0, 0.2 * backoff]."""
        delay = self._backoff + random.uniform(0.0, self._backoff * 0.2)
        self._backoff = min(self.max_backoff_sec, self._backoff * 2.0)
        return delay

    def handle_disconnect(self, close_status_code: int | None) -> float:
        """Xử lý sau khi WebSocket đóng: 4401 tự refresh JWT ngay, lỗi khác dùng backoff+jitter."""
        if close_status_code == 4401 and self.refresh_token_fn is not None:
            try:
                self.refresh_token_fn()
                self._backoff = self.initial_backoff_sec
                return 0.1
            except Exception as exc:
                logger.error("Refresh JWT sau 4401 thất bại: %s", exc)
        return self.next_reconnect_delay()

    def connect_once(self) -> int | None:
        self._last_close_code = None
        token = self.token_provider()
        headers = [f"Authorization: Bearer {token}"]

        def _on_open(ws):
            if not self._verify_pinned_peer_cert(ws):
                ws.close()
                return
            self._backoff = self.initial_backoff_sec
            logger.info("Kết nối WebSocket CommandListener thành công")

        def _on_message(_ws, message: str):
            self.dispatch_command(message)

        def _on_error(_ws, error):
            logger.warning("WebSocket lỗi: %s", error)

        def _on_close(_ws, close_status_code, _close_msg):
            self._last_close_code = close_status_code

        ws_app = websocket.WebSocketApp(
            self.ws_url,
            header=headers,
            on_open=_on_open,
            on_message=_on_message,
            on_error=_on_error,
            on_close=_on_close,
        )
        self._current_ws = ws_app
        ws_app.run_forever(
            sslopt=self._build_sslopt(),
            ping_interval=self.ping_interval,
            ping_timeout=self.ping_timeout,
        )
        return self._last_close_code

    def run(self) -> None:
        while not self.stop_event.is_set():
            close_code = self.connect_once()
            if self.stop_event.is_set():
                break
            wait_sec = self.handle_disconnect(close_code)
            self.stop_event.wait(timeout=wait_sec)

    def stop(self) -> None:
        self.stop_event.set()
        if self._current_ws is not None:
            try:
                self._current_ws.close()
            except Exception:
                pass
