import html
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from shared.network_constants import IPC_PORT

from agent.core.event_queue import enqueue_event
from agent.core.local_store import get_connection
from agent.core.logger import get_logger
from agent.core.notifier import pop_pending_notifications

logger = get_logger("ipc_server")
_last_tray_heartbeat = {"ts": 0.0}


def get_last_tray_heartbeat() -> float:
    return _last_tray_heartbeat["ts"]


def handle_diagnostics_request() -> dict:
    """Chẩn đoán mạng qua IPC (mở rộng đầy đủ ở OGK-095/098 E10)."""
    try:
        from agent.core.network_diag import run_full_diagnostics

        return run_full_diagnostics()
    except ImportError:
        return {"status": "diagnostics_ready", "details": "pending_e10_network_diag"}


def _verify_token(token: str) -> bool:
    try:
        from agent.core.ipc_token import verify_ipc_token

        return verify_ipc_token(token)
    except ImportError:
        return True


class IPCHandler(BaseHTTPRequestHandler):
    runtime = None  # được gắn trên class con bởi IPCServer

    def log_message(self, format, *args):  # noqa: A002
        pass  # tránh ghi stdout trong Windows Service

    def _send_json(self, code: int, body: dict) -> None:
        raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _check_auth(self, allow_query_token: bool = False) -> bool:
        token = self.headers.get("X-IPC-Token", "")
        if not token and allow_query_token:
            qs = parse_qs(urlparse(self.path).query)
            token = (qs.get("token") or [""])[0]
        if not _verify_token(token):
            self._send_json(401, {"ok": False, "error": "IPC token không hợp lệ"})
            return False
        return True

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/transparency":
            if not self._check_auth(allow_query_token=True):
                return
            self._serve_transparency_html()
            return
        if not self._check_auth():
            return

        if path == "/status":
            self._send_json(200, {"ok": True, "data": self.runtime.get_status_snapshot()})
        elif path == "/notifications":
            self._send_json(200, {"ok": True, "notifications": pop_pending_notifications()})
        elif path == "/today-usage":
            self._send_json(200, {"ok": True, "data": self._query_today_usage()})
        elif path == "/diagnostics":
            self._send_json(200, {"ok": True, "data": handle_diagnostics_request()})
        else:
            self._send_json(404, {"ok": False, "error": "Không tìm thấy endpoint IPC"})

    def do_POST(self) -> None:  # noqa: N802
        if not self._check_auth():
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8") if length else "{}"
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            self._send_json(400, {"ok": False, "error": "JSON không hợp lệ"})
            return

        path = urlparse(self.path).path
        if path == "/tray/heartbeat":
            _last_tray_heartbeat["ts"] = time.time()
            self.runtime.update_tray_telemetry(
                idle_sec=body.get("idle_sec"),
                fg_process=body.get("foreground_process"),
                session_locked=body.get("session_locked"),
            )
            self._send_json(
                200,
                {
                    "ok": True,
                    "should_lock": self.runtime.is_locked(),
                    "lock_reason": self.runtime._lock_reason,
                },
            )
        elif path == "/request-extra-time":
            minutes = int(body.get("minutes", 15))
            enqueue_event(
                "unlock_request",
                subject=f"extra_time_{minutes}min",
                device_id=self.runtime.device_id,
                child_id=self.runtime.child_id,
            )
            self._send_json(200, {"ok": True, "submitted": True})
        elif path == "/report-wrong-block":
            domain = str(body.get("subject", "")).strip()
            enqueue_event(
                "unlock_request",
                subject=f"wrong_block:{domain}",
                device_id=self.runtime.device_id,
                child_id=self.runtime.child_id,
            )
            self._send_json(200, {"ok": True, "submitted": True})
        else:
            self._send_json(404, {"ok": False, "error": "Không tìm thấy endpoint IPC"})

    def _query_today_usage(self) -> dict:
        with get_connection() as conn:
            rows = conn.execute("""
                SELECT type, subject, SUM(duration_sec) AS total_sec, COUNT(*) AS cnt
                FROM pending_events
                WHERE date(ts, 'localtime') = date('now', 'localtime')
                GROUP BY type, subject
                ORDER BY total_sec DESC, cnt DESC LIMIT 10
                """).fetchall()
        return {"items": [dict(r) for r in rows]}

    def _serve_transparency_html(self) -> None:
        usage = self._query_today_usage()["items"]
        status = self.runtime.get_status_snapshot()
        rows_html = "".join(
            f"<tr><td>{html.escape(str(r['type']))}</td>"
            f"<td>{html.escape(str(r['subject'] or '-'))}</td>"
            f"<td>{round((r['total_sec'] or 0) / 60, 1)} phút ({r['cnt']} lần)</td></tr>"
            for r in usage
        )
        empty_row = "<tr><td colspan=3>Chưa có dữ liệu hôm nay</td></tr>"
        page = (
            "<!DOCTYPE html><html lang='vi'><head><meta charset='utf-8'>"
            "<title>Hôm nay em đã dùng gì — OpenGuard Kids</title>"
            "<style>body{font-family:sans-serif;max-width:720px;margin:24px auto;"
            "padding:0 16px;background:#f8fafc}"
            ".card{background:#fff;padding:16px;border-radius:10px;"
            "box-shadow:0 1px 4px rgba(0,0,0,.08)}"
            "table{width:100%;border-collapse:collapse}"
            "th,td{padding:8px;border-bottom:1px solid #e2e8f0;text-align:left}</style>"
            "</head><body><div class='card'><h2>Hôm nay em đã dùng gì?</h2>"
            f"<p>Thời gian còn lại hôm nay: <b>{status['quota_remaining_min']} phút</b></p>"
            "<p><i>Lưu ý minh bạch (NT2): Chỉ lưu tên ứng dụng, tên miền cấp hai "
            "và thời lượng — KHÔNG lưu nội dung tin nhắn, URL chi tiết hay ảnh màn hình.</i></p>"
            "<table><thead><tr><th>Hoạt động</th><th>Ứng dụng / Trang web</th>"
            f"<th>Tổng</th></tr></thead><tbody>{rows_html or empty_row}</tbody></table>"
            "</div></body></html>"
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)


class IPCServer:
    def __init__(self, runtime, port: int = IPC_PORT):
        self.runtime = runtime
        handler_cls = type("BoundIPCHandler", (IPCHandler,), {"runtime": runtime})
        self._httpd = ThreadingHTTPServer(("127.0.0.1", port), handler_cls)
        self.port = int(self._httpd.server_address[1])
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            daemon=True,
            name="IPCServer",
        )
        self._thread.start()
        logger.info("IPC HTTP server lắng nghe tại http://127.0.0.1:%s", self.port)

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
