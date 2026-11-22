import requests
from shared.network_constants import IPC_PORT


def _read_token() -> str:
    try:
        from agent.core.ipc_token import read_ipc_token

        return read_ipc_token()
    except ImportError:
        return ""


class IPCClient:
    """Client cho Tray UI (user session) giao tiếp với OGKAgent Service (Session 0)."""

    def __init__(
        self,
        base_url: str = f"http://127.0.0.1:{IPC_PORT}",
        token: str | None = None,
        timeout: float = 3.0,
    ):
        self.base_url = base_url.rstrip("/")
        self._explicit_token = token
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        tok = self._explicit_token if self._explicit_token is not None else _read_token()
        return {"X-IPC-Token": tok} if tok else {}

    def get_status(self) -> dict:
        resp = requests.get(
            f"{self.base_url}/status",
            headers=self._headers(),
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()["data"]

    def pop_notifications(self) -> list[dict]:
        resp = requests.get(
            f"{self.base_url}/notifications",
            headers=self._headers(),
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()["notifications"]

    def get_today_usage(self) -> dict:
        resp = requests.get(
            f"{self.base_url}/today-usage",
            headers=self._headers(),
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()["data"]

    def send_tray_heartbeat(
        self,
        idle_sec: float | None = None,
        foreground_process: str | None = None,
        session_locked: bool | None = None,
    ) -> dict:
        resp = requests.post(
            f"{self.base_url}/tray/heartbeat",
            json={
                "idle_sec": idle_sec,
                "foreground_process": foreground_process,
                "session_locked": session_locked,
            },
            headers=self._headers(),
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def request_extra_time(self, minutes: int = 15) -> dict:
        resp = requests.post(
            f"{self.base_url}/request-extra-time",
            json={"minutes": minutes},
            headers=self._headers(),
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def report_wrong_block(self, subject: str) -> dict:
        resp = requests.post(
            f"{self.base_url}/report-wrong-block",
            json={"subject": subject},
            headers=self._headers(),
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()
