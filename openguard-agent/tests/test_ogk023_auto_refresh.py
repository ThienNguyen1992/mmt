import threading
import time
from concurrent.futures import ThreadPoolExecutor

from agent.core import config as agent_config
from agent.core import sync_client


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict):
        self.status_code = status_code
        self._payload = payload

    def json(self) -> dict:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _FakeSession:
    def __init__(self):
        self.refresh_calls = 0
        self.counter_lock = threading.Lock()
        self.valid_token = "fresh-jwt-token"

    def post(self, url: str, json: dict | None = None, headers: dict | None = None, timeout=10):
        if url.endswith("/enroll/refresh"):
            time.sleep(0.05)  # force overlap window if lock were missing
            with self.counter_lock:
                self.refresh_calls += 1
                return _FakeResponse(
                    200, {"access_token": f"{self.valid_token}-{self.refresh_calls}"}
                )

        auth = (headers or {}).get("Authorization", "")
        if auth.startswith(f"Bearer {self.valid_token}"):
            return _FakeResponse(200, {"ok": True})
        return _FakeResponse(401, {"detail": "expired"})


def test_call_with_auto_refresh_thread_safe_under_concurrent_workers(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_config, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(agent_config, "IPC_DIR", str(tmp_path / "ipc"))
    agent_config.save_config(
        {
            "device_id": "dev-1",
            "child_id": "child-1",
            "access_token": "expired-jwt",
            "refresh_token": "raw-refresh",
            "enrolled": True,
        }
    )

    fake_session = _FakeSession()

    def worker_call():
        return sync_client.call_with_auto_refresh(
            "post",
            "https://127.0.0.1:8443/events/batch",
            "https://127.0.0.1:8443",
            session=fake_session,
            json={"events": []},
        )

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = [fut.result() for fut in [pool.submit(worker_call) for _ in range(4)]]

    assert all(r.status_code == 200 for r in results)
    assert fake_session.refresh_calls == 1
    assert agent_config.load_config()["access_token"] == "fresh-jwt-token-1"
