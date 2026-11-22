import json
import ssl
from unittest.mock import MagicMock

from agent.core import command_listener as cl_mod
from agent.core.command_listener import CommandListener


def test_command_listener_dispatches_all_4_emergency_commands():
    events = []
    listener = CommandListener(
        "wss://127.0.0.1:8443/commands/ws/dev-1",
        token_provider=lambda: "jwt-1",
        on_lock_now=lambda cmd: events.append(("lock_now", cmd)),
        on_unlock=lambda cmd: events.append(("unlock", cmd)),
        on_add_minutes=lambda mins, cmd: events.append(("add_minutes", mins, cmd)),
        on_wipe_local_cache=lambda cmd: events.append(("wipe_local_cache", cmd)),
    )

    assert listener.dispatch_command(json.dumps({"type": "pong"})) is True
    assert listener.dispatch_command("not-json") is False
    assert listener.dispatch_command(json.dumps({"type": "unknown"})) is False

    assert listener.dispatch_command(json.dumps({"type": "lock_now"})) is True
    assert listener.dispatch_command(json.dumps({"type": "unlock"})) is True
    assert listener.dispatch_command(json.dumps({"type": "add_minutes", "minutes": 20})) is True
    assert listener.dispatch_command(json.dumps({"type": "wipe_local_cache"})) is True

    assert [item[0] for item in events] == ["lock_now", "unlock", "add_minutes", "wipe_local_cache"]
    assert events[2][1] == 20


def test_command_listener_sslopt_enforces_tls12_and_handles_4401_refresh(tmp_path):
    ca_file = tmp_path / "ca.crt"
    ca_file.write_text("", encoding="utf-8")

    # Test wss:// builds TLS 1.2+ sslopt without loading an invalid cert
    listener_wss = CommandListener(
        "wss://127.0.0.1:8443/commands/ws/dev-1",
        token_provider=lambda: "tok",
    )
    sslopt = listener_wss._build_sslopt()
    assert sslopt is not None
    assert sslopt["cert_reqs"] == ssl.CERT_REQUIRED
    assert sslopt["context"].minimum_version == ssl.TLSVersion.TLSv1_2

    # Test 4401 triggers refresh_token_fn and resets backoff
    refreshed = []
    listener = CommandListener(
        "ws://127.0.0.1:8000/commands/ws/dev-1",
        token_provider=lambda: "old-jwt",
        refresh_token_fn=lambda: refreshed.append("refreshed") or "new-jwt",
        initial_backoff_sec=2.0,
        max_backoff_sec=16.0,
    )
    d1 = listener.handle_disconnect(1006)
    d2 = listener.handle_disconnect(1006)
    assert 2.0 <= d1 <= 2.4
    assert 4.0 <= d2 <= 4.8

    d4401 = listener.handle_disconnect(4401)
    assert refreshed == ["refreshed"]
    assert d4401 == 0.1
    assert listener._backoff == 2.0


def test_command_listener_passes_bearer_header_and_keepalive_to_ws(monkeypatch):
    captured = {}

    class _FakeWSApp:
        def __init__(self, url, header=None, **callbacks):
            captured["url"] = url
            captured["header"] = header
            captured["callbacks"] = callbacks

        def run_forever(self, **kwargs):
            captured["run_kwargs"] = kwargs
            callbacks = captured["callbacks"]
            callbacks["on_close"](self, 1000, "done")

        def close(self):
            pass

    monkeypatch.setattr(cl_mod.websocket, "WebSocketApp", _FakeWSApp)

    listener = CommandListener(
        "wss://127.0.0.1:8443/commands/ws/dev-032",
        token_provider=lambda: "my-jwt-token",
        expected_fingerprint="aa" * 32,
        ping_interval=25,
        ping_timeout=10,
    )
    listener._build_sslopt = MagicMock(return_value={"cert_reqs": ssl.CERT_REQUIRED})

    close_code = listener.connect_once()
    assert close_code == 1000
    assert captured["url"] == "wss://127.0.0.1:8443/commands/ws/dev-032"
    assert captured["header"] == ["Authorization: Bearer my-jwt-token"]
    assert captured["run_kwargs"]["ping_interval"] == 25
    assert captured["run_kwargs"]["ping_timeout"] == 10
