from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from agent.service import install_service, windows_service


def test_configure_recovery_actions_runs_sc_failure_5s_10s_30s():
    calls = []

    def fake_runner(cmd, capture_output=True, text=True, check=False):
        calls.append(cmd)
        return SimpleNamespace(returncode=0, stdout="SUCCESS", stderr="")

    install_service.configure_recovery_actions("OGKAgent", runner=fake_runner)
    assert calls[0] == [
        "sc",
        "failure",
        "OGKAgent",
        "reset=",
        "86400",
        "actions=",
        "restart/5000/restart/10000/restart/30000",
    ]
    assert calls[1] == ["sc", "failureflag", "OGKAgent", "1"]


def test_configure_recovery_actions_raises_on_sc_error():
    def failing_runner(cmd, **kwargs):
        return SimpleNamespace(returncode=5, stdout="", stderr="Access is denied")

    with pytest.raises(RuntimeError, match="sc failure"):
        install_service.configure_recovery_actions("OGKAgent", runner=failing_runner)


def test_install_and_uninstall_service_call_win32_and_recovery(monkeypatch):
    if not windows_service.HAS_PYWIN32:
        pytest.skip("pywin32 required")

    import win32serviceutil

    hcl_calls = []
    monkeypatch.setattr(
        win32serviceutil,
        "HandleCommandLine",
        lambda cls, argv: hcl_calls.append((cls._svc_name_, argv[1:])),
    )
    recovery_mock = MagicMock()
    monkeypatch.setattr(install_service, "configure_recovery_actions", recovery_mock)

    install_service.install_and_start_service()
    recovery_mock.assert_called_once_with(service_name="OGKAgent")
    assert hcl_calls[0] == ("OGKAgent", ["--startup", "auto", "install"])
    assert hcl_calls[1] == ("OGKAgent", ["start"])

    hcl_calls.clear()
    install_service.uninstall_service()
    assert hcl_calls == [("OGKAgent", ["stop"]), ("OGKAgent", ["remove"])]
