import sys
import time

from agent.core.logger import get_logger
from agent.service.agent_runtime import AgentRuntime

logger = get_logger("windows_service")

try:
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil

    HAS_PYWIN32 = True
except ImportError:
    HAS_PYWIN32 = False


if HAS_PYWIN32:

    class OGKAgentService(win32serviceutil.ServiceFramework):
        _svc_name_ = "OGKAgent"
        _svc_display_name_ = "OpenGuard Kids Agent Service"
        _svc_description_ = (
            "Dịch vụ đồng hành bảo vệ và quản lý thời gian sử dụng máy tính cho trẻ em."
        )

        def __init__(self, args):
            super().__init__(args)
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
            self.runtime: AgentRuntime | None = None

        def SvcStop(self):  # noqa: N802
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            if self.runtime is not None:
                self.runtime.stop()
            win32event.SetEvent(self.hWaitStop)

        def SvcDoRun(self):  # noqa: N802
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            self.runtime = AgentRuntime()
            self.runtime.start()
            win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)
            self.runtime.stop()

else:

    class OGKAgentService:  # pragma: no cover - fallback ngoài Windows
        _svc_name_ = "OGKAgent"
        _svc_display_name_ = "OpenGuard Kids Agent Service"


def run_console() -> None:
    runtime = AgentRuntime()
    runtime.start()
    logger.info("OGKAgent đang chạy ở chế độ console. Nhấn Ctrl+C để dừng.")
    try:
        while not runtime.wait(timeout=1.0):
            time.sleep(0.1)
    except KeyboardInterrupt:
        logger.info("Nhận tín hiệu Ctrl+C, đang dừng OGKAgent...")
    finally:
        runtime.stop()


def _handle_setup_acl() -> None:
    from agent.core.acl_hardening import harden_agent_directories

    harden_agent_directories()


def _handle_install() -> None:
    from agent.service.install_service import install_and_start_service

    install_and_start_service()


def _handle_uninstall() -> None:
    from agent.service.install_service import uninstall_service

    uninstall_service()


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)

    if "--setup-acl" in args:
        _handle_setup_acl()
        return 0
    if "--install" in args:
        _handle_install()
        return 0
    if "--uninstall" in args:
        _handle_uninstall()
        return 0
    if args == ["console"]:
        run_console()
        return 0

    if not HAS_PYWIN32:
        logger.error("pywin32 không khả dụng trên hệ điều hành này; dùng chế độ 'console'.")
        return 1

    if not args:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(OGKAgentService)
        servicemanager.StartServiceCtrlDispatcher()
        return 0

    win32serviceutil.HandleCommandLine(OGKAgentService, argv=[sys.argv[0], *args])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
