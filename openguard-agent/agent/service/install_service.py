import subprocess
import sys

from agent.core.logger import get_logger

logger = get_logger("install_service")
SERVICE_NAME = "OGKAgent"


def configure_recovery_actions(
    service_name: str = SERVICE_NAME,
    runner=subprocess.run,
) -> None:
    """Cấu hình SCM tự khởi động lại service (5s / 10s / 30s) khi tiến trình bị kill."""
    cmd_failure = [
        "sc",
        "failure",
        service_name,
        "reset=",
        "86400",
        "actions=",
        "restart/5000/restart/10000/restart/30000",
    ]
    res = runner(cmd_failure, capture_output=True, text=True, check=False)
    if res.returncode != 0:
        raise RuntimeError(f"sc failure thất bại ({res.returncode}): {res.stderr or res.stdout}")

    cmd_flag = ["sc", "failureflag", service_name, "1"]
    flag_res = runner(cmd_flag, capture_output=True, text=True, check=False)
    if flag_res.returncode != 0:
        logger.warning("sc failureflag trả về %s: %s", flag_res.returncode, flag_res.stderr)

    logger.info("Đã cấu hình Service Recovery 5s/10s/30s cho %s", service_name)


def install_and_start_service(service_name: str = SERVICE_NAME) -> None:
    """Cài đặt OGKAgent dưới LocalSystem, gắn SCM recovery và khởi chạy."""
    import win32serviceutil

    from agent.service.windows_service import OGKAgentService

    win32serviceutil.HandleCommandLine(
        OGKAgentService,
        argv=[sys.argv[0], "--startup", "auto", "install"],
    )
    configure_recovery_actions(service_name=service_name)
    win32serviceutil.HandleCommandLine(
        OGKAgentService,
        argv=[sys.argv[0], "start"],
    )


def uninstall_service(service_name: str = SERVICE_NAME) -> None:
    """Dừng và gỡ cài đặt service bằng quyền Admin bình thường."""
    import win32serviceutil

    from agent.service.windows_service import OGKAgentService

    try:
        win32serviceutil.HandleCommandLine(
            OGKAgentService,
            argv=[sys.argv[0], "stop"],
        )
    except Exception as exc:
        logger.info("Service %s không đang chạy khi stop: %s", service_name, exc)

    win32serviceutil.HandleCommandLine(
        OGKAgentService,
        argv=[sys.argv[0], "remove"],
    )
