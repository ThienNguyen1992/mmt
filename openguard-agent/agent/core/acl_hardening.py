import ctypes
import os
import sys

from agent.core import config as agent_config
from agent.core.logger import get_logger

logger = get_logger("acl_hardening")

SID_SYSTEM = "S-1-5-18"
SID_ADMINISTRATORS = "S-1-5-32-544"
SID_USERS = "S-1-5-32-545"

try:
    import ntsecuritycon as con
    import win32security

    HAS_WIN32_SECURITY = True
    INHERIT_ALL = con.OBJECT_INHERIT_ACE | con.CONTAINER_INHERIT_ACE
except ImportError:
    HAS_WIN32_SECURITY = False
    con = None
    win32security = None
    INHERIT_ALL = 0


def is_running_as_admin() -> bool:
    """Kiểm tra tiến trình hiện tại có quyền Administrator/SYSTEM trên Windows không."""
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def build_directory_dacl(allow_users_read: bool):
    """Tạo Win32 DACL: SYSTEM & Administrators Full Control; Users chỉ Read khi được phép."""
    if not HAS_WIN32_SECURITY:
        raise RuntimeError("win32security chỉ khả dụng trên Windows")

    dacl = win32security.ACL()
    for sid_str in (SID_SYSTEM, SID_ADMINISTRATORS):
        dacl.AddAccessAllowedAceEx(
            win32security.ACL_REVISION_DS,
            INHERIT_ALL,
            con.FILE_ALL_ACCESS,
            win32security.ConvertStringSidToSid(sid_str),
        )
    if allow_users_read:
        dacl.AddAccessAllowedAceEx(
            win32security.ACL_REVISION_DS,
            INHERIT_ALL,
            con.FILE_GENERIC_READ | con.FILE_GENERIC_EXECUTE,
            win32security.ConvertStringSidToSid(SID_USERS),
        )
    return dacl


def _apply_dacl(path: str, allow_users_read: bool) -> None:
    if not os.path.isdir(path):
        raise FileNotFoundError(f"Không tìm thấy thư mục: {path}")
    dacl = build_directory_dacl(allow_users_read=allow_users_read)
    win32security.SetNamedSecurityInfo(
        path,
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        None,
        None,
        dacl,
        None,
    )


def harden_agent_directories() -> None:
    """Siết ACL tách biệt DATA_DIR (chỉ SYSTEM/Admin) và IPC_DIR (Users chỉ đọc)."""
    agent_config.ensure_app_data_dir()
    if not is_running_as_admin():
        raise PermissionError(
            "Cần quyền Administrator/SYSTEM để siết ACL DATA_DIR (tránh tự khóa tiến trình dev)"
        )
    _apply_dacl(agent_config.DATA_DIR, allow_users_read=False)
    _apply_dacl(agent_config.IPC_DIR, allow_users_read=True)
    logger.info("Đã siết ACL tách biệt DATA_DIR (private) và IPC_DIR (Users=RX)")
