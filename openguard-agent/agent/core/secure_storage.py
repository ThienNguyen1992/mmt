import base64

try:
    import win32crypt

    HAS_WIN32CRYPT = True
except ImportError:
    win32crypt = None
    HAS_WIN32CRYPT = False

CRYPTPROTECT_UI_FORBIDDEN = 0x1
CRYPTPROTECT_LOCAL_MACHINE = 0x4


def protect_secret(plaintext: str, description: str = "OpenGuardKids Secret") -> str:
    """Mã hóa secret bằng Windows DPAPI (CRYPTPROTECT_LOCAL_MACHINE), trả về Base64."""
    if not HAS_WIN32CRYPT:
        raise RuntimeError("win32crypt (DPAPI) chỉ khả dụng trên Windows")
    raw = plaintext.encode("utf-8")
    blob = win32crypt.CryptProtectData(
        raw,
        description,
        None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE,
    )
    return base64.b64encode(blob).decode("ascii")


def unprotect_secret(token_b64: str) -> str:
    """Giải mã chuỗi Base64 DPAPI về plaintext."""
    if not HAS_WIN32CRYPT:
        raise RuntimeError("win32crypt (DPAPI) chỉ khả dụng trên Windows")
    blob = base64.b64decode(token_b64.encode("ascii"))
    _descr, raw = win32crypt.CryptUnprotectData(
        blob,
        None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
    )
    return raw.decode("utf-8")
