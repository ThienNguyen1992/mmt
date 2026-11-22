from fastapi import HTTPException, Request
from itsdangerous import BadSignature, URLSafeTimedSerializer

from app.config import settings

csrf_serializer = URLSafeTimedSerializer(settings.secret_key, salt="csrf-protection")


def generate_csrf_token(session_token: str) -> str:
    """Sinh CSRF token gắn chặt với session_token hiện tại."""
    return csrf_serializer.dumps(session_token)


def validate_csrf_value(csrf_value: str | None, session_token: str) -> bool:
    """Kiểm tra CSRF token khớp session_token và chưa quá hạn phiên."""
    if not csrf_value or not session_token:
        return False
    try:
        decoded_session = csrf_serializer.loads(
            csrf_value,
            max_age=settings.session_expire_hours * 3600,
        )
        return decoded_session == session_token
    except BadSignature:
        return False


def verify_csrf_token(
    request: Request,
    session_token: str,
    form_token: str | None = None,
) -> None:
    csrf_value = request.headers.get("X-CSRF-Token") or form_token
    if not validate_csrf_value(csrf_value, session_token):
        raise HTTPException(status_code=403, detail="CSRF token thiếu hoặc không hợp lệ")


def csrf_protect(request: Request) -> None:
    """Dependency bảo vệ mọi API ghi (POST/PUT/DELETE/PATCH) bằng header X-CSRF-Token."""
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        session_token = request.cookies.get("ogk_session")
        if not session_token:
            raise HTTPException(status_code=401, detail="Chưa đăng nhập")
        verify_csrf_token(request, session_token)
