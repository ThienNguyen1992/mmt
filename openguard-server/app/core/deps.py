from datetime import datetime, timezone

from fastapi import Depends, Header, HTTPException, Request
from jwt import PyJWTError
from sqlalchemy.orm import Session

from app.core.security import decode_access_token
from app.database import get_db
from app.models.device import Device
from app.models.misc import Session as SessionModel
from app.models.parent import Parent


def _as_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def get_current_session(request: Request, db: Session = Depends(get_db)) -> SessionModel:
    """Lấy session hợp lệ từ cookie ogk_session (chưa revoked và chưa hết hạn)."""
    token = request.cookies.get("ogk_session")
    if not token:
        raise HTTPException(status_code=401, detail="Chưa đăng nhập")

    db_session = (
        db.query(SessionModel)
        .filter(
            SessionModel.session_token == token,
            SessionModel.revoked == False,  # noqa: E712
        )
        .first()
    )
    if not db_session or _as_utc(db_session.expires_at) < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Phiên đăng nhập đã hết hạn")
    return db_session


def get_current_parent(
    db_session: SessionModel = Depends(get_current_session),
    db: Session = Depends(get_db),
) -> Parent:
    """Chỉ cho phép vai trò parent hoặc admin — chặn child-view thao tác ghi/quản trị."""
    if db_session.role not in ("parent", "admin"):
        raise HTTPException(status_code=403, detail="Vai trò child-view chỉ có quyền xem")
    parent = db.query(Parent).filter(Parent.id == db_session.parent_id).first()
    if not parent:
        raise HTTPException(status_code=401, detail="Tài khoản không tồn tại")
    return parent


def get_current_admin(parent: Parent = Depends(get_current_parent)) -> Parent:
    """Chỉ cho phép vai trò admin."""
    if parent.role != "admin":
        raise HTTPException(status_code=403, detail="Yêu cầu quyền admin")
    return parent


def get_current_viewer(
    db_session: SessionModel = Depends(get_current_session),
) -> SessionModel:
    """Cho phép parent, admin hoặc child-view (trả về SessionModel để kiểm tra child_id)."""
    if db_session.role not in ("parent", "child-view", "admin"):
        raise HTTPException(status_code=403, detail="Không có quyền truy cập")
    return db_session


def get_current_device(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> Device:
    """Xác thực thiết bị Agent qua Bearer JWT và kiểm tra thiết bị còn active."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Thiếu access token")
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=401, detail="Thiếu access token")
    try:
        payload = decode_access_token(token)
    except PyJWTError as exc:
        raise HTTPException(
            status_code=401, detail="Access token không hợp lệ hoặc hết hạn"
        ) from exc

    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Loại token không hợp lệ")

    device_id = payload.get("sub")
    if not device_id:
        raise HTTPException(status_code=401, detail="Access token thiếu định danh thiết bị")

    device = (
        db.query(Device)
        .filter(Device.id == device_id, Device.is_active == True)  # noqa: E712
        .first()
    )
    if not device:
        raise HTTPException(status_code=401, detail="Thiết bị không tồn tại hoặc đã bị gỡ")
    return device
