from fastapi import Depends, Header, HTTPException
from jwt import PyJWTError
from sqlalchemy.orm import Session

from app.core.security import decode_access_token
from app.database import get_db
from app.models.device import Device


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
