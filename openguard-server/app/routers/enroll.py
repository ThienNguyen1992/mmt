import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.config import settings
from app.core.crypto import hash_device_secret
from app.core.csrf import csrf_protect
from app.core.deps import get_current_parent
from app.core.rate_limit import limiter
from app.core.security import (
    generate_device_access_token,
    generate_enrollment_code,
    generate_refresh_token_raw,
    get_policy_keys,
    hash_refresh_token,
)
from app.database import get_db
from app.models.audit import AuditLog
from app.models.child import Child
from app.models.device import Device
from app.models.enrollment import EnrollmentCode
from app.models.misc import RefreshToken
from app.models.parent import Parent
from app.schemas.enroll import (
    CreateEnrollmentCodeRequest,
    CreateEnrollmentCodeResponse,
    EnrollDeviceRequest,
    EnrollDeviceResponse,
    RefreshTokenRequest,
    RefreshTokenResponse,
)

router = APIRouter(prefix="/enroll", tags=["enroll"])


def _as_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


@router.post(
    "/create-code",
    response_model=CreateEnrollmentCodeResponse,
    dependencies=[Depends(csrf_protect)],
)
@limiter.limit("10/minute")
def create_enrollment_code(
    request: Request,
    payload: CreateEnrollmentCodeRequest,
    db: Session = Depends(get_db),
    parent: Parent = Depends(get_current_parent),
):
    if not payload.consent_confirmed:
        raise HTTPException(
            status_code=422,
            detail="Cần xác nhận sự đồng ý của phụ huynh (Nghị định 13/2023)",
        )

    child = (
        db.query(Child).filter(Child.id == payload.child_id, Child.parent_id == parent.id).first()
    )
    if not child:
        raise HTTPException(status_code=404, detail="Không tìm thấy hồ sơ trẻ thuộc tài khoản này")

    while True:
        code = generate_enrollment_code()
        exists = (
            db.query(EnrollmentCode.id)
            .filter(EnrollmentCode.code == code, EnrollmentCode.used == False)  # noqa: E712
            .first()
        )
        if not exists:
            break

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=settings.enrollment_code_expire_minutes)
    ip = request.client.host if request.client else "unknown"
    db.add(
        EnrollmentCode(
            code=code,
            parent_id=parent.id,
            child_id=child.id,
            consent_confirmed=True,
            consent_ip=ip,
            expires_at=expires_at,
        )
    )
    db.add(
        AuditLog(
            parent_id=parent.id,
            child_id=child.id,
            actor_role=parent.role,
            action="create_enrollment_code",
            ip_address=ip,
            new_value=f"code={code[:2]}******",
        )
    )
    db.commit()
    return CreateEnrollmentCodeResponse(code=code, expires_at=expires_at.isoformat())


@router.post("/device", response_model=EnrollDeviceResponse)
@limiter.limit("10/minute")
def enroll_device(
    request: Request,
    payload: EnrollDeviceRequest,
    db: Session = Depends(get_db),
):
    enrollment = (
        db.query(EnrollmentCode).filter(EnrollmentCode.code == payload.code.strip().upper()).first()
    )
    if not enrollment:
        raise HTTPException(status_code=404, detail="Mã ghép đôi không tồn tại")
    if enrollment.used:
        raise HTTPException(status_code=410, detail="Mã ghép đôi đã được sử dụng")

    now = datetime.now(timezone.utc)
    if _as_utc(enrollment.expires_at) < now:
        raise HTTPException(status_code=410, detail="Mã ghép đôi đã hết hạn")

    raw_device_secret = secrets.token_urlsafe(32)
    device = Device(
        child_id=enrollment.child_id,
        device_secret_hash=hash_device_secret(raw_device_secret),
        name=payload.device_name or "Thiết bị Windows",
    )
    device.fingerprint = payload.fingerprint
    db.add(device)
    db.flush()

    enrollment.used = True
    enrollment.used_at = now

    access_token = generate_device_access_token(device.id)
    refresh_raw = generate_refresh_token_raw()
    db.add(
        RefreshToken(
            device_id=device.id,
            token_hash=hash_refresh_token(refresh_raw),
            expires_at=now + timedelta(days=settings.refresh_token_expire_days),
        )
    )
    db.commit()

    _, pub_pem = get_policy_keys()
    return EnrollDeviceResponse(
        device_id=device.id,
        child_id=enrollment.child_id,
        access_token=access_token,
        refresh_token=refresh_raw,
        policy_public_key_pem=pub_pem.decode("ascii"),
    )


@router.post("/refresh", response_model=RefreshTokenResponse)
@limiter.limit("20/minute")
def refresh_access_token(
    request: Request,
    payload: RefreshTokenRequest,
    db: Session = Depends(get_db),
):
    token_hash = hash_refresh_token(payload.refresh_token)
    db_refresh = (
        db.query(RefreshToken)
        .filter(
            RefreshToken.token_hash == token_hash,
            RefreshToken.revoked == False,  # noqa: E712
        )
        .first()
    )
    if not db_refresh or _as_utc(db_refresh.expires_at) < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Refresh token không hợp lệ hoặc hết hạn")

    device = (
        db.query(Device)
        .filter(Device.id == db_refresh.device_id, Device.is_active == True)  # noqa: E712
        .first()
    )
    if not device:
        raise HTTPException(status_code=401, detail="Thiết bị đã bị gỡ")

    return RefreshTokenResponse(access_token=generate_device_access_token(device.id))


@router.post("/revoke/{device_id}", dependencies=[Depends(csrf_protect)])
def revoke_device(
    device_id: str,
    request: Request,
    db: Session = Depends(get_db),
    parent: Parent = Depends(get_current_parent),
):
    device = (
        db.query(Device)
        .join(Child)
        .filter(Device.id == device_id, Child.parent_id == parent.id)
        .first()
    )
    if not device:
        raise HTTPException(status_code=404, detail="Không tìm thấy thiết bị")

    db.query(RefreshToken).filter(RefreshToken.device_id == device_id).update({"revoked": True})
    device.is_active = False

    ip = request.client.host if request.client else "unknown"
    db.add(
        AuditLog(
            parent_id=parent.id,
            child_id=device.child_id,
            actor_role=parent.role,
            action="revoke_device",
            ip_address=ip,
            new_value=f"device_id={device_id}",
        )
    )
    db.commit()
    return {"message": "Đã gỡ thiết bị và thu hồi toàn bộ token"}
