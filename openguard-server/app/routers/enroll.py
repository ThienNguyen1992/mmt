from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.config import settings
from app.core.csrf import csrf_protect
from app.core.deps import get_current_parent
from app.core.rate_limit import limiter
from app.core.security import generate_enrollment_code
from app.database import get_db
from app.models.audit import AuditLog
from app.models.child import Child
from app.models.enrollment import EnrollmentCode
from app.models.parent import Parent
from app.schemas.enroll import CreateEnrollmentCodeRequest, CreateEnrollmentCodeResponse

router = APIRouter(prefix="/enroll", tags=["enroll"])


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
