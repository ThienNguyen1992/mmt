from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from app.config import settings
from app.core.deps import get_current_parent
from app.core.rate_limit import limiter
from app.core.security import generate_session_token, hash_password, verify_password
from app.database import get_db
from app.models.child import Child
from app.models.misc import Session as SessionModel
from app.models.parent import Parent
from app.schemas.auth import (
    ChildViewLoginRequest,
    LoginRequest,
    RegisterRequest,
    RegisterResponse,
)

router = APIRouter(prefix="/auth", tags=["auth"])


def _set_session_cookie(response: Response, session_token: str) -> None:
    response.set_cookie(
        key="ogk_session",
        value=session_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        max_age=settings.session_expire_hours * 3600,
    )


@router.post("/register", response_model=RegisterResponse, status_code=201)
@limiter.limit("5/minute")
def register(request: Request, payload: RegisterRequest, db: Session = Depends(get_db)):
    existing = db.query(Parent).filter(Parent.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=409, detail="Email đã được đăng ký")

    parent = Parent(
        email=payload.email,
        password_hash=hash_password(payload.password),
        role="parent",
    )
    db.add(parent)
    db.commit()
    db.refresh(parent)
    return RegisterResponse(id=parent.id, email=parent.email, role=parent.role)


def _as_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _register_failed_attempt(parent: Parent, db: Session) -> None:
    parent.failed_login_count = (parent.failed_login_count or 0) + 1
    if parent.failed_login_count >= settings.login_max_attempts:
        parent.locked_until = datetime.now(timezone.utc) + timedelta(
            minutes=settings.login_lockout_minutes
        )
    db.commit()


@router.post("/login")
@limiter.limit("10/minute")
def login(
    request: Request,
    payload: LoginRequest,
    response: Response,
    db: Session = Depends(get_db),
):
    now = datetime.now(timezone.utc)
    parent = db.query(Parent).filter(Parent.email == payload.email).first()

    locked_until = _as_utc(parent.locked_until) if parent else None
    if parent and locked_until and locked_until > now:
        remaining = int((locked_until - now).total_seconds() // 60) + 1
        raise HTTPException(
            status_code=423,
            detail=f"Tài khoản đang bị khóa tạm thời. Thử lại sau {remaining} phút.",
        )

    if not parent or not verify_password(payload.password, parent.password_hash):
        if parent:
            _register_failed_attempt(parent, db)
        raise HTTPException(status_code=401, detail="Email hoặc mật khẩu không đúng")

    parent.failed_login_count = 0
    parent.locked_until = None
    db.commit()

    session_token = generate_session_token()
    expires_at = now + timedelta(hours=settings.session_expire_hours)
    db.add(
        SessionModel(
            parent_id=parent.id,
            role=parent.role,
            session_token=session_token,
            expires_at=expires_at,
        )
    )
    db.commit()

    _set_session_cookie(response, session_token)
    return {
        "message": "Đăng nhập thành công",
        "parent_id": parent.id,
        "role": parent.role,
    }


@router.post("/child-view")
@limiter.limit("10/minute")
def create_child_view_session(
    request: Request,
    payload: ChildViewLoginRequest,
    response: Response,
    db: Session = Depends(get_db),
    parent: Parent = Depends(get_current_parent),
):
    child = (
        db.query(Child).filter(Child.id == payload.child_id, Child.parent_id == parent.id).first()
    )
    if not child:
        raise HTTPException(status_code=404, detail="Không tìm thấy hồ sơ trẻ")

    token = generate_session_token()
    expires_at = datetime.now(timezone.utc) + timedelta(hours=settings.session_expire_hours)
    db.add(
        SessionModel(
            parent_id=parent.id,
            child_id=child.id,
            role="child-view",
            session_token=token,
            expires_at=expires_at,
        )
    )
    db.commit()

    _set_session_cookie(response, token)
    return {
        "message": "Đã bật chế độ xem cho trẻ",
        "role": "child-view",
        "child_id": child.id,
    }
