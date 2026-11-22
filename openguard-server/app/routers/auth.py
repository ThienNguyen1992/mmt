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


@router.post("/login")
def login(
    request: Request,
    payload: LoginRequest,
    response: Response,
    db: Session = Depends(get_db),
):
    now = datetime.now(timezone.utc)
    parent = db.query(Parent).filter(Parent.email == payload.email).first()
    if not parent or not verify_password(payload.password, parent.password_hash):
        raise HTTPException(status_code=401, detail="Email hoặc mật khẩu không đúng")

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
def create_child_view_session(
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
