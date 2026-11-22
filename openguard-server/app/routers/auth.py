from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.rate_limit import limiter
from app.core.security import hash_password
from app.database import get_db
from app.models.parent import Parent
from app.schemas.auth import RegisterRequest, RegisterResponse

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=RegisterResponse, status_code=201)
@limiter.limit("5/minute")
def register(request: Request, payload: RegisterRequest, db: Session = Depends(get_db)):
    existing = db.query(Parent).filter(Parent.email == payload.email).first()
    print()
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
