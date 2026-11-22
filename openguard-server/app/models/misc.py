from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String

from app.database import Base
from app.models.parent import gen_uuid, utc_now


class Session(Base):
    __tablename__ = "sessions"

    id = Column(String, primary_key=True, default=gen_uuid)
    parent_id = Column(String, ForeignKey("parents.id", ondelete="CASCADE"), nullable=False)
    child_id = Column(
        String, ForeignKey("children.id", ondelete="CASCADE"), nullable=True
    )  # dùng cho role="child-view"
    role = Column(String, default="parent", nullable=False)  # "parent" | "child-view" | "admin"
    session_token = Column(String, unique=True, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(String, primary_key=True, default=gen_uuid)
    device_id = Column(
        String, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash = Column(String, unique=True, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
