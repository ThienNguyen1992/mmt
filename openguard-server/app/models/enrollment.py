from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String

from app.database import Base
from app.models.parent import gen_uuid, utc_now


class EnrollmentCode(Base):
    """Điểm ghi nhận sự đồng ý của phụ huynh khi gắn thiết bị (Nghị định 13/2023)."""

    __tablename__ = "enrollment_codes"

    id = Column(String, primary_key=True, default=gen_uuid)
    code = Column(String(8), unique=True, nullable=False, index=True)
    parent_id = Column(String, ForeignKey("parents.id", ondelete="CASCADE"), nullable=False)
    child_id = Column(String, ForeignKey("children.id", ondelete="CASCADE"), nullable=False)
    consent_confirmed = Column(Boolean, default=True, nullable=False)
    consent_ip = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used = Column(Boolean, default=False, nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
