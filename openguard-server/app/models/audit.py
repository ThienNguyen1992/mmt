from sqlalchemy import Column, DateTime, ForeignKey, String, Text

from app.database import Base
from app.models.parent import gen_uuid, utc_now


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True, default=gen_uuid)
    parent_id = Column(
        String, ForeignKey("parents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    child_id = Column(
        String, ForeignKey("children.id", ondelete="SET NULL"), nullable=True, index=True
    )
    actor_role = Column(String, default="parent", nullable=False)
    action = Column(String, nullable=False, index=True)
    ip_address = Column(String, nullable=False)
    old_value = Column(Text, nullable=True)
    new_value = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
