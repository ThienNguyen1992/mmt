import enum

from sqlalchemy import Column, DateTime, Enum, ForeignKey, Integer, String

from app.database import Base
from app.models.parent import gen_uuid, utc_now


class EventType(str, enum.Enum):
    app_start = "app_start"
    app_stop = "app_stop"
    domain_query = "domain_query"
    blocked_app = "blocked_app"
    blocked_domain = "blocked_domain"
    quota_warning = "quota_warning"
    locked = "locked"
    unlock_request = "unlock_request"
    override_granted = "override_granted"


class Event(Base):
    __tablename__ = "events"

    id = Column(String, primary_key=True, default=gen_uuid)
    # Kỹ thuật chống đếm trùng khi Agent retry batch sync (E3/E4)
    idempotency_key = Column(String, unique=True, nullable=False, index=True)

    # Đúng 7 trường nghiệp vụ bắt buộc theo đề bài F3 / NT2:
    ts = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    device_id = Column(
        String, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True
    )
    child_id = Column(
        String, ForeignKey("children.id", ondelete="CASCADE"), nullable=False, index=True
    )
    type = Column(Enum(EventType), nullable=False, index=True)
    subject = Column(String(255), nullable=True)  # tên app hoặc tên miền cấp hai (eTLD+1)
    duration_sec = Column(Integer, default=0, nullable=False)
    policy_id = Column(String, nullable=True)
