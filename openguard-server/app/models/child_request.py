from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text

from app.database import Base
from app.models.parent import gen_uuid, utc_now


class ChildRequest(Base):
    """NT3: Lưu yêu cầu của trẻ ('Xin thêm giờ' / 'Báo chặn nhầm') và phản hồi phụ huynh."""

    __tablename__ = "child_requests"

    id = Column(String, primary_key=True, default=gen_uuid)
    child_id = Column(
        String, ForeignKey("children.id", ondelete="CASCADE"), nullable=False, index=True
    )
    device_id = Column(String, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    request_type = Column(String, nullable=False)  # "extra_time" | "wrong_block"
    subject = Column(String, nullable=False)  # vd "extra_time_15min" hoặc domain "hocmai.vn"
    requested_minutes = Column(Integer, nullable=True)
    # "pending" | "approved" | "rejected"
    status = Column(String, default="pending", nullable=False)
    parent_note = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    responded_at = Column(DateTime(timezone=True), nullable=True)
