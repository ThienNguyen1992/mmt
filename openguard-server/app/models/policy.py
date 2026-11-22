from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text

from app.database import Base
from app.models.parent import gen_uuid, utc_now


class Policy(Base):
    __tablename__ = "policies"

    id = Column(String, primary_key=True, default=gen_uuid)
    device_id = Column(
        String, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True
    )
    version = Column(Integer, nullable=False)
    content_json = Column(Text, nullable=False)
    signature = Column(String, nullable=False)  # Ed25519 signature (base64)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
