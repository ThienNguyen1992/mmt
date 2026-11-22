from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String
from sqlalchemy.orm import relationship

from app.core.crypto import decrypt_aes_gcm, encrypt_aes_gcm
from app.database import Base
from app.models.parent import gen_uuid, utc_now


class Device(Base):
    __tablename__ = "devices"

    id = Column(String, primary_key=True, default=gen_uuid)
    child_id = Column(
        String, ForeignKey("children.id", ondelete="CASCADE"), nullable=False, index=True
    )
    fingerprint_enc = Column(String, nullable=False)  # AES-GCM mã hóa hardware fingerprint
    device_secret_hash = Column(String, nullable=True)  # SHA-256 bí mật thiết bị
    name = Column(String, nullable=False, default="Thiết bị Windows")
    is_active = Column(Boolean, default=True, nullable=False)
    last_seen_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    child = relationship("Child", back_populates="devices")

    @property
    def fingerprint(self) -> str:
        try:
            return decrypt_aes_gcm(self.fingerprint_enc)
        except Exception:
            return self.fingerprint_enc

    @fingerprint.setter
    def fingerprint(self, plain: str) -> None:
        self.fingerprint_enc = encrypt_aes_gcm(plain)
