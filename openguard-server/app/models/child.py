from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from app.core.crypto import decrypt_aes_gcm, encrypt_aes_gcm
from app.database import Base
from app.models.parent import gen_uuid, utc_now


class Child(Base):
    __tablename__ = "children"

    id = Column(String, primary_key=True, default=gen_uuid)
    parent_id = Column(
        String, ForeignKey("parents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name_enc = Column(String, nullable=False)  # AES-GCM mã hóa tên trẻ (F5)
    birth_year = Column(Integer, nullable=True)
    age_group = Column(String, default="6-11", nullable=False)  # chính sách mặc định 6-11 tuổi
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    devices = relationship("Device", back_populates="child", cascade="all, delete-orphan")

    @property
    def name(self) -> str:
        try:
            return decrypt_aes_gcm(self.name_enc)
        except Exception:
            return self.name_enc

    @name.setter
    def name(self, plain: str) -> None:
        self.name_enc = encrypt_aes_gcm(plain)
