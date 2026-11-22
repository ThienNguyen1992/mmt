from pathlib import Path

from app.models.event import Event, EventType

PRIVACY_PATH = Path(__file__).resolve().parents[2] / "PRIVACY.md"


def test_privacy_doc_matches_all_event_columns_and_9_types():
    assert PRIVACY_PATH.exists(), "Thiếu file PRIVACY.md ở thư mục gốc openguard-kids/"
    text = PRIVACY_PATH.read_text(encoding="utf-8")

    # Mọi cột trong bảng Event phải được giải thích rõ mục đích trong PRIVACY.md
    for col in Event.__table__.columns:
        assert f"events.{col.name}" in text, f"PRIVACY.md thiếu mô tả cột events.{col.name}"

    assert str(len(EventType)) in text or "9 loại" in text


def test_privacy_doc_covers_sensitive_tables_retention_and_decree_13():
    text = PRIVACY_PATH.read_text(encoding="utf-8")

    for required_token in (
        "children.name_enc",
        "devices.fingerprint_enc",
        "audit_logs",
        "enrollment_codes",
        "90 ngày",
        "AES-256-GCM",
        "Ed25519",
        "Argon2id",
        "Nghị định 13/2023",
        "TUYỆT ĐỐI KHÔNG thu thập",
        "keylogger",
        "Xóa toàn bộ dữ liệu của con tôi",
    ):
        assert required_token in text, f"PRIVACY.md thiếu nội dung bắt buộc: {required_token}"
