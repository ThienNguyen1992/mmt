import base64
import binascii
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

SERVER_BASE_DIR = Path(__file__).resolve().parents[1]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(SERVER_BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- 1. Cấu hình Môi trường & Mạng ---
    # Môi trường triển khai: 'dev' (local), 'lab' (thực nghiệm môn mạng), 'prod' (production)
    app_env: Literal["dev", "lab", "prod"] = "dev"

    # Địa chỉ IP server lắng nghe: '0.0.0.0' để nhận kết nối từ mọi card mạng (kể cả WSL / LAN)
    server_host: str = "0.0.0.0"

    # Cổng dịch vụ HTTPS của Server (8443 theo chuẩn mạng của dự án, hoặc 8000 khi dev HTTP)
    server_port: int = 8443

    # Danh sách URL frontend được phép gọi API (chống tấn công Cross-Origin / CSRF)
    cors_origins: str = "https://localhost:8443,https://127.0.0.1:8443"

    # --- 2. Cơ sở dữ liệu ---
    # Chuỗi kết nối SQLite lưu tại thư mục dùng chung openguard-kids/openguard.db
    database_url: str = "sqlite:///../openguard.db"

    # --- 3. Khóa Mật mã & Bảo mật Dữ liệu (F5) ---
    # Khóa bí mật dùng để ký và xác thực JWT token (Access Token, Refresh Token, CSRF token)
    secret_key: str = "dev-only-override-in-env-32bytes-min"

    # Khóa đối xứng 256-bit (Base64) dùng mã hóa AES-GCM dữ liệu nhạy cảm (tên trẻ, fingerprint)
    aes_gcm_key_b64: str = ""

    # Chuỗi bí mật thêm vào (pepper) trước khi băm SHA-256 mã bí mật thiết bị (chống Rainbow Table)
    device_secret_pepper: str = ""

    # --- 4. Chữ ký số Ed25519 & Chứng chỉ TLS/HTTPS ---
    # Private Key Ed25519 (chỉ Server giữ) dùng để ký chữ ký số lên các chính sách quản lý (Policy)
    policy_signing_private_key_pem_path: str = "./certs/policy_ed25519_private.pem"

    # Public Key Ed25519 (gửi cho Agent) để Agent kiểm tra tính toàn vẹn của Policy
    policy_signing_public_key_pem_path: str = "./certs/policy_ed25519_public.pem"

    # Đường dẫn chứng chỉ SSL/TLS server (chạy HTTPS 1.2+ mã hóa toàn bộ dữ liệu trên mạng)
    tls_cert_path: str = "./certs/server.crt"

    # Đường dẫn khóa bí mật SSL/TLS server
    tls_key_path: str = "./certs/server.key"

    # --- 5. Thời hạn Phiên Đăng nhập & Mã Ghép nối ---
    # Thời gian hết hạn của Access Token JWT (ngắn 15 phút để tăng tính an toàn)
    access_token_expire_minutes: int = 15

    # Thời gian hiệu lực của Refresh Token để cấp lại Access Token mới (mặc định 30 ngày)
    refresh_token_expire_days: int = 30

    # Thời hạn phiên đăng nhập Web Dashboard của phụ huynh (12 tiếng)
    session_expire_hours: int = 12

    # Thời gian sống của mã ghép nối thiết bị 6 số (chỉ có hiệu lực 10 phút để tránh bị dùng trộm)
    enrollment_code_expire_minutes: int = 10

    # --- 6. Chống Tấn công Dò Mật khẩu (Brute-force) ---
    # Số lần đăng nhập sai mật khẩu tối đa liên tiếp cho phép
    login_max_attempts: int = 5

    # Thời gian tạm khóa tài khoản (15 phút) nếu nhập sai quá số lần quy định
    login_lockout_minutes: int = 15

    # --- 7. Quản lý Dữ liệu & Trạng thái Ngoại tuyến (Offline Policy) ---
    # Thời hạn lưu trữ log tối đa (90 ngày) theo đúng quy định Nghị định 13/2023
    retention_days: int = 90

    # Chế độ khi mất mạng lâu: 'fail-closed' (khóa bảo vệ) hoặc 'fail-open' (mở tự do)
    offline_fail_mode: Literal["fail-closed", "fail-open"] = "fail-closed"

    # Số ngày ân hạn (3 ngày): máy con mất mạng vẫn chạy policy cũ trong 3 ngày trước khi siết
    offline_grace_days: int = 3

    # Khoảng thời gian không có heartbeat (120s = 2 chu kỳ) để đánh dấu thiết bị là Offline
    device_online_threshold_sec: int = 120

    # --- 8. Bảo mật Cookie ---
    # Cờ Secure cho Cookie: bắt buộc True ở prod/lab để cookie chỉ truyền qua kết nối HTTPS
    cookie_secure: bool = True

    @model_validator(mode="after")
    def _validate_security_settings(self) -> "Settings":
        if self.aes_gcm_key_b64:
            if self.aes_gcm_key_b64.startswith("CHANGE_ME"):
                raise ValueError("AES_GCM_KEY_B64 vẫn đang là giá trị placeholder CHANGE_ME")
            try:
                raw_key = base64.b64decode(self.aes_gcm_key_b64, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise ValueError("AES_GCM_KEY_B64 không phải chuỗi Base64 hợp lệ") from exc
            if len(raw_key) != 32:
                raise ValueError("AES_GCM_KEY_B64 phải giải mã ra đúng 32 bytes (256-bit)")

        if self.app_env != "dev":
            if (
                self.secret_key.startswith("CHANGE_ME")
                or self.secret_key.startswith("dev-only")
                or len(self.secret_key) < 32
            ):
                raise ValueError(
                    "SECRET_KEY phải là chuỗi ngẫu nhiên >= 32 ký tự ở môi trường lab/prod"
                )
            if not self.aes_gcm_key_b64:
                raise ValueError("Phải cấu hình AES_GCM_KEY_B64 ở môi trường lab/prod")
            if not self.cookie_secure:
                raise ValueError("COOKIE_SECURE phải bật true ở môi trường lab/prod (TLS)")
        return self

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    def resolve_path(self, raw_path: str) -> Path:
        p = Path(raw_path)
        return p if p.is_absolute() else (SERVER_BASE_DIR / p).resolve()


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
