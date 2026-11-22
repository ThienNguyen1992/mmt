import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import jwt
from passlib.context import CryptContext

from app.config import settings
from app.core.crypto import ensure_ed25519_keypair, sign_ed25519, verify_ed25519

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def hash_password(plain_password: str) -> str:
    return pwd_context.hash(plain_password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password, password_hash)


def generate_session_token() -> str:
    return secrets.token_urlsafe(48)


def generate_enrollment_code(length: int = 8) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # bỏ 0/O, 1/I tránh nhầm
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_device_access_token(device_id: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": device_id,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.access_token_expire_minutes)).timestamp()),
    }
    return jwt.encode(payload, settings.secret_key, algorithm="HS256")


def decode_access_token(token: str) -> dict:
    return jwt.decode(token, settings.secret_key, algorithms=["HS256"])


def generate_refresh_token_raw() -> str:
    return secrets.token_urlsafe(64)


def hash_refresh_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def get_policy_keys() -> tuple[bytes, bytes]:
    return ensure_ed25519_keypair(
        settings.policy_signing_private_key_pem_path,
        settings.policy_signing_public_key_pem_path,
    )


def sign_policy(content_json: str) -> str:
    """Ký policy bằng Ed25519 Private Key (Agent chỉ giữ Public Key, không thể tự giả mạo)."""
    priv_pem, _ = get_policy_keys()
    return sign_ed25519(content_json.encode("utf-8"), priv_pem)


def verify_policy_signature(content_json: str, signature_b64: str) -> bool:
    _, pub_pem = get_policy_keys()
    return verify_ed25519(content_json.encode("utf-8"), signature_b64, pub_pem)
