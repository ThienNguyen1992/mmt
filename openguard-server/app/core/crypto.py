import base64
import hashlib
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import settings


def _get_aes_key() -> bytes:
    if settings.aes_gcm_key_b64:
        key = base64.b64decode(settings.aes_gcm_key_b64)
        if len(key) != 32:
            raise ValueError("AES_GCM_KEY_B64 phải đúng 32 bytes (256-bit)")
        return key
    # Fallback dev/test chỉ khi chưa cấu hình key riêng: dẫn xuất từ secret_key
    return hashlib.sha256(settings.secret_key.encode("utf-8")).digest()


def encrypt_aes_gcm(plaintext: str) -> str:
    """Mã hóa chuỗi nhạy cảm bằng AES-256-GCM; trả về base64(nonce_12B + ciphertext_tag)."""
    key = _get_aes_key()
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ct).decode("ascii")


def decrypt_aes_gcm(token_b64: str) -> str:
    """Giải mã token base64(nonce_12B + ciphertext_tag) về plaintext."""
    key = _get_aes_key()
    raw = base64.b64decode(token_b64.encode("ascii"))
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")


def hash_device_secret(raw_secret: str) -> str:
    return hashlib.sha256(raw_secret.encode("utf-8")).hexdigest()


def ensure_ed25519_keypair(priv_path: str, pub_path: str) -> tuple[bytes, bytes]:
    priv_file = settings.resolve_path(priv_path)
    pub_file = settings.resolve_path(pub_path)
    priv_file.parent.mkdir(parents=True, exist_ok=True)
    pub_file.parent.mkdir(parents=True, exist_ok=True)

    if priv_file.exists() and pub_file.exists():
        return priv_file.read_bytes(), pub_file.read_bytes()

    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_file.write_bytes(priv_pem)
    pub_file.write_bytes(pub_pem)
    return priv_pem, pub_pem


def sign_ed25519(message: bytes, priv_pem: bytes) -> str:
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        raise TypeError("Private key không phải Ed25519")
    sig = priv.sign(message)
    return base64.b64encode(sig).decode("ascii")


def verify_ed25519(message: bytes, signature_b64: str, pub_pem: bytes) -> bool:
    try:
        pub = serialization.load_pem_public_key(pub_pem)
        if not isinstance(pub, Ed25519PublicKey):
            return False
        pub.verify(base64.b64decode(signature_b64.encode("ascii")), message)
        return True
    except Exception:
        return False
