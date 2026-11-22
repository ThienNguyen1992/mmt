import base64
import json
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agent.core.config import load_config
from agent.core.local_store import _write_lock, get_connection, init_schema
from agent.core.logger import get_logger

logger = get_logger("policy_enforcer")


def canonical_json(content: dict) -> str:
    return json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def verify_policy_signature_pem(content_json: str, signature_b64: str, pub_pem_str: str) -> bool:
    """Xác thực chữ ký Ed25519 chỉ dùng Public Key (Agent không giữ Private Key)."""
    try:
        pub = serialization.load_pem_public_key(pub_pem_str.encode("ascii"))
        if not isinstance(pub, Ed25519PublicKey):
            return False
        pub.verify(base64.b64decode(signature_b64.encode("ascii")), content_json.encode("utf-8"))
        return True
    except Exception:
        return False


class PolicyEnforcer:
    def __init__(self, device_id: str | None, public_key_pem: str | None = None):
        self.device_id = device_id
        self._public_key_pem = public_key_pem
        self.current_policy: dict | None = None
        init_schema()
        if self.device_id:
            self._load_from_cache()

    def _get_pub_key(self) -> str | None:
        if self._public_key_pem:
            return self._public_key_pem
        return load_config().get("policy_public_key_pem")

    def _load_from_cache(self) -> None:
        with get_connection() as conn:
            row = conn.execute(
                "SELECT version, content_json, signature, policy_id "
                "FROM policy_cache WHERE device_id=?",
                (self.device_id,),
            ).fetchone()
        if not row:
            return
        pub = self._get_pub_key()
        if not pub or not verify_policy_signature_pem(row["content_json"], row["signature"], pub):
            logger.critical("Policy trong cache local bị sửa đổi trái phép — bỏ qua cache!")
            return
        self.current_policy = {
            "policy_id": row["policy_id"],
            "version": row["version"],
            "content": json.loads(row["content_json"]),
            "signature": row["signature"],
        }

    def apply_new_policy(
        self,
        version: int,
        content: dict,
        signature: str,
        policy_id: str = "",
    ) -> bool:
        pub = self._get_pub_key()
        if not pub:
            logger.error("Chưa có policy_public_key_pem để xác thực policy")
            return False

        content_json = canonical_json(content)
        if not verify_policy_signature_pem(content_json, signature, pub):
            logger.error("TỪ CHỐI policy version=%s: chữ ký Ed25519 không hợp lệ!", version)
            return False

        with _write_lock, get_connection() as conn:
            conn.execute(
                """
                INSERT INTO policy_cache (
                    device_id, policy_id, version, content_json, signature, cached_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    policy_id=excluded.policy_id,
                    version=excluded.version,
                    content_json=excluded.content_json,
                    signature=excluded.signature,
                    cached_at=excluded.cached_at
                """,
                (
                    self.device_id,
                    policy_id or str(version),
                    version,
                    content_json,
                    signature,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            conn.commit()

        self.current_policy = {
            "policy_id": policy_id or str(version),
            "version": version,
            "content": content,
            "signature": signature,
        }
        logger.info("Áp dụng policy mới thành công, version=%s", version)
        return True

    def get_current_version(self) -> int:
        return self.current_policy["version"] if self.current_policy else 0

    def get_current_policy_id(self) -> str:
        return self.current_policy.get("policy_id", "0") if self.current_policy else "0"

    def get_content(self) -> dict | None:
        return self.current_policy["content"] if self.current_policy else None
