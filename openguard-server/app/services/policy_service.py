import json

from sqlalchemy.orm import Session

from app.core.security import sign_policy
from app.models.policy import Policy
from app.schemas.policy import PolicyContent


def canonical_policy_json(content: PolicyContent | dict) -> str:
    """Chuẩn hóa PolicyContent thành JSON deterministic để ký & xác thực Ed25519."""
    data = content.model_dump() if isinstance(content, PolicyContent) else content
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def get_latest_policy(db: Session, device_id: str) -> Policy | None:
    return (
        db.query(Policy)
        .filter(Policy.device_id == device_id)
        .order_by(Policy.version.desc())
        .first()
    )


def get_policy_history(db: Session, device_id: str) -> list[Policy]:
    return (
        db.query(Policy).filter(Policy.device_id == device_id).order_by(Policy.version.asc()).all()
    )


def create_new_policy_version(
    db: Session,
    device_id: str,
    content: PolicyContent,
    *,
    commit: bool = True,
) -> Policy:
    """Tạo bản ghi Policy mới tăng dần version, giữ nguyên lịch sử các bản cũ."""
    latest = get_latest_policy(db, device_id)
    next_version = (latest.version + 1) if latest else 1
    content_json = canonical_policy_json(content)
    signature = sign_policy(content_json)

    new_policy = Policy(
        device_id=device_id,
        version=next_version,
        content_json=content_json,
        signature=signature,
    )
    db.add(new_policy)
    if commit:
        db.commit()
        db.refresh(new_policy)
    else:
        db.flush()
    return new_policy
