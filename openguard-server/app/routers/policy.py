import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.csrf import csrf_protect
from app.core.deps import get_current_device, get_current_parent
from app.database import get_db
from app.models.audit import AuditLog
from app.models.child import Child
from app.models.device import Device
from app.models.parent import Parent
from app.schemas.heartbeat import HeartbeatRequest, HeartbeatResponse
from app.schemas.policy import PolicyResponse, PolicyUpdateRequest
from app.services.policy_service import create_new_policy_version, get_latest_policy

router = APIRouter(prefix="/policy", tags=["policy"])


@router.post("/{device_id}", response_model=PolicyResponse, dependencies=[Depends(csrf_protect)])
def update_policy(
    device_id: str,
    payload: PolicyUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    parent: Parent = Depends(get_current_parent),
):
    device = (
        db.query(Device)
        .join(Child)
        .filter(Device.id == device_id, Child.parent_id == parent.id)
        .first()
    )
    if not device:
        raise HTTPException(status_code=404, detail="Không tìm thấy thiết bị thuộc tài khoản này")

    old_policy = get_latest_policy(db, device_id)
    old_value = old_policy.content_json if old_policy else None
    new_policy = create_new_policy_version(db, device_id, payload.content, commit=False)

    client_ip = request.client.host if request.client else "unknown"
    db.add(
        AuditLog(
            parent_id=parent.id,
            child_id=device.child_id,
            actor_role=parent.role,
            action="update_policy",
            ip_address=client_ip,
            old_value=old_value,
            new_value=new_policy.content_json,
        )
    )
    db.commit()
    db.refresh(new_policy)

    return PolicyResponse(
        policy_id=new_policy.id,
        device_id=device_id,
        version=new_policy.version,
        content=json.loads(new_policy.content_json),
        signature=new_policy.signature,
        created_at=new_policy.created_at.isoformat(),
    )


@router.get("/{device_id}", response_model=PolicyResponse)
def get_policy(
    device_id: str,
    db: Session = Depends(get_db),
    device: Device = Depends(get_current_device),
):
    if device.id != device_id:
        raise HTTPException(status_code=403, detail="Token không khớp thiết bị")
    policy = get_latest_policy(db, device_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Thiết bị chưa có policy nào")
    return PolicyResponse(
        policy_id=policy.id,
        device_id=device_id,
        version=policy.version,
        content=json.loads(policy.content_json),
        signature=policy.signature,
        created_at=policy.created_at.isoformat(),
    )


@router.post("/heartbeat/{device_id}", response_model=HeartbeatResponse)
def heartbeat(
    device_id: str,
    payload: HeartbeatRequest,
    db: Session = Depends(get_db),
    device: Device = Depends(get_current_device),
):
    if device.id != device_id:
        raise HTTPException(status_code=403, detail="Token không khớp thiết bị")

    now = datetime.now(timezone.utc)
    device.last_seen_at = now
    db.commit()

    latest = get_latest_policy(db, device_id)
    server_ver = latest.version if latest else 0
    return HeartbeatResponse(
        server_policy_version=server_ver,
        policy_update_available=(server_ver != payload.policy_version),
        server_utc=now.isoformat(),
        pending_commands=[],
    )
