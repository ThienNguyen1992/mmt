import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from jwt import PyJWTError
from sqlalchemy.orm import Session

from app.core.csrf import csrf_protect
from app.core.deps import get_current_parent
from app.core.security import decode_access_token
from app.core.ws_manager import manager
from app.database import get_db
from app.models.audit import AuditLog
from app.models.child import Child
from app.models.device import Device
from app.models.parent import Parent

router = APIRouter(prefix="/commands", tags=["commands"])

ALLOWED_EMERGENCY_COMMANDS = {"lock_now", "unlock", "add_minutes", "wipe_local_cache"}


def _authenticate_ws(websocket: WebSocket, db: Session) -> Device | None:
    auth_header = websocket.headers.get("authorization", "")
    token = auth_header.removeprefix("Bearer ").strip() if auth_header.startswith("Bearer ") else ""
    if not token:
        token = websocket.query_params.get("token", "")
    if not token:
        return None
    try:
        payload = decode_access_token(token)
    except PyJWTError:
        return None
    if payload.get("type") != "access":
        return None
    return (
        db.query(Device)
        .filter(Device.id == payload.get("sub"), Device.is_active == True)  # noqa: E712
        .first()
    )


@router.websocket("/ws/{device_id}")
async def websocket_endpoint(websocket: WebSocket, device_id: str):
    db_provider = websocket.app.dependency_overrides.get(get_db, get_db)
    db_gen = db_provider()
    db = next(db_gen)
    try:
        device = _authenticate_ws(websocket, db)
    finally:
        try:
            next(db_gen)
        except StopIteration:
            pass

    if not device or device.id != device_id:
        await websocket.close(code=4401)
        return

    await manager.connect(device_id, websocket)
    try:
        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if isinstance(msg, dict) and msg.get("type") == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        await manager.disconnect(device_id)
    except Exception:
        await manager.disconnect(device_id)


@router.post("/send/{device_id}", dependencies=[Depends(csrf_protect)])
async def send_emergency_command(
    device_id: str,
    command: dict,
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
        raise HTTPException(status_code=404, detail="Không tìm thấy thiết bị")

    if command.get("type") not in ALLOWED_EMERGENCY_COMMANDS:
        raise HTTPException(status_code=422, detail="Loại lệnh khẩn không hợp lệ")

    payload = dict(command)
    payload["issued_at"] = datetime.now(timezone.utc).isoformat()
    sent = await manager.send_command(device_id, payload)

    ip = request.client.host if request.client else "unknown"
    db.add(
        AuditLog(
            parent_id=parent.id,
            child_id=device.child_id,
            actor_role=parent.role,
            action="send_emergency_command",
            ip_address=ip,
            new_value=json.dumps(payload, ensure_ascii=False),
        )
    )
    db.commit()
    return {"delivered": sent, "command": payload}
