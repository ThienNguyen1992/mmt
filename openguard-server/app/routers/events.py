from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.deps import get_current_device
from app.database import get_db
from app.models.child_request import ChildRequest
from app.models.device import Device
from app.models.event import Event, EventType
from app.schemas.event import EventBatchRequest, EventBatchResponse

router = APIRouter(prefix="/events", tags=["events"])


@router.post("/batch", response_model=EventBatchResponse)
def ingest_event_batch(
    payload: EventBatchRequest,
    db: Session = Depends(get_db),
    device: Device = Depends(get_current_device),
):
    for item in payload.events:
        if item.device_id != device.id or item.child_id != device.child_id:
            raise HTTPException(
                status_code=403, detail="device_id/child_id không khớp token thiết bị"
            )

    inserted = 0
    skipped = 0

    for item in payload.events:
        existing = db.query(Event.id).filter(Event.idempotency_key == item.idempotency_key).first()
        if existing:
            skipped += 1
            continue

        ev = Event(
            idempotency_key=item.idempotency_key,
            ts=item.ts,
            device_id=device.id,
            child_id=device.child_id,
            type=item.type,
            subject=item.subject,
            duration_sec=item.duration_sec,
            policy_id=item.policy_id,
        )
        try:
            with db.begin_nested():
                db.add(ev)
                db.flush()
            inserted += 1

            # Tự tạo ChildRequest nếu event là unlock_request (NT3)
            if item.type == EventType.unlock_request and item.subject:
                req_type = (
                    "wrong_block" if item.subject.startswith("wrong_block:") else "extra_time"
                )
                subj = item.subject.removeprefix("wrong_block:")
                db.add(
                    ChildRequest(
                        child_id=device.child_id,
                        device_id=device.id,
                        request_type=req_type,
                        subject=subj,
                        requested_minutes=15 if req_type == "extra_time" else None,
                    )
                )
        except IntegrityError:
            skipped += 1

    db.commit()
    return EventBatchResponse(inserted=inserted, skipped_duplicates=skipped)
