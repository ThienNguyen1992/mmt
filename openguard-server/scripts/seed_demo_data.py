"""Seed dữ liệu mẫu dev/test cho OpenGuard Kids (OGK-014)."""

from __future__ import annotations

import json
import sys
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

import app.models  # noqa: E402, F401
from app.core.crypto import hash_device_secret  # noqa: E402
from app.core.security import hash_password, sign_policy  # noqa: E402
from app.database import Base, SessionLocal, engine  # noqa: E402
from app.models import (  # noqa: E402
    AuditLog,
    Child,
    ChildRequest,
    Device,
    Event,
    EventType,
    Parent,
    Policy,
)

DEMO_PARENT_EMAIL = "phuhuynh.demo@openguard.local"
DEMO_PARENT_PASSWORD = "DemoPassword123!"


def build_default_policy_content(age_group: str = "6-11") -> dict:
    """Tạo cấu trúc PolicyContent mặc định tương thích E3–E8."""
    if age_group == "6-11":
        blocked_categories = ["social_media", "gaming", "inappropriate"]
        quota_weekday_min = 90
        quota_weekend_min = 120
    else:
        blocked_categories = ["inappropriate"]
        quota_weekday_min = 120
        quota_weekend_min = 180

    return {
        "quota_weekday_min": quota_weekday_min,
        "quota_weekend_min": quota_weekend_min,
        "weekly_schedule": "A" * (7 * 48),
        "app_rules": {
            "mode": "blacklist",
            "rules": [
                {"match_type": "name", "value": "steam.exe", "action": "block", "group": "game"},
                {"match_type": "name", "value": "word.exe", "action": "allow", "group": "study"},
            ],
            "group_quotas_min": {"game": 45},
        },
        "domain_rules": {
            "age_preset": age_group if age_group in ("6-11", "12-15") else "custom",
            "blocked_categories": blocked_categories,
            "custom_blocked_domains": ["example-blocked.test"],
            "custom_allowed_domains": ["hocmai.vn", "vio.edu.vn", "tongdai111.vn"],
            "safesearch_enforce": True,
        },
    }


def _canonical_json(data: dict) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def seed_demo_data(
    db,
    signer: Callable[[str], str] = sign_policy,
) -> dict[str, int | str]:
    """Tạo 1 parent, 2 child, 2 device, policy ký Ed25519 và event mẫu 7 ngày (idempotent)."""
    existing_parent = db.query(Parent).filter(Parent.email == DEMO_PARENT_EMAIL).first()
    if existing_parent is not None:
        return {
            "status": "already_seeded",
            "parent_id": existing_parent.id,
            "children": db.query(Child).filter(Child.parent_id == existing_parent.id).count(),
            "devices": (
                db.query(Device).join(Child).filter(Child.parent_id == existing_parent.id).count()
            ),
            "policies": (
                db.query(Policy)
                .join(Device)
                .join(Child)
                .filter(Child.parent_id == existing_parent.id)
                .count()
            ),
            "events": (
                db.query(Event).join(Child).filter(Child.parent_id == existing_parent.id).count()
            ),
        }

    now = datetime.now(timezone.utc)

    parent = Parent(
        email=DEMO_PARENT_EMAIL,
        password_hash=hash_password(DEMO_PARENT_PASSWORD),
        role="parent",
    )
    db.add(parent)
    db.flush()

    child_an = Child(parent_id=parent.id, name="Bé An", birth_year=2017, age_group="6-11")
    child_minh = Child(parent_id=parent.id, name="Bé Minh", birth_year=2013, age_group="12-15")
    db.add_all([child_an, child_minh])
    db.flush()

    device_an = Device(
        child_id=child_an.id,
        fingerprint="DEMO-HW-FP-BEAN-WIN11",
        device_secret_hash=hash_device_secret("demo-secret-an"),
        name="PC-BeAn-Win11",
        is_active=True,
        last_seen_at=now,
    )
    device_minh = Device(
        child_id=child_minh.id,
        fingerprint="DEMO-HW-FP-BEMINH-WIN11",
        device_secret_hash=hash_device_secret("demo-secret-minh"),
        name="Laptop-BeMinh-Win11",
        is_active=True,
        last_seen_at=now - timedelta(seconds=30),
    )
    db.add_all([device_an, device_minh])
    db.flush()

    policies = []
    for dev, age in ((device_an, "6-11"), (device_minh, "12-15")):
        content_json = _canonical_json(build_default_policy_content(age))
        policies.append(
            Policy(
                device_id=dev.id,
                version=1,
                content_json=content_json,
                signature=signer(content_json),
            )
        )
    db.add_all(policies)
    db.flush()

    events = []
    sample_specs = [
        (EventType.app_start, "word.exe", 0),
        (EventType.app_stop, "word.exe", 1800),
        (EventType.domain_query, "hocmai.vn", 0),
        (EventType.domain_query, "khanacademy.org", 0),
        (EventType.blocked_app, "steam.exe", 0),
        (EventType.blocked_domain, "example-blocked.test", 0),
        (EventType.quota_warning, "10m", 0),
    ]

    for day_offset in range(7):
        ts_base = now - timedelta(days=day_offset)
        for dev, ch, pol in (
            (device_an, child_an, policies[0]),
            (device_minh, child_minh, policies[1]),
        ):
            for idx, (ev_type, subject, dur) in enumerate(sample_specs):
                events.append(
                    Event(
                        idempotency_key=f"seed-{dev.id[:8]}-d{day_offset}-{idx}-{uuid.uuid4().hex[:8]}",
                        ts=ts_base - timedelta(minutes=idx * 5),
                        device_id=dev.id,
                        child_id=ch.id,
                        type=ev_type,
                        subject=subject,
                        duration_sec=dur,
                        policy_id=pol.id,
                    )
                )

    events.append(
        Event(
            idempotency_key=f"seed-unlock-{uuid.uuid4().hex[:8]}",
            ts=now - timedelta(hours=2),
            device_id=device_an.id,
            child_id=child_an.id,
            type=EventType.unlock_request,
            subject="extra_time_15min",
            duration_sec=0,
            policy_id=policies[0].id,
        )
    )
    events.append(
        Event(
            idempotency_key=f"seed-override-{uuid.uuid4().hex[:8]}",
            ts=now - timedelta(hours=1),
            device_id=device_an.id,
            child_id=child_an.id,
            type=EventType.override_granted,
            subject="extra_time_15min",
            duration_sec=900,
            policy_id=policies[0].id,
        )
    )
    db.add_all(events)

    db.add(
        AuditLog(
            parent_id=parent.id,
            child_id=child_an.id,
            actor_role="parent",
            action="seed_initial_policy",
            ip_address="127.0.0.1",
            old_value=None,
            new_value=policies[0].content_json,
        )
    )
    db.add(
        ChildRequest(
            child_id=child_an.id,
            device_id=device_an.id,
            request_type="wrong_block",
            subject="vio.edu.vn",
            status="pending",
        )
    )

    db.commit()
    return {
        "status": "seeded",
        "parent_id": parent.id,
        "children": 2,
        "devices": 2,
        "policies": len(policies),
        "events": len(events),
    }


def main() -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        summary = seed_demo_data(db)
        print(f"[OGK-014] Seed demo data hoàn tất: {summary}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
