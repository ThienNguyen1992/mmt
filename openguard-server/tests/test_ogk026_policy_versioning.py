import json

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.models  # noqa: F401
from app.config import settings
from app.core.security import verify_policy_signature
from app.database import Base
from app.models import Child, Device, Parent
from app.schemas.policy import PolicyContent
from app.services.policy_service import (
    create_new_policy_version,
    get_latest_policy,
    get_policy_history,
)


def test_policy_versioning_increments_and_preserves_history(tmp_path, monkeypatch):
    monkeypatch.setattr(
        settings, "policy_signing_private_key_pem_path", str(tmp_path / "certs" / "priv.pem")
    )
    monkeypatch.setattr(
        settings, "policy_signing_public_key_pem_path", str(tmp_path / "certs" / "pub.pem")
    )

    engine = create_engine(f"sqlite:///{tmp_path / 'ver.db'}", future=True)
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    try:
        db = SessionLocal()
        try:
            parent = Parent(email="p026@example.com", password_hash="$argon2id$dummy")
            db.add(parent)
            db.flush()
            child = Child(parent_id=parent.id, name="Bé An")
            db.add(child)
            db.flush()
            device = Device(child_id=child.id, fingerprint="FP-026")
            db.add(device)
            db.commit()

            p1 = create_new_policy_version(db, device.id, PolicyContent(quota_weekday_min=60))
            p2 = create_new_policy_version(db, device.id, PolicyContent(quota_weekday_min=90))
            p3 = create_new_policy_version(db, device.id, PolicyContent(quota_weekday_min=45))

            assert [p1.version, p2.version, p3.version] == [1, 2, 3]
            assert len({p1.id, p2.id, p3.id}) == 3

            latest = get_latest_policy(db, device.id)
            assert latest is not None
            assert latest.version == 3
            assert json.loads(latest.content_json)["quota_weekday_min"] == 45

            history = get_policy_history(db, device.id)
            assert [p.version for p in history] == [1, 2, 3]
            assert [json.loads(p.content_json)["quota_weekday_min"] for p in history] == [
                60,
                90,
                45,
            ]
            for pol in history:
                assert verify_policy_signature(pol.content_json, pol.signature)
        finally:
            db.close()
    finally:
        engine.dispose()
