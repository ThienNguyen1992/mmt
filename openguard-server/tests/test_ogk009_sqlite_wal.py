import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

import app.models  # noqa: F401
from app.database import Base, apply_sqlite_pragmas, engine, register_sqlite_pragmas
from app.models import Child, Device, Parent


def _create_wal_engine(db_file):
    test_engine = create_engine(
        f"sqlite:///{db_file}",
        connect_args={"check_same_thread": False},
        future=True,
    )
    register_sqlite_pragmas(test_engine)
    Base.metadata.create_all(bind=test_engine)
    return test_engine


def test_app_engine_has_sqlite_pragma_listener():
    if engine.dialect.name == "sqlite":
        assert event.contains(engine, "connect", apply_sqlite_pragmas)


def test_sqlite_wal_and_pragmas_enabled(tmp_path):
    db_file = tmp_path / "ogk009_wal.db"
    test_engine = _create_wal_engine(db_file)
    try:
        with test_engine.connect() as conn:
            journal_mode = conn.execute(text("PRAGMA journal_mode;")).scalar()
            synchronous = conn.execute(text("PRAGMA synchronous;")).scalar()
            foreign_keys = conn.execute(text("PRAGMA foreign_keys;")).scalar()
            busy_timeout = conn.execute(text("PRAGMA busy_timeout;")).scalar()

        assert str(journal_mode).lower() == "wal"
        assert synchronous == 1  # NORMAL
        assert foreign_keys == 1  # ON
        assert busy_timeout == 5000
    finally:
        test_engine.dispose()


def test_sqlite_foreign_keys_and_cascade_enforced(tmp_path):
    db_file = tmp_path / "ogk009_fk.db"
    test_engine = _create_wal_engine(db_file)
    SessionLocal = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)
    try:
        db = SessionLocal()
        try:
            orphan_child = Child(parent_id="non-existent-parent", name="Orphan")
            db.add(orphan_child)
            with pytest.raises(IntegrityError):
                db.commit()
            db.rollback()

            parent = Parent(
                email="walparent@example.com",
                password_hash="$argon2id$dummy",
                role="parent",
            )
            db.add(parent)
            db.flush()

            child = Child(parent_id=parent.id, name="Bé Bình")
            db.add(child)
            db.flush()

            device = Device(child_id=child.id, fingerprint="FP-WAL-01")
            db.add(device)
            db.commit()

            # Deleting parent must cascade to child & device when foreign_keys=ON
            db.delete(parent)
            db.commit()
            assert db.query(Child).count() == 0
            assert db.query(Device).count() == 0
        finally:
            db.close()
    finally:
        test_engine.dispose()


def test_sqlite_wal_concurrent_read_during_uncommitted_write(tmp_path):
    db_file = tmp_path / "ogk009_concurrent.db"
    test_engine = _create_wal_engine(db_file)
    SessionLocal = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)
    try:
        seed_db = SessionLocal()
        seed_db.add(
            Parent(
                email="existing@example.com",
                password_hash="$argon2id$dummy",
                role="parent",
            )
        )
        seed_db.commit()
        seed_db.close()

        writer = SessionLocal()
        reader = SessionLocal()
        try:
            writer.add(
                Parent(
                    email="writer@example.com",
                    password_hash="$argon2id$dummy",
                    role="parent",
                )
            )
            writer.flush()

            # Under WAL mode, a concurrent reader still reads committed rows cleanly
            emails = [row[0] for row in reader.query(Parent.email).all()]
            assert "existing@example.com" in emails
            writer.commit()
        finally:
            reader.close()
            writer.close()
    finally:
        test_engine.dispose()
