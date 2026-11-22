import os
import sqlite3
import subprocess
import sys
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

import app.models  # noqa: F401
from app.core import crypto
from app.database import Base
from app.models import AuditLog, Child, ChildRequest, Device, Event, Parent, Policy
from scripts.seed_demo_data import DEMO_PARENT_EMAIL, seed_demo_data

SERVER_DIR = Path(__file__).resolve().parents[1]


def test_seed_demo_data_creates_encrypted_children_signed_policies_and_events(tmp_path):
    db_file = tmp_path / "seed_test.db"
    test_engine = create_engine(f"sqlite:///{db_file}", future=True)

    @event.listens_for(test_engine, "connect")
    def _fk(dbapi_conn, _rec):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON;")
        cur.close()

    Base.metadata.create_all(bind=test_engine)
    SessionLocal = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)

    priv_pem, pub_pem = crypto.ensure_ed25519_keypair(
        str(tmp_path / "certs" / "priv.pem"),
        str(tmp_path / "certs" / "pub.pem"),
    )

    def signer(msg: str) -> str:
        return crypto.sign_ed25519(msg.encode("utf-8"), priv_pem)

    try:
        db = SessionLocal()
        try:
            summary = seed_demo_data(db, signer=signer)
            assert summary["status"] == "seeded"
            assert summary["children"] == 2
            assert summary["devices"] == 2
            assert summary["policies"] == 2
            assert summary["events"] >= 98

            # Idempotent on second run
            second = seed_demo_data(db, signer=signer)
            assert second["status"] == "already_seeded"
            assert db.query(Parent).filter(Parent.email == DEMO_PARENT_EMAIL).count() == 1
            assert db.query(Child).count() == 2
            assert db.query(Device).count() == 2
            assert db.query(Policy).count() == 2
            assert db.query(AuditLog).count() == 1
            assert db.query(ChildRequest).count() == 1
            assert db.query(Event).count() == summary["events"]

            # Verify Ed25519 signatures on all seeded policies
            for policy in db.query(Policy).all():
                assert crypto.verify_ed25519(
                    policy.content_json.encode("utf-8"), policy.signature, pub_pem
                )
        finally:
            db.close()

        # Verify sensitive fields are AES-GCM encrypted in SQLite
        with sqlite3.connect(db_file) as raw_conn:
            names = [row[0] for row in raw_conn.execute("SELECT name_enc FROM children").fetchall()]
            fps = [
                row[0] for row in raw_conn.execute("SELECT fingerprint_enc FROM devices").fetchall()
            ]
        assert len(names) == 2
        assert "Bé An" not in names and "Bé Minh" not in names
        assert {crypto.decrypt_aes_gcm(n) for n in names} == {"Bé An", "Bé Minh"}
        assert {crypto.decrypt_aes_gcm(fp) for fp in fps} == {
            "DEMO-HW-FP-BEAN-WIN11",
            "DEMO-HW-FP-BEMINH-WIN11",
        }
    finally:
        test_engine.dispose()


def test_seed_demo_data_cli_execution(tmp_path):
    db_file = tmp_path / "cli_seed.db"
    env = os.environ.copy()
    env["DATABASE_URL"] = f"sqlite:///{db_file.as_posix()}"
    env["POLICY_SIGNING_PRIVATE_KEY_PEM_PATH"] = str(tmp_path / "certs" / "priv.pem")
    env["POLICY_SIGNING_PUBLIC_KEY_PEM_PATH"] = str(tmp_path / "certs" / "pub.pem")

    proc = subprocess.run(
        [sys.executable, "scripts/seed_demo_data.py"],
        cwd=str(SERVER_DIR),
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert "[OGK-014]" in proc.stdout
    assert db_file.exists()

    with sqlite3.connect(db_file) as conn:
        assert conn.execute("SELECT COUNT(*) FROM parents").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM children").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(*) FROM policies").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] >= 98
