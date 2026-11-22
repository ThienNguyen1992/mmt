import base64
import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import create_engine, event, inspect
from sqlalchemy.orm import sessionmaker

import app.models  # noqa: F401
from app.core import crypto
from app.database import Base
from app.models import (
    AuditLog,
    Child,
    ChildRequest,
    Device,
    EnrollmentCode,
    Parent,
    Policy,
    RefreshToken,
    Session,
)


def _make_sqlite_session(db_file):
    engine = create_engine(
        f"sqlite:///{db_file}",
        connect_args={"check_same_thread": False},
        future=True,
    )

    @event.listens_for(engine, "connect")
    def _pragma(dbapi_conn, _rec):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON;")
        cur.close()

    Base.metadata.create_all(bind=engine)
    return engine, sessionmaker(bind=engine, autoflush=False, autocommit=False)


def test_aes_gcm_roundtrip_random_nonce_and_tamper_detection():
    plaintext = "Nguyễn Văn An - 6 tuổi"
    ct1 = crypto.encrypt_aes_gcm(plaintext)
    ct2 = crypto.encrypt_aes_gcm(plaintext)

    assert ct1 != plaintext
    assert ct2 != plaintext
    assert ct1 != ct2  # 12-byte random nonce each encryption
    assert crypto.decrypt_aes_gcm(ct1) == plaintext
    assert crypto.decrypt_aes_gcm(ct2) == plaintext

    raw = bytearray(base64.b64decode(ct1))
    raw[-1] ^= 0xFF
    tampered = base64.b64encode(bytes(raw)).decode("ascii")
    with pytest.raises(InvalidTag):
        crypto.decrypt_aes_gcm(tampered)


def test_aes_gcm_fallback_key_and_invalid_key_length(monkeypatch):
    monkeypatch.setattr(crypto.settings, "aes_gcm_key_b64", "")
    ct = crypto.encrypt_aes_gcm("fallback-test")
    assert crypto.decrypt_aes_gcm(ct) == "fallback-test"

    short_key_b64 = base64.b64encode(b"too-short-key").decode("ascii")
    monkeypatch.setattr(crypto.settings, "aes_gcm_key_b64", short_key_b64)
    with pytest.raises(ValueError, match="32 bytes"):
        crypto.encrypt_aes_gcm("should-fail")


def test_hash_device_secret():
    digest1 = crypto.hash_device_secret("device-secret-123")
    digest2 = crypto.hash_device_secret("device-secret-123")
    digest3 = crypto.hash_device_secret("device-secret-456")

    assert digest1 == digest2
    assert digest1 != digest3
    assert len(digest1) == 64
    assert digest1 != "device-secret-123"


def test_ed25519_keypair_sign_and_verify(tmp_path):
    priv_path = str(tmp_path / "certs" / "policy_priv.pem")
    pub_path = str(tmp_path / "certs" / "policy_pub.pem")

    priv1, pub1 = crypto.ensure_ed25519_keypair(priv_path, pub_path)
    priv2, pub2 = crypto.ensure_ed25519_keypair(priv_path, pub_path)
    assert priv1 == priv2
    assert pub1 == pub2

    payload = b'{"quota_weekday_min":60,"version":1}'
    sig = crypto.sign_ed25519(payload, priv1)
    assert crypto.verify_ed25519(payload, sig, pub1) is True

    # Modify 1 byte -> verification must fail
    tampered = b'{"quota_weekday_min":61,"version":1}'
    assert crypto.verify_ed25519(tampered, sig, pub1) is False

    # Wrong public key or corrupted signature -> False
    other_pub = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    assert crypto.verify_ed25519(payload, sig, other_pub) is False
    assert crypto.verify_ed25519(payload, "not-base64!", pub1) is False


def test_models_create_all_uuid_and_sqlite_encrypted_fields(tmp_path):
    db_file = tmp_path / "ogk008_test.db"
    engine, SessionLocal = _make_sqlite_session(db_file)
    try:
        table_names = set(inspect(engine).get_table_names())
        expected_tables = {
            "parents",
            "children",
            "devices",
            "policies",
            "audit_logs",
            "child_requests",
            "sessions",
            "refresh_tokens",
            "enrollment_codes",
        }
        assert expected_tables.issubset(table_names)

        priv_pem, pub_pem = crypto.ensure_ed25519_keypair(
            str(tmp_path / "priv.pem"),
            str(tmp_path / "pub.pem"),
        )
        now = datetime.now(timezone.utc)

        db = SessionLocal()
        try:
            parent = Parent(
                email="parent008@example.com",
                password_hash="$argon2id$dummyhash",
                role="parent",
            )
            db.add(parent)
            db.flush()

            child = Child(parent_id=parent.id, name="Bé An", birth_year=2017, age_group="6-11")
            db.add(child)
            db.flush()

            device = Device(
                child_id=child.id,
                fingerprint="HW-WIN11-SERIAL-999",
                device_secret_hash=crypto.hash_device_secret("raw-device-secret"),
                name="Laptop Bé An",
            )
            db.add(device)
            db.flush()

            policy_content = json.dumps({"quota_weekday_min": 90}, sort_keys=True)
            policy_sig = crypto.sign_ed25519(policy_content.encode("utf-8"), priv_pem)
            policy = Policy(
                device_id=device.id,
                version=1,
                content_json=policy_content,
                signature=policy_sig,
            )
            audit = AuditLog(
                parent_id=parent.id,
                child_id=child.id,
                actor_role="parent",
                action="create_policy",
                ip_address="192.168.1.10",
                new_value="v1",
            )
            req = ChildRequest(
                child_id=child.id,
                device_id=device.id,
                request_type="extra_time",
                subject="extra_time_15min",
                requested_minutes=15,
            )
            sess = Session(
                parent_id=parent.id,
                child_id=child.id,
                role="child-view",
                session_token="sess-tok-008",
                expires_at=now + timedelta(hours=12),
            )
            rtok = RefreshToken(
                device_id=device.id,
                token_hash=crypto.hash_device_secret("refresh-raw-008"),
                expires_at=now + timedelta(days=30),
            )
            code = EnrollmentCode(
                code="AB23CD45",
                parent_id=parent.id,
                child_id=child.id,
                consent_confirmed=True,
                consent_ip="192.168.1.10",
                expires_at=now + timedelta(minutes=10),
            )
            db.add_all([policy, audit, req, sess, rtok, code])
            db.commit()

            for record in (parent, child, device, policy, audit, req, sess, rtok, code):
                parsed = uuid.UUID(record.id)
                assert parsed.version == 4
                assert record.created_at is not None

            assert child.name == "Bé An"
            assert device.fingerprint == "HW-WIN11-SERIAL-999"
            assert crypto.verify_ed25519(
                policy.content_json.encode("utf-8"), policy.signature, pub_pem
            )
        finally:
            db.close()

        # Verify raw SQLite storage holds ciphertext (not plaintext)
        with sqlite3.connect(db_file) as raw_conn:
            raw_name_enc = raw_conn.execute("SELECT name_enc FROM children").fetchone()[0]
            raw_fp_enc = raw_conn.execute("SELECT fingerprint_enc FROM devices").fetchone()[0]
            raw_secret_hash = raw_conn.execute("SELECT device_secret_hash FROM devices").fetchone()[
                0
            ]

        assert raw_name_enc != "Bé An"
        assert "Bé An" not in raw_name_enc
        assert crypto.decrypt_aes_gcm(raw_name_enc) == "Bé An"

        assert raw_fp_enc != "HW-WIN11-SERIAL-999"
        assert "HW-WIN11-SERIAL-999" not in raw_fp_enc
        assert crypto.decrypt_aes_gcm(raw_fp_enc) == "HW-WIN11-SERIAL-999"

        assert raw_secret_hash == crypto.hash_device_secret("raw-device-secret")
    finally:
        engine.dispose()
