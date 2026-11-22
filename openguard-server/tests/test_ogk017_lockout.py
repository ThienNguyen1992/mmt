from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.core.security import hash_password
from app.database import Base, get_db
from app.main import app
from app.models import Parent


@pytest.fixture
def lockout_env():
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=test_engine)

    db = TestingSessionLocal()
    parent = Parent(
        email="lockout@example.com",
        password_hash=hash_password("CorrectPassword123"),
        role="parent",
    )
    db.add(parent)
    db.commit()
    db.close()

    def override_get_db():
        s = TestingSessionLocal()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, base_url="https://testserver") as client:
        yield client, TestingSessionLocal
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()


def test_lockout_15_min_after_5_failed_attempts_blocks_6th_correct_login(lockout_env):
    client, session_factory = lockout_env

    for _ in range(5):
        res = client.post(
            "/auth/login",
            json={"email": "lockout@example.com", "password": "WrongPassword!"},
        )
        assert res.status_code == 401

    db = session_factory()
    try:
        parent = db.query(Parent).filter(Parent.email == "lockout@example.com").one()
        assert parent.failed_login_count == 5
        assert parent.locked_until is not None
    finally:
        db.close()

    # 6th attempt even with the right password must return 423 Locked
    res6 = client.post(
        "/auth/login",
        json={"email": "lockout@example.com", "password": "CorrectPassword123"},
    )
    assert res6.status_code == 423


def test_successful_login_resets_failed_count_and_recovers_after_expiry(lockout_env):
    client, session_factory = lockout_env

    # 3 wrong attempts then 1 right attempt -> resets to 0
    for _ in range(3):
        assert (
            client.post(
                "/auth/login",
                json={"email": "lockout@example.com", "password": "Wrong!"},
            ).status_code
            == 401
        )
    assert (
        client.post(
            "/auth/login",
            json={"email": "lockout@example.com", "password": "CorrectPassword123"},
        ).status_code
        == 200
    )

    db = session_factory()
    try:
        parent = db.query(Parent).filter(Parent.email == "lockout@example.com").one()
        assert parent.failed_login_count == 0
        assert parent.locked_until is None

        # Simulate expired 15-min lockout -> login succeeds and resets counters
        parent.failed_login_count = 5
        parent.locked_until = datetime.now(timezone.utc) - timedelta(seconds=5)
        db.commit()
    finally:
        db.close()

    res = client.post(
        "/auth/login",
        json={"email": "lockout@example.com", "password": "CorrectPassword123"},
    )
    assert res.status_code == 200

    db = session_factory()
    try:
        parent = db.query(Parent).filter(Parent.email == "lockout@example.com").one()
        assert parent.failed_login_count == 0
        assert parent.locked_until is None
    finally:
        db.close()
