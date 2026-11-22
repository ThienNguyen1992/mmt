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
def rate_client():
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=test_engine)

    db = TestingSessionLocal()
    db.add(
        Parent(
            email="rate@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="parent",
        )
    )
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
        yield client
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()


def test_register_rate_limit_returns_429_after_5_requests(rate_client):
    for i in range(5):
        res = rate_client.post(
            "/auth/register",
            json={"email": f"u{i}@example.com", "password": "StrongPass123!"},
        )
        assert res.status_code == 201

    res6 = rate_client.post(
        "/auth/register",
        json={"email": "u5@example.com", "password": "StrongPass123!"},
    )
    assert res6.status_code == 429


def test_login_rate_limit_returns_429_after_10_requests(rate_client):
    for _ in range(10):
        res = rate_client.post(
            "/auth/login",
            json={"email": "rate@example.com", "password": "StrongPass123!"},
        )
        assert res.status_code == 200

    res11 = rate_client.post(
        "/auth/login",
        json={"email": "rate@example.com", "password": "StrongPass123!"},
    )
    assert res11.status_code == 429
