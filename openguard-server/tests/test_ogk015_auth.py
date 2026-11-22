import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.security import verify_password
from app.database import Base, get_db
from app.main import app
from app.models.parent import Parent


@pytest.fixture
def test_setup():
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=test_engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as client:
        yield client, TestingSessionLocal
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)


def test_register_success_argon2id(test_setup):
    client, session_factory = test_setup
    payload = {
        "email": "phuhuynh@example.com",
        "password": "PasswordStrong123",
    }
    res = client.post("/auth/register", json=payload)
    assert res.status_code == 201
    data = res.json()
    assert data["email"] == payload["email"]
    assert data["role"] == "parent"
    assert "id" in data

    # Kiểm tra trực tiếp trong DB
    db = session_factory()
    try:
        parent = db.query(Parent).filter(Parent.email == payload["email"]).first()
        assert parent is not None
        assert parent.password_hash.startswith("$argon2id$")
        assert verify_password("PasswordStrong123", parent.password_hash) is True
        assert verify_password("WrongPassword!", parent.password_hash) is False
    finally:
        db.close()


def test_register_password_too_short(test_setup):
    client, _ = test_setup
    # Mật khẩu 9 ký tự (< 10)
    payload = {
        "email": "short@example.com",
        "password": "Short1234",
    }
    res = client.post("/auth/register", json=payload)
    assert res.status_code == 422


def test_register_duplicate_email(test_setup):
    client, _ = test_setup
    payload = {
        "email": "duplicate@example.com",
        "password": "ValidPassword123",
    }
    # Lần 1: Thành công
    res1 = client.post("/auth/register", json=payload)
    assert res1.status_code == 201

    # Lần 2: Trùng email -> 409 Conflict
    res2 = client.post("/auth/register", json=payload)
    assert res2.status_code == 409
    assert res2.json()["detail"] == "Email đã được đăng ký"


def test_register_invalid_email(test_setup):
    client, _ = test_setup
    payload = {
        "email": "khong-phai-email",
        "password": "ValidPassword123",
    }
    res = client.post("/auth/register", json=payload)
    assert res.status_code == 422
