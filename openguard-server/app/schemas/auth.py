from pydantic import BaseModel, EmailStr, field_validator


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def password_min_length(cls, v: str) -> str:
        if len(v) < 10:
            raise ValueError("Mật khẩu phải có ít nhất 10 ký tự")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ChildViewLoginRequest(BaseModel):
    child_id: str


class RegisterResponse(BaseModel):
    id: str
    email: str
    role: str
