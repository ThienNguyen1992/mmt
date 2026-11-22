from pydantic import BaseModel


class CreateEnrollmentCodeRequest(BaseModel):
    child_id: str
    consent_confirmed: bool = True


class CreateEnrollmentCodeResponse(BaseModel):
    code: str
    expires_at: str


class EnrollDeviceRequest(BaseModel):
    code: str
    fingerprint: str
    device_name: str | None = None


class EnrollDeviceResponse(BaseModel):
    device_id: str
    child_id: str
    access_token: str
    refresh_token: str
    policy_public_key_pem: str
