from pydantic import BaseModel


class CreateEnrollmentCodeRequest(BaseModel):
    child_id: str
    consent_confirmed: bool = True


class CreateEnrollmentCodeResponse(BaseModel):
    code: str
    expires_at: str
