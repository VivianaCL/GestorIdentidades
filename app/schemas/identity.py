from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

class IdentityCreate(BaseModel):
    nombre: str
    email: EmailStr
    password: str
    rol: str
    cert_days_valid: Optional[float] = 365  # Duración del certificado en días (puede ser fraccionario para horas/minutos)

class IdentityStatusUpdate(BaseModel):
    estado: str    # REVOCADO, BAJA, etc.

class IdentityResponse(BaseModel):
    id: int
    nombre: str
    email: EmailStr
    rol: str
    estado: str
    cert_expires_at: Optional[datetime] = None

    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None
