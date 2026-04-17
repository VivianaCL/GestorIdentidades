from pydantic import BaseModel, EmailStr
from typing import Optional

class IdentityCreate(BaseModel):
    nombre: str
    email: EmailStr
    password: str  # Added strict requirement for initial password
    rol: str       # Opciones: Admin, Coordinator, Operative, External

class IdentityStatusUpdate(BaseModel):
    estado: str    # REVOCADO, BAJA, etc.

class IdentityResponse(BaseModel):
    id: int
    nombre: str
    email: EmailStr
    rol: str
    estado: str
    
    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None
