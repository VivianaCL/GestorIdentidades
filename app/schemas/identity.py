from pydantic import BaseModel, EmailStr
from typing import Optional

class IdentityCreate(BaseModel):
    actor_id: int  # ID del usuario que está haciendo la petición (0 para bootstrap de sistema)
    nombre: str
    email: EmailStr
    rol: str       # Opciones: Admin, Coordinator, Operative, External

class IdentityStatusUpdate(BaseModel):
    actor_id: int
    estado: str    # REVOCADO, BAJA, etc.

class IdentityResponse(BaseModel):
    id: int
    nombre: str
    email: EmailStr
    rol: str
    estado: str
    
    class Config:
        orm_mode = True
