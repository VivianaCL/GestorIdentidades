# Esquemas Pydantic para validación de entrada y formato de respuesta.
# Actúan como contratos entre el cliente HTTP y la lógica de negocio:
# definen qué campos se aceptan y cuáles se devuelven en cada endpoint.

from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime


class IdentityCreate(BaseModel):
    # Payload para crear una nueva identidad (endpoint POST /alta).
    nombre: str
    email: EmailStr
    password: str
    rol: str
    cert_days_valid: Optional[float] = 365  # Días de vigencia del certificado; acepta fracciones para horas


class IdentityStatusUpdate(BaseModel):
    # Payload mínimo para cambiar el estado de una identidad (revocación).
    estado: str  # Valores válidos: REVOCADO, BAJA, ACTIVO


class IdentityResponse(BaseModel):
    # Representación pública de una identidad.
    # Excluye deliberadamente la contraseña y el material criptográfico sensible.
    id: int
    nombre: str
    email: EmailStr
    rol: str
    estado: str
    cert_expires_at: Optional[datetime] = None

    class Config:
        orm_mode = True  # Permite construir este esquema directamente desde un objeto ORM


class Token(BaseModel):
    # Respuesta estándar del endpoint de login; contiene el JWT de acceso.
    access_token: str
    token_type: str


class TokenData(BaseModel):
    # Datos extraídos del payload del JWT durante la validación de sesión.
    email: Optional[str] = None


# ── Schemas MFA ───────────────────────────────────────────────────────────────

class MFASetupResponse(BaseModel):
    # Respuesta al iniciar la configuración de MFA: incluye el secreto y la URI
    # para que el frontend genere el código QR.
    secret: str
    uri: str

class MFAConfirmSetup(BaseModel):
    # Payload para confirmar la activación de MFA: el secreto provisional
    # y el primer código TOTP generado por la app del usuario.
    secret: str
    code: str

class MFAValidate(BaseModel):
    # Payload para completar el login cuando MFA está activo.
    temp_token: str
    code: str

class MFADisable(BaseModel):
    # Para desactivar MFA se requiere el código actual como confirmación.
    code: str

class MFAStatusResponse(BaseModel):
    # Indica si el usuario autenticado tiene MFA habilitado.
    mfa_enabled: bool
