# Definición de los modelos ORM que mapean las tablas de la base de datos.
# SQLAlchemy usa estas clases para traducir objetos Python a filas SQL y viceversa.

from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey
from sqlalchemy.sql import func
from app.db.database import Base


class Identity(Base):
    # Tabla principal: guarda a cada persona registrada en el sistema junto
    # con su material criptográfico y el estado de su acceso.
    __tablename__ = "identities"

    id = Column(Integer, primary_key=True, index=True)
    nombre = Column(String, index=True)
    email = Column(String, unique=True, index=True)  # Identificador único de login
    password_hash = Column(String)                   # Hash bcrypt; nunca la contraseña original

    rol = Column(String)  # Admin, Coordinator, Operative o External
    public_key_pem = Column(String)       # Llave pública RSA en formato PEM
    certificate_pem = Column(String)      # Certificado X.509 firmado por la CA raíz
    private_key_pem_encrypted = Column(String, nullable=True)  # Clave privada cifrada con Fernet (nunca en texto plano)

    estado = Column(String, default="ACTIVO", index=True)  # ACTIVO, REVOCADO o BAJA

    cert_expires_at = Column(DateTime(timezone=True), nullable=True)    # Fecha límite del certificado
    cert_revalidado = Column(Boolean, default=False, nullable=True)     # Marca si fue reactivado por un Admin

    mfa_enabled = Column(Boolean, default=False, nullable=False)        # Si el usuario tiene TOTP activo
    totp_secret_encrypted = Column(String, nullable=True)               # Secreto TOTP cifrado con Fernet

    fecha_creacion = Column(DateTime(timezone=True), server_default=func.now())
    fecha_modificacion = Column(DateTime(timezone=True), onupdate=func.now())


class AuditLog(Base):
    # Tabla de auditoría inmutable: registra cada acción relevante del sistema.
    # Permite rastrear quién hizo qué y cuándo sobre cada identidad.
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    identity_id = Column(Integer, ForeignKey("identities.id"), nullable=True, index=True)  # Identidad afectada
    actor_id = Column(Integer, nullable=True)   # Quién ejecutó la acción (puede ser diferente al afectado)
    accion = Column(String, index=True)         # ALTA, REVOCACION, BAJA, LOGIN_SUCCESS, etc.
    detalles = Column(String)                   # Descripción libre del evento

    fecha_evento = Column(DateTime(timezone=True), server_default=func.now())
