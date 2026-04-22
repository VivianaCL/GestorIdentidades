from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey
from sqlalchemy.sql import func
from app.db.database import Base

class Identity(Base):
    __tablename__ = "identities"

    id = Column(Integer, primary_key=True, index=True)
    nombre = Column(String, index=True)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String) # Hash bcrypt de la contraseña
    rol = Column(String)  
    public_key_pem = Column(String)  # Llave pública de la identidad
    certificate_pem = Column(String)  # Certificado X.509 en formato PEM
    estado = Column(String, default="ACTIVO", index=True)  # ACTIVO, REVOCADO, BAJA
    
    cert_expires_at = Column(DateTime(timezone=True), nullable=True)
    cert_revalidado = Column(Boolean, default=False, nullable=True)

    fecha_creacion = Column(DateTime(timezone=True), server_default=func.now())
    fecha_modificacion = Column(DateTime(timezone=True), onupdate=func.now())

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    identity_id = Column(Integer, ForeignKey("identities.id"), nullable=True, index=True)
    actor_id = Column(Integer, nullable=True)  # ID de quien ejecutó la acción (ej. un Admin)
    accion = Column(String, index=True)  # ALTA, REVOCACION, BAJA
    detalles = Column(String)
    
    fecha_evento = Column(DateTime(timezone=True), server_default=func.now())
