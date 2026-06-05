# Definición de los modelos ORM que mapean las tablas de la base de datos.
# SQLAlchemy usa estas clases para traducir objetos Python a filas SQL y viceversa.

from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey
from sqlalchemy.sql import func
from app.db.database import Base


class Identity(Base):
    # Tabla principal: guarda a cada persona registrada en el sistema junto
    # con su material criptográfico y el estado de su acceso.
    __tablename__ = "identities"

    id = Column(Integer, primary_key=True, index=True)
    # Clave visible legible por humanos: A001 para el primer Admin, C002 para el segundo
    # Coordinator, etc. Es más fácil de citar en conversaciones que el ID numérico interno.
    codigo = Column(String(10), unique=True, nullable=True, index=True)
    nombre = Column(String(255), index=True)
    email = Column(String(255), unique=True, index=True)  # Identificador único de login
    password_hash = Column(String(255))                   # Hash bcrypt; nunca la contraseña original

    rol = Column(String(50))  # Admin, Coordinator, Operative o External
    public_key_pem = Column(Text)       # Llave pública RSA en formato PEM
    certificate_pem = Column(Text)      # Certificado X.509 firmado por la CA raíz
    private_key_pem_encrypted = Column(Text, nullable=True)  # Clave privada cifrada con Fernet (nunca en texto plano)

    estado = Column(String(20), default="ACTIVO", index=True)  # ACTIVO, REVOCADO o BAJA

    cert_expires_at = Column(DateTime, nullable=True)    # Fecha límite del certificado
    cert_revalidado = Column(Boolean, default=False, nullable=True)     # Marca si fue reactivado por un Admin

    mfa_enabled = Column(Boolean, default=False, nullable=False)        # Si el usuario tiene TOTP activo
    totp_secret_encrypted = Column(Text, nullable=True)               # Secreto TOTP cifrado con Fernet

    # ── Consentimiento ARCO ───────────────────────────────────────────────────
    # Registra si el titular otorgó consentimiento explícito al momento del alta
    # y al momento de la baja, conforme al Derecho ARCO (LFPDPPP).
    # NULL indica un registro previo a la implementación del requisito.
    consentimiento_alta = Column(Boolean, nullable=True)          # True = consentimiento otorgado al crear la identidad
    fecha_consentimiento_alta = Column(DateTime, nullable=True)  # Momento exacto del consentimiento

    fecha_creacion = Column(DateTime, server_default=func.now())
    fecha_modificacion = Column(DateTime, onupdate=func.now())


class AuditLog(Base):
    # Tabla de auditoría inmutable: registra cada acción relevante del sistema.
    # Permite rastrear quién hizo qué y cuándo sobre cada identidad.
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    # Folio de seguimiento del evento: TKT-YYYYMMDD-NNNN.
    # Permite citar un evento específico en un reporte sin necesidad de conocer el ID interno.
    ticket = Column(String(20), nullable=True, index=True)
    identity_id = Column(Integer, ForeignKey("identities.id"), nullable=True, index=True)  # Identidad afectada
    # Copia desnormalizada del código visible (ej. A001) al momento del evento.
    # Se guarda aquí para que el historial sea legible incluso si el usuario es eliminado.
    identity_codigo = Column(String(10), nullable=True)
    actor_id = Column(Integer, nullable=True)        # Quién ejecutó la acción (puede ser diferente al afectado)
    # Copia del código visible del actor al momento del evento (igual que identity_codigo).
    # Así el log sigue siendo legible aunque el actor sea eliminado posteriormente.
    actor_codigo = Column(String(10), nullable=True)
    accion = Column(String(100), index=True)    # ALTA, REVOCACION, BAJA, LOGIN_SUCCESS, etc.
    detalles = Column(Text)                     # Descripción libre del evento

    fecha_evento = Column(DateTime, server_default=func.now())


class Message(Base):
    # Mensajes internos firmados digitalmente.
    # Soporta dos flujos:
    #   - Interno: destinatario es un usuario registrado (recipient_id apunta a Identity)
    #   - Externo:  destinatario es un email externo; se genera un token de un solo uso
    #              para que acceda a la página pública de visualización.
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)

    # Remitente: siempre un usuario interno con certificado
    sender_id = Column(Integer, ForeignKey("identities.id"), nullable=False, index=True)

    # Destinatario interno (nullable cuando el destino es externo)
    recipient_id = Column(Integer, ForeignKey("identities.id"), nullable=True, index=True)

    # Destinatario externo (nullable cuando el destino es interno)
    recipient_email_ext = Column(String(255), nullable=True)

    subject = Column(String(255))       # Asunto del mensaje
    body = Column(Text)                 # Cuerpo en texto plano

    # Firma S/MIME detached (PKCS#7 DER en base64).
    # Se almacena separada del cuerpo para poder verificar independientemente.
    signature_b64 = Column(Text, nullable=True)

    # Token de acceso para destinatarios externos (secrets.token_urlsafe)
    external_token = Column(String(128), nullable=True, unique=True, index=True)
    external_token_used = Column(Boolean, default=False)  # Se marca True en la primera vista

    leido = Column(Boolean, default=False)  # Para bandeja interna

    # Archivos adjuntos serializados como JSON: lista de objetos con
    # {filename, mime_type, data_b64}. El límite de 2 MB se aplica en el router
    # antes de guardar, no aquí, para dar un mensaje de error útil al usuario.
    attachments_json = Column(Text, nullable=True)

    fecha_envio = Column(DateTime, server_default=func.now(), index=True)
