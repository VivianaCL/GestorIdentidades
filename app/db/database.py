# Capa de acceso a datos.
# Soporta dos motores según la variable DB_ENGINE del entorno:
#   sqlite  → archivo local identities.db  (desarrollo)
#   mysql   → servidor MySQL/MariaDB        (producción en HostGator)

import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

load_dotenv()

DB_ENGINE = os.environ.get("DB_ENGINE", "sqlite").lower()

if DB_ENGINE == "mysql":
    DB_USER     = os.environ["DB_USER"]
    DB_PASSWORD = os.environ["DB_PASSWORD"]
    DB_HOST     = os.environ.get("DB_HOST", "localhost")
    DB_PORT     = os.environ.get("DB_PORT", "3306")
    DB_NAME     = os.environ["DB_NAME"]

    SQLALCHEMY_DATABASE_URL = (
        "mysql+pymysql://{user}:{pw}@{host}:{port}/{name}?charset=utf8mb4".format(
            user=DB_USER, pw=DB_PASSWORD, host=DB_HOST, port=DB_PORT, name=DB_NAME
        )
    )
    engine = create_engine(SQLALCHEMY_DATABASE_URL, pool_pre_ping=True)

else:
    # SQLite: no requiere credenciales, crea el archivo automáticamente
    SQLALCHEMY_DATABASE_URL = "sqlite:///./identities.db"
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL,
        connect_args={"check_same_thread": False}
    )

# Fábrica de sesiones: cada petición HTTP abre y cierra su propia sesión
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base declarativa de la que heredan todos los modelos ORM
Base = declarative_base()


def get_db():
    # Dependencia de FastAPI: entrega una sesión de DB por petición y la cierra al terminar.
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_identity(db, nombre: str, email: str, password_hash: str, rol: str,
                    public_key_pem: str, certificate_pem: str,
                    cert_expires_at=None, private_key_pem_encrypted: str = None):
    # Registra una nueva identidad con todo su material criptográfico.
    # La clave privada llega ya cifrada; la DB nunca ve el texto plano.
    from app.models.identity import Identity

    new_identity = Identity(
        nombre=nombre,
        email=email,
        password_hash=password_hash,
        rol=rol,
        public_key_pem=public_key_pem,
        certificate_pem=certificate_pem,
        cert_expires_at=cert_expires_at,
        private_key_pem_encrypted=private_key_pem_encrypted,
        estado="ACTIVO"
    )
    db.add(new_identity)
    db.commit()
    db.refresh(new_identity)
    return new_identity


def update_identity_status(db, identity_id: int, new_status: str):
    # Cambia el estado de una identidad (ej. a REVOCADO).
    # Se usa principalmente en el flujo de revocación de certificados.
    from app.models.identity import Identity

    identity = db.query(Identity).filter(Identity.id == identity_id).first()
    if identity:
        identity.estado = new_status
        db.commit()
        db.refresh(identity)
    return identity


def delete_identity(db, identity_id: int, hard_delete: bool = False):
    # Elimina una identidad de forma física (hard) o marca su estado como BAJA (soft).
    # El sistema actualmente usa hard delete para la operación de BAJA.
    from app.models.identity import Identity, Message

    identity = db.query(Identity).filter(Identity.id == identity_id).first()
    if identity:
        if hard_delete:
            # Eliminar mensajes asociados antes de borrar la identidad para evitar
            # que un futuro usuario con el mismo ID (reuso de SQLite) los herede.
            db.query(Message).filter(
                (Message.sender_id == identity_id) | (Message.recipient_id == identity_id)
            ).delete(synchronize_session=False)
            db.delete(identity)
        else:
            identity.estado = "BAJA"
        db.commit()
        if not hard_delete:
            db.refresh(identity)
    return identity


def log_audit_event(db, identity_id: int, actor_id: int, accion: str, detalles: str = ""):
    # Inserta un registro de auditoría. Se llama desde cualquier operación relevante
    # para garantizar trazabilidad completa de las acciones.
    from app.models.identity import AuditLog

    log = AuditLog(
        identity_id=identity_id,
        actor_id=actor_id,
        accion=accion,
        detalles=detalles
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    return log


def expire_stale_identities(db):
    """Marca como BAJA a usuarios efímeros (External/Operative) cuyo cert_expires_at
    ya venció. Admin y Coordinator no se tocan — ellos renuevan manualmente.
    Devuelve el número de identidades expiradas en esta ejecución."""
    import datetime
    from app.models.identity import Identity, AuditLog

    now = datetime.datetime.utcnow()
    expired = db.query(Identity).filter(
        Identity.estado == "ACTIVO",
        Identity.rol.in_(["External", "Operative"]),
        Identity.cert_expires_at != None,
        Identity.cert_expires_at < now,
    ).all()

    for u in expired:
        u.estado = "BAJA"
        log = AuditLog(
            identity_id=u.id,
            actor_id=None,
            accion="BAJA_AUTOMATICA",
            detalles="Certificado/cuenta vencido en {}. Baja automática por expiración.".format(
                u.cert_expires_at.strftime("%Y-%m-%d %H:%M UTC")
            ),
        )
        db.add(log)

    if expired:
        db.commit()

    return len(expired)


def get_audit_logs(db, identity_id: int = None):
    # Devuelve los logs de auditoría filtrados por identidad.
    # Si identity_id es None, retorna el historial completo del sistema.
    from app.models.identity import AuditLog

    query = db.query(AuditLog)
    if identity_id:
        query = query.filter(AuditLog.identity_id == identity_id)
    return query.all()
