from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Configuración de SQLite  local provisional
SQLALCHEMY_DATABASE_URL = "sqlite:///./identities.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_identity(db, nombre: str, email: str, password_hash: str, rol: str, public_key_pem: str, certificate_pem: str, cert_expires_at=None):
    """ I. ALTA: Registra una nueva identidad en la BD junto a su material criptográfico. """
    from app.models.identity import Identity

    new_identity = Identity(
        nombre=nombre,
        email=email,
        password_hash=password_hash,
        rol=rol,
        public_key_pem=public_key_pem,
        certificate_pem=certificate_pem,
        cert_expires_at=cert_expires_at,
        estado="ACTIVO"
    )
    db.add(new_identity)
    db.commit()
    db.refresh(new_identity)
    return new_identity

def update_identity_status(db, identity_id: int, new_status: str):
    """ II. REVOCACIÓN: Cambia el estado del certificado en la base de datos a REVOCADO (o el estado enviado). """
    from app.models.identity import Identity
    
    
    identity = db.query(Identity).filter(Identity.id == identity_id).first()
    if identity:
        identity.estado = new_status
        db.commit()
        db.refresh(identity)
    return identity

def delete_identity(db, identity_id: int, hard_delete: bool = False):
    """ III. BAJA: Marca una identidad como BAJA (Soft Delete) o la elimina completamente. """
    from app.models.identity import Identity
    
    identity = db.query(Identity).filter(Identity.id == identity_id).first()
    if identity:
        if hard_delete:
            db.delete(identity)
        else:
            identity.estado = "BAJA"
        db.commit()
        if not hard_delete:
            db.refresh(identity)
    return identity

def log_audit_event(db, identity_id: int, actor_id: int, accion: str, detalles: str = ""):
    """ IV. RASTREO: Registra logs de las acciones realizadas sobre las identidades. """
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

def get_audit_logs(db, identity_id: int = None):
    """ Obtiene registros del rastreo de movimientos de una identidad específica """
    from app.models.identity import AuditLog
    
    query = db.query(AuditLog)
    if identity_id:
        query = query.filter(AuditLog.identity_id == identity_id)
    return query.all()
