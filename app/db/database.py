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


# Prefijos de clave visible por rol. Cada letra identifica el nivel de la persona
# de un vistazo: A = Admin, C = Coordinator, O = Operative, X = External.
_ROLE_PREFIX = {"Admin": "A", "Coordinator": "C", "Operative": "O", "External": "X"}


def _generate_codigo(db, rol: str) -> str:
    """Asigna la siguiente clave visible disponible para un rol dado.

    La clave tiene el formato LNNN, por ejemplo A001 para el primer Admin,
    C003 para el tercer Coordinator, etc. Tomamos el número más alto que ya
    existe y sumamos 1, en lugar de contar filas, para que una baja definitiva
    no recicle el código de alguien que ya estuvo en el sistema.
    """
    from app.models.identity import Identity

    prefix = _ROLE_PREFIX.get(rol, "U")
    existing = db.query(Identity.codigo).filter(
        Identity.rol == rol, Identity.codigo.isnot(None)
    ).all()
    nums = [int(c[0][1:]) for c in existing if c[0] and c[0][1:].isdigit()]
    n = (max(nums) + 1) if nums else 1
    return f"{prefix}{n:03d}"


def create_identity(db, nombre: str, email: str, password_hash: str, rol: str,
                    public_key_pem: str, certificate_pem: str,
                    cert_expires_at=None, private_key_pem_encrypted: str = None):
    # Registra una nueva identidad con todo su material criptográfico.
    # La clave privada llega ya cifrada; la DB nunca ve el texto plano.
    from app.models.identity import Identity

    codigo = _generate_codigo(db, rol)

    new_identity = Identity(
        codigo=codigo,
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


def _generate_ticket(db) -> str:
    """Genera el folio de seguimiento para un evento de auditoría.

    El formato TKT-YYYYMMDD-NNNN es legible a simple vista: el segmento de
    fecha permite ubicar el día del evento sin consultar la base de datos, y
    el contador de cuatro dígitos reinicia cada jornada. Por ejemplo, el
    tercer evento del 29 de mayo de 2026 produce TKT-20260529-0003.

    Tener un folio visible en el log facilita el seguimiento cuando alguien
    reporta un incidente: basta citar el ticket para localizar el evento exacto.
    """
    import datetime
    from app.models.identity import AuditLog

    today = datetime.datetime.utcnow().strftime("%Y%m%d")
    prefix = f"TKT-{today}-"
    count = db.query(AuditLog).filter(AuditLog.ticket.like(f"{prefix}%")).count()
    return f"{prefix}{count + 1:04d}"


def log_audit_event(db, identity_id: int, actor_id: int, accion: str, detalles: str = ""):
    """Registra un evento en el log de auditoría.

    Además del ID numérico de la identidad afectada, copiamos su código visible
    (ej. A001) directamente en el log. Esto garantiza que aunque el usuario sea
    eliminado físicamente de la tabla 'identities', el historial de auditoría siga
    siendo legible sin necesidad de hacer JOINs sobre registros que ya no existen.

    Cada evento recibe un folio único (ticket) que facilita el seguimiento
    cuando se reporta un incidente: basta citar el folio para localizar el evento.
    """
    from app.models.identity import AuditLog, Identity

    # Copiamos el código visible tanto de la identidad afectada como del actor,
    # en el momento exacto del evento. Si alguno de los dos es eliminado después,
    # el log seguirá mostrando la clave legible sin necesidad de hacer JOINs.
    identity_codigo = None
    if identity_id:
        identity = db.query(Identity).filter(Identity.id == identity_id).first()
        if identity:
            identity_codigo = identity.codigo

    actor_codigo = None
    if actor_id:
        actor = db.query(Identity).filter(Identity.id == actor_id).first()
        if actor:
            actor_codigo = actor.codigo

    ticket = _generate_ticket(db)

    log = AuditLog(
        ticket=ticket,
        identity_id=identity_id,
        identity_codigo=identity_codigo,
        actor_id=actor_id,
        actor_codigo=actor_codigo,
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
        ticket = _generate_ticket(db)
        log = AuditLog(
            ticket=ticket,
            identity_id=u.id,
            identity_codigo=u.codigo,
            actor_id=None,
            actor_codigo=None,  # Baja automática del sistema; no hay actor humano
            accion="BAJA_AUTOMATICA",
            detalles="Certificado/cuenta vencido en {}. Baja automática por expiración.".format(
                u.cert_expires_at.strftime("%Y-%m-%d %H:%M UTC")
            ),
        )
        db.add(log)

    if expired:
        db.commit()

    return len(expired)


def migrate_codigos(db):
    """Retroalimenta con códigos visibles a los usuarios que existían antes de
    que se implementara la columna 'codigo'.

    Se ejecuta en cada arranque del servidor, pero si todos los registros ya
    tienen código se sale inmediatamente (costo: una sola consulta COUNT).
    El orden de asignación sigue la fecha de creación para que los usuarios
    más antiguos obtengan los números más bajos, lo cual es intuitivo.
    """
    from app.models.identity import Identity

    sin_codigo = db.query(Identity).filter(Identity.codigo.is_(None)).count()
    if not sin_codigo:
        return  # Nada que migrar; salida rápida

    for rol in ["Admin", "Coordinator", "Operative", "External"]:
        prefix = _ROLE_PREFIX.get(rol, "U")

        # Partimos del máximo ya asignado para no colisionar con códigos existentes
        existing = db.query(Identity.codigo).filter(
            Identity.rol == rol, Identity.codigo.isnot(None)
        ).all()
        nums = [int(c[0][1:]) for c in existing if c[0] and c[0][1:].isdigit()]
        next_n = (max(nums) + 1) if nums else 1

        # Los usuarios sin código se ordenan por antigüedad para numeración coherente
        identities = db.query(Identity).filter(
            Identity.rol == rol, Identity.codigo.is_(None)
        ).order_by(Identity.fecha_creacion, Identity.id).all()

        for identity in identities:
            identity.codigo = f"{prefix}{next_n:03d}"
            next_n += 1

    db.commit()


def get_audit_logs(db, identity_id: int = None):
    # Devuelve los logs de auditoría filtrados por identidad.
    # Si identity_id es None, retorna el historial completo del sistema.
    from app.models.identity import AuditLog

    query = db.query(AuditLog)
    if identity_id:
        query = query.filter(AuditLog.identity_id == identity_id)
    return query.all()
