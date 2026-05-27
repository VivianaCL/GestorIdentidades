# Punto de entrada de la aplicación FastAPI.
# Inicializa la base de datos y registra todos los routers.

import os
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from app.routers import identity
from app.db.database import engine, Base, SessionLocal, expire_stale_identities
from app.models.identity import Identity, AuditLog, Message
from sqlalchemy import text

# Crea todas las tablas que aún no existan en la base de datos
Base.metadata.create_all(bind=engine)

# Migraciones ligeras para SQLite: agrega columnas nuevas sin perder datos existentes.
# MySQL no las necesita porque create_all ya genera el esquema completo desde cero.
# Cada ADD COLUMN falla silenciosamente si la columna ya existe.
if os.environ.get("DB_ENGINE", "sqlite").lower() == "sqlite":
    with engine.connect() as _conn:
        for _sql in [
            "ALTER TABLE identities ADD COLUMN cert_expires_at DATETIME",
            "ALTER TABLE identities ADD COLUMN cert_revalidado BOOLEAN DEFAULT 0",
            "ALTER TABLE identities ADD COLUMN private_key_pem_encrypted TEXT",
            "ALTER TABLE identities ADD COLUMN mfa_enabled BOOLEAN DEFAULT 0",
            "ALTER TABLE identities ADD COLUMN totp_secret_encrypted TEXT",
            "ALTER TABLE identities ADD COLUMN consentimiento_alta BOOLEAN",
            "ALTER TABLE identities ADD COLUMN fecha_consentimiento_alta DATETIME",
            # Tabla messages: create_all la crea entera si no existe;
            # los ALTER solo cubren el caso de que ya existiera una versión anterior.
            "ALTER TABLE messages ADD COLUMN external_token_used BOOLEAN DEFAULT 0",
            "ALTER TABLE messages ADD COLUMN leido BOOLEAN DEFAULT 0",
        ]:
            try:
                _conn.execute(text(_sql))
                _conn.commit()
            except Exception:
                pass  # La columna ya existe; ignoramos el error

app = FastAPI(
    title="Gestor de Identidades API",
    description="Implementando Alta, Baja, Revocación y Rastreo con firmas X.509",
    version="1.0"
)


# Sirve el dashboard HTML embebido en la raíz del servicio
@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def serve_frontend():
    with open("app/frontend.html", "r", encoding="utf-8") as f:
        return f.read()


from app.routers import identity, auth, messages


@app.on_event("startup")
def startup_cleanup():
    # Al arrancar:
    # 1. Limpia certificados en roles que no deben tenerlos.
    # 2. Expira cuentas efímeras (External/Operative) cuyo plazo venció.
    db = SessionLocal()
    try:
        db.query(Identity).filter(Identity.rol.in_(["Operative", "External"])).update(
            {"certificate_pem": None, "public_key_pem": None},
            synchronize_session=False
        )
        db.commit()
        n = expire_stale_identities(db)
        if n:
            print("[startup] {} identidad(es) efímera(s) marcadas como BAJA por expiración.".format(n))
    finally:
        db.close()


# Registro de routers con sus prefijos de URL
app.include_router(auth.router,     prefix="/api/v1/auth",      tags=["Auth"])
app.include_router(identity.router, prefix="/api/v1/identities", tags=["Identities"])
app.include_router(messages.router, prefix="/api/v1/messages",   tags=["Messages"])


@app.get("/mensaje-externo", response_class=HTMLResponse, include_in_schema=False)
def mensaje_externo_redirect(token: str = ""):
    # Redirige la URL amigable del email al endpoint del router de mensajes.
    # Permite que el enlace enviado por correo sea legible: /mensaje-externo?token=xyz
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/api/v1/messages/externo/{}".format(token))


@app.get("/health", tags=["General"])
def health_check():
    # Endpoint de salud para verificar que el servicio responde correctamente.
    return {
        "status": "Healthy",
        "message": "Servicio Centralizado de Autoridad Criptográfica Activo!"
    }
