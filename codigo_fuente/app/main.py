# Punto de entrada de la aplicación FastAPI.
# Inicializa la base de datos, aplica migraciones ligeras y registra todos los routers.

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from app.routers import identity
from app.db.database import engine, Base, SessionLocal
from app.models.identity import Identity, AuditLog
from sqlalchemy import text

# Crea todas las tablas que aún no existan en la base de datos
Base.metadata.create_all(bind=engine)

# Migraciones manuales: agrega columnas nuevas sin perder datos existentes.
# SQLite no soporta ALTER TABLE complejo, por eso usamos ADD COLUMN individual.
with engine.connect() as _conn:
    for _col_sql in [
        "ALTER TABLE identities ADD COLUMN cert_expires_at DATETIME",
        "ALTER TABLE identities ADD COLUMN cert_revalidado BOOLEAN DEFAULT 0",
        "ALTER TABLE identities ADD COLUMN private_key_pem_encrypted TEXT",
    ]:
        try:
            _conn.execute(text(_col_sql))
            _conn.commit()
        except Exception:
            pass  # La columna ya existe; ignoramos el error de duplicado

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


from app.routers import identity, auth


@app.on_event("startup")
def cleanup_lower_level_certs():
    # Al arrancar, limpiamos cualquier certificado que pudiera haberse colado
    # en identidades de nivel bajo (Operative y External no deben tener certs).
    db = SessionLocal()
    try:
        db.query(Identity).filter(Identity.rol.in_(["Operative", "External"])).update(
            {"certificate_pem": None, "public_key_pem": None},
            synchronize_session=False
        )
        db.commit()
    finally:
        db.close()


# Registro de routers con sus prefijos de URL
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Auth"])
app.include_router(identity.router, prefix="/api/v1/identities", tags=["Identities"])


@app.get("/health", tags=["General"])
def health_check():
    # Endpoint de salud para verificar que el servicio responde correctamente.
    return {
        "status": "Healthy",
        "message": "Servicio Centralizado de Autoridad Criptográfica Activo!"
    }
