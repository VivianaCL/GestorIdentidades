from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from app.routers import identity
from app.db.database import engine, Base, SessionLocal
from app.models.identity import Identity, AuditLog

# Preparación de la Base de Datos SQLite y creación de tablas
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Gestor de Identidades API",
    description="Implementando Alta, Baja, Revocación y Rastreo con firmas X.509",
    version="1.0"
)

# Endpoint visual con el Dashboard que creamos
@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def serve_frontend():
    with open("app/frontend.html", "r", encoding="utf-8") as f:
        return f.read()

from app.routers import identity, auth

@app.on_event("startup")
def cleanup_lower_level_certs():
    """Elimina los certificados de usuarios Nivel 3 (Operative) y Nivel 4 (External)."""
    db = SessionLocal()
    try:
        db.query(Identity).filter(Identity.rol.in_(["Operative", "External"])).update(
            {"certificate_pem": None, "public_key_pem": None},
            synchronize_session=False
        )
        db.commit()
    finally:
        db.close()

# Acople de los Endpoints
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Auth"])
app.include_router(identity.router, prefix="/api/v1/identities", tags=["Identities"])

@app.get("/health", tags=["General"])
def health_check():
    """ 
    Ping de salud del servicio 
    """
    return {
        "status": "Healthy",
        "message": "Servicio Centralizado de Autoridad Criptográfica Activo!"
    }
