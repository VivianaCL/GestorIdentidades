from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db.database import get_db, create_identity, log_audit_event, update_identity_status, delete_identity, get_audit_logs
from app.models.identity import Identity
from app.schemas.identity import IdentityCreate, IdentityResponse, IdentityStatusUpdate
from app.core.crypto import build_root_ca, generate_key_pair, generate_user_certificate, get_current_identity, get_password_hash

router = APIRouter()


# Jerarquía: Nivel más bajo en número tiene mayor poder.
ROLE_LEVELS = {
    "Admin": 1,
    "Coordinator": 2,
    "Operative": 3,
    "External": 4
}

def check_hierarchy(actor: Identity, target_role: str):
    """
    Verifica que el actor tenga permisos para crear o modificar un rol objetivo.
    La regla es: Solo puedes crear a alguien subyacente estrictamente.
    (e.g., Admin(1) puede crear Coordinator(2); pero Coordinator(2) no puede crear otro Coordinator(2))
    """
    actor_level = ROLE_LEVELS.get(actor.rol, 99)
    target_level = ROLE_LEVELS.get(target_role, 99)
    
    if actor_level >= target_level:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Acceso denegado: Un perfil '{actor.rol}' no puede realizar la acción sobre nivel '{target_role}'."
        )

@router.post("/alta", response_model=IdentityResponse)
def endpoint_alta(data: IdentityCreate, db: Session = Depends(get_db), current_user: Identity = Depends(get_current_identity)):
    """ 
    I. ALTA: Valida nivel jerárquico, registra la identidad y le asocia sus certificados 
    """
    check_hierarchy(current_user, data.rol)

    if db.query(Identity).filter(Identity.email == data.email).first():
        raise HTTPException(status_code=400, detail="El correo ya se encuentra enlazado a otra identidad.")
    
    ca_priv, ca_cert, _, _ = build_root_ca()
    
    _, _, pub_obj, pub_pem = generate_key_pair()
    user_cert_pem = generate_user_certificate(pub_obj, data.nombre, ca_priv, ca_cert)
    
    hashed_password = get_password_hash(data.password)
    
    new_identity = create_identity(
        db, 
        data.nombre, 
        data.email, 
        hashed_password,
        data.rol, 
        pub_pem.decode('utf-8'), 
        user_cert_pem.decode('utf-8')
    )
    
    log_audit_event(
        db=db,
        identity_id=new_identity.id,
        actor_id=current_user.id,
        accion="ALTA",
        detalles=f"Alta exitosa. Rol asignado: {data.rol}"
    )
    
    return new_identity

# ── Rutas estáticas ANTES que las dinámicas (evita que FastAPI capture
#    "certificates" o "audit" como un identity_id entero) ────────────────────

@router.get("/")
def endpoint_get_all(db: Session = Depends(get_db), current_user: Identity = Depends(get_current_identity)):
    """ V. LISTADO GENÉRICO DE IDENTIDADES """
    return db.query(Identity).all()

@router.get("/certificates/all")
def endpoint_certificates(db: Session = Depends(get_db), current_user: Identity = Depends(get_current_identity)):
    """ VI. LISTADO GENÉRICO DE CERTIFICADOS """
    return db.query(Identity).all()

@router.get("/audit/all")
def endpoint_audit_all(db: Session = Depends(get_db), current_user: Identity = Depends(get_current_identity)):
    """ VII. RASTREO GLOBAL """
    if current_user.rol != "Admin":
         raise HTTPException(status_code=403, detail="Lectura Global restringida. Sólo los roles Admin pueden ver el log completo.")
    return get_audit_logs(db, identity_id=None)

# ── Rutas dinámicas (con path parameter) ─────────────────────────────────────

@router.put("/{identity_id}/revocar")
def endpoint_revocacion(identity_id: int, data: IdentityStatusUpdate, db: Session = Depends(get_db), current_user: Identity = Depends(get_current_identity)):
    """ II. REVOCACIÓN (El certificado se invalida, pero usuario persiste en DB) """
    target = db.query(Identity).filter(Identity.id == identity_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="La identidad objetivo a revocar no existe.")
        
    check_hierarchy(current_user, target.rol)
    
    updated_identity = update_identity_status(db, identity_id, data.estado)
    
    log_audit_event(
        db=db,
        identity_id=identity_id,
        actor_id=current_user.id,
        accion="REVOCACION",
        detalles=f"Certificado invalidado. Nuevo estatus: {data.estado}"
    )
    
    return {"message": f"El certificado de {target.nombre} ha sido marcado como {data.estado}.", "estado": updated_identity.estado}

@router.delete("/{identity_id}/baja")
def endpoint_baja(identity_id: int, db: Session = Depends(get_db), current_user: Identity = Depends(get_current_identity)):
    """ III. BAJA (Eliminación física total de la base de datos) """
    target = db.query(Identity).filter(Identity.id == identity_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="La identidad objetivo a borrar ya no existe.")
        
    check_hierarchy(current_user, target.rol)
    
    nombre_target = target.nombre
    # Borrado Duro (delete de tabla) como fue solicitado
    delete_identity(db, identity_id, hard_delete=True)
    
    log_audit_event(
        db=db,
        identity_id=identity_id,
        actor_id=current_user.id,
        accion="BAJA",
        detalles=f"El empleado {nombre_target} ha sido purgado y borrado físicamente de la Base de Datos."
    )
    
    return {"message": f"Usuario {nombre_target} ha sido eliminado definitivamente de la DB."}

@router.get("/{identity_id}/rastreo")
def endpoint_rastreo(identity_id: int, db: Session = Depends(get_db), current_user: Identity = Depends(get_current_identity)):
    """ IV. RASTREO (Historial de Auditoría) """
    # Si manda identity_id = 0, busca TODOS los logs globales
    if identity_id == 0:
        if current_user.rol != "Admin":
            raise HTTPException(status_code=403, detail="Lectura Global restringida. Sólo los roles Admin pueden ver el log completo.")
        logs = get_audit_logs(db, identity_id=None)
        return logs
        
    # Lectura individual de alguien
    target = db.query(Identity).filter(Identity.id == identity_id).first()
    if target:
        if current_user.id != target.id:
            check_hierarchy(current_user, target.rol)
            
    logs = get_audit_logs(db, identity_id=identity_id)
    return logs
