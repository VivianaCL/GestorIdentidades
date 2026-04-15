from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db.database import get_db, create_identity, log_audit_event, update_identity_status, delete_identity, get_audit_logs
from app.models.identity import Identity
from app.schemas.identity import IdentityCreate, IdentityResponse, IdentityStatusUpdate
from app.core.crypto import build_root_ca, generate_key_pair, generate_user_certificate

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
def endpoint_alta(data: IdentityCreate, db: Session = Depends(get_db)):
    """ 
    I. ALTA: Valida nivel jerárquico, registra la identidad y le asocia sus certificados 
    """
    if data.actor_id != 0:
        actor = db.query(Identity).filter(Identity.id == data.actor_id).first()
        if not actor:
            raise HTTPException(status_code=404, detail="Actor solicitante no fue encontrado en sistema.")
        check_hierarchy(actor, data.rol)
    else:
        if db.query(Identity).first():
            raise HTTPException(status_code=403, detail="El método de Bootstrap solo aplica para el primer registro cuando la tabla está vacía.")
        if data.rol != "Admin":
            raise HTTPException(status_code=400, detail="El Bootstrap initial está reservado solo para Admin.")

    if db.query(Identity).filter(Identity.email == data.email).first():
        raise HTTPException(status_code=400, detail="El correo ya se encuentra enlazado a otra identidad.")
    
    ca_priv, ca_cert, _, _ = build_root_ca()
    
    _, _, pub_obj, pub_pem = generate_key_pair()
    user_cert_pem = generate_user_certificate(pub_obj, data.nombre, ca_priv, ca_cert)
    
    new_identity = create_identity(
        db, 
        data.nombre, 
        data.email, 
        data.rol, 
        pub_pem.decode('utf-8'), 
        user_cert_pem.decode('utf-8')
    )
    
    log_audit_event(
        db=db,
        identity_id=new_identity.id,
        actor_id=data.actor_id,
        accion="ALTA",
        detalles=f"Alta exitosa. Rol asignado: {data.rol}"
    )
    
    return new_identity

@router.put("/{identity_id}/revocar")
def endpoint_revocacion(identity_id: int, data: IdentityStatusUpdate, db: Session = Depends(get_db)):
    """ II. REVOCACIÓN (El certificado se invalida, pero usuario persiste en DB) """
    actor = db.query(Identity).filter(Identity.id == data.actor_id).first()
    if not actor:
        raise HTTPException(status_code=404, detail="Actor solicitante no fue encontrado.")
        
    target = db.query(Identity).filter(Identity.id == identity_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="La identidad objetivo a revocar no existe.")
        
    check_hierarchy(actor, target.rol)
    
    updated_identity = update_identity_status(db, identity_id, data.estado)
    
    log_audit_event(
        db=db,
        identity_id=identity_id,
        actor_id=actor.id,
        accion="REVOCACION",
        detalles=f"Certificado invalidado. Nuevo estatus: {data.estado}"
    )
    
    return {"message": f"El certificado de {target.nombre} ha sido marcado como {data.estado}.", "estado": updated_identity.estado}

@router.delete("/{identity_id}/baja")
def endpoint_baja(identity_id: int, data: IdentityStatusUpdate, db: Session = Depends(get_db)):
    """ III. BAJA (Eliminación física total de la base de datos) """
    actor = db.query(Identity).filter(Identity.id == data.actor_id).first()
    if not actor:
        raise HTTPException(status_code=404, detail="Actor solicitante no fue encontrado.")
        
    target = db.query(Identity).filter(Identity.id == identity_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="La identidad objetivo a borrar ya no existe.")
        
    check_hierarchy(actor, target.rol)
    
    nombre_target = target.nombre
    # Borrado Duro (delete de tabla) como fue solicitado
    delete_identity(db, identity_id, hard_delete=True)
    
    log_audit_event(
        db=db,
        identity_id=identity_id, # Quedará en null en la BD si la FK tiene ON DELETE SET NULL, o se guarda el ID de todas formas
        actor_id=actor.id,
        accion="BAJA",
        detalles=f"El empleado {nombre_target} ha sido purgado y borrado físicamente de la Base de Datos."
    )
    
    return {"message": f"Usuario {nombre_target} ha sido eliminado definitivamente de la DB."}

@router.get("/{identity_id}/rastreo")
def endpoint_rastreo(identity_id: int, actor_id: int, db: Session = Depends(get_db)):
    """ IV. RASTREO (Historial de Auditoría) """
    actor = db.query(Identity).filter(Identity.id == actor_id).first()
    if not actor:
        raise HTTPException(status_code=404, detail="Auditor no encontrado.")
        
    # Si manda identity_id = 0, busca TODOS los logs globales
    if identity_id == 0:
        if actor.rol != "Admin":
            raise HTTPException(status_code=403, detail="Lectura Global restringida. Sólo los roles Admin pueden ver el log completo.")
        logs = get_audit_logs(db, identity_id=None)
        return logs
        
    # Lectura individual de alguien
    target = db.query(Identity).filter(Identity.id == identity_id).first()
    # Puede ser que el target fue dado de BAJA pero queremos ver el log. Si target es Null, no podemos leer el rol.
    # En ese caso, requerimos ser admin al menos, o simplemente dejamos pasar y filtramos:
    if target:
        # Si existe, checar si el actor es de nivel superior o es la misma persona leyendo su propio historial
        if actor.id != target.id:
            check_hierarchy(actor, target.rol)
            
    logs = get_audit_logs(db, identity_id=identity_id)
    return logs
