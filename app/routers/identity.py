from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db.database import get_db, create_identity, log_audit_event, update_identity_status, delete_identity, get_audit_logs
from app.models.identity import Identity
from app.schemas.identity import IdentityCreate, IdentityResponse, IdentityStatusUpdate
from app.core.crypto import build_root_ca, generate_key_pair, generate_user_certificate, get_current_identity, get_password_hash, create_ephemeral_certificate
from pydantic import BaseModel
import datetime

router = APIRouter()


# Esquema para crear certificados efímeros
class EphemeralCertRequest(BaseModel):
    duration_minutes: int  # Duración en minutos

# Esquema para renovar certificado
class RenovarCertRequest(BaseModel):
    days_valid: int  # Nueva duración en días


# Esquema para crear usuario efímero
class EphemeralUserRequest(BaseModel):
    nombre: str
    email: str
    password: str  # Contraseña ingresada por el usuario
    duration_minutes: int  # Duración en minutos


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
    
    if actor_level > target_level:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Acceso denegado: Un perfil '{actor.rol}' no puede realizar la acción sobre nivel '{target_role}'."
        )

@router.post("/alta", response_model=IdentityResponse)
def endpoint_alta(data: IdentityCreate, db: Session = Depends(get_db), current_user: Identity = Depends(get_current_identity)):
    """
    I. ALTA: Solo el Admin (nivel 1) puede crear colaboradores. Valida nivel jerárquico,
    registra la identidad y le asocia sus certificados.
    """
    if current_user.rol != "Admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acceso denegado: Solo los administradores de nivel 1 pueden crear nuevos colaboradores."
        )
    check_hierarchy(current_user, data.rol)

    if db.query(Identity).filter(Identity.email == data.email).first():
        raise HTTPException(status_code=400, detail="El correo ya se encuentra enlazado a otra identidad.")
    
    # Solo Nivel 1 (Admin) y Nivel 2 (Coordinator) obtienen certificados
    cert_expires_at = None
    if data.rol in ("Admin", "Coordinator"):
        days_valid = data.cert_days_valid if data.cert_days_valid and data.cert_days_valid > 0 else 365
        ca_priv, ca_cert, _, _ = build_root_ca()
        _, _, pub_obj, pub_pem = generate_key_pair()
        user_cert_pem = generate_user_certificate(pub_obj, data.nombre, ca_priv, ca_cert, days_valid=days_valid)
        pub_pem_str = pub_pem.decode('utf-8')
        cert_pem_str = user_cert_pem.decode('utf-8')
        cert_expires_at = datetime.datetime.utcnow() + datetime.timedelta(days=days_valid)
    else:
        pub_pem_str = None
        cert_pem_str = None

    hashed_password = get_password_hash(data.password)

    new_identity = create_identity(
        db,
        data.nombre,
        data.email,
        hashed_password,
        data.rol,
        pub_pem_str,
        cert_pem_str,
        cert_expires_at=cert_expires_at,
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

@router.post("/ephemeral/create")
def endpoint_create_ephemeral_cert(request: EphemeralCertRequest, db: Session = Depends(get_db), current_user: Identity = Depends(get_current_identity)):
    """
    VIII. CREAR CERTIFICADO EFÍMERO (Provisional para pruebas)
    Genera un certificado temporal con duración especificada en minutos.
    """
    # Validar duración (mínimo 1 minuto, máximo 7 días)
    if request.duration_minutes < 1 or request.duration_minutes > 7 * 24 * 60:
        raise HTTPException(
            status_code=400, 
            detail="La duración debe estar entre 1 minuto y 7 días."
        )
    
    try:
        # Crear CA raíz
        ca_private_key, ca_cert, _, _ = build_root_ca()
        
        # Crear certificado efímero
        cert_obj, cert_pem, private_pem, public_pem = create_ephemeral_certificate(
            user_name=current_user.email,
            duration_minutes=request.duration_minutes,
            ca_private_key=ca_private_key,
            ca_cert=ca_cert
        )
        
        # Registrar en auditoría
        log_audit_event(
            db=db,
            identity_id=current_user.id,
            actor_id=current_user.id,
            accion="EPHEMERAL_CERT_CREATED",
            detalles=f"Certificado efímero creado con duración de {request.duration_minutes} minuto(s)"
        )
        
        return {
            "success": True,
            "certificate_pem": cert_pem.decode('utf-8') if isinstance(cert_pem, bytes) else cert_pem,
            "private_key_pem": private_pem.decode('utf-8') if isinstance(private_pem, bytes) else private_pem,
            "public_key_pem": public_pem.decode('utf-8') if isinstance(public_pem, bytes) else public_pem,
            "valid_from": cert_obj.not_valid_before.isoformat(),
            "valid_until": cert_obj.not_valid_after.isoformat(),
            "duration_minutes": request.duration_minutes,
            "message": f"Certificado efímero creado exitosamente. Expirará en {request.duration_minutes} minuto(s)."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al crear certificado efímero: {str(e)}")

@router.post("/ephemeral/user")
def endpoint_create_ephemeral_user(request: EphemeralUserRequest, db: Session = Depends(get_db), current_user: Identity = Depends(get_current_identity)):
    """
    IX. CREAR USUARIO EFÍMERO (Provisional para pruebas)
    Genera un usuario temporal con certificado efímero.
    """
    # Validar duración (mínimo 1 minuto, máximo 7 días)
    if request.duration_minutes < 1 or request.duration_minutes > 7 * 24 * 60:
        raise HTTPException(
            status_code=400, 
            detail="La duración debe estar entre 1 minuto y 7 días."
        )
    
    # Validar contraseña
    if not request.password or len(request.password) < 4:
        raise HTTPException(
            status_code=400,
            detail="La contraseña debe tener al menos 4 caracteres."
        )
    
    # Verificar que el email no exista
    if db.query(Identity).filter(Identity.email == request.email).first():
        raise HTTPException(status_code=400, detail="El correo ya se encuentra enlazado a otra identidad.")
    
    try:
        # Usar la contraseña proporcionada
        hashed_password = get_password_hash(request.password)
        
        # Crear CA raíz
        ca_private_key, ca_cert, _, _ = build_root_ca()
        
        # Crear certificado efímero
        cert_obj, cert_pem, _, public_pem = create_ephemeral_certificate(
            user_name=request.email,
            duration_minutes=request.duration_minutes,
            ca_private_key=ca_private_key,
            ca_cert=ca_cert
        )
        
        # Crear la identidad efímera en la DB
        new_identity = create_identity(
            db,
            nombre=request.nombre,
            email=request.email,
            password_hash=hashed_password,
            rol="External",  # Siempre rol más bajo para efímeros
            public_key_pem=public_pem.decode('utf-8') if isinstance(public_pem, bytes) else public_pem,
            certificate_pem=cert_pem.decode('utf-8') if isinstance(cert_pem, bytes) else cert_pem
        )
        
        # Registrar en auditoría
        log_audit_event(
            db=db,
            identity_id=new_identity.id,
            actor_id=current_user.id,
            accion="EPHEMERAL_USER_CREATED",
            detalles=f"Usuario efímero creado: {request.email} con duración de {request.duration_minutes} minuto(s)"
        )
        
        return {
            "success": True,
            "user_id": new_identity.id,
            "nombre": request.nombre,
            "email": request.email,
            "password": request.password,
            "certificate_pem": cert_pem.decode('utf-8') if isinstance(cert_pem, bytes) else cert_pem,
            "public_key_pem": public_pem.decode('utf-8') if isinstance(public_pem, bytes) else public_pem,
            "valid_from": cert_obj.not_valid_before.isoformat(),
            "valid_until": cert_obj.not_valid_after.isoformat(),
            "duration_minutes": request.duration_minutes,
            "message": f"Usuario efímero creado exitosamente. Acceso válido hasta las {cert_obj.not_valid_after.strftime('%H:%M:%S')}."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al crear usuario efímero: {str(e)}")

# ── Rutas dinámicas (con path parameter) ─────────────────────────────────────

@router.put("/{identity_id}/renovar-cert")
def endpoint_renovar_cert(identity_id: int, data: RenovarCertRequest, db: Session = Depends(get_db), current_user: Identity = Depends(get_current_identity)):
    """ RENOVAR CERTIFICADO: Reemite el certificado de una identidad con nueva duración. """
    if data.days_valid < 1 or data.days_valid > 3650:
        raise HTTPException(status_code=400, detail="La duración debe estar entre 1 y 3650 días.")

    target = db.query(Identity).filter(Identity.id == identity_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Identidad no encontrada.")

    if target.rol not in ("Admin", "Coordinator"):
        raise HTTPException(status_code=400, detail="Solo Admin y Coordinator tienen certificados renovables.")

    check_hierarchy(current_user, target.rol)

    # Paso 1: Revocar el certificado actual
    target.estado = "REVOCADO"
    db.commit()

    log_audit_event(
        db=db,
        identity_id=identity_id,
        actor_id=current_user.id,
        accion="REVOCACION",
        detalles=f"Certificado revocado automáticamente como parte de la renovación de certificado."
    )

    # Paso 2: Generar nuevo par de claves y certificado
    ca_priv, ca_cert, _, _ = build_root_ca()
    _, _, pub_obj, pub_pem = generate_key_pair()
    new_cert_pem = generate_user_certificate(pub_obj, target.nombre, ca_priv, ca_cert, days_valid=data.days_valid)
    new_expires_at = datetime.datetime.utcnow() + datetime.timedelta(days=data.days_valid)

    # Paso 3: Activar la identidad con el nuevo certificado
    target.public_key_pem = pub_pem.decode('utf-8')
    target.certificate_pem = new_cert_pem.decode('utf-8')
    target.cert_expires_at = new_expires_at
    target.estado = "ACTIVO"
    db.commit()
    db.refresh(target)

    log_audit_event(
        db=db,
        identity_id=identity_id,
        actor_id=current_user.id,
        accion="CERT_RENOVADO",
        detalles=f"Nuevo certificado emitido por {data.days_valid} días. Nueva expiración: {new_expires_at.strftime('%Y-%m-%d')}"
    )

    return {
        "success": True,
        "message": f"Certificado renovado exitosamente. Nuevo vencimiento: {new_expires_at.strftime('%d/%m/%Y')}",
        "cert_expires_at": new_expires_at.isoformat()
    }

@router.put("/{identity_id}/revalidar-cert")
def endpoint_revalidar_cert(identity_id: int, db: Session = Depends(get_db), current_user: Identity = Depends(get_current_identity)):
    """ REVALIDAR CERTIFICADO: Solo Admin puede reactivar un certificado revocado. """
    if current_user.rol != "Admin":
        raise HTTPException(status_code=403, detail="Solo los administradores pueden revalidar certificados.")

    target = db.query(Identity).filter(Identity.id == identity_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Identidad no encontrada.")

    if target.rol not in ("Admin", "Coordinator"):
        raise HTTPException(status_code=400, detail="Solo Admin y Coordinator tienen certificados revalidables.")

    if target.estado != "REVOCADO":
        raise HTTPException(status_code=400, detail="El certificado no está revocado.")

    target.estado = "ACTIVO"
    target.cert_revalidado = True
    db.commit()
    db.refresh(target)

    log_audit_event(
        db=db,
        identity_id=identity_id,
        actor_id=current_user.id,
        accion="CERT_REVALIDADO",
        detalles=f"Certificado de {target.nombre} revalidado por administrador."
    )

    return {"message": f"El certificado de {target.nombre} ha sido revalidado.", "estado": "ACTIVO"}

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
    if current_user.rol != "Admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Acceso denegado: Solo los administradores de nivel 1 pueden dar de baja a un colaborador.")

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
