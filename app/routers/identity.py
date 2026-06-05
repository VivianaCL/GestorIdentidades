# Router principal de identidades.
# Agrupa todos los endpoints del ciclo de vida de una identidad:
# Alta, Revocación, Baja, Rastreo, Certificados efímeros y Descarga de certificados.

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db.database import get_db, create_identity, log_audit_event, update_identity_status, delete_identity, get_audit_logs, expire_stale_identities
from app.models.identity import Identity
from app.schemas.identity import IdentityCreate, IdentityResponse, IdentityStatusUpdate, BajaRequest, SMimeSignRequest
from app.core.crypto import (
    build_root_ca, generate_key_pair, generate_user_certificate,
    get_current_identity, get_password_hash, create_ephemeral_certificate,
    encrypt_private_key, decrypt_private_key,
    sign_smime
)
from fastapi.responses import Response
from pydantic import BaseModel
import datetime

router = APIRouter()

# Limpieza lazy: se ejecuta como máximo una vez por hora cuando se pide la lista.
# En HostGator el proceso puede no reiniciarse durante horas, así que este mecanismo
# cubre el intervalo entre reinicios sin necesidad de cron ni threads.
import time as _time
_last_expire_check: float = 0.0
_EXPIRE_CHECK_INTERVAL = 3600  # segundos


# ── Esquemas de request locales ───────────────────────────────────────────────

class EphemeralCertRequest(BaseModel):
    # Solicitud para generar un certificado efímero sin crear un nuevo usuario.
    duration_minutes: int

class RenovarCertRequest(BaseModel):
    # Solicitud para reemitir el certificado de una identidad existente.
    days_valid: int

class EphemeralUserRequest(BaseModel):
    # Solicitud para crear un usuario temporal con certificado de corta duración.
    nombre: str
    email: str
    password: str
    duration_minutes: int


# ── Jerarquía de roles ────────────────────────────────────────────────────────

# Número más bajo = mayor nivel de autoridad en el sistema
ROLE_LEVELS = {
    "Admin": 1,
    "Coordinator": 2,
    "Operative": 3,
    "External": 4
}

def check_hierarchy(actor: Identity, target_role: str):
    # Verifica que el actor tenga nivel jerárquico estrictamente mayor que el objetivo.
    # Nadie puede operar sobre alguien de igual o mayor jerarquía que la propia.
    actor_level = ROLE_LEVELS.get(actor.rol, 99)
    target_level = ROLE_LEVELS.get(target_role, 99)

    if actor_level >= target_level:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Acceso denegado: Un perfil '{actor.rol}' no puede realizar la acción sobre nivel '{target_role}'."
        )


# ── I. ALTA ───────────────────────────────────────────────────────────────────

@router.post("/alta")
def endpoint_alta(data: IdentityCreate, db: Session = Depends(get_db), current_user: Identity = Depends(get_current_identity)):
    """
    Crea una nueva identidad en el sistema.
    Solo el Admin puede ejecutarlo; solo puede crear roles de nivel inferior al suyo.
    Retorna la identidad creada junto con su certificado y clave privada (única entrega).
    """
    # El consentimiento explícito del titular es obligatorio (Derecho ARCO, punto 4)
    if not data.consentimiento_alta:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Se requiere consentimiento explícito del titular para registrar sus datos (Derecho ARCO)."
        )

    # Solo el Admin de nivel 1 puede dar de alta a nuevos colaboradores
    if current_user.rol != "Admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acceso denegado: Solo los administradores de nivel 1 pueden crear nuevos colaboradores."
        )
    check_hierarchy(current_user, data.rol)

    # Verificamos que el email no esté ya registrado
    if db.query(Identity).filter(Identity.email == data.email).first():
        raise HTTPException(status_code=400, detail="El correo ya se encuentra enlazado a otra identidad.")

    # Solo Admin y Coordinator reciben certificado X.509; los niveles bajos no lo necesitan
    cert_expires_at = None
    private_key_pem_str = None
    if data.rol in ("Admin", "Coordinator"):
        days_valid = data.cert_days_valid if data.cert_days_valid and data.cert_days_valid > 0 else 365
        ca_priv, ca_cert, _, _ = build_root_ca()
        priv_obj, priv_pem, pub_obj, pub_pem = generate_key_pair()
        user_cert_pem = generate_user_certificate(pub_obj, data.nombre, ca_priv, ca_cert, days_valid=days_valid, email=data.email)
        pub_pem_str = pub_pem.decode('utf-8')
        cert_pem_str = user_cert_pem.decode('utf-8')
        private_key_pem_str = priv_pem.decode('utf-8')   # Se entregará al admin, no se almacena en texto plano
        cert_expires_at = datetime.datetime.utcnow() + datetime.timedelta(days=days_valid)
    else:
        pub_pem_str = None
        cert_pem_str = None

    hashed_password = get_password_hash(data.password)

    # Ciframos la clave privada antes de persistirla; la DB nunca ve el PEM original
    encrypted_priv = encrypt_private_key(priv_pem) if data.rol in ("Admin", "Coordinator") else None

    new_identity = create_identity(
        db,
        data.nombre,
        data.email,
        hashed_password,
        data.rol,
        pub_pem_str,
        cert_pem_str,
        cert_expires_at=cert_expires_at,
        private_key_pem_encrypted=encrypted_priv,
    )

    # Registramos el consentimiento con su timestamp exacto (Derecho ARCO, punto 4)
    consent_timestamp = datetime.datetime.utcnow()
    new_identity.consentimiento_alta = True
    new_identity.fecha_consentimiento_alta = consent_timestamp
    db.commit()
    db.refresh(new_identity)

    log_audit_event(
        db=db,
        identity_id=new_identity.id,
        actor_id=current_user.id,
        accion="ALTA",
        detalles=f"Alta exitosa. Rol asignado: {data.rol}. Consentimiento ARCO otorgado en {consent_timestamp.strftime('%Y-%m-%d %H:%M:%S')} UTC."
    )

    # Devolvemos el certificado y la clave privada en claro en esta única respuesta.
    # Es responsabilidad del Admin distribuirla de forma segura al nuevo colaborador.
    response = {
        "id": new_identity.id,
        "codigo": new_identity.codigo,
        "nombre": new_identity.nombre,
        "email": new_identity.email,
        "rol": new_identity.rol,
        "estado": new_identity.estado,
        "cert_expires_at": new_identity.cert_expires_at.isoformat() if new_identity.cert_expires_at else None,
        "certificate_pem": cert_pem_str,
        "public_key_pem": pub_pem_str,
        "private_key_pem": private_key_pem_str,
    }
    return response


# ── Rutas estáticas (deben declararse antes de las rutas con parámetros) ──────

@router.get("/verify-candidates")
def verify_candidates(db: Session = Depends(get_db), current_user: Identity = Depends(get_current_identity)):
    """Lista de usuarios con certificado activo que pueden ser candidatos para verificar una firma.
    Solo devuelve información pública: id, nombre, email y rol."""
    users = db.query(Identity).filter(
        Identity.estado == "ACTIVO",
        Identity.certificate_pem != None,
        Identity.public_key_pem != None,
    ).all()
    return [{"id": u.id, "nombre": u.nombre, "email": u.email, "rol": u.rol} for u in users]


@router.get("/public-verify-candidates", include_in_schema=False)
def public_verify_candidates(db: Session = Depends(get_db)):
    """Versión pública (sin autenticación) de verify-candidates.
    Usada desde la página pública de mensajes externos."""
    users = db.query(Identity).filter(
        Identity.estado == "ACTIVO",
        Identity.certificate_pem != None,
        Identity.public_key_pem != None,
    ).all()
    return [{"id": u.id, "nombre": u.nombre, "email": u.email, "rol": u.rol} for u in users]


@router.get("/")
def endpoint_get_all(db: Session = Depends(get_db), current_user: Identity = Depends(get_current_identity)):
    # Devuelve la lista completa de identidades registradas.
    # Aprovecha la consulta para ejecutar la limpieza periódica de efímeros (máx. 1/hora).
    global _last_expire_check
    now = _time.time()
    if now - _last_expire_check > _EXPIRE_CHECK_INTERVAL:
        _last_expire_check = now
        expire_stale_identities(db)
    return db.query(Identity).all()

@router.get("/certificates/all")
def endpoint_certificates(db: Session = Depends(get_db), current_user: Identity = Depends(get_current_identity)):
    # Lista todas las identidades junto con su estado de certificado.
    return db.query(Identity).all()

@router.get("/audit/all")
def endpoint_audit_all(db: Session = Depends(get_db), current_user: Identity = Depends(get_current_identity)):
    # Devuelve el log de auditoría global. Restringido a Admin.
    if current_user.rol != "Admin":
        raise HTTPException(status_code=403, detail="Lectura Global restringida. Sólo los roles Admin pueden ver el log completo.")
    return get_audit_logs(db, identity_id=None)


# ── VIII. CERTIFICADO EFÍMERO (sin usuario nuevo) ─────────────────────────────

@router.post("/ephemeral/create")
def endpoint_create_ephemeral_cert(request: EphemeralCertRequest, db: Session = Depends(get_db), current_user: Identity = Depends(get_current_identity)):
    """
    Genera un certificado efímero para el usuario autenticado.
    Útil para firmar operaciones puntuales sin comprometer el certificado principal.
    Duración mínima: 1 minuto. Máxima: 7 días.
    """
    if request.duration_minutes < 1 or request.duration_minutes > 7 * 24 * 60:
        raise HTTPException(status_code=400, detail="La duración debe estar entre 1 minuto y 7 días.")

    try:
        ca_private_key, ca_cert, _, _ = build_root_ca()

        # Generamos el certificado efímero con su propio par de llaves
        cert_obj, cert_pem, private_pem, public_pem = create_ephemeral_certificate(
            user_name=current_user.email,
            duration_minutes=request.duration_minutes,
            ca_private_key=ca_private_key,
            ca_cert=ca_cert
        )

        log_audit_event(
            db=db,
            identity_id=current_user.id,
            actor_id=current_user.id,
            accion="EPHEMERAL_CERT_CREATED",
            detalles=f"Certificado efímero creado con duración de {request.duration_minutes} minuto(s)"
        )

        # El certificado efímero no se persiste en DB; se entrega completo aquí
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


# ── IX. USUARIO EFÍMERO ───────────────────────────────────────────────────────

@router.post("/ephemeral/user")
def endpoint_create_ephemeral_user(request: EphemeralUserRequest, db: Session = Depends(get_db), current_user: Identity = Depends(get_current_identity)):
    """
    Crea un usuario temporal con rol External y certificado de corta duración.
    Al vencer el certificado, el usuario pierde acceso automáticamente.
    """
    if request.duration_minutes < 1 or request.duration_minutes > 7 * 24 * 60:
        raise HTTPException(status_code=400, detail="La duración debe estar entre 1 minuto y 7 días.")

    if not request.password or len(request.password) < 4:
        raise HTTPException(status_code=400, detail="La contraseña debe tener al menos 4 caracteres.")

    if db.query(Identity).filter(Identity.email == request.email).first():
        raise HTTPException(status_code=400, detail="El correo ya se encuentra enlazado a otra identidad.")

    try:
        hashed_password = get_password_hash(request.password)
        ca_private_key, ca_cert, _, _ = build_root_ca()

        # El usuario efímero recibe su propio par de llaves y certificado temporal
        cert_obj, cert_pem, _, public_pem = create_ephemeral_certificate(
            user_name=request.email,
            duration_minutes=request.duration_minutes,
            ca_private_key=ca_private_key,
            ca_cert=ca_cert
        )

        # Siempre asignamos rol External para limitar los permisos del usuario temporal
        new_identity = create_identity(
            db,
            nombre=request.nombre,
            email=request.email,
            password_hash=hashed_password,
            rol="External",
            public_key_pem=public_pem.decode('utf-8') if isinstance(public_pem, bytes) else public_pem,
            certificate_pem=cert_pem.decode('utf-8') if isinstance(cert_pem, bytes) else cert_pem
        )

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
            "message": f"Usuario efímero creado exitosamente. Acceso válido hasta las {(cert_obj.not_valid_after - datetime.timedelta(hours=6)).strftime('%H:%M:%S')} (hora del centro de México)."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al crear usuario efímero: {str(e)}")


# ── Rutas dinámicas (con path parameter) ─────────────────────────────────────

@router.get("/{identity_id}/download-cert")
def endpoint_download_cert(identity_id: int, db: Session = Depends(get_db), current_user: Identity = Depends(get_current_identity)):
    """
    Descarga el certificado X.509, la clave pública y la clave privada de una identidad,
    entregándolos por separado en la respuesta.
    Solo el propio titular o un Admin pueden realizar la descarga.
    La clave privada se descifra en memoria; nunca sale en texto plano de la base de datos.
    Cada descarga queda registrada en el log de auditoría.
    """
    target = db.query(Identity).filter(Identity.id == identity_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Identidad no encontrada.")

    # Nadie más que el titular o un Admin puede ver las llaves de otra persona
    if current_user.id != target.id and current_user.rol != "Admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acceso denegado: Solo el propio usuario o un administrador pueden descargar este certificado."
        )

    if not target.certificate_pem:
        raise HTTPException(status_code=400, detail="Esta identidad no tiene certificado asignado.")

    # Desciframos la clave privada en memoria para entregarla al cliente autorizado
    private_key_pem = None
    if target.private_key_pem_encrypted:
        try:
            private_key_pem = decrypt_private_key(target.private_key_pem_encrypted).decode('utf-8')
        except Exception:
            raise HTTPException(status_code=500, detail="Error al descifrar la clave privada.")

    log_audit_event(
        db=db,
        identity_id=identity_id,
        actor_id=current_user.id,
        accion="CERT_DESCARGADO",
        detalles=f"Certificado descargado por {'el propio usuario' if current_user.id == identity_id else f'administrador (ID {current_user.id})'}."
    )

    # Devolvemos los tres componentes por separado para que el cliente los gestione individualmente
    return {
        "identity_id": target.id,
        "nombre": target.nombre,
        "email": target.email,
        "certificate_pem": target.certificate_pem,
        "public_key_pem": target.public_key_pem,
        "private_key_pem": private_key_pem,
        "cert_expires_at": target.cert_expires_at.isoformat() if target.cert_expires_at else None,
    }


# ── V-A. EXPORTAR PKCS#12 (S/MIME) ───────────────────────────────────────────

# ── V-B. FIRMAR CON S/MIME ────────────────────────────────────────────────────

@router.post("/{identity_id}/smime/sign")
def endpoint_sign_smime(identity_id: int, data: SMimeSignRequest, db: Session = Depends(get_db), current_user: Identity = Depends(get_current_identity)):
    """
    Firma digitalmente el contenido proporcionado usando la clave privada RSA de la identidad.
    Devuelve el mensaje S/MIME completo (multipart/signed, PKCS#7 detached) listo para enviar.

    Solo el propio titular puede firmar con su identidad; el Admin no puede hacerlo
    en nombre de otro (la firma representa la autoría del titular).
    """
    if current_user.id != identity_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acceso denegado: Solo el titular puede firmar con su propia identidad."
        )

    target = db.query(Identity).filter(Identity.id == identity_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Identidad no encontrada.")

    if target.estado != "ACTIVO":
        raise HTTPException(status_code=400, detail="No se puede firmar con una identidad revocada o inactiva.")

    if not target.certificate_pem or not target.private_key_pem_encrypted:
        raise HTTPException(status_code=400, detail="Esta identidad no tiene certificado o clave privada almacenados.")

    if not data.content or not data.content.strip():
        raise HTTPException(status_code=400, detail="El contenido a firmar no puede estar vacío.")

    try:
        private_key_pem = decrypt_private_key(target.private_key_pem_encrypted).decode('utf-8')
    except Exception:
        raise HTTPException(status_code=500, detail="Error al descifrar la clave privada.")

    try:
        signed_message = sign_smime(
            message_str=data.content,
            cert_pem_str=target.certificate_pem,
            private_key_pem_str=private_key_pem
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Error al generar la firma S/MIME: " + str(exc))

    log_audit_event(
        db=db,
        identity_id=identity_id,
        actor_id=current_user.id,
        accion="SMIME_FIRMADO",
        detalles="Mensaje firmado digitalmente con S/MIME PKCS#7."
    )

    return {
        "identity_id": target.id,
        "nombre": target.nombre,
        "email": target.email,
        "signed_message": signed_message,
        "format": "S/MIME multipart/signed (PKCS#7 detached, SHA-256)"
    }


@router.put("/{identity_id}/renovar-cert")
def endpoint_renovar_cert(identity_id: int, data: RenovarCertRequest, db: Session = Depends(get_db), current_user: Identity = Depends(get_current_identity)):
    """
    Renueva el certificado de una identidad: revoca el actual, genera un nuevo par de
    llaves y emite un certificado fresco con la duración indicada.
    Solo disponible para Admin y Coordinator.
    """
    if data.days_valid < 1 or data.days_valid > 3650:
        raise HTTPException(status_code=400, detail="La duración debe estar entre 1 y 3650 días.")

    target = db.query(Identity).filter(Identity.id == identity_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Identidad no encontrada.")

    if target.rol not in ("Admin", "Coordinator"):
        raise HTTPException(status_code=400, detail="Solo Admin y Coordinator tienen certificados renovables.")

    check_hierarchy(current_user, target.rol)

    # Paso 1: invalidamos el certificado actual antes de emitir el nuevo
    target.estado = "REVOCADO"
    db.commit()

    log_audit_event(
        db=db,
        identity_id=identity_id,
        actor_id=current_user.id,
        accion="REVOCACION",
        detalles=f"Certificado revocado automáticamente como parte de la renovación de certificado."
    )

    # Paso 2: generamos nuevo par de llaves y certificado firmado por la CA
    ca_priv, ca_cert, _, _ = build_root_ca()
    priv_obj, priv_pem, pub_obj, pub_pem = generate_key_pair()
    new_cert_pem = generate_user_certificate(pub_obj, target.nombre, ca_priv, ca_cert, days_valid=data.days_valid, email=target.email)
    new_expires_at = datetime.datetime.utcnow() + datetime.timedelta(days=data.days_valid)

    # Paso 3: persistimos el nuevo material criptográfico y reactivamos la identidad
    target.public_key_pem = pub_pem.decode('utf-8')
    target.certificate_pem = new_cert_pem.decode('utf-8')
    target.private_key_pem_encrypted = encrypt_private_key(priv_pem)  # Guardamos cifrada, no en texto plano
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
    """
    Reactiva un certificado revocado sin emitir uno nuevo.
    Solo el Admin puede hacerlo; útil cuando la revocación fue un error.
    """
    if current_user.rol != "Admin":
        raise HTTPException(status_code=403, detail="Solo los administradores pueden revalidar certificados.")

    target = db.query(Identity).filter(Identity.id == identity_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Identidad no encontrada.")

    if target.rol not in ("Admin", "Coordinator"):
        raise HTTPException(status_code=400, detail="Solo Admin y Coordinator tienen certificados revalidables.")

    if target.estado != "REVOCADO":
        raise HTTPException(status_code=400, detail="El certificado no está revocado.")

    # Marcamos como revalidado para distinguirlo de un certificado nunca revocado
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


# ── II. REVOCACIÓN ────────────────────────────────────────────────────────────

@router.put("/{identity_id}/revocar")
def endpoint_revocacion(identity_id: int, data: IdentityStatusUpdate, db: Session = Depends(get_db), current_user: Identity = Depends(get_current_identity)):
    """
    Invalida el certificado de una identidad. El usuario persiste en la DB
    pero no puede iniciar sesión mientras su estado sea REVOCADO.
    """
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


# ── III. BAJA ─────────────────────────────────────────────────────────────────

@router.delete("/{identity_id}/baja")
def endpoint_baja(identity_id: int, data: BajaRequest, db: Session = Depends(get_db), current_user: Identity = Depends(get_current_identity)):
    """
    Elimina físicamente una identidad de la base de datos (hard delete).
    Operación irreversible; solo el Admin puede ejecutarla.
    Requiere consentimiento explícito de baja conforme al Derecho ARCO (punto 4).
    """
    # El consentimiento explícito de salida es obligatorio (Derecho ARCO, punto 4)
    if not data.consentimiento_baja:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Se requiere consentimiento explícito del titular para eliminar sus datos (Derecho ARCO)."
        )

    if current_user.rol != "Admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Acceso denegado: Solo los administradores de nivel 1 pueden dar de baja a un colaborador.")

    target = db.query(Identity).filter(Identity.id == identity_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="La identidad objetivo a borrar ya no existe.")

    check_hierarchy(current_user, target.rol)

    nombre_target = target.nombre
    consent_timestamp = datetime.datetime.utcnow()
    delete_identity(db, identity_id, hard_delete=True)

    # El log persiste aunque la identidad se elimine (identity_id nullable en AuditLog)
    log_audit_event(
        db=db,
        identity_id=identity_id,
        actor_id=current_user.id,
        accion="BAJA",
        detalles=(
            f"El colaborador {nombre_target} ha sido eliminado físicamente de la Base de Datos. "
            f"Consentimiento de baja ARCO registrado en {consent_timestamp.strftime('%Y-%m-%d %H:%M:%S')} UTC."
        )
    )

    return {"message": f"Usuario {nombre_target} ha sido eliminado definitivamente de la DB."}


# ── IV. RASTREO ───────────────────────────────────────────────────────────────

@router.get("/{identity_id}/rastreo")
def endpoint_rastreo(identity_id: int, db: Session = Depends(get_db), current_user: Identity = Depends(get_current_identity)):
    """
    Devuelve el historial de auditoría de una identidad.
    Con identity_id=0 el Admin puede ver el log global completo.
    """
    # El ID 0 es una convención para solicitar el log global (solo Admin)
    if identity_id == 0:
        if current_user.rol != "Admin":
            raise HTTPException(status_code=403, detail="Lectura Global restringida. Sólo los roles Admin pueden ver el log completo.")
        logs = get_audit_logs(db, identity_id=None)
        return logs

    target = db.query(Identity).filter(Identity.id == identity_id).first()
    if target:
        # Un usuario puede ver su propio rastreo; para ver el de otro necesita jerarquía
        if current_user.id != target.id:
            check_hierarchy(current_user, target.rol)

    logs = get_audit_logs(db, identity_id=identity_id)
    return logs
