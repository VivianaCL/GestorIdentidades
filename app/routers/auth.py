# Router de autenticación.
# Gestiona el inicio y cierre de sesión usando JWT.
# El login valida credenciales, verifica que la cuenta esté activa y que el
# certificado digital no haya vencido antes de emitir el token de acceso.

import datetime
from datetime import timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from app.db.database import get_db, log_audit_event
from app.models.identity import Identity
from app.schemas.identity import Token, MFASetupResponse, MFAConfirmSetup, MFAValidate, MFADisable, MFAStatusResponse
from app.core.crypto import (
    verify_password, create_access_token, get_current_identity,
    ACCESS_TOKEN_EXPIRE_MINUTES, encrypt_private_key, decrypt_private_key,
    generate_totp_secret, get_totp_uri, verify_totp_code,
    create_mfa_pending_token, decode_mfa_pending_token,
)

router = APIRouter()


@router.post("/login")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # Buscamos al usuario por email; si no existe, devolvemos error genérico
    # (no revelamos si el email está o no registrado).
    user = db.query(Identity).filter(Identity.email == form_data.username).first()
    if_failed_login = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Correo electrónico o contraseña incorrectos",
    )

    if not user:
        raise if_failed_login

    # Verificamos la contraseña contra el hash almacenado
    if not verify_password(form_data.password, user.password_hash):
        log_audit_event(db, identity_id=user.id, actor_id=user.id, accion="LOGIN_FAILED", detalles="Contraseña incorrecta")
        raise if_failed_login

    # Bloqueamos si la cuenta fue revocada o dada de baja
    if user.estado != "ACTIVO":
        log_audit_event(db, identity_id=user.id, actor_id=user.id, accion="LOGIN_FAILED", detalles="Usuario bloqueado/inactivo")
        raise HTTPException(status_code=403, detail="La cuenta no está activa.")

    # Impedimos el acceso si el certificado X.509 expiró, sin importar la contraseña
    if user.cert_expires_at is not None:
        expires = user.cert_expires_at
        now = datetime.datetime.now(timezone.utc) if expires.tzinfo else datetime.datetime.utcnow()
        if now > expires:
            log_audit_event(db, identity_id=user.id, actor_id=user.id, accion="LOGIN_FAILED", detalles="Certificado digital vencido")
            raise HTTPException(status_code=403, detail="Acceso denegado: el certificado digital ha vencido.")

    # Si MFA está activo, emitimos un token temporal y pedimos el segundo factor
    if user.mfa_enabled:
        temp_token = create_mfa_pending_token(user.email)
        log_audit_event(db, identity_id=user.id, actor_id=user.id, accion="MFA_CHALLENGE", detalles="Segundo factor solicitado")
        return {"mfa_required": True, "temp_token": temp_token}

    # Sin MFA: generamos el JWT definitivo con el email y rol del usuario
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email, "rol": user.rol}, expires_delta=access_token_expires
    )

    log_audit_event(db, identity_id=user.id, actor_id=user.id, accion="LOGIN_SUCCESS", detalles="Inicio de sesión exitoso vía API")
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/mfa/validate", response_model=Token)
def mfa_validate(payload: MFAValidate, db: Session = Depends(get_db)):
    # Segunda fase del login: valida el código TOTP con el token temporal.
    invalid_exc = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Código MFA inválido o sesión expirada.")

    try:
        email = decode_mfa_pending_token(payload.temp_token)
    except ValueError:
        raise invalid_exc

    user = db.query(Identity).filter(Identity.email == email).first()
    if not user or not user.mfa_enabled or not user.totp_secret_encrypted:
        raise invalid_exc

    secret = decrypt_private_key(user.totp_secret_encrypted).decode()
    if not verify_totp_code(secret, payload.code):
        log_audit_event(db, identity_id=user.id, actor_id=user.id, accion="LOGIN_FAILED", detalles="Código MFA incorrecto")
        raise invalid_exc

    access_token = create_access_token(
        data={"sub": user.email, "rol": user.rol},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    log_audit_event(db, identity_id=user.id, actor_id=user.id, accion="LOGIN_SUCCESS", detalles="Inicio de sesión exitoso con MFA")
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/mfa/status", response_model=MFAStatusResponse)
def mfa_status(current_user: Identity = Depends(get_current_identity)):
    # Devuelve si el usuario autenticado tiene MFA activado.
    return {"mfa_enabled": bool(current_user.mfa_enabled)}


@router.post("/mfa/setup", response_model=MFASetupResponse)
def mfa_setup(current_user: Identity = Depends(get_current_identity)):
    # Genera un secreto TOTP provisional y la URI para mostrar el QR.
    # El secreto NO se guarda hasta que el usuario confirme con un código válido.
    if current_user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA ya está activado. Desactívalo primero.")
    secret = generate_totp_secret()
    uri = get_totp_uri(secret, current_user.email)
    return {"secret": secret, "uri": uri}


@router.post("/mfa/confirm-setup")
def mfa_confirm_setup(payload: MFAConfirmSetup, current_user: Identity = Depends(get_current_identity), db: Session = Depends(get_db)):
    # Valida el código TOTP con el secreto provisional y activa MFA si es correcto.
    if current_user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA ya está activado.")
    if not verify_totp_code(payload.secret, payload.code):
        raise HTTPException(status_code=400, detail="Código incorrecto. Verifica que la hora de tu dispositivo sea correcta.")
    # Re-consultamos el usuario en la sesión activa para que el commit persista
    user = db.query(Identity).filter(Identity.id == current_user.id).first()
    user.totp_secret_encrypted = encrypt_private_key(payload.secret.encode())
    user.mfa_enabled = True
    db.commit()
    log_audit_event(db, identity_id=current_user.id, actor_id=current_user.id, accion="MFA_ACTIVADO", detalles="Autenticación multifactor activada")
    return {"message": "Autenticación de dos factores activada correctamente."}


@router.post("/mfa/disable")
def mfa_disable(payload: MFADisable, current_user: Identity = Depends(get_current_identity), db: Session = Depends(get_db)):
    # Desactiva MFA tras validar el código actual como confirmación.
    if not current_user.mfa_enabled or not current_user.totp_secret_encrypted:
        raise HTTPException(status_code=400, detail="MFA no está activado.")
    secret = decrypt_private_key(current_user.totp_secret_encrypted).decode()
    if not verify_totp_code(secret, payload.code):
        raise HTTPException(status_code=400, detail="Código incorrecto.")
    # Re-consultamos en la sesión activa para que el commit persista
    user = db.query(Identity).filter(Identity.id == current_user.id).first()
    user.mfa_enabled = False
    user.totp_secret_encrypted = None
    db.commit()
    log_audit_event(db, identity_id=current_user.id, actor_id=current_user.id, accion="MFA_DESACTIVADO", detalles="Autenticación multifactor desactivada")
    return {"message": "Autenticación de dos factores desactivada."}


@router.post("/logout")
def logout(current_user: Identity = Depends(get_current_identity), db: Session = Depends(get_db)):
    # En un esquema JWT stateless el token no se invalida en servidor.
    # El logout real ocurre descartando el token en el cliente.
    # Aquí solo dejamos evidencia en el log de auditoría.
    log_audit_event(db, identity_id=current_user.id, actor_id=current_user.id, accion="LOGOUT", detalles="Cierre de sesión.")
    return {"message": "Sesión cerrada satisfactoriamente (deseche el JWT localmente)."}
