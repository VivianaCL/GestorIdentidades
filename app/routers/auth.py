from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from app.db.database import get_db, log_audit_event
from app.models.identity import Identity
from app.schemas.identity import Token
from app.core.crypto import verify_password, create_access_token, get_current_identity, ACCESS_TOKEN_EXPIRE_MINUTES

router = APIRouter()

@router.post("/login", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(Identity).filter(Identity.email == form_data.username).first()
    if_failed_login = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Correo electrónico o contraseña incorrectos",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    if not user:
        raise if_failed_login
    if not verify_password(form_data.password, user.password_hash):
        log_audit_event(db, identity_id=user.id, actor_id=user.id, accion="LOGIN_FAILED", detalles="Contraseña incorrecta")
        raise if_failed_login
        
    if user.estado != "ACTIVO":
        log_audit_event(db, identity_id=user.id, actor_id=user.id, accion="LOGIN_FAILED", detalles="Usuario bloqueado/inactivo")
        raise HTTPException(status_code=403, detail="La cuenta no está activa.")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email, "rol": user.rol}, expires_delta=access_token_expires
    )
    
    log_audit_event(db, identity_id=user.id, actor_id=user.id, accion="LOGIN_SUCCESS", detalles="Inicio de sesión exitoso vía API")
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/logout")
def logout(current_user: Identity = Depends(get_current_identity), db: Session = Depends(get_db)):
    """ 
    En JWT stateless, el logout principalmente sucede descartando el token en el Frontend.
    Para propósitos de auditoría, documentamos el suceso.
    """
    log_audit_event(db, identity_id=current_user.id, actor_id=current_user.id, accion="LOGOUT", detalles="Cierre de sesión.")
    return {"message": "Sesión cerrada satisfactoriamente (deseche el JWT localmente)."}
