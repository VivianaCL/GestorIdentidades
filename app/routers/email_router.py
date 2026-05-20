# Endpoint para manejar el flujo de autenticación OAuth2 de Outlook
# y el envío y verificación de correos firmados criptográficamente.
# Compatible con Python 3.6.8.

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.db.database import get_db, log_audit_event
from app.models.identity import Identity
from app.core.crypto import get_current_identity
from app.schemas.email_schemas import SendSignedEmailRequest, VerifyEmailRequest
from app.services.outlook_auth_service import get_auth_url, get_token_from_code
from app.services.crypto_email_service import sign_and_package_email, verify_email
from app.services.smtp_service import send_smtp_message
import os
import email

router = APIRouter()


# ── 1. Inicio de sesión con Outlook (OAuth2) ─────────────────────────────────

@router.get("/auth/outlook/login")
def outlook_login():
    """
    Retorna la URL de autorización de Microsoft.
    El frontend debe redirigir al usuario a esta URL para que inicie sesión en Outlook.
    """
    url = get_auth_url()
    return {"auth_url": url}


@router.get("/auth/outlook/callback")
def outlook_callback(code: str = Query(None), error: str = Query(None), error_description: str = Query(None)):
    """
    Recibe el código de autorización ('code') desde Microsoft tras el inicio de sesión.
    Intercambia el código por un Access Token de Graph API.
    """
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Error en autenticación de Outlook: {} - {}".format(error, error_description)
        )
        
    if not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No se recibió código de autorización de Microsoft."
        )
        
    token_response = get_token_from_code(code)
    
    if not token_response or "access_token" not in token_response:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Fallo al intercambiar el código por un token de acceso de Microsoft."
        )
        
    return {
        "ms_access_token": token_response["access_token"],
        "expires_in": token_response.get("expires_in"),
        "message": "Autenticación exitosa con Outlook. Guarda el 'ms_access_token' para enviar correos."
    }


# ── 2. Firma y envío de correo a través de Outlook ───────────────────────────

@router.post("/mail/send-signed")
def send_signed_email_endpoint(
    request: SendSignedEmailRequest,
    db: Session = Depends(get_db),
    current_user: Identity = Depends(get_current_identity)
):
    """
    Firma criptográficamente el correo y lo envía usando la cuenta de Outlook
    del usuario autenticado (requiere ms_access_token).
    """
    try:
        # 1. Empaquetar y firmar el mensaje
        mime_bytes = sign_and_package_email(
            user_db_obj=current_user,
            to_email=request.to_email,
            subject=request.subject,
            body_text=request.body_text,
            attachments=request.attachments
        )
        
        # 2. Enviar a través de SMTP usando las credenciales del .env
        smtp_user = os.environ.get("SMTP_USER")
        smtp_password = os.environ.get("SMTP_PASSWORD")
        
        if not smtp_user or not smtp_password or smtp_user == "tu_correo@casamonarca.org":
            raise ValueError("Las credenciales SMTP (SMTP_USER y SMTP_PASSWORD) no están configuradas en el archivo .env")
            
        # Parsear los bytes MIME de vuelta a un objeto EmailMessage o MIMEMultipart para smtplib
        mime_msg_obj = email.message_from_bytes(mime_bytes)
        
        send_smtp_message(
            mime_message=mime_msg_obj,
            smtp_user=smtp_user,
            smtp_password=smtp_password
        )
        
        # 3. Registrar en Auditoría
        log_audit_event(
            db=db,
            identity_id=current_user.id,
            actor_id=current_user.id,
            accion="EMAIL_SIGNED_AND_SENT",
            detalles="Correo seguro enviado a {}".format(request.to_email)
        )
        
        return {"success": True, "message": "Correo firmado y enviado exitosamente a {}".format(request.to_email)}
        
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error interno: {}".format(str(e)))


# ── 3. Verificación de firmas ────────────────────────────────────────────────

@router.post("/mail/verify")
def verify_email_endpoint(
    request: VerifyEmailRequest,
    db: Session = Depends(get_db),
    current_user: Identity = Depends(get_current_identity)
):
    """
    Endpoint para que cualquier usuario verifique la firma de un correo que recibió.
    El cliente extrae el texto, los adjuntos originales, 'signature.sig' (en base64) y 'certificate.pem'.
    """
    es_valido, mensaje = verify_email(
        body_text=request.body_text,
        attachments=request.attachments,
        signature_base64=request.signature_base64,
        sender_cert_pem=request.sender_cert_pem
    )
    
    # Registrar la verificación en el log de auditoría
    log_audit_event(
        db=db,
        identity_id=current_user.id,
        actor_id=current_user.id,
        accion="EMAIL_VERIFIED",
        detalles="Verificación de firma de correo solicitada. Resultado: {}".format("Válido" if es_valido else "Inválido")
    )
    
    if not es_valido:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=mensaje
        )
        
    return {"success": True, "message": mensaje}
