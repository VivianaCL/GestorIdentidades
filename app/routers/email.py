import os
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.database import get_db, log_audit_event
from app.models.identity import Identity
from app.schemas.email import SendSignedEmailRequest
from app.core.crypto import get_current_identity
from app.services.email_crypto_service import sign_and_package_email
from app.services.smtp_service import send_smtp_message

router = APIRouter()

@router.post("/send-signed")
def send_signed_email(
    request: SendSignedEmailRequest,
    db: Session = Depends(get_db),
    current_user: Identity = Depends(get_current_identity)
):
    """
    Firma criptográficamente un correo usando la llave privada del usuario,
    lo empaqueta con el certificado X.509 y lo envía vía Outlook (Office 365).
    """
    if not current_user.private_key_pem_encrypted or not current_user.certificate_pem:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El usuario no cuenta con un certificado o llave privada para firmar."
        )

    # Obtenemos las credenciales SMTP del entorno
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    
    if not smtp_user or not smtp_password:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Las credenciales SMTP no están configuradas en el servidor."
        )

    try:
        # Generar el paquete MIME firmado
        # La llave privada será eliminada de memoria dentro de esta función
        mime_msg = sign_and_package_email(
            sender_email=current_user.email,
            to_email=request.to_email,
            subject=request.subject,
            body_text=request.body_text,
            attachments=request.attachments or [],
            encrypted_private_key=current_user.private_key_pem_encrypted,
            certificate_pem=current_user.certificate_pem
        )

        # Enviar el correo usando SMTP de Office 365
        send_smtp_message(mime_msg, smtp_user, smtp_password)

        # Registrar la acción en el log de auditoría
        log_audit_event(
            db=db,
            identity_id=current_user.id,
            actor_id=current_user.id,
            accion="EMAIL_SIGNED_AND_SENT",
            detalles="Correo firmado y enviado a {}".format(request.to_email)
        )

        return {
            "success": True,
            "message": "Correo firmado y enviado correctamente a {}".format(request.to_email)
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error interno al enviar el correo: {}".format(str(e))
        )
