# Esquemas de validación para el módulo de correo firmado.
# Compatible con Python 3.6.8: se usa `typing` explícitamente.

from pydantic import BaseModel
from typing import List, Optional, Dict, Any


class SendSignedEmailRequest(BaseModel):
    """
    Payload para firmar y enviar un correo a través de la cuenta Outlook del usuario.
    - to_email: correo destino.
    - subject:  asunto del mensaje.
    - body_text: cuerpo en texto plano que será firmado.
    - attachments: lista opcional de diccionarios con al menos las claves
                   'filename' (str) y 'content' (str, base64 o texto plano).
    - ms_access_token: Access Token obtenido del flujo OAuth2 con Microsoft.
    """
    to_email: str
    subject: str
    body_text: str
    attachments: Optional[List[Dict[str, Any]]] = []
    ms_access_token: str   # Token de Graph API del usuario autenticado en Outlook


class VerifyEmailRequest(BaseModel):
    """
    Payload para verificar la firma de un correo recibido.
    El cliente debe extraer estos datos de los adjuntos del mensaje:
    - body_text:        cuerpo original del correo.
    - attachments:      adjuntos originales (misma estructura que en el envío).
    - signature_base64: contenido del archivo 'signature.sig' en Base64.
    - sender_cert_pem:  contenido del archivo 'certificate.pem' (certificado X.509 público).
    """
    body_text: str
    attachments: Optional[List[Dict[str, Any]]] = []
    signature_base64: str
    sender_cert_pem: str
