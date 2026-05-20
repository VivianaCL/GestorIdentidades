# Servicio para enviar correos electrónicos a través de Microsoft Graph API.
# Compatible con Python 3.6.8.

import base64
import requests

def send_mime_via_graph(access_token, mime_content_bytes):
    # type: (str, bytes) -> bool
    """
    Envía un mensaje en formato MIME utilizando Microsoft Graph API.
    
    Parámetros:
        access_token: Token de acceso válido obtenido vía MSAL (OAuth2).
        mime_content_bytes: Mensaje serializado en bytes (generado por MIMEMultipart).
        
    Retorna:
        True si se envió correctamente. Lanza excepción en caso de error.
    """
    # Graph API requiere que el contenido MIME esté codificado en Base64
    mime_base64 = base64.b64encode(mime_content_bytes).decode('utf-8')
    
    # Endpoint para enviar correo como el usuario autenticado
    url = "https://graph.microsoft.com/v1.0/me/sendMail"
    
    headers = {
        "Authorization": "Bearer {}".format(access_token),
        "Content-Type": "text/plain"  # Cuando pasamos MIME, el Content-Type debe ser text/plain
    }
    
    # MS Graph API requiere este formato exacto para enviar mensajes MIME directamente
    payload = mime_base64
    
    response = requests.post(url, headers=headers, data=payload)
    
    if response.status_code == 202:
        return True
    else:
        error_msg = "Error al enviar correo vía MS Graph. Código: {}. Detalle: {}".format(
            response.status_code, response.text
        )
        raise Exception(error_msg)
