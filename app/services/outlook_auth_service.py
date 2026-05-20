# Servicio de autenticación OAuth2 con Microsoft Identity Platform (MSAL).
# Implementa el flujo Authorization Code para que el usuario inicie sesión
# con su cuenta personal de Outlook y otorgue permiso de envío de correo.
# Compatible con Python 3.6.8.

import os
from typing import Optional, Dict, Any

import msal


# ── Configuración desde variables de entorno ─────────────────────────────────

CLIENT_ID     = os.environ.get("MS_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("MS_CLIENT_SECRET", "")
TENANT_ID     = os.environ.get("MS_TENANT_ID", "common")   # "common" permite cuentas personales y organizacionales
REDIRECT_URI  = os.environ.get("MS_REDIRECT_URI", "http://localhost:8000/api/v1/auth/outlook/callback")

# Scopes requeridos: envío de correo y perfil básico del usuario
SCOPES = ["https://graph.microsoft.com/Mail.Send",
          "https://graph.microsoft.com/User.Read"]


# Endpoint de autoridad de Microsoft Identity
AUTHORITY = "https://login.microsoftonline.com/{}".format(TENANT_ID)


def _build_msal_app():
    # type: () -> msal.ConfidentialClientApplication
    """
    Crea y devuelve una instancia de ConfidentialClientApplication de MSAL.
    Esta clase maneja internamente el token cache y la negociación OAuth2.
    """
    return msal.ConfidentialClientApplication(
        client_id=CLIENT_ID,
        client_credential=CLIENT_SECRET,
        authority=AUTHORITY,
    )


def get_auth_url():
    # type: () -> str
    """
    Genera la URL de autorización de Microsoft a la que se debe redirigir al usuario.
    El usuario verá la pantalla de inicio de sesión de Outlook y otorgará permisos.
    Retorna: URL completa (string).
    """
    app = _build_msal_app()
    auth_url = app.get_authorization_request_url(
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
    )
    return auth_url


def get_token_from_code(auth_code):
    # type: (str) -> Optional[Dict[str, Any]]
    """
    Intercambia el código de autorización devuelto por Microsoft por un Access Token.
    Este token se usará para llamar a Microsoft Graph API en nombre del usuario.

    Parámetros:
        auth_code: El código de un solo uso recibido en el callback de OAuth2.

    Retorna:
        Diccionario con 'access_token', 'expires_in', 'scope', etc.
        Retorna None si el intercambio falla.
    """
    app = _build_msal_app()
    result = app.acquire_token_by_authorization_code(
        code=auth_code,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
    )

    # MSAL devuelve 'error' en el dict si algo salió mal
    if "error" in result:
        return None

    return result
