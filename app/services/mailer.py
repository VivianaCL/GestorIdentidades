# Servicio de envío de correo electrónico.
# Soporta dos modos controlados por la variable de entorno SMTP_ENABLED:
#
#   SMTP_ENABLED=false (desarrollo local)
#     → No envía ningún email. Devuelve el enlace generado para que el
#       desarrollador pueda probarlo directamente en el navegador.
#
#   SMTP_ENABLED=true (producción en HostGator)
#     → Envía el email real vía SMTP usando las credenciales del .env.

import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

SMTP_ENABLED  = os.environ.get("SMTP_ENABLED", "false").lower() == "true"
SMTP_HOST     = os.environ.get("SMTP_HOST", "")
SMTP_PORT     = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER     = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM     = os.environ.get("SMTP_FROM", SMTP_USER)

# URL base del sistema; se usa para construir los enlaces externos
BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:8000")


def send_external_message(recipient_email, sender_name, subject, body_preview, token, firmado=False):
    """
    Envía al destinatario externo un correo con el enlace de un solo uso.

    En modo desarrollo (SMTP_ENABLED=false) solo retorna el enlace sin enviar nada.
    En producción envía el email real y también retorna el enlace.

    Retorna: (enviado: bool, enlace: str)
    """
    link = "{}/mensaje-externo?token={}".format(BASE_URL, token)

    if not SMTP_ENABLED:
        # Modo desarrollo: no envía — el enlace se muestra en el frontend
        return False, link

    firma_badge = ""
    if firmado:
        firma_badge = """
      <div style="margin:20px 0;padding:14px 18px;background:#f0faf4;border:1px solid #4fb87a66;
                  border-radius:8px;display:flex;align-items:flex-start;gap:12px">
        <span style="font-size:20px;color:#4fb87a;flex-shrink:0">&#10004;</span>
        <div>
          <div style="font-size:13px;font-weight:600;color:#2e7d52;margin-bottom:3px">
            Mensaje firmado digitalmente
          </div>
          <div style="font-size:12px;color:#555;line-height:1.5">
            Este mensaje fue firmado por <strong>{sender}</strong> con su certificado
            digital. Puedes verificar la autenticidad de la firma en el enlace.
          </div>
        </div>
      </div>""".format(sender=sender_name)

    html_body = """
    <div style="font-family:sans-serif;max-width:560px;margin:auto;padding:32px;
                background:#fafafa;border:1px solid #e0e0e0;border-radius:10px">
      <h2 style="color:#c46a1f;margin-bottom:4px">Tienes un mensaje de {sender}</h2>
      <p style="color:#555;font-size:13px;margin-bottom:24px">
        <strong>{subject}</strong>
      </p>
      <p style="color:#333;font-size:14px;line-height:1.6">{preview}</p>
      {firma_badge}
      <div style="margin:28px 0;text-align:center">
        <a href="{link}"
           style="background:#e8a045;color:#fff;padding:12px 28px;border-radius:8px;
                  text-decoration:none;font-weight:600;font-size:14px">
          Ver mensaje completo y verificar firma
        </a>
      </div>
      <p style="color:#aaa;font-size:11px;text-align:center">
        Este enlace es de un solo uso: solo funciona una vez.<br>
        Si no esperabas este mensaje, puedes ignorarlo.
      </p>
    </div>
    """.format(
        sender=sender_name,
        subject=subject,
        preview=body_preview[:200] + ("..." if len(body_preview) > 200 else ""),
        firma_badge=firma_badge,
        link=link
    )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "[Casa Monarca] Mensaje firmado de {}".format(sender_name)
    msg["From"]    = SMTP_FROM
    msg["To"]      = recipient_email
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_FROM, [recipient_email], msg.as_string())
        return True, link
    except Exception as exc:
        # Si falla el envío retornamos el error pero no rompemos el flujo
        raise RuntimeError("Error SMTP: {}".format(str(exc)))
