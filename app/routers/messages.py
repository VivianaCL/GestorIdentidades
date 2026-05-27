# Router de mensajería interna firmada digitalmente.
# Gestiona el envío, recepción y verificación de mensajes entre usuarios
# del sistema, y el envío con enlace de un solo uso a destinatarios externos.

import secrets
import base64
import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional

from app.db.database import get_db
from app.models.identity import Identity, Message
from app.core.crypto import get_current_identity, decrypt_private_key
from app.services.mailer import send_external_message

router = APIRouter()


# ── Schemas ───────────────────────────────────────────────────────────────────

class SendInternalRequest(BaseModel):
    recipient_id: int
    subject: str
    body: str

class SendExternalRequest(BaseModel):
    recipient_email: str
    subject: str
    body: str

class MessageResponse(BaseModel):
    id: int
    sender_id: int
    sender_nombre: Optional[str]
    sender_email: Optional[str]
    recipient_id: Optional[int]
    recipient_email_ext: Optional[str]
    subject: str
    body: str
    leido: bool
    fecha_envio: str
    tiene_firma: bool

    class Config:
        orm_mode = True


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sign_body(body, sender):
    """
    Firma el cuerpo del mensaje con la clave privada RSA del remitente.
    Devuelve la firma en base64 (DER) o None si el remitente no tiene clave.

    Usamos firma RSA-PSS directamente sobre el hash SHA-256 del cuerpo,
    sin construir el envoltorio MIME completo — eso simplifica la
    verificación desde el frontend y no requiere parsear MIME.
    """
    if not sender.private_key_pem_encrypted:
        return None

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.backends import default_backend

    priv_pem = decrypt_private_key(sender.private_key_pem_encrypted)
    private_key = serialization.load_pem_private_key(
        priv_pem, password=None, backend=default_backend()
    )
    signature = private_key.sign(
        body.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode("ascii")


def _verify_signature(body, signature_b64, cert_pem_str):
    """
    Verifica la firma RSA-PSS del cuerpo contra el certificado público
    del remitente. Devuelve (valido: bool, mensaje: str).
    """
    if not signature_b64 or not cert_pem_str:
        return False, "El mensaje no tiene firma o el remitente no tiene certificado."

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.backends import default_backend
    from cryptography import x509

    try:
        cert = x509.load_pem_x509_certificate(
            cert_pem_str.encode("utf-8"), default_backend()
        )
        public_key = cert.public_key()
        signature  = base64.b64decode(signature_b64)

        public_key.verify(
            signature,
            body.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True, "Firma válida. El mensaje no fue alterado y proviene del remitente indicado."
    except Exception:
        return False, "Firma inválida. El mensaje pudo haber sido alterado."


def _message_to_dict(msg, db):
    sender = db.query(Identity).filter(Identity.id == msg.sender_id).first()
    return {
        "id": msg.id,
        "sender_id": msg.sender_id,
        "sender_nombre": sender.nombre if sender else None,
        "sender_email":  sender.email  if sender else None,
        "recipient_id":  msg.recipient_id,
        "recipient_email_ext": msg.recipient_email_ext,
        "subject":  msg.subject,
        "body":     msg.body,
        "leido":    msg.leido,
        "fecha_envio": msg.fecha_envio.isoformat() if msg.fecha_envio else None,
        "tiene_firma": bool(msg.signature_b64),
    }


# ── I. ENVIAR MENSAJE INTERNO ─────────────────────────────────────────────────

@router.post("/send/internal")
def send_internal(
    data: SendInternalRequest,
    db: Session = Depends(get_db),
    current_user: Identity = Depends(get_current_identity)
):
    """
    Envía un mensaje firmado a otro usuario del sistema.
    Solo usuarios con certificado activo pueden firmar (Admin y Coordinator).
    Operative y External pueden enviar pero sin firma.
    """
    if data.recipient_id == current_user.id:
        raise HTTPException(status_code=400, detail="No puedes enviarte un mensaje a ti mismo.")

    recipient = db.query(Identity).filter(Identity.id == data.recipient_id).first()
    if not recipient or recipient.estado != "ACTIVO":
        raise HTTPException(status_code=404, detail="Destinatario no encontrado o inactivo.")

    if not data.subject.strip() or not data.body.strip():
        raise HTTPException(status_code=400, detail="El asunto y el cuerpo no pueden estar vacíos.")

    signature_b64 = _sign_body(data.body, current_user)

    msg = Message(
        sender_id=current_user.id,
        recipient_id=data.recipient_id,
        subject=data.subject.strip(),
        body=data.body.strip(),
        signature_b64=signature_b64,
    )
    db.add(msg)
    db.commit()
    db.refresh(msg)

    return {
        "success": True,
        "message_id": msg.id,
        "firmado": bool(signature_b64),
        "message": "Mensaje enviado{}".format(" y firmado digitalmente." if signature_b64 else " (sin firma — el remitente no tiene certificado activo).")
    }


# ── II. ENVIAR MENSAJE EXTERNO ────────────────────────────────────────────────

@router.post("/send/external")
def send_external(
    data: SendExternalRequest,
    db: Session = Depends(get_db),
    current_user: Identity = Depends(get_current_identity)
):
    """
    Envía un mensaje firmado a un email externo.
    Genera un token de un solo uso y envía un enlace al destinatario.
    En modo desarrollo (SMTP_ENABLED=false) devuelve el enlace directamente.
    """
    if not data.recipient_email.strip():
        raise HTTPException(status_code=400, detail="El email del destinatario es obligatorio.")
    if not data.subject.strip() or not data.body.strip():
        raise HTTPException(status_code=400, detail="El asunto y el cuerpo no pueden estar vacíos.")

    signature_b64 = _sign_body(data.body, current_user)
    token = secrets.token_urlsafe(48)

    msg = Message(
        sender_id=current_user.id,
        recipient_email_ext=data.recipient_email.strip(),
        subject=data.subject.strip(),
        body=data.body.strip(),
        signature_b64=signature_b64,
        external_token=token,
        external_token_used=False,
    )
    db.add(msg)
    db.commit()
    db.refresh(msg)

    try:
        enviado, enlace = send_external_message(
            recipient_email=data.recipient_email.strip(),
            sender_name=current_user.nombre,
            subject=data.subject.strip(),
            body_preview=data.body.strip(),
            token=token,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return {
        "success": True,
        "message_id": msg.id,
        "firmado": bool(signature_b64),
        "email_enviado": enviado,
        # En dev el enlace se expone aquí para pruebas; en prod también se devuelve
        # para que el admin pueda reenviarlo manualmente si lo necesita
        "enlace_acceso": enlace,
        "message": (
            "Email enviado a {}.".format(data.recipient_email)
            if enviado else
            "Modo desarrollo: email no enviado. Usa el enlace de acceso para probar."
        )
    }


# ── III. BANDEJA DE ENTRADA ───────────────────────────────────────────────────

@router.get("/inbox")
def get_inbox(
    db: Session = Depends(get_db),
    current_user: Identity = Depends(get_current_identity)
):
    """Devuelve los mensajes recibidos por el usuario autenticado, del más nuevo al más viejo."""
    msgs = (
        db.query(Message)
        .filter(Message.recipient_id == current_user.id)
        .order_by(Message.fecha_envio.desc())
        .all()
    )
    return [_message_to_dict(m, db) for m in msgs]


# ── IV. BANDEJA DE ENVIADOS ───────────────────────────────────────────────────

@router.get("/sent")
def get_sent(
    db: Session = Depends(get_db),
    current_user: Identity = Depends(get_current_identity)
):
    """Devuelve los mensajes enviados por el usuario autenticado."""
    msgs = (
        db.query(Message)
        .filter(Message.sender_id == current_user.id)
        .order_by(Message.fecha_envio.desc())
        .all()
    )
    return [_message_to_dict(m, db) for m in msgs]


# ── V. MARCAR COMO LEÍDO ──────────────────────────────────────────────────────

@router.put("/{message_id}/read")
def mark_read(
    message_id: int,
    db: Session = Depends(get_db),
    current_user: Identity = Depends(get_current_identity)
):
    msg = db.query(Message).filter(Message.id == message_id).first()
    if not msg or msg.recipient_id != current_user.id:
        raise HTTPException(status_code=404, detail="Mensaje no encontrado.")
    msg.leido = True
    db.commit()
    return {"ok": True}


# ── VI. VERIFICAR FIRMA (usuario interno) ─────────────────────────────────────

@router.get("/{message_id}/verify")
def verify_message(
    message_id: int,
    db: Session = Depends(get_db),
    current_user: Identity = Depends(get_current_identity)
):
    """
    Verifica la firma digital de un mensaje.
    Solo puede hacerlo el destinatario o el propio remitente.
    """
    msg = db.query(Message).filter(Message.id == message_id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Mensaje no encontrado.")

    if current_user.id != msg.recipient_id and current_user.id != msg.sender_id:
        raise HTTPException(status_code=403, detail="Acceso denegado.")

    sender = db.query(Identity).filter(Identity.id == msg.sender_id).first()
    valido, detalle = _verify_signature(msg.body, msg.signature_b64, sender.certificate_pem if sender else None)

    return {
        "valido": valido,
        "detalle": detalle,
        "sender_nombre": sender.nombre if sender else "Desconocido",
        "sender_email":  sender.email  if sender else None,
    }


# ── VII. PÁGINA PÚBLICA PARA EXTERNOS ────────────────────────────────────────

@router.get("/externo/{token}", response_class=HTMLResponse, include_in_schema=False)
def view_external_message(token: str, db: Session = Depends(get_db)):
    """
    Página pública de visualización para destinatarios externos.
    El token es de un solo uso: se bloquea el acceso a partir de la segunda visita.
    El destinatario debe guardar o imprimir el mensaje en la primera apertura.
    """
    msg = db.query(Message).filter(Message.external_token == token).first()
    if not msg:
        return HTMLResponse(_error_page("Enlace no válido o ya expirado."), status_code=404)

    # Enlace de un solo uso: si ya fue abierto antes, bloquear acceso
    if msg.external_token_used:
        return HTMLResponse(_error_page(
            "Este enlace ya fue utilizado. Por seguridad, cada enlace solo puede abrirse una vez."
        ), status_code=410)

    # Marcar como usado ANTES de mostrar el contenido (previene doble acceso por recarga rápida)
    msg.external_token_used = True
    db.commit()

    sender = db.query(Identity).filter(Identity.id == msg.sender_id).first()

    # Verificar firma
    valido, detalle_firma = _verify_signature(
        msg.body, msg.signature_b64, sender.certificate_pem if sender else None
    )

    fecha_str = msg.fecha_envio.strftime("%d/%m/%Y %H:%M UTC") if msg.fecha_envio else "—"
    firma_color = "#4fb87a" if valido else "#d94f4f"
    firma_icono = "✔" if valido else "✖"

    html = """<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Mensaje seguro · Casa Monarca</title>
  <link href="https://fonts.googleapis.com/css2?family=DM+Serif+Display&family=DM+Sans:wght@300;400;500;600&display=swap" rel="stylesheet"/>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{background:#0f1117;color:#e4e6ed;font-family:'DM Sans',sans-serif;min-height:100vh;
          display:flex;align-items:center;justify-content:center;padding:24px}}
    .card{{background:#181c27;border:1px solid #252a38;border-radius:16px;padding:40px;
           max-width:640px;width:100%;box-shadow:0 4px 32px rgba(0,0,0,.5)}}
    .logo{{font-family:'DM Serif Display',serif;font-size:22px;color:#e8a045;margin-bottom:28px}}
    .meta{{font-size:12px;color:#7a8099;margin-bottom:6px}}
    .subject{{font-size:20px;font-weight:600;margin-bottom:20px;color:#e4e6ed}}
    .body{{background:#0f1117;border:1px solid #252a38;border-radius:10px;padding:20px;
           font-size:14px;line-height:1.7;white-space:pre-wrap;word-break:break-word;margin-bottom:24px}}
    .firma-badge{{display:flex;align-items:flex-start;gap:12px;padding:16px 20px;
                  border-radius:10px;border:1px solid {firma_color}33;background:{firma_color}11}}
    .firma-icon{{font-size:22px;color:{firma_color};flex-shrink:0}}
    .firma-title{{font-size:13px;font-weight:600;color:{firma_color};margin-bottom:4px}}
    .firma-detail{{font-size:12px;color:#7a8099;line-height:1.5}}
    .footer{{margin-top:28px;font-size:11px;color:#3a3f52;text-align:center}}
    .warning-banner{{background:#e8a04511;border:1px solid #e8a04544;border-radius:10px;
      padding:14px 18px;margin-bottom:24px;display:flex;align-items:flex-start;gap:12px}}
    .warning-icon{{font-size:20px;flex-shrink:0}}
    .warning-text{{font-size:13px;color:#e8a045;line-height:1.5}}
    .btn-save{{display:inline-block;margin-top:20px;padding:10px 20px;background:#e8a045;
      color:#0f1117;border:none;border-radius:8px;font-size:13px;font-weight:600;
      cursor:pointer;text-decoration:none}}
    .btn-print{{display:inline-block;margin-top:20px;margin-left:10px;padding:10px 20px;
      background:transparent;color:#7a8099;border:1px solid #252a38;border-radius:8px;
      font-size:13px;font-weight:600;cursor:pointer}}
    @media print{{.warning-banner,.btn-save,.btn-print,.footer{{display:none}}}}
  </style>
</head>
<body>
<div class="card">
  <div class="logo">Casa Monarca · Mensaje Seguro</div>
  <div class="warning-banner">
    <div class="warning-icon">⚠</div>
    <div class="warning-text">
      <strong>Este enlace es de un solo uso.</strong><br/>
      Ya no podrás volver a abrirlo. Guarda o imprime el mensaje antes de cerrar esta página.
    </div>
  </div>
  <div class="meta">De: <strong>{sender_nombre}</strong> &lt;{sender_email}&gt;</div>
  <div class="meta" style="margin-bottom:16px">Enviado: {fecha}</div>
  <div class="subject">{subject}</div>
  <div class="body">{body}</div>
  <div class="firma-badge">
    <div class="firma-icon">{firma_icono}</div>
    <div>
      <div class="firma-title">Verificación de firma digital</div>
      <div class="firma-detail">{detalle_firma}</div>
    </div>
  </div>
  <div>
    <button class="btn-save" onclick="window.print()">Imprimir / Guardar PDF</button>
    <button class="btn-print" onclick="descargarTexto()">Descargar como .txt</button>
  </div>
  <div class="footer">Este mensaje fue enviado desde el Sistema de Gestión de Identidades de Casa Monarca.<br/>Este enlace ya no volverá a funcionar.</div>
<script>
function descargarTexto() {{
  var texto = "De: {sender_nombre} <{sender_email}>\nFecha: {fecha}\nAsunto: {subject}\n\n{body}\n\n---\n{detalle_firma}";
  var blob = new Blob([texto], {{type: "text/plain;charset=utf-8"}});
  var a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "mensaje_casamonarca.txt";
  a.click();
}}
</script>
</div>
</body>
</html>""".format(
        firma_color=firma_color,
        firma_icono=firma_icono,
        sender_nombre=sender.nombre if sender else "Remitente desconocido",
        sender_email=sender.email if sender else "—",
        fecha=fecha_str,
        subject=msg.subject,
        body=msg.body,
        detalle_firma=detalle_firma,
    )
    return HTMLResponse(html)


def _error_page(msg_text):
    return """<!DOCTYPE html>
<html lang="es"><head><meta charset="UTF-8"/><title>Error</title>
<style>body{{background:#0f1117;color:#e4e6ed;font-family:sans-serif;
  display:flex;align-items:center;justify-content:center;min-height:100vh}}
.box{{background:#181c27;border:1px solid #d94f4f44;border-radius:12px;padding:40px;text-align:center}}
h2{{color:#d94f4f;margin-bottom:12px}}p{{color:#7a8099}}</style></head>
<body><div class="box"><h2>Enlace no válido</h2><p>{}</p></div></body></html>""".format(msg_text)
