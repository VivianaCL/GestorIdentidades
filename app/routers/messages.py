# Router de mensajería institucional firmada digitalmente.
#
# Hay dos flujos principales:
#
#  1. Interno — entre usuarios registrados del sistema.
#     Cada mensaje lleva el cuerpo + un pie de firma institucional del remitente.
#     Si el remitente tiene clave privada (Admin/Coordinator), el contenido completo
#     se firma con RSA-PSS antes de guardarse, de modo que el destinatario puede
#     verificar que nadie alteró el texto después de enviarlo.
#
#  2. Externo — hacia cualquier dirección de correo fuera del sistema.
#     Se genera un enlace de un solo uso que se envía por email. Al abrirlo, el
#     destinatario ve el mensaje en una página pública y puede verificar la firma
#     haciendo clic en el remitente (sin necesitar cuenta en el sistema).
#
# Los archivos adjuntos viajan como base64 dentro del JSON.
# Límite: 2 MB totales por mensaje (configurado en ATTACHMENT_MAX_BYTES).

import json
import os
import secrets
import base64
import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional, List

from app.db.database import get_db
from app.models.identity import Identity, Message
from app.core.crypto import get_current_identity, decrypt_private_key
from app.services.mailer import send_external_message

router = APIRouter()

# Límite de adjuntos: 2 MB de datos brutos (decodificados de base64) por mensaje.
# Conservador para HostGator shared hosting; evita saturar disco y RAM.
ATTACHMENT_MAX_BYTES = 2 * 1024 * 1024   # 2 MB


# ── Schemas ───────────────────────────────────────────────────────────────────

class AttachmentIn(BaseModel):
    filename: str
    mime_type: str
    data_b64: str   # contenido del archivo en base64

class SendInternalRequest(BaseModel):
    recipient_id: int
    subject: str
    body: str
    attachments: Optional[List[AttachmentIn]] = []

class SendExternalRequest(BaseModel):
    recipient_email: str
    subject: str
    body: str
    attachments: Optional[List[AttachmentIn]] = []

class MessageResponse(BaseModel):
    id: int
    sender_id: int
    sender_nombre: Optional[str]
    sender_email: Optional[str]
    sender_codigo: Optional[str]
    recipient_id: Optional[int]
    recipient_email_ext: Optional[str]
    subject: str
    body: str
    leido: bool
    fecha_envio: str
    tiene_firma: bool
    attachments: Optional[List[dict]] = []

    class Config:
        orm_mode = True


# ── Helpers ───────────────────────────────────────────────────────────────────

def _validate_attachments(attachments: List[AttachmentIn]):
    """Comprueba que los adjuntos no superen el límite de tamaño total.

    La validación se hace decodificando el base64 para medir los bytes reales,
    no el tamaño del string base64 (que es ~33% más grande). Si alguno supera
    el límite acumulado, lanzamos un error antes de guardar nada en la base de datos.
    """
    total = 0
    for att in attachments:
        try:
            raw = base64.b64decode(att.data_b64)
        except Exception:
            raise HTTPException(status_code=400, detail=f"El adjunto '{att.filename}' tiene codificación base64 inválida.")
        total += len(raw)
        if total > ATTACHMENT_MAX_BYTES:
            raise HTTPException(
                status_code=400,
                detail=f"Los adjuntos superan el límite de {ATTACHMENT_MAX_BYTES // (1024*1024)} MB por mensaje."
            )


def _build_sender_footer(sender: Identity) -> str:
    """Construye el bloque de firma institucional que aparece al final de cada mensaje.

    El pie se adjunta al cuerpo ANTES de firmarlo digitalmente, por lo que la firma
    criptográfica también cubre la identidad del remitente. Si alguien manipulara el
    pie después de enviar el mensaje, la verificación de firma lo detectaría.
    """
    codigo = f" · {sender.codigo}" if sender.codigo else ""
    return (
        f"\n\n"
        f"— — — — — — — — — — — — — — — — — — — —\n"
        f"{sender.nombre}{codigo}\n"
        f"{sender.email}\n"
        f"Casa Monarca · Sistema de Gestión de Identidades\n"
        f"— — — — — — — — — — — — — — — — — — — —"
    )


def _sign_body(full_body: str, sender: Identity):
    """Firma el cuerpo del mensaje (incluyendo el pie institucional) con RSA-PSS.

    Solo los usuarios que tienen clave privada almacenada (Admin y Coordinator)
    pueden firmar. Para el resto se guarda el mensaje sin firma y se notifica al
    destinatario de que no hay garantía criptográfica de autoría.

    La firma cubre el texto completo tal como se almacena: si el cuerpo cambia
    (por cualquier razón), la verificación fallará.
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
        full_body.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode("ascii")


def _verify_signature(body: str, signature_b64: str, cert_pem_str: str):
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
    atts = json.loads(msg.attachments_json) if msg.attachments_json else []
    # Exponer solo metadatos de adjuntos en el listado (no los bytes)
    atts_meta = [{"filename": a["filename"], "mime_type": a.get("mime_type", ""), "data_b64": a.get("data_b64", "")} for a in atts]
    return {
        "id": msg.id,
        "sender_id": msg.sender_id,
        "sender_nombre": sender.nombre if sender else None,
        "sender_email":  sender.email  if sender else None,
        "sender_codigo": sender.codigo if sender else None,
        "recipient_id":  msg.recipient_id,
        "recipient_email_ext": msg.recipient_email_ext,
        "subject":  msg.subject,
        "body":     msg.body,
        "leido":    msg.leido,
        "fecha_envio": msg.fecha_envio.isoformat() if msg.fecha_envio else None,
        "tiene_firma": bool(msg.signature_b64),
        "attachments": atts_meta,
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
    El cuerpo incluye un pie de firma profesional antes de ser firmado y almacenado.
    """
    if data.recipient_id == current_user.id:
        raise HTTPException(status_code=400, detail="No puedes enviarte un mensaje a ti mismo.")

    recipient = db.query(Identity).filter(Identity.id == data.recipient_id).first()
    if not recipient or recipient.estado != "ACTIVO":
        raise HTTPException(status_code=404, detail="Destinatario no encontrado o inactivo.")

    if not data.subject.strip() or not data.body.strip():
        raise HTTPException(status_code=400, detail="El asunto y el cuerpo no pueden estar vacíos.")

    if data.attachments:
        _validate_attachments(data.attachments)

    # Construir cuerpo completo con pie de firma institucional
    footer = _build_sender_footer(current_user)
    full_body = data.body.strip() + footer

    signature_b64 = _sign_body(full_body, current_user)

    atts_json = json.dumps(
        [{"filename": a.filename, "mime_type": a.mime_type, "data_b64": a.data_b64} for a in data.attachments],
        ensure_ascii=False
    ) if data.attachments else None

    msg = Message(
        sender_id=current_user.id,
        recipient_id=data.recipient_id,
        subject=data.subject.strip(),
        body=full_body,
        signature_b64=signature_b64,
        attachments_json=atts_json,
    )
    db.add(msg)
    db.commit()
    db.refresh(msg)

    return {
        "success": True,
        "message_id": msg.id,
        "firmado": bool(signature_b64),
        "message": "Mensaje enviado{}".format(
            " y firmado digitalmente." if signature_b64
            else " (sin firma — el remitente no tiene certificado activo)."
        )
    }


# ── II. ENVIAR MENSAJE EXTERNO ────────────────────────────────────────────────

@router.post("/send/external")
def send_external(
    data: SendExternalRequest,
    db: Session = Depends(get_db),
    current_user: Identity = Depends(get_current_identity)
):
    """
    Envía un mensaje firmado a un email externo con enlace de un solo uso.
    """
    if not data.recipient_email.strip():
        raise HTTPException(status_code=400, detail="El email del destinatario es obligatorio.")
    if not data.subject.strip() or not data.body.strip():
        raise HTTPException(status_code=400, detail="El asunto y el cuerpo no pueden estar vacíos.")

    if data.attachments:
        _validate_attachments(data.attachments)

    footer = _build_sender_footer(current_user)
    full_body = data.body.strip() + footer

    signature_b64 = _sign_body(full_body, current_user)
    token = secrets.token_urlsafe(48)

    atts_json = json.dumps(
        [{"filename": a.filename, "mime_type": a.mime_type, "data_b64": a.data_b64} for a in data.attachments],
        ensure_ascii=False
    ) if data.attachments else None

    msg = Message(
        sender_id=current_user.id,
        recipient_email_ext=data.recipient_email.strip(),
        subject=data.subject.strip(),
        body=full_body,
        signature_b64=signature_b64,
        external_token=token,
        external_token_used=False,
        attachments_json=atts_json,
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
            firmado=bool(signature_b64),
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return {
        "success": True,
        "message_id": msg.id,
        "firmado": bool(signature_b64),
        "email_enviado": enviado,
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
    against_id: int = Query(..., description="ID de la identidad cuya clave pública se usará para verificar"),
    db: Session = Depends(get_db),
    current_user: Identity = Depends(get_current_identity)
):
    """Verifica la firma del mensaje contra la clave pública de la identidad indicada."""
    msg = db.query(Message).filter(Message.id == message_id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Mensaje no encontrado.")

    if current_user.id != msg.recipient_id and current_user.id != msg.sender_id:
        raise HTTPException(status_code=403, detail="Acceso denegado.")

    candidate = db.query(Identity).filter(Identity.id == against_id).first()
    if not candidate:
        raise HTTPException(status_code=404, detail="Identidad candidata no encontrada.")

    valido, detalle = _verify_signature(msg.body, msg.signature_b64, candidate.certificate_pem)

    return {
        "valido": valido,
        "detalle": detalle,
        "candidate_nombre": candidate.nombre,
        "candidate_email":  candidate.email,
    }


@router.get("/externo/{token}/verify-sig", include_in_schema=False)
def verify_external_sig(
    token: str,
    against_id: int = Query(...),
    db: Session = Depends(get_db)
):
    """Verificación pública de firma para destinatarios externos (requiere solo el token)."""
    msg = db.query(Message).filter(Message.external_token == token).first()
    if not msg:
        return JSONResponse({"error": "Mensaje no encontrado."}, status_code=404)

    candidate = db.query(Identity).filter(Identity.id == against_id).first()
    if not candidate:
        return JSONResponse({"error": "Identidad no encontrada."}, status_code=404)

    valido, detalle = _verify_signature(msg.body, msg.signature_b64, candidate.certificate_pem)
    return {
        "valido": valido,
        "detalle": detalle,
        "candidate_nombre": candidate.nombre,
        "candidate_email":  candidate.email,
    }


# ── VII. PÁGINA PÚBLICA PARA EXTERNOS ────────────────────────────────────────

@router.get("/externo/{token}", response_class=HTMLResponse, include_in_schema=False)
def view_external_message(token: str, db: Session = Depends(get_db)):
    """
    Página pública de visualización para destinatarios externos.
    Enlace de un solo uso. Muestra únicamente al remitente como candidato
    para verificación de firma (el usuario la activa al hacer clic).
    """
    msg = db.query(Message).filter(Message.external_token == token).first()
    if not msg:
        return HTMLResponse(_error_page("Enlace no válido o ya expirado."), status_code=404)

    if msg.external_token_used:
        return HTMLResponse(_error_page(
            "Este enlace ya fue utilizado. Por seguridad, cada enlace solo puede abrirse una vez."
        ), status_code=410)

    msg.external_token_used = True
    db.commit()

    sender = db.query(Identity).filter(Identity.id == msg.sender_id).first()
    fecha_str = msg.fecha_envio.strftime("%d/%m/%Y %H:%M UTC") if msg.fecha_envio else "—"

    # Adjuntos: lista de metadatos para el HTML (no se re-exponen los bytes en el JSON público)
    atts = json.loads(msg.attachments_json) if msg.attachments_json else []

    tiene_firma = bool(msg.signature_b64)
    sender_nombre = sender.nombre if sender else "Remitente desconocido"
    sender_email  = sender.email  if sender else "—"
    sender_codigo = sender.codigo if sender else None
    sender_id_val = sender.id     if sender else 0

    sender_label = f"{sender_nombre}"
    if sender_codigo:
        sender_label += f" · {sender_codigo}"

    # Construir sección de adjuntos en HTML
    att_html = ""
    if atts:
        items = "".join(
            f'<div style="display:flex;align-items:center;gap:10px;padding:8px 12px;'
            f'background:#0f1117;border:1px solid #252a38;border-radius:8px;margin-bottom:6px">'
            f'<span style="font-size:18px">📎</span>'
            f'<span style="font-size:13px;color:#e4e6ed;flex:1">{a["filename"]}</span>'
            f'<a href="data:{a.get("mime_type","application/octet-stream")};base64,{a["data_b64"]}" '
            f'download="{a["filename"]}" style="font-size:12px;color:#e8a045;font-weight:600;text-decoration:none">Descargar</a>'
            f'</div>'
            for a in atts
        )
        att_html = f"""
  <div style="margin-bottom:24px">
    <div style="font-size:13px;font-weight:600;color:#e4e6ed;margin-bottom:10px">
      Archivos adjuntos ({len(atts)})
    </div>
    {items}
  </div>"""

    # Sección firma: solo se muestra el remitente como candidato; verificación bajo demanda
    if tiene_firma:
        firma_section = f"""
  <div style="margin-top:28px;border-top:1px solid #252a38;padding-top:24px">
    <div style="font-size:13px;font-weight:600;color:#e4e6ed;margin-bottom:6px">
      ✉ Verificación de firma digital
    </div>
    <div style="font-size:12px;color:#7a8099;margin-bottom:14px">
      Este mensaje fue firmado digitalmente. Haz clic en el remitente para verificar la autenticidad.
    </div>
    <div id="ext-sender-card"
      onclick="extVerify({sender_id_val})"
      style="background:#0f1117;border:1px solid #252a38;border-radius:10px;padding:16px;cursor:pointer;
             transition:border-color .15s;max-width:320px"
      onmouseover="this.style.borderColor='#e8a045'"
      onmouseout="this.style.borderColor='#252a38'">
      <div style="font-weight:600;font-size:14px;color:#e4e6ed;margin-bottom:4px">{sender_label}</div>
      <div style="font-size:12px;color:#7a8099;margin-bottom:8px">{sender_email}</div>
      <div style="font-size:11px;color:#e8a045;font-weight:600">Haz clic para verificar firma →</div>
    </div>
    <div id="ext-verify-result" style="display:none;margin-top:14px;padding:14px 18px;border-radius:8px;font-size:13px"></div>
  </div>"""
    else:
        firma_section = """
  <div style="margin-top:28px;border-top:1px solid #252a38;padding-top:18px">
    <div style="padding:14px 18px;border-radius:8px;border:1px solid #7a809944;background:#7a809911;
                font-size:13px;color:#7a8099;display:flex;align-items:center;gap:10px">
      <span style="font-size:18px">ℹ</span>
      Este mensaje no contiene firma digital.
    </div>
  </div>"""

    html_body = """<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Mensaje seguro · Casa Monarca</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{background:#0f1117;color:#e4e6ed;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
          min-height:100vh;display:flex;align-items:flex-start;justify-content:center;padding:24px}}
    .card{{background:#181c27;border:1px solid #252a38;border-radius:16px;padding:40px;
           max-width:660px;width:100%;box-shadow:0 4px 32px rgba(0,0,0,.5);margin:auto}}
    .logo{{font-size:22px;font-weight:700;color:#e8a045;margin-bottom:28px;letter-spacing:-.3px}}
    .meta{{font-size:12px;color:#7a8099;margin-bottom:6px}}
    .subject{{font-size:20px;font-weight:600;margin-bottom:20px;color:#e4e6ed}}
    .body{{background:#0f1117;border:1px solid #252a38;border-radius:10px;padding:20px;
           font-size:14px;line-height:1.7;white-space:pre-wrap;word-break:break-word;margin-bottom:24px}}
    .footer{{margin-top:28px;font-size:11px;color:#3a3f52;text-align:center}}
    .warning-banner{{background:#e8a04511;border:1px solid #e8a04544;border-radius:10px;
      padding:14px 18px;margin-bottom:24px;display:flex;align-items:flex-start;gap:12px}}
    .warning-icon{{font-size:20px;flex-shrink:0}}
    .warning-text{{font-size:13px;color:#e8a045;line-height:1.5}}
    .btn-save{{display:inline-block;margin-top:20px;padding:10px 20px;background:#e8a045;
      color:#0f1117;border:none;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer}}
    .btn-print{{display:inline-block;margin-top:20px;margin-left:10px;padding:10px 20px;
      background:transparent;color:#7a8099;border:1px solid #252a38;border-radius:8px;
      font-size:13px;font-weight:600;cursor:pointer}}
    @media print{{.warning-banner,.btn-save,.btn-print,.footer{{display:none}}}}
  </style>
</head>
<body>
<div class="card">
  <div class="logo">🦋 Casa Monarca · Mensaje Seguro</div>
  <div class="warning-banner">
    <div class="warning-icon">⚠</div>
    <div class="warning-text">
      <strong>Este enlace es de un solo uso.</strong><br/>
      Ya no podrás volver a abrirlo. Guarda o imprime el mensaje antes de cerrar esta página.
    </div>
  </div>
  <div class="meta">De: <strong>{sender_label}</strong> &lt;{sender_email}&gt;</div>
  <div class="meta" style="margin-bottom:16px">Enviado: {fecha}</div>
  <div class="subject">{subject}</div>
  <div class="body">{body}</div>
  {att_html}
  {firma_section}
  <div style="margin-top:20px">
    <button class="btn-save" onclick="window.print()">Imprimir / Guardar PDF</button>
    <button class="btn-print" onclick="descargarTexto()">Descargar como .txt</button>
  </div>
  <div class="footer">Este mensaje fue enviado desde el Sistema de Gestión de Identidades de Casa Monarca.<br/>Este enlace ya no volverá a funcionar.</div>""".format(
        sender_label=sender_label,
        sender_email=sender_email,
        fecha=fecha_str,
        subject=msg.subject,
        body=msg.body,
        att_html=att_html,
        firma_section=firma_section,
    )

    base_url = os.environ.get("BASE_URL", "http://127.0.0.1:8000")
    msg_json = json.dumps({
        "sender_nombre": sender_nombre,
        "sender_email":  sender_email,
        "fecha":         fecha_str,
        "subject":       msg.subject,
        "body":          msg.body,
    }, ensure_ascii=False)

    html_script = (
        "\n<script>\nvar MSG=" + msg_json
        + ";\nvar EXT_TOKEN=" + json.dumps(token)
        + ";\nvar API_BASE=" + json.dumps(base_url) + ";\n"
        + """
function descargarTexto() {
  var t = "De: "+MSG.sender_nombre+" <"+MSG.sender_email+">"
    +"\\nFecha: "+MSG.fecha+"\\nAsunto: "+MSG.subject
    +"\\n\\n"+MSG.body;
  var b = new Blob([t], {type:"text/plain;charset=utf-8"});
  var a = document.createElement("a");
  a.href = URL.createObjectURL(b);
  a.download = "mensaje_casamonarca.txt";
  a.click();
}
function extVerify(senderId) {
  var card = document.getElementById("ext-sender-card");
  var result = document.getElementById("ext-verify-result");
  if (card) { card.style.borderColor = "#e8a045"; card.style.cursor = "wait"; }
  fetch(API_BASE+"/api/v1/messages/externo/"+EXT_TOKEN+"/verify-sig?against_id="+senderId)
    .then(function(r){return r.json();})
    .then(function(d){
      if (card) { card.style.cursor = "default"; }
      if (d.error) {
        result.style.cssText="display:block;padding:14px 18px;border-radius:8px;background:#d94f4f11;border:1px solid #d94f4f44;color:#d94f4f;font-size:13px";
        result.textContent=d.error; return;
      }
      var c = d.valido ? "#4fb87a" : "#d94f4f";
      result.style.cssText="display:block;padding:14px 18px;border-radius:8px;font-size:13px;"
        +"background:"+c+"11;border:1px solid "+c+"44;color:"+c;
      result.innerHTML="<strong>"+(d.valido?"✔ Firma válida — el mensaje es auténtico":"✖ La firma no pudo verificarse")
        +"</strong>"
        +"<br><span style='color:#7a8099;font-size:12px;margin-top:4px;display:block'>"+d.detalle+"</span>";
      if (card) card.style.borderColor = c;
    })
    .catch(function(){
      if (card) { card.style.cursor = "default"; }
      result.style.cssText="display:block;padding:14px 18px;border-radius:8px;background:#d94f4f11;border:1px solid #d94f4f44;color:#d94f4f;font-size:13px";
      result.textContent="Error al conectar con el servidor.";
    });
}
</script>
</div>
</body>
</html>"""
    )

    return HTMLResponse(html_body + html_script)


def _error_page(msg_text):
    return """<!DOCTYPE html>
<html lang="es"><head><meta charset="UTF-8"/><title>Error</title>
<style>body{{background:#0f1117;color:#e4e6ed;font-family:sans-serif;
  display:flex;align-items:center;justify-content:center;min-height:100vh}}
.box{{background:#181c27;border:1px solid #d94f4f44;border-radius:12px;padding:40px;text-align:center}}
h2{{color:#d94f4f;margin-bottom:12px}}p{{color:#7a8099}}</style></head>
<body><div class="box"><h2>Enlace no válido</h2><p>{}</p></div></body></html>""".format(msg_text)
