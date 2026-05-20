# Servicio de criptografía y empaquetado MIME para correos firmados.
# Implementa firma RSA-PSS con SHA-256 y verificación de firma.
# La llave privada NUNCA sale de esta función: se descifra, usa y elimina de memoria.
# Compatible con Python 3.6.8 y cryptography==3.4.8.

import base64
import json
from typing import List, Dict, Any, Tuple

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.exceptions import InvalidSignature

from app.core.crypto import decrypt_private_key


# ── Construcción del bloque de datos a firmar ─────────────────────────────────

def _build_signable_bytes(body_text, attachments):
    # type: (str, List[Dict[str, Any]]) -> bytes
    """
    Construye un bloque de bytes determinista que engloba el cuerpo del mensaje
    y todos los adjuntos en un orden fijo y reproducible.

    La librería 'cryptography' calculará el SHA-256 internamente al firmar/verificar,
    por lo que aquí entregamos los bytes crudos concatenados (no el hash).
    """
    result = bytearray()

    # 1. Bytes del cuerpo en texto plano
    result.extend(body_text.encode('utf-8'))

    # 2. Bytes de cada adjunto en orden determinista (serializado como JSON ordenado)
    for att in attachments:
        att_bytes = json.dumps(att, sort_keys=True, ensure_ascii=False).encode('utf-8')
        result.extend(att_bytes)

    return bytes(result)


# ── Firma y empaquetado ───────────────────────────────────────────────────────

def sign_and_package_email(user_db_obj, to_email, subject, body_text, attachments):
    # type: (Any, str, str, str, List[Dict[str, Any]]) -> bytes
    """
    Firma criptográficamente el mensaje y lo empaqueta en formato MIME.

    Flujo de seguridad:
        1. Descifra la llave privada RSA del usuario (cifrada con Fernet en la BD).
        2. Construye el bloque de bytes determinista del contenido.
        3. Firma con RSA-PSS + SHA-256 (la librería hashea internamente).
        4. ELIMINA la llave privada de la memoria RAM inmediatamente.
        5. Construye el paquete MIME con texto, adjuntos, firma y certificado público.

    Retorna:
        bytes con el mensaje MIME serializado, listo para enviar vía SMTP.
    """
    # ── a) Descifrar llave privada ────────────────────────────────────────────
    if not user_db_obj.private_key_pem_encrypted:
        raise ValueError("El usuario no tiene llave privada almacenada.")

    private_key_pem_bytes = decrypt_private_key(user_db_obj.private_key_pem_encrypted)
    private_key = serialization.load_pem_private_key(
        private_key_pem_bytes,
        password=None,
        backend=default_backend()
    )

    # ── b) Construir bloque de bytes a firmar ─────────────────────────────────
    data_to_sign = _build_signable_bytes(body_text, attachments or [])

    # ── c) Firma con RSA-PSS + SHA-256 ────────────────────────────────────────
    # PSS (Probabilistic Signature Scheme) es más seguro que PKCS1v15.
    # hashes.SHA256() le indica a la librería que hashee internamente los datos.
    # No usamos Prehashed porque no existe en cryptography==3.4.8.
    signature_bytes = private_key.sign(
        data_to_sign,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')

    # ── d) ELIMINAR llave privada de la RAM ───────────────────────────────────
    del private_key
    del private_key_pem_bytes

    # ── e) Construir mensaje MIME ─────────────────────────────────────────────
    msg = MIMEMultipart("mixed")
    msg['From']    = user_db_obj.email
    msg['To']      = to_email
    msg['Subject'] = subject

    # Cuerpo del mensaje en texto plano
    msg.attach(MIMEText(body_text, 'plain', 'utf-8'))

    # Adjuntos originales del usuario
    for att in (attachments or []):
        filename = att.get('filename', 'adjunto.bin')
        content  = att.get('content', '')
        part = MIMEBase('application', 'octet-stream')
        if isinstance(content, str):
            part.set_payload(content.encode('utf-8'))
        else:
            part.set_payload(content)
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', 'attachment; filename="{}"'.format(filename))
        msg.attach(part)

    # ── f) Adjuntar firma digital como 'signature.sig' ────────────────────────
    sig_part = MIMEBase('application', 'octet-stream')
    sig_part.set_payload(signature_b64.encode('utf-8'))
    encoders.encode_base64(sig_part)
    sig_part.add_header('Content-Disposition', 'attachment; filename="signature.sig"')
    msg.attach(sig_part)

    # ── g) Adjuntar certificado X.509 público como 'certificate.pem' ─────────
    # SÓLO el certificado público; la llave privada ya fue eliminada arriba.
    if not user_db_obj.certificate_pem:
        raise ValueError("El usuario no tiene certificado X.509 registrado.")

    cert_part = MIMEBase('application', 'x-x509-ca-cert')
    cert_part.set_payload(user_db_obj.certificate_pem.encode('utf-8'))
    encoders.encode_base64(cert_part)
    cert_part.add_header('Content-Disposition', 'attachment; filename="certificate.pem"')
    msg.attach(cert_part)

    # ── h) Serializar el mensaje MIME a bytes ─────────────────────────────────
    return msg.as_bytes()


# ── Verificación de firma ─────────────────────────────────────────────────────

def verify_email(body_text, attachments, signature_base64, sender_cert_pem):
    # type: (str, List[Dict[str, Any]], str, str) -> Tuple[bool, str]
    """
    Verifica la firma criptográfica de un correo recibido.

    Retorna:
        Tupla (bool, str): (es_valido, mensaje_descriptivo)
    """
    try:
        # ── a) Cargar certificado X.509 ───────────────────────────────────────
        cert = x509.load_pem_x509_certificate(
            sender_cert_pem.encode('utf-8'),
            backend=default_backend()
        )

        # ── b) Extraer llave pública del certificado ──────────────────────────
        public_key = cert.public_key()

        # ── c) Reconstruir el mismo bloque de bytes firmado originalmente ─────
        data_to_verify = _build_signable_bytes(body_text, attachments or [])

        # ── d) Decodificar firma Base64 ───────────────────────────────────────
        try:
            signature_bytes = base64.b64decode(signature_base64)
        except Exception:
            return False, "La firma no es un Base64 válido."

        # ── e) Verificar la firma ─────────────────────────────────────────────
        # La librería calcula el SHA-256 de data_to_verify internamente y
        # compara con lo que estaba codificado en la firma.
        public_key.verify(
            signature_bytes,
            data_to_verify,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return True, "Firma válida. El mensaje no ha sido alterado y proviene del titular del certificado."

    except InvalidSignature:
        return False, "Firma inválida: el mensaje fue alterado o el certificado no corresponde al firmante."
    except Exception as e:
        return False, "Error durante la verificación: {}".format(str(e))
