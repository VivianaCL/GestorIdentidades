import hashlib
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives import serialization

from app.core.crypto import decrypt_private_key


def sign_and_package_email(
    sender_email: str,
    to_email: str,
    subject: str,
    body_text: str,
    attachments: list,
    encrypted_private_key: bytes,
    certificate_pem: str
) -> MIMEMultipart:
    """
    Firma criptográficamente el correo y sus adjuntos, y lo empaqueta
    en formato MIME para su envío.
    """
    # a) Recuperar y descifrar la llave privada con Fernet
    private_key_pem_bytes = decrypt_private_key(encrypted_private_key)
    private_key = serialization.load_pem_private_key(
        private_key_pem_bytes,
        password=None
    )

    # b) Generar hash unificado (SHA-256) combinando de forma determinista el cuerpo y los adjuntos
    hasher = hashlib.sha256()
    hasher.update(body_text.encode('utf-8'))
    for att in attachments:
        hasher.update(att.encode('utf-8'))
    
    unified_hash = hasher.digest()

    # c) Firmar el hash con la llave privada usando padding PSS y obtener Base64
    signature = private_key.sign(
        unified_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        utils.Prehashed(hashes.SHA256())
    )
    signature_b64 = base64.b64encode(signature).decode('utf-8')

    # Limpiar llave privada de memoria manualmente
    del private_key
    del private_key_pem_bytes

    # d) Construir objeto MIMEMultipart("mixed") y agregar contenido
    msg = MIMEMultipart("mixed")
    msg['From'] = sender_email
    msg['To'] = to_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body_text, 'plain', 'utf-8'))

    # Agregar archivos adjuntos originales
    for i, att in enumerate(attachments):
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(att.encode('utf-8'))
        encoders.encode_base64(part)
        part.add_header(
            'Content-Disposition', 
            'attachment; filename="attachment_{}.txt"'.format(i + 1)
        )
        msg.attach(part)

    # e) Adjuntar firma digital como archivo virtual "signature.sig"
    sig_part = MIMEBase('application', 'octet-stream')
    sig_part.set_payload(signature_b64.encode('utf-8'))
    encoders.encode_base64(sig_part)
    sig_part.add_header('Content-Disposition', 'attachment; filename="signature.sig"')
    msg.attach(sig_part)

    # f) Adjuntar certificado público X.509
    cert_part = MIMEBase('application', 'x-x509-ca-cert')
    cert_part.set_payload(certificate_pem.encode('utf-8'))
    encoders.encode_base64(cert_part)
    cert_part.add_header('Content-Disposition', 'attachment; filename="sender_certificate.pem"')
    msg.attach(cert_part)

    return msg
