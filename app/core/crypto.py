# Módulo central de criptografía.
# Aquí vive todo lo relacionado con generación de llaves, certificados X.509,
# cifrado de claves privadas, hashing de contraseñas y manejo de tokens JWT.

import datetime
import os
import base64
import hashlib
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

# Herramientas de bajo nivel para RSA y serialización
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

# Cifrado simétrico para proteger claves privadas en reposo
from cryptography.fernet import Fernet

# Utilidades de autenticación y JWT
from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from app.db.database import get_db

# TOTP para autenticación multifactor
import pyotp

# Contexto de hashing para contraseñas de usuario (bcrypt)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Clave secreta del sistema; en producción debe venir de variable de entorno
SECRET_KEY = os.environ.get("SECRET_KEY", "b33fb4n6m0n4rc4")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480  # 8 horas de sesión activa

# Esquema OAuth2 que apunta al endpoint de login
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


# ── Cifrado de claves privadas ────────────────────────────────────────────────

def _get_fernet() -> Fernet:
    # Derivamos una clave Fernet de 256 bits a partir del SECRET_KEY.
    # SHA-256 convierte la cadena arbitraria en exactamente 32 bytes.
    key = base64.urlsafe_b64encode(hashlib.sha256(SECRET_KEY.encode()).digest())
    return Fernet(key)

def encrypt_private_key(private_pem: bytes) -> str:
    # Cifra la clave privada PEM antes de guardarla en la base de datos.
    # El resultado es un token Fernet (texto URL-safe), nunca texto plano.
    return _get_fernet().encrypt(private_pem).decode('utf-8')

def decrypt_private_key(encrypted: str) -> bytes:
    # Descifra en memoria la clave privada para entregarla al usuario autorizado.
    # La DB nunca contiene la clave en texto claro.
    return _get_fernet().decrypt(encrypted.encode('utf-8'))


# ── Manejo de contraseñas ─────────────────────────────────────────────────────

def verify_password(plain_password: str, hashed_password: str) -> bool:
    # Compara la contraseña en texto plano contra su hash bcrypt almacenado.
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    # Genera el hash bcrypt de una contraseña nueva.
    return pwd_context.hash(password)


# ── Tokens JWT ────────────────────────────────────────────────────────────────

def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None):
    # Crea un JWT firmado con los datos del usuario y una fecha de expiración.
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.utcnow() + expires_delta
    else:
        expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_identity(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    # Decodifica el JWT de la petición y devuelve la identidad autenticada.
    # Rechaza tokens inválidos, expirados o cuentas inactivas.
    from app.models.identity import Identity

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudieron validar las credenciales o sesión expirada.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    # Abrimos una sesión propia para no depender de la sesión inyectada por FastAPI
    from app.db.database import SessionLocal
    local_db = SessionLocal()
    try:
        user = local_db.query(Identity).filter(Identity.email == email).first()
        if user is None:
            raise credentials_exception
        # Bloqueamos el acceso si la cuenta fue revocada o dada de baja
        if user.estado != "ACTIVO":
            raise HTTPException(status_code=403, detail="Cuenta inactiva, dada de baja o suspendida.")
        return user
    finally:
        local_db.close()


# ── MFA / TOTP ───────────────────────────────────────────────────────────────

MFA_TOKEN_EXPIRE_MINUTES = 5  # El token temporal de MFA expira en 5 minutos

def generate_totp_secret() -> str:
    # Genera un secreto aleatorio en base32 compatible con Google Authenticator.
    return pyotp.random_base32()

def get_totp_uri(secret: str, email: str) -> str:
    # Devuelve la URI otpauth:// para mostrar como QR al usuario.
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name="Casa Monarca SGI")

def verify_totp_code(secret: str, code: str) -> bool:
    # Valida el código TOTP con una ventana de ±1 intervalo (30s) para tolerar drift de reloj.
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)

def create_mfa_pending_token(email: str) -> str:
    # Emite un JWT de corta vida que indica que el usuario completó la primera
    # fase (contraseña) pero aún debe validar el segundo factor TOTP.
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=MFA_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(
        {"sub": email, "mfa_pending": True, "exp": expire},
        SECRET_KEY,
        algorithm=ALGORITHM
    )

def decode_mfa_pending_token(token: str) -> str:
    # Decodifica el token temporal; lanza excepción si es inválido, expirado
    # o si no corresponde a una sesión MFA pendiente.
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if not payload.get("mfa_pending"):
            raise ValueError("Token no es de tipo MFA pendiente")
        email = payload.get("sub")
        if not email:
            raise ValueError("Token sin sujeto")
        return email
    except JWTError as exc:
        raise ValueError("Token MFA inválido o expirado") from exc


# ── Generación de material criptográfico ─────────────────────────────────────

def generate_key_pair():
    """
    Genera un par de llaves RSA de 2048 bits.
    Retorna: (llave_privada_obj, llave_privada_pem, llave_pública_obj, llave_pública_pem)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    # Serializamos la llave privada en formato PKCS8 sin cifrado local
    # (el cifrado se aplica en encrypt_private_key antes de guardar en DB)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Llave pública en formato estándar SubjectPublicKeyInfo
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key, private_pem, public_key, public_pem

def build_root_ca():
    """
    Crea una Autoridad Certificadora (CA) Raíz autofirmada con vigencia de 10 años.
    Esta CA es la que firma todos los certificados de identidad del sistema.
    """
    private_key, private_pem, public_key, public_pem = generate_key_pair()

    # El subject e issuer son iguales porque es autofirmado
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"MX"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Sistema Integral de Identidades"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"Root CA"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).add_extension(
        # La extensión BasicConstraints con ca=True es obligatoria para una CA
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(private_key, hashes.SHA256(), default_backend())

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    return private_key, cert, private_pem, cert_pem

def generate_user_certificate(public_key, user_name: str, ca_private_key, ca_cert, days_valid=365, email=None):
    """
    Emite un certificado X.509 para un usuario, firmado por la CA del sistema.
    El certificado acredita la identidad del titular dentro de la plataforma.

    Cuando se provee `email`, el certificado incluye las extensiones requeridas
    para S/MIME tanto en Thunderbird como en Outlook:
      - SubjectAlternativeName con rfc822Name  (Outlook lo exige para asociar al buzón)
      - KeyUsage: digitalSignature + contentCommitment
      - ExtendedKeyUsage: emailProtection (OID 1.3.6.1.5.5.7.3.4)
    """
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"MX"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Gestor de Identidades"),
        x509.NameAttribute(NameOID.COMMON_NAME, str(user_name)),
    ])

    builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=days_valid)
    )

    if email:
        # SubjectAlternativeName: Outlook busca aquí la dirección de correo
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name(str(email))]),
            critical=False
        )
        # KeyUsage: digitalSignature para firma; contentCommitment para no-repudio
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True
        )
        # ExtendedKeyUsage: emailProtection es obligatorio para que Outlook
        # reconozca el certificado como válido para S/MIME
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=False
        )

    cert = builder.sign(ca_private_key, hashes.SHA256(), default_backend())
    return cert.public_bytes(serialization.Encoding.PEM)

def create_ephemeral_certificate(user_name: str, duration_minutes: int, ca_private_key, ca_cert):
    """
    Genera un certificado de corta duración (efímero) medido en minutos.
    Útil para sesiones temporales o accesos puntuales de colaboradores externos.
    """
    # Generamos un par de llaves nuevo exclusivo para este certificado efímero
    private_key, private_pem, public_key, public_pem = generate_key_pair()

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"MX"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Gestor de Identidades"),
        x509.NameAttribute(NameOID.COMMON_NAME, str(user_name)),
    ])

    now = datetime.datetime.utcnow()

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now
    ).not_valid_after(
        # La expiración se calcula en minutos, no en días
        now + datetime.timedelta(minutes=duration_minutes)
    ).sign(ca_private_key, hashes.SHA256(), default_backend())

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return cert, cert_pem, private_pem, public_pem


# ── S/MIME ─────────────────────────────────────────────────────────────────────

def sign_smime(message_str, cert_pem_str, private_key_pem_str):
    """
    Firma message_str con S/MIME (PKCS#7 SignedData, firma detached).
    Devuelve el mensaje multipart/signed completo listo para enviar por correo.

    Usa los bindings internos de OpenSSL de cryptography 3.4.x:
      - PKCS7_sign()     → crea la estructura SignedData
      - i2d_PKCS7_bio()  → serializa a DER

    La constante PKCS7_DETACHED (0x40) indica firma separada: el cuerpo del
    mensaje viaja en texto claro y la firma va como adjunto smime.p7s.
    """
    import base64
    import uuid

    message_bytes = message_str.encode('utf-8') if isinstance(message_str, str) else message_str
    cert_pem = cert_pem_str.encode('utf-8')         if isinstance(cert_pem_str, str)        else cert_pem_str
    priv_pem = private_key_pem_str.encode('utf-8')  if isinstance(private_key_pem_str, str) else private_key_pem_str

    # Accedemos al backend OpenSSL que envuelve cryptography 3.4.x
    from cryptography.hazmat.backends.openssl.backend import backend as _ossl

    cert_obj = x509.load_pem_x509_certificate(cert_pem, _ossl)
    priv_obj = serialization.load_pem_private_key(priv_pem, password=None, backend=_ossl)

    lib = _ossl._lib
    ffi = _ossl._ffi

    # BIO de entrada con el contenido a firmar
    bio_in = lib.BIO_new_mem_buf(message_bytes, len(message_bytes))
    _ossl.openssl_assert(bio_in != ffi.NULL)

    try:
        # PKCS7_DETACHED = 0x40: la firma es separada del contenido
        p7 = lib.PKCS7_sign(cert_obj._x509, priv_obj._evp_pkey, ffi.NULL, bio_in, 0x40)
        _ossl.openssl_assert(p7 != ffi.NULL)

        try:
            # Serializar PKCS#7 a DER para incrustarlo en el adjunto MIME
            bio_der = lib.BIO_new(lib.BIO_s_mem())
            _ossl.openssl_assert(bio_der != ffi.NULL)
            try:
                lib.i2d_PKCS7_bio(bio_der, p7)
                buf_ptr = ffi.new("char **")
                buf_len = lib.BIO_get_mem_data(bio_der, buf_ptr)
                p7_der = bytes(ffi.buffer(buf_ptr[0], buf_len))
            finally:
                lib.BIO_free(bio_der)
        finally:
            lib.PKCS7_free(p7)
    finally:
        lib.BIO_free(bio_in)

    # Codificar la firma en base64 con líneas de 76 caracteres (RFC 2045)
    p7_b64 = base64.b64encode(p7_der).decode('ascii')
    p7_b64_wrapped = '\r\n'.join(p7_b64[i:i + 76] for i in range(0, len(p7_b64), 76))

    boundary = 'smime-' + uuid.uuid4().hex

    # Construir el mensaje multipart/signed conforme a RFC 5751
    signed_message = (
        'MIME-Version: 1.0\r\n'
        'Content-Type: multipart/signed;\r\n'
        '\tprotocol="application/pkcs7-signature";\r\n'
        '\tmicalg=sha-256;\r\n'
        '\tboundary="' + boundary + '"\r\n'
        '\r\n'
        'This is an S/MIME signed message\r\n'
        '\r\n'
        '--' + boundary + '\r\n'
        'Content-Type: text/plain; charset=utf-8\r\n'
        '\r\n'
        + (message_str if isinstance(message_str, str) else message_str.decode('utf-8')) + '\r\n'
        '\r\n'
        '--' + boundary + '\r\n'
        'Content-Type: application/pkcs7-signature; name=smime.p7s\r\n'
        'Content-Transfer-Encoding: base64\r\n'
        'Content-Disposition: attachment; filename=smime.p7s\r\n'
        '\r\n'
        + p7_b64_wrapped + '\r\n'
        '\r\n'
        '--' + boundary + '--\r\n'
    )

    return signed_message
