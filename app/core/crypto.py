import datetime
import os
from typing import Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from app.db.database import get_db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = os.environ.get("SECRET_KEY", "b33fb4n6m0n4rc4") # Clave secreta (debería exportarse por .env en prod)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480 # 8 horas

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.utcnow() + expires_delta
    else:
        expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_identity(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
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
        
    # Asumimos que db ya viene inyectado
    from app.db.database import SessionLocal
    local_db = SessionLocal()
    try:
        user = local_db.query(Identity).filter(Identity.email == email).first()
        if user is None:
            raise credentials_exception
        if user.estado != "ACTIVO":
            raise HTTPException(status_code=403, detail="Cuenta inactiva, dada de baja o suspendida.")
        return user
    finally:
        local_db.close()


def generate_key_pair():
    """ 
    Genera un par de llaves RSA seguras.
    Retorna la llave privada/pública en objeto, y su representación Serializada (PEM).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    public_key = private_key.public_key()
    
    # Exportar llave privada a string formato PEM (Sin encriptar localmente por ahora)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Exportar llave pública a string formato PEM
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_key, private_pem, public_key, public_pem

def build_root_ca():
    """
    Crea una Autoridad Certificadora (CA) Raíz.
    Esto debe usarse para generar la llave maestra con la que se firmarán 
    las identidades del sistema.
    """
    private_key, private_pem, public_key, public_pem = generate_key_pair()
    
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
        # Validez de 10 años para Root CA
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(private_key, hashes.SHA256(), default_backend())
    
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    
    # Retornamos los objetos y el PEM para guardar la master CA.
    return private_key, cert, private_pem, cert_pem

def generate_user_certificate(public_key, user_name: str, ca_private_key, ca_cert, days_valid=365  ):
    """
    Emite un certificado de identidad X.509 para un usuario,
    firmado digitalmente por la llave privada de la CA (Acreditando su identidad).
    """
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"MX"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Gestor de Identidades"),
        x509.NameAttribute(NameOID.COMMON_NAME, str(user_name)),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
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
        # Validez típica de identidad: 1 Año
        datetime.datetime.utcnow() + datetime.timedelta(days=days_valid)
    ).sign(ca_private_key, hashes.SHA256(), default_backend())
    
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return cert_pem

def create_ephemeral_certificate(user_name: str, duration_minutes: int, ca_private_key, ca_cert):
    """
    Crea un certificado efímero (temporal) con duración en minutos.
    """
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
        now + datetime.timedelta(minutes=duration_minutes)
    ).sign(ca_private_key, hashes.SHA256(), default_backend())
    
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return cert, cert_pem, private_pem, public_pem
