import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes


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

def generate_user_certificate(public_key, user_name: str, ca_private_key, ca_cert):
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
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).sign(ca_private_key, hashes.SHA256(), default_backend())
    
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return cert_pem
