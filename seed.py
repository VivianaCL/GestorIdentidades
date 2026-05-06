# Script de inicialización de datos (seed).
# Crea el usuario Administrador Maestro la primera vez que se levanta el sistema.
# Es seguro ejecutarlo múltiples veces: verifica que el admin no exista antes de crearlo.

from app.db.database import SessionLocal, engine, Base, create_identity, log_audit_event
from app.models.identity import Identity
from app.core.crypto import build_root_ca, generate_key_pair, generate_user_certificate, get_password_hash


def seed_admin():
    # Nos aseguramos de que las tablas estén creadas antes de insertar datos
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        # Si el admin ya existe, no hacemos nada para evitar duplicados
        admin = db.query(Identity).filter(Identity.email == "admin@casamonarca.com").first()
        if admin:
            print("El Administrador maestro ya existe.")
            return

        print("Generando material criptográfico para Administrador maestro...")

        # Creamos una CA raíz temporal solo para emitir el certificado inicial del admin
        ca_priv, ca_cert, _, _ = build_root_ca()
        _, _, pub_obj, pub_pem = generate_key_pair()

        user_cert_pem = generate_user_certificate(pub_obj, "Administrador Maestro", ca_priv, ca_cert)

        # La contraseña semilla se hashea; nunca se guarda en texto plano
        hashed_password = get_password_hash("monarca123!")

        print("Registrando en la Base de Datos...")
        new_admin = create_identity(
            db,
            nombre="Administrador Maestro",
            email="admin@casamonarca.com",
            password_hash=hashed_password,
            rol="Admin",
            public_key_pem=pub_pem.decode('utf-8'),
            certificate_pem=user_cert_pem.decode('utf-8')
            # Nota: el seed no almacena la clave privada del admin porque este
            # usuario es creado manualmente; sus credenciales se distribuyen aparte.
        )

        # Dejamos evidencia en el log de que fue creado por inicialización del sistema
        log_audit_event(
            db,
            actor_id=new_admin.id,
            accion="BOOTSTRAP",
            identity_id=new_admin.id,
            detalles="Creación automática de cuenta semilla para Admin."
        )

        print("\n" + "="*50)
        print("[OK] Administrador Maestro Creado Exitosamente")
        print("="*50)
        print(f"Usuario (Email): admin@casamonarca.com")
        print(f"Contraseña:     monarca123!")
        print("="*50)

    except Exception as e:
        print(f"Error al popular la base de datos: {e}")
    finally:
        db.close()


if __name__ == "__main__":
    seed_admin()
