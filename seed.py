import sys
import os

# Agregamos la ruta local
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.db.database import SessionLocal, create_identity, log_audit_event, Base, engine
from app.models.identity import Identity, AuditLog
from app.core.crypto import build_root_ca, generate_key_pair, generate_user_certificate

# Aseguramos que la DB y sus tablas existan
Base.metadata.create_all(bind=engine)

db = SessionLocal()

def manual_alta(actor_id, nombre, email, rol, ca_priv, ca_cert):
    # Generamos localmente sin pasar por el router web
    _, _, pub_obj, pub_pem = generate_key_pair()
    user_cert_pem = generate_user_certificate(pub_obj, nombre, ca_priv, ca_cert)
    
    new_identity = create_identity(
        db, nombre, email, rol, 
        pub_pem.decode('utf-8'), 
        user_cert_pem.decode('utf-8')
    )
    
    log_audit_event(
        db=db, identity_id=new_identity.id, actor_id=actor_id,
        accion="ALTA", detalles=f"Alta exitosa (por script seed). Rol asignado: {rol}"
    )
    return new_identity

def generate_fakes():
    print("Iniciando siembra (seed) de colaboradores falsos...")
    
    existing_users = db.query(Identity).count()
    if existing_users > 0:
        print("Limpiando base de datos anterior...")
        db.query(AuditLog).delete()
        db.query(Identity).delete()
        db.commit()

    try:
        # Usaremos la misma CA Root para firmar todos en esta prueba de sistema
        ca_priv, ca_cert, _, _ = build_root_ca()

        print("1. Registrando al Administrador Maestro...")
        admin = manual_alta(0, "Ada Lovelace", "admin@empresa.com", "Admin", ca_priv, ca_cert)
        print(f" -> Exito: {admin.nombre} (ID: {admin.id}, Rol: {admin.rol})")

        print("\n2. El Administrador da de alta a un Coordinador...")
        coord = manual_alta(admin.id, "Alan Turing", "coordinador@empresa.com", "Coordinator", ca_priv, ca_cert)
        print(f" -> Exito: {coord.nombre} (ID: {coord.id}, Rol: {coord.rol})")

        print("\n3. El Coordinador da de alta a personal Operativo...")
        nombres_ops = ["Charles Babbage", "Grace Hopper"]
        for nombre in nombres_ops:
            op = manual_alta(coord.id, nombre, f"{nombre.split()[0].lower()}@empresa.com", "Operative", ca_priv, ca_cert)
            print(f" -> Exito: {op.nombre} (ID: {op.id}, Rol: {op.rol})")

        # El Operativo (Grace Hopper) registra a un Externo
        # id de Hopper es probablemente 4 (si Admin=1, Coord=2, Charles=3, Grace=4)
        print("\n4. El Operativo (Grace Hopper) da de alta a un Auditor Externo...")
        operativo_gh = db.query(Identity).filter(Identity.nombre == "Grace Hopper").first()
        ext = manual_alta(operativo_gh.id, "Nikola Tesla", "auditoria@terceros.com", "External", ca_priv, ca_cert)
        print(f" -> Exito: {ext.nombre} (ID: {ext.id}, Rol: {ext.rol})")

        print("\n" + "="*50)
        print("TABLA DE RASTREO (AuditLogs) RESULTANTE")
        print("="*50)
        
        logs = db.query(AuditLog).all()
        for log in logs:
            actor = "Bootstrap" if log.actor_id == 0 else db.query(Identity).filter(Identity.id == log.actor_id).first().nombre
            target = db.query(Identity).filter(Identity.id == log.identity_id).first().nombre
            print(f"[Log {log.id}] | Accion: {log.accion}")
            print(f" -> Actor: {actor} -> Afecto a: {target}")
            print(f" -> Detalle: {log.detalles}")

    except Exception as e:
        print(f"\nError de ejecucion: {e}")
    finally:
        db.close()
        print("\nScript finalizado. Identidades guardadas en SQLite.")

if __name__ == "__main__":
    generate_fakes()
