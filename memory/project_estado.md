---
name: Estado del proyecto GestorIdentidades
description: Qué está implementado, decisiones técnicas clave y pendientes — actualizado v2.0.0
type: project
---

Sistema FastAPI de gestión de identidades con PKI X.509, MFA, S/MIME y mensajería firmada.
Deploy destino: HostGator shared hosting (sin Redis, sin cron, sin root).

## Stack
- Python 3.6.8, FastAPI 0.61.1, SQLAlchemy 1.3.24
- DB dual: SQLite (dev) / MySQL via PyMySQL (prod, `DB_ENGINE=mysql`)
- Frontend: SPA en `frontend.html` sin frameworks externos, tema oscuro con acentos dorados

---

## Implementado (v2.0.0)

### Identidades
- Alta, revocación, revalidación, baja definitiva (hard delete con consentimiento ARCO)
- Código visible por rol: A001 Admin, C001 Coordinator, O001 Operative, X001 External
- Migración automática al arrancar para registros anteriores sin código
- Jerarquía: Admin > Coordinator > Operative > External
- `delete_identity` elimina primero los mensajes del usuario antes del hard delete (evita herencia por reuso de ID en SQLite)

### Autenticación
- Login contraseña + JWT (8 h), login por clave criptográfica (challenge-response RSA-PSS), TOTP/MFA opcional
- Expiración automática de efímeros al login y al listar colaboradores (lazy, máx 1/h)

### Auditoría
- Folio TKT-YYYYMMDD-NNNN por evento
- `identity_codigo` y `actor_codigo` desnormalizados (legibles aunque el usuario sea eliminado)
- Vista global (Admin) y vista por identidad

### Mensajería
- Mensajes internos (firmados RSA-PSS) y externos (enlace de un solo uso)
- Pie de firma institucional añadido al cuerpo ANTES de firmarlo (cubre nombre + código + correo)
- Archivos adjuntos: límite 2 MB total por mensaje, base64 en JSON, descargables desde UI y página pública
- **Verificación interna:** todos los usuarios con certificado activo, en grilla de 2 col, con código visible
- **Verificación externa (página pública):** solo el remitente, verificación bajo demanda al hacer clic
- Firma S/MIME PKCS#7 detached desde pestaña Certificados

### Privacidad
- Aviso de Privacidad (LFPDPPP) y Términos y Condiciones desde pantalla de login
- Consentimiento ARCO con timestamp en alta y baja

---

## Decisiones técnicas relevantes

- **Límite adjuntos 2 MB:** conservador para HostGator shared; suficiente para PDFs y documentos ligeros
- **actor_codigo en AuditLog:** copiado al momento del evento; el log es legible aunque el actor sea eliminado
- **CA raíz no persistida:** se regenera en cada operación; los certificados no comparten cadena de confianza real — pendiente en TODO
- **JWT sin blocklist:** logout es cosmético — pendiente en TODO
- **Hora efímeros:** se convierte a UTC-6 en el mensaje de confirmación; timestamps internos siguen en UTC
- **SECRET_KEY default:** `b33fb4n6m0n4rc4` solo en dev; NO cambiar en prod sin re-cifrar la DB

---

## Problema conocido
- Admins creados con seed.py antes de la implementación de clave privada cifrada no pueden firmar correos
- Solución: renovar certificado desde frontend (Certificados → Extender) o `PUT /renovar-cert`

## Pendientes prioritarios (ver TODO.md)
- Persistir CA raíz
- Blocklist JWT en logout/revocación
- SECRET_KEY obligatorio al arrancar (abortar si no está definido)
- Suite de pruebas en tests/
- Migración formal con Alembic
