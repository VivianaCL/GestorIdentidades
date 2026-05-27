---
name: Estado del proyecto GestorIdentidades
description: Qué se ha implementado, qué falta y decisiones arquitectónicas clave
type: project
---

Sistema FastAPI de gestión de identidades con PKI X.509, MFA, S/MIME y mensajería firmada.

## Stack
- Python 3.6.8, FastAPI 0.61.1, SQLAlchemy 1.3.24
- DB dual: SQLite (dev, `DB_ENGINE=sqlite`) / MySQL via PyMySQL (prod HostGator, `DB_ENGINE=mysql`)
- Deploy destino: HostGator shared hosting

## Implementado en sesión actual

### Migración SQLite → MySQL
- `app/db/database.py` lee `DB_ENGINE` del `.env`; SQLite sigue funcionando en dev
- Modelos usan `String(n)` y `Text` en lugar de `String` sin longitud (requisito MySQL)
- Migraciones manuales `ALTER TABLE` solo corren cuando `DB_ENGINE=sqlite`

### S/MIME
- `export_pkcs12()` — exporta `.p12` compatible con Outlook/Thunderbird/Apple Mail
- `sign_smime()` — firma S/MIME multipart/signed (PKCS#7 detached)
- `generate_user_certificate()` ahora acepta `email` y añade SAN + KeyUsage + ExtendedKeyUsage (requerido por Outlook)
- Endpoints: `POST /{id}/smime/export-p12` y `POST /{id}/smime/sign`
- Integrados en frontend (pestaña Certificados)

### Sistema de mensajería firmada
- Modelo `Message` en DB (sender, recipient interno/externo, body, signature_b64, external_token)
- Firma RSA-PSS SHA-256 detached (no MIME completo — más simple de verificar)
- `app/routers/messages.py`: send/internal, send/external, inbox, sent, verify, externo/{token}
- `app/services/mailer.py`: SMTP dual dev (`SMTP_ENABLED=false` → enlace en pantalla) / prod
- Página pública `/mensaje-externo?token=...` para destinatarios externos sin login
- Pestaña "Correos" en frontend con Recibidos/Enviados, badge de no leídos, verificación de firma

## Problema conocido
- Admins creados con seed.py (ID 1, 5) no tienen `private_key_pem_encrypted` → no pueden firmar
- Solución: renovar certificado desde frontend (Certificados → Extender) o PUT /renovar-cert
- **Why:** Fueron creados antes de implementar almacenamiento de clave privada cifrada

## Variables de entorno clave (.env)
- `DB_ENGINE=sqlite|mysql`
- `SECRET_KEY=b33fb4n6m0n4rc4` ← clave actual en dev; NO cambiar sin re-cifrar DB
- `SMTP_ENABLED=false|true`
- `BASE_URL=http://127.0.0.1:8000`

## Pendiente (TODO.md)
- Remover SECRET_KEY hardcodeado del código
- Persistir CA raíz (actualmente se regenera en cada operación)
- Invalidación de JWT en logout (blocklist)
- Suite de pruebas en tests/
- Validación de fortaleza de contraseñas
- Expiración automática de usuarios efímeros
