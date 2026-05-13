# CHANGELOG — Gestor de Identidades

## [Unreleased]

- **Fix:** removido `pymysql` de `requirements.txt` (nunca fue requerido; la app usa SQLite exclusivamente).
- **Docs:** README actualizado con instalación sin entorno virtual, versión de Python corregida a 3.6.8 (probada) con nota de compatibilidad no verificada para 3.7–3.9.

---

## [1.0.0] — 2026-05-06

- **Frontend:** se añade visualización y descarga de la clave privada desde el dashboard web, entregada por separado del certificado.
- **Docs:** comentarios añadidos en todos los módulos principales (`crypto.py`, `database.py`, `main.py`, models, routers, schemas, `seed.py`) y README inicial del proyecto.

---

## [0.6.1] — 2026-04-24

- **Fix:** advertencia visible en el frontend al intentar extender/renovar un certificado, previniendo renovaciones accidentales.
- **Fix:** validación de rango de días en el endpoint de renovación (1–3650 días).

---

## [0.6.0] — 2026-04-23

- **Seguridad:** la revocación de un certificado ahora bloquea el login del usuario afectado de forma inmediata (verificación de estado en `auth.py`).
- **Refactor:** eliminación de los endpoints y UI de certificados efímeros del flujo principal del frontend; la funcionalidad se conserva en la API.
- **Fix:** corrección en esquemas Pydantic relacionados con usuarios efímeros.

---

## [0.5.0] — 2026-04-23

- **Funcionalidad:** ajuste de niveles de acceso por rol; Admin, Coordinator, Operative y External tienen permisos diferenciados de forma explícita.
- **Seed:** el script `seed.py` ahora genera el Admin maestro con su propio certificado X.509 y par de llaves RSA desde el primer arranque.

---

## [0.4.0] — 2026-04-22

- **Funcionalidad:** revalidación de certificados. Un Admin puede reactivar un certificado revocado sin emitir uno nuevo; se marca `cert_revalidado=True` para distinguirlo de certificados nunca revocados.
- **Modelo:** añadidos campos `cert_revalidado` y `cert_expires_at` a la tabla `identities` mediante migraciones manuales en startup.
- **Frontend:** panel de revalidación añadido al dashboard.
- **main.py:** evento `startup` que limpia material criptográfico de roles Operative y External al arrancar el servidor.

---

## [0.3.0] — 2026-04-17 / 2026-04-20

- **Funcionalidad:** certificados efímeros (por duración en minutos) y usuarios efímeros con rol External forzado.
- **Fix:** correcciones en jerarquía de permisos; un actor no puede operar sobre identidades de igual o mayor nivel.
- **Tests:** primeras pruebas manuales de certificados efímeros.
- **Seed:** admin inicial generado con certificado desde el arranque.
- **Frontend:** rediseño de layout y exposición de nuevos endpoints en la UI.

---

## [0.2.0] — 2026-04-17

- **Funcionalidad base:** módulo de criptografía (RSA 2048-bit, X.509, Fernet, JWT, bcrypt).
- **Módulos iniciales:** `database.py`, models (`Identity`, `AuditLog`), schemas Pydantic, routers de auth (login/logout) e identidades (alta, baja, revocación, rastreo).
- **Frontend:** HTML embebido servido desde la raíz.
- **Jerarquía de roles:** Admin > Coordinator > Operative > External.
- **Seguridad:** contraseñas hasheadas con bcrypt; clave privada cifrada con Fernet antes de persistirse en DB.

---

## [0.1.0] — 2026-04-15

- Estructura inicial del repositorio: módulos vacíos, esquemas base, módulo de criptografía y script de creación de DB.