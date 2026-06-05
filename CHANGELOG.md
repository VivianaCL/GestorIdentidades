# CHANGELOG — Gestor de Identidades

## [2.0.0] — 2026-05-29

### Identidades
- **Feat:** Códigos visibles por identidad (`A001`, `C002`, `O001`, `X003`…). Cada usuario recibe automáticamente una clave legible según su rol al ser creado. Los registros anteriores reciben código en el primer arranque del servidor.
- **Feat:** Búsqueda de colaboradores por código visible, además de nombre, correo y rol.
- **Feat:** Los diálogos de revocación y baja muestran el código visible en lugar del ID numérico.

### Auditoría
- **Feat:** Folio de seguimiento por evento de auditoría. Formato `TKT-YYYYMMDD-NNNN`, citable en reportes de incidentes.
- **Feat:** Copia desnormalizada del código visible de la identidad afectada en cada evento del log (`identity_codigo`). El historial sigue siendo legible aunque el usuario sea eliminado físicamente.

### Mensajería
- **Feat:** Pie de firma institucional añadido automáticamente a todos los mensajes (internos y externos). Incluye nombre, código visible y correo del remitente, cubierto por la firma digital.
- **Feat:** Archivos adjuntos en mensajes internos y externos. Límite de 2 MB totales por mensaje, validado tanto en el navegador como en el servidor. Los adjuntos son descargables directamente desde el detalle del mensaje y desde la página pública.
- **Feat:** Verificación de firma bajo demanda y acotada al remitente. El modal de verificación muestra solo al remitente del mensaje abierto; la verificación se ejecuta al hacer clic, no al abrir.
- **Feat:** Página pública de mensajes externos solo muestra al remitente como candidato para verificación de firma, eliminando la lista completa de usuarios del sistema.
- **Fix:** La hora de expiración en la creación de usuarios efímeros ahora se muestra en UTC-6 (hora del centro de México) en lugar de UTC.

### Privacidad y cumplimiento
- **Feat:** Aviso de Privacidad accesible desde la pantalla de login. Cubre los requisitos básicos de la LFPDPPP: responsable del tratamiento, datos recabados, finalidades, transferencias y derechos ARCO.
- **Feat:** Términos y Condiciones de Uso accesibles desde la pantalla de login. Define uso autorizado, responsabilidad del usuario, custodia de clave privada y legislación aplicable.

### Infraestructura
- **Refactor:** Migraciones SQLite actualizadas en `main.py` para las nuevas columnas (`identities.codigo`, `audit_logs.ticket`, `audit_logs.identity_codigo`, `messages.attachments_json`).
- **Docs:** Comentarios de código revisados para ser más descriptivos y orientados al "por qué", no solo al "qué".
- **Docs:** README completamente reescrito con tabla de variables de entorno, estructura actualizada del proyecto y descripción de todas las funcionalidades actuales.
- **Docs:** TODO actualizado: nuevos ítems marcados como completados, nuevas tareas pendientes añadidas.

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