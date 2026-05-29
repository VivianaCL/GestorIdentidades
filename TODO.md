# TODO — Gestor de Identidades

## Seguridad

- [ ] **Remover `SECRET_KEY` por defecto del código fuente.**
  El sistema debe exigir que la variable de entorno esté definida al arrancar; si no existe, debe abortar con un error claro en lugar de usar el valor hardcodeado `b33fb4n6m0n4rc4`.

- [ ] **Persistir la CA raíz.**
  Actualmente se genera una CA nueva en cada operación (alta, renovación, certificado efímero), por lo que los certificados emitidos no comparten cadena de confianza. La CA debe generarse una sola vez y almacenarse cifrada (en DB o en archivo) para construir una PKI real.

- [ ] **Invalidación de JWT en logout/revocación.**
  El logout actual es cosmético: el token sigue siendo válido hasta su expiración (8 h). Implementar una blocklist en memoria (o Redis) para invalidar tokens de forma inmediata al revocar o dar de baja a un usuario.

- [ ] **Validación de fortaleza de contraseñas en el alta.**
  El endpoint de alta no valida longitud ni complejidad de la contraseña. Los usuarios efímeros solo exigen mínimo 4 caracteres. Conviene aplicar al menos un mínimo de 8 caracteres con al menos un número o símbolo para todos los roles.

## Nuevas Funcionalidades

- [x] **Sistema de firma de correos.**
  Mensajería interna con firma RSA-PSS SHA-256 y verificación integrada. Mensajería externa con enlace de un solo uso y página pública de verificación. Firma S/MIME disponible desde la pestaña Certificados.

- [x] **Inicio de sesión por llave criptográfica.**
  Flujo challenge-response para Admin y Coordinator: el servidor emite un nonce, el navegador lo firma con la clave privada local (Web Crypto API) y el servidor verifica la firma RSA-PSS contra la clave pública almacenada.

- [x] **Expiración automática de usuarios efímeros.**
  Usuarios External y Operative con `cert_expires_at` vencido se marcan como `BAJA` automáticamente al arrancar el servidor, al intentar iniciar sesión y al cargar la lista de colaboradores (máximo una vez por hora).

- [x] **Códigos visibles por identidad.**
  Cada usuario recibe una clave legible (A001, C002, O001, X003…) además del ID interno. Aparece destacada en la tabla de colaboradores y es buscable. Los registros anteriores al despliegue reciben código automáticamente en el primer arranque.

- [x] **Folios de seguimiento en auditoría.**
  Cada evento del log de auditoría incluye un folio `TKT-YYYYMMDD-NNNN` y una copia del código visible de la identidad afectada, de modo que el historial siga siendo legible aunque el usuario sea eliminado físicamente.

- [x] **Aviso de Privacidad y Términos y Condiciones.**
  Accesibles desde la pantalla de login. El Aviso cubre los requisitos básicos de la LFPDPPP (responsable, datos recabados, finalidades, derechos ARCO). Los Términos definen el uso autorizado del sistema.

- [x] **Pie de firma institucional en correos.**
  Cada mensaje incluye automáticamente nombre, código visible y correo del remitente, cubierto por la firma digital. Cualquier manipulación del pie es detectable criptográficamente.

- [x] **Archivos adjuntos en mensajes.**
  Soporte para adjuntar archivos a mensajes internos y externos. Límite de 2 MB totales por mensaje (validado en frontend y backend). Los adjuntos son descargables directamente desde el detalle del mensaje y desde la página pública de externos.

- [x] **Verificación de firma bajo demanda y solo contra el remitente.**
  El modal de verificación muestra únicamente al remitente del mensaje (no todos los usuarios con certificado). La verificación se ejecuta al hacer clic, no automáticamente al abrir el mensaje. Aplica también a la página pública de mensajes externos.

- [ ] **Notificación por email al dar de alta un colaborador.**
  Cuando un Admin crea una nueva cuenta, el nuevo colaborador debería recibir un correo con instrucciones de primer acceso. Actualmente el Admin debe distribuir las credenciales manualmente.

- [ ] **Paginación en la vista de auditoría.**
  Cuando el log tenga cientos de entradas, cargarlas todas de golpe es ineficiente. Añadir paginación o scroll infinito en la vista de Auditoría.

## Calidad y Mantenimiento

- [ ] **Suite de pruebas en `tests/`.**
  El directorio existe pero no tiene pruebas automatizadas. Añadir pruebas de integración para los flujos principales: alta, login, revocación, baja y mensajería firmada.

- [ ] **Documentar comportamiento de `actor_id` huérfano.**
  Cuando un Admin es dado de baja, sus acciones previas en `audit_logs` quedan con `actor_id` apuntando a un ID eliminado. Definir política: soft-delete para admins, o copiar el nombre del actor en el log al momento del evento (similar a lo que ya se hace con `identity_codigo`).

- [ ] **Migración formal con Alembic.**
  Actualmente las migraciones son `ALTER TABLE` manuales en `main.py`. Para producción conviene usar Alembic para controlar versiones de esquema de forma reproducible y reversible.
