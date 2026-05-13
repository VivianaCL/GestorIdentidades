# TODO — Gestor de Identidades

## Seguridad

- [ ] **Remover `SECRET_KEY` por defecto del código fuente.**
  El sistema debe exigir que la variable de entorno esté definida al arrancar; si no existe, debe abortar con un error claro en lugar de usar el valor hardcodeado `b33fb4n6m0n4rc4`.

- [ ] **Persistir la CA raíz.**
  Actualmente se genera una CA nueva en cada operación (alta, renovación, certificado efímero), por lo que los certificados emitidos no comparten cadena de confianza. La CA debe generarse una sola vez y almacenarse cifrada (en DB o en archivo) para construir una PKI real.

- [ ] **Invalidación de JWT en logout/revocación.**
  El logout actual es cosmético: el token sigue siendo válido hasta su expiración (8h). Implementar una blocklist en memoria (o Redis) para invalidar tokens de forma inmediata al revocar o dar de baja a un usuario.

## Nuevas Funcionalidades

- [ ] **Sistema de firma de correos.**
  Permitir que las identidades firmen digitalmente correos electrónicos usando su clave privada RSA (S/MIME o PGP). Incluir endpoint para exportar el certificado en formato compatible con clientes de correo.

- [ ] **Inicio de sesión por llave criptográfica.**
  Añadir un flujo de autenticación alternativo donde administradores y coordinadores puedan autenticarse presentando su llave privada en lugar de usuario/contraseña. El servidor verificaría una firma sobre un challenge aleatorio (similar a SSH).

- [ ] **Expiración automática de usuarios efímeros.**
  Los usuarios efímeros persisten en DB aunque su certificado haya vencido. Añadir tarea de limpieza periódica (o verificación en login) que elimine o marque como `BAJA` a los usuarios cuyo `cert_expires_at` haya pasado.

## Calidad y Mantenimiento

- [ ] **Suite de pruebas en `tests/`.**
  El directorio existe pero la información está en una carpeta dentro de una máquina local de un miembro del equipo. Añadir pruebas de integración para los flujos principales: alta, login, revocación, baja y certificados efímeros.

- [ ] **Validación de fortaleza de contraseñas en el alta.**
  El endpoint de alta no valida longitud ni complejidad de la contraseña. Usuarios efímeros solo exigen mínimo 4 caracteres.

- [ ] **Documentar comportamiento de `actor_id` huérfano.**
  Cuando un Admin es dado de baja, sus acciones previas en `audit_logs` quedan con `actor_id` apuntando a un ID eliminado. Definir política (soft delete para admins, o preservar nombre en el log).
