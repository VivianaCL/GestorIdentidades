# TODO — Gestor de Identidades

## Seguridad

- [ ] **Remover `SECRET_KEY` por defecto del código fuente.**
  El sistema debe exigir que la variable de entorno esté definida al arrancar; si no existe, debe abortar con un error claro en lugar de usar el valor hardcodeado `b33fb4n6m0n4rc4`.

- [ ] **Persistir la CA raíz.**
  Actualmente se genera una CA nueva en cada operación (alta, renovación, certificado efímero), por lo que los certificados emitidos no comparten cadena de confianza. La CA debe generarse una sola vez y almacenarse cifrada (en DB o en archivo) para construir una PKI real.

- [ ] **Invalidación de JWT en logout/revocación.**
  El logout actual es cosmético: el token sigue siendo válido hasta su expiración (8h). Implementar una blocklist en memoria (o Redis) para invalidar tokens de forma inmediata al revocar o dar de baja a un usuario.

## Nuevas Funcionalidades

- [x] **Sistema de firma de correos.**
  Mensajería interna con firma RSA-PSS SHA-256 y verificación integrada. Mensajería externa con enlace de un solo uso y página pública de verificación. Firma S/MIME disponible desde la pestaña Certificados.

- [x] **Inicio de sesión por llave criptográfica.**
  Flujo challenge-response para Admin y Coordinator: el servidor emite un nonce, el navegador lo firma con la clave privada local (Web Crypto API) y el servidor verifica la firma RSA-PSS contra la clave pública almacenada. Incluye endpoint para descargar la clave privada PEM desde "Mi cuenta → Seguridad MFA".

- [x] **Expiración automática de usuarios efímeros.**
  Usuarios External y Operative con `cert_expires_at` vencido se marcan como `BAJA` automáticamente en tres momentos: arranque del servidor, intento de login propio, y carga de la lista de colaboradores (máximo una vez por hora).

## Calidad y Mantenimiento

- [ ] **Suite de pruebas en `tests/`.**
  El directorio existe pero la información está en una carpeta dentro de una máquina local de un miembro del equipo. Añadir pruebas de integración para los flujos principales: alta, login, revocación, baja y certificados efímeros.

- [ ] **Validación de fortaleza de contraseñas en el alta.**
  El endpoint de alta no valida longitud ni complejidad de la contraseña. Usuarios efímeros solo exigen mínimo 4 caracteres.

- [ ] **Documentar comportamiento de `actor_id` huérfano.**
  Cuando un Admin es dado de baja, sus acciones previas en `audit_logs` quedan con `actor_id` apuntando a un ID eliminado. Definir política (soft delete para admins, o preservar nombre en el log).
