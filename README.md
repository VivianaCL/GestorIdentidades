# Gestor de Identidades — Casa Monarca

A01571511 - Alberto Palomino Carvajal
A01571619 - Carlos Cuéllar Solís
A01285849 - Daniel Rodríguez Gallegos
A01571750 - Leonardo Albarran Valdes
A01571679 - Luis Javier Jacobo Morimoto
A01286191 - Viviana Carrizales Luna

---

## Descripción

Sistema de Gestión de Identidades (SGI) para Casa Monarca, Ayuda Humanitaria al Migrante, A.C.

Proporciona el ciclo de vida completo de identidades digitales dentro de la organización: alta, revocación, baja, certificados X.509, mensajería firmada y auditoría inmutable de cada acción. Todo desde un dashboard web integrado, sin dependencias externas en el navegador.

---

## Características principales

### Identidades y acceso
- **Alta de identidades** con generación automática de certificado X.509 y par de llaves RSA 2048-bit
- **Clave visible por identidad**: cada usuario recibe un código legible (A001, C002, O001, X003…) además del ID interno
- **Jerarquía de roles**: Admin > Coordinator > Operative > External — nadie puede operar sobre alguien de igual o mayor nivel
- **Revocación y revalidación** de certificados sin eliminar al usuario
- **Baja definitiva** (eliminación física) con consentimiento ARCO explícito
- **Expiración automática** de usuarios efímeros (External/Operative) al vencer su certificado

### Autenticación
- **Login por contraseña** con JWT (sesiones de 8 horas)
- **Login por clave criptográfica** (challenge-response RSA-PSS) para Admin y Coordinator
- **Segundo factor TOTP** compatible con Google Authenticator y Authy (opcional por usuario)
- **Bloqueo inmediato** al revocar: la verificación de estado ocurre en cada petición autenticada

### Certificados
- Certificados X.509 firmados por CA interna con extensiones S/MIME (SubjectAlternativeName, KeyUsage, ExtendedKeyUsage)
- **Certificados efímeros** medidos en minutos para accesos puntuales
- Clave privada almacenada siempre cifrada con Fernet (AES-128-CBC); la DB nunca ve texto plano

### Mensajería institucional firmada
- **Mensajes internos** entre usuarios del sistema con firma RSA-PSS sobre el cuerpo completo
- **Mensajes externos** a cualquier email, con enlace de un solo uso y página pública de verificación
- **Pie de firma institucional** añadido automáticamente a cada mensaje (cubierto por la firma digital)
- **Archivos adjuntos** (hasta 2 MB totales por mensaje) descargables directamente desde la interfaz
- **Verificación de firma bajo demanda**: se muestra solo el remitente como candidato y se verifica al hacer clic
- Firma S/MIME completa (PKCS#7 detached) disponible desde la pestaña Certificados

### Auditoría
- Log inmutable de todas las acciones: quién hizo qué, sobre quién y cuándo
- **Folio de seguimiento** por evento: formato `TKT-YYYYMMDD-NNNN`, citable en reportes de incidentes
- Clave visible del usuario afectado copiada en el log (permanece legible aunque el usuario sea eliminado)
- Vista global (solo Admin) y vista individual por identidad

### Cumplimiento y privacidad
- Campos de consentimiento ARCO (`consentimiento_alta`, `fecha_consentimiento_alta`) conforme a LFPDPPP
- **Aviso de Privacidad** y **Términos y Condiciones** accesibles desde la pantalla de login

---

## Requisitos de instalación

- Python 3.6.8 (versión probada; 3.7–3.9 podrían funcionar pero no han sido verificadas)
- `pip` (gestor de paquetes de Python)
- Entorno virtual recomendado: `venv` o `virtualenv`

---

## Instalación

### Opción A — Con entorno virtual (recomendado)

```bash
# 1. Clonar el repositorio
git clone https://github.com/VivianaCL/GestorIdentidades.git
cd GestorIdentidades

# 2. Crear y activar el entorno virtual
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate

# 3. Instalar dependencias
pip install -r requirements.txt
```

### Opción B — Sin entorno virtual

```bash
git clone https://github.com/VivianaCL/GestorIdentidades.git
cd GestorIdentidades
pip install -r requirements.txt
```

> Si tienes múltiples versiones de Python instaladas, usa `python -m pip install -r requirements.txt`.

---

## Configuración

Copia `.env.example` a `.env` y ajusta los valores:

| Variable | Descripción | Valor por defecto |
|---|---|---|
| `SECRET_KEY` | Clave para firmar JWT y cifrar claves privadas | `b33fb4n6m0n4rc4` |
| `DB_ENGINE` | Motor de base de datos: `sqlite` o `mysql` | `sqlite` |
| `DB_USER` / `DB_PASSWORD` / `DB_HOST` / `DB_NAME` | Credenciales MySQL (solo si `DB_ENGINE=mysql`) | — |
| `SMTP_ENABLED` | Activa el envío real de emails (`true`/`false`) | `false` |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASS` | Configuración del servidor SMTP | — |
| `BASE_URL` | URL pública del servidor (para los enlaces externos) | `http://127.0.0.1:8000` |

> **Importante**: en producción define `SECRET_KEY` como variable de entorno real, nunca uses el valor por defecto.

---

## Uso básico

### 1. Inicializar la base de datos con el administrador maestro

```bash
python seed.py
```

Crea el usuario `admin@casamonarca.com` con contraseña `monarca123!` y su certificado X.509. El código visible asignado será **A001**.

### 2. Levantar el servidor

```bash
uvicorn app.main:app --reload
```

El dashboard estará en `http://localhost:8000`.
La documentación Swagger en `http://localhost:8000/docs`.

### 3. Ejemplos de uso rápido (API)

**Login**
```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -F "username=admin@casamonarca.com" \
  -F "password=monarca123!"
```

**Dar de alta un Coordinator**
```bash
curl -X POST http://localhost:8000/api/v1/identities/alta \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "nombre": "Ana López",
    "email": "ana@casamonarca.com",
    "password": "pass123",
    "rol": "Coordinator",
    "cert_days_valid": 365,
    "consentimiento_alta": true
  }'
```

**Revocar un certificado**
```bash
curl -X PUT http://localhost:8000/api/v1/identities/{id}/revocar \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"estado": "REVOCADO"}'
```

**Consultar auditoría de una identidad**
```bash
curl http://localhost:8000/api/v1/identities/{id}/rastreo \
  -H "Authorization: Bearer <token>"
```

---

## Estructura del proyecto

```
GestorIdentidades/
│
├── app/
│   ├── core/
│   │   └── crypto.py          # RSA, X.509, Fernet, JWT, TOTP, S/MIME
│   │
│   ├── db/
│   │   └── database.py        # SQLAlchemy, CRUD, generación de códigos y folios
│   │
│   ├── models/
│   │   └── identity.py        # ORM: Identity, AuditLog, Message
│   │
│   ├── routers/
│   │   ├── auth.py            # Login (contraseña, clave criptográfica, TOTP), logout
│   │   ├── identity.py        # Alta, baja, revocación, rastreo, certificados efímeros
│   │   └── messages.py        # Mensajería interna y externa firmada, adjuntos
│   │
│   ├── schemas/
│   │   └── identity.py        # Esquemas Pydantic para validación y serialización
│   │
│   ├── services/
│   │   ├── audit.py           # (Reservado para lógica de auditoría reutilizable)
│   │   └── mailer.py          # Envío de emails SMTP para mensajes externos
│   │
│   ├── frontend.html          # Dashboard web SPA embebido (sin frameworks externos)
│   └── main.py                # Punto de entrada: FastAPI, migraciones SQLite, startup
│
├── seed.py                    # Crea el administrador maestro inicial
├── requirements.txt           # Dependencias Python del proyecto
├── .env.example               # Plantilla de variables de entorno
└── identities.db              # Base de datos SQLite (se crea automáticamente)
```

---

## Contribuciones

1. Crea una rama descriptiva: `git checkout -b feature/nombre-del-cambio`
2. Instala el entorno siguiendo los pasos de _Instalación_
3. Orden de lectura recomendado del código:
   `models/identity.py` → `db/database.py` → `core/crypto.py` → `routers/auth.py` → `routers/identity.py` → `routers/messages.py`
4. Ejecuta `python seed.py` y `uvicorn app.main:app --reload` para verificar que tu entorno funciona
5. Abre un Pull Request describiendo qué cambiaste y por qué

Convención de commits: `feat:`, `fix:`, `docs:`, `refactor:`.

---

## Pruebas básicas

```bash
pip install pytest
pytest tests/ -v
```

Para pruebas manuales usa Swagger UI en `http://localhost:8000/docs` con el servidor activo.

---

## Licencia de uso

MIT — cualquiera puede usar, modificar y distribuir el código, incluso comercialmente, mientras se mantenga el aviso de copyright.

---

## Contacto

Alberto Palomino Carvajal    A01571511@tec.mx  
Carlos Cuéllar Solís         A01571619@tec.mx  
Daniel Rodríguez Gallegos    A01285849@tec.mx  
Leonardo Albarran Valdes     A01571750@tec.mx  
Luis Javier Jacobo Morimoto  A01571679@tec.mx  
Viviana Carrizales Luna      A01286191@tec.mx  
