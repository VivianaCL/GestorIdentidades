# Gestor de Identidades

## Descripción

API REST para la gestión del ciclo de vida de identidades digitales dentro de una organización. Permite dar de alta, revocar y eliminar colaboradores, emitir certificados X.509 firmados, y auditar cada acción relevante del sistema.

---

## Características principales

- **Alta de identidades** con generación automática de certificado X.509 y par de llaves RSA
- **Revocación y revalidación** de certificados sin eliminar al usuario
- **Baja definitiva** (eliminación física) de identidades
- **Rastreo de auditoría** por identidad o global
- **Certificados efímeros** para sesiones o usuarios temporales
- **Descarga de certificados** con clave pública y privada entregadas por separado
- **Jerarquía de roles**: Admin > Coordinator > Operative > External
- **Autenticación JWT** con sesiones de 8 horas
- **Clave privada nunca en texto plano**: se cifra con Fernet (AES-128-CBC) antes de persistirse

---

## Requisitos de instalación

- Python 3.6.8 (versión probada; 3.7, 3.8 y 3.9 podrían funcionar pero no han sido verificadas)
- `pip` (gestor de paquetes de Python)
- (Recomendado) Entorno virtual: `venv` o `virtualenv`

---

## Instalación

### Opción A — Con entorno virtual (recomendado)

Evita conflictos con otros proyectos Python instalando las dependencias en un entorno aislado.

```bash
# 1. Clonar el repositorio
git clone <url-del-repositorio>
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

Instala las dependencias directamente en el Python del sistema. Útil para pruebas rápidas, pero puede generar conflictos de versiones si tienes otros proyectos.

```bash
# 1. Clonar el repositorio
git clone <url-del-repositorio>
cd GestorIdentidades

# 2. Instalar dependencias globalmente
pip install -r requirements.txt
```

> Si tienes múltiples versiones de Python instaladas, usa `pip3` o `python -m pip` para asegurarte de instalar en la versión correcta:
> ```bash
> python -m pip install -r requirements.txt
> ```

---

## Configuración

| Variable de entorno | Descripción | Valor por defecto |
|---|---|---|
| `SECRET_KEY` | Clave para firmar JWT y cifrar claves privadas | `b33fb4n6m0n4rc4` |

> **Importante**: en producción define `SECRET_KEY` como variable de entorno, nunca uses el valor por defecto.

```bash
# Ejemplo
export SECRET_KEY="tu_clave_secreta_larga_y_aleatoria"
```

---

## Uso básico

### 1. Inicializar la base de datos con el administrador maestro

```bash
python seed.py
```

Esto crea el usuario `admin@casamonarca.com` con contraseña `monarca123!`.

### 2. Levantar el servidor

```bash
uvicorn app.main:app --reload
```

El servicio queda disponible en `http://localhost:8000`.  
La documentación interactiva (Swagger UI) en `http://localhost:8000/docs`.

### 3. Ejemplos de uso rápido

**Login (obtener JWT)**
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
  -d '{"nombre":"Ana López","email":"ana@empresa.com","password":"pass123","rol":"Coordinator","cert_days_valid":365}'
```

**Descargar certificado y claves**
```bash
curl http://localhost:8000/api/v1/identities/{id}/download-cert \
  -H "Authorization: Bearer <token>"
```

**Revocar un certificado**
```bash
curl -X PUT http://localhost:8000/api/v1/identities/{id}/revocar \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"estado":"REVOCADO"}'
```

---

## Estructura del proyecto

```
GestorIdentidades/
│
├── app/
│   ├── core/
│   │   └── crypto.py          # Generación de llaves RSA, certificados X.509,
│   │                          # cifrado Fernet y manejo de JWT
│   │
│   ├── db/
│   │   └── database.py        # Configuración de SQLAlchemy y funciones CRUD base
│   │
│   ├── models/
│   │   └── identity.py        # Modelos ORM: Identity y AuditLog
│   │
│   ├── routers/
│   │   ├── auth.py            # Endpoints de login y logout
│   │   └── identity.py        # Endpoints de alta, baja, revocación, rastreo,
│   │                          # certificados efímeros y descarga de certificados
│   │
│   ├── schemas/
│   │   └── identity.py        # Esquemas Pydantic para validación y serialización
│   │
│   ├── services/
│   │   └── audit.py           # (Reservado para lógica de auditoría reutilizable)
│   │
│   ├── frontend.html          # Dashboard web embebido
│   └── main.py                # Punto de entrada: configuración de FastAPI y migraciones
│
├── tests/                     # Suite de pruebas
├── seed.py                    # Script para crear el administrador maestro inicial
├── requirements.txt           # Dependencias del proyecto
└── identities.db              # Base de datos SQLite (generada automáticamente)
```

---

## Contribuciones

Si deseas colaborar con el proyecto, sigue estos pasos:

1. **Clona el repositorio** y crea una rama con un nombre descriptivo:
   ```bash
   git clone <url-del-repositorio>
   cd GestorIdentidades
   git checkout -b feature/nombre-de-tu-cambio
   ```

2. **Instala el entorno** siguiendo los pasos de la sección _Instalación_.

3. **Explora el código**: los módulos están comentados y siguen una estructura lineal.  
   El orden recomendado de lectura es:
   `models/identity.py` → `db/database.py` → `core/crypto.py` → `routers/auth.py` → `routers/identity.py`

4. **Ejecuta el servidor y el seed** para verificar que tu entorno funciona:
   ```bash
   python seed.py
   uvicorn app.main:app --reload
   ```

5. **Realiza tus cambios** y asegúrate de que las pruebas pasen (ver sección _Pruebas_).

6. **Abre un Pull Request** describiendo qué cambiaste y por qué.

> Convención de commits: usa prefijos como `feat:`, `fix:`, `docs:` o `refactor:` para mantener el historial legible.

---

## Pruebas básicas

El directorio `tests/` está preparado para pruebas con `pytest`.

```bash
# Instalar pytest si no está instalado
pip install pytest

# Ejecutar todas las pruebas
pytest tests/

# Ejecutar con detalle
pytest tests/ -v
```

Para pruebas manuales rápidas puedes usar la documentación interactiva de FastAPI en `http://localhost:8000/docs` una vez levantado el servidor.

---

## Licencia de uso

Este proyecto se distribuye bajo la licencia **MIT**.

---

## Contacto

Para dudas, reportes o sugerencias, abre un _issue_ en el repositorio o contacta al equipo de desarrollo a través del correo institucional.
