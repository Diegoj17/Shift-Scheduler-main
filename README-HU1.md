# 📘 README – HU-01 Registrar Usuario

> **Archivo sugerido:** `docs/HU-01/README.md`

## 1) Resumen
- **Historia:** HU-01 – Registrar Usuario  
- **Objetivo:** Permitir que un usuario se registre en el sistema con email único y contraseña válida.  
- **Módulo:** `users`  
- **Criterios de aceptación (resumen):**  
  - CA1: Registro exitoso devuelve datos públicos del usuario.  
  - CA2: Rechazar correos duplicados.  
  - CA3: Rechazar contraseñas inválidas (mín. 8, letras y números).  

## 2) Stack y versiones
- **Django 5.0.x**, **DRF 3.15.x**
- **DB:** PostgreSQL 
- **Dependencias:** `djangorestframework`, `psycopg[binary]`, `python-dotenv`, `django-cors-headers`

## 3) Variables de entorno
Usar el `.env` en la raíz del proyecto:
```
DJANGO_SECRET_KEY=pedroalejandromo@ufps.edu.co
DEBUG=True
POSTGRES_DB=shiftscheduler
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_HOST=localhost  
POSTGRES_PORT=5432
```

## 4) Migraciones
```bash
python manage.py makemigrations
python manage.py migrate
```

## 5) Modelos y reglas de negocio
- **Modelo:** `users.User` (custom `AbstractUser` con email como USERNAME)
  - `email` (**único**)
  - `first_name`, `last_name`
  - `role` ∈ { `GERENTE`, `ADMIN`, `EMPLEADO` } (default: `EMPLEADO`)
  - `status` ∈ { `ACTIVE`, `BLOCKED`, `INACTIVE` } (default: `ACTIVE`)
- **Reglas:**  
  - Email único (case-insensitive).  
  - Password debe cumplir regex: mínimo 8 caracteres, al menos una letra y un número.  
  - El registro es **público** (sin autenticación).  

## 6) Permisos y seguridad
- **Auth:** No requerida para este endpoint.  
- **CORS:** habilitado con `django-cors-headers` (configurar orígenes en settings cuando se despliegue).  
- **Hash de contraseña:** `make_password()` (Django).  

## 7) Contrato de API
### Endpoint
- **POST** `/api/auth/register`

### Request (JSON)
```json
{
  "first_name": "Ana",
  "last_name": "Pérez",
  "email": "ana@example.com",
  "telefono":"3138880488",
  "password": "abc12345",
  "password_confirm": "abc12345",
  "role": "EMPLEADO"
}
```

### Response 201 (JSON)
```json
{
  "message": "Usuario registrado",
  "user": {
    "id": 1,
    "first_name": "Ana",
    "telefono":"3138880488"
    "last_name": "Pérez",
    "email": "ana@example.com",
    "role": "EMPLEADO",
    "status": "ACTIVE"
  }
}
```

### Errores
| HTTP | Formato                                 | Ejemplo                                                                 |
|-----:|-----------------------------------------|-------------------------------------------------------------------------|
| 400  | dict por campo (DRF)                    | {"email": ["El correo ya está registrado."]}                            |
| 400  | dict por campo (contraseñas no coinc.)  | {"password_confirm": "Las contraseñas no coinciden."}                   |
| 400  | dict por campo (password débil)         | {"password": ["La contraseña debe tener mínimo 8 caracteres e incluir letras y números."]} |

> **Nota:** si deseas formato uniforme con `code/message`, podemos envolver errores globales así:
```json
{ "code": "ERR_VALIDATION", "message": "Datos inválidos", "errors": { "email": ["..."] } }
```

## 8) Ejemplos de uso

### curl
```bash
curl -X POST http://localhost:8000/api/auth/register   -H "Content-Type: application/json"   -d '{
    "first_name":"Ana",
    "last_name":"Pérez",
    "email":"ana@example.com",
    "password":"abc12345",
    "password_confirm":"abc12345",
    "role":"EMPLEADO"
  }'
```

### fetch (frontend)
```ts
async function register(payload:{
  first_name:string; last_name:string; email:string;
  password:string; password_confirm:string; role:"EMPLEADO"|"GERENTE"|"ADMIN";
}){
  const res = await fetch("/api/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });

  if (!res.ok) {
    const err = await res.json();
    throw err;
  }

  return res.json(); // { message, user }
}
```

### Axios
```ts
import axios from "axios";
try {
  const { data } = await axios.post("/api/auth/register", payload);
  // data.user -> usar en el frontend
} catch (e:any) {
  if (e.response?.status === 400) {
    // e.response.data tiene errores por campo
  }
}
```

## 9) Pruebas
```bash
pytest -q
# o
python manage.py test users.tests.test_register
```
- **Casos**: registro exitoso, email duplicado, password inválida.

## 10) Checklist (DoD)
- [x] Endpoint documentado  
- [x] Validaciones: email único, contraseña fuerte, confirmación  
- [x] Tests verdes  
- [x] `users` registrado en `INSTALLED_APPS`  
- [x] Ruta en `core/urls.py`  
- [x] Verificado en pgAdmin (`users_user`)  

## 11) Changelog
- **v1.0.0** – Endpoint `POST /api/auth/register` estable con validaciones y tests.
