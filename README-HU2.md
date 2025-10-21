# 📘 README – HU-02 Iniciar Sesión (JWT)

> **Archivo sugerido:** `docs/HU-02/README.md`

## 1) Resumen
- **Historia:** HU-02 – Iniciar sesión (autenticación por email + contraseña).  
- **Objetivo:** Permitir que un usuario existente se autentique y obtenga tokens **JWT** (`access` y `refresh`) para acceder a endpoints protegidos.  
- **Módulo:** `users`  
- **Criterios de aceptación:**  
  - CA1: Login correcto devuelve `access`, `refresh` y datos públicos del usuario.  
  - CA2: Credenciales inválidas → error 401.  
  - CA3: Usuario bloqueado o inactivo → error 403.

---

## 2) Stack y versiones
- **Django 5.0.x**, **DRF 3.15.x**  
- **Autenticación:** `djangorestframework-simplejwt 5.3.x`  
- **DB:** PostgreSQL 16 o SQLite (modo local)

---

## 3) Variables de entorno
Usa el mismo `.env` de la HU-01, no requiere nuevas variables.  
Solo asegúrate de tener:
```env
DJANGO_SECRET_KEY=dev-secret
DEBUG=True
POSTGRES_DB=shift
POSTGRES_USER=shift
POSTGRES_PASSWORD=shiftpass
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
```

---

## 4) Configuración JWT en `core/settings.py`
```python
from datetime import timedelta

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework_simplejwt.authentication.JWTAuthentication",
        "rest_framework.authentication.SessionAuthentication",
    ],
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=60),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "AUTH_HEADER_TYPES": ("Bearer",),
}
```

---

## 5) Endpoints implementados
| Método | Ruta | Descripción |
|--------|------|-------------|
| `POST` | `/api/auth/login` | Login con email y contraseña |
| `POST` | `/api/auth/token/refresh` | Renueva el access token |
| `GET` | `/api/auth/me` | Devuelve el perfil del usuario autenticado |

---

## 6) Contrato de API

### POST `/api/auth/login`
**Request**
```json
{
  "email": "ana@example.com",
  "password": "abc12345"
}
```

**Response 200**
```json
{
  "access": "JWT_ACCESS_TOKEN",
  "refresh": "JWT_REFRESH_TOKEN",
  "user": {
    "id": 1,
    "first_name": "Ana",
    "last_name": "Pérez",
    "telefono": "3104567890",
    "email": "ana@example.com",
    "role": "EMPLEADO",
    "status": "ACTIVE"
  }
}
```

**Errores**
| Código | Causa | Ejemplo |
|--------|--------|---------|
| 401 | Credenciales inválidas | {"message": "Credenciales inválidas."} |
| 403 | Usuario bloqueado/inactivo | {"message": "Usuario no autorizado. Verifica tu estado."} |

---

### POST `/api/auth/token/refresh`
**Body**
```json
{ "refresh": "<JWT_REFRESH_TOKEN>" }
```
**200 OK**
```json
{ "access": "<NEW_ACCESS_TOKEN>" }
```

---

### GET `/api/auth/me`
**Header**
```
Authorization: Bearer <ACCESS_TOKEN>
```
**200 OK**
```json
{
  "user": {
    "id": 1,
    "first_name": "Ana",
    "last_name": "Pérez",
    "telefono": "3104567890",
    "email": "ana@example.com",
    "role": "EMPLEADO",
    "status": "ACTIVE"
  }
}
```

---

## 7) Uso en Postman
1. **Login:** guarda automáticamente `access` y `refresh` con script:
   ```js
   let res = pm.response.json();
   if (res.access) {
       pm.environment.set("access_token", res.access);
       pm.environment.set("refresh_token", res.refresh);
   }
   ```
2. **/me:** en pestaña *Authorization* → Type = Bearer Token → Token = `{{access_token}}`
3. **Refresh:** usa body  
   ```json
   { "refresh": "{{refresh_token}}" }
   ```  
   y script para actualizar:
   ```js
   let r = pm.response.json();
   if (r.access) pm.environment.set("access_token", r.access);
   ```

---

## 8) Ejemplo rápido (fetch)
```ts
const login = async (email, password) => {
  const r = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password })
  });
  if (!r.ok) throw await r.json();
  return r.json();
};
```

---

## 9) Checklist (Definition of Done)
- [x] Endpoints `/login`, `/token/refresh`, `/me` creados  
- [x] Validaciones 401/403 correctas  
- [x] Tokens JWT configurados en `SIMPLE_JWT`  
- [x] Probado en Postman con variables automáticas  
- [x] Compatible con HU-01 (modelo `users.User`)  

---

## 10) Changelog
- **v1.0.0** – Login JWT funcional con refresh y `/me`  
- **v1.1.0** – Integración con entorno Postman automático  
