# 📘 README – HU-04 Crear Usuarios (Administrador / Gerente)

> **Ubicación sugerida:** `docs/HU-04/README.md`

## 1) Resumen
- **Historia:** HU-04 – Crear Usuarios.
- **Objetivo:** Permitir que un **gerente/administrador** cree usuarios con: nombre, apellido, **telefono**, correo, contraseña, rol y estado.
- **Módulo:** `users`.
- **Precondición:** El solicitante debe estar autenticado y tener rol `ADMIN` o `GERENTE` (HU-02).

---

## 2) Endpoint
| Método | Ruta | Descripción |
|---|---|---|
| `POST` | `/api/auth/users/create` | Crea un nuevo usuario (solo ADMIN/GERENTE) |

---

## 3) Contrato de API

### 3.1 Headers
```
Authorization: Bearer <ACCESS_TOKEN>
Content-Type: application/json
```

### 3.2 Body (JSON)
```json
{
  "first_name": "María",
  "last_name": "López",
  "telefono": "3109876543",
  "email": "maria.lopez@example.com",
  "password": "Clave123",
  "password_confirm": "Clave123",
  "role": "EMPLEADO",
  "status": "ACTIVE"
}
```

### 3.3 Respuesta 201
```json
{
  "message": "Usuario creado con éxito.",
  "user": {
    "id": 5,
    "first_name": "María",
    "last_name": "López",
    "telefono": "3109876543",
    "email": "maria.lopez@example.com",
    "role": "EMPLEADO",
    "status": "ACTIVE"
  }
}
```

### 3.4 Errores típicos
| Código | Motivo | Ejemplo |
|---|---|---|
| 400 | Contraseñas no coinciden | {"password_confirm": "Las contraseñas no coinciden."} |
| 400 | Correo duplicado | {"email": "El correo ya está registrado."} |
| 401 | Falta token | {"detail": "Las credenciales de autenticación no se proveyeron."} |
| 403 | Rol no autorizado | {"detail": "No tienes permiso para crear usuarios."} |

---

## 4) Implementación (backend)

### 4.1 Serializer – `users/serializers.py`
```python
from rest_framework import serializers
from django.contrib.auth.hashers import make_password
from .models import User

class AdminCreateUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    password_confirm = serializers.CharField(write_only=True, required=True)
    telefono = serializers.CharField(required=False, allow_blank=True, max_length=15)

    class Meta:
        model = User
        fields = (
            "id", "first_name", "last_name", "telefono",
            "email", "password", "password_confirm",
            "role", "status"
        )

    def validate(self, data):
        if data["password"] != data["password_confirm"]:
            raise serializers.ValidationError({"password_confirm": "Las contraseñas no coinciden."})
        if User.objects.filter(email__iexact=data["email"]).exists():
            raise serializers.ValidationError({"email": "El correo ya está registrado."})
        return data

    def create(self, validated_data):
        validated_data.pop("password_confirm")
        validated_data["password"] = make_password(validated_data["password"])
        return User.objects.create(**validated_data)
```

### 4.2 Vista – `users/views.py`
```python
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from .serializers import AdminCreateUserSerializer
from .models import User

class AdminCreateUserView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = AdminCreateUserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        if request.user.role not in ["ADMIN", "GERENTE"]:
            return Response({"detail": "No tienes permiso para crear usuarios."}, status=403)

        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=400)

        user = serializer.save()
        return Response(
            {
                "message": "Usuario creado con éxito.",
                "user": {
                    "id": user.id,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "telefono": user.telefono,
                    "email": user.email,
                    "role": user.role,
                    "status": user.status
                }
            },
            status=status.HTTP_201_CREATED
        )
```

### 4.3 Rutas – `users/urls.py`
```python
from django.urls import path
from .views import AdminCreateUserView

urlpatterns += [
    path("users/create", AdminCreateUserView.as_view(), name="user-create-admin"),
]
```

> Nota: Si tus URLs de `users` están incluidas como `path("api/auth/", include("users.urls"))`, la ruta final será `/api/auth/users/create`.

---

## 5) Pruebas en Postman

1. Haz **login (HU-02)** con un usuario `ADMIN` o `GERENTE` y copia el `access` token.
2. En el request `POST /api/auth/users/create`:
   - Authorization → Type: **Bearer Token** → Token: `<ACCESS_TOKEN>` (o `{{access_token}}` si lo guardas con scripts).
   - Headers: `Content-Type: application/json`.
   - Body: **raw** → **JSON** → usa el ejemplo de arriba.
3. Envía. Deberías ver **201 Created** con el objeto `user`.

---

## 6) Checklist (DoD)
- [x] Endpoint protegido por JWT y rol (`ADMIN`/`GERENTE`).
- [x] Valida duplicado de correo y coincidencia de contraseñas.
- [x] Incluye campo **telefono**.
- [x] Respuestas claras de éxito/errores.
- [x] Probado en Postman.
- [x] Compatible con HU-01/HU-02/HU-03.

---

## 7) Notas para Frontend
- Requiere cabecera `Authorization: Bearer <access>`.
- Mostrar mensajes de error bajo los campos correspondientes (email/contraseña) y un toast para mensajes generales.
- Tras crear, refrescar listado de usuarios (si aplica) y limpiar formulario.
