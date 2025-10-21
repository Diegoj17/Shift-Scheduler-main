# 📘 README – HU-05 (PUT completo) Editar Usuarios

> **Ubicación sugerida:** `docs/HU-05-PUT/README.md`

## 1) Resumen
- **Historia:** HU-05 – Editar usuarios (versión con PUT completo).
- **Objetivo:** Permitir que un **gerente/administrador** actualice completamente la información de un usuario existente (nombre, apellido, teléfono, correo, rol, estado).  
- **Diferencia:** A diferencia de PATCH, el método **PUT** requiere enviar **todos los campos** del usuario.

---

## 2) Endpoint
| Método | Ruta | Descripción |
|---|---|---|
| `PUT` | `/api/auth/users/:id` | Actualiza completamente un usuario existente |

---

## 3) Contrato de API

### 3.1 Headers
```
Authorization: Bearer <ACCESS_TOKEN>
Content-Type: application/json
```

### 3.2 Body (ejemplo completo)
```json
{
  "first_name": "Alejandro",
  "last_name": "Fonseca",
  "telefono": "3109876543",
  "email": "alejandro.fonseca@example.com",
  "role": "EMPLEADO",
  "status": "ACTIVE"
}
```

### 3.3 Respuesta 200
```json
{
  "message": "Usuario actualizado con éxito.",
  "user": {
    "id": 5,
    "first_name": "Alejandro",
    "last_name": "Fonseca",
    "telefono": "3109876543",
    "email": "alejandro.fonseca@example.com",
    "role": "EMPLEADO",
    "status": "ACTIVE"
  }
}
```

### 3.4 Errores típicos
| Código | Motivo | Ejemplo |
|---|---|---|
| 400 | Correo duplicado | {"email": "El correo ya está registrado."} |
| 401 | Falta token | {"detail": "Las credenciales de autenticación no se proveyeron."} |
| 403 | Rol no autorizado | {"detail": "No tienes permiso para editar usuarios."} |
| 404 | Usuario no existe | {"detail": "No encontrado."} |

---

## 4) Implementación (backend)

### 4.1 Serializer – `users/serializers.py`
```python
from rest_framework import serializers
from .models import User

class AdminUpdateUserSerializer(serializers.ModelSerializer):
    telefono = serializers.CharField(required=False, allow_blank=True, max_length=15)
    email = serializers.EmailField(required=False)

    class Meta:
        model = User
        fields = ("id", "first_name", "last_name", "telefono", "email", "role", "status")

    def validate_email(self, value):
        if not value:
            return value
        qs = User.objects.filter(email__iexact=value)
        if self.instance:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise serializers.ValidationError("El correo ya está registrado.")
        return value
```

### 4.2 Vista – `users/views.py`
```python
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from .serializers import AdminUpdateUserSerializer
from .models import User

class AdminEditUserView(generics.UpdateAPIView):
    queryset = User.objects.all()
    serializer_class = AdminUpdateUserSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "pk"

    def update(self, request, *args, **kwargs):
        # Solo ADMIN/GERENTE pueden editar
        if request.user.role not in ["ADMIN", "GERENTE"]:
            return Response({"detail": "No tienes permiso para editar usuarios."}, status=403)

        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=False)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        user = serializer.instance
        return Response(
            {
                "message": "Usuario actualizado con éxito.",
                "user": {
                    "id": user.id,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "telefono": user.telefono,
                    "email": user.email,
                    "role": user.role,
                    "status": user.status,
                },
            },
            status=200,
        )
```

### 4.3 Rutas – `users/urls.py`
```python
from django.urls import path
from .views import AdminEditUserView

urlpatterns += [
    path("users/<int:pk>", AdminEditUserView.as_view(), name="user-edit-admin"),
]
```

> Si `users.urls` está incluido bajo `api/auth/`, la ruta completa es `/api/auth/users/<id>`.

---

## 5) Pruebas en Postman

### Escenario 1 – Edición exitosa
- **PUT** `http://127.0.0.1:8000/api/auth/users/5`
- **Headers:** `Authorization: Bearer <access>`, `Content-Type: application/json`
- **Body:**
```json
{
  "first_name": "Alejandro",
  "last_name": "Fonseca",
  "telefono": "3109876543",
  "email": "alejandro.fonseca@example.com",
  "role": "EMPLEADO",
  "status": "ACTIVE"
}
```
**Respuesta 200**: mensaje “Usuario actualizado con éxito.” y objeto `user`.

### Escenario 2 – Correo duplicado
- **PUT** a un usuario, cambiando `email` a uno que ya exista.  
**Respuesta 400**: `{"email": "El correo ya está registrado."}`

---

## 6) Checklist (DoD)
- [x] Endpoint `PUT /api/auth/users/<id>` protegido por JWT.
- [x] Solo `ADMIN/GERENTE` autorizados.
- [x] Validación de email único (case-insensitive).
- [x] Soporte de campos: `first_name`, `last_name`, `telefono`, `email`, `role`, `status`.
- [x] Mensaje de éxito requerido.
- [x] Probado en Postman.

---

## 7) Notas para Frontend
- Usar **PUT** para formularios completos.
- Manejar error 400 por `email` duplicado.
- Enviar header `Authorization: Bearer <access>`.
- Si un campo no se envía, su valor se sobrescribirá con vacío o `null`.
