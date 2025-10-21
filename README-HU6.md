# 🗑️ README – HU-06 Eliminar Usuarios (Administrador / Gerente)

> **Ubicación sugerida:** `docs/HU-06/README.md`

## 1) Resumen
- **Historia:** HU-06 – Eliminar usuarios.
- **Objetivo:** Permitir que un **gerente/administrador** elimine un usuario existente del sistema.
- **Alcance:** Eliminación directa (hard-delete). *Opcional:* puedes convertirlo en soft-delete cambiando `status` a `INACTIVE`.

---

## 2) Endpoint
| Método | Ruta | Descripción |
|---|---|---|
| `DELETE` | `/api/auth/users/:id` | Elimina un usuario por ID (solo ADMIN/GERENTE) |

---

## 3) Reglas de negocio
- Solo pueden eliminar **ADMIN** o **GERENTE**.
- No permitir que un usuario se elimine a sí mismo (seguridad).
- Responder con mensaje claro de éxito: **"Usuario eliminado con éxito."**
- Si el usuario no existe → 404.
- Si no tiene permisos → 403.

---

## 4) Implementación (backend)

### 4.1 Vista – `users/views.py`
```python
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from .models import User

class AdminDeleteUserView(generics.DestroyAPIView):
    queryset = User.objects.all()
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "pk"

    def delete(self, request, *args, **kwargs):
        # Solo ADMIN/GERENTE
        if request.user.role not in ["ADMIN", "GERENTE"]:
            return Response({"detail": "No tienes permiso para eliminar usuarios."}, status=403)

        instance = self.get_object()

        # Seguridad: no eliminarse a sí mismo
        if instance.pk == request.user.pk:
            return Response({"detail": "No puedes eliminar tu propio usuario."}, status=400)

        self.perform_destroy(instance)
        return Response({"message": "Usuario eliminado con éxito."}, status=200)
```

> **Soft-delete (opcional):** en lugar de `self.perform_destroy(instance)`, podrías hacer:
> ```python
> instance.status = "INACTIVE"
> instance.is_active = False
> instance.save(update_fields=["status", "is_active"])
> return Response({"message":"Usuario desactivado con éxito."}, status=200)
> ```

### 4.2 Rutas – `users/urls.py`
```python
from django.urls import path
from .views import AdminDeleteUserView

urlpatterns += [
    path("users/<int:pk>", AdminDeleteUserView.as_view(), name="user-delete-admin"),
]
```
> Si `users.urls` está incluido bajo `api/auth/`, la ruta completa es `/api/auth/users/<id>`.

---

## 5) Pruebas en Postman

### Escenario 1 – Eliminación exitosa
- **DELETE** `http://127.0.0.1:8000/api/auth/users/7`
- **Headers:** `Authorization: Bearer <access>`
- **Respuesta 200**
```json
{ "message": "Usuario eliminado con éxito." }
```

### Escenario 2 – Intentar eliminarse a sí mismo
- **DELETE** a `/api/auth/users/<tu_id>`
- **Respuesta 400**
```json
{ "detail": "No puedes eliminar tu propio usuario." }
```

### Escenario 3 – Sin permisos
- Rol `EMPLEADO` intentando eliminar
- **Respuesta 403**
```json
{ "detail": "No tienes permiso para eliminar usuarios." }
```

### Escenario 4 – Usuario no existe
- **DELETE** a un ID que no existe
- **Respuesta 404**
```json
{ "detail": "No encontrado." }
```

---

## 6) Checklist (DoD)
- [x] Endpoint `DELETE /api/auth/users/<id>` protegido por JWT.
- [x] Autorización por rol (ADMIN/GERENTE).
- [x] Mensaje de éxito estándar.
- [x] Bloqueo de auto-eliminación.
- [x] Pruebas en Postman (éxito, sin permisos, 404).
- [x] Ruta documentada y estable.

---

## 7) Notas para Frontend
- Confirmar con modal antes de eliminar.
- Manejar errores 400/403/404 con toasts o banners.
- Tras eliminar, refrescar el listado de usuarios.
- Si implementas soft-delete, cambia el copy de UI a “Desactivar usuario”.

