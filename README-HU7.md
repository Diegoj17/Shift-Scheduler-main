HU-07 – Bloquear Usuarios (Administrador / Gerente)
📂 Ruta sugerida: docs/HU-07/README.md

1️⃣ Resumen

Historia: HU-07 – Bloquear usuarios.

Objetivo: Permitir que un Gerente o Administrador bloquee usuarios inactivos o desvinculados para mantener la seguridad del sistema.

Acción: Cambia el status a "BLOQUEADO" y is_active=False.

2️⃣ Endpoint
Método	Ruta	Descripción
PUT	/api/auth/users/:id/block	Bloquea un usuario específico
3️⃣ Reglas de negocio

Solo ADMIN o GERENTE pueden bloquear usuarios.

Un usuario no puede bloquearse a sí mismo.

Si el usuario ya está bloqueado, se devuelve el mensaje:
"El usuario ya está bloqueado."

Se puede registrar una auditoría del bloqueo (opcional).

4️⃣ Implementación (backend)
🧩 Vista — users/views.py
from rest_framework import permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from .models import User

class AdminBlockUserView(APIView):
    """
    PUT /api/auth/users/<id>/block
    Cambia el estado del usuario a 'BLOQUEADO'.
    Solo ADMIN o GERENTE.
    """
    permission_classes = [permissions.IsAuthenticated]

    def put(self, request, pk):
        # Solo ADMIN/GERENTE pueden bloquear
        if request.user.role not in ["ADMIN", "GERENTE"]:
            return Response({"detail": "No tienes permiso para bloquear usuarios."}, status=403)

        try:
            user = User.objects.get(pk=pk)
        except User.DoesNotExist:
            return Response({"detail": "Usuario no encontrado."}, status=404)

        # No puede bloquearse a sí mismo
        if user.pk == request.user.pk:
            return Response({"detail": "No puedes bloquear tu propio usuario."}, status=400)

        # Verificar si ya está bloqueado
        if user.status == "BLOQUEADO":
            return Response({"message": "El usuario ya está bloqueado."}, status=400)

        # Bloquear usuario
        user.status = "BLOQUEADO"
        user.is_active = False
        user.save(update_fields=["status", "is_active"])

        # (Opcional) registrar auditoría
        print(f"[AUDITORÍA] {request.user.email} bloqueó al usuario {user.email}")

        return Response({"message": "Usuario bloqueado con éxito."}, status=200)

🧭 Rutas — users/urls.py
from django.urls import path
from .views import AdminBlockUserView

urlpatterns += [
    path("users/<int:pk>/block", AdminBlockUserView.as_view(), name="user-block-admin"),
]


Ruta completa: /api/auth/users/<id>/block

5️⃣ Pruebas en Postman
Escenario 1 — Bloqueo exitoso

PUT http://127.0.0.1:8000/api/auth/users/7/block
Headers:

Authorization: Bearer <ACCESS_TOKEN>
Content-Type: application/json


Respuesta 200

{ "message": "Usuario bloqueado con éxito." }

Escenario 2 — Usuario ya bloqueado

PUT al mismo usuario
400 Bad Request

{ "message": "El usuario ya está bloqueado." }

Escenario 3 — Sin permisos

403 Forbidden

{ "detail": "No tienes permiso para bloquear usuarios." }

Escenario 4 — Usuario no encontrado

404 Not Found

{ "detail": "Usuario no encontrado." }

Escenario 5 — Intento de auto-bloqueo

400 Bad Request

{ "detail": "No puedes bloquear tu propio usuario." }

6️⃣ Checklist (DoD)

 Endpoint protegido con JWT.

 Solo roles ADMIN y GERENTE.

 Cambia status a "BLOQUEADO" e is_active=False.

 Manejo de errores (400, 403, 404).

 Previene auto-bloqueo.

 Registro opcional de auditoría.