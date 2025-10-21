🛡️ HU-08 — Asignación de Roles y Permisos (Backend)
🎯 Objetivo

Como ADMIN/GERENTE, poder asignar a un usuario:

un rol (ADMIN, GERENTE, EMPLEADO)

un conjunto de permisos permitidos: ver, crear, editar, eliminar, aprobar

0️⃣ Pre-requisitos

Autenticación JWT (HU-02) funcionando.

Modelo User con los campos: email, role, status, telefono.

1️⃣ Modelo User

Archivo: users/models.py

from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    username = None
    email = models.EmailField(unique=True)

    telefono = models.CharField(max_length=15, blank=True)
    role = models.CharField(max_length=20, default="EMPLEADO")
    status = models.CharField(max_length=20, default="ACTIVE")

    # Nuevo campo de permisos
    permissions = models.JSONField(default=list, blank=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []


Comandos:

python manage.py makemigrations
python manage.py migrate

2️⃣ Serializer

Archivo: users/serializers.py

from rest_framework import serializers
from django.contrib.auth import get_user_model

User = get_user_model()

ALLOWED_ROLES = {"ADMIN", "GERENTE", "EMPLEADO"}
ALLOWED_PERMS = {"ver", "crear", "editar", "eliminar", "aprobar"}

class AssignRolePermsSerializer(serializers.Serializer):
    role = serializers.CharField(required=True)
    permissions = serializers.ListField(
        child=serializers.CharField(), allow_empty=True, required=True
    )

    def validate_role(self, value):
        if value not in ALLOWED_ROLES:
            raise serializers.ValidationError("Rol inválido. Use: ADMIN, GERENTE, EMPLEADO.")
        return value

    def validate_permissions(self, perms):
        invalid = [p for p in perms if p not in ALLOWED_PERMS]
        if invalid:
            raise serializers.ValidationError([f"Permiso no permitido: {p}" for p in invalid])
        seen = set()
        cleaned = []
        for p in perms:
            if p not in seen:
                seen.add(p)
                cleaned.append(p)
        return cleaned

    def update(self, instance, validated_data):
        instance.role = validated_data["role"]
        instance.permissions = validated_data["permissions"]
        instance.save(update_fields=["role", "permissions"])
        return instance

3️⃣ Vista

Archivo: users/views.py

from rest_framework import permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from .serializers import AssignRolePermsSerializer

User = get_user_model()

class AdminUserAccessView(APIView):
    """
    GET /api/auth/users/<id>/access
    PUT /api/auth/users/<id>/access
    Solo ADMIN o GERENTE.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self, pk):
        try:
            return User.objects.get(pk=pk)
        except User.DoesNotExist:
            return None

    def get(self, request, pk):
        if request.user.role not in ["ADMIN", "GERENTE"]:
            return Response({"detail": "No tienes permiso para ver acceso."}, status=403)
        user = self.get_object(pk)
        if not user:
            return Response({"detail": "Usuario no encontrado."}, status=404)
        return Response({
            "id": user.id,
            "email": user.email,
            "role": user.role,
            "permissions": user.permissions or []
        }, status=200)

    def put(self, request, pk):
        if request.user.role not in ["ADMIN", "GERENTE"]:
            return Response({"detail": "No tienes permiso para asignar roles/permisos."}, status=403)
        user = self.get_object(pk)
        if not user:
            return Response({"detail": "Usuario no encontrado."}, status=404)

        ser = AssignRolePermsSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        ser.update(user, ser.validated_data)

        return Response({
            "message": "Acceso actualizado con éxito.",
            "user": {
                "id": user.id,
                "email": user.email,
                "role": user.role,
                "permissions": user.permissions or []
            }
        }, status=200)

4️⃣ Rutas

Archivo: users/urls.py

from django.urls import path
from .views import AdminUserAccessView

urlpatterns += [
    path("users/<int:pk>/access", AdminUserAccessView.as_view(), name="user-access-admin"),
]


Ruta completa: /api/auth/users/<id>/access

5️⃣ Pruebas en Postman
✅ Escenario 1 — Asignación válida

PUT http://127.0.0.1:8000/api/auth/users/7/access

{
  "role": "GERENTE",
  "permissions": ["ver", "crear", "editar"]
}


200 OK

{
  "message": "Acceso actualizado con éxito.",
  "user": {
    "id": 7,
    "email": "empleado@example.com",
    "role": "GERENTE",
    "permissions": ["ver", "crear", "editar"]
  }
}

🚫 Escenario 2 — Permiso no permitido

PUT

{
  "role": "EMPLEADO",
  "permissions": ["ver", "publicar"]
}


400 Bad Request

{ "permissions": ["Permiso no permitido: publicar"] }

6️⃣ Checklist (DoD)

 GET/PUT /api/auth/users/<id>/access funcional

 Solo roles ADMIN y GERENTE autorizados

 Validación de roles y permisos

 Mensajes claros y manejo de errores

 Probado en Postman

7️⃣ Notas para Frontend

Usar <select> para role y checkboxes para permissions.

Enviar JSON { "role": "...", "permissions": [...] }.

Mostrar los mensajes del backend (toast o alert).

Refrescar tabla de usuarios tras guardar.