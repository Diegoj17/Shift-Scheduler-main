import time
from .models import User
from django.conf import settings
from django.core.cache import cache
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import smart_bytes
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework import status, permissions, generics
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import LoginSerializer, RegisterSerializer, UserPublicSerializer, AdminCreateUserSerializer,AdminUpdateUserSerializer, AssignRolePermsSerializer

class RegisterView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        ser = RegisterSerializer(data=request.data)
        if ser.is_valid():
            user = ser.save()
            return Response(
                {"message": "Usuario registrado", "user": UserPublicSerializer(user).data},
                status=status.HTTP_201_CREATED,
            )
        return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)
    
class LoginView(APIView):
    authentication_classes = []     # público
    permission_classes = []         # público

    def post(self, request):
        ser = LoginSerializer(data=request.data, context={"request": request})
        if not ser.is_valid():
            # unificamos formato de error
            detail = ser.errors.get("detail", ["Datos inválidos"])[0]
            code = status.HTTP_401_UNAUTHORIZED if "credenciales" in detail.lower() else status.HTTP_403_FORBIDDEN
            return Response({"message": detail}, status=code)

        user = ser.validated_data["user"]
        refresh = RefreshToken.for_user(user)
        return Response({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "user": UserPublicSerializer(user).data
        }, status=status.HTTP_200_OK)


class MeView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        return Response({"user": UserPublicSerializer(request.user).data})
    
from .serializers import (
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    UserPublicSerializer,
)

token_generator = PasswordResetTokenGenerator()

class PasswordResetRequestView(APIView):
    authentication_classes = []
    permission_classes = []

    RATE_LIMIT_SECONDS = 3600  # 1 por hora

    def post(self, request):
        ser = PasswordResetRequestSerializer(data=request.data)
        if not ser.is_valid():
            return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)

        user = ser.context["user"]
        # rate limit por email
        key = f"pwdreset:{user.email.lower()}"
        if cache.get(key):
            # 429 Too Many Requests
            return Response({"message": "Ya se solicitó un restablecimiento recientemente. Intenta más tarde."},
                            status=429)
        cache.set(key, True, self.RATE_LIMIT_SECONDS)

        uidb64 = urlsafe_base64_encode(smart_bytes(user.pk))
        token = token_generator.make_token(user)

        # arma enlace para el front si existe, si no, backend
        front_url = getattr(settings, "PASSWORD_RESET_CONFIRM_FRONTEND_URL", "")
        if front_url:
            link = f"{front_url}?uid={uidb64}&token={token}"
        else:
            link = request.build_absolute_uri(f"/api/auth/password/reset/confirm?uid={uidb64}&token={token}")

        subject = "Restablecer contraseña – Shift Scheduler"
        message = (
            f"Hola {user.first_name},\n\n"
            f"Solicitaste restablecer tu contraseña. Haz clic en el enlace (expira en 24 horas):\n\n{link}\n\n"
            "Si no fuiste tú, ignora este mensaje."
        )
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=False)

        # En desarrollo puedes (opcional) devolver los datos para facilitar test QA:
        if settings.DEBUG:
            return Response({"message": "Correo de restablecimiento enviado.", "uid": uidb64, "token": token},
                            status=200)
        return Response({"message": "Correo de restablecimiento enviado."}, status=200)


class PasswordResetConfirmView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        ser = PasswordResetConfirmSerializer(data=request.data)
        if not ser.is_valid():
            return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)

        user = ser.context["user"]
        new_pw = ser.validated_data["new_password"]
        user.set_password(new_pw)
        user.save()
        return Response({"message": "Contraseña actualizada correctamente."}, status=200)

class AdminCreateUserView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = AdminCreateUserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        # Solo roles con permiso
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

class AdminUpdateUserView(generics.UpdateAPIView):
    """
    PATCH /api/auth/users/<id>   -> actualización parcial
    PUT   /api/auth/users/<id>   -> actualización total
    Solo roles ADMIN o GERENTE.
    """
    queryset = User.objects.all()
    serializer_class = AdminUpdateUserSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "pk"

    def update(self, request, *args, **kwargs):
        # ✅ Autorización por rol
        if request.user.role not in ["ADMIN", "GERENTE"]:
            return Response({"detail": "No tienes permiso para editar usuarios."}, status=403)

        partial = request.method.lower() == "patch"
        instance = self.get_object()

        serializer = self.get_serializer(instance, data=request.data, partial=partial)
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
    
class AdminUserDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    GET    /api/auth/users/<id>   -> ver detalle (si lo quieres)
    PUT    /api/auth/users/<id>   -> actualizar completo
    PATCH  /api/auth/users/<id>   -> actualizar parcial
    DELETE /api/auth/users/<id>   -> eliminar
    Solo roles ADMIN o GERENTE.
    """
    queryset = User.objects.all()
    serializer_class = AdminUpdateUserSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "pk"

    def _check_role(self, request):
        return request.user.role in ["ADMIN", "GERENTE"]

    # PUT/PATCH
    def update(self, request, *args, **kwargs):
        if not self._check_role(request):
            return Response({"detail": "No tienes permiso para editar usuarios."}, status=403)

        partial = request.method.lower() == "patch"
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        user = serializer.instance
        return Response({
            "message": "Usuario actualizado con éxito.",
            "user": {
                "id": user.id,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "telefono": user.telefono,
                "email": user.email,
                "role": user.role,
                "status": user.status,
            }
        }, status=200)

    # DELETE
    def destroy(self, request, *args, **kwargs):
        if not self._check_role(request):
            return Response({"detail": "No tienes permiso para eliminar usuarios."}, status=403)

        instance = self.get_object()
        if instance.pk == request.user.pk:
            return Response({"detail": "No puedes eliminar tu propio usuario."}, status=400)

        self.perform_destroy(instance)
        return Response({"message": "Usuario eliminado con éxito."}, status=200)

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


User = get_user_model()

class AdminUserAccessView(APIView):
    """
    GET /api/auth/users/<id>/access  -> Obtiene rol + permisos
    PUT /api/auth/users/<id>/access  -> Asigna rol + permisos
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