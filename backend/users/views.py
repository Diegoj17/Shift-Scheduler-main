import time
import threading
import logging
from .models import User
from django.conf import settings
from django.core.cache import cache
from django.core.mail import send_mail, EmailMultiAlternatives
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import smart_bytes
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework import status, permissions, generics, serializers
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import LoginSerializer, RegisterSerializer, UserPublicSerializer, AdminCreateUserSerializer,AdminUpdateUserSerializer, AssignRolePermsSerializer
from . import serializers as user_serializers
from services.email_service import get_email_service, generate_reset_token
from django.views.decorators.csrf import ensure_csrf_cookie
from django.http import JsonResponse


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

class PasswordResetView(APIView):
    def post(self, request):
        email = request.data.get('email')
        # Always return a generic success message for security (do not disclose if email exists).
        # Perform the email send asynchronously to avoid blocking the request and risking
        # a gateway/proxy timeout (which can produce a 502 and no CORS headers).
        def _send_reset(to_email, user_name, reset_token):
            try:
                email_service = get_email_service()
                success = email_service.send_password_reset_email(
                    to_email=to_email,
                    reset_token=reset_token,
                    user_name=user_name
                )
                if not success:
                    logging.getLogger('users').warning(f"Failed to send password reset email to {to_email}")
            except Exception as e:
                logging.getLogger('users').exception(f"Exception while sending password reset email to {to_email}: {e}")

        try:
            user = User.objects.get(email=email)
            reset_token = generate_reset_token()
            # Guardar token en cache con TTL para validación posterior
            try:
                timeout = getattr(settings, 'PASSWORD_RESET_TIMEOUT', 3600)
                cache_key = f"password_reset:{reset_token}"
                cache.set(cache_key, str(user.pk), timeout)
                logging.getLogger('users').debug(f"Stored password reset token in cache for user {user.pk}")
            except Exception as e:
                logging.getLogger('users').exception(f"Could not store reset token in cache: {e}")
            # Dispatch async email sender
            threading.Thread(target=_send_reset, args=(user.email, user.first_name or user.email, reset_token), daemon=True).start()
        except User.DoesNotExist:
            # Intentionally ignore: we still return the same response below.
            logging.getLogger('users').info(f"Password reset requested for non-existing email: {email}")
        except Exception as e:
            # Catch unexpected errors during lookup/generation and log them; still return generic response.
            logging.getLogger('users').exception(f"Unexpected error during password reset request for {email}: {e}")

        return Response({"message": "Si el email existe, recibirás instrucciones"}, status=200)


class PasswordResetConfirmView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        data = request.data.copy()
        if 'uid' not in data and 'uid' in request.query_params:
            data['uid'] = request.query_params.get('uid')
        if 'token' not in data and 'token' in request.query_params:
            data['token'] = request.query_params.get('token')

        # Soporte para flujo simplificado: si el cliente envía solo 'token' (sin uid),
        # buscamos en cache el user id asociado y rellenamos uid para que el serializer
        # existente (que valida uid via urlsafe_base64_decode) funcione.
        token = data.get('token')
        if token and not data.get('uid'):
            try:
                cache_key = f"password_reset:{token}"
                user_pk = cache.get(cache_key)
                if user_pk:
                    # encodear el pk como uidb64 esperado por el serializer
                    data['uid'] = urlsafe_base64_encode(smart_bytes(user_pk))
                else:
                    logging.getLogger('users').warning(f"Password reset token not found in cache: {token}")
            except Exception as e:
                logging.getLogger('users').exception(f"Error checking password reset token in cache: {e}")

        ser = PasswordResetConfirmSerializer(data=data)
        if not ser.is_valid():
            return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)

        user = ser.context["user"]
        new_pw = ser.validated_data["new_password"]
        user.set_password(new_pw)
        user.save()

        # Si vino por nuestro token cacheado, eliminarlo para que no pueda reutilizarse
        try:
            token = data.get('token')
            if token:
                cache_key = f"password_reset:{token}"
                cache.delete(cache_key)
                logging.getLogger('users').debug(f"Deleted password reset token from cache: {token}")
        except Exception:
            pass

        # Envío ASÍNCRONO de confirmación
        def _send_confirmation_email():
            try:
                email_service = get_email_service()
                success = email_service.send_password_updated_email(
                    to_email=user.email,
                    user_name=user.first_name or user.email.split('@')[0]
                )
                if success:
                    print(f"✅ Email de confirmación enviado a {user.email}")
                else:
                    print(f"❌ Error enviando email de confirmación a {user.email}")
            except Exception as e:
                print(f"❌ Error en envío asíncrono de confirmación: {e}")

        threading.Thread(target=_send_confirmation_email, daemon=True).start()

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
                    "status": user.status,
                    "departamento": user.departamento,
                    "puesto": user.puesto,
                }
            },
            status=status.HTTP_201_CREATED
        )

class AdminListNonGerenteUsersView(generics.ListAPIView):
    """
    GET /api/auth/users/ -> Lista todos los usuarios excepto los que tienen role='GERENTE'.
    Solo accesible para usuarios autenticados con rol ADMIN o GERENTE.
    """
    serializer_class = UserPublicSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        # autorización por rol
        if self.request.user.role not in ["ADMIN", "GERENTE"]:
            return User.objects.none()
        # Excluir al propio usuario que hace la petición
        qs = User.objects.exclude(role="GERENTE")
        try:
            qs = qs.exclude(pk=self.request.user.pk)
        except Exception:
            pass
        return qs.order_by("id")

class AdminUpdateUserView(generics.UpdateAPIView):
    """
    PATCH /api/auth/users/<id>/update/   -> actualización parcial
    PUT   /api/auth/users/<id>/update/   -> actualización total
    Solo roles ADMIN o GERENTE.
    """
    queryset = User.objects.all()
    serializer_class = AdminUpdateUserSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "pk"

    def update(self, request, *args, **kwargs):
        # ✅ Autorización por rol
        if request.user.role not in ["ADMIN", "GERENTE"]:
            return Response(
                {"detail": "No tienes permiso para editar usuarios."}, 
                status=status.HTTP_403_FORBIDDEN
            )

        # ✅ No permitir que un usuario se edite a sí mismo (opcional)
        instance = self.get_object()
        if getattr(instance, 'role', None) == "GERENTE":
            return Response({"detail": "Usuario no encontrado."}, status=404)
        # No permitir operar sobre usuarios GERENTE a través de este endpoint
        if getattr(instance, 'role', None) == "GERENTE":
            return Response({"detail": "Usuario no encontrado."}, status=404)
        if instance.id == request.user.id:
            return Response(
                {"detail": "No puedes editar tu propio usuario desde aquí."}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        partial = request.method.lower() == "patch"
        
        try:
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
                        "departamento": getattr(user, 'departamento', None),
                        "puesto": getattr(user, 'puesto', None),
                    },
                },
                status=status.HTTP_200_OK,
            )
        except serializers.ValidationError as e:
            return Response(
                {"detail": "Error de validación", "errors": e.detail},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {"detail": f"Error al actualizar usuario: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
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
                "departamento": getattr(user, 'departamento', None),
                "puesto": getattr(user, 'puesto', None),
            }
        }, status=200)

    # DELETE
    def destroy(self, request, *args, **kwargs):
        if not self._check_role(request):
            return Response({"detail": "No tienes permiso para eliminar usuarios."}, status=403)

        instance = self.get_object()
        if getattr(instance, 'role', None) == "GERENTE":
            return Response({"detail": "Usuario no encontrado."}, status=404)
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
            if getattr(user, 'role', None) == "GERENTE":
                return Response({"detail": "Usuario no encontrado."}, status=404)
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
        if not user or getattr(user, 'role', None) == "GERENTE":
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
        if not user or getattr(user, 'role', None) == "GERENTE":
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

@ensure_csrf_cookie
def csrf(request):
    return JsonResponse({"detail": "CSRF cookie set"})