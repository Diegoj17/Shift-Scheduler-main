# users/views.py

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
from rest_framework.decorators import api_view, permission_classes
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import (
    LoginSerializer, 
    RegisterSerializer, 
    UserPublicSerializer, 
    AdminCreateUserSerializer,
    AdminUpdateUserSerializer, 
    AssignRolePermsSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer
    , PasswordChangeSerializer
)
from services.email_service import get_email_service, generate_reset_token
from django.views.decorators.csrf import ensure_csrf_cookie
from django.utils.decorators import method_decorator
from django.http import JsonResponse
from django.utils import timezone
from .models import PasswordResetToken


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
        
        response = Response({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "user": UserPublicSerializer(user).data
        }, status=status.HTTP_200_OK)
        
        # Asegurar headers CORS en la respuesta
        response["Access-Control-Allow-Origin"] = request.headers.get('Origin', '*')
        response["Access-Control-Allow-Credentials"] = "true"
        
        return response


class MeView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        return Response({"user": UserPublicSerializer(request.user).data})


token_generator = PasswordResetTokenGenerator()

class PasswordResetView(APIView):
    """
    Vista para solicitar restablecimiento de contraseña.
    ✅ CORREGIDO: Ahora devuelve 404 si el correo NO existe
    """
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        email = request.data.get('email')
        
        if not email:
            response = Response(
                {"message": "El correo electrónico es requerido"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
            response["Access-Control-Allow-Origin"] = request.headers.get('Origin', '*')
            return response

        # ✅ BUSCAR USUARIO - Si no existe, devolver ERROR 404
        try:
            user = User.objects.get(email__iexact=email)
            logging.getLogger('users').info(f"✅ Password reset requested for: {email}")
        except User.DoesNotExist:
            # ❌ CORREO NO EXISTE - Devolver ERROR 404
            logging.getLogger('users').info(f"❌ Password reset requested for non-existing email: {email}")
            response = Response(
                {"message": "No existe usuario con ese correo"}, 
                status=status.HTTP_404_NOT_FOUND
            )
            response["Access-Control-Allow-Origin"] = request.headers.get('Origin', '*')
            return response

        # ✅ CORREO EXISTE - Generar token y enviar email
        def _send_reset(to_email, user_name, reset_token, uid=None):
            try:
                email_service = get_email_service()
                success = email_service.send_password_reset_email(
                    to_email=to_email,
                    reset_token=reset_token,
                    user_name=user_name,
                    uid=uid
                )
                if not success:
                    logging.getLogger('users').warning(f"Failed to send password reset email to {to_email}")
            except Exception as e:
                logging.getLogger('users').exception(f"Exception while sending password reset email to {to_email}: {e}")

        try:
            # Prefer DB-backed token (persistent, revocable). Create and store it
            try:
                timeout = getattr(settings, 'PASSWORD_RESET_TIMEOUT', 3600)
                prt = PasswordResetToken.create_token_for_user(user, ttl_seconds=timeout)
                reset_token = prt.token
                logging.getLogger('users').debug(f"Created DB password reset token for user {user.pk}")
            except Exception:
                # Fallback to cache-based token generation when DB fails
                reset_token = generate_reset_token()
                try:
                    timeout = getattr(settings, 'PASSWORD_RESET_TIMEOUT', 3600)
                    cache_key = f"password_reset:{reset_token}"
                    cache.set(cache_key, str(user.pk), timeout)
                    logging.getLogger('users').debug(f"Stored password reset token in cache for user {user.pk}")
                except Exception as e:
                    logging.getLogger('users').exception(f"Could not store reset token in cache: {e}")
            
            # Encode uidb64 for frontend consumption (preferred)
            try:
                uidb64 = urlsafe_base64_encode(smart_bytes(user.pk))
            except Exception:
                uidb64 = None

            # Dispatch async email sender
            threading.Thread(
                target=_send_reset, 
                args=(user.email, user.first_name or user.email, reset_token, uidb64), 
                daemon=True
            ).start()
            
        except Exception as e:
            # Catch unexpected errors during token generation
            logging.getLogger('users').exception(f"Unexpected error during password reset for {email}: {e}")
            response = Response(
                {"message": "Error al procesar la solicitud"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            response["Access-Control-Allow-Origin"] = request.headers.get('Origin', '*')
            return response

        # ✅ ÉXITO - Correo existe y se está enviando el email
        response = Response(
            {"message": "Se ha enviado un enlace de recuperación a tu correo electrónico"}, 
            status=status.HTTP_200_OK
        )
        response["Access-Control-Allow-Origin"] = request.headers.get('Origin', '*')
        return response

# Compatibilidad hacia atrás: algunas partes del código (urls.py) importaban
# `PasswordResetRequestView`. Mantener el nombre antiguo como alias para evitar
# ImportError durante despliegues que esperan la vista con ese identificador.
PasswordResetRequestView = PasswordResetView


class PasswordResetConfirmView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        import logging
        logger = logging.getLogger('users')
        
        logger.info(f"🔄 Password reset confirm - Data recibida: {request.data}")
        
        data = request.data.copy()
        
        # Obtener uid y token de query params si no están en body
        if 'uid' not in data and 'uid' in request.query_params:
            data['uid'] = request.query_params.get('uid')
        if 'token' not in data and 'token' in request.query_params:
            data['token'] = request.query_params.get('token')
        
        logger.info(f"📝 UID: {data.get('uid')}, Token: {data.get('token')[:10]}..." if data.get('token') else "No token")

        # Soporte para flujo simplificado: si solo hay token, buscar uid en cache
        token = data.get('token')
        if token and not data.get('uid'):
            try:
                cache_key = f"password_reset:{token}"
                user_pk = cache.get(cache_key)
                if user_pk:
                    data['uid'] = urlsafe_base64_encode(smart_bytes(user_pk))
                    logger.info(f"✅ UID recuperado de cache: {user_pk}")
                else:
                    logger.warning(f"⚠️ Token no encontrado en cache: {token}")
            except Exception as e:
                logger.exception(f"Error recuperando UID de cache: {e}")

        # Validar con serializer
        ser = PasswordResetConfirmSerializer(data=data)
        if not ser.is_valid():
            logger.error(f"❌ Errores de validación: {ser.errors}")
            return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)

        user = ser.context["user"]
        new_pw = ser.validated_data["new_password"]
        
        logger.info(f"✅ Actualizando contraseña para user {user.pk} ({user.email})")
        
        user.set_password(new_pw)
        user.save()

        # Limpiar tokens
        try:
            token = data.get('token')
            if token:
                # Cache
                try:
                    cache_key = f"password_reset:{token}"
                    cache.delete(cache_key)
                    logger.info(f"🗑️ Token eliminado de cache")
                except Exception:
                    pass

                # DB
                try:
                    prt = PasswordResetToken.objects.filter(token=token, used=False).first()
                    if prt:
                        prt.mark_used()
                        logger.info(f"✅ Token DB marcado como usado")
                except Exception as e:
                    logger.exception(f"Error marcando token DB como usado: {e}")
        except Exception as e:
            logger.exception(f"Error limpiando tokens: {e}")

        # Envío ASÍNCRONO de confirmación
        def _send_confirmation_email():
            try:
                email_service = get_email_service()
                success = email_service.send_password_updated_email(
                    to_email=user.email,
                    user_name=user.first_name or user.email.split('@')[0]
                )
                if success:
                    logger.info(f"✅ Email de confirmación enviado a {user.email}")
                else:
                    logger.warning(f"❌ Error enviando email de confirmación a {user.email}")
            except Exception as e:
                logger.exception(f"Error en envío asíncrono de confirmación: {e}")

        threading.Thread(target=_send_confirmation_email, daemon=True).start()

        response = Response({"message": "Contraseña actualizada correctamente."}, status=200)
        response["Access-Control-Allow-Origin"] = request.headers.get('Origin', '*')
        return response


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

        response = Response({"message": "Usuario bloqueado con éxito."}, status=200)
        response["Access-Control-Allow-Origin"] = request.headers.get('Origin', '*')
        return response


class PasswordChangeView(APIView):
    """Endpoint para que el usuario autenticado cambie su propia contraseña.

    Método: POST
    Body: { "old_password": "..", "new_password": "..", "new_password_confirm": ".." }
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = PasswordChangeSerializer(data=request.data, context={"request": request})
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = request.user
        new_pw = serializer.validated_data['new_password']
        user.set_password(new_pw)
        user.save()

        # Enviar cabeceras CORS para compatibilidad con frontend
        resp = Response({"message": "Contraseña actualizada correctamente."}, status=200)
        resp["Access-Control-Allow-Origin"] = request.headers.get('Origin', '*')
        resp["Access-Control-Allow-Credentials"] = "true"
        return resp


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
        
        response = Response({
            "id": user.id,
            "email": user.email,
            "role": user.role,
            "permissions": user.permissions or []
        }, status=200)
        response["Access-Control-Allow-Origin"] = request.headers.get('Origin', '*')
        return response

    def put(self, request, pk):
        if request.user.role not in ["ADMIN", "GERENTE"]:
            return Response({"detail": "No tienes permiso para asignar roles/permisos."}, status=403)
        user = self.get_object(pk)
        if not user or getattr(user, 'role', None) == "GERENTE":
            return Response({"detail": "Usuario no encontrado."}, status=404)

        ser = AssignRolePermsSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        ser.update(user, ser.validated_data)

        response = Response({
            "message": "Acceso actualizado con éxito.",
            "user": {
                "id": user.id,
                "email": user.email,
                "role": user.role,
                "permissions": user.permissions or []
            }
        }, status=200)
        response["Access-Control-Allow-Origin"] = request.headers.get('Origin', '*')
        return response


# ✅ NUEVO: Endpoint para obtener todos los usuarios para turnos
@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_all_users_for_shifts(request):
    """
    Endpoint para obtener TODOS los usuarios activos del sistema.
    Muestra si tienen o no perfil de Employee.
    
    GET /api/auth/users/for-shifts/
    
    Retorna:
    [
        {
            "user_id": 6,
            "employee_id": 1,  // o null si no tiene
            "has_employee": true,  // o false
            "name": "Diego Jaimes",
            "position": "Supervisor de Turnos",
            "departamento": "Operaciones",
            "email": "diego@example.com",
            "role": "EMPLEADO"
        },
        ...
    ]
    """
    try:
        from shifts.models import Employee
        
        # Obtener todos los usuarios activos
        users = User.objects.filter(status='ACTIVE').order_by('first_name', 'last_name')
        
        data = []
        for user in users:
            # Construir nombre completo
            full_name = f"{user.first_name} {user.last_name}".strip()
            if not full_name:
                full_name = user.email
            
            # Construir posición
            position = getattr(user, 'puesto', None) or 'Sin puesto'
            departamento = getattr(user, 'departamento', None) or 'Sin departamento'
            
            # ✅ Verificar si tiene Employee (sin crearlo)
            try:
                employee = Employee.objects.get(user=user)
                employee_id = employee.id
                has_employee = True
            except Employee.DoesNotExist:
                employee_id = None
                has_employee = False
            
            user_data = {
                'user_id': user.id,                     # ✅ USER_ID (para enviar al backend)
                'employee_id': employee_id,             # ✅ EMPLOYEE_ID (si existe)
                'has_employee': has_employee,           # ℹ️ Flag informativo
                'name': full_name,
                'position': position,
                'departamento': departamento,
                'email': user.email,
                'role': user.role
            }
            
            data.append(user_data)
        
        return Response(data, status=200)
        
    except Exception as exc:
        import logging
        import traceback
        logging.getLogger('users').exception("Error obteniendo usuarios para turnos")
        return Response({
            'error': str(exc),
            'traceback': traceback.format_exc()
        }, status=500)


# Vista CSRF mejorada
@ensure_csrf_cookie
def csrf(request):
    response = JsonResponse({"detail": "CSRF cookie set"})
    # Headers CORS explícitos
    response["Access-Control-Allow-Origin"] = request.headers.get('Origin', 'http://localhost:4000')
    response["Access-Control-Allow-Credentials"] = "true"
    response["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-CSRFToken"
    response["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


# Vista adicional para manejar preflight OPTIONS requests
def cors_preflight(request):
    """
    Maneja requests OPTIONS para CORS preflight
    """
    response = JsonResponse({"detail": "Preflight OK"})
    response["Access-Control-Allow-Origin"] = request.headers.get('Origin', 'http://localhost:4000')
    response["Access-Control-Allow-Credentials"] = "true"
    response["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-CSRFToken"
    response["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
    return response