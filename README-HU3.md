# 📘 README – HU-03 Restablecer Contraseña

> **Archivo sugerido:** `docs/HU-03/README.md`

## 1) Resumen
- **Historia:** HU-03 – Restablecer contraseña (password reset vía email).
- **Objetivo:** Permitir que un usuario solicite un enlace de restablecimiento y, usando `uid`+`token`, defina una nueva contraseña.
- **Módulo:** `users`
- **Criterios de aceptación (resumen):**
  - CA1: Enviar correo con enlace de restablecimiento (expira en **24 h**).
  - CA2: Limitar a **1 solicitud por hora** por email.
  - CA3: Confirmar cambio con `uid` y `token`; validar contraseñas.

---

## 2) Stack y versiones
- **Django 5.0.x**, **DRF 3.15.x**
- **Tokens:** `PasswordResetTokenGenerator` (core Django)
- **Cache (rate-limit):** backend por defecto o Redis/Memcached (recomendado en prod)
- **Email:** backend de consola en dev / SMTP en prod

---

## 3) Variables de entorno y settings
En `core/settings.py`:
```python
from datetime import timedelta
import os

PASSWORD_RESET_TIMEOUT = 60 * 60 * 24  # 24 horas

# Backend de email en desarrollo
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
DEFAULT_FROM_EMAIL = "no-reply@shift-scheduler.local"

# (Opcional) URL del front para construir el enlace del correo
PASSWORD_RESET_CONFIRM_FRONTEND_URL = os.getenv("PASSWORD_RESET_CONFIRM_FRONTEND_URL", "")
```
> En producción configura SMTP: `EMAIL_HOST`, `EMAIL_PORT`, `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD`, `EMAIL_USE_TLS/SSL`.

---

## 4) Endpoints implementados
| Método | Ruta | Descripción |
|--------|------|-------------|
| `POST` | `/api/auth/password/reset` | Solicita el envío de correo con enlace de restablecimiento |
| `POST` | `/api/auth/password/reset/confirm` | Valida `uid`+`token` y cambia la contraseña |

---

## 5) Contrato de API

### 5.1 POST `/api/auth/password/reset`
**Body (JSON)**
```json
{ "email": "ana@example.com" }
```
**200 OK (dev)**
```json
{ "message": "Correo de restablecimiento enviado.", "uid": "Mg", "token": "..." }
```
**200 OK (prod)**
```json
{ "message": "Correo de restablecimiento enviado." }
```
**Errores**
- `400` → `{"email": ["Correo no registrado."]}`
- `429` → `{"message": "Ya se solicitó un restablecimiento recientemente. Intenta más tarde."}`

### 5.2 POST `/api/auth/password/reset/confirm`
**Body (JSON)**
```json
{
  "uid": "<UID_DEL_CORREO_O_RESPUESTA_DEBUG>",
  "token": "<TOKEN_DEL_CORREO_O_RESPUESTA_DEBUG>",
  "new_password": "NuevaClave123",
  "new_password_confirm": "NuevaClave123"
}
```
**200 OK**
```json
{ "message": "Contraseña actualizada correctamente." }
```
**Errores**
- `400` → `{"uid": ["UID inválido."]}` o `{"token": ["Token inválido o expirado."]}`
- `400` → `{"new_password_confirm": "Las contraseñas no coinciden."}`
- `400` → errores de política de contraseña (validadores de Django)

---

## 6) Implementación (resumen de código)

### 6.1 Serializers (`users/serializers.py`)
```python
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.utils.encoding import force_str, smart_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework import serializers

User = get_user_model()
token_generator = PasswordResetTokenGenerator()

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        try:
            user = User.objects.get(email__iexact=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("Correo no registrado.")
        self.context["user"] = user
        return value

class PasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True)
    new_password_confirm = serializers.CharField(write_only=True)

    def validate(self, attrs):
        if attrs["new_password"] != attrs["new_password_confirm"]:
            raise serializers.ValidationError({"new_password_confirm": "Las contraseñas no coinciden."})
        validate_password(attrs["new_password"])
        return attrs

    def validate_uid(self, value):
        try:
            uid = force_str(urlsafe_base64_decode(value))
            user = User.objects.get(pk=uid)
        except Exception:
            raise serializers.ValidationError("UID inválido.")
        self.context["user"] = user
        return value

    def validate_token(self, value):
        user = self.context.get("user")
        if not user or not token_generator.check_token(user, value):
            raise serializers.ValidationError("Token inválido o expirado.")
        return value
```

### 6.2 Vistas (`users/views.py`)
```python
from django.conf import settings
from django.core.cache import cache
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import smart_bytes
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .serializers import PasswordResetRequestSerializer, PasswordResetConfirmSerializer

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
        key = f"pwdreset:{user.email.lower()}"
        if cache.get(key):
            return Response({"message": "Ya se solicitó un restablecimiento recientemente. Intenta más tarde."},
                            status=429)
        cache.set(key, True, self.RATE_LIMIT_SECONDS)

        uidb64 = urlsafe_base64_encode(smart_bytes(user.pk))
        token = token_generator.make_token(user)

        front_url = getattr(settings, "PASSWORD_RESET_CONFIRM_FRONTEND_URL", "")
        if front_url:
            link = f"{front_url}?uid={uidb64}&token={token}"
        else:
            link = request.build_absolute_uri(f"/api/auth/password/reset/confirm?uid={uidb64}&token={token}")

        subject = "Restablecer contraseña – Shift Scheduler"
        message = (f"Hola {user.first_name},\n\n"
                   f"Solicitaste restablecer tu contraseña. Enlace (24 h):\n{link}\n\n"
                   "Si no fuiste tú, ignora este mensaje.")
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=False)

        if settings.DEBUG:
            return Response({"message": "Correo de restablecimiento enviado.", "uid": uidb64, "token": token}, status=200)
        return Response({"message": "Correo de restablecimiento enviado."}, status=200)

class PasswordResetConfirmView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        ser = PasswordResetConfirmSerializer(data=request.data)
        if not ser.is_valid():
            return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)

        user = ser.context["user"]
        user.set_password(ser.validated_data["new_password"])
        user.save()
        return Response({"message": "Contraseña actualizada correctamente."}, status=200)
```

### 6.3 Rutas (`users/urls.py`)
```python
from django.urls import path
from .views import PasswordResetRequestView, PasswordResetConfirmView

urlpatterns += [
    path("password/reset", PasswordResetRequestView.as_view(), name="password-reset-request"),
    path("password/reset/confirm", PasswordResetConfirmView.as_view(), name="password-reset-confirm"),
]
```

---

## 7) Pruebas en Postman (paso a paso)

### A) Solicitud de reset
- **POST** `http://127.0.0.1:8000/api/auth/password/reset`
- **Headers:** `Content-Type: application/json`
- **Body:**
```json
{ "email": "ana@example.com" }
```
- **200 OK (dev)**: verás `{ message, uid, token }` y también el correo en la consola del servidor.

### B) Confirmación de reset
- **POST** `http://127.0.0.1:8000/api/auth/password/reset/confirm`
- **Headers:** `Content-Type: application/json`
- **Body:**
```json
{
  "uid": "<UID>",
  "token": "<TOKEN>",
  "new_password": "NuevaClave123",
  "new_password_confirm": "NuevaClave123"
}
```

> Luego prueba el login de HU-02 con la nueva contraseña.

---

## 8) Checklist (DoD)
- [x] Endpoint de solicitud con rate-limit (1/h)
- [x] Enlace con `uid`+`token` (expira 24 h)
- [x] Endpoint de confirmación con validación de token
- [x] Política de contraseñas aplicada
- [x] Probado en Postman
- [x] Compatible con HU-01/HU-02

---

## 9) Changelog
- **v1.0.0** – Implementación inicial de restablecimiento de contraseña.
