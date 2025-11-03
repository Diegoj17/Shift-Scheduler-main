from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    RegisterView, 
    LoginView, 
    MeView, 
    PasswordResetRequestView, 
    PasswordResetConfirmView, 
    AdminCreateUserView,
    AdminUserDetailView,
    AdminUpdateUserView,
    AdminBlockUserView,
    AdminUserAccessView,
    AdminListNonGerenteUsersView,
    csrf,
    cors_preflight
)

# Vistas que manejan OPTIONS explícitamente
class CORSLoginView(LoginView):
    def options(self, request, *args, **kwargs):
        response = Response({"detail": "OK"})
        response["Access-Control-Allow-Origin"] = request.headers.get('Origin', '*')
        response["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        response["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-CSRFToken"
        response["Access-Control-Allow-Credentials"] = "true"
        return response

class CORSRegisterView(RegisterView):
    def options(self, request, *args, **kwargs):
        response = Response({"detail": "OK"})
        response["Access-Control-Allow-Origin"] = request.headers.get('Origin', '*')
        response["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        response["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-CSRFToken"
        response["Access-Control-Allow-Credentials"] = "true"
        return response

urlpatterns = [
    # Autenticación básica con soporte CORS
    path("register/", CORSRegisterView.as_view(), name="auth-register"),
    path("login/", CORSLoginView.as_view(), name="auth-login"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token-refresh"),
    path("me/", MeView.as_view(), name="auth-me"),
    
    # Recuperación de contraseña
    path("password/reset/", PasswordResetRequestView.as_view(), name="password-reset-request"),
    path("password/reset/confirm/", PasswordResetConfirmView.as_view(), name="password-reset-confirm"),
    
    # Administración de usuarios
    path("users/create/", AdminCreateUserView.as_view(), name="user-create-admin"),
    path("users/", AdminListNonGerenteUsersView.as_view(), name="user-list-admin"),
    path("users/<int:pk>/", AdminUserDetailView.as_view(), name="user-detail-admin"),
    path("users/<int:pk>/update/", AdminUpdateUserView.as_view(), name="user-update-admin"),
    path("users/<int:pk>/block/", AdminBlockUserView.as_view(), name="user-block-admin"),
    path("users/<int:pk>/access/", AdminUserAccessView.as_view(), name="user-access-admin"),
    
    # CSRF y CORS
    path("csrf/", csrf, name="csrf-cookie"),
    path("cors-preflight/", cors_preflight, name="cors-preflight"),
]