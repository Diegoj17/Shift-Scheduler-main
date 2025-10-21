from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import RegisterView, LoginView, MeView, PasswordResetRequestView, PasswordResetConfirmView, AdminCreateUserView,AdminUserDetailView,AdminBlockUserView,AdminUserAccessView

urlpatterns = [
    path("register", RegisterView.as_view(), name="auth-register"),
    path("login", LoginView.as_view(), name="auth-login"),
    path("token/refresh", TokenRefreshView.as_view(), name="token-refresh"),
    path("me", MeView.as_view(), name="auth-me"),
    path("password/reset", PasswordResetRequestView.as_view(), name="password-reset-request"),
    path("password/reset/confirm", PasswordResetConfirmView.as_view(), name="password-reset-confirm"),
    path("users/create", AdminCreateUserView.as_view(), name="user-create-admin"),
    path("users/<int:pk>", AdminUserDetailView.as_view(), name="user-detail-admin"),
    path("users/<int:pk>/block", AdminBlockUserView.as_view(), name="user-block-admin"),
    path("users/<int:pk>/access", AdminUserAccessView.as_view(), name="user-access-admin"),
]
