from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import RegisterView, LoginView, MeView, PasswordResetRequestView, PasswordResetConfirmView, AdminCreateUserView,AdminUserDetailView,AdminUpdateUserView,AdminBlockUserView,AdminUserAccessView
from .views import AdminListNonGerenteUsersView

# Import opcional del endpoint csrf: si por alguna razón la vista no existe
# (por ejemplo en despliegues intermedios), evitamos que la importación falle
# y detenga el arranque de Django.
try:
    from .views import csrf  # view decorated with ensure_csrf_cookie
    _HAS_CSRF_VIEW = True
except Exception:
    csrf = None
    _HAS_CSRF_VIEW = False

urlpatterns = [
    path("register/", RegisterView.as_view(), name="auth-register"),
    path("login/", LoginView.as_view(), name="auth-login"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token-refresh"),
    path("me/", MeView.as_view(), name="auth-me"),
    path("password/reset/", PasswordResetRequestView.as_view(), name="password-reset-request"),
    path("password/reset/confirm/", PasswordResetConfirmView.as_view(), name="password-reset-confirm"),
    path("users/create/", AdminCreateUserView.as_view(), name="user-create-admin"),
    path("users/", AdminListNonGerenteUsersView.as_view(), name="user-list-admin"),
    path("users/<int:pk>/", AdminUserDetailView.as_view(), name="user-detail-admin"),
    path("users/<int:pk>/update/", AdminUpdateUserView.as_view(), name="user-update-admin"),
    path("users/<int:pk>/block/", AdminBlockUserView.as_view(), name="user-block-admin"),
    path("users/<int:pk>/access/", AdminUserAccessView.as_view(), name="user-access-admin"),
]

# Añadir ruta csrf solo si la vista se importó correctamente
if _HAS_CSRF_VIEW and csrf is not None:
    urlpatterns.append(path("csrf/", csrf, name="csrf-cookie"))
 
