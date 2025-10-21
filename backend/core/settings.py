# ... imports anteriores ...
import dj_database_url
import os
from dotenv import load_dotenv
import dj_database_url
from datetime import timedelta

load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Quick-start development settings - unsuitable for production
SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "dev-secret-key-change-in-production")

# En producción, DEBUG debe ser False
DEBUG = os.getenv("DEBUG", "False") == "True"

# Configura ALLOWED_HOSTS para producción
ALLOWED_HOSTS = [
    "localhost",
    "127.0.0.1",
    ".railway.app",  # Permite todos los subdominios de Railway
]

# Application definition
INSTALLED_APPS = [
    "django.contrib.admin","django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    'rest_framework_simplejwt',
    "corsheaders",
    "users",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = 'core.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'core.wsgi.application'

# DATABASE CONFIGURATION - USANDO TU DATABASE_URL DE RAILWAY
DATABASES = {
    'default': dj_database_url.config(
        # Esta es tu variable DATABASE_URL de Railway
        default='postgresql://postgres:MNaIbwASWZPLIgjEvMBPaVOrgWgRdLDw@switchyard.proxy.rlwy.net:10210/railway',
        conn_max_age=600,
        conn_health_checks=True,
        ssl_require=True  # Importante para Railway
    )
}

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
AUTH_USER_MODEL = "users.User"
LANGUAGE_CODE = "es"
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = 'static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# REST Framework
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework_simplejwt.authentication.JWTAuthentication",
        "rest_framework.authentication.SessionAuthentication",
    ],
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=60),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "AUTH_HEADER_TYPES": ("Bearer",),
    'ROTATE_REFRESH_TOKENS': True,
}

# Email configuration
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
DEFAULT_FROM_EMAIL = "no-reply@shift-scheduler.local"

# Password reset
PASSWORD_RESET_TIMEOUT = 60 * 60 * 24  # 86400 segundos
PASSWORD_RESET_CONFIRM_FRONTEND_URL = os.getenv(
    "PASSWORD_RESET_CONFIRM_FRONTEND_URL", ""
)

# CSRF settings - IMPORTANTE para Railway
CSRF_TRUSTED_ORIGINS = [
    "http://localhost:4000",
    "http://localhost:5173",
    "https://*.railway.app",  # ✅ Permite todos los subdominios de Railway
]

# CORS settings - ACTUALIZADO para producción
CORS_ALLOWED_ORIGINS = [
    "http://localhost:4000",
    "http://localhost:5173",
]

# En producción, permite tu dominio de Railway
CORS_ALLOWED_ORIGINS.append("https://*.railway.app")

CORS_ALLOW_CREDENTIALS = True

# Solo permite todos los orígenes en desarrollo
if DEBUG:
    CORS_ALLOW_ALL_ORIGINS = True
else:
    CORS_ALLOW_ALL_ORIGINS = True

# Security settings for production
if not DEBUG:
    SECURE_SSL_REDIRECT = True
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True