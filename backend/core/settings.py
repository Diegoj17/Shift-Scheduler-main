from pathlib import Path
import os
import dj_database_url
from datetime import timedelta
# Import defaults para CORS
from corsheaders.defaults import default_headers, default_methods
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "dev-secret-key-change-in-production")
DEBUG = os.getenv("DEBUG", "False") == "True"

ALLOWED_HOSTS = [
    "localhost",
    "127.0.0.1",
    ".railway.app",
]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "rest_framework_simplejwt",
    "corsheaders",
    "users",
    "shifts",
    "notificacion",
    "django_celery_beat",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "core.middleware.EnsureCORSOnExceptionMiddleware",
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
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'core.wsgi.application'

# DATABASE CONFIGURATION - Compatible con psycopg3
DATABASE_URL = os.getenv('DATABASE_URL')

if DATABASE_URL:
    # Producción - Railway
    DATABASES = {
        'default': dj_database_url.parse(DATABASE_URL)
    }
else:
    # Desarrollo local
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

AUTH_USER_MODEL = "users.User"
LANGUAGE_CODE = "es-co"  # ✅ Español de Colombia
TIME_ZONE = 'America/Bogota'  # ✅ Zona horaria de Colombia (GMT-5)
USE_I18N = True  # Internacionalización
USE_L10N = True  # Localización (formatos de fecha/hora)
USE_TZ = True # Usar zonas horarias (timestamps en UTC en BD, convertidos a local al mostrar)

STATIC_URL = 'static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

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

CSRF_TRUSTED_ORIGINS = [
    "http://localhost:4000",
    "http://localhost:5173",
    "https://*.railway.app",
    "https://shiftscheduler1.vercel.app"
]

CORS_ALLOWED_ORIGINS = [
    "http://localhost:4000",
    "http://localhost:5173",
    "https://shiftscheduler1.vercel.app"
]

CORS_ALLOW_CREDENTIALS = True

CORS_ALLOW_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
]

CORS_ALLOW_METHODS = [
    'DELETE',
    'GET',
    'OPTIONS',
    'PATCH',
    'POST',
    'PUT',
]

if DEBUG:
    CORS_ALLOW_ALL_ORIGINS = True

if not DEBUG:
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    CSRF_COOKIE_SECURE = True
    SESSION_COOKIE_SECURE = True

# ✅ CONFIGURACIÓN SEGURA DE SENDGRID - SIN CLAVES EXPUESTAS
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")  # Solo variable de entorno

# Opcional: clave pública para verificar firmas del Event Webhook de SendGrid
# Copia la "Clave de verificación" desde el panel de SendGrid y pégala en la variable
# `SENDGRID_WEBHOOK_PUBLIC_KEY` como una sola línea (PEM o base64). Para habilitar
# la verificación marque `SENDGRID_VERIFY_SIGNATURE=True` en el entorno.
SENDGRID_VERIFY_SIGNATURE = os.getenv("SENDGRID_VERIFY_SIGNATURE", "False") == "True"
SENDGRID_WEBHOOK_PUBLIC_KEY = os.getenv("SENDGRID_WEBHOOK_PUBLIC_KEY")

# Celery configuration
# Permitir varios nombres de variable (Railway, Upstash, etc.) antes de caer a localhost
DEFAULT_REDIS_URL = (
    os.getenv('CELERY_BROKER_URL') or
    os.getenv('REDIS_URL') or
    os.getenv('UPSTASH_REDIS_URL') or
    'redis://localhost:6379/0'
)
CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', DEFAULT_REDIS_URL)
CELERY_RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND', CELERY_BROKER_URL)

# ✅ ZONA HORARIA: Usar America/Bogota en toda la aplicación
CELERY_TIMEZONE = 'America/Bogota'  # ⚠️ CAMBIO CRÍTICO
CELERY_ENABLE_UTC = False  # ⚠️ CAMBIO CRÍTICO: Desactivar UTC

# ✅ Usar django-celery-beat para gestionar tareas periódicas desde admin
CELERY_BEAT_SCHEDULER = 'django_celery_beat.schedulers:DatabaseScheduler'

# ✅ NO usar CELERY_TASK_ALWAYS_EAGER en producción (solo para testing)
CELERY_TASK_ALWAYS_EAGER = os.getenv('CELERY_TASK_ALWAYS_EAGER', 'False') == 'True'

# ✅ Configuración adicional para tareas programadas
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_TIME_LIMIT = 30 * 60  # 30 minutos
CELERY_WORKER_PREFETCH_MULTIPLIER = 1  # Procesar de una en una

# ✅ Configuración de conexión con Redis
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True
CELERY_BROKER_CONNECTION_RETRY = True
CELERY_BROKER_CONNECTION_MAX_RETRIES = 10
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "smtp.sendgrid.net"
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_TIMEOUT = 30

# Para SendGrid, el USERNAME siempre es 'apikey' y el PASSWORD es tu API Key
EMAIL_HOST_USER = "apikey"
EMAIL_HOST_PASSWORD = SENDGRID_API_KEY  

DEFAULT_FROM_EMAIL = os.getenv(
    "DEFAULT_FROM_EMAIL",
    "soporteshiftscheduler1@gmail.com"  # Fallback seguro
)

FRONTEND_URL = os.getenv("FRONTEND_URL", "https://shiftscheduler1.vercel.app")

PASSWORD_RESET_CONFIRM_FRONTEND_URL = os.getenv(
    "PASSWORD_RESET_CONFIRM_FRONTEND_URL",
    "https://shiftscheduler1.vercel.app/reset-password/confirm"  # Ruta de tu frontend
)

# Configuración adicional para el sistema de recuperación de contraseña
PASSWORD_RESET_TIMEOUT = 86400  # 24 horas en segundos

# Logging para depuración de emails
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
        },
        'users': {
            'handlers': ['console'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False,
        },
        'django.core.mail': {
            'handlers': ['console'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False,
        },
    },
}

