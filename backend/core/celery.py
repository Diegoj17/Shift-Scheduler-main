import os
from celery import Celery
from django.conf import settings

# ✅ CRÍTICO: Configurar Django settings ANTES de crear la app Celery
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')

app = Celery('core')

# ✅ Cargar configuración desde Django settings
app.config_from_object('django.conf:settings', namespace='CELERY')

# ✅ ZONA HORARIA: Usar la misma que Django (America/Bogota)
app.conf.update(
    timezone='America/Bogota',  # Zona horaria de Colombia
    enable_utc=False,  # ⚠️ CAMBIO CRÍTICO: Desactivar UTC para usar zona local
    broker_connection_retry_on_startup=True,
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    result_backend=settings.CELERY_RESULT_BACKEND,
    broker_url=settings.CELERY_BROKER_URL,
    task_track_started=True,
    task_time_limit=30 * 60,  # 30 minutos
    worker_prefetch_multiplier=1,  # Procesar tareas de una en una
    beat_schedule={
        'check-reminders-every-5-minutes': {
            'task': 'notificacion.tasks.check_pending_reminders',
            'schedule': 300.0,  # Cada 5 minutos
        },
    },
)

# ✅ Auto-descubrir tareas de todas las apps instaladas
app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)

@app.task(bind=True, ignore_result=True)
def debug_task(self):
    """Tarea de debug para verificar que Celery funciona"""
    print(f'Request: {self.request!r}')
    print(f'Timezone: {app.conf.timezone}')
    print(f'Enable UTC: {app.conf.enable_utc}')