from django.core.checks import register, Error
from django.conf import settings


@register()
def check_sendgrid_api_key(app_configs, **kwargs):
    """Comprueba que la API key de SendGrid esté configurada.

    Esta check falla con Error si `SENDGRID_API_KEY` no está definido.
    Útil para CI/CD: `manage.py check` devolverá error y fallará el pipeline.
    """
    errors = []

    key = getattr(settings, 'SENDGRID_API_KEY', None)
    if not key:
        errors.append(
            Error(
                'SENDGRID_API_KEY no configurada en variables de entorno.',
                hint='Asegúrate de definir SENDGRID_API_KEY en el entorno o en el servicio de secretos.',
                id='notificacion.E001',
            )
        )

    return errors
