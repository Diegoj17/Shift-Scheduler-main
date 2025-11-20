from django.apps import AppConfig

class NotificationsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'notificacion'
    verbose_name = 'Notificaciones'
    
    def ready(self):
        """
        Importa las señales cuando la app está lista
        """
        # Este import asegura que las señales se registren
        try:
            import notificacion.signals  # noqa
        except Exception:
            # Signals module is optional; ignore if not present
            pass