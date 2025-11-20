from django.apps import AppConfig

class NotificationsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'notifications'
    verbose_name = 'Notificaciones'
    
    def ready(self):
        """
        Importa las señales cuando la app está lista
        """
        # Este import asegura que las señales se registren
        import notifications.signals  # noqa