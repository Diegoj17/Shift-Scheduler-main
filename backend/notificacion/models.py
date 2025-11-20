from django.db import models
from django.conf import settings
from django.utils import timezone

class Notification(models.Model):
    """
    Modelo para almacenar notificaciones del sistema
    """
    TYPE_CHOICES = [
        ('shift_assigned', 'Turno Asignado'),
        ('shift_modified', 'Turno Modificado'),
        ('shift_cancelled', 'Turno Cancelado'),
        ('shift_reminder', 'Recordatorio de Turno'),
        ('request_approved', 'Solicitud Aprobada'),
        ('request_rejected', 'Solicitud Rechazada'),
        ('info', 'Información'),
        ('warning', 'Advertencia'),
        ('success', 'Éxito'),
    ]
    
    ICON_CHOICES = [
        ('calendar', 'Calendario'),
        ('clock', 'Reloj'),
        ('info', 'Información'),
        ('warning', 'Advertencia'),
        ('success', 'Éxito'),
    ]
    
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='notifications',
        verbose_name='Usuario'
    )
    type = models.CharField(
        max_length=50,
        choices=TYPE_CHOICES,
        default='info',
        verbose_name='Tipo'
    )
    icon = models.CharField(
        max_length=20,
        choices=ICON_CHOICES,
        default='info',
        verbose_name='Icono'
    )
    title = models.CharField(
        max_length=200,
        verbose_name='Título'
    )
    message = models.TextField(
        verbose_name='Mensaje'
    )
    # ✅ Relación con Shift
    related_shift = models.ForeignKey(
        'shifts.Shift',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='notifications',
        verbose_name='Turno relacionado'
    )
    # ✅ Relación con ShiftChangeRequest
    related_request = models.ForeignKey(
        'shifts.ShiftChangeRequest',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='notifications',
        verbose_name='Solicitud relacionada'
    )
    is_read = models.BooleanField(
        default=False,
        verbose_name='Leída'
    )
    email_sent = models.BooleanField(
        default=False,
        verbose_name='Email enviado'
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name='Fecha de creación'
    )
    read_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name='Fecha de lectura'
    )
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Notificación'
        verbose_name_plural = 'Notificaciones'
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['user', 'is_read']),
        ]
    
    def __str__(self):
        return f"{self.user.get_full_name() or self.user.email} - {self.title}"
    
    def mark_as_read(self):
        """Marca la notificación como leída"""
        if not self.is_read:
            self.is_read = True
            self.read_at = timezone.now()
            self.save(update_fields=['is_read', 'read_at'])
    
    def get_time_since_created(self):
        """Retorna el tiempo transcurrido desde la creación"""
        from django.utils.timesince import timesince
        return f"Hace {timesince(self.created_at)}"


class NotificationPreference(models.Model):
    """
    Preferencias de notificación por usuario
    """
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='notification_preferences',
        verbose_name='Usuario'
    )
    
    # Notificaciones por panel
    panel_shift_assigned = models.BooleanField(default=True, verbose_name='Panel: Turno asignado')
    panel_shift_modified = models.BooleanField(default=True, verbose_name='Panel: Turno modificado')
    panel_shift_cancelled = models.BooleanField(default=True, verbose_name='Panel: Turno cancelado')
    panel_shift_reminder = models.BooleanField(default=True, verbose_name='Panel: Recordatorio')
    panel_request_response = models.BooleanField(default=True, verbose_name='Panel: Respuesta solicitud')
    
    # Notificaciones por email
    email_shift_assigned = models.BooleanField(default=True, verbose_name='Email: Turno asignado')
    email_shift_modified = models.BooleanField(default=True, verbose_name='Email: Turno modificado')
    email_shift_cancelled = models.BooleanField(default=True, verbose_name='Email: Turno cancelado')
    email_shift_reminder = models.BooleanField(default=True, verbose_name='Email: Recordatorio')
    email_request_response = models.BooleanField(default=True, verbose_name='Email: Respuesta solicitud')
    
    # Configuración de recordatorios
    reminder_hours_before = models.IntegerField(
        default=2,
        verbose_name='Horas antes para recordatorio',
        help_text='Horas antes del turno para enviar recordatorio'
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'Preferencia de Notificación'
        verbose_name_plural = 'Preferencias de Notificación'
    
    def __str__(self):
        return f"Preferencias de {self.user.get_full_name() or self.user.email}"