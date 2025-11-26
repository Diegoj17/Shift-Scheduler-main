from celery import shared_task
from celery.utils.log import get_task_logger
from django.db import transaction

logger = get_task_logger(__name__)


@shared_task(bind=True, max_retries=3)
def send_shift_reminder_task(self, reminder_id):
    """Task para enviar un recordatorio de turno por id de ShiftReminder.
    Hace retry con backoff exponencial en caso de errores transitorios.
    """
    try:
        from shifts.models import ShiftReminder
        from notificacion.services import notification_service

        reminder = ShiftReminder.objects.select_related('shift', 'user').get(pk=reminder_id)

        if reminder.sent:
            logger.info(f"Recordatorio {reminder_id} ya marcado como enviado; saltando.")
            return True

        # Llamar al servicio que crea la notificación y envía email si aplica
        notification = notification_service.notify_shift_reminder(reminder.shift, reminder.user, reminder.reminder_type)

        # Si la notificación fue creada (panel), marcamos como enviado
        if notification is not None:
            reminder.sent = True
            reminder.save(update_fields=['sent'])
            logger.info(f"Recordatorio {reminder_id} enviado y marcado como sent")
            return True

        # Si no se creó la notificación, lanzar excepción para reintentar
        raise Exception("No se creó Notification al ejecutar task send_shift_reminder_task")

    except Exception as exc:
        logger.exception(f"Error en send_shift_reminder_task para {reminder_id}: {exc}")
        try:
            # backoff exponencial, limitado a 1 hora
            countdown = min(60 * 2 ** self.request.retries, 3600)
            raise self.retry(exc=exc, countdown=countdown)
        except Exception:
            logger.exception("Retry falló o task agotó reintentos")
            raise
from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from django.db.models import Q
from .models import NotificationPreference
from .services import notification_service
import logging

logger = logging.getLogger(__name__)

@shared_task
def send_shift_reminders():
    """
    Tarea programada para enviar recordatorios de turnos
    Se ejecuta periódicamente (cada hora, por ejemplo)
    """
    try:
        from shifts.models import Shift  # Import aquí para evitar circular imports
        
        # Calcular el rango de tiempo para recordatorios
        now = timezone.now()
        
        # Obtener todas las preferencias con recordatorios habilitados
        preferences = NotificationPreference.objects.filter(
            Q(panel_shift_reminder=True) | Q(email_shift_reminder=True)
        ).select_related('user')
        
        reminder_count = 0
        
        for preference in preferences:
            try:
                # Calcular la ventana de tiempo para este usuario
                reminder_time = now + timedelta(hours=preference.reminder_hours_before)
                
                # Buscar turnos que empiecen en la ventana de recordatorio
                shifts = Shift.objects.filter(
                    employee__user=preference.user,  # Asumiendo relación Employee -> User
                    date=reminder_time.date(),
                    start_time__hour=reminder_time.hour,
                    start_time__minute=reminder_time.minute,
                    # Excluir turnos ya recordados recientemente
                    # notifications__type='shift_reminder',
                    # notifications__created_at__gte=now - timedelta(hours=1)
                ).exclude(
                    # Excluir turnos cancelados u "bloqueados" en el modelo actual
                    is_locked=True
                )
                
                for shift in shifts:
                    # Enviar recordatorio
                    notification_service.notify_shift_reminder(shift, preference.user)
                    reminder_count += 1
                    
            except Exception as e:
                logger.error(f"Error enviando recordatorio para usuario {preference.user.id}: {str(e)}")
                continue
        
        logger.info(f"✓ Recordatorios enviados: {reminder_count}")
        return f"Recordatorios enviados: {reminder_count}"
        
    except Exception as e:
        logger.error(f"❌ Error en tarea de recordatorios: {str(e)}", exc_info=True)
        return f"Error: {str(e)}"