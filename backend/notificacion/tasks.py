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
                    # Excluir turnos cancelados
                    status='cancelled'
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