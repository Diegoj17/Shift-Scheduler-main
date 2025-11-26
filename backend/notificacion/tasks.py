# notificacion/tasks.py - VERSIÓN FINAL COMPLETA
from celery import shared_task
from celery.utils.log import get_task_logger
from django.utils import timezone
from django.db import transaction
import traceback

logger = get_task_logger(__name__)


@shared_task(
    bind=True,
    max_retries=3,
    name='notificacion.tasks.send_shift_reminder_task'
)
def send_shift_reminder_task(self, reminder_id):
    """
    ✅ Tarea Celery para enviar un recordatorio de turno específico
    Incluye reintentos con backoff exponencial
    """
    try:
        from shifts.models import ShiftReminder
        from notificacion.services import notification_service
        
        logger.info(f"📧 [Task] Ejecutando recordatorio {reminder_id}")
        logger.info(f"    - Task ID: {self.request.id}")
        logger.info(f"    - Hora actual: {timezone.localtime().strftime('%Y-%m-%d %H:%M:%S %Z')}")
        logger.info(f"    - Reintentos: {self.request.retries}/{self.max_retries}")
        
        # ✅ Obtener el recordatorio con sus relaciones
        try:
            reminder = ShiftReminder.objects.select_related(
                'shift', 
                'user', 
                'shift__shift_type', 
                'shift__employee',
                'shift__employee__user'
            ).get(pk=reminder_id)
        except ShiftReminder.DoesNotExist:
            logger.error(f"❌ Recordatorio {reminder_id} no encontrado en la BD")
            return {'status': 'error', 'message': 'Recordatorio no existe'}
        
        logger.info(f"    - Usuario: {reminder.user.email}")
        logger.info(f"    - Turno: {reminder.shift.id} ({reminder.shift.date} {reminder.shift.start_time})")
        logger.info(f"    - Tipo: {reminder.reminder_type}")
        logger.info(f"    - Ya enviado: {reminder.sent}")
        
        # ✅ Verificar si ya fue enviado
        if reminder.sent:
            logger.warning(f"⚠️ Recordatorio {reminder_id} ya fue enviado previamente")
            return {
                'status': 'already_sent',
                'reminder_id': reminder_id,
                'sent_at': reminder.created_at.isoformat() if hasattr(reminder, 'sent_at') else None
            }
        
        # ✅ Enviar la notificación (panel + email según preferencias)
        try:
            notification = notification_service.notify_shift_reminder(
                reminder.shift,
                reminder.user,
                reminder.reminder_type
            )
            
            if notification is not None:
                # ✅ Marcar como enviado usando transaction para evitar race conditions
                with transaction.atomic():
                    reminder.sent = True
                    reminder.save(update_fields=['sent'])
                
                logger.info(f"✅ Recordatorio {reminder_id} enviado exitosamente")
                logger.info(f"    - Notification ID: {notification.id}")
                logger.info(f"    - Email enviado: {notification.email_sent}")
                
                return {
                    'status': 'success',
                    'reminder_id': reminder_id,
                    'notification_id': notification.id,
                    'email_sent': notification.email_sent,
                    'sent_at': timezone.localtime().isoformat()
                }
            else:
                # Si notification_service retornó None, algo falló
                error_msg = "notification_service.notify_shift_reminder retornó None"
                logger.error(f"❌ {error_msg} para recordatorio {reminder_id}")
                raise Exception(error_msg)
                
        except Exception as e:
            error_msg = f"Error al enviar notificación: {str(e)}"
            logger.error(f"❌ {error_msg}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            
            # ✅ Reintentar con backoff exponencial
            if self.request.retries < self.max_retries:
                # Backoff: 120s, 240s, 480s (limitado a 1 hora)
                countdown = min(60 * 2 ** self.request.retries, 3600)
                logger.info(f"🔄 Reintentando en {countdown}s (intento {self.request.retries + 1}/{self.max_retries})")
                raise self.retry(exc=e, countdown=countdown)
            else:
                logger.error(f"❌ Agotados los reintentos para recordatorio {reminder_id}")
                return {
                    'status': 'failed',
                    'reminder_id': reminder_id,
                    'error': str(e),
                    'retries_exhausted': True
                }
                
    except Exception as exc:
        logger.exception(f"❌ Error crítico en send_shift_reminder_task({reminder_id}): {exc}")
        
        # Intentar retry una última vez
        try:
            if self.request.retries < self.max_retries:
                countdown = min(60 * 2 ** self.request.retries, 3600)
                raise self.retry(exc=exc, countdown=countdown)
        except Exception:
            logger.exception("❌ Retry falló o task agotó todos los reintentos")
        
        return {
            'status': 'error',
            'reminder_id': reminder_id,
            'error': str(exc)
        }


@shared_task(name='notificacion.tasks.check_pending_reminders')
def check_pending_reminders():
    """
    ✅ Tarea periódica para verificar y enviar recordatorios pendientes
    Se ejecuta cada 5 minutos via Celery Beat
    """
    try:
        logger.info("=" * 60)
        logger.info("🔍 [Beat] Iniciando verificación de recordatorios pendientes")
        logger.info(f"    - Hora actual: {timezone.localtime().strftime('%Y-%m-%d %H:%M:%S %Z')}")
        
        from notificacion.services import notification_service
        
        # ✅ Delegar al servicio de notificaciones
        sent_count = notification_service.send_scheduled_reminders()
        
        logger.info(f"✅ [Beat] Verificación completada: {sent_count} recordatorios procesados")
        logger.info("=" * 60)
        
        return {
            'status': 'success',
            'sent_count': sent_count,
            'checked_at': timezone.localtime().isoformat()
        }
        
    except Exception as e:
        logger.exception(f"❌ Error crítico en check_pending_reminders: {e}")
        return {
            'status': 'error',
            'error': str(e),
            'checked_at': timezone.localtime().isoformat()
        }


@shared_task(name='notificacion.tasks.cleanup_old_reminders')
def cleanup_old_reminders(days=7):
    """
    ✅ Limpia recordatorios antiguos ya enviados (opcional)
    Ejecutar semanalmente para mantener la BD limpia
    """
    try:
        from shifts.models import ShiftReminder
        from datetime import timedelta
        
        cutoff_date = timezone.now() - timedelta(days=days)
        
        deleted_count, _ = ShiftReminder.objects.filter(
            sent=True,
            created_at__lt=cutoff_date
        ).delete()
        
        logger.info(f"🗑️ Eliminados {deleted_count} recordatorios antiguos (>{days} días)")
        
        return {
            'status': 'success',
            'deleted_count': deleted_count,
            'cutoff_date': cutoff_date.isoformat()
        }
        
    except Exception as e:
        logger.exception(f"❌ Error limpiando recordatorios: {e}")
        return {
            'status': 'error',
            'error': str(e)
        }


@shared_task(name='notificacion.tasks.cleanup_old_notifications')
def cleanup_old_notifications(days=30):
    """
    ✅ Limpia notificaciones antiguas leídas (opcional)
    Ejecutar mensualmente para mantener la BD limpia
    """
    try:
        from notificacion.models import Notification
        from datetime import timedelta
        
        cutoff_date = timezone.now() - timedelta(days=days)
        
        deleted_count, _ = Notification.objects.filter(
            is_read=True,
            created_at__lt=cutoff_date
        ).delete()
        
        logger.info(f"🗑️ Eliminadas {deleted_count} notificaciones antiguas leídas (>{days} días)")
        
        return {
            'status': 'success',
            'deleted_count': deleted_count,
            'cutoff_date': cutoff_date.isoformat()
        }
        
    except Exception as e:
        logger.exception(f"❌ Error limpiando notificaciones: {e}")
        return {
            'status': 'error',
            'error': str(e)
        }