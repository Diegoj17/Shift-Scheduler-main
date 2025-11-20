from django.db.models.signals import post_save, pre_save, post_delete
from django.dispatch import receiver
from .models import Shift, ShiftChangeRequest
from notificacion.services import notification_service
import logging

logger = logging.getLogger(__name__)

# ============================================
# SEÑALES PARA TURNOS
# ✅ ADAPTADAS para trabajar con employee.user
# ============================================

@receiver(post_save, sender=Shift)
def notify_shift_created(sender, instance, created, **kwargs):
    """
    Envía notificación cuando se crea un nuevo turno
    """
    if created and instance.employee and instance.employee.user:
        try:
            user = instance.employee.user
            logger.info(f"📅 Nuevo turno creado para {user.email}")
            notification_service.notify_shift_assigned(instance, user)
        except Exception as e:
            logger.error(f"Error enviando notificación de turno creado: {str(e)}")


@receiver(pre_save, sender=Shift)
def track_shift_changes(sender, instance, **kwargs):
    """
    Detecta cambios en un turno existente y envía notificaciones
    """
    if instance.pk:  # Solo si el turno ya existe
        try:
            old_shift = Shift.objects.get(pk=instance.pk)
            
            # ✅ Detectar cambios relevantes
            changes_detected = (
                old_shift.date != instance.date or
                old_shift.start_time != instance.start_time or
                old_shift.end_time != instance.end_time or
                old_shift.shift_type != instance.shift_type or
                old_shift.employee != instance.employee
            )
            
            if changes_detected and instance.employee and instance.employee.user:
                user = instance.employee.user
                logger.info(f"📝 Turno modificado para {user.email}")
                # Guardamos un flag para enviar notificación después del save
                instance._notify_modification = True
                instance._modified_user = user
                
        except Shift.DoesNotExist:
            pass
        except Exception as e:
            logger.error(f"Error rastreando cambios de turno: {str(e)}")


@receiver(post_save, sender=Shift)
def notify_shift_modified(sender, instance, created, **kwargs):
    """
    Envía notificación después de modificar un turno
    """
    if not created:
        try:
            # Notificar modificación
            if hasattr(instance, '_notify_modification') and instance._notify_modification:
                user = getattr(instance, '_modified_user', None)
                if user:
                    notification_service.notify_shift_modified(instance, user)
                delattr(instance, '_notify_modification')
                if hasattr(instance, '_modified_user'):
                    delattr(instance, '_modified_user')
                
        except Exception as e:
            logger.error(f"Error enviando notificación de turno modificado: {str(e)}")
            
@receiver(post_delete, sender=Shift)
def notify_shift_deleted(sender, instance, **kwargs):
    """
    Envía notificación cuando se elimina un turno
    ✅ MEJORADO: Más robusto con verificación de existencia
    """
    try:
        # ✅ Verificar que el objeto todavía tiene referencia al employee
        if hasattr(instance, 'employee') and instance.employee and hasattr(instance.employee, 'user'):
            user = instance.employee.user
            logger.info(f"🗑️ [Signal] Notificación de turno eliminado para {user.email}")
            
            # ✅ Enviar notificación de turno cancelado
            notification_service.notify_shift_cancelled(instance, user)
        else:
            logger.warning("⚠️ [Signal] No se pudo enviar notificación - referencia a employee/user perdida")
            
    except Exception as e:
        logger.error(f"❌ Error en señal de turno eliminado: {str(e)}", exc_info=True)


# ============================================
# SEÑALES PARA SOLICITUDES DE CAMBIO
# ✅ ADAPTADAS para trabajar con requesting_employee.user
# ============================================

@receiver(post_save, sender=ShiftChangeRequest)
def notify_request_status_change(sender, instance, created, **kwargs):
    """
    Envía notificación cuando cambia el estado de una solicitud
    """
    if not created:
        try:
            # ✅ Obtener usuario del empleado solicitante
            requester_user = instance.requesting_employee.user if instance.requesting_employee else None
            
            if not requester_user:
                logger.warning(f"⚠️ Solicitud {instance.id} sin usuario asociado")
                return
            
            # Notificar aprobación
            if instance.status == 'approved':
                logger.info(f"✅ Solicitud aprobada para {requester_user.email}")
                notification_service.notify_request_approved(instance, requester_user)
                
                # ✅ También notificar al empleado propuesto si existe
                if instance.proposed_employee and instance.proposed_employee.user:
                    proposed_user = instance.proposed_employee.user
                    if proposed_user != requester_user:
                        notification_service.notify_request_approved(instance, proposed_user)
            
            # Notificar rechazo
            elif instance.status == 'rejected':
                logger.info(f"❌ Solicitud rechazada para {requester_user.email}")
                notification_service.notify_request_rejected(
                    instance,
                    requester_user,
                    reason=instance.manager_comment
                )
                
        except Exception as e:
            logger.error(f"Error enviando notificación de solicitud: {str(e)}", exc_info=True)