# shifts/signals.py - VERSIÓN COMPLETA CON GESTIÓN DE RECORDATORIOS
from django.db.models.signals import post_save, pre_save, post_delete
from django.dispatch import receiver
from .models import Shift, ShiftChangeRequest, ShiftReminder
from notificacion.services import notification_service
import logging

logger = logging.getLogger(__name__)

# ============================================
# SEÑALES PARA TURNOS CON GESTIÓN DE RECORDATORIOS
# ============================================

@receiver(post_save, sender=Shift)
def manage_shift_notifications_and_reminders(sender, instance, created, **kwargs):
    """
    Gestiona notificaciones y recordatorios cuando se crea/modifica un turno
    """
    if instance.employee and instance.employee.user:
        try:
            user = instance.employee.user
            
            if created:
                # Nuevo turno - notificar y programar recordatorios
                logger.info(f"📅 Nuevo turno creado para {user.email}")
                notification_service.notify_shift_assigned(instance, user)
            else:
                # Turno modificado - verificar si hay cambios relevantes
                if hasattr(instance, '_notify_modification') and instance._notify_modification:
                    logger.info(f"📝 Turno modificado para {user.email}")
                    notification_service.notify_shift_modified(instance, user)
                    
        except Exception as e:
            logger.error(f"Error en señal de turno creado/modificado: {str(e)}")

@receiver(pre_save, sender=Shift)
def track_shift_changes(sender, instance, **kwargs):
    """
    Detecta cambios en un turno existente para reprogramar recordatorios
    """
    if instance.pk:  # Solo si el turno ya existe
        try:
            old_shift = Shift.objects.get(pk=instance.pk)
            
            # ✅ Detectar cambios relevantes que requieren reprogramar recordatorios
            changes_detected = (
                old_shift.date != instance.date or
                old_shift.start_time != instance.start_time or
                old_shift.end_time != instance.end_time or
                old_shift.employee != instance.employee
            )
            
            if changes_detected and instance.employee and instance.employee.user:
                user = instance.employee.user
                # Guardamos flag para notificar después del save
                instance._notify_modification = True
                instance._modified_user = user
                
        except Shift.DoesNotExist:
            pass
        except Exception as e:
            logger.error(f"Error rastreando cambios de turno: {str(e)}")

@receiver(post_delete, sender=Shift)
def handle_shift_deletion(sender, instance, **kwargs):
    """
    Maneja la eliminación de turnos - notifica y cancela recordatorios
    """
    try:
        if hasattr(instance, 'employee') and instance.employee and hasattr(instance.employee, 'user'):
            user = instance.employee.user
            logger.info(f"🗑️ [Signal] Notificación de turno eliminado para {user.email}")
            
            # ✅ Cancelar recordatorios programados
            notification_service.cancel_shift_reminders(instance)
            
            # ✅ Enviar notificación de turno cancelado
            notification_service.notify_shift_cancelled(instance, user)
        else:
            logger.warning("⚠️ [Signal] No se pudo enviar notificación - referencia a employee/user perdida")
            
    except Exception as e:
        logger.error(f"❌ Error en señal de turno eliminado: {str(e)}", exc_info=True)

# ============================================
# SEÑALES PARA SOLICITUDES DE CAMBIO
# ============================================

@receiver(post_save, sender=ShiftChangeRequest)
def notify_new_request_created(sender, instance, created, **kwargs):
    """
    Envía notificación cuando se crea una NUEVA solicitud a todos los gerentes/admin
    """
    if created:
        try:
            logger.info(f"🆕 [Signal] Nueva solicitud creada: ID={instance.id}")
            
            # ✅ Obtener todos los gerentes/admin para notificar
            from django.contrib.auth import get_user_model
            User = get_user_model()
            
            managers = User.objects.filter(
                role__in=['ADMIN', 'GERENTE', 'MANAGER']
            )
            
            logger.info(f"👔 Notificando a {managers.count()} gerentes/admin")
            
            for manager in managers:
                try:
                    notification_service.notify_request_created(instance, manager)
                    logger.info(f"✅ Notificación enviada a {manager.email}")
                except Exception as e:
                    logger.error(f"❌ Error notificando a {manager.email}: {str(e)}")
                    
        except Exception as e:
            logger.error(f"💥 Error en señal de nueva solicitud: {str(e)}", exc_info=True)

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

# ============================================
# SEÑAL PARA LIMPIAR RECORDATORIOS CUANDO SE ELIMINA UN TURNO
# ============================================

@receiver(post_delete, sender=Shift)
def cleanup_shift_reminders(sender, instance, **kwargs):
    """
    Limpia recordatorios cuando se elimina un turno
    """
    try:
        # Eliminar recordatorios asociados al turno
        deleted_count = ShiftReminder.objects.filter(shift=instance).delete()[0]
        if deleted_count > 0:
            logger.info(f"🧹 Eliminados {deleted_count} recordatorios del turno {instance.id}")
    except Exception as e:
        logger.error(f"❌ Error limpiando recordatorios: {str(e)}", exc_info=True)