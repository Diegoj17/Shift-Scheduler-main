from django.db.models.signals import post_save, pre_save, post_delete
from django.dispatch import receiver
from django.db import transaction
from .models import Shift, ShiftChangeRequest, ShiftReminder
from notificacion.services import notification_service
import logging

logger = logging.getLogger(__name__)

# ============================================
# SEÑALES PARA TURNOS - AUTOMÁTICO CON RECORDATORIOS
# ============================================

@receiver(pre_save, sender=Shift)
def track_shift_changes(sender, instance, **kwargs):
    """
    ✅ PASO 1: Detecta cambios ANTES de guardar
    Para saber si debemos reprogramar recordatorios
    """
    if instance.pk:  # Solo si el turno YA existe (es una actualización)
        try:
            old_shift = Shift.objects.get(pk=instance.pk)
            
            # ✅ Detectar cambios relevantes que afectan recordatorios
            date_changed = old_shift.date != instance.date
            time_changed = old_shift.start_time != instance.start_time or old_shift.end_time != instance.end_time
            employee_changed = old_shift.employee != instance.employee
            
            changes_detected = date_changed or time_changed or employee_changed
            
            if changes_detected:
                # Guardar flags para usar después del save
                instance._notify_modification = True
                instance._old_employee = old_shift.employee
                
                logger.info(f"📝 Cambios detectados en turno {instance.id}:")
                if date_changed:
                    logger.info(f"   - Fecha: {old_shift.date} → {instance.date}")
                if time_changed:
                    logger.info(f"   - Hora: {old_shift.start_time} → {instance.start_time}")
                if employee_changed:
                    logger.info(f"   - Empleado: {old_shift.employee} → {instance.employee}")
            else:
                instance._notify_modification = False
                
        except Shift.DoesNotExist:
            # El turno no existía antes (caso raro, debería ser created=True)
            instance._notify_modification = False
        except Exception as e:
            logger.error(f"❌ Error rastreando cambios de turno: {str(e)}", exc_info=True)
            instance._notify_modification = False


@receiver(post_save, sender=Shift)
def manage_shift_notifications_and_reminders(sender, instance, created, **kwargs):
    """
    ✅ PASO 2: AUTOMÁTICO - Notifica y programa recordatorios
    Se ejecuta DESPUÉS de guardar el turno
    """
    # ✅ Verificar que tenga empleado asignado
    if not instance.employee or not instance.employee.user:
        logger.warning(f"⚠️ Turno {instance.id} sin empleado asignado, saltando notificaciones")
        return
    
    try:
        user = instance.employee.user
        
        if created:
            # ========================================
            # ✅ TURNO NUEVO: Notificar + Programar Recordatorios AUTOMÁTICAMENTE
            # ========================================
            logger.info(f"📅 [AUTOMÁTICO] Nuevo turno {instance.id} creado por admin para {user.email}")
            logger.info(f"   - Fecha: {instance.date} {instance.start_time} - {instance.end_time}")
            
            # ✅ notify_shift_assigned YA llama a schedule_shift_reminders internamente
            notification = notification_service.notify_shift_assigned(instance, user)
            
            if notification:
                logger.info(f"✅ Notificación de asignación enviada + recordatorios programados automáticamente")
            else:
                logger.warning(f"⚠️ No se pudo crear notificación de asignación")
            
        else:
            # ========================================
            # ✅ TURNO ACTUALIZADO: Verificar si hubo cambios relevantes
            # ========================================
            should_notify = getattr(instance, '_notify_modification', False)
            
            if should_notify:
                logger.info(f"📝 [AUTOMÁTICO] Turno {instance.id} modificado por admin")
                
                # ✅ Si cambió el empleado, notificar al empleado anterior
                old_employee = getattr(instance, '_old_employee', None)
                if old_employee and old_employee != instance.employee and old_employee.user:
                    logger.info(f"   - Notificando cancelación al empleado anterior: {old_employee.user.email}")
                    notification_service.notify_shift_cancelled(instance, old_employee.user)
                
                # ✅ Notificar modificación al empleado actual
                # notify_shift_modified YA llama a reschedule_shift_reminders internamente
                notification = notification_service.notify_shift_modified(instance, user)
                
                if notification:
                    logger.info(f"✅ Notificación de modificación enviada + recordatorios reprogramados automáticamente")
                else:
                    logger.warning(f"⚠️ No se pudo crear notificación de modificación")
            
            # Limpiar flags temporales
            if hasattr(instance, '_notify_modification'):
                delattr(instance, '_notify_modification')
            if hasattr(instance, '_old_employee'):
                delattr(instance, '_old_employee')
                
    except Exception as e:
        logger.error(f"❌ Error en señal post_save de turno: {str(e)}", exc_info=True)


@receiver(post_delete, sender=Shift)
def handle_shift_deletion(sender, instance, **kwargs):
    """
    ✅ AUTOMÁTICO: Cuando se elimina un turno
    - Notifica cancelación al empleado
    - Cancela recordatorios programados
    - Limpia registros de ShiftReminder
    """
    try:
        # ✅ Verificar que tengamos referencia al usuario
        if hasattr(instance, 'employee') and instance.employee and hasattr(instance.employee, 'user'):
            user = instance.employee.user
            
            logger.info(f"🗑️ [AUTOMÁTICO] Turno {instance.id} eliminado por admin")
            logger.info(f"   - Empleado afectado: {user.email}")
            
            # ✅ Cancelar recordatorios programados (elimina de BD y Celery)
            cancelled_count = notification_service.cancel_shift_reminders(instance)
            logger.info(f"   - {cancelled_count} recordatorios cancelados")
            
            # ✅ Notificar cancelación al empleado
            notification = notification_service.notify_shift_cancelled(instance, user)
            
            if notification:
                logger.info(f"✅ Notificación de cancelación enviada automáticamente")
            else:
                logger.warning(f"⚠️ No se pudo crear notificación de cancelación")
        else:
            logger.warning("⚠️ No se pudo enviar notificación - referencia a employee/user perdida")
            
        # ✅ Limpiar recordatorios huérfanos (por si acaso)
        deleted_reminders = ShiftReminder.objects.filter(shift_id=instance.id).delete()[0]
        if deleted_reminders > 0:
            logger.info(f"🧹 Limpiados {deleted_reminders} recordatorios huérfanos del turno {instance.id}")
            
    except Exception as e:
        logger.error(f"❌ Error en señal post_delete de turno: {str(e)}", exc_info=True)


# ============================================
# SEÑALES PARA SOLICITUDES DE CAMBIO - AUTOMÁTICO
# ============================================

@receiver(post_save, sender=ShiftChangeRequest)
def handle_shift_change_request(sender, instance, created, **kwargs):
    """
    ✅ AUTOMÁTICO: Gestiona notificaciones de solicitudes de cambio
    """
    try:
        if created:
            # ========================================
            # ✅ NUEVA SOLICITUD: Notificar a todos los gerentes/admin
            # ========================================
            logger.info(f"🆕 [AUTOMÁTICO] Nueva solicitud de cambio creada: ID={instance.id}")
            
            from django.contrib.auth import get_user_model
            User = get_user_model()
            
            # ✅ Obtener solo gerentes y admin (roles con mayúsculas)
            managers = User.objects.filter(
                role__in=['ADMIN', 'GERENTE', 'MANAGER'],
                is_active=True
            )
            
            logger.info(f"👔 Notificando a {managers.count()} gerentes/admin")
            
            notified_count = 0
            failed_count = 0
            
            for manager in managers:
                try:
                    notification = notification_service.notify_request_created(instance, manager)
                    if notification:
                        notified_count += 1
                        logger.info(f"   ✓ {manager.email}")
                    else:
                        failed_count += 1
                        logger.warning(f"   ⚠️ Falló para {manager.email}")
                except Exception as e:
                    failed_count += 1
                    logger.error(f"   ❌ Error notificando a {manager.email}: {str(e)}")
            
            logger.info(f"✅ Notificaciones enviadas: {notified_count} exitosas, {failed_count} fallidas")
            
        else:
            # ========================================
            # ✅ SOLICITUD ACTUALIZADA: Verificar cambio de estado
            # ========================================
            requester_user = instance.requesting_employee.user if instance.requesting_employee else None
            
            if not requester_user:
                logger.warning(f"⚠️ Solicitud {instance.id} sin usuario asociado")
                return
            
            # ✅ APROBADA
            if instance.status == 'approved':
                logger.info(f"✅ [AUTOMÁTICO] Solicitud {instance.id} APROBADA")
                logger.info(f"   - Solicitante: {requester_user.email}")
                
                # Notificar al solicitante
                notification = notification_service.notify_request_approved(instance, requester_user)
                if notification:
                    logger.info(f"   ✓ Notificación enviada al solicitante")
                
                # ✅ Si hay empleado propuesto diferente, también notificarlo
                if instance.proposed_employee and instance.proposed_employee.user:
                    proposed_user = instance.proposed_employee.user
                    if proposed_user != requester_user:
                        notification = notification_service.notify_request_approved(instance, proposed_user)
                        if notification:
                            logger.info(f"   ✓ Notificación enviada al empleado propuesto: {proposed_user.email}")
            
            # ✅ RECHAZADA
            elif instance.status == 'rejected':
                logger.info(f"❌ [AUTOMÁTICO] Solicitud {instance.id} RECHAZADA")
                logger.info(f"   - Solicitante: {requester_user.email}")
                
                reason = instance.manager_comment or "No especificado"
                logger.info(f"   - Motivo: {reason}")
                
                notification = notification_service.notify_request_rejected(
                    instance,
                    requester_user,
                    reason=instance.manager_comment
                )
                
                if notification:
                    logger.info(f"   ✓ Notificación de rechazo enviada")
                
    except Exception as e:
        logger.error(f"❌ Error en señal de solicitud de cambio: {str(e)}", exc_info=True)


# ============================================
# SEÑAL DE LIMPIEZA - PREVENCIÓN DE HUÉRFANOS
# ============================================

@receiver(post_delete, sender=Shift)
def cleanup_orphaned_reminders(sender, instance, **kwargs):
    """
    ✅ Limpieza de seguridad: Elimina recordatorios huérfanos
    Se ejecuta DESPUÉS de eliminar el turno
    """
    try:
        # Buscar recordatorios que referencien este turno
        # (no deberían existir si cancel_shift_reminders funcionó)
        orphaned_reminders = ShiftReminder.objects.filter(shift_id=instance.id)
        count = orphaned_reminders.count()
        
        if count > 0:
            logger.warning(f"⚠️ Encontrados {count} recordatorios huérfanos del turno {instance.id}")
            deleted = orphaned_reminders.delete()[0]
            logger.info(f"🧹 Limpiados {deleted} recordatorios huérfanos")
            
    except Exception as e:
        logger.error(f"❌ Error limpiando recordatorios huérfanos: {str(e)}", exc_info=True)