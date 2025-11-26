# notificacion/services.py - VERSIÓN COMPLETA CON RECORDATORIOS
import logging
from django.conf import settings
from django.utils import timezone
from .models import Notification, NotificationPreference
from services.email_service import get_email_service

logger = logging.getLogger(__name__)

class NotificationService:
    """
    Servicio centralizado para crear y enviar notificaciones
    ✅ Incluye sistema completo de recordatorios programados
    """
    
    def __init__(self):
        self.email_service = get_email_service()
        logger.info("✅ NotificationService usando EmailService funcional")
    
    def create_notification(
        self,
        user,
        notification_type,
        title,
        message,
        icon='info',
        related_shift=None,
        related_request=None,
        send_email=True
    ):
        """
        Crea una notificación en el panel y opcionalmente envía email
        """
        try:
            # Obtener preferencias del usuario (crear si no existen)
            preferences, _ = NotificationPreference.objects.get_or_create(user=user)
            
            # Verificar si el usuario quiere notificaciones de panel para este tipo
            panel_enabled = self._check_panel_preference(preferences, notification_type)
            
            if not panel_enabled:
                logger.info(f"Usuario {user.email} tiene deshabilitadas las notificaciones de panel para {notification_type}")
                return None
            
            # Crear notificación en el panel
            notification = Notification.objects.create(
                user=user,
                type=notification_type,
                icon=icon,
                title=title,
                message=message,
                related_shift=related_shift,
                related_request=related_request
            )
            
            logger.info(f"✓ Notificación creada para {user.email}: {title}")
            
            # Enviar email si está habilitado
            if send_email:
                email_enabled = self._check_email_preference(preferences, notification_type)
                if email_enabled:
                    email_sent = self._send_notification_email(user, notification_type, title, message, related_shift)
                    if email_sent:
                        notification.email_sent = True
                        notification.save(update_fields=['email_sent'])
            
            return notification
            
        except Exception as e:
            logger.error(f"❌ Error creando notificación para {user.email}: {str(e)}", exc_info=True)
            return None
    
    def _check_panel_preference(self, preferences, notification_type):
        """Verifica si las notificaciones de panel están habilitadas"""
        mapping = {
            'shift_assigned': preferences.panel_shift_assigned,
            'shift_modified': preferences.panel_shift_modified,
            'shift_cancelled': preferences.panel_shift_cancelled,
            'shift_reminder': preferences.panel_shift_reminder,
            'request_created': preferences.panel_request_response,
            'request_approved': preferences.panel_request_response,
            'request_rejected': preferences.panel_request_response,
        }
        return mapping.get(notification_type, True)
    
    def _check_email_preference(self, preferences, notification_type):
        """Verifica si las notificaciones de email están habilitadas"""
        mapping = {
            'shift_assigned': preferences.email_shift_assigned,
            'shift_modified': preferences.email_shift_modified,
            'shift_cancelled': preferences.email_shift_cancelled,
            'shift_reminder': preferences.email_shift_reminder,
            'request_created': preferences.email_request_response,
            'request_approved': preferences.email_request_response,
            'request_rejected': preferences.email_request_response,
        }
        return mapping.get(notification_type, True)
    
    def _send_notification_email(self, user, notification_type, title, message, related_shift=None):
        """Envía el email de notificación"""
        try:
            # Preparar contenido del email
            plain_content = f"""
{title}

Hola {user.get_full_name() or user.email},

{message}

{f"Fecha: {related_shift.date.strftime('%d/%m/%Y')} {related_shift.start_time.strftime('%H:%M')}" if related_shift else ""}

---
Shift Scheduler
            """
            
            # Preparar HTML content
            shift_details = ""
            if related_shift:
                shift_type_name = related_shift.shift_type.name if related_shift.shift_type else 'Sin tipo'
                shift_details = f"""
                <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <strong>📅 Detalles del Turno:</strong><br>
                    Fecha: {related_shift.date.strftime('%d/%m/%Y')}<br>
                    Hora: {related_shift.start_time.strftime('%H:%M')} - {related_shift.end_time.strftime('%H:%M')}<br>
                    Tipo: {shift_type_name}<br>
                    {f"Notas: {related_shift.notes}" if related_shift.notes else ""}
                </div>
                """
            
            color_map = {
                'shift_assigned': '#28a745',
                'shift_modified': '#ffc107',
                'shift_cancelled': '#dc3545', 
                'shift_reminder': '#007bff',
                'request_created': '#17a2b8',
                'request_approved': '#28a745',
                'request_rejected': '#dc3545',
            }
            header_color = color_map.get(notification_type, '#007bff')
            
            frontend_url = getattr(settings, 'FRONTEND_URL', 'https://shiftscheduler1.vercel.app')
            calendar_url = f"{frontend_url}/login"

            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>{title}</title>
            </head>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 20px; background-color: #f4f4f4;">
                <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <div style="background: {header_color}; color: white; padding: 30px 20px; text-align: center;">
                        <h1 style="margin: 0; font-size: 24px;">Shift Scheduler</h1>
                        <p style="margin: 10px 0 0 0; font-size: 16px;">{title}</p>
                    </div>
                    <div style="padding: 30px 20px;">
                        <h2 style="color: #333; margin-top: 0;">Hola {user.get_full_name() or user.email},</h2>
                        <p>{message}</p>
                        {shift_details}
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="{calendar_url}" style="display: inline-block; padding: 14px 28px; background: {header_color}; color: white; text-decoration: none; border-radius: 5px; font-weight: bold;">
                                Ver Mi Calendario
                            </a>
                        </div>
                        <p style="color: #666; font-size: 14px;">
                            Puedes gestionar tus preferencias de notificación desde tu perfil.
                        </p>
                    </div>
                    <div style="padding: 20px; text-align: center; font-size: 12px; color: #666; background: #f8f9fa;">
                        <p>© 2025 Shift Scheduler - Sistema de Gestión de Turnos</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            subject = f"Shift Scheduler - {title}"
            logger.info(f"📧 Enviando email de notificación a {user.email} usando EmailService")
            
            return self.email_service.send_notification_email(
                to_email=user.email,
                subject=subject,
                plain_text_content=plain_content,
                html_content=html_content
            )
                
        except Exception as e:
            logger.error(f"❌ Error enviando email a {user.email}: {str(e)}", exc_info=True)
            return False

    # ============================================
    # SISTEMA DE RECORDATORIOS PROGRAMADOS
    # ============================================
    
    def schedule_shift_reminders(self, shift):
        """
        Programa recordatorios automáticos para un turno
        - 1 hora antes
        - 30 minutos antes
        """
        try:
            if not shift.employee or not shift.employee.user:
                logger.warning(f"⚠️ No se pueden programar recordatorios - turno sin empleado: {shift.id}")
                return
            
            user = shift.employee.user
            
            # Calcular fecha/hora del turno
            shift_datetime = timezone.make_aware(
                timezone.datetime.combine(shift.date, shift.start_time)
            )
            
            # Obtener preferencias del usuario
            preferences, _ = NotificationPreference.objects.get_or_create(user=user)
            
            # Programar recordatorios según preferencias
            from shifts.models import ShiftReminder

            # Eliminar recordatorios previos para este turno/usuario para evitar duplicados
            try:
                deleted = ShiftReminder.objects.filter(shift=shift, user=user).delete()
                if deleted and deleted[0] > 0:
                    logger.info(f"♻️ Eliminados {deleted[0]} recordatorios previos para turno {shift.id}")
            except Exception:
                logger.exception("No se pudieron eliminar recordatorios previos")

            reminders_to_schedule = []

            # Recordatorio 1 hora antes
            if preferences.email_shift_reminder or preferences.panel_shift_reminder:
                from datetime import timedelta
                reminder_1h = shift_datetime - timedelta(hours=1)
                now = timezone.now()
                if reminder_1h > now:
                    reminders_to_schedule.append(ShiftReminder(
                        shift=shift,
                        user=user,
                        reminder_time=reminder_1h,
                        reminder_type='1_hour'
                    ))
                    logger.info(f"⏰ Programado recordatorio 1h para turno {shift.id} a las {reminder_1h}")
                else:
                    # Si la hora del recordatorio ya pasó recientemente (ej. se modificó el turno),
                    # enviar la notificación inmediatamente para no perder el recordatorio.
                    # Consideramos "recientemente" como dentro de la última hora.
                    if reminder_1h > now - timedelta(hours=1):
                        try:
                            logger.info(f"⚡ Recordatorio 1h ya pasó recientemente para turno {shift.id}; enviando ahora")
                            self.notify_shift_reminder(shift, user, '1_hour')
                        except Exception:
                            logger.exception("Error enviando recordatorio 1h inmediato")

            # Recordatorio 30 minutos antes
            if preferences.email_shift_reminder or preferences.panel_shift_reminder:
                from datetime import timedelta
                reminder_30m = shift_datetime - timedelta(minutes=30)
                now = timezone.now()
                if reminder_30m > now:
                    reminders_to_schedule.append(ShiftReminder(
                        shift=shift,
                        user=user,
                        reminder_time=reminder_30m,
                        reminder_type='30_min'
                    ))
                    logger.info(f"⏰ Programado recordatorio 30min para turno {shift.id} a las {reminder_30m}")
                else:
                    # Si la hora del recordatorio ya pasó recientemente (ej. se modificó el turno),
                    # enviar la notificación inmediatamente. Consideramos "recientemente" como últimos 30 minutos.
                    if reminder_30m > now - timedelta(minutes=30):
                        try:
                            logger.info(f"⚡ Recordatorio 30min ya pasó recientemente para turno {shift.id}; enviando ahora")
                            self.notify_shift_reminder(shift, user, '30_min')
                        except Exception:
                            logger.exception("Error enviando recordatorio 30min inmediato")

            # Crear recordatorios programados
            if reminders_to_schedule:
                ShiftReminder.objects.bulk_create(reminders_to_schedule)
                logger.info(f"✅ Programados {len(reminders_to_schedule)} recordatorios para turno {shift.id}")
            
        except Exception as e:
            logger.error(f"❌ Error programando recordatorios: {str(e)}", exc_info=True)
    
    def send_scheduled_reminders(self):
        """
        Envía recordatorios programados que están pendientes
        Se ejecuta automáticamente cada minuto
        """
        try:
            now = timezone.now()
            from shifts.models import ShiftReminder
            reminders = ShiftReminder.objects.filter(
                reminder_time__lte=now,
                sent=False
            ).select_related('shift', 'user', 'shift__shift_type')

            sent_count = 0
            for reminder in reminders:
                try:
                    # Enviar notificación de recordatorio (crea Notification en panel y puede enviar email)
                    notification = self.notify_shift_reminder(reminder.shift, reminder.user, reminder.reminder_type)

                    # Comportamiento de marcado:
                    # - Si el usuario tiene habilitado email para recordatorios, sólo marcar como 'sent'
                    #   cuando el campo Notification.email_sent sea True (evita perder reintentos).
                    # - Si el usuario únicamente usa panel (no email), marcar como enviado igualmente.
                    prefs = None
                    try:
                        prefs = NotificationPreference.objects.filter(user=reminder.user).first()
                    except Exception:
                        prefs = None

                    email_required = bool(prefs.email_shift_reminder) if prefs is not None else False

                    if notification is None:
                        logger.error(f"❌ No se creó Notification para el recordatorio {reminder.id}")
                        # No marcar como enviado para intentar de nuevo
                        continue

                    if email_required:
                        # Si se requería email, marcar como enviado sólo si Notification.email_sent == True
                        if getattr(notification, 'email_sent', False):
                            reminder.sent = True
                            reminder.save(update_fields=['sent'])
                            sent_count += 1
                            logger.info(f"✅ Recordatorio enviado (email confirm): {reminder.id} - {reminder.reminder_type}")
                        else:
                            logger.warning(f"⚠️ Email no enviado para recordatorio {reminder.id}; se intentará nuevamente")
                            # No marcar como enviado para permitir reintentos en próximas ejecuciones
                            continue
                    else:
                        # Solo panel: marcar como enviado
                        reminder.sent = True
                        reminder.save(update_fields=['sent'])
                        sent_count += 1
                        logger.info(f"✅ Recordatorio enviado (panel): {reminder.id} - {reminder.reminder_type}")

                except Exception as e:
                    logger.error(f"❌ Error enviando recordatorio {reminder.id}: {str(e)}", exc_info=True)
                    continue

            logger.info(f"📨 Recordatorios procesados: {sent_count} enviados")
            return sent_count
            
        except Exception as e:
            logger.error(f"❌ Error en send_scheduled_reminders: {str(e)}", exc_info=True)
            return 0
    
    def cancel_shift_reminders(self, shift):
        """
        Cancela recordatorios programados cuando se elimina un turno
        """
        try:
            from shifts.models import ShiftReminder
            deleted_count, _ = ShiftReminder.objects.filter(shift=shift).delete()
            logger.info(f"🗑️ Recordatorios cancelados para turno {shift.id}: {deleted_count}")
            return deleted_count
        except Exception as e:
            logger.error(f"❌ Error cancelando recordatorios: {str(e)}")
            return 0
    
    def reschedule_shift_reminders(self, shift):
        """
        Reprograma recordatorios cuando se modifica un turno
        """
        try:
            # Cancelar recordatorios existentes
            self.cancel_shift_reminders(shift)
            # Programar nuevos recordatorios
            self.schedule_shift_reminders(shift)
            logger.info(f"🔄 Recordatorios reprogramados para turno {shift.id}")
        except Exception as e:
            logger.error(f"❌ Error reprogramando recordatorios: {str(e)}")

    # ============================================
    # MÉTODOS ESPECÍFICOS PARA CADA TIPO DE NOTIFICACIÓN
    # ============================================
    
    def notify_shift_assigned(self, shift, user):
        """Notifica cuando se asigna un turno"""
        title = "Nuevo Turno Asignado"
        message = f"Se te ha asignado un turno para el {shift.date.strftime('%d/%m/%Y')} de {shift.start_time.strftime('%H:%M')} a {shift.end_time.strftime('%H:%M')}."
        
        # Programar recordatorios automáticos
        self.schedule_shift_reminders(shift)
        
        return self.create_notification(
            user=user,
            notification_type='shift_assigned',
            title=title,
            message=message,
            icon='calendar',
            related_shift=shift,
            send_email=True
        )
    
    def notify_shift_modified(self, shift, user):
        """Notifica cuando se modifica un turno"""
        title = "Turno Modificado"
        message = f"Tu turno del {shift.date.strftime('%d/%m/%Y')} ha sido modificado. Revisa los nuevos detalles."
        
        # Reprogramar recordatorios
        self.reschedule_shift_reminders(shift)
        
        return self.create_notification(
            user=user,
            notification_type='shift_modified',
            title=title,
            message=message,
            icon='warning',
            related_shift=shift,
            send_email=True
        )
    
    def notify_shift_cancelled(self, shift, user):
        """Notifica cuando se cancela un turno"""
        title = "Turno Cancelado"
        message = f"Tu turno del {shift.date.strftime('%d/%m/%Y')} de {shift.start_time.strftime('%H:%M')} a {shift.end_time.strftime('%H:%M')} ha sido cancelado."
        
        # Cancelar recordatorios programados
        self.cancel_shift_reminders(shift)
        
        return self.create_notification(
            user=user,
            notification_type='shift_cancelled',
            title=title,
            message=message,
            icon='warning',
            related_shift=None,
            send_email=True
        )
    
    def notify_shift_reminder(self, shift, user, reminder_type='1_hour'):
        """Envía recordatorio de turno próximo"""
        from datetime import datetime
        
        title = "Recordatorio de Turno"
        
        # Calcular tiempo hasta el turno
        shift_datetime = datetime.combine(shift.date, shift.start_time)
        now = datetime.now()
        
        if reminder_type == '1_hour':
            time_text = "en 1 hora"
        elif reminder_type == '30_min':
            time_text = "en 30 minutos"
        else:
            hours_until = (shift_datetime - now).total_seconds() / 3600
            if hours_until <= 1:
                time_text = f"en {int(hours_until * 60)} minutos"
            else:
                time_text = f"en {int(hours_until)} horas"
        
        message = f"Recordatorio: Tu turno comienza {time_text}. Fecha: {shift.date.strftime('%d/%m/%Y')} a las {shift.start_time.strftime('%H:%M')}."
        
        return self.create_notification(
            user=user,
            notification_type='shift_reminder',
            title=title,
            message=message,
            icon='clock',
            related_shift=shift,
            send_email=True
        )
    
    def notify_request_created(self, request, manager_user):
        """Notifica a gerentes/admin cuando se crea una NUEVA solicitud"""
        title = "Nueva Solicitud de Cambio"
    
        # Obtener información del empleado solicitante
        requester_name = "Empleado desconocido"
        if request.requesting_employee and request.requesting_employee.user:
            requester_name = request.requesting_employee.user.get_full_name() or request.requesting_employee.user.email
    
        # Obtener información del turno original
        shift_info = ""
        if request.original_shift:
            shift_date = request.original_shift.date.strftime('%d/%m/%Y')
            shift_time = f"{request.original_shift.start_time.strftime('%H:%M')} - {request.original_shift.end_time.strftime('%H:%M')}"
            shift_info = f" para el turno del {shift_date} ({shift_time})"
    
        message = f"El empleado {requester_name} ha enviado una solicitud de cambio de turno{shift_info}."
    
        return self.create_notification(
            user=manager_user,
            notification_type='request_created', 
            title=title,
            message=message,
            icon='info',
            related_request=request,
            send_email=True
        )
    
    def notify_request_approved(self, request, user):
        """Notifica cuando se aprueba una solicitud"""
        title = "Solicitud Aprobada"
        message = f"Tu solicitud de cambio de turno ha sido aprobada."
        
        return self.create_notification(
            user=user,
            notification_type='request_approved',
            title=title,
            message=message,
            icon='success',
            related_request=request,
            send_email=True
        )
    
    def notify_request_rejected(self, request, user, reason=None):
        """Notifica cuando se rechaza una solicitud"""
        title = "Solicitud Rechazada"
        message = f"Tu solicitud de cambio de turno ha sido rechazada."
        if reason:
            message += f" Motivo: {reason}"
        
        return self.create_notification(
            user=user,
            notification_type='request_rejected',
            title=title,
            message=message,
            icon='warning',
            related_request=request,
            send_email=True
        )


# Instancia global
notification_service = NotificationService()