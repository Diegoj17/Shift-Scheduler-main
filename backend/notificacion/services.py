# notificacion/services.py - VERSIÓN FINAL COMPLETA Y CORREGIDA

import logging
from django.conf import settings
from django.utils import timezone
import pytz
from datetime import timedelta
from .models import Notification, NotificationPreference
from services.email_service import get_email_service
import time
from celery import current_app as celery_app
import traceback

logger = logging.getLogger(__name__)

class NotificationService:
    """
    Servicio centralizado para crear y enviar notificaciones
    ✅ VERSIÓN FINAL: Manejo robusto de emails + zona horaria correcta
    """
    
    def __init__(self):
        self.email_service = get_email_service()
        self.local_tz = pytz.timezone(settings.TIME_ZONE)
        logger.info(f"✅ NotificationService inicializado con zona horaria: {settings.TIME_ZONE}")
    
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
        ✅ MEJORADO: Manejo robusto de errores de email
        """
        try:
            # Obtener preferencias del usuario
            preferences, _ = NotificationPreference.objects.get_or_create(user=user)
            
            # Verificar preferencias de panel
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
            
            logger.info(f"✓ Notificación creada en panel para {user.email}: {title}")
            
            # ✅ CRÍTICO: Intentar enviar email con reintentos
            if send_email:
                email_enabled = self._check_email_preference(preferences, notification_type)
                if email_enabled:
                    email_sent = self._send_notification_email_with_retry(
                        user, notification_type, title, message, related_shift
                    )
                    
                    if email_sent:
                        notification.email_sent = True
                        notification.save(update_fields=['email_sent'])
                        logger.info(f"✅ Email enviado exitosamente a {user.email}")
                    else:
                        logger.warning(f"⚠️ No se pudo enviar email a {user.email} después de reintentos")
            
            return notification
            
        except Exception as e:
            logger.error(f"❌ Error creando notificación para {user.email}: {str(e)}", exc_info=True)
            return None
    
    def _send_notification_email_with_retry(self, user, notification_type, title, message, related_shift=None, max_retries=3):
        """
        ✅ NUEVO: Envía email con sistema de reintentos
        """
        for attempt in range(1, max_retries + 1):
            try:
                logger.info(f"📧 [Intento {attempt}/{max_retries}] Enviando email a {user.email}")
                
                success = self._send_notification_email(user, notification_type, title, message, related_shift)
                
                if success:
                    logger.info(f"✅ Email enviado exitosamente en intento {attempt}")
                    return True
                else:
                    logger.warning(f"⚠️ Intento {attempt} falló, email_service retornó False")
                    if attempt < max_retries:
                        wait_time = attempt * 2  # Espera progresiva: 2s, 4s, 6s
                        logger.info(f"⏳ Esperando {wait_time}s antes del siguiente intento...")
                        time.sleep(wait_time)
                    
            except Exception as e:
                logger.error(f"❌ Error en intento {attempt}: {str(e)}")
                if attempt < max_retries:
                    wait_time = attempt * 2
                    logger.info(f"⏳ Esperando {wait_time}s antes del siguiente intento...")
                    time.sleep(wait_time)
        
        logger.error(f"❌ Falló el envío de email a {user.email} después de {max_retries} intentos")
        return False
    
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
        """
        Envía el email de notificación
        ✅ MEJORADO: Manejo de errores más robusto
        """
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
            logger.info(f"📧 Enviando email de notificación a {user.email}")
            
            # ✅ CRÍTICO: Capturar el resultado del envío
            email_sent = self.email_service.send_notification_email(
                to_email=user.email,
                subject=subject,
                plain_text_content=plain_content,
                html_content=html_content
            )
            
            if email_sent:
                logger.info(f"✅ Email enviado exitosamente a {user.email}")
                return True
            else:
                logger.error(f"❌ email_service.send_notification_email retornó False para {user.email}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Excepción enviando email a {user.email}: {str(e)}", exc_info=True)
            return False

    # ============================================
    # SISTEMA DE RECORDATORIOS PROGRAMADOS
    # ============================================
    
    def schedule_shift_reminders(self, shift):
        """
        ✅ FINAL: Programa recordatorios usando zona horaria de Colombia
        Crea registros en BD y programa tareas Celery
        """
        try:
            if not shift.employee or not shift.employee.user:
                logger.warning(f"⚠️ No se pueden programar recordatorios - turno sin empleado: {shift.id}")
                return
            
            user = shift.employee.user
            
            # ✅ Construir fecha/hora del turno en zona horaria LOCAL (America/Bogota)
            shift_datetime_naive = timezone.datetime.combine(shift.date, shift.start_time)
            shift_datetime_local = timezone.make_aware(shift_datetime_naive, self.local_tz)
            
            logger.info(f"🕐 [Recordatorios] Programando para turno {shift.id}:")
            logger.info(f"   - Empleado: {user.email}")
            logger.info(f"   - Fecha/Hora local: {shift_datetime_local.strftime('%Y-%m-%d %H:%M %Z')}")
            
            # ✅ Obtener preferencias del usuario
            preferences, _ = NotificationPreference.objects.get_or_create(user=user)
            
            if not preferences.email_shift_reminder and not preferences.panel_shift_reminder:
                logger.info(f"⚠️ Usuario {user.email} tiene deshabilitados todos los recordatorios")
                return
            
            from shifts.models import ShiftReminder

            # ✅ Eliminar recordatorios previos para evitar duplicados
            try:
                deleted = ShiftReminder.objects.filter(shift=shift, user=user).delete()
                if deleted and deleted[0] > 0:
                    logger.info(f"♻️ Eliminados {deleted[0]} recordatorios previos del turno {shift.id}")
            except Exception as e:
                logger.warning(f"⚠️ Error eliminando recordatorios previos: {e}")

            reminders_to_schedule = []
            now_local = timezone.localtime()  # Hora actual en America/Bogota

            # ========================================
            # ✅ RECORDATORIO 1 HORA ANTES
            # ========================================
            reminder_1h_local = shift_datetime_local - timedelta(hours=1)
            
            logger.info(f"   - Recordatorio 1h: {reminder_1h_local.strftime('%Y-%m-%d %H:%M %Z')}")
            logger.info(f"   - Hora actual: {now_local.strftime('%Y-%m-%d %H:%M %Z')}")
            
            if reminder_1h_local > now_local:
                reminders_to_schedule.append({
                    'type': '1_hour',
                    'time': reminder_1h_local
                })
                logger.info(f"⏰ Programado recordatorio 1h para: {reminder_1h_local.strftime('%Y-%m-%d %H:%M %Z')}")
            else:
                # Si ya pasó pero fue hace menos de 1 hora, enviar inmediatamente
                time_diff = (now_local - reminder_1h_local).total_seconds() / 60  # minutos
                if time_diff < 60:
                    logger.info(f"⚡ Recordatorio 1h ya pasó ({int(time_diff)}min atrás), enviando inmediatamente")
                    try:
                        self.notify_shift_reminder(shift, user, '1_hour')
                    except Exception as e:
                        logger.exception(f"❌ Error enviando recordatorio 1h inmediato: {e}")

            # ========================================
            # ✅ RECORDATORIO 30 MINUTOS ANTES
            # ========================================
            reminder_30m_local = shift_datetime_local - timedelta(minutes=30)
            
            logger.info(f"   - Recordatorio 30min: {reminder_30m_local.strftime('%Y-%m-%d %H:%M %Z')}")
            
            if reminder_30m_local > now_local:
                reminders_to_schedule.append({
                    'type': '30_min',
                    'time': reminder_30m_local
                })
                logger.info(f"⏰ Programado recordatorio 30min para: {reminder_30m_local.strftime('%Y-%m-%d %H:%M %Z')}")
            else:
                # Si ya pasó pero fue hace menos de 30 minutos, enviar inmediatamente
                time_diff = (now_local - reminder_30m_local).total_seconds() / 60
                if time_diff < 30:
                    logger.info(f"⚡ Recordatorio 30min ya pasó ({int(time_diff)}min atrás), enviando inmediatamente")
                    try:
                        self.notify_shift_reminder(shift, user, '30_min')
                    except Exception as e:
                        logger.exception(f"❌ Error enviando recordatorio 30min inmediato: {e}")

            # ========================================
            # ✅ CREAR RECORDATORIOS EN BD Y PROGRAMAR CELERY TASKS
            # ========================================
            if reminders_to_schedule:
                created_count = 0
                failed_count = 0
                
                for reminder_data in reminders_to_schedule:
                    try:
                        # Crear el recordatorio en la BD
                        reminder = ShiftReminder.objects.create(
                            shift=shift,
                            user=user,
                            reminder_time=reminder_data['time'],
                            reminder_type=reminder_data['type']
                        )
                        created_count += 1
                        
                        logger.info(f"✅ Recordatorio {reminder.id} creado en BD:")
                        logger.info(f"   - Tipo: {reminder.reminder_type}")
                        logger.info(f"   - Hora: {reminder.reminder_time.strftime('%Y-%m-%d %H:%M %Z')}")
                        
                        # ✅ Programar la tarea Celery
                        try:
                            from notificacion.tasks import send_shift_reminder_task
                            
                            # ETA debe ser en la zona horaria de Celery (America/Bogota)
                            # Normalizar el ETA según la configuración de Celery para evitar
                            # desalineos entre la hora local (America/Bogota) y la hora que
                            # interpreta el worker (usualmente UTC).
                            try:
                                # Obtener configuración de Celery
                                celery_enable_utc = getattr(celery_app.conf, 'enable_utc', True)
                            except Exception:
                                celery_enable_utc = True

                            eta_to_use = reminder.reminder_time
                            try:
                                if timezone.is_aware(eta_to_use):
                                    if celery_enable_utc:
                                        # Pasar ETA en UTC (recomendado cuando enable_utc=True)
                                        eta_to_use = eta_to_use.astimezone(pytz.UTC)
                                    else:
                                        # Pasar ETA en la zona que Celery espera (usar TIME_ZONE)
                                        eta_to_use = eta_to_use.astimezone(self.local_tz)
                            except Exception:
                                # Fallback: pasar el valor tal cual
                                pass

                            logger.info(f"⏳ Programando tarea Celery para reminder {reminder.id} con ETA: {eta_to_use} (tz={getattr(eta_to_use, 'tzinfo', None)})")
                            async_result = send_shift_reminder_task.apply_async(
                                args=[reminder.id],
                                eta=eta_to_use
                            )
                            
                            # Guardar el task ID para trazabilidad
                            if hasattr(async_result, 'id'):
                                # Guardar task id solo si el modelo lo soporta (evita errores si falta el campo)
                                if hasattr(reminder, 'celery_task_id'):
                                    reminder.celery_task_id = async_result.id
                                    try:
                                        reminder.save(update_fields=['celery_task_id'])
                                    except Exception:
                                        # En casos raros la DB/migraciones pueden no exponer el campo
                                        logger.warning(f"⚠️ No se pudo guardar celery_task_id en reminder {reminder.id}")
                                else:
                                    logger.info(f"ℹ️ El modelo ShiftReminder no tiene campo 'celery_task_id'; task id: {async_result.id}")
                                logger.info(f"⏳ Tarea Celery programada: {async_result.id}")
                            else:
                                logger.info(f"⏳ Tarea Celery programada (sin task ID)")
                                
                        except Exception as e:
                            logger.warning(f"⚠️ No se pudo programar tarea Celery para recordatorio {reminder.id}: {e}")
                            logger.warning(f"   El recordatorio quedó en BD y será procesado por check_pending_reminders")
                            
                    except Exception as e:
                        failed_count += 1
                        logger.exception(f"❌ Error creando recordatorio {reminder_data['type']}: {e}")

                logger.info(f"✅ Resumen: {created_count} recordatorios creados, {failed_count} fallidos para turno {shift.id}")
            else:
                logger.warning(f"⚠️ No se programaron recordatorios (todos los tiempos ya pasaron)")
            
        except Exception as e:
            logger.error(f"❌ Error crítico programando recordatorios para turno {shift.id}: {str(e)}", exc_info=True)

    def send_scheduled_reminders(self):
        """
        ✅ FINAL: Envía recordatorios pendientes comparando con hora local
        Llamado por la tarea periódica check_pending_reminders
        """
        try:
            now_local = timezone.localtime()  # Hora actual en America/Bogota
            
            logger.info(f"🔍 [Recordatorios] Verificando pendientes:")
            logger.info(f"   - Hora local: {now_local.strftime('%Y-%m-%d %H:%M:%S %Z')}")
            
            from shifts.models import ShiftReminder
            
            # ✅ Buscar recordatorios pendientes
            # reminder_time está en America/Bogota (aware), comparar con now_local
            reminders = ShiftReminder.objects.filter(
                sent=False
            ).select_related('shift', 'user', 'shift__shift_type', 'shift__employee')
            
            # Filtrar manualmente los que ya pasaron su hora
            pending_reminders = []
            for reminder in reminders:
                # Asegurar que reminder_time esté en la zona horaria correcta
                reminder_time_local = reminder.reminder_time
                if timezone.is_aware(reminder_time_local):
                    reminder_time_local = reminder_time_local.astimezone(self.local_tz)
                
                if reminder_time_local <= now_local:
                    pending_reminders.append(reminder)
            
            logger.info(f"📋 Recordatorios pendientes encontrados: {len(pending_reminders)}")

            sent_count = 0
            failed_count = 0
            
            for reminder in pending_reminders:
                try:
                    reminder_time_local = reminder.reminder_time.astimezone(self.local_tz)
                    
                    logger.info(f"📨 Procesando recordatorio {reminder.id}:")
                    logger.info(f"   - Usuario: {reminder.user.email}")
                    logger.info(f"   - Tipo: {reminder.reminder_type}")
                    logger.info(f"   - Programado: {reminder_time_local.strftime('%Y-%m-%d %H:%M %Z')}")
                    
                    # ✅ Enviar notificación
                    notification = self.notify_shift_reminder(
                        reminder.shift,
                        reminder.user,
                        reminder.reminder_type
                    )

                    if notification is None:
                        logger.error(f"❌ notify_shift_reminder retornó None para recordatorio {reminder.id}")
                        failed_count += 1
                        continue

                    # ✅ Verificar preferencias de email
                    prefs = NotificationPreference.objects.filter(user=reminder.user).first()
                    email_required = prefs.email_shift_reminder if prefs else False

                    # ✅ Marcar como enviado si el panel fue exitoso
                    # (Incluso si el email falló, para evitar bloqueos)
                    if email_required and not getattr(notification, 'email_sent', False):
                        logger.warning(f"⚠️ Email falló para recordatorio {reminder.id}, pero marcando como enviado")
                    
                    reminder.sent = True
                    reminder.save(update_fields=['sent'])
                    sent_count += 1
                    logger.info(f"✅ Recordatorio {reminder.id} procesado exitosamente")

                except Exception as e:
                    logger.error(f"❌ Error procesando recordatorio {reminder.id}: {str(e)}", exc_info=True)
                    failed_count += 1
                    continue

            logger.info(f"📨 Resumen: {sent_count} enviados, {failed_count} fallidos de {len(pending_reminders)} pendientes")
            return sent_count
            
        except Exception as e:
            logger.error(f"❌ Error crítico en send_scheduled_reminders: {str(e)}", exc_info=True)
            return 0
    
    def cancel_shift_reminders(self, shift):
        """Cancela recordatorios programados"""
        try:
            from shifts.models import ShiftReminder
            deleted_count, _ = ShiftReminder.objects.filter(shift=shift).delete()
            logger.info(f"🗑️ Recordatorios cancelados para turno {shift.id}: {deleted_count}")
            return deleted_count
        except Exception as e:
            logger.error(f"❌ Error cancelando recordatorios: {str(e)}")
            return 0
    
    def reschedule_shift_reminders(self, shift):
        """Reprograma recordatorios cuando se modifica un turno"""
        try:
            logger.info(f"🔄 Reprogramando recordatorios para turno {shift.id}")
            self.cancel_shift_reminders(shift)
            self.schedule_shift_reminders(shift)
            logger.info(f"✅ Recordatorios reprogramados para turno {shift.id}")
        except Exception as e:
            logger.error(f"❌ Error reprogramando recordatorios: {str(e)}")

    # ============================================
    # MÉTODOS ESPECÍFICOS DE NOTIFICACIÓN
    # ============================================
    
    def notify_shift_assigned(self, shift, user):
        """Notifica cuando se asigna un turno"""
        title = "Nuevo Turno Asignado"
        message = f"Se te ha asignado un turno para el {shift.date.strftime('%d/%m/%Y')} de {shift.start_time.strftime('%H:%M')} a {shift.end_time.strftime('%H:%M')}."
        
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
        
        shift_datetime_naive = datetime.combine(shift.date, shift.start_time)
        shift_datetime_local = self.local_tz.localize(shift_datetime_naive)
        now_local = timezone.now().astimezone(self.local_tz)
        
        if reminder_type == '1_hour':
            time_text = "en 1 hora"
        elif reminder_type == '30_min':
            time_text = "en 30 minutos"
        else:
            hours_until = (shift_datetime_local - now_local).total_seconds() / 3600
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
        """Notifica a gerentes cuando se crea una solicitud"""
        title = "Nueva Solicitud de Cambio"
    
        requester_name = "Empleado desconocido"
        if request.requesting_employee and request.requesting_employee.user:
            requester_name = request.requesting_employee.user.get_full_name() or request.requesting_employee.user.email
    
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