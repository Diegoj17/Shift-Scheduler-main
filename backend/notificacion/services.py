# notificacion/services.py - VERSIÓN CORREGIDA
import logging
from django.conf import settings
from django.utils import timezone
from .models import Notification, NotificationPreference
from services.email_service import get_email_service

logger = logging.getLogger(__name__)

class NotificationService:
    """
    Servicio centralizado para crear y enviar notificaciones
    ✅ Usa el mismo EmailService que funciona para recuperación de contraseña
    """
    
    def __init__(self):
        # Usar el servicio de email que ya sabemos que funciona
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
            
            # Enviar email si está habilitado - USANDO EL SERVICIO QUE SÍ FUNCIONA
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
            'request_approved': preferences.email_request_response,
            'request_rejected': preferences.email_request_response,
        }
        return mapping.get(notification_type, True)
    
    def _send_notification_email(self, user, notification_type, title, message, related_shift=None):
        """Envía el email de notificación usando el EmailService que SÍ funciona"""
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
                'request_approved': '#28a745',
                'request_rejected': '#dc3545',
            }
            header_color = color_map.get(notification_type, '#007bff')
            
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
                            <a href="{getattr(settings, 'FRONTEND_URL', '')}/mi-calendario" style="display: inline-block; padding: 14px 28px; background: {header_color}; color: white; text-decoration: none; border-radius: 5px; font-weight: bold;">
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
            
            # ✅ USAR EL MISMO SERVICIO QUE FUNCIONA PARA RECUPERACIÓN
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
    # MÉTODOS ESPECÍFICOS PARA CADA TIPO DE NOTIFICACIÓN
    # ✅ Adaptados para trabajar con Employee -> User
    # ============================================
    
    def notify_shift_assigned(self, shift, user):
        """Notifica cuando se asigna un turno"""
        title = "Nuevo Turno Asignado"
        message = f"Se te ha asignado un turno para el {shift.date.strftime('%d/%m/%Y')} de {shift.start_time.strftime('%H:%M')} a {shift.end_time.strftime('%H:%M')}."
        
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
        
        return self.create_notification(
            user=user,
            notification_type='shift_cancelled',
            title=title,
            message=message,
            icon='warning',
            related_shift=shift,
            send_email=True
        )
    
    def notify_shift_reminder(self, shift, user):
        """Envía recordatorio de turno próximo"""
        from datetime import datetime
        
        title = "Recordatorio de Turno"
        
        # Calcular horas hasta el turno
        shift_datetime = datetime.combine(shift.date, shift.start_time)
        now = datetime.now()
        hours_until = (shift_datetime - now).total_seconds() / 3600
        
        message = f"Recordatorio: Tu turno comienza en {int(hours_until)} horas. Fecha: {shift.date.strftime('%d/%m/%Y')} a las {shift.start_time.strftime('%H:%M')}."
        
        return self.create_notification(
            user=user,
            notification_type='shift_reminder',
            title=title,
            message=message,
            icon='clock',
            related_shift=shift,
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