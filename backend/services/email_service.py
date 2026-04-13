import os
import logging
from django.conf import settings
from django.core.mail import EmailMultiAlternatives

logger = logging.getLogger(__name__)

class EmailService:
    def __init__(self):
        self.from_email = (
            os.environ.get('EMAIL_FROM') or 
            os.environ.get('DEFAULT_FROM_EMAIL') or 
            getattr(settings, "DEFAULT_FROM_EMAIL", "soporteshiftscheduler1@gmail.com")
        )
        self.frontend_url = os.environ.get('FRONTEND_URL', 'https://shiftscheduler1.vercel.app')
        logger.info(f"✅ EmailService SMTP inicializado (from: {self.from_email})")

    def send_password_reset_email(self, to_email, reset_token, user_name=None, uid=None):
        try:
            base = os.environ.get('PASSWORD_RESET_CONFIRM_FRONTEND_URL') or self.frontend_url
            if uid:
                reset_url = f"{base}?uid={uid}&token={reset_token}"
            else:
                reset_url = f"{base}/reset-password/confirm?token={reset_token}"

            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Restablecer Contraseña</title>
            </head>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 20px; background-color: #f4f4f4;">
                <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <div style="background: #007bff; color: white; padding: 30px 20px; text-align: center;">
                        <h1 style="margin: 0; font-size: 24px;">Shift Scheduler</h1>
                    </div>
                    <div style="padding: 30px 20px;">
                        <h2 style="color: #333; margin-top: 0;">Hola {user_name or 'Usuario'},</h2>
                        <p>Recibimos una solicitud para restablecer la contraseña de tu cuenta.</p>
                        
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="{reset_url}" style="display: inline-block; padding: 14px 28px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; font-weight: bold;">
                                Restablecer Contraseña
                            </a>
                        </div>
                        
                        <p>Si el botón no funciona, copia y pega este enlace:</p>
                        <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
                            <a href="{reset_url}" style="color: #007bff; word-break: break-all;">{reset_url}</a>
                        </div>
                        
                        <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 12px; margin: 20px 0;">
                            <strong>⚠️ Importante:</strong> Este enlace expira en 1 hora.
                        </div>
                        
                        <p style="color: #666; font-size: 14px;">
                            Si no solicitaste este cambio, ignora este email.
                        </p>
                    </div>
                    <div style="padding: 20px; text-align: center; font-size: 12px; color: #666; background: #f8f9fa;">
                        <p>© 2025 Shift Scheduler</p>
                    </div>
                </div>
            </body>
            </html>
            """

            plain_content = f"""
Recuperación de Contraseña - Shift Scheduler

Hola {user_name or 'Usuario'},

Recibimos una solicitud para restablecer tu contraseña.

Haz clic aquí: {reset_url}

Este enlace expira en 1 hora.

Si no solicitaste este cambio, ignora este email.

---
Shift Scheduler
            """

            msg = EmailMultiAlternatives(
                subject="Restablecimiento de contraseña - Shift Scheduler",
                body=plain_content,
                from_email=self.from_email,
                to=[to_email]
            )
            msg.attach_alternative(html_content, "text/html")
            msg.send()
            logger.info(f"✅ Email de recuperación enviado a {to_email}")
            return True
        except Exception as e:
            logger.error(f"❌ Error enviando email de recuperación a {to_email}: {str(e)}", exc_info=True)
            return False

    def send_password_updated_email(self, to_email, user_name=None):
        try:
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Contraseña Actualizada</title>
            </head>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 20px; background-color: #f4f4f4;">
                <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <div style="background: #28a745; color: white; padding: 30px 20px; text-align: center;">
                        <h1 style="margin: 0; font-size: 24px;">Contraseña Actualizada</h1>
                    </div>
                    <div style="padding: 30px 20px;">
                        <div style="text-align: center; font-size: 48px; margin: 20px 0;">✅</div>
                        <h2 style="color: #333; margin-top: 0;">Hola {user_name or 'Usuario'},</h2>
                        <p>Tu contraseña ha sido <strong>actualizada correctamente</strong>.</p>
                        
                        <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0;">
                            <strong>⚠️ ¿No fuiste tú?</strong><br>
                            Si no realizaste este cambio, contacta con soporte inmediatamente.
                        </div>
                    </div>
                    <div style="padding: 20px; text-align: center; font-size: 12px; color: #666; background: #f8f9fa;">
                        <p>© 2025 Shift Scheduler</p>
                    </div>
                </div>
            </body>
            </html>
            """

            plain_content = f"""
Contraseña Actualizada - Shift Scheduler

Hola {user_name or 'Usuario'},

Tu contraseña ha sido actualizada correctamente.

¿No fuiste tú? Contacta con soporte inmediatamente.

---
Shift Scheduler
            """

            msg = EmailMultiAlternatives(
                subject="Contraseña actualizada - Shift Scheduler",
                body=plain_content,
                from_email=self.from_email,
                to=[to_email]
            )
            msg.attach_alternative(html_content, "text/html")
            msg.send()
            logger.info(f"✅ Email de confirmación enviado a {to_email}")
            return True
        except Exception as e:
            logger.error(f"❌ Error enviando confirmación a {to_email}: {str(e)}", exc_info=True)
            return False

    def send_notification_email(self, to_email, subject, plain_text_content, html_content=None):
        try:
            if html_content is None:
                html_content = f"<pre>{plain_text_content}</pre>"

            msg = EmailMultiAlternatives(
                subject=subject,
                body=plain_text_content,
                from_email=self.from_email,
                to=[to_email]
            )
            msg.attach_alternative(html_content, "text/html")
            msg.send()
            logger.info(f"✅ Notificación enviada a {to_email}")
            return True
        except Exception as e:
            logger.error(f"❌ Error enviando notificación a {to_email}: {str(e)}", exc_info=True)
            return False

    def send_shift_reminder_email(self, to_email, user_name, shift_date, start_time, end_time, shift_details=None):
        try:
            formatted_date = shift_date.strftime("%d/%m/%Y")
            formatted_start = start_time.strftime("%H:%M")
            formatted_end = end_time.strftime("%H:%M")

            if shift_details:
                details_block = f"""
                        <div style="display: flex; align-items: center; margin-bottom: 10px;">
                            <span style="background: #6f42c1; color: white; border-radius: 50%; width: 30px; height: 30px; display: flex; align-items: center; justify-content: center; margin-right: 10px;">📋</span>
                            <strong>Detalles:</strong> {shift_details}
                        </div>
                """
            else:
                details_block = ""

            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Recordatorio de Turno</title>
            </head>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 20px; background-color: #f4f4f4;">
                <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <div style="background: #ff9800; color: white; padding: 30px 20px; text-align: center;">
                        <h1 style="margin: 0; font-size: 24px;">⏰ Recordatorio de Turno</h1>
                    </div>
                    <div style="padding: 30px 20px;">
                        <h2 style="color: #333; margin-top: 0;">Hola {user_name},</h2>
                        <p>Este es un recordatorio de tu próximo turno:</p>

                        <div style="background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 8px; padding: 20px; margin: 20px 0;">
                            <div style="display: flex; align-items: center; margin-bottom: 10px;">
                                <span style="background: #007bff; color: white; border-radius: 50%; width: 30px; height: 30px; display: flex; align-items: center; justify-content: center; margin-right: 10px;">📅</span>
                                <strong>Fecha:</strong> {formatted_date}
                            </div>
                            <div style="display: flex; align-items: center; margin-bottom: 10px;">
                                <span style="background: #28a745; color: white; border-radius: 50%; width: 30px; height: 30px; display: flex; align-items: center; justify-content: center; margin-right: 10px;">⏰</span>
                                <strong>Horario:</strong> {formatted_start} - {formatted_end}
                            </div>
                            {details_block}
                        </div>

                        <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0;">
                            <strong>💡 Recordatorio:</strong> Tu turno comienza pronto. Por favor asegúrate de estar disponible.
                        </div>
                    </div>
                    <div style="padding: 20px; text-align: center; font-size: 12px; color: #666; background: #f8f9fa;">
                        <p>© 2025 Shift Scheduler</p>
                    </div>
                </div>
            </body>
            </html>
            """

            plain_content_lines = [
                "Recordatorio de Turno - Shift Scheduler",
                "",
                f"Hola {user_name},",
                "",
                "Este es un recordatorio de tu próximo turno:",
                "",
                f"📅 Fecha: {formatted_date}",
                f"⏰ Horario: {formatted_start} - {formatted_end}",
            ]
            if shift_details:
                plain_content_lines.append(f"📋 Detalles: {shift_details}")
            plain_content_lines.extend([
                "",
                "💡 Tu turno comienza pronto. Por favor asegúrate de estar disponible.",
                "",
                "---",
                "Shift Scheduler"
            ])
            plain_content = "\n".join(plain_content_lines)

            msg = EmailMultiAlternatives(
                subject=f"⏰ Recordatorio de turno para el {formatted_date}",
                body=plain_content,
                from_email=self.from_email,
                to=[to_email]
            )
            msg.attach_alternative(html_content, "text/html")
            msg.send()
            logger.info(f"✅ Recordatorio de turno enviado a {to_email}")
            return True
        except Exception as e:
            logger.error(f"❌ Error enviando recordatorio a {to_email}: {str(e)}", exc_info=True)
            return False

# Instancia global
email_service = None

def get_email_service():
    global email_service
    if email_service is None:
        email_service = EmailService()
    return email_service