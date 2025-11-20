import os
import logging
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, To, From, Category
import secrets

logger = logging.getLogger(__name__)

class EmailService:
    def __init__(self):
        api_key = os.environ.get('SENDGRID_API_KEY')
        if not api_key:
            logger.error("SENDGRID_API_KEY no encontrada en variables de entorno")
            raise ValueError("SENDGRID_API_KEY no configurada")
        
        self.sg = SendGridAPIClient(api_key)
        self.from_email = os.environ.get('EMAIL_FROM', 'soporteshiftscheduler1@gmail.com')
        self.frontend_url = os.environ.get('FRONTEND_URL', 'https://shiftscheduler1.vercel.app')
        logger.info(f"EmailService inicializado con from_email: {self.from_email}")
    
    def send_password_reset_email(self, to_email, reset_token, user_name=None, uid=None):
        """
        Envía email de recuperación de contraseña - OPTIMIZADO CONTRA SPAM
        """
        try:
            # Prefer frontend-specific PASSWORD_RESET_CONFIRM_FRONTEND_URL if set in env
            base = os.environ.get('PASSWORD_RESET_CONFIRM_FRONTEND_URL') or self.frontend_url

            if uid:
                reset_url = f"{base}?uid={uid}&token={reset_token}"
            else:
                reset_url = f"{base}/reset-password/confirm?token={reset_token}"
            
            # Plantilla HTML mejorada para deliverability
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
                        <p>© 2025 Shift Scheduler - Desarrollado por Casi Tech</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            # Contenido de texto plano (IMPORTANTE para evitar spam)
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
            
            # Crear mensaje SIN categorías problemáticas
            message = Mail(
                from_email=From(self.from_email, "Shift Scheduler"),
                to_emails=To(to_email),
                subject="Restablecimiento de contraseña - Shift Scheduler",
                html_content=html_content,
                plain_text_content=plain_content
            )
            
            # NO usar categorías hasta que el dominio esté verificado
            # message.add_category(Category("password_reset"))
            
            # Enviar email
            response = self.sg.send(message)
            
            logger.info(f"✓ Email de recuperación enviado a {to_email}. Status: {response.status_code}")
            
            return response.status_code == 202
            
        except Exception as e:
            logger.error(f"❌ Error enviando email de recuperación a {to_email}: {str(e)}", exc_info=True)
            return False
    
    def send_password_updated_email(self, to_email, user_name=None):
        """
        Envía email confirmando actualización de contraseña
        """
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
            
            message = Mail(
                from_email=From(self.from_email, "Shift Scheduler"),
                to_emails=To(to_email),
                subject="Contraseña actualizada - Shift Scheduler",
                html_content=html_content,
                plain_text_content=plain_content
            )
            
            response = self.sg.send(message)
            logger.info(f"✓ Email de confirmación enviado a {to_email}. Status: {response.status_code}")
            return response.status_code == 202
            
        except Exception as e:
            logger.error(f"❌ Error enviando email de confirmación a {to_email}: {str(e)}")
            return False

    def send_notification_email(self, to_email, subject, plain_text_content, html_content=None):
        """
        Envía un email genérico para notificaciones del sistema.
        """
        try:
            if html_content is None:
                html_content = f"<pre>{plain_text_content}</pre>"

            message = Mail(
                from_email=From(self.from_email, "Shift Scheduler"),
                to_emails=To(to_email),
                subject=subject,
                html_content=html_content,
                plain_text_content=plain_text_content
            )

            response = self.sg.send(message)
            logger.info(f"✓ Email de notificación enviado a {to_email}. Status: {response.status_code}")
            return response.status_code == 202

        except Exception as e:
            logger.error(f"❌ Error enviando email de notificación a {to_email}: {str(e)}", exc_info=True)
            return False

# Instancia global
email_service = None

def get_email_service():
    global email_service
    if email_service is None:
        email_service = EmailService()
    return email_service

def generate_reset_token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)