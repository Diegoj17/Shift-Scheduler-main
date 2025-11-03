import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, To, From
import logging

logger = logging.getLogger(__name__)

class EmailService:
    def __init__(self):
        self.sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
        self.from_email = os.environ.get('EMAIL_FROM', 'noreply@shiftscheduler.com')
        self.frontend_url = os.environ.get('FRONTEND_URL', 'https://shiftschedulerl.vercel.app')
    
    def send_password_reset_email(self, to_email, reset_token, user_name=None):
        """
        Envía email de recuperación de contraseña
        """
        try:
            reset_url = f"{self.frontend_url}/reset-password/config.html?token={reset_token}"
            
            # Plantilla HTML para recuperación de contraseña
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                    .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .header {{ background: #007bff; color: white; padding: 20px; text-align: center; }}
                    .content {{ padding: 20px; background: #f9f9f9; }}
                    .button {{ display: inline-block; padding: 12px 24px; background: #007bff; 
                             color: white; text-decoration: none; border-radius: 4px; margin: 20px 0; }}
                    .footer {{ padding: 20px; text-align: center; font-size: 12px; color: #666; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>Recuperación de Contraseña</h1>
                    </div>
                    <div class="content">
                        <h2>Hola {user_name or 'Usuario'},</h2>
                        <p>Has solicitado restablecer tu contraseña. Haz clic en el siguiente botón para crear una nueva contraseña:</p>
                        
                        <div style="text-align: center;">
                            <a href="{reset_url}" class="button">Restablecer Contraseña</a>
                        </div>
                        
                        <p>Si el botón no funciona, copia y pega este enlace en tu navegador:</p>
                        <p><a href="{reset_url}">{reset_url}</a></p>
                        
                        <p><strong>Este enlace expirará en 1 hora.</strong></p>
                        
                        <p>Si no solicitaste este cambio, puedes ignorar este mensaje.</p>
                    </div>
                    <div class="footer">
                        <p>© 2024 Shift Scheduler. Todos los derechos reservados.</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            # Contenido plano para clientes de email que no soportan HTML
            plain_content = f"""
            Hola {user_name or 'Usuario'},
            
            Has solicitado restablecer tu contraseña. 
            
            Usa el siguiente enlace para crear una nueva contraseña:
            {reset_url}
            
            Este enlace expirará en 1 hora.
            
            Si no solicitaste este cambio, puedes ignorar este mensaje.
            
            Saludos,
            Equipo Shift Scheduler
            """
            
            message = Mail(
                from_email=From(self.from_email, "Shift Scheduler"),
                to_emails=To(to_email),
                subject="Recuperación de Contraseña - Shift Scheduler",
                html_content=html_content,
                plain_text_content=plain_content
            )
            
            response = self.sg.send(message)
            logger.info(f"Email de recuperación enviado a {to_email}. Status: {response.status_code}")
            return True
            
        except Exception as e:
            logger.error(f"Error enviando email de recuperación: {str(e)}")
            return False
    
    def send_password_updated_email(self, to_email, user_name=None):
        """
        Envía email confirmando que la contraseña fue actualizada
        """
        try:
            # Plantilla HTML para contraseña actualizada
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                    .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .header {{ background: #28a745; color: white; padding: 20px; text-align: center; }}
                    .content {{ padding: 20px; background: #f9f9f9; }}
                    .footer {{ padding: 20px; text-align: center; font-size: 12px; color: #666; }}
                    .success-icon {{ font-size: 48px; color: #28a745; margin: 20px 0; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>Contraseña Actualizada</h1>
                    </div>
                    <div class="content" style="text-align: center;">
                        <div class="success-icon">✓</div>
                        <h2>¡Contraseña actualizada exitosamente!</h2>
                        <p>Hola {user_name or 'Usuario'},</p>
                        <p>Tu contraseña ha sido actualizada correctamente.</p>
                        <p>Si no realizaste este cambio, por favor contacta inmediatamente al soporte.</p>
                    </div>
                    <div class="footer">
                        <p>© 2024 Shift Scheduler. Todos los derechos reservados.</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            # Contenido plano
            plain_content = f"""
            Hola {user_name or 'Usuario'},
            
            Tu contraseña ha sido actualizada exitosamente.
            
            Si no realizaste este cambio, por favor contacta inmediatamente al soporte.
            
            Saludos,
            Equipo Shift Scheduler
            """
            
            message = Mail(
                from_email=From(self.from_email, "Shift Scheduler"),
                to_emails=To(to_email),
                subject="Contraseña Actualizada - Shift Scheduler",
                html_content=html_content,
                plain_text_content=plain_content
            )
            
            response = self.sg.send(message)
            logger.info(f"Email de confirmación enviado a {to_email}. Status: {response.status_code}")
            return True
            
        except Exception as e:
            logger.error(f"Error enviando email de confirmación: {str(e)}")
            return False

# Instancia global del servicio de email
email_service = EmailService()