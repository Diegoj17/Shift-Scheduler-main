import os
import logging
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, To, From

logger = logging.getLogger(__name__)

class EmailService:
    def __init__(self):
        api_key = os.environ.get('SENDGRID_API_KEY')
        if not api_key:
            logger.error("SENDGRID_API_KEY no encontrada en variables de entorno")
            raise ValueError("SENDGRID_API_KEY no configurada")
        
        self.sg = SendGridAPIClient(api_key)
        self.from_email = os.environ.get('EMAIL_FROM') or os.environ.get('DEFAULT_FROM_EMAIL', 'soporteshiftscheduleri@gmail.com')
        self.frontend_url = os.environ.get('FRONTEND_URL', 'https://shiftschedulert.vercel.app')
        logger.info(f"EmailService inicializado con: {self.from_email}")
    
    def send_password_reset_email(self, to_email, reset_token, user_name=None):
        """
        Envía email de recuperación de contraseña
        """
        try:
            reset_url = f"{self.frontend_url}/reset-password/config.html?token={reset_token}"
            
            # Usar la plantilla que proporcionaste
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
                        <h1>Recupere la contraseña de tu cuenta</h1>
                    </div>
                    <div class="content">
                        <h2>Hola {user_name or 'Usuario'},</h2>
                        <p>Recupere tu contraseña para poder acceder a la cuenta.</p>
                        <p>Haga clic en el botón de abajo para comenzar.</p>
                        
                        <div style="text-align: center;">
                            <a href="{reset_url}" class="button">Reestablecer Contraseña</a>
                        </div>
                        
                        <p>Si el botón no funciona, copia y pega este enlace en tu navegador:</p>
                        <p><a href="{reset_url}">{reset_url}</a></p>
                        
                        <p><strong>Este enlace expirará en 1 hora.</strong></p>
                    </div>
                    <div class="footer">
                        <p>2025 © Todos los derechos reservados. Desarrollado por: Casi Tech - Grupo 9 AyD</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            plain_content = f"""
            Recupere la contraseña de tu cuenta

            Hola {user_name or 'Usuario'},

            Recupere tu contraseña para poder acceder a la cuenta.
            Haga clic en el enlace para comenzar:

            {reset_url}

            Este enlace expirará en 1 hora.

            2025 © Todos los derechos reservados. Desarrollado por: Casi Tech - Grupo 9 AyD
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
            # Usar la plantilla que proporcionaste
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
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>Tu contraseña ha sido actualizada</h1>
                    </div>
                    <div class="content">
                        <p>Hola {user_name or 'Usuario'},</p>
                        <p>Queremos informarte que tu contraseña ha sido actualizada correctamente.</p>
                        <p>Si no realizaste este cambio, te recomendamos cambiarla nuevamente o contactar con soporte de inmediato.</p>
                    </div>
                    <div class="footer">
                        <p>2025 © Todos los derechos reservados. Desarrollado por: Casi Tech - Grupo 9 AyD</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            plain_content = f"""
            Tu contraseña ha sido actualizada

            Hola {user_name or 'Usuario'},

            Queremos informarte que tu contraseña ha sido actualizada correctamente.

            Si no realizaste este cambio, te recomendamos cambiarla nuevamente o contactar con soporte de inmediato.

            2025 © Todos los derechos reservados. Desarrollado por: Casi Tech - Grupo 9 AyD
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