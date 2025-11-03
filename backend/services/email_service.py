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
        # ✅ CORRECCIÓN: Usar el mismo email que está en Railway
        self.from_email = os.environ.get('EMAIL_FROM', 'soporteshiftscheduler1@gmail.com')
        self.frontend_url = os.environ.get('FRONTEND_URL', 'https://shiftscheduler1.vercel.app')
        logger.info(f"EmailService inicializado con from_email: {self.from_email}")
    
    def send_password_reset_email(self, to_email, reset_token, user_name=None):
        """
        Envía email de recuperación de contraseña
        """
        try:
            # Construir la URL de reset
            reset_url = f"{self.frontend_url}/reset-password/config.html?token={reset_token}"
            
            # Plantilla HTML
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <style>
                    body {{ 
                        font-family: Arial, sans-serif; 
                        line-height: 1.6; 
                        color: #333;
                        margin: 0;
                        padding: 0;
                        background-color: #f4f4f4;
                    }}
                    .container {{ 
                        max-width: 600px; 
                        margin: 20px auto; 
                        background-color: #ffffff;
                        border-radius: 8px;
                        overflow: hidden;
                        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    }}
                    .header {{ 
                        background: linear-gradient(135deg, #007bff 0%, #0056b3 100%);
                        color: white; 
                        padding: 30px 20px; 
                        text-align: center;
                    }}
                    .header h1 {{
                        margin: 0;
                        font-size: 24px;
                        font-weight: 600;
                    }}
                    .content {{ 
                        padding: 30px 20px;
                        background: #ffffff;
                    }}
                    .content h2 {{
                        color: #333;
                        font-size: 20px;
                        margin-top: 0;
                    }}
                    .content p {{
                        margin: 15px 0;
                        color: #555;
                    }}
                    .button {{ 
                        display: inline-block; 
                        padding: 14px 28px; 
                        background: #007bff;
                        color: white !important; 
                        text-decoration: none; 
                        border-radius: 5px;
                        font-weight: 600;
                        margin: 20px 0;
                        transition: background 0.3s ease;
                    }}
                    .button:hover {{
                        background: #0056b3;
                    }}
                    .url-box {{
                        background: #f8f9fa;
                        padding: 15px;
                        border-radius: 5px;
                        border-left: 4px solid #007bff;
                        margin: 20px 0;
                        word-break: break-all;
                    }}
                    .url-box a {{
                        color: #007bff;
                        text-decoration: none;
                    }}
                    .warning {{
                        background: #fff3cd;
                        border-left: 4px solid #ffc107;
                        padding: 12px;
                        margin: 20px 0;
                        border-radius: 4px;
                    }}
                    .footer {{ 
                        padding: 20px; 
                        text-align: center; 
                        font-size: 12px; 
                        color: #666;
                        background: #f8f9fa;
                        border-top: 1px solid #e9ecef;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔐 Recuperación de Contraseña</h1>
                    </div>
                    <div class="content">
                        <h2>Hola {user_name or 'Usuario'},</h2>
                        <p>Hemos recibido una solicitud para restablecer la contraseña de tu cuenta en <strong>Shift Scheduler</strong>.</p>
                        <p>Haz clic en el botón de abajo para crear una nueva contraseña:</p>
                        
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="{reset_url}" class="button">Restablecer Contraseña</a>
                        </div>
                        
                        <p>Si el botón no funciona, copia y pega este enlace en tu navegador:</p>
                        <div class="url-box">
                            <a href="{reset_url}">{reset_url}</a>
                        </div>
                        
                        <div class="warning">
                            <strong>⚠️ Importante:</strong> Este enlace expirará en <strong>1 hora</strong> por razones de seguridad.
                        </div>
                        
                        <p style="margin-top: 30px; color: #666; font-size: 14px;">
                            Si no solicitaste este cambio, puedes ignorar este correo de forma segura. Tu contraseña no cambiará.
                        </p>
                    </div>
                    <div class="footer">
                        <p style="margin: 5px 0;">© 2025 Shift Scheduler - Todos los derechos reservados</p>
                        <p style="margin: 5px 0; color: #999;">Desarrollado por: Casi Tech - Grupo 9 AyD</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            # Contenido de texto plano
            plain_content = f"""
Recuperación de Contraseña - Shift Scheduler

Hola {user_name or 'Usuario'},

Hemos recibido una solicitud para restablecer la contraseña de tu cuenta.

Haz clic en el siguiente enlace para crear una nueva contraseña:
{reset_url}

⚠️ IMPORTANTE: Este enlace expirará en 1 hora por razones de seguridad.

Si no solicitaste este cambio, puedes ignorar este correo de forma segura.

---
© 2025 Shift Scheduler - Todos los derechos reservados
Desarrollado por: Casi Tech - Grupo 9 AyD
            """
            
            # Crear el mensaje
            message = Mail(
                from_email=From(self.from_email, "Shift Scheduler"),
                to_emails=To(to_email),
                subject="Recuperación de Contraseña - Shift Scheduler",
                html_content=html_content,
                plain_text_content=plain_content
            )
            
            # Enviar el email
            response = self.sg.send(message)
            
            # Log de éxito
            logger.info(f"✓ Email de recuperación enviado a {to_email}. Status: {response.status_code}")
            
            if response.status_code == 202:
                return True
            else:
                logger.warning(f"Código de respuesta inusual: {response.status_code}")
                return False
            
        except Exception as e:
            logger.error(f"❌ Error enviando email de recuperación a {to_email}: {str(e)}", exc_info=True)
            return False
    
    def send_password_updated_email(self, to_email, user_name=None):
        """
        Envía email confirmando que la contraseña fue actualizada
        """
        try:
            # Plantilla HTML
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <style>
                    body {{ 
                        font-family: Arial, sans-serif; 
                        line-height: 1.6; 
                        color: #333;
                        margin: 0;
                        padding: 0;
                        background-color: #f4f4f4;
                    }}
                    .container {{ 
                        max-width: 600px; 
                        margin: 20px auto; 
                        background-color: #ffffff;
                        border-radius: 8px;
                        overflow: hidden;
                        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    }}
                    .header {{ 
                        background: linear-gradient(135deg, #28a745 0%, #20833b 100%);
                        color: white; 
                        padding: 30px 20px; 
                        text-align: center;
                    }}
                    .header h1 {{
                        margin: 0;
                        font-size: 24px;
                        font-weight: 600;
                    }}
                    .content {{ 
                        padding: 30px 20px;
                        background: #ffffff;
                    }}
                    .content p {{
                        margin: 15px 0;
                        color: #555;
                    }}
                    .success-icon {{
                        text-align: center;
                        font-size: 48px;
                        margin: 20px 0;
                    }}
                    .alert {{
                        background: #fff3cd;
                        border-left: 4px solid #ffc107;
                        padding: 15px;
                        margin: 20px 0;
                        border-radius: 4px;
                    }}
                    .footer {{ 
                        padding: 20px; 
                        text-align: center; 
                        font-size: 12px; 
                        color: #666;
                        background: #f8f9fa;
                        border-top: 1px solid #e9ecef;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>✅ Contraseña Actualizada</h1>
                    </div>
                    <div class="content">
                        <div class="success-icon">🔒</div>
                        <p><strong>Hola {user_name or 'Usuario'},</strong></p>
                        <p>Te confirmamos que tu contraseña ha sido <strong>actualizada correctamente</strong> en Shift Scheduler.</p>
                        
                        <div class="alert">
                            <strong>⚠️ ¿No fuiste tú?</strong><br>
                            Si no realizaste este cambio, te recomendamos:
                            <ul style="margin: 10px 0;">
                                <li>Restablecer tu contraseña inmediatamente</li>
                                <li>Contactar con nuestro equipo de soporte</li>
                            </ul>
                        </div>
                        
                        <p style="margin-top: 30px; color: #666;">
                            Gracias por usar Shift Scheduler. Si tienes alguna pregunta, no dudes en contactarnos.
                        </p>
                    </div>
                    <div class="footer">
                        <p style="margin: 5px 0;">© 2025 Shift Scheduler - Todos los derechos reservados</p>
                        <p style="margin: 5px 0; color: #999;">Desarrollado por: Casi Tech - Grupo 9 AyD</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            # Contenido de texto plano
            plain_content = f"""
Contraseña Actualizada - Shift Scheduler

Hola {user_name or 'Usuario'},

Te confirmamos que tu contraseña ha sido actualizada correctamente.

⚠️ ¿NO FUISTE TÚ?
Si no realizaste este cambio, te recomendamos restablecer tu contraseña inmediatamente y contactar con nuestro equipo de soporte.

Gracias por usar Shift Scheduler.

---
© 2025 Shift Scheduler - Todos los derechos reservados
Desarrollado por: Casi Tech - Grupo 9 AyD
            """
            
            # Crear el mensaje
            message = Mail(
                from_email=From(self.from_email, "Shift Scheduler"),
                to_emails=To(to_email),
                subject="Contraseña Actualizada - Shift Scheduler",
                html_content=html_content,
                plain_text_content=plain_content
            )
            
            # Enviar el email
            response = self.sg.send(message)
            
            # Log de éxito
            logger.info(f"✓ Email de confirmación enviado a {to_email}. Status: {response.status_code}")
            
            if response.status_code == 202:
                return True
            else:
                logger.warning(f"Código de respuesta inusual: {response.status_code}")
                return False
            
        except Exception as e:
            logger.error(f"❌ Error enviando email de confirmación a {to_email}: {str(e)}", exc_info=True)
            return False

# Instancia global del servicio de email
email_service = None

def get_email_service():
    """
    Obtiene o crea la instancia del servicio de email
    """
    global email_service
    if email_service is None:
        email_service = EmailService()
    return email_service