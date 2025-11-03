import os
import logging
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, To, From, ReplyTo, Header
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
    
    def send_password_reset_email(self, to_email, reset_token, user_name=None):
        """
        Envía email de recuperación de contraseña
        OPTIMIZADO PARA EVITAR SPAM
        """
        try:
            reset_url = f"{self.frontend_url}/reset-password/confirm?token={reset_token}"
            
            # HTML optimizado para deliverability
            html_content = f"""
            <!DOCTYPE html>
            <html lang="es">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Restablecimiento de contraseña</title>
            </head>
            <body style="font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333333; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f5f5f5;">
                
                <!-- Container Principal -->
                <div style="background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    
                    <!-- Header -->
                    <div style="background: linear-gradient(135deg, #3498db 0%, #2980b9 100%); padding: 30px; text-align: center;">
                        <h1 style="color: #ffffff; margin: 0; font-size: 24px; font-weight: 600;">Shift Scheduler</h1>
                    </div>
                    
                    <!-- Contenido -->
                    <div style="padding: 40px 30px;">
                        
                        <h2 style="color: #2c3e50; margin-top: 0; margin-bottom: 20px; font-size: 20px; font-weight: 600;">
                            Restablecimiento de contraseña
                        </h2>
                        
                        <p style="margin: 15px 0; color: #555555; font-size: 15px;">
                            Hola {user_name or 'Usuario'},
                        </p>
                        
                        <p style="margin: 15px 0; color: #555555; font-size: 15px;">
                            Hemos recibido una solicitud para restablecer la contraseña de tu cuenta en Shift Scheduler. 
                            Si no realizaste esta solicitud, puedes ignorar este correo de forma segura.
                        </p>
                        
                        <p style="margin: 15px 0; color: #555555; font-size: 15px;">
                            Para continuar con el restablecimiento de tu contraseña, haz clic en el siguiente botón:
                        </p>
                        
                        <!-- Botón CTA -->
                        <div style="text-align: center; margin: 35px 0;">
                            <a href="{reset_url}" 
                               style="display: inline-block; 
                                      padding: 15px 35px; 
                                      background-color: #3498db; 
                                      color: #ffffff !important; 
                                      text-decoration: none; 
                                      border-radius: 5px; 
                                      font-weight: 600;
                                      font-size: 16px;
                                      box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                                Restablecer mi contraseña
                            </a>
                        </div>
                        
                        <!-- Enlace alternativo -->
                        <div style="background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin: 25px 0;">
                            <p style="margin: 0 0 10px 0; font-size: 14px; color: #666666;">
                                Si el botón no funciona, copia y pega el siguiente enlace en tu navegador:
                            </p>
                            <p style="margin: 0; word-break: break-all; font-size: 13px;">
                                <a href="{reset_url}" style="color: #3498db; text-decoration: none;">{reset_url}</a>
                            </p>
                        </div>
                        
                        <!-- Información importante -->
                        <div style="background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 25px 0; border-radius: 4px;">
                            <p style="margin: 0; font-size: 14px; color: #856404;">
                                <strong>Nota importante:</strong> Este enlace es válido por 1 hora. 
                                Si expira, puedes solicitar uno nuevo desde nuestra página de inicio de sesión.
                            </p>
                        </div>
                        
                        <!-- Soporte -->
                        <p style="margin: 30px 0 10px 0; font-size: 14px; color: #666666;">
                            Si tienes alguna pregunta o necesitas ayuda, no dudes en contactarnos 
                            respondiendo a este correo.
                        </p>
                        
                        <p style="margin: 25px 0 0 0; font-size: 15px; color: #555555;">
                            Saludos cordiales,<br>
                            <strong style="color: #2c3e50;">El equipo de Shift Scheduler</strong>
                        </p>
                        
                    </div>
                    
                    <!-- Footer -->
                    <div style="background-color: #f8f9fa; padding: 25px 30px; border-top: 1px solid #e9ecef;">
                        <p style="margin: 5px 0; font-size: 12px; color: #999999; text-align: center;">
                            © 2025 Shift Scheduler. Todos los derechos reservados.
                        </p>
                        <p style="margin: 5px 0; font-size: 12px; color: #999999; text-align: center;">
                            Desarrollado por Casi Tech - Grupo 9 AyD
                        </p>
                        <p style="margin: 15px 0 5px 0; font-size: 11px; color: #aaaaaa; text-align: center;">
                            Este correo fue enviado a {to_email} porque solicitaste restablecer tu contraseña.
                        </p>
                    </div>
                    
                </div>
                
            </body>
            </html>
            """
            
            # Texto plano COMPLETO y bien formateado (crítico para deliverability)
            plain_content = f"""
SHIFT SCHEDULER
Restablecimiento de contraseña

================================================================================

Hola {user_name or 'Usuario'},

Hemos recibido una solicitud para restablecer la contraseña de tu cuenta en 
Shift Scheduler.

Para continuar con el restablecimiento, visita el siguiente enlace:

{reset_url}

NOTA IMPORTANTE: 
Este enlace es válido por 1 hora. Si expira, puedes solicitar uno nuevo 
desde nuestra página de inicio de sesión.

Si no realizaste esta solicitud, puedes ignorar este correo de forma segura. 
Tu contraseña no será modificada.

SOPORTE:
Si tienes alguna pregunta o necesitas ayuda, no dudes en contactarnos 
respondiendo a este correo.

Saludos cordiales,
El equipo de Shift Scheduler

================================================================================

© 2025 Shift Scheduler. Todos los derechos reservados.
Desarrollado por Casi Tech - Grupo 9 AyD

Este correo fue enviado a {to_email} porque solicitaste restablecer tu 
contraseña.
            """
            
            # CORRECCIÓN: Crear el mensaje sin headers problemáticos
            message = Mail(
                from_email=From(self.from_email, "Shift Scheduler"),
                to_emails=To(to_email),
                subject="Restablecimiento de contraseña - Shift Scheduler",
                html_content=html_content,
                plain_text_content=plain_content
            )
            
            # CORRECCIÓN: Agregar reply_to correctamente
            message.reply_to = ReplyTo(self.from_email, "Shift Scheduler")
            
            # CORRECCIÓN: Eliminar headers problemáticos que pueden causar spam
            # En su lugar, usar categorías de SendGrid
            message.add_category("password_reset")
            message.add_category("transactional")
            
            # Enviar
            response = self.sg.send(message)
            
            logger.info(f"✓ Email de recuperación enviado a {to_email}. Status: {response.status_code}")
            
            return response.status_code == 202
            
        except Exception as e:
            logger.error(f"❌ Error enviando email de recuperación a {to_email}: {str(e)}", exc_info=True)
            return False
    
    def send_password_updated_email(self, to_email, user_name=None):
        """
        Envía email confirmando que la contraseña fue actualizada
        OPTIMIZADO PARA EVITAR SPAM
        """
        try:
            html_content = f"""
            <!DOCTYPE html>
            <html lang="es">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Contraseña actualizada</title>
            </head>
            <body style="font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333333; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f5f5f5;">
                
                <div style="background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    
                    <!-- Header -->
                    <div style="background: linear-gradient(135deg, #28a745 0%, #20833b 100%); padding: 30px; text-align: center;">
                        <h1 style="color: #ffffff; margin: 0; font-size: 24px; font-weight: 600;">Shift Scheduler</h1>
                    </div>
                    
                    <!-- Contenido -->
                    <div style="padding: 40px 30px;">
                        
                        <div style="text-align: center; margin-bottom: 25px;">
                            <div style="display: inline-block; width: 60px; height: 60px; background-color: #d4edda; border-radius: 50%; line-height: 60px; font-size: 30px;">
                                ✓
                            </div>
                        </div>
                        
                        <h2 style="color: #2c3e50; margin: 0 0 20px 0; font-size: 20px; font-weight: 600; text-align: center;">
                            Contraseña actualizada correctamente
                        </h2>
                        
                        <p style="margin: 15px 0; color: #555555; font-size: 15px;">
                            Hola {user_name or 'Usuario'},
                        </p>
                        
                        <p style="margin: 15px 0; color: #555555; font-size: 15px;">
                            Te confirmamos que la contraseña de tu cuenta en Shift Scheduler ha sido 
                            actualizada correctamente.
                        </p>
                        
                        <p style="margin: 15px 0; color: #555555; font-size: 15px;">
                            Ahora puedes iniciar sesión con tu nueva contraseña.
                        </p>
                        
                        <!-- Alerta de seguridad -->
                        <div style="background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 25px 0; border-radius: 4px;">
                            <p style="margin: 0 0 10px 0; font-size: 14px; color: #856404;">
                                <strong>¿No fuiste tú?</strong>
                            </p>
                            <p style="margin: 0; font-size: 14px; color: #856404;">
                                Si no realizaste este cambio, te recomendamos restablecer tu contraseña 
                                inmediatamente y contactar con nuestro equipo de soporte.
                            </p>
                        </div>
                        
                        <p style="margin: 30px 0 10px 0; font-size: 14px; color: #666666;">
                            Si tienes alguna pregunta, no dudes en contactarnos respondiendo a este correo.
                        </p>
                        
                        <p style="margin: 25px 0 0 0; font-size: 15px; color: #555555;">
                            Saludos cordiales,<br>
                            <strong style="color: #2c3e50;">El equipo de Shift Scheduler</strong>
                        </p>
                        
                    </div>
                    
                    <!-- Footer -->
                    <div style="background-color: #f8f9fa; padding: 25px 30px; border-top: 1px solid #e9ecef;">
                        <p style="margin: 5px 0; font-size: 12px; color: #999999; text-align: center;">
                            © 2025 Shift Scheduler. Todos los derechos reservados.
                        </p>
                        <p style="margin: 5px 0; font-size: 12px; color: #999999; text-align: center;">
                            Desarrollado por Casi Tech - Grupo 9 AyD
                        </p>
                        <p style="margin: 15px 0 5px 0; font-size: 11px; color: #aaaaaa; text-align: center;">
                            Este es un correo informativo sobre la seguridad de tu cuenta.
                        </p>
                    </div>
                    
                </div>
                
            </body>
            </html>
            """
            
            plain_content = f"""
SHIFT SCHEDULER
Contraseña actualizada correctamente

================================================================================

Hola {user_name or 'Usuario'},

Te confirmamos que la contraseña de tu cuenta en Shift Scheduler ha sido 
actualizada correctamente.

Ahora puedes iniciar sesión con tu nueva contraseña.

¿NO FUISTE TÚ?
Si no realizaste este cambio, te recomendamos restablecer tu contraseña 
inmediatamente y contactar con nuestro equipo de soporte.

SOPORTE:
Si tienes alguna pregunta, no dudes en contactarnos respondiendo a este correo.

Saludos cordiales,
El equipo de Shift Scheduler

================================================================================

© 2025 Shift Scheduler. Todos los derechos reservados.
Desarrollado por Casi Tech - Grupo 9 AyD

Este es un correo informativo sobre la seguridad de tu cuenta.
            """
            
            # CORRECCIÓN: Mismo patrón para el segundo método
            message = Mail(
                from_email=From(self.from_email, "Shift Scheduler"),
                to_emails=To(to_email),
                subject="Contraseña actualizada - Shift Scheduler",
                html_content=html_content,
                plain_text_content=plain_content
            )
            
            # CORRECCIÓN: Agregar reply_to correctamente
            message.reply_to = ReplyTo(self.from_email, "Shift Scheduler")
            
            # CORRECCIÓN: Usar categorías en lugar de headers
            message.add_category("password_updated")
            message.add_category("transactional")
            
            response = self.sg.send(message)
            
            logger.info(f"✓ Email de confirmación enviado a {to_email}. Status: {response.status_code}")
            
            return response.status_code == 202
            
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

def generate_reset_token(length: int = 32) -> str:
    """Genera un token seguro apto para usar en enlaces de restablecimiento."""
    return secrets.token_urlsafe(length)