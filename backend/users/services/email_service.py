import logging
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags

logger = logging.getLogger(__name__)

class EmailService:
    @staticmethod
    def send_password_reset_email(user, reset_token, reset_url):
        """
        Envía email de recuperación de contraseña
        
        Args:
            user: Instancia del usuario
            reset_token: Token de recuperación
            reset_url: URL completa para resetear contraseña
        """
        try:
            subject = "Recuperación de Contraseña - Shift Scheduler"
            
            # Contexto para el template
            context = {
                'user': user,
                'reset_url': reset_url,
                'token': reset_token,
            }
            
            # Renderizar template HTML
            html_message = render_to_string('registration/password_reset_email.html', context)
            plain_message = strip_tags(html_message)
            
            # Enviar email
            send_mail(
                subject=subject,
                message=plain_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                html_message=html_message,
                fail_silently=False,
            )
            
            logger.info(f"Email de recuperación enviado a {user.email}")
            return True
            
        except Exception as e:
            logger.error(f"Error enviando email de recuperación a {user.email}: {str(e)}")
            return False

    @staticmethod
    def send_welcome_email(user, temp_password=None):
        """
        Envía email de bienvenida (opcional)
        """
        try:
            subject = "Bienvenido a Shift Scheduler"
            
            context = {
                'user': user,
                'temp_password': temp_password,
            }
            
            html_message = render_to_string('registration/welcome_email.html', context)
            plain_message = strip_tags(html_message)
            
            send_mail(
                subject=subject,
                message=plain_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                html_message=html_message,
                fail_silently=False,
            )
            
            logger.info(f"Email de bienvenida enviado a {user.email}")
            return True
            
        except Exception as e:
            logger.error(f"Error enviando email de bienvenida a {user.email}: {str(e)}")
            return False