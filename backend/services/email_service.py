import os
import logging
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, To, From, Category
from python_http_client.exceptions import HTTPError
import secrets
import time

logger = logging.getLogger(__name__)

class EmailService:
    def __init__(self):
        # Soportar varios nombres de variable de entorno para flexibilidad en distintos entornos
        api_key = os.environ.get('SENDGRID_API_KEY') or os.environ.get('SENDGRID_KEY')
        if not api_key:
            logger.error("SENDGRID_API_KEY no encontrada en variables de entorno.")
            raise ValueError("SENDGRID_API_KEY no configurada")

        self.sg = SendGridAPIClient(api_key)
        # El email remitente puede estar en EMAIL_FROM o DEFAULT_FROM_EMAIL según despliegue
        self.from_email = os.environ.get('EMAIL_FROM') or os.environ.get('DEFAULT_FROM_EMAIL') or 'soporteshiftscheduler1@gmail.com'
        self.frontend_url = os.environ.get('FRONTEND_URL', 'https://shiftscheduler1.vercel.app')
        logger.info(f"EmailService inicializado con from_email: {self.from_email}")

        # Verificar validez de la clave (llamada de solo lectura a perfil de usuario)
        try:
            # Esta llamada no envía correos; valida la autenticación de la API key
            resp = self.sg.client.user.profile.get()
            status = getattr(resp, 'status_code', None)
            if status and int(status) >= 200 and int(status) < 300:
                logger.info("✔️ SendGrid API key validada correctamente")
            else:
                logger.warning(f"⚠️ Respuesta inesperada validando SendGrid API key: status={status}")
        except HTTPError as he:
            logger.exception("❌ SendGrid API key inválida o error al validar. Levantando excepción para fallback.")
            raise
        except Exception as e:
            logger.exception(f"❌ Error verificando SendGrid API key: {e}")
            raise
    
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
            return self._send_with_retry(message)

        except HTTPError as he:
            # HTTPError proviene del cliente HTTP de SendGrid: contiene status_code y body
            try:
                status = getattr(he, 'status_code', '<no-status>')
                body = getattr(he, 'body', getattr(he, 'args', str(he)))
                logger.error(f"❌ HTTPError enviando email de recuperación a {to_email}: status={status} body={body}")
            except Exception:
                logger.exception("❌ HTTPError sin detalles al enviar email de recuperación")
            return False
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
            
            return self._send_with_retry(message)
        except HTTPError as he:
            try:
                status = getattr(he, 'status_code', '<no-status>')
                body = getattr(he, 'body', getattr(he, 'args', str(he)))
                logger.error(f"❌ HTTPError enviando confirmación a {to_email}: status={status} body={body}")
            except Exception:
                logger.exception("❌ HTTPError sin detalles al enviar confirmación")
            return False
        except Exception as e:
            logger.error(f"❌ Error enviando email de confirmación a {to_email}: {str(e)}", exc_info=True)
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

            return self._send_with_retry(message)
        except HTTPError as he:
            try:
                status = getattr(he, 'status_code', '<no-status>')
                body = getattr(he, 'body', getattr(he, 'args', str(he)))
                logger.error(f"❌ HTTPError enviando notificación a {to_email}: status={status} body={body}")
            except Exception:
                logger.exception("❌ HTTPError sin detalles al enviar notificación")
            return False
        except Exception as e:
            logger.error(f"❌ Error enviando email de notificación a {to_email}: {str(e)}", exc_info=True)
            return False
    def send_shift_reminder_email(self, to_email, user_name, shift_date, start_time, end_time, shift_details=None):
        """Envía email de recordatorio de turno - optimizado y seguro contra errores de formato."""
        try:
            # Formatear fecha y hora
            formatted_date = shift_date.strftime("%d/%m/%Y")
            formatted_start = start_time.strftime("%H:%M")
            formatted_end = end_time.strftime("%H:%M")

            # Bloque de detalles opcional (evitar nested f-strings dentro de la plantilla)
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
                        <p>© 2025 Shift Scheduler - Sistema de Gestión de Turnos</p>
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
            plain_content_lines.extend(["", "💡 Recordatorio: Tu turno comienza pronto. Por favor asegúrate de estar disponible.", "", "---", "Shift Scheduler - Sistema de Gestión de Turnos"])
            plain_content = "\n".join(plain_content_lines)

            message = Mail(
                from_email=From(self.from_email, "Shift Scheduler"),
                to_emails=To(to_email),
                subject=f"⏰ Recordatorio de turno para el {formatted_date}",
                html_content=html_content,
                plain_text_content=plain_content
            )

            return self._send_with_retry(message)

        except HTTPError as he:
            try:
                status = getattr(he, 'status_code', '<no-status>')
                body = getattr(he, 'body', getattr(he, 'args', str(he)))
                logger.error(f"❌ HTTPError enviando recordatorio a {to_email}: status={status} body={body}")
            except Exception:
                logger.exception("❌ HTTPError sin detalles al enviar recordatorio")
            return False
        except Exception as e:
            logger.error(f"❌ Error enviando email de recordatorio a {to_email}: {str(e)}", exc_info=True)
            return False

    def _send_with_retry(self, message, max_retries: int = 3):
        """Envía el `message` usando SendGrid con reintentos y backoff exponencial.
        No reintenta en errores cliente 4xx (salvo 429), reintenta en 5xx y excepciones transitorias.
        """
        for attempt in range(1, max_retries + 1):
            try:
                response = self.sg.send(message)
                status = getattr(response, 'status_code', None)
                body = getattr(response, 'body', None)

                # Normalizar body (puede ser bytes)
                try:
                    if isinstance(body, (bytes, bytearray)):
                        body_text = body.decode('utf-8', errors='replace')
                    else:
                        body_text = str(body)
                except Exception:
                    body_text = repr(body)

                logger.info(f"Envío email intento {attempt}/{max_retries}, status={status}")
                # Log detallado bajo demanda: variable de entorno `SENDGRID_DEBUG_BODY` o logger DEBUG
                sendgrid_debug = os.getenv('SENDGRID_DEBUG_BODY', 'False') == 'True'
                if sendgrid_debug or logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"SendGrid response body: {body_text}")

                if status == 202:
                    return True

                # Client errors (except 429 Too Many Requests) should not be retried
                if status and 400 <= status < 500 and status != 429:
                    logger.error(f"Error cliente al enviar email: status={status} body={body_text}")
                    return False

                # Else: server error or unexpected status - retry
                logger.warning(f"Respuesta inesperada de SendGrid: status={status} body={body_text}")

            except HTTPError as he:
                status = getattr(he, 'status_code', None)
                body = getattr(he, 'body', getattr(he, 'args', str(he)))
                try:
                    if isinstance(body, (bytes, bytearray)):
                        body_text = body.decode('utf-8', errors='replace')
                    else:
                        body_text = str(body)
                except Exception:
                    body_text = repr(body)

                logger.error(f"HTTPError al enviar email: status={status} body={body_text}")
                # Log detallado si está habilitado
                sendgrid_debug = os.getenv('SENDGRID_DEBUG_BODY', 'False') == 'True'
                if sendgrid_debug or logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"HTTPError detalles: {he}")

                if status and 400 <= status < 500 and status != 429:
                    return False
            except Exception as exc:
                logger.exception(f"Excepción al enviar email (intento {attempt}): {exc}")

            # Esperar antes del siguiente intento
            if attempt < max_retries:
                backoff = min(2 ** attempt, 60)
                logger.info(f"Esperando {backoff}s antes de reintentar...")
                time.sleep(backoff)

        logger.error("Agotados los reintentos al enviar email")
        return False

# Instancia global
email_service = None

def get_email_service():
    global email_service
    if email_service is None:
        try:
            email_service = EmailService()
        except Exception as e:
            # Fallback seguro: evitar que la app o los comandos fallen si SendGrid no está disponible
            logger.warning(f"⚠️ No se pudo inicializar EmailService ({e}). Usando DummyEmailService fallback.")
            class DummyEmailService:
                def send_password_reset_email(self, to_email, reset_token, user_name=None, uid=None):
                    logger.info(f"[DummyEmailService] send_password_reset_email a {to_email} (simulado)")
                    return False

                def send_password_updated_email(self, to_email, user_name=None):
                    logger.info(f"[DummyEmailService] send_password_updated_email a {to_email} (simulado)")
                    return False

                def send_notification_email(self, to_email, subject, plain_text_content, html_content=None):
                    logger.info(f"[DummyEmailService] send_notification_email a {to_email} (simulado)")
                    return False

                def send_shift_reminder_email(self, to_email, user_name, shift_date, start_time, end_time, shift_details=None):
                    logger.info(f"[DummyEmailService] send_shift_reminder_email a {to_email} (simulado)")
                    return False

            email_service = DummyEmailService()
    return email_service

def generate_reset_token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)

