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
        """
        ✅ CORREGIDO: Inicializa sin validación bloqueante
        La validación de la API key se hace en el primer envío real
        """
        # Soportar varios nombres de variable de entorno
        api_key = os.environ.get('SENDGRID_API_KEY') or os.environ.get('SENDGRID_KEY')
        if not api_key:
            logger.error("❌ SENDGRID_API_KEY no encontrada en variables de entorno")
            raise ValueError("SENDGRID_API_KEY no configurada")

        self.sg = SendGridAPIClient(api_key)
        
        # Email remitente
        self.from_email = (
            os.environ.get('EMAIL_FROM') or 
            os.environ.get('DEFAULT_FROM_EMAIL') or 
            'soporteshiftscheduler1@gmail.com'
        )
        
        self.frontend_url = os.environ.get('FRONTEND_URL', 'https://shiftscheduler1.vercel.app')
        
        # ✅ CAMBIO CRÍTICO: NO validar la API key en __init__
        # La validación se hará en el primer envío real
        logger.info(f"✅ EmailService inicializado")
        logger.info(f"   - From: {self.from_email}")
        logger.info(f"   - Frontend: {self.frontend_url}")
        logger.info(f"   - API Key: {'*' * 20}{api_key[-8:] if len(api_key) > 8 else '****'}")

    def _format_time_12h(self, value):
        """Convierte una hora a formato 12h con am/pm."""
        if value is None:
            return ""

        if hasattr(value, 'strftime'):
            return value.strftime("%I:%M %p").lstrip("0").lower()

        text = str(value).strip()
        for fmt in ("%H:%M:%S", "%H:%M", "%I:%M %p", "%I:%M%p"):
            try:
                parsed = time.strptime(text, fmt)
                return time.strftime("%I:%M %p", parsed).lstrip("0").lower()
            except Exception:
                continue

        return text.lower()
    
    def send_password_reset_email(self, to_email, reset_token, user_name=None, uid=None):
        """
        Envía email de recuperación de contraseña
        """
        try:
            # Construir URL de reseteo
            base = os.environ.get('PASSWORD_RESET_CONFIRM_FRONTEND_URL') or self.frontend_url
            if uid:
                reset_url = f"{base}?uid={uid}&token={reset_token}"
            else:
                reset_url = f"{base}/reset-password/confirm?token={reset_token}"
            
            # HTML content
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
            
            # Plain text content
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
            
            # Crear mensaje
            message = Mail(
                from_email=From(self.from_email, "Shift Scheduler"),
                to_emails=To(to_email),
                subject="Restablecimiento de contraseña - Shift Scheduler",
                html_content=html_content,
                plain_text_content=plain_content
            )
            
            # Enviar con reintentos
            return self._send_with_retry(message, email_type="password_reset")

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
            
            return self._send_with_retry(message, email_type="password_updated")
            
        except Exception as e:
            logger.error(f"❌ Error enviando confirmación a {to_email}: {str(e)}", exc_info=True)
            return False

    def send_notification_email(self, to_email, subject, plain_text_content, html_content=None):
        """
        ✅ Envía email genérico para notificaciones del sistema
        Usado por el sistema de recordatorios
        """
        try:
            logger.info(f"📧 Preparando notificación para {to_email}")
            logger.info(f"   - Subject: {subject}")
            
            if html_content is None:
                html_content = f"<pre>{plain_text_content}</pre>"

            message = Mail(
                from_email=From(self.from_email, "Shift Scheduler"),
                to_emails=To(to_email),
                subject=subject,
                html_content=html_content,
                plain_text_content=plain_text_content
            )

            result = self._send_with_retry(message, email_type="notification")
            
            if result:
                logger.info(f"✅ Notificación enviada exitosamente a {to_email}")
            else:
                logger.error(f"❌ Falló el envío de notificación a {to_email}")
            
            return result
            
        except Exception as e:
            logger.error(f"❌ Error enviando notificación a {to_email}: {str(e)}", exc_info=True)
            return False

    def send_shift_reminder_email(self, to_email, user_name, shift_date, start_time, end_time, shift_details=None):
        """
        Envía email de recordatorio de turno
        """
        try:
            # Formatear fecha y hora
            formatted_date = shift_date.strftime("%d/%m/%Y")
            formatted_start = self._format_time_12h(start_time)
            formatted_end = self._format_time_12h(end_time)

            # Bloque de detalles opcional
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

            message = Mail(
                from_email=From(self.from_email, "Shift Scheduler"),
                to_emails=To(to_email),
                subject=f"⏰ Recordatorio de turno para el {formatted_date}",
                html_content=html_content,
                plain_text_content=plain_content
            )

            return self._send_with_retry(message, email_type="shift_reminder")

        except Exception as e:
            logger.error(f"❌ Error enviando recordatorio a {to_email}: {str(e)}", exc_info=True)
            return False

    def send_shifts_cancelled_email(self, to_email, user_name, shifts):
        """
        Envía un solo correo listando todos los turnos cancelados.
        shifts: lista de dicts con 'date', 'start_time', 'end_time'
        """
        try:
            login_url = os.environ.get('FRONTEND_LOGIN_URL', 'https://shiftscheduler1.vercel.app/login')

            # Construir lista en HTML
            shifts_html = "".join([
                f"""
                <div style="padding:12px 14px;border-bottom:1px solid #f3d0d0;display:flex;justify-content:space-between;gap:12px;">
                    <div><strong style="color:#7f1d1d;">{s['date']}</strong></div>
                    <div style="color:#444;">{self._format_time_12h(s['start_time'])} - {self._format_time_12h(s['end_time'])}</div>
                </div>
                """
                for s in shifts
            ])
            html_content = f"""
            <html>
            <body style="margin:0;padding:0;background:#fff5f5;font-family:Arial,Helvetica,sans-serif;">
                <div style="max-width:640px;margin:28px auto;background:#ffffff;border:1px solid #f2b8b5;border-radius:16px;overflow:hidden;box-shadow:0 10px 30px rgba(153, 27, 27, 0.12);">
                    <div style="background:linear-gradient(135deg,#dc2626,#ef4444);color:white;padding:34px 28px;text-align:center;">
                        <div style="display:inline-block;background:rgba(255,255,255,0.18);padding:6px 12px;border-radius:999px;font-size:12px;font-weight:700;letter-spacing:.4px;text-transform:uppercase;margin-bottom:14px;">
                            Cancelación de turno
                        </div>
                        <h1 style="margin:0;font-size:28px;line-height:1.2;">Shift Scheduler</h1>
                        <div style="margin-top:10px;font-size:18px;font-weight:700;">Tu turno fue cancelado</div>
                    </div>
                    <div style="padding:28px;">
                        <p style="margin:0 0 16px;font-size:18px;color:#2f2f2f;font-weight:700;">Hola {user_name},</p>
                        <p style="margin:0 0 22px;color:#555;font-size:15px;line-height:1.6;">
                            Los siguientes turnos fueron cancelados. Inicia sesión para revisar tu calendario.
                        </p>

                        <div style="background:#fffafa;border:1px solid #f3c7c7;border-radius:14px;overflow:hidden;margin:18px 0 24px;">
                            <div style="padding:14px 16px;background:#fee2e2;color:#7f1d1d;font-weight:700;border-bottom:1px solid #f3c7c7;">
                                Turnos cancelados
                            </div>
                            <div style="font-size:14px;">
                                {shifts_html}
                            </div>
                        </div>

                        <div style="text-align:center;margin:28px 0 14px;">
                            <a href="{login_url}" style="display:inline-block;padding:14px 26px;background:#dc2626;color:#ffffff;text-decoration:none;border-radius:10px;font-weight:700;box-shadow:0 6px 14px rgba(220,38,38,0.22);">
                                Iniciar sesión y ver calendario
                            </a>
                        </div>
                        <p style="margin:0;color:#6b7280;font-size:13px;line-height:1.6;text-align:center;">
                            Si no esperabas este cambio, revisa tu cuenta al ingresar.
                        </p>
                    </div>
                    <div style="padding:18px 24px;text-align:center;font-size:12px;color:#7a7a7a;background:#fff7f7;border-top:1px solid #f5d0d0;">
                        <p>© 2025 Shift Scheduler - Sistema de Gestión de Turnos</p>
                    </div>
                </div>
            </body>
            </html>
            """
            # Plain text
            shifts_text = "\n".join([
                f"- {s['date']} de {self._format_time_12h(s['start_time'])} a {self._format_time_12h(s['end_time'])}"
                for s in shifts
            ])
            plain_content = f"""Turnos Cancelados - Shift Scheduler

Hola {user_name},

Los siguientes turnos han sido cancelados:
{shifts_text}

Inicia sesión para revisar tu calendario: {login_url}

---
Shift Scheduler
"""
            message = Mail(
                from_email=From(self.from_email, "Shift Scheduler"),
                to_emails=To(to_email),
                subject="Turnos cancelados - Shift Scheduler",
                html_content=html_content,
                plain_text_content=plain_content
            )
            return self._send_with_retry(message, email_type="shifts_cancelled")
        except Exception as e:
            logger.error(f"❌ Error enviando email de turnos cancelados a {to_email}: {str(e)}", exc_info=True)
            return False

    def send_shifts_created_email(self, to_email, user_name, shifts):
        """
        Envía un solo correo listando todos los turnos creados (por duplicación).
        shifts: lista de dicts con 'date', 'start_time', 'end_time'
        """
        try:
            total_shifts = len(shifts)
            shifts_rows = "".join([
                f"""
                <tr>
                    <td style="padding:12px 14px;border-bottom:1px solid #f3e7b0;">{s['date']}</td>
                    <td style="padding:12px 14px;border-bottom:1px solid #f3e7b0;">{self._format_time_12h(s['start_time'])}</td>
                    <td style="padding:12px 14px;border-bottom:1px solid #f3e7b0;">{self._format_time_12h(s['end_time'])}</td>
                </tr>
                """
                for s in shifts
            ])

            html_content = f"""
            <html>
            <body style="margin:0;padding:0;background:#fff8e1;font-family:Arial,Helvetica,sans-serif;">
                <div style="max-width:640px;margin:28px auto;background:#ffffff;border:1px solid #ffe08a;border-radius:16px;overflow:hidden;box-shadow:0 10px 30px rgba(173, 132, 0, 0.12);">
                    <div style="background:linear-gradient(135deg,#f4b400,#f59e0b);color:#1f1f1f;padding:34px 28px;text-align:center;">
                        <div style="display:inline-block;background:rgba(255,255,255,0.28);color:#1f1f1f;padding:6px 12px;border-radius:999px;font-size:12px;font-weight:700;letter-spacing:.4px;text-transform:uppercase;margin-bottom:14px;">
                            Duplicación de turnos
                        </div>
                        <h1 style="margin:0;font-size:28px;line-height:1.2;">Shift Scheduler</h1>
                        <div style="margin-top:10px;font-size:18px;font-weight:700;">Turnos duplicados correctamente</div>
                    </div>

                    <div style="padding:28px;">
                        <p style="margin:0 0 16px;font-size:18px;color:#2f2f2f;font-weight:700;">Hola {user_name},</p>
                        <p style="margin:0 0 22px;color:#555;font-size:15px;line-height:1.6;">
                            Se duplicaron <strong>{total_shifts}</strong> turnos y quedaron programados en tu calendario.
                        </p>

                        <div style="background:#fffdf4;border:1px solid #f5d36b;border-radius:14px;overflow:hidden;margin:18px 0 24px;">
                            <div style="padding:14px 16px;background:#fff1c2;color:#6b4e00;font-weight:700;border-bottom:1px solid #f5d36b;">
                                Detalles de los turnos duplicados
                            </div>
                            <table style="width:100%;border-collapse:collapse;font-size:14px;color:#2f2f2f;">
                                <thead>
                                    <tr style="background:#fff8dc;text-align:left;color:#6b4e00;">
                                        <th style="padding:12px 14px;border-bottom:1px solid #f3e7b0;">Fecha</th>
                                        <th style="padding:12px 14px;border-bottom:1px solid #f3e7b0;">Inicio</th>
                                        <th style="padding:12px 14px;border-bottom:1px solid #f3e7b0;">Fin</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {shifts_rows}
                                </tbody>
                            </table>
                        </div>

                        <div style="text-align:center;margin:28px 0 14px;">
                            <a href="{self.frontend_url}/calendar" style="display:inline-block;padding:14px 26px;background:#d97706;color:#ffffff;text-decoration:none;border-radius:10px;font-weight:700;box-shadow:0 6px 14px rgba(217,119,6,0.22);">
                                Ver mi calendario
                            </a>
                        </div>

                    </div>

                    <div style="padding:18px 24px;text-align:center;font-size:12px;color:#7a7a7a;background:#fffaf0;border-top:1px solid #f5e6ba;">
                        © 2025 Shift Scheduler - Sistema de Gestión de Turnos
                    </div>
                </div>
            </body>
            </html>
            """

            shifts_text = "\n".join([
                f"- {s['date']} de {self._format_time_12h(s['start_time'])} a {self._format_time_12h(s['end_time'])}"
                for s in shifts
            ])
            plain_content = f"""Turnos duplicados - Shift Scheduler

Hola {user_name},

Se duplicaron {total_shifts} turnos y quedaron programados en tu calendario:
{shifts_text}

---
Shift Scheduler
"""
            message = Mail(
                from_email=From(self.from_email, "Shift Scheduler"),
                to_emails=To(to_email),
                subject="Turnos duplicados - Shift Scheduler",
                html_content=html_content,
                plain_text_content=plain_content
            )
            return self._send_with_retry(message, email_type="shifts_created")
        except Exception as e:
            logger.error(f"❌ Error enviando email de turnos creados a {to_email}: {str(e)}", exc_info=True)
            return False

    def _send_with_retry(self, message, max_retries: int = 3, email_type: str = "generic"):
        """
        ✅ MEJORADO: Envía email con reintentos y logging detallado
        """
        for attempt in range(1, max_retries + 1):
            try:
                logger.info(f"📤 [{email_type}] Intento {attempt}/{max_retries} - Enviando a {message.to[0]['email'] if message.to else 'unknown'}")
                
                response = self.sg.send(message)
                status = getattr(response, 'status_code', None)
                body = getattr(response, 'body', None)

                # Normalizar body
                try:
                    if isinstance(body, (bytes, bytearray)):
                        body_text = body.decode('utf-8', errors='replace')
                    else:
                        body_text = str(body)
                except Exception:
                    body_text = repr(body)

                logger.info(f"📨 SendGrid response: status={status}")
                
                # Debug detallado si está habilitado
                if os.getenv('SENDGRID_DEBUG_BODY', 'False') == 'True' or logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"Response body: {body_text}")

                # ✅ 202 = Email aceptado para envío
                if status == 202:
                    logger.info(f"✅ Email enviado exitosamente (status 202)")
                    return True

                # ❌ Errores de cliente (4xx) NO reintentar, excepto 429
                if status and 400 <= status < 500 and status != 429:
                    logger.error(f"❌ Error cliente SendGrid: status={status}")
                    logger.error(f"   Body: {body_text}")
                    return False

                # ⚠️ Errores de servidor (5xx) o inesperados - reintentar
                logger.warning(f"⚠️ Respuesta inesperada: status={status}, reintentando...")

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

                logger.error(f"❌ HTTPError: status={status}")
                logger.error(f"   Body: {body_text}")
                
                # Debug detallado
                if os.getenv('SENDGRID_DEBUG_BODY', 'False') == 'True' or logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"HTTPError completo: {he}")

                # NO reintentar errores de cliente
                if status and 400 <= status < 500 and status != 429:
                    return False
                    
            except Exception as exc:
                logger.exception(f"❌ Excepción inesperada en intento {attempt}: {exc}")

            # ⏳ Esperar antes del siguiente intento
            if attempt < max_retries:
                backoff = min(2 ** attempt, 60)
                logger.info(f"⏳ Esperando {backoff}s antes de reintentar...")
                time.sleep(backoff)

        logger.error(f"❌ Agotados {max_retries} reintentos enviando email")
        return False


# ============================================
# INSTANCIA GLOBAL CON INICIALIZACIÓN SEGURA
# ============================================

email_service = None

def get_email_service():
    """
    ✅ MEJORADO: Inicializa email_service con manejo robusto de errores
    """
    global email_service
    
    if email_service is None:
        try:
            email_service = EmailService()
            logger.info("✅ EmailService inicializado correctamente")
        except ValueError as ve:
            # Falta la API key
            logger.error(f"❌ EmailService no disponible: {ve}")
            logger.error("   Configura SENDGRID_API_KEY en las variables de entorno")
            email_service = _get_dummy_email_service()
        except Exception as e:
            # Otros errores (red, permisos, etc.)
            logger.warning(f"⚠️ No se pudo inicializar EmailService: {e}")
            logger.warning("   Usando DummyEmailService como fallback")
            email_service = _get_dummy_email_service()
    
    return email_service


def _get_dummy_email_service():
    """
    ✅ Servicio dummy para desarrollo/testing sin SendGrid
    """
    class DummyEmailService:
        def __init__(self):
            logger.warning("⚠️ DummyEmailService activo - Los emails NO se enviarán realmente")
        
        def send_password_reset_email(self, to_email, reset_token, user_name=None, uid=None):
            logger.info(f"[DUMMY] Recuperación de contraseña para {to_email}")
            logger.info(f"        Token: {reset_token}")
            return False

        def send_password_updated_email(self, to_email, user_name=None):
            logger.info(f"[DUMMY] Confirmación de contraseña para {to_email}")
            return False

        def send_notification_email(self, to_email, subject, plain_text_content, html_content=None):
            logger.info(f"[DUMMY] Notificación para {to_email}")
            logger.info(f"        Subject: {subject}")
            return False

        def send_shift_reminder_email(self, to_email, user_name, shift_date, start_time, end_time, shift_details=None):
            logger.info(f"[DUMMY] Recordatorio de turno para {to_email}")
            logger.info(f"        Fecha: {shift_date} {start_time}")
            return False

    return DummyEmailService()


def generate_reset_token(length: int = 32) -> str:
    """
    Genera token seguro para reseteo de contraseña
    """
    return secrets.token_urlsafe(length)