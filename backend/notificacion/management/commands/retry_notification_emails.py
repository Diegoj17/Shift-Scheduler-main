# shifts/management/commands/retry_notification_emails.py
from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from notificacion.models import Notification
from notificacion.services import notification_service
from shifts.models import ShiftReminder
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Reintenta enviar emails para notificaciones con email_sent=False'

    def add_arguments(self, parser):
        parser.add_argument(
            '--hours',
            type=int,
            default=72,
            help='Ventana en horas hacia atrás (default: 72h)'
        )
        parser.add_argument(
            '--limit',
            type=int,
            default=0,
            help='Máximo de notificaciones a procesar (0 = sin límite)'
        )
        parser.add_argument(
            '--only-shift-reminders',
            action='store_true',
            help='Procesar solo notificaciones tipo shift_reminder'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Simular sin enviar emails'
        )

    def handle(self, *args, **options):
        hours = options['hours']
        limit = options['limit']
        only_shift = options['only_shift_reminders']
        dry_run = options['dry_run']

        since = timezone.now() - timedelta(hours=hours)

        # Filtrar notificaciones pendientes
        qs = Notification.objects.filter(
            email_sent=False,
            created_at__gte=since
        ).select_related('user', 'related_shift', 'related_shift__shift_type')

        if only_shift:
            qs = qs.filter(type='shift_reminder')

        qs = qs.order_by('created_at')
        total = qs.count()

        self.stdout.write(
            self.style.WARNING(
                f"\n{'🔍 [DRY RUN]' if dry_run else '🔁'} Reintentando emails "
                f"(desde {since.strftime('%Y-%m-%d %H:%M')})"
            )
        )
        self.stdout.write(f"📊 Total candidatos: {total}")

        if limit and limit > 0:
            qs = qs[:limit]
            self.stdout.write(f"⚠️  Limitado a {limit} notificaciones")

        if dry_run:
            self.stdout.write(self.style.WARNING("\n🔍 MODO DRY RUN - No se enviarán emails\n"))

        processed = 0
        success = 0
        failures = 0
        skipped = 0

        for notification in qs:
            processed += 1

            # Información básica
            user_email = notification.user.email
            notif_type = notification.type
            created = notification.created_at.strftime('%Y-%m-%d %H:%M')

            self.stdout.write(
                f"\n[{processed}/{total}] Notification ID={notification.id} "
                f"| User={user_email} | Type={notif_type} | Created={created}"
            )

            try:
                # Verificar preferencias del usuario
                from notificacion.models import NotificationPreference
                prefs, _ = NotificationPreference.objects.get_or_create(
                    user=notification.user
                )

                # Verificar si el usuario tiene habilitado email para este tipo
                email_enabled = notification_service._check_email_preference(
                    prefs, 
                    notif_type
                )

                if not email_enabled:
                    self.stdout.write(
                        self.style.WARNING(
                            f"  ⊘ Usuario tiene deshabilitado email para {notif_type}"
                        )
                    )
                    skipped += 1
                    continue

                # DRY RUN: solo mostrar, no enviar
                if dry_run:
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"  ✓ [DRY RUN] Se enviaría email: {notification.title}"
                        )
                    )
                    success += 1
                    continue

                # Enviar email
                sent = notification_service._send_notification_email(
                    notification.user,
                    notification.type,
                    notification.title,
                    notification.message,
                    related_shift=notification.related_shift
                )

                if sent:
                    # Actualizar Notification
                    notification.email_sent = True
                    notification.save(update_fields=['email_sent'])
                    success += 1

                    self.stdout.write(
                        self.style.SUCCESS(f"  ✓ Email enviado exitosamente")
                    )

                    # Marcar ShiftReminder asociado como enviado
                    if notification.related_shift:
                        try:
                            updated = ShiftReminder.objects.filter(
                                shift=notification.related_shift,
                                user=notification.user,
                                sent=False
                            ).update(sent=True)

                            if updated > 0:
                                self.stdout.write(
                                    f"    ↳ {updated} ShiftReminder(s) marcados como enviados"
                                )
                        except Exception as e:
                            logger.warning(
                                f"No se pudo actualizar ShiftReminder: {e}"
                            )
                else:
                    failures += 1
                    self.stdout.write(
                        self.style.ERROR(
                            f"  ✗ No se pudo enviar email - quedará para reintento"
                        )
                    )

            except Exception as e:
                failures += 1
                logger.exception(f"Error procesando Notification {notification.id}")
                self.stdout.write(
                    self.style.ERROR(f"  ✗ Error: {str(e)}")
                )

        # Resumen final
        self.stdout.write("\n" + "="*60)
        self.stdout.write(
            self.style.SUCCESS(
                f"\n✅ Proceso finalizado"
                f"{' [DRY RUN]' if dry_run else ''}"
            )
        )
        self.stdout.write(f"  📊 Procesadas: {processed}")
        self.stdout.write(f"  ✓ Exitosas: {success}")
        self.stdout.write(f"  ✗ Fallidas: {failures}")
        self.stdout.write(f"  ⊘ Omitidas: {skipped}")
        self.stdout.write("="*60 + "\n")

        if failures > 0:
            self.stdout.write(
                self.style.WARNING(
                    f"⚠️  {failures} notificaciones no pudieron enviarse. "
                    "Revisa los logs para más detalles."
                )
            )