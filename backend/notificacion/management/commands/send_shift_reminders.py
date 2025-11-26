from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from notificacion.models import Notification, NotificationPreference
from shifts.models import Shift, ShiftReminder
from notificacion.services import notification_service
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Envía recordatorios de turno programados a los empleados'

    def add_arguments(self, parser):
        parser.add_argument(
            '--test',
            action='store_true',
            help='Modo prueba: muestra los recordatorios pendientes sin enviarlos',
        )
        parser.add_argument(
            '--reschedule-all',
            action='store_true',
            help='Reprograma todos los recordatorios para turnos futuros',
        )
        parser.add_argument(
            '--cleanup',
            action='store_true',
            help='Limpia recordatorios antiguos o duplicados',
        )

    def handle(self, *args, **options):
        try:
            if options['reschedule_all']:
                self.reschedule_all_reminders()
                return
                
            if options['cleanup']:
                self.cleanup_reminders()
                return

            if options['test']:
                self.test_reminders()
                return

            # Ejecución normal - enviar recordatorios programados
            self.send_scheduled_reminders()
                
        except Exception as e:
            logger.error(f"❌ Error en comando de recordatorios: {str(e)}")
            self.stdout.write(
                self.style.ERROR(f"❌ Error: {str(e)}")
            )

    def send_scheduled_reminders(self):
        """Envía recordatorios programados que están pendientes"""
        self.stdout.write("🔄 Buscando recordatorios programados...")
        
        sent_count = notification_service.send_scheduled_reminders()
        
        if sent_count > 0:
            self.stdout.write(
                self.style.SUCCESS(f"✅ {sent_count} recordatorios enviados exitosamente")
            )
        else:
            self.stdout.write("ℹ️ No hay recordatorios pendientes para enviar")

    def test_reminders(self):
        """Modo prueba: muestra recordatorios pendientes sin enviarlos"""
        self.stdout.write("🔍 Modo prueba - Mostrando recordatorios pendientes...")
        
        now = timezone.now()
        pending_reminders = ShiftReminder.objects.filter(
            reminder_time__lte=now,
            sent=False
        ).select_related('shift', 'user', 'shift__shift_type')
        
        self.stdout.write(f"📋 Recordatorios pendientes: {pending_reminders.count()}")
        
        for reminder in pending_reminders:
            shift = reminder.shift
            user = reminder.user
            
            self.stdout.write(
                f"  - 📅 Turno {shift.id}: {user.email} "
                f"| {reminder.reminder_type} "
                f"| Programado: {reminder.reminder_time.strftime('%Y-%m-%d %H:%M')} "
                f"| Turno: {shift.date} {shift.start_time}-{shift.end_time}"
            )
        
        # También mostrar próximos recordatorios programados
        future_reminders = ShiftReminder.objects.filter(
            reminder_time__gt=now,
            sent=False
        ).select_related('shift', 'user').order_by('reminder_time')[:10]
        
        self.stdout.write(f"\n🔮 Próximos recordatorios (primeros 10): {future_reminders.count()}")
        
        for reminder in future_reminders:
            self.stdout.write(
                f"  - ⏰ {reminder.user.email} "
                f"| {reminder.reminder_type} "
                f"| Enviar: {reminder.reminder_time.strftime('%m-%d %H:%M')} "
                f"| Turno: {reminder.shift.date}"
            )
        
        self.stdout.write("ℹ️ Modo prueba - no se enviaron recordatorios")

    def reschedule_all_reminders(self):
        """Reprograma todos los recordatorios para turnos futuros"""
        self.stdout.write("🔄 Reprogramando todos los recordatorios...")
        
        # Limpiar recordatorios existentes
        deleted_count = ShiftReminder.objects.all().delete()[0]
        self.stdout.write(f"🧹 Eliminados {deleted_count} recordatorios existentes")
        
        # Obtener turnos futuros (próximos 60 días)
        today = timezone.now().date()
        future_date = today + timedelta(days=60)
        
        future_shifts = Shift.objects.filter(
            date__gte=today,
            date__lte=future_date
        ).select_related('employee__user')
        
        scheduled_count = 0
        errors = 0
        
        for shift in future_shifts:
            if shift.employee and shift.employee.user:
                try:
                    notification_service.schedule_shift_reminders(shift)
                    scheduled_count += 1
                    
                    if scheduled_count % 50 == 0:  # Log cada 50 turnos
                        self.stdout.write(f"⏰ Programados {scheduled_count} recordatorios...")
                        
                except Exception as e:
                    errors += 1
                    logger.error(f"Error programando recordatorios para turno {shift.id}: {str(e)}")
        
        self.stdout.write(
            self.style.SUCCESS(
                f"✅ Reprogramación completada: {scheduled_count} turnos programados, {errors} errores"
            )
        )

    def cleanup_reminders(self):
        """Limpia recordatorios antiguos, duplicados o inconsistentes"""
        self.stdout.write("🧹 Iniciando limpieza de recordatorios...")
        
        now = timezone.now()
        
        # 1. Eliminar recordatorios de turnos que ya pasaron (más de 1 día)
        old_date = now.date() - timedelta(days=1)
        old_reminders = ShiftReminder.objects.filter(
            shift__date__lt=old_date
        )
        old_count = old_reminders.delete()[0]
        self.stdout.write(f"🗑️  Eliminados {old_count} recordatorios de turnos pasados")
        
        # 2. Eliminar recordatorios enviados hace más de 7 días
        old_sent_date = now - timedelta(days=7)
        old_sent_reminders = ShiftReminder.objects.filter(
            sent=True,
            reminder_time__lt=old_sent_date
        )
        old_sent_count = old_sent_reminders.delete()[0]
        self.stdout.write(f"🗑️  Eliminados {old_sent_count} recordatorios enviados antiguos")
        
        # 3. Encontrar y eliminar duplicados
        from django.db.models import Count
        duplicates = ShiftReminder.objects.filter(
            sent=False
        ).values('shift', 'user', 'reminder_type').annotate(
            count=Count('id')
        ).filter(count__gt=1)
        
        dup_count = 0
        for dup in duplicates:
            # Mantener el más reciente, eliminar los demás
            keep = ShiftReminder.objects.filter(
                shift=dup['shift'],
                user=dup['user'],
                reminder_type=dup['reminder_type']
            ).order_by('-reminder_time').first()
            
            deleted = ShiftReminder.objects.filter(
                shift=dup['shift'],
                user=dup['user'],
                reminder_type=dup['reminder_type']
            ).exclude(id=keep.id).delete()[0]
            
            dup_count += deleted
        
        self.stdout.write(f"🔍 Eliminados {dup_count} recordatorios duplicados")
        
        # 4. Eliminar recordatorios para turnos que no existen
        invalid_reminders = ShiftReminder.objects.filter(shift__isnull=True)
        invalid_count = invalid_reminders.delete()[0]
        self.stdout.write(f"❌ Eliminados {invalid_count} recordatorios sin turno")
        
        total_cleaned = old_count + old_sent_count + dup_count + invalid_count
        self.stdout.write(
            self.style.SUCCESS(f"✅ Limpieza completada: {total_cleaned} registros eliminados")
        )

    def check_system_health(self):
        """Verifica la salud del sistema de recordatorios"""
        self.stdout.write("🏥 Verificando salud del sistema de recordatorios...")
        
        now = timezone.now()
        
        # Estadísticas generales
        total_reminders = ShiftReminder.objects.count()
        pending_reminders = ShiftReminder.objects.filter(sent=False).count()
        sent_reminders = ShiftReminder.objects.filter(sent=True).count()
        
        self.stdout.write(f"📊 Estadísticas de recordatorios:")
        self.stdout.write(f"  - Total: {total_reminders}")
        self.stdout.write(f"  - Pendientes: {pending_reminders}")
        self.stdout.write(f"  - Enviados: {sent_reminders}")
        
        # Recordatorios próximos (próximas 24 horas)
        next_24h = now + timedelta(hours=24)
        upcoming_reminders = ShiftReminder.objects.filter(
            reminder_time__range=[now, next_24h],
            sent=False
        ).count()
        
        self.stdout.write(f"  - Próximos 24h: {upcoming_reminders}")
        
        # Turnos futuros sin recordatorios programados
        future_shifts = Shift.objects.filter(
            date__gte=now.date(),
            date__lte=now.date() + timedelta(days=30)
        ).count()
        
        shifts_with_reminders = Shift.objects.filter(
            date__gte=now.date(),
            date__lte=now.date() + timedelta(days=30),
            reminders__isnull=False
        ).distinct().count()
        
        coverage = (shifts_with_reminders / future_shifts * 100) if future_shifts > 0 else 0
        
        self.stdout.write(f"📈 Cobertura de recordatorios:")
        self.stdout.write(f"  - Turnos futuros (30 días): {future_shifts}")
        self.stdout.write(f"  - Con recordatorios: {shifts_with_reminders}")
        self.stdout.write(f"  - Cobertura: {coverage:.1f}%")
        
        # Verificar configuraciones de usuarios
        users_with_prefs = NotificationPreference.objects.count()
        users_without_prefs = NotificationPreference.objects.filter(
            email_shift_reminder=False,
            panel_shift_reminder=False
        ).count()
        
        self.stdout.write(f"👥 Configuraciones de usuarios:")
        self.stdout.write(f"  - Usuarios con preferencias: {users_with_prefs}")
        self.stdout.write(f"  - Usuarios sin recordatorios: {users_without_prefs}")
        
        if coverage < 80:
            self.stdout.write(
                self.style.WARNING("⚠️  Cobertura baja - considere reprogramar recordatorios")
            )
        else:
            self.stdout.write(
                self.style.SUCCESS("✅ Sistema de recordatorios saludable")
            )