from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.apps import apps

class Command(BaseCommand):
    help = (
        "Detecta y limpia Employees duplicados por user_id. \n"
        "Por defecto corre en modo dry-run (reporta cambios). Usar --apply para reassign/delete."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            '--apply', action='store_true', dest='apply', default=False,
            help='Aplicar los cambios (reassign y eliminar duplicados). Si no se pasa, solo dry-run.'
        )
        parser.add_argument(
            '--force', action='store_true', dest='force', default=False,
            help='Forzar operación sin confirmación interactiva (útil para scripts/CI).'
        )

    def handle(self, *args, **options):
        Employee = apps.get_model('shifts', 'Employee')
        Shift = apps.get_model('shifts', 'Shift')
        Availability = apps.get_model('shifts', 'Availability')

        apply_changes = options['apply']
        force = options['force']

        self.stdout.write('Buscando usuarios con múltiples Employee...')

        # Agrupar por user_id
        from django.db.models import Count
        duplicates_qs = (
            Employee.objects.values('user_id')
            .annotate(c=Count('id'))
            .filter(c__gt=1)
            .order_by('-c')
        )

        total_users = duplicates_qs.count()
        if total_users == 0:
            self.stdout.write(self.style.SUCCESS('No se encontraron usuarios con Employee duplicados.'))
            return

        self.stdout.write(self.style.WARNING(f'Se encontraron {total_users} usuarios con más de 1 Employee.'))

        for entry in duplicates_qs:
            user_id = entry['user_id']
            employees = list(Employee.objects.filter(user_id=user_id).order_by('id'))
            kept = employees[0]
            duplicates = employees[1:]

            self.stdout.write('\n' + '-'*60)
            self.stdout.write(self.style.NOTICE(f'User ID: {user_id} -> mantener Employee ID {kept.id} ; duplicados: {[d.id for d in duplicates]}'))

            # report counts of related objects
            shifts_count = Shift.objects.filter(employee_id__in=[d.id for d in duplicates]).count()
            avail_count = Availability.objects.filter(employee_id__in=[d.id for d in duplicates]).count()

            self.stdout.write(f'  Shifts a reasignar: {shifts_count}')
            self.stdout.write(f'  Availabilities a reasignar/delete: {avail_count}')

            if not apply_changes:
                continue

            # apply changes: either interactive confirm or forced
            if not force:
                confirm = input(f"Aplicar cambios para user {user_id}? (yes/[no]) ")
                if confirm.lower() != 'yes':
                    self.stdout.write('Omitido por decisión del operador')
                    continue

            # Ejecutar reasignación dentro de transacción
            try:
                with transaction.atomic():
                    # Reasignar shifts
                    Shift.objects.filter(employee_id__in=[d.id for d in duplicates]).update(employee_id=kept.id)
                    # Intentamos reasignar availabilities; si hay constraint, reasignar también
                    Availability.objects.filter(employee_id__in=[d.id for d in duplicates]).update(employee_id=kept.id)
                    # Borrar duplicados
                    for d in duplicates:
                        d.delete()
                self.stdout.write(self.style.SUCCESS(f'Aplicado: reasignados y borrados duplicados para user {user_id}'))
            except Exception as exc:
                self.stdout.write(self.style.ERROR(f'Error aplicando cambios para user {user_id}: {exc}'))

        self.stdout.write(self.style.SUCCESS('Proceso completado.'))
