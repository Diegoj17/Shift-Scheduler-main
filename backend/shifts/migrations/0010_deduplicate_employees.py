"""Migration data: deduplicate Employee rows per User.

This migration finds multiple Employee records referencing the same user
and consolidates them into a single Employee record per user. It
reassigns related Shifts and Availability entries to the kept Employee
and deletes the duplicate Employee rows.

The migration is idempotent and safe to run on databases where no
duplicates exist.
"""
from django.conf import settings
from django.db import migrations


def deduplicate_employees(apps, schema_editor):
    Employee = apps.get_model('shifts', 'Employee')
    Shift = apps.get_model('shifts', 'Shift')
    Availability = apps.get_model('shifts', 'Availability')

    # Resolve user model from settings.AUTH_USER_MODEL
    user_setting = settings.AUTH_USER_MODEL
    if isinstance(user_setting, str) and '.' in user_setting:
        user_app_label, user_model_name = user_setting.split('.')
    else:
        # Fallback to auth.User
        user_app_label, user_model_name = 'auth', 'User'

    User = apps.get_model(user_app_label, user_model_name)

    # Iterate each user and ensure only one Employee remains
    for user in User.objects.all():
        employees = list(Employee.objects.filter(user_id=user.pk).order_by('pk'))
        if len(employees) <= 1:
            continue

        kept = employees[0]
        duplicates = employees[1:]

        # Merge some non-critical fields if missing on kept
        for dup in duplicates:
            try:
                # If kept has empty or placeholder position, try to use dup's
                if (not getattr(kept, 'position', None)) and getattr(dup, 'position', None):
                    kept.position = dup.position
                if getattr(dup, 'is_active', None) is False:
                    # If any duplicate marks inactive, prefer kept's value (no-op)
                    pass

                kept.save()

                # Reassign related Shifts and Availability to the kept Employee
                Shift.objects.filter(employee_id=dup.pk).update(employee_id=kept.pk)
                Availability.objects.filter(employee_id=dup.pk).update(employee_id=kept.pk)

                # Finally delete the duplicate Employee row
                dup.delete()
            except Exception as exc:
                # Keep migration robust: print and continue
                print(f"Warning: failed merging Employee {dup.pk} into {kept.pk}: {exc}")


def noop_reverse(apps, schema_editor):
    # Not reversible: restoring duplicates automatically is unsafe
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('shifts', '0009_availability'),
    ]

    operations = [
        migrations.RunPython(deduplicate_employees, reverse_code=migrations.RunPython.noop),
    ]
