"""Remove problematic Employee with pk=6 if exists.

This data migration is targeted and idempotent. It will:
 - If Employee(pk=6) exists and there is another Employee for the same user,
   reassign that employee's Shifts and Availability to the other Employee and
   delete pk=6.
 - If Employee(pk=6) exists and there is NO other Employee for the same user,
   set related Shifts' employee to NULL (Shift.employee is nullable) and delete
   related Availability rows (which have a non-null FK), then delete pk=6.

Reverse is noop for safety.
"""
from django.db import migrations


def remove_employee_6(apps, schema_editor):
    Employee = apps.get_model('shifts', 'Employee')
    Shift = apps.get_model('shifts', 'Shift')
    Availability = apps.get_model('shifts', 'Availability')

    try:
        emp = Employee.objects.filter(pk=6).first()
        if not emp:
            print('Employee pk=6 not found; nothing to do')
            return

        user_id = emp.user_id
        # look for other employee for the same user
        other = Employee.objects.filter(user_id=user_id).exclude(pk=6).order_by('pk').first()

        if other:
            print(f'Reassigning related objects from Employee 6 to Employee {other.pk}')
            Shift.objects.filter(employee_id=6).update(employee_id=other.pk)
            Availability.objects.filter(employee_id=6).update(employee_id=other.pk)
            emp.delete()
            print('Employee 6 deleted after reassignment')
        else:
            print('No other Employee for the same user found. Reassigning Shifts to NULL and deleting Availabilities.')
            Shift.objects.filter(employee_id=6).update(employee_id=None)
            Availability.objects.filter(employee_id=6).delete()
            emp.delete()
            print('Employee 6 deleted; related Availabilities removed')

    except Exception as exc:
        print(f'Error while handling Employee 6: {exc}')


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('shifts', '0010_deduplicate_employees'),
    ]

    operations = [
        migrations.RunPython(remove_employee_6, reverse_code=migrations.RunPython.noop),
    ]
