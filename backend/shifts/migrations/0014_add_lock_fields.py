from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("shifts", "0013_shiftchangerequest"),
    ]

    operations = [
        migrations.AddField(
            model_name="shift",
            name="is_locked",
            field=models.BooleanField(default=False, help_text="Turno bloqueado para edición"),
        ),
        migrations.AddField(
            model_name="shift",
            name="lock_reason",
            field=models.CharField(max_length=200, null=True, blank=True, help_text="Motivo del bloqueo"),
        ),
        migrations.AddField(
            model_name="shift",
            name="locked_at",
            field=models.DateTimeField(null=True, blank=True, help_text="Fecha de bloqueo"),
        ),
    ]
