from django.db import models
from django.conf import settings
from django.core.exceptions import ValidationError

class ShiftType(models.Model):
    name = models.CharField(max_length=50, unique=True)
    start_time = models.TimeField()
    end_time = models.TimeField()
    color = models.CharField(max_length=7, default='#3788d8')  # Color hexadecimal
    
    def clean(self):
        if self.start_time >= self.end_time:
            raise ValidationError("La hora de fin debe ser mayor a la hora de inicio")
    
    def __str__(self):
        return self.name

    class Meta:
        db_table = 'shifts_shifttype'
        verbose_name = "Tipo de Turno"
        verbose_name_plural = "Tipos de Turno"

class Employee(models.Model):
    # Enlazar al modelo de usuario configurado en settings.AUTH_USER_MODEL
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    position = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    
    def __str__(self):
        return f"{self.user.first_name} {self.user.last_name}"

class Shift(models.Model):
    # Campos marcados como nullable temporalmente para permitir migraciones
    # incrementales (se crearán migraciones de alteración una vez que los
    # datos sean backfilled).
    date = models.DateField(null=True, blank=True)
    start_time = models.TimeField(null=True, blank=True)
    end_time = models.TimeField(null=True, blank=True)
    employee = models.ForeignKey(Employee, on_delete=models.CASCADE, null=True, blank=True)
    shift_type = models.ForeignKey(ShiftType, on_delete=models.CASCADE, null=True, blank=True)
    # role se elimina del modelo y de la forma de creación: el rol/puesto
    # se obtiene del `User`/`Employee` (asignado por Gerente/Admin).
    # Conservamos notes.
    notes = models.TextField(blank=True, null=True)
    
    class Meta:
        unique_together = ['employee', 'date', 'start_time']
        ordering = ['date', 'start_time']
    
    def clean(self):
        # Validar que la hora de fin sea mayor a la de inicio
        if self.start_time >= self.end_time:
            raise ValidationError("La hora de fin debe ser mayor a la hora de inicio")
        
        # Validar que no haya solapamientos para el mismo empleado
        overlapping_shifts = Shift.objects.filter(
            employee=self.employee,
            date=self.date
        ).exclude(pk=self.pk).filter(
            models.Q(start_time__lt=self.end_time, end_time__gt=self.start_time)
        )
        
        if overlapping_shifts.exists():
            raise ValidationError("El empleado ya tiene un turno asignado en este horario")
    
    def __str__(self):
        return f"{self.employee} - {self.date} {self.start_time}-{self.end_time}"