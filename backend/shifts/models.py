from django.db import models
from django.conf import settings
from django.core.exceptions import ValidationError

class ShiftType(models.Model):
    name = models.CharField(max_length=50, unique=True)
    start_time = models.TimeField()
    end_time = models.TimeField()
    color = models.CharField(max_length=7, default='#3788d8')  # Color hexadecimal
    
    def clean(self):
        # ✅ PERMITIR TURNOS NOCTURNOS (cuando end_time < start_time)
        # Esto significa que el turno cruza la medianoche
        if self.start_time == self.end_time:
            raise ValidationError("La hora de inicio y fin no pueden ser iguales")
        
        # No validamos start_time < end_time porque los turnos nocturnos son válidos
        # Ejemplo: 18:00 - 05:59 es un turno nocturno válido según el frontend
    
    def is_overnight(self):
        """Determina si es un turno nocturno (cruza medianoche)"""
        return self.end_time < self.start_time
    
    def get_shift_period(self):
        """Determina el período del turno según la lógica del frontend"""
        hour = self.start_time.hour
        
        # Según la lógica del frontend:
        # Mañana: 6:00 AM - 11:59 AM (6-11)
        # Tarde: 12:00 PM - 5:59 PM (12-17)  
        # Noche: 6:00 PM - 5:59 AM (18-23, 0-5)
        
        if 6 <= hour < 12:
            return 'morning'
        elif 12 <= hour < 18:
            return 'afternoon'
        else:
            return 'night'
    
    def duration_hours(self):
        """Calcula la duración en horas considerando turnos nocturnos"""
        from datetime import datetime, timedelta
        
        if self.is_overnight():
            # Turno nocturno: calcular desde start_time hasta medianoche + desde medianoche hasta end_time
            start_dt = datetime.combine(datetime.today(), self.start_time)
            end_dt = datetime.combine(datetime.today() + timedelta(days=1), self.end_time)
            duration = (end_dt - start_dt).total_seconds() / 3600
        else:
            # Turno diurno
            start_dt = datetime.combine(datetime.today(), self.start_time)
            end_dt = datetime.combine(datetime.today(), self.end_time)
            duration = (end_dt - start_dt).total_seconds() / 3600
        
        return duration
    
    def __str__(self):
        return f"{self.name} ({self.get_shift_period()})"

    class Meta:
        db_table = 'shifts_shifttype'
        verbose_name = "Tipo de Turno"
        verbose_name_plural = "Tipos de Turno"

class Employee(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE,
        unique=True  # ✅ CRÍTICO: Asegurar que cada User tenga solo un Employee
    )
    position = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        # ✅ Agregar constraint a nivel de base de datos
        constraints = [
            models.UniqueConstraint(
                fields=['user'],
                name='unique_employee_per_user'
            )
        ]
    
    def __str__(self):
        return f"{self.user.first_name} {self.user.last_name}"

class Shift(models.Model):
    date = models.DateField(null=True, blank=True)
    start_time = models.TimeField(null=True, blank=True)
    end_time = models.TimeField(null=True, blank=True)
    employee = models.ForeignKey(Employee, on_delete=models.CASCADE, null=True, blank=True)
    shift_type = models.ForeignKey(ShiftType, on_delete=models.CASCADE, null=True, blank=True)
    notes = models.TextField(blank=True, null=True)
    
    class Meta:
        unique_together = ['employee', 'date', 'start_time']
        ordering = ['date', 'start_time']
    
    def is_overnight(self):
        """Determina si es un turno nocturno (cruza medianoche)"""
        return self.end_time < self.start_time
    
    def get_shift_period(self):
        """Determina el período del turno según la lógica del frontend"""
        hour = self.start_time.hour
        
        # Según la lógica del frontend:
        # Mañana: 6:00 AM - 11:59 AM (6-11)
        # Tarde: 12:00 PM - 5:59 PM (12-17)  
        # Noche: 6:00 PM - 5:59 AM (18-23, 0-5)
        
        if 6 <= hour < 12:
            return 'morning'
        elif 12 <= hour < 18:
            return 'afternoon'
        else:
            return 'night'
    
    def get_actual_end_date(self):
        """Obtiene la fecha real de fin (puede ser del día siguiente)"""
        from datetime import timedelta
        if self.is_overnight():
            return self.date + timedelta(days=1)
        return self.date
    
    def clean(self):
        from datetime import datetime, timedelta
        
        # ✅ PERMITIR TURNOS NOCTURNOS (cuando end_time < start_time)
        if self.start_time == self.end_time:
            raise ValidationError("La hora de inicio y fin no pueden ser iguales")
        
        # No validamos start_time < end_time porque los turnos nocturnos son válidos
        
        # ✅ VALIDACIÓN DE SOLAPAMIENTO MEJORADA PARA TURNOS NOCTURNOS
        if self.is_overnight():
            # Para turnos nocturnos, verificar solapamiento en dos partes:
            # 1. Desde start_time hasta medianoche del mismo día
            # 2. Desde medianoche hasta end_time del día siguiente
            
            # Conflictos en el mismo día (parte nocturna)
            conflicts_same_day = Shift.objects.filter(
                employee=self.employee,
                date=self.date,
                start_time__lt='23:59:59',  # Hasta medianoche
                end_time__gt=self.start_time
            ).exclude(pk=self.pk if self.pk else None)
            
            # Conflictos en el día siguiente (parte matutina)
            next_day = self.date + timedelta(days=1)
            conflicts_next_day = Shift.objects.filter(
                employee=self.employee,
                date=next_day,
                start_time__lt=self.end_time,
                end_time__gt='00:00:00'
            ).exclude(pk=self.pk if self.pk else None)
            
            conflicts = conflicts_same_day.union(conflicts_next_day)
            
        else:
            # Para turnos diurnos (mismo día)
            conflicts = Shift.objects.filter(
                employee=self.employee,
                date=self.date
            ).exclude(pk=self.pk if self.pk else None).filter(
                models.Q(start_time__lt=self.end_time, end_time__gt=self.start_time)
            )
        
        if conflicts.exists():
            raise ValidationError("El empleado ya tiene un turno asignado en este horario")
    
    def duration_hours(self):
        """Calcula la duración en horas considerando turnos nocturnos"""
        from datetime import datetime, timedelta
        
        if self.is_overnight():
            # Turno nocturno: calcular desde start_time hasta medianoche + desde medianoche hasta end_time
            start_dt = datetime.combine(self.date, self.start_time)
            end_dt = datetime.combine(self.date + timedelta(days=1), self.end_time)
            duration = (end_dt - start_dt).total_seconds() / 3600
        else:
            # Turno diurno
            start_dt = datetime.combine(self.date, self.start_time)
            end_dt = datetime.combine(self.date, self.end_time)
            duration = (end_dt - start_dt).total_seconds() / 3600
        
        return duration
    
    def __str__(self):
        period = self.get_shift_period()
        return f"{self.employee} - {self.date} {self.start_time}-{self.end_time} ({period})"
    
class Availability(models.Model):
    """
    Modelo para registrar disponibilidad/no disponibilidad de empleados.
    Los empleados registran rangos horarios donde pueden o no trabajar.
    """
    TYPE_CHOICES = [
        ('available', 'Disponible'),
        ('unavailable', 'No Disponible'),
    ]
    
    employee = models.ForeignKey(Employee, on_delete=models.CASCADE, related_name='availabilities')
    date = models.DateField()
    start_time = models.TimeField()
    end_time = models.TimeField()
    type = models.CharField(max_length=20, choices=TYPE_CHOICES, default='available')
    notes = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'shifts_availability'
        verbose_name = "Disponibilidad"
        verbose_name_plural = "Disponibilidades"
        ordering = ['date', 'start_time']
        # Un empleado no puede tener múltiples registros idénticos
        unique_together = ['employee', 'date', 'start_time', 'type']
    
    def clean(self):
        """Validaciones del modelo"""
        from django.core.exceptions import ValidationError
        from datetime import timedelta
        
        # ✅ Permitir turnos nocturnos (cuando end_time < start_time)
        if self.start_time == self.end_time:
            raise ValidationError("La hora de inicio y fin no pueden ser iguales")
        
        # ✅ Validar solapamiento con otras disponibilidades del mismo empleado
        is_overnight = self.end_time < self.start_time
        
        if is_overnight:
            # Para registros nocturnos, verificar solapamiento en dos partes
            conflicts_same_day = Availability.objects.filter(
                employee=self.employee,
                date=self.date,
                start_time__lt='23:59:59',
                end_time__gt=self.start_time
            ).exclude(pk=self.pk if self.pk else None)
            
            next_day = self.date + timedelta(days=1)
            conflicts_next_day = Availability.objects.filter(
                employee=self.employee,
                date=next_day,
                start_time__lt=self.end_time,
                end_time__gt='00:00:00'
            ).exclude(pk=self.pk if self.pk else None)
            
            if conflicts_same_day.exists() or conflicts_next_day.exists():
                raise ValidationError("Ya existe un registro de disponibilidad que se solapa con este horario")
        else:
            # Para registros diurnos
            conflicts = Availability.objects.filter(
                employee=self.employee,
                date=self.date
            ).exclude(pk=self.pk if self.pk else None).filter(
                models.Q(start_time__lt=self.end_time, end_time__gt=self.start_time)
            )
            
            if conflicts.exists():
                raise ValidationError("Ya existe un registro de disponibilidad que se solapa con este horario")
    
    def is_overnight(self):
        """Determina si el registro cruza medianoche"""
        return self.end_time < self.start_time
    
    def duration_hours(self):
        """Calcula la duración en horas"""
        from datetime import datetime, timedelta
        
        if self.is_overnight():
            start_dt = datetime.combine(self.date, self.start_time)
            end_dt = datetime.combine(self.date + timedelta(days=1), self.end_time)
            duration = (end_dt - start_dt).total_seconds() / 3600
        else:
            start_dt = datetime.combine(self.date, self.start_time)
            end_dt = datetime.combine(self.date, self.end_time)
            duration = (end_dt - start_dt).total_seconds() / 3600
        
        return duration
    
    def get_color(self):
        """Retorna el color según el tipo"""
        return '#22543d' if self.type == 'available' else '#742a2a'
    
    def __str__(self):
        type_display = "Disponible" if self.type == 'available' else "No Disponible"
        return f"{self.employee} - {self.date} {self.start_time}-{self.end_time} ({type_display})"