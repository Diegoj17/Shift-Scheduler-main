from django.db import models
from django.conf import settings


class Shift(models.Model):
    """Modelo que representa un turno del empleado.

    start y end son DateTime para soportar turnos que cruzan medianoche.
    """
    employee = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='shifts')
    start = models.DateTimeField()
    end = models.DateTimeField()
    shift_type = models.CharField(max_length=50, blank=True, null=True)
    role_in_shift = models.CharField(max_length=50, blank=True, null=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='created_shifts')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['start']
        indexes = [
            models.Index(fields=['employee', 'start', 'end']),
        ]

    def __str__(self):
        return f"{self.employee.email}: {self.start.isoformat()} - {self.end.isoformat()}"
