from django.contrib import admin
from .models import Shift, ShiftType, Employee, Availability

@admin.register(ShiftType)
class ShiftTypeAdmin(admin.ModelAdmin):
    # Mostrar sólo campos existentes en el modelo ShiftType
    list_display = ['name', 'start_time', 'end_time', 'color']
    # No usar filtros basados en métodos (is_overnight no es un Field en ShiftType)
    list_filter = []

@admin.register(Shift)
class ShiftAdmin(admin.ModelAdmin):
    # Podemos mostrar métodos del modelo (duration_hours, is_overnight) en list_display
    list_display = ['employee', 'date', 'start_time', 'end_time', 'shift_type', 'is_overnight', 'duration_hours']
    # No incluir métodos en list_filter; usar sólo campos reales
    list_filter = ['date', 'shift_type', 'employee']
    search_fields = ['employee__user__first_name', 'employee__user__last_name']

@admin.register(Employee)
class EmployeeAdmin(admin.ModelAdmin):
    list_display = ['user', 'position', 'is_active']
    list_filter = ['is_active', 'position']
    

@admin.register(Availability)
class AvailabilityAdmin(admin.ModelAdmin):
    list_display = ['employee', 'date', 'start_time', 'end_time', 'type', 'duration_hours', 'created_at']
    list_filter = ['type', 'date', 'employee']
    search_fields = ['employee__user__first_name', 'employee__user__last_name', 'notes']
    ordering = ['-date', 'start_time']
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('employee__user')


