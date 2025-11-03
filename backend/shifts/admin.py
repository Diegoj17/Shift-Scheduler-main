from django.contrib import admin
from .models import Shift, ShiftType, Employee

@admin.register(ShiftType)
class ShiftTypeAdmin(admin.ModelAdmin):
    list_display = ['name', 'start_time', 'end_time', 'color']
    list_editable = ['color']

@admin.register(Employee)
class EmployeeAdmin(admin.ModelAdmin):
    list_display = ['user', 'position', 'is_active']
    list_filter = ['is_active', 'position']

@admin.register(Shift)
class ShiftAdmin(admin.ModelAdmin):
    list_display = ['employee', 'date', 'start_time', 'end_time', 'shift_type', 'role']
    list_filter = ['date', 'shift_type', 'employee']
    search_fields = ['employee__user__first_name', 'employee__user__last_name', 'role']