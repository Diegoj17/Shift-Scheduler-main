from django.contrib import admin
from .models import Shift


@admin.register(Shift)
class ShiftAdmin(admin.ModelAdmin):
    list_display = ('employee', 'start', 'end', 'shift_type', 'role_in_shift')
    list_filter = ('shift_type', 'role_in_shift')
