from django.contrib import admin
from .models import Notification, NotificationPreference

@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ['user', 'type', 'title', 'is_read', 'email_sent', 'created_at']
    list_filter = ['type', 'is_read', 'email_sent', 'created_at']
    search_fields = ['user__email', 'user__first_name', 'user__last_name', 'title', 'message']
    readonly_fields = ['created_at', 'read_at']
    date_hierarchy = 'created_at'
    
    fieldsets = (
        ('Información General', {
            'fields': ('user', 'type', 'icon', 'title', 'message')
        }),
        ('Estado', {
            'fields': ('is_read', 'read_at', 'email_sent')
        }),
        ('Relaciones', {
            'fields': ('related_shift', 'related_request'),
            'classes': ('collapse',)
        }),
        ('Fechas', {
            'fields': ('created_at',),
            'classes': ('collapse',)
        }),
    )

@admin.register(NotificationPreference)
class NotificationPreferenceAdmin(admin.ModelAdmin):
    list_display = ['user', 'reminder_hours_before', 'updated_at']
    search_fields = ['user__email', 'user__first_name', 'user__last_name']
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = (
        ('Usuario', {
            'fields': ('user',)
        }),
        ('Notificaciones de Panel', {
            'fields': (
                'panel_shift_assigned',
                'panel_shift_modified',
                'panel_shift_cancelled',
                'panel_shift_reminder',
                'panel_request_response'
            )
        }),
        ('Notificaciones por Email', {
            'fields': (
                'email_shift_assigned',
                'email_shift_modified',
                'email_shift_cancelled',
                'email_shift_reminder',
                'email_request_response'
            )
        }),
        ('Configuración', {
            'fields': ('reminder_hours_before',)
        }),
        ('Fechas', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )