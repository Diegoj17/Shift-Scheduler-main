from rest_framework import serializers
from .models import Notification, NotificationPreference

class NotificationSerializer(serializers.ModelSerializer):
    """
    Serializer para las notificaciones
    """
    time = serializers.SerializerMethodField()
    unread = serializers.SerializerMethodField()
    
    class Meta:
        model = Notification
        fields = [
            'id',
            'type',
            'icon',
            'title',
            'message',
            'is_read',
            'unread',
            'created_at',
            'read_at',
            'time',
            'related_shift',
            'related_request',
            'email_sent'
        ]
        read_only_fields = ['created_at', 'read_at', 'email_sent']
    
    def get_time(self, obj):
        """Retorna tiempo relativo de la notificación"""
        return obj.get_time_since_created()
    
    def get_unread(self, obj):
        """Retorna si la notificación no ha sido leída"""
        return not obj.is_read


class NotificationPreferenceSerializer(serializers.ModelSerializer):
    """
    Serializer para las preferencias de notificación
    """
    class Meta:
        model = NotificationPreference
        fields = [
            'id',
            'panel_shift_assigned',
            'panel_shift_modified',
            'panel_shift_cancelled',
            'panel_shift_reminder',
            'panel_request_response',
            'email_shift_assigned',
            'email_shift_modified',
            'email_shift_cancelled',
            'email_shift_reminder',
            'email_request_response',
            'reminder_hours_before',
            'created_at',
            'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']