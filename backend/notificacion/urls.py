from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import NotificationViewSet, NotificationPreferenceViewSet

router = DefaultRouter()
router.register(r'notifications', NotificationViewSet, basename='notification')
router.register(r'preferences', NotificationPreferenceViewSet, basename='notification-preference')

urlpatterns = [
    path('', include(router.urls)),
    
    # Endpoints adicionales para NotificationViewSet
    path('notifications/<int:pk>/mark_as_read/', 
         NotificationViewSet.as_view({'post': 'mark_as_read'}), 
         name='notification-mark-read'),
    
    path('notifications/mark_all_as_read/', 
         NotificationViewSet.as_view({'post': 'mark_all_as_read'}), 
         name='notification-mark-all-read'),
    
    path('notifications/delete_all_read/', 
         NotificationViewSet.as_view({'delete': 'delete_all_read'}), 
         name='notification-delete-all-read'),
    
    path('notifications/unread_count/', 
         NotificationViewSet.as_view({'get': 'unread_count'}), 
         name='notification-unread-count'),
    
    # Endpoints para NotificationPreferenceViewSet
    path('preferences/update_preferences/', 
         NotificationPreferenceViewSet.as_view({'put': 'update_preferences', 'patch': 'update_preferences'}), 
         name='notification-preferences-update'),
]