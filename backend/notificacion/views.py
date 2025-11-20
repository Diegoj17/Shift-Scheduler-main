from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from .models import Notification, NotificationPreference
from .serializers import NotificationSerializer, NotificationPreferenceSerializer
from rest_framework.pagination import PageNumberPagination


class StandardResultsSetPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100

class NotificationViewSet(viewsets.ModelViewSet):
    """
    ViewSet para gestionar notificaciones del usuario
    """
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination
    
    def get_queryset(self):
        """Retorna solo las notificaciones del usuario actual"""
        return Notification.objects.filter(user=self.request.user)
    
    def list(self, request):
        """Lista todas las notificaciones del usuario"""
        queryset = self.get_queryset()
        
        # Filtros opcionales
        is_read = request.query_params.get('is_read')
        if is_read is not None:
            is_read_bool = is_read.lower() == 'true'
            queryset = queryset.filter(is_read=is_read_bool)
        
        # Soporte para paginación si se pasan params de paginación
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            paginated = self.get_paginated_response(serializer.data).data

            # Normalize response to keep existing frontend keys
            return Response({
                'count': queryset.count(),
                'unread_count': self.get_queryset().filter(is_read=False).count(),
                'notifications': paginated.get('results', []),
                'next': paginated.get('next'),
                'previous': paginated.get('previous')
            })

        # Límite simple (legacy) si se usa param `limit`
        limit = request.query_params.get('limit')
        if limit:
            try:
                queryset = queryset[:int(limit)]
            except ValueError:
                pass

        serializer = self.get_serializer(queryset, many=True)
        return Response({
            'count': queryset.count(),
            'unread_count': self.get_queryset().filter(is_read=False).count(),
            'notifications': serializer.data
        })
    
    @action(detail=True, methods=['post'])
    def mark_as_read(self, request, pk=None):
        """Marca una notificación como leída"""
        notification = self.get_object()
        notification.mark_as_read()
        
        serializer = self.get_serializer(notification)
        return Response(serializer.data)
    
    @action(detail=False, methods=['post'])
    def mark_all_as_read(self, request):
        """Marca todas las notificaciones como leídas"""
        updated = self.get_queryset().filter(is_read=False).update(
            is_read=True,
            read_at=timezone.now()
        )
        
        return Response({
            'message': f'{updated} notificaciones marcadas como leídas',
            'updated_count': updated
        })
    
    @action(detail=False, methods=['get'])
    def unread_count(self, request):
        """Retorna el conteo de notificaciones no leídas"""
        count = self.get_queryset().filter(is_read=False).count()
        return Response({'unread_count': count})
    
    @action(detail=False, methods=['delete'])
    def delete_all_read(self, request):
        """Elimina todas las notificaciones leídas"""
        deleted_count, _ = self.get_queryset().filter(is_read=True).delete()
        
        return Response({
            'message': f'{deleted_count} notificaciones eliminadas',
            'deleted_count': deleted_count
        })
        
    def retrieve(self, request, pk=None):
        """Detalle de una notificación específica"""
        notification = self.get_object()
        serializer = self.get_serializer(notification)
        return Response(serializer.data)

    def destroy(self, request, pk=None):
        """Eliminar una notificación específica"""
        notification = self.get_object()
        notification.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class NotificationPreferenceViewSet(viewsets.ModelViewSet):
    """
    ViewSet para gestionar preferencias de notificación
    """
    serializer_class = NotificationPreferenceSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        """Retorna solo las preferencias del usuario actual"""
        return NotificationPreference.objects.filter(user=self.request.user)
    
    def list(self, request):
        """Retorna las preferencias del usuario (crea si no existen)"""
        preferences, created = NotificationPreference.objects.get_or_create(
            user=request.user
        )
        serializer = self.get_serializer(preferences)
        return Response(serializer.data)
    
    @action(detail=False, methods=['put', 'patch'])
    def update_preferences(self, request):
        """Actualiza las preferencias del usuario"""
        preferences, created = NotificationPreference.objects.get_or_create(
            user=request.user
        )
        
        serializer = self.get_serializer(
            preferences,
            data=request.data,
            partial=True
        )
        
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)