from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from .models import Notification, NotificationPreference
from .serializers import NotificationSerializer, NotificationPreferenceSerializer
from rest_framework.pagination import PageNumberPagination
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse, JsonResponse
import json
import logging

logger = logging.getLogger(__name__)
from django.conf import settings
import base64

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from cryptography.exceptions import InvalidSignature
    CRYPTO_AVAILABLE = True
except Exception:
    CRYPTO_AVAILABLE = False


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


@csrf_exempt
def sendgrid_event_webhook(request):
    """
    Endpoint para recibir eventos del Event Webhook de SendGrid.
    Recibe un JSON array con uno o más eventos y los procesa.
    - Para pruebas locales, puedes deshabilitar la firma en SendGrid y usar ngrok.
    - Para producción, habilita la verificación de firma en SendGrid y valida los headers.
    """
    if request.method != 'POST':
        return HttpResponse(status=405)

    # Verificar firma si está habilitado en settings
    if getattr(settings, 'SENDGRID_VERIFY_SIGNATURE', False):
        sig_header = request.META.get('HTTP_X_TWILIO_EMAIL_EVENT_WEBHOOK_SIGNATURE')
        ts_header = request.META.get('HTTP_X_TWILIO_EMAIL_EVENT_WEBHOOK_TIMESTAMP')
        pubkey = getattr(settings, 'SENDGRID_WEBHOOK_PUBLIC_KEY', None)

        if not CRYPTO_AVAILABLE:
            logger.error('cryptography no está disponible; no se puede verificar firma')
            return HttpResponse(status=500)

        if not sig_header or not ts_header or not pubkey:
            logger.warning('Falta firma/timestamp/clave pública para verificar webhook')
            return HttpResponse(status=400)

        try:
            payload_bytes = request.body
            signed = ts_header.encode('utf-8') + payload_bytes

            # Preparar clave pública: puede venir base64 o ya en PEM
            pub = pubkey.strip()
            if not pub.startswith('-----BEGIN'):
                # envolver en PEM
                pub = '-----BEGIN PUBLIC KEY-----\n' + pub + '\n-----END PUBLIC KEY-----\n'

            public_key = load_pem_public_key(pub.encode('utf-8'))

            signature = base64.b64decode(sig_header)

            # Intentar verificación ECDSA (SendGrid usa ECDSA P-256 en la mayoría de cuentas)
            try:
                public_key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
            except InvalidSignature:
                # Probar RSA PKCS1v15 por compatibilidad
                try:
                    public_key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
                except InvalidSignature:
                    logger.warning('Firma inválida en webhook SendGrid')
                    return HttpResponse(status=403)
        except Exception:
            logger.exception('Error verificando firma del webhook SendGrid')
            return HttpResponse(status=400)

    try:
        payload = request.body.decode('utf-8')
        events = json.loads(payload)
    except Exception:
        logger.exception('Payload inválido en webhook SendGrid')
        return HttpResponse(status=400)

    # events es una lista de objetos con key 'event' (p.ej. 'bounce','delivered','open','click','spamreport')
    for ev in events:
        try:
            logger.info(f"SendGrid event recibido: {ev}")

            ev_type = ev.get('event')
            email = ev.get('email')

            # Ejemplo de acciones: si hay bounce/spamreport/dropped -> marcar usuario en supresión
            if ev_type in ('bounce', 'dropped', 'spamreport'):
                logger.warning(f"Evento de supresión: {ev_type} para {email}")
                # Aquí puedes marcar el usuario como no susceptible a emails o guardar el evento en DB
                # from .models import EmailSuppression  # ejemplo
                # EmailSuppression.objects.create(email=email, event=ev_type, raw=ev)

            # Si necesitas otras acciones, amplia este bloque (p.ej. delivered -> confirmar entrega)

        except Exception:
            logger.exception('Error procesando evento SendGrid')
            continue

    return JsonResponse({'received': len(events)})

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