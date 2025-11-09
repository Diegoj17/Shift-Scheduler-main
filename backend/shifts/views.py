from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse
from django.contrib import messages
from django.db import transaction
from django.views.generic import ListView, CreateView, UpdateView, DeleteView
from django.urls import reverse_lazy
from datetime import datetime, timedelta
import json

from .models import Shift, ShiftType, Employee
from .forms import ShiftForm, ShiftTypeForm, ShiftDuplicateForm

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework_simplejwt.authentication import JWTAuthentication
from .serializers import ShiftTypeSerializer, ShiftCreateSerializer, ShiftUpdateSerializer, ShiftSerializer, AvailabilitySerializer, AvailabilityListSerializer, TimeEntrySerializer, TimeEntryListSerializer, ShiftChangeRequestListSerializer, ShiftChangeRequestSerializer, ShiftChangeRequestReviewSerializer
import logging
import traceback
from django.conf import settings
from django.db import connection
from django.contrib.auth import get_user_model
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt


class ShiftListView(ListView):
    model = Shift
    template_name = 'shifts/shift_list.html'
    context_object_name = 'shifts'


def shift_calendar(request):
    shifts = Shift.objects.select_related('employee', 'shift_type').all()
    shift_types = ShiftType.objects.all()
    employees = Employee.objects.filter(is_active=True)
    
    shifts_data = []
    for shift in shifts:
        shifts_data.append({
            'id': shift.id,
            # Mostrar puesto/rol según el perfil del empleado (asignado por gerente/admin)
            'title': f"{shift.employee.user.first_name} - {getattr(shift.employee.user, 'puesto', None) or getattr(shift.employee, 'position', '')}",
            'start': f"{shift.date}T{shift.start_time}",
            'end': f"{shift.date}T{shift.end_time}",
            'color': shift.shift_type.color,
            'employee': shift.employee.user.get_full_name(),
            'shift_type': shift.shift_type.name,
            'role': getattr(shift.employee.user, 'puesto', None) or getattr(shift.employee, 'position', None),
        })
    
    context = {
        'shifts_json': json.dumps(shifts_data),
        'shift_types': shift_types,
        'employees': employees,
    }
    return render(request, 'shifts/calendar.html', context)

class ShiftCreateView(CreateView):
    model = Shift
    form_class = ShiftForm
    template_name = 'shifts/shift_form.html'
    success_url = reverse_lazy('shift_calendar')
    
    def form_valid(self, form):
        try:
            # Asignar automáticamente el role/puesto desde el perfil del empleado
            # (el gerente/admin debe haberlo rellenado en el usuario o en el
            # objeto Employee). No confíes en datos del formulario para eso.
            employee = form.cleaned_data.get('employee')
            role_value = None
            if employee is not None:
                # intento: primero desde el usuario enlazado
                try:
                    user = getattr(employee, 'user', None)
                    if user is not None:
                        role_value = getattr(user, 'puesto', None)
                except Exception:
                    role_value = None

                # fallback al campo `position` del modelo Employee (si existe)
                if not role_value:
                    try:
                        role_value = getattr(employee, 'position', None)
                    except Exception:
                        role_value = None

            # asignar al instance antes de guardar
            if role_value:
                form.instance.role = role_value

            response = super().form_valid(form)
            messages.success(self.request, 'Turno creado exitosamente')
            return response
        except Exception as e:
            messages.error(self.request, f'Error al crear turno: {str(e)}')
            return self.form_invalid(form)

class ShiftUpdateView(UpdateView):
    model = Shift
    form_class = ShiftForm
    template_name = 'shifts/shift_form.html'
    success_url = reverse_lazy('shift_calendar')
    
    def form_valid(self, form):
        try:
            response = super().form_valid(form)
            messages.success(self.request, 'Turno actualizado exitosamente')
            return response
        except Exception as e:
            messages.error(self.request, f'Error al actualizar turno: {str(e)}')
            return self.form_invalid(form)

class ShiftDeleteView(DeleteView):
    model = Shift
    template_name = 'shifts/shift_confirm_delete.html'
    success_url = reverse_lazy('shift_calendar')
    
    def delete(self, request, *args, **kwargs):
        messages.success(request, 'Horario eliminado exitosamente')
        return super().delete(request, *args, **kwargs)

def shift_duplicate(request):
    if request.method == 'POST':
        form = ShiftDuplicateForm(request.POST)
        if form.is_valid():
            start_date = form.cleaned_data['start_date']
            end_date = form.cleaned_data['end_date']
            target_start_date = form.cleaned_data['target_start_date']
            
            # Calcular diferencia de días
            day_difference = (target_start_date - start_date).days
            
            # Obtener turnos en el rango origen
            source_shifts = Shift.objects.filter(
                date__range=[start_date, end_date]
            ).select_related('employee', 'shift_type')
            
            created_count = 0
            conflict_count = 0
            conflicts = []
            
            with transaction.atomic():
                for source_shift in source_shifts:
                    new_date = source_shift.date + timedelta(days=day_difference)
                    
                    # Verificar si ya existe un turno para el empleado en la nueva fecha/hora
                    conflicting_shift = Shift.objects.filter(
                        employee=source_shift.employee,
                        date=new_date,
                        start_time__lt=source_shift.end_time,
                        end_time__gt=source_shift.start_time
                    ).exists()
                    
                    if not conflicting_shift:
                        # Crear nuevo turno
                        Shift.objects.create(
                            date=new_date,
                            start_time=source_shift.start_time,
                            end_time=source_shift.end_time,
                            employee=source_shift.employee,
                            shift_type=source_shift.shift_type,
                            notes=source_shift.notes
                        )
                        created_count += 1
                    else:
                        conflict_count += 1
                        conflicts.append({
                            'employee': source_shift.employee,
                            'date': new_date,
                            'time': f"{source_shift.start_time}-{source_shift.end_time}"
                        })
            
            if conflict_count == 0:
                messages.success(request, f'Duplicación completada. {created_count} turnos creados.')
            else:
                messages.warning(request, f'Duplicación parcial. {created_count} turnos creados, {conflict_count} conflictos detectados.')
                
                # Pasar conflictos a la template si es necesario
                request.session['duplication_conflicts'] = conflicts
            
            return redirect('shift_calendar')
    else:
        form = ShiftDuplicateForm()
    
    return render(request, 'shifts/shift_duplicate.html', {'form': form})

# Vistas para ShiftType
class ShiftTypeListView(ListView):
    model = ShiftType
    template_name = 'shifts/shifttype_list.html'
    context_object_name = 'shift_types'

class ShiftTypeCreateView(CreateView):
    model = ShiftType
    form_class = ShiftTypeForm
    template_name = 'shifts/shifttype_form.html'
    success_url = reverse_lazy('shifttype_list')
    
    def form_valid(self, form):
        try:
            response = super().form_valid(form)
            messages.success(self.request, 'Tipo de turno creado exitosamente')
            return response
        except Exception as e:
            messages.error(self.request, f'Error al crear tipo de turno: {str(e)}')
            return self.form_invalid(form)

class ShiftTypeUpdateView(UpdateView):
    model = ShiftType
    form_class = ShiftTypeForm
    template_name = 'shifts/shifttype_form.html'
    success_url = reverse_lazy('shifttype_list')
    
    def form_valid(self, form):
        try:
            response = super().form_valid(form)
            messages.success(self.request, 'Tipo de turno actualizado exitosamente')
            return response
        except Exception as e:
            messages.error(self.request, f'Error al actualizar tipo de turno: {str(e)}')
            return self.form_invalid(form)

class ShiftTypeDeleteView(DeleteView):
    model = ShiftType
    template_name = 'shifts/shifttype_confirm_delete.html'
    success_url = reverse_lazy('shifttype_list')
    
    def delete(self, request, *args, **kwargs):
        messages.success(request, 'Tipo de turno eliminado exitosamente')
        return super().delete(request, *args, **kwargs)


@method_decorator(csrf_exempt, name='dispatch')
class ShiftTypeListAPIView(APIView):
    """API para listar todos los tipos de turno"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        shift_types = ShiftType.objects.all()
        serializer = ShiftTypeSerializer(shift_types, many=True)
        return Response(serializer.data)

@method_decorator(csrf_exempt, name='dispatch')
class ShiftTypeCreateAPIView(APIView):
    """API para crear tipos de turno"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            serializer = ShiftTypeSerializer(data=request.data)
            if serializer.is_valid():
                instance = serializer.save()
                return Response(ShiftTypeSerializer(instance).data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as exc:
            # Log full traceback for server logs
            logging.exception("Unhandled exception creating ShiftType")
            # In DEBUG return full traceback to help debugging; in production return generic message
            if getattr(settings, 'DEBUG', False):
                tb = traceback.format_exc()
                return Response({'detail': str(exc), 'traceback': tb}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response({'detail': 'Internal server error while creating ShiftType'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_exempt, name='dispatch')
class ShiftCreateAPIView(APIView):
    """API para crear turnos desde el frontend (JSON).
    
    ✅ SIMPLIFICADO: Solo pasa datos al serializer sin procesamiento
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            logging.info(f"📥 [ShiftCreateAPIView] Datos recibidos: {request.data}")
            
            # ✅ NO PROCESAR - Pasar directo al serializer
            serializer = ShiftCreateSerializer(data=request.data, context={'request': request})
            
            if serializer.is_valid():
                instance = serializer.save()
                
                logging.info(f"✅ Turno creado: ID={instance.id}, Employee ID={instance.employee.id}, User ID={instance.employee.user.id}")
                
                # Devolver representación completa
                return Response({
                    'id': instance.id,
                    'date': instance.date.isoformat() if instance.date else None,
                    'start_time': instance.start_time.isoformat() if instance.start_time else None,
                    'end_time': instance.end_time.isoformat() if instance.end_time else None,
                    'start': f"{instance.date}T{instance.start_time}" if instance.date and instance.start_time else None,
                    'end': f"{instance.date}T{instance.end_time}" if instance.date and instance.end_time else None,
                    'employee_id': instance.employee.id,
                    'employee_user_id': instance.employee.user.id,
                    'shift_type_id': instance.shift_type.id,
                    'notes': instance.notes,
                }, status=status.HTTP_201_CREATED)
            
            logging.warning(f"❌ Validación fallida: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as exc:
            logging.exception("💥 Error creando turno")
            if getattr(settings, 'DEBUG', False):
                return Response({
                    'detail': str(exc), 
                    'traceback': traceback.format_exc()
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response({
                'detail': 'Error al crear turno'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@method_decorator(csrf_exempt, name='dispatch')
class ShiftTypeUpdateAPIView(APIView):
    """API para actualizar tipos de turno"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def put(self, request, pk, *args, **kwargs):
        try:
            shift_type = ShiftType.objects.get(pk=pk)
        except ShiftType.DoesNotExist:
            return Response(
                {"error": "Tipo de turno no encontrado"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        serializer = ShiftTypeSerializer(shift_type, data=request.data)
        if serializer.is_valid():
            instance = serializer.save()
            return Response(ShiftTypeSerializer(instance).data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@method_decorator(csrf_exempt, name='dispatch')
class ShiftTypeDeleteAPIView(APIView):
    """API para eliminar tipos de turno"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, pk, *args, **kwargs):
        try:
            shift_type = ShiftType.objects.get(pk=pk)
        except ShiftType.DoesNotExist:
            return Response(
                {"error": "Tipo de turno no encontrado"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        shift_type.delete()
        return Response(
            {"message": "Tipo de turno eliminado exitosamente"}, 
            status=status.HTTP_204_NO_CONTENT
        )


@method_decorator(csrf_exempt, name='dispatch')
class ShiftListAPIView(APIView):
    """API para listar todos los turnos con información completa"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        try:
            import pytz
            logger = logging.getLogger(__name__)
            logger.info("🔍 [ShiftListAPIView] Iniciando...")
            
            # ✅ Obtener zona horaria local
            local_tz = pytz.timezone(settings.TIME_ZONE)
            
            # Obtener turnos con relaciones precargadas
            shifts = Shift.objects.select_related(
                'employee__user', 
                'shift_type'
            ).all().order_by('-date', '-start_time')
            
            shifts_data = []
            
            for shift in shifts:
                try:
                    # Validar datos mínimos
                    if not all([shift.date, shift.start_time, shift.end_time, shift.employee]):
                        logger.warning(f"⚠️ Shift {shift.id} con datos incompletos")
                        continue
                    
                    # ✅ CRÍTICO: Obtener IDs correctos
                    employee_id = shift.employee.id                     # Employee ID (BD)
                    user_id = shift.employee.user.id if shift.employee.user else None  # User ID
                    
                    logger.info(f"📊 Shift {shift.id}: employee_id={employee_id}, user_id={user_id}")
                    
                    # Información del empleado
                    employee_name = "Sin nombre"
                    role = "Sin rol"
                    
                    if shift.employee.user:
                        user = shift.employee.user
                        first_name = getattr(user, 'first_name', '') or ''
                        last_name = getattr(user, 'last_name', '') or ''
                        employee_name = f"{first_name} {last_name}".strip() or user.email
                        
                        # Rol/Puesto
                        puesto = getattr(user, 'puesto', None)
                        if puesto and puesto != "NULL":
                            role = puesto
                        else:
                            role = getattr(shift.employee, 'position', 'Sin rol') or 'Sin rol'
                    
                    # Tipo de turno
                    color = '#3788d8'
                    shift_type_name = 'Sin tipo'
                    shift_type_id = None
                    
                    if shift.shift_type:
                        color = getattr(shift.shift_type, 'color', '#3788d8') or '#3788d8'
                        shift_type_name = shift.shift_type.name
                        shift_type_id = shift.shift_type.id
                    
                    # ✅ CRÍTICO: Formatear fechas sin zona horaria (formato local)
                    # La fecha ya es un objeto date (sin hora), usar directamente
                    shift_date_str = shift.date.isoformat()
                    
                    # Para las horas, usar formato HH:MM:SS sin zona horaria
                    start_time_str = shift.start_time.isoformat() if shift.start_time else '00:00:00'
                    end_time_str = shift.end_time.isoformat() if shift.end_time else '00:00:00'
                    
                    # ✅ Crear timestamps combinando fecha + hora (sin TZ)
                    start_datetime_str = f"{shift_date_str}T{start_time_str}"
                    end_datetime_str = f"{shift_date_str}T{end_time_str}"
                    
                    logger.debug(f"📅 Shift {shift.id}: date={shift_date_str}, start={start_time_str}, end={end_time_str}")
                    
                    shift_info = {
                        'id': shift.id,
                        'title': f"{employee_name} - {role}",
                        'start': start_datetime_str,
                        'end': end_datetime_str,
                        'color': color,
                        
                        # ✅ CRÍTICO: Información del empleado
                        'employee': employee_name,
                        'employee_id': employee_id,           # Employee ID (referencia BD)
                        'employee_user_id': user_id,          # ✅ USER_ID (para enviar al backend)
                        'employeeId': employee_id,            # Compatibilidad
                        'employeeUserId': user_id,            # ✅ Para frontend
                        'employeeName': employee_name,        # ✅ Para modal
                        'role': role,
                        
                        # ✅ Información del tipo de turno
                        'shift_type_id': shift_type_id,
                        'shift_type_name': shift_type_name,
                        'shiftTypeId': shift_type_id,         # Compatibilidad
                        'shiftTypeName': shift_type_name,     # Compatibilidad
                        
                        # ✅ Campos adicionales para edición (FORMATO LOCAL sin TZ)
                        'date': shift_date_str,
                        'start_time': start_time_str,
                        'end_time': end_time_str,
                        'startTime': start_time_str,  # Compatibilidad
                        'endTime': end_time_str,      # Compatibilidad
                        'notes': shift.notes or '',
                    }
                    
                    shifts_data.append(shift_info)
                    logger.debug(f"✅ Shift {shift.id}: employee_id={employee_id}, user_id={user_id}")
                    
                except Exception as shift_error:
                    logger.exception(f"💥 Error procesando shift {shift.id}: {shift_error}")
                    continue
            
            logger.info(f"✅ [ShiftListAPIView] Retornando {len(shifts_data)} turnos")
            return Response(shifts_data, status=status.HTTP_200_OK)
            
        except Exception as exc:
            logger = logging.getLogger(__name__)
            logger.exception("💥 [ShiftListAPIView] Error global")
            if getattr(settings, 'DEBUG', False):
                return Response({
                    'error': 'Error interno del servidor',
                    'detail': str(exc),
                    'traceback': traceback.format_exc()
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response({
                'error': 'Error interno del servidor'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_exempt, name='dispatch')
class ShiftUpdateAPIView(APIView):
    """API para actualizar un turno existente."""
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def put(self, request, pk, *args, **kwargs):
        logging.info(f"🔄 [ShiftUpdateAPIView] Iniciando actualización del turno {pk}")
        logging.info(f"📥 Datos recibidos: {request.data}")
        
        try:
            shift = Shift.objects.get(pk=pk)
            logging.info(f"✅ Turno encontrado: ID={shift.id}, Employee ID={shift.employee.id}, User ID={shift.employee.user.id}")
        except Shift.DoesNotExist:
            logging.error(f"❌ Turno {pk} no encontrado")
            return Response({'error': 'Turno no encontrado'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logging.error(f"❌ Error buscando turno: {str(e)}")
            return Response({'error': 'Error interno'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # ✅ LOG DETALLADO para debugging
        logging.info(f"🔍 DEBUG - Employee ID recibido: {request.data.get('employee')}")
        logging.info(f"🔍 DEBUG - Employee actual: {shift.employee.id}")
        logging.info(f"🔍 DEBUG - ShiftType ID recibido: {request.data.get('shift_type')}")

        try:
            serializer = ShiftCreateSerializer(instance=shift, data=request.data)
            
            if serializer.is_valid():
                logging.info("✅ Serializer válido, procediendo a guardar...")
                instance = serializer.save()
                
                logging.info(f"✅ Turno actualizado exitosamente: ID={instance.id}")
                return Response({
                    'id': instance.id,
                    'date': instance.date.isoformat(),
                    'start_time': instance.start_time.isoformat(),
                    'end_time': instance.end_time.isoformat(),
                    'employee': instance.employee.id,
                    'employee_user_id': instance.employee.user.id,
                    'shift_type': instance.shift_type.id,
                    'notes': instance.notes or '',
                }, status=status.HTTP_200_OK)
            else:
                logging.error(f"❌ Errores de validación: {serializer.errors}")
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
                
        except Exception as exc:
            logging.exception("💥 Error CRÍTICO al actualizar turno")
            return Response({
                'detail': 'Error interno del servidor al actualizar turno',
                'error': str(exc)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_exempt, name='dispatch')
class ShiftDeleteAPIView(APIView):
    """API para eliminar un turno por pk."""
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, pk, *args, **kwargs):
        try:
            shift = Shift.objects.get(pk=pk)
        except Shift.DoesNotExist:
            return Response({'error': 'Turno no encontrado'}, status=status.HTTP_404_NOT_FOUND)

        try:
            shift.delete()
            return Response({'message': 'Turno eliminado exitosamente'}, status=status.HTTP_204_NO_CONTENT)
        except Exception as exc:
            logging.exception("Unhandled exception deleting Shift via API")
            if getattr(settings, 'DEBUG', False):
                return Response({'detail': str(exc), 'traceback': traceback.format_exc()}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response({'detail': 'Error al eliminar turno'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_exempt, name='dispatch')
class ShiftDuplicateAPIView(APIView):
    """API para duplicar turnos desde un rango origen hacia una fecha objetivo.

    Espera JSON con: start_date, end_date, target_start_date (formato ISO YYYY-MM-DD).
    Devuelve conteos y lista de conflictos (si los hay).
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        data = request.data
        try:
            start_date_str = data.get('start_date')
            end_date_str = data.get('end_date')
            target_start_date_str = data.get('target_start_date')

            if not (start_date_str and end_date_str and target_start_date_str):
                return Response({'error': 'start_date, end_date y target_start_date son requeridos'}, status=status.HTTP_400_BAD_REQUEST)

            start_date = datetime.fromisoformat(start_date_str).date()
            end_date = datetime.fromisoformat(end_date_str).date()
            target_start_date = datetime.fromisoformat(target_start_date_str).date()

        except Exception as exc:
            return Response({'error': 'Formato de fecha inválido, usar YYYY-MM-DD'}, status=status.HTTP_400_BAD_REQUEST)

        day_difference = (target_start_date - start_date).days

        source_shifts = Shift.objects.filter(date__range=[start_date, end_date]).select_related('employee', 'shift_type')

        created_count = 0
        conflict_count = 0
        conflicts = []

        with transaction.atomic():
            for source_shift in source_shifts:
                new_date = source_shift.date + timedelta(days=day_difference)

                conflicting_shift = Shift.objects.filter(
                    employee=source_shift.employee,
                    date=new_date,
                    start_time__lt=source_shift.end_time,
                    end_time__gt=source_shift.start_time
                ).exists()

                if not conflicting_shift:
                    Shift.objects.create(
                        date=new_date,
                        start_time=source_shift.start_time,
                        end_time=source_shift.end_time,
                        employee=source_shift.employee,
                        shift_type=source_shift.shift_type,
                        notes=source_shift.notes
                    )
                    created_count += 1
                else:
                    conflict_count += 1
                    conflicts.append({
                        'employee_id': getattr(source_shift.employee, 'id', None),
                        'date': new_date.isoformat(),
                        'time': f"{source_shift.start_time}-{source_shift.end_time}",
                    })

        result = {
            'created': created_count,
            'conflicts': conflict_count,
            'conflict_items': conflicts,
        }

        status_code = status.HTTP_201_CREATED if conflict_count == 0 else status.HTTP_207_MULTI_STATUS
        return Response(result, status=status_code)
    
class MyShiftsAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        import logging
        from django.utils import timezone
        import pytz
        from datetime import datetime, timedelta
        
        logger = logging.getLogger(__name__)
        
        try:
            user = request.user
            logger.info(f"🔍 [MyShiftsAPIView] Usuario autenticado: ID={user.id}, Email={user.email}")
            
            # Buscar el Employee asociado al usuario
            try:
                employee = Employee.objects.get(user=user)
                logger.info(f"✅ [MyShiftsAPIView] Employee encontrado: ID={employee.id}, Position={employee.position}")
                
                # ✅ OBTENER PARÁMETROS DE FILTRO CON ZONA HORARIA CORRECTA
                start_date = request.query_params.get('start_date')
                end_date = request.query_params.get('end_date')
                
                logger.info(f"📅 Parámetros de filtro recibidos: start_date={start_date}, end_date={end_date}")
                
                # Construir queryset base
                shifts_qs = Shift.objects.filter(employee=employee).select_related(
                    'shift_type', 'employee__user'
                )
                
                # ✅ APLICAR FILTROS DE FECHA CON ZONA HORARIA LOCAL
                local_tz = pytz.timezone(settings.TIME_ZONE)  # 'America/Bogota'
                
                if start_date:
                    try:
                        # Convertir a datetime con zona horaria local
                        start_date_naive = datetime.fromisoformat(start_date)
                        start_date_local = local_tz.localize(start_date_naive)
                        shifts_qs = shifts_qs.filter(date__gte=start_date_local.date())
                        logger.info(f"📅 Filtrado desde: {start_date_local.date()}")
                    except (ValueError, TypeError) as e:
                        logger.warning(f"⚠️ Error al parsear start_date: {e}")
                
                if end_date:
                    try:
                        # Convertir a datetime con zona horaria local
                        end_date_naive = datetime.fromisoformat(end_date)
                        end_date_local = local_tz.localize(end_date_naive)
                        shifts_qs = shifts_qs.filter(date__lte=end_date_local.date())
                        logger.info(f"📅 Filtrado hasta: {end_date_local.date()}")
                    except (ValueError, TypeError) as e:
                        logger.warning(f"⚠️ Error al parsear end_date: {e}")
                
                # Ordenar por fecha y hora
                shifts_qs = shifts_qs.order_by('date', 'start_time')
                
                total_shifts = shifts_qs.count()
                logger.info(f"📊 [MyShiftsAPIView] Total de turnos después de filtros: {total_shifts}")
                
                # ✅ Obtener la fecha/hora actual en la zona horaria local para filtrar turnos futuros
                now_local = timezone.now().astimezone(local_tz)
                
                # Construir respuesta
                results = []
                for s in shifts_qs:
                    # ✅ Calcular si el turno tiene más de 24 horas de anticipación
                    shift_datetime_naive = datetime.combine(s.date, s.start_time)
                    shift_datetime_local = local_tz.localize(shift_datetime_naive)
                    
                    # Calcular diferencia en horas
                    time_diff = shift_datetime_local - now_local
                    hours_until_shift = time_diff.total_seconds() / 3600
                    
                    # Solo incluir turnos con más de 24 horas de anticipación
                    if hours_until_shift >= 24:
                        # Obtener información del empleado
                        employee_position = s.employee.position if s.employee else None
                        user_obj = s.employee.user if s.employee else None
                        employee_name = f"{user_obj.first_name or ''} {user_obj.last_name or ''}".strip() if user_obj else None
                        
                        shift_data = {
                            'id': s.id,
                            'date': s.date.isoformat() if s.date else None,
                            'start_time': s.start_time.isoformat() if s.start_time else None,
                            'end_time': s.end_time.isoformat() if s.end_time else None,
                            'start': f"{s.date}T{s.start_time}" if s.date and s.start_time else None,
                            'end': f"{s.date}T{s.end_time}" if s.date and s.end_time else None,
                            'employee': s.employee.id,
                            'employee_name': employee_name,
                            'employee_position': employee_position,  
                            'shift_type': s.shift_type.id if s.shift_type else None,
                            'shift_type_name': getattr(s.shift_type, 'name', None),
                            'shift_type_color': getattr(s.shift_type, 'color', None),
                            'notes': s.notes or '',
                            'status': 'confirmed',
                            'hours_until_shift': hours_until_shift  # Para debugging
                        }
                        results.append(shift_data)
                        
                        logger.info(f"📋 Turno {s.id}: Fecha={s.date}, Horas hasta turno={hours_until_shift:.1f}")
                    else:
                        logger.info(f"⏰ Turno {s.id} excluido: Muy pronto (horas hasta turno={hours_until_shift:.1f})")
                
                logger.info(f"✅ [MyShiftsAPIView] Retornando {len(results)} turnos válidos")
                return Response({'results': results}, status=status.HTTP_200_OK)
                
            except Employee.DoesNotExist:
                logger.error(f"❌ [MyShiftsAPIView] NO existe Employee para usuario {user.id}")
                return Response({
                    'results': [],
                    'message': 'No se encontró registro de empleado para este usuario'
                }, status=status.HTTP_200_OK)
                
        except Exception as exc:
            logger.exception("💥 [MyShiftsAPIView] Error inesperado al obtener turnos")
            if getattr(settings, 'DEBUG', False):
                return Response({
                    'results': [],
                    'error': str(exc),
                    'traceback': traceback.format_exc()
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response({'results': [], 'error': 'Error interno del servidor'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@method_decorator(csrf_exempt, name='dispatch')
class AvailabilityCreateAPIView(APIView):
    """
    API para que SOLO EMPLEADOS registren su disponibilidad.
    POST /api/shifts/availability/new/
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request, *args, **kwargs):
        logger = logging.getLogger(__name__)
        
        try:
            user = request.user
            logger.info(f"📝 [AvailabilityCreate] Usuario: {user.email}, Rol: {user.role}")
            
            # ✅ SOLO EMPLEADOS pueden crear disponibilidad
            if user.role in ['ADMIN', 'GERENTE']:
                return Response({
                    'detail': 'Solo los empleados pueden crear registros de disponibilidad'
                }, status=status.HTTP_403_FORBIDDEN)
            
            # Verificar que el usuario tenga perfil de empleado
            try:
                employee = Employee.objects.get(user=user)
            except Employee.DoesNotExist:
                return Response({
                    'detail': 'No se encontró perfil de empleado para este usuario'
                }, status=status.HTTP_404_NOT_FOUND)
            
            logger.info(f"📝 Datos recibidos: {request.data}")
            
            serializer = AvailabilitySerializer(data=request.data, context={'request': request})
            
            if serializer.is_valid():
                instance = serializer.save()
                
                # Construir respuesta
                response_data = {
                    'id': instance.id,
                    'date': instance.date.isoformat(),
                    'start_time': instance.start_time.isoformat(),
                    'end_time': instance.end_time.isoformat(),
                    'type': instance.type,
                    'color': instance.get_color(),
                    'notes': instance.notes or '',
                    'employee': instance.employee.id,
                    'employee_name': f"{instance.employee.user.first_name} {instance.employee.user.last_name}".strip(),
                    'duration_hours': instance.duration_hours()
                }
                
                logger.info(f"✅ Disponibilidad creada: ID={instance.id}")
                return Response(response_data, status=status.HTTP_201_CREATED)
            
            logger.warning(f"❌ Validación fallida: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as exc:
            logger.exception("💥 Error al crear disponibilidad")
            if getattr(settings, 'DEBUG', False):
                return Response({
                    'detail': str(exc),
                    'traceback': traceback.format_exc()
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response({
                'detail': 'Error al crear disponibilidad'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_exempt, name='dispatch')
class AvailabilityListAPIView(APIView):
    """
    API para listar disponibilidades.
    GET /api/shifts/availability/
    
    - EMPLEADOS: Solo ven sus propias disponibilidades
    - GERENTE/ADMIN: Pueden ver disponibilidades de todos
    
    Filtros opcionales (solo para GERENTE/ADMIN):
    - start_date: Fecha inicio (YYYY-MM-DD)
    - end_date: Fecha fin (YYYY-MM-DD)
    - employee: ID del empleado
    - type: available o unavailable
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, *args, **kwargs):
        from .models import Availability
        import pytz
        logger = logging.getLogger(__name__)
        
        try:
            user = request.user
            logger.info(f"🔍 [AvailabilityList] Usuario: {user.email}, Rol: {user.role}")
            
            # ✅ Si es EMPLEADO, solo ver sus propias disponibilidades
            if user.role == 'EMPLEADO':
                try:
                    employee = Employee.objects.get(user=user)
                    availabilities = Availability.objects.filter(employee=employee)
                    logger.info(f"👤 Empleado viendo sus disponibilidades: {availabilities.count()}")
                except Employee.DoesNotExist:
                    return Response({
                        'results': [],
                        'message': 'No se encontró perfil de empleado'
                    }, status=status.HTTP_200_OK)
            else:
                # ✅ GERENTE/ADMIN pueden ver todas (solo consulta)
                availabilities = Availability.objects.all()
                logger.info(f"👔 Gerente/Admin consultando todas las disponibilidades: {availabilities.count()}")
            
            # ✅ Aplicar filtros (solo para GERENTE/ADMIN)
            if user.role in ['ADMIN', 'GERENTE']:
                start_date = request.query_params.get('start_date')
                end_date = request.query_params.get('end_date')
                employee_id = request.query_params.get('employee')
                availability_type = request.query_params.get('type')
                
                if start_date:
                    try:
                        from datetime import datetime
                        start_date_obj = datetime.fromisoformat(start_date).date()
                        availabilities = availabilities.filter(date__gte=start_date_obj)
                        logger.info(f"📅 Filtrado desde: {start_date_obj}")
                    except (ValueError, TypeError):
                        pass
                
                if end_date:
                    try:
                        from datetime import datetime
                        end_date_obj = datetime.fromisoformat(end_date).date()
                        availabilities = availabilities.filter(date__lte=end_date_obj)
                        logger.info(f"📅 Filtrado hasta: {end_date_obj}")
                    except (ValueError, TypeError):
                        pass
                
                if employee_id:
                    availabilities = availabilities.filter(employee_id=employee_id)
                    logger.info(f"👤 Filtrado por empleado: {employee_id}")
                
                if availability_type in ['available', 'unavailable']:
                    availabilities = availabilities.filter(type=availability_type)
                    logger.info(f"🏷️ Filtrado por tipo: {availability_type}")
            
            availabilities = availabilities.select_related('employee__user').order_by('date', 'start_time')
            
            # ✅ Construir respuesta manualmente (sin timezone)
            results = []
            for avail in availabilities:
                try:
                    # ✅ Formatear sin zona horaria
                    result_data = {
                        'id': avail.id,
                        'employee_id': avail.employee.id,
                        'employee_name': f"{avail.employee.user.first_name} {avail.employee.user.last_name}".strip() if avail.employee.user else "Desconocido",
                        'employee_position': avail.employee.position or getattr(avail.employee.user, 'puesto', None) or 'Sin puesto',
                        'employee_area': getattr(avail.employee.user, 'departamento', None) or 'Sin área',
                        'date': avail.date.isoformat(),  # ✅ Formato local YYYY-MM-DD
                        'start_time': avail.start_time.isoformat(),  # ✅ HH:MM:SS
                        'end_time': avail.end_time.isoformat(),  # ✅ HH:MM:SS
                        'type': avail.type,
                        'color': avail.get_color(),
                        'notes': avail.notes or '',
                        'duration_hours': avail.duration_hours(),
                        'created_at': avail.created_at.isoformat()
                    }
                    results.append(result_data)
                except Exception as e:
                    logger.exception(f"💥 Error procesando disponibilidad {avail.id}: {e}")
                    continue
            
            logger.info(f"✅ Retornando {len(results)} disponibilidades")
            return Response({'results': results}, status=status.HTTP_200_OK)
            
        except Exception as exc:
            logger.exception("💥 Error al listar disponibilidades")
            if getattr(settings, 'DEBUG', False):
                return Response({
                    'results': [],
                    'error': str(exc),
                    'traceback': traceback.format_exc()
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response({
                'results': [],
                'error': 'Error interno del servidor'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@method_decorator(csrf_exempt, name='dispatch')
class EmployeeListAPIView(APIView):
    """
    API para listar empleados.
    - ADMIN/GERENTE: ven todos los empleados
    - EMPLEADO: ve solo su propio perfil
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        from .models import Employee
        logger = logging.getLogger(__name__)

        try:
            user = request.user
            logger.info(f"🔍 [EmployeeList] Usuario: {user.email}, Rol: {user.role}")

            if user.role == 'EMPLEADO':
                try:
                    emp = Employee.objects.select_related('user').get(user=user)
                    employees_qs = Employee.objects.filter(pk=emp.pk)
                    logger.info(f"👤 Empleado solicitando su propio perfil: ID={emp.id}")
                except Employee.DoesNotExist:
                    return Response({'results': [], 'message': 'No se encontró perfil de empleado'}, status=status.HTTP_200_OK)
            else:
                employees_qs = Employee.objects.select_related('user').all()
                logger.info(f"👔 Gerente/Admin consultando empleados: total={employees_qs.count()}")

            results = []
            for e in employees_qs:
                u = getattr(e, 'user', None)
                results.append({
                    'id': e.id,
                    'user_id': u.id if u else None,
                    'first_name': getattr(u, 'first_name', '') if u else '',
                    'last_name': getattr(u, 'last_name', '') if u else '',
                    'email': getattr(u, 'email', None) if u else None,
                    'position': e.position,
                    'is_active': e.is_active,
                })

            return Response({'results': results}, status=status.HTTP_200_OK)

        except Exception as exc:
            logger.exception("💥 Error listando empleados")
            if getattr(settings, 'DEBUG', False):
                return Response({'results': [], 'error': str(exc), 'traceback': traceback.format_exc()}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response({'results': [], 'error': 'Error interno del servidor'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_exempt, name='dispatch')
class AvailabilityUpdateAPIView(APIView):
    """
    API para actualizar una disponibilidad.
    PUT /api/shifts/availability/<id>/edit/
    
    ✅ SOLO el empleado DUEÑO puede editar su propia disponibilidad
    ❌ Gerentes/Admin NO pueden editar
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def put(self, request, pk, *args, **kwargs):
        from .models import Availability
        logger = logging.getLogger(__name__)
        
        try:
            user = request.user
            
            # ✅ GERENTE/ADMIN no pueden editar disponibilidades
            if user.role in ['ADMIN', 'GERENTE']:
                return Response({
                    'detail': 'Solo los empleados pueden editar registros de disponibilidad'
                }, status=status.HTTP_403_FORBIDDEN)
            
            availability = Availability.objects.get(pk=pk)
            
            # ✅ Verificar que el empleado sea el dueño
            if availability.employee.user != user:
                return Response({
                    'detail': 'No tienes permiso para editar esta disponibilidad'
                }, status=status.HTTP_403_FORBIDDEN)
            
            logger.info(f"🔄 [AvailabilityUpdate] Usuario {user.email} editando disponibilidad {pk}")
            
            serializer = AvailabilitySerializer(
                instance=availability,
                data=request.data,
                context={'request': request}
            )
            
            if serializer.is_valid():
                instance = serializer.save()
                
                response_data = {
                    'id': instance.id,
                    'date': instance.date.isoformat(),
                    'start_time': instance.start_time.isoformat(),
                    'end_time': instance.end_time.isoformat(),
                    'type': instance.type,
                    'color': instance.get_color(),
                    'notes': instance.notes or '',
                    'employee': instance.employee.id
                }
                
                logger.info(f"✅ Disponibilidad actualizada: ID={instance.id}")
                return Response(response_data, status=status.HTTP_200_OK)
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        except Availability.DoesNotExist:
            return Response({
                'error': 'Disponibilidad no encontrada'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as exc:
            logger.exception("💥 Error al actualizar disponibilidad")
            if getattr(settings, 'DEBUG', False):
                return Response({
                    'detail': str(exc),
                    'traceback': traceback.format_exc()
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response({
                'detail': 'Error al actualizar disponibilidad'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_exempt, name='dispatch')
class AvailabilityDeleteAPIView(APIView):
    """
    API para eliminar una disponibilidad.
    DELETE /api/shifts/availability/<id>/delete/
    
    ✅ SOLO el empleado DUEÑO puede eliminar su propia disponibilidad
    ❌ Gerentes/Admin NO pueden eliminar
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def delete(self, request, pk, *args, **kwargs):
        from .models import Availability
        logger = logging.getLogger(__name__)
        
        try:
            user = request.user
            
            # ✅ GERENTE/ADMIN no pueden eliminar disponibilidades
            if user.role in ['ADMIN', 'GERENTE']:
                return Response({
                    'detail': 'Solo los empleados pueden eliminar registros de disponibilidad'
                }, status=status.HTTP_403_FORBIDDEN)
            
            availability = Availability.objects.get(pk=pk)
            
            # ✅ Verificar que el empleado sea el dueño
            if availability.employee.user != user:
                return Response({
                    'detail': 'No tienes permiso para eliminar esta disponibilidad'
                }, status=status.HTTP_403_FORBIDDEN)
            
            logger.info(f"🗑️ [AvailabilityDelete] Usuario {user.email} eliminando disponibilidad {pk}")
            
            availability.delete()
            logger.info(f"✅ Disponibilidad eliminada: ID={pk}")
            
            return Response({
                'message': 'Disponibilidad eliminada exitosamente'
            }, status=status.HTTP_204_NO_CONTENT)
            
        except Availability.DoesNotExist:
            return Response({
                'error': 'Disponibilidad no encontrada'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as exc:
            logger.exception("💥 Error al eliminar disponibilidad")
            if getattr(settings, 'DEBUG', False):
                return Response({
                    'detail': str(exc),
                    'traceback': traceback.format_exc()
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response({
                'detail': 'Error al eliminar disponibilidad'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_exempt, name='dispatch')
class CheckEmployeeAvailabilityAPIView(APIView):
    """
    API para verificar si un empleado está disponible en un horario específico.
    POST /api/shifts/availability/check/
    
    ✅ GERENTE/ADMIN pueden verificar disponibilidad de cualquier empleado
    ✅ EMPLEADOS pueden verificar su propia disponibilidad
    
    Body: {
        "employee": employee_id,
        "date": "YYYY-MM-DD",
        "start_time": "HH:MM",
        "end_time": "HH:MM"
    }
    
    Response: {
        "is_available": true/false,
        "message": "...",
        "conflicts": [...],
        "color": "#22543d" o "#742a2a"
    }
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request, *args, **kwargs):
        from .models import Availability
        from datetime import datetime, timedelta
        logger = logging.getLogger(__name__)
        
        try:
            user = request.user
            employee_id = request.data.get('employee')
            date_str = request.data.get('date')
            start_time_str = request.data.get('start_time')
            end_time_str = request.data.get('end_time')
            
            if not all([employee_id, date_str, start_time_str, end_time_str]):
                return Response({
                    'error': 'Faltan parámetros requeridos'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            try:
                employee = Employee.objects.get(pk=employee_id)
                
                # ✅ Si es EMPLEADO, solo puede verificar su propia disponibilidad
                if user.role == 'EMPLEADO':
                    if employee.user != user:
                        return Response({
                            'detail': 'Solo puedes verificar tu propia disponibilidad'
                        }, status=status.HTTP_403_FORBIDDEN)
                
                date_obj = datetime.fromisoformat(date_str).date()
                start_time_obj = datetime.fromisoformat(f"{date_str}T{start_time_str}").time()
                end_time_obj = datetime.fromisoformat(f"{date_str}T{end_time_str}").time()
            except Employee.DoesNotExist:
                return Response({
                    'error': 'Empleado no encontrado'
                }, status=status.HTTP_404_NOT_FOUND)
            except Exception as e:
                return Response({
                    'error': f'Datos inválidos: {str(e)}'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            logger.info(f"🔍 [CheckAvailability] Verificando empleado {employee_id} para {date_str} {start_time_str}-{end_time_str}")
            
            # ✅ Buscar disponibilidades del empleado en esa fecha
            is_overnight = end_time_obj < start_time_obj
            
            if is_overnight:
                # Turno nocturno
                availabilities_same_day = Availability.objects.filter(
                    employee=employee,
                    date=date_obj,
                    start_time__lt='23:59:59',
                    end_time__gt=start_time_obj
                )
                
                next_day = date_obj + timedelta(days=1)
                availabilities_next_day = Availability.objects.filter(
                    employee=employee,
                    date=next_day,
                    start_time__lt=end_time_obj,
                    end_time__gt='00:00:00'
                )
                
                availabilities = availabilities_same_day.union(availabilities_next_day)
            else:
                # Turno diurno
                availabilities = Availability.objects.filter(
                    employee=employee,
                    date=date_obj,
                    start_time__lt=end_time_obj,
                    end_time__gt=start_time_obj
                )
            
            # ✅ Determinar disponibilidad
            has_unavailable = availabilities.filter(type='unavailable').exists()
            has_available = availabilities.filter(type='available').exists()
            
            if has_unavailable:
                # Hay un registro de NO disponible
                conflicts = list(availabilities.filter(type='unavailable').values(
                    'id', 'date', 'start_time', 'end_time', 'type', 'notes'
                ))
                logger.info(f"❌ Empleado NO disponible - {len(conflicts)} conflictos")
                return Response({
                    'is_available': False,
                    'message': 'El empleado NO está disponible en este horario',
                    'conflicts': conflicts,
                    'color': '#742a2a'
                }, status=status.HTTP_200_OK)
            elif has_available:
                # Hay un registro de disponible
                logger.info(f"✅ Empleado disponible (registro explícito)")
                return Response({
                    'is_available': True,
                    'message': 'El empleado está disponible en este horario',
                    'conflicts': [],
                    'color': '#22543d'
                }, status=status.HTTP_200_OK)
            else:
                # No hay registros - se asume disponible por defecto
                logger.info(f"✅ Empleado disponible (sin registros, asumido)")
                return Response({
                    'is_available': True,
                    'message': 'No hay registros de disponibilidad (asumido disponible)',
                    'conflicts': [],
                    'color': '#22543d'
                }, status=status.HTTP_200_OK)
            
        except Exception as exc:
            logger.exception("💥 Error verificando disponibilidad")
            if getattr(settings, 'DEBUG', False):
                return Response({
                    'error': str(exc),
                    'traceback': traceback.format_exc()
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response({
                'error': 'Error interno del servidor'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
@method_decorator(csrf_exempt, name='dispatch')
class TimeEntryCreateAPIView(APIView):
    """
    API para registrar entrada/salida de empleados.
    POST /api/shifts/time-entry/new/
    
    ✅ SOLO EMPLEADOS pueden registrar
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request, *args, **kwargs):
        logger = logging.getLogger(__name__)
        
        try:
            user = request.user
            logger.info(f"📝 [TimeEntryCreate] Usuario: {user.email}, Tipo: {request.data.get('entry_type')}")
            
            serializer = TimeEntrySerializer(data=request.data, context={'request': request})
            
            if serializer.is_valid():
                instance = serializer.save()
                
                response_data = {
                    'id': instance.id,
                    'employee': instance.employee.id,
                    'employee_name': f"{instance.employee.user.first_name} {instance.employee.user.last_name}".strip(),
                    'entry_type': instance.entry_type,
                    'timestamp': instance.timestamp.isoformat(),
                    'date': instance.date.isoformat(),
                    'time': instance.time.isoformat(),
                    'shift_id': instance.shift.id if instance.shift else None,
                    'notes': instance.notes or '',
                    'location': instance.location or ''
                }
                
                logger.info(f"✅ Registro creado: ID={instance.id}, Tipo={instance.entry_type}")
                return Response(response_data, status=status.HTTP_201_CREATED)
            
            logger.warning(f"❌ Validación fallida: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as exc:
            logger.exception("💥 Error al crear registro de asistencia")
            if getattr(settings, 'DEBUG', False):
                return Response({
                    'detail': str(exc),
                    'traceback': traceback.format_exc()
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response({
                'detail': 'Error al crear registro de asistencia'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_exempt, name='dispatch')
class TimeEntryListAPIView(APIView):
    """
    API para listar registros de entrada/salida.
    GET /api/shifts/time-entry/
    
    - EMPLEADOS: Solo ven sus propios registros
    - GERENTE/ADMIN: Pueden ver registros de todos
    
    Filtros opcionales:
    - start_date: Fecha inicio (YYYY-MM-DD)
    - end_date: Fecha fin (YYYY-MM-DD)
    - employee: ID del empleado (solo para GERENTE/ADMIN)
    - entry_type: check_in o check_out
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, *args, **kwargs):
        from .models import TimeEntry
        logger = logging.getLogger(__name__)
        
        try:
            user = request.user
            logger.info(f"🔍 [TimeEntryList] Usuario: {user.email}, Rol: {user.role}")
            
            # ✅ Si es EMPLEADO, solo ver sus propios registros
            if user.role == 'EMPLEADO':
                try:
                    employee = Employee.objects.get(user=user)
                    time_entries = TimeEntry.objects.filter(employee=employee)
                    logger.info(f"👤 Empleado viendo sus registros: {time_entries.count()}")
                except Employee.DoesNotExist:
                    return Response({
                        'results': [],
                        'message': 'No se encontró perfil de empleado'
                    }, status=status.HTTP_200_OK)
            else:
                # ✅ GERENTE/ADMIN pueden ver todos
                time_entries = TimeEntry.objects.all()
                logger.info(f"👔 Gerente/Admin consultando todos los registros: {time_entries.count()}")
            
            # ✅ Aplicar filtros
            start_date = request.query_params.get('start_date')
            end_date = request.query_params.get('end_date')
            employee_id = request.query_params.get('employee')
            entry_type = request.query_params.get('entry_type')
            
            if start_date:
                try:
                    from datetime import datetime
                    start_date_obj = datetime.fromisoformat(start_date).date()
                    time_entries = time_entries.filter(timestamp__date__gte=start_date_obj)
                except (ValueError, TypeError):
                    pass
            
            if end_date:
                try:
                    from datetime import datetime
                    end_date_obj = datetime.fromisoformat(end_date).date()
                    time_entries = time_entries.filter(timestamp__date__lte=end_date_obj)
                except (ValueError, TypeError):
                    pass
            
            if employee_id and user.role in ['ADMIN', 'GERENTE']:
                time_entries = time_entries.filter(employee_id=employee_id)
            
            if entry_type in ['check_in', 'check_out']:
                time_entries = time_entries.filter(entry_type=entry_type)
            
            time_entries = time_entries.select_related('employee__user', 'shift').order_by('-timestamp')
            
            # ✅ Serializar resultados
            serializer = TimeEntryListSerializer(time_entries, many=True)
            
            logger.info(f"✅ Retornando {len(serializer.data)} registros")
            return Response({'results': serializer.data}, status=status.HTTP_200_OK)
            
        except Exception as exc:
            logger.exception("💥 Error al listar registros")
            if getattr(settings, 'DEBUG', False):
                return Response({
                    'results': [],
                    'error': str(exc),
                    'traceback': traceback.format_exc()
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response({
                'results': [],
                'error': 'Error interno del servidor'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_exempt, name='dispatch')
class MyLastTimeEntryAPIView(APIView):
    """
    API para obtener el último registro del empleado autenticado.
    GET /api/shifts/time-entry/last/
    
    Útil para saber si el siguiente registro debe ser check_in o check_out
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, *args, **kwargs):
        from .models import TimeEntry
        logger = logging.getLogger(__name__)
        
        try:
            user = request.user
            
            if user.role in ['ADMIN', 'GERENTE']:
                return Response({
                    'detail': 'Este endpoint es solo para empleados'
                }, status=status.HTTP_403_FORBIDDEN)
            
            try:
                employee = Employee.objects.get(user=user)
            except Employee.DoesNotExist:
                return Response({
                    'last_entry': None,
                    'next_action': 'check_in'
                }, status=status.HTTP_200_OK)
            
            last_entry = TimeEntry.objects.filter(employee=employee).order_by('-timestamp').first()
            
            if last_entry:
                next_action = 'check_out' if last_entry.entry_type == 'check_in' else 'check_in'
                
                return Response({
                    'last_entry': {
                        'id': last_entry.id,
                        'entry_type': last_entry.entry_type,
                        'timestamp': last_entry.timestamp.isoformat(),
                        'shift_id': last_entry.shift.id if last_entry.shift else None
                    },
                    'next_action': next_action
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'last_entry': None,
                    'next_action': 'check_in'
                }, status=status.HTTP_200_OK)
                
        except Exception as exc:
            logger.exception("💥 Error al obtener último registro")
            return Response({
                'error': 'Error interno del servidor'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
@method_decorator(csrf_exempt, name='dispatch')
class ShiftChangeRequestCreateAPIView(APIView):
    """
    API para que EMPLEADOS creen solicitudes de cambio.
    POST /api/shifts/change-requests/new/
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request, *args, **kwargs):
        logger = logging.getLogger(__name__)
        
        try:
            user = request.user
            logger.info(f"📝 [ShiftChangeRequest] Usuario: {user.email}")
            
            serializer = ShiftChangeRequestSerializer(
                data=request.data,
                context={'request': request}
            )
            
            if serializer.is_valid():
                instance = serializer.save()
                
                response_data = {
                    'id': instance.id,
                    'status': instance.status,
                    'created_at': instance.created_at.isoformat(),
                    'message': 'Solicitud enviada exitosamente'
                }
                
                logger.info(f"✅ Solicitud creada: ID={instance.id}")
                return Response(response_data, status=status.HTTP_201_CREATED)
            
            logger.warning(f"❌ Validación fallida: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as exc:
            logger.exception("💥 Error al crear solicitud")
            if getattr(settings, 'DEBUG', False):
                return Response({
                    'detail': str(exc),
                    'traceback': traceback.format_exc()
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response({
                'detail': 'Error al crear solicitud'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_exempt, name='dispatch')
class ShiftChangeRequestListAPIView(APIView):
    """
    API para listar solicitudes.
    GET /api/shifts/change-requests/
    
    - EMPLEADOS: Solo ven sus propias solicitudes
    - GERENTE/ADMIN: Ven todas las solicitudes
    
    Filtros:
    - status: pending, approved, rejected
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, *args, **kwargs):
        from .models import ShiftChangeRequest, Employee
        logger = logging.getLogger(__name__)
        
        try:
            user = request.user
            logger.info(f"🔍 [ShiftChangeRequestList] Usuario: {user.email}, Rol: {user.role}")
            
            # ✅ Si es EMPLEADO, solo ver sus solicitudes
            if user.role == 'EMPLEADO':
                try:
                    employee = Employee.objects.get(user=user)
                    requests_qs = ShiftChangeRequest.objects.filter(requesting_employee=employee)
                    logger.info(f"👤 Empleado viendo sus solicitudes: {requests_qs.count()}")
                except Employee.DoesNotExist:
                    return Response({
                        'results': [],
                        'message': 'No se encontró perfil de empleado'
                    }, status=status.HTTP_200_OK)
            else:
                # ✅ GERENTE/ADMIN pueden ver todas
                requests_qs = ShiftChangeRequest.objects.all()
                logger.info(f"👔 Gerente consultando todas las solicitudes: {requests_qs.count()}")
            
            # ✅ Aplicar filtros
            status_filter = request.query_params.get('status')
            if status_filter in ['pending', 'approved', 'rejected']:
                requests_qs = requests_qs.filter(status=status_filter)
            
            requests_qs = requests_qs.select_related(
                'requesting_employee__user',
                'original_shift__shift_type',
                'proposed_employee__user',
                'proposed_shift',
                'reviewed_by'
            ).order_by('-created_at')
            
            # ✅ Serializar
            serializer = ShiftChangeRequestListSerializer(requests_qs, many=True)
            
            logger.info(f"✅ Retornando {len(serializer.data)} solicitudes")
            return Response({'results': serializer.data}, status=status.HTTP_200_OK)
            
        except Exception as exc:
            logger.exception("💥 Error listando solicitudes")
            if getattr(settings, 'DEBUG', False):
                return Response({
                    'results': [],
                    'error': str(exc),
                    'traceback': traceback.format_exc()
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response({
                'results': [],
                'error': 'Error interno del servidor'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_exempt, name='dispatch')
class ShiftChangeRequestReviewAPIView(APIView):
    """
    API para que GERENTES aprueben/rechacen solicitudes.
    PUT /api/shifts/change-requests/<id>/review/
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def put(self, request, pk, *args, **kwargs):
        from .models import ShiftChangeRequest
        logger = logging.getLogger(__name__)
        
        try:
            user = request.user
            
            # ✅ Verificar rol
            if user.role not in ['ADMIN', 'GERENTE']:
                return Response({
                    'detail': 'Solo gerentes pueden revisar solicitudes'
                }, status=status.HTTP_403_FORBIDDEN)
            
            try:
                change_request = ShiftChangeRequest.objects.get(pk=pk)
            except ShiftChangeRequest.DoesNotExist:
                return Response({
                    'error': 'Solicitud no encontrada'
                }, status=status.HTTP_404_NOT_FOUND)
            
            # ✅ Verificar que esté pendiente
            if change_request.status != 'pending':
                return Response({
                    'detail': f'La solicitud ya fue {change_request.get_status_display()}'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            logger.info(f"🔄 [Review] Gerente {user.email} revisando solicitud {pk}")
            
            serializer = ShiftChangeRequestReviewSerializer(
                instance=change_request,
                data=request.data,
                context={'request': request}
            )
            
            if serializer.is_valid():
                instance = serializer.save()
                
                response_data = {
                    'id': instance.id,
                    'status': instance.status,
                    'manager_comment': instance.manager_comment,
                    'reviewed_at': instance.reviewed_at.isoformat() if instance.reviewed_at else None
                }
                
                logger.info(f"✅ Solicitud revisada: ID={instance.id}, Estado={instance.status}")
                return Response(response_data, status=status.HTTP_200_OK)
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as exc:
            logger.exception("💥 Error revisando solicitud")
            if getattr(settings, 'DEBUG', False):
                return Response({
                    'detail': str(exc),
                    'traceback': traceback.format_exc()
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response({
                'detail': 'Error al revisar solicitud'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
@method_decorator(csrf_exempt, name='dispatch')
class EmployeeShiftsAPIView(APIView):
    """
    API para obtener turnos de un empleado específico (para intercambios).
    GET /api/shifts/employees/<employee_id>/shifts/
    
    Retorna solo turnos futuros (>24h) que sean válidos para intercambio.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, employee_id, *args, **kwargs):
        logger = logging.getLogger(__name__)
        
        try:
            user = request.user
            logger.info(f"🔍 [EmployeeShifts] Usuario: {user.email} consultando turnos de empleado {employee_id}")
            
            # Verificar que el empleado exista
            try:
                target_employee = Employee.objects.get(pk=employee_id)
            except Employee.DoesNotExist:
                return Response({
                    'results': [],
                    'error': 'Empleado no encontrado'
                }, status=status.HTTP_404_NOT_FOUND)
            
            # Obtener fecha actual y fecha límite (próximos 60 días)
            from datetime import datetime, timedelta
            today = datetime.now().date()
            limit_date = today + timedelta(days=60)
            
            # Obtener turnos del empleado
            shifts = Shift.objects.filter(
                employee=target_employee,
                date__gte=today,
                date__lte=limit_date
            ).select_related('shift_type').order_by('date', 'start_time')
            
            # Filtrar solo turnos con >24h de anticipación
            valid_shifts = []
            for shift in shifts:
                shift_datetime = datetime.combine(shift.date, shift.start_time)
                hours_until = (shift_datetime - datetime.now()).total_seconds() / 3600
                
                if hours_until >= 24:
                    valid_shifts.append(shift)
            
            logger.info(f"✅ Turnos válidos encontrados: {len(valid_shifts)}")
            
            # Serializar resultados
            results = []
            for shift in valid_shifts:
                shift_data = {
                    'id': shift.id,
                    'date': shift.date.isoformat(),
                    'start_time': shift.start_time.isoformat(),
                    'end_time': shift.end_time.isoformat(),
                    'shift_type_id': shift.shift_type.id if shift.shift_type else None,
                    'shift_type_name': shift.shift_type.name if shift.shift_type else 'Sin tipo',
                    'shift_type_color': shift.shift_type.color if shift.shift_type else '#3788d8',
                    'employee_id': shift.employee.id,
                    'employee_name': f"{shift.employee.user.first_name} {shift.employee.user.last_name}".strip()
                }
                results.append(shift_data)
            
            return Response({'results': results}, status=status.HTTP_200_OK)
            
        except Exception as exc:
            logger.exception("💥 Error obteniendo turnos del empleado")
            if getattr(settings, 'DEBUG', False):
                return Response({
                    'results': [],
                    'error': str(exc),
                    'traceback': traceback.format_exc()
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response({
                'results': [],
                'error': 'Error interno del servidor'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
@method_decorator(csrf_exempt, name='dispatch')
class EmployeeShiftsAPIView(APIView):
    """
    API para obtener turnos de un empleado específico (para intercambios).
    GET /api/shifts/employees/<employee_id>/shifts/
    
    Retorna solo turnos futuros (>24h) que sean válidos para intercambio.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, employee_id, *args, **kwargs):
        from django.utils import timezone
        import pytz
        
        logger = logging.getLogger(__name__)
        
        try:
            user = request.user
            logger.info(f"🔍 [EmployeeShifts] Usuario: {user.email} consultando turnos de empleado {employee_id}")
            
            # Verificar que el empleado exista
            try:
                target_employee = Employee.objects.get(pk=employee_id)
            except Employee.DoesNotExist:
                return Response({
                    'results': [],
                    'error': 'Empleado no encontrado'
                }, status=status.HTTP_404_NOT_FOUND)
            
            # ✅ Obtener fecha actual en zona horaria local
            local_tz = pytz.timezone(settings.TIME_ZONE)
            now_local = timezone.now().astimezone(local_tz)
            
            # Obtener turnos del empleado (próximos 60 días)
            from datetime import timedelta
            today = now_local.date()
            limit_date = today + timedelta(days=60)
            
            # Obtener turnos del empleado
            shifts = Shift.objects.filter(
                employee=target_employee,
                date__gte=today,
                date__lte=limit_date
            ).select_related('shift_type').order_by('date', 'start_time')
            
            # ✅ Filtrar solo turnos con >24h de anticipación usando zona horaria local
            valid_shifts = []
            for shift in shifts:
                shift_datetime_naive = datetime.combine(shift.date, shift.start_time)
                shift_datetime_local = local_tz.localize(shift_datetime_naive)
                
                hours_until = (shift_datetime_local - now_local).total_seconds() / 3600
                
                if hours_until >= 24:
                    valid_shifts.append(shift)
            
            logger.info(f"✅ Turnos válidos encontrados: {len(valid_shifts)}")
            
            # Serializar resultados
            results = []
            for shift in valid_shifts:
                shift_data = {
                    'id': shift.id,
                    'date': shift.date.isoformat(),
                    'start_time': shift.start_time.isoformat(),
                    'end_time': shift.end_time.isoformat(),
                    'shift_type_id': shift.shift_type.id if shift.shift_type else None,
                    'shift_type_name': shift.shift_type.name if shift.shift_type else 'Sin tipo',
                    'shift_type_color': shift.shift_type.color if shift.shift_type else '#3788d8',
                    'employee_id': shift.employee.id,
                    'employee_name': f"{shift.employee.user.first_name} {shift.employee.user.last_name}".strip()
                }
                results.append(shift_data)
            
            return Response({'results': results}, status=status.HTTP_200_OK)
            
        except Exception as exc:
            logger.exception("💥 Error obteniendo turnos del empleado")
            if getattr(settings, 'DEBUG', False):
                return Response({
                    'results': [],
                    'error': str(exc),
                    'traceback': traceback.format_exc()
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response({
                'results': [],
                'error': 'Error interno del servidor'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)