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
from .serializers import ShiftTypeSerializer, ShiftCreateSerializer, ShiftSerializer, AvailabilitySerializer, AvailabilityListSerializer
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
            logger = logging.getLogger(__name__)
            logger.info("🔍 [ShiftListAPIView] Iniciando...")
            
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
                    
                    # Formatear fechas
                    start_datetime = datetime.combine(shift.date, shift.start_time)
                    end_datetime = datetime.combine(shift.date, shift.end_time)
                    
                    shift_info = {
                        'id': shift.id,
                        'title': f"{employee_name} - {role}",
                        'start': start_datetime.isoformat(),
                        'end': end_datetime.isoformat(),
                        'color': color,
                        
                        # ✅ CRÍTICO: Información del empleado
                        'employee': employee_name,
                        'employee_id': employee_id,           # Employee ID (referencia BD)
                        'employee_user_id': user_id,          # ✅ USER_ID (para enviar al backend)
                        'employeeId': employee_id,            # Compatibilidad
                        'employeeUserId': user_id,            # ✅ Para frontend
                        'role': role,
                        
                        # ✅ Información del tipo de turno
                        'shift_type_id': shift_type_id,
                        'shift_type_name': shift_type_name,
                        'shiftTypeId': shift_type_id,         # Compatibilidad
                        'shiftTypeName': shift_type_name,     # Compatibilidad
                        
                        # ✅ Campos adicionales para edición
                        'date': shift.date.isoformat(),
                        'start_time': shift.start_time.isoformat(),
                        'end_time': shift.end_time.isoformat(),
                        'startTime': shift.start_time.isoformat(),  # Compatibilidad
                        'endTime': shift.end_time.isoformat(),      # Compatibilidad
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
    """API para actualizar un turno existente.
    
    ✅ SIMPLIFICADO: Solo pasa datos al serializer
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def put(self, request, pk, *args, **kwargs):
        logging.info(f"🔄 [ShiftUpdateAPIView] Actualizando turno {pk}")
        logging.info(f"📥 Datos recibidos: {request.data}")
        
        try:
            shift = Shift.objects.get(pk=pk)
            logging.info(f"✅ Turno encontrado: Shift ID={shift.pk}, Employee ID={shift.employee.pk}, User ID={shift.employee.user.id}")
        except Shift.DoesNotExist:
            return Response({'error': 'Turno no encontrado'}, status=status.HTTP_404_NOT_FOUND)

        # ✅ NO PROCESAR - Pasar directo al serializer
        serializer = ShiftCreateSerializer(instance=shift, data=request.data)
        
        if serializer.is_valid():
            try:
                instance = serializer.save()
                logging.info(f"✅ Turno actualizado: Shift ID={instance.id}, Employee ID={instance.employee.id}, User ID={instance.employee.user.id}")
                
                return Response({
                    'id': instance.id,
                    'date': instance.date.isoformat() if instance.date else None,
                    'start_time': instance.start_time.isoformat() if instance.start_time else None,
                    'end_time': instance.end_time.isoformat() if instance.end_time else None,
                    'start': f"{instance.date}T{instance.start_time}" if instance.date and instance.start_time else None,
                    'end': f"{instance.date}T{instance.end_time}" if instance.date and instance.end_time else None,
                    'employee': instance.employee.id,
                    'employee_user_id': instance.employee.user.id,
                    'shift_type': instance.shift_type.id,
                    'notes': instance.notes or '',
                }, status=status.HTTP_200_OK)
                
            except Exception as exc:
                logging.exception("💥 Error al actualizar turno")
                if getattr(settings, 'DEBUG', False):
                    return Response({
                        'detail': str(exc), 
                        'traceback': traceback.format_exc()
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                return Response({
                    'detail': 'Error al actualizar turno'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        logging.error(f"❌ Errores de validación: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


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
        logger = logging.getLogger(__name__)
        
        try:
            user = request.user
            logger.info(f"🔍 [MyShiftsAPIView] Usuario autenticado: ID={user.id}, Email={user.email}")
            
            # Buscar el Employee asociado al usuario
            try:
                employee = Employee.objects.get(user=user)
                logger.info(f"✅ [MyShiftsAPIView] Employee encontrado: ID={employee.id}, Position={employee.position}")
                
                # ✅ OBTENER PARÁMETROS DE FILTRO
                start_date = request.query_params.get('start_date')
                end_date = request.query_params.get('end_date')
                
                logger.info(f"📅 Parámetros de filtro recibidos: start_date={start_date}, end_date={end_date}")
                
                # Construir queryset base
                shifts_qs = Shift.objects.filter(employee=employee).select_related(
                    'shift_type', 'employee__user'
                )
                
                # ✅ APLICAR FILTROS DE FECHA
                if start_date:
                    try:
                        start_date_obj = datetime.fromisoformat(start_date).date()
                        shifts_qs = shifts_qs.filter(date__gte=start_date_obj)
                        logger.info(f"📅 Filtrado desde: {start_date_obj}, Turnos después del filtro: {shifts_qs.count()}")
                    except (ValueError, TypeError) as e:
                        logger.warning(f"⚠️ Error al parsear start_date: {e}")
                
                if end_date:
                    try:
                        end_date_obj = datetime.fromisoformat(end_date).date()
                        shifts_qs = shifts_qs.filter(date__lte=end_date_obj)
                        logger.info(f"📅 Filtrado hasta: {end_date_obj}, Turnos después del filtro: {shifts_qs.count()}")
                    except (ValueError, TypeError) as e:
                        logger.warning(f"⚠️ Error al parsear end_date: {e}")
                
                # Ordenar por fecha y hora
                shifts_qs = shifts_qs.order_by('date', 'start_time')
                
                total_shifts = shifts_qs.count()
                logger.info(f"📊 [MyShiftsAPIView] Total de turnos después de filtros: {total_shifts}")
                
                # Construir respuesta
                results = []
                for s in shifts_qs:
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
                        'status': 'confirmed'
                    }
                    results.append(shift_data)
                    
                    logger.info(f"📋 Turno {s.id}: Fecha={s.date}, Position={employee_position}")
                
                logger.info(f"✅ [MyShiftsAPIView] Retornando {len(results)} turnos")
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
                        start_date_obj = datetime.fromisoformat(start_date).date()
                        availabilities = availabilities.filter(date__gte=start_date_obj)
                        logger.info(f"📅 Filtrado desde: {start_date_obj}")
                    except (ValueError, TypeError):
                        pass
                
                if end_date:
                    try:
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
            
            # ✅ Serializar resultados
            serializer = AvailabilityListSerializer(availabilities, many=True)
            
            logger.info(f"✅ Retornando {len(serializer.data)} disponibilidades")
            return Response({'results': serializer.data}, status=status.HTTP_200_OK)
            
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