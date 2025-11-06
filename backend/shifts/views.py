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
from .serializers import ShiftTypeSerializer, ShiftCreateSerializer
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

    Endpoint: POST /api/shifts/new/
    Requiere JWT Authentication y devuelve 201 con el turno creado.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            # Normalize incoming payload: some frontends send a User.id instead of
            # an Employee.pk. Try to resolve and rewrite `employee` to Employee.pk
            # before validation to give clearer behaviour.
            incoming = request.data.copy()
            emp_val = incoming.get('employee')
            if emp_val is not None:
                # try as Employee.pk
                from .models import Employee as _Employee
                try:
                    _Employee.objects.get(pk=int(emp_val))
                except Exception:
                    # try as user__pk and rewrite to the employee.pk if found
                    try:
                        emp_obj = _Employee.objects.get(user__pk=int(emp_val))
                        incoming['employee'] = emp_obj.pk
                        logging.debug("ShiftCreateAPIView: resolved employee user id %s -> employee id %s", emp_val, emp_obj.pk)
                    except Exception:
                        # leave as-is; serializer will raise a validation error
                        logging.debug("ShiftCreateAPIView: could not resolve employee id %s", emp_val)

            # pasar contexto no es estrictamente necesario pero es útil si en el
            # futuro queremos usar request.user dentro del serializer
            serializer = ShiftCreateSerializer(data=incoming, context={'request': request})
            if serializer.is_valid():
                instance = serializer.save()
                # devolver representación simple
                return Response({
                        'id': instance.id,
                        'date': instance.date.isoformat() if instance.date else None,
                        'start_time': instance.start_time.isoformat() if instance.start_time else None,
                        'end_time': instance.end_time.isoformat() if instance.end_time else None,
                        'start': f"{instance.date}T{instance.start_time}" if instance.date and instance.start_time else None,
                        'end': f"{instance.date}T{instance.end_time}" if instance.date and instance.end_time else None,
                        'employee_id': getattr(instance.employee, 'id', None),
                        'employee_user_id': getattr(getattr(instance.employee, 'user', None), 'id', None),
                        'shift_type_id': getattr(instance.shift_type, 'id', None),
                        'notes': instance.notes,
                    }, status=status.HTTP_201_CREATED)
            # Loguear detalles para facilitar debugging de 400s desde frontend
            logging.warning("ShiftCreateAPIView: petición inválida %s -> %s", request.data, serializer.errors)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as exc:
            logging.exception("Unhandled exception creating Shift via API")
            if getattr(settings, 'DEBUG', False):
                return Response({'detail': str(exc), 'traceback': traceback.format_exc()}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response({'detail': 'Error al crear turno'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

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
    """API ultra-segura para debugging"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        try:
            print("🔍 INICIANDO ShiftListAPIView")
            
            shifts_data = []
            shift_count = 0
            
            try:
                # Consulta básica
                shifts = Shift.objects.all()
                shift_count = shifts.count()
                print(f"📊 Total shifts encontrados: {shift_count}")
                
                for shift in shifts:
                    try:
                        print(f"🔄 Procesando shift ID: {shift.id}")
                        
                        # Validar datos mínimos
                        if not shift.date:
                            print(f"  ⚠️ Shift {shift.id} sin fecha")
                            continue
                        if not shift.start_time:
                            print(f"  ⚠️ Shift {shift.id} sin start_time")
                            continue
                        if not shift.end_time:
                            print(f"  ⚠️ Shift {shift.id} sin end_time")
                            continue
                        if not shift.employee:
                            print(f"  ⚠️ Shift {shift.id} sin employee")
                            continue
                        
                        # Información básica
                        employee_name = f"Empleado-{shift.employee.id}" if shift.employee else "Sin empleado"
                        role = "Sin rol"
                        
                        # Solo intentar obtener user si employee existe
                        if shift.employee and hasattr(shift.employee, 'user'):
                            try:
                                if shift.employee.user:
                                    user = shift.employee.user
                                    first_name = getattr(user, 'first_name', '') or ''
                                    last_name = getattr(user, 'last_name', '') or ''
                                    employee_name = f"{first_name} {last_name}".strip() or employee_name
                                    
                                    # Manejar puesto de forma segura
                                    puesto = getattr(user, 'puesto', None)
                                    if puesto and puesto != "NULL":
                                        role = puesto
                                    else:
                                        role = getattr(shift.employee, 'position', 'Sin rol') or 'Sin rol'
                            except Exception as user_error:
                                print(f"  ⚠️ Error obteniendo user para shift {shift.id}: {user_error}")
                                role = getattr(shift.employee, 'position', 'Sin rol') or 'Sin rol'
                        
                        # Tipo de turno
                        color = '#3788d8'
                        if shift.shift_type:
                            color = getattr(shift.shift_type, 'color', '#3788d8') or '#3788d8'
                        
                        # Formatear fechas
                        try:
                            start_datetime = datetime.combine(shift.date, shift.start_time)
                            end_datetime = datetime.combine(shift.date, shift.end_time)
                            
                            shift_info = {
                                'id': shift.id,
                                'title': f"{employee_name} - {role}",
                                'start': start_datetime.isoformat(),
                                'end': end_datetime.isoformat(),
                                'color': color,
                                'employee': employee_name,
                                'role': role,
                            }
                            
                            shifts_data.append(shift_info)
                            print(f"  ✅ Shift {shift.id} procesado: {employee_name}")
                            
                        except Exception as date_error:
                            print(f"  ❌ Error con fechas en shift {shift.id}: {date_error}")
                            continue
                            
                    except Exception as shift_error:
                        print(f"  💥 Error grave en shift {shift.id}: {shift_error}")
                        continue
                
                print(f"🎯 FINALIZADO: {len(shifts_data)} shifts procesados exitosamente")
                return Response(shifts_data)
                
            except Exception as query_error:
                print(f"💥 ERROR en consulta principal: {query_error}")
                return Response({"error": "Error en consulta de datos"}, status=500)
                
        except Exception as global_error:
            print(f"💥💥 ERROR GLOBAL: {global_error}")
            import traceback
            print(traceback.format_exc())
            return Response(
                {"error": "Error interno del servidor"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_exempt, name='dispatch')
class ShiftUpdateAPIView(APIView):
    """API para actualizar un turno existente."""
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def put(self, request, pk, *args, **kwargs):
        print(f"🔄 [ShiftUpdateAPIView] Actualizando turno {pk}")
        print(f"📝 Datos recibidos: {request.data}")
        
        try:
            shift = Shift.objects.get(pk=pk)
            print(f"✅ Turno encontrado: ID={shift.pk}, Employee={shift.employee.pk}, Date={shift.date}")
        except Shift.DoesNotExist:
            return Response({'error': 'Turno no encontrado'}, status=status.HTTP_404_NOT_FOUND)

        # ✅ Pasar la instancia al serializer para que sepa que es un update
        serializer = ShiftCreateSerializer(instance=shift, data=request.data)
        
        if serializer.is_valid():
            try:
                instance = serializer.save()
                print(f"✅ Turno actualizado exitosamente: {instance.id}")
                
                return Response({
                            'id': instance.id,
                            'date': instance.date.isoformat() if instance.date else None,
                            'start_time': instance.start_time.isoformat() if instance.start_time else None,
                            'end_time': instance.end_time.isoformat() if instance.end_time else None,
                            'start': f"{instance.date}T{instance.start_time}" if instance.date and instance.start_time else None,
                            'end': f"{instance.date}T{instance.end_time}" if instance.date and instance.end_time else None,
                            'employee': getattr(instance.employee, 'id', None),
                            'employee_user_id': getattr(getattr(instance.employee, 'user', None), 'id', None),
                            'shift_type': getattr(instance.shift_type, 'id', None),
                            'notes': instance.notes or '',
                        }, status=status.HTTP_200_OK)
            except Exception as exc:
                logging.exception("Error al actualizar turno")
                print(f"❌ Error al guardar: {exc}")
                if getattr(settings, 'DEBUG', False):
                    return Response({
                        'detail': str(exc), 
                        'traceback': traceback.format_exc()
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                return Response({'detail': 'Error al actualizar turno'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        print(f"❌ Errores de validación: {serializer.errors}")
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
                        'employee_user_id': getattr(getattr(s.employee, 'user', None), 'id', None),
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