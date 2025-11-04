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
from .serializers import ShiftTypeSerializer
from .serializers import ShiftCreateSerializer
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
                    'employee_id': getattr(instance.employee, 'id', None),
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
    """API para devolver turnos en JSON para el calendario del frontend."""
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        try:
            User = get_user_model()
            shifts = []

            # Helper para formatear de forma segura
            def safe_iso(dt):
                if dt is None:
                    return None
                if hasattr(dt, 'isoformat'):
                    try:
                        return dt.isoformat()
                    except Exception:
                        return str(dt)
                return str(dt)

            try:
                # Usar ORM con todas las relaciones necesarias
                qs = Shift.objects.select_related(
                    'employee', 
                    'shift_type', 
                    'employee__user'
                ).filter(
                    date__isnull=False,
                    start_time__isnull=False,
                    end_time__isnull=False,
                    employee__isnull=False
                )
                
                for shift in qs:
                    # Obtener información del empleado
                    employee_name = "Sin nombre"
                    role = "Sin rol"
                    
                    if shift.employee and shift.employee.user:
                        user = shift.employee.user
                        employee_name = f"{user.first_name} {user.last_name}".strip()
                        # Obtener el rol del campo 'puesto' del User
                        role = getattr(user, 'puesto', '') or getattr(shift.employee, 'position', 'Sin rol')
                    
                    # Obtener información del tipo de turno
                    shift_type_name = shift.shift_type.name if shift.shift_type else "Sin tipo"
                    color = shift.shift_type.color if shift.shift_type else '#3788d8'
                    
                    # Formatear fechas para FullCalendar
                    start_datetime = datetime.combine(shift.date, shift.start_time)
                    end_datetime = datetime.combine(shift.date, shift.end_time)
                    
                    shifts.append({
                        'id': shift.id,
                        'title': f"{employee_name} - {role}",
                        'start': safe_iso(start_datetime),
                        'end': safe_iso(end_datetime),
                        'color': color,
                        'employee': employee_name,
                        'shift_type': shift_type_name,
                        'role': role,
                        'employee_id': shift.employee.id if shift.employee else None,
                        'extendedProps': {
                            'notes': shift.notes or '',
                            'shift_type_id': shift.shift_type.id if shift.shift_type else None
                        }
                    })

                return Response(shifts)

            except Exception as orm_error:
                logging.error(f"ORM error in ShiftListAPIView: {str(orm_error)}")
                
                # Fallback a raw SQL si el ORM falla
                with connection.cursor() as cursor:
                    cursor.execute("""
                        SELECT 
                            ss.id, ss.date, ss.start_time, ss.end_time, 
                            ss.employee_id, ss.shift_type_id, ss.notes,
                            st.name as shift_type_name, st.color,
                            eu.first_name, eu.last_name, eu.puesto,
                            se.position
                        FROM shifts_shift ss
                        LEFT JOIN shifts_shifttype st ON ss.shift_type_id = st.id
                        LEFT JOIN shifts_employee se ON ss.employee_id = se.id
                        LEFT JOIN users_user eu ON se.user_id = eu.id
                        WHERE ss.date IS NOT NULL 
                        AND ss.start_time IS NOT NULL 
                        AND ss.end_time IS NOT NULL
                        AND ss.employee_id IS NOT NULL
                    """)
                    rows = cursor.fetchall()

                for row in rows:
                    (pk, date, start_time, end_time, employee_id, 
                     shift_type_id, notes, shift_type_name, color, 
                     first_name, last_name, puesto, position) = row
                    
                    employee_name = f"{first_name} {last_name}".strip() if first_name and last_name else "Sin nombre"
                    
                    # Priorizar puesto del User, luego position del Employee
                    role = puesto or position or "Sin rol"
                    
                    if date and start_time and end_time:
                        start_datetime = datetime.combine(date, start_time)
                        end_datetime = datetime.combine(date, end_time)
                        
                        shifts.append({
                            'id': pk,
                            'title': f"{employee_name} - {role}",
                            'start': safe_iso(start_datetime),
                            'end': safe_iso(end_datetime),
                            'color': color or '#3788d8',
                            'employee': employee_name,
                            'shift_type': shift_type_name or "Sin tipo",
                            'role': role,
                            'employee_id': employee_id,
                            'extendedProps': {
                                'notes': notes or '',
                                'shift_type_id': shift_type_id
                            }
                        })

                return Response(shifts)
                
        except Exception as exc:
            logging.exception("Error fetching shifts for API")
            if getattr(settings, 'DEBUG', False):
                tb = traceback.format_exc()
                return Response({
                    'detail': str(exc), 
                    'traceback': tb
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response({
                'detail': 'Error al obtener turnos'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_exempt, name='dispatch')
class ShiftUpdateAPIView(APIView):
    """API para actualizar un turno existente."""
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def put(self, request, pk, *args, **kwargs):
        try:
            shift = Shift.objects.get(pk=pk)
        except Shift.DoesNotExist:
            return Response({'error': 'Turno no encontrado'}, status=status.HTTP_404_NOT_FOUND)

        # Reutilizamos el serializer de creación para validar/guardar
        serializer = ShiftCreateSerializer(shift, data=request.data)
        if serializer.is_valid():
            try:
                instance = serializer.save()
                return Response({
                    'id': instance.id,
                    'date': instance.date.isoformat() if instance.date else None,
                    'start_time': instance.start_time.isoformat() if instance.start_time else None,
                    'end_time': instance.end_time.isoformat() if instance.end_time else None,
                    'employee_id': getattr(instance.employee, 'id', None),
                    'shift_type_id': getattr(instance.shift_type, 'id', None),
                    'notes': instance.notes,
                })
            except Exception as exc:
                logging.exception("Unhandled exception updating Shift via API")
                if getattr(settings, 'DEBUG', False):
                    return Response({'detail': str(exc), 'traceback': traceback.format_exc()}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                return Response({'detail': 'Error al actualizar turno'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

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
