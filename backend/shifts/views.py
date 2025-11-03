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
            'title': f"{shift.employee.user.first_name} - {shift.role}",
            'start': f"{shift.date}T{shift.start_time}",
            'end': f"{shift.date}T{shift.end_time}",
            'color': shift.shift_type.color,
            'employee': shift.employee.user.get_full_name(),
            'shift_type': shift.shift_type.name,
            'role': shift.role,
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
                            role=source_shift.role,
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