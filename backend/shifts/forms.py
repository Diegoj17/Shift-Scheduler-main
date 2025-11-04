from django import forms
from .models import Shift, ShiftType, Employee
from django.core.exceptions import ValidationError

class ShiftTypeForm(forms.ModelForm):
    class Meta:
        model = ShiftType
        fields = ['name', 'start_time', 'end_time', 'color']
        widgets = {
            'start_time': forms.TimeInput(attrs={'type': 'time'}),
            'end_time': forms.TimeInput(attrs={'type': 'time'}),
            'color': forms.TextInput(attrs={'type': 'color'}),
        }
    
    def clean(self):
        cleaned_data = super().clean()
        start_time = cleaned_data.get('start_time')
        end_time = cleaned_data.get('end_time')
        
        if start_time and end_time and start_time >= end_time:
            raise ValidationError("La hora de fin debe ser mayor a la hora de inicio")
        
        return cleaned_data

class ShiftForm(forms.ModelForm):
    class Meta:
        model = Shift
        # removemos `role` del formulario de creación/edición rápida porque
        # el puesto/rol se obtiene del perfil del empleado (asignado por
        # Gerente/Admin). Se conserva `notes`.
        fields = ['date', 'start_time', 'end_time', 'employee', 'shift_type', 'notes']
        widgets = {
            'date': forms.DateInput(attrs={'type': 'date'}),
            'start_time': forms.TimeInput(attrs={'type': 'time'}),
            'end_time': forms.TimeInput(attrs={'type': 'time'}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['employee'].queryset = Employee.objects.filter(is_active=True)

class ShiftDuplicateForm(forms.Form):
    start_date = forms.DateField(widget=forms.DateInput(attrs={'type': 'date'}))
    end_date = forms.DateField(widget=forms.DateInput(attrs={'type': 'date'}))
    target_start_date = forms.DateField(widget=forms.DateInput(attrs={'type': 'date'}))
    
    def clean(self):
        cleaned_data = super().clean()
        start_date = cleaned_data.get('start_date')
        end_date = cleaned_data.get('end_date')
        target_start_date = cleaned_data.get('target_start_date')
        
        if start_date and end_date and start_date > end_date:
            raise ValidationError("La fecha de inicio debe ser anterior a la fecha de fin")
        
        return cleaned_data