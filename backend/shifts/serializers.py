# serializers.py

from rest_framework import serializers
from django.utils import timezone
from .models import Shift, ShiftType, Employee
from django.contrib.auth import get_user_model
import logging
from datetime import time, timedelta

User = get_user_model()
logger = logging.getLogger(__name__)

class ShiftSerializer(serializers.ModelSerializer):
    class Meta:
        model = Shift
        fields = ("id", "employee", "start", "end", "shift_type", "role_in_shift", "notes", "created_by", "created_at")
        read_only_fields = ("id", "created_by", "created_at")

    def validate(self, data):
        start = data.get('start')
        end = data.get('end')
        employee = data.get('employee')

        if not start or not end:
            raise serializers.ValidationError("start y end son requeridos.")

        if start >= end:
            raise serializers.ValidationError("La fecha/hora de inicio debe ser anterior a la de fin.")

        qs = Shift.objects.filter(employee=employee, start__lt=end, end__gt=start)
        if self.instance:
            qs = qs.exclude(pk=self.instance.pk)

        if qs.exists():
            conflict = qs.first()
            raise serializers.ValidationError({
                "conflict": f"Solapamiento con turno existente {conflict.start.isoformat()} - {conflict.end.isoformat()}"
            })

        try:
            emp = User.objects.get(pk=employee.pk if hasattr(employee, 'pk') else employee)
            if emp.status != User.Status.ACTIVE:
                raise serializers.ValidationError({"employee": "Empleado no está activo/disponible."})
        except User.DoesNotExist:
            raise serializers.ValidationError({"employee": "Empleado no encontrado."})

        return data

    def create(self, validated_data):
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            validated_data['created_by'] = request.user
        return super().create(validated_data)


class ShiftTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = ShiftType
        fields = ('id', 'name', 'start_time', 'end_time', 'color')
        read_only_fields = ('id',)

    def validate(self, data):
        start = data.get('start_time')
        end = data.get('end_time')
        
        if start and end:
            if start == end:
                raise serializers.ValidationError("La hora de inicio y fin no pueden ser iguales")
        return data


class ShiftCreateSerializer(serializers.Serializer):
    date = serializers.DateField()
    start_time = serializers.TimeField()
    end_time = serializers.TimeField()
    employee = serializers.IntegerField()  # ✅ Recibe USER_ID
    shift_type = serializers.IntegerField()
    notes = serializers.CharField(allow_blank=True, required=False)
    
    def validate(self, data):
        from .models import Employee, Shift, ShiftType
        from django.core.exceptions import ValidationError
        from django.contrib.auth import get_user_model
        from django.db import transaction
        from datetime import timedelta
        User = get_user_model()

        date = data.get('date')
        start_time = data.get('start_time')
        end_time = data.get('end_time')
        emp_id = data.get('employee')

        # ✅ Permitir turnos nocturnos
        is_overnight_shift = end_time < start_time
        
        if not is_overnight_shift and start_time >= end_time:
            raise serializers.ValidationError(
                "La hora de inicio debe ser anterior a la de fin para turnos diurnos."
            )

        # ✅ NUEVA LÓGICA: Buscar o crear Employee ATÓMICAMENTE
        employee = None
        
        if isinstance(emp_id, dict):
            emp_val = emp_id.get('id') or emp_id.get('pk')
        else:
            emp_val = emp_id

        try:
            user_id = int(emp_val) if emp_val is not None else None
        except (TypeError, ValueError):
            raise serializers.ValidationError({
                "employee": f"ID inválido: {emp_val}"
            })

        if user_id is None:
            raise serializers.ValidationError({
                "employee": "El ID es requerido"
            })

        logger.info(f"🔍 [ShiftCreateSerializer] ID recibido: {user_id}")
        
        # ✅ PASO 1: Buscar usuario
        try:
            user = User.objects.get(pk=user_id)
            logger.info(f"✅ User encontrado: ID={user.id}, Email={user.email}")
        except User.DoesNotExist:
            raise serializers.ValidationError({
                "employee": f"No existe usuario con ID {user_id}"
            })

        # ✅ PASO 2: Buscar o crear Employee (ATÓMICO para evitar duplicados)
        with transaction.atomic():
            employee, created = Employee.objects.select_for_update().get_or_create(
                user=user,
                defaults={
                    'position': getattr(user, 'puesto', None) or 'Sin especificar',
                    'is_active': True
                }
            )
            
            if created:
                logger.info(f"✅ Employee CREADO: ID={employee.id} para User={user.email}")
            else:
                logger.info(f"✅ Employee EXISTENTE: ID={employee.id} para User={user.email}")

        # ✅ Validar que está activo
        if not employee.is_active:
            raise serializers.ValidationError({
                "employee": "El empleado no está activo"
            })

        # ✅ Verificar solapamiento
        if is_overnight_shift:
            conflicts_same_day = Shift.objects.filter(
                employee=employee,
                date=date,
                start_time__lt='23:59:59',
                end_time__gt=start_time
            )
            
            next_day = date + timedelta(days=1)
            conflicts_next_day = Shift.objects.filter(
                employee=employee,
                date=next_day,
                start_time__lt=end_time,
                end_time__gt='00:00:00'
            )
            
            conflicts = conflicts_same_day.union(conflicts_next_day)
        else:
            conflicts = Shift.objects.filter(
                employee=employee,
                date=date,
                start_time__lt=end_time,
                end_time__gt=start_time
            )
        
        if self.instance:
            conflicts = conflicts.exclude(pk=self.instance.pk)
        
        if conflicts.exists():
            c = conflicts.first()
            raise serializers.ValidationError({
                "detail": f"Solapamiento con turno existente: {c.start_time} - {c.end_time} en {c.date}"
            })

        # ✅ Validar ShiftType
        try:
            shift_type_obj = ShiftType.objects.get(pk=data.get('shift_type'))
        except ShiftType.DoesNotExist:
            raise serializers.ValidationError({
                "shift_type": "Tipo de turno no encontrado"
            })

        data['employee_obj'] = employee
        data['shift_type_obj'] = shift_type_obj
        data['is_overnight'] = is_overnight_shift
        return data

    def create(self, validated_data):
        from .models import Shift

        logger.info(f"📝 Creando turno para Employee ID: {validated_data['employee_obj'].id}")
        
        shift = Shift(
            date=validated_data['date'],
            start_time=validated_data['start_time'],
            end_time=validated_data['end_time'],
            employee=validated_data['employee_obj'],
            shift_type=validated_data['shift_type_obj'],
            notes=validated_data.get('notes', '')
        )
        shift.full_clean()
        shift.save()
        
        logger.info(f"✅ Turno creado: ID={shift.id}, Employee={shift.employee.id}")
        return shift

    def update(self, instance, validated_data):
        logger.info(f"🔄 Actualizando turno {instance.pk}")
        logger.info(f"📝 Datos validados: Employee ID={validated_data['employee_obj'].id}")
        
        instance.date = validated_data.get('date', instance.date)
        instance.start_time = validated_data.get('start_time', instance.start_time)
        instance.end_time = validated_data.get('end_time', instance.end_time)
        instance.employee = validated_data.get('employee_obj', instance.employee)
        instance.shift_type = validated_data.get('shift_type_obj', instance.shift_type)
        instance.notes = validated_data.get('notes', instance.notes)
        
        instance.full_clean()
        instance.save()
        
        logger.info(f"✅ Turno {instance.pk} actualizado - Employee: {instance.employee.id}")
        return instance


class AvailabilitySerializer(serializers.Serializer):
    """Serializer para crear/actualizar disponibilidades - SOLO EMPLEADOS"""
    id = serializers.IntegerField(read_only=True)
    date = serializers.DateField()
    start_time = serializers.TimeField()
    end_time = serializers.TimeField()
    type = serializers.ChoiceField(choices=['available', 'unavailable'])
    notes = serializers.CharField(allow_blank=True, required=False)
    
    def validate(self, data):
        from .models import Availability, Employee
        from datetime import timedelta
        
        date = data.get('date')
        start_time = data.get('start_time')
        end_time = data.get('end_time')
        
        # ✅ Validar que no sean iguales
        if start_time == end_time:
            raise serializers.ValidationError({
                "detail": "La hora de inicio y fin no pueden ser iguales"
            })
        
        # ✅ Determinar si es un registro nocturno
        is_overnight = end_time < start_time
        
        # ✅ Obtener empleado del usuario autenticado
        request = self.context.get('request')
        
        if not request or not request.user.is_authenticated:
            raise serializers.ValidationError({"detail": "Autenticación requerida"})
        
        # ✅ CRITICAL: Solo empleados pueden crear/editar disponibilidades
        if request.user.role in ['ADMIN', 'GERENTE']:
            raise serializers.ValidationError({
                "detail": "Solo los empleados pueden gestionar disponibilidades"
            })
        
        try:
            employee = Employee.objects.get(user=request.user)
            logger.info(f"✅ Employee encontrado: ID={employee.id}, User={request.user.email}")
        except Employee.DoesNotExist:
            raise serializers.ValidationError({
                "detail": "No se encontró perfil de empleado para este usuario"
            })
        
        # ✅ Verificar solapamiento
        if is_overnight:
            conflicts_same_day = Availability.objects.filter(
                employee=employee,
                date=date,
                start_time__lt='23:59:59',
                end_time__gt=start_time
            )
            
            next_day = date + timedelta(days=1)
            conflicts_next_day = Availability.objects.filter(
                employee=employee,
                date=next_day,
                start_time__lt=end_time,
                end_time__gt='00:00:00'
            )
            
            conflicts = conflicts_same_day.union(conflicts_next_day)
        else:
            conflicts = Availability.objects.filter(
                employee=employee,
                date=date,
                start_time__lt=end_time,
                end_time__gt=start_time
            )
        
        if self.instance:
            conflicts = conflicts.exclude(pk=self.instance.pk)
        
        if conflicts.exists():
            raise serializers.ValidationError({
                "detail": "Rango horario inválido o superpuesto"
            })
        
        data['employee_obj'] = employee
        data['is_overnight'] = is_overnight
        return data
    
    def create(self, validated_data):
        from .models import Availability
        
        availability = Availability(
            employee=validated_data['employee_obj'],
            date=validated_data['date'],
            start_time=validated_data['start_time'],
            end_time=validated_data['end_time'],
            type=validated_data['type'],
            notes=validated_data.get('notes', '')
        )
        availability.full_clean()
        availability.save()
        return availability
    
    def update(self, instance, validated_data):
        instance.date = validated_data.get('date', instance.date)
        instance.start_time = validated_data.get('start_time', instance.start_time)
        instance.end_time = validated_data.get('end_time', instance.end_time)
        instance.type = validated_data.get('type', instance.type)
        instance.notes = validated_data.get('notes', instance.notes)
        instance.full_clean()
        instance.save()
        return instance


class AvailabilityListSerializer(serializers.Serializer):
    """Serializer para listar disponibilidades con información completa"""
    id = serializers.IntegerField()
    employee_id = serializers.IntegerField(source='employee.id')
    employee_name = serializers.SerializerMethodField()
    employee_position = serializers.SerializerMethodField()
    employee_area = serializers.SerializerMethodField()
    date = serializers.DateField()
    start_time = serializers.TimeField()
    end_time = serializers.TimeField()
    type = serializers.CharField()
    color = serializers.SerializerMethodField()
    notes = serializers.CharField()
    duration_hours = serializers.SerializerMethodField()
    created_at = serializers.DateTimeField()
    
    def get_employee_name(self, obj):
        if obj.employee and obj.employee.user:
            return f"{obj.employee.user.first_name} {obj.employee.user.last_name}".strip()
        return "Desconocido"
    
    def get_employee_position(self, obj):
        if obj.employee:
            return obj.employee.position or getattr(obj.employee.user, 'puesto', None) or 'Sin puesto'
        return 'Sin puesto'
    
    def get_employee_area(self, obj):
        if obj.employee and obj.employee.user:
            return getattr(obj.employee.user, 'departamento', None) or 'Sin área'
        return 'Sin área'
    
    def get_color(self, obj):
        return obj.get_color()
    
    def get_duration_hours(self, obj):
        return obj.duration_hours()