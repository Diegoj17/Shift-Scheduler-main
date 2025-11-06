from rest_framework import serializers
from django.utils import timezone
from .models import Shift, ShiftType, Employee
from django.contrib.auth import get_user_model

User = get_user_model()


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
    employee = serializers.IntegerField()
    shift_type = serializers.IntegerField()
    notes = serializers.CharField(allow_blank=True, required=False)

    def validate(self, data):
        from .models import Employee, Shift, ShiftType
        from django.core.exceptions import ValidationError
        from django.contrib.auth import get_user_model
        from datetime import datetime, timedelta
        User = get_user_model()

        date = data.get('date')
        start_time = data.get('start_time')
        end_time = data.get('end_time')
        emp_id = data.get('employee')

        # ✅ CORREGIDO: Permitir turnos nocturnos
        is_overnight_shift = end_time < start_time
        
        if not is_overnight_shift and start_time >= end_time:
            raise serializers.ValidationError("La hora de inicio debe ser anterior a la de fin para turnos diurnos.")

        # Validar empleado
        employee = None
        
        if isinstance(emp_id, dict):
            emp_val = emp_id.get('id') or emp_id.get('pk')
        else:
            emp_val = emp_id

        emp_int = None
        try:
            if emp_val is not None:
                emp_int = int(emp_val)
        except (TypeError, ValueError):
            emp_int = None

        if emp_int is not None:
            employee = Employee.objects.filter(pk=emp_int).first()
            if not employee:
                employee = Employee.objects.filter(user__pk=emp_int).first()
                if not employee:
                    try:
                        user_tmp = User.objects.filter(pk=emp_int).first()
                        if user_tmp:
                            employee = Employee.objects.create(
                                user=user_tmp,
                                position=getattr(user_tmp, 'puesto', '') or 'Desconocido',
                                is_active=True
                            )
                    except Exception:
                        employee = None

        if not employee and isinstance(emp_val, str) and '@' in emp_val:
            user = User.objects.filter(email=emp_val).first()
            if user:
                employee = Employee.objects.filter(user=user).first()

        if not employee:
            raise serializers.ValidationError({
                "employee": f"Empleado no encontrado (valor recibido: {emp_id}). Envíe Employee.id o User.id."
            })

        if not getattr(employee, 'is_active', True):
            raise serializers.ValidationError({"employee": "Empleado no está activo."})

        # ✅ CRÍTICO: Verificar solapamiento - LÓGICA MEJORADA PARA TURNOS NOCTURNOS
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
            print(f"🔄 [ShiftCreateSerializer] Actualizando turno {self.instance.pk} - excluyendo de validación")
        
        if conflicts.exists():
            c = conflicts.first()
            raise serializers.ValidationError({
                "detail": f"Solapamiento con turno existente: {c.start_time} - {c.end_time} en {c.date}"
            })

        try:
            ShiftType.objects.get(pk=data.get('shift_type'))
        except ShiftType.DoesNotExist:
            raise serializers.ValidationError({"shift_type": "Tipo de turno no encontrado."})

        data['employee_obj'] = employee
        data['shift_type_obj'] = ShiftType.objects.get(pk=data.get('shift_type'))
        data['is_overnight'] = is_overnight_shift
        return data

    def create(self, validated_data):
        from .models import Shift

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
        return shift

    def update(self, instance, validated_data):
        from .models import Shift
        
        print(f"🔄 [ShiftCreateSerializer] Actualizando turno {instance.pk}")
        print(f"📝 Datos validados: {validated_data}")
        
        instance.date = validated_data.get('date', instance.date)
        instance.start_time = validated_data.get('start_time', instance.start_time)
        instance.end_time = validated_data.get('end_time', instance.end_time)
        instance.employee = validated_data.get('employee_obj', instance.employee)
        instance.shift_type = validated_data.get('shift_type_obj', instance.shift_type)
        instance.notes = validated_data.get('notes', instance.notes)
        
        instance.full_clean()
        instance.save()
        
        print(f"✅ Turno {instance.pk} actualizado exitosamente")
        return instance
