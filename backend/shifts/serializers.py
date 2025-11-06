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
    employee = serializers.IntegerField()
    shift_type = serializers.IntegerField()
    notes = serializers.CharField(allow_blank=True, required=False)

    def _get_or_create_employee(self, emp_id):
        """
        Obtiene el Employee CORRECTAMENTE basado en el ID proporcionado.
        """
        logger.info(f"🔍 [ShiftCreateSerializer] Buscando empleado para ID: {emp_id}")
        
        # ✅ PRIMERO: Buscar Employee por su ID directo
        employee = Employee.objects.filter(pk=emp_id).first()
        if employee:
            logger.info(f"✅ [ShiftCreateSerializer] Employee encontrado por pk={emp_id}")
            if not employee.user:
                logger.error(f"❌ Employee {emp_id} no tiene usuario asociado")
                raise serializers.ValidationError({
                    "employee": f"El empleado {emp_id} no tiene usuario asociado"
                })
            return employee
        
        # ✅ SEGUNDO: Buscar Employee por user_id
        employee = Employee.objects.filter(user_id=emp_id).first()
        if employee:
            logger.info(f"✅ [ShiftCreateSerializer] Employee encontrado por user_id={emp_id}")
            return employee
        
        # ✅ TERCERO: Buscar User y verificar si ya tiene Employee
        user = User.objects.filter(pk=emp_id).first()
        if user:
            employee = Employee.objects.filter(user=user).first()
            if employee:
                logger.info(f"✅ [ShiftCreateSerializer] Employee encontrado para User {emp_id}")
                return employee
            
            # ❌ NO CREAR EMPLOYEES AUTOMÁTICAMENTE
            logger.error(f"❌ [ShiftCreateSerializer] User {emp_id} no tiene Employee asociado")
            raise serializers.ValidationError({
                "employee": f"El usuario {user.get_full_name()} no tiene un perfil de empleado. Contacte al administrador."
            })
        
        logger.error(f"❌ [ShiftCreateSerializer] No se pudo encontrar Employee para ID: {emp_id}")
        raise serializers.ValidationError({
            "employee": f"No se pudo encontrar empleado para el ID: {emp_id}"
        })

    def validate(self, data):
        date = data.get('date')
        start_time = data.get('start_time')
        end_time = data.get('end_time')
        emp_id = data.get('employee')
        
        logger.info(f"🔍 [ShiftCreateSerializer] Validando: date={date}, start={start_time}, end={end_time}, emp_id={emp_id}")

        # ✅ CORREGIDO: Permitir turnos nocturnos
        is_overnight_shift = end_time < start_time
        
        if not is_overnight_shift and start_time >= end_time:
            raise serializers.ValidationError("La hora de inicio debe ser anterior a la de fin para turnos diurnos.")

        # ✅ CRÍTICO: Obtener Employee
        try:
            employee = self._get_or_create_employee(emp_id)
        except serializers.ValidationError:
            raise
        except Exception as e:
            logger.exception(f"❌ [ShiftCreateSerializer] Error inesperado obteniendo empleado: {e}")
            raise serializers.ValidationError({
                "employee": f"Error al procesar empleado: {str(e)}"
            })

        if not getattr(employee, 'is_active', True):
            raise serializers.ValidationError({"employee": "Empleado no está activo."})

        logger.info(f"✅ [ShiftCreateSerializer] Empleado validado: Employee.id={employee.id}, User.id={employee.user.id}")

        # ✅ Verificar duplicados EXACTOS
        exact_duplicate = Shift.objects.filter(
            employee=employee,
            date=date,
            start_time=start_time,
            end_time=end_time
        )
        
        if self.instance:
            exact_duplicate = exact_duplicate.exclude(pk=self.instance.pk)
            logger.info(f"🔄 [ShiftCreateSerializer] Modo UPDATE - excluyendo turno {self.instance.pk}")
        
        if exact_duplicate.exists():
            dup = exact_duplicate.first()
            logger.error(f"❌ [ShiftCreateSerializer] Duplicado EXACTO: ID={dup.id}")
            raise serializers.ValidationError({
                "detail": f"Ya existe un turno idéntico (ID={dup.id}) para este empleado en esta fecha y horario."
            })

        # ✅ CRÍTICO: Verificar solapamiento - LÓGICA MEJORADA
        if is_overnight_shift:
            logger.info(f"🌙 [ShiftCreateSerializer] Turno nocturno detectado")

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
            
            if self.instance:
                conflicts_same_day = conflicts_same_day.exclude(pk=self.instance.pk)
                conflicts_next_day = conflicts_next_day.exclude(pk=self.instance.pk)
                logger.info(f"🔄 [ShiftCreateSerializer] Actualizando turno nocturno {self.instance.pk} - excluyendo de validación")
            
            conflicts = conflicts_same_day.union(conflicts_next_day)
            
        else:
            logger.info(f"☀️ [ShiftCreateSerializer] Turno diurno detectado")
            
            conflicts = Shift.objects.filter(
                employee=employee,
                date=date,
                start_time__lt=end_time,
                end_time__gt=start_time
            )
            
            if self.instance:
                conflicts = conflicts.exclude(pk=self.instance.pk)
                logger.info(f"🔄 [ShiftCreateSerializer] Actualizando turno diurno {self.instance.pk} - excluyendo de validación")
        
        if conflicts.exists():
            c = conflicts.first()
            logger.error(f"❌ [ShiftCreateSerializer] Solapamiento con turno ID={c.id}")
            raise serializers.ValidationError({
                "detail": f"Solapamiento con turno existente: {c.start_time} - {c.end_time} en {c.date}"
            })

        logger.info(f"✅ [ShiftCreateSerializer] Sin conflictos")

        # Validar ShiftType
        try:
            shift_type = ShiftType.objects.get(pk=data.get('shift_type'))
        except ShiftType.DoesNotExist:
            raise serializers.ValidationError({"shift_type": "Tipo de turno no encontrado."})

        data['employee_obj'] = employee
        data['shift_type_obj'] = shift_type
        data['is_overnight'] = is_overnight_shift
        logger.info(f"✅ [ShiftCreateSerializer] Validación completada")
        return data

    def create(self, validated_data):
        logger.info(f"💾 [ShiftCreateSerializer] Creando turno")

        try:
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
            
            # ✅ DEBUG: Verificar que el turno se guardó correctamente
            saved_shift = Shift.objects.get(pk=shift.id)
            logger.info(f"✅ [ShiftCreateSerializer] Turno creado: ID={shift.id}, Employee.id={shift.employee.id}, User.id={shift.employee.user.id}")
            logger.info(f"🔍 [ShiftCreateSerializer] Turno guardado en BD: Employee={saved_shift.employee.id}, User={saved_shift.employee.user.id}")
            
            return shift
            
        except Exception as e:
            logger.exception(f"❌ [ShiftCreateSerializer] Error al guardar turno: {e}")
            raise

    def update(self, instance, validated_data):
        logger.info(f"🔄 [ShiftCreateSerializer] Actualizando turno {instance.pk}")

        instance.date = validated_data.get('date', instance.date)
        instance.start_time = validated_data.get('start_time', instance.start_time)
        instance.end_time = validated_data.get('end_time', instance.end_time)
        instance.employee = validated_data.get('employee_obj', instance.employee)
        instance.shift_type = validated_data.get('shift_type_obj', instance.shift_type)
        instance.notes = validated_data.get('notes', instance.notes)
        
        instance.full_clean()
        instance.save()
        
        logger.info(f"✅ [ShiftCreateSerializer] Turno {instance.pk} actualizado")
        return instance