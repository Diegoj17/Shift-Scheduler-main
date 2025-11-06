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
    employee = serializers.IntegerField()  # ✅ Esto debe ser el EMPLOYEE_ID, no USER_ID
    shift_type = serializers.IntegerField()
    notes = serializers.CharField(allow_blank=True, required=False)

    def _get_employee(self, emp_id):
        """
        Obtiene el Employee BASADO EN EL EMPLOYEE_ID
        """
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"🔍 [ShiftCreateSerializer] Buscando Employee para ID: {emp_id}")
        
        try:
            # ✅ BUSCAR DIRECTAMENTE POR EMPLOYEE ID
            employee = Employee.objects.get(pk=emp_id)
            logger.info(f"✅ [ShiftCreateSerializer] Employee encontrado: ID={employee.id}, User={employee.user.id}, Nombre={employee.user.get_full_name()}")
            
            # ✅ VERIFICAR QUE TENGA USER ASOCIADO
            if not employee.user:
                logger.error(f"❌ Employee {emp_id} no tiene usuario asociado")
                raise serializers.ValidationError({
                    "employee": f"El empleado {emp_id} no tiene usuario asociado"
                })
                
            # ✅ VERIFICAR QUE ESTÉ ACTIVO
            if not getattr(employee, 'is_active', True):
                logger.warning(f"⚠️ Employee {emp_id} no está activo")
                raise serializers.ValidationError({
                    "employee": f"El empleado {employee.user.get_full_name()} no está activo"
                })
                
            return employee
            
        except Employee.DoesNotExist:
            logger.error(f"❌ [ShiftCreateSerializer] Employee {emp_id} no encontrado")
            raise serializers.ValidationError({
                "employee": f"Empleado con ID {emp_id} no encontrado"
            })
        except Exception as e:
            logger.exception(f"❌ [ShiftCreateSerializer] Error inesperado: {e}")
            raise serializers.ValidationError({
                "employee": f"Error al procesar empleado: {str(e)}"
            })

    def validate(self, data):
        date = data.get('date')
        start_time = data.get('start_time')
        end_time = data.get('end_time')
        emp_id = data.get('employee')  # ✅ Este debe ser EMPLOYEE_ID
        
        logger.info(f"🔍 [ShiftCreateSerializer] Validando turno - Employee ID: {emp_id}")
        
        # ✅ OBTENER EMPLOYEE
        try:
            employee = self._get_employee(emp_id)
        except serializers.ValidationError as ve:
            # Re-lanzar la validación específica de employee
            raise ve
        except Exception as e:
            logger.exception(f"❌ Error inesperado obteniendo empleado: {e}")
            raise serializers.ValidationError({
                "employee": f"Error al procesar empleado: {str(e)}"
            })

        # ✅ RESTANTE DE LA VALIDACIÓN (igual que antes)
        is_overnight_shift = end_time < start_time
        
        if not is_overnight_shift and start_time >= end_time:
            raise serializers.ValidationError("La hora de inicio debe ser anterior a la de fin para turnos diurnos.")

        # Verificar duplicados EXACTOS
        exact_duplicate = Shift.objects.filter(
            employee=employee,
            date=date,
            start_time=start_time,
            end_time=end_time
        )
        
        if self.instance:
            exact_duplicate = exact_duplicate.exclude(pk=self.instance.pk)
        
        if exact_duplicate.exists():
            dup = exact_duplicate.first()
            raise serializers.ValidationError({
                "detail": f"Ya existe un turno idéntico (ID={dup.id}) para este empleado"
            })

        # Verificar solapamiento
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
            
            if self.instance:
                conflicts_same_day = conflicts_same_day.exclude(pk=self.instance.pk)
                conflicts_next_day = conflicts_next_day.exclude(pk=self.instance.pk)
            
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

        # Validar ShiftType
        try:
            shift_type = ShiftType.objects.get(pk=data.get('shift_type'))
        except ShiftType.DoesNotExist:
            raise serializers.ValidationError({"shift_type": "Tipo de turno no encontrado."})

        data['employee_obj'] = employee
        data['shift_type_obj'] = shift_type
        data['is_overnight'] = is_overnight_shift
        
        logger.info(f"✅ [ShiftCreateSerializer] Validación completada para Employee {employee.id}")
        return data