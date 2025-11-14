# serializers.py

from rest_framework import serializers
from django.utils import timezone
from .models import Shift, ShiftType, Employee, Availability, TimeEntry
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
    employee = serializers.IntegerField()  # ✅ SIEMPRE recibe USER_ID
    shift_type = serializers.IntegerField()
    notes = serializers.CharField(allow_blank=True, required=False)
    
    def validate(self, data):
        from .models import Employee, Shift, ShiftType
        from django.contrib.auth import get_user_model
        from django.db import transaction
        from datetime import timedelta
        User = get_user_model()

        date = data.get('date')
        start_time = data.get('start_time')
        end_time = data.get('end_time')
        user_id = data.get('employee')

        # ✅ NUEVO: Verificar si estamos editando un turno bloqueado
        if self.instance:
            if self.instance.is_locked:
                raise serializers.ValidationError({
                    "detail": f"Este turno no puede ser editado. Motivo: {self.instance.lock_reason or 'Turno intercambiado mediante solicitud aprobada.'}"
                })

        is_overnight_shift = end_time < start_time
        
        if not is_overnight_shift and start_time >= end_time:
            raise serializers.ValidationError(
                "La hora de inicio debe ser anterior a la de fin para turnos diurnos."
            )

        try:
            incoming_id = int(user_id)
        except (TypeError, ValueError):
            raise serializers.ValidationError({
                "employee": f"ID inválido: {user_id}"
            })

        logger.info(f"🔍 [ShiftCreateSerializer] Procesando ID entrante: {incoming_id}")

        employee = None

        # 1) Intentar encontrar Employee por PK
        try:
            employee = Employee.objects.get(pk=incoming_id)
            logger.info(f"✅ Employee encontrado por PK: Employee ID={employee.id}, User ID={employee.user.id}")
        except Employee.DoesNotExist:
            # 2) Si no existe Employee con ese PK, tratar el valor como User.pk
            try:
                user = User.objects.get(pk=incoming_id)
                logger.info(f"✅ User encontrado: ID={user.id}")
            except User.DoesNotExist:
                raise serializers.ValidationError({
                    "employee": f"No existe Employee ni User con ID {incoming_id}"
                })

            emp_qs = Employee.objects.filter(user=user)
            emp_count = emp_qs.count()
            if emp_count > 1:
                logger.error(f"❌ DUPLICADOS: User {incoming_id} tiene {emp_count} Employees!")
                raise serializers.ValidationError({
                    "employee": "Error: Usuario con múltiples perfiles de empleado."
                })

            employee = emp_qs.first()
            if not employee:
                logger.info(f"⚠️ No existe Employee para User ID={user.id}, creando...")
                with transaction.atomic():
                    employee, created = Employee.objects.select_for_update().get_or_create(
                        user=user,
                        defaults={
                            'position': getattr(user, 'puesto', None) or 'Sin especificar',
                            'is_active': True
                        }
                    )
                    if created:
                        logger.info(f"✅ Employee CREADO: ID={employee.id}")

        if not employee.is_active:
            raise serializers.ValidationError({
                "employee": "El empleado no está activo"
            })

        # ✅ CORRECCIÓN: Aplicar exclude ANTES de verificar existencia
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
            
            # ✅ CRÍTICO: Excluir instancia ANTES de verificar existencia
            if self.instance:
                conflicts_same_day = conflicts_same_day.exclude(pk=self.instance.pk)
                conflicts_next_day = conflicts_next_day.exclude(pk=self.instance.pk)
            
            # Verificar existencia sin usar union
            if conflicts_same_day.exists() or conflicts_next_day.exists():
                c = conflicts_same_day.first() or conflicts_next_day.first()
                raise serializers.ValidationError({
                    "detail": f"Solapamiento con turno existente: {c.start_time} - {c.end_time} en {c.date}"
                })
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

        employee = validated_data['employee_obj']
        logger.info(f"📝 Creando turno - Employee ID: {employee.id}, User ID: {employee.user.id}")
        
        shift = Shift(
            date=validated_data['date'],
            start_time=validated_data['start_time'],
            end_time=validated_data['end_time'],
            employee=employee,
            shift_type=validated_data['shift_type_obj'],
            notes=validated_data.get('notes', '')
        )
        shift.full_clean()
        shift.save()
        
        logger.info(f"✅ Turno creado exitosamente: Shift ID={shift.id}, Employee ID={shift.employee.id}, User ID={shift.employee.user.id}")
        return shift

    def update(self, instance, validated_data):
        employee = validated_data['employee_obj']
        logger.info(f"🔄 Actualizando turno {instance.pk} - Nuevo Employee ID: {employee.id}, User ID: {employee.user.id}")
        
        instance.date = validated_data.get('date', instance.date)
        instance.start_time = validated_data.get('start_time', instance.start_time)
        instance.end_time = validated_data.get('end_time', instance.end_time)
        instance.employee = employee
        instance.shift_type = validated_data.get('shift_type_obj', instance.shift_type)
        instance.notes = validated_data.get('notes', instance.notes)
        
        instance.full_clean()
        instance.save()
        
        logger.info(f"✅ Turno {instance.pk} actualizado - Employee: {instance.employee.id}, User: {instance.employee.user.id}")
        return instance

class ShiftUpdateSerializer(serializers.Serializer):
    """Serializer específico para ACTUALIZAR turnos - usa EMPLOYEE_ID"""
    date = serializers.DateField()
    start_time = serializers.TimeField()
    end_time = serializers.TimeField()
    employee = serializers.IntegerField()  # ✅ EMPLOYEE_ID (de la tabla shifts_employee)
    shift_type = serializers.IntegerField()
    notes = serializers.CharField(allow_blank=True, required=False)
    
    def validate(self, data):
        from .models import Employee, Shift, ShiftType
        from datetime import timedelta
        
        date = data.get('date')
        start_time = data.get('start_time')
        end_time = data.get('end_time')
        employee_id = data.get('employee')  # ✅ EMPLOYEE_ID

        # ✅ Permitir turnos nocturnos
        is_overnight_shift = end_time < start_time
        
        if not is_overnight_shift and start_time >= end_time:
            raise serializers.ValidationError(
                "La hora de inicio debe ser anterior a la de fin para turnos diurnos."
            )

        # ✅ Validar que employee_id existe
        try:
            employee = Employee.objects.get(pk=employee_id)
            logger.info(f"✅ Employee encontrado: ID={employee.id}, User ID={employee.user.id}")
        except Employee.DoesNotExist:
            raise serializers.ValidationError({
                "employee": f"No existe empleado con ID {employee_id}"
            })

        # ✅ Validar que está activo
        if not employee.is_active:
            raise serializers.ValidationError({
                "employee": "El empleado no está activo"
            })

        # ✅ Verificar solapamiento
        if is_overnight_shift:
            # Para turnos nocturnos, comprobar conflictos por separado
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

            # Excluir instancia actual en cada queryset
            if self.instance:
                conflicts_same_day = conflicts_same_day.exclude(pk=self.instance.pk)
                conflicts_next_day = conflicts_next_day.exclude(pk=self.instance.pk)

            if conflicts_same_day.exists() or conflicts_next_day.exists():
                c = conflicts_same_day.first() or conflicts_next_day.first()
                raise serializers.ValidationError({
                    "detail": f"Solapamiento con turno existente: {c.start_time} - {c.end_time} en {c.date}"
                })
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

    def update(self, instance, validated_data):
        employee = validated_data['employee_obj']
        logger.info(f"🔄 Actualizando turno {instance.pk} - Employee ID: {employee.id}, User ID: {employee.user.id}")
        
        instance.date = validated_data.get('date', instance.date)
        instance.start_time = validated_data.get('start_time', instance.start_time)
        instance.end_time = validated_data.get('end_time', instance.end_time)
        instance.employee = employee
        instance.shift_type = validated_data.get('shift_type_obj', instance.shift_type)
        instance.notes = validated_data.get('notes', instance.notes)
        
        instance.full_clean()
        instance.save()
        
        logger.info(f"✅ Turno {instance.pk} actualizado - Employee: {instance.employee.id}, User: {instance.employee.user.id}")
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

            # Excluir instancia actual en cada queryset
            if self.instance:
                conflicts_same_day = conflicts_same_day.exclude(pk=self.instance.pk)
                conflicts_next_day = conflicts_next_day.exclude(pk=self.instance.pk)

            if conflicts_same_day.exists() or conflicts_next_day.exists():
                raise serializers.ValidationError({
                    "detail": "Rango horario inválido o superpuesto"
                })
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
    
class TimeEntrySerializer(serializers.Serializer):
    """Serializer para registrar entrada/salida de empleados"""
    id = serializers.IntegerField(read_only=True)
    entry_type = serializers.ChoiceField(choices=['check_in', 'check_out'])
    notes = serializers.CharField(allow_blank=True, required=False)
    location = serializers.CharField(allow_blank=True, required=False)
    shift_id = serializers.IntegerField(required=False, allow_null=True)
    
    def validate(self, data):
        from .models import Employee, Shift, TimeEntry
        from django.utils import timezone
        from datetime import timedelta, time as datetime_time
        import pytz
        from django.conf import settings
        
        request = self.context.get('request')
        
        if not request or not request.user.is_authenticated:
            raise serializers.ValidationError({"detail": "Autenticación requerida"})
        
        # ✅ SOLO EMPLEADOS pueden registrar entrada/salida
        if request.user.role in ['ADMIN', 'GERENTE']:
            raise serializers.ValidationError({
                "detail": "Solo los empleados pueden registrar entrada/salida"
            })
        
        try:
            employee = Employee.objects.get(user=request.user)
            logger.info(f"✅ Employee encontrado: ID={employee.id}, User={request.user.email}")
        except Employee.DoesNotExist:
            raise serializers.ValidationError({
                "detail": "No se encontró perfil de empleado para este usuario"
            })
        
        entry_type = data.get('entry_type')
        
        # ✅ NUEVO: Verificar registros de HOY (en zona horaria local)
        local_tz = pytz.timezone(settings.TIME_ZONE)
        now_local = timezone.now().astimezone(local_tz)
        today_local = now_local.date()
        
        # Calcular inicio y fin del día en hora local
        start_of_day_local = timezone.make_aware(
            timezone.datetime.combine(today_local, datetime_time.min),
            local_tz
        )
        end_of_day_local = timezone.make_aware(
            timezone.datetime.combine(today_local, datetime_time.max),
            local_tz
        )
        
        # Buscar registros de hoy
        today_entries = TimeEntry.objects.filter(
            employee=employee,
            timestamp__gte=start_of_day_local,
            timestamp__lte=end_of_day_local
        ).order_by('timestamp')
        
        check_in_today = today_entries.filter(entry_type='check_in').first()
        check_out_today = today_entries.filter(entry_type='check_out').first()
        
        logger.info(f"📅 Registros de HOY ({today_local}): check_in={bool(check_in_today)}, check_out={bool(check_out_today)}")
        
        # ✅ Validar que no haya registros duplicados del día
        if entry_type == 'check_in':
            if check_in_today:
                raise serializers.ValidationError({
                    "detail": f"Ya tienes una entrada registrada hoy a las {check_in_today.timestamp_local.strftime('%H:%M:%S')}"
                })
        elif entry_type == 'check_out':
            if check_out_today:
                raise serializers.ValidationError({
                    "detail": f"Ya tienes una salida registrada hoy a las {check_out_today.timestamp_local.strftime('%H:%M:%S')}"
                })
            if not check_in_today:
                raise serializers.ValidationError({
                    "detail": "Debes registrar una entrada antes de registrar una salida"
                })
        
        # ✅ Validar secuencia lógica con el último registro general
        last_entry = TimeEntry.objects.filter(employee=employee).order_by('-timestamp').first()
        
        if last_entry:
            if last_entry.entry_type == entry_type:
                if entry_type == 'check_in':
                    raise serializers.ValidationError({
                        "detail": "Ya tienes una entrada registrada. Debes registrar una salida primero."
                    })
                else:
                    raise serializers.ValidationError({
                        "detail": "Ya tienes una salida registrada. Debes registrar una entrada primero."
                    })
        else:
            # Primer registro debe ser check_in
            if entry_type == 'check_out':
                raise serializers.ValidationError({
                    "detail": "Debes registrar una entrada antes de registrar una salida."
                })
        
        # ✅ Buscar turno activo (opcional)
        shift = None
        shift_id = data.get('shift_id')
        
        if shift_id:
            try:
                shift = Shift.objects.get(pk=shift_id, employee=employee)
            except Shift.DoesNotExist:
                raise serializers.ValidationError({
                    "shift_id": "Turno no encontrado o no pertenece a este empleado"
                })
        else:
            # Buscar turno del día actual
            current_time = now_local.time()
            
            # Buscar turno que coincida con la hora actual
            potential_shifts = Shift.objects.filter(
                employee=employee,
                date=today_local,
                start_time__lte=current_time,
                end_time__gte=current_time
            )
            
            if potential_shifts.exists():
                shift = potential_shifts.first()
                logger.info(f"✅ Turno encontrado automáticamente: {shift.id}")
        
        data['employee_obj'] = employee
        data['shift_obj'] = shift
        return data
    
    def create(self, validated_data):
        from .models import TimeEntry
        
        time_entry = TimeEntry(
            employee=validated_data['employee_obj'],
            shift=validated_data.get('shift_obj'),
            entry_type=validated_data['entry_type'],
            notes=validated_data.get('notes', ''),
            location=validated_data.get('location', '')
        )
        time_entry.save()
        
        logger.info(f"✅ Registro creado: {time_entry.entry_type} - {time_entry.timestamp_local}")
        return time_entry


class TimeEntryListSerializer(serializers.Serializer):
    """Serializer para listar registros de entrada/salida"""
    id = serializers.IntegerField()
    employee_id = serializers.IntegerField(source='employee.id')
    employee_name = serializers.SerializerMethodField()
    entry_type = serializers.CharField()
    timestamp = serializers.DateTimeField()
    date = serializers.SerializerMethodField()
    time = serializers.SerializerMethodField()
    shift_id = serializers.IntegerField(source='shift.id', allow_null=True)
    notes = serializers.CharField()
    location = serializers.CharField()
    
    def get_employee_name(self, obj):
        if obj.employee and obj.employee.user:
            return f"{obj.employee.user.first_name} {obj.employee.user.last_name}".strip()
        return "Desconocido"
    
    def get_date(self, obj):
        return obj.date.isoformat()
    
    def get_time(self, obj):
        return obj.time.isoformat()
    
class ShiftChangeRequestSerializer(serializers.Serializer):
    """Serializer para crear solicitudes de cambio de turno (EMPLEADOS)"""
    id = serializers.IntegerField(read_only=True)
    original_shift = serializers.IntegerField()  # Shift ID
    proposed_employee = serializers.IntegerField(required=False, allow_null=True)  # Employee ID
    proposed_shift = serializers.IntegerField(required=False, allow_null=True)  # Shift ID
    reason = serializers.CharField()
    
    def validate(self, data):
        from .models import ShiftChangeRequest, Employee, Shift
        from datetime import datetime, timedelta
        
        request = self.context.get('request')
        
        if not request or not request.user.is_authenticated:
            raise serializers.ValidationError({"detail": "Autenticación requerida"})
        
        # ✅ SOLO EMPLEADOS pueden crear solicitudes
        if request.user.role in ['ADMIN', 'GERENTE']:
            raise serializers.ValidationError({
                "detail": "Solo los empleados pueden crear solicitudes de cambio"
            })
        
        try:
            employee = Employee.objects.get(user=request.user)
        except Employee.DoesNotExist:
            raise serializers.ValidationError({
                "detail": "No se encontró perfil de empleado"
            })
        
        # ✅ Validar turno original
        try:
            original_shift = Shift.objects.get(pk=data.get('original_shift'))
        except Shift.DoesNotExist:
            raise serializers.ValidationError({
                "original_shift": "Turno no encontrado"
            })
        
        # ✅ Verificar que el turno pertenezca al empleado
        if original_shift.employee != employee:
            raise serializers.ValidationError({
                "original_shift": "Este turno no te pertenece"
            })
        
        # ✅ Validar plazo de 24 horas
        shift_datetime = datetime.combine(
            original_shift.date,
            original_shift.start_time
        )
        now = datetime.now()
        hours_until_shift = (shift_datetime - now).total_seconds() / 3600
        
        if hours_until_shift < 24:
            raise serializers.ValidationError({
                "detail": "No se puede solicitar cambio con menos de 24 horas de anticipación"
            })
        
        # ✅ Validar que no exista solicitud pendiente para este turno
        existing_request = ShiftChangeRequest.objects.filter(
            original_shift=original_shift,
            status='pending'
        ).exists()
        
        if existing_request:
            raise serializers.ValidationError({
                "detail": "Ya existe una solicitud pendiente para este turno"
            })
        
        # ✅ Si propone compañero, validar
        proposed_employee = None
        proposed_shift = None
        
        if data.get('proposed_employee'):
            try:
                proposed_employee = Employee.objects.get(pk=data.get('proposed_employee'))
            except Employee.DoesNotExist:
                raise serializers.ValidationError({
                    "proposed_employee": "Empleado propuesto no encontrado"
                })
            
            # Verificar que no sea el mismo
            if proposed_employee == employee:
                raise serializers.ValidationError({
                    "proposed_employee": "No puedes proponer un intercambio contigo mismo"
                })
            
            # ✅ Si hay empleado propuesto, debe haber turno propuesto
            if not data.get('proposed_shift'):
                raise serializers.ValidationError({
                    "proposed_shift": "Debes especificar el turno del compañero propuesto"
                })
            
            try:
                proposed_shift = Shift.objects.get(pk=data.get('proposed_shift'))
            except Shift.DoesNotExist:
                raise serializers.ValidationError({
                    "proposed_shift": "Turno propuesto no encontrado"
                })
            
            # ✅ Verificar que el turno propuesto pertenezca al empleado propuesto
            if proposed_shift.employee != proposed_employee:
                raise serializers.ValidationError({
                    "proposed_shift": "El turno no pertenece al empleado propuesto"
                })
            
            # ✅ Verificar disponibilidad (no solapamiento)
            # El empleado solicitante debe poder tomar el turno del propuesto
            conflicts = Shift.objects.filter(
                employee=employee,
                date=proposed_shift.date,
                start_time__lt=proposed_shift.end_time,
                end_time__gt=proposed_shift.start_time
            ).exclude(pk=original_shift.pk)
            
            if conflicts.exists():
                raise serializers.ValidationError({
                    "proposed_shift": "Tienes otro turno que se solapa con el turno propuesto"
                })
        
        # ✅ Validar motivo
        if not data.get('reason') or len(data.get('reason').strip()) < 10:
            raise serializers.ValidationError({
                "reason": "El motivo debe tener al menos 10 caracteres"
            })
        
        data['employee_obj'] = employee
        data['original_shift_obj'] = original_shift
        data['proposed_employee_obj'] = proposed_employee
        data['proposed_shift_obj'] = proposed_shift
        
        return data
    
    def create(self, validated_data):
        from .models import ShiftChangeRequest
        
        request_obj = ShiftChangeRequest(
            requesting_employee=validated_data['employee_obj'],
            original_shift=validated_data['original_shift_obj'],
            proposed_employee=validated_data.get('proposed_employee_obj'),
            proposed_shift=validated_data.get('proposed_shift_obj'),
            reason=validated_data['reason'],
            status='pending'
        )
        request_obj.full_clean()
        request_obj.save()
        
        logger.info(f"✅ Solicitud de cambio creada: ID={request_obj.id}")
        return request_obj


class ShiftChangeRequestListSerializer(serializers.Serializer):
    """Serializer para listar solicitudes (GERENTES y EMPLEADOS)"""
    id = serializers.IntegerField()
    requesting_employee_id = serializers.IntegerField(source='requesting_employee.id')
    requesting_employee_name = serializers.SerializerMethodField()
    requesting_employee_position = serializers.SerializerMethodField()
    
    original_shift_id = serializers.IntegerField(source='original_shift.id')
    original_shift_date = serializers.DateField(source='original_shift.date')
    original_shift_start = serializers.TimeField(source='original_shift.start_time')
    original_shift_end = serializers.TimeField(source='original_shift.end_time')
    original_shift_type = serializers.SerializerMethodField()
    
    proposed_employee_id = serializers.IntegerField(source='proposed_employee.id', allow_null=True)
    proposed_employee_name = serializers.SerializerMethodField()
    
    proposed_shift_id = serializers.IntegerField(source='proposed_shift.id', allow_null=True)
    proposed_shift_date = serializers.SerializerMethodField()
    proposed_shift_start = serializers.SerializerMethodField()
    proposed_shift_end = serializers.SerializerMethodField()
    
    reason = serializers.CharField()
    status = serializers.CharField()
    manager_comment = serializers.CharField(allow_null=True)
    reviewed_by_name = serializers.SerializerMethodField()
    
    created_at = serializers.DateTimeField()
    reviewed_at = serializers.DateTimeField(allow_null=True)
    
    def get_requesting_employee_name(self, obj):
        if obj.requesting_employee and obj.requesting_employee.user:
            return f"{obj.requesting_employee.user.first_name} {obj.requesting_employee.user.last_name}".strip()
        return "Desconocido"
    
    def get_requesting_employee_position(self, obj):
        if obj.requesting_employee:
            return obj.requesting_employee.position or "Sin puesto"
        return "Sin puesto"
    
    def get_original_shift_type(self, obj):
        if obj.original_shift and obj.original_shift.shift_type:
            return obj.original_shift.shift_type.name
        return None
    
    def get_proposed_employee_name(self, obj):
        if obj.proposed_employee and obj.proposed_employee.user:
            return f"{obj.proposed_employee.user.first_name} {obj.proposed_employee.user.last_name}".strip()
        return None
    
    def get_proposed_shift_date(self, obj):
        if obj.proposed_shift:
            return obj.proposed_shift.date.isoformat()
        return None
    
    def get_proposed_shift_start(self, obj):
        if obj.proposed_shift:
            return obj.proposed_shift.start_time.isoformat()
        return None
    
    def get_proposed_shift_end(self, obj):
        if obj.proposed_shift:
            return obj.proposed_shift.end_time.isoformat()
        return None
    
    def get_reviewed_by_name(self, obj):
        if obj.reviewed_by:
            return f"{obj.reviewed_by.first_name} {obj.reviewed_by.last_name}".strip()
        return None


class ShiftChangeRequestReviewSerializer(serializers.Serializer):
    """Serializer para aprobar/rechazar solicitudes (GERENTES)"""
    action = serializers.ChoiceField(choices=['approve', 'reject'])
    manager_comment = serializers.CharField(required=False, allow_blank=True)
    
    def validate(self, data):
        request = self.context.get('request')
        
        if not request or not request.user.is_authenticated:
            raise serializers.ValidationError({"detail": "Autenticación requerida"})
        
        # ✅ SOLO GERENTE/ADMIN pueden revisar
        if request.user.role not in ['ADMIN', 'GERENTE']:
            raise serializers.ValidationError({
                "detail": "Solo gerentes pueden revisar solicitudes"
            })
        
        # ✅ Si rechaza, comentario es obligatorio
        if data.get('action') == 'reject':
            if not data.get('manager_comment') or len(data.get('manager_comment').strip()) < 10:
                raise serializers.ValidationError({
                    "manager_comment": "Debe ingresar un motivo para el rechazo (mínimo 10 caracteres)"
                })
        
        return data
    
    def update(self, instance, validated_data):
        from django.utils import timezone
        from django.db import transaction
        from datetime import datetime, timedelta
    
        action = validated_data.get('action')
        request = self.context.get('request')
    
        with transaction.atomic():
            if action == 'approve':
                instance.status = 'approved'
                instance.reviewed_by = request.user
                instance.reviewed_at = timezone.now()
                instance.manager_comment = validated_data.get('manager_comment', 'Solicitud aprobada')
            
                original_shift = instance.original_shift
            
                if instance.proposed_employee and instance.proposed_shift:
                    proposed_shift = instance.proposed_shift
                
                    logger.info(f"🔄 Iniciando intercambio:")
                    logger.info(f"   Turno Original: Employee={original_shift.employee.id}, Date={original_shift.date}")
                    logger.info(f"   Turno Propuesto: Employee={proposed_shift.employee.id}, Date={proposed_shift.date}")
                
                    # Guardar datos
                    original_employee = original_shift.employee
                    proposed_employee = proposed_shift.employee
                
                    original_data = {
                        'date': original_shift.date,
                        'start_time': original_shift.start_time,
                        'end_time': original_shift.end_time,
                        'shift_type': original_shift.shift_type,
                        'notes': original_shift.notes
                    }
                
                    proposed_data = {
                        'date': proposed_shift.date,
                        'start_time': proposed_shift.start_time,
                        'end_time': proposed_shift.end_time,
                        'shift_type': proposed_shift.shift_type,
                        'notes': proposed_shift.notes
                    }
                
                    # Mover turnos a fechas temporales
                    temp_date = datetime(9999, 12, 31).date()
                    logger.info(f"📦 Moviendo turnos a fecha temporal: {temp_date}")
                
                    original_shift.date = temp_date
                    original_shift.save(update_fields=['date'])
                
                    proposed_shift.date = temp_date
                    proposed_shift.save(update_fields=['date'])
                
                    logger.info(f"✅ Turnos movidos a fecha temporal")
                
                    # Intercambiar datos
                    logger.info(f"🔄 Intercambiando datos...")
                
                    # Original shift ahora tiene datos del propuesto
                    original_shift.employee = original_employee
                    original_shift.date = proposed_data['date']
                    original_shift.start_time = proposed_data['start_time']
                    original_shift.end_time = proposed_data['end_time']
                    original_shift.shift_type = proposed_data['shift_type']
                    original_shift.notes = f"Intercambiado - {proposed_data['notes']}" if proposed_data['notes'] else "Turno intercambiado"
                
                    # ✅ NUEVO: Bloquear turno para edición
                    original_shift.is_locked = True
                    original_shift.lock_reason = f"Intercambiado con {proposed_employee.user.first_name} {proposed_employee.user.last_name}"
                    original_shift.locked_at = timezone.now()
                    original_shift.save()
                
                    logger.info(f"✅ Turno 1 actualizado y bloqueado: Employee={original_employee.id}")
                
                    # Proposed shift ahora tiene datos del original
                    proposed_shift.employee = proposed_employee
                    proposed_shift.date = original_data['date']
                    proposed_shift.start_time = original_data['start_time']
                    proposed_shift.end_time = original_data['end_time']
                    proposed_shift.shift_type = original_data['shift_type']
                    proposed_shift.notes = f"Intercambiado - {original_data['notes']}" if original_data['notes'] else "Turno intercambiado"
                
                    # ✅ NUEVO: Bloquear turno para edición
                    proposed_shift.is_locked = True
                    proposed_shift.lock_reason = f"Intercambiado con {original_employee.user.first_name} {original_employee.user.last_name}"
                    proposed_shift.locked_at = timezone.now()
                    proposed_shift.save()
                
                    logger.info(f"✅ Turno 2 actualizado y bloqueado: Employee={proposed_employee.id}")
                    logger.info(f"🎉 Intercambio completado - Turnos bloqueados para edición")
                
                else:
                    # Solo liberar el turno (sin compañero propuesto)
                    logger.info(f"⚠️ Turno {original_shift.id} aprobado para cambio sin propuesta")
            
            elif action == 'reject':
                instance.status = 'rejected'
                instance.reviewed_by = request.user
                instance.reviewed_at = timezone.now()
                instance.manager_comment = validated_data.get('manager_comment')
            
                logger.info(f"❌ Solicitud rechazada: ID={instance.id}")
        
            instance.save()
            
        return instance