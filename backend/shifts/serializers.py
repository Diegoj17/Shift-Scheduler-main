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
        user_id = data.get('employee')  # ✅ Es USER_ID

        # ✅ Permitir turnos nocturnos
        is_overnight_shift = end_time < start_time
        
        if not is_overnight_shift and start_time >= end_time:
            raise serializers.ValidationError(
                "La hora de inicio debe ser anterior a la de fin para turnos diurnos."
            )

        # El campo `employee` puede venir como USER_ID o como EMPLOYEE_ID.
        # Primero intentamos interpretarlo como Employee.pk (caso más probable desde el frontend).
        try:
            incoming_id = int(user_id)
        except (TypeError, ValueError):
            raise serializers.ValidationError({
                "employee": f"ID inválido: {user_id}"
            })

        logger.info(f"🔍 [ShiftCreateSerializer] Procesando ID entrante: {incoming_id} (puede ser Employee.pk o User.pk)")

        employee = None

        # 1) Intentar encontrar Employee por PK
        try:
            employee = Employee.objects.get(pk=incoming_id)
            logger.info(f"✅ Employee encontrado por PK: Employee ID={employee.id}, User ID={employee.user.id}")
        except Employee.DoesNotExist:
            # 2) Si no existe Employee con ese PK, tratar el valor como User.pk
            try:
                user = User.objects.get(pk=incoming_id)
                logger.info(f"✅ User encontrado: ID={user.id}, Email={getattr(user, 'email', None)}")
            except User.DoesNotExist:
                raise serializers.ValidationError({
                    "employee": f"No existe Employee ni User con ID {incoming_id}"
                })

            # Buscar Employee relacionado con el User
            emp_qs = Employee.objects.filter(user=user)
            emp_count = emp_qs.count()
            if emp_count > 1:
                logger.error(f"❌ DUPLICADOS: User {incoming_id} tiene {emp_count} Employees!")
                raise serializers.ValidationError({
                    "employee": "Error: Usuario con múltiples perfiles de empleado. Contacte al administrador para limpiar la base de datos."
                })

            employee = emp_qs.first()
            if not employee:
                # Crear Employee si no existe (una sola vez atomically)
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
                        logger.info(f"✅ Employee CREADO: ID={employee.id} para User={user.email}")
                    else:
                        logger.info(f"✅ Employee ya existía (creado por otro proceso): ID={employee.id}")

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