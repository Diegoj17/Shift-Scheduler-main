from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_str, smart_bytes
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate
from django.contrib.auth.tokens import PasswordResetTokenGenerator

from .models import User, ALLOWED_PERMS
from .validators import validate_password_strength

User = get_user_model()
token_generator = PasswordResetTokenGenerator()

ALLOWED_ROLES = {"ADMIN", "GERENTE", "EMPLEADO"}


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    password_confirm = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ("id", "first_name", "last_name", "telefono", "email", "password", "password_confirm", "role")
        read_only_fields = ("id",)

    def validate_email(self, value):
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("El correo ya está registrado.")
        return value

    def validate(self, attrs):
        pw = attrs.get("password")
        pw2 = attrs.pop("password_confirm", None)
        if pw != pw2:
            raise serializers.ValidationError({"password_confirm": "Las contraseñas no coinciden."})
        validate_password_strength(pw)
        return attrs

    def create(self, validated_data):
        validated_data["password"] = make_password(validated_data["password"])
        return User.objects.create(**validated_data)


class UserPublicSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "first_name", "last_name", "telefono", "email", "role", "status", "departamento", "puesto")


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")

        user = authenticate(request=self.context.get("request"), email=email, password=password)
        if not user:
            raise serializers.ValidationError({"detail": "Credenciales inválidas."})

        if not user.is_active or user.status in ("BLOCKED", "INACTIVE"):
            raise serializers.ValidationError({"detail": "Usuario no autorizado. Verifica tu estado."})

        attrs["user"] = user
        return attrs


class AssignRolePermsSerializer(serializers.Serializer):
    role = serializers.CharField(required=True)
    permissions = serializers.ListField(
        child=serializers.CharField(), allow_empty=True, required=True
    )

    def validate_role(self, value):
        if value not in ALLOWED_ROLES:
            raise serializers.ValidationError("Rol inválido. Use: ADMIN, GERENTE, EMPLEADO.")
        return value

    def validate_permissions(self, perms):
        invalid = [p for p in perms if p not in ALLOWED_PERMS]
        if invalid:
            raise serializers.ValidationError([f"Permiso no permitido: {p}" for p in invalid])
        seen = set()
        cleaned = []
        for p in perms:
            if p not in seen:
                seen.add(p)
                cleaned.append(p)
        return cleaned

    def update(self, instance, validated_data):
        instance.role = validated_data["role"]
        instance.permissions = validated_data["permissions"]
        instance.save(update_fields=["role", "permissions"])
        return instance


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        try:
            user = User.objects.get(email__iexact=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("Correo no registrado.")
        self.context["user"] = user
        return value


class PasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True)
    new_password_confirm = serializers.CharField(write_only=True)

    def validate(self, attrs):
        if attrs["new_password"] != attrs["new_password_confirm"]:
            raise serializers.ValidationError({"new_password_confirm": "Las contraseñas no coinciden."})
        
        # Validar fortaleza de contraseña
        try:
            validate_password(attrs["new_password"])
        except Exception as e:
            raise serializers.ValidationError({"new_password": str(e)})
        
        return attrs

    def validate_uid(self, value):
        try:
            uid = force_str(urlsafe_base64_decode(value))
            user = User.objects.get(pk=uid)
        except Exception:
            raise serializers.ValidationError("UID inválido.")
        self.context["user"] = user
        return value

    def validate_token(self, value):
        """
        Valida el token - soporta tanto tokens Django como tokens UUID custom
        """
        from django.core.cache import cache
        from .models import PasswordResetToken
        import logging
        
        logger = logging.getLogger('users')
        user = self.context.get("user")
        
        if not user:
            raise serializers.ValidationError("Usuario no encontrado.")
        
        # ✅ PRIORIDAD 1: Intentar validar token custom desde DB
        try:
            db_token = PasswordResetToken.objects.filter(
                user=user,
                token=value,
                used=False
            ).first()
            
            if db_token:
                if db_token.is_expired():
                    logger.warning(f"Token DB expirado para user {user.pk}")
                    raise serializers.ValidationError("Token expirado.")
                
                logger.info(f"✅ Token DB válido para user {user.pk}")
                return value
        except serializers.ValidationError:
            raise
        except Exception as e:
            logger.warning(f"Error checking DB token: {e}")
        
        # ✅ PRIORIDAD 2: Intentar validar token custom desde cache
        try:
            cache_key = f"password_reset:{value}"
            cached_user_pk = cache.get(cache_key)
            
            if cached_user_pk and str(cached_user_pk) == str(user.pk):
                logger.info(f"✅ Token cache válido para user {user.pk}")
                return value
        except Exception as e:
            logger.warning(f"Error checking cache token: {e}")
        
        # ✅ PRIORIDAD 3: Intentar validar con Django default token generator (fallback)
        try:
            if token_generator.check_token(user, value):
                logger.info(f"✅ Token Django válido para user {user.pk}")
                return value
        except Exception as e:
            logger.warning(f"Error checking Django token: {e}")
        
        # ❌ Ninguna validación funcionó
        logger.error(f"❌ Token inválido para user {user.pk}")
        raise serializers.ValidationError("Token inválido o expirado.")


class AdminCreateUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    password_confirm = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = (
            "id", "first_name", "last_name", "telefono",
            "email", "password", "password_confirm",
            "role", "status", "departamento", "puesto"
        )

    def validate(self, data):
        if data["password"] != data["password_confirm"]:
            raise serializers.ValidationError({"password_confirm": "Las contraseñas no coinciden."})
        if User.objects.filter(email__iexact=data["email"]).exists():
            raise serializers.ValidationError({"email": "El correo ya está registrado."})
        # Cuando un administrador/gerente crea un usuario, debe proporcionar departamento y puesto
        if not data.get("departamento") or not data.get("puesto"):
            raise serializers.ValidationError({"detalle": "departamento y puesto son obligatorios para la creación por administrador."})
        return data

    def create(self, validated_data):
        validated_data.pop("password_confirm")
        validated_data["password"] = make_password(validated_data["password"])
        user = User.objects.create(**validated_data)
        return user


class AdminUpdateUserSerializer(serializers.ModelSerializer):
    """
    Serializer para actualización de usuarios por Admin/Gerente.
    NO requiere contraseña para actualizar.
    """
    telefono = serializers.CharField(required=False, allow_blank=True, allow_null=True, max_length=15)
    email = serializers.EmailField(required=False)

    class Meta:
        model = User
        fields = ("id", "first_name", "last_name", "telefono", "email", "role", "status", "departamento", "puesto")
        read_only_fields = ("id",)
        extra_kwargs = {
            'first_name': {'required': False},
            'last_name': {'required': False},
            'role': {'required': False},
            'status': {'required': False},
        }

    def validate_email(self, value):
        """Validar que el email no esté en uso por otro usuario"""
        if value in (None, ""):
            return value

        qs = User.objects.filter(email__iexact=value)
        if self.instance:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise serializers.ValidationError("El correo ya está registrado.")
        return value

    def validate_telefono(self, value):
        """Validar formato de teléfono"""
        if value and value.strip():
            clean_value = value.strip()
            if not clean_value.isdigit():
                raise serializers.ValidationError("El teléfono solo debe contener dígitos.")
            if len(clean_value) != 10:
                raise serializers.ValidationError("El teléfono debe tener exactamente 10 dígitos.")
        return value

    def validate_role(self, value):
        """Validar que el rol sea válido"""
        if value not in User.Role.values:
            raise serializers.ValidationError(
                f"Rol inválido. Debe ser uno de: {', '.join(User.Role.values)}"
            )
        return value

    def validate_status(self, value):
        """Validar que el status sea válido"""
        if value not in User.Status.values:
            raise serializers.ValidationError(
                f"Status inválido. Debe ser uno de: {', '.join(User.Status.values)}"
            )
        return value

    def update(self, instance, validated_data):
        """Actualizar el usuario con los datos validados"""
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance