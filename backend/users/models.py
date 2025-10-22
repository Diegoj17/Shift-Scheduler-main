from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.db.models.signals import pre_save, post_save
from django.dispatch import receiver



class UserManager(BaseUserManager):
    """Manager personalizado para usar email como identificador principal."""

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("El email es obligatorio.")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("El superusuario debe tener is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("El superusuario debe tener is_superuser=True.")

        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    class Role(models.TextChoices):
        GERENTE = "GERENTE", "Gerente"
        ADMIN = "ADMIN", "Administrador"
        EMPLEADO = "EMPLEADO", "Empleado"

    class Status(models.TextChoices):
        ACTIVE = "ACTIVE", "Activo"
        BLOCKED = "BLOCKED", "Bloqueado"
        INACTIVE = "INACTIVE", "Inactivo"

    username = None  # Eliminamos el username
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    telefono = models.CharField(max_length=15, blank=True, null=True)
    role = models.CharField(max_length=10, choices=Role.choices, default=Role.EMPLEADO)
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.ACTIVE)

    permissions = models.JSONField(default=list, blank=True)
    
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["first_name", "last_name"]

    # 👇 Aquí enlazamos el nuevo manager
    objects = UserManager()

    def __str__(self):
        return f"{self.email} ({self.role})"


# Permisos canónicos usados en la aplicación. Mantenerlos aquí evita
# importaciones circulares (serializers pueden importarlo desde models).
ALLOWED_PERMS = {"ver", "crear", "editar", "eliminar", "aprobar"}
# Lista que se guarda en la JSONField (orden no importante)
ALLOWED_PERMS_LIST = list(ALLOWED_PERMS)


@receiver(pre_save, sender=User)
def _store_previous_role(sender, instance, **kwargs):
    """Antes de guardar, almacenar temporalmente el rol previo (si existe)
    en el propio objeto para que post_save pueda compararlo sin consultas extra.
    """
    if instance.pk:
        try:
            prev = User.objects.get(pk=instance.pk)
            instance._previous_role = prev.role
        except User.DoesNotExist:
            instance._previous_role = None
    else:
        instance._previous_role = None


@receiver(post_save, sender=User)
def _sync_permissions_by_role(sender, instance, created, **kwargs):
    """Asegura que los roles ADMIN y GERENTE tengan el conjunto canónico de
    permisos, y que EMPLEADO (u otros) no tengan permisos.

    Usamos update() en lugar de instance.save() para evitar bucles de señales.
    """
    try:
        # Roles que deben tener los permisos canónicos
        if instance.role in (User.Role.ADMIN, User.Role.GERENTE):
            # Si los permisos actuales difieren, actualizarlos en BD
            if set(instance.permissions or []) != ALLOWED_PERMS:
                User.objects.filter(pk=instance.pk).update(permissions=ALLOWED_PERMS_LIST)
        else:
            # Otros roles (por ejemplo EMPLEADO) no deben conservar permisos
            if instance.permissions:
                User.objects.filter(pk=instance.pk).update(permissions=[])
    except Exception:
        # No queremos que un error en esta lógica impida operaciones sobre usuario
        pass

    
def _desired_permissions_for_role(role):
    return ALLOWED_PERMS_LIST if role in (User.Role.ADMIN, User.Role.GERENTE) else []


# Sobrescribimos save para forzar sincronización de permisos cuando se guarda
def _user_save_with_perm_sync(self, *args, **kwargs):
    """Asegura que el campo `permissions` tenga el valor deseado antes de guardar.

    Si se pasa `update_fields`, añadimos `permissions` a ellos cuando sea necesario
    para garantizar que se escriba en la BD.
    """
    # calcular permisos deseados según el rol actual
    try:
        desired = _desired_permissions_for_role(self.role)
    except Exception:
        desired = []

    need_update_permissions = (self.permissions or []) != desired
    update_fields = kwargs.get("update_fields", None)

    if need_update_permissions:
        # actualizar el atributo en memoria
        self.permissions = desired
        # si se especificaron update_fields, asegurarse que incluya 'permissions'
        if update_fields is not None:
            uf = set(update_fields)
            if "permissions" not in uf:
                uf.add("permissions")
                kwargs["update_fields"] = list(uf)

    # llamar al save original (evitar doble-binding si ya fue reemplazado)
    return _orig_user_save(self, *args, **kwargs)


# Conectamos la función como método en la clase User de forma segura
_orig_user_save = User.save
User.save = _user_save_with_perm_sync
