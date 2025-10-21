import re
from rest_framework import serializers

PASSWORD_REGEX = re.compile(r"^(?=.*[A-Za-z])(?=.*\d).{8,}$")

def validate_password_strength(pw: str):
    if not PASSWORD_REGEX.match(pw or ""):
        raise serializers.ValidationError(
            "La contraseña debe tener mínimo 8 caracteres e incluir letras y números."
        )
