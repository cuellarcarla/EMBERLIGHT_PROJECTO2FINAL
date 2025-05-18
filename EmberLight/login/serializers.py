from rest_framework import serializers
from django.contrib.auth import authenticate
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from .models import User


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email']
        read_only_fields = ['id']


class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'password']
        extra_kwargs = {
            'password': {'write_only': True},
            'email': {'required': True}
        }

    def validate(self, data):
        username = data.get("username", "")
        email = data.get("email", "")

        if User.objects.filter(username__iexact=username).exists():
            raise serializers.ValidationError({
                'username': 'El nombre de usuario ya está en uso.'
            })

        try:
            validate_email(email)
        except ValidationError:
            raise serializers.ValidationError({
                'email': 'Introduce un correo electrónico válido.'
            })

        if User.objects.filter(email__iexact=email).exists():
            raise serializers.ValidationError({
                'email': 'Este correo electrónico ya está registrado.'
            })

        return data

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = authenticate(username=data["username"], password=data["password"])
        if not user:
            raise serializers.ValidationError("Usuario o contraseña incorrectos.")
        return {"user": user}
