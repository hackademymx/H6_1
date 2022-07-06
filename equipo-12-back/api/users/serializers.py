from rest_framework import serializers

from rest_framework.serializers import (EmailField, HyperlinkedIdentityField, ModelSerializer, SerializerMethodField, ValidationError, CharField, IntegerField)
from django.contrib.auth.models import User

from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from .models import User, Role, DatosAcademicos, NivelAcademico, Status



class UserRoleSerializer(serializers.ModelSerializer):
	class Meta:
		model = Role 
		fields = ["id", "name"]

class UserSerializer(serializers.ModelSerializer):
	class Meta: 
		model = User 
		fields = '__all__'
		extra_kwargs = {
		'password':{'write_only': True},
		'pwd_count': {'write_only': True},
		}


class UserSignUpSerializer(serializers.ModelSerializer):
	role = UserRoleSerializer
	
	class Meta:
		model = User
		fields = ['email', 'password', 'is_active', 'is_verified', 'role']

		extra_kwargs = {
		'password':{'write_only': True},
		'pwd_count': {'write_only': True},
		}


	def validate(self, attrs):
		password = attrs['password']
		SpecialSym =['$', '@', '#', '%', '!', '&']

		if len(password) < 6 or len(password) > 20:
			raise serializers.ValidationError("password must contain unless 6 charachters maximun 20")

		if password == 'P@ssword123':
			raise serializers.ValidationError("This can't be your password")

		if not any(char.isupper() for char in password):
			raise serializers.ValidationError("password must contain one uppercase letter")
		
		if not any(char.islower() for char in password):
			raise serializers.ValidationError("password must contain one lowercase letter")

		if not any(char in SpecialSym for char in password):
			raise serializers.ValidationError("password must contain one special charachter")


		if not any(char.isdigit() for char in password):
			raise serializers.ValidationError("password must contain at least one number")


		return attrs

	def create(self, validated_data):
		password = validated_data.pop('password', None)
		instance = self.Meta.model(**validated_data)
		if password is not None:
			instance.set_password(password)
			instance.save()
			return instance


class ResetPasswordEmailRequestSerializer(serializers.ModelSerializer):

	class Meta:
		model = User
		fields = ['email']


class SetNewPasswordSerializer(serializers.ModelSerializer):
	password = serializers.CharField(
		min_length=8, max_length=68, write_only=True)
	
	class Meta:
		model = User 
		fields = ['password', 'is_active']

	def validate(self, data):
		user = User(**data)
		password = data.get('password')
		SpecialSym =['$', '@', '#', '%', '&', '!']

		if len(password) < 6 or len(password) > 20:
			raise serializers.ValidationError("password must contain unless 6 charachters maximun 20")

			
		if not any(char.isupper() for char in password):
			raise serializers.ValidationError("password must contain one uppercase letter")
		
		if not any(char.islower() for char in password):
			raise serializers.ValidationError("password must contain one lowercase letter")

		if not any(char in SpecialSym for char in password):
			raise serializers.ValidationError("password must contain one special charachter")

		if not any(char.isdigit() for char in password):
			raise serializers.ValidationError("password must contain at least one number")


		else: 
			return data

class LogoutSerializer(serializers.ModelSerializer):
	refresh = serializers.CharField()

	default_error_message = {
		'bad_token': ('Token is expired or invalid')
	}

	def validate(self, attrs):
		self.token = attrs['refresh']
		return attrs

	def save(self, **kwargs):
		try:
			RefreshToken(self.token).blacklist()
		except TokenError:
			self.fail('bad_token')
	



#captura de datos academicos 
class NivelSerializer(serializers.ModelSerializer):
    class Meta:
        model = NivelAcademico
        fields = ['id', 'nivel_academico']

class StatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = Status
        fields = '__all__'



class DatosAcademicosSerializer(serializers.ModelSerializer):
    class Meta:
        model = DatosAcademicos
        fields = ['usuario', 'nivel_academico', 'nombre', 'institucion', 'duracion', 'status']


