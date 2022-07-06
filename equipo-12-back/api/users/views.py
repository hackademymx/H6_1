from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages

from rest_framework import status, permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAuthenticatedOrReadOnly
from rest_framework.exceptions import AuthenticationFailed

from .models import User, DatosAcademicos, NivelAcademico, Status

from django.http import HttpResponse, HttpResponseRedirect
from django.contrib import messages
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse


import datetime
from datetime import timedelta
import jwt
import os

from users.models import User
from users.serializers import UserSignUpSerializer, LogoutSerializer, UserSerializer, ResetPasswordEmailRequestSerializer, SetNewPasswordSerializer, UserRoleSerializer
from users.serializers import DatosAcademicosSerializer, NivelSerializer, StatusSerializer
from users.utils import Util
from core.settings import base

from rest_framework_simplejwt.tokens import RefreshToken



# Generates tokens manually.
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

# Registro de usuario
class UserSignUpView(APIView):
	def post(self, request):
		serializer = UserSignUpSerializer(data= request.data)
		if serializer.is_valid(raise_exception=True):
			serializer.save()
			user_data = serializer.data 
			user = User.objects.get(email=user_data['email'])
			refresh = RefreshToken.for_user(user)

			current_site = get_current_site(request).domain
			relativeLink = reverse('email-verify')

			absurl = 'http://'+current_site+relativeLink+"?token="+str(refresh)
			# print(absurl)
			email_body = 'Hi '+user.email+'Use this link below to verify your email \n' + absurl 
			data = {'email_body': email_body, 'to_email': user.email, 'email_subject': 'Verify your email'}
			Util.send_email(data)

			return Response({'status': 200, 
				'payload': serializer.data, 
				'refresh': str(refresh),
				'access': str(refresh.access_token), 
				'message': 'Check your email to verify your account before login'})
		else:
			return Response({'status': 403, 'message': 'El email o password ingresados no cumplen los criterios del registro'})


# Verificacion de email
class VerifyEmailView(APIView):

	def get(self, request):
		token = request.GET.get('token')
		# print(token)
		try:
			payload = jwt.decode(token, options={"verify_signature": False}, algorithms=['HS256'])
			# print(payload)
			user = User.objects.get(id=payload['user_id'])
			if not user.is_verified:
				user.is_verified = True
			if not user.is_active:
				user.is_active = True
				user.save()
			return Response({'email': 'successfully activated'}, status=status.HTTP_200_OK)
		except jwt.ExpiredSignatureError as identifier:
			return Response({'error': 'Activation Expired'}, status=status.HTTP_400_BAD_REQUEST)
		except jwt.exceptions.DecodeError as identifier:
			return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)

# Login de usuario
class UserLoginView(APIView):

	permissions_classes = (AllowAny,)
	
	def post(self, request):
		email = request.data['email']
		password = request.data['password']
		user = User.objects.filter(email=email).first()

		if user is None:
			return Response({'status':404, 
				'message':'User not found'})

		if not user.check_password(password):
			user.pwd_count += 1
			total_pwd = user.pwd_count
			user.save()
			print(total_pwd)
			if total_pwd >= 4:
				user.is_active = False
				user.save()
				return Response({'status': 403, 'message': 'Usuario ha sido bloqueado por demasiados intentos'})
			return Response({'status':401, 'message': 'Incorrect password'})


		

			if total_pwd >= 4:
				user.is_active = False 
				user.save()
				return Response({'status':401, 
					'message': 'Your account has been blocked'})
			return Response({'status':401,
				'message':'Incorrect Password'})

		if not user.is_verified:
			return Response({'status':401,
				'message':'Account is not verified'})

		if user.is_active == False:
			return Response({'status':403, 'message':'Your account has been block for too many attempts... Please follow the instruction to reset your password'})

		user.pwd_count = 0
		user.save()
			
		payload = {
				'id': user.id,
				'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
				'iat': datetime.datetime.utcnow()
				}

		refresh = RefreshToken.for_user(user)
		
		#token = jwt.encode(payload, 'secret', algorithm='HS256').decode('utf-8')
		
		response = Response()

		#response.set_cookie(key='jwt', value=token, httponly=True)
		#response.setdefault(key='token', value=token)

		response.data = {
				'access': str(refresh.access_token),
				'refresh': str(refresh), 
				'status': 200,
				'id': user.id
			}

		return response



# Cambiar contraseña por medio de email=========
class PasswordRecoveryEmail(APIView):
	serializer = ResetPasswordEmailRequestSerializer

	def post(self, request):
		serializer = self.serializer(data=request.data)
		email = request.data.get('email', '')

		if User.objects.filter(email=email).exists():
			user = User.objects.get(email=email)
			refresh = RefreshToken.for_user(user)
			#current_site = get_current_site(
				#request=request).domain
			relativeLink = base.FRONT_URL
			print(relativeLink)

			absurl = relativeLink+"?token="+str(refresh)
			email_body = 'Hola '+user.email+' Use este enlace para cambiar su contraseña   \n'+absurl
			data = {'email_body': email_body, 'to_email': user.email, 'email_subject': 'Password change'}
			Util.send_email(data)

			return Response({'status':200, 'message': 'Check your email to recover your password'})
		return Response({'status':404, 'message': 'No existe un usuario con ese email'})



# Vista para escribir la nueva contraseña del usuario
class SetNewPasswordView(APIView):
	serializer = SetNewPasswordSerializer

	def patch(self, request):
		token = request.data['token']
		try:
			payload = jwt.decode(token, options={"verify_signature": False}, algorithms=['HS256'])
		except jwt.ExpiredSignatureError:
			return Response({'status':401, 'message':'Not authorized'})
		user = User.objects.filter(id=payload['user_id']).first()
		serializer = SetNewPasswordSerializer(data=request.data)
		if serializer.is_valid():
			password = request.data['password']
			user.set_password(password)
			user.is_active = True
			user.save()
		else: 
			return Response({'status':401, 'message': 'password must be longer than 6 charachters, contain symbols, numbers, uppercase and lowercase'})
		return Response({'status': 200, 'sucess': True, 'message': 'Password reset success'})


class LogoutView(APIView):
	permission_classes = (IsAuthenticated,)

	def post(self, request):
		try:
			refresh_token = request.data["refresh"]
			token = RefreshToken(refresh_token)
			token.blacklist()
			return Response({'status': 204})
		except Exception as e:
			return Response({'status': 400})

# View for user roles
class UserRoleView(APIView):
	def post(self, request):
		serializer = UserRoleSerializer(data= request.data)
		serializer.is_valid(raise_exception=True)
		serializer.save()

		return Response(serializer.data, status=status.HTTP_200_OK)


#captura de datos academicos
#vista del perfil#perfilecreate

class PerfilAcademico(APIView):
	permissions_classes = [IsAuthenticated]
	def post(self, request):
		data = request.data
		serializer = DatosAcademicosSerializer(data=data)
		if serializer.is_valid():
			serializer.save()
			return Response({'status':201, 'message':'datos academicos actualizados', 'data': serializer.data})
			return Response({'status':400, 'message':'solicitud incorrecta', 'data': serializer.data})







