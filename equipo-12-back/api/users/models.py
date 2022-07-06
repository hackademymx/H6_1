from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractUser
from django.urls import reverse

# modelo de tipo de solicitante
class Role(models.Model):
	name = models.CharField(max_length=120, unique=True)

	class Meta:
		db_table = 'roles'

	def __str__(self):
		return self.name

class UserManager(BaseUserManager):
    def create_user(self, email, password=None):
        if not email:
            raise TypeError("Enter a valid email address.")
        if not password:
            raise TypeError("Enter a valid password.")

        user = self.model(
            email=self.normalize_email(email),
        )
        user.set_password(password)
        user.is_active=True
        user.save()
        return user



class User(AbstractUser):
	username = None
	email = models.EmailField(max_length=50, unique=True)
	password = models.CharField(max_length=200)
	is_active = models.BooleanField(default=False)
	is_superuser = models.BooleanField(default=False)
	is_verified = models.BooleanField(default=False)

	role = models.ForeignKey(Role, on_delete=models.CASCADE, null=True)

	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	pwd_count = models.IntegerField(default=0)

	USERNAME_FIELD = 'email'
	REQUIRED_FIELDS = []


	class Meta:
		db_table = 'usersapp'

		ordering = ["-updated_at"]

	def total_pwd(self):
		return self.pwd_count.count()
		
	def __str__(self):

		return self.email

#modelo para la lista precargada H6
class NivelAcademico(models.Model):
    nivel_academico = models.CharField(max_length=100)
    class Meta:
        db_table = 'nivel' #hace referencia a la tabla en la bd
    def __str__(self):
        return self.nivel_academico

#finalizado, trunco etc
class Status(models.Model):
    status = models.CharField(max_length=100)
    class Meta:
        db_table = 'status'
    def __str__(self):
        return self.status

#solicitante 
class DatosAcademicos(models.Model):
    usuario = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True)
    nivel_academico = models.ForeignKey(NivelAcademico, on_delete=models.CASCADE, null=True)
    nombre = models.CharField(max_length=50)
    institucion = models.CharField(max_length=100)
    duracion = models.CharField(max_length=100)
    status = models.ForeignKey(Status, on_delete=models.CASCADE, null=True)
    created_at = models.DateTimeField(auto_now_add=True) #se le asigna la fecha cuando se registra
    updated_at= models.DateTimeField(auto_now_add=True) #se puede actualizar a futuro, cada vez que haya un PUT


    class Meta:
        db_table = 'datos_academicos'
    
    def __str__(self):
        return str(self.usuario)



