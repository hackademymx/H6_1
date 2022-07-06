# Generated by Django 4.0.3 on 2022-07-03 01:40

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0003_alter_user_password'),
    ]

    operations = [
        migrations.CreateModel(
            name='NivelAcademico',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('nivel_academico', models.CharField(max_length=100)),
            ],
            options={
                'db_table': 'nivel',
            },
        ),
        migrations.CreateModel(
            name='Status',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('status', models.CharField(max_length=100)),
            ],
            options={
                'db_table': 'status',
            },
        ),
        migrations.CreateModel(
            name='DatosAcademicos',
            fields=[
                ('usuario', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, serialize=False, to=settings.AUTH_USER_MODEL)),
                ('nombre', models.CharField(max_length=50)),
                ('institucion', models.CharField(max_length=100)),
                ('duracion', models.CharField(max_length=100)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now_add=True)),
                ('nivel_academico', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='users.nivelacademico')),
                ('status', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='users.status')),
            ],
            options={
                'db_table': 'datos_academicos',
            },
        ),
    ]
