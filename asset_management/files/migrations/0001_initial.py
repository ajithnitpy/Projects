import files.models
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('assets', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='FileRepository',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=200)),
                ('description', models.TextField(blank=True)),
                ('access_type', models.CharField(
                    choices=[('open', 'Open Access'), ('lab', 'Lab / Location Based'), ('restricted', 'Restricted')],
                    default='open', max_length=20,
                )),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('created_by', models.ForeignKey(
                    null=True, on_delete=django.db.models.deletion.SET_NULL,
                    related_name='created_repos', to=settings.AUTH_USER_MODEL,
                )),
                ('department', models.ForeignKey(
                    blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                    related_name='file_repositories', to='assets.department',
                )),
                ('location', models.ForeignKey(
                    blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                    related_name='file_repositories', to='assets.location',
                )),
            ],
            options={
                'verbose_name_plural': 'File Repositories',
                'ordering': ['name'],
            },
        ),
        migrations.CreateModel(
            name='SharedFile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=200)),
                ('description', models.TextField(blank=True)),
                ('file', models.FileField(upload_to=files.models.file_upload_path)),
                ('file_name', models.CharField(blank=True, max_length=255)),
                ('file_size', models.PositiveBigIntegerField(default=0)),
                ('mime_type', models.CharField(blank=True, max_length=100)),
                ('download_count', models.PositiveIntegerField(default=0)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('repository', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='files', to='files.filerepository',
                )),
                ('uploaded_by', models.ForeignKey(
                    null=True, on_delete=django.db.models.deletion.SET_NULL,
                    related_name='uploaded_files', to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
    ]
