from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_userprofile_department_fk'),
    ]

    operations = [
        migrations.AddField(
            model_name='role',
            name='can_upload_file',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='role',
            name='can_delete_file',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='role',
            name='can_create_repo',
            field=models.BooleanField(default=False),
        ),
    ]
