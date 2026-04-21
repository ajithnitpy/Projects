from django.db import models
from django.contrib.auth.models import User


class FileRepository(models.Model):
    ACCESS_CHOICES = [
        ('open', 'Open Access'),
        ('lab', 'Lab / Location Based'),
        ('restricted', 'Restricted'),
    ]
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    access_type = models.CharField(max_length=20, choices=ACCESS_CHOICES, default='open')
    location = models.ForeignKey(
        'assets.Location', on_delete=models.SET_NULL, null=True, blank=True,
        related_name='file_repositories',
    )
    department = models.ForeignKey(
        'assets.Department', on_delete=models.SET_NULL, null=True, blank=True,
        related_name='file_repositories',
    )
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, related_name='created_repos'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    def is_accessible_by(self, user):
        if self.access_type == 'open':
            return True
        if not user or not user.is_authenticated:
            return False
        if user.is_superuser:
            return True
        profile = getattr(user, 'profile', None)
        if profile and profile.role and profile.role.role_type in ('admin', 'manager'):
            return True
        if self.access_type == 'lab':
            if profile and self.department_id and profile.department_id == self.department_id:
                return True
            return False
        return False  # restricted

    class Meta:
        ordering = ['name']
        verbose_name_plural = 'File Repositories'


def file_upload_path(instance, filename):
    return f'shared_files/{instance.repository_id}/{filename}'


class SharedFile(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    file = models.FileField(upload_to=file_upload_path)
    file_name = models.CharField(max_length=255, blank=True)
    file_size = models.PositiveBigIntegerField(default=0)
    mime_type = models.CharField(max_length=100, blank=True)
    repository = models.ForeignKey(
        FileRepository, on_delete=models.CASCADE, related_name='files'
    )
    uploaded_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, related_name='uploaded_files'
    )
    download_count = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title

    def save(self, *args, **kwargs):
        if self.file:
            if not self.file_name:
                self.file_name = self.file.name.split('/')[-1]
            try:
                self.file_size = self.file.size
            except Exception:
                pass
        super().save(*args, **kwargs)

    @property
    def size_display(self):
        size = self.file_size
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f'{size:.1f} {unit}'
            size /= 1024
        return f'{size:.1f} TB'

    @property
    def file_extension(self):
        name = self.file_name or ''
        parts = name.rsplit('.', 1)
        return parts[1].lower() if len(parts) == 2 else ''

    @property
    def icon_class(self):
        ext = self.file_extension
        icons = {
            'pdf': 'bi-file-earmark-pdf text-danger',
            'doc': 'bi-file-earmark-word text-primary',
            'docx': 'bi-file-earmark-word text-primary',
            'xls': 'bi-file-earmark-excel text-success',
            'xlsx': 'bi-file-earmark-excel text-success',
            'ppt': 'bi-file-earmark-ppt text-warning',
            'pptx': 'bi-file-earmark-ppt text-warning',
            'zip': 'bi-file-earmark-zip text-secondary',
            'rar': 'bi-file-earmark-zip text-secondary',
            'jpg': 'bi-file-earmark-image text-info',
            'jpeg': 'bi-file-earmark-image text-info',
            'png': 'bi-file-earmark-image text-info',
            'gif': 'bi-file-earmark-image text-info',
            'mp4': 'bi-file-earmark-play text-danger',
            'mp3': 'bi-file-earmark-music text-warning',
            'txt': 'bi-file-earmark-text text-muted',
            'csv': 'bi-file-earmark-spreadsheet text-success',
            'py': 'bi-file-earmark-code text-info',
        }
        return icons.get(ext, 'bi-file-earmark text-secondary')

    class Meta:
        ordering = ['-created_at']
