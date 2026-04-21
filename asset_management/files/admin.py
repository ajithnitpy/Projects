from django.contrib import admin
from .models import FileRepository, SharedFile


@admin.register(FileRepository)
class FileRepositoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'access_type', 'location', 'department', 'created_by', 'created_at']
    list_filter = ['access_type', 'location', 'department']
    search_fields = ['name', 'description']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(SharedFile)
class SharedFileAdmin(admin.ModelAdmin):
    list_display = ['title', 'repository', 'file_name', 'file_size', 'uploaded_by', 'download_count', 'created_at']
    list_filter = ['repository']
    search_fields = ['title', 'file_name', 'description']
    readonly_fields = ['file_size', 'file_name', 'mime_type', 'download_count', 'created_at', 'updated_at']
