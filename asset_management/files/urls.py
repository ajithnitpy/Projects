from django.urls import path
from . import views

urlpatterns = [
    path('', views.file_landing, name='file_landing'),
    path('dashboard/', views.file_dashboard, name='file_dashboard'),
    path('repos/', views.repository_list, name='repository_list'),
    path('repos/create/', views.repository_create, name='repository_create'),
    path('repos/<int:repo_pk>/', views.file_list, name='file_list'),
    path('repos/<int:repo_pk>/upload/', views.file_upload, name='file_upload'),
    path('repos/<int:repo_pk>/edit/', views.repository_edit, name='repository_edit'),
    path('repos/<int:repo_pk>/delete/', views.repository_delete, name='repository_delete'),
    path('download/<int:file_pk>/', views.file_download, name='file_download'),
    path('delete/<int:file_pk>/', views.file_delete, name='file_delete'),
]
