from django import forms
from .models import FileRepository, SharedFile


class FileRepositoryForm(forms.ModelForm):
    class Meta:
        model = FileRepository
        fields = ['name', 'description', 'access_type', 'location', 'department']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Repository name'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'access_type': forms.Select(attrs={'class': 'form-select'}),
            'location': forms.Select(attrs={'class': 'form-select'}),
            'department': forms.Select(attrs={'class': 'form-select'}),
        }


class SharedFileUploadForm(forms.ModelForm):
    class Meta:
        model = SharedFile
        fields = ['title', 'description', 'file']
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'File title'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'placeholder': 'Optional description'}),
            'file': forms.FileInput(attrs={'class': 'form-control'}),
        }
