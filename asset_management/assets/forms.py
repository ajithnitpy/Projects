from django import forms
from django.core.exceptions import ValidationError
from .models import Asset, Category, Location, Department, AssetIncident, AssetUpgrade


class AssetForm(forms.ModelForm):
    class Meta:
        model = Asset
        exclude = ['inventory_id', 'created_by', 'updated_by', 'created_at', 'updated_at']
        widgets = {
            'date_of_purchase': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'inventory_number': forms.TextInput(attrs={'class': 'form-control'}),
            'inventory_name': forms.TextInput(attrs={'class': 'form-control'}),
            'make': forms.TextInput(attrs={'class': 'form-control'}),
            'model': forms.TextInput(attrs={'class': 'form-control'}),
            'serial_number': forms.TextInput(attrs={'class': 'form-control'}),
            'year_of_purchase': forms.NumberInput(attrs={'class': 'form-control', 'min': '1900', 'max': '2100'}),
            'purchase_price': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'}),
            'vendor': forms.TextInput(attrs={'class': 'form-control'}),
            'assigned_to': forms.TextInput(attrs={'class': 'form-control'}),
            'working_status': forms.Select(attrs={'class': 'form-select'}),
            'condition': forms.Select(attrs={'class': 'form-select'}),
            'category': forms.Select(attrs={'class': 'form-select'}),
            'location': forms.Select(attrs={'class': 'form-select'}),
            'department': forms.Select(attrs={'class': 'form-select'}),
            'warranty_years': forms.NumberInput(attrs={'class': 'form-control', 'min': '0'}),
            'incidence_details': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'upgradation_details': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'image': forms.FileInput(attrs={'class': 'form-control', 'accept': 'image/*'}),
        }


class CategoryForm(forms.ModelForm):
    class Meta:
        model = Category
        fields = ['name', 'description']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        }


class LocationForm(forms.ModelForm):
    class Meta:
        model = Location
        fields = ['name', 'building', 'floor', 'room', 'address']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'building': forms.TextInput(attrs={'class': 'form-control'}),
            'floor': forms.TextInput(attrs={'class': 'form-control'}),
            'room': forms.TextInput(attrs={'class': 'form-control'}),
            'address': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        }


class DepartmentForm(forms.ModelForm):
    class Meta:
        model = Department
        fields = ['name', 'head', 'description']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'head': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        }


class AssetIncidentForm(forms.ModelForm):
    class Meta:
        model = AssetIncident
        fields = ['title', 'description', 'severity', 'resolution_notes', 'resolved_at']
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'severity': forms.Select(attrs={'class': 'form-select'}),
            'resolution_notes': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'resolved_at': forms.DateTimeInput(attrs={'type': 'datetime-local', 'class': 'form-control'}),
        }


class AssetUpgradeForm(forms.ModelForm):
    class Meta:
        model = AssetUpgrade
        fields = ['title', 'description', 'upgrade_date', 'cost', 'performed_by']
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'upgrade_date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'cost': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'}),
            'performed_by': forms.TextInput(attrs={'class': 'form-control'}),
        }


class ImportForm(forms.Form):
    IMPORT_TYPE_CHOICES = [
        ('assets', 'Assets'),
        ('categories', 'Categories'),
        ('locations', 'Locations'),
        ('departments', 'Departments'),
    ]
    import_type = forms.ChoiceField(choices=IMPORT_TYPE_CHOICES, widget=forms.Select(attrs={'class': 'form-select'}))
    file = forms.FileField(widget=forms.FileInput(attrs={'class': 'form-control', 'accept': '.csv,.xlsx,.xls'}))

    def clean_file(self):
        f = self.cleaned_data['file']
        ext = f.name.split('.')[-1].lower()
        if ext not in ['csv', 'xlsx', 'xls']:
            raise ValidationError('Only CSV and Excel files are allowed.')
        return f


class AssetFilterForm(forms.Form):
    search = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Search assets...'}))
    category = forms.ModelChoiceField(queryset=Category.objects.all(), required=False, empty_label='All Categories', widget=forms.Select(attrs={'class': 'form-select'}))
    location = forms.ModelChoiceField(queryset=Location.objects.all(), required=False, empty_label='All Locations', widget=forms.Select(attrs={'class': 'form-select'}))
    department = forms.ModelChoiceField(queryset=Department.objects.all(), required=False, empty_label='All Departments', widget=forms.Select(attrs={'class': 'form-select'}))
    condition = forms.ChoiceField(choices=[('', 'All Conditions')] + Asset.CONDITION_CHOICES, required=False, widget=forms.Select(attrs={'class': 'form-select'}))
    working_status = forms.ChoiceField(choices=[('', 'All Statuses')] + Asset.STATUS_CHOICES, required=False, widget=forms.Select(attrs={'class': 'form-select'}))
