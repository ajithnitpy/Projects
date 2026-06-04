from import_export import resources, fields
from import_export.widgets import ForeignKeyWidget
from .models import Asset, Category, Location, Department


class CategoryResource(resources.ModelResource):
    class Meta:
        model = Category
        fields = ['id', 'name', 'description']
        export_order = ['id', 'name', 'description']


class LocationResource(resources.ModelResource):
    class Meta:
        model = Location
        fields = ['id', 'name', 'building', 'floor', 'room', 'address']
        export_order = ['id', 'name', 'building', 'floor', 'room', 'address']


class DepartmentResource(resources.ModelResource):
    class Meta:
        model = Department
        fields = ['id', 'name', 'head', 'description']
        export_order = ['id', 'name', 'head', 'description']


class AssetResource(resources.ModelResource):
    category = fields.Field(
        column_name='category',
        attribute='category',
        widget=ForeignKeyWidget(Category, field='name')
    )
    location = fields.Field(
        column_name='location',
        attribute='location',
        widget=ForeignKeyWidget(Location, field='name')
    )
    department = fields.Field(
        column_name='department',
        attribute='department',
        widget=ForeignKeyWidget(Department, field='name')
    )

    class Meta:
        model = Asset
        fields = [
            'inventory_id', 'inventory_number', 'inventory_name', 'category',
            'make', 'model', 'serial_number', 'date_of_purchase', 'year_of_purchase',
            'purchase_price', 'vendor', 'location', 'department', 'assigned_to',
            'working_status', 'condition', 'warranty_years', 'incidence_details',
            'upgradation_details', 'description',
        ]
        export_order = [
            'inventory_id', 'inventory_number', 'inventory_name', 'category',
            'make', 'model', 'serial_number', 'date_of_purchase', 'year_of_purchase',
            'purchase_price', 'vendor', 'location', 'department', 'assigned_to',
            'working_status', 'condition', 'warranty_years',
        ]
        import_id_fields = ['inventory_number']
        skip_unchanged = True
        report_skipped = True
