from django.contrib import admin
from import_export.admin import ImportExportModelAdmin
from .models import Asset, Category, Location, Department, AssetIncident, AssetUpgrade, ActivityLog
from .resources import AssetResource, CategoryResource, LocationResource, DepartmentResource


@admin.register(Category)
class CategoryAdmin(ImportExportModelAdmin):
    resource_class = CategoryResource
    list_display = ['name', 'description', 'created_at']
    search_fields = ['name']


@admin.register(Location)
class LocationAdmin(ImportExportModelAdmin):
    resource_class = LocationResource
    list_display = ['name', 'building', 'floor', 'room', 'created_at']
    search_fields = ['name', 'building']


@admin.register(Department)
class DepartmentAdmin(ImportExportModelAdmin):
    resource_class = DepartmentResource
    list_display = ['name', 'head', 'created_at']
    search_fields = ['name']


class AssetIncidentInline(admin.TabularInline):
    model = AssetIncident
    extra = 0
    readonly_fields = ['reported_at']


class AssetUpgradeInline(admin.TabularInline):
    model = AssetUpgrade
    extra = 0
    readonly_fields = ['created_at']


@admin.register(Asset)
class AssetAdmin(ImportExportModelAdmin):
    resource_class = AssetResource
    list_display = [
        'inventory_number', 'inventory_name', 'category', 'location',
        'department', 'working_status', 'condition', 'warranty_status', 'created_at'
    ]
    list_filter = ['working_status', 'condition', 'category', 'department', 'location']
    search_fields = ['inventory_number', 'inventory_name', 'serial_number', 'assigned_to']
    readonly_fields = ['inventory_id', 'created_at', 'updated_at', 'created_by', 'updated_by']
    inlines = [AssetIncidentInline, AssetUpgradeInline]
    fieldsets = [
        ('Basic Information', {
            'fields': ['inventory_number', 'inventory_name', 'category', 'image', 'description']
        }),
        ('Hardware Details', {
            'fields': ['make', 'model', 'serial_number', 'vendor']
        }),
        ('Purchase Details', {
            'fields': ['date_of_purchase', 'year_of_purchase', 'purchase_price', 'warranty_years']
        }),
        ('Location & Ownership', {
            'fields': ['location', 'department', 'assigned_to']
        }),
        ('Status & Condition', {
            'fields': ['working_status', 'condition', 'incidence_details', 'upgradation_details']
        }),
        ('Metadata', {
            'fields': ['inventory_id', 'created_by', 'updated_by', 'created_at', 'updated_at'],
            'classes': ['collapse']
        }),
    ]

    def save_model(self, request, obj, form, change):
        if not change:
            obj.created_by = request.user
        obj.updated_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(AssetIncident)
class AssetIncidentAdmin(admin.ModelAdmin):
    list_display = ['asset', 'title', 'severity', 'reported_by', 'reported_at', 'resolved_at']
    list_filter = ['severity', 'reported_at']
    search_fields = ['asset__inventory_number', 'title']
    readonly_fields = ['reported_at']


@admin.register(AssetUpgrade)
class AssetUpgradeAdmin(admin.ModelAdmin):
    list_display = ['asset', 'title', 'upgrade_date', 'cost', 'performed_by']
    search_fields = ['asset__inventory_number', 'title']
    readonly_fields = ['created_at']


@admin.register(ActivityLog)
class ActivityLogAdmin(admin.ModelAdmin):
    list_display = ['user', 'action', 'model_name', 'object_repr', 'ip_address', 'timestamp']
    list_filter = ['action', 'model_name', 'timestamp']
    search_fields = ['user__username', 'object_repr']
    readonly_fields = ['user', 'action', 'model_name', 'object_id', 'object_repr', 'changes', 'ip_address', 'timestamp']

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
