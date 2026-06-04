from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User
from import_export.admin import ImportExportModelAdmin
from .models import Role, UserProfile
from .resources import RoleResource, UserProfileResource


@admin.register(Role)
class RoleAdmin(ImportExportModelAdmin):
    resource_class = RoleResource
    list_display = [
        'name', 'role_type', 'can_add_asset', 'can_edit_asset',
        'can_delete_asset', 'can_manage_users', 'created_at'
    ]
    list_filter = ['role_type']
    search_fields = ['name']


class UserProfileInline(admin.StackedInline):
    model = UserProfile
    can_delete = False
    verbose_name_plural = 'Profile'
    fields = ['role', 'employee_id', 'department', 'phone', 'avatar', 'is_active']


class UserAdmin(BaseUserAdmin):
    inlines = [UserProfileInline]
    list_display = ['username', 'email', 'first_name', 'last_name', 'get_role', 'is_active']

    def get_role(self, obj):
        try:
            return obj.profile.role
        except UserProfile.DoesNotExist:
            return '-'
    get_role.short_description = 'Role'


admin.site.unregister(User)
admin.site.register(User, UserAdmin)
