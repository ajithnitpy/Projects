from import_export import resources, fields
from import_export.widgets import ForeignKeyWidget
from django.contrib.auth.models import User
from .models import Role, UserProfile


class RoleResource(resources.ModelResource):
    class Meta:
        model = Role
        fields = [
            'id', 'name', 'role_type', 'can_add_asset', 'can_edit_asset',
            'can_delete_asset', 'can_view_asset', 'can_import_export',
            'can_manage_users', 'can_manage_roles', 'can_view_logs', 'description'
        ]
        export_order = ['id', 'name', 'role_type']


class UserProfileResource(resources.ModelResource):
    username = fields.Field(column_name='username', attribute='user__username')
    email = fields.Field(column_name='email', attribute='user__email')
    first_name = fields.Field(column_name='first_name', attribute='user__first_name')
    last_name = fields.Field(column_name='last_name', attribute='user__last_name')
    role = fields.Field(
        column_name='role',
        attribute='role',
        widget=ForeignKeyWidget(Role, field='name')
    )

    class Meta:
        model = UserProfile
        fields = ['username', 'email', 'first_name', 'last_name', 'role', 'employee_id', 'department', 'phone']
        export_order = ['username', 'email', 'first_name', 'last_name', 'role', 'employee_id', 'department']
