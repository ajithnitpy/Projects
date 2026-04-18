from django.db import models
from django.contrib.auth.models import User


class Role(models.Model):
    ROLE_CHOICES = [
        ('admin', 'Administrator'),
        ('manager', 'Asset Manager'),
        ('editor', 'Editor'),
        ('viewer', 'Viewer'),
    ]
    name = models.CharField(max_length=50, unique=True)
    role_type = models.CharField(max_length=20, choices=ROLE_CHOICES, default='viewer')
    can_add_asset = models.BooleanField(default=False)
    can_edit_asset = models.BooleanField(default=False)
    can_delete_asset = models.BooleanField(default=False)
    can_view_asset = models.BooleanField(default=True)
    can_import_export = models.BooleanField(default=False)
    can_manage_users = models.BooleanField(default=False)
    can_manage_roles = models.BooleanField(default=False)
    can_view_logs = models.BooleanField(default=False)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

    class Meta:
        ordering = ['name']


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True, blank=True)
    employee_id = models.CharField(max_length=50, blank=True)
    # FK to Department — controls which department's assets this user sees
    department = models.ForeignKey(
        'assets.Department',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='user_profiles',
    )
    phone = models.CharField(max_length=20, blank=True)
    avatar = models.ImageField(upload_to='avatars/', null=True, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.get_full_name() or self.user.username}"

    def has_permission(self, perm):
        if self.user.is_superuser:
            return True
        if self.role:
            return getattr(self.role, perm, False)
        return False

    @property
    def is_department_scoped(self):
        """True when the user should only see their own department's assets."""
        if self.user.is_superuser:
            return False
        if self.role and self.role.role_type in ('admin', 'manager'):
            return False
        return self.department is not None

    class Meta:
        ordering = ['user__username']
