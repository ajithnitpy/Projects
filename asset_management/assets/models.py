from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import date


class Category(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name_plural = 'Categories'
        ordering = ['name']


class Location(models.Model):
    name = models.CharField(max_length=100)
    building = models.CharField(max_length=100, blank=True)
    floor = models.CharField(max_length=50, blank=True)
    room = models.CharField(max_length=50, blank=True)
    address = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        parts = [self.name]
        if self.building:
            parts.append(self.building)
        if self.floor:
            parts.append(f"Floor {self.floor}")
        if self.room:
            parts.append(f"Room {self.room}")
        return ' - '.join(parts)

    class Meta:
        ordering = ['name']


class Department(models.Model):
    name = models.CharField(max_length=100, unique=True)
    head = models.CharField(max_length=100, blank=True)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

    class Meta:
        ordering = ['name']


class Asset(models.Model):
    CONDITION_CHOICES = [
        ('working', 'Working'),
        ('write_off', 'Write Off'),
        ('condemned', 'Condemned'),
        ('obsolete', 'Obsolete'),
        ('disposed', 'Disposed'),
    ]

    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('under_repair', 'Under Repair'),
        ('in_store', 'In Store'),
        ('transferred', 'Transferred'),
    ]

    inventory_id = models.AutoField(primary_key=True)
    inventory_number = models.CharField(max_length=50, unique=True)
    inventory_name = models.CharField(max_length=200)
    category = models.ForeignKey(Category, on_delete=models.SET_NULL, null=True, blank=True, related_name='assets')
    make = models.CharField(max_length=100, blank=True)
    model = models.CharField(max_length=100, blank=True)
    serial_number = models.CharField(max_length=100, blank=True)
    date_of_purchase = models.DateField(null=True, blank=True)
    year_of_purchase = models.PositiveIntegerField(null=True, blank=True)
    purchase_price = models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True)
    vendor = models.CharField(max_length=200, blank=True)
    location = models.ForeignKey(Location, on_delete=models.SET_NULL, null=True, blank=True, related_name='assets')
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True, blank=True, related_name='assets')
    assigned_to = models.CharField(max_length=200, blank=True)
    working_status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    condition = models.CharField(max_length=20, choices=CONDITION_CHOICES, default='working')
    warranty_years = models.PositiveIntegerField(default=0)
    incidence_details = models.TextField(blank=True)
    upgradation_details = models.TextField(blank=True)
    description = models.TextField(blank=True)
    image = models.ImageField(upload_to='assets/', null=True, blank=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_assets')
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='updated_assets')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.inventory_number} - {self.inventory_name}"

    def save(self, *args, **kwargs):
        if self.date_of_purchase and not self.year_of_purchase:
            self.year_of_purchase = self.date_of_purchase.year
        super().save(*args, **kwargs)

    @property
    def warranty_expiry_date(self):
        if self.date_of_purchase and self.warranty_years:
            from dateutil.relativedelta import relativedelta
            try:
                from dateutil.relativedelta import relativedelta
                return self.date_of_purchase.replace(year=self.date_of_purchase.year + self.warranty_years)
            except ValueError:
                return None
        return None

    @property
    def warranty_status(self):
        if not self.date_of_purchase or not self.warranty_years:
            return 'No Warranty'
        expiry = self.warranty_expiry_date
        if expiry is None:
            return 'No Warranty'
        today = date.today()
        if today > expiry:
            return 'Expired'
        diff = expiry - today
        if diff.days <= 90:
            return 'Expiring Soon'
        return 'Active'

    @property
    def warranty_days_remaining(self):
        if not self.date_of_purchase or not self.warranty_years:
            return None
        expiry = self.warranty_expiry_date
        if expiry is None:
            return None
        today = date.today()
        diff = (expiry - today).days
        return diff

    class Meta:
        ordering = ['-created_at']


class AssetIncident(models.Model):
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='incidents')
    title = models.CharField(max_length=200)
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='medium')
    reported_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    reported_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolution_notes = models.TextField(blank=True)

    def __str__(self):
        return f"{self.asset.inventory_number} - {self.title}"

    class Meta:
        ordering = ['-reported_at']


class AssetUpgrade(models.Model):
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='upgrades')
    title = models.CharField(max_length=200)
    description = models.TextField()
    upgrade_date = models.DateField()
    cost = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    performed_by = models.CharField(max_length=200, blank=True)
    recorded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.asset.inventory_number} - {self.title}"

    class Meta:
        ordering = ['-upgrade_date']


class ActivityLog(models.Model):
    ACTION_CHOICES = [
        ('create', 'Created'),
        ('update', 'Updated'),
        ('delete', 'Deleted'),
        ('import', 'Imported'),
        ('export', 'Exported'),
        ('login', 'Login'),
        ('logout', 'Logout'),
        ('view', 'Viewed'),
    ]
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    model_name = models.CharField(max_length=100)
    object_id = models.CharField(max_length=50, blank=True)
    object_repr = models.CharField(max_length=200, blank=True)
    changes = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user} - {self.action} - {self.model_name} - {self.timestamp}"

    class Meta:
        ordering = ['-timestamp']
