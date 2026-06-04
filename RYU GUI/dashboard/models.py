"""Persistence models for events, threats, and audit trail."""
from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()


class Event(models.Model):
    """Event log shown on the dashboard 'Recent Events' table."""

    class EventType(models.TextChoices):
        SWITCH_CONNECTED = "switch_connected", "Switch Connected"
        SWITCH_DISCONNECTED = "switch_disconnected", "Switch Disconnected"
        FLOW_INSTALLED = "flow_installed", "Flow Installed"
        FLOW_REMOVED = "flow_removed", "Flow Removed"
        HOST_DETECTED = "host_detected", "Host Detected"
        LINK_UP = "link_up", "Link Up"
        LINK_DOWN = "link_down", "Link Down"
        THREAT_DETECTED = "threat_detected", "Threat Detected"
        MITIGATION_APPLIED = "mitigation_applied", "Mitigation Applied"
        ERROR = "error", "Error"

    class Severity(models.TextChoices):
        INFO = "info", "Info"
        WARNING = "warning", "Warning"
        CRITICAL = "critical", "Critical"

    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    event_type = models.CharField(max_length=32, choices=EventType.choices)
    source = models.CharField(max_length=128, blank=True)
    description = models.TextField(blank=True)
    severity = models.CharField(
        max_length=16, choices=Severity.choices, default=Severity.INFO
    )
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-timestamp"]
        indexes = [models.Index(fields=["-timestamp"])]

    def __str__(self):
        return f"[{self.timestamp:%H:%M:%S}] {self.event_type}: {self.source}"


class Switch(models.Model):
    """Cached snapshot of switches discovered by the Ryu controller."""

    dpid = models.CharField(max_length=32, unique=True)
    name = models.CharField(max_length=64, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    n_ports = models.IntegerField(default=0)
    n_flows = models.IntegerField(default=0)
    last_seen = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Switch {self.dpid}"


class Host(models.Model):
    """Cached snapshot of hosts discovered by Ryu."""
    mac = models.CharField(max_length=32, unique=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    switch = models.ForeignKey(
        Switch, on_delete=models.SET_NULL, null=True, related_name="hosts"
    )
    port_no = models.IntegerField(null=True)
    is_iot = models.BooleanField(default=False)
    last_seen = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Host {self.mac}"


class Threat(models.Model):
    """Threats flagged by the GNN inference engine."""

    class Status(models.TextChoices):
        DETECTED = "detected", "Detected"
        MITIGATED = "mitigated", "Mitigated"
        FALSE_POSITIVE = "false_positive", "False Positive"

    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    src_ip = models.GenericIPAddressField()
    dst_ip = models.GenericIPAddressField(null=True, blank=True)
    threat_type = models.CharField(max_length=64)  # DDoS, Mirai, Scan, etc.
    confidence = models.FloatField()
    status = models.CharField(
        max_length=16, choices=Status.choices, default=Status.DETECTED
    )
    mitigation_rule = models.JSONField(default=dict, blank=True)
    features = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-timestamp"]

    def __str__(self):
        return f"{self.threat_type} from {self.src_ip} ({self.confidence:.2f})"


class ControllerStatus(models.Model):
    """Single-row table tracking controller status (last poll)."""

    is_online = models.BooleanField(default=False)
    last_checked = models.DateTimeField(auto_now=True)
    version = models.CharField(max_length=32, blank=True)
    uptime_seconds = models.BigIntegerField(default=0)

    @classmethod
    def current(cls):
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj
