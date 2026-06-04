from django.contrib import admin
from .models import Event, Switch, Host, Threat, ControllerStatus


@admin.register(Event)
class EventAdmin(admin.ModelAdmin):
    list_display = ("timestamp", "event_type", "source", "severity")
    list_filter = ("event_type", "severity")
    search_fields = ("source", "description")


@admin.register(Switch)
class SwitchAdmin(admin.ModelAdmin):
    list_display = ("dpid", "name", "is_active", "n_ports", "n_flows", "last_seen")
    list_filter = ("is_active",)


@admin.register(Host)
class HostAdmin(admin.ModelAdmin):
    list_display = ("mac", "ip_address", "switch", "is_iot", "last_seen")
    list_filter = ("is_iot",)


@admin.register(Threat)
class ThreatAdmin(admin.ModelAdmin):
    list_display = ("timestamp", "threat_type", "src_ip", "confidence", "status")
    list_filter = ("threat_type", "status")


admin.site.register(ControllerStatus)
