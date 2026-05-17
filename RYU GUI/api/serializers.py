from rest_framework import serializers
from dashboard.models import Event, Switch, Host, Threat, ControllerStatus


class EventSerializer(serializers.ModelSerializer):
    class Meta:
        model = Event
        fields = "__all__"


class SwitchSerializer(serializers.ModelSerializer):
    class Meta:
        model = Switch
        fields = "__all__"


class HostSerializer(serializers.ModelSerializer):
    class Meta:
        model = Host
        fields = "__all__"


class ThreatSerializer(serializers.ModelSerializer):
    class Meta:
        model = Threat
        fields = "__all__"


class ControllerStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = ControllerStatus
        fields = "__all__"
