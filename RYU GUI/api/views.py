"""DRF API for the Ryu SDN dashboard."""
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated

from dashboard.models import Event, Switch, Host, Threat, ControllerStatus
from dashboard.ryu_client import RyuClient
from .serializers import (EventSerializer, SwitchSerializer, HostSerializer,
                          ThreatSerializer, ControllerStatusSerializer)


class EventViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Event.objects.all()
    serializer_class = EventSerializer


class SwitchViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Switch.objects.all()
    serializer_class = SwitchSerializer


class HostViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Host.objects.all()
    serializer_class = HostSerializer


class ThreatViewSet(viewsets.ModelViewSet):
    queryset = Threat.objects.all()
    serializer_class = ThreatSerializer
    permission_classes = [IsAuthenticated]

    @action(detail=True, methods=["post"])
    def mitigate(self, request, pk=None):
        threat = self.get_object()
        client = RyuClient()
        try:
            client.post_mitigation(threat.src_ip, action="drop")
            threat.status = Threat.Status.MITIGATED
            threat.save()
            Event.objects.create(
                event_type=Event.EventType.MITIGATION_APPLIED,
                source=threat.src_ip,
                description=f"Mitigation applied for {threat.threat_type}",
                severity=Event.Severity.WARNING,
            )
            return Response({"status": "mitigated"})
        except Exception as exc:
            return Response({"error": str(exc)}, status=status.HTTP_502_BAD_GATEWAY)


class ControllerStatusView(APIView):
    def get(self, request):
        client = RyuClient()
        try:
            switches = client.get_switches()
            online = True
        except Exception:
            switches = []
            online = False
        s = ControllerStatus.current()
        s.is_online = online
        s.save()
        return Response({
            "is_online": online,
            "n_switches": len(switches),
            "version": s.version or "Ryu 4.34",
        })


class LiveSnapshotView(APIView):
    """Returns a single JSON snapshot of all dashboard KPIs."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        client = RyuClient()
        try:
            switches = client.get_switches()
        except Exception:
            switches = []
        try:
            hosts = client.get_hosts()
        except Exception:
            hosts = []
        try:
            links = client.get_links()
        except Exception:
            links = []
        try:
            n_flows = client.get_total_flow_count()
        except Exception:
            n_flows = 0
        try:
            pps = client.get_packet_rate()
        except Exception:
            pps = 0
        return Response({
            "n_switches": len(switches),
            "n_hosts": len(hosts),
            "n_links": len(links),
            "n_flows": n_flows,
            "pps": pps,
            "topology": client.get_topology_graph() if switches else None,
        })
