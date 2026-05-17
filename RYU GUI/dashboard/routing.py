"""Channels WebSocket routing for the dashboard app."""
from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    re_path(r"ws/dashboard/$", consumers.DashboardConsumer.as_asgi()),
    re_path(r"ws/threats/$", consumers.ThreatConsumer.as_asgi()),
]
