"""
Django Channels consumers — push live updates to the dashboard UI.

DashboardConsumer:
  • Polls Ryu every 2s, sends {switches, hosts, links, flows, pps} updates.
  • Broadcasts events from group 'dashboard.events' (pushed by Ryu app via REST).

ThreatConsumer:
  • Pushes GNN-detected threats to the Threats page in real time.
"""
import asyncio
import json
import logging
from channels.generic.websocket import AsyncJsonWebsocketConsumer
from asgiref.sync import sync_to_async

from .ryu_client import RyuClient

log = logging.getLogger(__name__)


class DashboardConsumer(AsyncJsonWebsocketConsumer):
    group_name = "dashboard.events"

    async def connect(self):
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()
        self._poll_task = asyncio.create_task(self._poll_loop())

    async def disconnect(self, close_code):
        if hasattr(self, "_poll_task"):
            self._poll_task.cancel()
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def _poll_loop(self):
        client = RyuClient()
        while True:
            try:
                payload = await sync_to_async(self._snapshot, thread_sensitive=False)(client)
                await self.send_json({"type": "snapshot", **payload})
            except Exception as e:  # noqa: BLE001
                log.debug("Ryu poll failed: %s", e)
                await self.send_json({"type": "snapshot.error", "detail": str(e)})
            await asyncio.sleep(2)

    @staticmethod
    def _snapshot(client: RyuClient):
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
        return {
            "n_switches": len(switches), "n_hosts": len(hosts),
            "n_links": len(links), "n_flows": n_flows, "pps": pps,
        }

    # group handler
    async def dashboard_event(self, event):
        await self.send_json(event["payload"])


class ThreatConsumer(AsyncJsonWebsocketConsumer):
    group_name = "threats"

    async def connect(self):
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def threat_event(self, event):
        await self.send_json(event["payload"])
