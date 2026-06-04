"""
Ryu REST API client.

Ryu (running on Ubuntu) typically exposes these northbound REST endpoints:
  • ofctl_rest             /stats/switches, /stats/flow/<dpid>, /stats/port/<dpid> ...
  • rest_topology          /v1.0/topology/switches, /links, /hosts
  • rest_router            /router/<dpid>
  • custom app  (port 8081)  /sdn/threats, /sdn/mitigate

Run on Ubuntu with, e.g.:
    ryu-manager ryu.app.ofctl_rest ryu.app.rest_topology ryu_apps/sdn_security_controller.py
"""
import logging
import time
from typing import Any, Dict, List
import requests
from django.conf import settings

log = logging.getLogger(__name__)


class RyuClient:
    """Thin synchronous client over Ryu's REST APIs.

    Methods raise requests.RequestException on connection failure; callers
    should catch and fall back to cached DB values.
    """

    def __init__(self, base_url: str | None = None, ofctl_url: str | None = None,
                 timeout: float = 3.0):
        self.base_url = (base_url or settings.RYU_REST_URL).rstrip("/")
        self.ofctl_url = (ofctl_url or settings.RYU_OFCTL_URL).rstrip("/")
        self.custom_url = settings.CUSTOM_RYU_APP_URL.rstrip("/")
        self.timeout = timeout
        self._packet_rate_state = {"last_bytes": 0, "last_ts": 0.0}

    # ---------- helpers ----------
    def _get(self, url: str) -> Any:
        log.debug("GET %s", url)
        r = requests.get(url, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def _post(self, url: str, data: Dict) -> Any:
        log.debug("POST %s %s", url, data)
        r = requests.post(url, json=data, timeout=self.timeout)
        r.raise_for_status()
        return r.json() if r.text else {}

    # ---------- ofctl_rest ----------
    def get_switches(self) -> List[int]:
        return self._get(f"{self.ofctl_url}/stats/switches")

    def get_switches_detail(self) -> List[Dict]:
        """Return [{dpid, n_flows, n_ports, ...}, ...] enriched per switch."""
        dpids = self.get_switches()
        out = []
        for dpid in dpids:
            try:
                flows = self._get(f"{self.ofctl_url}/stats/flow/{dpid}")[str(dpid)]
                ports = self._get(f"{self.ofctl_url}/stats/port/{dpid}")[str(dpid)]
                desc = self._get(f"{self.ofctl_url}/stats/desc/{dpid}")[str(dpid)]
                out.append({
                    "dpid": hex(dpid),
                    "name": desc.get("dp_desc", ""),
                    "is_active": True,
                    "n_flows": len(flows),
                    "n_ports": len(ports),
                    "last_seen": "live",
                })
            except Exception as e:  # noqa: BLE001
                log.warning("Switch %s detail failed: %s", dpid, e)
        return out

    def get_total_flow_count(self) -> int:
        total = 0
        for dpid in self.get_switches():
            flows = self._get(f"{self.ofctl_url}/stats/flow/{dpid}")[str(dpid)]
            total += len(flows)
        return total

    def get_all_flows(self) -> List[Dict]:
        out = []
        for dpid in self.get_switches():
            flows = self._get(f"{self.ofctl_url}/stats/flow/{dpid}")[str(dpid)]
            for f in flows:
                f["dpid"] = hex(dpid)
                out.append(f)
        return out

    def get_packet_rate(self) -> int:
        """Compute aggregate packets/sec across all ports."""
        total_bytes = 0
        for dpid in self.get_switches():
            ports = self._get(f"{self.ofctl_url}/stats/port/{dpid}")[str(dpid)]
            total_bytes += sum(int(p.get("rx_packets", 0)) + int(p.get("tx_packets", 0))
                               for p in ports)
        now = time.time()
        prev = self._packet_rate_state
        if prev["last_ts"] == 0:
            self._packet_rate_state = {"last_bytes": total_bytes, "last_ts": now}
            return 0
        delta_t = max(now - prev["last_ts"], 1e-3)
        rate = int(max(0, total_bytes - prev["last_bytes"]) / delta_t)
        self._packet_rate_state = {"last_bytes": total_bytes, "last_ts": now}
        return rate

    # ---------- topology REST ----------
    def get_topology_switches(self) -> List[Dict]:
        return self._get(f"{self.base_url}/v1.0/topology/switches")

    def get_links(self) -> List[Dict]:
        try:
            return self._get(f"{self.base_url}/v1.0/topology/links")
        except requests.RequestException:
            return []

    def get_hosts(self) -> List[Dict]:
        try:
            return self._get(f"{self.base_url}/v1.0/topology/hosts")
        except requests.RequestException:
            return []

    def get_topology_graph(self) -> Dict:
        """Compose a graph payload {nodes, edges} for the frontend."""
        nodes = [{"id": "ctrl", "label": "Ryu Controller", "type": "controller",
                  "x": 350, "y": 40}]
        edges = []
        switches = self.get_topology_switches()
        for i, s in enumerate(switches):
            sid = f"s{i+1}"
            nodes.append({"id": sid, "label": sid.upper(), "type": "switch",
                          "x": 100 + i * 130, "y": 140, "dpid": s["dpid"]})
            edges.append({"source": "ctrl", "target": sid, "kind": "control"})
        for li in self.get_links():
            edges.append({"source": f"s{int(li['src']['dpid'], 16) % 100}",
                          "target": f"s{int(li['dst']['dpid'], 16) % 100}"})
        for j, h in enumerate(self.get_hosts()):
            hid = f"h{j+1}"
            nodes.append({"id": hid, "label": hid.upper(), "type": "host",
                          "x": 80 + (j % 6) * 110, "y": 250})
            # connect host to its switch
            dpid_idx = (int(h.get("port", {}).get("dpid", "1"), 16) % len(switches)) \
                if switches else 0
            edges.append({"source": f"s{dpid_idx+1}", "target": hid})
        return {"nodes": nodes, "edges": edges}

    # ---------- flow modification (used by mitigation) ----------
    def install_drop_flow(self, dpid: int, match: Dict,
                          priority: int = 65000, idle_timeout: int = 60) -> Dict:
        body = {
            "dpid": dpid, "table_id": 0, "priority": priority,
            "idle_timeout": idle_timeout, "match": match, "actions": [],
        }
        return self._post(f"{self.ofctl_url}/stats/flowentry/add", body)

    def install_meter(self, dpid: int, meter_id: int, rate_kbps: int) -> Dict:
        body = {"dpid": dpid, "meter_id": meter_id, "flags": "KBPS",
                "bands": [{"type": "DROP", "rate": rate_kbps}]}
        return self._post(f"{self.ofctl_url}/stats/meterentry/add", body)

    # ---------- custom controller app ----------
    def get_custom_threats(self) -> List[Dict]:
        try:
            return self._get(f"{self.custom_url}/sdn/threats")
        except requests.RequestException:
            return []

    def post_mitigation(self, src_ip: str, action: str = "drop",
                        dpid: int | None = None) -> Dict:
        return self._post(f"{self.custom_url}/sdn/mitigate",
                          {"src_ip": src_ip, "action": action, "dpid": dpid})
