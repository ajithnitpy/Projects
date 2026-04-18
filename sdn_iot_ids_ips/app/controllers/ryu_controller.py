"""
Ryu SDN Controller REST API client.

Communicates with the Ryu controller's built-in REST API
(ryu.app.ofctl_rest) to read topology state and install/delete
OpenFlow flow rules dynamically — the core IPS enforcement plane.

Ryu REST endpoints used
------------------------
GET  /stats/switches              → list all datapath IDs
GET  /stats/flow/<dpid>           → flow table of a switch
GET  /stats/port/<dpid>           → port counters
POST /stats/flowentry/add         → install a flow rule
DELETE /stats/flowentry/delete    → delete a flow rule
POST /stats/flowentry/delete_all  → flush all flows on a switch
GET  /topology/links              → link-state topology (ryu.app.gui_topology.gui_topology)
"""

import time
import logging
from typing import Any, Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

# Default Ryu REST API base
DEFAULT_RYU_URL = "http://127.0.0.1:8080"

# OpenFlow 1.3 priority levels
PRIORITY_NORMAL = 100
PRIORITY_IDS_MIRROR = 200
PRIORITY_BLOCK = 65535

# OpenFlow 1.3 output actions
OFPP_CONTROLLER = 0xFFFFFFFD
OFPP_FLOOD = 0xFFFFFFFB


def _build_session(retries: int = 3, backoff: float = 0.5) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=[500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


class RyuControllerClient:
    """
    Thin REST wrapper around the Ryu ofctl_rest application.

    All methods return the parsed JSON response or raise on HTTP error.
    """

    def __init__(self, base_url: str = DEFAULT_RYU_URL, timeout: int = 5):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._session = _build_session()

    # ------------------------------------------------------------------
    # Low-level helpers
    # ------------------------------------------------------------------

    def _get(self, path: str) -> Any:
        url = f"{self.base_url}{path}"
        resp = self._session.get(url, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, payload: dict) -> Any:
        url = f"{self.base_url}{path}"
        resp = self._session.post(url, json=payload, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json() if resp.text.strip() else {}

    def _delete(self, path: str, payload: dict) -> Any:
        url = f"{self.base_url}{path}"
        resp = self._session.delete(url, json=payload, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json() if resp.text.strip() else {}

    # ------------------------------------------------------------------
    # Topology discovery
    # ------------------------------------------------------------------

    def get_switches(self) -> list[int]:
        """Return list of datapath IDs (integers)."""
        return self._get("/stats/switches")

    def get_links(self) -> list[dict]:
        """Return link-state topology from ryu.app.gui_topology."""
        return self._get("/v1.0/topology/links")

    def get_hosts(self) -> list[dict]:
        return self._get("/v1.0/topology/hosts")

    # ------------------------------------------------------------------
    # Flow table inspection
    # ------------------------------------------------------------------

    def get_flows(self, dpid: int) -> list[dict]:
        return self._get(f"/stats/flow/{dpid}")

    def get_port_stats(self, dpid: int) -> list[dict]:
        return self._get(f"/stats/port/{dpid}")

    def get_port_desc(self, dpid: int) -> list[dict]:
        return self._get(f"/stats/portdesc/{dpid}")

    # ------------------------------------------------------------------
    # Flow rule management (IPS enforcement)
    # ------------------------------------------------------------------

    def add_flow(
        self,
        dpid: int,
        priority: int,
        match: dict,
        actions: list,
        idle_timeout: int = 0,
        hard_timeout: int = 0,
        table_id: int = 0,
        cookie: int = 0,
    ) -> dict:
        """
        Install an OpenFlow 1.3 flow rule.

        Example — mirror suspicious traffic to controller:
        >>> client.add_flow(
        ...     dpid=1,
        ...     priority=PRIORITY_IDS_MIRROR,
        ...     match={"ip_proto": 6, "ipv4_src": "192.168.1.100"},
        ...     actions=[{"type": "OUTPUT", "port": OFPP_CONTROLLER}],
        ...     idle_timeout=60,
        ... )
        """
        payload = {
            "dpid": dpid,
            "cookie": cookie,
            "cookie_mask": 0,
            "table_id": table_id,
            "idle_timeout": idle_timeout,
            "hard_timeout": hard_timeout,
            "priority": priority,
            "flags": 1,   # OFPFF_SEND_FLOW_REM
            "match": match,
            "actions": actions,
        }
        logger.info("Installing flow dpid=%d priority=%d match=%s", dpid, priority, match)
        return self._post("/stats/flowentry/add", payload)

    def delete_flow(
        self,
        dpid: int,
        match: dict,
        priority: int = PRIORITY_BLOCK,
        table_id: int = 0,
    ) -> dict:
        payload = {
            "dpid": dpid,
            "table_id": table_id,
            "priority": priority,
            "match": match,
            "actions": [],
        }
        logger.info("Deleting flow dpid=%d match=%s", dpid, match)
        return self._post("/stats/flowentry/delete", payload)

    def flush_flows(self, dpid: int) -> dict:
        logger.warning("Flushing ALL flows on dpid=%d", dpid)
        return self._delete("/stats/flowentry/delete_all", {"dpid": dpid})

    # ------------------------------------------------------------------
    # IPS-specific convenience methods
    # ------------------------------------------------------------------

    def block_ip(
        self,
        dpid: int,
        src_ip: str,
        hard_timeout: int = 300,
        direction: str = "both",
    ) -> list[dict]:
        """
        Drop all packets from (or to) src_ip on the given switch.

        direction: "src", "dst", or "both"
        """
        results = []
        if direction in ("src", "both"):
            results.append(self.add_flow(
                dpid=dpid,
                priority=PRIORITY_BLOCK,
                match={"eth_type": 0x0800, "ipv4_src": src_ip},
                actions=[],  # empty = DROP
                hard_timeout=hard_timeout,
                cookie=0xDEAD0001,
            ))
        if direction in ("dst", "both"):
            results.append(self.add_flow(
                dpid=dpid,
                priority=PRIORITY_BLOCK,
                match={"eth_type": 0x0800, "ipv4_dst": src_ip},
                actions=[],
                hard_timeout=hard_timeout,
                cookie=0xDEAD0002,
            ))
        logger.warning("BLOCK applied: dpid=%d src=%s hard_timeout=%ds", dpid, src_ip, hard_timeout)
        return results

    def rate_limit_ip(
        self,
        dpid: int,
        src_ip: str,
        meter_id: int = 1,
        rate_kbps: int = 512,
    ) -> dict:
        """
        Apply a meter-based rate limit to an IP (OpenFlow 1.3 meters).
        """
        meter_payload = {
            "dpid": dpid,
            "meter_id": meter_id,
            "flags": ["KBPS"],
            "bands": [{"type": "DROP", "rate": rate_kbps, "burst_size": 64}],
        }
        self._post("/stats/meterentry/add", meter_payload)

        return self.add_flow(
            dpid=dpid,
            priority=PRIORITY_BLOCK - 1,
            match={"eth_type": 0x0800, "ipv4_src": src_ip},
            actions=[{"type": "METER", "meter_id": meter_id},
                     {"type": "OUTPUT", "port": OFPP_FLOOD}],
            idle_timeout=120,
        )

    def mirror_to_ids(
        self,
        dpid: int,
        match: dict,
        mirror_port: int,
    ) -> dict:
        """
        Clone matching packets to mirror_port (e.g. a Snort/Suricata tap).
        Normal forwarding continues via FLOOD; mirror is an additional action.
        """
        return self.add_flow(
            dpid=dpid,
            priority=PRIORITY_IDS_MIRROR,
            match=match,
            actions=[
                {"type": "OUTPUT", "port": mirror_port},
                {"type": "OUTPUT", "port": OFPP_FLOOD},
            ],
            idle_timeout=0,
        )

    def redirect_to_honeypot(
        self,
        dpid: int,
        src_ip: str,
        honeypot_port: int,
        hard_timeout: int = 600,
    ) -> dict:
        """Redirect all traffic from src_ip to a honeypot port."""
        return self.add_flow(
            dpid=dpid,
            priority=PRIORITY_BLOCK,
            match={"eth_type": 0x0800, "ipv4_src": src_ip},
            actions=[{"type": "OUTPUT", "port": honeypot_port}],
            hard_timeout=hard_timeout,
            cookie=0xBEEF0001,
        )

    # ------------------------------------------------------------------
    # Topology-aware helpers
    # ------------------------------------------------------------------

    def get_topology_snapshot(self) -> dict:
        """Return a full topology snapshot suitable for the dashboard."""
        try:
            switches = self.get_switches()
        except Exception as exc:
            logger.error("Cannot reach Ryu controller: %s", exc)
            return {"switches": [], "links": [], "hosts": [], "flows": {}}

        flows = {}
        for dpid in switches:
            try:
                flows[dpid] = self.get_flows(dpid)
            except Exception:
                flows[dpid] = []

        try:
            links = self.get_links()
        except Exception:
            links = []

        try:
            hosts = self.get_hosts()
        except Exception:
            hosts = []

        return {
            "switches": switches,
            "links": links,
            "hosts": hosts,
            "flows": flows,
            "timestamp": time.time(),
        }
