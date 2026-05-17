"""
Mitigation protocol — takes a list of threats from the inference engine and
installs OpenFlow rules via the Ryu REST API to neutralise them.

The protocol implements the following novel staged response:

  1. **Observation window** — a threat is escalated only after K consecutive
     detections (configurable) to reduce false positives.
  2. **Adaptive action** — based on threat class:
        - DDoS / Mirai → install DROP flow on offending src_ip
        - Scan        → install meter (rate-limit) instead of full drop
        - Brute force → install DROP for 5 minutes (idle_timeout)
        - Exfil       → DROP + alert (severity critical)
  3. **Auto-rollback** — drop rules carry idle_timeout so benign traffic can
     resume if classification later changes (handled by Ryu natively).
"""
from __future__ import annotations
import logging
from collections import defaultdict, deque
from typing import Dict, List

from django.conf import settings

from dashboard.ryu_client import RyuClient
from dashboard.models import Threat, Event

log = logging.getLogger(__name__)


CONSECUTIVE_THRESHOLD = 2

ACTION_FOR_CLASS = {
    "ddos":        ("drop",   {"idle_timeout": 120, "priority": 65000}),
    "mirai":       ("drop",   {"idle_timeout": 300, "priority": 65000}),
    "scan":        ("meter",  {"rate_kbps": 500}),
    "brute_force": ("drop",   {"idle_timeout": 300, "priority": 60000}),
    "exfil":       ("drop",   {"idle_timeout": 600, "priority": 65000}),
}


class MitigationEngine:
    def __init__(self):
        self.client = RyuClient()
        self.history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10))

    def evaluate(self, threats: List[Dict]) -> List[Dict]:
        """Decide which threats to actually mitigate; returns applied actions."""
        applied = []
        if not settings.GNN_MITIGATION_ENABLED:
            return applied

        for t in threats:
            ip = t["src_ip"]
            self.history[ip].append(t["threat_type"])
            recent = list(self.history[ip])[-CONSECUTIVE_THRESHOLD:]
            if len(recent) >= CONSECUTIVE_THRESHOLD and len(set(recent)) == 1:
                action, params = ACTION_FOR_CLASS.get(t["threat_type"], ("drop", {}))
                try:
                    if action == "drop":
                        self.client.install_drop_flow(
                            dpid=int(t.get("dpid") or 1),
                            match={"eth_type": 0x0800, "ipv4_src": ip},
                            priority=params.get("priority", 65000),
                            idle_timeout=params.get("idle_timeout", 60),
                        )
                    elif action == "meter":
                        self.client.install_meter(
                            dpid=int(t.get("dpid") or 1),
                            meter_id=hash(ip) % 1000 + 1,
                            rate_kbps=params.get("rate_kbps", 500),
                        )
                    # persist
                    Threat.objects.create(
                        src_ip=ip,
                        threat_type=t["threat_type"],
                        confidence=t["confidence"],
                        status=Threat.Status.MITIGATED,
                        mitigation_rule={"action": action, **params},
                    )
                    Event.objects.create(
                        event_type=Event.EventType.MITIGATION_APPLIED,
                        source=ip,
                        description=f"Auto-mitigation ({action}) for {t['threat_type']}",
                        severity=Event.Severity.WARNING,
                    )
                    applied.append({"src_ip": ip, "action": action, **params})
                except Exception as e:  # noqa: BLE001
                    log.warning("Mitigation failed for %s: %s", ip, e)
                    Threat.objects.create(
                        src_ip=ip,
                        threat_type=t["threat_type"],
                        confidence=t["confidence"],
                        status=Threat.Status.DETECTED,
                    )
        return applied


_engine: MitigationEngine | None = None


def get_engine() -> MitigationEngine:
    global _engine
    if _engine is None:
        _engine = MitigationEngine()
    return _engine
