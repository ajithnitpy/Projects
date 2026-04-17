"""
High-level SDN flow manager.

Bridges the IDS/IPS engine to the Ryu controller: translates
IDS alerts into the correct OpenFlow enforcement action and
maintains a local audit log of all mitigation actions.
"""

import time
import threading
import logging
from collections import defaultdict
from typing import Optional

from app.controllers.ryu_controller import RyuControllerClient, PRIORITY_BLOCK

logger = logging.getLogger(__name__)

# Attack-class → default IPS action
IPS_ACTION_MAP = {
    0: "allow",         # Normal
    1: "block",         # DoS
    2: "mirror",        # Probe  — gather intel first
    3: "rate_limit",    # R2L
    4: "honeypot",      # U2R
}

DEFAULT_BLOCK_TIMEOUT = 300   # seconds
DEFAULT_MIRROR_PORT = 2       # physical port connected to IDS sensor
DEFAULT_HONEYPOT_PORT = 3


class MitigationRecord:
    __slots__ = ("src_ip", "dpid", "action", "attack_class", "timestamp", "expires_at")

    def __init__(self, src_ip, dpid, action, attack_class, duration):
        self.src_ip = src_ip
        self.dpid = dpid
        self.action = action
        self.attack_class = attack_class
        self.timestamp = time.time()
        self.expires_at = self.timestamp + duration if duration else 0

    def is_active(self) -> bool:
        return self.expires_at == 0 or time.time() < self.expires_at

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "dpid": self.dpid,
            "action": self.action,
            "attack_class": self.attack_class,
            "timestamp": self.timestamp,
            "expires_at": self.expires_at,
            "active": self.is_active(),
        }


class SDNFlowManager:
    """
    Translates IDS detection results into SDN enforcement actions.

    Thread-safe; safe to call from Flask request handlers and background
    threads simultaneously.
    """

    def __init__(
        self,
        ryu_url: str = "http://127.0.0.1:8080",
        default_dpid: int = 1,
        block_timeout: int = DEFAULT_BLOCK_TIMEOUT,
        mirror_port: int = DEFAULT_MIRROR_PORT,
        honeypot_port: int = DEFAULT_HONEYPOT_PORT,
    ):
        self.ryu = RyuControllerClient(base_url=ryu_url)
        self.default_dpid = default_dpid
        self.block_timeout = block_timeout
        self.mirror_port = mirror_port
        self.honeypot_port = honeypot_port

        self._mitigation_log: list[MitigationRecord] = []
        self._lock = threading.Lock()

        # Track already-mitigated IPs to avoid redundant flow installs
        self._active_mitigations: dict[str, MitigationRecord] = {}

    # ------------------------------------------------------------------
    # Core enforcement
    # ------------------------------------------------------------------

    def enforce(
        self,
        src_ip: str,
        attack_class: int,
        dpid: Optional[int] = None,
        confidence: float = 1.0,
    ) -> dict:
        """
        Enforce an IPS action for the given attack class.

        Returns a status dict describing the action taken.
        """
        dpid = dpid or self.default_dpid
        action = IPS_ACTION_MAP.get(attack_class, "allow")

        if action == "allow":
            return {"action": "allow", "src_ip": src_ip, "dpid": dpid}

        with self._lock:
            existing = self._active_mitigations.get(src_ip)
            if existing and existing.is_active():
                logger.debug("Mitigation already active for %s (%s)", src_ip, existing.action)
                return {"action": "already_mitigated", "src_ip": src_ip, "existing": existing.action}

        result = {}
        duration = self.block_timeout

        try:
            if action == "block":
                self.ryu.block_ip(dpid, src_ip, hard_timeout=self.block_timeout)
                result = {"action": "block", "src_ip": src_ip, "dpid": dpid, "timeout": self.block_timeout}

            elif action == "mirror":
                match = {"eth_type": 0x0800, "ipv4_src": src_ip}
                self.ryu.mirror_to_ids(dpid, match, self.mirror_port)
                result = {"action": "mirror", "src_ip": src_ip, "mirror_port": self.mirror_port}
                duration = 0  # permanent until cleared

            elif action == "rate_limit":
                self.ryu.rate_limit_ip(dpid, src_ip)
                result = {"action": "rate_limit", "src_ip": src_ip, "dpid": dpid}
                duration = 120

            elif action == "honeypot":
                self.ryu.redirect_to_honeypot(dpid, src_ip, self.honeypot_port, self.block_timeout)
                result = {"action": "honeypot", "src_ip": src_ip, "honeypot_port": self.honeypot_port}

        except Exception as exc:
            logger.error("Flow enforcement failed for %s: %s", src_ip, exc)
            result = {"action": "error", "src_ip": src_ip, "error": str(exc)}
            return result

        record = MitigationRecord(src_ip, dpid, action, attack_class, duration)
        with self._lock:
            self._active_mitigations[src_ip] = record
            self._mitigation_log.append(record)

        logger.warning("IPS enforcement: %s", result)
        return result

    # ------------------------------------------------------------------
    # Revocation
    # ------------------------------------------------------------------

    def revoke(self, src_ip: str, dpid: Optional[int] = None) -> dict:
        """Remove all IPS rules for src_ip and clear mitigation state."""
        dpid = dpid or self.default_dpid
        with self._lock:
            record = self._active_mitigations.pop(src_ip, None)

        if not record:
            return {"status": "not_found", "src_ip": src_ip}

        try:
            self.ryu.delete_flow(dpid, {"eth_type": 0x0800, "ipv4_src": src_ip})
            self.ryu.delete_flow(dpid, {"eth_type": 0x0800, "ipv4_dst": src_ip})
        except Exception as exc:
            logger.error("Revoke failed for %s: %s", src_ip, exc)
            return {"status": "error", "src_ip": src_ip, "error": str(exc)}

        return {"status": "revoked", "src_ip": src_ip, "previous_action": record.action}

    # ------------------------------------------------------------------
    # Audit / status
    # ------------------------------------------------------------------

    def get_active_mitigations(self) -> list[dict]:
        with self._lock:
            active = {ip: r for ip, r in self._active_mitigations.items() if r.is_active()}
            self._active_mitigations = active
            return [r.to_dict() for r in active.values()]

    def get_mitigation_log(self, limit: int = 100) -> list[dict]:
        with self._lock:
            return [r.to_dict() for r in self._mitigation_log[-limit:]]

    def get_topology(self) -> dict:
        return self.ryu.get_topology_snapshot()

    def get_flow_stats(self, dpid: Optional[int] = None) -> list[dict]:
        dpid = dpid or self.default_dpid
        return self.ryu.get_flows(dpid)
