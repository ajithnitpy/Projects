"""
Suricata IDS integration for the SDN/IoT AI-IDS/IPS pipeline.

Suricata writes structured JSON events to /var/log/suricata/eve.json
(EVE JSON format).  This module:
  1. Tails eve.json in a background thread.
  2. Parses alert events into SuricataAlert objects.
  3. Dispatches alerts to registered callbacks (AI ensemble, IPS engine).
  4. Supports Suricata rule generation for AI-detected threats.

EVE JSON alert event (simplified):
{
  "timestamp": "2024-01-01T00:00:01.123456+0000",
  "event_type": "alert",
  "src_ip": "192.168.1.100",
  "src_port": 12345,
  "dest_ip": "10.0.0.1",
  "dest_port": 80,
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 2013504,
    "rev": 5,
    "signature": "ET SCAN Nmap Scripting Engine",
    "category": "Web Application Attack",
    "severity": 1
  },
  "flow": {"pkts_toserver": 10, "pkts_toclient": 0, "bytes_toserver": 500, "bytes_toclient": 0}
}
"""

import json
import time
import threading
import logging
from pathlib import Path
from typing import Optional, Callable

logger = logging.getLogger(__name__)

# Suricata severity → attack class
SEVERITY_CLASS_MAP = {
    1: 1,   # High   → DoS
    2: 2,   # Medium → Probe
    3: 3,   # Low    → R2L
}

# Known Suricata SID ranges → attack class
SID_RANGES = [
    (2000000, 2099999, 2),   # ET Scan
    (2100000, 2199999, 1),   # ET DoS
    (2200000, 2299999, 3),   # ET Policy
    (2400000, 2499999, 4),   # ET Exploit
]

SURICATA_RULE_TEMPLATE = (
    'alert {proto} {src} any -> any any '
    '(msg:"AI-IDS {msg}"; sid:{sid}; rev:1; '
    'classtype:trojan-activity; metadata: created_at {ts};)\n'
)


def _sid_to_class(sid: int) -> int:
    for lo, hi, cls in SID_RANGES:
        if lo <= sid <= hi:
            return cls
    return 1  # default DoS


class SuricataAlert:
    __slots__ = (
        "timestamp", "src_ip", "src_port", "dst_ip", "dst_port",
        "proto", "action", "gid", "sid", "rev", "signature",
        "category", "severity", "attack_class",
        "pkts_toserver", "pkts_toclient",
        "bytes_toserver", "bytes_toclient",
    )

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)

    def to_dict(self) -> dict:
        return {s: getattr(self, s, None) for s in self.__slots__}

    @classmethod
    def from_eve(cls, record: dict) -> Optional["SuricataAlert"]:
        if record.get("event_type") != "alert":
            return None
        alert_data = record.get("alert", {})
        flow = record.get("flow", {})
        sid = int(alert_data.get("signature_id", 0))
        severity = int(alert_data.get("severity", 3))
        attack_class = SEVERITY_CLASS_MAP.get(severity, _sid_to_class(sid))

        return cls(
            timestamp=record.get("timestamp", ""),
            src_ip=record.get("src_ip", ""),
            src_port=int(record.get("src_port", 0)),
            dst_ip=record.get("dest_ip", ""),
            dst_port=int(record.get("dest_port", 0)),
            proto=record.get("proto", "").upper(),
            action=alert_data.get("action", "allowed"),
            gid=int(alert_data.get("gid", 1)),
            sid=sid,
            rev=int(alert_data.get("rev", 1)),
            signature=alert_data.get("signature", ""),
            category=alert_data.get("category", ""),
            severity=severity,
            attack_class=attack_class,
            pkts_toserver=int(flow.get("pkts_toserver", 0)),
            pkts_toclient=int(flow.get("pkts_toclient", 0)),
            bytes_toserver=int(flow.get("bytes_toserver", 0)),
            bytes_toclient=int(flow.get("bytes_toclient", 0)),
        )


class SuricataIDS:
    """
    Suricata EVE JSON consumer.

    Usage
    -----
    >>> suri = SuricataIDS()
    >>> suri.register_callback(my_handler)
    >>> suri.start()
    ...
    >>> suri.stop()
    """

    def __init__(
        self,
        eve_log: str = "/var/log/suricata/eve.json",
        rules_dir: str = "/etc/suricata/rules",
        ai_rules_file: str = "ai-ids.rules",
        poll_interval: float = 0.5,
    ):
        self.eve_log = Path(eve_log)
        self.rules_dir = Path(rules_dir)
        self.ai_rules_file = ai_rules_file
        self.poll_interval = poll_interval

        self._callbacks: list[Callable[[SuricataAlert], None]] = []
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._alerts: list[SuricataAlert] = []
        self._lock = threading.Lock()
        self._file_pos: int = 0
        self._sid_counter: int = 9100000  # starting SID for AI-generated rules

    # ------------------------------------------------------------------
    # Callback registration
    # ------------------------------------------------------------------

    def register_callback(self, fn: Callable[[SuricataAlert], None]) -> None:
        self._callbacks.append(fn)

    def _dispatch(self, alert: SuricataAlert) -> None:
        with self._lock:
            self._alerts.append(alert)
        for fn in self._callbacks:
            try:
                fn(alert)
            except Exception as exc:
                logger.error("Suricata callback error: %s", exc)

    # ------------------------------------------------------------------
    # Background EVE tailer
    # ------------------------------------------------------------------

    def _tail_loop(self) -> None:
        logger.info("Suricata EVE tailer started: %s", self.eve_log)
        while not self._stop_event.is_set():
            if not self.eve_log.exists():
                time.sleep(self.poll_interval)
                continue

            with open(self.eve_log, "r", errors="replace") as fh:
                fh.seek(self._file_pos)
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    alert = SuricataAlert.from_eve(record)
                    if alert:
                        self._dispatch(alert)
                self._file_pos = fh.tell()

            time.sleep(self.poll_interval)

    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._tail_loop, daemon=True, name="suricata-tailer")
        self._thread.start()
        logger.info("SuricataIDS background thread started")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)
        logger.info("SuricataIDS stopped")

    # ------------------------------------------------------------------
    # Dynamic rule generation
    # ------------------------------------------------------------------

    def write_ai_rule(
        self,
        src_ip: str,
        proto: str = "ip",
        msg: str = "AI-IDS detected threat",
        sid: Optional[int] = None,
    ) -> Path:
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        if sid is None:
            sid = self._sid_counter
            self._sid_counter += 1

        rules_path = self.rules_dir / self.ai_rules_file
        ts = time.strftime("%Y_%m_%d")
        rule = SURICATA_RULE_TEMPLATE.format(
            proto=proto, src=src_ip, msg=msg, sid=sid, ts=ts
        )
        with open(rules_path, "a") as f:
            f.write(rule)
        logger.info("Suricata rule written: %s", rule.strip())
        return rules_path

    # ------------------------------------------------------------------
    # Flow feature extraction from EVE stats
    # ------------------------------------------------------------------

    @staticmethod
    def extract_flow_features(alert: SuricataAlert) -> dict:
        """
        Extract minimal numeric features from a Suricata alert that can
        be fed directly into the AI ensemble for secondary classification.
        """
        return {
            "src_port": alert.src_port,
            "dst_port": alert.dst_port,
            "proto_tcp": int(alert.proto == "TCP"),
            "proto_udp": int(alert.proto == "UDP"),
            "proto_icmp": int(alert.proto == "ICMP"),
            "pkts_toserver": alert.pkts_toserver,
            "pkts_toclient": alert.pkts_toclient,
            "bytes_toserver": alert.bytes_toserver,
            "bytes_toclient": alert.bytes_toclient,
            "severity": alert.severity,
            "sid": alert.sid,
        }

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def get_recent_alerts(self, limit: int = 50) -> list[dict]:
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:]]

    def get_alert_count(self) -> int:
        with self._lock:
            return len(self._alerts)

    def get_alert_stats(self) -> dict:
        with self._lock:
            alerts = list(self._alerts)
        class_counts: dict[int, int] = {}
        proto_counts: dict[str, int] = {}
        for a in alerts:
            class_counts[a.attack_class] = class_counts.get(a.attack_class, 0) + 1
            proto_counts[a.proto] = proto_counts.get(a.proto, 0) + 1
        return {
            "total": len(alerts),
            "by_class": class_counts,
            "by_proto": proto_counts,
        }
