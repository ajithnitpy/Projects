"""
Snort IDS integration for the SDN/IoT AI-IDS/IPS pipeline.

Responsibilities
----------------
1. Tail /var/log/snort/alert (or a configurable path) for new alerts.
2. Parse unified2 binary logs (preferred) or fast-alert text format.
3. Forward parsed alerts to the AI ensemble for secondary classification.
4. Optionally write Snort rules dynamically when the AI detects a new pattern.

Snort alert text format (fast-alert):
  MM/DD-HH:MM:SS.ffffff  [**] [GID:SID:REV] MSG [**] [Classification: X]
  [Priority: N] {PROTO} SRC:PORT -> DST:PORT
"""

import re
import time
import threading
import logging
from pathlib import Path
from typing import Optional, Callable

logger = logging.getLogger(__name__)

# Regex for Snort fast-alert format
_FAST_ALERT_RE = re.compile(
    r"(?P<timestamp>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"
    r"(?P<msg>.+?)\s+\[\*\*\].*?"
    r"\{(?P<proto>\w+)\}\s+"
    r"(?P<src>[\d.]+):(?P<sport>\d+)\s+->\s+"
    r"(?P<dst>[\d.]+):(?P<dport>\d+)",
    re.DOTALL,
)

# Known Snort SID → attack class (0=Normal,1=DoS,2=Probe,3=R2L,4=U2R)
SID_CLASS_MAP: dict[int, int] = {
    1000001: 1,   # ICMP flood
    1000002: 1,   # SYN flood
    1000003: 2,   # port scan (nmap)
    1000004: 3,   # FTP brute force
    1000005: 4,   # privilege escalation
    1100001: 1,   # HTTP DoS
    2000001: 2,   # DNS sweep
}

SNORT_RULES_TEMPLATE = (
    'alert {proto} {src} any -> any any '
    '(msg:"AI-IDS: {msg}"; sid:{sid}; rev:1; '
    'classtype:attempted-dos;)\n'
)


class SnortAlert:
    __slots__ = ("timestamp", "gid", "sid", "rev", "msg", "proto",
                 "src_ip", "src_port", "dst_ip", "dst_port", "attack_class")

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)

    def to_dict(self) -> dict:
        return {s: getattr(self, s, None) for s in self.__slots__}


class SnortIDS:
    """
    Snort alert consumer and rule generator.

    Usage
    -----
    >>> snort = SnortIDS(alert_log="/var/log/snort/alert")
    >>> snort.register_callback(my_handler)   # called per alert
    >>> snort.start()                         # background thread
    ...
    >>> snort.stop()
    """

    def __init__(
        self,
        alert_log: str = "/var/log/snort/alert",
        rules_dir: str = "/etc/snort/rules",
        ai_rules_file: str = "ai_ids.rules",
        poll_interval: float = 0.5,
    ):
        self.alert_log = Path(alert_log)
        self.rules_dir = Path(rules_dir)
        self.ai_rules_file = ai_rules_file
        self.poll_interval = poll_interval

        self._callbacks: list[Callable[[SnortAlert], None]] = []
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._alerts: list[SnortAlert] = []
        self._lock = threading.Lock()
        self._file_pos: int = 0

    # ------------------------------------------------------------------
    # Callback registration
    # ------------------------------------------------------------------

    def register_callback(self, fn: Callable[[SnortAlert], None]) -> None:
        self._callbacks.append(fn)

    def _dispatch(self, alert: SnortAlert) -> None:
        with self._lock:
            self._alerts.append(alert)
        for fn in self._callbacks:
            try:
                fn(alert)
            except Exception as exc:
                logger.error("Snort callback error: %s", exc)

    # ------------------------------------------------------------------
    # Alert parsing
    # ------------------------------------------------------------------

    @staticmethod
    def parse_fast_alert(line: str) -> Optional[SnortAlert]:
        m = _FAST_ALERT_RE.search(line)
        if not m:
            return None
        d = m.groupdict()
        sid = int(d["sid"])
        return SnortAlert(
            timestamp=d["timestamp"],
            gid=int(d["gid"]),
            sid=sid,
            rev=int(d["rev"]),
            msg=d["msg"].strip(),
            proto=d["proto"],
            src_ip=d["src"],
            src_port=int(d["sport"]),
            dst_ip=d["dst"],
            dst_port=int(d["dport"]),
            attack_class=SID_CLASS_MAP.get(sid, 1),  # default DoS
        )

    # ------------------------------------------------------------------
    # Background tailer
    # ------------------------------------------------------------------

    def _tail_loop(self) -> None:
        logger.info("Snort tailer started: %s", self.alert_log)
        while not self._stop_event.is_set():
            if not self.alert_log.exists():
                time.sleep(self.poll_interval)
                continue

            with open(self.alert_log, "r", errors="replace") as fh:
                fh.seek(self._file_pos)
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    alert = self.parse_fast_alert(line)
                    if alert:
                        self._dispatch(alert)
                self._file_pos = fh.tell()

            time.sleep(self.poll_interval)

    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._tail_loop, daemon=True, name="snort-tailer")
        self._thread.start()
        logger.info("SnortIDS background thread started")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)
        logger.info("SnortIDS stopped")

    # ------------------------------------------------------------------
    # Dynamic rule generation
    # ------------------------------------------------------------------

    def write_ai_rule(
        self,
        src_ip: str,
        proto: str = "ip",
        msg: str = "AI-IDS detected threat",
        sid: int = 9000001,
    ) -> Path:
        """
        Append a Snort rule for the AI-detected threat IP.
        Returns the path of the rules file written.
        """
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        rules_path = self.rules_dir / self.ai_rules_file
        rule = SNORT_RULES_TEMPLATE.format(
            proto=proto, src=src_ip, msg=msg, sid=sid
        )
        with open(rules_path, "a") as f:
            f.write(rule)
        logger.info("Snort rule written: %s", rule.strip())
        return rules_path

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
        for a in alerts:
            class_counts[a.attack_class] = class_counts.get(a.attack_class, 0) + 1
        return {
            "total": len(alerts),
            "by_class": class_counts,
        }
