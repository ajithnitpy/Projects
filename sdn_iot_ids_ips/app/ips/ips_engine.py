"""
Unified IPS Engine — the central decision point for the AI-IDS/IPS pipeline.

Data flow
---------
  [Snort alert]  ──┐
  [Suricata alert]──┤→ IPSEngine.process_alert()
  [Flow packet]  ──┘         │
                             ↓
                   EnsembleIDS.predict_single()
                             │
                    ┌────────┴─────────┐
                 Normal?            Attack?
                    │                  │
                 log only        SDNFlowManager.enforce()
                                       │
                              ┌────────┴──────────┐
                           block/          Snort+Suricata
                           rate-limit/     write_ai_rule()
                           honeypot/
                           mirror
"""

import time
import threading
import logging
import queue
from typing import Optional
import numpy as np

from app.models.ensemble import EnsembleIDS
from app.controllers.flow_manager import SDNFlowManager
from app.ids.snort_integration import SnortIDS, SnortAlert
from app.ids.suricata_integration import SuricataIDS, SuricataAlert

logger = logging.getLogger(__name__)

ATTACK_LABELS = {0: "Normal", 1: "DoS", 2: "Probe", 3: "R2L", 4: "U2R"}

# Minimum confidence to act without VAE confirmation
CONFIDENCE_THRESHOLD = 0.70
# Maximum queue depth before oldest events are dropped
MAX_QUEUE = 4096


class AlertEvent:
    """Normalised internal alert event."""
    __slots__ = ("src_ip", "dst_ip", "proto", "src_port", "dst_port",
                 "raw_class", "source", "timestamp", "features")

    def __init__(self, **kw):
        self.timestamp = time.time()
        for k, v in kw.items():
            setattr(self, k, v)

    def to_dict(self) -> dict:
        return {s: getattr(self, s, None) for s in self.__slots__}


class IPSDecision:
    """Outcome of IPS processing for a single alert event."""
    __slots__ = ("alert", "ai_label", "ai_confidence", "action",
                 "vae_score", "is_attack", "timestamp")

    def __init__(self, **kw):
        self.timestamp = time.time()
        for k, v in kw.items():
            setattr(self, k, v)

    def to_dict(self) -> dict:
        d = {}
        for s in self.__slots__:
            v = getattr(self, s, None)
            if hasattr(v, "to_dict"):
                d[s] = v.to_dict()
            else:
                d[s] = v
        return d


class IPSEngine:
    """
    Central IPS engine: consumes IDS alerts, runs AI classification,
    and drives SDN enforcement.

    Parameters
    ----------
    ensemble      : Pre-trained EnsembleIDS model.
    flow_manager  : SDNFlowManager connected to Ryu.
    snort         : Optional SnortIDS instance.
    suricata      : Optional SuricataIDS instance.
    confidence_th : Minimum AI confidence for autonomous enforcement.
    write_ids_rules: Whether to auto-generate Snort/Suricata rules.
    """

    def __init__(
        self,
        ensemble: EnsembleIDS,
        flow_manager: SDNFlowManager,
        snort: Optional[SnortIDS] = None,
        suricata: Optional[SuricataIDS] = None,
        confidence_th: float = CONFIDENCE_THRESHOLD,
        write_ids_rules: bool = True,
        dpid: int = 1,
    ):
        self.ensemble = ensemble
        self.flow_manager = flow_manager
        self.snort = snort
        self.suricata = suricata
        self.confidence_th = confidence_th
        self.write_ids_rules = write_ids_rules
        self.dpid = dpid

        self._alert_queue: queue.Queue[AlertEvent] = queue.Queue(maxsize=MAX_QUEUE)
        self._decisions: list[IPSDecision] = []
        self._lock = threading.Lock()
        self._worker: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Register IDS callbacks
        if snort:
            snort.register_callback(self._snort_callback)
        if suricata:
            suricata.register_callback(self._suricata_callback)

    # ------------------------------------------------------------------
    # IDS callbacks
    # ------------------------------------------------------------------

    def _snort_callback(self, alert: SnortAlert) -> None:
        event = AlertEvent(
            src_ip=alert.src_ip,
            dst_ip=alert.dst_ip,
            proto=alert.proto,
            src_port=alert.src_port,
            dst_port=alert.dst_port,
            raw_class=alert.attack_class,
            source="snort",
            features=None,
        )
        self._enqueue(event)

    def _suricata_callback(self, alert: SuricataAlert) -> None:
        features_dict = SuricataIDS.extract_flow_features(alert)
        event = AlertEvent(
            src_ip=alert.src_ip,
            dst_ip=alert.dst_ip,
            proto=alert.proto,
            src_port=alert.src_port,
            dst_port=alert.dst_port,
            raw_class=alert.attack_class,
            source="suricata",
            features=features_dict,
        )
        self._enqueue(event)

    def _enqueue(self, event: AlertEvent) -> None:
        try:
            self._alert_queue.put_nowait(event)
        except queue.Full:
            logger.warning("IPS alert queue full — dropping oldest event")
            try:
                self._alert_queue.get_nowait()
            except queue.Empty:
                pass
            self._alert_queue.put_nowait(event)

    # ------------------------------------------------------------------
    # Manual flow processing
    # ------------------------------------------------------------------

    def process_flow(self, features: np.ndarray, src_ip: str, dst_ip: str = "") -> IPSDecision:
        """
        Directly classify a network flow feature vector and enforce if needed.
        Called from the Flask API when packets arrive via the SDN controller.
        """
        result = self.ensemble.predict_single(features)
        label = result["label"]
        confidence = result["confidence"]

        action = "allow"
        if result["is_attack"] and confidence >= self.confidence_th:
            enforcement = self.flow_manager.enforce(
                src_ip=src_ip,
                attack_class=label,
                dpid=self.dpid,
                confidence=confidence,
            )
            action = enforcement.get("action", "error")
            if self.write_ids_rules and label != 0:
                self._write_ids_rules_for(src_ip, label)

        decision = IPSDecision(
            alert=None,
            ai_label=label,
            ai_confidence=confidence,
            action=action,
            vae_score=result.get("vae_score"),
            is_attack=result["is_attack"],
        )
        with self._lock:
            self._decisions.append(decision)
        return decision

    def process_alert(self, event: AlertEvent) -> IPSDecision:
        """
        Process a pre-parsed IDS alert (from Snort/Suricata).
        When the event contains extracted features, run AI classification;
        otherwise trust the raw IDS class.
        """
        if event.features is not None:
            feature_vec = self._dict_to_feature_vec(event.features)
            result = self.ensemble.predict_single(feature_vec)
            label = result["label"]
            confidence = result["confidence"]
            vae_score = result.get("vae_score")
        else:
            label = event.raw_class
            confidence = 0.8   # IDS signature match → high confidence
            vae_score = None

        action = "allow"
        if label != 0 and confidence >= self.confidence_th:
            enforcement = self.flow_manager.enforce(
                src_ip=event.src_ip,
                attack_class=label,
                dpid=self.dpid,
                confidence=confidence,
            )
            action = enforcement.get("action", "error")
            if self.write_ids_rules:
                self._write_ids_rules_for(event.src_ip, label)

        decision = IPSDecision(
            alert=event,
            ai_label=label,
            ai_confidence=confidence,
            action=action,
            vae_score=vae_score,
            is_attack=(label != 0),
        )
        with self._lock:
            self._decisions.append(decision)
        return decision

    # ------------------------------------------------------------------
    # Background worker
    # ------------------------------------------------------------------

    def _worker_loop(self) -> None:
        logger.info("IPS worker thread started")
        while not self._stop_event.is_set():
            try:
                event = self._alert_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self.process_alert(event)
            except Exception as exc:
                logger.error("IPS worker error: %s", exc)

    def start(self) -> None:
        self._stop_event.clear()
        self._worker = threading.Thread(target=self._worker_loop, daemon=True, name="ips-worker")
        self._worker.start()
        if self.snort:
            self.snort.start()
        if self.suricata:
            self.suricata.start()
        logger.info("IPSEngine started")

    def stop(self) -> None:
        self._stop_event.set()
        if self.snort:
            self.snort.stop()
        if self.suricata:
            self.suricata.stop()
        if self._worker:
            self._worker.join(timeout=5)
        logger.info("IPSEngine stopped")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _dict_to_feature_vec(features: dict, length: int = 78) -> np.ndarray:
        vec = np.zeros(length, dtype=np.float32)
        keys = sorted(features.keys())
        for i, k in enumerate(keys[:length]):
            try:
                vec[i] = float(features[k])
            except (TypeError, ValueError):
                pass
        return vec

    def _write_ids_rules_for(self, src_ip: str, label: int) -> None:
        msg = f"AI-IDS: {ATTACK_LABELS.get(label, 'Attack')} from {src_ip}"
        if self.snort:
            try:
                self.snort.write_ai_rule(src_ip=src_ip, msg=msg)
            except Exception as exc:
                logger.warning("Snort rule write failed: %s", exc)
        if self.suricata:
            try:
                self.suricata.write_ai_rule(src_ip=src_ip, msg=msg)
            except Exception as exc:
                logger.warning("Suricata rule write failed: %s", exc)

    # ------------------------------------------------------------------
    # Status / audit
    # ------------------------------------------------------------------

    def get_recent_decisions(self, limit: int = 50) -> list[dict]:
        with self._lock:
            return [d.to_dict() for d in self._decisions[-limit:]]

    def get_stats(self) -> dict:
        with self._lock:
            decisions = list(self._decisions)
        total = len(decisions)
        attacks = sum(1 for d in decisions if d.is_attack)
        by_class: dict[int, int] = {}
        by_action: dict[str, int] = {}
        for d in decisions:
            by_class[d.ai_label] = by_class.get(d.ai_label, 0) + 1
            by_action[d.action] = by_action.get(d.action, 0) + 1
        return {
            "total_events": total,
            "attack_events": attacks,
            "normal_events": total - attacks,
            "queue_depth": self._alert_queue.qsize(),
            "by_class": by_class,
            "by_action": by_action,
        }
