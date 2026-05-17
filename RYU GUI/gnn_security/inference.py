"""
Live inference engine — invoked by the Django REST endpoint /api/gnn/infer/.

Receives a batch of flows from the custom Ryu app, builds the IP-graph,
runs HGAGN inference, returns predicted threat classes + per-node confidence.
"""
from __future__ import annotations
import logging
from typing import Dict, List

import numpy as np
from django.conf import settings

from .models import load_model, TORCH_AVAILABLE
from .data_prep import build_graph_from_flows, ATTACK_CLASSES

log = logging.getLogger(__name__)


class InferenceEngine:
    """Thin wrapper: loads the trained model once and re-uses it."""

    def __init__(self, model_path: str | None = None,
                 threshold: float | None = None):
        self.model_path = model_path or settings.GNN_MODEL_PATH
        self.threshold = float(threshold or settings.GNN_THREAT_THRESHOLD)
        self.model, self.backend = load_model(self.model_path)

    def infer(self, flows: List[Dict]) -> Dict:
        """Run inference on a batch of flow records. Returns:

            {
              "threats": [{src_ip, threat_type, confidence, dpid, auto_mitigate}, ...],
              "node_classifications": [{ip, label, probs}, ...]
            }
        """
        if not flows:
            return {"threats": [], "node_classifications": []}

        x, ei, ew, _, ip_to_idx = build_graph_from_flows(flows)
        idx_to_ip = {i: ip for ip, i in ip_to_idx.items()}

        if self.backend == "torch" and TORCH_AVAILABLE:
            import torch
            with torch.no_grad():
                xt = torch.tensor(x, dtype=torch.float32)
                eit = torch.tensor(ei, dtype=torch.long)
                ewt = torch.tensor(ew, dtype=torch.float32)
                logits = self.model(xt, eit, edge_weight=ewt)
                probs = torch.softmax(logits, dim=1).cpu().numpy()
                labels = probs.argmax(axis=1)
        else:
            labels, probs = self.model.predict(x)

        node_classes = []
        threats = []
        # map src_ip → first flow's dpid (for mitigation)
        dpid_by_ip = {f["src_ip"]: f.get("dpid") for f in flows}
        for i, lab in enumerate(labels):
            ip = idx_to_ip[i]
            conf = float(probs[i, lab])
            label_name = ATTACK_CLASSES[int(lab)]
            node_classes.append({"ip": ip, "label": label_name,
                                 "confidence": conf, "probs": probs[i].tolist()})
            if label_name != "benign" and conf >= self.threshold:
                threats.append({
                    "src_ip": ip,
                    "threat_type": label_name,
                    "confidence": conf,
                    "dpid": dpid_by_ip.get(ip),
                    "auto_mitigate": settings.GNN_MITIGATION_ENABLED and conf >= 0.9,
                })

        log.info("GNN inference: %d nodes, %d threats", len(node_classes), len(threats))
        return {"threats": threats, "node_classifications": node_classes}


# Single module-level engine — lazy-loaded on first request
_engine: InferenceEngine | None = None


def get_engine() -> InferenceEngine:
    global _engine
    if _engine is None:
        _engine = InferenceEngine()
    return _engine
