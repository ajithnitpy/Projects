"""
Flask REST API for the SDN/IoT AI-IDS/IPS system.

Endpoints
---------
POST /api/v1/predict           Classify a single flow feature vector
POST /api/v1/predict/batch     Classify a batch of flows
GET  /api/v1/metrics           Latest model evaluation metrics
GET  /api/v1/alerts/snort      Recent Snort alerts
GET  /api/v1/alerts/suricata   Recent Suricata alerts
GET  /api/v1/decisions         Recent IPS decisions
GET  /api/v1/mitigations       Active SDN mitigations
POST /api/v1/mitigations/revoke Revoke a mitigation
GET  /api/v1/topology          SDN topology snapshot
GET  /api/v1/flows/<dpid>      OpenFlow table for a switch
GET  /api/v1/stats             System-wide statistics
POST /api/v1/train             Trigger model retraining (async)
POST /api/v1/evaluate          Run full evaluation on test data
"""

import logging
import numpy as np
from flask import Blueprint, request, jsonify, current_app

logger = logging.getLogger(__name__)

api_bp = Blueprint("api", __name__)


def _get_engine():
    return current_app.extensions.get("ips_engine")


def _get_flow_manager():
    return current_app.extensions.get("flow_manager")


def _get_ensemble():
    return current_app.extensions.get("ensemble")


def _get_snort():
    return current_app.extensions.get("snort")


def _get_suricata():
    return current_app.extensions.get("suricata")


# ------------------------------------------------------------------
# Prediction endpoints
# ------------------------------------------------------------------

@api_bp.route("/predict", methods=["POST"])
def predict():
    """
    Classify a single network flow.

    Request body (JSON):
    {
      "features": [f1, f2, ..., f78],  // float array
      "src_ip": "192.168.1.100",       // optional, for IPS enforcement
      "enforce": true                  // optional, default false
    }
    """
    data = request.get_json(force=True, silent=True) or {}
    features = data.get("features")
    if not features:
        return jsonify({"error": "features array required"}), 400

    try:
        feat_vec = np.array(features, dtype=np.float32)
        if feat_vec.ndim != 1:
            return jsonify({"error": "features must be a 1-D array"}), 400
    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400

    ensemble = _get_ensemble()
    if ensemble is None:
        return jsonify({"error": "Model not loaded"}), 503

    result = ensemble.predict_single(feat_vec)

    src_ip = data.get("src_ip", "0.0.0.0")
    enforce = data.get("enforce", False)

    if enforce and result["is_attack"]:
        engine = _get_engine()
        if engine:
            decision = engine.process_flow(feat_vec, src_ip)
            result["ips_action"] = decision.action

    return jsonify(result)


@api_bp.route("/predict/batch", methods=["POST"])
def predict_batch():
    """
    Classify a batch of flows.

    Request body:
    {
      "features": [[f1..f78], [f1..f78], ...],
      "src_ips": ["1.2.3.4", ...],   // optional
      "enforce": false
    }
    """
    data = request.get_json(force=True, silent=True) or {}
    features = data.get("features")
    if not features:
        return jsonify({"error": "features array required"}), 400

    try:
        X = np.array(features, dtype=np.float32)
        if X.ndim != 2:
            return jsonify({"error": "features must be a 2-D array"}), 400
    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400

    ensemble = _get_ensemble()
    if ensemble is None:
        return jsonify({"error": "Model not loaded"}), 503

    preds = ensemble.cnn.predict(X).tolist()
    probas = ensemble.cnn.predict_proba(X).tolist()

    from app.models.cnn_ids import ATTACK_LABELS
    results = [
        {
            "label": p,
            "attack_name": ATTACK_LABELS.get(p, "Unknown"),
            "is_attack": p != 0,
            "probabilities": prob,
        }
        for p, prob in zip(preds, probas)
    ]
    return jsonify({"count": len(results), "predictions": results})


# ------------------------------------------------------------------
# Metrics & evaluation
# ------------------------------------------------------------------

@api_bp.route("/metrics", methods=["GET"])
def get_metrics():
    metrics = current_app.extensions.get("latest_metrics", {})
    return jsonify(metrics)


@api_bp.route("/evaluate", methods=["POST"])
def evaluate():
    """
    Run a full evaluation on provided test data.

    Request body:
    {
      "features": [[...], ...],
      "labels": [0, 1, 2, ...]
    }
    """
    data = request.get_json(force=True, silent=True) or {}
    features = data.get("features")
    labels = data.get("labels")
    if not features or not labels:
        return jsonify({"error": "features and labels required"}), 400

    try:
        X = np.array(features, dtype=np.float32)
        y = np.array(labels, dtype=np.int64)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400

    ensemble = _get_ensemble()
    if ensemble is None:
        return jsonify({"error": "Model not loaded"}), 503

    metrics = ensemble.evaluate(X, y)
    current_app.extensions["latest_metrics"] = metrics
    return jsonify(metrics)


# ------------------------------------------------------------------
# IDS alert endpoints
# ------------------------------------------------------------------

@api_bp.route("/alerts/snort", methods=["GET"])
def snort_alerts():
    limit = int(request.args.get("limit", 50))
    snort = _get_snort()
    if snort is None:
        return jsonify({"alerts": [], "message": "Snort not configured"})
    return jsonify({
        "alerts": snort.get_recent_alerts(limit),
        "stats": snort.get_alert_stats(),
    })


@api_bp.route("/alerts/suricata", methods=["GET"])
def suricata_alerts():
    limit = int(request.args.get("limit", 50))
    suricata = _get_suricata()
    if suricata is None:
        return jsonify({"alerts": [], "message": "Suricata not configured"})
    return jsonify({
        "alerts": suricata.get_recent_alerts(limit),
        "stats": suricata.get_alert_stats(),
    })


# ------------------------------------------------------------------
# IPS decisions & mitigations
# ------------------------------------------------------------------

@api_bp.route("/decisions", methods=["GET"])
def get_decisions():
    limit = int(request.args.get("limit", 50))
    engine = _get_engine()
    if engine is None:
        return jsonify({"decisions": []})
    return jsonify({
        "decisions": engine.get_recent_decisions(limit),
        "stats": engine.get_stats(),
    })


@api_bp.route("/mitigations", methods=["GET"])
def get_mitigations():
    fm = _get_flow_manager()
    if fm is None:
        return jsonify({"mitigations": []})
    return jsonify({
        "active": fm.get_active_mitigations(),
        "log": fm.get_mitigation_log(limit=int(request.args.get("limit", 50))),
    })


@api_bp.route("/mitigations/revoke", methods=["POST"])
def revoke_mitigation():
    data = request.get_json(force=True, silent=True) or {}
    src_ip = data.get("src_ip")
    if not src_ip:
        return jsonify({"error": "src_ip required"}), 400
    fm = _get_flow_manager()
    if fm is None:
        return jsonify({"error": "Flow manager not available"}), 503
    result = fm.revoke(src_ip)
    return jsonify(result)


# ------------------------------------------------------------------
# SDN topology & flows
# ------------------------------------------------------------------

@api_bp.route("/topology", methods=["GET"])
def get_topology():
    fm = _get_flow_manager()
    if fm is None:
        return jsonify({"error": "Flow manager not available"}), 503
    return jsonify(fm.get_topology())


@api_bp.route("/flows/<int:dpid>", methods=["GET"])
def get_flows(dpid: int):
    fm = _get_flow_manager()
    if fm is None:
        return jsonify({"error": "Flow manager not available"}), 503
    try:
        flows = fm.get_flow_stats(dpid)
        return jsonify({"dpid": dpid, "flows": flows})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 502


# ------------------------------------------------------------------
# System stats
# ------------------------------------------------------------------

@api_bp.route("/stats", methods=["GET"])
def system_stats():
    engine = _get_engine()
    fm = _get_flow_manager()
    snort = _get_snort()
    suricata = _get_suricata()

    return jsonify({
        "ips": engine.get_stats() if engine else {},
        "active_mitigations": len(fm.get_active_mitigations()) if fm else 0,
        "snort_alerts": snort.get_alert_count() if snort else 0,
        "suricata_alerts": suricata.get_alert_count() if suricata else 0,
    })


# ------------------------------------------------------------------
# Training endpoint
# ------------------------------------------------------------------

@api_bp.route("/train", methods=["POST"])
def train():
    """
    Trigger model training on synthetic data (for demo).
    In production, pass dataset paths in the request body.
    """
    import threading
    from app.utils.preprocessing import TrafficPreprocessor

    ensemble = _get_ensemble()
    if ensemble is None:
        return jsonify({"error": "Ensemble not initialised"}), 503

    data = request.get_json(force=True, silent=True) or {}
    epochs = int(data.get("epochs", 10))
    n_samples = int(data.get("n_samples", 5000))

    def _train():
        X, y = TrafficPreprocessor.generate_synthetic(n_samples=n_samples)
        history = ensemble.fit(X, y, epochs=epochs)
        current_app.extensions["training_history"] = history
        logger.info("Background training complete")

    t = threading.Thread(target=_train, daemon=True, name="train-thread")
    t.start()
    return jsonify({"status": "training started", "epochs": epochs, "n_samples": n_samples})
