"""
Flask REST API for the SDN/IoT AI-IDS/IPS system.

Endpoints
---------
POST /api/v1/predict               Classify a single flow feature vector
POST /api/v1/predict/batch         Classify a batch of flows
GET  /api/v1/metrics               Latest model evaluation metrics
GET  /api/v1/alerts/snort          Recent Snort alerts
GET  /api/v1/alerts/suricata       Recent Suricata alerts
GET  /api/v1/decisions             Recent IPS decisions
GET  /api/v1/mitigations           Active SDN mitigations
POST /api/v1/mitigations/revoke    Revoke a mitigation
GET  /api/v1/topology              SDN topology snapshot
GET  /api/v1/flows/<dpid>          OpenFlow table for a switch
GET  /api/v1/stats                 System-wide statistics
POST /api/v1/train                 Trigger model retraining (async)
POST /api/v1/evaluate              Run full evaluation on test data

RRD endpoints
POST /api/v1/rrd/classify          Classify a single .rrd file
POST /api/v1/rrd/classify/batch    Classify all .rrd files in a directory
POST /api/v1/rrd/train             Train models on a labelled .rrd directory
POST /api/v1/rrd/watch/start       Start live RRD watcher on a directory
POST /api/v1/rrd/watch/stop        Stop the RRD watcher
GET  /api/v1/rrd/watch/status      Watcher stats and recent decisions
GET  /api/v1/rrd/info              Metadata for a single .rrd file
"""

import logging
import threading
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


# ==================================================================
# RRD endpoints
# ==================================================================

def _get_rrd_engineer():
    return current_app.extensions.get("rrd_engineer")

def _get_rrd_watcher_bridge():
    return current_app.extensions.get("rrd_bridge")


# ------------------------------------------------------------------
# GET /api/v1/rrd/info
# ------------------------------------------------------------------

@api_bp.route("/rrd/info", methods=["GET"])
def rrd_info():
    """
    Return RRD metadata for a single file.

    Query params:
      path : absolute path to the .rrd file
    """
    path = request.args.get("path")
    if not path:
        return jsonify({"error": "path query parameter required"}), 400

    from app.utils.rrd_reader import RRDReader
    reader = RRDReader()
    try:
        info = reader.info(path)
        return jsonify({
            "path": info.path,
            "last_update": info.last_update,
            "step_seconds": info.step,
            "data_sources": info.data_sources,
            "ds_types": info.ds_types,
            "rras": info.rras,
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ------------------------------------------------------------------
# POST /api/v1/rrd/classify
# ------------------------------------------------------------------

@api_bp.route("/rrd/classify", methods=["POST"])
def rrd_classify():
    """
    Classify a single .rrd file with the AI ensemble.

    Request body (JSON):
    {
      "path"         : "/var/lib/collectd/rrd/router1/interface-eth0/if_octets.rrd",
      "lookback_sec" : 3600,   // optional, default 3600
      "src_ip"       : "192.168.1.1",   // optional, for IPS enforcement
      "enforce"      : false            // optional
    }
    """
    data = request.get_json(force=True, silent=True) or {}
    path = data.get("path")
    if not path:
        return jsonify({"error": "path required"}), 400

    ensemble = _get_ensemble()
    if ensemble is None:
        return jsonify({"error": "Model not loaded"}), 503

    from app.utils.rrd_feature_engineer import RRDFeatureEngineer
    lookback = int(data.get("lookback_sec", 3600))
    engineer = RRDFeatureEngineer(lookback_sec=lookback)

    try:
        vec = engineer.live_vector(path, lookback_sec=lookback)
    except Exception as exc:
        return jsonify({"error": f"RRD read failed: {exc}"}), 500

    prediction = ensemble.predict_single(vec)
    prediction["feature_vector_length"] = int(len(vec))
    prediction["rrd_path"] = path

    src_ip = data.get("src_ip", "0.0.0.0")
    enforce = data.get("enforce", False)
    if enforce and prediction["is_attack"]:
        engine = _get_engine()
        if engine:
            decision = engine.process_flow(vec, src_ip)
            prediction["ips_action"] = decision.action

    return jsonify(prediction)


# ------------------------------------------------------------------
# POST /api/v1/rrd/classify/batch
# ------------------------------------------------------------------

@api_bp.route("/rrd/classify/batch", methods=["POST"])
def rrd_classify_batch():
    """
    Classify all .rrd files found under a directory.

    Request body (JSON):
    {
      "directory"    : "/var/lib/collectd/rrd",
      "file_pattern" : "**/*.rrd",   // optional
      "lookback_sec" : 3600,
      "max_files"    : 0,            // 0 = unlimited
      "enforce"      : false
    }

    Returns a list of per-file classification results.
    """
    data = request.get_json(force=True, silent=True) or {}
    directory = data.get("directory")
    if not directory:
        return jsonify({"error": "directory required"}), 400

    ensemble = _get_ensemble()
    if ensemble is None:
        return jsonify({"error": "Model not loaded"}), 503

    from app.utils.rrd_feature_engineer import classify_rrd_directory

    engine = _get_engine() if data.get("enforce") else None

    try:
        results = classify_rrd_directory(
            directory=directory,
            ensemble=ensemble,
            file_pattern=data.get("file_pattern", "**/*.rrd"),
            lookback_sec=int(data.get("lookback_sec", 3600)),
        )
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    attacks = [r for r in results if r.get("is_attack")]
    if engine and attacks:
        for r in attacks:
            if "error" not in r:
                vec_placeholder = np.zeros(78, dtype=np.float32)
                engine.process_flow(vec_placeholder, "0.0.0.0")

    return jsonify({
        "directory": directory,
        "total_files": len(results),
        "attacks_detected": len(attacks),
        "results": results,
    })


# ------------------------------------------------------------------
# POST /api/v1/rrd/train
# ------------------------------------------------------------------

@api_bp.route("/rrd/train", methods=["POST"])
def rrd_train():
    """
    Train the ensemble on labelled .rrd files from a directory tree.

    Expected directory layout (Cacti-style):
      <root>/
        normal/    *.rrd   → label 0
        dos/       *.rrd   → label 1
        probe/     *.rrd   → label 2
        r2l/       *.rrd   → label 3
        u2r/       *.rrd   → label 4

    Alternatively pass label_map: {"stem": label, ...} in the request.

    Request body (JSON):
    {
      "directory"    : "/data/rrd_dataset",
      "label_map"    : {"router1_eth0": 1, "sensor2_wlan0": 0},  // optional
      "file_pattern" : "**/*.rrd",
      "lookback_sec" : 3600,
      "window_step"  : 300,   // sliding window stride (0 = one window per file)
      "epochs"       : 20,
      "max_files"    : 0
    }
    """
    import threading

    data = request.get_json(force=True, silent=True) or {}
    directory = data.get("directory")
    if not directory:
        return jsonify({"error": "directory required"}), 400

    ensemble = _get_ensemble()
    if ensemble is None:
        return jsonify({"error": "Model not loaded"}), 503

    def _rrd_train_job():
        from app.utils.rrd_feature_engineer import RRDFeatureEngineer
        from sklearn.model_selection import train_test_split

        label_map_raw = data.get("label_map", {})
        label_map = {k: int(v) for k, v in label_map_raw.items()}

        engineer = RRDFeatureEngineer(
            label_map=label_map,
            lookback_sec=int(data.get("lookback_sec", 3600)),
            window_step=int(data.get("window_step", 0)),
        )

        try:
            X, y = engineer.directory_to_dataset(
                directory=directory,
                file_pattern=data.get("file_pattern", "**/*.rrd"),
                max_files=int(data.get("max_files", 0)),
            )
        except Exception as exc:
            logger.error("RRD dataset load failed: %s", exc)
            current_app.extensions["rrd_train_status"] = {"error": str(exc)}
            return

        if len(X) == 0:
            current_app.extensions["rrd_train_status"] = {"error": "No data loaded"}
            return

        logger.info("RRD training: %d samples, labels=%s", len(X), dict(zip(*np.unique(y, return_counts=True))))
        history = ensemble.fit(X, y, epochs=int(data.get("epochs", 20)))

        if len(X) > 10:
            _, X_te, _, y_te = train_test_split(X, y, test_size=0.2, random_state=42)
            metrics = ensemble.evaluate(X_te, y_te)
            current_app.extensions["latest_metrics"] = metrics
            current_app.extensions["rrd_train_status"] = {
                "status": "complete",
                "samples": int(len(X)),
                "accuracy": metrics["ensemble"]["accuracy"],
                "f1_macro": metrics["ensemble"]["f1_macro"],
                "recall_macro": metrics["ensemble"]["recall_macro"],
                "mse": metrics["ensemble"]["mse"],
            }
        else:
            current_app.extensions["rrd_train_status"] = {
                "status": "complete", "samples": int(len(X))
            }
        logger.info("RRD training complete")

    current_app.extensions["rrd_train_status"] = {"status": "running"}
    t = threading.Thread(target=_rrd_train_job, daemon=True, name="rrd-train")
    t.start()
    return jsonify({"status": "rrd training started", "directory": directory})


@api_bp.route("/rrd/train/status", methods=["GET"])
def rrd_train_status():
    return jsonify(current_app.extensions.get("rrd_train_status", {"status": "not started"}))


# ------------------------------------------------------------------
# POST /api/v1/rrd/watch/start
# ------------------------------------------------------------------

@api_bp.route("/rrd/watch/start", methods=["POST"])
def rrd_watch_start():
    """
    Start the live RRD watcher on a directory.

    Request body (JSON):
    {
      "directory"     : "/var/lib/collectd/rrd",
      "poll_interval" : 30,   // seconds between scans
      "lookback_sec"  : 600
    }
    """
    data = request.get_json(force=True, silent=True) or {}
    directory = data.get("directory")
    if not directory:
        return jsonify({"error": "directory required"}), 400

    ensemble = _get_ensemble()
    engine = _get_engine()
    if ensemble is None or engine is None:
        return jsonify({"error": "Model / engine not loaded"}), 503

    existing = _get_rrd_watcher_bridge()
    if existing:
        existing.stop()

    from app.utils.rrd_watcher import RRDIPSBridge
    bridge = RRDIPSBridge(
        directory=directory,
        ips_engine=engine,
        ensemble=ensemble,
        poll_interval=float(data.get("poll_interval", 30)),
        lookback_sec=int(data.get("lookback_sec", 600)),
    )
    bridge.start()
    current_app.extensions["rrd_bridge"] = bridge
    return jsonify({"status": "watcher started", "directory": directory})


@api_bp.route("/rrd/watch/stop", methods=["POST"])
def rrd_watch_stop():
    bridge = _get_rrd_watcher_bridge()
    if bridge is None:
        return jsonify({"status": "not running"})
    bridge.stop()
    current_app.extensions.pop("rrd_bridge", None)
    return jsonify({"status": "stopped"})


@api_bp.route("/rrd/watch/status", methods=["GET"])
def rrd_watch_status():
    bridge = _get_rrd_watcher_bridge()
    if bridge is None:
        return jsonify({"status": "not running"})
    return jsonify({
        "status": "running",
        "watcher": bridge.get_watcher_stats(),
        "recent_decisions": bridge.get_decisions(limit=int(request.args.get("limit", 20))),
    })
