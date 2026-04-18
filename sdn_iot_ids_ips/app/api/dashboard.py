"""
Dashboard blueprint — serves the real-time monitoring UI and
pushes live events to connected browsers via Flask-SocketIO.
"""

import time
import threading
import logging
from flask import Blueprint, render_template, current_app
from app import socketio

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint("dashboard", __name__)

# Push interval for background broadcaster
_PUSH_INTERVAL = 2.0


@dashboard_bp.route("/")
def index():
    return render_template("index.html")


@dashboard_bp.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


# ------------------------------------------------------------------
# SocketIO events
# ------------------------------------------------------------------

@socketio.on("connect")
def on_connect():
    logger.debug("WebSocket client connected")
    _push_stats()


@socketio.on("disconnect")
def on_disconnect():
    logger.debug("WebSocket client disconnected")


@socketio.on("request_stats")
def on_request_stats():
    _push_stats()


def _push_stats():
    """Push a stats snapshot to the requesting client."""
    engine = current_app.extensions.get("ips_engine")
    fm = current_app.extensions.get("flow_manager")
    snort = current_app.extensions.get("snort")
    suricata = current_app.extensions.get("suricata")
    metrics = current_app.extensions.get("latest_metrics", {})

    payload = {
        "timestamp": time.time(),
        "ips_stats": engine.get_stats() if engine else {},
        "active_mitigations": fm.get_active_mitigations() if fm else [],
        "snort_stats": snort.get_alert_stats() if snort else {},
        "suricata_stats": suricata.get_alert_stats() if suricata else {},
        "metrics": {
            "accuracy": metrics.get("ensemble", {}).get("accuracy", 0),
            "f1_macro": metrics.get("ensemble", {}).get("f1_macro", 0),
            "recall_macro": metrics.get("ensemble", {}).get("recall_macro", 0),
            "mse": metrics.get("ensemble", {}).get("mse", 0),
        },
    }
    socketio.emit("stats_update", payload)


def start_background_broadcaster(app):
    """
    Spawn a background thread that broadcasts live stats to all
    connected WebSocket clients every _PUSH_INTERVAL seconds.
    """
    def _loop():
        while True:
            time.sleep(_PUSH_INTERVAL)
            with app.app_context():
                try:
                    _push_stats()
                except Exception as exc:
                    logger.debug("Broadcaster error: %s", exc)

    t = threading.Thread(target=_loop, daemon=True, name="ws-broadcaster")
    t.start()
    logger.info("WebSocket broadcaster started (interval=%.1fs)", _PUSH_INTERVAL)
