"""
Application entry point.

Startup sequence
----------------
1. Create Flask app and register blueprints.
2. Initialise EnsembleIDS, SDNFlowManager, SnortIDS, SuricataIDS.
3. Optionally train on synthetic data so the API is ready immediately.
4. Start IPSEngine background worker.
5. Start WebSocket broadcaster.
6. Run Flask-SocketIO server.

Usage
-----
    python run.py                         # development (auto-trains)
    FLASK_ENV=production python run.py    # production

Environment variables
---------------------
See config/config.py for the full list.
"""

import os
import logging
import threading

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger(__name__)


def create_components(app):
    """Initialise all system components and attach them to app.extensions."""
    from config.config import BaseConfig as Cfg
    from app.models.ensemble import EnsembleIDS
    from app.controllers.flow_manager import SDNFlowManager
    from app.ids.snort_integration import SnortIDS
    from app.ids.suricata_integration import SuricataIDS
    from app.ips.ips_engine import IPSEngine

    # Core model
    ensemble = EnsembleIDS(
        cnn_weight=app.config["ENSEMBLE_CNN_WEIGHT"],
        lstm_weight=app.config["ENSEMBLE_LSTM_WEIGHT"],
        vae_weight=app.config["ENSEMBLE_VAE_WEIGHT"],
        alert_threshold=app.config["CONFIDENCE_THRESHOLD"],
        device=app.config["DEVICE"],
    )

    # SDN controller
    flow_manager = SDNFlowManager(
        ryu_url=app.config["RYU_REST_URL"],
        default_dpid=app.config["RYU_DEFAULT_DPID"],
        block_timeout=app.config["BLOCK_TIMEOUT"],
        mirror_port=app.config["MIRROR_PORT"],
        honeypot_port=app.config["HONEYPOT_PORT"],
    )

    # IDS sensors (log paths may not exist in dev — that's OK, threads will wait)
    snort = SnortIDS(
        alert_log=app.config["SNORT_ALERT_LOG"],
        rules_dir=app.config["SNORT_RULES_DIR"],
    )
    suricata = SuricataIDS(
        eve_log=app.config["SURICATA_EVE_LOG"],
        rules_dir=app.config["SURICATA_RULES_DIR"],
    )

    # IPS engine
    engine = IPSEngine(
        ensemble=ensemble,
        flow_manager=flow_manager,
        snort=snort,
        suricata=suricata,
        confidence_th=app.config["CONFIDENCE_THRESHOLD"],
        write_ids_rules=app.config["WRITE_IDS_RULES"],
        dpid=app.config["RYU_DEFAULT_DPID"],
    )

    app.extensions["ensemble"] = ensemble
    app.extensions["flow_manager"] = flow_manager
    app.extensions["snort"] = snort
    app.extensions["suricata"] = suricata
    app.extensions["ips_engine"] = engine
    app.extensions["latest_metrics"] = {}

    return ensemble, engine


def auto_train(app, ensemble):
    """Train on synthetic data in a background thread."""
    from app.utils.preprocessing import TrafficPreprocessor

    n = app.config["SYNTHETIC_TRAIN_SAMPLES"]
    epochs = app.config["SYNTHETIC_TRAIN_EPOCHS"]
    logger.info("Auto-training on %d synthetic samples for %d epochs …", n, epochs)

    X, y = TrafficPreprocessor.generate_synthetic(n_samples=n)
    history = ensemble.fit(X, y, epochs=epochs)

    # Run evaluation
    from app.utils.metrics import ModelEvaluator
    from sklearn.model_selection import train_test_split
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    metrics = ensemble.evaluate(X_te, y_te)
    app.extensions["latest_metrics"] = metrics
    app.extensions["training_history"] = history

    logger.info(
        "Training complete — ensemble acc=%.4f  f1=%.4f  recall=%.4f  mse=%.6f",
        metrics["ensemble"]["accuracy"],
        metrics["ensemble"]["f1_macro"],
        metrics["ensemble"]["recall_macro"],
        metrics["ensemble"]["mse"],
    )


def main():
    from app import create_app, socketio
    from app.api.dashboard import start_background_broadcaster

    env = os.getenv("FLASK_ENV", "development")
    from config.config import config_map
    cfg = config_map.get(env, config_map["development"])

    app = create_app(cfg)

    with app.app_context():
        ensemble, engine = create_components(app)

        if app.config["AUTO_TRAIN_ON_STARTUP"]:
            t = threading.Thread(
                target=auto_train, args=(app, ensemble), daemon=True, name="auto-train"
            )
            t.start()

        engine.start()

    start_background_broadcaster(app)

    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "5000"))
    logger.info("Starting SDN IoT AI-IDS/IPS on %s:%d  [%s]", host, port, env)
    socketio.run(app, host=host, port=port, debug=app.config["DEBUG"], use_reloader=False)


if __name__ == "__main__":
    main()
