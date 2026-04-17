"""
Application configuration for the SDN IoT AI-IDS/IPS system.
"""

import os


class BaseConfig:
    SECRET_KEY = os.getenv("SECRET_KEY", "sdn-iot-ids-ips-dev-key-change-in-prod")
    DEBUG = False
    TESTING = False

    # Ryu controller
    RYU_REST_URL = os.getenv("RYU_REST_URL", "http://127.0.0.1:8080")
    RYU_DEFAULT_DPID = int(os.getenv("RYU_DEFAULT_DPID", "1"))

    # IDS log paths
    SNORT_ALERT_LOG = os.getenv("SNORT_ALERT_LOG", "/var/log/snort/alert")
    SNORT_RULES_DIR = os.getenv("SNORT_RULES_DIR", "/etc/snort/rules")
    SURICATA_EVE_LOG = os.getenv("SURICATA_EVE_LOG", "/var/log/suricata/eve.json")
    SURICATA_RULES_DIR = os.getenv("SURICATA_RULES_DIR", "/etc/suricata/rules")

    # Model
    NUM_FEATURES = int(os.getenv("NUM_FEATURES", "78"))
    NUM_CLASSES = int(os.getenv("NUM_CLASSES", "5"))
    DEVICE = os.getenv("DEVICE", "cpu")           # "cuda" for GPU
    CNN_DROPOUT = float(os.getenv("CNN_DROPOUT", "0.4"))
    LSTM_DROPOUT = float(os.getenv("LSTM_DROPOUT", "0.4"))
    VAE_DROPOUT = float(os.getenv("VAE_DROPOUT", "0.2"))
    ENSEMBLE_CNN_WEIGHT = float(os.getenv("ENSEMBLE_CNN_WEIGHT", "0.45"))
    ENSEMBLE_LSTM_WEIGHT = float(os.getenv("ENSEMBLE_LSTM_WEIGHT", "0.45"))
    ENSEMBLE_VAE_WEIGHT = float(os.getenv("ENSEMBLE_VAE_WEIGHT", "0.10"))
    CONFIDENCE_THRESHOLD = float(os.getenv("CONFIDENCE_THRESHOLD", "0.70"))

    # IPS
    BLOCK_TIMEOUT = int(os.getenv("BLOCK_TIMEOUT", "300"))
    MIRROR_PORT = int(os.getenv("MIRROR_PORT", "2"))
    HONEYPOT_PORT = int(os.getenv("HONEYPOT_PORT", "3"))
    WRITE_IDS_RULES = os.getenv("WRITE_IDS_RULES", "true").lower() == "true"

    # SocketIO
    SOCKETIO_ASYNC_MODE = "threading"

    # Pre-trained model paths (optional — if set, model is loaded at startup)
    MODEL_SAVE_DIR = os.getenv("MODEL_SAVE_DIR", "./saved_models")
    AUTO_TRAIN_ON_STARTUP = os.getenv("AUTO_TRAIN_ON_STARTUP", "true").lower() == "true"
    SYNTHETIC_TRAIN_SAMPLES = int(os.getenv("SYNTHETIC_TRAIN_SAMPLES", "8000"))
    SYNTHETIC_TRAIN_EPOCHS = int(os.getenv("SYNTHETIC_TRAIN_EPOCHS", "20"))


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    AUTO_TRAIN_ON_STARTUP = True
    SYNTHETIC_TRAIN_SAMPLES = 5000
    SYNTHETIC_TRAIN_EPOCHS = 10


class ProductionConfig(BaseConfig):
    DEBUG = False
    AUTO_TRAIN_ON_STARTUP = False


class TestingConfig(BaseConfig):
    TESTING = True
    AUTO_TRAIN_ON_STARTUP = False
    SYNTHETIC_TRAIN_SAMPLES = 500
    SYNTHETIC_TRAIN_EPOCHS = 2


config_map = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}
