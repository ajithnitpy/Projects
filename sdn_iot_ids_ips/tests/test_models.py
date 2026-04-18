"""
Unit tests for SDN IoT AI-IDS/IPS models and evaluation pipeline.

Run with:  python -m pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import numpy as np
import pytest

from app.utils.preprocessing import TrafficPreprocessor
from app.utils.metrics import ModelEvaluator, compute_ids_metrics, compute_per_class_metrics
from app.models.cnn_ids import CNNIntrusionDetector, NUM_FEATURES, NUM_CLASSES
from app.models.lstm_ids import LSTMIntrusionDetector
from app.models.autoencoder import AnomalyAutoencoder
from app.models.ensemble import EnsembleIDS
from app.ids.snort_integration import SnortIDS
from app.ids.suricata_integration import SuricataIDS, SuricataAlert

# ── Fixtures ─────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def synthetic_data():
    X, y = TrafficPreprocessor.generate_synthetic(n_samples=400, random_state=0)
    return X, y


@pytest.fixture(scope="module")
def split_data(synthetic_data):
    X, y = synthetic_data
    prep = TrafficPreprocessor()
    return prep.train_test_split(X, y, test_size=0.25)


# ── Preprocessing tests ──────────────────────────────────────────

class TestPreprocessor:
    def test_synthetic_shape(self, synthetic_data):
        X, y = synthetic_data
        assert X.shape == (400, NUM_FEATURES)
        assert y.shape == (400,)
        assert set(np.unique(y)).issubset(set(range(NUM_CLASSES)))

    def test_train_test_split_stratified(self, split_data):
        X_tr, X_te, y_tr, y_te = split_data
        assert len(X_tr) + len(X_te) == 400
        assert X_tr.shape[1] == NUM_FEATURES

    def test_packet_to_vector(self):
        prep = TrafficPreprocessor()
        packet = {"proto": "tcp", "src_port": 80, "dst_port": 443, "length": 512}
        vec = prep.packet_to_vector(packet)
        assert vec.shape == (NUM_FEATURES,)
        assert vec.dtype == np.float32


# ── CNN tests ────────────────────────────────────────────────────

class TestCNN:
    def test_forward_shape(self):
        import torch
        model = CNNIntrusionDetector()
        x = torch.randn(4, NUM_FEATURES)
        out = model(x)
        assert out.shape == (4, NUM_CLASSES)

    def test_fit_and_predict(self, split_data):
        X_tr, X_te, y_tr, y_te = split_data
        model = CNNIntrusionDetector(dropout_rate=0.3)
        history = model.fit(X_tr, y_tr, epochs=2, batch_size=64)
        assert "loss" in history
        assert "accuracy" in history
        assert "mse" in history

        preds = model.predict(X_te)
        assert preds.shape == (len(X_te),)
        assert set(np.unique(preds)).issubset(set(range(NUM_CLASSES)))

    def test_evaluate_returns_all_metrics(self, split_data):
        X_tr, X_te, y_tr, y_te = split_data
        model = CNNIntrusionDetector()
        model.fit(X_tr, y_tr, epochs=2, batch_size=64)
        metrics = model.evaluate(X_te, y_te)
        for key in ("accuracy", "f1_macro", "recall_macro", "precision_macro",
                    "mse", "dropout_rate", "confusion_matrix"):
            assert key in metrics, f"Missing metric: {key}"

    def test_dropout_rate_stored(self):
        model = CNNIntrusionDetector(dropout_rate=0.5)
        assert model.dropout_rate == 0.5


# ── LSTM tests ───────────────────────────────────────────────────

class TestLSTM:
    def test_forward_shape(self):
        import torch
        model = LSTMIntrusionDetector(seq_len=4)
        x = torch.randn(8, 4, NUM_FEATURES)
        out = model(x)
        assert out.shape == (8, NUM_CLASSES)

    def test_sequence_creation(self):
        X = np.random.rand(50, NUM_FEATURES).astype(np.float32)
        y = np.zeros(50, dtype=np.int64)
        X_seq, y_seq = LSTMIntrusionDetector.create_sequences(X, y, seq_len=5)
        assert X_seq.shape == (46, 5, NUM_FEATURES)
        assert y_seq.shape == (46,)

    def test_fit_predict(self, split_data):
        X_tr, X_te, y_tr, y_te = split_data
        model = LSTMIntrusionDetector(seq_len=4, hidden_size=32, num_layers=1)
        model.fit(X_tr, y_tr, epochs=2, batch_size=32)
        preds = model.predict(X_te)
        assert len(preds) == len(X_te) - model.seq_len + 1


# ── Autoencoder tests ────────────────────────────────────────────

class TestAutoencoder:
    def test_fit_and_anomaly_score(self, synthetic_data):
        X, y = synthetic_data
        X_normal = X[y == 0]
        model = AnomalyAutoencoder(latent_dim=16)
        model.fit(X_normal, epochs=2, batch_size=64)
        scores = model.anomaly_score(X[:20])
        assert scores.shape == (20,)
        assert model.threshold > 0

    def test_predict_binary(self, synthetic_data):
        X, y = synthetic_data
        X_normal = X[y == 0]
        model = AnomalyAutoencoder(latent_dim=16)
        model.fit(X_normal, epochs=2, batch_size=64)
        preds = model.predict(X[:20])
        assert set(np.unique(preds)).issubset({0, 1})

    def test_evaluate_metrics(self, synthetic_data):
        X, y = synthetic_data
        X_normal = X[y == 0]
        model = AnomalyAutoencoder(latent_dim=16)
        model.fit(X_normal, epochs=2, batch_size=64)
        y_binary = (y != 0).astype(int)
        metrics = model.evaluate(X, y_binary)
        for key in ("accuracy", "f1", "recall", "mse", "threshold"):
            assert key in metrics


# ── Ensemble tests ───────────────────────────────────────────────

class TestEnsemble:
    def test_predict_single(self, split_data):
        X_tr, X_te, y_tr, y_te = split_data
        ens = EnsembleIDS(device="cpu")
        ens.fit(X_tr, y_tr, epochs=2, batch_size=64)
        result = ens.predict_single(X_te[0])
        assert "label" in result
        assert "confidence" in result
        assert "is_attack" in result
        assert "vae_score" in result
        assert "cnn_probabilities" in result

    def test_evaluate_all_submodels(self, split_data):
        X_tr, X_te, y_tr, y_te = split_data
        ens = EnsembleIDS(device="cpu")
        ens.fit(X_tr, y_tr, epochs=2, batch_size=64)
        metrics = ens.evaluate(X_te, y_te)
        assert "ensemble" in metrics
        assert "cnn" in metrics
        assert "lstm" in metrics
        assert "vae" in metrics
        em = metrics["ensemble"]
        for key in ("accuracy", "f1_macro", "recall_macro", "mse", "confusion_matrix"):
            assert key in em


# ── Metrics utilities tests ──────────────────────────────────────

class TestMetrics:
    def test_ids_metrics(self):
        y_true = np.array([0, 0, 1, 1, 2, 0])
        y_pred = np.array([0, 1, 1, 0, 2, 0])
        m = compute_ids_metrics(y_true, y_pred)
        assert "detection_rate" in m
        assert "false_alarm_rate" in m
        assert 0 <= m["detection_rate"] <= 1
        assert 0 <= m["false_alarm_rate"] <= 1

    def test_per_class_metrics(self):
        y_true = np.array([0, 1, 2, 0, 1])
        y_pred = np.array([0, 1, 0, 0, 2])
        per = compute_per_class_metrics(y_true, y_pred, num_classes=3)
        assert "Normal" in per
        assert "DoS" in per

    def test_model_evaluator_full(self):
        rng = np.random.default_rng(42)
        n = 200
        y_true = rng.integers(0, NUM_CLASSES, n)
        y_pred = rng.integers(0, NUM_CLASSES, n)
        y_proba = rng.dirichlet(np.ones(NUM_CLASSES), n).astype(np.float32)
        ev = ModelEvaluator(model_name="test", dropout_rate=0.3)
        report = ev.evaluate(y_true, y_pred, y_proba)
        assert report["accuracy"] >= 0
        assert "mse" in report
        assert "roc_auc" in report
        assert "ids_metrics" in report
        assert "per_class" in report

    def test_evaluator_compare(self):
        reports = [
            {"model": "CNN",  "accuracy": 0.92, "f1_macro": 0.90, "recall_macro": 0.88, "precision_macro": 0.91, "mse": 0.01, "ids_metrics": {"detection_rate": 0.97, "false_alarm_rate": 0.02}, "dropout_rate": 0.4},
            {"model": "LSTM", "accuracy": 0.91, "f1_macro": 0.89, "recall_macro": 0.87, "precision_macro": 0.90, "mse": 0.012, "ids_metrics": {"detection_rate": 0.95, "false_alarm_rate": 0.03}, "dropout_rate": 0.4},
        ]
        summary = ModelEvaluator.compare(reports)
        assert "CNN" in summary
        assert "LSTM" in summary


# ── IDS integration tests ────────────────────────────────────────

class TestSnortIntegration:
    def test_parse_fast_alert(self):
        line = (
            "01/15-12:34:56.789012  [**] [1:1000002:1] SYN Flood Detected [**] "
            "[Classification: Attempted Denial of Service] [Priority: 2] "
            "{TCP} 10.0.0.5:54321 -> 192.168.1.1:80"
        )
        alert = SnortIDS.parse_fast_alert(line)
        assert alert is not None
        assert alert.src_ip == "10.0.0.5"
        assert alert.dst_ip == "192.168.1.1"
        assert alert.sid == 1000002
        assert alert.attack_class == 1  # DoS from SID_CLASS_MAP

    def test_parse_invalid_line(self):
        assert SnortIDS.parse_fast_alert("not an alert") is None

    def test_alert_stats(self):
        snort = SnortIDS()
        assert snort.get_alert_count() == 0
        stats = snort.get_alert_stats()
        assert stats["total"] == 0


class TestSuricataIntegration:
    def test_from_eve_alert(self):
        record = {
            "event_type": "alert",
            "src_ip": "192.168.1.50", "src_port": 4444,
            "dest_ip": "10.0.0.1",   "dest_port": 22,
            "proto": "TCP",
            "alert": {"action": "allowed", "gid": 1, "signature_id": 2400001,
                      "rev": 3, "signature": "ET EXPLOIT SSH scan", "category": "Exploit", "severity": 1},
            "flow": {"pkts_toserver": 5, "pkts_toclient": 0, "bytes_toserver": 300, "bytes_toclient": 0},
        }
        alert = SuricataAlert.from_eve(record)
        assert alert is not None
        assert alert.src_ip == "192.168.1.50"
        assert alert.attack_class == 4   # U2R from SID range 2400000-2499999

    def test_from_eve_non_alert(self):
        assert SuricataAlert.from_eve({"event_type": "dns"}) is None

    def test_extract_flow_features(self):
        record = {
            "event_type": "alert",
            "src_ip": "1.2.3.4", "src_port": 80,
            "dest_ip": "5.6.7.8", "dest_port": 443,
            "proto": "TCP",
            "alert": {"gid": 1, "signature_id": 100, "rev": 1, "severity": 2, "action": "allowed"},
            "flow": {"pkts_toserver": 3, "pkts_toclient": 2, "bytes_toserver": 150, "bytes_toclient": 80},
        }
        alert = SuricataAlert.from_eve(record)
        features = SuricataIDS.extract_flow_features(alert)
        assert features["proto_tcp"] == 1
        assert features["pkts_toserver"] == 3
