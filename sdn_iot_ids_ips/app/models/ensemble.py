"""
Ensemble IDS that combines CNN, LSTM and VAE predictions via weighted voting.

Voting strategy:
  - CNN  and LSTM outputs are multi-class probability vectors.
  - VAE  output is a binary anomaly flag (mapped to class 0/1).
  - Final label is argmax of the weighted sum of CNN + LSTM probabilities,
    overridden to class 1 ("DoS") when the VAE fires AND ensemble
    confidence is below an alert_threshold.
"""

import numpy as np
import logging
from typing import Optional

from app.models.cnn_ids import CNNIntrusionDetector, NUM_CLASSES, ATTACK_LABELS
from app.models.lstm_ids import LSTMIntrusionDetector
from app.models.autoencoder import AnomalyAutoencoder
from sklearn.metrics import (
    accuracy_score, f1_score, recall_score, precision_score,
    confusion_matrix, mean_squared_error, classification_report
)

logger = logging.getLogger(__name__)


class EnsembleIDS:
    """
    Weighted ensemble of CNN + LSTM + VAE for SDN/IoT intrusion detection.

    Parameters
    ----------
    cnn_weight, lstm_weight : float
        Weights for the supervised classifiers (must sum ≤ 1.0).
    vae_weight : float
        Boosting factor applied when VAE detects an anomaly.
    alert_threshold : float
        Minimum ensemble confidence to accept the majority class;
        below this, the VAE anomaly flag overrides to "attack".
    """

    def __init__(
        self,
        cnn_weight: float = 0.45,
        lstm_weight: float = 0.45,
        vae_weight: float = 0.10,
        alert_threshold: float = 0.60,
        device: str = "cpu",
    ):
        self.cnn_weight = cnn_weight
        self.lstm_weight = lstm_weight
        self.vae_weight = vae_weight
        self.alert_threshold = alert_threshold
        self.device = device

        self.cnn = CNNIntrusionDetector()
        self.lstm = LSTMIntrusionDetector()
        self.vae = AnomalyAutoencoder()

        self._models_trained = False

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def fit(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_normal: Optional[np.ndarray] = None,
        epochs: int = 30,
        batch_size: int = 256,
    ) -> dict:
        """
        Train CNN and LSTM on labelled data; train VAE on normal-only subset.
        If X_normal is not supplied, rows where y_train == 0 are used.
        """
        if X_normal is None:
            X_normal = X_train[y_train == 0]

        logger.info("Training CNN …")
        cnn_history = self.cnn.fit(X_train, y_train, epochs=epochs, batch_size=batch_size, device=self.device)

        logger.info("Training LSTM …")
        lstm_history = self.lstm.fit(X_train, y_train, epochs=epochs, batch_size=batch_size, device=self.device)

        logger.info("Training VAE on %d normal samples …", len(X_normal))
        vae_history = self.vae.fit(X_normal, epochs=epochs, batch_size=batch_size, device=self.device)

        self._models_trained = True
        return {
            "cnn": cnn_history,
            "lstm": lstm_history,
            "vae": vae_history,
        }

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        cnn_proba = self.cnn.predict_proba(X, self.device)    # (N, C)
        lstm_proba = self.lstm.predict_proba(X, self.device)  # (N, C) — may be shorter due to seq

        # VAE anomaly scores → binary flag, expanded to class dimension
        vae_anomaly = self.vae.predict(X, self.device)        # (N,) — 0/1

        # Align lengths (LSTM consumes seq_len-1 leading rows)
        seq_offset = self.lstm.seq_len - 1
        cnn_proba_aligned = cnn_proba[seq_offset:]
        vae_anomaly_aligned = vae_anomaly[seq_offset:]

        # Weighted combination of supervised models
        combined = self.cnn_weight * cnn_proba_aligned + self.lstm_weight * lstm_proba

        # Boost "attack" classes when VAE fires
        attack_boost = np.zeros_like(combined)
        attack_boost[:, 1:] = self.vae_weight                  # boost all non-normal classes
        anomaly_mask = vae_anomaly_aligned.astype(bool)
        combined[anomaly_mask] += attack_boost[anomaly_mask]

        # Re-normalise
        combined = combined / combined.sum(axis=1, keepdims=True)
        return combined

    def predict(self, X: np.ndarray) -> np.ndarray:
        proba = self.predict_proba(X)
        confidence = proba.max(axis=1)
        labels = proba.argmax(axis=1)

        # Override low-confidence predictions to "DoS" (class 1)
        # when VAE still detects anomaly
        vae_anomaly = self.vae.predict(X, self.device)
        seq_offset = self.lstm.seq_len - 1
        vae_anomaly_aligned = vae_anomaly[seq_offset:]

        override_mask = (confidence < self.alert_threshold) & vae_anomaly_aligned.astype(bool)
        labels[override_mask] = 1
        return labels

    # ------------------------------------------------------------------
    # Real-time single-flow prediction
    # ------------------------------------------------------------------

    def predict_single(self, flow_features: np.ndarray) -> dict:
        """
        Predict a single network flow.

        flow_features: 1-D array of length num_features
        Returns a dict with label, confidence, vae_score, attack_name.
        """
        X = flow_features.reshape(1, -1)

        cnn_proba = self.cnn.predict_proba(X, self.device)[0]
        vae_score = float(self.vae.anomaly_score(X, self.device)[0])
        vae_flag = vae_score > self.vae.threshold

        # Simple CNN-only for real-time (no LSTM window available)
        label = int(cnn_proba.argmax())
        confidence = float(cnn_proba.max())

        if vae_flag and confidence < self.alert_threshold:
            label = 1   # escalate to DoS/generic attack
            confidence = max(confidence, 0.5)

        return {
            "label": label,
            "attack_name": ATTACK_LABELS.get(label, "Unknown"),
            "confidence": confidence,
            "is_attack": label != 0,
            "vae_score": vae_score,
            "vae_anomaly": vae_flag,
            "cnn_probabilities": {ATTACK_LABELS[i]: float(p) for i, p in enumerate(cnn_proba)},
        }

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> dict:
        y_pred = self.predict(X_test)
        proba = self.predict_proba(X_test)

        seq_offset = self.lstm.seq_len - 1
        y_test_aligned = y_test[seq_offset:]
        y_onehot = np.eye(NUM_CLASSES)[y_test_aligned]
        mse = mean_squared_error(y_onehot, proba)

        cnn_metrics = self.cnn.evaluate(X_test, y_test, self.device)
        lstm_metrics = self.lstm.evaluate(X_test, y_test, self.device)
        vae_metrics = self.vae.evaluate(X_test, (y_test != 0).astype(int), self.device)

        metrics = {
            "ensemble": {
                "accuracy": accuracy_score(y_test_aligned, y_pred),
                "f1_macro": f1_score(y_test_aligned, y_pred, average="macro", zero_division=0),
                "f1_weighted": f1_score(y_test_aligned, y_pred, average="weighted", zero_division=0),
                "recall_macro": recall_score(y_test_aligned, y_pred, average="macro", zero_division=0),
                "precision_macro": precision_score(y_test_aligned, y_pred, average="macro", zero_division=0),
                "mse": mse,
                "weights": {
                    "cnn": self.cnn_weight,
                    "lstm": self.lstm_weight,
                    "vae": self.vae_weight,
                },
                "dropout_rates": {
                    "cnn": self.cnn.dropout_rate,
                    "lstm": self.lstm.dropout_rate,
                    "vae": self.vae.dropout_rate,
                },
                "confusion_matrix": confusion_matrix(y_test_aligned, y_pred).tolist(),
                "classification_report": classification_report(
                    y_test_aligned, y_pred,
                    target_names=[ATTACK_LABELS[i] for i in range(NUM_CLASSES)],
                    zero_division=0,
                ),
            },
            "cnn": cnn_metrics,
            "lstm": lstm_metrics,
            "vae": vae_metrics,
        }

        logger.info(
            "Ensemble — acc=%.4f  f1=%.4f  recall=%.4f  mse=%.6f",
            metrics["ensemble"]["accuracy"],
            metrics["ensemble"]["f1_macro"],
            metrics["ensemble"]["recall_macro"],
            metrics["ensemble"]["mse"],
        )
        return metrics
