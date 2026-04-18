"""
CNN-based Intrusion Detection System for SDN/IoT network traffic.

Treats each network flow feature vector as a 1D signal and applies
convolutional filters to detect spatial patterns associated with attacks.
"""

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, f1_score, recall_score, precision_score,
    confusion_matrix, mean_squared_error, classification_report
)
import logging

logger = logging.getLogger(__name__)

# NSL-KDD / CIC-IDS-2018 compatible feature count
NUM_FEATURES = 78
NUM_CLASSES = 5  # Normal, DoS, Probe, R2L, U2R

ATTACK_LABELS = {
    0: "Normal",
    1: "DoS",
    2: "Probe",
    3: "R2L",
    4: "U2R",
}


class CNNBlock(nn.Module):
    def __init__(self, in_channels, out_channels, kernel_size=3, dropout_rate=0.3):
        super().__init__()
        self.conv = nn.Conv1d(in_channels, out_channels, kernel_size, padding=kernel_size // 2)
        self.bn = nn.BatchNorm1d(out_channels)
        self.dropout = nn.Dropout(dropout_rate)

    def forward(self, x):
        return self.dropout(F.relu(self.bn(self.conv(x))))


class CNNIntrusionDetector(nn.Module):
    """
    1-D CNN for network intrusion detection.

    Input shape: (batch, 1, num_features)
    Output shape: (batch, num_classes) — raw logits
    """

    def __init__(
        self,
        num_features: int = NUM_FEATURES,
        num_classes: int = NUM_CLASSES,
        dropout_rate: float = 0.4,
    ):
        super().__init__()
        self.num_features = num_features
        self.num_classes = num_classes
        self.dropout_rate = dropout_rate

        self.block1 = CNNBlock(1, 64, kernel_size=3, dropout_rate=dropout_rate)
        self.block2 = CNNBlock(64, 128, kernel_size=3, dropout_rate=dropout_rate)
        self.block3 = CNNBlock(128, 256, kernel_size=3, dropout_rate=dropout_rate)

        self.global_avg_pool = nn.AdaptiveAvgPool1d(1)

        self.classifier = nn.Sequential(
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Dropout(dropout_rate),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Dropout(dropout_rate),
            nn.Linear(64, num_classes),
        )

        self.scaler = StandardScaler()
        self._is_fitted = False

    # ------------------------------------------------------------------
    # Forward
    # ------------------------------------------------------------------

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (batch, num_features)  →  (batch, 1, num_features)
        if x.dim() == 2:
            x = x.unsqueeze(1)
        x = self.block1(x)
        x = self.block2(x)
        x = self.block3(x)
        x = self.global_avg_pool(x).squeeze(-1)   # (batch, 256)
        return self.classifier(x)

    # ------------------------------------------------------------------
    # Training helpers
    # ------------------------------------------------------------------

    def fit(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        epochs: int = 50,
        batch_size: int = 256,
        lr: float = 1e-3,
        device: str = "cpu",
    ) -> dict:
        device = torch.device(device)
        self.to(device)

        X_scaled = self.scaler.fit_transform(X_train).astype(np.float32)
        self._is_fitted = True

        dataset = TensorDataset(
            torch.tensor(X_scaled).to(device),
            torch.tensor(y_train, dtype=torch.long).to(device),
        )
        loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

        optimizer = torch.optim.Adam(self.parameters(), lr=lr, weight_decay=1e-4)
        criterion = nn.CrossEntropyLoss()
        scheduler = torch.optim.lr_scheduler.StepLR(optimizer, step_size=10, gamma=0.5)

        history = {"loss": [], "accuracy": [], "mse": []}

        self.train()
        for epoch in range(epochs):
            epoch_loss, correct, total = 0.0, 0, 0
            all_preds, all_targets = [], []

            for X_batch, y_batch in loader:
                optimizer.zero_grad()
                logits = self(X_batch)
                loss = criterion(logits, y_batch)
                loss.backward()
                optimizer.step()

                preds = logits.argmax(dim=1)
                epoch_loss += loss.item() * len(y_batch)
                correct += (preds == y_batch).sum().item()
                total += len(y_batch)
                all_preds.extend(preds.cpu().numpy())
                all_targets.extend(y_batch.cpu().numpy())

            scheduler.step()

            avg_loss = epoch_loss / total
            acc = correct / total
            mse = mean_squared_error(all_targets, all_preds)
            history["loss"].append(avg_loss)
            history["accuracy"].append(acc)
            history["mse"].append(mse)

            if (epoch + 1) % 10 == 0:
                logger.info(
                    "CNN epoch %d/%d  loss=%.4f  acc=%.4f  mse=%.4f",
                    epoch + 1, epochs, avg_loss, acc, mse,
                )

        return history

    # ------------------------------------------------------------------
    # Inference & evaluation
    # ------------------------------------------------------------------

    def predict(self, X: np.ndarray, device: str = "cpu") -> np.ndarray:
        device = torch.device(device)
        self.to(device)
        self.eval()

        if self._is_fitted:
            X = self.scaler.transform(X).astype(np.float32)
        else:
            X = X.astype(np.float32)

        with torch.no_grad():
            tensor = torch.tensor(X).to(device)
            logits = self(tensor)
            return logits.argmax(dim=1).cpu().numpy()

    def predict_proba(self, X: np.ndarray, device: str = "cpu") -> np.ndarray:
        device = torch.device(device)
        self.to(device)
        self.eval()

        if self._is_fitted:
            X = self.scaler.transform(X).astype(np.float32)
        else:
            X = X.astype(np.float32)

        with torch.no_grad():
            tensor = torch.tensor(X).to(device)
            return F.softmax(self(tensor), dim=1).cpu().numpy()

    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray, device: str = "cpu") -> dict:
        y_pred = self.predict(X_test, device)
        proba = self.predict_proba(X_test, device)

        # Per-class one-hot for MSE
        y_onehot = np.eye(self.num_classes)[y_test]
        mse = mean_squared_error(y_onehot, proba)

        metrics = {
            "accuracy": accuracy_score(y_test, y_pred),
            "f1_macro": f1_score(y_test, y_pred, average="macro", zero_division=0),
            "f1_weighted": f1_score(y_test, y_pred, average="weighted", zero_division=0),
            "recall_macro": recall_score(y_test, y_pred, average="macro", zero_division=0),
            "precision_macro": precision_score(y_test, y_pred, average="macro", zero_division=0),
            "mse": mse,
            "dropout_rate": self.dropout_rate,
            "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
            "classification_report": classification_report(
                y_test, y_pred,
                target_names=[ATTACK_LABELS[i] for i in range(self.num_classes)],
                zero_division=0,
            ),
        }

        logger.info(
            "CNN Evaluation — acc=%.4f  f1=%.4f  recall=%.4f  mse=%.6f",
            metrics["accuracy"], metrics["f1_macro"], metrics["recall_macro"], metrics["mse"],
        )
        return metrics
