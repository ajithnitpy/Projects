"""
Bidirectional LSTM for sequential/temporal intrusion detection in SDN/IoT.

Traffic flows arrive as time-ordered windows; the LSTM captures temporal
dependencies (e.g., slow-scan, multi-step DoS) that CNN cannot.
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

NUM_FEATURES = 78
NUM_CLASSES = 5
SEQ_LEN = 10  # sliding-window length over consecutive flows

ATTACK_LABELS = {0: "Normal", 1: "DoS", 2: "Probe", 3: "R2L", 4: "U2R"}


class LSTMIntrusionDetector(nn.Module):
    """
    Bidirectional LSTM with attention for sequential traffic analysis.

    Input:  (batch, seq_len, num_features)
    Output: (batch, num_classes) logits
    """

    def __init__(
        self,
        num_features: int = NUM_FEATURES,
        num_classes: int = NUM_CLASSES,
        hidden_size: int = 128,
        num_layers: int = 2,
        dropout_rate: float = 0.4,
        seq_len: int = SEQ_LEN,
    ):
        super().__init__()
        self.num_features = num_features
        self.num_classes = num_classes
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.dropout_rate = dropout_rate
        self.seq_len = seq_len

        self.input_proj = nn.Linear(num_features, hidden_size)

        self.lstm = nn.LSTM(
            input_size=hidden_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout_rate if num_layers > 1 else 0.0,
        )

        # Scaled dot-product attention over the sequence
        self.attn_linear = nn.Linear(hidden_size * 2, 1)

        self.classifier = nn.Sequential(
            nn.Linear(hidden_size * 2, 128),
            nn.ReLU(),
            nn.Dropout(dropout_rate),
            nn.Linear(128, num_classes),
        )

        self.scaler = StandardScaler()
        self._is_fitted = False

    # ------------------------------------------------------------------
    # Attention helper
    # ------------------------------------------------------------------

    def _attention(self, lstm_out: torch.Tensor) -> torch.Tensor:
        # lstm_out: (batch, seq, hidden*2)
        scores = self.attn_linear(lstm_out).squeeze(-1)          # (batch, seq)
        weights = F.softmax(scores, dim=1).unsqueeze(-1)          # (batch, seq, 1)
        return (lstm_out * weights).sum(dim=1)                    # (batch, hidden*2)

    # ------------------------------------------------------------------
    # Forward
    # ------------------------------------------------------------------

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (batch, seq_len, num_features)
        x = F.relu(self.input_proj(x))                            # (batch, seq, hidden)
        lstm_out, _ = self.lstm(x)                                # (batch, seq, hidden*2)
        context = self._attention(lstm_out)                       # (batch, hidden*2)
        return self.classifier(context)

    # ------------------------------------------------------------------
    # Data windowing
    # ------------------------------------------------------------------

    @staticmethod
    def create_sequences(X: np.ndarray, y: np.ndarray, seq_len: int):
        """Slide a window of length seq_len over rows; label = last step."""
        xs, ys = [], []
        for i in range(len(X) - seq_len + 1):
            xs.append(X[i: i + seq_len])
            ys.append(y[i + seq_len - 1])
        return np.array(xs, dtype=np.float32), np.array(ys, dtype=np.int64)

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def fit(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        epochs: int = 50,
        batch_size: int = 128,
        lr: float = 1e-3,
        device: str = "cpu",
    ) -> dict:
        device = torch.device(device)
        self.to(device)

        X_scaled = self.scaler.fit_transform(X_train).astype(np.float32)
        self._is_fitted = True

        X_seq, y_seq = self.create_sequences(X_scaled, y_train, self.seq_len)
        dataset = TensorDataset(
            torch.tensor(X_seq).to(device),
            torch.tensor(y_seq).to(device),
        )
        loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

        optimizer = torch.optim.AdamW(self.parameters(), lr=lr, weight_decay=1e-4)
        criterion = nn.CrossEntropyLoss()
        scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

        history = {"loss": [], "accuracy": [], "f1": [], "recall": [], "mse": []}

        self.train()
        for epoch in range(epochs):
            epoch_loss, all_preds, all_targets = 0.0, [], []

            for X_batch, y_batch in loader:
                optimizer.zero_grad()
                logits = self(X_batch)
                loss = criterion(logits, y_batch)
                loss.backward()
                nn.utils.clip_grad_norm_(self.parameters(), max_norm=1.0)
                optimizer.step()

                preds = logits.argmax(dim=1)
                epoch_loss += loss.item() * len(y_batch)
                all_preds.extend(preds.cpu().numpy())
                all_targets.extend(y_batch.cpu().numpy())

            scheduler.step()

            n = len(all_targets)
            avg_loss = epoch_loss / n
            acc = accuracy_score(all_targets, all_preds)
            f1 = f1_score(all_targets, all_preds, average="macro", zero_division=0)
            rec = recall_score(all_targets, all_preds, average="macro", zero_division=0)
            mse = mean_squared_error(all_targets, all_preds)

            history["loss"].append(avg_loss)
            history["accuracy"].append(acc)
            history["f1"].append(f1)
            history["recall"].append(rec)
            history["mse"].append(mse)

            if (epoch + 1) % 10 == 0:
                logger.info(
                    "LSTM epoch %d/%d  loss=%.4f  acc=%.4f  f1=%.4f  recall=%.4f  mse=%.4f",
                    epoch + 1, epochs, avg_loss, acc, f1, rec, mse,
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
        X_seq, _ = self.create_sequences(X, np.zeros(len(X)), self.seq_len)

        with torch.no_grad():
            tensor = torch.tensor(X_seq).to(device)
            return self(tensor).argmax(dim=1).cpu().numpy()

    def predict_proba(self, X: np.ndarray, device: str = "cpu") -> np.ndarray:
        device = torch.device(device)
        self.to(device)
        self.eval()

        if self._is_fitted:
            X = self.scaler.transform(X).astype(np.float32)
        X_seq, _ = self.create_sequences(X, np.zeros(len(X)), self.seq_len)

        with torch.no_grad():
            tensor = torch.tensor(X_seq).to(device)
            return F.softmax(self(tensor), dim=1).cpu().numpy()

    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray, device: str = "cpu") -> dict:
        y_pred = self.predict(X_test, device)
        proba = self.predict_proba(X_test, device)

        # Align y_test with the windowed predictions (last seq_len-1 rows are consumed)
        y_test_aligned = y_test[self.seq_len - 1:]
        y_onehot = np.eye(self.num_classes)[y_test_aligned]
        mse = mean_squared_error(y_onehot, proba)

        metrics = {
            "accuracy": accuracy_score(y_test_aligned, y_pred),
            "f1_macro": f1_score(y_test_aligned, y_pred, average="macro", zero_division=0),
            "f1_weighted": f1_score(y_test_aligned, y_pred, average="weighted", zero_division=0),
            "recall_macro": recall_score(y_test_aligned, y_pred, average="macro", zero_division=0),
            "precision_macro": precision_score(y_test_aligned, y_pred, average="macro", zero_division=0),
            "mse": mse,
            "dropout_rate": self.dropout_rate,
            "confusion_matrix": confusion_matrix(y_test_aligned, y_pred).tolist(),
            "classification_report": classification_report(
                y_test_aligned, y_pred,
                target_names=[ATTACK_LABELS[i] for i in range(self.num_classes)],
                zero_division=0,
            ),
        }

        logger.info(
            "LSTM Evaluation — acc=%.4f  f1=%.4f  recall=%.4f  mse=%.6f",
            metrics["accuracy"], metrics["f1_macro"], metrics["recall_macro"], metrics["mse"],
        )
        return metrics
