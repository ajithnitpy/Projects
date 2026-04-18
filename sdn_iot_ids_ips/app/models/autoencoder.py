"""
Variational Autoencoder (VAE) for unsupervised anomaly detection in IoT traffic.

Trained on normal traffic only; high reconstruction error signals an anomaly.
Threshold is set to the 95th-percentile reconstruction loss on training data.
"""

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import (
    roc_auc_score, average_precision_score, mean_squared_error,
    accuracy_score, f1_score, recall_score, precision_score, confusion_matrix
)
import logging

logger = logging.getLogger(__name__)

NUM_FEATURES = 78


class VAEEncoder(nn.Module):
    def __init__(self, input_dim: int, latent_dim: int, dropout_rate: float):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, 256), nn.ReLU(), nn.Dropout(dropout_rate),
            nn.Linear(256, 128),       nn.ReLU(), nn.Dropout(dropout_rate),
        )
        self.mu_layer = nn.Linear(128, latent_dim)
        self.logvar_layer = nn.Linear(128, latent_dim)

    def forward(self, x):
        h = self.net(x)
        return self.mu_layer(h), self.logvar_layer(h)


class VAEDecoder(nn.Module):
    def __init__(self, latent_dim: int, output_dim: int, dropout_rate: float):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(latent_dim, 128), nn.ReLU(), nn.Dropout(dropout_rate),
            nn.Linear(128, 256),        nn.ReLU(), nn.Dropout(dropout_rate),
            nn.Linear(256, output_dim), nn.Sigmoid(),
        )

    def forward(self, z):
        return self.net(z)


class AnomalyAutoencoder(nn.Module):
    """
    Variational Autoencoder trained on normal SDN/IoT traffic.

    Anomaly score = per-sample reconstruction MSE.
    Binary prediction = score > threshold (set during fit).
    """

    def __init__(
        self,
        num_features: int = NUM_FEATURES,
        latent_dim: int = 32,
        dropout_rate: float = 0.2,
        threshold_percentile: float = 95.0,
    ):
        super().__init__()
        self.num_features = num_features
        self.latent_dim = latent_dim
        self.dropout_rate = dropout_rate
        self.threshold_percentile = threshold_percentile

        self.encoder = VAEEncoder(num_features, latent_dim, dropout_rate)
        self.decoder = VAEDecoder(latent_dim, num_features, dropout_rate)

        self.scaler = MinMaxScaler()
        self.threshold: float = 0.0
        self._is_fitted = False

    # ------------------------------------------------------------------
    # Reparameterisation trick
    # ------------------------------------------------------------------

    @staticmethod
    def _reparameterise(mu: torch.Tensor, logvar: torch.Tensor) -> torch.Tensor:
        std = torch.exp(0.5 * logvar)
        eps = torch.randn_like(std)
        return mu + eps * std

    # ------------------------------------------------------------------
    # Loss = reconstruction + β·KL
    # ------------------------------------------------------------------

    @staticmethod
    def _vae_loss(
        x: torch.Tensor,
        x_recon: torch.Tensor,
        mu: torch.Tensor,
        logvar: torch.Tensor,
        beta: float = 1.0,
    ) -> torch.Tensor:
        recon = F.mse_loss(x_recon, x, reduction="sum")
        kl = -0.5 * torch.sum(1 + logvar - mu.pow(2) - logvar.exp())
        return recon + beta * kl

    # ------------------------------------------------------------------
    # Forward
    # ------------------------------------------------------------------

    def forward(self, x: torch.Tensor):
        mu, logvar = self.encoder(x)
        z = self._reparameterise(mu, logvar)
        x_recon = self.decoder(z)
        return x_recon, mu, logvar

    def reconstruction_error(self, x: torch.Tensor) -> torch.Tensor:
        """Per-sample MSE between input and reconstruction (no grad)."""
        with torch.no_grad():
            x_recon, _, _ = self(x)
            return F.mse_loss(x_recon, x, reduction="none").mean(dim=1)

    # ------------------------------------------------------------------
    # Training (on normal data only)
    # ------------------------------------------------------------------

    def fit(
        self,
        X_normal: np.ndarray,
        epochs: int = 50,
        batch_size: int = 256,
        lr: float = 1e-3,
        beta: float = 1.0,
        device: str = "cpu",
    ) -> dict:
        device = torch.device(device)
        self.to(device)

        X_scaled = self.scaler.fit_transform(X_normal).astype(np.float32)
        self._is_fitted = True

        dataset = TensorDataset(torch.tensor(X_scaled).to(device))
        loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

        optimizer = torch.optim.Adam(self.parameters(), lr=lr, weight_decay=1e-5)
        history = {"loss": [], "recon_mse": []}

        self.train()
        for epoch in range(epochs):
            epoch_loss, n = 0.0, 0
            for (x_batch,) in loader:
                optimizer.zero_grad()
                x_recon, mu, logvar = self(x_batch)
                loss = self._vae_loss(x_batch, x_recon, mu, logvar, beta)
                loss.backward()
                optimizer.step()
                epoch_loss += loss.item()
                n += len(x_batch)

            avg_loss = epoch_loss / n
            # Compute reconstruction MSE on training set for threshold
            with torch.no_grad():
                all_errors = self.reconstruction_error(
                    torch.tensor(X_scaled).to(device)
                ).cpu().numpy()
            recon_mse = float(np.mean(all_errors))
            history["loss"].append(avg_loss)
            history["recon_mse"].append(recon_mse)

            if (epoch + 1) % 10 == 0:
                logger.info(
                    "VAE epoch %d/%d  loss=%.4f  recon_mse=%.6f",
                    epoch + 1, epochs, avg_loss, recon_mse,
                )

        # Set anomaly threshold at percentile of training reconstruction errors
        with torch.no_grad():
            errors = self.reconstruction_error(
                torch.tensor(X_scaled).to(device)
            ).cpu().numpy()
        self.threshold = float(np.percentile(errors, self.threshold_percentile))
        logger.info("Anomaly threshold set to %.6f (p%.0f)", self.threshold, self.threshold_percentile)
        return history

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def anomaly_score(self, X: np.ndarray, device: str = "cpu") -> np.ndarray:
        device = torch.device(device)
        self.to(device)
        self.eval()
        if self._is_fitted:
            X = self.scaler.transform(X).astype(np.float32)
        return self.reconstruction_error(torch.tensor(X).to(device)).cpu().numpy()

    def predict(self, X: np.ndarray, device: str = "cpu") -> np.ndarray:
        scores = self.anomaly_score(X, device)
        return (scores > self.threshold).astype(int)

    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray, device: str = "cpu") -> dict:
        """
        y_test: binary — 0 = normal, 1 = anomaly/attack
        """
        scores = self.anomaly_score(X_test, device)
        y_pred = (scores > self.threshold).astype(int)
        mse = mean_squared_error(y_test, scores)

        metrics = {
            "accuracy": accuracy_score(y_test, y_pred),
            "f1": f1_score(y_test, y_pred, zero_division=0),
            "recall": recall_score(y_test, y_pred, zero_division=0),
            "precision": precision_score(y_test, y_pred, zero_division=0),
            "mse": mse,
            "roc_auc": roc_auc_score(y_test, scores) if len(np.unique(y_test)) > 1 else 0.0,
            "avg_precision": average_precision_score(y_test, scores) if len(np.unique(y_test)) > 1 else 0.0,
            "threshold": self.threshold,
            "dropout_rate": self.dropout_rate,
            "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        }

        logger.info(
            "VAE Evaluation — acc=%.4f  f1=%.4f  recall=%.4f  roc_auc=%.4f  mse=%.6f",
            metrics["accuracy"], metrics["f1"], metrics["recall"],
            metrics["roc_auc"], metrics["mse"],
        )
        return metrics
