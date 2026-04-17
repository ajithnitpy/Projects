"""
Comprehensive model evaluation utilities for SDN/IoT IDS/IPS.

Computes and formats all evaluation metrics:
  - MSE (mean squared error on probability outputs)
  - Accuracy
  - F1 (macro, weighted, per-class)
  - Recall (macro, per-class)
  - Precision (macro, per-class)
  - Confusion matrix
  - ROC-AUC (one-vs-rest)
  - Detection Rate (DR) / False Positive Rate (FPR) — IDS-specific
  - Dropout rate per model (regularisation transparency)
  - Training curve statistics
"""

import numpy as np
import logging
from typing import Optional
from sklearn.metrics import (
    accuracy_score, f1_score, recall_score, precision_score,
    confusion_matrix, mean_squared_error, classification_report,
    roc_auc_score, roc_curve, precision_recall_curve,
    average_precision_score,
)
from sklearn.preprocessing import label_binarize

logger = logging.getLogger(__name__)

ATTACK_LABELS = {0: "Normal", 1: "DoS", 2: "Probe", 3: "R2L", 4: "U2R"}
NUM_CLASSES = 5


def compute_ids_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    """
    Compute IDS-specific metrics.

    Detection Rate (DR)   = TP / (TP + FN)  =  recall for attack class
    False Alarm Rate (FAR)= FP / (FP + TN)  =  FPR for normal class
    """
    # Binary: 0=normal, 1=attack
    y_true_bin = (y_true != 0).astype(int)
    y_pred_bin = (y_pred != 0).astype(int)

    cm = confusion_matrix(y_true_bin, y_pred_bin, labels=[0, 1])
    if cm.shape == (2, 2):
        tn, fp, fn, tp = cm.ravel()
    else:
        tn = fp = fn = tp = 0

    dr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    far = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "detection_rate": dr,
        "false_alarm_rate": far,
        "true_positives": int(tp),
        "false_positives": int(fp),
        "true_negatives": int(tn),
        "false_negatives": int(fn),
    }


def compute_per_class_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    num_classes: int = NUM_CLASSES,
) -> dict:
    per_class = {}
    for cls in range(num_classes):
        y_t = (y_true == cls).astype(int)
        y_p = (y_pred == cls).astype(int)
        per_class[ATTACK_LABELS.get(cls, str(cls))] = {
            "precision": float(precision_score(y_t, y_p, zero_division=0)),
            "recall": float(recall_score(y_t, y_p, zero_division=0)),
            "f1": float(f1_score(y_t, y_p, zero_division=0)),
            "support": int((y_true == cls).sum()),
        }
    return per_class


def compute_roc_auc(
    y_true: np.ndarray,
    y_proba: np.ndarray,
    num_classes: int = NUM_CLASSES,
) -> dict:
    classes = list(range(num_classes))
    y_bin = label_binarize(y_true, classes=classes)
    roc_aucs = {}
    for i, cls in enumerate(classes):
        if y_bin[:, i].sum() == 0:
            roc_aucs[ATTACK_LABELS.get(cls, str(cls))] = 0.0
            continue
        try:
            roc_aucs[ATTACK_LABELS.get(cls, str(cls))] = float(
                roc_auc_score(y_bin[:, i], y_proba[:, i])
            )
        except Exception:
            roc_aucs[ATTACK_LABELS.get(cls, str(cls))] = 0.0
    macro_auc = float(np.mean(list(roc_aucs.values())))
    return {"per_class": roc_aucs, "macro": macro_auc}


class ModelEvaluator:
    """
    One-stop evaluation helper.  Pass predictions and probabilities,
    get back a fully populated metrics dict.

    Parameters
    ----------
    model_name   : Name tag for logging.
    num_classes  : Number of output classes.
    dropout_rate : Reported dropout used during training.
    """

    def __init__(
        self,
        model_name: str = "model",
        num_classes: int = NUM_CLASSES,
        dropout_rate: float = 0.0,
    ):
        self.model_name = model_name
        self.num_classes = num_classes
        self.dropout_rate = dropout_rate

    def evaluate(
        self,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        y_proba: Optional[np.ndarray] = None,
        training_history: Optional[dict] = None,
    ) -> dict:
        """
        Full evaluation report.

        y_true   : integer class labels (0..num_classes-1)
        y_pred   : integer predicted labels
        y_proba  : (N, num_classes) probability matrix — required for MSE/AUC
        training_history : dict of lists from model.fit() — adds curve stats
        """
        # Core classification metrics
        acc = accuracy_score(y_true, y_pred)
        f1_macro = f1_score(y_true, y_pred, average="macro", zero_division=0)
        f1_weighted = f1_score(y_true, y_pred, average="weighted", zero_division=0)
        recall_macro = recall_score(y_true, y_pred, average="macro", zero_division=0)
        precision_macro = precision_score(y_true, y_pred, average="macro", zero_division=0)

        report = {
            "model": self.model_name,
            "dropout_rate": self.dropout_rate,
            "num_samples": int(len(y_true)),
            "accuracy": float(acc),
            "f1_macro": float(f1_macro),
            "f1_weighted": float(f1_weighted),
            "recall_macro": float(recall_macro),
            "precision_macro": float(precision_macro),
            "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
            "classification_report": classification_report(
                y_true, y_pred,
                target_names=[ATTACK_LABELS.get(i, str(i)) for i in range(self.num_classes)],
                zero_division=0,
            ),
            "per_class": compute_per_class_metrics(y_true, y_pred, self.num_classes),
            "ids_metrics": compute_ids_metrics(y_true, y_pred),
        }

        # Probability-dependent metrics
        if y_proba is not None:
            y_onehot = np.eye(self.num_classes)[y_true]
            report["mse"] = float(mean_squared_error(y_onehot, y_proba))
            report["roc_auc"] = compute_roc_auc(y_true, y_proba, self.num_classes)
        else:
            report["mse"] = None
            report["roc_auc"] = None

        # Training curve statistics
        if training_history:
            report["training_curve"] = self._summarise_history(training_history)

        self._log_summary(report)
        return report

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _summarise_history(history: dict) -> dict:
        summary = {}
        for key, values in history.items():
            if not values:
                continue
            arr = np.array(values, dtype=float)
            summary[key] = {
                "final": float(arr[-1]),
                "best": float(arr.min() if "loss" in key or "mse" in key else arr.max()),
                "mean": float(arr.mean()),
                "std": float(arr.std()),
                "epochs": len(arr),
            }
        return summary

    def _log_summary(self, report: dict) -> None:
        mse_str = f"  mse={report['mse']:.6f}" if report.get("mse") is not None else ""
        dr = report["ids_metrics"]["detection_rate"]
        far = report["ids_metrics"]["false_alarm_rate"]
        logger.info(
            "[%s] acc=%.4f  f1=%.4f  recall=%.4f%s  DR=%.4f  FAR=%.4f  dropout=%.2f",
            report["model"],
            report["accuracy"],
            report["f1_macro"],
            report["recall_macro"],
            mse_str,
            dr,
            far,
            report["dropout_rate"],
        )

    # ------------------------------------------------------------------
    # Comparison utility
    # ------------------------------------------------------------------

    @staticmethod
    def compare(reports: list[dict]) -> dict:
        """
        Compare multiple model evaluation reports side by side.
        Returns a summary table dict keyed by model name.
        """
        summary = {}
        for r in reports:
            name = r.get("model", "unknown")
            summary[name] = {
                "accuracy": r.get("accuracy"),
                "f1_macro": r.get("f1_macro"),
                "recall_macro": r.get("recall_macro"),
                "precision_macro": r.get("precision_macro"),
                "mse": r.get("mse"),
                "detection_rate": r.get("ids_metrics", {}).get("detection_rate"),
                "false_alarm_rate": r.get("ids_metrics", {}).get("false_alarm_rate"),
                "dropout_rate": r.get("dropout_rate"),
            }
        return summary
