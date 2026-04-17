"""
Network traffic feature engineering for SDN/IoT IDS/IPS.

Handles:
  - NSL-KDD dataset parsing and encoding
  - CIC-IDS-2018 CSV parsing
  - Raw packet dict → feature vector conversion (for live SDN flows)
  - Label encoding / decoding
  - Train/test split with stratification
"""

import numpy as np
import pandas as pd
import logging
from pathlib import Path
from typing import Optional
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split

logger = logging.getLogger(__name__)

# Attack categories → integer label
ATTACK_MAP = {
    # Normal
    "normal": 0,
    # DoS
    "back": 1, "land": 1, "neptune": 1, "pod": 1,
    "smurf": 1, "teardrop": 1, "udpstorm": 1, "mailbomb": 1,
    # Probe
    "ipsweep": 2, "mscan": 2, "nmap": 2, "portsweep": 2, "saint": 2, "satan": 2,
    # R2L
    "ftp_write": 3, "guess_passwd": 3, "imap": 3, "multihop": 3,
    "named": 3, "phf": 3, "sendmail": 3, "snmpgetattack": 3,
    "snmpguess": 3, "spy": 3, "warezclient": 3, "warezmaster": 3,
    "xlock": 3, "xsnoop": 3,
    # U2R
    "buffer_overflow": 4, "httptunnel": 4, "loadmodule": 4,
    "perl": 4, "ps": 4, "rootkit": 4, "sqlattack": 4, "xterm": 4,
}

# NSL-KDD column names
NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes",
    "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
    "num_failed_logins", "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty",
]

CATEGORICAL_COLS = ["protocol_type", "service", "flag"]


class TrafficPreprocessor:
    """
    Preprocessing pipeline for network traffic datasets.

    Supports NSL-KDD and CIC-IDS-2018 formats, plus a generic
    packet-dict → vector converter for live SDN traffic.
    """

    def __init__(self, num_features: int = 78):
        self.num_features = num_features
        self.scaler = StandardScaler()
        self.label_encoders: dict[str, LabelEncoder] = {}
        self._fitted = False
        self._feature_names: list[str] = []

    # ------------------------------------------------------------------
    # NSL-KDD
    # ------------------------------------------------------------------

    def load_nsl_kdd(self, path: str, fit: bool = True) -> tuple[np.ndarray, np.ndarray]:
        df = pd.read_csv(path, header=None, names=NSL_KDD_COLUMNS)
        df = df.drop(columns=["difficulty"], errors="ignore")

        # Encode labels
        df["label"] = df["label"].str.lower().map(
            lambda x: ATTACK_MAP.get(x, ATTACK_MAP.get(x.split("_")[0], 0))
        )
        y = df["label"].values.astype(np.int64)
        df = df.drop(columns=["label"])

        # Encode categoricals
        for col in CATEGORICAL_COLS:
            if col in df.columns:
                if fit:
                    le = LabelEncoder()
                    df[col] = le.fit_transform(df[col].astype(str))
                    self.label_encoders[col] = le
                else:
                    le = self.label_encoders.get(col)
                    if le:
                        df[col] = df[col].astype(str).map(
                            lambda v, _le=le: (
                                _le.transform([v])[0]
                                if v in _le.classes_
                                else 0
                            )
                        )
                    else:
                        df[col] = 0

        X = df.values.astype(np.float32)

        # Pad or truncate to self.num_features
        X = self._pad_or_truncate(X)

        if fit:
            X = self.scaler.fit_transform(X).astype(np.float32)
            self._feature_names = list(df.columns)
            self._fitted = True
        else:
            X = self.scaler.transform(X).astype(np.float32)

        logger.info("NSL-KDD loaded: %d samples, %d features", len(X), X.shape[1])
        return X, y

    # ------------------------------------------------------------------
    # CIC-IDS-2018 (CSV with header)
    # ------------------------------------------------------------------

    def load_cic_ids(self, path: str, fit: bool = True) -> tuple[np.ndarray, np.ndarray]:
        df = pd.read_csv(path)
        df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]

        label_col = next((c for c in df.columns if "label" in c), None)
        if not label_col:
            raise ValueError("No label column found in CIC-IDS CSV")

        # Encode labels
        raw_labels = df[label_col].str.strip().str.lower()
        y = raw_labels.map(lambda x: 0 if x in ("benign", "normal") else 1).values.astype(np.int64)
        df = df.drop(columns=[label_col])

        # Drop non-numeric & infinite
        df = df.select_dtypes(include=[np.number])
        df = df.replace([np.inf, -np.inf], np.nan)
        df = df.fillna(df.median(numeric_only=True))

        X = df.values.astype(np.float32)
        X = self._pad_or_truncate(X)

        if fit:
            X = self.scaler.fit_transform(X).astype(np.float32)
            self._fitted = True
        else:
            X = self.scaler.transform(X).astype(np.float32)

        logger.info("CIC-IDS loaded: %d samples, %d features", len(X), X.shape[1])
        return X, y

    # ------------------------------------------------------------------
    # Live packet dict → feature vector
    # ------------------------------------------------------------------

    def packet_to_vector(self, packet: dict) -> np.ndarray:
        """
        Convert a raw packet/flow dict (from Ryu PacketIn or scapy) to a
        fixed-length float32 numpy vector for model inference.

        Expected keys (all optional, default 0):
          src_ip, dst_ip, src_port, dst_port, proto, length, ttl,
          tcp_flags, icmp_type, flow_duration, pkt_count, byte_count, …
        """
        proto_map = {"tcp": 6, "udp": 17, "icmp": 1}
        proto_str = str(packet.get("proto", "tcp")).lower()
        proto_num = proto_map.get(proto_str, 0)

        vec = np.zeros(self.num_features, dtype=np.float32)
        vec[0] = float(packet.get("duration", 0))
        vec[1] = float(proto_num)
        vec[2] = float(packet.get("src_port", 0))
        vec[3] = float(packet.get("dst_port", 0))
        vec[4] = float(packet.get("src_bytes", packet.get("length", 0)))
        vec[5] = float(packet.get("dst_bytes", 0))
        vec[6] = float(packet.get("pkt_count", 1))
        vec[7] = float(packet.get("byte_count", packet.get("length", 0)))
        vec[8] = float(packet.get("ttl", 64))
        vec[9] = float(packet.get("tcp_flags", 0))
        vec[10] = float(packet.get("icmp_type", 0))
        vec[11] = float(packet.get("flow_duration", 0))
        vec[12] = float(packet.get("in_port", 0))

        if self._fitted:
            vec = self.scaler.transform(vec.reshape(1, -1)).flatten().astype(np.float32)
        return vec

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _pad_or_truncate(self, X: np.ndarray) -> np.ndarray:
        n, d = X.shape
        if d >= self.num_features:
            return X[:, :self.num_features]
        padded = np.zeros((n, self.num_features), dtype=X.dtype)
        padded[:, :d] = X
        return padded

    def train_test_split(
        self,
        X: np.ndarray,
        y: np.ndarray,
        test_size: float = 0.2,
        random_state: int = 42,
    ) -> tuple:
        return train_test_split(X, y, test_size=test_size, stratify=y, random_state=random_state)

    # ------------------------------------------------------------------
    # Synthetic data generator (for testing without a real dataset)
    # ------------------------------------------------------------------

    @staticmethod
    def generate_synthetic(
        n_samples: int = 10000,
        num_features: int = 78,
        num_classes: int = 5,
        random_state: int = 42,
    ) -> tuple[np.ndarray, np.ndarray]:
        """
        Generate a synthetic labelled dataset that mimics network traffic
        distributions across the 5 attack categories.
        """
        rng = np.random.default_rng(random_state)
        X_list, y_list = [], []

        # Class proportions: mostly normal, then DoS, then others
        proportions = [0.55, 0.25, 0.10, 0.06, 0.04]
        class_means = [
            rng.uniform(0, 1, num_features),      # Normal
            rng.uniform(5, 10, num_features),      # DoS — high byte counts
            rng.uniform(0, 2, num_features),       # Probe
            rng.uniform(1, 3, num_features),       # R2L
            rng.uniform(2, 5, num_features),       # U2R
        ]

        for cls, (prop, mean) in enumerate(zip(proportions, class_means)):
            n = int(n_samples * prop)
            noise = rng.normal(0, 0.5, (n, num_features))
            X_list.append((mean + noise).astype(np.float32))
            y_list.append(np.full(n, cls, dtype=np.int64))

        X = np.vstack(X_list)
        y = np.concatenate(y_list)
        perm = rng.permutation(len(X))
        return X[perm], y[perm]
