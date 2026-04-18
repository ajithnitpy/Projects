"""
RRD → Deep Learning feature engineering pipeline.

Converts raw RRD time-series (bytes/packets/errors per second) into
fixed-length 78-float feature vectors that the CNN / LSTM / VAE ensemble
already expects.

Feature extraction strategy
-----------------------------
For each RRD fetch window we compute statistical aggregates per DS
column, then concatenate them into a single row vector.  For the LSTM
we also build sliding-window sequences of consecutive windows.

Per-DS statistical features (10 features × up to 8 DS columns = 80,
truncated/padded to 78):
  [0]  mean           – baseline traffic level
  [1]  std            – variability / burstiness
  [2]  min
  [3]  max
  [4]  p95            – 95th-percentile (detects spikes)
  [5]  rate_of_change – mean abs Δ between consecutive samples
  [6]  skewness       – distribution asymmetry
  [7]  kurtosis       – tail heaviness (anomaly indicator)
  [8]  zero_frac      – fraction of zero values (link down / no traffic)
  [9]  spike_frac     – fraction of values > mean + 3σ  (burst / DoS)

Security heuristics appended as extra features:
  [78]  upload_ratio   = bytes_out / (bytes_in + 1)   > 1 → data exfil
  [79]  error_rate     = errors / (pkts_in + 1)
  [80]  connection_rate = conn / (duration + 1)

These are sliced back to 78 features after all features are assembled.

Labelling (for supervised training from labelled RRD directories)
-----------------------------------------------------------------
RRD directories under Cacti / Collectd are named by host or interface.
Users can pass a label_fn callable or a label_map dict keyed by
file name stem to assign attack labels (0-4).

Attack label convention (matches the existing ensemble):
  0 = Normal  1 = DoS  2 = Probe  3 = R2L  4 = U2R
"""

import re
import logging
from pathlib import Path
from typing import Callable, Optional, Union

import numpy as np
from scipy.stats import skew, kurtosis

from app.utils.rrd_reader import RRDFetch, RRDReader, RRDDirectoryScanner

logger = logging.getLogger(__name__)

NUM_FEATURES = 78          # model input width
STATS_PER_DS = 10          # number of stat features per DS column
MAX_DS = NUM_FEATURES // STATS_PER_DS   # = 7 DS columns fit cleanly

# Attack class labels
NORMAL = 0
DOS = 1
PROBE = 2
R2L = 3
U2R = 4

# Heuristic pattern → label (applied to RRD file path stems)
_PATH_LABEL_RE: list[tuple[re.Pattern, int]] = [
    (re.compile(r"(dos|flood|syn|icmp_flood|udpflood)", re.I), DOS),
    (re.compile(r"(scan|probe|nmap|sweep)",              re.I), PROBE),
    (re.compile(r"(r2l|brute|ftp|ssh_auth)",             re.I), R2L),
    (re.compile(r"(u2r|priv|exploit|root)",              re.I), U2R),
]


# ------------------------------------------------------------------
# Statistical feature extraction
# ------------------------------------------------------------------

def _safe_stat(arr: np.ndarray, fn) -> float:
    """Call fn(arr) and return 0.0 on any error (e.g. empty/constant array)."""
    try:
        v = float(fn(arr))
        return v if np.isfinite(v) else 0.0
    except Exception:
        return 0.0


def extract_stats(series: np.ndarray) -> np.ndarray:
    """
    Compute the 10 security-relevant statistics for a single DS column.

    series : 1-D float array (already NaN-filled, per-second rates)
    Returns a length-10 float32 array.
    """
    if len(series) == 0:
        return np.zeros(STATS_PER_DS, dtype=np.float32)

    s = series.astype(np.float64)
    mean_v = _safe_stat(s, np.mean)
    std_v  = _safe_stat(s, np.std)

    feat = np.array([
        mean_v,
        std_v,
        _safe_stat(s, np.min),
        _safe_stat(s, np.max),
        _safe_stat(s, lambda x: np.percentile(x, 95)),
        _safe_stat(np.abs(np.diff(s)), np.mean) if len(s) > 1 else 0.0,
        _safe_stat(s, skew),
        _safe_stat(s, kurtosis),
        float(np.mean(s == 0)),
        float(np.mean(s > mean_v + 3 * std_v)) if std_v > 0 else 0.0,
    ], dtype=np.float32)
    return feat


def rrd_fetch_to_vector(fetch: RRDFetch, num_features: int = NUM_FEATURES) -> np.ndarray:
    """
    Convert a single RRDFetch (one file, one time window) to a
    fixed-length float32 feature vector.

    Steps:
      1. Compute STATS_PER_DS statistics per DS column.
      2. Concatenate all DS stats into one long vector.
      3. Pad / truncate to num_features.
    """
    ds_count = fetch.values.shape[1] if fetch.values.ndim == 2 else 1
    parts = []

    for col_idx in range(ds_count):
        col = fetch.values[:, col_idx] if fetch.values.ndim == 2 else fetch.values
        parts.append(extract_stats(col))

    vec = np.concatenate(parts, dtype=np.float32)

    # Security ratio features appended at end if room exists
    if "bytes_in" in fetch.ds_names and "bytes_out" in fetch.ds_names:
        bi_idx = fetch.ds_names.index("bytes_in")
        bo_idx = fetch.ds_names.index("bytes_out")
        bi = float(np.nanmean(fetch.values[:, bi_idx]))
        bo = float(np.nanmean(fetch.values[:, bo_idx]))
        upload_ratio = bo / (bi + 1)
        vec = np.append(vec, np.float32(upload_ratio))

    # Pad or truncate
    if len(vec) >= num_features:
        return vec[:num_features]
    padded = np.zeros(num_features, dtype=np.float32)
    padded[:len(vec)] = vec
    return padded


# ------------------------------------------------------------------
# Sequence builder (for LSTM)
# ------------------------------------------------------------------

def build_sequences(
    vectors: np.ndarray,
    seq_len: int = 10,
) -> np.ndarray:
    """
    Build overlapping sequences from a matrix of row-vectors.

    vectors : (N, num_features)
    Returns  : (N - seq_len + 1, seq_len, num_features)
    """
    N, F = vectors.shape
    if N < seq_len:
        raise ValueError(f"Need at least {seq_len} samples for seq_len={seq_len}, got {N}")
    seqs = np.stack([vectors[i: i + seq_len] for i in range(N - seq_len + 1)])
    return seqs.astype(np.float32)


# ------------------------------------------------------------------
# Labelling helpers
# ------------------------------------------------------------------

def label_from_path(path: Union[str, Path]) -> int:
    """Infer attack label from the file path stem using regex heuristics."""
    stem = Path(path).stem
    for pattern, label in _PATH_LABEL_RE:
        if pattern.search(stem):
            return label
    return NORMAL


# ------------------------------------------------------------------
# Main feature engineering class
# ------------------------------------------------------------------

class RRDFeatureEngineer:
    """
    Converts a directory of .rrd files into training arrays (X, y)
    ready for the EnsembleIDS or individual CNN/LSTM/VAE models.

    Parameters
    ----------
    reader        : RRDReader instance (controls CF, NaN fill, etc.)
    num_features  : Output feature vector length (default 78).
    label_fn      : Optional callable(Path) → int for custom labelling.
    label_map     : Optional {stem: label} dict override.
    lookback_sec  : Fetch window in seconds per file (default 1 hour).
    window_step   : Slide each window by this many seconds for
                    multi-window sampling per file (0 = one window only).
    """

    def __init__(
        self,
        reader: Optional[RRDReader] = None,
        num_features: int = NUM_FEATURES,
        label_fn: Optional[Callable[[Path], int]] = None,
        label_map: Optional[dict[str, int]] = None,
        lookback_sec: int = 3600,
        window_step: int = 0,
    ):
        self.reader = reader or RRDReader(nan_fill=0.0)
        self.num_features = num_features
        self.label_fn = label_fn or label_from_path
        self.label_map = label_map or {}
        self.lookback_sec = lookback_sec
        self.window_step = window_step

    # ------------------------------------------------------------------
    # Single-file processing
    # ------------------------------------------------------------------

    def file_to_vectors(
        self,
        rrd_path: Union[str, Path],
        start: Optional[int] = None,
        end: Optional[int] = None,
    ) -> tuple[np.ndarray, int]:
        """
        Extract feature vector(s) from a single .rrd file.

        Returns (X, label) where:
          X     : (W, num_features) — W windows from this file
          label : integer class
        """
        import time
        now = int(time.time())
        start = start or (now - self.lookback_sec)
        end = end or now

        path = Path(rrd_path)
        label_from_map = self.label_map.get(path.stem)
        label = label_from_map if label_from_map is not None else self.label_fn(path)

        if self.window_step > 0:
            vectors = self._multi_window(path, start, end)
        else:
            fetch = self.reader.fetch(path, start=start, end=end)
            vec = rrd_fetch_to_vector(fetch, self.num_features)
            vectors = vec.reshape(1, -1)

        return vectors, label

    def _multi_window(
        self,
        path: Path,
        start: int,
        end: int,
    ) -> np.ndarray:
        """Slide a lookback window across [start, end] and collect vectors."""
        import time as _time
        win_start = start
        vecs = []
        while win_start + self.lookback_sec <= end:
            win_end = win_start + self.lookback_sec
            try:
                fetch = self.reader.fetch(path, start=win_start, end=win_end)
                vecs.append(rrd_fetch_to_vector(fetch, self.num_features))
            except Exception as exc:
                logger.debug("Window fetch failed %s [%d-%d]: %s", path, win_start, win_end, exc)
            win_start += self.window_step

        return np.vstack(vecs) if vecs else np.zeros((1, self.num_features), dtype=np.float32)

    # ------------------------------------------------------------------
    # Directory-level processing
    # ------------------------------------------------------------------

    def directory_to_dataset(
        self,
        directory: Union[str, Path],
        start: Optional[int] = None,
        end: Optional[int] = None,
        file_pattern: str = "**/*.rrd",
        max_files: int = 0,
    ) -> tuple[np.ndarray, np.ndarray]:
        """
        Scan a directory, load all .rrd files, and return (X, y) arrays.

        X : (N, num_features)   float32
        y : (N,)                int64 class labels
        """
        scanner = RRDDirectoryScanner(
            reader=self.reader,
            file_pattern=file_pattern,
            max_files=max_files,
            lookback_sec=self.lookback_sec,
        )
        rrd_paths = scanner.scan(directory)

        X_list, y_list = [], []
        for p in rrd_paths:
            try:
                vecs, label = self.file_to_vectors(p, start=start, end=end)
                X_list.append(vecs)
                y_list.extend([label] * len(vecs))
                logger.debug("Loaded %s → %d vectors, label=%d", p.name, len(vecs), label)
            except Exception as exc:
                logger.warning("Failed %s: %s", p, exc)

        if not X_list:
            logger.warning("No RRD data loaded from %s", directory)
            return np.empty((0, self.num_features), dtype=np.float32), np.empty(0, dtype=np.int64)

        X = np.vstack(X_list).astype(np.float32)
        y = np.array(y_list, dtype=np.int64)
        logger.info("RRD dataset: %d samples from %d files", len(X), len(X_list))
        return X, y

    # ------------------------------------------------------------------
    # Live single-file inference (no label needed)
    # ------------------------------------------------------------------

    def live_vector(
        self,
        rrd_path: Union[str, Path],
        lookback_sec: Optional[int] = None,
    ) -> np.ndarray:
        """
        Compute the feature vector for the most-recent window of one RRD file.
        Useful for real-time inference triggered by a file-system watcher.

        Returns shape (num_features,).
        """
        import time
        now = int(time.time())
        lb = lookback_sec or self.lookback_sec
        fetch = self.reader.fetch(rrd_path, start=now - lb, end=now)
        return rrd_fetch_to_vector(fetch, self.num_features)


# ------------------------------------------------------------------
# Convenience: load directory → classify with ensemble
# ------------------------------------------------------------------

def classify_rrd_directory(
    directory: Union[str, Path],
    ensemble,
    label_map: Optional[dict[str, int]] = None,
    file_pattern: str = "**/*.rrd",
    lookback_sec: int = 3600,
    window_step: int = 0,
    verbose: bool = True,
) -> list[dict]:
    """
    End-to-end helper: scan a directory, extract features, run AI classification.

    Parameters
    ----------
    directory   : Path to .rrd file tree.
    ensemble    : Trained EnsembleIDS instance.
    label_map   : Optional {stem: label} for evaluation mode.
    Returns a list of dicts, one per .rrd file.
    """
    from pathlib import Path as _Path

    engineer = RRDFeatureEngineer(
        label_map=label_map or {},
        lookback_sec=lookback_sec,
        window_step=window_step,
    )

    scanner = RRDDirectoryScanner(file_pattern=file_pattern)
    paths = scanner.scan(directory)
    results = []

    for rrd_path in paths:
        try:
            vec = engineer.live_vector(rrd_path, lookback_sec=lookback_sec)
            prediction = ensemble.predict_single(vec)
            row = {
                "file": str(rrd_path),
                "stem": _Path(rrd_path).stem,
                **prediction,
            }
            if label_map or True:
                row["true_label"] = engineer.label_fn(_Path(rrd_path))
            if verbose:
                status = "ATTACK" if prediction["is_attack"] else "normal"
                logger.info(
                    "%-40s  %-8s  %-10s  conf=%.2f  vae=%.4f",
                    _Path(rrd_path).name[:40],
                    status,
                    prediction["attack_name"],
                    prediction["confidence"],
                    prediction.get("vae_score", 0),
                )
            results.append(row)
        except Exception as exc:
            logger.warning("Classification failed for %s: %s", rrd_path, exc)
            results.append({"file": str(rrd_path), "error": str(exc)})

    return results
