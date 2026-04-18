"""
Unit tests for RRD reader, feature engineering, and watcher.

Tests use synthetic in-memory data (no real .rrd files needed).
A minimal mock RRDFetch is constructed directly to test the
feature engineering pipeline without needing rrdtool installed.
"""

import sys
import os
import time
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import numpy as np
import pytest

from app.utils.rrd_reader import RRDFetch, RRDReader, RRDDirectoryScanner
from app.utils.rrd_feature_engineer import (
    extract_stats, rrd_fetch_to_vector, build_sequences,
    label_from_path, RRDFeatureEngineer, NUM_FEATURES, STATS_PER_DS,
    NORMAL, DOS, PROBE, R2L, U2R,
)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def make_fetch(
    n_samples: int = 120,
    n_ds: int = 2,
    ds_names: list = None,
    seed: int = 42,
) -> RRDFetch:
    """Create a synthetic RRDFetch that mimics network traffic data."""
    rng = np.random.default_rng(seed)
    now = int(time.time())
    timestamps = np.arange(now - n_samples * 300, now, 300, dtype=np.int64)[:n_samples]
    values = rng.exponential(1000, (n_samples, n_ds)).astype(np.float64)
    return RRDFetch(
        path="/fake/traffic.rrd",
        cf="AVERAGE",
        start=int(timestamps[0]) - 300,
        end=int(timestamps[-1]),
        step=300,
        ds_names=ds_names or [f"ds{i}" for i in range(n_ds)],
        timestamps=timestamps,
        values=values,
        last_update=int(timestamps[-1]),
    )


# ------------------------------------------------------------------
# extract_stats tests
# ------------------------------------------------------------------

class TestExtractStats:
    def test_output_shape(self):
        series = np.random.rand(100).astype(np.float64)
        feat = extract_stats(series)
        assert feat.shape == (STATS_PER_DS,)
        assert feat.dtype == np.float32

    def test_empty_series(self):
        feat = extract_stats(np.array([]))
        assert feat.shape == (STATS_PER_DS,)
        assert np.all(feat == 0)

    def test_spike_fraction_high_traffic(self):
        # Inject obvious spikes — spike_frac should be > 0
        series = np.ones(100, dtype=np.float64)
        series[10] = 1000.0
        series[50] = 1000.0
        feat = extract_stats(series)
        spike_frac = feat[9]
        assert spike_frac > 0

    def test_zero_fraction_all_zeros(self):
        feat = extract_stats(np.zeros(50))
        zero_frac = feat[8]
        assert zero_frac == pytest.approx(1.0)

    def test_constant_series(self):
        feat = extract_stats(np.full(60, 500.0))
        assert feat[1] == pytest.approx(0.0, abs=1e-5)   # std = 0
        assert feat[5] == pytest.approx(0.0, abs=1e-5)   # rate_of_change = 0


# ------------------------------------------------------------------
# rrd_fetch_to_vector tests
# ------------------------------------------------------------------

class TestRRDFetchToVector:
    def test_output_length(self):
        fetch = make_fetch(n_ds=3)
        vec = rrd_fetch_to_vector(fetch)
        assert vec.shape == (NUM_FEATURES,)
        assert vec.dtype == np.float32

    def test_all_nan_filled(self):
        fetch = make_fetch(n_ds=2)
        fetch.values[:] = np.nan
        vec = rrd_fetch_to_vector(fetch)
        # After NaN fill the reader sets nan_fill=0; vector should be finite
        assert np.all(np.isfinite(vec))

    def test_upload_ratio_appended_for_bytes_ds(self):
        fetch = make_fetch(n_ds=2, ds_names=["bytes_in", "bytes_out"])
        vec = rrd_fetch_to_vector(fetch)
        assert vec.shape == (NUM_FEATURES,)

    def test_single_ds(self):
        fetch = make_fetch(n_ds=1)
        vec = rrd_fetch_to_vector(fetch)
        assert vec.shape == (NUM_FEATURES,)

    def test_many_ds_truncated(self):
        fetch = make_fetch(n_ds=20)
        vec = rrd_fetch_to_vector(fetch)
        assert vec.shape == (NUM_FEATURES,)


# ------------------------------------------------------------------
# build_sequences tests
# ------------------------------------------------------------------

class TestBuildSequences:
    def test_shape(self):
        X = np.random.rand(50, NUM_FEATURES).astype(np.float32)
        seqs = build_sequences(X, seq_len=10)
        assert seqs.shape == (41, 10, NUM_FEATURES)

    def test_insufficient_data(self):
        X = np.random.rand(5, NUM_FEATURES).astype(np.float32)
        with pytest.raises(ValueError):
            build_sequences(X, seq_len=10)

    def test_dtype(self):
        X = np.ones((30, NUM_FEATURES), dtype=np.float64)
        seqs = build_sequences(X, seq_len=5)
        assert seqs.dtype == np.float32


# ------------------------------------------------------------------
# label_from_path tests
# ------------------------------------------------------------------

class TestLabelFromPath:
    @pytest.mark.parametrize("name,expected", [
        ("dos_attack_host1.rrd",    DOS),
        ("syn_flood_eth0.rrd",      DOS),
        ("udpflood_test.rrd",       DOS),
        ("nmap_scan_results.rrd",   PROBE),
        ("portsweep_192168.rrd",    PROBE),
        ("ftp_brute_force.rrd",     R2L),
        ("ssh_auth_failures.rrd",   R2L),
        ("exploit_rootkit.rrd",     U2R),
        ("priv_escalation.rrd",     U2R),
        ("normal_traffic.rrd",      NORMAL),
        ("router1_eth0.rrd",        NORMAL),
    ])
    def test_label_heuristics(self, name, expected):
        assert label_from_path(Path(name)) == expected


# ------------------------------------------------------------------
# RRDFeatureEngineer tests
# ------------------------------------------------------------------

class TestRRDFeatureEngineer:
    def test_live_vector_shape(self, monkeypatch):
        """live_vector should return (NUM_FEATURES,) without real rrdtool."""
        fetch = make_fetch(n_ds=4)

        def fake_fetch(self, path, start=None, end=None, cf=None):
            return fetch

        monkeypatch.setattr(RRDReader, "fetch", fake_fetch)
        eng = RRDFeatureEngineer()
        vec = eng.live_vector("/fake/test.rrd", lookback_sec=3600)
        assert vec.shape == (NUM_FEATURES,)

    def test_file_to_vectors_single_window(self, monkeypatch):
        fetch = make_fetch(n_ds=2)

        def fake_fetch(self, path, start=None, end=None, cf=None):
            return fetch

        monkeypatch.setattr(RRDReader, "fetch", fake_fetch)
        eng = RRDFeatureEngineer(window_step=0)
        vecs, label = eng.file_to_vectors("/fake/normal_traffic.rrd")
        assert vecs.shape == (1, NUM_FEATURES)
        assert label == NORMAL

    def test_file_to_vectors_multi_window(self, monkeypatch):
        fetch = make_fetch(n_ds=2)

        def fake_fetch(self, path, start=None, end=None, cf=None):
            return fetch

        monkeypatch.setattr(RRDReader, "fetch", fake_fetch)
        eng = RRDFeatureEngineer(lookback_sec=3600, window_step=600)
        # 3600-second lookback with 600-second step → 6 windows possible
        vecs, label = eng.file_to_vectors(
            "/fake/dos_attack.rrd",
            start=int(time.time()) - 7200,
            end=int(time.time()),
        )
        assert vecs.ndim == 2
        assert vecs.shape[1] == NUM_FEATURES
        assert label == DOS

    def test_directory_to_dataset(self, monkeypatch, tmp_path):
        """Create fake .rrd files and check that the dataset shape is correct."""
        # Create dummy files in labelled subdirs
        for subdir, label_name in [("normal", "normal"), ("dos", "dos_attack")]:
            (tmp_path / subdir).mkdir()
            (tmp_path / subdir / f"{label_name}.rrd").touch()

        fetch = make_fetch(n_ds=2)

        def fake_fetch(self, path, start=None, end=None, cf=None):
            return fetch

        monkeypatch.setattr(RRDReader, "fetch", fake_fetch)
        eng = RRDFeatureEngineer()
        X, y = eng.directory_to_dataset(tmp_path)
        assert X.shape[1] == NUM_FEATURES
        assert len(X) == len(y)

    def test_label_map_override(self, monkeypatch):
        fetch = make_fetch(n_ds=2)

        def fake_fetch(self, path, start=None, end=None, cf=None):
            return fetch

        monkeypatch.setattr(RRDReader, "fetch", fake_fetch)
        eng = RRDFeatureEngineer(label_map={"my_router": PROBE})
        _, label = eng.file_to_vectors("/var/rrd/my_router.rrd")
        assert label == PROBE


# ------------------------------------------------------------------
# RRDDirectoryScanner tests
# ------------------------------------------------------------------

class TestRRDDirectoryScanner:
    def test_scan_finds_rrd_files(self, tmp_path):
        (tmp_path / "a.rrd").touch()
        (tmp_path / "subdir").mkdir()
        (tmp_path / "subdir" / "b.rrd").touch()
        (tmp_path / "c.txt").touch()

        scanner = RRDDirectoryScanner()
        paths = scanner.scan(tmp_path)
        stems = [p.stem for p in paths]
        assert "a" in stems
        assert "b" in stems
        assert "c" not in stems

    def test_max_files_limit(self, tmp_path):
        for i in range(10):
            (tmp_path / f"file{i}.rrd").touch()
        scanner = RRDDirectoryScanner(max_files=3)
        paths = scanner.scan(tmp_path)
        assert len(paths) == 3

    def test_empty_directory(self, tmp_path):
        scanner = RRDDirectoryScanner()
        paths = scanner.scan(tmp_path)
        assert paths == []


# ------------------------------------------------------------------
# End-to-end: classify_rrd_directory with mock ensemble
# ------------------------------------------------------------------

class TestClassifyRRDDirectory:
    def test_classify_directory(self, monkeypatch, tmp_path):
        (tmp_path / "normal.rrd").touch()
        (tmp_path / "dos_flood.rrd").touch()

        fetch = make_fetch(n_ds=2)

        def fake_fetch(self, path, start=None, end=None, cf=None):
            return fetch

        monkeypatch.setattr(RRDReader, "fetch", fake_fetch)

        class MockEnsemble:
            def predict_single(self, vec):
                return {
                    "label": 0,
                    "attack_name": "Normal",
                    "confidence": 0.85,
                    "is_attack": False,
                    "vae_score": 0.001,
                    "vae_anomaly": False,
                    "cnn_probabilities": {},
                }

        from app.utils.rrd_feature_engineer import classify_rrd_directory
        results = classify_rrd_directory(tmp_path, MockEnsemble(), verbose=False)
        assert len(results) == 2
        assert all("file" in r for r in results)
        assert all("attack_name" in r for r in results if "error" not in r)
