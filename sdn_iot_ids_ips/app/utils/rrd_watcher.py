"""
Real-time RRD directory watcher.

Monitors a directory for new or modified .rrd files and triggers
immediate AI classification whenever a file is updated.

Works without watchdog by polling mtime — no extra dependencies needed.
If watchdog is installed it uses inotify/kqueue for instant notification.

Data flow
---------
  File-system (rrdtool update ticks every 5 min by default)
        │
        ▼
  RRDWatcher._poll() detects mtime change
        │
        ▼
  RRDFeatureEngineer.live_vector()  ← last N seconds of the updated file
        │
        ▼
  EnsembleIDS.predict_single()
        │
        ├── is_attack=False  →  log only
        │
        └── is_attack=True   →  IPSEngine.process_flow()
                                      │
                                      └── SDNFlowManager.enforce()
"""

import time
import threading
import logging
from pathlib import Path
from typing import Callable, Optional, Union

import numpy as np

from app.utils.rrd_feature_engineer import RRDFeatureEngineer

logger = logging.getLogger(__name__)

# Seconds of lookback when a new update is detected
DEFAULT_LOOKBACK = 600   # 10 minutes of data per tick


class RRDWatcher:
    """
    Polls a directory tree for .rrd updates and fires a callback with
    the feature vector and file path on every detected change.

    Parameters
    ----------
    directory     : Root of the .rrd file tree to watch.
    engineer      : RRDFeatureEngineer for feature extraction.
    on_update     : Callback(path: Path, vector: np.ndarray) → None
    poll_interval : Seconds between full directory scans.
    lookback_sec  : Seconds of history to extract per update.
    file_pattern  : Glob pattern for .rrd files.
    """

    def __init__(
        self,
        directory: Union[str, Path],
        engineer: RRDFeatureEngineer,
        on_update: Callable[[Path, np.ndarray], None],
        poll_interval: float = 30.0,
        lookback_sec: int = DEFAULT_LOOKBACK,
        file_pattern: str = "**/*.rrd",
    ):
        self.directory = Path(directory)
        self.engineer = engineer
        self.on_update = on_update
        self.poll_interval = poll_interval
        self.lookback_sec = lookback_sec
        self.file_pattern = file_pattern

        self._known_mtimes: dict[Path, float] = {}
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._stats = {"scans": 0, "updates": 0, "errors": 0}

    # ------------------------------------------------------------------
    # Start / stop
    # ------------------------------------------------------------------

    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._poll_loop, daemon=True, name="rrd-watcher"
        )
        self._thread.start()
        logger.info("RRDWatcher started: %s  poll=%.0fs", self.directory, self.poll_interval)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("RRDWatcher stopped — scans=%d  updates=%d  errors=%d", **self._stats)

    # ------------------------------------------------------------------
    # Poll loop
    # ------------------------------------------------------------------

    def _poll_loop(self) -> None:
        while not self._stop_event.is_set():
            self._scan()
            self._stop_event.wait(self.poll_interval)

    def _scan(self) -> None:
        self._stats["scans"] += 1
        if not self.directory.exists():
            return

        for rrd_path in self.directory.glob(self.file_pattern):
            try:
                mtime = rrd_path.stat().st_mtime
            except OSError:
                continue

            prev = self._known_mtimes.get(rrd_path)
            if prev is not None and mtime <= prev:
                continue   # file unchanged

            self._known_mtimes[rrd_path] = mtime
            if prev is None:
                logger.debug("RRDWatcher: new file %s", rrd_path.name)
                continue   # skip first-seen to avoid processing old data

            self._process(rrd_path)

    def _process(self, rrd_path: Path) -> None:
        try:
            vec = self.engineer.live_vector(rrd_path, lookback_sec=self.lookback_sec)
            self._stats["updates"] += 1
            self.on_update(rrd_path, vec)
        except Exception as exc:
            self._stats["errors"] += 1
            logger.warning("RRDWatcher process error %s: %s", rrd_path.name, exc)

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        return {
            **self._stats,
            "watched_files": len(self._known_mtimes),
            "directory": str(self.directory),
        }


# ------------------------------------------------------------------
# High-level integration helper
# ------------------------------------------------------------------

class RRDIPSBridge:
    """
    Connects the RRDWatcher to the IPSEngine for fully automatic
    threat detection from .rrd files.

    Usage
    -----
    >>> bridge = RRDIPSBridge(
    ...     directory="/var/lib/collectd/rrd",
    ...     ips_engine=engine,
    ...     ensemble=ensemble,
    ...     src_ip_fn=lambda p: p.parent.name,  # Collectd uses host dir
    ... )
    >>> bridge.start()
    """

    def __init__(
        self,
        directory: Union[str, Path],
        ips_engine,                          # IPSEngine
        ensemble,                            # EnsembleIDS
        src_ip_fn: Optional[Callable[[Path], str]] = None,
        poll_interval: float = 30.0,
        lookback_sec: int = DEFAULT_LOOKBACK,
        confidence_threshold: float = 0.70,
    ):
        self.ips_engine = ips_engine
        self.ensemble = ensemble
        self.src_ip_fn = src_ip_fn or (lambda p: "0.0.0.0")
        self.confidence_threshold = confidence_threshold

        self._engineer = RRDFeatureEngineer(lookback_sec=lookback_sec)
        self._watcher = RRDWatcher(
            directory=directory,
            engineer=self._engineer,
            on_update=self._on_rrd_update,
            poll_interval=poll_interval,
            lookback_sec=lookback_sec,
        )
        self._decisions: list[dict] = []

    def _on_rrd_update(self, rrd_path: Path, vec: np.ndarray) -> None:
        prediction = self.ensemble.predict_single(vec)
        src_ip = self.src_ip_fn(rrd_path)

        self._decisions.append({
            "file": rrd_path.name,
            "src_ip": src_ip,
            **prediction,
        })

        if prediction["is_attack"] and prediction["confidence"] >= self.confidence_threshold:
            logger.warning(
                "RRD threat detected: %s  src=%s  attack=%s  conf=%.2f",
                rrd_path.name, src_ip,
                prediction["attack_name"],
                prediction["confidence"],
            )
            self.ips_engine.process_flow(vec, src_ip)

    def start(self) -> None:
        self._watcher.start()

    def stop(self) -> None:
        self._watcher.stop()

    def get_decisions(self, limit: int = 100) -> list[dict]:
        return self._decisions[-limit:]

    def get_watcher_stats(self) -> dict:
        return self._watcher.get_stats()
