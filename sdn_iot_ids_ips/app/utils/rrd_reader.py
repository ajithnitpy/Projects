"""
RRD (Round Robin Database) file reader for security threat detection.

RRD files are produced by network monitoring tools:
  Cacti, Collectd, Nagios/Nagiosgraph, MRTG, Munin, Prometheus exporters, etc.

They store dense time-series of network counters such as:
  - Bytes/packets in/out per interface
  - TCP connection counts, SYN rates
  - ICMP / UDP flood counters
  - CPU / memory (IoT device health)
  - DNS query rates, HTTP request rates
  - NetFlow-derived aggregates

Reading strategy (two-tier)
-----------------------------
1. Primary  : python-rrdtool  (C binding, fast)
   Install  : pip install rrdtool
2. Fallback : subprocess call to the `rrdtool` CLI binary
   Install  : apt install rrdtool  /  yum install rrdtool

Both paths return identical data structures.

RRD data source types
----------------------
COUNTER  - monotonically increasing (wraps at 32/64-bit boundary) e.g. ifInOctets
GAUGE    - absolute value e.g. CPU%
DERIVE   - signed rate of change
ABSOLUTE - reset-on-read counter

All values returned as per-second rates (rrdtool normalises COUNTER/DERIVE).
"""

import os
import time
import subprocess
import logging
from pathlib import Path
from typing import Optional, Union
from dataclasses import dataclass, field

import numpy as np

logger = logging.getLogger(__name__)

# Attempt to import the C binding; fall back to CLI
try:
    import rrdtool as _rrdtool
    _HAVE_RRDTOOL_LIB = True
    logger.debug("python-rrdtool C binding available")
except ImportError:
    _HAVE_RRDTOOL_LIB = False
    logger.info("python-rrdtool not installed — using rrdtool CLI fallback")


# ------------------------------------------------------------------
# Data containers
# ------------------------------------------------------------------

@dataclass
class RRDInfo:
    """Metadata extracted from an RRD file header."""
    path: str
    last_update: int           # Unix timestamp of last written sample
    step: int                  # base step in seconds
    data_sources: list[str]    # DS names
    ds_types: dict[str, str]   # DS name → type (COUNTER, GAUGE, …)
    rras: list[dict]           # Round Robin Archives (CF, rows, pdp_per_row)


@dataclass
class RRDFetch:
    """Data returned by an rrdtool FETCH operation."""
    path: str
    cf: str                    # consolidation function used
    start: int
    end: int
    step: int
    ds_names: list[str]
    timestamps: np.ndarray     # shape (T,)
    values: np.ndarray         # shape (T, len(ds_names))  — NaN where no data
    last_update: int = 0


# ------------------------------------------------------------------
# Core reader class
# ------------------------------------------------------------------

class RRDReader:
    """
    Reads one or many .rrd files and returns structured numpy arrays.

    Parameters
    ----------
    prefer_cf : Consolidation Function to prefer when fetching.
                One of "AVERAGE", "MAX", "MIN", "LAST".
    resolution: Desired time resolution in seconds (0 = RRD native step).
    nan_fill   : Value used to replace NaN entries (None keeps NaN).
    """

    VALID_CF = ("AVERAGE", "MAX", "MIN", "LAST")

    def __init__(
        self,
        prefer_cf: str = "AVERAGE",
        resolution: int = 0,
        nan_fill: Optional[float] = 0.0,
    ):
        if prefer_cf not in self.VALID_CF:
            raise ValueError(f"prefer_cf must be one of {self.VALID_CF}")
        self.prefer_cf = prefer_cf
        self.resolution = resolution
        self.nan_fill = nan_fill

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def info(self, rrd_path: Union[str, Path]) -> RRDInfo:
        """Return metadata for a single RRD file."""
        path = str(rrd_path)
        if _HAVE_RRDTOOL_LIB:
            return self._info_lib(path)
        return self._info_cli(path)

    def fetch(
        self,
        rrd_path: Union[str, Path],
        start: Optional[int] = None,
        end: Optional[int] = None,
        cf: Optional[str] = None,
    ) -> RRDFetch:
        """
        Fetch time-series data from a single RRD file.

        start / end : Unix timestamps (default: last 1 hour)
        cf          : Consolidation function (overrides prefer_cf)
        """
        path = str(rrd_path)
        now = int(time.time())
        start = start or (now - 3600)
        end = end or now
        cf = cf or self.prefer_cf

        if _HAVE_RRDTOOL_LIB:
            result = self._fetch_lib(path, cf, start, end)
        else:
            result = self._fetch_cli(path, cf, start, end)

        if self.nan_fill is not None:
            result.values = np.where(np.isnan(result.values), self.nan_fill, result.values)

        return result

    # ------------------------------------------------------------------
    # python-rrdtool C binding implementations
    # ------------------------------------------------------------------

    @staticmethod
    def _info_lib(path: str) -> RRDInfo:
        raw = _rrdtool.info(path)
        step = raw.get("step", 300)
        last_update = raw.get("last_update", 0)

        ds_names, ds_types = [], {}
        rras = []
        i = 0
        while f"ds[{i}].type" in raw or any(k.startswith(f"ds[") for k in raw):
            # rrdtool returns dict keys like ds[traffic_in].type
            break
        # Parse DS entries (key format: "ds[name].field")
        for k, v in raw.items():
            if k.startswith("ds[") and k.endswith("].type"):
                ds_name = k[3: k.index("]")]
                if ds_name not in ds_names:
                    ds_names.append(ds_name)
                ds_types[ds_name] = v

        # Parse RRA entries
        rra_idx = 0
        while True:
            prefix = f"rra[{rra_idx}]"
            if f"{prefix}.cf" not in raw:
                break
            rras.append({
                "cf": raw[f"{prefix}.cf"],
                "rows": raw.get(f"{prefix}.rows", 0),
                "pdp_per_row": raw.get(f"{prefix}.pdp_per_row", 1),
            })
            rra_idx += 1

        return RRDInfo(
            path=path,
            last_update=last_update,
            step=step,
            data_sources=ds_names,
            ds_types=ds_types,
            rras=rras,
        )

    @staticmethod
    def _fetch_lib(path: str, cf: str, start: int, end: int) -> RRDFetch:
        (t_start, t_end, t_step), ds_names, rows = _rrdtool.fetch(
            path, cf,
            "--start", str(start),
            "--end", str(end),
        )
        ts = np.arange(t_start + t_step, t_end + t_step, t_step, dtype=np.int64)
        n = min(len(rows), len(ts))
        values = np.array(
            [[v if v is not None else np.nan for v in row] for row in rows[:n]],
            dtype=np.float64,
        )
        last_update = int(time.time())
        try:
            raw_info = _rrdtool.info(path)
            last_update = raw_info.get("last_update", last_update)
        except Exception:
            pass
        return RRDFetch(
            path=path, cf=cf,
            start=t_start, end=t_end, step=t_step,
            ds_names=list(ds_names),
            timestamps=ts[:n],
            values=values,
            last_update=last_update,
        )

    # ------------------------------------------------------------------
    # rrdtool CLI fallback implementations
    # ------------------------------------------------------------------

    @staticmethod
    def _run(cmd: list[str]) -> str:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            raise RuntimeError(f"rrdtool error: {result.stderr.strip()}")
        return result.stdout

    @classmethod
    def _info_cli(cls, path: str) -> RRDInfo:
        out = cls._run(["rrdtool", "info", path])
        raw: dict = {}
        for line in out.splitlines():
            if " = " in line:
                k, _, v = line.partition(" = ")
                raw[k.strip()] = v.strip().strip('"')

        step = int(raw.get("step", 300))
        last_update = int(raw.get("last_update", 0))
        ds_names, ds_types, rras = [], {}, []

        for k, v in raw.items():
            if k.startswith("ds[") and k.endswith("].type"):
                name = k[3: k.index("]")]
                if name not in ds_names:
                    ds_names.append(name)
                ds_types[name] = v

        rra_idx = 0
        while True:
            prefix = f"rra[{rra_idx}]"
            cf_key = f"{prefix}.cf"
            if cf_key not in raw:
                break
            rras.append({
                "cf": raw[cf_key],
                "rows": int(raw.get(f"{prefix}.rows", 0)),
                "pdp_per_row": int(raw.get(f"{prefix}.pdp_per_row", 1)),
            })
            rra_idx += 1

        return RRDInfo(
            path=path,
            last_update=last_update,
            step=step,
            data_sources=ds_names,
            ds_types=ds_types,
            rras=rras,
        )

    @classmethod
    def _fetch_cli(cls, path: str, cf: str, start: int, end: int) -> RRDFetch:
        out = cls._run([
            "rrdtool", "fetch", path, cf,
            "--start", str(start),
            "--end", str(end),
        ])
        lines = [l for l in out.splitlines() if l.strip()]
        if not lines:
            raise RuntimeError(f"No data returned for {path}")

        # First line: DS names
        ds_names = lines[0].split()
        timestamps, rows = [], []
        t_start = t_end = t_step = 0

        for line in lines[1:]:
            parts = line.split(":")
            if len(parts) < 2:
                continue
            ts = int(parts[0].strip())
            vals = []
            for v in parts[1].split():
                try:
                    vals.append(float(v) if v.lower() != "nan" else np.nan)
                except ValueError:
                    vals.append(np.nan)
            if vals:
                timestamps.append(ts)
                rows.append(vals)

        if not timestamps:
            raise RuntimeError(f"Could not parse fetch output for {path}")

        ts_arr = np.array(timestamps, dtype=np.int64)
        val_arr = np.array(rows, dtype=np.float64)
        t_step = int(ts_arr[1] - ts_arr[0]) if len(ts_arr) > 1 else 300
        t_start = int(ts_arr[0]) - t_step
        t_end = int(ts_arr[-1])

        # Get last_update from info
        try:
            info = cls._info_cli(path)
            last_update = info.last_update
        except Exception:
            last_update = t_end

        return RRDFetch(
            path=path, cf=cf,
            start=t_start, end=t_end, step=t_step,
            ds_names=ds_names,
            timestamps=ts_arr,
            values=val_arr,
            last_update=last_update,
        )


# ------------------------------------------------------------------
# Directory scanner
# ------------------------------------------------------------------

class RRDDirectoryScanner:
    """
    Recursively scans a directory tree for .rrd files and loads them
    into a unified list of RRDFetch objects.

    Parameters
    ----------
    reader       : RRDReader instance.
    file_pattern : Glob pattern inside the directory (default "**/*.rrd").
    max_files    : Hard cap on number of files processed (0 = unlimited).
    lookback_sec : How far back to fetch data (default 1 hour).
    """

    def __init__(
        self,
        reader: Optional[RRDReader] = None,
        file_pattern: str = "**/*.rrd",
        max_files: int = 0,
        lookback_sec: int = 3600,
    ):
        self.reader = reader or RRDReader()
        self.file_pattern = file_pattern
        self.max_files = max_files
        self.lookback_sec = lookback_sec

    def scan(self, directory: Union[str, Path]) -> list[Path]:
        """Return sorted list of .rrd file paths found under directory."""
        root = Path(directory)
        paths = sorted(root.glob(self.file_pattern))
        if self.max_files:
            paths = paths[: self.max_files]
        logger.info("Found %d .rrd files under %s", len(paths), directory)
        return paths

    def load_all(
        self,
        directory: Union[str, Path],
        start: Optional[int] = None,
        end: Optional[int] = None,
    ) -> list[RRDFetch]:
        """
        Fetch data from every .rrd file found in directory.
        Returns a list of RRDFetch objects (failed files are skipped).
        """
        now = int(time.time())
        start = start or (now - self.lookback_sec)
        end = end or now
        results = []
        for path in self.scan(directory):
            try:
                fetch = self.reader.fetch(path, start=start, end=end)
                results.append(fetch)
            except Exception as exc:
                logger.warning("Skipping %s: %s", path, exc)
        logger.info("Loaded %d RRD files successfully", len(results))
        return results

    def load_info_all(self, directory: Union[str, Path]) -> list[RRDInfo]:
        """Return metadata for all .rrd files (no data fetch)."""
        infos = []
        for path in self.scan(directory):
            try:
                infos.append(self.reader.info(path))
            except Exception as exc:
                logger.warning("Info failed for %s: %s", path, exc)
        return infos
