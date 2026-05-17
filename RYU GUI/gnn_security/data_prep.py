"""
Data preparation for the HGAGN model.

Goals:
  • Convert a CICIDS-style flow CSV (or live Ryu flow stats) into a PyG Data
    object: x [N, F], edge_index [2, E], edge_weight [E], y [N].
  • Build an *IP-graph*: nodes are endpoints, edges are observed flows.
  • Aggregate flow statistics per node (mean/std/min/max of packet/byte/dur).

The aggregation is novel in that we add **entropy-based features** computed
over a node's outgoing flow distribution; many IoT attacks (Mirai scanning,
slowloris) generate skewed distributions that simple averages miss.

Usage:
  python -m gnn_security.data_prep --input data/cicids.csv --out data/graph.pt
"""
from __future__ import annotations
import argparse
import logging
import os
from collections import defaultdict

import numpy as np

log = logging.getLogger(__name__)

ATTACK_CLASSES = ["benign", "ddos", "mirai", "scan", "brute_force", "exfil"]
CLASS_TO_IDX = {c: i for i, c in enumerate(ATTACK_CLASSES)}

# Feature columns expected in the flow record (raw):
RAW_FEATURES = [
    "packet_count", "byte_count", "duration_sec",
    "proto", "src_port", "dst_port",
]
# Aggregated features per node (length = 16)
NODE_FEATURE_DIM = 16


def _entropy(values: np.ndarray) -> float:
    """Shannon entropy on a non-negative array, normalised."""
    if values.size == 0:
        return 0.0
    p = values.astype(float)
    s = p.sum()
    if s <= 0:
        return 0.0
    p = p / s
    p = p[p > 0]
    return float(-(p * np.log(p)).sum())


def aggregate_node_features(flows_by_node: dict) -> dict:
    """Aggregate raw flow records into per-node fixed-size feature vectors."""
    feats = {}
    for ip, flows in flows_by_node.items():
        pkts = np.array([f["packet_count"] for f in flows], dtype=float)
        byts = np.array([f["byte_count"] for f in flows], dtype=float)
        durs = np.array([f["duration_sec"] for f in flows], dtype=float)
        protos = np.array([f["proto"] for f in flows], dtype=float)
        ports = np.array([f["dst_port"] for f in flows], dtype=float)

        vec = np.array([
            pkts.mean() if pkts.size else 0,
            pkts.std()  if pkts.size else 0,
            byts.mean() if byts.size else 0,
            byts.std()  if byts.size else 0,
            durs.mean() if durs.size else 0,
            durs.max()  if durs.size else 0,
            (protos == 6).mean()  if protos.size else 0,  # TCP fraction
            (protos == 17).mean() if protos.size else 0,  # UDP fraction
            (protos == 1).mean()  if protos.size else 0,  # ICMP fraction
            float(len(flows)),                            # flow count
            _entropy(pkts),
            _entropy(byts),
            _entropy(ports),
            float(np.unique(ports).size),                 # port diversity
            float(np.unique([f["dst_ip"] for f in flows]).size),  # fan-out
            float(np.unique([f["src_ip"] for f in flows]).size),  # fan-in
        ], dtype=np.float32)
        feats[ip] = vec
    return feats


def build_graph_from_flows(flows: list, labels: dict | None = None):
    """Build (x, edge_index, edge_weight, y, ip_to_idx) from a list of flow dicts.

    Each flow dict must include src_ip, dst_ip, packet_count, byte_count,
    duration_sec, proto, src_port, dst_port.
    """
    # group by node
    by_src = defaultdict(list)
    nodes = set()
    for f in flows:
        nodes.add(f["src_ip"])
        nodes.add(f["dst_ip"])
        by_src[f["src_ip"]].append(f)
        # include reverse for aggregation completeness
        by_src[f["dst_ip"]].append(f)

    ip_to_idx = {ip: i for i, ip in enumerate(sorted(nodes))}
    feats = aggregate_node_features(by_src)
    x = np.zeros((len(ip_to_idx), NODE_FEATURE_DIM), dtype=np.float32)
    for ip, idx in ip_to_idx.items():
        x[idx] = feats.get(ip, np.zeros(NODE_FEATURE_DIM, dtype=np.float32))

    edges_src, edges_dst, edges_w = [], [], []
    for f in flows:
        s = ip_to_idx[f["src_ip"]]; d = ip_to_idx[f["dst_ip"]]
        edges_src.append(s); edges_dst.append(d)
        edges_w.append(float(f["byte_count"]) + 1.0)
    edge_index = np.array([edges_src, edges_dst], dtype=np.int64)
    edge_weight = np.log1p(np.array(edges_w, dtype=np.float32))

    y = None
    if labels:
        y = np.zeros(len(ip_to_idx), dtype=np.int64)
        for ip, lab in labels.items():
            if ip in ip_to_idx:
                y[ip_to_idx[ip]] = CLASS_TO_IDX.get(lab, 0)

    return x, edge_index, edge_weight, y, ip_to_idx


def synthesize_dataset(n_benign: int = 80, n_attackers: int = 20):
    """Create a synthetic CICIDS-like dataset for training/CI tests.

    Useful when you don't have the real CICIDS or BoT-IoT data on hand.
    """
    rng = np.random.default_rng(0)
    flows = []
    labels = {}

    benign_ips = [f"10.0.0.{i+1}" for i in range(n_benign)]
    for ip in benign_ips:
        labels[ip] = "benign"
    for src in benign_ips:
        for _ in range(rng.integers(2, 6)):
            dst = rng.choice(benign_ips)
            if dst == src:
                continue
            flows.append({
                "src_ip": src, "dst_ip": str(dst),
                "packet_count": int(rng.integers(5, 50)),
                "byte_count": int(rng.integers(400, 5000)),
                "duration_sec": int(rng.integers(1, 30)),
                "proto": int(rng.choice([6, 17])),
                "src_port": int(rng.integers(1024, 65535)),
                "dst_port": int(rng.choice([80, 443, 22, 53])),
            })

    # attackers
    attack_types = ["ddos", "mirai", "scan", "brute_force", "exfil"]
    for i in range(n_attackers):
        ip = f"192.168.1.{i+1}"
        lab = attack_types[i % len(attack_types)]
        labels[ip] = lab
        # generate skewed traffic
        for _ in range(rng.integers(20, 80)):
            dst = rng.choice(benign_ips)
            if lab == "ddos":
                pkts, byts, dur = int(rng.integers(500, 2000)), int(rng.integers(50_000, 200_000)), 1
                proto, dport = 17, int(rng.choice([53, 80]))
            elif lab == "mirai":
                pkts, byts, dur = int(rng.integers(1, 4)), int(rng.integers(40, 200)), 1
                proto, dport = 6, int(rng.choice([23, 2323, 80]))
            elif lab == "scan":
                pkts, byts, dur = int(rng.integers(1, 3)), int(rng.integers(60, 120)), 1
                proto, dport = 6, int(rng.integers(1, 65535))
            elif lab == "brute_force":
                pkts, byts, dur = int(rng.integers(10, 60)), int(rng.integers(500, 3000)), 5
                proto, dport = 6, int(rng.choice([22, 3389]))
            else:  # exfil
                pkts, byts, dur = int(rng.integers(50, 200)), int(rng.integers(100_000, 800_000)), 60
                proto, dport = 6, 443
            flows.append({
                "src_ip": ip, "dst_ip": str(dst),
                "packet_count": pkts, "byte_count": byts, "duration_sec": dur,
                "proto": proto,
                "src_port": int(rng.integers(1024, 65535)),
                "dst_port": dport,
            })
    return flows, labels


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", help="CSV of flow records (CICIDS-style)")
    parser.add_argument("--out", default="data/graph.npz", help="Output path")
    args = parser.parse_args()

    if args.input and os.path.exists(args.input):
        import pandas as pd
        df = pd.read_csv(args.input)
        flows = df[RAW_FEATURES + ["src_ip", "dst_ip"]].to_dict("records")
        labels = dict(zip(df["src_ip"], df.get("label", ["benign"] * len(df))))
    else:
        log.warning("No input — generating synthetic dataset.")
        flows, labels = synthesize_dataset()

    x, ei, ew, y, ip_to_idx = build_graph_from_flows(flows, labels)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    np.savez(args.out, x=x, edge_index=ei, edge_weight=ew, y=y,
             ip_to_idx=np.array(list(ip_to_idx.items()), dtype=object))
    log.info("Saved graph to %s (%d nodes, %d edges)", args.out, x.shape[0], ei.shape[1])


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
