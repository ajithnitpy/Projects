"""
Trigger the GNN inference endpoint with synthetic 'attack' flows so you can
exercise the full pipeline without standing up Mininet.

    python tools/simulate_attack.py
"""
import json
import random
import time
import requests

URL = "http://127.0.0.1:8000/api/gnn/infer/"

ATTACK_PATTERNS = {
    "ddos":  {"packet_count": 1500, "byte_count": 120_000, "duration_sec": 1,
              "proto": 17, "dst_port": 80},
    "mirai": {"packet_count": 2, "byte_count": 80, "duration_sec": 1,
              "proto": 6, "dst_port": 23},
    "scan":  {"packet_count": 1, "byte_count": 80, "duration_sec": 1,
              "proto": 6, "dst_port": None},
}


def generate_batch():
    flows = []
    # benign
    for i in range(40):
        flows.append({
            "src_ip": f"10.0.0.{random.randint(1, 50)}",
            "dst_ip": f"10.0.0.{random.randint(1, 50)}",
            "packet_count": random.randint(5, 80),
            "byte_count": random.randint(400, 5000),
            "duration_sec": random.randint(1, 30),
            "proto": random.choice([6, 17]),
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([80, 443]),
            "dpid": 1,
        })
    # attackers
    for cls, pat in ATTACK_PATTERNS.items():
        for k in range(10):
            flows.append({
                "src_ip": f"192.168.1.{random.randint(1,250)}",
                "dst_ip": f"10.0.0.{random.randint(1,50)}",
                "src_port": random.randint(1024, 65535),
                "dst_port": pat["dst_port"] or random.randint(1, 65535),
                "proto": pat["proto"], "dpid": 1,
                "packet_count": pat["packet_count"],
                "byte_count": pat["byte_count"],
                "duration_sec": pat["duration_sec"],
            })
    return flows


def main():
    while True:
        flows = generate_batch()
        try:
            r = requests.post(URL, json={"flows": flows}, timeout=4)
            data = r.json()
            print(f"sent {len(flows)} flows -> "
                  f"{len(data.get('threats', []))} threats, "
                  f"{len(data.get('applied_mitigations', []))} mitigations")
        except Exception as e:
            print("error:", e)
        time.sleep(5)


if __name__ == "__main__":
    main()
