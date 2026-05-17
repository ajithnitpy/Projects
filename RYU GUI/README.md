# Ryu SDN Controller Dashboard — with GNN-based IoT Security Mitigation

A full-stack Django web application that:

1. Renders the **Ryu SDN Controller GUI** dashboard (matching the design in
   `ryu dashboard.png`) — KPI cards, live network topology, OpenFlow pipeline
   architecture, Ryu internal architecture, event log, and connection flow.
2. Integrates with a **Ryu controller on Ubuntu** via its REST APIs
   (`ofctl_rest`, `rest_topology`) plus a **custom Ryu controller app**
   (`ryu_apps/sdn_security_controller.py`) that exposes additional endpoints
   for threat reporting and OpenFlow rule pushdown.
3. Implements a **novel Hybrid GCN+GAT graph neural network (HGAGN)** with a
   **Flow-Entropy Attention Bias** for SDN-IoT intrusion detection, and a
   staged **mitigation protocol** that pushes OpenFlow drop/meter rules back
   to Ryu to neutralise detected attacks in real time.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          Ubuntu host                                │
│                                                                     │
│  Mininet / OVS  ──OpenFlow──▶  Ryu controller (port 6633/6653)      │
│                                  │                                  │
│                                  ├─ ryu.app.ofctl_rest     :8080    │
│                                  ├─ ryu.app.rest_topology  :8080    │
│                                  └─ sdn_security_controller :8081   │
│                                          ▲ │                        │
│                            REST + WS ────┘ │ POST /api/gnn/infer/   │
│                                            ▼                        │
│  Django ASGI (Daphne)  ◀─────────  HGAGN inference + mitigation     │
│   ├─ dashboard (Channels live updates)                              │
│   ├─ api  (DRF + SimpleJWT)                                         │
│   └─ gnn_security (HGAGN model, mitigation engine)                  │
│                                                                     │
│  Postgres / SQLite        Redis (Channels)        Nginx (reverse)   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Project layout

```
RYU GUI/
├── manage.py
├── requirements.txt
├── .env.example
├── README.md
├── Dockerfile               # Django container
├── Dockerfile.ryu           # Ryu controller container
├── docker-compose.yml       # Full stack
├── ryu_dashboard/           # Django project (settings, asgi, urls)
├── dashboard/               # Frontend app — matches the uploaded layout
│   ├── templates/dashboard/*.html
│   ├── static/dashboard/css/style.css
│   ├── ryu_client.py        # REST client for Ryu
│   ├── consumers.py         # Channels WebSocket consumers
│   ├── views.py / urls.py
│   └── management/commands/seed_demo.py
├── api/                     # DRF REST API
├── gnn_security/            # GNN module
│   ├── models.py            # HGAGN (Hybrid GCN+GAT)  ← novel model
│   ├── data_prep.py         # Build IP-graph from flows
│   ├── train.py             # Training script
│   ├── inference.py         # Live inference engine
│   ├── mitigation.py        # Staged mitigation protocol
│   └── views.py / urls.py
├── ryu_apps/
│   ├── sdn_security_controller.py   # Custom Ryu app (run with ryu-manager)
│   └── flow_monitor.py
├── deploy/
│   ├── nginx.conf, nginx_ubuntu.conf
│   ├── ryu-dashboard.service
│   ├── ryu-controller.service
│   └── gunicorn.service
└── tools/
    ├── mininet_demo_topology.py
    └── simulate_attack.py
```

---

## Quick start — local dev (Windows / macOS / Linux)

Even without Ryu running, the dashboard works with mocked data.

```bash
python -m venv .venv
.venv\Scripts\activate                 # Windows
# source .venv/bin/activate            # macOS / Linux

pip install -r requirements.txt        # PyTorch + PyG are large
copy .env.example .env                 # cp on Linux

python manage.py migrate
python manage.py createsuperuser
python manage.py seed_demo             # populate demo data

python manage.py runserver
# open http://127.0.0.1:8000/  → login with the superuser
```

If you don't want to install PyTorch / PyTorch-Geometric for the dev box, the
GNN module falls back to a NumPy classifier automatically.

---

## Production — Ubuntu (bare metal)

```bash
# 1. System packages
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git \
    nginx redis-server postgresql-15

# 2. Project user + code
sudo useradd -m -s /bin/bash ryu
sudo mkdir -p /opt/ryu-dashboard && sudo chown ryu:ryu /opt/ryu-dashboard
sudo -u ryu git clone <your-repo-url> /opt/ryu-dashboard
cd /opt/ryu-dashboard
sudo -u ryu python3 -m venv venv
sudo -u ryu ./venv/bin/pip install -r requirements.txt
sudo -u ryu ./venv/bin/pip install eventlet==0.30.2 ryu==4.34

# 3. Configure
sudo -u ryu cp .env.example .env
sudo -u ryu nano .env       # set DB_ENGINE=postgres, secrets, etc.

# 4. Database
sudo -u postgres createuser ryu
sudo -u postgres createdb -O ryu ryu_dashboard

# 5. Migrate + collectstatic
cd /opt/ryu-dashboard
sudo -u ryu ./venv/bin/python manage.py migrate
sudo -u ryu ./venv/bin/python manage.py collectstatic --noinput
sudo -u ryu ./venv/bin/python manage.py createsuperuser

# 6. systemd services
sudo cp deploy/ryu-dashboard.service /etc/systemd/system/
sudo cp deploy/ryu-controller.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ryu-dashboard ryu-controller

# 7. Nginx
sudo cp deploy/nginx_ubuntu.conf /etc/nginx/sites-available/ryu-dashboard
sudo ln -s /etc/nginx/sites-available/ryu-dashboard /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

Then point your switches (Mininet, OVS, hardware) at the controller:

```bash
sudo ovs-vsctl set-controller br0 tcp:<ubuntu-host>:6653
```

---

## Production — Docker Compose

```bash
cp .env.example .env       # set POSTGRES_PASSWORD etc.
docker compose up --build -d

# bring up a test topology in another window
sudo mn --controller=remote,ip=127.0.0.1,port=6653 \
        --switch=ovsk,protocols=OpenFlow13 \
        --topo=tree,depth=2,fanout=3
```

Then open <http://localhost/>.

---

## Trying the GNN pipeline

### 1. Train the model (synthetic data is auto-generated if no CSV is given)

```bash
python -m gnn_security.data_prep --out data/graph.npz
python -m gnn_security.train --epochs 60 \
    --out gnn_security/checkpoints/hybrid_gcn_gat.pt
```

You should see `test ≈ 0.92` accuracy on synthetic data.

To train on real data, supply a CICIDS / BoT-IoT CSV with columns
`src_ip, dst_ip, packet_count, byte_count, duration_sec, proto, src_port,
dst_port, label`:

```bash
python -m gnn_security.data_prep --input data/cicids.csv --out data/graph.npz
```

### 2. Exercise the inference + mitigation pipeline

```bash
# In a second terminal (Django must be running):
python tools/simulate_attack.py
```

You will see threats appear at <http://127.0.0.1:8000/threats/> with confidence
scores, and matching auto-mitigation events at <http://127.0.0.1:8000/logs/>.

### 3. Inspect the novel model

`gnn_security/models.py` defines **HGAGN** with these components:

- `GCNConv → GATConv (multi-head, dropout) → GCNConv` backbone
- A **Flow-Entropy Attention Bias** (`FlowEntropyBias`) module that augments
  edge weights with a learned entropy-of-traffic term, biasing attention toward
  neighbors with anomalous packet/byte distributions
- A 2-layer MLP head producing 6-way logits over
  `[benign, ddos, mirai, scan, brute_force, exfil]`

This combination is the novel contribution: the GAT layer alone misses
low-rate IoT attacks that have small byte counts but high *entropy*; the GCN
alone misses the importance of just a few neighbors; the entropy bias glues
them together for SDN-IoT.

---

## REST API

All endpoints require JWT auth (`POST /api/auth/token/` with username/password
to obtain a token, then send `Authorization: Bearer <token>`).

| Method | Path                          | Purpose                              |
|--------|-------------------------------|--------------------------------------|
| POST   | `/api/auth/token/`            | Obtain JWT pair                      |
| POST   | `/api/auth/token/refresh/`    | Refresh access token                 |
| GET    | `/api/snapshot/`              | KPIs + topology                      |
| GET    | `/api/controller/status/`     | Is Ryu reachable?                    |
| GET    | `/api/switches/`              | Cached switches                      |
| GET    | `/api/hosts/`                 | Cached hosts                         |
| GET    | `/api/events/`                | Event log                            |
| GET    | `/api/threats/`               | Detected threats                     |
| POST   | `/api/threats/<id>/mitigate/` | Mitigate a specific threat           |
| POST   | `/api/gnn/infer/`             | Called by Ryu app; returns threats   |
| GET    | `/api/gnn/status/`            | Model backend + threshold            |

WebSocket endpoints:

| Path                | Pushes                                          |
|---------------------|-------------------------------------------------|
| `ws://.../ws/dashboard/` | KPI snapshots every 2 s + ad-hoc events   |
| `ws://.../ws/threats/`   | New threats as they're detected           |

---

## Troubleshooting

* **Dashboard cards all show 0** – Ryu isn't reachable. Either run
  `ryu-manager …`, point `RYU_REST_URL` at it, or run `python manage.py
  seed_demo` to load demo data.
* **`torch_geometric` install fails** – PyG wheels are platform-specific; see
  <https://pytorch-geometric.readthedocs.io/en/latest/install/installation.html>.
  The Django app still runs without it (NumPy fallback model).
* **WebSocket fails** – make sure you're running Daphne (`runserver` also
  supports it in Django 4.2 via Channels). Behind Nginx, ensure the
  `proxy_set_header Upgrade $http_upgrade` block is in place.
* **`ryu-manager` import errors** – Ryu requires `eventlet < 0.34`. Pin it:
  `pip install eventlet==0.30.2 ryu==4.34`.

---

## Credits

- Frontend layout adapted from the uploaded reference design
  (`ryu dashboard.png`).
- HGAGN architecture (Hybrid GCN+GAT with Flow-Entropy Attention Bias) is
  original to this project.
