"""
Training script for the HGAGN (Hybrid GCN + GAT) SDN-IoT attack classifier.

Run:
    python -m gnn_security.train --epochs 60 --out gnn_security/checkpoints/hybrid_gcn_gat.pt
"""
from __future__ import annotations
import argparse
import logging
import os
import numpy as np

log = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default="data/graph.npz",
                        help="Graph .npz produced by data_prep.py")
    parser.add_argument("--epochs", type=int, default=60)
    parser.add_argument("--lr", type=float, default=5e-3)
    parser.add_argument("--hidden", type=int, default=64)
    parser.add_argument("--heads", type=int, default=4)
    parser.add_argument("--out", default="gnn_security/checkpoints/hybrid_gcn_gat.pt")
    args = parser.parse_args()

    try:
        import torch
        from torch_geometric.data import Data
        from .models import HGAGN
    except Exception as exc:
        log.error("Cannot train — PyTorch / torch-geometric not installed: %s", exc)
        return

    if not os.path.exists(args.data):
        log.info("No data file at %s — synthesising one.", args.data)
        from .data_prep import synthesize_dataset, build_graph_from_flows
        flows, labels = synthesize_dataset()
        x, ei, ew, y, _ = build_graph_from_flows(flows, labels)
    else:
        d = np.load(args.data, allow_pickle=True)
        x, ei, ew, y = d["x"], d["edge_index"], d["edge_weight"], d["y"]

    x_t = torch.tensor(x, dtype=torch.float32)
    ei_t = torch.tensor(ei, dtype=torch.long)
    ew_t = torch.tensor(ew, dtype=torch.float32)
    y_t = torch.tensor(y, dtype=torch.long)

    # train/val/test mask
    n = x_t.shape[0]
    rng = np.random.default_rng(42)
    idx = rng.permutation(n)
    n_train = int(0.6 * n); n_val = int(0.2 * n)
    train_mask = torch.zeros(n, dtype=torch.bool); train_mask[idx[:n_train]] = True
    val_mask = torch.zeros(n, dtype=torch.bool); val_mask[idx[n_train:n_train + n_val]] = True
    test_mask = torch.zeros(n, dtype=torch.bool); test_mask[idx[n_train + n_val:]] = True

    model = HGAGN(in_dim=x_t.shape[1], hidden_dim=args.hidden,
                  n_classes=int(y_t.max().item()) + 1, heads=args.heads)
    opt = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=5e-4)
    loss_fn = torch.nn.CrossEntropyLoss()

    best_val = 0.0; best_state = None
    for epoch in range(1, args.epochs + 1):
        model.train()
        opt.zero_grad()
        out = model(x_t, ei_t, edge_weight=ew_t)
        loss = loss_fn(out[train_mask], y_t[train_mask])
        loss.backward()
        opt.step()
        # eval
        model.eval()
        with torch.no_grad():
            out = model(x_t, ei_t, edge_weight=ew_t)
            pred = out.argmax(dim=1)
            val_acc = (pred[val_mask] == y_t[val_mask]).float().mean().item()
            train_acc = (pred[train_mask] == y_t[train_mask]).float().mean().item()
        log.info("epoch %3d  loss=%.4f  train=%.3f  val=%.3f",
                 epoch, loss.item(), train_acc, val_acc)
        if val_acc > best_val:
            best_val = val_acc
            best_state = {k: v.clone() for k, v in model.state_dict().items()}

    if best_state is not None:
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        torch.save(best_state, args.out)
        model.load_state_dict(best_state)
    # test
    model.eval()
    with torch.no_grad():
        out = model(x_t, ei_t, edge_weight=ew_t)
        pred = out.argmax(dim=1)
        test_acc = (pred[test_mask] == y_t[test_mask]).float().mean().item()
    log.info("BEST val=%.3f  TEST=%.3f  ->  %s", best_val, test_acc, args.out)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    main()
