"""Bake canonical simulation data for the browser demos (Plutus's pattern).

The Python simulators in hermes/ are the source of truth; this script freezes a
few seeded runs and a probability table into JSON so the web demos can play them
back without re-deriving anything client-side.

Run:  .venv/bin/python export.py
"""

import json
import os

from hermes.network import double_spend_probability, simulate_consensus

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "web", "network", "data")


def bake() -> None:
    os.makedirs(OUT, exist_ok=True)

    # a handful of consensus runs that each contain a real reorg (and forks)
    fork_rate = 0.30
    seeds = [s for s in range(1, 200)
             if simulate_consensus(seed=s, fork_rate=fork_rate)["reorgs"] >= 1][:5]
    runs = [simulate_consensus(seed=s, fork_rate=fork_rate) for s in seeds]
    _write("consensus.json", {"runs": runs})

    # double-spend success probability over attacker hashpower q and confirmations n
    qs = [round(0.05 * i, 2) for i in range(1, 10)]      # 0.05 .. 0.45
    ns = list(range(0, 11))                              # 0 .. 10 confirmations
    grid = {
        str(q): {str(n): round(double_spend_probability(q, n, trials=8000, seed=12345), 4)
                 for n in ns}
        for q in qs
    }
    _write("probabilities.json", {"q_values": qs, "n_values": ns, "grid": grid})

    print(f"baked {len(runs)} consensus runs + {len(qs) * len(ns)} probability cells -> {OUT}")


def _write(name: str, obj) -> None:
    with open(os.path.join(OUT, name), "w") as f:
        json.dump(obj, f, separators=(",", ":"))


if __name__ == "__main__":
    bake()
