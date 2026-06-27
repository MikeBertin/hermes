"""Vectors for the transaction model and the consensus / 51% simulators."""

import pytest

from hermes.tx import Tx, TxIn, TxOut, UTXOSet, conflicts
from hermes.network import (
    simulate_consensus, simulate_51, double_spend_probability,
)


# --- transactions ---------------------------------------------------------
def test_txid_is_deterministic_and_input_sensitive():
    a = Tx([TxIn("aa" * 32, 0)], [TxOut(100, "merchant")])
    b = Tx([TxIn("aa" * 32, 0)], [TxOut(100, "merchant")])
    c = Tx([TxIn("aa" * 32, 0)], [TxOut(100, "attacker")])
    assert a.txid == b.txid          # same content -> same id
    assert a.txid != c.txid          # different output -> different id
    assert len(a.txid) == 64


def test_double_spend_is_a_conflict():
    funding = TxIn("bb" * 32, 1)
    pay = Tx([funding], [TxOut(50, "merchant")])
    cheat = Tx([funding], [TxOut(50, "attacker")])      # same input, different payee
    assert conflicts(pay, cheat)


def test_utxo_rejects_double_spend():
    coinbase = Tx([], [TxOut(50, "alice")])
    u = UTXOSet()
    u.add(coinbase)
    funding = TxIn(coinbase.txid, 0)
    u.apply(Tx([funding], [TxOut(50, "merchant")]))
    with pytest.raises(ValueError):
        u.apply(Tx([funding], [TxOut(50, "attacker")]))   # input already spent


# --- consensus tree -------------------------------------------------------
def test_consensus_tree_is_well_formed():
    sim = simulate_consensus(seed=1)
    blocks = {b["id"]: b for b in sim["blocks"]}
    # every parent exists; heights increment by one
    for b in blocks.values():
        if b["parent"] is not None:
            assert b["parent"] in blocks
            assert b["height"] == blocks[b["parent"]]["height"] + 1
    # the main chain runs unbroken from the tip back to genesis
    chain, n = [], sim["tip"]
    while n is not None:
        chain.append(n)
        n = blocks[n]["parent"]
    assert chain[-1] == 0
    assert set(sim["main"]) == set(chain)


def test_forks_and_reorgs_happen():
    # across seeds, at least one network should orphan a block...
    assert any(simulate_consensus(seed=s)["orphans"] for s in range(6))
    # ...and at least one should require a reorg (the most-work chain switches)
    assert any(simulate_consensus(seed=s, fork_rate=0.30)["reorgs"] >= 1 for s in range(12))


# --- 51% attack -----------------------------------------------------------
def test_double_spend_probability_bounds_and_monotonicity():
    p_low = double_spend_probability(0.1, 6, trials=4000, seed=1)
    p_high = double_spend_probability(0.45, 1, trials=4000, seed=1)
    assert p_low < 0.05               # patient merchant, weak attacker -> very unlikely
    assert p_high > 0.5               # near-parity attacker, 1 confirmation -> likely
    assert double_spend_probability(1.0, 6) == 1.0

    # more hashpower helps the attacker; more confirmations help the merchant
    assert double_spend_probability(0.35, 3, trials=4000, seed=2) > \
        double_spend_probability(0.15, 3, trials=4000, seed=2)
    assert double_spend_probability(0.3, 1, trials=4000, seed=3) > \
        double_spend_probability(0.3, 6, trials=4000, seed=3)


def test_simulate_51_reports_an_outcome():
    run = simulate_51(seed=7, q=0.45, confirmations=2)
    assert run["outcome"] in ("reversed", "safe")
    assert run["timeline"][-1]["round"] == len(run["timeline"])
