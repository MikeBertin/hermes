"""Consensus by simulation — forks, reorgs, and the 51% double-spend.

Bitcoin has no chairman. Every node just keeps the chain with the most work on
it. Two consequences fall out of that one rule, and this module simulates both:

1. **Forks & reorgs.** When two miners find a block at nearly the same time,
   the network briefly disagrees. The tie breaks as soon as someone extends one
   side; the shorter side's blocks become orphans. (`simulate_consensus`)

2. **The 51% attack.** An attacker who can out-mine the rest can secretly build
   a longer chain that omits a payment, then publish it to *reverse* a
   transaction the recipient already treated as confirmed. The probability of
   success is a gambler's-ruin race. (`simulate_51`, `double_spend_probability`)

Everything is seeded, so runs are reproducible and can be baked to JSON for the
browser by export.py.
"""

from __future__ import annotations

import random
from dataclasses import asdict, dataclass, field


# ---------------------------------------------------------------- consensus ---
@dataclass
class Block:
    id: int
    parent: int | None
    height: int
    miner: str
    order: int                 # the step at which it was mined (its "time")
    lane: int = 0              # vertical slot for drawing


def simulate_consensus(seed: int = 1, n_blocks: int = 26, fork_rate: float = 0.22,
                       miners: tuple[str, ...] = ("A", "B", "C")) -> dict:
    """Grow a block tree where near-simultaneous discovery causes forks.

    With probability ``fork_rate`` a new block is built on a near-tip block
    rather than the strict tip, creating a sibling; whichever side is extended
    next wins, which produces the occasional reorg."""
    rng = random.Random(seed)
    blocks: dict[int, Block] = {0: Block(0, None, 0, "genesis", 0)}
    best = 0

    for order in range(1, n_blocks + 1):
        max_h = blocks[best].height
        near_tip = [b.id for b in blocks.values() if b.height >= max_h - 1]
        parent = rng.choice(near_tip) if (rng.random() < fork_rate and len(near_tip) > 1) else best
        b = Block(order, parent, blocks[parent].height + 1, rng.choice(miners), order)
        blocks[b.id] = b
        if b.height > blocks[best].height:        # longest chain, first-seen wins ties
            best = b.id

    main = _main_chain(blocks, best)
    _assign_lanes(blocks, main)
    return {
        "seed": seed,
        "blocks": [asdict(b) for b in blocks.values()],
        "tip": best,
        "main": sorted(main),
        "orphans": sorted(set(blocks) - main - {0}),
        "reorgs": _count_reorgs(blocks, n_blocks),
    }


def _count_reorgs(blocks: dict[int, Block], n_blocks: int) -> int:
    """Replay block discovery in order; count each time the most-work chain drops
    a block it previously contained (i.e. a node would have to reorganise)."""
    prev: set[int] = {0}
    reorgs = 0
    for step in range(1, n_blocks + 1):
        vis = [b for b in blocks.values() if b.order <= step]
        tip = max(vis, key=lambda b: (b.height, -b.order))   # longest, first-seen on ties
        chain, n = set(), tip.id
        while n is not None:
            chain.add(n)
            n = blocks[n].parent
        if prev - chain:        # a previously-main block fell off -> reorg
            reorgs += 1
        prev = chain
    return reorgs


def _main_chain(blocks: dict[int, Block], tip: int) -> set[int]:
    chain, n = set(), tip
    while n is not None:
        chain.add(n)
        n = blocks[n].parent
    return chain


def _assign_lanes(blocks: dict[int, Block], main: set[int]) -> None:
    """Lane 0 for the main chain; orphan branches get their own lanes."""
    by_height: dict[int, list[int]] = {}
    for b in blocks.values():
        by_height.setdefault(b.height, []).append(b.id)
    for height, ids in by_height.items():
        slot = 1
        for bid in sorted(ids):
            if bid in main:
                blocks[bid].lane = 0
            else:
                blocks[bid].lane = slot
                slot += 1


# ------------------------------------------------------------- 51% attack ---
def simulate_51(seed: int, q: float, confirmations: int,
                give_up_lead: int = 8, max_rounds: int = 200) -> dict:
    """One seeded race. The merchant ships once the honest chain reaches
    ``confirmations``; the attacker, mining a private chain that double-spends
    the payment, wins if their chain ever overtakes the honest one."""
    rng = random.Random(seed)
    honest = attacker = 0
    timeline = []
    shipped = False
    outcome = "racing"
    for rnd in range(1, max_rounds + 1):
        if rng.random() < q:
            attacker += 1
            who = "attacker"
        else:
            honest += 1
            who = "honest"
        if honest >= confirmations:
            shipped = True
        timeline.append({"round": rnd, "who": who, "honest": honest,
                         "attacker": attacker, "shipped": shipped})
        if shipped and attacker > honest:
            outcome = "reversed"
            break
        if shipped and honest - attacker >= give_up_lead:
            outcome = "safe"
            break
    if outcome == "racing":
        outcome = "reversed" if attacker > honest else "safe"
    return {"seed": seed, "q": q, "confirmations": confirmations,
            "timeline": timeline, "outcome": outcome,
            "honest": honest, "attacker": attacker}


def double_spend_probability(q: float, confirmations: int, trials: int = 20000,
                             seed: int = 0, cap_lead: int = 40) -> float:
    """Monte-Carlo probability that a double-spend succeeds, given the attacker
    controls a fraction ``q`` of hashpower and the merchant waits
    ``confirmations`` blocks. Matches the classic gambler's-ruin result."""
    if q >= 0.5:
        return 1.0
    rng = random.Random(seed)
    wins = 0
    for _ in range(trials):
        honest = attacker = 0
        while True:
            if rng.random() < q:
                attacker += 1
            else:
                honest += 1
            if honest >= confirmations and attacker > honest:
                wins += 1
                break
            if honest >= confirmations and honest - attacker >= cap_lead:
                break
    return wins / trials
