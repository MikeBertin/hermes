"""Merkle trees — how a block fingerprints all its transactions in 32 bytes,
and how a light wallet proves one is included without downloading the rest.

Every block header carries a single *merkle root*: hash the transactions in
pairs, then hash the pairs, and so on up to one value. Change any transaction
and the root changes, so the root (committed to by proof-of-work) locks in the
entire list. The payoff is the **merkle proof**: to convince someone a given
transaction is in a block, you hand over only the ~log2(n) sibling hashes along
its path to the root — a few hundred bytes instead of the whole block. That is
what SPV ("simplified payment verification") wallets — and on-chain proof-of-
reserves — rely on.

Bitcoin quirks reproduced here:
- hashes are combined with double-SHA-256;
- if a level has an odd number of nodes, the last one is duplicated;
- txids live in *internal* (little-endian) byte order inside the tree, the
  reverse of the big-endian form block explorers display.
"""

from __future__ import annotations

from .sha256 import double_sha256


def merkle_parent(left: bytes, right: bytes) -> bytes:
    """The parent of two nodes: double-SHA-256 of their concatenation."""
    return double_sha256(left + right)


def merkle_parent_level(hashes: list[bytes]) -> list[bytes]:
    """One step up the tree. An odd node count duplicates the final hash — the
    quirk behind Bitcoin's CVE-2012-2459 duplicate-tx malleability."""
    if len(hashes) == 1:
        return hashes
    if len(hashes) % 2 == 1:
        hashes = hashes + [hashes[-1]]
    return [merkle_parent(hashes[i], hashes[i + 1]) for i in range(0, len(hashes), 2)]


def merkle_levels(hashes: list[bytes]) -> list[list[bytes]]:
    """Every level from the leaves up to (and including) the single root —
    handy for drawing the tree."""
    if not hashes:
        raise ValueError("need at least one leaf")
    levels = [list(hashes)]
    while len(levels[-1]) > 1:
        levels.append(merkle_parent_level(levels[-1]))
    return levels


def merkle_root(hashes: list[bytes]) -> bytes:
    """Collapse the leaves to the single 32-byte root (internal byte order)."""
    return merkle_levels(hashes)[-1][0]


def merkle_proof(hashes: list[bytes], index: int) -> list[tuple[bytes, bool]]:
    """The inclusion proof for leaf ``index``: the sibling hash at each level on
    the way to the root, paired with a flag — ``True`` if the sibling sits on
    the *left* (so the parent is ``sibling ‖ current``)."""
    proof: list[tuple[bytes, bool]] = []
    level = list(hashes)
    i = index
    while len(level) > 1:
        if len(level) % 2 == 1:
            level = level + [level[-1]]
        if i % 2 == 0:
            proof.append((level[i + 1], False))   # sibling on the right
        else:
            proof.append((level[i - 1], True))     # sibling on the left
        level = merkle_parent_level(level)
        i //= 2
    return proof


def verify_merkle_proof(leaf: bytes, proof: list[tuple[bytes, bool]], root: bytes) -> bool:
    """Replay a proof from a leaf up to a claimed root. This is the whole of
    SPV: an O(log n) check that needs the header's root, not the block."""
    h = leaf
    for sibling, sibling_on_left in proof:
        h = merkle_parent(sibling, h) if sibling_on_left else merkle_parent(h, sibling)
    return h == root


# --- display-order convenience (block explorers show big-endian txids) --------
def root_from_txids(txids: list[str]) -> str:
    """Merkle root from display-order (big-endian) txid hex, returned the same
    way — matching what a block header / explorer shows."""
    leaves = [bytes.fromhex(t)[::-1] for t in txids]
    return merkle_root(leaves)[::-1].hex()
