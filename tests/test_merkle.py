"""Merkle tree + inclusion-proof vectors.

Anchored to a real block: Bitcoin block 100000 has four transactions, and our
merkle root for them must equal the root in its header — the same root its
proof-of-work commits to.
"""

from hermes.merkle import (
    merkle_proof, merkle_root, root_from_txids, verify_merkle_proof,
)

# Block 100000 (display-order txids) and its header merkle root.
BLOCK_100000_TXIDS = [
    "8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87",
    "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4",
    "6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4",
    "e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d",
]
BLOCK_100000_ROOT = "f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766"


def _leaves():
    return [bytes.fromhex(t)[::-1] for t in BLOCK_100000_TXIDS]   # internal order


def test_real_block_merkle_root():
    assert root_from_txids(BLOCK_100000_TXIDS) == BLOCK_100000_ROOT


def test_every_leaf_has_a_valid_proof():
    leaves = _leaves()
    root = merkle_root(leaves)
    for i, leaf in enumerate(leaves):
        proof = merkle_proof(leaves, i)
        assert len(proof) == 2                       # 4 leaves -> depth 2
        assert verify_merkle_proof(leaf, proof, root)


def test_tampered_leaf_is_rejected():
    leaves = _leaves()
    root = merkle_root(leaves)
    proof = merkle_proof(leaves, 0)
    forged = bytes([leaves[0][0] ^ 0x01]) + leaves[0][1:]
    assert not verify_merkle_proof(forged, proof, root)
    # a real leaf with someone else's proof also fails
    assert not verify_merkle_proof(leaves[0], merkle_proof(leaves, 1), root)


def test_odd_level_duplicates_last():
    # three leaves: the level is padded by duplicating the final hash
    leaves = _leaves()[:3]
    root = merkle_root(leaves)
    for i, leaf in enumerate(leaves):
        assert verify_merkle_proof(leaf, merkle_proof(leaves, i), root)


def test_single_leaf_is_its_own_root():
    leaf = _leaves()[0]
    assert merkle_root([leaf]) == leaf
    assert verify_merkle_proof(leaf, merkle_proof([leaf], 0), leaf)
