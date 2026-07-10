"""FROST DKG — distributed key generation (PedPoP), the trustless setup for FROST.

Demo 15's FROST leaned on a **trusted dealer**: one party knew the whole group secret,
Shamir-split it, and handed out the shares. That party is a single point of failure — it
could keep a copy, or hand out a backdoored split. Distributed key generation removes it.

Each of the *n* participants runs their *own* Shamir sharing of a secret only they chose,
and sends one sub-share to every other participant. Everyone's long-term share is the sum
of the sub-shares they received; the group key is the sum of everyone's public contribution.
So the group secret is ``Σ aᵢ₀`` — **never assembled by anyone, at any point** — yet the
shares each participant ends up with are ordinary FROST shares that demo 15's signer accepts
unchanged. The dealer is gone; the ceremony is trustless.

This is Pedersen DKG with proofs of possession (**PedPoP**), from the FROST paper /
``draft-irtf-cfrg-frost``. RFC 9591 standardises only the *signing* half, so there are no
official DKG test vectors; correctness is pinned by self-consistency (see the tests): every
sub-share verifies against its author's public commitment, each participant's proof of
possession verifies, and — the real proof — the resulting shares produce a signature that
the RFC-vector-anchored ``frost.verify`` accepts.

Two rounds:
  * **Round 1** — commit to a random degree ``t-1`` polynomial (publish ``φ = aₖ·G``) and a
    proof you know its constant term ``a₀`` (stops a rogue participant steering the group key).
  * **Round 2** — send each participant ``j`` the private evaluation ``fᵢ(j)``; verify every
    sub-share you receive against its author's commitment, then sum them into your share.
"""

from __future__ import annotations

from .curve import G, N, Point
from .frost import _hash_to_scalar, _ser_element, _ser_scalar, polynomial_evaluate


# --- proof of possession (a Schnorr signature over the polynomial's constant term) ---
def _pop_challenge(identifier: int, commitment0: Point, r_point: Point) -> int:
    """Domain-separated Schnorr challenge binding the prover's identifier, their public
    contribution ``a₀·G``, and the proof's nonce commitment."""
    return _hash_to_scalar(
        _ser_scalar(identifier) + _ser_element(commitment0) + _ser_element(r_point), b"dkg")


def round1_commit(identifier: int, coefficients: list[int], pop_randomness: bytes):
    """Participant ``identifier``'s round-1 broadcast, from the ``t`` random polynomial
    ``coefficients`` ``[a₀, …, a_{t-1}]`` they chose.

    Returns ``(commitment, proof)`` where ``commitment = [aₖ·G]`` is the public vector of
    coefficient commitments (its head ``a₀·G`` is this party's contribution to the group
    key), and ``proof = (R, μ)`` is a Schnorr proof of knowledge of ``a₀``."""
    commitment = [c * G for c in coefficients]
    # deterministic proof nonce — reproducible, and can't repeat across secrets
    k = _hash_to_scalar(pop_randomness + _ser_scalar(coefficients[0]), b"dkg-nonce")
    r_point = k * G
    challenge = _pop_challenge(identifier, commitment[0], r_point)
    mu = (k + coefficients[0] * challenge) % N
    return commitment, (r_point, mu)


def verify_pop(identifier: int, commitment: list[Point], proof: tuple) -> bool:
    """Verify participant ``identifier``'s proof of possession of ``a₀`` (``μ·G == R + c·φ₀``).
    A rogue participant who published a contribution they can't open would be rejected here —
    the check that stops them cancelling honest contributions out of the group key."""
    r_point, mu = proof
    challenge = _pop_challenge(identifier, commitment[0], r_point)
    return mu * G == r_point + challenge * commitment[0]


# --- round two: sub-shares and their verification ---------------------------
def secret_share_for(coefficients: list[int], recipient: int) -> int:
    """The private sub-share participant sends to ``recipient``: ``fᵢ(recipient)``."""
    return polynomial_evaluate(recipient, coefficients)


def verify_share(recipient: int, sender_commitment: list[Point], share_value: int) -> bool:
    """``recipient`` checks a received sub-share against the sender's public commitment:
    ``fₛ(recipient)·G == Σₖ recipientᵏ · φ_{s,k}`` — Feldman verification, so a sender can't
    hand out a share inconsistent with what they committed to publicly."""
    expected = Point(None, None)
    for k, phi_k in enumerate(sender_commitment):
        expected = expected + pow(recipient, k, N) * phi_k
    return share_value * G == expected


# --- finalize ----------------------------------------------------------------
def finalize(received_shares: list[int], all_commitments: list[list[Point]]):
    """Combine the sub-shares participant received (one from every participant, including
    their own ``fᵢ(i)``) into their long-term FROST secret share, and sum every
    participant's ``φ₀`` into the group public key.

    Returns ``(secret_share, group_public_key, verification_share)``. The ``secret_share`` is
    a point on ``f = Σ fⱼ`` whose constant term — the group secret — is never formed."""
    secret_share = sum(received_shares) % N
    group_public_key = Point(None, None)
    for commitment in all_commitments:
        group_public_key = group_public_key + commitment[0]
    return secret_share, group_public_key, secret_share * G
