"""FROST — Flexible Round-Optimized Schnorr Threshold signatures (RFC 9591).

MuSig2 (demo 12) is *n-of-n*: every cosigner must sign. FROST is *t-of-n* — any
threshold t of the n key-holders can produce one signature, and any t-1 cannot.
A 2-of-3 treasury where any two officers authorise a payment, yet the chain sees
a single ordinary Schnorr signature: that is FROST.

The group secret is never assembled. It is Shamir-shared once (here by a trusted
dealer), and signing recombines the shares *inside* the signature via Lagrange
interpolation — the secret itself never exists in one place. Signing is two
rounds, like MuSig2: commit nonce pairs, then exchange signature shares.

This implements the ``FROST(secp256k1, SHA-256)`` ciphersuite from RFC 9591
exactly, including its ``hash_to_field`` / ``expand_message_xmd`` (RFC 9380) hash
construction. Note this ciphersuite's challenge hash is *not* BIP-340's, so the
resulting 65-byte ``(R, z)`` signature is threshold Schnorr but not a drop-in
Taproot spend (a BIP-340 FROST variant exists but isn't yet standardised).
"""

from __future__ import annotations

from .curve import G, N, Point
from .keys import PublicKey
from .sha256 import sha256

CONTEXT = b"FROST-secp256k1-SHA256-v1"


# --- serialization (SEC1: 33-byte compressed points, 32-byte scalars) --------
def _ser_scalar(s: int) -> bytes:
    return (s % N).to_bytes(32, "big")


def _ser_element(point: Point) -> bytes:
    return PublicKey(point).sec(compressed=True)


def _deser_element(buf: bytes) -> Point:
    return PublicKey.parse(buf).point


# --- ciphersuite hashes (RFC 9591 §6.5) --------------------------------------
def _expand_message_xmd(msg: bytes, dst: bytes, length: int) -> bytes:
    """RFC 9380 §5.3.1 expand_message_xmd with SHA-256."""
    b_in_bytes, s_in_bytes = 32, 64            # SHA-256 output / block size
    ell = -(-length // b_in_bytes)             # ceil
    if ell > 255 or length > 65535 or len(dst) > 255:
        raise ValueError("expand_message_xmd: invalid parameters")
    dst_prime = dst + bytes([len(dst)])
    msg_prime = b"\x00" * s_in_bytes + msg + length.to_bytes(2, "big") + b"\x00" + dst_prime
    b0 = sha256(msg_prime)
    blocks = [sha256(b0 + b"\x01" + dst_prime)]
    for i in range(2, ell + 1):
        xored = bytes(a ^ b for a, b in zip(b0, blocks[-1]))
        blocks.append(sha256(xored + bytes([i]) + dst_prime))
    return b"".join(blocks)[:length]


def _hash_to_scalar(msg: bytes, suffix: bytes) -> int:
    # hash_to_field(m, 1): expand to L=48 bytes, interpret big-endian, reduce mod n
    return int.from_bytes(_expand_message_xmd(msg, CONTEXT + suffix, 48), "big") % N


def h1(msg: bytes) -> int:   # "rho" — binding factors
    return _hash_to_scalar(msg, b"rho")


def h2(msg: bytes) -> int:   # "chal" — the signature challenge
    return _hash_to_scalar(msg, b"chal")


def h3(msg: bytes) -> int:   # "nonce" — nonce generation
    return _hash_to_scalar(msg, b"nonce")


def h4(msg: bytes) -> bytes:  # "msg" — message pre-hash (fixed length)
    return sha256(CONTEXT + b"msg" + msg)


def h5(msg: bytes) -> bytes:  # "com" — commitment-list pre-hash (fixed length)
    return sha256(CONTEXT + b"com" + msg)


# --- trusted-dealer key generation (Shamir, RFC 9591 Appendix C) -------------
def polynomial_evaluate(x: int, coefficients: list[int]) -> int:
    """Evaluate a polynomial (constant term first) at ``x`` via Horner's rule."""
    value = 0
    for coeff in reversed(coefficients):
        value = (value * x + coeff) % N
    return value


def trusted_dealer_keygen(secret: int, coefficients: list[int], max_participants: int):
    """Split ``secret`` into ``max_participants`` Shamir shares over a polynomial
    whose constant term is the secret and whose other ``coefficients`` set the
    threshold (degree t-1 ⇒ t shares needed). Returns ``(shares, group_pubkey)``,
    where each share is ``(identifier, value)`` and identifiers are 1..n."""
    poly = [secret] + list(coefficients)
    shares = [(i, polynomial_evaluate(i, poly)) for i in range(1, max_participants + 1)]
    return shares, secret * G


def derive_interpolating_value(identifiers: list[int], x_i: int) -> int:
    """The Lagrange coefficient λ_i for participant ``x_i`` within the signing set
    ``identifiers`` — the weight that recombines shares back toward f(0)."""
    if x_i not in identifiers:
        raise ValueError("invalid parameters: x_i not in the list")
    num, den = 1, 1
    for x_j in identifiers:
        if x_j == x_i:
            continue
        num = (num * x_j) % N
        den = (den * (x_j - x_i)) % N
    return (num * pow(den, -1, N)) % N


# --- round one: nonces & commitments -----------------------------------------
def nonce_generate(secret: int, randomness: bytes) -> int:
    """Derive a single-use nonce by hashing fresh randomness with the secret share
    (RFC 9591 §4.1) — a bad RNG alone can't leak or repeat it."""
    return h3(randomness + _ser_scalar(secret))


def commit(secret: int, hiding_randomness: bytes, binding_randomness: bytes):
    """A participant's round-one output: a pair of nonces (kept private) and their
    commitments (published). FROST uses *two* nonces — the binding one, weighted
    per-session, is what defeats the parallel-session forgery MuSig2 also guards
    against."""
    hiding_nonce = nonce_generate(secret, hiding_randomness)
    binding_nonce = nonce_generate(secret, binding_randomness)
    return (hiding_nonce, binding_nonce), (hiding_nonce * G, binding_nonce * G)


# --- binding factors, group commitment, challenge (RFC 9591 §4.4-4.6) --------
def encode_group_commitment_list(commitment_list: list) -> bytes:
    """Serialize the sorted ``(identifier, hiding_commit, binding_commit)`` list."""
    out = b""
    for identifier, hiding_commit, binding_commit in commitment_list:
        out += _ser_scalar(identifier) + _ser_element(hiding_commit) + _ser_element(binding_commit)
    return out


def compute_binding_factors(group_public_key: Point, commitment_list: list, msg: bytes):
    """One binding factor ρ_i per participant, each committing to the whole
    session (group key, message, and *every* commitment) — so no signer can pick
    their nonce after seeing the others'."""
    prefix = _ser_element(group_public_key) + h4(msg) + h5(encode_group_commitment_list(commitment_list))
    return [(identifier, h1(prefix + _ser_scalar(identifier)))
            for identifier, _, _ in commitment_list]


def compute_group_commitment(commitment_list: list, binding_factor_list: list) -> Point:
    """The session nonce R = Σ (hiding_i + ρ_i · binding_i)."""
    factors = dict(binding_factor_list)
    group_commitment = Point(None, None)
    for identifier, hiding_commit, binding_commit in commitment_list:
        group_commitment = group_commitment + hiding_commit + factors[identifier] * binding_commit
    return group_commitment


def compute_challenge(group_commitment: Point, group_public_key: Point, msg: bytes) -> int:
    return h2(_ser_element(group_commitment) + _ser_element(group_public_key) + msg)


# --- round two: signature shares, aggregation, verification ------------------
def sign(identifier: int, secret_share: int, group_public_key: Point,
         nonces: tuple, msg: bytes, commitment_list: list) -> int:
    """Participant ``identifier``'s signature share:
    ``z_i = hiding + ρ_i·binding + λ_i·s_i·c``. The Lagrange weight λ_i folds the
    Shamir share into the joint signature without ever reconstructing the secret."""
    binding_factor_list = compute_binding_factors(group_public_key, commitment_list, msg)
    binding_factor = dict(binding_factor_list)[identifier]
    group_commitment = compute_group_commitment(commitment_list, binding_factor_list)
    lambda_i = derive_interpolating_value([i for i, _, _ in commitment_list], identifier)
    challenge = compute_challenge(group_commitment, group_public_key, msg)
    hiding_nonce, binding_nonce = nonces
    return (hiding_nonce + binding_nonce * binding_factor + lambda_i * secret_share * challenge) % N


def aggregate(commitment_list: list, msg: bytes, group_public_key: Point, sig_shares: list):
    """Combine the shares into one Schnorr signature ``(R, z)``. R is the session
    commitment; z = Σ z_i."""
    binding_factor_list = compute_binding_factors(group_public_key, commitment_list, msg)
    group_commitment = compute_group_commitment(commitment_list, binding_factor_list)
    return group_commitment, sum(sig_shares) % N


def verify_share(identifier: int, secret_commitment: Point, sig_share: int,
                 group_public_key: Point, group_commitment: Point,
                 commitment_list: list, binding_factor_list: list, msg: bytes) -> bool:
    """Check one participant's share on its own (RFC 9591 §5.4 identifiable abort):
    ``z_i·G == (hiding_i + ρ_i·binding_i) + λ_i·challenge·PK_i`` — so a bad share
    is pinned on its author before aggregation."""
    commits = {i: (h, b) for i, h, b in commitment_list}
    hiding_commit, binding_commit = commits[identifier]
    binding_factor = dict(binding_factor_list)[identifier]
    comm_share = hiding_commit + binding_factor * binding_commit
    challenge = compute_challenge(group_commitment, group_public_key, msg)
    lambda_i = derive_interpolating_value([i for i, _, _ in commitment_list], identifier)
    return sig_share * G == comm_share + (challenge * lambda_i) * secret_commitment


def verify(msg: bytes, signature: tuple, group_public_key: Point) -> bool:
    """Verify the aggregate as a plain prime-order Schnorr signature (RFC 9591
    Appendix B): ``z·G == R + c·PK``."""
    group_commitment, z = signature
    challenge = compute_challenge(group_commitment, group_public_key, msg)
    return z * G == group_commitment + challenge * group_public_key


def serialize_signature(signature: tuple) -> bytes:
    """Canonical 65-byte encoding: ``SerializeElement(R) || SerializeScalar(z)``."""
    group_commitment, z = signature
    return _ser_element(group_commitment) + _ser_scalar(z)
