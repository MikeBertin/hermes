"""Lightning payment channels — the revocation/penalty mechanism (BOLT-3).

A Lightning channel lets two parties pay each other thousands of times while
touching the blockchain only twice: once to *open* (a 2-of-2 funding output) and
once to *close*. In between, the current balance is a **commitment transaction**
each side holds but doesn't broadcast — spend the funding output, pay each party
its share. To move money, they simply sign a *new* commitment and throw the old
one away.

But "throw away" isn't enforceable on its own: nothing physically stops a cheater
from broadcasting a stale commitment where they were richer. The fix — the single
idea that makes off-chain state trustless — is the **revocation key**. Each
commitment's ``to_local`` output can be spent two ways:

  * by its owner, but only after a ``to_self_delay`` (OP_CHECKSEQUENCEVERIFY); or
  * immediately by the *counterparty*, if they hold the **revocation private key**.

That revocation key is a blinded 2-of-2 secret (BOLT-3 §"revocationpubkey"): it
can only be assembled once the owner *reveals* the per-commitment secret for a
state — which is exactly what "revoking" an old state means. So publishing a
revoked commitment hands the counterparty the key to take *everything* before the
delay elapses. Cheating is not merely detected; it is punished.

This module builds the real BOLT-3 scripts and key derivations from scratch. It
models a channel with no in-flight HTLCs (``to_local`` + ``to_remote`` only); HTLC
routing is Lightning's other half and out of scope here.
"""

from __future__ import annotations

from dataclasses import dataclass

from .curve import G, N, Point
from .ecdsa import der, sign
from .keys import PublicKey, hash160
from .ripemd160 import ripemd160
from .script import (
    Script, encode_num, OP_IF, OP_NOTIF, OP_ELSE, OP_ENDIF, OP_DROP, OP_DUP,
    OP_SWAP, OP_SIZE, OP_2, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160,
    OP_CHECKSIG, OP_CHECKMULTISIG, OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY,
)
from .sha256 import sha256
from .transaction import (
    Tx, TxInput, TxOutput, multisig_script, p2wpkh_script, p2wsh_script,
    p2wsh_address, SIGHASH_ALL,
)


def _sec(point: Point) -> bytes:
    """The 33-byte compressed SEC serialization used everywhere in BOLT-3 hashes."""
    return PublicKey(point).sec(compressed=True)


def _sha256_int(data: bytes) -> int:
    return int.from_bytes(sha256(data), "big")


# --- BOLT-3 key derivation ---------------------------------------------------
def derive_pubkey(basepoint: Point, per_commitment_point: Point) -> Point:
    """A per-commitment public key: ``basepoint + SHA256(ppc || basepoint)·G``.

    Rotating every commitment's keys this way means an old commitment sitting in
    a watchtower reveals nothing about the parties' long-term basepoints."""
    h = _sha256_int(_sec(per_commitment_point) + _sec(basepoint))
    return basepoint + h * G


def derive_privkey(basepoint_secret: int, per_commitment_point: Point) -> int:
    """The private key matching :func:`derive_pubkey` — computable only by the
    owner of ``basepoint_secret``: ``basepoint_secret + SHA256(ppc || basepoint)``."""
    basepoint = basepoint_secret * G
    h = _sha256_int(_sec(per_commitment_point) + _sec(basepoint))
    return (basepoint_secret + h) % N


def derive_revocation_pubkey(revocation_basepoint: Point,
                             per_commitment_point: Point) -> Point:
    """The blinded revocation key (BOLT-3):

        revocation_basepoint · SHA256(revocation_basepoint || ppc)
          + per_commitment_point · SHA256(ppc || revocation_basepoint)

    It mixes one point from each party. Neither the node supplying the basepoint
    nor the node supplying the per-commitment point can know the matching private
    key alone — that needs *both* underlying secrets."""
    h1 = _sha256_int(_sec(revocation_basepoint) + _sec(per_commitment_point))
    h2 = _sha256_int(_sec(per_commitment_point) + _sec(revocation_basepoint))
    return h1 * revocation_basepoint + h2 * per_commitment_point


def derive_revocation_privkey(revocation_basepoint_secret: int,
                              per_commitment_secret: int) -> int:
    """Assemble the revocation *private* key. This is the crux: it exists only
    once *both* secrets are in one hand — which happens the moment the owner
    reveals ``per_commitment_secret`` to revoke that state."""
    revocation_basepoint = revocation_basepoint_secret * G
    per_commitment_point = per_commitment_secret * G
    h1 = _sha256_int(_sec(revocation_basepoint) + _sec(per_commitment_point))
    h2 = _sha256_int(_sec(per_commitment_point) + _sec(revocation_basepoint))
    return (revocation_basepoint_secret * h1 + per_commitment_secret * h2) % N


def per_commitment_secret(seed: bytes, index: int) -> bytes:
    """Derive the per-commitment secret for ``index`` from a 32-byte ``seed``
    (BOLT-3 Appendix D ``generate_from_seed``).

    Secrets are handed out from the top index (2**48 - 1) downward. The bit-flip
    cascade means that revealing the secret for index *i* lets the receiver
    recompute every secret for the higher indices already revoked — so they store
    O(1) state, not one secret per update. (The compact O(48)-entry *storage*
    tree is an optimization we don't need here; generation is the whole idea.)"""
    p = bytearray(seed)
    for b in range(47, -1, -1):
        if (index >> b) & 1:
            p[b // 8] ^= 1 << (b % 8)      # flip bit (b mod 8) of byte (b div 8)
            p = bytearray(sha256(bytes(p)))
    return bytes(p)


# --- funding output (2-of-2) -------------------------------------------------
def funding_script(pubkey_a: bytes, pubkey_b: bytes) -> Script:
    """The channel funding witnessScript: a 2-of-2 bare multisig with the two
    keys sorted lexicographically (BOLT-3 orders them so both peers build the
    identical script)."""
    return multisig_script(2, sorted([pubkey_a, pubkey_b]))


def funding_address(pubkey_a: bytes, pubkey_b: bytes, testnet: bool = False) -> str:
    """The ``bc1q…/tb1…`` P2WSH address both parties fund to open the channel."""
    return p2wsh_address(funding_script(pubkey_a, pubkey_b), testnet=testnet)


# --- the to_local output script ----------------------------------------------
def to_local_script(revocation_pubkey: bytes, to_self_delay: int,
                    local_delayed_pubkey: bytes) -> Script:
    """The BOLT-3 ``to_local`` witnessScript — the heart of the penalty scheme:

        OP_IF   <revocation_pubkey>
        OP_ELSE <to_self_delay> OP_CHECKSEQUENCEVERIFY OP_DROP <local_delayed_pubkey>
        OP_ENDIF OP_CHECKSIG

    The IF branch is the counterparty's instant justice path; the ELSE branch is
    the owner's own funds, spendable only after ``to_self_delay`` blocks."""
    return Script([
        OP_IF, revocation_pubkey,
        OP_ELSE, encode_num(to_self_delay), OP_CHECKSEQUENCEVERIFY, OP_DROP,
        local_delayed_pubkey,
        OP_ENDIF, OP_CHECKSIG,
    ])


# --- commitment transaction --------------------------------------------------
@dataclass
class Commitment:
    """A signed-or-unsigned commitment transaction plus the metadata a spender
    (owner *or* punisher) needs to spend its ``to_local`` output."""
    tx: Tx
    to_local_script: Script
    to_local_index: int | None      # output index of to_local (None if 0-value)
    to_local_amount: int


def commitment_tx(funding_txid: bytes, funding_index: int, *,
                  to_local_amount: int, to_remote_amount: int,
                  revocation_pubkey: bytes, local_delayed_pubkey: bytes,
                  to_self_delay: int, remote_pubkey: bytes,
                  testnet: bool = False) -> Commitment:
    """Build one party's commitment transaction spending the funding output.

    Two outputs: ``to_local`` (this party's balance, behind the delay/revocation
    :func:`to_local_script`) and ``to_remote`` (the counterparty's balance, a
    plain P2WPKH they can sweep immediately — they aren't the one who might cheat
    with *this* transaction). Still needs the 2-of-2 funding signature from both
    peers before it is valid; see :func:`sign_funding`."""
    ts = to_local_script(revocation_pubkey, to_self_delay, local_delayed_pubkey)
    outputs, to_local_index = [], None
    if to_local_amount > 0:
        to_local_index = len(outputs)
        outputs.append(TxOutput(to_local_amount, p2wsh_script(sha256(ts.raw_serialize()))))
    if to_remote_amount > 0:
        outputs.append(TxOutput(to_remote_amount, p2wpkh_script(hash160(remote_pubkey))))
    tx = Tx(2, [TxInput(funding_txid, funding_index)], outputs, testnet=testnet)
    return Commitment(tx, ts, to_local_index, to_local_amount)


def sign_funding(tx: Tx, index: int, funding_amount: int,
                 secret_a: int, secret_b: int) -> None:
    """2-of-2 sign a spend of the funding output. Orders the two signatures to
    match the sorted key order inside :func:`funding_script`, as OP_CHECKMULTISIG
    requires."""
    pub_a = PublicKey(secret_a * G).sec()
    pub_b = PublicKey(secret_b * G).sec()
    order = sorted([(pub_a, secret_a), (pub_b, secret_b)], key=lambda kv: kv[0])
    witness_script = multisig_script(2, [pub for pub, _ in order])
    tx.sign_input_p2wsh_multisig(index, [sec for _, sec in order], witness_script, funding_amount)


# --- spending the to_local output --------------------------------------------
def _to_local_z(tx: Tx, index: int, commitment: Commitment) -> int:
    """The BIP-143 sighash for a to_local spend: scriptCode is the witnessScript,
    and the value committed to is the to_local amount."""
    return tx.sig_hash_bip143(index, commitment.to_local_script, commitment.to_local_amount)


def penalty_tx(commitment: Commitment, sweep_script: Script, fee: int = 0) -> Tx:
    """Build the counterparty's *justice* transaction: sweep a broadcast, revoked
    commitment's ``to_local`` output to an address they control. nSequence is 0 —
    the revocation path has no relative timelock, so it can land immediately (and
    must, before the cheater's own delayed path matures)."""
    if commitment.to_local_index is None:
        raise ValueError("this commitment has no to_local output to sweep")
    prev = bytes.fromhex(commitment.tx.txid())
    tin = TxInput(prev, commitment.to_local_index, sequence=0)
    return Tx(2, [tin], [TxOutput(commitment.to_local_amount - fee, sweep_script)])


def sign_penalty(tx: Tx, index: int, commitment: Commitment,
                 revocation_privkey: int) -> None:
    """Sign the penalty input with the assembled revocation key and take the
    IF branch. The witness stack is ``<sig> <1> <witnessScript>``: the ``1`` is a
    truthy selector that makes OP_IF choose the revocation path."""
    z = _to_local_z(tx, index, commitment)
    sig = der(sign(revocation_privkey, z, low_s=True)) + SIGHASH_ALL.to_bytes(1, "big")
    tx.inputs[index].witness = [sig, b"\x01", commitment.to_local_script.raw_serialize()]


def sign_to_local_delayed(tx: Tx, index: int, commitment: Commitment,
                          local_delayed_privkey: int) -> None:
    """Sign the owner's own delayed reclaim of ``to_local`` (the ELSE branch).

    The witness is ``<sig> <> <witnessScript>``: the empty item is a falsy
    selector so OP_IF falls through to the OP_CHECKSEQUENCEVERIFY branch. This
    only confirms once the spending input's nSequence ≥ ``to_self_delay``; set
    that on the input before signing."""
    z = _to_local_z(tx, index, commitment)
    sig = der(sign(local_delayed_privkey, z, low_s=True)) + SIGHASH_ALL.to_bytes(1, "big")
    tx.inputs[index].witness = [sig, b"", commitment.to_local_script.raw_serialize()]


# --- HTLCs: the contracts that route a payment across hops -------------------
# A Hash-Time-Locked Contract pays out to whoever reveals a preimage R with
# hash(R) == payment_hash, or refunds the sender after a timeout. Chain them
# across channels (Alice→Bob→Carol) with *decreasing* timeouts and one preimage
# settles the whole path trustlessly — the core of Lightning routing.

def payment_hash(preimage: bytes) -> bytes:
    """A payment is identified by ``SHA256(preimage)``. The receiver picks a
    random preimage, shares only its hash (the invoice), and reveals the preimage
    to claim — which simultaneously lets each hop claim from the one before it."""
    return sha256(preimage)


def htlc_offered_script(revocation_pubkey: bytes, remote_htlcpubkey: bytes,
                        local_htlcpubkey: bytes, payment_hash: bytes) -> Script:
    """The BOLT-3 *offered* HTLC witnessScript (the output on the paying side).

    Three ways to spend: the counterparty with the **revocation key** (if this is
    a revoked commitment), the counterparty with the **preimage** (they got paid),
    or the owner via a timelocked HTLC-timeout transaction (a 2-of-2 that forces
    the delay). The ``OP_SIZE 32 OP_EQUAL`` gate checks whether a 32-byte preimage
    was supplied to pick the preimage vs timeout branch."""
    return Script([
        OP_DUP, OP_HASH160, hash160(revocation_pubkey), OP_EQUAL,
        OP_IF,
            OP_CHECKSIG,
        OP_ELSE,
            remote_htlcpubkey, OP_SWAP, OP_SIZE, encode_num(32), OP_EQUAL,
            OP_NOTIF,
                OP_DROP, OP_2, OP_SWAP, local_htlcpubkey, OP_2, OP_CHECKMULTISIG,
            OP_ELSE,
                OP_HASH160, ripemd160(payment_hash), OP_EQUALVERIFY,
                OP_CHECKSIG,
            OP_ENDIF,
        OP_ENDIF,
    ])


def htlc_received_script(revocation_pubkey: bytes, remote_htlcpubkey: bytes,
                         local_htlcpubkey: bytes, payment_hash: bytes,
                         cltv_expiry: int) -> Script:
    """The BOLT-3 *received* HTLC witnessScript (the output on the paid side).

    Symmetric to the offered one, but the branches swap roles: the owner claims
    with the **preimage** (via a 2-of-2 HTLC-success tx), or the counterparty
    refunds after an absolute ``cltv_expiry`` (OP_CHECKLOCKTIMEVERIFY) — or sweeps
    instantly with the revocation key. The decreasing ``cltv_expiry`` per hop is
    what makes multi-hop routing safe for the middle nodes."""
    return Script([
        OP_DUP, OP_HASH160, hash160(revocation_pubkey), OP_EQUAL,
        OP_IF,
            OP_CHECKSIG,
        OP_ELSE,
            remote_htlcpubkey, OP_SWAP, OP_SIZE, encode_num(32), OP_EQUAL,
            OP_IF,
                OP_HASH160, ripemd160(payment_hash), OP_EQUALVERIFY,
                OP_2, OP_SWAP, local_htlcpubkey, OP_2, OP_CHECKMULTISIG,
            OP_ELSE,
                OP_DROP, encode_num(cltv_expiry), OP_CHECKLOCKTIMEVERIFY, OP_DROP,
                OP_CHECKSIG,
            OP_ENDIF,
        OP_ENDIF,
    ])


def htlc_script(payment_hash: bytes, receiver_pubkey: bytes,
                sender_pubkey: bytes, cltv_expiry: int) -> Script:
    """A *canonical* HTLC — the logical contract a hop enforces, stripped of the
    channel's revocation/second-stage machinery (which BOLT-3's fuller scripts add
    for unilateral closes). This is the classic hashlock-or-timeout also used by
    cross-chain atomic swaps, and the form the routing demo walks through:

        OP_IF   OP_HASH160 <ripemd160(payment_hash)> OP_EQUALVERIFY <receiver> OP_CHECKSIG
        OP_ELSE <cltv_expiry> OP_CHECKLOCKTIMEVERIFY OP_DROP <sender> OP_CHECKSIG
        OP_ENDIF

    Claim path (receiver, needs the preimage): witness ``<sig> <preimage> <1>``.
    Refund path (sender, after the timeout):  witness ``<sig> <>``."""
    return Script([
        OP_IF,
            OP_HASH160, ripemd160(payment_hash), OP_EQUALVERIFY,
            receiver_pubkey, OP_CHECKSIG,
        OP_ELSE,
            encode_num(cltv_expiry), OP_CHECKLOCKTIMEVERIFY, OP_DROP,
            sender_pubkey, OP_CHECKSIG,
        OP_ENDIF,
    ])
