"""Real Bitcoin transactions — the byte-exact wire format that nodes accept.

This is the bridge from "correct in theory" to "broadcastable". A transaction is
a version, a list of inputs (each pointing at a previous output it spends and
carrying an unlocking script), a list of outputs (an amount + a locking script),
and a locktime. To authorize an input you sign a specially-mangled copy of the
whole transaction (SIGHASH_ALL), DER-encode the signature, and drop it into the
input's script.

Unlike the simplified model in tx.py (used by the network sim), everything here
serializes to the exact bytes Bitcoin Core would hash and relay.
"""

from __future__ import annotations

import io

from .ecdsa import Signature, der, parse_der, sign, verify
from .keys import PublicKey, hash160
from .script import (
    Script, OP_0, OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_HASH160,
)
from .sha256 import double_sha256

SIGHASH_ALL = 1


# --- varint (CompactSize) ----------------------------------------------------
def encode_varint(i: int) -> bytes:
    if i < 0xFD:
        return i.to_bytes(1, "little")
    if i <= 0xFFFF:
        return b"\xfd" + i.to_bytes(2, "little")
    if i <= 0xFFFFFFFF:
        return b"\xfe" + i.to_bytes(4, "little")
    return b"\xff" + i.to_bytes(8, "little")


def read_varint(s: io.BytesIO) -> int:
    i = s.read(1)[0]
    if i == 0xFD:
        return int.from_bytes(s.read(2), "little")
    if i == 0xFE:
        return int.from_bytes(s.read(4), "little")
    if i == 0xFF:
        return int.from_bytes(s.read(8), "little")
    return i


def _serialize_script(script: Script | None) -> bytes:
    raw = script.raw_serialize() if script else b""
    return encode_varint(len(raw)) + raw


def _read_script(s: io.BytesIO) -> Script:
    length = read_varint(s)
    return Script.parse_raw(s.read(length))


# --- locking-script helpers --------------------------------------------------
def p2pkh_script(h160: bytes) -> Script:
    """The standard pay-to-public-key-hash locking script."""
    return Script([OP_DUP, OP_HASH160, h160, OP_EQUALVERIFY, OP_CHECKSIG])


def p2wpkh_script(h160: bytes) -> Script:
    """The native-SegWit P2WPKH locking script: ``OP_0 <20-byte key hash>``."""
    return Script([OP_0, h160])


# --- inputs / outputs --------------------------------------------------------
class TxInput:
    def __init__(self, prev_txid: bytes, prev_index: int,
                 script_sig: Script | None = None, sequence: int = 0xFFFFFFFF,
                 witness: list[bytes] | None = None):
        self.prev_txid = prev_txid          # 32 bytes, display (big-endian) order
        self.prev_index = prev_index
        self.script_sig = script_sig
        self.sequence = sequence
        self.witness = witness              # SegWit: the unlocking stack items

    @classmethod
    def parse(cls, s: io.BytesIO) -> "TxInput":
        prev_txid = s.read(32)[::-1]        # stored little-endian on the wire
        prev_index = int.from_bytes(s.read(4), "little")
        script_sig = _read_script(s)
        sequence = int.from_bytes(s.read(4), "little")
        return cls(prev_txid, prev_index, script_sig, sequence)

    def serialize(self) -> bytes:
        return (
            self.prev_txid[::-1]
            + self.prev_index.to_bytes(4, "little")
            + _serialize_script(self.script_sig)
            + self.sequence.to_bytes(4, "little")
        )


class TxOutput:
    def __init__(self, amount: int, script_pubkey: Script):
        self.amount = amount                # satoshis
        self.script_pubkey = script_pubkey

    @classmethod
    def parse(cls, s: io.BytesIO) -> "TxOutput":
        amount = int.from_bytes(s.read(8), "little")
        return cls(amount, _read_script(s))

    def serialize(self) -> bytes:
        return self.amount.to_bytes(8, "little") + _serialize_script(self.script_pubkey)


# --- transaction -------------------------------------------------------------
class Tx:
    def __init__(self, version: int, inputs: list[TxInput], outputs: list[TxOutput],
                 locktime: int = 0, testnet: bool = False):
        self.version = version
        self.inputs = inputs
        self.outputs = outputs
        self.locktime = locktime
        self.testnet = testnet

    @classmethod
    def parse(cls, data: bytes, testnet: bool = False) -> "Tx":
        s = io.BytesIO(data)
        version = int.from_bytes(s.read(4), "little")
        marker = s.read(2)
        segwit = marker == b"\x00\x01"      # SegWit marker+flag after the version
        if not segwit:
            s.seek(4)                       # rewind: those bytes were the input count
        inputs = [TxInput.parse(s) for _ in range(read_varint(s))]
        outputs = [TxOutput.parse(s) for _ in range(read_varint(s))]
        if segwit:
            for tin in inputs:
                tin.witness = [s.read(read_varint(s)) for _ in range(read_varint(s))]
        locktime = int.from_bytes(s.read(4), "little")
        return cls(version, inputs, outputs, locktime, testnet)

    def _has_witness(self) -> bool:
        return any(tin.witness is not None for tin in self.inputs)

    def _serialize_legacy(self) -> bytes:
        """The pre-SegWit byte layout (no marker/flag/witness). This is what the
        txid hashes — so a tx's identity doesn't depend on its signatures."""
        out = self.version.to_bytes(4, "little")
        out += encode_varint(len(self.inputs))
        for tin in self.inputs:
            out += tin.serialize()
        out += encode_varint(len(self.outputs))
        for tout in self.outputs:
            out += tout.serialize()
        out += self.locktime.to_bytes(4, "little")
        return out

    def serialize(self) -> bytes:
        """Full wire serialization — SegWit format (with the witness) when any
        input carries one, otherwise the legacy layout."""
        if not self._has_witness():
            return self._serialize_legacy()
        out = self.version.to_bytes(4, "little") + b"\x00\x01"   # marker + flag
        out += encode_varint(len(self.inputs))
        for tin in self.inputs:
            out += tin.serialize()
        out += encode_varint(len(self.outputs))
        for tout in self.outputs:
            out += tout.serialize()
        for tin in self.inputs:
            items = tin.witness or []
            out += encode_varint(len(items))
            for item in items:
                out += encode_varint(len(item)) + item
        out += self.locktime.to_bytes(4, "little")
        return out

    def txid(self) -> str:
        return double_sha256(self._serialize_legacy())[::-1].hex()

    # --- signing ----------------------------------------------------------
    def sig_hash(self, index: int, prev_script_pubkey: Script) -> int:
        """The legacy SIGHASH_ALL digest for input ``index``: every input's
        script is blanked except this one, which gets the prevout's script."""
        out = self.version.to_bytes(4, "little")
        out += encode_varint(len(self.inputs))
        for i, tin in enumerate(self.inputs):
            script = prev_script_pubkey if i == index else None
            out += TxInput(tin.prev_txid, tin.prev_index, script, tin.sequence).serialize()
        out += encode_varint(len(self.outputs))
        for tout in self.outputs:
            out += tout.serialize()
        out += self.locktime.to_bytes(4, "little")
        out += SIGHASH_ALL.to_bytes(4, "little")
        return int.from_bytes(double_sha256(out), "big")

    def sign_input(self, index: int, secret: int, prev_script_pubkey: Script) -> None:
        z = self.sig_hash(index, prev_script_pubkey)
        sig = der(sign(secret, z, low_s=True)) + SIGHASH_ALL.to_bytes(1, "big")
        sec = PublicKey(_g_mul(secret)).sec(compressed=True)
        self.inputs[index].script_sig = Script([sig, sec])

    def verify_input(self, index: int, prev_script_pubkey: Script) -> bool:
        tin = self.inputs[index]
        sig_bytes, sec = tin.script_sig.cmds[0], tin.script_sig.cmds[1]
        z = self.sig_hash(index, prev_script_pubkey)
        return verify(PublicKey.parse(sec).point, z, parse_der(sig_bytes[:-1]))

    # --- SegWit (BIP-143) signing -----------------------------------------
    def sig_hash_bip143(self, index: int, script_code: Script, amount: int) -> int:
        """The BIP-143 SIGHASH_ALL digest for a witness input.

        SegWit fixed two warts of the legacy sighash: the amount being signed is
        now committed to (no more lying to offline signers about fees), and the
        prevouts/sequences/outputs are pre-hashed once instead of re-serialized
        per input (so signing N inputs is linear, not quadratic).
        """
        prevouts = b"".join(
            tin.prev_txid[::-1] + tin.prev_index.to_bytes(4, "little")
            for tin in self.inputs
        )
        sequences = b"".join(tin.sequence.to_bytes(4, "little") for tin in self.inputs)
        outputs = b"".join(tout.serialize() for tout in self.outputs)
        tin = self.inputs[index]
        preimage = (
            self.version.to_bytes(4, "little")
            + double_sha256(prevouts)
            + double_sha256(sequences)
            + tin.prev_txid[::-1] + tin.prev_index.to_bytes(4, "little")
            + _serialize_script(script_code)
            + amount.to_bytes(8, "little")
            + tin.sequence.to_bytes(4, "little")
            + double_sha256(outputs)
            + self.locktime.to_bytes(4, "little")
            + SIGHASH_ALL.to_bytes(4, "little")
        )
        return int.from_bytes(double_sha256(preimage), "big")

    def sign_input_p2wpkh(self, index: int, secret: int, amount: int) -> None:
        """Sign a native-SegWit P2WPKH input. The scriptCode BIP-143 signs is the
        same P2PKH script the key hash would lock; the result goes in the witness
        (signature, pubkey), and the scriptSig stays empty."""
        sec = PublicKey(_g_mul(secret)).sec(compressed=True)
        script_code = p2pkh_script(hash160(sec))
        z = self.sig_hash_bip143(index, script_code, amount)
        sig = der(sign(secret, z, low_s=True)) + SIGHASH_ALL.to_bytes(1, "big")
        self.inputs[index].script_sig = Script([])
        self.inputs[index].witness = [sig, sec]

    def verify_input_p2wpkh(self, index: int, amount: int) -> bool:
        sig_bytes, sec = self.inputs[index].witness
        z = self.sig_hash_bip143(index, p2pkh_script(hash160(sec)), amount)
        return verify(PublicKey.parse(sec).point, z, parse_der(sig_bytes[:-1]))


def _g_mul(secret: int):
    from .curve import G
    return secret * G


# --- locking script from an address ------------------------------------------
def address_to_h160(address: str) -> bytes:
    from .base58 import b58check_decode
    return b58check_decode(address)[1:]      # drop the version byte


def p2pkh_from_address(address: str) -> Script:
    return p2pkh_script(address_to_h160(address))


def address_to_script(address: str) -> Script:
    """The locking script for paying any supported address — base58 P2PKH
    (``1.../m.../n...``) or native-SegWit P2WPKH (``bc1.../tb1...``)."""
    from .bech32 import decode_segwit
    if address[:3].lower() in ("bc1", "tb1"):
        hrp = address[:2].lower()
        witver, prog = decode_segwit(hrp, address)
        if witver is None:
            raise ValueError(f"invalid bech32 address: {address}")
        if witver != 0 or len(prog) != 20:
            raise ValueError("only witness-v0 P2WPKH payments are supported")
        return p2wpkh_script(prog)
    return p2pkh_from_address(address)


# --- testnet network I/O (read-only fetch + broadcast) -----------------------
def _api(testnet: bool) -> str:
    return "https://blockstream.info/testnet/api" if testnet else "https://blockstream.info/api"


def fetch_utxos(address: str, testnet: bool = True) -> list[dict]:
    """List confirmed/unconfirmed unspent outputs for an address."""
    import json
    import urllib.request
    url = f"{_api(testnet)}/address/{address}/utxo"
    return json.loads(urllib.request.urlopen(url, timeout=30).read())


def broadcast(raw_hex: str, testnet: bool = True) -> str:
    """POST a raw transaction; returns the txid on success."""
    import urllib.request
    req = urllib.request.Request(f"{_api(testnet)}/tx", data=raw_hex.encode(), method="POST")
    return urllib.request.urlopen(req, timeout=30).read().decode().strip()
