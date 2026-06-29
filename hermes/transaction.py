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
    Script, OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_HASH160,
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


# --- P2PKH helpers -----------------------------------------------------------
def p2pkh_script(h160: bytes) -> Script:
    """The standard pay-to-public-key-hash locking script."""
    return Script([OP_DUP, OP_HASH160, h160, OP_EQUALVERIFY, OP_CHECKSIG])


# --- inputs / outputs --------------------------------------------------------
class TxInput:
    def __init__(self, prev_txid: bytes, prev_index: int,
                 script_sig: Script | None = None, sequence: int = 0xFFFFFFFF):
        self.prev_txid = prev_txid          # 32 bytes, display (big-endian) order
        self.prev_index = prev_index
        self.script_sig = script_sig
        self.sequence = sequence

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
        inputs = [TxInput.parse(s) for _ in range(read_varint(s))]
        outputs = [TxOutput.parse(s) for _ in range(read_varint(s))]
        locktime = int.from_bytes(s.read(4), "little")
        return cls(version, inputs, outputs, locktime, testnet)

    def serialize(self) -> bytes:
        out = self.version.to_bytes(4, "little")
        out += encode_varint(len(self.inputs))
        for tin in self.inputs:
            out += tin.serialize()
        out += encode_varint(len(self.outputs))
        for tout in self.outputs:
            out += tout.serialize()
        out += self.locktime.to_bytes(4, "little")
        return out

    def txid(self) -> str:
        return double_sha256(self.serialize())[::-1].hex()

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


def _g_mul(secret: int):
    from .curve import G
    return secret * G


# --- P2PKH from an address ---------------------------------------------------
def address_to_h160(address: str) -> bytes:
    from .base58 import b58check_decode
    return b58check_decode(address)[1:]      # drop the version byte


def p2pkh_from_address(address: str) -> Script:
    return p2pkh_script(address_to_h160(address))


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
