"""A minimal transaction + UTXO model.

This is the conceptual core a double-spend needs: a transaction spends specific
previous outputs (inputs) and creates new ones (outputs), and two transactions
that spend the *same* input are in conflict — only one can ever be in the chain.

It is deliberately simplified (recipients are plain labels, no scripts, no DER):
just enough to give every payment a real, hash-derived txid and to detect
conflicts. The full byte-exact serialization Bitcoin broadcasts is built later,
for the testnet stage.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .sha256 import double_sha256


@dataclass(frozen=True)
class TxIn:
    txid: str        # the funding transaction
    vout: int        # which output of it

    def serialize(self) -> bytes:
        return bytes.fromhex(self.txid) + self.vout.to_bytes(4, "little")


@dataclass(frozen=True)
class TxOut:
    value: int       # in satoshis
    recipient: str   # a label, e.g. "merchant"

    def serialize(self) -> bytes:
        r = self.recipient.encode()
        return self.value.to_bytes(8, "little") + len(r).to_bytes(1, "little") + r


@dataclass
class Tx:
    vin: list[TxIn] = field(default_factory=list)
    vout: list[TxOut] = field(default_factory=list)

    def serialize(self) -> bytes:
        out = len(self.vin).to_bytes(1, "little")
        for i in self.vin:
            out += i.serialize()
        out += len(self.vout).to_bytes(1, "little")
        for o in self.vout:
            out += o.serialize()
        return out

    @property
    def txid(self) -> str:
        # double-SHA256, shown in the usual little-endian display order
        return double_sha256(self.serialize())[::-1].hex()


def conflicts(a: Tx, b: Tx) -> bool:
    """True if two transactions try to spend any of the same outputs."""
    return bool(set(a.vin) & set(b.vin))


class UTXOSet:
    """A tiny set of unspent outputs keyed by (txid, vout)."""

    def __init__(self):
        self.utxos: set[tuple[str, int]] = set()

    def add(self, tx: Tx) -> None:
        for vout in range(len(tx.vout)):
            self.utxos.add((tx.txid, vout))

    def is_spendable(self, txin: TxIn) -> bool:
        return (txin.txid, txin.vout) in self.utxos

    def apply(self, tx: Tx) -> None:
        """Spend the inputs, create the outputs. Raises on a double-spend."""
        for i in tx.vin:
            if not self.is_spendable(i):
                raise ValueError(f"input {i.txid}:{i.vout} already spent or unknown")
        for i in tx.vin:
            self.utxos.discard((i.txid, i.vout))
        self.add(tx)
