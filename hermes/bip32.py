"""BIP-32 — hierarchical deterministic keys.

One 512-bit seed becomes a master key, and from it an entire tree of child keys,
each addressed by a path like ``m/44'/0'/0'/0/3``. A ``'`` marks a *hardened*
step, which mixes in the parent's private key so that leaking a public key can't
expose its siblings. This is what every modern wallet does: back up one phrase,
recover every address.
"""

from __future__ import annotations

from dataclasses import dataclass

from .base58 import b58check_encode
from .curve import G, N
from .keys import PublicKey, hash160
from .sha512 import hmac_sha512

HARDENED = 0x80000000
_XPRV = bytes.fromhex("0488ade4")   # mainnet version bytes
_XPUB = bytes.fromhex("0488b21e")


@dataclass
class HDKey:
    secret: int
    chain_code: bytes
    depth: int = 0
    parent_fingerprint: bytes = b"\x00\x00\x00\x00"
    child_number: int = 0

    # --- construction -----------------------------------------------------
    @classmethod
    def from_seed(cls, seed: bytes) -> "HDKey":
        I = hmac_sha512(b"Bitcoin seed", seed)
        return cls(int.from_bytes(I[:32], "big"), I[32:])

    # --- derivation -------------------------------------------------------
    def child(self, index: int) -> "HDKey":
        hardened = index >= HARDENED
        if hardened:
            data = b"\x00" + self.secret.to_bytes(32, "big") + index.to_bytes(4, "big")
        else:
            data = self.public_sec() + index.to_bytes(4, "big")
        I = hmac_sha512(self.chain_code, data)
        IL = int.from_bytes(I[:32], "big")
        child_secret = (IL + self.secret) % N
        if IL >= N or child_secret == 0:
            # probability ~2^-128; BIP-32 says such a child is invalid and the
            # caller should proceed with the next index
            raise ValueError(f"invalid child key at index {index}; use the next index")
        return HDKey(child_secret, I[32:], self.depth + 1, self.fingerprint(), index)

    def derive_path(self, path: str) -> "HDKey":
        node = self
        for part in path.split("/"):
            if part in ("m", ""):
                continue
            hardened = part.endswith("'") or part.endswith("h")
            index = int(part.rstrip("'h")) + (HARDENED if hardened else 0)
            node = node.child(index)
        return node

    # --- public side ------------------------------------------------------
    def public_sec(self) -> bytes:
        return PublicKey(self.secret * G).sec(compressed=True)

    def fingerprint(self) -> bytes:
        return hash160(self.public_sec())[:4]

    def address(self, testnet: bool = False) -> str:
        return PublicKey(self.secret * G).address(compressed=True, testnet=testnet)

    # --- serialization ----------------------------------------------------
    def _serialize(self, version: bytes, key_data: bytes) -> str:
        payload = (
            version
            + self.depth.to_bytes(1, "big")
            + self.parent_fingerprint
            + self.child_number.to_bytes(4, "big")
            + self.chain_code
            + key_data
        )
        return b58check_encode(payload)

    def xprv(self) -> str:
        return self._serialize(_XPRV, b"\x00" + self.secret.to_bytes(32, "big"))

    def xpub(self) -> str:
        return self._serialize(_XPUB, self.public_sec())
