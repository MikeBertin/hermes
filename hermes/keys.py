"""Private keys, public keys, WIF, and Bitcoin addresses.

This is the pipeline Karpathy's tour walks through:

    secret (a number)  --*G-->  public point  --SEC-->  bytes
        --SHA256--> --RIPEMD160--> 20-byte hash --+version+checksum--> address

Plus WIF (Wallet Import Format), the Base58Check encoding of the private key
itself.
"""

from __future__ import annotations

from .base58 import b58check_encode
from .bech32 import encode_segwit
from .curve import G, N, P, Point
from .ripemd160 import ripemd160
from .sha256 import sha256

# version bytes
_ADDR_VERSION = {False: b"\x00", True: b"\x6f"}  # mainnet / testnet P2PKH
_WIF_VERSION = {False: b"\x80", True: b"\xef"}
_HRP = {False: "bc", True: "tb"}                 # mainnet / testnet bech32 prefix


def hash160(data: bytes) -> bytes:
    """RIPEMD-160(SHA-256(data)) — Bitcoin's public-key hash."""
    return ripemd160(sha256(data))


class PublicKey:
    """A point on secp256k1, with Bitcoin serialization helpers."""

    def __init__(self, point: Point):
        self.point = point

    def sec(self, compressed: bool = True) -> bytes:
        """SEC serialization of the point."""
        x = self.point.x.num.to_bytes(32, "big")
        if not compressed:
            y = self.point.y.num.to_bytes(32, "big")
            return b"\x04" + x + y
        prefix = b"\x02" if self.point.y.num % 2 == 0 else b"\x03"
        return prefix + x

    @classmethod
    def parse(cls, sec: bytes) -> "PublicKey":
        """Recover the point from SEC bytes. For compressed keys we solve for y
        with a modular square root (secp256k1's prime is ≡ 3 mod 4, so the root
        is just a single modular exponentiation), then pick the parity."""
        if sec[0] == 4:
            x = int.from_bytes(sec[1:33], "big")
            y = int.from_bytes(sec[33:65], "big")
            return cls(Point(x, y))
        x = int.from_bytes(sec[1:33], "big")
        alpha = (pow(x, 3, P) + 7) % P
        beta = pow(alpha, (P + 1) // 4, P)        # the square root
        even_beta = beta if beta % 2 == 0 else P - beta
        odd_beta = P - even_beta
        want_even = sec[0] == 2
        return cls(Point(x, even_beta if want_even else odd_beta))

    def hash160(self, compressed: bool = True) -> bytes:
        return hash160(self.sec(compressed))

    def address(self, compressed: bool = True, testnet: bool = False) -> str:
        payload = _ADDR_VERSION[testnet] + self.hash160(compressed)
        return b58check_encode(payload)

    def p2wpkh_address(self, testnet: bool = False) -> str:
        """Native SegWit (P2WPKH) address: bech32 of witness v0 + the key hash.
        Always uses the *compressed* pubkey — SegWit forbids uncompressed keys."""
        return encode_segwit(_HRP[testnet], 0, self.hash160(compressed=True))


class PrivateKey:
    """A secret scalar. ``public_key()`` derives the matching point."""

    def __init__(self, secret: int):
        if not 1 <= secret < N:
            raise ValueError("secret out of range 1..n-1")
        self.secret = secret

    def public_key(self) -> PublicKey:
        return PublicKey(self.secret * G)

    def wif(self, compressed: bool = True, testnet: bool = False) -> str:
        payload = _WIF_VERSION[testnet] + self.secret.to_bytes(32, "big")
        if compressed:
            payload += b"\x01"
        return b58check_encode(payload)

    def address(self, compressed: bool = True, testnet: bool = False) -> str:
        return self.public_key().address(compressed, testnet)
