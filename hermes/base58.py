"""Base58 and Base58Check encoding.

Base58 is Base64 with the visually ambiguous characters removed (no 0, O, I, l
and no +/). Base58Check wraps a payload with a 4-byte double-SHA-256 checksum so
that a mistyped address fails loudly instead of sending coins into the void. This
is how WIF private keys and legacy ``1...`` addresses are written.
"""

from __future__ import annotations

from .sha256 import double_sha256

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_INDEX = {c: i for i, c in enumerate(ALPHABET)}


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    chars = []
    while n > 0:
        n, rem = divmod(n, 58)
        chars.append(ALPHABET[rem])
    # each leading zero byte becomes a leading '1'
    pad = len(data) - len(data.lstrip(b"\x00"))
    return "1" * pad + "".join(reversed(chars))


def b58decode(string: str) -> bytes:
    n = 0
    for ch in string:
        if ch not in _INDEX:
            raise ValueError(f"invalid base58 character {ch!r}")
        n = n * 58 + _INDEX[ch]
    # recover the bytes, then restore leading-zero bytes from leading '1's
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    pad = len(string) - len(string.lstrip("1"))
    return b"\x00" * pad + body


def b58check_encode(payload: bytes) -> str:
    checksum = double_sha256(payload)[:4]
    return b58encode(payload + checksum)


def b58check_decode(string: str) -> bytes:
    raw = b58decode(string)
    payload, checksum = raw[:-4], raw[-4:]
    if double_sha256(payload)[:4] != checksum:
        raise ValueError("bad Base58Check checksum")
    return payload
