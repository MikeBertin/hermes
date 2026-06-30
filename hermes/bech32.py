"""Bech32 / Bech32m address encoding (BIP-173, BIP-350).

SegWit addresses don't use Base58Check — they use bech32, a checksummed base-32
format that's case-insensitive, QR-friendly, and catches typos with a BCH code
(it can *locate* errors, not just detect them). Witness v0 (P2WPKH / P2WSH) uses
plain bech32; witness v1+ (Taproot) uses bech32m, which differs only by the
final XOR constant. The human-readable prefix is ``bc`` on mainnet, ``tb`` on
testnet.

Reference algorithm follows the worked code in BIP-173 / BIP-350.
"""

from __future__ import annotations

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

BECH32 = "bech32"     # witness v0
BECH32M = "bech32m"   # witness v1+
_CONST = {BECH32: 1, BECH32M: 0x2BC830A3}


def _polymod(values: list[int]) -> int:
    """The BCH checksum step shared by encode and verify."""
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _verify(hrp: str, data: list[int]) -> str | None:
    const = _polymod(_hrp_expand(hrp) + data)
    for spec, c in _CONST.items():
        if const == c:
            return spec
    return None


def _create_checksum(hrp: str, data: list[int], spec: str) -> list[int]:
    values = _hrp_expand(hrp) + data
    polymod = _polymod(values + [0] * 6) ^ _CONST[spec]
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_encode(hrp: str, data: list[int], spec: str) -> str:
    combined = data + _create_checksum(hrp, data, spec)
    return hrp + "1" + "".join(CHARSET[d] for d in combined)


def bech32_decode(bech: str) -> tuple[str | None, list[int] | None, str | None]:
    if any(ord(c) < 33 or ord(c) > 126 for c in bech):
        return None, None, None
    if bech.lower() != bech and bech.upper() != bech:
        return None, None, None            # mixed case is forbidden
    bech = bech.lower()
    pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return None, None, None
    if not all(c in CHARSET for c in bech[pos + 1:]):
        return None, None, None
    hrp = bech[:pos]
    data = [CHARSET.find(c) for c in bech[pos + 1:]]
    spec = _verify(hrp, data)
    if spec is None:
        return None, None, None
    return hrp, data[:-6], spec


def convertbits(data: list[int], frombits: int, tobits: int, pad: bool = True) -> list[int] | None:
    """Regroup a bit-stream from ``frombits``-wide to ``tobits``-wide units —
    here, the 8-bit witness program <-> 5-bit bech32 symbols."""
    acc = bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or value >> frombits:
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def encode_segwit(hrp: str, witver: int, witprog: bytes) -> str | None:
    """Encode a SegWit address from its witness version and program."""
    spec = BECH32 if witver == 0 else BECH32M
    data = convertbits(list(witprog), 8, 5)
    if data is None:
        return None
    ret = bech32_encode(hrp, [witver] + data, spec)
    # round-trip as a self-check (the reference impl does this too)
    if decode_segwit(hrp, ret) == (None, None):
        return None
    return ret


def decode_segwit(hrp: str, addr: str) -> tuple[int | None, bytes | None]:
    """Decode a SegWit address, validating the witness version/length rules."""
    hrpgot, data, spec = bech32_decode(addr)
    if hrpgot != hrp or data is None:
        return None, None
    decoded = convertbits(data[1:], 5, 8, False)
    if decoded is None or not 2 <= len(decoded) <= 40:
        return None, None
    witver = data[0]
    if witver > 16:
        return None, None
    if witver == 0 and len(decoded) not in (20, 32):
        return None, None
    if (witver == 0) != (spec == BECH32):     # v0<->bech32, v1+<->bech32m
        return None, None
    return witver, bytes(decoded)
