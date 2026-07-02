"""BIP-39 — turning randomness into a memorable seed phrase, and back.

Entropy (128–256 bits) is checksummed with SHA-256, sliced into 11-bit chunks,
and each chunk indexes a fixed 2048-word list to give a mnemonic. The mnemonic
plus an optional passphrase is then stretched through PBKDF2-HMAC-SHA512 (2048
rounds) into the 512-bit seed that BIP-32 grows a key tree from.
"""

from __future__ import annotations

import os
import unicodedata

from .sha256 import sha256
from .sha512 import pbkdf2_hmac_sha512

_WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "english.txt")
_wordlist: list[str] | None = None


def wordlist() -> list[str]:
    """Lazily load the 2048-word English wordlist."""
    global _wordlist
    if _wordlist is None:
        with open(_WORDLIST_PATH, encoding="utf-8") as f:
            _wordlist = [w.strip() for w in f if w.strip()]
        if len(_wordlist) != 2048:
            raise ValueError(f"wordlist must be 2048 words, got {len(_wordlist)}")
    return _wordlist


def entropy_to_mnemonic(entropy: bytes) -> str:
    if len(entropy) not in (16, 20, 24, 28, 32):
        raise ValueError("entropy must be 128–256 bits in 32-bit steps")
    checksum_bits = len(entropy) * 8 // 32
    checksum = sha256(entropy)[0] >> (8 - checksum_bits)
    bits = int.from_bytes(entropy, "big") << checksum_bits | checksum
    total_bits = len(entropy) * 8 + checksum_bits
    words = wordlist()
    out = []
    for i in range(total_bits // 11):
        shift = total_bits - 11 * (i + 1)
        out.append(words[(bits >> shift) & 0x7FF])
    return " ".join(out)


def mnemonic_to_entropy(mnemonic: str) -> bytes:
    words = wordlist()
    index = {w: i for i, w in enumerate(words)}
    parts = mnemonic.split()
    if len(parts) not in (12, 15, 18, 21, 24):
        raise ValueError(f"mnemonic must be 12/15/18/21/24 words, got {len(parts)}")
    bits = 0
    for w in parts:
        if w not in index:
            raise ValueError(f"word not in list: {w}")
        bits = (bits << 11) | index[w]
    total_bits = len(parts) * 11
    checksum_bits = total_bits // 33
    ent_bits = total_bits - checksum_bits
    entropy = (bits >> checksum_bits).to_bytes(ent_bits // 8, "big")
    if sha256(entropy)[0] >> (8 - checksum_bits) != bits & ((1 << checksum_bits) - 1):
        raise ValueError("bad mnemonic checksum")
    return entropy


def is_valid(mnemonic: str) -> bool:
    try:
        mnemonic_to_entropy(mnemonic)
        return True
    except ValueError:
        return False


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    mnemonic = unicodedata.normalize("NFKD", mnemonic)
    salt = unicodedata.normalize("NFKD", "mnemonic" + passphrase)
    return pbkdf2_hmac_sha512(mnemonic.encode("utf-8"), salt.encode("utf-8"), 2048, 64)
