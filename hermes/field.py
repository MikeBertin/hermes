"""Finite-field arithmetic over a prime field GF(p).

The whole of elliptic-curve cryptography is just arithmetic where the numbers
"wrap around" a prime ``p``. A :class:`FieldElement` is a single number in the
range ``0 .. p-1`` that knows how to add, subtract, multiply, divide and
exponentiate itself modulo ``p``. Division is multiplication by the modular
inverse, which Python gives us via ``pow(x, -1, p)`` (Fermat's little theorem
under the hood for prime ``p``).

Nothing here is Bitcoin-specific — it is the bedrock that :mod:`hermes.curve`
builds the secp256k1 group on top of.
"""

from __future__ import annotations


class FieldElement:
    __slots__ = ("num", "prime")

    def __init__(self, num: int, prime: int):
        if not 0 <= num < prime:
            raise ValueError(f"num {num} not in field range 0..{prime - 1}")
        self.num = num
        self.prime = prime

    # --- plumbing ---------------------------------------------------------
    def __repr__(self) -> str:
        return f"FieldElement_{self.prime}({self.num})"

    def __eq__(self, other) -> bool:
        return (
            isinstance(other, FieldElement)
            and self.num == other.num
            and self.prime == other.prime
        )

    def __hash__(self) -> int:
        return hash((self.num, self.prime))

    def _check(self, other: "FieldElement") -> None:
        if self.prime != other.prime:
            raise TypeError("cannot operate on elements from different fields")

    # --- field operations -------------------------------------------------
    def __add__(self, other: "FieldElement") -> "FieldElement":
        self._check(other)
        return FieldElement((self.num + other.num) % self.prime, self.prime)

    def __sub__(self, other: "FieldElement") -> "FieldElement":
        self._check(other)
        return FieldElement((self.num - other.num) % self.prime, self.prime)

    def __mul__(self, other: "FieldElement") -> "FieldElement":
        self._check(other)
        return FieldElement((self.num * other.num) % self.prime, self.prime)

    def __pow__(self, exponent: int) -> "FieldElement":
        # pow() handles negative exponents (modular inverse) on Python 3.8+.
        return FieldElement(pow(self.num, exponent, self.prime), self.prime)

    def __truediv__(self, other: "FieldElement") -> "FieldElement":
        self._check(other)
        return self * (other ** -1)

    def __rmul__(self, scalar: int) -> "FieldElement":
        # plain-integer * FieldElement, used occasionally for readability
        return FieldElement((scalar * self.num) % self.prime, self.prime)
