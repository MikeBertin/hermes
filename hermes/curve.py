"""secp256k1 — the elliptic curve Bitcoin uses.

The curve is ``y^2 = x^3 + 7`` over the prime field GF(p). Its points, plus a
special "point at infinity" that acts as zero, form a group: you can *add* two
points geometrically (chord-and-tangent) and *multiply* a point by an integer
(repeated addition). That scalar multiplication is the one-way street public-key
cryptography stands on:

    public_key = private_key * G

where ``G`` is a fixed generator point and ``private_key`` is just a 256-bit
number. Recovering the number from the point would mean solving the discrete-log
problem, which nobody knows how to do.

Everything here is built from :class:`hermes.field.FieldElement` — no crypto
libraries.
"""

from __future__ import annotations

from .field import FieldElement

# secp256k1 domain parameters --------------------------------------------------
P = 2**256 - 2**32 - 977                  # the field prime
A = 0                                      # curve coefficient a (y^2 = x^3 + ax + b)
B = 7                                      # curve coefficient b
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # group order
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _f(num: int) -> FieldElement:
    """Wrap a raw integer as a field element on secp256k1's prime field."""
    return FieldElement(num % P, P)


class Point:
    """A point on secp256k1. ``x is None`` represents the point at infinity."""

    __slots__ = ("x", "y")

    def __init__(self, x, y):
        if x is None and y is None:
            self.x = None
            self.y = None
            return
        self.x = x if isinstance(x, FieldElement) else _f(x)
        self.y = y if isinstance(y, FieldElement) else _f(y)
        # verify the point actually lies on the curve y^2 = x^3 + 7
        if self.y ** 2 != self.x ** 3 + _f(B):
            raise ValueError(f"({self.x.num}, {self.y.num}) is not on secp256k1")

    # --- plumbing ---------------------------------------------------------
    @property
    def is_infinity(self) -> bool:
        return self.x is None

    def __repr__(self) -> str:
        if self.is_infinity:
            return "Point(infinity)"
        return f"Point({hex(self.x.num)}, {hex(self.y.num)})"

    def __eq__(self, other) -> bool:
        return isinstance(other, Point) and self.x == other.x and self.y == other.y

    def __hash__(self) -> int:
        return hash((None, None) if self.is_infinity else (self.x, self.y))

    # --- the group law ----------------------------------------------------
    def __add__(self, other: "Point") -> "Point":
        # adding the identity (point at infinity)
        if self.is_infinity:
            return other
        if other.is_infinity:
            return self

        # P + (-P) = infinity  (same x, mirrored y -> vertical line)
        if self.x == other.x and self.y != other.y:
            return Point(None, None)

        if self == other:
            # doubling: tangent line. If y == 0 the tangent is vertical.
            if self.y.num == 0:
                return Point(None, None)
            slope = (_f(3) * self.x ** 2 + _f(A)) / (_f(2) * self.y)
        else:
            # distinct points: slope of the chord
            slope = (other.y - self.y) / (other.x - self.x)

        x3 = slope ** 2 - self.x - other.x
        y3 = slope * (self.x - x3) - self.y
        return Point(x3, y3)

    def __rmul__(self, coefficient: int) -> "Point":
        """Scalar multiplication ``k * point`` via double-and-add."""
        coef = coefficient % N
        result = Point(None, None)  # identity
        current = self
        while coef:
            if coef & 1:
                result = result + current
            current = current + current
            coef >>= 1
        return result


# The generator point G and a convenience handle to the identity.
G = Point(_GX, _GY)
INFINITY = Point(None, None)
