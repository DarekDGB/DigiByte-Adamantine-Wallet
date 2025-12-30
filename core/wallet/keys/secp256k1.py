"""
Minimal secp256k1 implementation.

Goal: iPhone + CI-safe correctness.
We implement only what we need first:
- scalar multiplication k*G
- point addition
- compressed/uncompressed public key encoding
- parsing compressed/uncompressed pubkeys (for watch-only BIP32 public derivation)
- tweak-add: (tweak*G) + PubKey

Reference curve: secp256k1
y^2 = x^3 + 7 mod p
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..errors import WalletError


class Secp256k1Error(WalletError):
    pass


# Curve parameters
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
B = 7

# Base point (generator)
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424

# Curve order
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _modinv(a: int, n: int) -> int:
    if a == 0:
        raise Secp256k1Error("Inverse of zero.")
    return pow(a, n - 2, n)


@dataclass(frozen=True)
class Point:
    x: Optional[int]
    y: Optional[int]

    @property
    def is_infinity(self) -> bool:
        return self.x is None and self.y is None


INF = Point(None, None)
G = Point(Gx, Gy)


def _is_on_curve(Pt: Point) -> bool:
    if Pt.is_infinity:
        return True
    x, y = Pt.x, Pt.y
    assert x is not None and y is not None
    return (y * y - (x * x * x + B)) % P == 0


def _point_add(p1: Point, p2: Point) -> Point:
    if p1.is_infinity:
        return p2
    if p2.is_infinity:
        return p1

    x1, y1 = p1.x, p1.y
    x2, y2 = p2.x, p2.y
    assert x1 is not None and y1 is not None and x2 is not None and y2 is not None

    # p1 + (-p1) = INF
    if x1 == x2 and (y1 + y2) % P == 0:
        return INF

    if x1 == x2 and y1 == y2:
        # doubling
        lam = (3 * x1 * x1 + A) * _modinv(2 * y1 % P, P) % P
    else:
        # addition
        lam = (y2 - y1) * _modinv((x2 - x1) % P, P) % P

    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return Point(x3, y3)


def scalar_mult(k: int, point: Point = G) -> Point:
    if k < 0 or k >= N:
        raise Secp256k1Error("Scalar out of range.")
    if k == 0 or point.is_infinity:
        return INF

    result = INF
    addend = point

    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1

    return result


def pubkey_from_privkey(privkey_32: bytes, compressed: bool = True) -> bytes:
    if len(privkey_32) != 32:
        raise Secp256k1Error("Private key must be 32 bytes.")
    k = int.from_bytes(privkey_32, "big")
    if k <= 0 or k >= N:
        raise Secp256k1Error("Invalid private key scalar.")

    Pt = scalar_mult(k, G)
    if Pt.is_infinity or not _is_on_curve(Pt):
        raise Secp256k1Error("Derived point invalid.")

    return pubkey_from_point(Pt, compressed=compressed)


# ----------------------------
# Public key parsing/encoding
# ----------------------------

def _sqrt_mod_p(a: int) -> int:
    """
    sqrt(a) mod p for secp256k1 where p % 4 == 3:
    sqrt = a^((p+1)/4) mod p.
    """
    return pow(a, (P + 1) // 4, P)


def pubkey_from_point(point: Point, compressed: bool = True) -> bytes:
    if point.is_infinity or not _is_on_curve(point):
        raise Secp256k1Error("Invalid point.")
    x = point.x
    y = point.y
    assert x is not None and y is not None

    xb = x.to_bytes(32, "big")
    yb = y.to_bytes(32, "big")

    if not compressed:
        return b"\x04" + xb + yb

    prefix = b"\x03" if (y & 1) else b"\x02"
    return prefix + xb


def parse_pubkey(pubkey: bytes) -> Point:
    """
    Parse compressed (33) or uncompressed (65) secp256k1 public key into a Point.
    """
    if len(pubkey) == 33 and pubkey[0] in (2, 3):
        prefix = pubkey[0]
        x = int.from_bytes(pubkey[1:], "big")
        if x <= 0 or x >= P:
            raise Secp256k1Error("Invalid x for compressed pubkey.")

        # y^2 = x^3 + 7 mod p
        y2 = (pow(x, 3, P) + B) % P
        y = _sqrt_mod_p(y2)

        # choose parity based on prefix
        if (y & 1) != (prefix & 1):
            y = (-y) % P

        Pt = Point(x, y)
        if not _is_on_curve(Pt):
            raise Secp256k1Error("Parsed point not on curve.")
        return Pt

    if len(pubkey) == 65 and pubkey[0] == 4:
        x = int.from_bytes(pubkey[1:33], "big")
        y = int.from_bytes(pubkey[33:65], "big")
        Pt = Point(x, y)
        if not _is_on_curve(Pt):
            raise Secp256k1Error("Parsed point not on curve.")
        return Pt

    raise Secp256k1Error("Unsupported pubkey format.")


def tweak_add_pubkey(parent_pubkey: bytes, tweak32: bytes, compressed: bool = True) -> bytes:
    """
    Compute child_pub = parent_pub + (tweak * G)
    Used for BIP32 non-hardened public derivation.

    tweak must be 32 bytes and represent an integer in [1, N-1].
    """
    if len(tweak32) != 32:
        raise Secp256k1Error("tweak must be 32 bytes")
    tweak = int.from_bytes(tweak32, "big")
    if tweak <= 0 or tweak >= N:
        raise Secp256k1Error("Invalid tweak scalar")

    parent_pt = parse_pubkey(parent_pubkey)
    tweak_pt = scalar_mult(tweak, G)
    child_pt = _point_add(parent_pt, tweak_pt)

    if child_pt.is_infinity or not _is_on_curve(child_pt):
        raise Secp256k1Error("tweak-add resulted in invalid point")

    return pubkey_from_point(child_pt, compressed=compressed)
