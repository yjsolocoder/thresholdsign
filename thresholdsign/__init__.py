"""thresholdsign - Shamir secret sharing over a prime field.

Public API: Share / split_secret / reconstruct_secret / evaluate_polynomial.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence

__all__ = [
    "DEFAULT_PRIME",
    "Share",
    "evaluate_polynomial",
    "reconstruct_secret",
    "split_secret",
]

# Mersenne prime 2**127 - 1: large enough for integer secrets, small enough that
# every arithmetic operation stays cheap in pure Python.
DEFAULT_PRIME = (1 << 127) - 1


@dataclass(frozen=True)
class Share:
    """One evaluation point of the sharing polynomial."""

    x: int
    y: int


def evaluate_polynomial(coefficients: Sequence[int], x: int, *, prime: int = DEFAULT_PRIME) -> int:
    """Evaluate the polynomial by Horner's rule modulo ``prime``."""
    if not coefficients:
        raise ValueError("coefficients must not be empty")
    result = 0
    for coefficient in reversed(coefficients):
        result = (result * x + coefficient) % prime
    return result


def split_secret(
    secret: int,
    threshold: int,
    share_count: int,
    *,
    prime: int = DEFAULT_PRIME,
    randbelow: Callable[[int], int] = secrets.randbelow,
) -> list[Share]:
    """Split ``secret`` into ``share_count`` shares, any ``threshold`` of which rebuild it."""
    if not isinstance(threshold, int) or not isinstance(share_count, int):
        raise TypeError("threshold and share_count must be integers")
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    if share_count < threshold:
        raise ValueError("share_count must be at least threshold")
    if share_count >= prime:
        raise ValueError("share_count must be smaller than the modulus")
    if not 0 <= secret < prime:
        raise ValueError("secret must satisfy 0 <= secret < prime")

    coefficients = [secret] + [randbelow(prime) for _ in range(threshold - 1)]
    return [
        Share(x=x, y=evaluate_polynomial(coefficients, x, prime=prime))
        for x in range(1, share_count + 1)
    ]


def reconstruct_secret(shares: Iterable[Share], *, prime: int = DEFAULT_PRIME) -> int:
    """Rebuild the constant term by Lagrange interpolation at x = 0."""
    materialised = list(shares)
    if not materialised:
        raise ValueError("at least one share is required")
    for share in materialised:
        if not isinstance(share, Share):
            raise TypeError("shares must be Share instances")
        if not 0 < share.x < prime:
            raise ValueError("share index must satisfy 0 < x < prime")
    indices = [share.x for share in materialised]
    if len(set(indices)) != len(indices):
        raise ValueError("duplicate share index")

    secret = 0
    for position, share in enumerate(materialised):
        numerator = 1
        denominator = 1
        for other_position, other in enumerate(materialised):
            if position == other_position:
                continue
            numerator = numerator * (-other.x) % prime
            denominator = denominator * (share.x - other.x) % prime
        secret = (secret + share.y * numerator * pow(denominator, -1, prime)) % prime
    return secret
