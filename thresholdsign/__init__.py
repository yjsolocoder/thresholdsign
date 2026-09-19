"""thresholdsign - Shamir secret sharing over a prime field.

Public API: Share / split_secret / reconstruct_secret / evaluate_polynomial,
plus Feldman verifiable secret sharing: FeldmanCommitment /
split_secret_verifiable / verify_share.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence

__all__ = [
    "DEFAULT_PRIME",
    "FeldmanCommitment",
    "Share",
    "evaluate_polynomial",
    "reconstruct_secret",
    "split_secret",
    "split_secret_verifiable",
    "verify_share",
]

# Mersenne prime 2**127 - 1: large enough for integer secrets, small enough that
# every arithmetic operation stays cheap in pure Python.
DEFAULT_PRIME = (1 << 127) - 1


@dataclass(frozen=True)
class Share:
    """One evaluation point of the sharing polynomial."""

    x: int
    y: int


@dataclass(frozen=True)
class FeldmanCommitment:
    """Feldman commitments to the sharing polynomial's coefficients.

    ``values[j]`` is ``generator ** a_j mod group_prime`` for coefficient
    ``a_j``, starting from the constant term. The commitments bind the dealer
    to one polynomial without revealing its coefficients.
    """

    values: tuple[int, ...]
    field_prime: int
    group_prime: int
    generator: int


def _is_prime(candidate: int) -> bool:
    """Deterministic Miller-Rabin against a fixed base set (exact below 2**128)."""
    if candidate < 2:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if candidate % small == 0:
            return candidate == small
    odd_part = candidate - 1
    doublings = 0
    while odd_part % 2 == 0:
        odd_part //= 2
        doublings += 1
    for base in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71):
        if base >= candidate:
            continue
        witness = pow(base, odd_part, candidate)
        if witness in (1, candidate - 1):
            continue
        for _ in range(doublings - 1):
            witness = witness * witness % candidate
            if witness == candidate - 1:
                break
        else:
            return False
    return True


def _validate_group_parameters(field_prime: int, group_prime: int, generator: int) -> None:
    """Enforce the Feldman group constraints: both moduli prime, ``field_prime``
    dividing ``group_prime - 1``, and ``generator`` a non-trivial element of
    order ``field_prime`` in the multiplicative group mod ``group_prime``."""
    for name, value in (
        ("prime", field_prime),
        ("group_prime", group_prime),
        ("generator", generator),
    ):
        if not isinstance(value, int):
            raise TypeError(f"{name} must be an integer")
    if not _is_prime(field_prime):
        raise ValueError("prime must be a prime number")
    if not _is_prime(group_prime):
        raise ValueError("group_prime must be a prime number")
    if (group_prime - 1) % field_prime != 0:
        raise ValueError("prime must divide group_prime - 1")
    if not 1 < generator < group_prime:
        raise ValueError("generator must satisfy 1 < generator < group_prime")
    # field_prime is prime, so g != 1 with g**field_prime == 1 has exact order field_prime.
    if pow(generator, field_prime, group_prime) != 1:
        raise ValueError("generator must have order prime in the multiplicative group")


def evaluate_polynomial(coefficients: Sequence[int], x: int, *, prime: int = DEFAULT_PRIME) -> int:
    """Evaluate the polynomial by Horner's rule modulo ``prime``."""
    if not coefficients:
        raise ValueError("coefficients must not be empty")
    result = 0
    for coefficient in reversed(coefficients):
        result = (result * x + coefficient) % prime
    return result


def _sample_coefficients(
    secret: int,
    threshold: int,
    share_count: int,
    prime: int,
    randbelow: Callable[[int], int],
) -> list[int]:
    """Validate the splitting arguments and draw the polynomial coefficients."""
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
    return [secret] + [randbelow(prime) for _ in range(threshold - 1)]


def split_secret(
    secret: int,
    threshold: int,
    share_count: int,
    *,
    prime: int = DEFAULT_PRIME,
    randbelow: Callable[[int], int] = secrets.randbelow,
) -> list[Share]:
    """Split ``secret`` into ``share_count`` shares, any ``threshold`` of which rebuild it."""
    coefficients = _sample_coefficients(secret, threshold, share_count, prime, randbelow)
    return [
        Share(x=x, y=evaluate_polynomial(coefficients, x, prime=prime))
        for x in range(1, share_count + 1)
    ]


def split_secret_verifiable(
    secret: int,
    threshold: int,
    share_count: int,
    *,
    prime: int = DEFAULT_PRIME,
    group_prime: int,
    generator: int,
    randbelow: Callable[[int], int] = secrets.randbelow,
) -> tuple[list[Share], FeldmanCommitment]:
    """Like :func:`split_secret`, but also return a Feldman commitment to the
    polynomial so each share can be checked with :func:`verify_share`."""
    _validate_group_parameters(prime, group_prime, generator)
    coefficients = _sample_coefficients(secret, threshold, share_count, prime, randbelow)
    shares = [
        Share(x=x, y=evaluate_polynomial(coefficients, x, prime=prime))
        for x in range(1, share_count + 1)
    ]
    commitment = FeldmanCommitment(
        values=tuple(pow(generator, coefficient, group_prime) for coefficient in coefficients),
        field_prime=prime,
        group_prime=group_prime,
        generator=generator,
    )
    return shares, commitment


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


def verify_share(share: Share, commitment: FeldmanCommitment) -> bool:
    """Check ``share`` against a Feldman commitment.

    Verifies ``generator ** y == prod(C_j ** (x ** j)) mod group_prime`` with
    the exponents reduced modulo ``field_prime``. A well-formed share that
    simply does not match the committed polynomial returns ``False``; malformed
    inputs raise ``TypeError``/``ValueError``.
    """
    if not isinstance(share, Share):
        raise TypeError("share must be a Share instance")
    if not isinstance(commitment, FeldmanCommitment):
        raise TypeError("commitment must be a FeldmanCommitment instance")
    if not commitment.values:
        raise ValueError("commitment must contain at least one value")
    _validate_group_parameters(
        commitment.field_prime, commitment.group_prime, commitment.generator
    )
    for value in commitment.values:
        if not isinstance(value, int):
            raise TypeError("commitment values must be integers")
        if not 1 <= value < commitment.group_prime:
            raise ValueError("commitment values must lie in the multiplicative group")
    if not isinstance(share.x, int) or not isinstance(share.y, int):
        raise TypeError("share coordinates must be integers")
    if not 0 < share.x < commitment.field_prime:
        raise ValueError("share index must satisfy 0 < x < field_prime")
    if not 0 <= share.y < commitment.field_prime:
        raise ValueError("share value must satisfy 0 <= y < field_prime")

    field_prime = commitment.field_prime
    group_prime = commitment.group_prime
    expected = 1
    for degree, value in enumerate(commitment.values):
        exponent = pow(share.x, degree, field_prime)
        expected = expected * pow(value, exponent, group_prime) % group_prime
    return pow(commitment.generator, share.y, group_prime) == expected
