"""thresholdsign - Shamir secret sharing over a prime field.

Public API: Share / FeldmanCommitment / PedersenCommitment / split_secret /
split_secret_verifiable / split_secret_pedersen / verify_share /
verify_pedersen_share / reconstruct_secret / evaluate_polynomial.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence

__all__ = [
    "DEFAULT_PRIME",
    "Share",
    "FeldmanCommitment",
    "PedersenCommitment",
    "evaluate_polynomial",
    "split_secret",
    "split_secret_verifiable",
    "split_secret_pedersen",
    "verify_share",
    "verify_pedersen_share",
    "reconstruct_secret",
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
    """Feldman commitments ``C_j = generator ** a_j mod group_prime``.

    ``values`` holds one commitment per polynomial coefficient, ordered from
    the constant term up: ``values[j]`` commits to coefficient ``a_j``.
    The committed coefficients themselves are never stored.
    """

    values: tuple[int, ...]
    field_prime: int
    group_prime: int
    generator: int


@dataclass(frozen=True)
class PedersenCommitment:
    """Pedersen commitments ``C_j = generator ** a_j * blinding_generator ** b_j mod group_prime``.

    ``values`` holds one commitment per polynomial coefficient, ordered from
    the constant term up: ``values[j]`` commits to coefficient ``a_j`` of the
    sharing polynomial together with coefficient ``b_j`` of the random
    blinding polynomial. The two generators ``generator`` (``g``) and
    ``blinding_generator`` (``h``) must be distinct non-identity elements of
    the order-``field_prime`` subgroup; no party need know the discrete log of
    one with respect to the other. The coefficients ``a_j`` and ``b_j`` are
    never stored, so unlike a Feldman commitment the constant-term commitment
    ``C_0`` hides the secret information-theoretically.
    """

    values: tuple[int, ...]
    field_prime: int
    group_prime: int
    generator: int
    blinding_generator: int


def evaluate_polynomial(coefficients: Sequence[int], x: int, *, prime: int = DEFAULT_PRIME) -> int:
    """Evaluate the polynomial by Horner's rule modulo ``prime``."""
    if not coefficients:
        raise ValueError("coefficients must not be empty")
    result = 0
    for coefficient in reversed(coefficients):
        result = (result * x + coefficient) % prime
    return result


def _sharing_coefficients(
    secret: int,
    threshold: int,
    share_count: int,
    prime: int,
    randbelow: Callable[[int], int],
) -> list[int]:
    """Validate the sharing parameters and build the polynomial coefficients.

    The constant term is the secret and every other coefficient is drawn
    uniformly from the field; this is the single coefficient rule shared by
    :func:`split_secret` and :func:`split_secret_verifiable`.
    """
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
    coefficients = _sharing_coefficients(secret, threshold, share_count, prime, randbelow)
    return [
        Share(x=x, y=evaluate_polynomial(coefficients, x, prime=prime))
        for x in range(1, share_count + 1)
    ]


def _is_prime(value: int) -> bool:
    """Deterministic Miller-Rabin primality test, exact for every 64-bit int."""
    if value < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for small in small_primes:
        if value % small == 0:
            return value == small
    # Bases that make Miller-Rabin exact for every integer below 2**64.
    bases: tuple[int, ...] = (2, 325, 9375, 28178, 450775, 9780504, 1795265022)
    if value >= 1 << 64:
        bases = bases + tuple(secrets.randbelow(value - 3) + 2 for _ in range(20))

    d = value - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2
    for base in bases:
        base %= value
        if base < 2:
            continue
        x = pow(base, d, value)
        if x in (1, value - 1):
            continue
        for _ in range(s - 1):
            x = x * x % value
            if x == value - 1:
                break
        else:
            return False
    return True


def _validate_feldman_parameters(
    field_prime: int,
    group_prime: int,
    generator: int,
    blinding_generator: int | None = None,
) -> None:
    """Check the Feldman/Pedersen group setup, distinguishing TypeError from ValueError.

    With ``blinding_generator`` omitted this validates a single Feldman
    generator; supplied, it additionally pins the second Pedersen generator
    ``h`` to the same order-``field_prime`` subgroup and requires it to differ
    from ``g``.
    """
    parameters = [
        ("prime", field_prime),
        ("group_prime", group_prime),
        ("generator", generator),
    ]
    if blinding_generator is not None:
        parameters.append(("blinding_generator", blinding_generator))
    for name, value in parameters:
        if not isinstance(value, int):
            raise TypeError(f"{name} must be an integer")

    if not _is_prime(field_prime):
        raise ValueError("prime must be prime")
    if not _is_prime(group_prime):
        raise ValueError("group_prime must be prime")
    if (group_prime - 1) % field_prime != 0:
        raise ValueError("prime must divide group_prime - 1")
    if not 1 < generator < group_prime:
        raise ValueError("generator must satisfy 1 < generator < group_prime")
    # generator must be a non-identity element whose order is exactly
    # field_prime; under the divisibility condition above the subgroup of that
    # order is unique, so generator ** field_prime == 1 together with
    # generator != 1 pins the order down (field_prime is prime).
    if pow(generator, field_prime, group_prime) != 1:
        raise ValueError("generator must have order prime in the multiplicative group")
    if blinding_generator is not None:
        if not 1 < blinding_generator < group_prime:
            raise ValueError(
                "blinding_generator must satisfy 1 < blinding_generator < group_prime"
            )
        if blinding_generator == generator:
            raise ValueError("blinding_generator must differ from generator")
        if pow(blinding_generator, field_prime, group_prime) != 1:
            raise ValueError(
                "blinding_generator must have order prime in the multiplicative group"
            )


def split_secret_verifiable(
    secret: int,
    threshold: int,
    share_count: int,
    *,
    group_prime: int,
    generator: int,
    prime: int = DEFAULT_PRIME,
    randbelow: Callable[[int], int] = secrets.randbelow,
) -> tuple[list[Share], FeldmanCommitment]:
    """Split ``secret`` like :func:`split_secret`, returning a Feldman commitment.

    Accepts every parameter of :func:`split_secret` plus the required
    ``group_prime`` and ``generator``. The sharing polynomial follows the same
    coefficient rule; for each coefficient ``a_j`` a commitment
    ``C_j = generator ** a_j mod group_prime`` is published. The raw
    coefficients (and therefore the random padding) are never exposed.
    """
    _validate_feldman_parameters(prime, group_prime, generator)
    coefficients = _sharing_coefficients(secret, threshold, share_count, prime, randbelow)

    shares = [
        Share(x=x, y=evaluate_polynomial(coefficients, x, prime=prime))
        for x in range(1, share_count + 1)
    ]
    commitments = tuple(pow(generator, coefficient, group_prime) for coefficient in coefficients)
    commitment = FeldmanCommitment(
        values=commitments,
        field_prime=prime,
        group_prime=group_prime,
        generator=generator,
    )
    return shares, commitment


def split_secret_pedersen(
    secret: int,
    threshold: int,
    share_count: int,
    *,
    group_prime: int,
    generator: int,
    blinding_generator: int,
    prime: int = DEFAULT_PRIME,
    randbelow: Callable[[int], int] = secrets.randbelow,
) -> tuple[list[Share], list[Share], PedersenCommitment]:
    """Split ``secret`` like :func:`split_secret`, returning a Pedersen commitment.

    Accepts every parameter of :func:`split_secret` plus the required
    ``group_prime``, ``generator`` (``g``) and ``blinding_generator`` (``h``).
    The sharing polynomial follows the same coefficient rule as
    :func:`split_secret`; the same ``randbelow`` then draws a further
    ``threshold`` blinding coefficients ``b_j`` for a random blinding
    polynomial. Each coefficient is committed to as
    ``C_j = g ** a_j * h ** b_j mod group_prime``.

    Returns ``(shares, blinding_shares, commitment)`` where ``shares`` evaluate
    the sharing polynomial and ``blinding_shares`` evaluate the blinding
    polynomial; matching list positions share the same ``x`` coordinate.
    Neither the coefficients ``a_j`` (including the secret) nor the blinding
    coefficients ``b_j`` are stored anywhere, so the constant-term commitment
    hides the secret.
    """
    _validate_feldman_parameters(prime, group_prime, generator, blinding_generator)
    coefficients = _sharing_coefficients(secret, threshold, share_count, prime, randbelow)
    blinding_coefficients = [randbelow(prime) for _ in range(threshold)]

    shares = [
        Share(x=x, y=evaluate_polynomial(coefficients, x, prime=prime))
        for x in range(1, share_count + 1)
    ]
    blinding_shares = [
        Share(x=x, y=evaluate_polynomial(blinding_coefficients, x, prime=prime))
        for x in range(1, share_count + 1)
    ]
    commitments = tuple(
        pow(generator, coefficient, group_prime)
        * pow(blinding_generator, blinding, group_prime)
        % group_prime
        for coefficient, blinding in zip(coefficients, blinding_coefficients)
    )
    commitment = PedersenCommitment(
        values=commitments,
        field_prime=prime,
        group_prime=group_prime,
        generator=generator,
        blinding_generator=blinding_generator,
    )
    return shares, blinding_shares, commitment


def _validate_commitment_setup(
    values: tuple[int, ...],
    field_prime: int,
    group_prime: int,
    generators: Sequence[int],
) -> None:
    """Validate the contents and group setup of a Feldman/Pedersen commitment.

    ``generators`` carries one generator (Feldman) or two (Pedersen); the
    second must be a non-identity element of the order-``field_prime``
    subgroup distinct from the first.
    """
    if not isinstance(values, tuple):
        raise TypeError("commitment values must be a tuple")
    if not values:
        raise ValueError("commitment must contain at least one value")
    for value in values:
        if not isinstance(value, int):
            raise TypeError("commitment values must be integers")
        if not 0 < value < group_prime:
            raise ValueError("commitment values must satisfy 0 < value < group_prime")

    if not _is_prime(field_prime) or not _is_prime(group_prime):
        raise ValueError("field_prime and group_prime must be prime")
    if (group_prime - 1) % field_prime != 0:
        raise ValueError("field_prime must divide group_prime - 1")
    generator = generators[0]
    if not 1 < generator < group_prime or pow(generator, field_prime, group_prime) != 1:
        raise ValueError("generator must be a non-identity element of order field_prime")
    if len(generators) > 1:
        blinding_generator = generators[1]
        if (
            not 1 < blinding_generator < group_prime
            or blinding_generator == generator
            or pow(blinding_generator, field_prime, group_prime) != 1
        ):
            raise ValueError(
                "blinding_generator must be a non-identity element of order "
                "field_prime distinct from generator"
            )
    for value in values:
        if pow(value, field_prime, group_prime) != 1:
            raise ValueError("every commitment value must lie in the order-field_prime subgroup")


def verify_share(share: Share, commitment: FeldmanCommitment) -> bool:
    """Check ``share`` against a Feldman commitment.

    Verifies ``generator ** y == product(C_j ** x**j) mod group_prime`` with
    exponents reduced modulo ``field_prime``. Returns ``True`` on a match and
    ``False`` for a well-formed share that was tampered with or belongs to a
    different polynomial. Malformed arguments raise TypeError/ValueError.
    """
    if not isinstance(share, Share):
        raise TypeError("share must be a Share instance")
    if not isinstance(commitment, FeldmanCommitment):
        raise TypeError("commitment must be a FeldmanCommitment instance")
    for name, value in (
        ("share.x", share.x),
        ("share.y", share.y),
        ("field_prime", commitment.field_prime),
        ("group_prime", commitment.group_prime),
        ("generator", commitment.generator),
    ):
        if not isinstance(value, int):
            raise TypeError(f"{name} must be an integer")

    field_prime = commitment.field_prime
    group_prime = commitment.group_prime
    generator = commitment.generator
    _validate_commitment_setup(
        commitment.values, field_prime, group_prime, (generator,)
    )

    if not 0 < share.x < field_prime:
        raise ValueError("share index must satisfy 0 < x < field_prime")
    if not 0 <= share.y < field_prime:
        raise ValueError("share value must satisfy 0 <= y < field_prime")

    expected = pow(generator, share.y, group_prime)
    x_power = 1
    product = 1
    for c_j in commitment.values:
        product = product * pow(c_j, x_power, group_prime) % group_prime
        x_power = x_power * share.x % field_prime
    return product == expected


def verify_pedersen_share(
    share: Share, blinding_share: Share, commitment: PedersenCommitment
) -> bool:
    """Check a share/blinding-share pair against a Pedersen commitment.

    Verifies
    ``g ** y * h ** y' == product(C_j ** x**j) mod group_prime`` with
    exponents reduced modulo ``field_prime``. Returns ``True`` on a match.
    A tampered share, two shares with different ``x`` coordinates, or a
    cross-combination from different positions returns ``False``; malformed
    arguments raise TypeError/ValueError.
    """
    if not isinstance(share, Share):
        raise TypeError("share must be a Share instance")
    if not isinstance(blinding_share, Share):
        raise TypeError("blinding_share must be a Share instance")
    if not isinstance(commitment, PedersenCommitment):
        raise TypeError("commitment must be a PedersenCommitment instance")
    for name, value in (
        ("share.x", share.x),
        ("share.y", share.y),
        ("blinding_share.x", blinding_share.x),
        ("blinding_share.y", blinding_share.y),
        ("field_prime", commitment.field_prime),
        ("group_prime", commitment.group_prime),
        ("generator", commitment.generator),
        ("blinding_generator", commitment.blinding_generator),
    ):
        if not isinstance(value, int):
            raise TypeError(f"{name} must be an integer")

    field_prime = commitment.field_prime
    group_prime = commitment.group_prime
    generator = commitment.generator
    blinding_generator = commitment.blinding_generator
    _validate_commitment_setup(
        commitment.values,
        field_prime,
        group_prime,
        (generator, blinding_generator),
    )

    for name, checked_share in (("share", share), ("blinding_share", blinding_share)):
        if not 0 < checked_share.x < field_prime:
            raise ValueError(f"{name} index must satisfy 0 < x < field_prime")
        if not 0 <= checked_share.y < field_prime:
            raise ValueError(f"{name} value must satisfy 0 <= y < field_prime")

    # The two shares are evaluations of the two polynomials at the same
    # coordinate; different coordinates are a well-formed but wrong pairing.
    if share.x != blinding_share.x:
        return False

    expected = (
        pow(generator, share.y, group_prime)
        * pow(blinding_generator, blinding_share.y, group_prime)
        % group_prime
    )
    x_power = 1
    product = 1
    for c_j in commitment.values:
        product = product * pow(c_j, x_power, group_prime) % group_prime
        x_power = x_power * share.x % field_prime
    return product == expected


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
