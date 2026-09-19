"""thresholdsign - Shamir secret sharing over a prime field.

Public API: Share / FeldmanCommitment / PedersenCommitment / split_secret /
split_secret_verifiable / split_secret_pedersen / verify_share /
verify_pedersen_share / reconstruct_secret / evaluate_polynomial, plus the
single-round Pedersen DKG: DKGContribution / DKGReceivedShare / DKGResult /
DKGRejection / create_dkg_contribution / verify_dkg_received_share /
aggregate_dkg, and the two-round threshold Schnorr signature built on it:
SigningContribution / SigningDKGResult / NonceCommitment / SignatureShare /
Signature / SigningRejection / create_signing_contribution /
aggregate_signing_dkg / create_nonce_commitment / create_signature_share /
verify_signature_share / aggregate_signatures / verify_signature.
"""

from __future__ import annotations

import hashlib
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
    "DKGContribution",
    "DKGReceivedShare",
    "DKGResult",
    "DKGRejection",
    "create_dkg_contribution",
    "verify_dkg_received_share",
    "aggregate_dkg",
    "SigningContribution",
    "SigningDKGResult",
    "NonceCommitment",
    "SignatureShare",
    "Signature",
    "SigningRejection",
    "create_signing_contribution",
    "aggregate_signing_dkg",
    "create_nonce_commitment",
    "create_signature_share",
    "verify_signature_share",
    "aggregate_signatures",
    "verify_signature",
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


@dataclass(frozen=True)
class DKGReceivedShare:
    """The double share one DKG participant receives from one sender.

    ``sender_id`` names the contribution the share came from and
    ``receiver_id`` the participant it is addressed to. Both share
    coordinates must equal ``receiver_id`` for the share to verify.
    """

    sender_id: int
    receiver_id: int
    share: Share
    blinding_share: Share


@dataclass(frozen=True)
class DKGContribution:
    """One participant's single-round Pedersen DKG contribution.

    ``participant_ids`` is the strictly increasing, duplicate-free tuple of
    every participant's id. ``shares`` and ``blinding_shares`` hold the
    double share addressed to each participant: position ``i`` belongs to
    ``participant_ids[i]`` and both coordinates equal it. ``commitment``
    commits to the sender's random sharing and blinding polynomials; the
    secret coefficients themselves never appear in the object.
    """

    sender_id: int
    participant_ids: tuple[int, ...]
    shares: tuple[Share, ...]
    blinding_shares: tuple[Share, ...]
    commitment: PedersenCommitment


@dataclass(frozen=True)
class DKGResult:
    """Successful DKG aggregation: summed double shares and the joint commitment.

    ``shares`` / ``blinding_shares`` hold, for each position of
    ``participant_ids``, the sum of every contribution's double share for
    that receiver; ``commitment`` is the componentwise product of the
    individual Pedersen commitments. Neither the joint secret nor any
    polynomial coefficient is stored: no party ever learns them.
    """

    participant_ids: tuple[int, ...]
    shares: tuple[Share, ...]
    blinding_shares: tuple[Share, ...]
    commitment: PedersenCommitment


@dataclass(frozen=True)
class DKGRejection:
    """A contribution that failed verification, identified by its sender."""

    sender_id: int


def _dkg_polynomials(
    sender_id: int,
    participant_ids: Iterable[int],
    threshold: int,
    *,
    prime: int,
    group_prime: int,
    generator: int,
    blinding_generator: int,
    randbelow: Callable[[int], int],
) -> tuple[tuple[int, ...], list[int], list[int]]:
    """Validate the DKG parameters and draw the sharing/blinding coefficients.

    Returns the sorted participant id tuple together with the ``threshold``
    coefficients of the random sharing polynomial and of the random blinding
    polynomial, all drawn from ``randbelow``. This is the single validation
    and coefficient rule shared by :func:`create_dkg_contribution` and
    :func:`create_signing_contribution`.
    """
    if not isinstance(sender_id, int):
        raise TypeError("sender_id must be an integer")
    if not isinstance(threshold, int):
        raise TypeError("threshold must be an integer")
    ids = list(participant_ids)
    for participant_id in ids:
        if not isinstance(participant_id, int):
            raise TypeError("participant ids must be integers")

    _validate_feldman_parameters(prime, group_prime, generator, blinding_generator)

    if not ids:
        raise ValueError("at least one participant id is required")
    if len(set(ids)) != len(ids):
        raise ValueError("participant ids must be unique")
    for participant_id in ids:
        if not 0 < participant_id < prime:
            raise ValueError("participant ids must satisfy 1 <= id <= prime - 1")
    if sender_id not in ids:
        raise ValueError("sender_id must be one of the participant ids")
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    if threshold > len(ids):
        raise ValueError("threshold must not exceed the number of participants")

    coefficients = [randbelow(prime) for _ in range(threshold)]
    blinding_coefficients = [randbelow(prime) for _ in range(threshold)]
    return tuple(sorted(ids)), coefficients, blinding_coefficients


def _build_dkg_contribution(
    sender_id: int,
    ordered_ids: tuple[int, ...],
    coefficients: Sequence[int],
    blinding_coefficients: Sequence[int],
    *,
    prime: int,
    group_prime: int,
    generator: int,
    blinding_generator: int,
) -> DKGContribution:
    """Build the DKG contribution of already-drawn sharing/blinding polynomials."""
    shares = tuple(
        Share(
            x=participant_id,
            y=evaluate_polynomial(coefficients, participant_id, prime=prime),
        )
        for participant_id in ordered_ids
    )
    blinding_shares = tuple(
        Share(
            x=participant_id,
            y=evaluate_polynomial(blinding_coefficients, participant_id, prime=prime),
        )
        for participant_id in ordered_ids
    )
    commitment = PedersenCommitment(
        values=tuple(
            pow(generator, coefficient, group_prime)
            * pow(blinding_generator, blinding, group_prime)
            % group_prime
            for coefficient, blinding in zip(coefficients, blinding_coefficients)
        ),
        field_prime=prime,
        group_prime=group_prime,
        generator=generator,
        blinding_generator=blinding_generator,
    )
    return DKGContribution(
        sender_id=sender_id,
        participant_ids=ordered_ids,
        shares=shares,
        blinding_shares=blinding_shares,
        commitment=commitment,
    )


def create_dkg_contribution(
    sender_id: int,
    participant_ids: Iterable[int],
    threshold: int,
    *,
    group_prime: int,
    generator: int,
    blinding_generator: int,
    prime: int = DEFAULT_PRIME,
    randbelow: Callable[[int], int] = secrets.randbelow,
) -> DKGContribution:
    """Create one participant's contribution to a single-round Pedersen DKG.

    Every participant runs this once with the same ``participant_ids``,
    ``threshold`` and group parameters. The sender draws a random sharing
    polynomial and a random blinding polynomial (``threshold`` coefficients
    each, all from ``randbelow``; a deterministic source may legitimately
    produce an all-zero contribution), commits to both with a Pedersen
    commitment, and evaluates a double share for each participant id. Ids
    must satisfy ``1 <= id <= prime - 1``, must be unique, and the sender
    must be one of the participants. The joint secret is the sum of all
    participants' random constant terms, so nobody ever knows it.
    """
    ordered_ids, coefficients, blinding_coefficients = _dkg_polynomials(
        sender_id,
        participant_ids,
        threshold,
        prime=prime,
        group_prime=group_prime,
        generator=generator,
        blinding_generator=blinding_generator,
        randbelow=randbelow,
    )
    return _build_dkg_contribution(
        sender_id,
        ordered_ids,
        coefficients,
        blinding_coefficients,
        prime=prime,
        group_prime=group_prime,
        generator=generator,
        blinding_generator=blinding_generator,
    )


def verify_dkg_received_share(
    received: DKGReceivedShare, commitment: PedersenCommitment
) -> bool:
    """Check a received DKG double share against the sender's Pedersen commitment.

    Reuses the Pedersen check of :func:`verify_pedersen_share`: a match
    returns ``True``; a well-formed share that was tampered with, or whose
    coordinates do not name ``receiver_id``, returns ``False``. Illegal ids,
    coordinates, values or commitments raise TypeError/ValueError.
    """
    if not isinstance(received, DKGReceivedShare):
        raise TypeError("received must be a DKGReceivedShare instance")
    if not isinstance(commitment, PedersenCommitment):
        raise TypeError("commitment must be a PedersenCommitment instance")
    for name, value in (
        ("sender_id", received.sender_id),
        ("receiver_id", received.receiver_id),
    ):
        if not isinstance(value, int):
            raise TypeError(f"{name} must be an integer")
    if not isinstance(received.share, Share):
        raise TypeError("received.share must be a Share instance")
    if not isinstance(received.blinding_share, Share):
        raise TypeError("received.blinding_share must be a Share instance")
    if not isinstance(commitment.field_prime, int):
        raise TypeError("field_prime must be an integer")

    field_prime = commitment.field_prime
    if not 0 < received.sender_id < field_prime:
        raise ValueError("sender id must satisfy 1 <= sender_id <= field_prime - 1")
    if not 0 < received.receiver_id < field_prime:
        raise ValueError("receiver id must satisfy 1 <= receiver_id <= field_prime - 1")

    if not verify_pedersen_share(received.share, received.blinding_share, commitment):
        return False
    # Both coordinates must name the addressed receiver (the Pedersen check
    # already pins the two coordinates to each other).
    return received.share.x == received.receiver_id


def _check_dkg_contribution_types(contribution: DKGContribution) -> None:
    """Type-check every field of a DKG contribution, raising TypeError."""
    if not isinstance(contribution.sender_id, int):
        raise TypeError("sender_id must be an integer")
    if not isinstance(contribution.participant_ids, tuple):
        raise TypeError("participant_ids must be a tuple")
    for participant_id in contribution.participant_ids:
        if not isinstance(participant_id, int):
            raise TypeError("participant ids must be integers")
    for name, shares in (
        ("shares", contribution.shares),
        ("blinding_shares", contribution.blinding_shares),
    ):
        if not isinstance(shares, tuple):
            raise TypeError(f"{name} must be a tuple")
        for share in shares:
            if not isinstance(share, Share):
                raise TypeError(f"{name} must contain Share instances")
    commitment = contribution.commitment
    if not isinstance(commitment, PedersenCommitment):
        raise TypeError("commitment must be a PedersenCommitment instance")
    for name, value in (
        ("field_prime", commitment.field_prime),
        ("group_prime", commitment.group_prime),
        ("generator", commitment.generator),
        ("blinding_generator", commitment.blinding_generator),
    ):
        if not isinstance(value, int):
            raise TypeError(f"{name} must be an integer")
    if not isinstance(commitment.values, tuple):
        raise TypeError("commitment values must be a tuple")


def _check_dkg_contribution_structure(contribution: DKGContribution) -> None:
    """Validate the ids, lengths and threshold of one contribution (ValueError)."""
    ids = contribution.participant_ids
    if not ids:
        raise ValueError("participant ids must not be empty")
    if any(ids[index] >= ids[index + 1] for index in range(len(ids) - 1)):
        raise ValueError("participant ids must be strictly increasing and unique")
    field_prime = contribution.commitment.field_prime
    for participant_id in ids:
        if not 0 < participant_id < field_prime:
            raise ValueError("participant ids must satisfy 1 <= id <= field_prime - 1")
    if contribution.sender_id not in ids:
        raise ValueError("sender_id must be one of the participant ids")
    if not len(contribution.shares) == len(contribution.blinding_shares) == len(ids):
        raise ValueError("each participant id must have exactly one double share")
    if not 1 <= len(contribution.commitment.values) <= len(ids):
        raise ValueError("threshold must satisfy 1 <= threshold <= participant count")


def _check_dkg_contributions_consistent(materialised: list[DKGContribution]) -> None:
    """Cross-contribution consistency checks shared by both DKG aggregations.

    Every contribution must agree on the participant ids, the threshold and
    the group parameters, and each participant must contribute exactly once.
    """
    first = materialised[0]
    participant_ids = first.participant_ids
    first_commitment = first.commitment
    threshold = len(first_commitment.values)
    for contribution in materialised:
        _check_dkg_contribution_structure(contribution)
        commitment = contribution.commitment
        if contribution.participant_ids != participant_ids:
            raise ValueError("contributions must agree on the same participant ids")
        if (
            commitment.field_prime != first_commitment.field_prime
            or commitment.group_prime != first_commitment.group_prime
            or commitment.generator != first_commitment.generator
            or commitment.blinding_generator != first_commitment.blinding_generator
        ):
            raise ValueError("contributions must share the same group parameters")
        if len(commitment.values) != threshold:
            raise ValueError("contributions must share the same threshold")

    sender_ids = [contribution.sender_id for contribution in materialised]
    if len(set(sender_ids)) != len(sender_ids):
        raise ValueError("duplicate contribution from the same participant")
    if set(sender_ids) != set(participant_ids):
        raise ValueError("each participant must contribute exactly once")


def _verify_dkg_contribution(contribution: DKGContribution) -> bool:
    """True iff every double share verifies against the sender's Pedersen commitment."""
    for index, receiver_id in enumerate(contribution.participant_ids):
        received = DKGReceivedShare(
            sender_id=contribution.sender_id,
            receiver_id=receiver_id,
            share=contribution.shares[index],
            blinding_share=contribution.blinding_shares[index],
        )
        if not verify_dkg_received_share(received, contribution.commitment):
            return False
    return True


def _combine_dkg_contributions(ordered: list[DKGContribution]) -> DKGResult:
    """Sum the double shares and multiply the commitments of sorted contributions."""
    first_commitment = ordered[0].commitment
    participant_ids = ordered[0].participant_ids
    threshold = len(first_commitment.values)
    field_prime = first_commitment.field_prime
    group_prime = first_commitment.group_prime
    shares = []
    blinding_shares = []
    for index, receiver_id in enumerate(participant_ids):
        y = 0
        y_blinding = 0
        for contribution in ordered:
            y = (y + contribution.shares[index].y) % field_prime
            y_blinding = (y_blinding + contribution.blinding_shares[index].y) % field_prime
        shares.append(Share(x=receiver_id, y=y))
        blinding_shares.append(Share(x=receiver_id, y=y_blinding))
    joint_values = []
    for position in range(threshold):
        value = 1
        for contribution in ordered:
            value = value * contribution.commitment.values[position] % group_prime
        joint_values.append(value)
    return DKGResult(
        participant_ids=participant_ids,
        shares=tuple(shares),
        blinding_shares=tuple(blinding_shares),
        commitment=PedersenCommitment(
            values=tuple(joint_values),
            field_prime=field_prime,
            group_prime=group_prime,
            generator=first_commitment.generator,
            blinding_generator=first_commitment.blinding_generator,
        ),
    )


def aggregate_dkg(
    contributions: Iterable[DKGContribution],
) -> DKGResult | list[DKGRejection]:
    """Combine one verified contribution per participant into the joint key material.

    Every participant must contribute exactly once, and all contributions
    must agree on the participant ids, the threshold and the group
    parameters. Missing or duplicate participants, illegal ids or
    commitments, and inconsistent parameters raise ValueError; wrong types
    raise TypeError. Each double share is verified against its sender's
    commitment and failures are never dropped: if any contribution does not
    verify, the result is a list of :class:`DKGRejection` naming every
    sender whose contribution failed.

    On success the double shares of all contributions are added modulo
    ``field_prime`` and the commitments are multiplied componentwise modulo
    ``group_prime``, so the input order does not affect the result. Any
    ``threshold`` receivers can rebuild the joint secret from their
    aggregated shares with :func:`reconstruct_secret`, yet no single party
    ever learns it.
    """
    materialised = list(contributions)
    if not materialised:
        raise ValueError("at least one contribution is required")
    for contribution in materialised:
        if not isinstance(contribution, DKGContribution):
            raise TypeError("contributions must be DKGContribution instances")
        _check_dkg_contribution_types(contribution)
    _check_dkg_contributions_consistent(materialised)

    # Sort by sender so the input order cannot influence the outcome.
    ordered = sorted(materialised, key=lambda contribution: contribution.sender_id)

    rejections = [
        DKGRejection(sender_id=contribution.sender_id)
        for contribution in ordered
        if not _verify_dkg_contribution(contribution)
    ]
    if rejections:
        return rejections
    return _combine_dkg_contributions(ordered)


@dataclass(frozen=True)
class SigningContribution:
    """One participant's DKG contribution plus a Feldman commitment to it.

    ``dkg_contribution`` is the participant's ordinary single-round Pedersen
    DKG contribution; ``feldman_commitment`` commits to the *same* secret
    sharing polynomial (coefficient for coefficient, without the blinding
    polynomial), so the group can derive public verification material for
    threshold signatures. The secret coefficients never appear in the object.
    """

    dkg_contribution: DKGContribution
    feldman_commitment: FeldmanCommitment


@dataclass(frozen=True)
class SigningDKGResult:
    """Successful signing-DKG aggregation: joint key material and public keys.

    ``dkg_result`` is the ordinary DKG aggregation result; ``public_key`` is
    the joint public key ``Y = generator ** secret mod group_prime``;
    ``verification_shares`` holds, for each position of
    ``dkg_result.participant_ids``, the participant's public verification
    share ``Y_i = generator ** s_i mod group_prime`` where ``s_i`` is that
    participant's aggregated secret share. Neither the joint secret nor any
    polynomial coefficient is stored.
    """

    dkg_result: DKGResult
    public_key: int
    verification_shares: tuple[int, ...]


@dataclass(frozen=True)
class NonceCommitment:
    """One signer's round-1 nonce commitment ``value = generator ** r mod group_prime``.

    The secret nonce ``r`` itself is returned separately by
    :func:`create_nonce_commitment` and must be kept private and never reused.
    """

    signer_id: int
    value: int


@dataclass(frozen=True)
class SignatureShare:
    """One signer's round-2 signature share ``z_i = r_i + c * lambda_i * s_i mod q``."""

    signer_id: int
    value: int


@dataclass(frozen=True)
class Signature:
    """An aggregated threshold Schnorr signature.

    ``signer_ids`` is the strictly increasing tuple of signers, ``nonce`` is
    the combined commitment ``R = product(R_i) mod group_prime`` and ``value``
    is the combined response ``z = sum(z_i) mod field_prime``.
    """

    signer_ids: tuple[int, ...]
    nonce: int
    value: int


@dataclass(frozen=True)
class SigningRejection:
    """A signature share that failed verification, identified by its signer."""

    signer_id: int


def create_signing_contribution(
    sender_id: int,
    participant_ids: Iterable[int],
    threshold: int,
    *,
    group_prime: int,
    generator: int,
    blinding_generator: int,
    prime: int = DEFAULT_PRIME,
    randbelow: Callable[[int], int] = secrets.randbelow,
) -> SigningContribution:
    """Create one participant's contribution to a threshold-signing DKG.

    Follows exactly the validation and coefficient rule of
    :func:`create_dkg_contribution`: the same random sharing and blinding
    polynomials (``threshold`` coefficients each, all drawn from
    ``randbelow``) produce the Pedersen DKG contribution, and the same
    secret sharing polynomial is additionally committed to with a Feldman
    commitment ``F_j = generator ** a_j mod group_prime``. The Feldman
    commitment lets the group derive the joint public key and each
    participant's public verification share without revealing any
    coefficient; the secret coefficients are never stored.
    """
    ordered_ids, coefficients, blinding_coefficients = _dkg_polynomials(
        sender_id,
        participant_ids,
        threshold,
        prime=prime,
        group_prime=group_prime,
        generator=generator,
        blinding_generator=blinding_generator,
        randbelow=randbelow,
    )
    contribution = _build_dkg_contribution(
        sender_id,
        ordered_ids,
        coefficients,
        blinding_coefficients,
        prime=prime,
        group_prime=group_prime,
        generator=generator,
        blinding_generator=blinding_generator,
    )
    feldman_commitment = FeldmanCommitment(
        values=tuple(pow(generator, coefficient, group_prime) for coefficient in coefficients),
        field_prime=prime,
        group_prime=group_prime,
        generator=generator,
    )
    return SigningContribution(
        dkg_contribution=contribution,
        feldman_commitment=feldman_commitment,
    )


def _check_signing_contribution_types(contribution: SigningContribution) -> None:
    """Type-check every field of a signing contribution, raising TypeError."""
    if not isinstance(contribution.dkg_contribution, DKGContribution):
        raise TypeError("dkg_contribution must be a DKGContribution instance")
    commitment = contribution.feldman_commitment
    if not isinstance(commitment, FeldmanCommitment):
        raise TypeError("feldman_commitment must be a FeldmanCommitment instance")
    for name, value in (
        ("field_prime", commitment.field_prime),
        ("group_prime", commitment.group_prime),
        ("generator", commitment.generator),
    ):
        if not isinstance(value, int):
            raise TypeError(f"{name} must be an integer")
    if not isinstance(commitment.values, tuple):
        raise TypeError("commitment values must be a tuple")
    for value in commitment.values:
        if not isinstance(value, int):
            raise TypeError("commitment values must be integers")


def _feldman_evaluate(
    values: tuple[int, ...], x: int, *, field_prime: int, group_prime: int
) -> int:
    """Evaluate a Feldman commitment in the exponent: ``product(C_j ** x**j)``."""
    product = 1
    x_power = 1
    for c_j in values:
        product = product * pow(c_j, x_power, group_prime) % group_prime
        x_power = x_power * x % field_prime
    return product


def aggregate_signing_dkg(
    contributions: Iterable[SigningContribution],
) -> SigningDKGResult | list[DKGRejection]:
    """Combine signing contributions into joint key material and public keys.

    Applies the same checks as :func:`aggregate_dkg` to the embedded
    Pedersen contributions (missing or duplicate participants, inconsistent
    ids, threshold or group parameters raise ValueError; wrong types raise
    TypeError), and additionally requires each Feldman commitment to be
    well-formed, to share the Pedersen group parameters and to commit to the
    same threshold. Every double share is verified against its sender's
    Pedersen commitment and every share against the sender's Feldman
    commitment; failures are never dropped: if any contribution does not
    verify, the result is a list of :class:`DKGRejection` naming every
    sender whose contribution failed, sorted by ``sender_id`` regardless of
    the input order.

    On success returns a :class:`SigningDKGResult`: the ordinary
    :class:`DKGResult`, the joint public key ``Y`` (the product of the
    constant-term Feldman commitments) and each participant's verification
    share ``Y_i`` (the product of the Feldman commitments evaluated at the
    participant's id), so the input order does not affect the result.
    """
    materialised = list(contributions)
    if not materialised:
        raise ValueError("at least one contribution is required")
    for contribution in materialised:
        if not isinstance(contribution, SigningContribution):
            raise TypeError("contributions must be SigningContribution instances")
        _check_signing_contribution_types(contribution)
        _check_dkg_contribution_types(contribution.dkg_contribution)

    inner = [contribution.dkg_contribution for contribution in materialised]
    _check_dkg_contributions_consistent(inner)

    for contribution in materialised:
        pedersen = contribution.dkg_contribution.commitment
        feldman = contribution.feldman_commitment
        if (
            feldman.field_prime != pedersen.field_prime
            or feldman.group_prime != pedersen.group_prime
            or feldman.generator != pedersen.generator
        ):
            raise ValueError("both commitments must share the same group parameters")
        if len(feldman.values) != len(pedersen.values):
            raise ValueError("both commitments must commit to the same threshold")
        _validate_commitment_setup(
            feldman.values,
            feldman.field_prime,
            feldman.group_prime,
            (feldman.generator,),
        )

    # Sort by sender so the input order cannot influence the outcome.
    ordered = sorted(materialised, key=lambda contribution: contribution.dkg_contribution.sender_id)

    rejections = []
    for contribution in ordered:
        dkg_contribution = contribution.dkg_contribution
        if not _verify_dkg_contribution(dkg_contribution):
            rejections.append(DKGRejection(sender_id=dkg_contribution.sender_id))
            continue
        feldman = contribution.feldman_commitment
        if not all(
            verify_share(share, feldman) for share in dkg_contribution.shares
        ):
            rejections.append(DKGRejection(sender_id=dkg_contribution.sender_id))
    if rejections:
        return rejections

    dkg_result = _combine_dkg_contributions([c.dkg_contribution for c in ordered])
    field_prime = dkg_result.commitment.field_prime
    group_prime = dkg_result.commitment.group_prime
    public_key = 1
    for contribution in ordered:
        public_key = (
            public_key * contribution.feldman_commitment.values[0] % group_prime
        )
    verification_shares = tuple(
        _product_of_feldman_evaluations(ordered, participant_id, field_prime, group_prime)
        for participant_id in dkg_result.participant_ids
    )
    return SigningDKGResult(
        dkg_result=dkg_result,
        public_key=public_key,
        verification_shares=verification_shares,
    )


def _product_of_feldman_evaluations(
    ordered: list[SigningContribution],
    participant_id: int,
    field_prime: int,
    group_prime: int,
) -> int:
    """The verification share ``Y_i``: every Feldman commitment evaluated at the id."""
    value = 1
    for contribution in ordered:
        value = (
            value
            * _feldman_evaluate(
                contribution.feldman_commitment.values,
                participant_id,
                field_prime=field_prime,
                group_prime=group_prime,
            )
            % group_prime
        )
    return value


def _check_message(message: bytes) -> bytes:
    """Require a bytes-like message, raising TypeError otherwise."""
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be bytes")
    return bytes(message)


def _check_message(message: bytes) -> bytes:
    """Require a bytes-like message, raising TypeError otherwise."""
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be bytes")
    return bytes(message)


def _schnorr_challenge(
    message: bytes,
    public_key: int,
    nonce: int,
    signer_ids: tuple[int, ...],
    *,
    field_prime: int,
    group_prime: int,
) -> int:
    """The Fiat-Shamir challenge ``c`` of a threshold Schnorr signing session.

    Hashes the domain-separation tag, the SHA-256 digest of the message and
    the ``L``-byte unsigned big-endian encodings of ``Y``, ``R`` and every
    signer id (in strictly increasing order), where
    ``L = ceil(group_prime.bit_length() / 8)``; the digest is interpreted
    big-endian and reduced modulo ``field_prime``.
    """
    length = (group_prime.bit_length() + 7) // 8
    hasher = hashlib.sha256()
    hasher.update(b"thresholdsign/schnorr/v1")
    hasher.update(hashlib.sha256(message).digest())
    hasher.update(public_key.to_bytes(length, "big"))
    hasher.update(nonce.to_bytes(length, "big"))
    for signer_id in signer_ids:
        hasher.update(signer_id.to_bytes(length, "big"))
    return int.from_bytes(hasher.digest(), "big") % field_prime


def _lagrange_weight(indices: tuple[int, ...], position: int, prime: int) -> int:
    """The Lagrange coefficient of ``indices[position]`` at x = 0 modulo ``prime``."""
    numerator = 1
    denominator = 1
    for other_position, other in enumerate(indices):
        if other_position == position:
            continue
        numerator = numerator * other % prime
        denominator = denominator * (other - indices[position]) % prime
    return numerator * pow(denominator, -1, prime) % prime


def _check_signing_result(
    result: SigningDKGResult,
) -> tuple[int, int, int, int, tuple[int, ...]]:
    """Validate a SigningDKGResult and return (field_prime, group_prime,
    generator, threshold, participant_ids)."""
    if not isinstance(result, SigningDKGResult):
        raise TypeError("result must be a SigningDKGResult instance")
    dkg_result = result.dkg_result
    if not isinstance(dkg_result, DKGResult):
        raise TypeError("dkg_result must be a DKGResult instance")
    commitment = dkg_result.commitment
    if not isinstance(commitment, PedersenCommitment):
        raise TypeError("commitment must be a PedersenCommitment instance")
    if not isinstance(result.public_key, int):
        raise TypeError("public_key must be an integer")
    if not isinstance(result.verification_shares, tuple):
        raise TypeError("verification_shares must be a tuple")
    for value in result.verification_shares:
        if not isinstance(value, int):
            raise TypeError("verification shares must be integers")
    if not isinstance(dkg_result.participant_ids, tuple):
        raise TypeError("participant_ids must be a tuple")
    for participant_id in dkg_result.participant_ids:
        if not isinstance(participant_id, int):
            raise TypeError("participant ids must be integers")
    for name, shares in (
        ("shares", dkg_result.shares),
        ("blinding_shares", dkg_result.blinding_shares),
    ):
        if not isinstance(shares, tuple):
            raise TypeError(f"{name} must be a tuple")
        for share in shares:
            if not isinstance(share, Share):
                raise TypeError(f"{name} must contain Share instances")
    for name, value in (
        ("field_prime", commitment.field_prime),
        ("group_prime", commitment.group_prime),
        ("generator", commitment.generator),
        ("blinding_generator", commitment.blinding_generator),
    ):
        if not isinstance(value, int):
            raise TypeError(f"{name} must be an integer")
    if not isinstance(commitment.values, tuple):
        raise TypeError("commitment values must be a tuple")

    field_prime = commitment.field_prime
    group_prime = commitment.group_prime
    generator = commitment.generator
    ids = dkg_result.participant_ids
    _validate_commitment_setup(
        commitment.values,
        field_prime,
        group_prime,
        (generator, commitment.blinding_generator),
    )
    if not ids:
        raise ValueError("participant ids must not be empty")
    if any(ids[index] >= ids[index + 1] for index in range(len(ids) - 1)):
        raise ValueError("participant ids must be strictly increasing and unique")
    for participant_id in ids:
        if not 0 < participant_id < field_prime:
            raise ValueError("participant ids must satisfy 1 <= id <= field_prime - 1")
    if not len(dkg_result.shares) == len(dkg_result.blinding_shares) == len(ids):
        raise ValueError("each participant id must have exactly one double share")
    if len(result.verification_shares) != len(ids):
        raise ValueError("each participant id must have exactly one verification share")
    if not 1 <= len(commitment.values) <= len(ids):
        raise ValueError("threshold must satisfy 1 <= threshold <= participant count")
    if not 0 < result.public_key < group_prime or pow(
        result.public_key, field_prime, group_prime
    ) != 1:
        raise ValueError("public_key must lie in the order-field_prime subgroup")
    for value in result.verification_shares:
        if not 0 < value < group_prime or pow(value, field_prime, group_prime) != 1:
            raise ValueError(
                "verification shares must lie in the order-field_prime subgroup"
            )
    return field_prime, group_prime, generator, len(commitment.values), ids


def _check_nonce_commitments(
    materialised: list[NonceCommitment],
    *,
    field_prime: int,
    group_prime: int,
    threshold: int,
    participant_ids: tuple[int, ...],
) -> tuple[int, ...]:
    """Validate one signing session's nonce commitments; return the sorted signer ids.

    Signer ids must be unique DKG participants and number at least
    ``threshold``; every commitment value must be a non-identity element of
    the order-``field_prime`` subgroup (a zero nonce commits to the
    identity), and all values must be distinct so a reused nonce is
    rejected.
    """
    for commitment in materialised:
        if not isinstance(commitment, NonceCommitment):
            raise TypeError("nonce commitments must be NonceCommitment instances")
        if not isinstance(commitment.signer_id, int):
            raise TypeError("signer_id must be an integer")
        if not isinstance(commitment.value, int):
            raise TypeError("nonce commitment value must be an integer")
    if not materialised:
        raise ValueError("at least one nonce commitment is required")
    signer_ids = [commitment.signer_id for commitment in materialised]
    if len(set(signer_ids)) != len(signer_ids):
        raise ValueError("duplicate nonce commitment from the same signer")
    for signer_id in signer_ids:
        if signer_id not in participant_ids:
            raise ValueError("signer must be one of the DKG participants")
    if len(signer_ids) < threshold:
        raise ValueError("at least threshold signers are required")
    values = [commitment.value for commitment in materialised]
    for value in values:
        if not 1 < value < group_prime or pow(value, field_prime, group_prime) != 1:
            raise ValueError(
                "nonce commitment must be a non-identity element of the "
                "order-field_prime subgroup"
            )
    if len(set(values)) != len(values):
        raise ValueError("nonce values must not be reused")
    return tuple(sorted(signer_ids))


def create_nonce_commitment(
    signer_id: int,
    *,
    group_prime: int,
    generator: int,
    prime: int = DEFAULT_PRIME,
    randbelow: Callable[[int], int] = secrets.randbelow,
) -> tuple[int, NonceCommitment]:
    """Round 1 of a signing session: draw a one-time nonce and commit to it.

    Draws a fresh non-zero nonce ``r`` (uniform in ``1..prime - 1`` via the
    injectable ``randbelow``) and returns ``(r, commitment)`` where
    ``commitment.value = generator ** r mod group_prime``. The signer keeps
    ``r`` secret for round 2 and publishes the commitment; a nonce must
    never be reused across messages or sessions, as reuse leaks the secret
    share.
    """
    if not isinstance(signer_id, int):
        raise TypeError("signer_id must be an integer")
    _validate_feldman_parameters(prime, group_prime, generator)
    if not 0 < signer_id < prime:
        raise ValueError("signer_id must satisfy 1 <= signer_id <= prime - 1")
    nonce = randbelow(prime - 1) + 1
    return nonce, NonceCommitment(
        signer_id=signer_id, value=pow(generator, nonce, group_prime)
    )


def _combine_nonce_values(
    materialised: list[NonceCommitment], group_prime: int
) -> int:
    """The combined nonce commitment ``R = product(R_i) mod group_prime``."""
    nonce = 1
    for commitment in materialised:
        nonce = nonce * commitment.value % group_prime
    return nonce


def create_signature_share(
    signer_id: int,
    message: bytes,
    *,
    nonce: int,
    share: Share,
    nonce_commitments: Iterable[NonceCommitment],
    result: SigningDKGResult,
) -> SignatureShare:
    """Round 2 of a signing session: compute one signer's signature share.

    ``nonce`` is the signer's secret one-time nonce from
    :func:`create_nonce_commitment`, ``share`` the signer's aggregated
    secret share from the DKG result (its ``x`` must equal ``signer_id``),
    and ``nonce_commitments`` the published commitments of every signer of
    this session, whose ids must be unique DKG participants numbering at
    least the threshold. The share is
    ``z_i = r_i + c * lambda_i * s_i mod field_prime`` with the challenge
    ``c`` of :func:`_schnorr_challenge` and the Lagrange weight
    ``lambda_i`` of the signer set at x = 0.
    """
    if not isinstance(signer_id, int):
        raise TypeError("signer_id must be an integer")
    message = _check_message(message)
    if not isinstance(nonce, int):
        raise TypeError("nonce must be an integer")
    if not isinstance(share, Share):
        raise TypeError("share must be a Share instance")
    field_prime, group_prime, generator, threshold, participant_ids = (
        _check_signing_result(result)
    )
    if not 0 < signer_id < field_prime:
        raise ValueError("signer_id must satisfy 1 <= signer_id <= field_prime - 1")
    if not 0 < nonce < field_prime:
        raise ValueError("nonce must satisfy 1 <= nonce <= field_prime - 1")
    if share.x != signer_id:
        raise ValueError("share must be the signer's own aggregated share")
    if not 0 <= share.y < field_prime:
        raise ValueError("share value must satisfy 0 <= y < field_prime")

    commitments = list(nonce_commitments)
    signer_ids = _check_nonce_commitments(
        commitments,
        field_prime=field_prime,
        group_prime=group_prime,
        threshold=threshold,
        participant_ids=participant_ids,
    )
    if signer_id not in signer_ids:
        raise ValueError("signer must publish a nonce commitment for this session")
    own = next(c for c in commitments if c.signer_id == signer_id)
    if pow(generator, nonce, group_prime) != own.value:
        raise ValueError("nonce does not match the signer's published commitment")

    combined_nonce = _combine_nonce_values(commitments, group_prime)
    challenge = _schnorr_challenge(
        message,
        result.public_key,
        combined_nonce,
        signer_ids,
        field_prime=field_prime,
        group_prime=group_prime,
    )
    weight = _lagrange_weight(signer_ids, signer_ids.index(signer_id), field_prime)
    return SignatureShare(
        signer_id=signer_id,
        value=(nonce + challenge * weight * share.y) % field_prime,
    )


def _signature_share_matches(
    value: int,
    nonce_value: int,
    verification_share: int,
    weight: int,
    challenge: int,
    *,
    field_prime: int,
    group_prime: int,
    generator: int,
) -> bool:
    """The share equation ``g ** z_i == R_i * Y_i ** (c * lambda_i) mod group_prime``."""
    expected = (
        nonce_value
        * pow(verification_share, weight * challenge % field_prime, group_prime)
        % group_prime
    )
    return pow(generator, value, group_prime) == expected


def verify_signature_share(
    share: SignatureShare,
    message: bytes,
    *,
    nonce_commitments: Iterable[NonceCommitment],
    result: SigningDKGResult,
) -> bool:
    """Check one signature share against the session's public material.

    Verifies ``g ** z_i == R_i * Y_i ** (c * lambda_i) mod group_prime``
    using the signer's nonce commitment ``R_i``, the signer's verification
    share ``Y_i`` from the DKG result and the session challenge ``c``.
    Returns ``True`` on a match and ``False`` for a well-formed share that
    was tampered with or belongs to a different message or session.
    Malformed arguments raise TypeError/ValueError; a share whose signer
    published no nonce commitment raises ValueError.
    """
    if not isinstance(share, SignatureShare):
        raise TypeError("share must be a SignatureShare instance")
    if not isinstance(share.signer_id, int):
        raise TypeError("signer_id must be an integer")
    if not isinstance(share.value, int):
        raise TypeError("share value must be an integer")
    message = _check_message(message)
    field_prime, group_prime, generator, threshold, participant_ids = (
        _check_signing_result(result)
    )
    commitments = list(nonce_commitments)
    signer_ids = _check_nonce_commitments(
        commitments,
        field_prime=field_prime,
        group_prime=group_prime,
        threshold=threshold,
        participant_ids=participant_ids,
    )
    if not 0 <= share.value < field_prime:
        raise ValueError("share value must satisfy 0 <= z < field_prime")
    if share.signer_id not in signer_ids:
        raise ValueError("share does not belong to a signer of this session")

    combined_nonce = _combine_nonce_values(commitments, group_prime)
    challenge = _schnorr_challenge(
        message,
        result.public_key,
        combined_nonce,
        signer_ids,
        field_prime=field_prime,
        group_prime=group_prime,
    )
    position = signer_ids.index(share.signer_id)
    weight = _lagrange_weight(signer_ids, position, field_prime)
    own = next(c for c in commitments if c.signer_id == share.signer_id)
    verification_share = result.verification_shares[
        participant_ids.index(share.signer_id)
    ]
    return _signature_share_matches(
        share.value,
        own.value,
        verification_share,
        weight,
        challenge,
        field_prime=field_prime,
        group_prime=group_prime,
        generator=generator,
    )


def aggregate_signatures(
    shares: Iterable[SignatureShare],
    message: bytes,
    *,
    nonce_commitments: Iterable[NonceCommitment],
    result: SigningDKGResult,
) -> Signature | list[SigningRejection]:
    """Combine one verified signature share per signer into the signature.

    Every signer of the session (named by the nonce commitments) must
    provide exactly one share; duplicate or missing signers raise
    ValueError, as do illegal values or session parameters, while wrong
    types raise TypeError. Each share is verified as in
    :func:`verify_signature_share` and failures are never dropped: if any
    share does not verify, the result is a list of :class:`SigningRejection`
    naming every signer whose share failed, sorted by ``signer_id``
    regardless of the input order.

    On success returns the :class:`Signature` with the strictly increasing
    signer ids, the combined nonce commitment ``R = product(R_i)`` and the
    combined response ``z = sum(z_i) mod field_prime``.
    """
    materialised = list(shares)
    for share in materialised:
        if not isinstance(share, SignatureShare):
            raise TypeError("shares must be SignatureShare instances")
        if not isinstance(share.signer_id, int):
            raise TypeError("signer_id must be an integer")
        if not isinstance(share.value, int):
            raise TypeError("share value must be an integer")
    message = _check_message(message)
    field_prime, group_prime, generator, threshold, participant_ids = (
        _check_signing_result(result)
    )
    commitments = list(nonce_commitments)
    signer_ids = _check_nonce_commitments(
        commitments,
        field_prime=field_prime,
        group_prime=group_prime,
        threshold=threshold,
        participant_ids=participant_ids,
    )
    share_signer_ids = [share.signer_id for share in materialised]
    if len(set(share_signer_ids)) != len(share_signer_ids):
        raise ValueError("duplicate signature share from the same signer")
    if set(share_signer_ids) != set(signer_ids):
        raise ValueError("each signer must provide exactly one signature share")
    for share in materialised:
        if not 0 <= share.value < field_prime:
            raise ValueError("share value must satisfy 0 <= z < field_prime")

    combined_nonce = _combine_nonce_values(commitments, group_prime)
    challenge = _schnorr_challenge(
        message,
        result.public_key,
        combined_nonce,
        signer_ids,
        field_prime=field_prime,
        group_prime=group_prime,
    )
    rejections = []
    for position, signer_id in enumerate(signer_ids):
        share = next(s for s in materialised if s.signer_id == signer_id)
        own = next(c for c in commitments if c.signer_id == signer_id)
        verification_share = result.verification_shares[
            participant_ids.index(signer_id)
        ]
        weight = _lagrange_weight(signer_ids, position, field_prime)
        if not _signature_share_matches(
            share.value,
            own.value,
            verification_share,
            weight,
            challenge,
            field_prime=field_prime,
            group_prime=group_prime,
            generator=generator,
        ):
            rejections.append(SigningRejection(signer_id=signer_id))
    if rejections:
        return rejections

    value = sum(share.value for share in materialised) % field_prime
    return Signature(signer_ids=signer_ids, nonce=combined_nonce, value=value)


def verify_signature(
    signature: Signature,
    message: bytes,
    *,
    public_key: int,
    group_prime: int,
    generator: int,
    prime: int = DEFAULT_PRIME,
) -> bool:
    """Verify an aggregated threshold Schnorr signature against the joint key.

    Recomputes the challenge ``c`` from the message, ``public_key`` (``Y``),
    the signature's combined nonce ``R`` and its signer ids, and checks
    ``g ** z == R * Y ** c mod group_prime``. Returns ``True`` on a match
    and ``False`` for a well-formed signature that does not match the
    message or key; malformed arguments raise TypeError/ValueError.
    """
    if not isinstance(signature, Signature):
        raise TypeError("signature must be a Signature instance")
    message = _check_message(message)
    if not isinstance(signature.signer_ids, tuple):
        raise TypeError("signer_ids must be a tuple")
    for signer_id in signature.signer_ids:
        if not isinstance(signer_id, int):
            raise TypeError("signer ids must be integers")
    for name, value in (
        ("nonce", signature.nonce),
        ("value", signature.value),
        ("public_key", public_key),
    ):
        if not isinstance(value, int):
            raise TypeError(f"{name} must be an integer")

    _validate_feldman_parameters(prime, group_prime, generator)

    signer_ids = signature.signer_ids
    if not signer_ids:
        raise ValueError("at least one signer id is required")
    if any(signer_ids[index] >= signer_ids[index + 1] for index in range(len(signer_ids) - 1)):
        raise ValueError("signer ids must be strictly increasing and unique")
    for signer_id in signer_ids:
        if not 0 < signer_id < prime:
            raise ValueError("signer ids must satisfy 1 <= id <= prime - 1")
    if not 0 <= signature.value < prime:
        raise ValueError("signature value must satisfy 0 <= z < prime")
    for name, element in (("nonce", signature.nonce), ("public_key", public_key)):
        if not 0 < element < group_prime or pow(element, prime, group_prime) != 1:
            raise ValueError(f"{name} must lie in the order-prime subgroup")

    challenge = _schnorr_challenge(
        message,
        public_key,
        signature.nonce,
        signer_ids,
        field_prime=prime,
        group_prime=group_prime,
    )
    expected = signature.nonce * pow(public_key, challenge, group_prime) % group_prime
    return pow(generator, signature.value, group_prime) == expected
