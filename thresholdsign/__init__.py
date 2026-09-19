"""thresholdsign - Shamir secret sharing over a prime field.

Public API: Share / FeldmanCommitment / PedersenCommitment / split_secret /
split_secret_verifiable / split_secret_pedersen / verify_share /
verify_pedersen_share / reconstruct_secret / evaluate_polynomial, plus the
single-round Pedersen DKG: DKGContribution / DKGReceivedShare / DKGResult /
DKGRejection / create_dkg_contribution / verify_dkg_received_share /
aggregate_dkg.
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
    "DKGContribution",
    "DKGReceivedShare",
    "DKGResult",
    "DKGRejection",
    "create_dkg_contribution",
    "verify_dkg_received_share",
    "aggregate_dkg",
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
    """One dealt share pair of a Pedersen DKG contribution.

    ``sender_id`` identifies the participant whose contribution the pair
    belongs to and ``receiver_id`` the participant it is addressed to. Both
    ids are evaluation points of the sharing and blinding polynomials, so an
    honestly built pair satisfies
    ``share.x == blinding_share.x == receiver_id``.
    """

    sender_id: int
    receiver_id: int
    share: Share
    blinding_share: Share


@dataclass(frozen=True)
class DKGContribution:
    """One participant's dealing in a single-round Pedersen DKG.

    ``participant_ids`` lists every participant's evaluation point in
    strictly increasing (hence unique) order; ``shares`` carries exactly one
    :class:`DKGReceivedShare` per participant in the same order, and
    ``commitment`` commits to the sender's sharing and blinding polynomials.
    The polynomials themselves — and therefore the sender's secret
    contribution — are never stored.
    """

    sender_id: int
    participant_ids: tuple[int, ...]
    shares: tuple[DKGReceivedShare, ...]
    commitment: PedersenCommitment


@dataclass(frozen=True)
class DKGResult:
    """One receiver's outcome of a successful Pedersen DKG aggregation.

    ``share`` and ``blinding_share`` are the receiver's aggregated double
    share (every contribution's pair added modulo ``field_prime``) and
    ``commitment`` is the joint commitment (every contribution's commitment
    multiplied component-wise modulo ``group_prime``). The joint secret and
    every polynomial coefficient are absent by construction: they are never
    stored on this object.
    """

    receiver_id: int
    share: Share
    blinding_share: Share
    commitment: PedersenCommitment
    participant_ids: tuple[int, ...]


@dataclass(frozen=True)
class DKGRejection:
    """A failed Pedersen DKG aggregation, naming the faulty sender."""

    sender_id: int


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
    """Deal one participant's contribution to a single-round Pedersen DKG.

    Every participant calls this once with the same ``participant_ids``,
    ``threshold`` and group parameters. The sender's secret contribution is
    the constant term of a random degree-``threshold - 1`` polynomial whose
    coefficients are all drawn from ``randbelow`` — a deterministic source
    may legitimately produce an all-zero (zero-secret) contribution. A
    second random polynomial of the same degree blinds the first, and each
    participant id receives the double share evaluating both polynomials at
    that id; every coefficient is committed to Pedersen-style, exactly as in
    :func:`split_secret_pedersen`.

    Participant ids and the sender id must be integers in ``1..prime - 1``
    and the participant ids must be unique; they are stored strictly
    increasing. No network, broadcast, persistence or signature step is
    performed — authenticating the sender is the caller's responsibility.
    """
    _validate_feldman_parameters(prime, group_prime, generator, blinding_generator)
    if not isinstance(sender_id, int):
        raise TypeError("sender_id must be an integer")
    if not isinstance(threshold, int):
        raise TypeError("threshold must be an integer")
    ids = tuple(participant_ids)
    for participant_id in ids:
        if not isinstance(participant_id, int):
            raise TypeError("participant ids must be integers")

    if not 0 < sender_id < prime:
        raise ValueError("sender_id must satisfy 0 < sender_id < prime")
    if not ids:
        raise ValueError("at least one participant id is required")
    for participant_id in ids:
        if not 0 < participant_id < prime:
            raise ValueError("participant ids must satisfy 0 < id < prime")
    if len(set(ids)) != len(ids):
        raise ValueError("participant ids must be unique")
    ids = tuple(sorted(ids))
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    if threshold > len(ids):
        raise ValueError("threshold must not exceed the participant count")

    coefficients = [randbelow(prime) for _ in range(threshold)]
    blinding_coefficients = [randbelow(prime) for _ in range(threshold)]

    shares = tuple(
        DKGReceivedShare(
            sender_id=sender_id,
            receiver_id=participant_id,
            share=Share(
                x=participant_id,
                y=evaluate_polynomial(coefficients, participant_id, prime=prime),
            ),
            blinding_share=Share(
                x=participant_id,
                y=evaluate_polynomial(blinding_coefficients, participant_id, prime=prime),
            ),
        )
        for participant_id in ids
    )
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
    return DKGContribution(
        sender_id=sender_id,
        participant_ids=ids,
        shares=shares,
        commitment=commitment,
    )


def verify_dkg_received_share(
    received_share: DKGReceivedShare, contribution: DKGContribution
) -> bool:
    """Check a dealt share pair against its contribution's Pedersen commitment.

    Reuses the Pedersen equation of :func:`verify_pedersen_share` unchanged
    and additionally requires consistent addressing: the pair must come from
    the contribution's sender and both polynomial coordinates must equal
    ``received_share.receiver_id``. Returns ``True`` on a match and ``False``
    for a well-formed pair that was tampered with or is addressed
    inconsistently; malformed arguments raise TypeError/ValueError.
    """
    if not isinstance(received_share, DKGReceivedShare):
        raise TypeError("received_share must be a DKGReceivedShare instance")
    if not isinstance(contribution, DKGContribution):
        raise TypeError("contribution must be a DKGContribution instance")
    commitment = contribution.commitment
    if not isinstance(commitment, PedersenCommitment):
        raise TypeError("contribution commitment must be a PedersenCommitment instance")
    share = received_share.share
    blinding_share = received_share.blinding_share
    if not isinstance(share, Share):
        raise TypeError("received_share.share must be a Share instance")
    if not isinstance(blinding_share, Share):
        raise TypeError("received_share.blinding_share must be a Share instance")
    for name, value in (
        ("received_share.sender_id", received_share.sender_id),
        ("received_share.receiver_id", received_share.receiver_id),
        ("contribution.sender_id", contribution.sender_id),
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
    _validate_commitment_setup(
        commitment.values,
        field_prime,
        commitment.group_prime,
        (commitment.generator, commitment.blinding_generator),
    )

    for name, participant_id in (
        ("sender_id", received_share.sender_id),
        ("receiver_id", received_share.receiver_id),
    ):
        if not 0 < participant_id < field_prime:
            raise ValueError(f"{name} must satisfy 0 < id < field_prime")
    for name, checked_share in (("share", share), ("blinding_share", blinding_share)):
        if not 0 < checked_share.x < field_prime:
            raise ValueError(f"{name} index must satisfy 0 < x < field_prime")
        if not 0 <= checked_share.y < field_prime:
            raise ValueError(f"{name} value must satisfy 0 <= y < field_prime")

    # Everything below is well-formed but wrong: a pair from another sender,
    # addressed to a non-participant or to a different coordinate, or a pair
    # that simply does not lie on the committed polynomials.
    if received_share.sender_id != contribution.sender_id:
        return False
    if received_share.receiver_id not in contribution.participant_ids:
        return False
    if share.x != received_share.receiver_id or blinding_share.x != received_share.receiver_id:
        return False
    return verify_pedersen_share(share, blinding_share, commitment)


def _validate_dkg_contribution(contribution: DKGContribution) -> None:
    """Check the structure of one DKG contribution (TypeError vs ValueError).

    Only structural legality is established here — every dealt pair is
    addressed consistently and in range. Whether the pairs actually lie on
    the committed polynomials is a verification question, answered by
    :func:`aggregate_dkg` with a :class:`DKGRejection` instead of an
    exception.
    """
    commitment = contribution.commitment
    if not isinstance(commitment, PedersenCommitment):
        raise TypeError("contribution commitment must be a PedersenCommitment instance")
    participant_ids = contribution.participant_ids
    if not isinstance(participant_ids, tuple):
        raise TypeError("participant_ids must be a tuple")
    if not isinstance(contribution.sender_id, int):
        raise TypeError("sender_id must be an integer")
    for participant_id in participant_ids:
        if not isinstance(participant_id, int):
            raise TypeError("participant ids must be integers")
    for name, value in (
        ("field_prime", commitment.field_prime),
        ("group_prime", commitment.group_prime),
        ("generator", commitment.generator),
        ("blinding_generator", commitment.blinding_generator),
    ):
        if not isinstance(value, int):
            raise TypeError(f"{name} must be an integer")

    field_prime = commitment.field_prime
    _validate_commitment_setup(
        commitment.values,
        field_prime,
        commitment.group_prime,
        (commitment.generator, commitment.blinding_generator),
    )

    if not 0 < contribution.sender_id < field_prime:
        raise ValueError("sender_id must satisfy 0 < sender_id < field_prime")
    if not participant_ids:
        raise ValueError("participant_ids must not be empty")
    for participant_id in participant_ids:
        if not 0 < participant_id < field_prime:
            raise ValueError("participant ids must satisfy 0 < id < field_prime")
    if tuple(sorted(participant_ids)) != participant_ids or len(set(participant_ids)) != len(
        participant_ids
    ):
        raise ValueError("participant ids must be strictly increasing and unique")

    shares = contribution.shares
    if not isinstance(shares, tuple):
        raise TypeError("contribution shares must be a tuple")
    if len(shares) != len(participant_ids):
        raise ValueError("contribution must carry exactly one share per participant")
    for received, receiver_id in zip(shares, participant_ids):
        if not isinstance(received, DKGReceivedShare):
            raise TypeError("contribution shares must be DKGReceivedShare instances")
        if not isinstance(received.share, Share) or not isinstance(
            received.blinding_share, Share
        ):
            raise TypeError("received shares must carry Share instances")
        for value in (
            received.sender_id,
            received.receiver_id,
            received.share.x,
            received.share.y,
            received.blinding_share.x,
            received.blinding_share.y,
        ):
            if not isinstance(value, int):
                raise TypeError("received share fields must be integers")
        if received.sender_id != contribution.sender_id:
            raise ValueError("share sender must match the contribution sender")
        if received.receiver_id != receiver_id:
            raise ValueError("shares must be ordered by participant id")
        if received.share.x != receiver_id or received.blinding_share.x != receiver_id:
            raise ValueError("share coordinates must equal the receiver id")
        if not 0 <= received.share.y < field_prime:
            raise ValueError("share value must satisfy 0 <= y < field_prime")
        if not 0 <= received.blinding_share.y < field_prime:
            raise ValueError("blinding share value must satisfy 0 <= y < field_prime")


def aggregate_dkg(contributions: Iterable[DKGContribution]) -> list[DKGResult] | DKGRejection:
    """Aggregate one verified contribution per participant into final shares.

    Requires exactly one structurally legal contribution per participant,
    all sharing the same participant ids, threshold and group parameters;
    every dealt share pair is then verified against its contribution's
    commitment. A failed verification is never silently dropped: the result
    is a :class:`DKGRejection` naming that contribution's ``sender_id``.

    On success each receiver's double share is the sum of every
    contribution's pair modulo ``field_prime`` and the joint commitment is
    the component-wise product of every commitment modulo ``group_prime``,
    so any ``threshold`` receivers can rebuild the joint secret (the sum of
    all secret contributions) with :func:`reconstruct_secret`. The result
    does not depend on the order of ``contributions``. Structural problems
    (missing or duplicate participants, illegal ids or commitments,
    inconsistent parameters) raise ValueError, wrong types raise TypeError.
    """
    materialised = list(contributions)
    if not materialised:
        raise ValueError("at least one contribution is required")
    for contribution in materialised:
        if not isinstance(contribution, DKGContribution):
            raise TypeError("contributions must be DKGContribution instances")
    for contribution in materialised:
        _validate_dkg_contribution(contribution)

    first = materialised[0]
    participant_ids = first.participant_ids
    commitment = first.commitment
    threshold = len(commitment.values)
    if threshold > len(participant_ids):
        raise ValueError("threshold must not exceed the participant count")
    for other in materialised[1:]:
        other_commitment = other.commitment
        if other.participant_ids != participant_ids:
            raise ValueError("all contributions must share the same participant ids")
        if (
            other_commitment.field_prime != commitment.field_prime
            or other_commitment.group_prime != commitment.group_prime
            or other_commitment.generator != commitment.generator
            or other_commitment.blinding_generator != commitment.blinding_generator
        ):
            raise ValueError("all contributions must share the same group parameters")
        if len(other_commitment.values) != threshold:
            raise ValueError("all contributions must use the same threshold")

    sender_ids = [contribution.sender_id for contribution in materialised]
    if len(set(sender_ids)) != len(sender_ids):
        raise ValueError("duplicate contribution from the same sender")
    if set(sender_ids) != set(participant_ids):
        raise ValueError("each participant must contribute exactly once")

    # Verify in sender order so that the outcome never depends on the input
    # order; a failed pair rejects the run and names its sender.
    ordered = sorted(materialised, key=lambda contribution: contribution.sender_id)
    for contribution in ordered:
        for received in contribution.shares:
            if not verify_dkg_received_share(received, contribution):
                return DKGRejection(sender_id=contribution.sender_id)

    field_prime = commitment.field_prime
    group_prime = commitment.group_prime
    joint_values = []
    for position in range(threshold):
        product = 1
        for contribution in ordered:
            product = product * contribution.commitment.values[position] % group_prime
        joint_values.append(product)
    joint_commitment = PedersenCommitment(
        values=tuple(joint_values),
        field_prime=field_prime,
        group_prime=group_prime,
        generator=commitment.generator,
        blinding_generator=commitment.blinding_generator,
    )

    results = []
    for position, receiver_id in enumerate(participant_ids):
        y = sum(contribution.shares[position].share.y for contribution in ordered) % field_prime
        blinding_y = (
            sum(contribution.shares[position].blinding_share.y for contribution in ordered)
            % field_prime
        )
        results.append(
            DKGResult(
                receiver_id=receiver_id,
                share=Share(x=receiver_id, y=y),
                blinding_share=Share(x=receiver_id, y=blinding_y),
                commitment=joint_commitment,
                participant_ids=participant_ids,
            )
        )
    return results
