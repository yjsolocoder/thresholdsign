"""thresholdsign - Shamir secret sharing over a prime field.

Public API: Share / FeldmanCommitment / PedersenCommitment / split_secret /
split_secret_verifiable / split_secret_pedersen / verify_share /
verify_pedersen_share / reconstruct_secret / evaluate_polynomial, plus the
single-round Pedersen DKG: DKGContribution / DKGReceivedShare / DKGResult /
DKGRejection / create_dkg_contribution / verify_dkg_received_share /
aggregate_dkg. The signing extension adds SigningContribution /
SigningDKGResult / create_signing_contribution / aggregate_signing_dkg,
proactive share refresh via create_refresh / refresh, member resharing via
create_reshare / reshare, and the two-round
threshold Schnorr protocol: SigningNonceCommitment /
SigningRound / SignatureShare / SignatureShareRejection / AggregateSignature /
create_signing_nonce_commitment / create_signing_round / create_signature_share
/ verify_signature_share / aggregate_signature / verify_signature, signing
audit receipts: SigningAudit / create_audit / check_audit, the stateless
nonce-reuse audit NonceReuse / find_nonce_reuse, leaked-share recovery from
reused nonces via NonceLeak / recover_leaks, publicly
verifiable key-rotation authorization: Rotation / rotation_payload /
verify_rotation, the persistent, multi-hop authorization chain
RotationChain / verify_rotation_chain / encode_rotation_chain /
decode_rotation_chain, and the stateless, threshold-Schnorr-authenticated
audit chain: AuditChain / audit_chain_payload / verify_audit_chain /
encode_audit_chain / decode_audit_chain.
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
    "create_signing_contribution",
    "aggregate_signing_dkg",
    "create_refresh",
    "refresh",
    "create_reshare",
    "reshare",
    "SigningNonceCommitment",
    "SigningRound",
    "SignatureShare",
    "SignatureShareRejection",
    "AggregateSignature",
    "create_signing_nonce_commitment",
    "create_signing_round",
    "create_signature_share",
    "verify_signature_share",
    "aggregate_signature",
    "verify_signature",
    "schnorr_challenge",
    "SigningAudit",
    "create_audit",
    "check_audit",
    "NonceReuse",
    "find_nonce_reuse",
    "NonceLeak",
    "recover_leaks",
    "Rotation",
    "rotation_payload",
    "verify_rotation",
    "encode_rotation",
    "decode_rotation",
    "RotationChain",
    "verify_rotation_chain",
    "encode_rotation_chain",
    "decode_rotation_chain",
    "AuditChain",
    "audit_chain_payload",
    "verify_audit_chain",
    "encode_audit_chain",
    "decode_audit_chain",
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


def _validate_dkg_dealing_parameters(
    sender_id: int,
    participant_ids: Iterable[int],
    threshold: int,
    prime: int,
    group_prime: int,
    generator: int,
    blinding_generator: int,
) -> tuple[int, ...]:
    """Validate the arguments of a (signing) DKG contribution, returning sorted ids.

    Shared by :func:`create_dkg_contribution` and
    :func:`create_signing_contribution`, which accept the same arguments and
    must reject the same illegal inputs.
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

    return tuple(sorted(ids))


def _deal_dkg_contribution(
    sender_id: int,
    participant_ids: Iterable[int],
    threshold: int,
    *,
    group_prime: int,
    generator: int,
    blinding_generator: int,
    prime: int = DEFAULT_PRIME,
    randbelow: Callable[[int], int] = secrets.randbelow,
    constant: int | None = None,
):
    """Validate a dealing and draw its polynomials and double shares.

    Returns ``(ordered_ids, coefficients, blinding_coefficients, shares,
    blinding_shares, pedersen_commitment)``; the coefficients stay inside the
    package and let :func:`create_signing_contribution` add a Feldman
    commitment to the very same sharing polynomial. With ``constant`` set,
    the sharing polynomial's constant term is fixed at that value (and is not
    drawn from ``randbelow``); the remaining sharing coefficients and every
    blinding coefficient follow the usual draw order. This supports the
    proactive refresh dealing (a zero constant shifts every share without
    changing the joint secret) and the reshare dealing (a Lagrange-weighted
    old share as the constant).
    """
    ordered_ids = _validate_dkg_dealing_parameters(
        sender_id,
        participant_ids,
        threshold,
        prime,
        group_prime,
        generator,
        blinding_generator,
    )
    if constant is None:
        coefficients = [randbelow(prime) for _ in range(threshold)]
    else:
        coefficients = [constant] + [randbelow(prime) for _ in range(threshold - 1)]
    blinding_coefficients = [randbelow(prime) for _ in range(threshold)]

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
    return (
        ordered_ids,
        coefficients,
        blinding_coefficients,
        shares,
        blinding_shares,
        commitment,
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
    (
        ordered_ids,
        _coefficients,
        _blinding_coefficients,
        shares,
        blinding_shares,
        commitment,
    ) = _deal_dkg_contribution(
        sender_id,
        participant_ids,
        threshold,
        group_prime=group_prime,
        generator=generator,
        blinding_generator=blinding_generator,
        prime=prime,
        randbelow=randbelow,
    )
    return DKGContribution(
        sender_id=sender_id,
        participant_ids=ordered_ids,
        shares=shares,
        blinding_shares=blinding_shares,
        commitment=commitment,
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

    # Sort by sender so the input order cannot influence the outcome.
    ordered = sorted(materialised, key=lambda contribution: contribution.sender_id)

    rejections = []
    for contribution in ordered:
        for index, receiver_id in enumerate(contribution.participant_ids):
            received = DKGReceivedShare(
                sender_id=contribution.sender_id,
                receiver_id=receiver_id,
                share=contribution.shares[index],
                blinding_share=contribution.blinding_shares[index],
            )
            if not verify_dkg_received_share(received, contribution.commitment):
                rejections.append(DKGRejection(sender_id=contribution.sender_id))
                break
    if rejections:
        return rejections

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


# ---------------------------------------------------------------------------
# Signing DKG: the single-round Pedersen DKG plus, over the very same sharing
# polynomial, a Feldman commitment that makes each participant's verification
# share public.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SigningContribution:
    """One participant's DKG contribution augmented for threshold signing.

    ``contribution`` is an ordinary :class:`DKGContribution` (the Pedersen
    double shares and Pedersen commitment unchanged); ``feldman_commitment``
    commits to the coefficients of the *same* sharing polynomial as
    ``contribution``'s shares, one Feldman value ``g ** a_j mod group_prime``
    per coefficient. The coefficients never appear, so the object contains
    neither the sender's secret nor any polynomial coefficient.
    """

    contribution: DKGContribution
    feldman_commitment: FeldmanCommitment


@dataclass(frozen=True)
class SigningDKGResult:
    """Successful signing DKG aggregation.

    ``result`` is the unchanged :class:`DKGResult` :func:`aggregate_dkg`
    would produce; ``public_key`` is the joint verification key
    ``Y = g ** joint_secret mod group_prime`` and ``verification_shares``
    holds one ``Y_i = g ** s_i mod group_prime`` per position of
    ``result.participant_ids`` (s_i is that receiver's aggregated secret
    share). The joint secret and the individual shares are never stored.
    """

    result: DKGResult
    public_key: int
    verification_shares: tuple[int, ...]


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
    """Create a Pedersen DKG contribution and a Feldman commitment to the same polynomial.

    Accepts exactly the arguments of :func:`create_dkg_contribution` and
    validates them identically. The returned object carries the original
    :class:`DKGContribution` together with a :class:`FeldmanCommitment`
    built from the same drawn sharing polynomial (the blinding polynomial
    plays no part in it), so every receiver can later verify signature
    shares against the public verification shares without learning any
    secret coefficient.
    """
    (
        ordered_ids,
        coefficients,
        _blinding_coefficients,
        shares,
        blinding_shares,
        pedersen_commitment,
    ) = _deal_dkg_contribution(
        sender_id,
        participant_ids,
        threshold,
        group_prime=group_prime,
        generator=generator,
        blinding_generator=blinding_generator,
        prime=prime,
        randbelow=randbelow,
    )
    contribution = DKGContribution(
        sender_id=sender_id,
        participant_ids=ordered_ids,
        shares=shares,
        blinding_shares=blinding_shares,
        commitment=pedersen_commitment,
    )
    feldman_commitment = FeldmanCommitment(
        values=tuple(pow(generator, coefficient, group_prime) for coefficient in coefficients),
        field_prime=prime,
        group_prime=group_prime,
        generator=generator,
    )
    return SigningContribution(
        contribution=contribution,
        feldman_commitment=feldman_commitment,
    )


def create_refresh(
    sender_id: int,
    key: SigningDKGResult,
    *,
    randbelow: Callable[[int], int] = secrets.randbelow,
) -> SigningContribution:
    """Create one participant's zero-secret contribution for proactive refresh.

    This is :func:`create_signing_contribution` over the group parameters,
    participant ids and threshold of an existing :class:`SigningDKGResult`
    ``key``, except that the sharing polynomial's constant term is fixed at
    zero instead of being drawn, so the sender's contribution adds nothing to
    the joint secret (its Feldman constant-term commitment is
    ``g ** 0 == 1``). The remaining ``threshold - 1`` sharing coefficients
    are drawn first, then all ``threshold`` blinding coefficients, in exactly
    the order of :func:`create_signing_contribution`. Summing one such
    contribution per participant into the old shares rerandomises every share
    without changing the joint secret or public key; ``threshold = 1`` is
    supported (there are no non-constant draws at all).
    """
    if not isinstance(key, SigningDKGResult):
        raise TypeError("key must be a SigningDKGResult instance")
    _check_signing_setup(key)
    _check_signing_dkg_structure(key)

    result = key.result
    pedersen = result.commitment
    threshold = len(pedersen.values)
    (
        ordered_ids,
        coefficients,
        _blinding_coefficients,
        shares,
        blinding_shares,
        commitment,
    ) = _deal_dkg_contribution(
        sender_id,
        result.participant_ids,
        threshold,
        group_prime=pedersen.group_prime,
        generator=pedersen.generator,
        blinding_generator=pedersen.blinding_generator,
        prime=pedersen.field_prime,
        randbelow=randbelow,
        constant=0,
    )
    dealing = DKGContribution(
        sender_id=sender_id,
        participant_ids=ordered_ids,
        shares=shares,
        blinding_shares=blinding_shares,
        commitment=commitment,
    )
    feldman_commitment = FeldmanCommitment(
        values=tuple(
            pow(pedersen.generator, coefficient, pedersen.group_prime)
            for coefficient in coefficients
        ),
        field_prime=pedersen.field_prime,
        group_prime=pedersen.group_prime,
        generator=pedersen.generator,
    )
    return SigningContribution(
        contribution=dealing,
        feldman_commitment=feldman_commitment,
    )


def _check_signing_contribution_types(contribution: SigningContribution) -> None:
    """Type-check a SigningContribution, including its nested objects."""
    if not isinstance(contribution, SigningContribution):
        raise TypeError("contributions must be SigningContribution instances")
    if not isinstance(contribution.contribution, DKGContribution):
        raise TypeError("contribution must be a DKGContribution instance")
    if not isinstance(contribution.feldman_commitment, FeldmanCommitment):
        raise TypeError("feldman_commitment must be a FeldmanCommitment instance")
    _check_dkg_contribution_types(contribution.contribution)
    commitment = contribution.feldman_commitment
    for name, value in (
        ("field_prime", commitment.field_prime),
        ("group_prime", commitment.group_prime),
        ("generator", commitment.generator),
    ):
        if not isinstance(value, int):
            raise TypeError(f"{name} must be an integer")
    if not isinstance(commitment.values, tuple):
        raise TypeError("feldman commitment values must be a tuple")


def _check_signing_contribution_structure(contribution: SigningContribution) -> None:
    """Validate ids, lengths, setup and threshold agreement (ValueError).

    Reuses the structure checks of the plain DKG contribution and then pins
    the Feldman commitment to the same group and the same threshold as the
    Pedersen commitment. Binding both commitments to the *same sharing
    polynomial* is checked separately in
    :func:`aggregate_signing_dkg`, after the plain Pedersen verification,
    so a tampered double share keeps producing a DKGRejection exactly as in
    :func:`aggregate_dkg`.
    """
    dealing = contribution.contribution
    _check_dkg_contribution_structure(dealing)
    feldman = contribution.feldman_commitment
    pedersen = dealing.commitment
    if (
        feldman.field_prime != pedersen.field_prime
        or feldman.group_prime != pedersen.group_prime
        or feldman.generator != pedersen.generator
    ):
        raise ValueError("the two commitments must share the same group parameters")
    if len(feldman.values) != len(pedersen.values):
        raise ValueError("the two commitments must share the same threshold")
    _validate_commitment_setup(
        feldman.values, feldman.field_prime, feldman.group_prime, (feldman.generator,)
    )


def aggregate_signing_dkg(
    contributions: Iterable[SigningContribution],
) -> SigningDKGResult | list[DKGRejection]:
    """Aggregate signing contributions into the joint key and verification shares.

    Every participant must contribute exactly once with agreeing ids,
    threshold and group parameters; the plain-DKG checks of
    :func:`aggregate_dkg` apply unchanged and each nested contribution's
    double shares are verified against its Pedersen commitment. Failures
    are never dropped: the result is a sender-sorted ``list`` of
    :class:`DKGRejection` naming every contribution that failed its Pedersen
    verification (a malformed or unbound Feldman commitment is an illegal
    input and raises ValueError instead).

    On success returns a :class:`SigningDKGResult`: the unchanged
    :class:`DKGResult`, the joint public key
    ``Y = product of the contributions' constant-term Feldman commitments``
    and one verification share ``Y_i`` per participant, each the product of
    every contribution's Feldman evaluation at ``i``.
    """
    materialised = list(contributions)
    if not materialised:
        raise ValueError("at least one contribution is required")
    for contribution in materialised:
        _check_signing_contribution_types(contribution)
    for contribution in materialised:
        _check_signing_contribution_structure(contribution)

    dealings = [contribution.contribution for contribution in materialised]

    # Structural consistency (ids, threshold, group parameters, exactly one
    # contribution per participant) is the plain DKG aggregation's job.
    first = dealings[0]
    participant_ids = first.participant_ids
    first_pedersen = first.commitment
    threshold = len(first_pedersen.values)
    for dealing in dealings:
        commitment = dealing.commitment
        if dealing.participant_ids != participant_ids:
            raise ValueError("contributions must agree on the same participant ids")
        if (
            commitment.field_prime != first_pedersen.field_prime
            or commitment.group_prime != first_pedersen.group_prime
            or commitment.generator != first_pedersen.generator
            or commitment.blinding_generator != first_pedersen.blinding_generator
        ):
            raise ValueError("contributions must share the same group parameters")
        if len(commitment.values) != threshold:
            raise ValueError("contributions must share the same threshold")
    sender_ids = [dealing.sender_id for dealing in dealings]
    if len(set(sender_ids)) != len(sender_ids):
        raise ValueError("duplicate contribution from the same participant")
    if set(sender_ids) != set(participant_ids):
        raise ValueError("each participant must contribute exactly once")

    ordered = sorted(materialised, key=lambda item: item.contribution.sender_id)

    rejections: list[DKGRejection] = []
    for item in ordered:
        dealing = item.contribution
        for index, receiver_id in enumerate(dealing.participant_ids):
            received = DKGReceivedShare(
                sender_id=dealing.sender_id,
                receiver_id=receiver_id,
                share=dealing.shares[index],
                blinding_share=dealing.blinding_shares[index],
            )
            if not verify_dkg_received_share(received, dealing.commitment):
                rejections.append(DKGRejection(sender_id=dealing.sender_id))
                break
    if rejections:
        return rejections

    # Every surviving double share is Pedersen-valid; the Feldman commitment
    # must additionally evaluate on the same sharing polynomial. A mismatch
    # here is an internally inconsistent contribution (legal pieces, wrong
    # pairing), reported as an illegal input rather than a rejection.
    for item in ordered:
        for share in item.contribution.shares:
            if not verify_share(share, item.feldman_commitment):
                raise ValueError(
                    "Feldman commitment must match the contribution shares"
                )

    result = aggregate_dkg([item.contribution for item in ordered])
    assert isinstance(result, DKGResult)

    group_prime = first_pedersen.group_prime
    public_key = 1
    verification_shares: list[int] = [1 for _ in participant_ids]
    for item in ordered:
        feldman = item.feldman_commitment
        public_key = public_key * feldman.values[0] % group_prime
        for index, receiver_id in enumerate(participant_ids):
            x_power = 1
            evaluation = 1
            for value in feldman.values:
                evaluation = evaluation * pow(value, x_power, group_prime) % group_prime
                x_power = x_power * receiver_id % feldman.field_prime
            verification_shares[index] = (
                verification_shares[index] * evaluation % group_prime
            )
    return SigningDKGResult(
        result=result,
        public_key=public_key,
        verification_shares=tuple(verification_shares),
    )


def refresh(
    contributions: Iterable[SigningContribution],
    key: SigningDKGResult,
) -> SigningDKGResult | list[DKGRejection]:
    """Proactively refresh the shares of ``key`` with zero-secret contributions.

    Every participant of ``key`` must contribute exactly once with the same
    participant ids, threshold and group parameters; the plain-DKG structural
    checks of :func:`aggregate_signing_dkg` apply unchanged and each nested
    contribution's double shares are verified against its Pedersen
    commitment. Beyond those checks, every contribution's Feldman constant-
    term commitment must be ``1`` (proving a zero sharing constant term) and
    its double shares must lie on the polynomial committed to by both its
    commitments. A contribution that fails any of these cryptographic checks
    is named in a sender-sorted ``list`` of :class:`DKGRejection`; malformed
    arguments, missing/duplicate participants or inconsistent parameters
    raise TypeError/ValueError as in :func:`aggregate_signing_dkg`.

    On success the double shares are added fieldwise to ``key``'s and both
    commitment families are multiplied groupwise, so the joint secret and the
    public key are unchanged (every contribution's Feldman constant
    commitment is 1) while ``verification_shares`` are recomputed from the new
    aggregated shares. The result is independent of the input order. The
    library keeps no state: the caller must destroy the old shares and adopt
    the returned ones, and signatures made under the old key remain valid.
    """
    if not isinstance(key, SigningDKGResult):
        raise TypeError("key must be a SigningDKGResult instance")
    _check_signing_setup(key)
    _check_signing_dkg_structure(key)

    materialised = list(contributions)
    if not materialised:
        raise ValueError("at least one contribution is required")
    for contribution in materialised:
        _check_signing_contribution_types(contribution)
    for contribution in materialised:
        _check_signing_contribution_structure(contribution)

    old_result = key.result
    old_pedersen = old_result.commitment
    participant_ids = old_result.participant_ids
    threshold = len(old_pedersen.values)
    dealings = [contribution.contribution for contribution in materialised]
    for dealing in dealings:
        commitment = dealing.commitment
        if dealing.participant_ids != participant_ids:
            raise ValueError("contributions must agree on the same participant ids")
        if (
            commitment.field_prime != old_pedersen.field_prime
            or commitment.group_prime != old_pedersen.group_prime
            or commitment.generator != old_pedersen.generator
            or commitment.blinding_generator != old_pedersen.blinding_generator
        ):
            raise ValueError("contributions must share the same group parameters")
        if len(commitment.values) != threshold:
            raise ValueError("contributions must share the same threshold")
    sender_ids = [dealing.sender_id for dealing in dealings]
    if len(set(sender_ids)) != len(sender_ids):
        raise ValueError("duplicate contribution from the same participant")
    if set(sender_ids) != set(participant_ids):
        raise ValueError("each participant must contribute exactly once")

    ordered = sorted(materialised, key=lambda item: item.contribution.sender_id)

    rejections: list[DKGRejection] = []
    for item in ordered:
        dealing = item.contribution
        failed = False
        for index, receiver_id in enumerate(dealing.participant_ids):
            received = DKGReceivedShare(
                sender_id=dealing.sender_id,
                receiver_id=receiver_id,
                share=dealing.shares[index],
                blinding_share=dealing.blinding_shares[index],
            )
            if not verify_dkg_received_share(received, dealing.commitment):
                failed = True
                break
            if not verify_share(dealing.shares[index], item.feldman_commitment):
                failed = True
                break
        if failed or item.feldman_commitment.values[0] != 1:
            rejections.append(DKGRejection(sender_id=dealing.sender_id))
    if rejections:
        return rejections

    field_prime = old_pedersen.field_prime
    group_prime = old_pedersen.group_prime
    new_shares = []
    new_blinding_shares = []
    for index, receiver_id in enumerate(participant_ids):
        y = old_result.shares[index].y
        y_blinding = old_result.blinding_shares[index].y
        for item in ordered:
            y = (y + item.contribution.shares[index].y) % field_prime
            y_blinding = (
                y_blinding + item.contribution.blinding_shares[index].y
            ) % field_prime
        new_shares.append(Share(x=receiver_id, y=y))
        new_blinding_shares.append(Share(x=receiver_id, y=y_blinding))

    new_pedersen_values = []
    for position in range(threshold):
        value = old_pedersen.values[position]
        for item in ordered:
            value = value * item.contribution.commitment.values[position] % group_prime
        new_pedersen_values.append(value)

    new_result = DKGResult(
        participant_ids=participant_ids,
        shares=tuple(new_shares),
        blinding_shares=tuple(new_blinding_shares),
        commitment=PedersenCommitment(
            values=tuple(new_pedersen_values),
            field_prime=field_prime,
            group_prime=group_prime,
            generator=old_pedersen.generator,
            blinding_generator=old_pedersen.blinding_generator,
        ),
    )

    # Every contribution has a zero constant term, so the product of the
    # constant-term Feldman commitments is 1 and the public key is unchanged.
    verification_shares = tuple(
        pow(old_pedersen.generator, share.y, group_prime)
        for share in new_shares
    )
    return SigningDKGResult(
        result=new_result,
        public_key=key.public_key,
        verification_shares=verification_shares,
    )


# ---------------------------------------------------------------------------
# Member resharing: a threshold quorum of old participants re-deals the joint
# secret to a (possibly different) member set under an arbitrary new
# threshold. Each dealer shares its Lagrange-weighted old share, so the new
# shares rebuild the very same joint secret and the public key is unchanged.
# ---------------------------------------------------------------------------


def _check_reshare_dealers(
    dealers: Iterable[int],
    participant_ids: tuple[int, ...],
    old_threshold: int,
    members: tuple[int, ...] | None = None,
) -> list[int]:
    """Validate the dealer set of a resharing, returning it as a list.

    Dealers must be strictly increasing, unique, number at least the old
    threshold, and every dealer must be a participant of the old key; with
    ``members`` given, every dealer must also be one of the new members (the
    dealer both holds an old share and receives a new one).
    """
    if isinstance(dealers, (str, bytes)):
        raise TypeError("dealers must be an iterable of integers")
    dealer_list = list(dealers)
    for dealer in dealer_list:
        if not isinstance(dealer, int) or isinstance(dealer, bool):
            raise TypeError("dealer ids must be integers")
    if not dealer_list:
        raise ValueError("at least one dealer is required")
    if len(set(dealer_list)) != len(dealer_list):
        raise ValueError("dealer ids must be unique")
    if dealer_list != sorted(dealer_list):
        raise ValueError("dealer ids must be strictly increasing")
    if len(dealer_list) < old_threshold:
        raise ValueError("dealers must number at least the old threshold")
    for dealer in dealer_list:
        if dealer not in participant_ids:
            raise ValueError("every dealer must be a participant of the old key")
    if members is not None:
        for dealer in dealer_list:
            if dealer not in members:
                raise ValueError("every dealer must be one of the new members")
    return dealer_list


def create_reshare(
    sender: int,
    share: int,
    dealers: Iterable[int],
    members: Iterable[int],
    threshold: int,
    key: SigningDKGResult,
    *,
    rng: Callable[[int], int] = secrets.randbelow,
) -> SigningContribution:
    """Create one dealer's contribution to a member resharing of ``key``.

    ``sender`` is one of the old participants; ``share`` is its aggregated
    secret share ``s_i`` of ``key`` (checked against the old verification
    share ``Y_i``, a mismatch raises ValueError). ``dealers`` is the strictly
    increasing, duplicate-free quorum of old participants re-dealing the
    secret: it must number at least the old threshold and every dealer must
    be a participant of ``key`` and one of the new ``members``. ``members``
    is the new participant-id set and ``threshold`` the new threshold ``t``;
    both follow the usual DKG dealing constraints.

    The sender's new sharing polynomial over ``members`` has the constant
    term ``lambda_i * share mod q`` (not drawn), where ``lambda_i`` is the
    sender's Lagrange weight at zero over ``dealers``; then ``t - 1`` sharing
    coefficients and ``t`` blinding coefficients are drawn from ``rng(q)`` in
    exactly the order of :func:`create_signing_contribution`. Summing one
    such contribution per dealer makes the new constant terms add up to
    ``sum(lambda_i * s_i)`` — the old joint secret — so any ``t`` new members
    rebuild it while the public key stays unchanged.
    """
    if not isinstance(key, SigningDKGResult):
        raise TypeError("key must be a SigningDKGResult instance")
    _check_signing_setup(key)
    _check_signing_dkg_structure(key)
    if not isinstance(sender, int) or isinstance(sender, bool):
        raise TypeError("sender must be an integer")
    if not isinstance(share, int) or isinstance(share, bool):
        raise TypeError("share must be an integer")

    old_result = key.result
    pedersen = old_result.commitment
    field_prime = pedersen.field_prime
    group_prime = pedersen.group_prime
    generator = pedersen.generator
    old_ids = old_result.participant_ids
    old_threshold = len(pedersen.values)

    ordered_members = _validate_dkg_dealing_parameters(
        sender,
        members,
        threshold,
        field_prime,
        group_prime,
        generator,
        pedersen.blinding_generator,
    )
    dealer_list = _check_reshare_dealers(
        dealers, old_ids, old_threshold, ordered_members
    )
    if sender not in dealer_list:
        raise ValueError("sender must be one of the dealers")

    if not 0 <= share < field_prime:
        raise ValueError("share must satisfy 0 <= share < field_prime")
    sender_index = old_ids.index(sender)
    if pow(generator, share, group_prime) != key.verification_shares[sender_index]:
        raise ValueError("share does not match the old verification share Y_i")

    weight = _lagrange_weight(sender, dealer_list, field_prime)
    (
        ordered_ids,
        coefficients,
        _blinding_coefficients,
        shares,
        blinding_shares,
        commitment,
    ) = _deal_dkg_contribution(
        sender,
        ordered_members,
        threshold,
        group_prime=group_prime,
        generator=generator,
        blinding_generator=pedersen.blinding_generator,
        prime=field_prime,
        randbelow=rng,
        constant=weight * share % field_prime,
    )
    dealing = DKGContribution(
        sender_id=sender,
        participant_ids=ordered_ids,
        shares=shares,
        blinding_shares=blinding_shares,
        commitment=commitment,
    )
    feldman_commitment = FeldmanCommitment(
        values=tuple(
            pow(generator, coefficient, group_prime) for coefficient in coefficients
        ),
        field_prime=field_prime,
        group_prime=group_prime,
        generator=generator,
    )
    return SigningContribution(
        contribution=dealing,
        feldman_commitment=feldman_commitment,
    )


def reshare(
    contributions: Iterable[SigningContribution],
    dealers: Iterable[int],
    key: SigningDKGResult,
) -> SigningDKGResult | list[DKGRejection]:
    """Aggregate one resharing contribution per dealer into the new key.

    ``dealers`` is the strictly increasing, duplicate-free quorum of old
    participants re-dealing the secret of ``key``; it must number at least
    the old threshold and every dealer must be a participant of ``key``.
    Every dealer must contribute exactly once, and all contributions must
    agree on the new member ids, the new threshold and the old group
    parameters; missing or duplicate dealers, illegal ids or commitments and
    inconsistent parameters raise ValueError, wrong types raise TypeError.

    Beyond the plain-DKG checks, every contribution's Feldman constant-term
    commitment must equal ``Y_i ** lambda_i`` (the sender's old verification
    share raised to its Lagrange weight over ``dealers``) and its double
    shares must lie on the polynomial committed to by both its commitments.
    A contribution that fails any of these cryptographic checks is named in a
    sender-sorted ``list`` of :class:`DKGRejection`, never silently dropped.

    On success the double shares of all contributions are added fieldwise and
    both commitment families are multiplied groupwise, so the result is
    independent of the input order. The new constant terms sum to the old
    joint secret, hence ``public_key`` is unchanged (old signatures remain
    valid) while the new shares, over the new member set and threshold, can
    sign at once; ``verification_shares`` are recomputed as ``g ** s_i``. The
    library keeps no state: the caller must distribute the new shares and
    destroy the old ones.
    """
    if not isinstance(key, SigningDKGResult):
        raise TypeError("key must be a SigningDKGResult instance")
    _check_signing_setup(key)
    _check_signing_dkg_structure(key)

    old_result = key.result
    old_pedersen = old_result.commitment
    old_ids = old_result.participant_ids
    old_threshold = len(old_pedersen.values)
    dealer_list = _check_reshare_dealers(dealers, old_ids, old_threshold)

    materialised = list(contributions)
    if not materialised:
        raise ValueError("at least one contribution is required")
    for contribution in materialised:
        _check_signing_contribution_types(contribution)
    for contribution in materialised:
        _check_signing_contribution_structure(contribution)

    dealings = [contribution.contribution for contribution in materialised]
    first = dealings[0]
    member_ids = first.participant_ids
    threshold = len(first.commitment.values)
    for dealing in dealings:
        commitment = dealing.commitment
        if dealing.participant_ids != member_ids:
            raise ValueError("contributions must agree on the same participant ids")
        if (
            commitment.field_prime != old_pedersen.field_prime
            or commitment.group_prime != old_pedersen.group_prime
            or commitment.generator != old_pedersen.generator
            or commitment.blinding_generator != old_pedersen.blinding_generator
        ):
            raise ValueError("contributions must share the same group parameters")
        if len(commitment.values) != threshold:
            raise ValueError("contributions must share the same threshold")
    sender_ids = [dealing.sender_id for dealing in dealings]
    if len(set(sender_ids)) != len(sender_ids):
        raise ValueError("duplicate contribution from the same dealer")
    if set(sender_ids) != set(dealer_list):
        raise ValueError("each dealer must contribute exactly once")

    ordered = sorted(materialised, key=lambda item: item.contribution.sender_id)
    field_prime = old_pedersen.field_prime
    group_prime = old_pedersen.group_prime
    weights = {
        dealer: _lagrange_weight(dealer, dealer_list, field_prime)
        for dealer in dealer_list
    }

    rejections: list[DKGRejection] = []
    for item in ordered:
        dealing = item.contribution
        failed = False
        for index, receiver_id in enumerate(dealing.participant_ids):
            received = DKGReceivedShare(
                sender_id=dealing.sender_id,
                receiver_id=receiver_id,
                share=dealing.shares[index],
                blinding_share=dealing.blinding_shares[index],
            )
            if not verify_dkg_received_share(received, dealing.commitment):
                failed = True
                break
            if not verify_share(dealing.shares[index], item.feldman_commitment):
                failed = True
                break
        # The Feldman constant must commit to lambda_i * s_i: exactly the old
        # verification share Y_i raised to the sender's Lagrange weight.
        expected_constant = pow(
            key.verification_shares[old_ids.index(dealing.sender_id)],
            weights[dealing.sender_id],
            group_prime,
        )
        if failed or item.feldman_commitment.values[0] != expected_constant:
            rejections.append(DKGRejection(sender_id=dealing.sender_id))
    if rejections:
        return rejections

    new_shares = []
    new_blinding_shares = []
    for index, receiver_id in enumerate(member_ids):
        y = 0
        y_blinding = 0
        for item in ordered:
            y = (y + item.contribution.shares[index].y) % field_prime
            y_blinding = (
                y_blinding + item.contribution.blinding_shares[index].y
            ) % field_prime
        new_shares.append(Share(x=receiver_id, y=y))
        new_blinding_shares.append(Share(x=receiver_id, y=y_blinding))

    new_pedersen_values = []
    for position in range(threshold):
        value = 1
        for item in ordered:
            value = value * item.contribution.commitment.values[position] % group_prime
        new_pedersen_values.append(value)

    new_result = DKGResult(
        participant_ids=member_ids,
        shares=tuple(new_shares),
        blinding_shares=tuple(new_blinding_shares),
        commitment=PedersenCommitment(
            values=tuple(new_pedersen_values),
            field_prime=field_prime,
            group_prime=group_prime,
            generator=old_pedersen.generator,
            blinding_generator=old_pedersen.blinding_generator,
        ),
    )

    # Every Feldman constant was verified as Y_i ** lambda_i, so their
    # product is g ** (sum lambda_i * s_i) == old public key: unchanged.
    verification_shares = tuple(
        pow(old_pedersen.generator, share.y, group_prime) for share in new_shares
    )
    return SigningDKGResult(
        result=new_result,
        public_key=key.public_key,
        verification_shares=verification_shares,
    )


# ---------------------------------------------------------------------------
# Two-round threshold Schnorr signatures over the signing DKG key.
# Round 1: each signer publishes R_i = g ** r_i for a one-off nonzero nonce.
# Round 2: after the challenge is fixed, each signer publishes
# z_i = r_i + c * lambda_i * s_i mod q; the aggregator sums the shares.
# ---------------------------------------------------------------------------

SCHNORR_TAG = b"thresholdsign/schnorr/v1"


@dataclass(frozen=True)
class SigningNonceCommitment:
    """One signer's round-one commitment ``R_i = g ** r_i mod group_prime``.

    ``signer_id`` is the DKG participant publishing the commitment and
    ``commitment`` is the public value ``R_i``. The nonce itself never
    appears and must never be reused; only the signer retains it to produce
    its signature share.
    """

    signer_id: int
    commitment: int


@dataclass(frozen=True)
class SigningRound:
    """The agreed round-one material that fixes one signing instance.

    ``message`` is the exact byte string being signed; ``signer_ids`` is the
    strictly increasing, duplicate-free tuple of contributing signers (at
    least ``threshold`` of them); ``nonce_commitments`` holds one
    :class:`SigningNonceCommitment` per signer in the same order; ``R`` is
    the product of every ``R_i`` modulo ``group_prime`` and ``challenge`` is
    the Fiat-Shamir integer challenge ``c`` (reduced modulo ``field_prime``).
    A round may not be reused for another message or another signer set.
    """

    message: bytes
    signer_ids: tuple[int, ...]
    nonce_commitments: tuple[SigningNonceCommitment, ...]
    R: int
    challenge: int


@dataclass(frozen=True)
class SignatureShare:
    """One signer's round-two partial signature ``z_i``.

    ``signer_id`` names the publishing signer; ``nonce_commitment`` repeats
    its round-one value ``R_i`` (binding the share to its round) and ``z`` is
    ``r_i + c * lambda_i * s_i mod field_prime``. The secret nonce and the
    secret share never appear.
    """

    signer_id: int
    nonce_commitment: int
    z: int


@dataclass(frozen=True)
class SignatureShareRejection:
    """A signature share that failed verification, identified by its signer."""

    signer_id: int


@dataclass(frozen=True)
class AggregateSignature:
    """The threshold Schnorr signature ``(R, z)`` on a fixed message.

    ``signer_ids`` records the strictly increasing signing set whose
    signature this is: the Fiat-Shamir challenge binds those ids, so an
    external verifier needs them to reconstruct ``c``.
    """

    R: int
    z: int
    signer_ids: tuple[int, ...]


def _draw_nonzero_nonce(randbelow: Callable[[int], int], prime: int) -> int:
    """Draw a one-off nonce uniformly from ``1 .. prime - 1``.

    The injected ``randbelow`` works over ``prime - 1`` values like
    :func:`secrets.randbelow`; rejecting a zero draw guarantees a non-identity
    commitment and keeps nonce reuse the caller's sole responsibility.
    """
    nonce = randbelow(prime - 1)
    if not isinstance(nonce, int) or isinstance(nonce, bool):
        raise TypeError("randbelow must return an integer")
    if not 0 <= nonce < prime - 1:
        raise ValueError("randbelow must return a value in range(prime - 1)")
    return nonce + 1


def create_signing_nonce_commitment(
    signer_id: int,
    *,
    group_prime: int,
    generator: int,
    prime: int = DEFAULT_PRIME,
    randbelow: Callable[[int], int] = secrets.randbelow,
) -> tuple[SigningNonceCommitment, int]:
    """Draw a one-off nonce ``r_i`` and publish ``R_i = g ** r_i``.

    Returns ``(commitment, nonce)``; the nonce is returned only to its own
    signer and must be discarded after the signature share is produced, and
    never reused across messages or rounds. The same injected ``randbelow``
    convention as everywhere else applies, except the draw is over
    ``prime - 1`` and a zero result is rejected so the nonce is nonzero.
    """
    if not isinstance(signer_id, int) or isinstance(signer_id, bool):
        raise TypeError("signer_id must be an integer")
    _validate_feldman_parameters(prime, group_prime, generator)
    if not 0 < signer_id < prime:
        raise ValueError("signer_id must satisfy 1 <= signer_id <= prime - 1")

    nonce = _draw_nonzero_nonce(randbelow, prime)
    return SigningNonceCommitment(signer_id=signer_id, commitment=pow(generator, nonce, group_prime)), nonce


def _encode_integer(value: int, length: int) -> bytes:
    """Unsigned big-endian encoding of ``value`` in exactly ``length`` bytes."""
    return value.to_bytes(length, "big", signed=False)


def schnorr_challenge(
    message: bytes,
    public_key: int,
    R: int,
    signer_ids: Sequence[int],
    *,
    field_prime: int,
    group_prime: int,
) -> int:
    """Compute the Fiat-Shamir challenge ``c`` of the threshold Schnorr scheme.

    ``c = int(SHA256(tag || SHA256(message) || Y || R || id_1 || ... || id_k))
    mod field_prime`` where the tag is ``b"thresholdsign/schnorr/v1"`` and
    every integer is the unsigned big-endian representation in
    ``L = ceil(group_prime.bit_length() / 8)`` bytes. Signer ids are taken in
    the (strictly increasing) order given, so the encoding is canonical.
    """
    length = (group_prime.bit_length() + 7) // 8
    digest = hashlib.sha256(message).digest()
    buffer = bytearray(SCHNORR_TAG)
    buffer += digest
    buffer += _encode_integer(public_key, length)
    buffer += _encode_integer(R, length)
    for signer_id in signer_ids:
        buffer += _encode_integer(signer_id, length)
    return int.from_bytes(hashlib.sha256(buffer).digest(), "big") % field_prime


def _check_signing_setup(
    dkg_result: SigningDKGResult,
) -> tuple[DKGResult, int, int, int, int]:
    """Type-check a SigningDKGResult and return its plain parameters."""
    if not isinstance(dkg_result, SigningDKGResult):
        raise TypeError("dkg_result must be a SigningDKGResult instance")
    result = dkg_result.result
    if not isinstance(result, DKGResult):
        raise TypeError("dkg_result.result must be a DKGResult instance")
    if not isinstance(result.commitment, PedersenCommitment):
        raise TypeError("dkg_result.result.commitment must be a PedersenCommitment instance")
    if not isinstance(result.participant_ids, tuple):
        raise TypeError("participant_ids must be a tuple")
    for name, shares in (
        ("result.shares", result.shares),
        ("result.blinding_shares", result.blinding_shares),
    ):
        if not isinstance(shares, tuple):
            raise TypeError(f"{name} must be a tuple")
        for share in shares:
            if not isinstance(share, Share):
                raise TypeError(f"{name} must contain Share instances")
    if not isinstance(dkg_result.public_key, int) or isinstance(dkg_result.public_key, bool):
        raise TypeError("public_key must be an integer")
    if not isinstance(dkg_result.verification_shares, tuple):
        raise TypeError("verification_shares must be a tuple")
    for value in dkg_result.verification_shares:
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError("verification shares must be integers")
    pedersen = result.commitment
    for name, value in (
        ("field_prime", pedersen.field_prime),
        ("group_prime", pedersen.group_prime),
        ("generator", pedersen.generator),
    ):
        if not isinstance(value, int):
            raise TypeError(f"{name} must be an integer")
    return (
        result,
        dkg_result.public_key,
        pedersen.field_prime,
        pedersen.group_prime,
        pedersen.generator,
    )


def _check_signing_dkg_structure(dkg_result: SigningDKGResult) -> None:
    """Value-validate the nested DKG result and verification shares of a signing DKG."""
    result = dkg_result.result
    pedersen = result.commitment
    field_prime = pedersen.field_prime
    group_prime = pedersen.group_prime
    ids = result.participant_ids
    if not isinstance(ids, tuple) or not ids:
        raise ValueError("participant ids must be a non-empty tuple")
    if any(ids[index] >= ids[index + 1] for index in range(len(ids) - 1)):
        raise ValueError("participant ids must be strictly increasing and unique")
    for name, shares in (
        ("shares", result.shares),
        ("blinding_shares", result.blinding_shares),
    ):
        if not isinstance(shares, tuple) or len(shares) != len(ids):
            raise ValueError(f"{name} must contain one Share per participant")
        for participant_id, share in zip(ids, shares):
            if not isinstance(share, Share) or share.x != participant_id:
                raise ValueError(f"{name} must be aligned with the participant ids")
    _validate_commitment_setup(
        pedersen.values,
        field_prime,
        group_prime,
        (pedersen.generator, pedersen.blinding_generator),
    )
    if len(pedersen.values) > len(ids):
        raise ValueError("threshold must not exceed the number of participants")
    if len(dkg_result.verification_shares) != len(ids):
        raise ValueError("one verification share per participant is required")
    for value in dkg_result.verification_shares:
        if not 0 < value < group_prime:
            raise ValueError("verification shares must satisfy 0 < Y_i < group_prime")
        if pow(value, field_prime, group_prime) != 1:
            raise ValueError("verification shares must lie in the order-field_prime subgroup")
    if not 0 < dkg_result.public_key < group_prime:
        raise ValueError("public_key must satisfy 0 < Y < group_prime")
    if pow(dkg_result.public_key, field_prime, group_prime) != 1:
        raise ValueError("public_key must lie in the order-field_prime subgroup")

def _validate_round_parts(
    message: object,
    ids: object,
    commitments: object,
    field_prime: int,
    group_prime: int,
    participant_ids: Sequence[int],
    threshold: int,
) -> tuple[tuple[int, ...], tuple[SigningNonceCommitment, ...]]:
    """Validate the raw parts of a signing round, returning canonical id/R lists."""
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")
    if isinstance(ids, (str, bytes)):
        raise TypeError("signer_ids must be an iterable of integers")
    if isinstance(commitments, (str, bytes)):
        raise TypeError("nonce_commitments must be an iterable of SigningNonceCommitment")

    for signer_id in ids:
        if not isinstance(signer_id, int) or isinstance(signer_id, bool):
            raise TypeError("signer ids must be integers")
        if not 0 < signer_id < field_prime:
            raise ValueError("signer ids must satisfy 1 <= id <= field_prime - 1")
    if not ids:
        raise ValueError("at least one signer is required")
    if len(set(ids)) != len(ids):
        raise ValueError("signer ids must be unique")
    ordered_ids = tuple(sorted(ids))
    if tuple(ids) != ordered_ids:
        raise ValueError("signer ids must be strictly increasing")
    if any(signer_id not in participant_ids for signer_id in ordered_ids):
        raise ValueError("every signer must be a DKG participant")
    if len(ordered_ids) < threshold:
        raise ValueError("at least threshold signers are required")

    for commitment in commitments:
        if not isinstance(commitment, SigningNonceCommitment):
            raise TypeError("nonce_commitments must contain SigningNonceCommitment instances")
        if not isinstance(commitment.signer_id, int) or isinstance(commitment.signer_id, bool):
            raise TypeError("nonce commitment signer_id must be an integer")
        if not isinstance(commitment.commitment, int) or isinstance(commitment.commitment, bool):
            raise TypeError("nonce commitment value must be an integer")
    commitment_by_signer = {commitment.signer_id: commitment for commitment in commitments}
    if set(commitment_by_signer) != set(ordered_ids) or len(commitments) != len(ordered_ids):
        raise ValueError("each signer must publish exactly one nonce commitment")

    ordered_commitments = tuple(commitment_by_signer[signer_id] for signer_id in ordered_ids)
    R_values = [commitment.commitment for commitment in ordered_commitments]
    for value in R_values:
        if not 1 < value < group_prime:
            raise ValueError("nonce commitment must satisfy 1 < R_i < group_prime")
        if pow(value, field_prime, group_prime) != 1:
            raise ValueError("nonce commitment must lie in the order-field_prime subgroup")
    if len(set(R_values)) != len(R_values):
        raise ValueError("nonce commitments must be unique")
    return ordered_ids, ordered_commitments


def _validate_signing_round(
    round_info: SigningRound,
    field_prime: int,
    group_prime: int,
    participant_ids: Sequence[int],
    threshold: int,
) -> tuple[int, ...]:
    """Type- and value-check an existing SigningRound against its DKG context.

    Returns the canonical signer ids. Structural malformation raises
    TypeError/ValueError; consistency between ``R`` / ``challenge`` and the
    round contents is left to the caller, which reports it as a rejected
    share rather than an illegal input.
    """
    if not isinstance(round_info, SigningRound):
        raise TypeError("round_info must be a SigningRound instance")
    if not isinstance(round_info.message, bytes):
        raise TypeError("round message must be bytes")
    if not isinstance(round_info.signer_ids, tuple):
        raise TypeError("round signer_ids must be a tuple")
    if not isinstance(round_info.nonce_commitments, tuple):
        raise TypeError("round nonce_commitments must be a tuple")
    if not isinstance(round_info.R, int) or isinstance(round_info.R, bool):
        raise TypeError("round R must be an integer")
    if not isinstance(round_info.challenge, int) or isinstance(round_info.challenge, bool):
        raise TypeError("round challenge must be an integer")

    ids, commitments = _validate_round_parts(
        round_info.message,
        round_info.signer_ids,
        round_info.nonce_commitments,
        field_prime,
        group_prime,
        participant_ids,
        threshold,
    )
    if not 0 < round_info.R < group_prime:
        raise ValueError("round R must satisfy 0 < R < group_prime")
    if not 0 <= round_info.challenge < field_prime:
        raise ValueError("round challenge must satisfy 0 <= c < field_prime")
    return ids


def create_signing_round(
    message: bytes,
    signer_ids: Iterable[int],
    nonce_commitments: Iterable[SigningNonceCommitment],
    dkg_result: SigningDKGResult,
) -> SigningRound:
    """Assemble the round-one commitments into a fixed :class:`SigningRound`.

    ``signer_ids`` must be unique DKG participants, strictly increasing, and
    number at least ``threshold``; ``nonce_commitments`` must contain exactly
    one round-one commitment per signer, whose ``R_i`` values are distinct
    non-identity elements of the order-``field_prime`` subgroup. Distinct
    ``R_i`` stop one signer copying another's commitment. The aggregate
    ``R`` is the product of every ``R_i`` and the challenge binds the tag,
    the message SHA-256 digest, ``Y``, ``R`` and the L-byte encodings of the
    signer ids.
    """
    result, public_key, field_prime, group_prime, _generator = _check_signing_setup(dkg_result)
    _check_signing_dkg_structure(dkg_result)
    threshold = len(result.commitment.values)

    ids = signer_ids if isinstance(signer_ids, tuple) else tuple(signer_ids)
    commitments = (
        nonce_commitments
        if isinstance(nonce_commitments, tuple)
        else tuple(nonce_commitments)
    )
    ordered_ids, ordered_commitments = _validate_round_parts(
        message,
        ids,
        commitments,
        field_prime,
        group_prime,
        result.participant_ids,
        threshold,
    )

    R = 1
    for commitment in ordered_commitments:
        R = R * commitment.commitment % group_prime
    challenge = schnorr_challenge(
        message,
        public_key,
        R,
        ordered_ids,
        field_prime=field_prime,
        group_prime=group_prime,
    )
    return SigningRound(
        message=message,
        signer_ids=ordered_ids,
        nonce_commitments=ordered_commitments,
        R=R,
        challenge=challenge,
    )


def _lagrange_weight(signer_id: int, signer_ids: Sequence[int], prime: int) -> int:
    """Lagrange coefficient of ``signer_id`` evaluated at zero, modulo ``prime``."""
    numerator = 1
    denominator = 1
    for other_id in signer_ids:
        if other_id == signer_id:
            continue
        numerator = numerator * (-other_id) % prime
        denominator = denominator * (signer_id - other_id) % prime
    return numerator * pow(denominator, -1, prime) % prime


def create_signature_share(
    signer_id: int,
    secret_share: int,
    nonce: int,
    round_info: SigningRound,
    dkg_result: SigningDKGResult,
) -> SignatureShare:
    """Produce one signer's round-two share ``z_i = r_i + c * lambda_i * s_i mod q``.

    ``secret_share`` is the signer's aggregated DKG share ``s_i`` and
    ``nonce`` is the one-off nonzero value behind its round-one ``R_i``; the
    Lagrange weight is taken at zero over exactly the round's signer set.
    The nonce is checked against the published commitment and must not be
    zero or reused (reuse is the caller's responsibility to avoid). Neither
    the nonce nor the secret share is stored in the returned object.
    """
    if not isinstance(signer_id, int) or isinstance(signer_id, bool):
        raise TypeError("signer_id must be an integer")
    if not isinstance(secret_share, int) or isinstance(secret_share, bool):
        raise TypeError("secret_share must be an integer")
    if not isinstance(nonce, int) or isinstance(nonce, bool):
        raise TypeError("nonce must be an integer")
    if not isinstance(round_info, SigningRound):
        raise TypeError("round_info must be a SigningRound instance")
    result, _public_key, field_prime, group_prime, generator = _check_signing_setup(dkg_result)
    _check_signing_dkg_structure(dkg_result)
    _validate_signing_round(
        round_info,
        field_prime,
        group_prime,
        result.participant_ids,
        len(result.commitment.values),
    )

    if signer_id not in round_info.signer_ids:
        raise ValueError("signer must take part in the signing round")
    if signer_id not in result.participant_ids:
        raise ValueError("signer must be a DKG participant")
    if not 0 <= secret_share < field_prime:
        raise ValueError("secret_share must satisfy 0 <= s_i < field_prime")
    if not 0 < nonce < field_prime:
        raise ValueError("nonce must satisfy 1 <= r_i <= field_prime - 1")

    index = round_info.signer_ids.index(signer_id)
    R_i = round_info.nonce_commitments[index].commitment
    if pow(generator, nonce, group_prime) != R_i:
        raise ValueError("nonce does not match the published round-one commitment")

    weight = _lagrange_weight(signer_id, round_info.signer_ids, field_prime)
    z = (nonce + round_info.challenge * weight * secret_share) % field_prime
    return SignatureShare(signer_id=signer_id, nonce_commitment=R_i, z=z)


def verify_signature_share(
    share: SignatureShare,
    round_info: SigningRound,
    dkg_result: SigningDKGResult,
) -> bool:
    """Check one signature share: ``g ** z_i == R_i * Y_i ** (c * lambda_i)``.

    Returns ``True`` on a match. A share with a tampered ``z`` or wrong
    nonce commitment, one produced for another message or signing round, or
    a signer absent from the DKG returns ``False`` for well-formed inputs;
    malformed arguments raise TypeError/ValueError. The round's ``R`` and
    challenge are re-derived from its contents so a hand-edited round cannot
    validate.
    """
    if not isinstance(share, SignatureShare):
        raise TypeError("share must be a SignatureShare instance")
    if not isinstance(share.signer_id, int) or isinstance(share.signer_id, bool):
        raise TypeError("share.signer_id must be an integer")
    if not isinstance(share.z, int) or isinstance(share.z, bool):
        raise TypeError("share.z must be an integer")
    if not isinstance(share.nonce_commitment, int) or isinstance(share.nonce_commitment, bool):
        raise TypeError("share.nonce_commitment must be an integer")
    result, public_key, field_prime, group_prime, generator = _check_signing_setup(dkg_result)
    _check_signing_dkg_structure(dkg_result)
    _validate_signing_round(
        round_info,
        field_prime,
        group_prime,
        result.participant_ids,
        len(result.commitment.values),
    )

    if not 0 < share.signer_id < field_prime:
        raise ValueError("signer id must satisfy 1 <= id <= field_prime - 1")
    if not 0 <= share.z < field_prime:
        raise ValueError("signature share z must satisfy 0 <= z < field_prime")
    if not 1 < share.nonce_commitment < group_prime:
        raise ValueError("nonce commitment must satisfy 1 < R_i < group_prime")

    if share.signer_id not in round_info.signer_ids:
        return False
    if share.signer_id not in result.participant_ids:
        return False
    index = round_info.signer_ids.index(share.signer_id)
    if share.nonce_commitment != round_info.nonce_commitments[index].commitment:
        return False

    R = 1
    for commitment in round_info.nonce_commitments:
        R = R * commitment.commitment % group_prime
    if R != round_info.R:
        return False
    challenge = schnorr_challenge(
        round_info.message,
        public_key,
        R,
        round_info.signer_ids,
        field_prime=field_prime,
        group_prime=group_prime,
    )
    if challenge != round_info.challenge:
        return False

    weight = _lagrange_weight(share.signer_id, round_info.signer_ids, field_prime)
    share_index = result.participant_ids.index(share.signer_id)
    Y_i = dkg_result.verification_shares[share_index]
    expected = (
        share.nonce_commitment
        * pow(Y_i, challenge * weight % field_prime, group_prime)
        % group_prime
    )
    return pow(generator, share.z, group_prime) == expected


def aggregate_signature(
    shares: Iterable[SignatureShare],
    round_info: SigningRound,
    dkg_result: SigningDKGResult,
) -> AggregateSignature | list[SignatureShareRejection]:
    """Verify and sum the round-two shares of a signing round.

    Every signer of ``round_info`` must contribute exactly once, in any
    order; duplicate or missing signers raise ValueError and wrong types
    raise TypeError. Each share is checked with
    :func:`verify_signature_share` and every failure is returned in a
    signer-id-sorted :class:`SignatureShareRejection` list, never silently
    dropped, independently of the input order. On success the ``z_i`` are
    summed modulo ``field_prime`` and returned with the round's ``R`` and
    signer set as the :class:`AggregateSignature`.
    """
    result, _public_key, field_prime, group_prime, _generator = _check_signing_setup(dkg_result)
    _check_signing_dkg_structure(dkg_result)
    _validate_signing_round(
        round_info,
        field_prime,
        group_prime,
        result.participant_ids,
        len(result.commitment.values),
    )

    materialised = list(shares)
    if not materialised:
        raise ValueError("at least one signature share is required")
    for share in materialised:
        if not isinstance(share, SignatureShare):
            raise TypeError("shares must be SignatureShare instances")
        if not isinstance(share.signer_id, int) or isinstance(share.signer_id, bool):
            raise TypeError("share signer_id must be an integer")
        if not isinstance(share.z, int) or isinstance(share.z, bool):
            raise TypeError("share z must be an integer")
        if not isinstance(share.nonce_commitment, int) or isinstance(share.nonce_commitment, bool):
            raise TypeError("share nonce_commitment must be an integer")

    share_ids = [share.signer_id for share in materialised]
    if len(set(share_ids)) != len(share_ids):
        raise ValueError("duplicate signature share from the same signer")
    if set(share_ids) != set(round_info.signer_ids):
        raise ValueError("each round signer must contribute exactly once")

    ordered = sorted(materialised, key=lambda share: share.signer_id)
    rejections: list[SignatureShareRejection] = []
    z_total = 0
    for share in ordered:
        if not verify_signature_share(share, round_info, dkg_result):
            rejections.append(SignatureShareRejection(signer_id=share.signer_id))
            continue
        z_total = (z_total + share.z) % field_prime
    if rejections:
        return rejections

    return AggregateSignature(R=round_info.R, z=z_total, signer_ids=round_info.signer_ids)


def verify_signature(
    message: bytes,
    signature: AggregateSignature,
    public_key: int,
    *,
    group_prime: int,
    generator: int,
    prime: int = DEFAULT_PRIME,
) -> bool:
    """Verify a threshold Schnorr signature: ``g ** z == R * Y ** c``.

    Recomputes the challenge from the tag, ``SHA256(message)``, ``Y``, the
    signature's ``R`` and the L-byte big-endian encodings of
    ``signature.signer_ids``, exactly as in :func:`schnorr_challenge` with
    ``L = ceil(group_prime.bit_length() / 8)``. Returns ``True`` on a match;
    a well-formed signature that was tampered with, or belongs to another
    message, signer set or key, returns ``False``. Malformed arguments
    raise TypeError/ValueError.
    """
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")
    if not isinstance(signature, AggregateSignature):
        raise TypeError("signature must be an AggregateSignature instance")
    if not isinstance(public_key, int) or isinstance(public_key, bool):
        raise TypeError("public_key must be an integer")
    if not isinstance(signature.R, int) or isinstance(signature.R, bool):
        raise TypeError("signature.R must be an integer")
    if not isinstance(signature.z, int) or isinstance(signature.z, bool):
        raise TypeError("signature.z must be an integer")
    if not isinstance(signature.signer_ids, tuple):
        raise TypeError("signature.signer_ids must be a tuple")
    for signer_id in signature.signer_ids:
        if not isinstance(signer_id, int) or isinstance(signer_id, bool):
            raise TypeError("signer ids must be integers")
        if not 0 < signer_id < prime:
            raise ValueError("signer ids must satisfy 1 <= id <= prime - 1")
    if not signature.signer_ids:
        raise ValueError("at least one signer is required")
    if any(
        signature.signer_ids[index] >= signature.signer_ids[index + 1]
        for index in range(len(signature.signer_ids) - 1)
    ):
        raise ValueError("signer ids must be strictly increasing and unique")

    _validate_feldman_parameters(prime, group_prime, generator)
    if not 0 < signature.R < group_prime:
        raise ValueError("signature R must satisfy 0 < R < group_prime")
    if not 0 <= signature.z < prime:
        raise ValueError("signature z must satisfy 0 <= z < prime")
    if not 0 < public_key < group_prime:
        raise ValueError("public_key must satisfy 0 < Y < group_prime")
    if pow(signature.R, prime, group_prime) != 1:
        raise ValueError("signature R must lie in the order-prime subgroup")
    if pow(public_key, prime, group_prime) != 1:
        raise ValueError("public_key must lie in the order-prime subgroup")

    challenge = schnorr_challenge(
        message,
        public_key,
        signature.R,
        signature.signer_ids,
        field_prime=prime,
        group_prime=group_prime,
    )
    return pow(generator, signature.z, group_prime) == (
        signature.R * pow(public_key, challenge, group_prime) % group_prime
    )


# ---------------------------------------------------------------------------
# Signing audit receipts: a self-contained, byte-level record of one signing
# round's round-two verification. The payload binds the message digest, the
# public key, the round's R and challenge, and one row (id, R_i, z_i) per
# signer, plus a status byte and — only when every share passed — the
# aggregated z. It never contains a nonce, a secret share or a coefficient.
# ---------------------------------------------------------------------------

AUDIT_TAG = b"thresholdsign/audit/v1"


@dataclass(frozen=True)
class SigningAudit:
    """An opaque audit receipt for one signing round's share verification.

    ``payload`` is the canonical byte encoding produced by
    :func:`create_audit`: the tag ``b"thresholdsign/audit/v1"``, the 32-byte
    SHA-256 digest of the message, the public key ``Y``, the round's ``R``
    and challenge ``c``, the row count ``n``, one row per signer, a status
    byte, a present byte and — only when the status is 1 — the aggregated
    ``z``. It contains no nonce, secret share or polynomial coefficient.
    """

    payload: bytes


def create_audit(
    message: bytes,
    shares: Iterable[SignatureShare],
    round_info: SigningRound,
    dkg_result: SigningDKGResult,
) -> SigningAudit:
    """Verify the round-two shares of a signing round and record the outcome.

    ``message`` must be the round's message, otherwise ValueError is raised.
    Every signer of ``round_info`` must contribute exactly one share, in any
    order; duplicate or missing signers raise ValueError and wrong types raise
    TypeError, exactly as in :func:`aggregate_signature`. The shares are
    re-verified with :func:`verify_signature_share` in ascending
    ``signer_id`` order. The returned :class:`SigningAudit` payload encodes,
    in order: the tag ``b"thresholdsign/audit/v1"``, the 32-byte
    ``SHA256(message)`` digest, ``Y``, ``R`` and ``c`` (each an unsigned
    big-endian integer in the Schnorr width
    ``L = ceil(group_prime.bit_length() / 8)`` bytes), the row count ``n`` as
    a 4-byte unsigned big-endian integer, one row per signer sorted by
    ascending ``signer_id`` (each row the L-byte encodings of ``id``,
    ``R_i`` and ``z_i``), a one-byte status and a one-byte present flag. The
    rows record the submitted ``nonce_commitment`` and ``z`` verbatim, even
    for shares whose commitment mismatches the round or whose share equation
    fails — such shares still yield a status-0 receipt and their row values
    are never rewritten. The status is 1 when every share verifies — then
    present is 1 and the aggregated ``z = sum(z_i) mod field_prime`` is
    appended in L bytes — and 0 otherwise, in which case present is 0 and
    no ``z`` is appended.
    """
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")
    result, public_key, field_prime, group_prime, _generator = _check_signing_setup(dkg_result)
    _check_signing_dkg_structure(dkg_result)
    _validate_signing_round(
        round_info,
        field_prime,
        group_prime,
        result.participant_ids,
        len(result.commitment.values),
    )
    if message != round_info.message:
        raise ValueError("message must match the signing round message")

    materialised = list(shares)
    if not materialised:
        raise ValueError("at least one signature share is required")
    for share in materialised:
        if not isinstance(share, SignatureShare):
            raise TypeError("shares must be SignatureShare instances")
        if not isinstance(share.signer_id, int) or isinstance(share.signer_id, bool):
            raise TypeError("share signer_id must be an integer")
        if not isinstance(share.z, int) or isinstance(share.z, bool):
            raise TypeError("share z must be an integer")
        if not isinstance(share.nonce_commitment, int) or isinstance(share.nonce_commitment, bool):
            raise TypeError("share nonce_commitment must be an integer")

    share_ids = [share.signer_id for share in materialised]
    if len(set(share_ids)) != len(share_ids):
        raise ValueError("duplicate signature share from the same signer")
    if set(share_ids) != set(round_info.signer_ids):
        raise ValueError("each round signer must contribute exactly once")

    ordered = sorted(materialised, key=lambda share: share.signer_id)
    verified = [
        verify_signature_share(share, round_info, dkg_result) for share in ordered
    ]
    status = 1 if all(verified) else 0

    length = (group_prime.bit_length() + 7) // 8
    buffer = bytearray(AUDIT_TAG)
    buffer += hashlib.sha256(message).digest()
    buffer += _encode_integer(public_key, length)
    buffer += _encode_integer(round_info.R, length)
    buffer += _encode_integer(round_info.challenge, length)
    buffer += len(ordered).to_bytes(4, "big", signed=False)
    for share in ordered:
        buffer += _encode_integer(share.signer_id, length)
        buffer += _encode_integer(share.nonce_commitment, length)
        buffer += _encode_integer(share.z, length)
    if status == 1:
        z_total = 0
        for share in ordered:
            z_total = (z_total + share.z) % field_prime
        buffer += b"\x01\x01"
        buffer += _encode_integer(z_total, length)
    else:
        buffer += b"\x00\x00"
    return SigningAudit(payload=bytes(buffer))


def _decode_audit_payload(
    payload: bytes, field_prime: int, group_prime: int
) -> tuple[bytes, int, int, int, list[tuple[int, int, int]], int, int | None]:
    """Parse an audit payload, raising ValueError on any structural defect.

    Returns ``(digest, Y, R, c, rows, status, z)`` where ``rows`` is a list
    of ``(signer_id, R_i, z_i)`` triples and ``z`` is the appended aggregate
    (``None`` when the present flag is 0). Every encoded integer must lie in
    its legal domain and the rows must be strictly increasing by signer id;
    the status byte must be 0 or 1 and must agree with the present flag and
    the presence of the trailing aggregate ``z``.
    """
    length = (group_prime.bit_length() + 7) // 8
    if not payload.startswith(AUDIT_TAG):
        raise ValueError("audit payload must start with the audit tag")
    offset = len(AUDIT_TAG)
    header = 32 + 3 * length + 4 + 2
    if len(payload) < offset + header:
        raise ValueError("audit payload is truncated")

    digest = payload[offset:offset + 32]
    offset += 32
    public_key = int.from_bytes(payload[offset:offset + length], "big")
    offset += length
    R = int.from_bytes(payload[offset:offset + length], "big")
    offset += length
    challenge = int.from_bytes(payload[offset:offset + length], "big")
    offset += length
    row_count = int.from_bytes(payload[offset:offset + 4], "big")
    offset += 4

    rows_length = row_count * 3 * length
    if len(payload) < offset + rows_length + 2:
        raise ValueError("audit payload is truncated")
    rows = []
    for _ in range(row_count):
        signer_id = int.from_bytes(payload[offset:offset + length], "big")
        offset += length
        nonce_commitment = int.from_bytes(payload[offset:offset + length], "big")
        offset += length
        z_i = int.from_bytes(payload[offset:offset + length], "big")
        offset += length
        rows.append((signer_id, nonce_commitment, z_i))

    status = payload[offset]
    present = payload[offset + 1]
    offset += 2
    if status not in (0, 1):
        raise ValueError("audit status must be 0 or 1")
    if present not in (0, 1):
        raise ValueError("audit present flag must be 0 or 1")
    if status == 1 and present != 1:
        raise ValueError("a passed audit must mark the aggregate z as present")
    if status == 0 and present != 0:
        raise ValueError("a failed audit must not mark the aggregate z as present")
    z = None
    if present == 1:
        if len(payload) != offset + length:
            raise ValueError("audit payload must end with the aggregate z")
        z = int.from_bytes(payload[offset:offset + length], "big")
    elif len(payload) != offset:
        raise ValueError("audit payload must not carry an aggregate z")

    if not 0 < public_key < group_prime:
        raise ValueError("audit Y must satisfy 0 < Y < group_prime")
    if not 0 < R < group_prime:
        raise ValueError("audit R must satisfy 0 < R < group_prime")
    if not 0 <= challenge < field_prime:
        raise ValueError("audit challenge must satisfy 0 <= c < field_prime")
    previous_id = 0
    for signer_id, nonce_commitment, z_i in rows:
        if not 0 < signer_id < field_prime:
            raise ValueError("audit signer ids must satisfy 1 <= id <= field_prime - 1")
        if signer_id <= previous_id:
            raise ValueError("audit rows must be strictly increasing by signer id")
        previous_id = signer_id
        if not 1 < nonce_commitment < group_prime:
            raise ValueError("audit R_i must satisfy 1 < R_i < group_prime")
        if pow(nonce_commitment, field_prime, group_prime) != 1:
            raise ValueError("audit R_i must lie in the order-field_prime subgroup")
        if not 0 <= z_i < field_prime:
            raise ValueError("audit z_i must satisfy 0 <= z_i < field_prime")
    if z is not None and not 0 <= z < field_prime:
        raise ValueError("audit z must satisfy 0 <= z < field_prime")
    return digest, public_key, R, challenge, rows, status, z


def check_audit(
    message: bytes,
    receipt: SigningAudit,
    dkg_result: SigningDKGResult,
) -> bool:
    """Re-verify an audit receipt against the message and the signing key.

    Decodes ``receipt.payload`` (structural or decoding defects raise
    ValueError, wrong types raise TypeError; this includes rows fewer than
    ``threshold``, signer ids that are not DKG participants, rows not
    strictly increasing, or a row ``R_i`` that is not a non-identity element
    of the order-``field_prime`` subgroup) and recomputes everything from
    the message and ``dkg_result``: the message digest, the public key, the
    Fiat-Shamir challenge from the header ``R``, the aggregate ``R`` from
    the row commitments, the per-row share verification
    ``g ** z_i == R_i * Y_i ** (c * lambda_i)`` and, when the status byte is
    1, the aggregated ``z`` and the aggregate signature
    ``g ** z == R * Y ** c``. A row-``R_i`` product that differs from the
    header ``R`` or a failed share equation does not fail the receipt
    outright: it determines the recomputed status, which must equal the
    recorded one — so a faithfully created failure receipt re-verifies as
    ``True``. Returns ``True`` only if every recomputed value is consistent
    with the payload; a well-formed payload that was tampered with, or
    belongs to another message or key, returns ``False``.
    """
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")
    if not isinstance(receipt, SigningAudit):
        raise TypeError("receipt must be a SigningAudit instance")
    if not isinstance(receipt.payload, bytes):
        raise TypeError("receipt payload must be bytes")
    result, public_key, field_prime, group_prime, generator = _check_signing_setup(dkg_result)
    _check_signing_dkg_structure(dkg_result)
    threshold = len(result.commitment.values)

    digest, Y, R, challenge, rows, status, z = _decode_audit_payload(
        receipt.payload, field_prime, group_prime
    )

    signer_ids = tuple(row[0] for row in rows)
    if len(signer_ids) < threshold:
        raise ValueError("audit rows must cover at least threshold signers")
    if any(signer_id not in result.participant_ids for signer_id in signer_ids):
        raise ValueError("audit signer ids must be DKG participants")

    if digest != hashlib.sha256(message).digest():
        return False
    if Y != public_key:
        return False

    recomputed_R = 1
    for _signer_id, nonce_commitment, _z_i in rows:
        recomputed_R = recomputed_R * nonce_commitment % group_prime
    recomputed_challenge = schnorr_challenge(
        message,
        public_key,
        R,
        signer_ids,
        field_prime=field_prime,
        group_prime=group_prime,
    )
    if recomputed_challenge != challenge:
        return False

    all_verified = recomputed_R == R
    z_total = 0
    for signer_id, nonce_commitment, z_i in rows:
        weight = _lagrange_weight(signer_id, signer_ids, field_prime)
        share_index = result.participant_ids.index(signer_id)
        Y_i = dkg_result.verification_shares[share_index]
        expected = (
            nonce_commitment
            * pow(Y_i, challenge * weight % field_prime, group_prime)
            % group_prime
        )
        if pow(generator, z_i, group_prime) != expected:
            all_verified = False
        z_total = (z_total + z_i) % field_prime
    if (1 if all_verified else 0) != status:
        return False

    if status == 1:
        if z != z_total:
            return False
        if pow(generator, z, group_prime) != (
            R * pow(public_key, challenge, group_prime) % group_prime
        ):
            return False
    return True


# ---------------------------------------------------------------------------
# Key-rotation authorization: a publicly verifiable certificate that the old
# threshold key approves switching to a new key. The new key comes from a
# fresh signing DKG; the old key's quorum signs a canonical payload binding
# the group parameters, both public keys, the new member ids and the new
# threshold. The certificate carries no secret share, nonce or coefficient;
# the share handover itself remains the caller's responsibility.
# ---------------------------------------------------------------------------

ROTATION_TAG = b"thresholdsign/rotation/v1"


@dataclass(frozen=True)
class Rotation:
    """A publicly verifiable authorization to rotate a threshold signing key.

    ``old`` and ``new`` are the joint public keys of the old and the new
    signing DKG, ``ids`` the strictly increasing, duplicate-free tuple of the
    new member ids, ``t`` the new threshold and ``q`` / ``p`` / ``g`` the
    shared field prime, group prime and generator. ``sig`` is the old key's
    threshold signature on :func:`rotation_payload` of those values. The
    certificate contains no old or new secret share, no nonce and no
    polynomial coefficient, so anyone holding the old public key can check it
    with :func:`verify_rotation`.
    """

    old: int
    new: int
    ids: tuple[int, ...]
    t: int
    q: int
    p: int
    g: int
    sig: AggregateSignature


def rotation_payload(
    old: int,
    new: int,
    ids: tuple[int, ...],
    t: int,
    q: int,
    p: int,
    g: int,
) -> bytes:
    """Encode the canonical message the old key signs to authorize a rotation.

    ``old`` / ``new`` are the old and new joint public keys, ``ids`` the
    strictly increasing new member ids, ``t`` the new threshold and
    ``q`` / ``p`` / ``g`` the field prime, group prime and generator both
    keys live in. Wrong types raise TypeError; an illegal group setup, an
    illegal public key, illegal member ids or an illegal threshold raise
    ValueError.

    The payload is, in order: the tag ``b"thresholdsign/rotation/v1"``, then
    ``q``, ``p``, ``g``, ``old``, ``new``, the member count as a 4-byte
    unsigned big-endian integer, ``t``, and the ascending member ids. Every
    integer except the count is an unsigned big-endian encoding in exactly
    ``L = ceil(p.bit_length() / 8)`` bytes; there are no separators or length
    prefixes, and the ids are delimited solely by the member count. The
    signature itself is not part of the payload. The result is meant to be
    used as ``SigningRound.message`` of the old key's signing protocol.
    """
    for name, value in (
        ("old", old),
        ("new", new),
        ("t", t),
        ("q", q),
        ("p", p),
        ("g", g),
    ):
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError(f"{name} must be an integer")
    if not isinstance(ids, tuple):
        raise TypeError("ids must be a tuple")
    for member_id in ids:
        if not isinstance(member_id, int) or isinstance(member_id, bool):
            raise TypeError("member ids must be integers")

    _validate_feldman_parameters(q, p, g)
    for name, public_key in (("old", old), ("new", new)):
        if not 0 < public_key < p:
            raise ValueError(f"{name} public key must satisfy 0 < {name} < p")
        if pow(public_key, q, p) != 1:
            raise ValueError(f"{name} public key must lie in the order-q subgroup")
    if not ids:
        raise ValueError("at least one member id is required")
    for member_id in ids:
        if not 0 < member_id < q:
            raise ValueError("member ids must satisfy 1 <= id <= q - 1")
    if any(ids[index] >= ids[index + 1] for index in range(len(ids) - 1)):
        raise ValueError("member ids must be strictly increasing and unique")
    if not 1 <= t <= len(ids):
        raise ValueError("threshold must satisfy 1 <= t <= member count")

    length = (p.bit_length() + 7) // 8
    buffer = bytearray(ROTATION_TAG)
    for value in (q, p, g, old, new):
        buffer += _encode_integer(value, length)
    buffer += len(ids).to_bytes(4, "big", signed=False)
    buffer += _encode_integer(t, length)
    for member_id in ids:
        buffer += _encode_integer(member_id, length)
    return bytes(buffer)


def verify_rotation(cert: Rotation) -> bool:
    """Verify a rotation certificate against the old public key it names.

    Rebuilds the canonical payload from ``cert``'s ``old``, ``new``, ``ids``,
    ``t``, ``q``, ``p`` and ``g`` and checks ``cert.sig`` as a threshold
    Schnorr signature of the old key on that payload (via
    :func:`verify_signature`). Returns ``True`` when the signature matches; a
    well-formed certificate whose signature was tampered with, or belongs to
    another payload or key, returns ``False``. Wrong types raise TypeError
    and an illegally structured certificate (illegal group, public key,
    member ids, threshold or signature encoding) raises ValueError.
    """
    if not isinstance(cert, Rotation):
        raise TypeError("cert must be a Rotation instance")
    payload = rotation_payload(cert.old, cert.new, cert.ids, cert.t, cert.q, cert.p, cert.g)
    return verify_signature(
        payload,
        cert.sig,
        cert.old,
        group_prime=cert.p,
        generator=cert.g,
        prime=cert.q,
    )


# ---------------------------------------------------------------------------
# Canonical certificate transport: a self-delimiting, byte-for-byte
# reproducible encoding of a Rotation for cross-implementation exchange and
# persistence. Unlike rotation_payload (fixed-width fields inside one group),
# every integer carries its own minimal length prefix, so the stream needs no
# out-of-band parameters to parse. Encoding never checks the signature and
# keeps no state; authorization stays verify_rotation's sole job.
# ---------------------------------------------------------------------------

ROTATION_CERT_TAG = b"thresholdsign/rotation-cert/v1"


def _encode_varint(value: int) -> bytes:
    """4-byte unsigned big-endian length followed by the minimal unsigned BE value.

    Zero encodes as the single body byte ``00``; positive values carry no
    leading zero. Negative values are rejected by the caller (ValueError).
    """
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError("value must be an integer")
    if value < 0:
        raise ValueError("integer values must be unsigned")
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big", signed=False)
    if len(body) > 0xFFFFFFFF:
        raise ValueError("integer encoding too long")
    return len(body).to_bytes(4, "big", signed=False) + body


def _read_varint(
    stream: bytes, offset: int, *, what: str = "rotation certificate"
) -> tuple[int, int]:
    """Read one length-prefixed integer at ``offset``, returning ``(value, next)``.

    Raises ValueError on truncation, an over-long or leading-zero body.
    ``what`` names the surrounding structure for the error message.
    """
    if offset + 4 > len(stream):
        raise ValueError(f"truncated {what}")
    length = int.from_bytes(stream[offset:offset + 4], "big")
    offset += 4
    if length == 0 or offset + length > len(stream):
        raise ValueError(f"truncated {what}")
    body = stream[offset:offset + length]
    # The single byte 00 is the canonical zero; any longer body starting
    # with 00 (including 00 00) carries a forbidden leading zero.
    if length > 1 and body[0] == 0:
        raise ValueError("non-canonical integer encoding")
    return int.from_bytes(body, "big", signed=False), offset + length


def _read_id_list(
    stream: bytes, offset: int, *, name: str, what: str = "rotation certificate"
) -> tuple[tuple[int, ...], int]:
    """Read a 4-byte-counted, strictly increasing list of positive integers."""
    if offset + 4 > len(stream):
        raise ValueError(f"truncated {what}")
    count = int.from_bytes(stream[offset:offset + 4], "big")
    offset += 4
    if count == 0:
        raise ValueError(f"{name} must be non-empty")
    ids = []
    for _ in range(count):
        member_id, offset = _read_varint(stream, offset, what=what)
        if member_id == 0:
            raise ValueError(f"{name} must be positive")
        if ids and member_id <= ids[-1]:
            raise ValueError(f"{name} must be strictly increasing and unique")
        ids.append(member_id)
    return tuple(ids), offset


def _check_rotation_fields(
    old: int,
    new: int,
    ids: tuple[int, ...],
    t: int,
    q: int,
    p: int,
    g: int,
    sig: AggregateSignature,
) -> None:
    """Type- and structure-check every Rotation field, mirroring verify_rotation.

    The signature is checked for structural legality only; whether it actually
    authorizes the rotation is left to verify_rotation.
    """
    for name, value in (
        ("old", old),
        ("new", new),
        ("t", t),
        ("q", q),
        ("p", p),
        ("g", g),
    ):
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError(f"{name} must be an integer")
    if not isinstance(ids, tuple):
        raise TypeError("ids must be a tuple")
    for member_id in ids:
        if not isinstance(member_id, int) or isinstance(member_id, bool):
            raise TypeError("member ids must be integers")
    if not isinstance(sig, AggregateSignature):
        raise TypeError("sig must be an AggregateSignature instance")
    if not isinstance(sig.R, int) or isinstance(sig.R, bool):
        raise TypeError("sig.R must be an integer")
    if not isinstance(sig.z, int) or isinstance(sig.z, bool):
        raise TypeError("sig.z must be an integer")
    if not isinstance(sig.signer_ids, tuple):
        raise TypeError("sig.signer_ids must be a tuple")
    for signer_id in sig.signer_ids:
        if not isinstance(signer_id, int) or isinstance(signer_id, bool):
            raise TypeError("signer ids must be integers")

    _validate_feldman_parameters(q, p, g)
    for name, public_key in (("old", old), ("new", new)):
        if not 0 < public_key < p:
            raise ValueError(f"{name} public key must satisfy 0 < {name} < p")
        if pow(public_key, q, p) != 1:
            raise ValueError(f"{name} public key must lie in the order-q subgroup")
    if not ids:
        raise ValueError("at least one member id is required")
    for member_id in ids:
        if not 0 < member_id < q:
            raise ValueError("member ids must satisfy 1 <= id <= q - 1")
    if any(ids[index] >= ids[index + 1] for index in range(len(ids) - 1)):
        raise ValueError("member ids must be strictly increasing and unique")
    if not 1 <= t <= len(ids):
        raise ValueError("threshold must satisfy 1 <= t <= member count")

    if sig.signer_ids:
        for signer_id in sig.signer_ids:
            if not 0 < signer_id < q:
                raise ValueError("signer ids must satisfy 1 <= id <= q - 1")
        if any(
            sig.signer_ids[index] >= sig.signer_ids[index + 1]
            for index in range(len(sig.signer_ids) - 1)
        ):
            raise ValueError("signer ids must be strictly increasing and unique")
    if not 0 < sig.R < p:
        raise ValueError("signature R must satisfy 0 < R < p")
    if pow(sig.R, q, p) != 1:
        raise ValueError("signature R must lie in the order-q subgroup")
    if not 0 <= sig.z < q:
        raise ValueError("signature z must satisfy 0 <= z < q")
    if not sig.signer_ids:
        raise ValueError("at least one signer is required")


def encode_rotation(cert: Rotation) -> bytes:
    """Canonically encode a rotation certificate for transport or persistence.

    The encoding starts with the tag ``b"thresholdsign/rotation-cert/v1"`` and
    then writes, in order, ``old``, ``new``, ``ids``, ``t``, ``q``, ``p``,
    ``g`` and finally the signature's ``R``, ``z`` and ``signer_ids``, with
    no extra separators. Every integer is a 4-byte unsigned big-endian length
    followed by its shortest unsigned big-endian value: zero is the single
    body byte ``00`` and positive values carry no leading zero. Both ``ids``
    and ``signer_ids`` are preceded by their own 4-byte element count; every
    listed id is then encoded as an integer.

    Only a structurally valid :class:`Rotation` is accepted — wrong field
    types raise TypeError and an illegal group setup, public key, member set,
    threshold or signature structure raises ValueError, exactly as
    :func:`verify_rotation` would — but the signature is not required to
    match: a structurally legal certificate with a bad signature still
    encodes, and :func:`verify_rotation` remains the way to test
    authorization afterwards. The output for a given certificate is unique,
    and the encoding carries no network, storage or hidden state.
    """
    if not isinstance(cert, Rotation):
        raise TypeError("cert must be a Rotation instance")
    _check_rotation_fields(
        cert.old, cert.new, cert.ids, cert.t, cert.q, cert.p, cert.g, cert.sig
    )

    buffer = bytearray(ROTATION_CERT_TAG)
    buffer += _encode_varint(cert.old)
    buffer += _encode_varint(cert.new)
    buffer += len(cert.ids).to_bytes(4, "big", signed=False)
    for member_id in cert.ids:
        buffer += _encode_varint(member_id)
    for value in (cert.t, cert.q, cert.p, cert.g):
        buffer += _encode_varint(value)
    buffer += _encode_varint(cert.sig.R)
    buffer += _encode_varint(cert.sig.z)
    buffer += len(cert.sig.signer_ids).to_bytes(4, "big", signed=False)
    for signer_id in cert.sig.signer_ids:
        buffer += _encode_varint(signer_id)
    return bytes(buffer)


def decode_rotation(payload: bytes) -> Rotation:
    """Decode the canonical encoding produced by :func:`encode_rotation`.

    Accepts only the single canonical form: the tag
    ``b"thresholdsign/rotation-cert/v1"`` followed by length-prefixed
    ``old``, ``new``, ``ids``, ``t``, ``q``, ``p``, ``g`` and the
    signature's ``R``, ``z``, ``signer_ids``. A non-bytes argument raises
    TypeError; a wrong or missing tag, truncation, trailing bytes, a
    non-canonical integer (leading zero or over-long length), a count that
    does not match the stream, empty, non-positive, non-increasing or
    duplicate ids, or any illegal group, public key or signature structure
    raises ValueError. A successfully decoded certificate re-encodes to
    exactly the input bytes.

    Decoding never verifies the signature: a structurally legal certificate
    whose signature does not authorize the rotation is returned normally and
    :func:`verify_rotation` reports it as ``False``.
    """
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    if not payload.startswith(ROTATION_CERT_TAG):
        raise ValueError("bad rotation certificate tag")
    offset = len(ROTATION_CERT_TAG)

    old, offset = _read_varint(payload, offset)
    new, offset = _read_varint(payload, offset)
    ids, offset = _read_id_list(payload, offset, name="member ids")
    t, offset = _read_varint(payload, offset)
    q, offset = _read_varint(payload, offset)
    p, offset = _read_varint(payload, offset)
    g, offset = _read_varint(payload, offset)
    R, offset = _read_varint(payload, offset)
    z, offset = _read_varint(payload, offset)
    signer_ids, offset = _read_id_list(payload, offset, name="signer ids")
    if offset != len(payload):
        raise ValueError("trailing bytes after rotation certificate")

    cert = Rotation(
        old=old,
        new=new,
        ids=ids,
        t=t,
        q=q,
        p=p,
        g=g,
        sig=AggregateSignature(R=R, z=z, signer_ids=signer_ids),
    )
    _check_rotation_fields(old, new, ids, t, q, p, g, cert.sig)
    if encode_rotation(cert) != payload:
        raise ValueError("non-canonical rotation certificate")
    return cert


# ---------------------------------------------------------------------------
# Persistent rotation chains: a sequence of Rotation certificates that lets an
# observer starting from a trusted old public key verify repeated key
# rotations hop by hop. The anchor names the out-of-band trusted key and each
# certificate links to the next via new == next.old. A chain is a plain value
# — it carries no network, storage or hidden state, and each certificate's
# authorization remains verify_rotation's sole job.
# ---------------------------------------------------------------------------

ROTATION_CHAIN_TAG = b"thresholdsign/rotation-chain/v1"


@dataclass(frozen=True)
class RotationChain:
    """A non-empty, order-preserving chain of :class:`Rotation` certificates.

    ``anchor`` is the trusted public key the chain starts from and
    ``certificates`` the non-empty tuple of rotation certificates in chain
    order: the first certificate's ``old`` must equal ``anchor`` and every
    adjacent pair must satisfy ``certificates[i].new == certificates[i + 1].old``
    (enforced by :func:`verify_rotation_chain`, not by construction). Like
    :class:`Rotation`, the dataclass is frozen, positionally constructible and
    compared by value.
    """

    anchor: int
    certificates: tuple[Rotation, ...]


def verify_rotation_chain(chain: RotationChain) -> bool:
    """Verify every hop of a rotation chain starting from the trusted anchor.

    ``chain.anchor`` must equal the first certificate's ``old`` and each
    adjacent pair must satisfy ``cert.new == next_cert.old``; every
    certificate is then checked with :func:`verify_rotation`. The result is
    the logical AND of the linkage checks and all per-certificate
    verifications. A wrong argument type raises TypeError; an empty chain, a
    non-tuple certificate sequence, a non-:class:`Rotation` element, a
    non-integer anchor or a boolean anchor raise ValueError, exactly as the
    structural checks of :func:`encode_rotation_chain` do.
    """
    if not isinstance(chain, RotationChain):
        raise TypeError("chain must be a RotationChain instance")
    _check_rotation_chain_fields(chain.anchor, chain.certificates)

    result = chain.anchor == chain.certificates[0].old
    previous_new = chain.certificates[0].new
    for cert in chain.certificates[1:]:
        result = (previous_new == cert.old) and result
        previous_new = cert.new
    for cert in chain.certificates:
        result = verify_rotation(cert) and result
    return result


def _check_rotation_chain_fields(
    anchor: int, certificates: tuple[Rotation, ...]
) -> None:
    """Type- and structure-check the chain container, without verifying certs."""
    if not isinstance(anchor, int) or isinstance(anchor, bool):
        raise TypeError("anchor must be an integer")
    if not isinstance(certificates, tuple):
        raise TypeError("certificates must be a tuple")
    if not certificates:
        raise ValueError("certificates must be non-empty")
    for cert in certificates:
        if not isinstance(cert, Rotation):
            raise TypeError("certificates must contain Rotation instances")


def encode_rotation_chain(chain: RotationChain) -> bytes:
    """Canonically encode a rotation chain for transport or persistence.

    The encoding starts with the tag
    ``b"thresholdsign/rotation-chain/v1"`` followed by the certificate count
    as a 4-byte unsigned big-endian integer, the anchor frame and then one
    frame per certificate in chain order. Both frame kinds are a 4-byte
    unsigned big-endian length followed by the frame content: the anchor
    content is the anchor's shortest unsigned big-endian integer (zero is the
    single byte ``00``) and the certificate content is
    :func:`encode_rotation` of the certificate.

    Only the chain container and the certificate structures are checked —
    the anchor is merely required to be a non-negative integer and the
    signatures need not match; :func:`verify_rotation_chain` remains the way
    to test the linkage and authorizations. Wrong types raise TypeError and
    an empty chain, a non-tuple or non-:class:`Rotation` sequence, a negative
    or over-long anchor, or an illegal certificate raises ValueError. The
    output for a given chain is unique and carries no network, storage or
    hidden state.
    """
    if not isinstance(chain, RotationChain):
        raise TypeError("chain must be a RotationChain instance")
    _check_rotation_chain_fields(chain.anchor, chain.certificates)
    if chain.anchor < 0:
        raise ValueError("anchor must be non-negative")

    anchor_body = chain.anchor.to_bytes(
        (chain.anchor.bit_length() + 7) // 8 or 1, "big", signed=False
    )
    if len(anchor_body) > 0xFFFFFFFF:
        raise ValueError("anchor encoding too long")
    count = len(chain.certificates)
    if count > 0xFFFFFFFF:
        raise ValueError("too many certificates")

    frames = [
        len(anchor_body).to_bytes(4, "big", signed=False) + anchor_body
    ]
    for cert in chain.certificates:
        body = encode_rotation(cert)
        if len(body) > 0xFFFFFFFF:
            raise ValueError("certificate encoding too long")
        frames.append(len(body).to_bytes(4, "big", signed=False) + body)

    buffer = bytearray(ROTATION_CHAIN_TAG)
    buffer += count.to_bytes(4, "big", signed=False)
    for frame in frames:
        buffer += frame
    return bytes(buffer)


def _read_frame(stream: bytes, offset: int, *, what: str) -> tuple[bytes, int]:
    """Read one 4-byte-length-prefixed frame body at ``offset``."""
    if offset + 4 > len(stream):
        raise ValueError(f"truncated rotation chain {what}")
    length = int.from_bytes(stream[offset:offset + 4], "big")
    offset += 4
    if length == 0 or offset + length > len(stream):
        raise ValueError(f"truncated rotation chain {what}")
    return bytes(stream[offset:offset + length]), offset + length


def decode_rotation_chain(payload: bytes) -> RotationChain:
    """Decode the canonical encoding produced by :func:`encode_rotation_chain`.

    Accepts only the single canonical form: the tag
    ``b"thresholdsign/rotation-chain/v1"``, the 4-byte unsigned big-endian
    certificate count, one anchor frame and then exactly that many
    certificate frames, each a 4-byte unsigned big-endian length followed by
    its content — the shortest unsigned big-endian anchor (zero is ``00``)
    and an :func:`encode_rotation` certificate. A non-bytes argument raises
    TypeError; an empty chain, a negative or non-canonical anchor, an illegal
    certificate, a count mismatch, truncation, trailing bytes or a
    non-canonical frame raise ValueError, as does any certificate that
    :func:`decode_rotation` rejects. A successfully decoded chain re-encodes
    to exactly the input bytes.

    Decoding never verifies the certificates or the linkage: a structurally
    legal chain whose signatures do not authorize the rotations, or whose
    anchor and ``old`` keys do not line up, is returned normally and
    :func:`verify_rotation_chain` reports it as ``False``.
    """
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    if not payload.startswith(ROTATION_CHAIN_TAG):
        raise ValueError("bad rotation chain tag")
    offset = len(ROTATION_CHAIN_TAG)

    if offset + 4 > len(payload):
        raise ValueError("truncated rotation chain certificate count")
    count = int.from_bytes(payload[offset:offset + 4], "big")
    offset += 4
    if count == 0:
        raise ValueError("certificates must be non-empty")

    anchor_body, offset = _read_frame(payload, offset, what="anchor")
    if len(anchor_body) > 1 and anchor_body[0] == 0:
        raise ValueError("non-canonical anchor encoding")
    anchor = int.from_bytes(anchor_body, "big", signed=False)

    certificates = []
    for index in range(count):
        body, offset = _read_frame(
            payload, offset, what=f"certificate {index + 1}"
        )
        certificates.append(decode_rotation(body))
    if offset != len(payload):
        raise ValueError("trailing bytes after rotation chain")

    chain = RotationChain(anchor=anchor, certificates=tuple(certificates))
    if encode_rotation_chain(chain) != payload:
        raise ValueError("non-canonical rotation chain")
    return chain


# ---------------------------------------------------------------------------
# Stateless nonce-reuse audit: scan a batch of audit receipts for one signer
# republishing the same round-one commitment R_i under the same key. Every
# receipt is re-verified with check_audit first; only status-1 receipts take
# part. The function keeps no state between calls — each batch stands alone.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NonceReuse:
    """One signer's reused round-one nonce commitment, with the evidence.

    ``signer_id`` names the DKG participant and ``nonce_commitment`` the
    round-one value ``R_i`` that appears in the rows of more than one
    distinct verified receipt; ``receipts`` holds those status-1
    :class:`SigningAudit` receipts, deduplicated and ordered by their
    ``payload`` bytes. Reusing ``R_i`` across messages exposes the signer's
    secret share, so every reported finding is critical.
    """

    signer_id: int
    nonce_commitment: int
    receipts: tuple[SigningAudit, ...]


def find_nonce_reuse(
    records: Iterable[tuple[bytes, SigningAudit]],
    dkg_result: SigningDKGResult,
) -> tuple[NonceReuse, ...]:
    """Report every ``(signer_id, R_i)`` pair reused across distinct receipts.

    ``records`` pairs each audited message with its receipt: every item must
    be a ``(message, receipt)`` tuple with the ``bytes`` message first and
    the :class:`SigningAudit` second. Each record is re-verified with
    :func:`check_audit` against ``dkg_result``: a structurally illegal
    receipt raises ValueError, a well-formed receipt that does not match its
    message or the key also raises ValueError, and wrong argument or record
    element types raise TypeError. Only receipts whose recorded status is 1
    take part in the scan.

    The surviving receipts are decoded and their rows grouped by
    ``(signer_id, R_i)``; a group is reported only when its pair appears in
    at least two *distinct* payloads, so resubmitting the same receipt never
    manufactures an alert. Each :class:`NonceReuse` carries the group's
    receipts deduplicated and ordered by payload bytes, and the findings are
    returned as a tuple sorted by ascending ``signer_id`` then
    ``nonce_commitment`` — the result does not depend on the input order.
    The function is stateless: it examines only the batch it is given and
    keeps no history across calls.
    """
    _result, _public_key, field_prime, group_prime, _generator = (
        _check_signing_setup(dkg_result)
    )
    _check_signing_dkg_structure(dkg_result)

    if isinstance(records, (str, bytes)):
        raise TypeError("records must be an iterable of (message, receipt) tuples")
    materialised = list(records)

    groups: dict[tuple[int, int], dict[bytes, SigningAudit]] = {}
    for record in materialised:
        if not isinstance(record, tuple) or len(record) != 2:
            raise TypeError("records must contain (message, receipt) tuples")
        message, receipt = record
        if not isinstance(message, bytes):
            raise TypeError("record message must be bytes")
        if not isinstance(receipt, SigningAudit):
            raise TypeError("record receipt must be a SigningAudit instance")
        if not check_audit(message, receipt, dkg_result):
            raise ValueError("receipt does not match its message or the key")
        _digest, _Y, _R, _challenge, rows, status, _z = _decode_audit_payload(
            receipt.payload, field_prime, group_prime
        )
        if status != 1:
            continue
        for signer_id, nonce_commitment, _z_i in rows:
            groups.setdefault((signer_id, nonce_commitment), {})[
                receipt.payload
            ] = receipt

    findings = []
    for (signer_id, nonce_commitment), by_payload in groups.items():
        if len(by_payload) < 2:
            continue
        receipts = tuple(by_payload[payload] for payload in sorted(by_payload))
        findings.append(
            NonceReuse(
                signer_id=signer_id,
                nonce_commitment=nonce_commitment,
                receipts=receipts,
            )
        )
    findings.sort(key=lambda finding: (finding.signer_id, finding.nonce_commitment))
    return tuple(findings)


# ---------------------------------------------------------------------------
# Leaked-share recovery: from two verified status-1 receipts in which one
# signer republished the same round-one commitment R_i, solve the two
# Schnorr responses z_i = r_i + c * lambda_i * s_i for the signer's secret
# share s_i. Builds on find_nonce_reuse for the grouping; keeps no state.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NonceLeak:
    """One signer's secret share recovered from a reused round-one nonce.

    ``signer_id`` names the DKG participant, ``commitment`` the reused
    round-one value ``R_i``, ``share`` the recovered secret share ``s_i``
    (verified against the signer's public verification share ``Y_i``) and
    ``receipts`` the two status-1 :class:`SigningAudit` receipts the
    recovery used, ordered by their ``payload`` bytes.
    """

    signer_id: int
    commitment: int
    share: int
    receipts: tuple[SigningAudit, ...]


def recover_leaks(
    records: Iterable[tuple[bytes, SigningAudit]],
    key: SigningDKGResult,
) -> tuple[NonceLeak, ...]:
    """Recover exposed secret shares from receipts with reused nonces.

    ``records`` pairs each audited message with its receipt, exactly as in
    :func:`find_nonce_reuse`, which is called first: every record is
    re-verified with :func:`check_audit` against ``key``, only status-1
    receipts take part, and the ``(signer_id, R_i)`` groups follow its
    deduplication and payload-ordering rules. Wrong argument or record
    element types raise TypeError; a structurally illegal receipt or one
    that does not match its message or the key raises ValueError.

    For each reuse group, every receipt contributes its signer's response
    ``z_i`` and the coefficient ``a = c * lambda_i mod q`` (``c`` the
    receipt's challenge, ``lambda_i`` the signer's Lagrange weight at zero
    over that receipt's signer set). The pair of receipts with the smallest
    payload bytes satisfying ``a1 != a2`` then yields
    ``s = (z1 - z2) / (a1 - a2) mod q``. The recovered share must satisfy
    ``g ** share == Y_i mod p`` against the signer's verification share,
    otherwise ValueError is raised. A group whose receipts all share the
    same ``a`` has no invertible pair and is ignored.

    Each reported :class:`NonceLeak` carries the two receipts the recovery
    used, ordered by payload bytes; the findings are returned as a tuple
    sorted by ascending ``signer_id`` then ``commitment``, so the result
    does not depend on the input order. The function is stateless.
    """
    reuses = find_nonce_reuse(records, key)

    result = key.result
    pedersen = result.commitment
    field_prime = pedersen.field_prime
    group_prime = pedersen.group_prime
    generator = pedersen.generator

    leaks = []
    for reuse in reuses:
        # reuse.receipts is already deduplicated and ordered by payload.
        entries = []
        for receipt in reuse.receipts:
            _digest, _Y, _R, challenge, rows, _status, _z = _decode_audit_payload(
                receipt.payload, field_prime, group_prime
            )
            signer_ids = tuple(row[0] for row in rows)
            z_i = next(row[2] for row in rows if row[0] == reuse.signer_id)
            weight = _lagrange_weight(reuse.signer_id, signer_ids, field_prime)
            entries.append((receipt, challenge * weight % field_prime, z_i))

        # The lexicographically smallest pair by payload with a1 != a2: the
        # first receipt paired with the first later receipt of a different
        # coefficient. No such partner means every coefficient is equal.
        pair = None
        first_receipt, first_a, first_z = entries[0]
        for receipt, a, z in entries[1:]:
            if a != first_a:
                pair = (receipt, a, z)
                break
        if pair is None:
            continue
        second_receipt, second_a, second_z = pair

        share = (
            (first_z - second_z)
            * pow(first_a - second_a, -1, field_prime)
            % field_prime
        )
        share_index = result.participant_ids.index(reuse.signer_id)
        if pow(generator, share, group_prime) != key.verification_shares[share_index]:
            raise ValueError(
                "recovered share does not match the verification share Y_i"
            )
        leaks.append(
            NonceLeak(
                signer_id=reuse.signer_id,
                commitment=reuse.nonce_commitment,
                share=share,
                receipts=(first_receipt, second_receipt),
            )
        )
    leaks.sort(key=lambda leak: (leak.signer_id, leak.commitment))
    return tuple(leaks)


# ---------------------------------------------------------------------------
# Stateless audit chains: a non-empty, order-preserving batch of
# (message, SigningAudit) receipt records sealed by one threshold Schnorr
# signature. The signed chain message commits to the verifying public key
# and, at every record position, to the message digest and the receipt
# digest, so deleting, inserting, reordering or cross-key-substituting a
# receipt all invalidate the signature. The library keeps no state: the
# chain is a plain value and every receipt is re-checked on verification.
# ---------------------------------------------------------------------------

AUDIT_CHAIN_TAG = b"ts/ac/v1"


@dataclass(frozen=True)
class AuditChain:
    """A non-empty, order-preserving batch of audit receipts sealed by one signature.

    ``records`` is the non-empty tuple of ``(message, audit)`` pairs in chain
    order, each ``message`` the exact bytes its :class:`SigningAudit` receipt
    was created for; ``signature`` is the threshold Schnorr
    :class:`AggregateSignature` on :func:`audit_chain_payload` of the records
    and the verifying public key. The dataclass is frozen, positionally
    constructible and compared by value; the records keep their order and the
    chain carries no network, storage or hidden state. Neither the container
    nor the signature is checked at construction time —
    :func:`verify_audit_chain` is the way to test a chain afterwards.
    """

    records: tuple[tuple[bytes, SigningAudit], ...]
    signature: AggregateSignature


def _minimal_be(value: int) -> bytes:
    """Shortest unsigned big-endian encoding of a non-negative integer (0 -> b"\\x00")."""
    return value.to_bytes((value.bit_length() + 7) // 8 or 1, "big", signed=False)


def _check_audit_chain_records(records: object) -> int:
    """Type- and structure-check the records container of an audit chain.

    Records must be a non-empty tuple of ``(bytes, SigningAudit)`` pairs; the
    receipts themselves are not decoded here (that is :func:`check_audit`'s
    job during verification). Returns the record count.
    """
    if not isinstance(records, tuple):
        raise TypeError("records must be a tuple")
    try:
        count = len(records)
    except OverflowError:
        raise ValueError("too many records") from None
    if count == 0:
        raise ValueError("records must be non-empty")
    for record in records:
        if not isinstance(record, tuple) or len(record) != 2:
            raise TypeError("each record must be a (message, audit) tuple")
        message, audit = record
        if not isinstance(message, bytes):
            raise TypeError("record message must be bytes")
        if not isinstance(audit, SigningAudit):
            raise TypeError("record audit must be a SigningAudit instance")
        if not isinstance(audit.payload, bytes):
            raise TypeError("record audit payload must be bytes")
    return count


def audit_chain_payload(
    records: tuple[tuple[bytes, SigningAudit], ...], public_key: int
) -> bytes:
    """Encode the canonical chain message the threshold key signs.

    ``records`` must be a non-empty tuple of ``(message, audit)`` pairs and
    ``public_key`` the positive integer verification key the chain is sealed
    for. Wrong types raise TypeError — a non-tuple record sequence, a record
    that is not a ``(bytes, SigningAudit)`` pair, or a non-integer (including
    boolean) public key; an empty chain, a non-positive public key or a
    record count that does not fit the 8-byte counter raise ValueError.

    The payload is, in order: the tag ``b"ts/ac/v1"``,
    ``SHA256(BE(public_key))`` where ``BE`` is the key's shortest unsigned
    big-endian encoding, the record count as an 8-byte unsigned big-endian
    integer, and then one ``SHA256(message) || SHA256(audit.payload)`` pair
    per record in tuple order. It carries no signature and keeps no state,
    and is meant to be used as the ``SigningRound.message`` of the sealing
    threshold signing protocol.
    """
    if not isinstance(public_key, int) or isinstance(public_key, bool):
        raise TypeError("public_key must be an integer")
    count = _check_audit_chain_records(records)
    if public_key <= 0:
        raise ValueError("public_key must be positive")
    if count > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("too many records")

    buffer = bytearray(AUDIT_CHAIN_TAG)
    buffer += hashlib.sha256(_minimal_be(public_key)).digest()
    buffer += count.to_bytes(8, "big", signed=False)
    for message, audit in records:
        buffer += hashlib.sha256(message).digest()
        buffer += hashlib.sha256(audit.payload).digest()
    return bytes(buffer)


def verify_audit_chain(chain: AuditChain, key: SigningDKGResult) -> bool:
    """Verify an audit chain against its records and the threshold key.

    Every ``(message, audit)`` record of ``chain.records`` is first re-checked
    in chain order with :func:`check_audit` against ``key`` (so both
    successful and faithfully recorded failure receipts re-verify), and the
    canonical :func:`audit_chain_payload` of the records and
    ``key.public_key`` is then checked as ``chain.signature``'s threshold
    Schnorr message via :func:`verify_signature`. Returns ``True`` only when
    every receipt matches its message and the key and the signature seals the
    exact record sequence; deleting or inserting a record, reordering
    records, substituting a receipt from another key (cross-key replacement),
    tampering with a receipt or the signature, or presenting the chain under
    another key all return ``False`` for well-formed inputs.

    A non-:class:`AuditChain` argument, a non-:class:`AggregateSignature`
    signature or any wrong record/key field type raises TypeError; an empty
    chain, a structurally illegal receipt or signature, or a malformed
    ``key`` raises ValueError, exactly as :func:`check_audit` and
    :func:`verify_signature` would.
    """
    if not isinstance(chain, AuditChain):
        raise TypeError("chain must be an AuditChain instance")
    if not isinstance(chain.signature, AggregateSignature):
        raise TypeError("chain signature must be an AggregateSignature instance")
    _check_audit_chain_records(chain.records)
    _result, public_key, field_prime, group_prime, generator = _check_signing_setup(key)
    _check_signing_dkg_structure(key)

    for message, audit in chain.records:
        if not check_audit(message, audit, key):
            return False

    payload = audit_chain_payload(chain.records, public_key)
    return verify_signature(
        payload,
        chain.signature,
        public_key,
        group_prime=group_prime,
        generator=generator,
        prime=field_prime,
    )


# ---------------------------------------------------------------------------
# Canonical transport/persistence encoding for AuditChain. The wire format
# restores structure only: it neither decodes nor checks the receipts and
# never verifies the sealing signature, and it carries no hidden state.
# ---------------------------------------------------------------------------

AUDIT_CHAIN_WIRE_TAG = b"thresholdsign/audit-chain/v1"


def _check_audit_chain_signature(signature: object) -> None:
    """Type- and structure-check the sealing signature without a group or key.

    ``R`` and ``z`` only need to be non-negative integers (their group/field
    ranges are unknown without the verifying key) and ``signer_ids`` a
    non-empty tuple of positive, strictly increasing integers; whether the
    signature actually seals the chain is left to :func:`verify_audit_chain`.
    """
    if not isinstance(signature, AggregateSignature):
        raise TypeError("chain signature must be an AggregateSignature instance")
    for name, value in (("R", signature.R), ("z", signature.z)):
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError(f"signature.{name} must be an integer")
        if value < 0:
            raise ValueError(f"signature.{name} must be non-negative")
    if not isinstance(signature.signer_ids, tuple):
        raise TypeError("signature.signer_ids must be a tuple")
    if not signature.signer_ids:
        raise ValueError("at least one signer is required")
    for signer_id in signature.signer_ids:
        if not isinstance(signer_id, int) or isinstance(signer_id, bool):
            raise TypeError("signer ids must be integers")
        if signer_id <= 0:
            raise ValueError("signer ids must satisfy 1 <= id")
    if any(
        signature.signer_ids[index] >= signature.signer_ids[index + 1]
        for index in range(len(signature.signer_ids) - 1)
    ):
        raise ValueError("signer ids must be strictly increasing and unique")


def _read_audit_chain_bytes(
    stream: bytes, offset: int, *, what: str, allow_empty: bool
) -> tuple[bytes, int]:
    """Read one 4-byte-length-prefixed byte frame at ``offset``.

    Message frames may be empty; receipt frames may not. Raises ValueError on
    truncation or a zero-length frame when ``allow_empty`` is false.
    """
    if offset + 4 > len(stream):
        raise ValueError(f"truncated audit chain {what} length")
    length = int.from_bytes(stream[offset:offset + 4], "big")
    offset += 4
    if not allow_empty and length == 0:
        raise ValueError(f"audit chain {what} must be non-empty")
    if offset + length > len(stream):
        raise ValueError(f"truncated audit chain {what}")
    return bytes(stream[offset:offset + length]), offset + length


def encode_audit_chain(chain: AuditChain) -> bytes:
    """Canonically encode an audit chain for transport or persistence.

    The encoding starts with the tag
    ``b"thresholdsign/audit-chain/v1"`` followed by the record count as a
    4-byte unsigned big-endian integer, then one frame pair per record in
    strict ``records`` order, and finally the signature frame. Each record
    writes the 4-byte unsigned big-endian message length and the raw
    ``message`` bytes (empty messages are allowed), then the 4-byte unsigned
    big-endian receipt length and the raw :attr:`SigningAudit.payload`
    (receipts must be non-empty). The signature frame writes ``R``, ``z`` and
    then the 4-byte unsigned big-endian ``signer_ids`` count followed by the
    ascending ids; every integer is a 4-byte unsigned big-endian length
    followed by its shortest unsigned big-endian value (zero is the single
    byte ``00``, positive values carry no leading zero).

    Only the field types and structure are checked — a non-empty tuple of
    ``(bytes, SigningAudit)`` records and a structurally legal
    :class:`AggregateSignature` — but neither the receipts nor the signature
    need to match anything; :func:`verify_audit_chain` remains the way to test
    the chain afterwards. Wrong types raise TypeError; an empty chain, an
    empty receipt, a negative signature integer, an empty, non-positive or
    non-increasing signer set, an over-long frame or a count that does not
    fit the 4-byte counter raises ValueError. The output for a given chain is
    unique and carries no network, storage or hidden state.
    """
    if not isinstance(chain, AuditChain):
        raise TypeError("chain must be an AuditChain instance")
    count = _check_audit_chain_records(chain.records)
    _check_audit_chain_signature(chain.signature)
    if count > 0xFFFFFFFF:
        raise ValueError("too many records")

    buffer = bytearray(AUDIT_CHAIN_WIRE_TAG)
    buffer += count.to_bytes(4, "big", signed=False)
    for index, (message, audit) in enumerate(chain.records):
        if len(message) > 0xFFFFFFFF:
            raise ValueError(f"record {index + 1} message too long")
        if not audit.payload:
            raise ValueError(f"record {index + 1} receipt payload must be non-empty")
        if len(audit.payload) > 0xFFFFFFFF:
            raise ValueError(f"record {index + 1} receipt payload too long")
        buffer += len(message).to_bytes(4, "big", signed=False)
        buffer += message
        buffer += len(audit.payload).to_bytes(4, "big", signed=False)
        buffer += audit.payload

    buffer += _encode_varint(chain.signature.R)
    buffer += _encode_varint(chain.signature.z)
    buffer += len(chain.signature.signer_ids).to_bytes(4, "big", signed=False)
    for signer_id in chain.signature.signer_ids:
        buffer += _encode_varint(signer_id)
    return bytes(buffer)


def decode_audit_chain(payload: bytes) -> AuditChain:
    """Decode the canonical encoding produced by :func:`encode_audit_chain`.

    Accepts only the single canonical form: the tag
    ``b"thresholdsign/audit-chain/v1"``, the 4-byte unsigned big-endian
    record count (at least one), exactly that many record frame pairs — each
    a 4-byte length-prefixed (possibly empty) message followed by a 4-byte
    length-prefixed non-empty receipt — and then the signature frame:
    length-prefixed ``R`` and ``z``, the 4-byte ``signer_ids`` count and the
    ascending, length-prefixed ids. A non-bytes argument raises TypeError; a
    wrong or missing tag, an empty chain, a zero-length receipt, a count
    mismatch, truncation, trailing bytes or a non-canonical integer (leading
    zero or over-long length) raises ValueError, as do empty, zero or
    non-increasing signer ids. A successfully decoded chain re-encodes to
    exactly the input bytes.

    Decoding restores the structure only: receipts are never decoded or
    checked and the sealing signature is never verified — a chain whose
    receipts do not match its messages or whose signature does not seal the
    records is returned normally and :func:`verify_audit_chain` reports it as
    ``False``.
    """
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    if not payload.startswith(AUDIT_CHAIN_WIRE_TAG):
        raise ValueError("bad audit chain tag")
    offset = len(AUDIT_CHAIN_WIRE_TAG)

    if offset + 4 > len(payload):
        raise ValueError("truncated audit chain record count")
    count = int.from_bytes(payload[offset:offset + 4], "big")
    offset += 4
    if count == 0:
        raise ValueError("records must be non-empty")

    records = []
    for index in range(count):
        message, offset = _read_audit_chain_bytes(
            payload,
            offset,
            what=f"record {index + 1} message",
            allow_empty=True,
        )
        receipt, offset = _read_audit_chain_bytes(
            payload,
            offset,
            what=f"record {index + 1} receipt",
            allow_empty=False,
        )
        records.append((message, SigningAudit(payload=receipt)))

    R, offset = _read_varint(payload, offset, what="audit chain signature R")
    z, offset = _read_varint(payload, offset, what="audit chain signature z")
    signer_ids, offset = _read_id_list(
        payload, offset, name="signer ids", what="audit chain signature"
    )
    if offset != len(payload):
        raise ValueError("trailing bytes after audit chain")

    chain = AuditChain(
        records=tuple(records),
        signature=AggregateSignature(R=R, z=z, signer_ids=signer_ids),
    )
    if encode_audit_chain(chain) != payload:
        raise ValueError("non-canonical audit chain")
    return chain
