"""thresholdsign - Shamir secret sharing over a prime field.

Public API: Share / FeldmanCommitment / PedersenCommitment / split_secret /
split_secret_verifiable / split_secret_pedersen / verify_share /
verify_pedersen_share / reconstruct_secret / evaluate_polynomial, plus
recover_secret / RecoveryReport that reconstruct the secret from a share set
containing tampered shares by identifying the unique degree-below-threshold
polynomial agreeing with the most shares, plus the
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
reused nonces via NonceLeak / recover_leaks, the canonical nonce-reuse
transport encoding encode_nonce_reuse / decode_nonce_reuse, the canonical
leaked-share transport encoding encode_nonce_leak / decode_nonce_leak and
its key-only verifier verify_nonce_leak, the canonical batched
leaked-share transport encoding encode_nonce_leak_report /
decode_nonce_leak_report and its key-only verifier
verify_nonce_leak_report, the threshold-Schnorr-authenticated
whole-report seal ReportSeal / seal_message / encode_seal /
decode_seal / verify_seal, the order-preserving batch of seals
SealHistory / history_message / check_history and its canonical
transport encoding encode_history / decode_history, plus single-seal
Merkle inclusion proofs SealHistoryProof / make_history_proof /
check_history_proof that locate one seal in a sealed history without
the full history, plus the proof-plus-signature bundle
SealHistoryProofBundle / encode_history_proof_bundle /
decode_history_proof_bundle / verify_history_proof_bundle, and the compact multi-seal proofs
SealHistoryMultiProof / make_history_multi_proof /
check_history_multi_proof that locate several seals at once with the
one root signature, plus their canonical transport encoding
encode_history_multi_proof / decode_history_multi_proof and the
proof-plus-signature bundle SealHistoryMultiProofBundle /
encode_history_multi_proof_bundle / decode_history_multi_proof_bundle /
verify_history_multi_proof_bundle, and the append-only consistency proofs
SealHistoryExtension / make_history_extension / check_history_extension
that confirm an old sealed item sequence is a prefix of a new one from
the two root signatures alone without disclosing any seal, plus their
canonical transport encoding encode_history_extension /
decode_history_extension, and the self-contained bundle
SealHistoryExtensionBundle / encode_history_extension_bundle /
decode_history_extension_bundle / verify_history_extension_bundle that
pairs the consistency proof with its old and new root signatures, and the
non-empty, order-preserving chain of such bundles
SealHistoryExtensionBundleChain /
encode_history_extension_bundle_chain /
decode_history_extension_bundle_chain /
verify_history_extension_bundle_chain that archives and verifies a run of
consecutive extensions as one order-preserving object, and the
space-saving incremental form SealHistoryExtensionDeltaChain /
expand_history_delta / compact_history_delta that carries the first hop's
extension in full and then only each later hop's newly appended 32-byte
leaf batches with the shared checkpoint signatures stored once, along
with its canonical transport encoding encode_history_delta /
decode_history_delta and the stateless whole-chain verifier
verify_history_delta, plus half-open interval slicing slice_history_delta
and adjacent-chain splicing concatenate_history_delta for segmented
transport and archive reassembly, and the multi-cut batch form of the
same pair partition_history_delta / join_history_delta_segments for
splitting a long chain into several consecutive hop segments at once and
folding an ordered tuple of segments back into one chain, and the
self-delimiting segment-set transport encoding
encode_history_delta_segments / decode_history_delta_segments for
archiving or transferring several consecutive segments as one ordered
object, and the whole-archive threshold-Schnorr seal of that segment set
HistoryDeltaSegmentsSeal / hds_message with its transport encoding
encode_hds / decode_hds and key-bound verifier verify_hds, and the
non-empty order-preserving chain of such whole-archive seals
HistoryDeltaSegmentsSealChain / hdsc_message with its transport
encoding encode_hdsc / decode_hdsc and key-bound verifier verify_hdsc,
and the compact multi-seal membership proofs over that chain HDSCProof /
make_hdsc_proof / check_hdsc_proof that locate several seals at once
behind one root signature, with their canonical transport encoding
encode_hdsc_proof / decode_hdsc_proof, and the proof-plus-root-signature
bundle HDSCProofBundle / encode_hdsc_proof_bundle /
decode_hdsc_proof_bundle / verify_hdsc_proof_bundle, and the
non-empty order-preserving archive HDSCProofBundleArchive of such
bundles, whose outer signature binds hdsc_proof_bundle_archive_message
over the existing canonical bundle encodings and the verifying public
key, with the key-bound verifier verify_hdsc_proof_bundle_archive that
re-checks every bundle with verify_hdsc_proof_bundle before the outer
verify_signature, and the canonical archive transport encoding
encode_hdsc_proof_bundle_archive / decode_hdsc_proof_bundle_archive for
transferring or persisting a whole archive as one self-delimiting byte
string, and the compact multi-package membership proofs over such an
archive HDSCArchiveProof / make_hdsc_archive_proof /
check_hdsc_archive_proof that locate several archive bundles at once
behind one fresh root signature — with no transport encoding of their
own and no proof-plus-root-signature bundle type — and the
cross-key form RHE / encode_rhe / decode_rhe / check_rhe that ties the
two root signatures to a non-empty RotationChain so the old and new
roots may be signed by different threshold keys, publicly
verifiable key-rotation authorization: Rotation / rotation_payload /
verify_rotation, the persistent, multi-hop authorization chain
RotationChain / verify_rotation_chain / encode_rotation_chain /
decode_rotation_chain, and the stateless, threshold-Schnorr-authenticated
audit chain: AuditChain / audit_chain_payload / verify_audit_chain.
Merkle inclusion proofs over a chain's records: AuditProof / make_proof /
check_proof, the compact multi-record proofs AuditMultiProof /
make_multi_proof / check_multi_proof that certify several ordered records
with the one root signature, plus their canonical transport encodings
encode_audit_proof / decode_audit_proof and encode_audit_multi_proof /
decode_audit_multi_proof, and the proof-plus-signature bundles
AuditProofBundle / encode_audit_proof_bundle /
decode_audit_proof_bundle / verify_audit_proof_bundle and
AuditMultiProofBundle / encode_audit_multi_proof_bundle /
decode_audit_multi_proof_bundle / verify_audit_multi_proof_bundle. Append-only consistency proofs over the same tree:
AuditExtensionProof / make_extension / check_extension, letting an observer
verify — from two threshold signatures alone — that an old record sequence
is a prefix of a new one, without seeing any message or receipt, plus their
canonical transport encoding encode_extension / decode_extension, and the
dual-signature consistency bundle AuditExtensionProofBundle /
encode_audit_extension_proof_bundle / decode_audit_extension_proof_bundle /
verify_audit_extension_proof_bundle, and the non-empty, order-preserving
chain of such bundles AuditExtensionProofBundleChain /
encode_audit_extension_proof_bundle_chain /
decode_audit_extension_proof_bundle_chain /
verify_audit_extension_proof_bundle_chain, and the flattened checkpoint
chain AuditExtensionCheckpointChain /
encode_audit_extension_checkpoint_chain /
decode_audit_extension_checkpoint_chain /
verify_audit_extension_checkpoint_chain, the space-saving incremental
form AuditExtensionDeltaCheckpointChain /
expand_audit_extension_delta_checkpoint_chain /
compact_audit_extension_delta_checkpoint_chain and its canonical
transport encoding encode_audit_extension_delta_checkpoint_chain /
decode_audit_extension_delta_checkpoint_chain /
verify_audit_extension_delta_checkpoint_chain, plus half-open interval
slicing slice_audit_extension_delta_checkpoint_chain and adjacent-chain
splicing concatenate_audit_extension_delta_checkpoint_chains for
segmented transport and archive reassembly, and the multi-cut batch
form of the same pair partition_delta_chain / join_delta_chain_segments
for splitting a long chain into several consecutive hop segments at
once and folding an ordered tuple of segments back into one chain, and
the self-delimiting segment-set transport encoding
encode_delta_chain_segments / decode_delta_chain_segments for archiving
or transferring several consecutive segments as one ordered object, and
the stateless whole-set verifier verify_delta_chain_segments for
confirming every segment's signatures and every seam between neighbours
in one call, and its stateless failure diagnoser DeltaDiagnosis /
diagnose_delta_chain_segments that locates the first failing segment,
hop or seam in input order without guessing at the cryptographic cause,
and the frozen DeltaReport / dr_message that binds a diagnosis, the
canonical segment-set encoding and a verifying public key into one
threshold-Schnorr-signed message, with its transport encoding
encode_dr / decode_dr and key-bound verifier verify_dr, and the
self-contained diagnostic bundle DeltaReportBundle that carries the
diagnosed segment set together with its report, with its transport
encoding encode_delta_report_bundle / decode_delta_report_bundle and
key-bound verifier verify_delta_report_bundle, and the non-empty
order-preserving archive DeltaReportBundleArchive of whole bundles,
with its transport encoding
encode_delta_report_bundle_archive / decode_delta_report_bundle_archive
and key-bound verifier verify_delta_report_bundle_archive, and the
whole-archive threshold-Schnorr seal DeltaReportBundleArchiveSeal /
archive_seal_message, with its transport encoding
encode_delta_report_bundle_archive_seal /
decode_delta_report_bundle_archive_seal and key-bound verifier
verify_delta_report_bundle_archive_seal, and the non-empty
order-preserving chain DeltaReportBundleArchiveSealChain of such seals,
whose outer signature binds drasc_message over the existing canonical
seal encodings and the verifying public key, with the key-bound
verifier verify_dc that re-checks every seal before the outer
signature, and the canonical chain transport encoding
encode_delta_report_bundle_archive_seal_chain /
decode_delta_report_bundle_archive_seal_chain for transferring or
persisting a whole chain as one self-delimiting byte string, and the
compact multi-seal inclusion proofs SMP / make_smp / check_smp that
locate several archive seals at once in such a chain with one root
signature over a SHA256 Merkle tree of the existing canonical seal
encodings, carrying only the companion digests not themselves
disclosed (and never an odd-tail self-pair), and the canonical SMP
bundle transport SMPBundle / encode_smp_bundle / decode_smp_bundle /
verify_smp_bundle that carries an SMP together with its root signature
as one self-delimiting byte string, and the non-empty order-preserving
archive SMPBundleArchive of such bundles, whose outer signature binds
smp_bundle_archive_message over the existing canonical SMP bundle
encodings and the verifying public key, with the key-bound verifier
verify_smp_bundle_archive that re-checks every bundle with
verify_smp_bundle before the outer verify_signature, and the canonical
archive transport encoding encode_smp_bundle_archive /
decode_smp_bundle_archive for transferring or persisting a whole
archive as one self-delimiting byte string.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from itertools import combinations
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
    "recover_secret",
    "RecoveryReport",
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
    "encode_nonce_reuse",
    "decode_nonce_reuse",
    "NonceLeak",
    "recover_leaks",
    "encode_nonce_leak",
    "decode_nonce_leak",
    "verify_nonce_leak",
    "NonceLeakReport",
    "encode_nonce_leak_report",
    "decode_nonce_leak_report",
    "verify_nonce_leak_report",
    "ReportSeal",
    "seal_message",
    "encode_seal",
    "decode_seal",
    "verify_seal",
    "SealHistory",
    "history_message",
    "check_history",
    "encode_history",
    "decode_history",
    "SealHistoryProof",
    "make_history_proof",
    "check_history_proof",
    "encode_history_proof",
    "decode_history_proof",
    "SealHistoryProofBundle",
    "encode_history_proof_bundle",
    "decode_history_proof_bundle",
    "verify_history_proof_bundle",
    "SealHistoryMultiProof",
    "make_history_multi_proof",
    "check_history_multi_proof",
    "encode_history_multi_proof",
    "decode_history_multi_proof",
    "SealHistoryMultiProofBundle",
    "encode_history_multi_proof_bundle",
    "decode_history_multi_proof_bundle",
    "verify_history_multi_proof_bundle",
    "SealHistoryExtension",
    "make_history_extension",
    "check_history_extension",
    "encode_history_extension",
    "decode_history_extension",
    "SealHistoryExtensionBundle",
    "encode_history_extension_bundle",
    "decode_history_extension_bundle",
    "verify_history_extension_bundle",
    "SealHistoryExtensionBundleChain",
    "encode_history_extension_bundle_chain",
    "decode_history_extension_bundle_chain",
    "verify_history_extension_bundle_chain",
    "SealHistoryExtensionDeltaChain",
    "expand_history_delta",
    "compact_history_delta",
    "encode_history_delta",
    "decode_history_delta",
    "verify_history_delta",
    "slice_history_delta",
    "concatenate_history_delta",
    "partition_history_delta",
    "join_history_delta_segments",
    "encode_history_delta_segments",
    "decode_history_delta_segments",
    "HistoryDeltaSegmentsSeal",
    "hds_message",
    "encode_hds",
    "decode_hds",
    "verify_hds",
    "HistoryDeltaSegmentsSealChain",
    "hdsc_message",
    "encode_hdsc",
    "decode_hdsc",
    "verify_hdsc",
    "HDSCProof",
    "make_hdsc_proof",
    "check_hdsc_proof",
    "encode_hdsc_proof",
    "decode_hdsc_proof",
    "HDSCProofBundle",
    "encode_hdsc_proof_bundle",
    "decode_hdsc_proof_bundle",
    "verify_hdsc_proof_bundle",
    "HDSCProofBundleArchive",
    "hdsc_proof_bundle_archive_message",
    "verify_hdsc_proof_bundle_archive",
    "encode_hdsc_proof_bundle_archive",
    "decode_hdsc_proof_bundle_archive",
    "HDSCArchiveProof",
    "make_hdsc_archive_proof",
    "check_hdsc_archive_proof",
    "RHE",
    "encode_rhe",
    "decode_rhe",
    "check_rhe",
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
    "AuditProof",
    "make_proof",
    "check_proof",
    "AuditMultiProof",
    "make_multi_proof",
    "check_multi_proof",
    "encode_audit_proof",
    "decode_audit_proof",
    "AuditProofBundle",
    "encode_audit_proof_bundle",
    "decode_audit_proof_bundle",
    "verify_audit_proof_bundle",
    "encode_audit_multi_proof",
    "decode_audit_multi_proof",
    "AuditMultiProofBundle",
    "encode_audit_multi_proof_bundle",
    "decode_audit_multi_proof_bundle",
    "verify_audit_multi_proof_bundle",
    "AuditExtensionProof",
    "make_extension",
    "check_extension",
    "encode_extension",
    "decode_extension",
    "AuditExtensionProofBundle",
    "encode_audit_extension_proof_bundle",
    "decode_audit_extension_proof_bundle",
    "verify_audit_extension_proof_bundle",
    "AuditExtensionProofBundleChain",
    "encode_audit_extension_proof_bundle_chain",
    "decode_audit_extension_proof_bundle_chain",
    "verify_audit_extension_proof_bundle_chain",
    "AuditExtensionCheckpointChain",
    "encode_audit_extension_checkpoint_chain",
    "decode_audit_extension_checkpoint_chain",
    "verify_audit_extension_checkpoint_chain",
    "AuditExtensionDeltaCheckpointChain",
    "expand_audit_extension_delta_checkpoint_chain",
    "compact_audit_extension_delta_checkpoint_chain",
    "slice_audit_extension_delta_checkpoint_chain",
    "concatenate_audit_extension_delta_checkpoint_chains",
    "partition_delta_chain",
    "join_delta_chain_segments",
    "encode_audit_extension_delta_checkpoint_chain",
    "decode_audit_extension_delta_checkpoint_chain",
    "verify_audit_extension_delta_checkpoint_chain",
    "encode_delta_chain_segments",
    "decode_delta_chain_segments",
    "verify_delta_chain_segments",
    "DeltaDiagnosis",
    "diagnose_delta_chain_segments",
    "DeltaReport",
    "dr_message",
    "encode_dr",
    "decode_dr",
    "verify_dr",
    "DeltaReportBundle",
    "encode_delta_report_bundle",
    "decode_delta_report_bundle",
    "verify_delta_report_bundle",
    "DeltaReportBundleArchive",
    "encode_delta_report_bundle_archive",
    "decode_delta_report_bundle_archive",
    "verify_delta_report_bundle_archive",
    "DeltaReportBundleArchiveSeal",
    "archive_seal_message",
    "encode_delta_report_bundle_archive_seal",
    "decode_delta_report_bundle_archive_seal",
    "verify_delta_report_bundle_archive_seal",
    "DeltaReportBundleArchiveSealChain",
    "drasc_message",
    "verify_dc",
    "encode_delta_report_bundle_archive_seal_chain",
    "decode_delta_report_bundle_archive_seal_chain",
    "SMP",
    "make_smp",
    "check_smp",
    "SMPBundle",
    "encode_smp_bundle",
    "decode_smp_bundle",
    "verify_smp_bundle",
    "SMPBundleArchive",
    "smp_bundle_archive_message",
    "verify_smp_bundle_archive",
    "encode_smp_bundle_archive",
    "decode_smp_bundle_archive",
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
class RecoveryReport:
    """Outcome of an error-share-identifying secret reconstruction.

    ``secret`` is the constant term of the decision polynomial, the value it
    takes at ``x = 0``, matching :func:`reconstruct_secret`. ``accepted`` is
    the tuple of shares that lie on that polynomial and ``rejected`` the
    remaining shares; both are ordered by ascending ``x``. The dataclass is
    frozen, positionally constructible and compared by value.
    """

    secret: int
    accepted: tuple[Share, ...]
    rejected: tuple[Share, ...]


def _interpolate_coefficients(points: Sequence[Share], prime: int) -> tuple[int, ...]:
    """Interpolate the unique degree-<len(points) polynomial at ``points``.

    ``points`` must have distinct, non-zero ``x`` coordinates. Returns the
    coefficient tuple from the constant term up, reduced modulo ``prime``.
    """
    width = len(points)
    coefficients = [0] * width
    for point in points:
        # L_i(x) = y_i * prod_{j != i} (x - x_j) / (x_i - x_j); build the
        # numerator as ascending coefficients and add it, scaled, to the
        # running polynomial.
        numerator: list[int] = [1]
        denominator = 1
        for other in points:
            if other.x == point.x:
                continue
            numerator = [
                (-other.x * numerator[0]) % prime,
                *[
                    (numerator[position] - other.x * numerator[position + 1]) % prime
                    for position in range(len(numerator) - 1)
                ],
                numerator[-1],
            ]
            denominator = denominator * (point.x - other.x) % prime
        scale = point.y * pow(denominator, -1, prime) % prime
        for position in range(width):
            coefficients[position] = (
                coefficients[position] + scale * numerator[position]
            ) % prime
    return tuple(coefficients)


def recover_secret(
    shares: tuple[Share, ...] | list[Share],
    threshold: int,
    *,
    prime: int = DEFAULT_PRIME,
) -> RecoveryReport:
    """Reconstruct a secret while identifying tampered shares.

    Among the polynomials of degree below ``threshold`` over ``GF(prime)``,
    pick the unique one that agrees with the most supplied shares. A share
    agrees with a polynomial when it evaluates to the share's ``y`` at its
    ``x``. ``accepted`` holds every share agreeing with that polynomial and
    ``rejected`` every other share; both are ordered by ascending ``x``. The
    reported secret is the polynomial's value at ``x = 0``, the same value
    :func:`reconstruct_secret` returns for the accepted shares.

    The decision depends only on share contents and ``threshold``, never on
    submission order. A tie for the most-agreeing polynomial, or no
    polynomial agreeing with at least ``threshold`` shares, cannot be
    decided and raises ``ValueError``.
    """
    if not isinstance(shares, (tuple, list)):
        raise TypeError("shares must be a tuple or list")
    if not isinstance(threshold, int) or isinstance(threshold, bool):
        raise TypeError("threshold must be an integer")
    if not isinstance(prime, int) or isinstance(prime, bool):
        raise TypeError("prime must be an integer")

    for share in shares:
        if not isinstance(share, Share):
            raise TypeError("shares must contain Share instances")
        if not isinstance(share.x, int) or isinstance(share.x, bool):
            raise TypeError("share indices must be integers")
        if not isinstance(share.y, int) or isinstance(share.y, bool):
            raise TypeError("share values must be integers")

    if not shares:
        raise ValueError("at least one share is required")
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    if threshold > len(shares):
        raise ValueError("threshold must not exceed the number of shares")
    if not _is_prime(prime):
        raise ValueError("prime must be prime")

    ordered = sorted(shares, key=lambda share: share.x)
    for position, share in enumerate(ordered):
        if not 0 < share.x < prime:
            raise ValueError("share index must satisfy 0 < x < prime")
        if not 0 <= share.y < prime:
            raise ValueError("share value must satisfy 0 <= y < prime")
        if position > 0 and share.x == ordered[position - 1].x:
            raise ValueError("duplicate share index")

    # Every degree-<threshold candidate that can matter is the interpolant of
    # some threshold-sized subset; distinct interpolants are deduplicated by
    # their coefficient tuples. Evaluating each candidate at every supplied
    # point counts the shares it agrees with.
    best_coefficients: tuple[int, ...] | None = None
    best_count = 0
    tied = False
    seen: set[tuple[int, ...]] = set()
    for combo in combinations(ordered, threshold):
        coefficients = _interpolate_coefficients(combo, prime)
        if coefficients in seen:
            continue
        seen.add(coefficients)
        count = sum(
            1
            for share in ordered
            if evaluate_polynomial(coefficients, share.x, prime=prime) == share.y
        )
        if count > best_count:
            best_count = count
            best_coefficients = coefficients
            tied = False
        elif count == best_count and coefficients != best_coefficients:
            tied = True

    if best_count < threshold:
        raise ValueError(
            "no polynomial of degree below threshold agrees with threshold shares"
        )
    if tied:
        raise ValueError("multiple polynomials agree with the most shares; cannot decide")

    assert best_coefficients is not None
    secret = best_coefficients[0]
    accepted = tuple(
        share
        for share in ordered
        if evaluate_polynomial(best_coefficients, share.x, prime=prime) == share.y
    )
    rejected = tuple(
        share
        for share in ordered
        if evaluate_polynomial(best_coefficients, share.x, prime=prime) != share.y
    )
    return RecoveryReport(secret, accepted, rejected)


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
    return _schnorr_challenge_from_digest(
        hashlib.sha256(message).digest(),
        public_key,
        R,
        signer_ids,
        field_prime=field_prime,
        group_prime=group_prime,
    )


def _schnorr_challenge_from_digest(
    digest: bytes,
    public_key: int,
    R: int,
    signer_ids: Sequence[int],
    *,
    field_prime: int,
    group_prime: int,
) -> int:
    """The Fiat-Shamir challenge of a message whose SHA-256 digest is known."""
    length = (group_prime.bit_length() + 7) // 8
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


def _read_id_list(stream: bytes, offset: int, *, name: str) -> tuple[tuple[int, ...], int]:
    """Read a 4-byte-counted, strictly increasing list of positive integers."""
    if offset + 4 > len(stream):
        raise ValueError("truncated rotation certificate")
    count = int.from_bytes(stream[offset:offset + 4], "big")
    offset += 4
    if count == 0:
        raise ValueError(f"{name} must be non-empty")
    ids = []
    for _ in range(count):
        member_id, offset = _read_varint(stream, offset)
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
# Canonical nonce-reuse transport: a self-delimiting, byte-for-byte
# reproducible encoding of a NonceReuse finding for cross-implementation
# exchange and persistence. Decoding restores the structure only — receipts
# are stored opaque and are neither parsed nor re-verified, and no reuse is
# checked: find_nonce_reuse remains the sole detector afterwards.
# ---------------------------------------------------------------------------

NONCE_REUSE_WIRE_TAG = b"thresholdsign/nr/v1"


def encode_nonce_reuse(item: NonceReuse) -> bytes:
    """Canonically encode a nonce-reuse finding for transport or persistence.

    The encoding is the direct concatenation, in order, of the tag
    ``b"thresholdsign/nr/v1"``, ``VARINT(signer_id)`` and
    ``VARINT(nonce_commitment)`` (both positive), the receipt count as a
    4-byte unsigned big-endian integer, and one frame per receipt — a
    4-byte unsigned big-endian payload length followed by the raw
    :class:`SigningAudit` payload bytes. There must be at least two
    receipts, every payload must be non-empty, and the payloads must appear
    in strictly increasing byte order, exactly as
    :func:`find_nonce_reuse` produces them. A ``VARINT`` is a 4-byte
    unsigned big-endian body length followed by the shortest unsigned
    big-endian value (zero is the single byte ``00`` and positive values
    carry no leading zero).

    A non-:class:`NonceReuse` argument or a wrong field type (a non-integer
    ``signer_id`` or ``nonce_commitment`` including booleans, a non-tuple
    receipts sequence, a non-:class:`SigningAudit` receipt or a non-bytes
    payload) raises TypeError; a non-positive integer, fewer than two
    receipts, an empty, duplicated or out-of-order payload, or an over-long
    frame raises ValueError. The payloads are not parsed and no reuse is
    verified: the output for a given finding is unique and the encoding
    carries no network, storage or hidden state.
    """
    if not isinstance(item, NonceReuse):
        raise TypeError("item must be a NonceReuse instance")
    signer_id = item.signer_id
    nonce_commitment = item.nonce_commitment
    receipts = item.receipts
    if not isinstance(signer_id, int) or isinstance(signer_id, bool):
        raise TypeError("item.signer_id must be an integer")
    if not isinstance(nonce_commitment, int) or isinstance(nonce_commitment, bool):
        raise TypeError("item.nonce_commitment must be an integer")
    if not isinstance(receipts, tuple):
        raise TypeError("item.receipts must be a tuple")
    if signer_id <= 0:
        raise ValueError("item.signer_id must be positive")
    if nonce_commitment <= 0:
        raise ValueError("item.nonce_commitment must be positive")
    if len(receipts) < 2:
        raise ValueError("a nonce-reuse finding needs at least two receipts")
    if len(receipts) > 0xFFFFFFFF:
        raise ValueError("too many receipts")

    buffer = bytearray(NONCE_REUSE_WIRE_TAG)
    buffer += _encode_varint(signer_id)
    buffer += _encode_varint(nonce_commitment)
    buffer += len(receipts).to_bytes(4, "big", signed=False)
    previous = None
    for receipt in receipts:
        if not isinstance(receipt, SigningAudit):
            raise TypeError("each receipt must be a SigningAudit instance")
        payload = receipt.payload
        if not isinstance(payload, bytes):
            raise TypeError("each receipt payload must be bytes")
        if not payload:
            raise ValueError("receipt payloads must be non-empty")
        if len(payload) > 0xFFFFFFFF:
            raise ValueError("receipt encoding too long")
        if previous is not None and payload <= previous:
            raise ValueError(
                "receipt payloads must be strictly increasing and unique"
            )
        previous = payload
        buffer += len(payload).to_bytes(4, "big", signed=False)
        buffer += payload
    return bytes(buffer)


def decode_nonce_reuse(blob: bytes) -> NonceReuse:
    """Decode the canonical encoding produced by :func:`encode_nonce_reuse`.

    Accepts only the single canonical form: the tag
    ``b"thresholdsign/nr/v1"``, the length-prefixed positive integers
    ``signer_id`` and ``nonce_commitment`` (each a 4-byte unsigned
    big-endian length followed by its shortest unsigned big-endian value,
    zero encoded as the single byte ``00``), a 4-byte receipt count of at
    least two, and that many frames of a 4-byte non-zero length followed by
    raw payload bytes that are strictly increasing and unique. A non-bytes
    argument raises TypeError; a wrong or missing tag, a zero
    ``signer_id`` or ``nonce_commitment``, fewer than two receipts, an
    empty, duplicated or unordered payload, a non-canonical integer
    (leading zero or over-long length), a count that does not match the
    frames present, truncation, or trailing bytes raises ValueError. A
    successfully decoded finding re-encodes to exactly the input bytes.

    Decoding only restores the structure: the receipts are constructed as
    opaque :class:`SigningAudit` values and are neither parsed nor
    verified, and the claimed nonce reuse is not checked. A structurally
    legal finding whose receipts do not actually attest to a reuse is
    returned normally.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not blob.startswith(NONCE_REUSE_WIRE_TAG):
        raise ValueError("bad nonce-reuse tag")
    offset = len(NONCE_REUSE_WIRE_TAG)

    signer_id, offset = _read_varint(blob, offset, what="nonce-reuse signer_id")
    nonce_commitment, offset = _read_varint(
        blob, offset, what="nonce-reuse nonce commitment"
    )
    if signer_id == 0:
        raise ValueError("nonce-reuse signer_id must be positive")
    if nonce_commitment == 0:
        raise ValueError("nonce-reuse nonce_commitment must be positive")

    if offset + 4 > len(blob):
        raise ValueError("truncated nonce-reuse receipt count")
    receipt_count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    if receipt_count < 2:
        raise ValueError("a nonce-reuse finding needs at least two receipts")

    receipts = []
    previous = None
    for _ in range(receipt_count):
        payload, offset = _read_audit_proof_block(
            blob, offset, what="nonce-reuse receipt"
        )
        if previous is not None and payload <= previous:
            raise ValueError(
                "nonce-reuse receipts must be strictly increasing and unique"
            )
        previous = payload
        receipts.append(SigningAudit(payload=payload))
    if offset != len(blob):
        raise ValueError("trailing bytes after nonce-reuse finding")

    item = NonceReuse(
        signer_id=signer_id,
        nonce_commitment=nonce_commitment,
        receipts=tuple(receipts),
    )
    if encode_nonce_reuse(item) != blob:
        raise ValueError("non-canonical nonce-reuse encoding")
    return item


# ---------------------------------------------------------------------------
# Canonical leaked-share transport and key-only leak verification: a
# self-delimiting, byte-for-byte reproducible encoding of a NonceLeak for
# cross-implementation exchange and persistence, plus a verifier that
# re-derives the exposed share from the two receipts and the signing key
# alone. Decoding restores the structure only — receipts are stored opaque
# and are neither parsed nor re-verified; verify_nonce_leak remains the way
# to test the claim afterwards.
# ---------------------------------------------------------------------------

NONCE_LEAK_WIRE_TAG = b"thresholdsign/nl/v1"


def _check_nonce_leak_fields(item: NonceLeak) -> None:
    """Type- and structure-check every NonceLeak field (encode/verify share this)."""
    if not isinstance(item.signer_id, int) or isinstance(item.signer_id, bool):
        raise TypeError("item.signer_id must be an integer")
    if not isinstance(item.commitment, int) or isinstance(item.commitment, bool):
        raise TypeError("item.commitment must be an integer")
    if not isinstance(item.share, int) or isinstance(item.share, bool):
        raise TypeError("item.share must be an integer")
    if not isinstance(item.receipts, tuple):
        raise TypeError("item.receipts must be a tuple")
    for receipt in item.receipts:
        if not isinstance(receipt, SigningAudit):
            raise TypeError("each receipt must be a SigningAudit instance")
        if not isinstance(receipt.payload, bytes):
            raise TypeError("each receipt payload must be bytes")
    if item.signer_id <= 0:
        raise ValueError("item.signer_id must be positive")
    if item.commitment <= 0:
        raise ValueError("item.commitment must be positive")
    if item.share < 0:
        raise ValueError("item.share must be non-negative")
    if len(item.receipts) != 2:
        raise ValueError("a nonce-leak finding needs exactly two receipts")
    first, second = (receipt.payload for receipt in item.receipts)
    if not first or not second:
        raise ValueError("receipt payloads must be non-empty")
    if second <= first:
        raise ValueError("receipt payloads must be strictly increasing and unique")


def encode_nonce_leak(item: NonceLeak) -> bytes:
    """Canonically encode a leaked-share finding for transport or persistence.

    The encoding is the direct concatenation, in order, of the tag
    ``b"thresholdsign/nl/v1"``, ``VARINT(signer_id)``,
    ``VARINT(commitment)`` and ``VARINT(share)`` (the first two positive,
    the share non-negative), the constant receipt count 2 as a 4-byte
    unsigned big-endian integer, and one frame per receipt — a 4-byte
    unsigned big-endian payload length followed by the raw
    :class:`SigningAudit` payload bytes. There must be exactly two
    receipts, every payload must be non-empty, and the payloads must
    appear in strictly increasing byte order, exactly as
    :func:`recover_leaks` produces them. A ``VARINT`` is a 4-byte
    unsigned big-endian body length followed by the shortest unsigned
    big-endian value (zero is the single byte ``00`` and positive values
    carry no leading zero).

    A non-:class:`NonceLeak` argument or a wrong field type (a
    non-integer ``signer_id``, ``commitment`` or ``share`` including
    booleans, a non-tuple receipts sequence, a non-:class:`SigningAudit`
    receipt or a non-bytes payload) raises TypeError; a non-positive
    ``signer_id`` or ``commitment``, a negative ``share``, a receipt
    count other than two, an empty, duplicated or out-of-order payload,
    or an over-long frame raises ValueError. The payloads are not parsed
    and the claimed leak is not verified: the output for a given finding
    is unique and the encoding carries no network, storage or hidden
    state.
    """
    if not isinstance(item, NonceLeak):
        raise TypeError("item must be a NonceLeak instance")
    _check_nonce_leak_fields(item)

    buffer = bytearray(NONCE_LEAK_WIRE_TAG)
    buffer += _encode_varint(item.signer_id)
    buffer += _encode_varint(item.commitment)
    buffer += _encode_varint(item.share)
    buffer += (2).to_bytes(4, "big", signed=False)
    for receipt in item.receipts:
        payload = receipt.payload
        if len(payload) > 0xFFFFFFFF:
            raise ValueError("receipt encoding too long")
        buffer += len(payload).to_bytes(4, "big", signed=False)
        buffer += payload
    return bytes(buffer)


def decode_nonce_leak(blob: bytes) -> NonceLeak:
    """Decode the canonical encoding produced by :func:`encode_nonce_leak`.

    Accepts only the single canonical form: the tag
    ``b"thresholdsign/nl/v1"``, the length-prefixed integers
    ``signer_id``, ``commitment`` and ``share`` (each a 4-byte unsigned
    big-endian length followed by its shortest unsigned big-endian value,
    zero encoded as the single byte ``00``), the constant 4-byte receipt
    count 2, and two frames of a 4-byte non-zero length followed by raw
    payload bytes that are strictly increasing and unique. A non-bytes
    argument raises TypeError; a wrong or missing tag, a zero
    ``signer_id`` or ``commitment``, a receipt count other than two, an
    empty, duplicated or unordered payload, a non-canonical integer
    (leading zero or over-long length), truncation, or trailing bytes
    raises ValueError. A successfully decoded finding re-encodes to
    exactly the input bytes.

    Decoding only restores the structure: the receipts are constructed as
    opaque :class:`SigningAudit` values and are neither parsed nor
    verified, and the claimed leak is not checked. A structurally legal
    finding whose receipts do not actually expose the share is returned
    normally, and :func:`verify_nonce_leak` reports it as ``False``.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not blob.startswith(NONCE_LEAK_WIRE_TAG):
        raise ValueError("bad nonce-leak tag")
    offset = len(NONCE_LEAK_WIRE_TAG)

    signer_id, offset = _read_varint(blob, offset, what="nonce-leak signer_id")
    commitment, offset = _read_varint(blob, offset, what="nonce-leak commitment")
    share, offset = _read_varint(blob, offset, what="nonce-leak share")
    if signer_id == 0:
        raise ValueError("nonce-leak signer_id must be positive")
    if commitment == 0:
        raise ValueError("nonce-leak commitment must be positive")

    if offset + 4 > len(blob):
        raise ValueError("truncated nonce-leak receipt count")
    receipt_count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    if receipt_count != 2:
        raise ValueError("a nonce-leak finding carries exactly two receipts")

    receipts = []
    previous = None
    for _ in range(receipt_count):
        payload, offset = _read_audit_proof_block(
            blob, offset, what="nonce-leak receipt"
        )
        if previous is not None and payload <= previous:
            raise ValueError(
                "nonce-leak receipts must be strictly increasing and unique"
            )
        previous = payload
        receipts.append(SigningAudit(payload=payload))
    if offset != len(blob):
        raise ValueError("trailing bytes after nonce-leak finding")

    item = NonceLeak(
        signer_id=signer_id,
        commitment=commitment,
        share=share,
        receipts=tuple(receipts),
    )
    if encode_nonce_leak(item) != blob:
        raise ValueError("non-canonical nonce-leak encoding")
    return item


def verify_nonce_leak(item: NonceLeak, key: SigningDKGResult) -> bool:
    """Re-derive a leaked share from its two receipts and the signing key.

    ``item`` must be a structurally legal :class:`NonceLeak` exactly as
    :func:`encode_nonce_leak` requires — wrong field types raise
    TypeError, an illegal structure (a non-positive ``signer_id`` or
    ``commitment``, a negative ``share``, other than two receipts, an
    empty, duplicated or out-of-order payload) raises ValueError — and
    ``key`` is validated like in :func:`check_audit`. Each receipt is
    then decoded (structural or decoding defects raise ValueError,
    including rows fewer than ``threshold`` or signer ids that are not
    DKG participants) and re-verified against ``key`` alone, without the
    messages: the Fiat-Shamir challenge is recomputed from the receipt's
    message digest, the aggregate ``R`` from the row commitments, every
    row's share equation ``g ** z_i == R_i * Y_i ** (c * lambda_i)`` and
    the aggregate ``z`` with ``g ** z == R * Y ** c`` must all match the
    recorded values, and both receipts must be successful (status 1).

    From each receipt the coefficient ``a = c * lambda_i mod q`` of the
    leaked signer's response is computed over that receipt's signer set.
    The two coefficients must differ and the two row commitments must
    equal each other and ``item.commitment``; the share is then solved as
    ``s = (z1 - z2) / (a1 - a2) mod q`` and must equal ``item.share`` and
    satisfy ``g ** s == Y_i mod p`` against the signer's verification
    share. Any mismatch returns ``False``; only a fully consistent
    finding returns ``True``. The function is stateless.
    """
    if not isinstance(item, NonceLeak):
        raise TypeError("item must be a NonceLeak instance")
    _check_nonce_leak_fields(item)
    result, public_key, field_prime, group_prime, generator = (
        _check_signing_setup(key)
    )
    _check_signing_dkg_structure(key)
    if item.signer_id not in result.participant_ids:
        raise ValueError("item.signer_id must be a DKG participant")
    threshold = len(result.commitment.values)

    entries = []
    for receipt in item.receipts:
        _digest, Y, R, challenge, rows, status, z = _decode_audit_payload(
            receipt.payload, field_prime, group_prime
        )
        signer_ids = tuple(row[0] for row in rows)
        if len(signer_ids) < threshold:
            raise ValueError("audit rows must cover at least threshold signers")
        if any(
            signer_id not in result.participant_ids for signer_id in signer_ids
        ):
            raise ValueError("audit signer ids must be DKG participants")

        if status != 1:
            return False
        if Y != public_key:
            return False
        recomputed_challenge = _schnorr_challenge_from_digest(
            _digest,
            public_key,
            R,
            signer_ids,
            field_prime=field_prime,
            group_prime=group_prime,
        )
        if recomputed_challenge != challenge:
            return False
        recomputed_R = 1
        for _signer_id, nonce_commitment, _z_i in rows:
            recomputed_R = recomputed_R * nonce_commitment % group_prime
        if recomputed_R != R:
            return False
        z_total = 0
        for signer_id, nonce_commitment, z_i in rows:
            weight = _lagrange_weight(signer_id, signer_ids, field_prime)
            share_index = result.participant_ids.index(signer_id)
            Y_i = key.verification_shares[share_index]
            expected = (
                nonce_commitment
                * pow(Y_i, challenge * weight % field_prime, group_prime)
                % group_prime
            )
            if pow(generator, z_i, group_prime) != expected:
                return False
            z_total = (z_total + z_i) % field_prime
        if z != z_total:
            return False
        if pow(generator, z, group_prime) != (
            R * pow(public_key, challenge, group_prime) % group_prime
        ):
            return False

        row = next((row for row in rows if row[0] == item.signer_id), None)
        if row is None:
            return False
        weight = _lagrange_weight(item.signer_id, signer_ids, field_prime)
        entries.append((challenge * weight % field_prime, row[1], row[2]))

    (first_a, first_commitment, first_z), (second_a, second_commitment, second_z) = (
        entries
    )
    if first_commitment != second_commitment:
        return False
    if first_commitment != item.commitment:
        return False
    if first_a == second_a:
        return False
    solved = (
        (first_z - second_z)
        * pow(first_a - second_a, -1, field_prime)
        % field_prime
    )
    if solved != item.share:
        return False
    share_index = result.participant_ids.index(item.signer_id)
    if pow(generator, solved, group_prime) != key.verification_shares[share_index]:
        return False
    return True


# ---------------------------------------------------------------------------
# Canonical batched leaked-share transport and key-only verification: a
# self-delimiting, byte-for-byte reproducible encoding of a non-empty,
# strictly keyed tuple of NonceLeak findings for cross-implementation
# exchange and persistence, plus a verifier that checks every finding with
# verify_nonce_leak. Decoding restores the structure only — nested findings
# are decoded with decode_nonce_leak (whose receipts stay opaque) and no
# leak is verified: verify_nonce_leak_report remains the way to test the
# claims afterwards.
# ---------------------------------------------------------------------------

NONCE_LEAK_REPORT_WIRE_TAG = b"thresholdsign/nlr/v1"


@dataclass(frozen=True)
class NonceLeakReport:
    """A non-empty, key-ordered batch of leaked-share findings.

    ``items`` is the non-empty tuple of :class:`NonceLeak` findings ordered
    by strictly increasing ``(signer_id, commitment)`` pairs with no
    duplicates, exactly as :func:`recover_leaks` returns a batch. The
    dataclass is frozen, positionally constructible and compared by value;
    it carries no network, storage or hidden state. Neither the container
    nor the ordering is checked at construction time —
    :func:`encode_nonce_leak_report` and :func:`verify_nonce_leak_report`
    are the ways to test a report afterwards.
    """

    items: tuple[NonceLeak, ...]


def _check_nonce_leak_report_fields(items: object) -> int:
    """Type- and structure-check the items container of a nonce-leak report.

    Items must be a non-empty tuple of :class:`NonceLeak` findings whose
    ``(signer_id, commitment)`` pairs are strictly increasing and unique;
    each nested finding is checked with
    :func:`_check_nonce_leak_fields`. Returns the item count.
    """
    if not isinstance(items, tuple):
        raise TypeError("items must be a tuple")
    try:
        count = len(items)
    except OverflowError:
        raise ValueError("too many findings") from None
    if count == 0:
        raise ValueError("items must be non-empty")
    previous_key = None
    for item in items:
        if not isinstance(item, NonceLeak):
            raise TypeError("items must contain NonceLeak instances")
        _check_nonce_leak_fields(item)
        key = (item.signer_id, item.commitment)
        if previous_key is not None and key <= previous_key:
            raise ValueError(
                "items must be strictly increasing and unique by "
                "(signer_id, commitment)"
            )
        previous_key = key
    return count


def encode_nonce_leak_report(report: NonceLeakReport) -> bytes:
    """Canonically encode a batch of leaked-share findings for transport.

    The encoding is the direct concatenation, in order, of the tag
    ``b"thresholdsign/nlr/v1"``, the item count ``n`` as a 4-byte unsigned
    big-endian integer, and one frame per item in the report's original
    order — a 4-byte unsigned big-endian length followed by the raw
    :func:`encode_nonce_leak` output. ``items`` must be a non-empty tuple
    of :class:`NonceLeak` findings whose ``(signer_id, commitment)`` pairs
    are strictly increasing and unique; the findings are never sorted or
    otherwise re-ordered.

    A non-:class:`NonceLeakReport` argument or a wrong field type (a
    non-tuple ``items`` sequence or a non-:class:`NonceLeak` element,
    plus every type error :func:`encode_nonce_leak` raises, booleans
    included) raises TypeError; an empty report, out-of-order or
    duplicate keys, an illegal nested finding, or an over-long frame
    raises ValueError. The nested findings are not verified: the output
    for a given report is unique and the encoding carries no network,
    storage or hidden state.
    """
    if not isinstance(report, NonceLeakReport):
        raise TypeError("report must be a NonceLeakReport instance")
    count = _check_nonce_leak_report_fields(report.items)
    if count > 0xFFFFFFFF:
        raise ValueError("too many findings")

    buffer = bytearray(NONCE_LEAK_REPORT_WIRE_TAG)
    buffer += count.to_bytes(4, "big", signed=False)
    for item in report.items:
        body = encode_nonce_leak(item)
        if len(body) > 0xFFFFFFFF:
            raise ValueError("nonce-leak encoding too long")
        buffer += len(body).to_bytes(4, "big", signed=False)
        buffer += body
    return bytes(buffer)


def decode_nonce_leak_report(blob: bytes) -> NonceLeakReport:
    """Decode the canonical encoding produced by :func:`encode_nonce_leak_report`.

    Accepts only the single canonical form: the tag
    ``b"thresholdsign/nlr/v1"``, the 4-byte unsigned big-endian item
    count ``n`` (non-zero), and then exactly ``n`` frames, each a 4-byte
    non-zero length followed by bytes that :func:`decode_nonce_leak`
    accepts (so every nested finding must itself be canonical). The
    decoded findings' ``(signer_id, commitment)`` pairs must be strictly
    increasing and unique. A non-bytes argument raises TypeError; a
    wrong or missing tag, a zero count, a count/frame mismatch, an
    empty frame, truncation, trailing bytes, a non-canonical nested
    encoding, or out-of-order or duplicate keys raises ValueError. A
    successfully decoded report re-encodes to exactly the input bytes.

    Decoding only restores the structure: nested findings are decoded
    frame by frame, their receipts remain opaque, no finding is
    re-ordered and no leak is verified. A structurally legal report
    whose findings do not actually expose their shares is returned
    normally, and :func:`verify_nonce_leak_report` reports it as
    ``False``.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not blob.startswith(NONCE_LEAK_REPORT_WIRE_TAG):
        raise ValueError("bad nonce-leak report tag")
    offset = len(NONCE_LEAK_REPORT_WIRE_TAG)

    if offset + 4 > len(blob):
        raise ValueError("truncated nonce-leak report item count")
    count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    if count == 0:
        raise ValueError("nonce-leak report must be non-empty")

    items = []
    previous_key = None
    for index in range(count):
        body, offset = _read_audit_proof_block(
            blob, offset, what=f"nonce-leak report item {index + 1}"
        )
        item = decode_nonce_leak(body)
        key = (item.signer_id, item.commitment)
        if previous_key is not None and key <= previous_key:
            raise ValueError(
                "nonce-leak report items must be strictly increasing and "
                "unique by (signer_id, commitment)"
            )
        previous_key = key
        items.append(item)
    if offset != len(blob):
        raise ValueError("trailing bytes after nonce-leak report")

    report = NonceLeakReport(items=tuple(items))
    if encode_nonce_leak_report(report) != blob:
        raise ValueError("non-canonical nonce-leak report encoding")
    return report


def verify_nonce_leak_report(
    report: NonceLeakReport, key: SigningDKGResult
) -> bool:
    """Verify every finding of a nonce-leak report against the signing key.

    ``report`` must be a structurally legal :class:`NonceLeakReport`
    exactly as :func:`encode_nonce_leak_report` requires — wrong field
    types raise TypeError, an empty report, a non-tuple ``items``
    sequence, a non-:class:`NonceLeak` element, out-of-order or
    duplicate keys, or an illegal nested finding raise ValueError — and
    ``key`` is validated like in :func:`verify_nonce_leak`. Each item
    is then checked with :func:`verify_nonce_leak`; every item must
    verify for the result to be ``True``, and any single legal
    mismatch makes the whole report ``False``. Findings are verified in
    order, but the verdict is the logical AND of all of them, so the
    result does not depend on their order. The function is stateless.
    """
    if not isinstance(report, NonceLeakReport):
        raise TypeError("report must be a NonceLeakReport instance")
    _check_nonce_leak_report_fields(report.items)

    result = True
    for item in report.items:
        result = verify_nonce_leak(item, key) and result
    return result


# ---------------------------------------------------------------------------
# Whole-report seals: a threshold Schnorr AggregateSignature over a canonical
# message that binds the exact NonceLeakReport encoding and the verifying
# public key. The seal is a plain value with no network, storage or hidden
# state; seal_message builds the signed message, encode_seal/decode_seal move
# it over the wire, and verify_seal first checks the report itself and then
# the signature.
# ---------------------------------------------------------------------------

REPORT_SEAL_TAG = b"ts/nlrs/v1"
REPORT_SEAL_WIRE_TAG = b"ts/nlrs/w1"


@dataclass(frozen=True)
class ReportSeal:
    """A whole nonce-leak report sealed by one threshold Schnorr signature.

    ``report`` is the sealed :class:`NonceLeakReport`; ``signature`` is the
    threshold Schnorr :class:`AggregateSignature` on
    :func:`seal_message` of the report and the verifying public key. The
    dataclass is frozen, positionally constructible and compared by value;
    it carries no network, storage or hidden state. Neither field is
    checked at construction time — :func:`verify_seal` is the way to test a
    seal afterwards.
    """

    report: NonceLeakReport
    signature: AggregateSignature


def seal_message(report: NonceLeakReport, public_key: int) -> bytes:
    """Encode the canonical message the threshold key signs to seal a report.

    The message is, in order, the tag ``b"ts/nlrs/v1"``, the 32-byte
    ``SHA256`` digest of :func:`encode_nonce_leak_report` output ``E`` for
    ``report``, and ``VARINT(public_key)`` — the same 4-byte unsigned
    big-endian length followed by the shortest unsigned big-endian value
    used throughout the canonical transport encodings (zero is the single
    byte ``00``, positive values carry no leading zero). It carries no
    signature and keeps no state.

    ``report`` must be a structurally legal :class:`NonceLeakReport`
    exactly as :func:`encode_nonce_leak_report` requires and
    ``public_key`` a non-boolean non-negative integer. Wrong field types
    raise TypeError; an illegal report, a negative or boolean public key,
    or an over-long key encoding raises ValueError.
    """
    if not isinstance(report, NonceLeakReport):
        raise TypeError("report must be a NonceLeakReport instance")
    if not isinstance(public_key, int) or isinstance(public_key, bool):
        raise TypeError("public_key must be an integer")
    # Raises TypeError/ValueError for an illegal report, exactly like the
    # encoder itself.
    encoded_report = encode_nonce_leak_report(report)
    encoded_key = _encode_varint(public_key)
    return REPORT_SEAL_TAG + hashlib.sha256(encoded_report).digest() + encoded_key


def _check_report_seal_fields(seal: object) -> None:
    """Type- and structure-check a ReportSeal value (without its report)."""
    if not isinstance(seal, ReportSeal):
        raise TypeError("seal must be a ReportSeal instance")
    if not isinstance(seal.report, NonceLeakReport):
        raise TypeError("seal.report must be a NonceLeakReport instance")
    if not isinstance(seal.signature, AggregateSignature):
        raise TypeError("seal.signature must be an AggregateSignature instance")
    if not isinstance(seal.signature.R, int) or isinstance(seal.signature.R, bool):
        raise TypeError("signature.R must be an integer")
    if not isinstance(seal.signature.z, int) or isinstance(seal.signature.z, bool):
        raise TypeError("signature.z must be an integer")
    if not isinstance(seal.signature.signer_ids, tuple):
        raise TypeError("signature.signer_ids must be a tuple")
    for signer_id in seal.signature.signer_ids:
        if not isinstance(signer_id, int) or isinstance(signer_id, bool):
            raise TypeError("signer ids must be integers")

    if seal.signature.R <= 0:
        raise ValueError("signature R must be positive")
    if seal.signature.z < 0:
        raise ValueError("signature z must be non-negative")
    if not seal.signature.signer_ids:
        raise ValueError("at least one signer is required")
    if any(signer_id <= 0 for signer_id in seal.signature.signer_ids):
        raise ValueError("signer ids must be positive")
    if any(
        seal.signature.signer_ids[index] >= seal.signature.signer_ids[index + 1]
        for index in range(len(seal.signature.signer_ids) - 1)
    ):
        raise ValueError("signer ids must be strictly increasing and unique")


def encode_seal(seal: ReportSeal) -> bytes:
    """Canonically encode a report seal for transport or persistence.

    The encoding is, in order, the tag ``b"ts/nlrs/w1"``, the 4-byte
    unsigned big-endian length ``len(E)`` followed by the raw report
    encoding ``E = encode_nonce_leak_report(seal.report)``,
    ``VARINT(R)``, ``VARINT(z)``, the 4-byte unsigned big-endian signer
    count ``k``, and one ``VARINT(id)`` per ascending signer id. A
    ``VARINT`` is a 4-byte unsigned big-endian body length followed by
    the shortest unsigned big-endian value (zero is the single byte
    ``00``, positive values carry no leading zero); ``R`` must be
    positive and ``z`` may be zero.

    Only a structurally legal :class:`ReportSeal` is accepted: the report
    must be encodable by :func:`encode_nonce_leak_report` and the
    signature an :class:`AggregateSignature` with a positive ``R``, a
    non-negative ``z`` and a non-empty tuple of strictly increasing
    positive ids. The signature is not checked against the report and
    the report's findings are not verified: the output for a given seal
    is unique and the encoding carries no network, storage or hidden
    state. Wrong field types raise TypeError; an illegal report or
    signature structure or an over-long frame raises ValueError.
    """
    _check_report_seal_fields(seal)
    encoded_report = encode_nonce_leak_report(seal.report)
    signature = seal.signature
    signer_count = len(signature.signer_ids)
    if len(encoded_report) > 0xFFFFFFFF:
        raise ValueError("nonce-leak report encoding too long")
    if signer_count > 0xFFFFFFFF:
        raise ValueError("too many signer ids")

    buffer = bytearray(REPORT_SEAL_WIRE_TAG)
    buffer += len(encoded_report).to_bytes(4, "big", signed=False)
    buffer += encoded_report
    buffer += _encode_varint(signature.R)
    buffer += _encode_varint(signature.z)
    buffer += signer_count.to_bytes(4, "big", signed=False)
    for signer_id in signature.signer_ids:
        buffer += _encode_varint(signer_id)
    return bytes(buffer)


def decode_seal(blob: bytes) -> ReportSeal:
    """Decode the canonical encoding produced by :func:`encode_seal`.

    Accepts only the single canonical form: the tag ``b"ts/nlrs/w1"``, a
    4-byte non-zero report length followed by bytes that
    :func:`decode_nonce_leak_report` accepts, the length-prefixed
    integers ``R`` and ``z``, the 4-byte non-zero signer count ``k`` and
    then exactly ``k`` strictly increasing positive signer ids. A
    non-bytes argument raises TypeError; a wrong or missing tag, a zero
    or over-long report length, a non-canonical nested report, a zero
    ``R``, a negative value, a zero or mismatched signer count, a
    non-canonical integer (leading zero or over-long length),
    truncation, or trailing bytes raises ValueError. A successfully
    decoded seal re-encodes to exactly the input bytes.

    Decoding only restores the structure: the nested report is decoded
    with :func:`decode_nonce_leak_report` (which verifies no finding) and
    the signature is not checked. A structurally legal seal whose report
    does not verify or whose signature does not seal it is returned
    normally, and :func:`verify_seal` reports it as ``False``.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not blob.startswith(REPORT_SEAL_WIRE_TAG):
        raise ValueError("bad report seal tag")
    offset = len(REPORT_SEAL_WIRE_TAG)

    encoded_report, offset = _read_audit_proof_block(
        blob, offset, what="sealed nonce-leak report"
    )
    report = decode_nonce_leak_report(encoded_report)

    R, offset = _read_varint(blob, offset, what="report seal signature R")
    z, offset = _read_varint(blob, offset, what="report seal signature z")
    if R == 0:
        raise ValueError("report seal signature R must be positive")

    if offset + 4 > len(blob):
        raise ValueError("truncated report seal signer count")
    signer_count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    if signer_count == 0:
        raise ValueError("report seal must name at least one signer")

    signer_ids = []
    for _ in range(signer_count):
        signer_id, offset = _read_varint(blob, offset, what="report seal signer id")
        if signer_id == 0:
            raise ValueError("report seal signer ids must be positive")
        if signer_ids and signer_id <= signer_ids[-1]:
            raise ValueError(
                "report seal signer ids must be strictly increasing and unique"
            )
        signer_ids.append(signer_id)
    if offset != len(blob):
        raise ValueError("trailing bytes after report seal")

    seal = ReportSeal(
        report=report,
        signature=AggregateSignature(
            R=R, z=z, signer_ids=tuple(signer_ids)
        ),
    )
    if encode_seal(seal) != blob:
        raise ValueError("non-canonical report seal encoding")
    return seal


def verify_seal(seal: ReportSeal, key: SigningDKGResult) -> bool:
    """Verify a report seal against its report and the threshold key.

    ``seal`` must be a structurally legal :class:`ReportSeal` — its
    report encodable by :func:`encode_nonce_leak_report` and its
    signature an :class:`AggregateSignature` with a positive ``R``, a
    non-negative ``z`` and a non-empty tuple of strictly increasing
    positive signer ids — and ``key`` a legal :class:`SigningDKGResult`.
    Wrong field types raise TypeError; an illegal report, signature or
    key structure raises ValueError.

    Every finding of the sealed report is first checked with
    :func:`verify_nonce_leak_report` against ``key``; the canonical
    :func:`seal_message` of the report and ``key.public_key`` is then
    checked as the signature's threshold Schnorr message via
    :func:`verify_signature` with the key's group parameters. Returns
    ``True`` only when both checks pass; a well-formed seal whose report
    contains a bad finding, whose signature was tampered with, or which
    seals another report or key returns ``False``. The function is
    stateless.
    """
    _check_report_seal_fields(seal)
    _result, public_key, field_prime, group_prime, generator = _check_signing_setup(key)
    _check_signing_dkg_structure(key)

    if not verify_nonce_leak_report(seal.report, key):
        return False
    message = seal_message(seal.report, public_key)
    return verify_signature(
        message,
        seal.signature,
        public_key,
        group_prime=group_prime,
        generator=generator,
        prime=field_prime,
    )


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
# Canonical audit-chain transport: a self-delimiting, byte-for-byte
# reproducible encoding of an AuditChain for cross-implementation exchange and
# persistence. Note this tag is distinct from AUDIT_CHAIN_TAG (b"ts/ac/v1"),
# which prefixes the chain *message* the threshold key signs: this framing
# carries the records and the signature themselves and is never signed as a
# whole. Decoding restores structure only — receipts are not decoded and no
# signature is checked, so verify_audit_chain remains the sole verifier.
# ---------------------------------------------------------------------------

AUDIT_CHAIN_WIRE_TAG = b"thresholdsign/audit-chain/v1"


def _check_audit_chain_signature(signature: object) -> int:
    """Type- and structure-check an audit chain's sealing signature.

    The integers and signer set are checked only as the unsigned, ordered
    structures the wire framing needs; nothing here places ``R``/``z`` in a
    group (that takes group parameters and is :func:`verify_signature`'s
    job). ``R`` must be strictly positive (a real commitment is never the
    identity, and the same value is illegal under :func:`verify_signature`),
    while ``z`` may be zero and then encodes as the single body byte ``00``.
    Returns the signer count.
    """
    if not isinstance(signature, AggregateSignature):
        raise TypeError("chain signature must be an AggregateSignature instance")
    if not isinstance(signature.R, int) or isinstance(signature.R, bool):
        raise TypeError("signature.R must be an integer")
    if not isinstance(signature.z, int) or isinstance(signature.z, bool):
        raise TypeError("signature.z must be an integer")
    if not isinstance(signature.signer_ids, tuple):
        raise TypeError("signature.signer_ids must be a tuple")
    try:
        signer_count = len(signature.signer_ids)
    except OverflowError:
        raise ValueError("too many signer ids") from None
    for signer_id in signature.signer_ids:
        if not isinstance(signer_id, int) or isinstance(signer_id, bool):
            raise TypeError("signer ids must be integers")

    if signature.R <= 0:
        raise ValueError("signature R must be positive")
    if signature.z < 0:
        raise ValueError("signature z must be non-negative")
    if signer_count == 0:
        raise ValueError("at least one signer is required")
    for signer_id in signature.signer_ids:
        if signer_id <= 0:
            raise ValueError("signer ids must be positive")
    if any(prev >= next_ for prev, next_ in zip(signature.signer_ids,
                                                signature.signer_ids[1:])):
        raise ValueError("signer ids must be strictly increasing and unique")
    return signer_count


def encode_audit_chain(chain: AuditChain) -> bytes:
    """Canonically encode an audit chain for transport or persistence.

    The encoding starts with the tag ``b"thresholdsign/audit-chain/v1"`` and
    then writes the record count as a 4-byte unsigned big-endian integer, one
    frame per record strictly in ``records`` tuple order, and finally the
    signature frame. A record frame is the 4-byte unsigned big-endian message
    length followed by the raw ``message``, then the 4-byte unsigned
    big-endian receipt length followed by the raw ``SigningAudit.payload``:
    an empty message is allowed but an empty receipt is not, and the chain
    must hold at least one record. The signature frame writes ``R``, ``z``,
    the 4-byte unsigned big-endian ``signer_ids`` count and then the ascending
    signer ids; each integer is a 4-byte unsigned big-endian length followed
    by its shortest unsigned big-endian value (zero is the single byte
    ``00``, positive values carry no leading zero). ``R`` must be positive;
    ``z`` may be zero and then encodes as the single byte ``00``.

    Only a chain whose field types and structure are legal is accepted — the
    records must be a non-empty tuple of ``(bytes, SigningAudit)`` pairs with
    non-empty payloads and the signature an :class:`AggregateSignature` with
    a positive ``R``, non-negative ``z`` and a non-empty tuple of strictly
    increasing positive ids — but neither the receipts nor the signature are
    required to match anything: :func:`verify_audit_chain` stays the way to
    test a chain afterwards. Wrong field types raise TypeError; an empty
    chain, an empty receipt, a non-positive ``R``, a negative ``z``, a
    non-increasing signer id or an over-long frame (including record or
    signer counts that do not fit the 4-byte counters) raises ValueError.
    The output for a given chain is unique and the encoding carries no
    network, storage or hidden state.
    """
    if not isinstance(chain, AuditChain):
        raise TypeError("chain must be an AuditChain instance")
    count = _check_audit_chain_records(chain.records)
    signer_count = _check_audit_chain_signature(chain.signature)
    if count > 0xFFFFFFFF:
        raise ValueError("too many records")
    if signer_count > 0xFFFFFFFF:
        raise ValueError("too many signer ids")

    buffer = bytearray(AUDIT_CHAIN_WIRE_TAG)
    buffer += count.to_bytes(4, "big", signed=False)
    for index, (message, audit) in enumerate(chain.records):
        if not audit.payload:
            raise ValueError(f"record {index + 1} receipt must be non-empty")
        if len(message) > 0xFFFFFFFF:
            raise ValueError(f"record {index + 1} message encoding too long")
        if len(audit.payload) > 0xFFFFFFFF:
            raise ValueError(f"record {index + 1} receipt encoding too long")
        buffer += len(message).to_bytes(4, "big", signed=False)
        buffer += message
        buffer += len(audit.payload).to_bytes(4, "big", signed=False)
        buffer += audit.payload

    signature = chain.signature
    buffer += _encode_varint(signature.R)
    buffer += _encode_varint(signature.z)
    buffer += signer_count.to_bytes(4, "big", signed=False)
    for signer_id in signature.signer_ids:
        buffer += _encode_varint(signer_id)
    return bytes(buffer)


def _read_audit_chain_block(
    stream: bytes, offset: int, *, what: str, allow_empty: bool = False
) -> tuple[bytes, int]:
    """Read one 4-byte-length-prefixed record block body at ``offset``."""
    if offset + 4 > len(stream):
        raise ValueError(f"truncated audit chain {what} length")
    length = int.from_bytes(stream[offset:offset + 4], "big")
    offset += 4
    if length == 0 and not allow_empty:
        raise ValueError(f"audit chain {what} must be non-empty")
    if offset + length > len(stream):
        raise ValueError(f"truncated audit chain {what}")
    return bytes(stream[offset:offset + length]), offset + length


def decode_audit_chain(payload: bytes) -> AuditChain:
    """Decode the canonical encoding produced by :func:`encode_audit_chain`.

    Accepts only the single canonical form: the tag
    ``b"thresholdsign/audit-chain/v1"``, the 4-byte unsigned big-endian
    record count (never zero), that many record frames in order — each a
    4-byte unsigned big-endian message length (which may be zero) followed by
    the raw message, and a 4-byte unsigned big-endian receipt length (never
    zero) followed by the raw ``SigningAudit.payload`` — and then the
    signature frame: ``R`` (which must be positive), ``z`` (which may be
    zero, encoded as the single byte ``00``), the 4-byte unsigned
    big-endian ``signer_ids`` count and the ascending signer ids, each
    integer a 4-byte length-prefixed shortest unsigned big-endian value. A
    non-bytes argument raises TypeError; a wrong or missing tag, an empty
    chain, a zero-length receipt, a count mismatch, truncation, trailing
    bytes, a zero ``R``, an empty, zero, duplicate or non-increasing signer
    id, or a non-canonical integer (leading zero or over-long length)
    raises ValueError. A successfully decoded chain re-encodes to exactly
    the input bytes.

    Decoding only restores the structure: receipt payloads are stored opaque
    and neither they nor the signature are verified, and the chain carries no
    network, storage or hidden state. A structurally legal chain whose
    receipts do not match their messages or whose signature does not seal the
    records is returned normally, and :func:`verify_audit_chain` reports it as
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
        message, offset = _read_audit_chain_block(
            payload,
            offset,
            what=f"record {index + 1} message",
            allow_empty=True,
        )
        receipt, offset = _read_audit_chain_block(
            payload, offset, what=f"record {index + 1} receipt"
        )
        records.append((message, SigningAudit(payload=receipt)))

    R, offset = _read_varint(payload, offset, what="audit chain signature R")
    z, offset = _read_varint(payload, offset, what="audit chain signature z")
    if R == 0:
        raise ValueError("signature R must be positive")

    if offset + 4 > len(payload):
        raise ValueError("truncated audit chain signer count")
    signer_count = int.from_bytes(payload[offset:offset + 4], "big")
    offset += 4
    if signer_count == 0:
        raise ValueError("signer ids must be non-empty")

    signer_ids = []
    for index in range(signer_count):
        signer_id, offset = _read_varint(
            payload, offset, what=f"audit chain signer id {index + 1}"
        )
        if signer_id == 0:
            raise ValueError("signer ids must be positive")
        if signer_ids and signer_id <= signer_ids[-1]:
            raise ValueError("signer ids must be strictly increasing and unique")
        signer_ids.append(signer_id)

    if offset != len(payload):
        raise ValueError("trailing bytes after audit chain")

    chain = AuditChain(
        records=tuple(records),
        signature=AggregateSignature(R=R, z=z, signer_ids=tuple(signer_ids)),
    )
    if encode_audit_chain(chain) != payload:
        raise ValueError("non-canonical audit chain")
    return chain


# ---------------------------------------------------------------------------
# Merkle inclusion proofs over an audit chain's records: a compact proof that
# one ``(message, audit)`` record sits, at a fixed position, in the exact
# non-empty record sequence an AuditChain carries. The tree is SHA256 with
# domain-separated leaf/node prefixes; the record-root statement to sign is
# ``b"am/r" || U64(n) || root``. No state is kept and check_proof re-runs
# check_audit on the leaf record and verify_signature on the sealing
# signature, so a proof certifies both membership and the receipt itself.
# ---------------------------------------------------------------------------

AUDIT_PROOF_LEAF_TAG = b"am/l"
AUDIT_PROOF_NODE_TAG = b"am/n"
AUDIT_PROOF_ROOT_TAG = b"am/r"

AUDIT_PROOF_DIGEST_SIZE = 32  # SHA256 output width; every tree node is this wide


def _audit_proof_u64(value: int) -> bytes:
    """8-byte unsigned big-endian encoding of a non-negative integer < 2**64."""
    return value.to_bytes(8, "big", signed=False)


def _audit_proof_leaf(index: int, message: bytes, audit: SigningAudit) -> bytes:
    """The index-bound leaf digest ``H(b"am/l" || U64(i) || H(m) || H(a.payload))``."""
    return hashlib.sha256(
        AUDIT_PROOF_LEAF_TAG
        + _audit_proof_u64(index)
        + hashlib.sha256(message).digest()
        + hashlib.sha256(audit.payload).digest()
    ).digest()


def _audit_proof_node(left: bytes, right: bytes) -> bytes:
    """The ordered internal digest ``H(b"am/n" || left || right)``."""
    return hashlib.sha256(AUDIT_PROOF_NODE_TAG + left + right).digest()


def _audit_proof_levels(
    records: tuple[tuple[bytes, SigningAudit], ...],
) -> list[tuple[bytes, ...]]:
    """Build the leaf level and every internal level up to the single root.

    A level with an odd tail width is paired with its own last node
    duplicated, so every level above the leaves has an even width.
    """
    levels: list[tuple[bytes, ...]] = [
        tuple(
            _audit_proof_leaf(index, message, audit)
            for index, (message, audit) in enumerate(records)
        )
    ]
    current = levels[0]
    while len(current) > 1:
        if len(current) % 2 == 1:
            current = current + current[-1:]
        current = tuple(
            _audit_proof_node(current[index], current[index + 1])
            for index in range(0, len(current), 2)
        )
        levels.append(current)
    return levels


@dataclass(frozen=True)
class AuditProof:
    """A Merkle inclusion proof for one record of an audit chain.

    The fields, in order, are ``i`` (the non-negative leaf position),
    ``n`` (the total, non-empty record count), ``m`` (the proven record's
    exact message bytes), ``a`` (its :class:`SigningAudit` receipt) and
    ``p`` (the sibling digests on the path from the leaf level up to — but
    not including — the root, each exactly 32 bytes; the tuple is empty
    for a one-record tree). The dataclass is frozen, positionally
    constructible and compared by value, and carries no network, storage
    or hidden state. Field types and bounds are not checked at
    construction time — :func:`check_proof` is the way to test a proof
    afterwards.
    """

    i: int
    n: int
    m: bytes
    a: SigningAudit
    p: tuple[bytes, ...]


def make_proof(
    records: tuple[tuple[bytes, SigningAudit], ...], index: int
) -> tuple[bytes, AuditProof]:
    """Build the root statement and a leaf inclusion proof for one record.

    ``records`` must be the same non-empty, order-preserving tuple of
    ``(message, SigningAudit)`` pairs an :class:`AuditChain` seals and
    ``index`` the leaf position to prove. The tree uses SHA256 with leaves
    ``H(b"am/l" || U64(i) || H(message) || H(audit.payload))`` and internal
    nodes ``H(b"am/n" || left || right)``; a level with an odd tail width
    duplicates its last node for pairing. Returns ``(message, proof)`` where
    ``message`` is ``b"am/r" || U64(n) || root`` (the 8-byte unsigned
    big-endian record count followed by the 32-byte root) — the bytes to be
    threshold-signed — and ``proof`` is the :class:`AuditProof` for leaf
    ``index`` whose ``p`` lists the 32-byte sibling digests from the leaf
    level up to the root.

    Wrong argument types raise TypeError: a non-tuple record sequence, a
    malformed record (exactly the rules of :func:`audit_chain_payload`), or
    a non-integer (including boolean) index. An empty record sequence, a
    record count that does not fit the 8-byte counter, or an index outside
    ``0 <= i < n`` raises ValueError.
    """
    if not isinstance(index, int) or isinstance(index, bool):
        raise TypeError("index must be an integer")
    count = _check_audit_chain_records(records)
    if count > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("too many records")
    if index < 0 or index >= count:
        raise ValueError("index out of range")

    levels = _audit_proof_levels(records)
    try:
        message, audit = records[index]
    except IndexError:
        raise ValueError("index out of range") from None

    path = []
    position = index
    for level in levels[:-1]:
        width = len(level)
        padded = level if width % 2 == 0 else level + level[-1:]
        path.append(padded[position ^ 1])
        position //= 2

    root = levels[-1][0]
    proof = AuditProof(
        i=index, n=count, m=message, a=audit, p=tuple(path)
    )
    return AUDIT_PROOF_ROOT_TAG + _audit_proof_u64(count) + root, proof


def _validate_audit_proof_structure(
    proof: object,
) -> tuple[int, int, bytes, SigningAudit, tuple[bytes, ...]]:
    """Type- and structure-check an :class:`AuditProof`, returning its fields.

    Shared by :func:`check_proof` and the wire codec. Only the container
    structure is checked: the receipt payload is kept opaque and neither it
    nor the path is parsed or cryptographically verified here. The bounds are
    ``0 < n < 2**64`` and ``0 <= i < n``; the path must hold exactly
    ``(n - 1).bit_length()`` entries, each 32 bytes, and the receipt payload
    must be non-empty (the message may be empty). Wrong field types raise
    TypeError; illegal bounds, an empty receipt or a bad path shape raise
    ValueError.
    """
    if not isinstance(proof, AuditProof):
        raise TypeError("proof must be an AuditProof instance")
    index = proof.i
    count = proof.n
    message = proof.m
    audit = proof.a
    path = proof.p
    if not isinstance(index, int) or isinstance(index, bool):
        raise TypeError("proof.i must be an integer")
    if not isinstance(count, int) or isinstance(count, bool):
        raise TypeError("proof.n must be an integer")
    if not isinstance(message, bytes):
        raise TypeError("proof.m must be bytes")
    if not isinstance(audit, SigningAudit):
        raise TypeError("proof.a must be a SigningAudit instance")
    if not isinstance(audit.payload, bytes):
        raise TypeError("proof.a payload must be bytes")
    if not isinstance(path, tuple):
        raise TypeError("proof.p must be a tuple")
    for sibling in path:
        if not isinstance(sibling, bytes):
            raise TypeError("proof.p entries must be bytes")

    if count <= 0:
        raise ValueError("proof.n must be positive")
    if count > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("too many records")
    if index < 0 or index >= count:
        raise ValueError("proof.i out of range")
    if not audit.payload:
        raise ValueError("proof.a payload must be non-empty")
    expected_depth = (count - 1).bit_length()
    if len(path) != expected_depth:
        raise ValueError("proof.p has the wrong length for proof.n")
    for sibling in path:
        if len(sibling) != AUDIT_PROOF_DIGEST_SIZE:
            raise ValueError("proof.p entries must be exactly 32 bytes")
    return index, count, message, audit, path


def check_proof(
    proof: AuditProof,
    signature: AggregateSignature,
    key: SigningDKGResult,
) -> bool:
    """Rebuild a proof's Merkle root and verify its record and sealing signature.

    The leaf digest is recomputed from ``proof.i``, ``proof.m`` and
    ``proof.a`` exactly as in :func:`make_proof`, and the root is rebuilt
    level by level while tracking the current level's width. At each level
    the current position is paired by its parity — an even position is
    hashed on the left, an odd position on the right — except for an odd
    tail: when the level has odd width and the current node is its last
    member it has no companion, so it is paired with itself
    (``H(node, node)``), exactly the last-node duplication the tree builder
    uses; the supplied sibling at that level is then irrelevant. The width
    for the next level is ``(width + 1) // 2``. The embedded record is then
    re-checked with :func:`check_audit` against ``key``, and the statement
    ``b"am/r" || U64(n) || root`` is checked as ``signature``'s threshold
    Schnorr message via :func:`verify_signature`. Returns ``True`` only when
    the rebuilt root matches the signed statement, the receipt matches its
    message and the key, and the signature verifies; a well-formed proof
    whose root, record or signature was tampered with, or which is presented
    under another key, returns ``False``.

    A non-:class:`AuditProof` or non-:class:`AggregateSignature` argument
    or any wrong field type (non-integer ``i``/``n`` including booleans,
    non-bytes message, non-:class:`SigningAudit` receipt, a non-tuple path
    or non-bytes path entry) raises TypeError; a non-positive or
    over-64-bit ``n``, an out-of-range ``i``, an empty receipt, a path
    entry that is not exactly 32 bytes, a path whose length does not fit
    ``n``, or a structurally illegal receipt, signature or ``key`` raises
    ValueError, exactly as :func:`check_audit` and
    :func:`verify_signature` would.
    """
    index, count, message, audit, path = _validate_audit_proof_structure(proof)
    if not isinstance(signature, AggregateSignature):
        raise TypeError("signature must be an AggregateSignature instance")

    _result, public_key, field_prime, group_prime, generator = _check_signing_setup(key)
    _check_signing_dkg_structure(key)

    node = _audit_proof_leaf(index, message, audit)
    position = index
    width = count
    for sibling in path:
        if width % 2 == 1 and position == width - 1:
            # Odd tail with no companion: pair the node with itself, as the
            # tree builder duplicated its last node for pairing.
            node = _audit_proof_node(node, node)
        elif position % 2 == 0:
            node = _audit_proof_node(node, sibling)
        else:
            node = _audit_proof_node(sibling, node)
        position //= 2
        width = (width + 1) // 2

    signed_message = AUDIT_PROOF_ROOT_TAG + _audit_proof_u64(count) + node
    if not check_audit(message, audit, key):
        return False
    return verify_signature(
        signed_message,
        signature,
        public_key,
        group_prime=group_prime,
        generator=generator,
        prime=field_prime,
    )


# ---------------------------------------------------------------------------
# Compact multi-record inclusion proofs: one root signature certifies that
# several disclosed records belong to the same ordered, indexed set. The tree
# is exactly make_proof's tree; a single AuditMultiProof carries only the
# siblings that are not themselves disclosed records (or odd-tail self-pairs),
# so the whole set can be audited from one signature without hidden state.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuditMultiProof:
    """A compact Merkle inclusion proof for several records at once.

    The fields, in order, are ``indices`` (the proven leaf positions as a
    non-empty tuple of strictly increasing, unique non-negative integers),
    ``n`` (the total, non-empty record count), ``records`` (the proven
    records, one ``(message, SigningAudit)`` pair per entry of
    ``indices``, in the same order) and ``siblings`` (the 32-byte sibling
    digests consumed from the leaf level up to the root, in ascending level
    order; the tuple is empty when no companion digests are needed). The
    dataclass is frozen, positionally constructible and compared by value,
    and carries no network, storage or hidden state. Field types and bounds
    are not checked at construction time — :func:`check_multi_proof` is the
    way to test a proof afterwards.
    """

    indices: tuple[int, ...]
    n: int
    records: tuple[tuple[bytes, SigningAudit], ...]
    siblings: tuple[bytes, ...]


def make_multi_proof(
    records: tuple[tuple[bytes, SigningAudit], ...],
    indices: tuple[int, ...],
) -> tuple[bytes, AuditMultiProof]:
    """Build the root statement and a compact inclusion proof for several records.

    ``records`` must be the same non-empty, order-preserving tuple of
    ``(message, SigningAudit)`` pairs an :class:`AuditChain` seals, with
    ``n == len(records)``, and ``indices`` a non-empty tuple of leaf
    positions to prove. The tree is exactly :func:`make_proof`'s tree.
    Returns ``(message, proof)`` where ``message`` is
    ``b"am/r" || U64(n) || root`` — the bytes to be threshold-signed — and
    ``proof`` is the :class:`AuditMultiProof` whose ``records`` pair up one
    to one with ``indices``. Its ``siblings`` are collected level by level,
    in ascending level order (leaves upward), one entry per needed
    companion: at a level a position is paired left to right; when the
    companion position is itself a proven node carried in the proof, or the
    node is the last member of an odd-width level (which the tree pairs with
    itself), no sibling is appended; otherwise the companion digest is.
    Proven nodes from lower levels feed the level above exactly as in the
    tree, so no digest is sent twice.

    Wrong argument types raise TypeError: a non-tuple record sequence or
    index sequence, a non-integer (including boolean) index, or a malformed
    record (exactly the rules of :func:`audit_chain_payload`). An empty
    record sequence or index tuple, a record count that does not fit the
    8-byte counter, indices that are not strictly increasing and unique, or
    an index outside ``0 <= i < n`` raises ValueError.
    """
    if not isinstance(indices, tuple):
        raise TypeError("indices must be a tuple")
    count = _check_audit_chain_records(records)
    if count > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("too many records")
    if len(indices) == 0:
        raise ValueError("indices must be non-empty")
    previous = -1
    for index in indices:
        if not isinstance(index, int) or isinstance(index, bool):
            raise TypeError("each index must be an integer")
        if index <= previous:
            raise ValueError("indices must be strictly increasing and unique")
        if index < 0 or index >= count:
            raise ValueError("index out of range")
        previous = index

    levels = _audit_proof_levels(records)

    siblings: list[bytes] = []
    positions = set(indices)
    for level in levels[:-1]:
        width = len(level)
        padded = level if width % 2 == 0 else level + level[-1:]
        next_positions = set()
        for position in sorted(positions):
            if width % 2 == 1 and position == width - 1:
                # Odd tail with no companion: the tree pairs it with itself.
                pass
            elif (position ^ 1) in positions:
                # The companion is itself a disclosed node; nothing to send.
                pass
            else:
                siblings.append(padded[position ^ 1])
            next_positions.add(position // 2)
        positions = next_positions

    root = levels[-1][0]
    proof_records = tuple(records[index] for index in indices)
    proof = AuditMultiProof(
        indices=tuple(indices),
        n=count,
        records=proof_records,
        siblings=tuple(siblings),
    )
    return AUDIT_PROOF_ROOT_TAG + _audit_proof_u64(count) + root, proof


def _required_multi_proof_siblings(count: int, indices: tuple[int, ...]) -> int:
    """Number of 32-byte companion digests a multi-proof for ``count`` leaves must carry.

    Replays :func:`make_multi_proof`'s level walk structurally: at each level
    a proven node needs a sibling unless it is the odd-width tail (paired
    with itself) or its companion is itself a proven node at that level. The
    answer depends only on ``n`` and the disclosed positions — never on the
    records or the digests — so it is the unique sibling count both encoders
    and decoders can demand.
    """
    required = 0
    positions = set(indices)
    width = count
    while width > 1:
        next_positions = set()
        for position in sorted(positions):
            if width % 2 == 1 and position == width - 1:
                # Odd tail with no companion: the tree pairs it with itself.
                pass
            elif (position ^ 1) in positions:
                # The companion is itself a disclosed node; nothing to send.
                pass
            else:
                required += 1
            next_positions.add(position // 2)
        positions = next_positions
        width = (width + 1) // 2
    return required


def _validate_audit_multi_proof_structure(
    proof: object,
) -> tuple[tuple[int, ...], int, tuple[tuple[bytes, SigningAudit], ...], tuple[bytes, ...]]:
    """Type- and structure-check an :class:`AuditMultiProof`, returning its fields.

    Only the container structure is checked: the receipt payloads are kept
    opaque and neither they nor the siblings are cryptographically verified
    here. The bounds are ``0 < n < 2**64``, a non-empty
    ``indices``/``records`` pair of equal length with strictly increasing
    indices in ``0 <= i < n`` and well-formed ``(bytes, SigningAudit)``
    records with non-empty payloads, and a siblings tuple whose entries are
    exactly 32 bytes. Wrong field types raise TypeError; illegal bounds or
    shapes raise ValueError. The number of siblings is derived uniquely from
    ``n`` and ``indices`` (the compact walk sends one companion per proven
    node that is neither an odd tail nor paired with another proven node), so
    a missing or extra sibling raises ValueError here — before any root is
    rebuilt.
    """
    if not isinstance(proof, AuditMultiProof):
        raise TypeError("proof must be an AuditMultiProof instance")
    indices = proof.indices
    count = proof.n
    proof_records = proof.records
    siblings = proof.siblings
    if not isinstance(indices, tuple):
        raise TypeError("proof.indices must be a tuple")
    if not isinstance(count, int) or isinstance(count, bool):
        raise TypeError("proof.n must be an integer")
    if not isinstance(proof_records, tuple):
        raise TypeError("proof.records must be a tuple")
    if not isinstance(siblings, tuple):
        raise TypeError("proof.siblings must be a tuple")

    if count <= 0:
        raise ValueError("proof.n must be positive")
    if count > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("too many records")
    if len(indices) == 0:
        raise ValueError("proof.indices must be non-empty")
    if len(indices) != len(proof_records):
        raise ValueError("proof.records must pair one-to-one with proof.indices")

    previous = -1
    for index in indices:
        if not isinstance(index, int) or isinstance(index, bool):
            raise TypeError("proof.indices entries must be integers")
        if index <= previous:
            raise ValueError("proof.indices must be strictly increasing and unique")
        if index < 0 or index >= count:
            raise ValueError("proof.indices entry out of range")
        previous = index

    for record in proof_records:
        if not isinstance(record, tuple) or len(record) != 2:
            raise TypeError("each proof record must be a (message, audit) tuple")
        message, audit = record
        if not isinstance(message, bytes):
            raise TypeError("proof record message must be bytes")
        if not isinstance(audit, SigningAudit):
            raise TypeError("proof record audit must be a SigningAudit instance")
        if not isinstance(audit.payload, bytes):
            raise TypeError("proof record audit payload must be bytes")
        if not audit.payload:
            raise ValueError("proof record audit payload must be non-empty")

    for sibling in siblings:
        if not isinstance(sibling, bytes):
            raise TypeError("proof.siblings entries must be bytes")
    for sibling in siblings:
        if len(sibling) != AUDIT_PROOF_DIGEST_SIZE:
            raise ValueError("proof.siblings entries must be exactly 32 bytes")
    required_siblings = _required_multi_proof_siblings(count, indices)
    if len(siblings) != required_siblings:
        raise ValueError(
            "proof.siblings count is not the one determined by n and indices"
        )
    return indices, count, proof_records, siblings


def check_multi_proof(
    proof: AuditMultiProof,
    signature: AggregateSignature,
    key: SigningDKGResult,
) -> bool:
    """Rebuild a multi-proof's Merkle root and verify its records and signature.

    Every disclosed record's leaf digest is recomputed from its position and
    ``(message, audit)`` exactly as in :func:`make_proof`. The root is then
    rebuilt level by level while consuming ``proof.siblings`` in ascending
    level order: the current level holds the digests of the proven nodes at
    their current positions, paired left to right; when a companion is
    itself a current-level node its digest is used directly, when the node
    is the last member of an odd-width level it is paired with itself, and
    otherwise the next 32-byte entry of ``siblings`` is consumed. The
    current width contracts as ``(width + 1) // 2``. Every embedded record
    is re-checked with :func:`check_audit` against ``key`` (in index order),
    and the statement ``b"am/r" || U64(n) || root`` is checked as
    ``signature``'s threshold Schnorr message via :func:`verify_signature`.
    Returns ``True`` only when the rebuild consumes every sibling exactly
    and reaches the single signed root, every receipt matches its message
    and the key, and the signature verifies; a well-formed proof whose
    records, indices, siblings, root or signature was tampered with —
    records swapped or altered, a missing, extra or misplaced sibling — or
    which is presented under another key, returns ``False``.

    A non-:class:`AuditMultiProof` or non-:class:`AggregateSignature`
    argument or any wrong field type (non-tuple indices/records/siblings, a
    non-integer ``n`` or index including booleans, a non-bytes record
    message or sibling, a non-:class:`SigningAudit` receipt) raises
    TypeError; a non-positive or over-64-bit ``n``, empty indices, an index
    out of range or not strictly increasing, a records tuple that does not
    pair one-to-one with the indices, an empty receipt, a sibling that is
    not exactly 32 bytes, too few or too many siblings for the indicated
    positions, or a structurally illegal receipt, signature or ``key``
    raises ValueError, exactly as :func:`check_audit` and
    :func:`verify_signature` would.
    """
    indices, count, proof_records, siblings = _validate_audit_multi_proof_structure(proof)
    if not isinstance(signature, AggregateSignature):
        raise TypeError("signature must be an AggregateSignature instance")

    _result, public_key, field_prime, group_prime, generator = _check_signing_setup(key)
    _check_signing_dkg_structure(key)

    nodes = {
        index: _audit_proof_leaf(index, message, audit)
        for index, (message, audit) in zip(indices, proof_records)
    }
    pending = iter(siblings)
    width = count
    while width > 1:
        next_nodes = {}
        for position in sorted(nodes):
            parent = position // 2
            if parent in next_nodes:
                continue
            if width % 2 == 1 and position == width - 1:
                # Odd tail with no companion: pair the node with itself.
                next_nodes[parent] = _audit_proof_node(nodes[position], nodes[position])
            elif (position ^ 1) in nodes:
                left = position if position % 2 == 0 else position ^ 1
                next_nodes[parent] = _audit_proof_node(nodes[left], nodes[left ^ 1])
            else:
                try:
                    sibling = next(pending)
                except StopIteration:
                    raise ValueError("proof.siblings is missing entries") from None
                if position % 2 == 0:
                    next_nodes[parent] = _audit_proof_node(nodes[position], sibling)
                else:
                    next_nodes[parent] = _audit_proof_node(sibling, nodes[position])
        nodes = next_nodes
        width = (width + 1) // 2

    try:
        next(pending)
    except StopIteration:
        pass
    else:
        raise ValueError("proof.siblings has extra entries")

    signed_message = AUDIT_PROOF_ROOT_TAG + _audit_proof_u64(count) + nodes[0]
    for (message, audit) in proof_records:
        if not check_audit(message, audit, key):
            return False
    return verify_signature(
        signed_message,
        signature,
        public_key,
        group_prime=group_prime,
        generator=generator,
        prime=field_prime,
    )


# ---------------------------------------------------------------------------
# Canonical audit-proof transport: a self-delimiting, byte-for-byte
# reproducible encoding of an AuditProof for cross-implementation exchange and
# persistence. Decoding restores structure only — the receipt is not parsed,
# no signature is checked and no state is kept, so check_proof remains the
# sole verifier afterwards.
# ---------------------------------------------------------------------------

AUDIT_PROOF_WIRE_TAG = b"thresholdsign/audit-proof/v1"


def encode_audit_proof(proof: AuditProof) -> bytes:
    """Canonically encode an audit proof for transport or persistence.

    The encoding is the direct concatenation, in order, of the tag
    ``b"thresholdsign/audit-proof/v1"``, ``VARINT(i)`` and ``VARINT(n)``, the
    message frame, the receipt frame, the path count as a 4-byte unsigned
    big-endian integer and then the raw 32-byte path entries. A ``VARINT`` is
    a 4-byte unsigned big-endian body length followed by the shortest
    unsigned big-endian value (zero is the single byte ``00`` and positive
    values carry no leading zero); each frame is a 4-byte unsigned big-endian
    length followed by the raw bytes. The message may be empty but the
    receipt must be non-empty, ``n`` must satisfy ``0 < n < 2**64`` and
    ``i`` must satisfy ``0 <= i < n``, and the path count must be
    ``(n - 1).bit_length()`` entries of exactly 32 bytes.

    Only a structurally legal :class:`AuditProof` is accepted — wrong field
    types raise TypeError and illegal bounds, an empty receipt, a bad path
    shape or an over-long frame raise ValueError, exactly as
    :func:`check_proof`'s structural checks do — but the receipt is not
    parsed and no signature is checked: :func:`check_proof` stays the way to
    verify a proof afterwards. The output for a given proof is unique and
    the encoding carries no network, storage or hidden state.
    """
    if not isinstance(proof, AuditProof):
        raise TypeError("proof must be an AuditProof instance")
    index, count, message, audit, path = _validate_audit_proof_structure(proof)
    if len(message) > 0xFFFFFFFF:
        raise ValueError("message encoding too long")
    if len(audit.payload) > 0xFFFFFFFF:
        raise ValueError("receipt encoding too long")

    buffer = bytearray(AUDIT_PROOF_WIRE_TAG)
    buffer += _encode_varint(index)
    buffer += _encode_varint(count)
    buffer += len(message).to_bytes(4, "big", signed=False)
    buffer += message
    buffer += len(audit.payload).to_bytes(4, "big", signed=False)
    buffer += audit.payload
    buffer += len(path).to_bytes(4, "big", signed=False)
    for sibling in path:
        buffer += sibling
    return bytes(buffer)


def _read_audit_proof_block(
    stream: bytes, offset: int, *, what: str, allow_empty: bool = False
) -> tuple[bytes, int]:
    """Read one 4-byte-length-prefixed proof frame body at ``offset``."""
    if offset + 4 > len(stream):
        raise ValueError(f"truncated audit proof {what} length")
    length = int.from_bytes(stream[offset:offset + 4], "big")
    offset += 4
    if length == 0 and not allow_empty:
        raise ValueError(f"audit proof {what} must be non-empty")
    if offset + length > len(stream):
        raise ValueError(f"truncated audit proof {what}")
    return bytes(stream[offset:offset + length]), offset + length


def decode_audit_proof(payload: bytes) -> AuditProof:
    """Decode the canonical encoding produced by :func:`encode_audit_proof`.

    Accepts only the single canonical form: the tag
    ``b"thresholdsign/audit-proof/v1"``, the length-prefixed integers ``i``
    and ``n`` (each a 4-byte unsigned big-endian length followed by its
    shortest unsigned big-endian value, zero encoded as the single byte
    ``00``), the message frame (a 4-byte length, possibly zero, followed by
    the raw message), the receipt frame (a 4-byte non-zero length followed by
    the raw receipt bytes), the 4-byte path count and then exactly that many
    raw 32-byte path entries. A non-bytes argument raises TypeError; a wrong
    or missing tag, an empty receipt, an out-of-range ``i``, an over-64-bit
    ``n``, a non-canonical integer (leading zero or over-long length),
    truncation, trailing bytes, or a path count that does not equal
    ``(n - 1).bit_length()`` (including entries that are not exactly 32
    bytes) raises ValueError. A successfully decoded proof re-encodes to
    exactly the input bytes.

    Decoding only restores the structure: the receipt is stored opaque and
    is neither parsed nor verified, no signature is checked and no state is
    kept. A structurally legal proof whose receipt does not match its
    message or whose sealing signature is invalid is returned normally, and
    :func:`check_proof` reports it as ``False``.
    """
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    if not payload.startswith(AUDIT_PROOF_WIRE_TAG):
        raise ValueError("bad audit proof tag")
    offset = len(AUDIT_PROOF_WIRE_TAG)

    index, offset = _read_varint(payload, offset, what="audit proof i")
    count, offset = _read_varint(payload, offset, what="audit proof n")
    message, offset = _read_audit_proof_block(
        payload, offset, what="message", allow_empty=True
    )
    receipt, offset = _read_audit_proof_block(payload, offset, what="receipt")

    if offset + 4 > len(payload):
        raise ValueError("truncated audit proof path count")
    path_count = int.from_bytes(payload[offset:offset + 4], "big")
    offset += 4
    path = []
    for _ in range(path_count):
        if offset + AUDIT_PROOF_DIGEST_SIZE > len(payload):
            raise ValueError("truncated audit proof path")
        path.append(bytes(payload[offset:offset + AUDIT_PROOF_DIGEST_SIZE]))
        offset += AUDIT_PROOF_DIGEST_SIZE
    if offset != len(payload):
        raise ValueError("trailing bytes after audit proof")

    proof = AuditProof(
        i=index,
        n=count,
        m=message,
        a=SigningAudit(payload=receipt),
        p=tuple(path),
    )
    _validate_audit_proof_structure(proof)
    if encode_audit_proof(proof) != payload:
        raise ValueError("non-canonical audit proof")
    return proof


# ---------------------------------------------------------------------------
# Canonical audit-proof bundle transport: a self-delimiting, byte-for-byte
# reproducible encoding of an AuditProof together with the AggregateSignature
# on its b"am/r" || U64(n) || root statement, for cross-implementation
# exchange and persistence. Decoding restores structure only — the nested
# proof goes through decode_audit_proof, its receipt is not parsed and no
# signature is checked, so verify_audit_proof_bundle remains the sole
# verifier afterwards.
# ---------------------------------------------------------------------------

AUDIT_PROOF_BUNDLE_WIRE_TAG = b"ts/apb/v1"


@dataclass(frozen=True)
class AuditProofBundle:
    """A single-record audit proof together with its root signature.

    The fields, in order, are ``proof`` (an :class:`AuditProof`) and
    ``signature`` (the :class:`AggregateSignature` on the proof's
    ``b"am/r" || U64(n) || root`` statement). The dataclass is frozen,
    positionally constructible and compared by value, and carries no
    network, storage or hidden state. Field types and bounds are not
    checked at construction time — :func:`encode_audit_proof_bundle`
    checks the structure and :func:`verify_audit_proof_bundle` is the
    way to test a bundle afterwards.
    """

    proof: AuditProof
    signature: AggregateSignature


def encode_audit_proof_bundle(bundle: AuditProofBundle) -> bytes:
    """Canonically encode an audit proof bundle for transport or persistence.

    The encoding is, in order, the tag ``b"ts/apb/v1"``, the 4-byte
    unsigned big-endian length ``len(P)`` followed by
    ``P = encode_audit_proof(bundle.proof)`` (never empty), and then the
    signature frame: ``VARINT(R)``, ``VARINT(z)``, the 4-byte unsigned
    big-endian signer count ``k`` and one ``VARINT(id)`` per ascending
    signer id. A ``VARINT`` is a 4-byte unsigned big-endian body length
    followed by the shortest unsigned big-endian value (zero is the
    single byte ``00``, positive values carry no leading zero); ``R``
    must be positive and ``z`` may be zero.

    Only a structurally legal :class:`AuditProofBundle` is accepted
    — a non-bundle or non-:class:`AuditProof` proof argument, or
    wrong proof/signature field types, raise TypeError and illegal proof
    or signature structure (the exact bounds of
    :func:`encode_audit_proof`, a non-positive ``R``, a negative ``z``,
    an empty or non-strictly-increasing signer id tuple) or an over-long
    frame raises ValueError, exactly as :func:`check_proof`'s
    structural checks do — but the receipt is not parsed and the
    signature is not checked against the root:
    :func:`verify_audit_proof_bundle` stays the way to verify a bundle
    afterwards. The output for a given bundle is unique and the encoding
    carries no network, storage or hidden state.
    """
    if not isinstance(bundle, AuditProofBundle):
        raise TypeError("bundle must be an AuditProofBundle instance")
    if not isinstance(bundle.proof, AuditProof):
        raise TypeError("bundle.proof must be an AuditProof instance")
    encoded_proof = encode_audit_proof(bundle.proof)
    signer_count = _check_history_proof_bundle_signature(bundle.signature)
    if len(encoded_proof) > 0xFFFFFFFF:
        raise ValueError("audit proof encoding too long")
    if signer_count > 0xFFFFFFFF:
        raise ValueError("too many signer ids")

    buffer = bytearray(AUDIT_PROOF_BUNDLE_WIRE_TAG)
    buffer += len(encoded_proof).to_bytes(4, "big", signed=False)
    buffer += encoded_proof
    buffer += _encode_varint(bundle.signature.R)
    buffer += _encode_varint(bundle.signature.z)
    buffer += signer_count.to_bytes(4, "big", signed=False)
    for signer_id in bundle.signature.signer_ids:
        buffer += _encode_varint(signer_id)
    return bytes(buffer)


def decode_audit_proof_bundle(blob: bytes) -> AuditProofBundle:
    """Decode the canonical encoding produced by :func:`encode_audit_proof_bundle`.

    Accepts only the single canonical form: the tag ``b"ts/apb/v1"``, a
    4-byte non-zero frame length followed by bytes that
    :func:`decode_audit_proof` accepts, the length-prefixed integers
    ``R`` and ``z``, the 4-byte non-zero signer count ``k`` and then
    exactly ``k`` strictly increasing positive signer ids. A non-bytes
    argument raises TypeError; a wrong or missing tag, a zero or
    over-long proof frame length, a non-canonical nested proof, a zero
    ``R``, a non-canonical integer (leading zero or over-long length), a
    zero signer count, a non-positive or non-increasing signer id,
    truncation, or trailing bytes raises ValueError. A successfully
    decoded bundle re-encodes to exactly the input bytes.

    Decoding only restores the structure: the nested proof is decoded
    with :func:`decode_audit_proof` (which keeps the receipt opaque and
    verifies nothing) and the signature is not checked. A structurally
    legal bundle whose receipt does not match its message or whose
    signature does not sign the root is returned normally, and
    :func:`verify_audit_proof_bundle` reports it as ``False``.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not blob.startswith(AUDIT_PROOF_BUNDLE_WIRE_TAG):
        raise ValueError("bad audit proof bundle tag")
    offset = len(AUDIT_PROOF_BUNDLE_WIRE_TAG)

    encoded_proof, offset = _read_audit_proof_block(
        blob, offset, what="audit proof bundle proof"
    )
    proof = decode_audit_proof(encoded_proof)

    R, offset = _read_varint(
        blob, offset, what="audit proof bundle signature R"
    )
    z, offset = _read_varint(
        blob, offset, what="audit proof bundle signature z"
    )
    if R == 0:
        raise ValueError("audit proof bundle signature R must be positive")

    if offset + 4 > len(blob):
        raise ValueError("truncated audit proof bundle signer count")
    signer_count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    if signer_count == 0:
        raise ValueError("audit proof bundle must name at least one signer")

    signer_ids = []
    for _ in range(signer_count):
        signer_id, offset = _read_varint(
            blob,
            offset,
            what="audit proof bundle signer id",
        )
        if signer_id == 0:
            raise ValueError("audit proof bundle signer ids must be positive")
        if signer_ids and signer_id <= signer_ids[-1]:
            raise ValueError(
                "audit proof bundle signer ids must be strictly "
                "increasing and unique"
            )
        signer_ids.append(signer_id)
    if offset != len(blob):
        raise ValueError("trailing bytes after audit proof bundle")

    bundle = AuditProofBundle(
        proof=proof,
        signature=AggregateSignature(R=R, z=z, signer_ids=tuple(signer_ids)),
    )
    if encode_audit_proof_bundle(bundle) != blob:
        raise ValueError("non-canonical audit proof bundle encoding")
    return bundle


def verify_audit_proof_bundle(
    bundle: AuditProofBundle, key: SigningDKGResult
) -> bool:
    """Verify a bundle exactly as :func:`check_proof` would.

    This is a convenience wrapper over
    ``check_proof(bundle.proof, bundle.signature, key)``: the Merkle
    root is rebuilt from the proof, the embedded record re-checked with
    :func:`check_audit` and the signature verified on
    ``b"am/r" || U64(n) || root``. Returns ``True`` only when all of
    them hold; a well-formed bundle with a tampered record, receipt,
    path or signature, or one presented under another key, returns
    ``False``.

    A non-:class:`AuditProofBundle` argument raises TypeError;
    illegal nested proof, signature or key structure raises
    TypeError/ValueError, exactly as :func:`check_proof` does.
    """
    if not isinstance(bundle, AuditProofBundle):
        raise TypeError("bundle must be an AuditProofBundle instance")
    return check_proof(bundle.proof, bundle.signature, key)


# ---------------------------------------------------------------------------
# Canonical audit-multi-proof transport: a self-delimiting, byte-for-byte
# reproducible encoding of an AuditMultiProof for cross-implementation
# exchange and persistence. Decoding restores structure only — the receipts
# are not parsed, no signature is checked and no state is kept, so
# check_multi_proof remains the sole verifier afterwards.
# ---------------------------------------------------------------------------

AUDIT_MULTI_PROOF_WIRE_TAG = b"thresholdsign/audit-multi-proof/v1"


def encode_audit_multi_proof(proof: AuditMultiProof) -> bytes:
    """Canonically encode a multi-record audit proof for transport or storage.

    The encoding is the direct concatenation, in order, of the tag
    ``b"thresholdsign/audit-multi-proof/v1"``, ``VARINT(n)``, the index count
    as a 4-byte unsigned big-endian integer, one ``VARINT(index)`` per proven
    leaf in the proof's strictly increasing order, the record count as a
    4-byte unsigned big-endian integer, one frame pair per record — a
    4-byte unsigned big-endian message length followed by the raw message
    bytes (possibly empty), then a 4-byte unsigned big-endian receipt length
    followed by the raw ``SigningAudit.payload`` bytes (non-empty) — and
    finally the sibling count as a 4-byte unsigned big-endian integer
    followed by the raw 32-byte sibling digests in their original order. A
    ``VARINT`` is a 4-byte unsigned big-endian body length followed by the
    shortest unsigned big-endian value (zero is the single byte ``00`` and
    positive values carry no leading zero).

    Only a structurally legal :class:`AuditMultiProof` is accepted — a
    non-proof or wrong field types raise TypeError and illegal bounds, an
    empty index tuple, a record tuple that does not pair one-to-one with the
    indices, an empty receipt, a sibling that is not exactly 32 bytes, or a
    sibling count other than the unique one derived from ``n`` and the
    indices raise ValueError, exactly as :func:`check_multi_proof`'s
    structural checks do — but the receipts are not parsed and no signature
    is checked: :func:`check_multi_proof` stays the way to verify a proof
    afterwards. The output for a given proof is unique and the encoding
    carries no network, storage or hidden state.
    """
    if not isinstance(proof, AuditMultiProof):
        raise TypeError("proof must be an AuditMultiProof instance")
    indices, count, proof_records, siblings = _validate_audit_multi_proof_structure(proof)
    if len(indices) > 0xFFFFFFFF:
        raise ValueError("too many indices")
    if len(siblings) > 0xFFFFFFFF:
        raise ValueError("too many siblings")
    for message, audit in proof_records:
        if len(message) > 0xFFFFFFFF:
            raise ValueError("message encoding too long")
        if len(audit.payload) > 0xFFFFFFFF:
            raise ValueError("receipt encoding too long")

    buffer = bytearray(AUDIT_MULTI_PROOF_WIRE_TAG)
    buffer += _encode_varint(count)
    buffer += len(indices).to_bytes(4, "big", signed=False)
    for index in indices:
        buffer += _encode_varint(index)
    buffer += len(proof_records).to_bytes(4, "big", signed=False)
    for message, audit in proof_records:
        buffer += len(message).to_bytes(4, "big", signed=False)
        buffer += message
        buffer += len(audit.payload).to_bytes(4, "big", signed=False)
        buffer += audit.payload
    buffer += len(siblings).to_bytes(4, "big", signed=False)
    for sibling in siblings:
        buffer += sibling
    return bytes(buffer)


def decode_audit_multi_proof(payload: bytes) -> AuditMultiProof:
    """Decode the canonical encoding produced by :func:`encode_audit_multi_proof`.

    Accepts only the single canonical form: the tag
    ``b"thresholdsign/audit-multi-proof/v1"``, the length-prefixed integer
    ``n`` (a 4-byte unsigned big-endian length followed by its shortest
    unsigned big-endian value, zero encoded as the single byte ``00``), the
    4-byte index count followed by one canonical ``VARINT`` per strictly
    increasing index, the 4-byte record count (which must equal the index
    count) followed by that many message frames (a 4-byte length, possibly
    zero, followed by the raw message) and receipt frames (a 4-byte
    non-zero length followed by the raw receipt bytes), and finally the
    4-byte sibling count followed by exactly that many raw 32-byte sibling
    digests, where the count must be the unique one derived from ``n`` and
    the disclosed indices. A non-bytes argument raises TypeError; a wrong or
    missing tag, an empty index list or receipt, an out-of-range ``n``, a
    record count that does not match the index count, indices that are not
    strictly increasing or lie outside ``0 <= i < n``, a missing or extra
    sibling relative to the count ``n`` and the indices require, a sibling
    that is not exactly 32 bytes, truncation, trailing bytes, or a
    non-canonical integer (leading zero or over-long length) raises
    ValueError. A successfully decoded proof re-encodes to exactly the input
    bytes.

    Decoding only restores the structure: the receipts are stored opaque
    and are neither parsed nor verified, no signature is checked and no
    state is kept. A structurally legal proof whose records or siblings do
    not rebuild the signed root or whose sealing signature is invalid is
    returned normally, and :func:`check_multi_proof` reports it as
    ``False``.
    """
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    if not payload.startswith(AUDIT_MULTI_PROOF_WIRE_TAG):
        raise ValueError("bad audit multi-proof tag")
    offset = len(AUDIT_MULTI_PROOF_WIRE_TAG)

    count, offset = _read_varint(payload, offset, what="audit multi-proof n")

    if offset + 4 > len(payload):
        raise ValueError("truncated audit multi-proof index count")
    index_count = int.from_bytes(payload[offset:offset + 4], "big")
    offset += 4
    if index_count == 0:
        raise ValueError("audit multi-proof indices must be non-empty")
    indices = []
    for _ in range(index_count):
        index, offset = _read_varint(
            payload, offset, what="audit multi-proof index"
        )
        indices.append(index)

    if offset + 4 > len(payload):
        raise ValueError("truncated audit multi-proof record count")
    record_count = int.from_bytes(payload[offset:offset + 4], "big")
    offset += 4
    if record_count != index_count:
        raise ValueError(
            "audit multi-proof record count must match the index count"
        )
    records = []
    for _ in range(record_count):
        message, offset = _read_audit_proof_block(
            payload, offset, what="multi-proof message", allow_empty=True
        )
        receipt, offset = _read_audit_proof_block(
            payload, offset, what="multi-proof receipt"
        )
        records.append((message, SigningAudit(payload=receipt)))

    if offset + 4 > len(payload):
        raise ValueError("truncated audit multi-proof sibling count")
    sibling_count = int.from_bytes(payload[offset:offset + 4], "big")
    offset += 4
    siblings = []
    for _ in range(sibling_count):
        if offset + AUDIT_PROOF_DIGEST_SIZE > len(payload):
            raise ValueError("truncated audit multi-proof sibling")
        siblings.append(
            bytes(payload[offset:offset + AUDIT_PROOF_DIGEST_SIZE])
        )
        offset += AUDIT_PROOF_DIGEST_SIZE
    if offset != len(payload):
        raise ValueError("trailing bytes after audit multi-proof")

    proof = AuditMultiProof(
        indices=tuple(indices),
        n=count,
        records=tuple(records),
        siblings=tuple(siblings),
    )
    _validate_audit_multi_proof_structure(proof)
    if encode_audit_multi_proof(proof) != payload:
        raise ValueError("non-canonical audit multi-proof")
    return proof


# ---------------------------------------------------------------------------
# Canonical audit-multi-proof bundle transport: a self-delimiting,
# byte-for-byte reproducible encoding of an AuditMultiProof together with the
# AggregateSignature on its b"am/r" || U64(n) || root statement, for
# cross-implementation exchange and persistence. Decoding restores structure
# only — the nested proof goes through decode_audit_multi_proof, its receipts
# are not parsed and no signature is checked, so verify_audit_multi_proof_bundle
# remains the sole verifier afterwards.
# ---------------------------------------------------------------------------

AUDIT_MULTI_PROOF_BUNDLE_WIRE_TAG = b"ts/ampb/v1"


@dataclass(frozen=True)
class AuditMultiProofBundle:
    """A multi-record audit proof together with its root signature.

    The fields, in order, are ``proof`` (an :class:`AuditMultiProof`) and
    ``signature`` (the :class:`AggregateSignature` on the proof's
    ``b"am/r" || U64(n) || root`` statement). The dataclass is frozen,
    positionally constructible and compared by value, and carries no
    network, storage or hidden state. Field types and bounds are not
    checked at construction time —
    :func:`encode_audit_multi_proof_bundle` checks the structure and
    :func:`verify_audit_multi_proof_bundle` is the way to test a bundle
    afterwards.
    """

    proof: AuditMultiProof
    signature: AggregateSignature


def encode_audit_multi_proof_bundle(bundle: AuditMultiProofBundle) -> bytes:
    """Canonically encode an audit multi-proof bundle for transport or persistence.

    The encoding is, in order, the tag ``b"ts/ampb/v1"``, the 4-byte
    unsigned big-endian length ``len(P)`` followed by
    ``P = encode_audit_multi_proof(bundle.proof)`` (never empty), and then
    the signature frame: ``VARINT(R)``, ``VARINT(z)``, the 4-byte unsigned
    big-endian signer count ``k`` and one ``VARINT(id)`` per ascending
    signer id. A ``VARINT`` is a 4-byte unsigned big-endian body length
    followed by the shortest unsigned big-endian value (zero is the single
    byte ``00``, positive values carry no leading zero); ``R`` must be
    positive and ``z`` may be zero.

    Only a structurally legal :class:`AuditMultiProofBundle` is accepted
    — a non-bundle or non-:class:`AuditMultiProof` proof argument, or
    wrong proof/signature field types, raise TypeError and illegal proof
    or signature structure (the exact bounds of
    :func:`encode_audit_multi_proof`, a non-positive ``R``, a negative
    ``z``, an empty or non-strictly-increasing signer id tuple) or an
    over-long frame raises ValueError, exactly as
    :func:`check_multi_proof`'s structural checks do — but the receipts
    are not parsed and the signature is not checked against the root:
    :func:`verify_audit_multi_proof_bundle` stays the way to verify a
    bundle afterwards. The output for a given bundle is unique and the
    encoding carries no network, storage or hidden state.
    """
    if not isinstance(bundle, AuditMultiProofBundle):
        raise TypeError("bundle must be an AuditMultiProofBundle instance")
    if not isinstance(bundle.proof, AuditMultiProof):
        raise TypeError(
            "bundle.proof must be an AuditMultiProof instance"
        )
    encoded_proof = encode_audit_multi_proof(bundle.proof)
    signer_count = _check_history_proof_bundle_signature(bundle.signature)
    if len(encoded_proof) > 0xFFFFFFFF:
        raise ValueError("audit multi-proof encoding too long")
    if signer_count > 0xFFFFFFFF:
        raise ValueError("too many signer ids")

    buffer = bytearray(AUDIT_MULTI_PROOF_BUNDLE_WIRE_TAG)
    buffer += len(encoded_proof).to_bytes(4, "big", signed=False)
    buffer += encoded_proof
    buffer += _encode_varint(bundle.signature.R)
    buffer += _encode_varint(bundle.signature.z)
    buffer += signer_count.to_bytes(4, "big", signed=False)
    for signer_id in bundle.signature.signer_ids:
        buffer += _encode_varint(signer_id)
    return bytes(buffer)


def decode_audit_multi_proof_bundle(blob: bytes) -> AuditMultiProofBundle:
    """Decode the canonical encoding produced by :func:`encode_audit_multi_proof_bundle`.

    Accepts only the single canonical form: the tag ``b"ts/ampb/v1"``, a
    4-byte non-zero frame length followed by bytes that
    :func:`decode_audit_multi_proof` accepts, the length-prefixed
    integers ``R`` and ``z``, the 4-byte non-zero signer count ``k`` and
    then exactly ``k`` strictly increasing positive signer ids. A
    non-bytes argument raises TypeError; a wrong or missing tag, a zero
    or over-long proof frame length, a non-canonical nested proof, a zero
    ``R``, a non-canonical integer (leading zero or over-long length), a
    zero signer count, a non-positive or non-increasing signer id,
    truncation, or trailing bytes raises ValueError. A successfully
    decoded bundle re-encodes to exactly the input bytes.

    Decoding only restores the structure: the nested proof is decoded
    with :func:`decode_audit_multi_proof` (which keeps the receipts
    opaque and verifies nothing) and the signature is not checked. A
    structurally legal bundle whose receipts do not match their messages
    or whose signature does not sign the root is returned normally, and
    :func:`verify_audit_multi_proof_bundle` reports it as ``False``.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not blob.startswith(AUDIT_MULTI_PROOF_BUNDLE_WIRE_TAG):
        raise ValueError("bad audit multi-proof bundle tag")
    offset = len(AUDIT_MULTI_PROOF_BUNDLE_WIRE_TAG)

    encoded_proof, offset = _read_audit_proof_block(
        blob, offset, what="audit multi-proof bundle proof"
    )
    proof = decode_audit_multi_proof(encoded_proof)

    R, offset = _read_varint(
        blob, offset, what="audit multi-proof bundle signature R"
    )
    z, offset = _read_varint(
        blob, offset, what="audit multi-proof bundle signature z"
    )
    if R == 0:
        raise ValueError("audit multi-proof bundle signature R must be positive")

    if offset + 4 > len(blob):
        raise ValueError("truncated audit multi-proof bundle signer count")
    signer_count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    if signer_count == 0:
        raise ValueError("audit multi-proof bundle must name at least one signer")

    signer_ids = []
    for _ in range(signer_count):
        signer_id, offset = _read_varint(
            blob,
            offset,
            what="audit multi-proof bundle signer id",
        )
        if signer_id == 0:
            raise ValueError(
                "audit multi-proof bundle signer ids must be positive"
            )
        if signer_ids and signer_id <= signer_ids[-1]:
            raise ValueError(
                "audit multi-proof bundle signer ids must be strictly "
                "increasing and unique"
            )
        signer_ids.append(signer_id)
    if offset != len(blob):
        raise ValueError("trailing bytes after audit multi-proof bundle")

    bundle = AuditMultiProofBundle(
        proof=proof,
        signature=AggregateSignature(R=R, z=z, signer_ids=tuple(signer_ids)),
    )
    if encode_audit_multi_proof_bundle(bundle) != blob:
        raise ValueError("non-canonical audit multi-proof bundle encoding")
    return bundle


def verify_audit_multi_proof_bundle(
    bundle: AuditMultiProofBundle, key: SigningDKGResult
) -> bool:
    """Verify a bundle exactly as :func:`check_multi_proof` would.

    This is a convenience wrapper over
    ``check_multi_proof(bundle.proof, bundle.signature, key)``: the Merkle
    root is rebuilt from the multi-proof, every embedded record
    re-checked with :func:`check_audit` and the signature verified on
    ``b"am/r" || U64(n) || root``. Returns ``True`` only when all of them
    hold; a well-formed bundle with a tampered record, receipt, sibling
    or signature, or one presented under another key, returns ``False``.

    A non-:class:`AuditMultiProofBundle` argument raises TypeError;
    illegal nested proof, signature or key structure raises
    TypeError/ValueError, exactly as :func:`check_multi_proof` does.
    """
    if not isinstance(bundle, AuditMultiProofBundle):
        raise TypeError("bundle must be an AuditMultiProofBundle instance")
    return check_multi_proof(bundle.proof, bundle.signature, key)


# ---------------------------------------------------------------------------
# Append-only consistency (extension) proofs over the same audit Merkle tree:
# a compact statement that the first ``old_n`` records of a chain are exactly
# the records of an older, shorter chain. The proof carries only the leaf
# digests — never a message or a receipt — and both the old and the new
# statement are the ordinary record-root messages ``b"am/r" || U64(n) ||
# root`` of the shared tree rules, so an observer needs nothing but the two
# threshold signatures to check the prefix relation. No state is kept.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuditExtensionProof:
    """An append-only consistency proof between two audit-chain record roots.

    The fields, in order, are ``old_n`` (the non-empty old record count,
    strictly smaller than the new total) and ``leaves`` (the 32-byte leaf
    digests of the full new record sequence, in order, each exactly
    ``H(b"am/l" || U64(i) || H(message) || H(audit.payload))`` as in
    :func:`make_proof`; the tuple is non-empty). The first ``old_n`` leaves
    rebuild the old root and all of them rebuild the new root, so the proof
    discloses no message or receipt — only their digests. The dataclass is
    frozen, positionally constructible and compared by value, and carries no
    network, storage or hidden state. Field types and bounds are not checked
    at construction time — :func:`check_extension` is the way to test a
    proof afterwards.
    """

    old_n: int
    leaves: tuple[bytes, ...]


def _audit_extension_root(leaves: tuple[bytes, ...]) -> bytes:
    """Root digest of the AuditProof tree rebuilt directly from leaf digests.

    The pairing rules are exactly those of :func:`_audit_proof_levels`: a
    level with an odd tail width duplicates its last node, and internal
    nodes are ``H(b"am/n" || left || right)``.
    """
    current = leaves
    while len(current) > 1:
        if len(current) % 2 == 1:
            current = current + current[-1:]
        current = tuple(
            _audit_proof_node(current[index], current[index + 1])
            for index in range(0, len(current), 2)
        )
    return current[0]


def make_extension(
    records: tuple[tuple[bytes, SigningAudit], ...], old_n: int
) -> tuple[bytes, bytes, AuditExtensionProof]:
    """Build the old and new root statements and a consistency proof.

    ``records`` must be the same non-empty, order-preserving tuple of
    ``(message, SigningAudit)`` pairs an :class:`AuditChain` seals and
    ``old_n`` the old record count, which must be non-zero and strictly
    smaller than the total record count. The tree rules are exactly those of
    :func:`make_proof`; the first ``old_n`` leaves give the old root and all
    leaves give the new root. Returns ``(old_message, new_message, proof)``
    where both messages are ``b"am/r" || U64(n) || root`` with ``n`` the old
    count and the total count respectively — the bytes to be
    threshold-signed — and ``proof`` is the :class:`AuditExtensionProof`
    carrying every leaf digest.

    Wrong argument types raise TypeError: a non-tuple record sequence, a
    malformed record (exactly the rules of :func:`audit_chain_payload`), or
    a non-integer (including boolean) ``old_n``. An empty record sequence, a
    record count that does not fit the 8-byte counter, or an ``old_n``
    outside ``0 < old_n < n`` raises ValueError.
    """
    if not isinstance(old_n, int) or isinstance(old_n, bool):
        raise TypeError("old_n must be an integer")
    count = _check_audit_chain_records(records)
    if count > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("too many records")
    if old_n <= 0 or old_n >= count:
        raise ValueError("old_n out of range")

    leaves = tuple(
        _audit_proof_leaf(index, message, audit)
        for index, (message, audit) in enumerate(records)
    )
    old_root = _audit_extension_root(leaves[:old_n])
    new_root = _audit_extension_root(leaves)
    old_message = AUDIT_PROOF_ROOT_TAG + _audit_proof_u64(old_n) + old_root
    new_message = AUDIT_PROOF_ROOT_TAG + _audit_proof_u64(count) + new_root
    proof = AuditExtensionProof(old_n=old_n, leaves=leaves)
    return old_message, new_message, proof


def _validate_audit_extension_structure(
    proof: object,
) -> tuple[int, tuple[bytes, ...]]:
    """Type- and structure-check an :class:`AuditExtensionProof`.

    Shared by :func:`check_extension`. The bounds are
    ``0 < old_n < len(leaves)`` and ``len(leaves) <= 2**64 - 1``; the leaf
    tuple must be non-empty and every entry exactly 32 bytes. Wrong field
    types raise TypeError; illegal bounds, an empty leaf tuple or a leaf of
    the wrong width raise ValueError.
    """
    if not isinstance(proof, AuditExtensionProof):
        raise TypeError("proof must be an AuditExtensionProof instance")
    old_n = proof.old_n
    leaves = proof.leaves
    if not isinstance(old_n, int) or isinstance(old_n, bool):
        raise TypeError("proof.old_n must be an integer")
    if not isinstance(leaves, tuple):
        raise TypeError("proof.leaves must be a tuple")
    for leaf in leaves:
        if not isinstance(leaf, bytes):
            raise TypeError("proof.leaves entries must be bytes")

    try:
        count = len(leaves)
    except OverflowError:
        raise ValueError("too many leaves") from None
    if count == 0:
        raise ValueError("proof.leaves must be non-empty")
    if count > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("too many leaves")
    if old_n <= 0 or old_n >= count:
        raise ValueError("proof.old_n out of range")
    for leaf in leaves:
        if len(leaf) != AUDIT_PROOF_DIGEST_SIZE:
            raise ValueError("proof.leaves entries must be exactly 32 bytes")
    return old_n, leaves


def check_extension(
    proof: AuditExtensionProof,
    old_sig: AggregateSignature,
    new_sig: AggregateSignature,
    key: SigningDKGResult,
) -> bool:
    """Verify a consistency proof against its two threshold signatures.

    The old root is rebuilt from the first ``proof.old_n`` leaves of
    ``proof.leaves`` and the new root from all of them, exactly as in
    :func:`make_extension`; the statements ``b"am/r" || U64(old_n) ||
    old_root`` and ``b"am/r" || U64(n) || new_root`` are then checked as
    ``old_sig``'s and ``new_sig``'s threshold Schnorr messages via
    :func:`verify_signature` under ``key``. Returns ``True`` only when both
    signatures verify: an observer learns nothing but the two signatures and
    the leaf digests, yet is convinced the old record sequence is a prefix
    of the new one. A well-formed proof whose leaves or ``old_n`` were
    tampered with, a swapped or mismatched signature pair, or a proof
    presented under another key returns ``False``.

    A non-:class:`AuditExtensionProof` proof, a
    non-:class:`AggregateSignature` signature or any wrong field type
    (non-integer ``old_n`` including booleans, a non-tuple leaf sequence or
    non-bytes leaf) raises TypeError; an empty leaf tuple, a leaf that is
    not exactly 32 bytes, a total over ``2**64 - 1``, an ``old_n`` outside
    ``0 < old_n < n``, or a structurally illegal signature or ``key`` raises
    ValueError, exactly as :func:`verify_signature` would.
    """
    old_n, leaves = _validate_audit_extension_structure(proof)
    if not isinstance(old_sig, AggregateSignature):
        raise TypeError("old_sig must be an AggregateSignature instance")
    if not isinstance(new_sig, AggregateSignature):
        raise TypeError("new_sig must be an AggregateSignature instance")

    _result, public_key, field_prime, group_prime, generator = _check_signing_setup(key)
    _check_signing_dkg_structure(key)

    old_root = _audit_extension_root(leaves[:old_n])
    new_root = _audit_extension_root(leaves)
    old_message = AUDIT_PROOF_ROOT_TAG + _audit_proof_u64(old_n) + old_root
    new_message = AUDIT_PROOF_ROOT_TAG + _audit_proof_u64(len(leaves)) + new_root
    if not verify_signature(
        old_message,
        old_sig,
        public_key,
        group_prime=group_prime,
        generator=generator,
        prime=field_prime,
    ):
        return False
    return verify_signature(
        new_message,
        new_sig,
        public_key,
        group_prime=group_prime,
        generator=generator,
        prime=field_prime,
    )


# ---------------------------------------------------------------------------
# Canonical audit-extension transport: a fixed-width, byte-for-byte
# reproducible encoding of an AuditExtensionProof for cross-implementation
# exchange and persistence. Decoding restores structure only — the leaf
# digests are not parsed, no signature is checked and no state is kept, so
# check_extension remains the sole verifier afterwards.
# ---------------------------------------------------------------------------

AUDIT_EXTENSION_WIRE_TAG = b"thresholdsign/audit-extension/v1"


def encode_extension(proof: AuditExtensionProof) -> bytes:
    """Canonically encode a consistency proof for transport or persistence.

    The encoding is the direct concatenation, in order, of the tag
    ``b"thresholdsign/audit-extension/v1"``, ``old_n`` as an 8-byte unsigned
    big-endian integer, the leaf count ``n`` as an 8-byte unsigned big-endian
    integer and then every leaf digest in its original order, each exactly
    32 bytes, with no further separators; the total length is therefore
    uniquely determined by the tag and ``n``. The bounds are
    ``0 < old_n < n < 2**64``.

    Only a structurally legal :class:`AuditExtensionProof` is accepted —
    wrong field types raise TypeError and illegal bounds, an empty leaf
    tuple or a leaf of the wrong width raise ValueError, exactly as
    :func:`check_extension`'s structural checks do — but the leaf digests
    are not parsed and no signature is required or checked:
    :func:`check_extension` stays the way to verify a proof afterwards. The
    output for a given proof is unique and the encoding carries no network,
    storage or hidden state.
    """
    old_n, leaves = _validate_audit_extension_structure(proof)
    count = len(leaves)
    buffer = bytearray(AUDIT_EXTENSION_WIRE_TAG)
    buffer += old_n.to_bytes(8, "big", signed=False)
    buffer += count.to_bytes(8, "big", signed=False)
    for leaf in leaves:
        buffer += leaf
    return bytes(buffer)


def decode_extension(payload: bytes) -> AuditExtensionProof:
    """Decode the canonical encoding produced by :func:`encode_extension`.

    Accepts only the single canonical form: the tag
    ``b"thresholdsign/audit-extension/v1"``, ``old_n`` and the leaf count
    ``n`` as 8-byte unsigned big-endian integers, and then exactly ``n``
    raw 32-byte leaf digests with nothing before, between or after them.
    A non-bytes argument raises TypeError; a wrong or missing tag, an empty
    leaf sequence, an ``old_n`` outside ``0 < old_n < n``, an ``n`` of
    ``2**64`` or more, truncation, trailing bytes, or a leaf count that
    does not match the remaining bytes raises ValueError. A successfully
    decoded proof re-encodes to exactly the input bytes.

    Decoding only restores the structure: the leaf digests are stored
    opaque and are neither parsed nor verified, no signature is checked and
    no state is kept. A structurally legal proof whose signatures do not
    match its roots is returned normally, and :func:`check_extension`
    reports it as ``False``.
    """
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    if not payload.startswith(AUDIT_EXTENSION_WIRE_TAG):
        raise ValueError("bad audit extension tag")
    offset = len(AUDIT_EXTENSION_WIRE_TAG)

    if offset + 16 > len(payload):
        raise ValueError("truncated audit extension header")
    old_n = int.from_bytes(payload[offset:offset + 8], "big", signed=False)
    count = int.from_bytes(payload[offset + 8:offset + 16], "big", signed=False)
    offset += 16

    body = payload[offset:]
    if len(body) != count * AUDIT_PROOF_DIGEST_SIZE:
        raise ValueError("audit extension leaf count does not match the payload")
    leaves = tuple(
        body[index * AUDIT_PROOF_DIGEST_SIZE:(index + 1) * AUDIT_PROOF_DIGEST_SIZE]
        for index in range(count)
    )

    proof = AuditExtensionProof(old_n=old_n, leaves=leaves)
    _validate_audit_extension_structure(proof)
    return proof


# ---------------------------------------------------------------------------
# Canonical audit-extension bundle transport: a self-delimiting,
# byte-for-byte reproducible encoding of an AuditExtensionProof together
# with the old- and new-root AggregateSignature pair, for
# cross-implementation exchange and persistence. Decoding restores
# structure only — the nested proof goes through decode_extension, its
# leaf digests stay opaque and no signature is checked, so
# verify_audit_extension_proof_bundle remains the sole verifier
# afterwards.
# ---------------------------------------------------------------------------

AUDIT_EXTENSION_PROOF_BUNDLE_WIRE_TAG = b"ts/aepb/v1"


@dataclass(frozen=True)
class AuditExtensionProofBundle:
    """A consistency proof together with its two root signatures.

    The fields, in order, are ``proof`` (an :class:`AuditExtensionProof`),
    ``old_signature`` (the :class:`AggregateSignature` on the old
    ``b"am/r" || U64(old_n) || old_root`` statement) and ``new_signature``
    (the :class:`AggregateSignature` on the new
    ``b"am/r" || U64(n) || new_root`` statement). The dataclass is frozen,
    positionally constructible and compared by value, and carries no
    network, storage or hidden state. Field types and bounds are not
    checked at construction time — :func:`encode_audit_extension_proof_bundle`
    checks the structure and :func:`verify_audit_extension_proof_bundle`
    is the way to test a bundle afterwards.
    """

    proof: AuditExtensionProof
    old_signature: AggregateSignature
    new_signature: AggregateSignature


def encode_audit_extension_proof_bundle(
    bundle: AuditExtensionProofBundle,
) -> bytes:
    """Canonically encode a consistency-proof bundle for transport or persistence.

    The encoding is, in order, the tag ``b"ts/aepb/v1"``, the 4-byte
    unsigned big-endian length ``len(P)`` followed by
    ``P = encode_extension(bundle.proof)`` (never empty), and then the old
    and new signature frames, each exactly the signature frame of
    :func:`encode_audit_proof_bundle`: ``VARINT(R)``, ``VARINT(z)``, the
    4-byte unsigned big-endian signer count ``k`` and one ``VARINT(id)``
    per ascending signer id. A ``VARINT`` is a 4-byte unsigned big-endian
    body length followed by the shortest unsigned big-endian value (zero
    is the single byte ``00``, positive values carry no leading zero);
    ``R`` must be positive and ``z`` may be zero.

    Only a structurally legal :class:`AuditExtensionProofBundle` is
    accepted — a non-bundle or non-:class:`AuditExtensionProof` proof
    argument, or wrong proof/signature field types, raise TypeError and
    illegal proof or signature structure (the exact bounds of
    :func:`encode_extension`, a non-positive ``R``, a negative ``z``, an
    empty or non-strictly-increasing signer id tuple) or an over-long
    frame raises ValueError, exactly as :func:`check_extension`'s
    structural checks do — but the prefix relation is not verified and
    neither signature is checked against the roots:
    :func:`verify_audit_extension_proof_bundle` stays the way to verify a
    bundle afterwards. The output for a given bundle is unique and the
    encoding carries no network, storage or hidden state.
    """
    if not isinstance(bundle, AuditExtensionProofBundle):
        raise TypeError("bundle must be an AuditExtensionProofBundle instance")
    if not isinstance(bundle.proof, AuditExtensionProof):
        raise TypeError("bundle.proof must be an AuditExtensionProof instance")
    encoded_proof = encode_extension(bundle.proof)
    old_signer_count = _check_history_proof_bundle_signature(
        bundle.old_signature, field="bundle.old_signature"
    )
    new_signer_count = _check_history_proof_bundle_signature(
        bundle.new_signature, field="bundle.new_signature"
    )
    if len(encoded_proof) > 0xFFFFFFFF:
        raise ValueError("audit extension proof encoding too long")
    if old_signer_count > 0xFFFFFFFF or new_signer_count > 0xFFFFFFFF:
        raise ValueError("too many signer ids")

    buffer = bytearray(AUDIT_EXTENSION_PROOF_BUNDLE_WIRE_TAG)
    buffer += len(encoded_proof).to_bytes(4, "big", signed=False)
    buffer += encoded_proof
    for signature, signer_count in (
        (bundle.old_signature, old_signer_count),
        (bundle.new_signature, new_signer_count),
    ):
        buffer += _encode_varint(signature.R)
        buffer += _encode_varint(signature.z)
        buffer += signer_count.to_bytes(4, "big", signed=False)
        for signer_id in signature.signer_ids:
            buffer += _encode_varint(signer_id)
    return bytes(buffer)


def _read_bundle_signature_frame(
    stream: bytes, offset: int, *, what: str
) -> tuple[AggregateSignature, int]:
    """Read one canonical bundle signature frame at ``offset``.

    The frame is ``VARINT(R)``, ``VARINT(z)``, the 4-byte non-zero signer
    count and then exactly that many strictly increasing positive
    ``VARINT(id)`` entries — the same rules
    :func:`decode_audit_proof_bundle` applies to its single signature.
    """
    R, offset = _read_varint(stream, offset, what=f"{what} signature R")
    z, offset = _read_varint(stream, offset, what=f"{what} signature z")
    if R == 0:
        raise ValueError(f"{what} signature R must be positive")

    if offset + 4 > len(stream):
        raise ValueError(f"truncated {what} signer count")
    signer_count = int.from_bytes(stream[offset:offset + 4], "big")
    offset += 4
    if signer_count == 0:
        raise ValueError(f"{what} must name at least one signer")

    signer_ids = []
    for _ in range(signer_count):
        signer_id, offset = _read_varint(
            stream, offset, what=f"{what} signer id"
        )
        if signer_id == 0:
            raise ValueError(f"{what} signer ids must be positive")
        if signer_ids and signer_id <= signer_ids[-1]:
            raise ValueError(
                f"{what} signer ids must be strictly increasing and unique"
            )
        signer_ids.append(signer_id)
    return (
        AggregateSignature(R=R, z=z, signer_ids=tuple(signer_ids)),
        offset,
    )


def decode_audit_extension_proof_bundle(
    blob: bytes,
) -> AuditExtensionProofBundle:
    """Decode the canonical encoding produced by :func:`encode_audit_extension_proof_bundle`.

    Accepts only the single canonical form: the tag ``b"ts/aepb/v1"``, a
    4-byte non-zero frame length followed by bytes that
    :func:`decode_extension` accepts, and then the old and new signature
    frames, each the length-prefixed integers ``R`` and ``z``, the 4-byte
    non-zero signer count ``k`` and exactly ``k`` strictly increasing
    positive signer ids. A non-bytes argument raises TypeError; a wrong or
    missing tag, a zero or over-long proof frame length, a non-canonical
    nested proof, a zero ``R``, a non-canonical integer (leading zero or
    over-long length), a zero signer count, a non-positive or
    non-increasing signer id, truncation, or trailing bytes raises
    ValueError. A successfully decoded bundle re-encodes to exactly the
    input bytes.

    Decoding only restores the structure: the nested proof is decoded
    with :func:`decode_extension` (which keeps the leaf digests opaque
    and verifies nothing) and neither signature is checked. A
    structurally legal bundle whose signatures do not match its roots is
    returned normally, and
    :func:`verify_audit_extension_proof_bundle` reports it as ``False``.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not blob.startswith(AUDIT_EXTENSION_PROOF_BUNDLE_WIRE_TAG):
        raise ValueError("bad audit extension proof bundle tag")
    offset = len(AUDIT_EXTENSION_PROOF_BUNDLE_WIRE_TAG)

    encoded_proof, offset = _read_audit_proof_block(
        blob, offset, what="audit extension proof bundle proof"
    )
    proof = decode_extension(encoded_proof)

    old_signature, offset = _read_bundle_signature_frame(
        blob, offset, what="audit extension proof bundle old"
    )
    new_signature, offset = _read_bundle_signature_frame(
        blob, offset, what="audit extension proof bundle new"
    )
    if offset != len(blob):
        raise ValueError("trailing bytes after audit extension proof bundle")

    bundle = AuditExtensionProofBundle(
        proof=proof,
        old_signature=old_signature,
        new_signature=new_signature,
    )
    if encode_audit_extension_proof_bundle(bundle) != blob:
        raise ValueError("non-canonical audit extension proof bundle encoding")
    return bundle


def verify_audit_extension_proof_bundle(
    bundle: AuditExtensionProofBundle, key: SigningDKGResult
) -> bool:
    """Verify a bundle exactly as :func:`check_extension` would.

    This is a convenience wrapper over
    ``check_extension(bundle.proof, bundle.old_signature,
    bundle.new_signature, key)``: the old and new roots are rebuilt from
    the proof's leaves and each signature verified on its
    ``b"am/r" || U64(n) || root`` statement. Returns ``True`` only when
    both hold; a well-formed bundle with tampered leaves or ``old_n``, a
    swapped or mismatched signature pair, or one presented under another
    key, returns ``False``.

    A non-:class:`AuditExtensionProofBundle` argument raises TypeError;
    illegal nested proof, signature or key structure raises
    TypeError/ValueError, exactly as :func:`check_extension` does.
    """
    if not isinstance(bundle, AuditExtensionProofBundle):
        raise TypeError("bundle must be an AuditExtensionProofBundle instance")
    return check_extension(
        bundle.proof, bundle.old_signature, bundle.new_signature, key
    )


# ---------------------------------------------------------------------------
# Canonical audit-extension bundle chain transport: a self-delimiting,
# byte-for-byte reproducible encoding of a non-empty, order-preserving
# sequence of AuditExtensionProofBundle values, for cross-implementation
# exchange and persistence. Adjacent bundles link when the predecessor's
# leaf set is exactly the successor's old prefix. Decoding restores
# structure only and neither the per-bundle signatures nor the linkage are
# checked, so verify_audit_extension_proof_bundle_chain remains the sole
# verifier afterwards.
# ---------------------------------------------------------------------------

AUDIT_EXTENSION_PROOF_BUNDLE_CHAIN_WIRE_TAG = b"ts/aepbc/v1"


@dataclass(frozen=True)
class AuditExtensionProofBundleChain:
    """A non-empty, order-preserving chain of extension-proof bundles.

    ``items`` is the non-empty tuple of
    :class:`AuditExtensionProofBundle` values in chain order: for every
    adjacent pair the predecessor's leaf count must equal the successor's
    ``proof.old_n`` and the predecessor's ``proof.leaves`` must equal the
    successor's ``proof.leaves[:old_n]`` (enforced by
    :func:`verify_audit_extension_proof_bundle_chain`, not by
    construction). The dataclass is frozen, positionally constructible and
    compared by value, and carries no network, storage or hidden state.
    Item types and the non-empty bound are not checked at construction
    time — :func:`encode_audit_extension_proof_bundle_chain` checks the
    structure and :func:`verify_audit_extension_proof_bundle_chain` is the
    way to test a chain afterwards.
    """

    items: tuple[AuditExtensionProofBundle, ...]


def _check_audit_extension_proof_bundle_chain_items(items: object) -> int:
    """Type- and structure-check a chain's items container, without verifying.

    Items must be a non-empty tuple of
    :class:`AuditExtensionProofBundle` values; the bundles themselves are
    neither encoded nor verified here (that is
    :func:`verify_audit_extension_proof_bundle`'s job during verification).
    Returns the item count.
    """
    if not isinstance(items, tuple):
        raise TypeError("items must be a tuple")
    try:
        count = len(items)
    except OverflowError:
        raise ValueError("too many chain items") from None
    if count == 0:
        raise ValueError("items must be non-empty")
    for item in items:
        if not isinstance(item, AuditExtensionProofBundle):
            raise TypeError(
                "each chain item must be an AuditExtensionProofBundle instance"
            )
    return count


def encode_audit_extension_proof_bundle_chain(
    chain: AuditExtensionProofBundleChain,
) -> bytes:
    """Canonically encode a chain of consistency-proof bundles.

    The encoding is, in order, the tag ``b"ts/aepbc/v1"``, the item count
    ``n = len(chain.items)`` as a 4-byte unsigned big-endian integer, and
    then one frame per item in chain order: each frame is the 4-byte
    unsigned big-endian length ``len(E)`` followed by
    ``E = encode_audit_extension_proof_bundle(item)``, the existing
    canonical single-bundle encoding (never empty).

    Only the chain container and the bundle structures are checked — the
    prefix linkage is not verified and neither signature is checked:
    :func:`verify_audit_extension_proof_bundle_chain` stays the way to
    verify a chain afterwards. A non-chain argument or a non-tuple item
    sequence raises TypeError, and a non-:class:`AuditExtensionProofBundle`
    element raises TypeError exactly as
    :func:`encode_audit_extension_proof_bundle` does for its proof and
    signature fields. An empty chain, an over-long count or frame, or an
    illegal nested bundle raises ValueError. The output for a given chain
    is unique and the encoding carries no network, storage or hidden
    state.
    """
    if not isinstance(chain, AuditExtensionProofBundleChain):
        raise TypeError(
            "chain must be an AuditExtensionProofBundleChain instance"
        )
    count = _check_audit_extension_proof_bundle_chain_items(chain.items)
    if count > 0xFFFFFFFF:
        raise ValueError("too many chain items")

    bodies = []
    for item in chain.items:
        body = encode_audit_extension_proof_bundle(item)
        if len(body) > 0xFFFFFFFF:
            raise ValueError("audit extension proof bundle encoding too long")
        bodies.append(body)

    buffer = bytearray(AUDIT_EXTENSION_PROOF_BUNDLE_CHAIN_WIRE_TAG)
    buffer += count.to_bytes(4, "big", signed=False)
    for body in bodies:
        buffer += len(body).to_bytes(4, "big", signed=False)
        buffer += body
    return bytes(buffer)


def decode_audit_extension_proof_bundle_chain(
    blob: bytes,
) -> AuditExtensionProofBundleChain:
    """Decode the canonical encoding produced by :func:`encode_audit_extension_proof_bundle_chain`.

    Accepts only the single canonical form: the tag
    ``b"ts/aepbc/v1"``, the 4-byte unsigned big-endian non-zero item
    count ``n``, and then exactly ``n`` frames, each a 4-byte unsigned
    big-endian non-zero length followed by bytes that
    :func:`decode_audit_extension_proof_bundle` accepts. A non-bytes
    argument raises TypeError; a wrong or missing tag, an empty chain, a
    zero or over-long frame length, an illegal nested bundle, a count
    mismatch, truncation, or trailing bytes raises ValueError. A
    successfully decoded chain re-encodes to exactly the input bytes.

    Decoding only restores the structure: every nested bundle goes through
    :func:`decode_audit_extension_proof_bundle`, whose leaf digests stay
    opaque and whose signatures are not checked, and the prefix linkage
    between adjacent bundles is not checked either. A structurally legal
    chain whose signatures do not match or whose bundles do not link is
    returned normally, and
    :func:`verify_audit_extension_proof_bundle_chain` reports it as
    ``False``.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not blob.startswith(AUDIT_EXTENSION_PROOF_BUNDLE_CHAIN_WIRE_TAG):
        raise ValueError("bad audit extension proof bundle chain tag")
    offset = len(AUDIT_EXTENSION_PROOF_BUNDLE_CHAIN_WIRE_TAG)

    if offset + 4 > len(blob):
        raise ValueError("truncated audit extension proof bundle chain count")
    count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    if count == 0:
        raise ValueError("audit extension proof bundle chain must be non-empty")

    items = []
    for index in range(count):
        body, offset = _read_audit_proof_block(
            blob,
            offset,
            what=f"audit extension proof bundle chain item {index + 1}",
        )
        items.append(decode_audit_extension_proof_bundle(body))
    if offset != len(blob):
        raise ValueError(
            "trailing bytes after audit extension proof bundle chain"
        )

    chain = AuditExtensionProofBundleChain(items=tuple(items))
    if encode_audit_extension_proof_bundle_chain(chain) != blob:
        raise ValueError(
            "non-canonical audit extension proof bundle chain encoding"
        )
    return chain


def verify_audit_extension_proof_bundle_chain(
    chain: AuditExtensionProofBundleChain, key: SigningDKGResult
) -> bool:
    """Verify every bundle of a chain and the prefix linkage between neighbours.

    Each item is verified with
    :func:`verify_audit_extension_proof_bundle` against ``key``, and for
    every adjacent pair the predecessor's leaf count must equal the
    successor's ``proof.old_n`` and the predecessor's ``proof.leaves``
    must equal the first ``old_n`` leaves of the successor's
    ``proof.leaves`` — the old tree of each hop is exactly the new tree
    of the previous one. Returns ``True`` only when every single bundle
    verifies and every linkage holds; a well-formed chain with a
    mismatched signature pair, tampered leaves, a gap or overlap between
    neighbours, or one presented under another key returns ``False``.

    A non-:class:`AuditExtensionProofBundleChain` argument raises
    TypeError; an empty chain, a non-tuple item sequence, a
    non-:class:`AuditExtensionProofBundle` element, or an illegal nested
    bundle or key structure raises TypeError/ValueError, exactly as the
    structural checks of :func:`encode_audit_extension_proof_bundle_chain`
    and :func:`verify_audit_extension_proof_bundle` do. The function is
    stateless.
    """
    if not isinstance(chain, AuditExtensionProofBundleChain):
        raise TypeError(
            "chain must be an AuditExtensionProofBundleChain instance"
        )
    _check_audit_extension_proof_bundle_chain_items(chain.items)

    result = True
    previous = None
    for bundle in chain.items:
        if not verify_audit_extension_proof_bundle(bundle, key):
            result = False
        if previous is not None:
            previous_leaves = previous.proof.leaves
            old_n = bundle.proof.old_n
            if (
                len(previous_leaves) != old_n
                or previous_leaves != bundle.proof.leaves[:old_n]
            ):
                result = False
        previous = bundle
    return result


# ---------------------------------------------------------------------------
# Canonical audit-extension checkpoint chain transport: a self-delimiting,
# byte-for-byte reproducible encoding of a non-empty, order-preserving
# sequence of AuditExtensionProof values together with the n+1 checkpoint
# root signatures that bracket them. Adjacent proofs link when the
# predecessor's leaf set is exactly the successor's old prefix; the shared
# checkpoint signature between two hops is stored only once. Decoding
# restores structure only — the nested proofs go through decode_extension,
# their leaf digests stay opaque and no signature or linkage is checked, so
# verify_audit_extension_checkpoint_chain remains the sole verifier
# afterwards.
# ---------------------------------------------------------------------------

AUDIT_EXTENSION_CHECKPOINT_CHAIN_WIRE_TAG = b"ts/aepcc/v1"


@dataclass(frozen=True)
class AuditExtensionCheckpointChain:
    """A non-empty, order-preserving chain of consistency proofs and checkpoints.

    The fields, in order, are ``proofs`` (the non-empty tuple of
    :class:`AuditExtensionProof` values in chain order) and ``signatures``
    (the tuple of :class:`AggregateSignature` checkpoint root signatures,
    exactly ``len(proofs) + 1`` long): proof ``i`` is bracketed by
    signatures ``i`` (its old root) and ``i + 1`` (its new root), so the
    new-root signature of one hop is the old-root signature of the next.
    For every adjacent proof pair the predecessor's leaf count must equal
    the successor's ``proof.old_n`` and the predecessor's ``leaves`` must
    equal the successor's ``leaves[:old_n]`` (enforced by
    :func:`verify_audit_extension_checkpoint_chain`, not by construction).
    The dataclass is frozen, positionally constructible and compared by
    value, and carries no network, storage or hidden state. Field types
    and bounds are not checked at construction time —
    :func:`encode_audit_extension_checkpoint_chain` checks the structure
    and :func:`verify_audit_extension_checkpoint_chain` is the way to test
    a chain afterwards.
    """

    proofs: tuple[AuditExtensionProof, ...]
    signatures: tuple[AggregateSignature, ...]


def _check_audit_extension_checkpoint_chain_fields(
    chain: object,
) -> tuple[int, tuple[AuditExtensionProof, ...], tuple[AggregateSignature, ...]]:
    """Type- and structure-check a checkpoint chain's fields, without verifying.

    ``proofs`` must be a non-empty tuple of :class:`AuditExtensionProof`
    values and ``signatures`` a tuple of :class:`AggregateSignature`
    values exactly one longer than ``proofs``; the proofs and signatures
    themselves are neither encoded nor verified here (that is
    :func:`check_extension`'s job during verification). Returns
    ``(proof_count, proofs, signatures)``.
    """
    if not isinstance(chain, AuditExtensionCheckpointChain):
        raise TypeError(
            "chain must be an AuditExtensionCheckpointChain instance"
        )
    proofs = chain.proofs
    signatures = chain.signatures
    if not isinstance(proofs, tuple):
        raise TypeError("chain.proofs must be a tuple")
    if not isinstance(signatures, tuple):
        raise TypeError("chain.signatures must be a tuple")
    try:
        proof_count = len(proofs)
        signature_count = len(signatures)
    except OverflowError:
        raise ValueError("too many chain items") from None
    if proof_count == 0:
        raise ValueError("chain.proofs must be non-empty")
    for proof in proofs:
        if not isinstance(proof, AuditExtensionProof):
            raise TypeError(
                "each chain proof must be an AuditExtensionProof instance"
            )
    for signature in signatures:
        if not isinstance(signature, AggregateSignature):
            raise TypeError(
                "each chain signature must be an AggregateSignature instance"
            )
    if signature_count != proof_count + 1:
        raise ValueError(
            "chain.signatures must contain exactly len(chain.proofs) + 1 "
            "signatures"
        )
    return proof_count, proofs, signatures


def encode_audit_extension_checkpoint_chain(
    chain: AuditExtensionCheckpointChain,
) -> bytes:
    """Canonically encode a checkpoint chain for transport or persistence.

    The encoding is, in order, the tag ``b"ts/aepcc/v1"``, the proof count
    ``n = len(chain.proofs)`` as a 4-byte unsigned big-endian integer, then
    one frame per proof in chain order — each the 4-byte unsigned
    big-endian length ``len(E)`` followed by
    ``E = encode_extension(proof)`` (never empty) — and finally the
    ``n + 1`` checkpoint signature frames in order, proof ``i`` bracketed
    by frames ``i`` and ``i + 1``. Every signature frame is exactly the
    signature frame of :func:`encode_audit_proof_bundle`:
    ``VARINT(R)``, ``VARINT(z)``, the 4-byte unsigned big-endian signer
    count ``k`` and one ``VARINT(id)`` per ascending signer id.

    Only the chain container and the nested proof and signature
    structures are checked — the prefix linkage is not verified and no
    signature is checked against any root:
    :func:`verify_audit_extension_checkpoint_chain` stays the way to
    verify a chain afterwards. A non-chain argument or non-tuple field
    raises TypeError, and a non-:class:`AuditExtensionProof` proof or
    non-:class:`AggregateSignature` signature element raises TypeError
    exactly as :func:`encode_extension` and
    :func:`encode_audit_extension_proof_bundle` do for their fields. An
    empty proof tuple, a signature count other than ``n + 1``, an
    over-long count or frame, or an illegal nested proof or signature
    raises ValueError. The output for a given chain is unique and the
    encoding carries no network, storage or hidden state.
    """
    proof_count, proofs, signatures = (
        _check_audit_extension_checkpoint_chain_fields(chain)
    )
    if proof_count > 0xFFFFFFFF:
        raise ValueError("too many chain proofs")

    bodies = []
    for proof in proofs:
        body = encode_extension(proof)
        if len(body) > 0xFFFFFFFF:
            raise ValueError("audit extension proof encoding too long")
        bodies.append(body)

    signer_counts = []
    for index, signature in enumerate(signatures):
        signer_count = _check_history_proof_bundle_signature(
            signature, field=f"chain.signatures[{index}]"
        )
        if signer_count > 0xFFFFFFFF:
            raise ValueError("too many signer ids")
        signer_counts.append(signer_count)

    buffer = bytearray(AUDIT_EXTENSION_CHECKPOINT_CHAIN_WIRE_TAG)
    buffer += proof_count.to_bytes(4, "big", signed=False)
    for body in bodies:
        buffer += len(body).to_bytes(4, "big", signed=False)
        buffer += body
    for signature, signer_count in zip(signatures, signer_counts):
        buffer += _encode_varint(signature.R)
        buffer += _encode_varint(signature.z)
        buffer += signer_count.to_bytes(4, "big", signed=False)
        for signer_id in signature.signer_ids:
            buffer += _encode_varint(signer_id)
    return bytes(buffer)


def decode_audit_extension_checkpoint_chain(
    blob: bytes,
) -> AuditExtensionCheckpointChain:
    """Decode the canonical encoding produced by :func:`encode_audit_extension_checkpoint_chain`.

    Accepts only the single canonical form: the tag
    ``b"ts/aepcc/v1"``, the 4-byte unsigned big-endian non-zero proof
    count ``n``, then exactly ``n`` frames, each a 4-byte unsigned
    big-endian non-zero length followed by bytes that
    :func:`decode_extension` accepts, and finally exactly ``n + 1``
    signature frames, each the length-prefixed integers ``R`` and ``z``,
    the 4-byte non-zero signer count ``k`` and exactly ``k`` strictly
    increasing positive signer ids. A non-bytes argument raises
    TypeError; a wrong or missing tag, an empty chain, a zero or
    over-long proof frame length, a non-canonical nested proof or
    signature integer, a zero ``R``, a zero signer count, a non-positive
    or non-increasing signer id, a count mismatch, truncation, or
    trailing bytes raises ValueError. A successfully decoded chain
    re-encodes to exactly the input bytes.

    Decoding only restores the structure: every nested proof goes through
    :func:`decode_extension`, whose leaf digests stay opaque, no
    signature frame is checked and the prefix linkage between adjacent
    proofs is not checked either. A structurally legal chain whose
    signatures do not match or whose proofs do not link is returned
    normally, and :func:`verify_audit_extension_checkpoint_chain`
    reports it as ``False``.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not blob.startswith(AUDIT_EXTENSION_CHECKPOINT_CHAIN_WIRE_TAG):
        raise ValueError("bad audit extension checkpoint chain tag")
    offset = len(AUDIT_EXTENSION_CHECKPOINT_CHAIN_WIRE_TAG)

    if offset + 4 > len(blob):
        raise ValueError("truncated audit extension checkpoint chain count")
    count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    if count == 0:
        raise ValueError("audit extension checkpoint chain must be non-empty")

    proofs = []
    for index in range(count):
        body, offset = _read_audit_proof_block(
            blob,
            offset,
            what=f"audit extension checkpoint chain proof {index + 1}",
        )
        proofs.append(decode_extension(body))

    signatures = []
    for index in range(count + 1):
        signature, offset = _read_bundle_signature_frame(
            blob,
            offset,
            what=f"audit extension checkpoint chain signature {index + 1}",
        )
        signatures.append(signature)
    if offset != len(blob):
        raise ValueError(
            "trailing bytes after audit extension checkpoint chain"
        )

    chain = AuditExtensionCheckpointChain(
        proofs=tuple(proofs), signatures=tuple(signatures)
    )
    if encode_audit_extension_checkpoint_chain(chain) != blob:
        raise ValueError(
            "non-canonical audit extension checkpoint chain encoding"
        )
    return chain


def verify_audit_extension_checkpoint_chain(
    chain: AuditExtensionCheckpointChain, key: SigningDKGResult
) -> bool:
    """Verify every proof hop of a checkpoint chain and the linkage between neighbours.

    Proof ``i`` is verified with
    ``check_extension(chain.proofs[i], chain.signatures[i],
    chain.signatures[i + 1], key)``: the checkpoint signatures bracket
    each hop and the new root of one hop shares its signature with the
    next hop's old root. For every adjacent proof pair the predecessor's
    leaf count must equal the successor's ``old_n`` and the
    predecessor's ``leaves`` must equal the first ``old_n`` leaves of the
    successor's ``leaves`` — the old tree of each hop is exactly the new
    tree of the previous one. Returns ``True`` only when every hop
    verifies and every linkage holds; a well-formed chain with a
    mismatched signature, tampered leaves, a gap or overlap between
    neighbours, or one presented under another key returns ``False``.

    A non-:class:`AuditExtensionCheckpointChain` argument raises
    TypeError; an empty proof tuple, a non-tuple field, a
    non-:class:`AuditExtensionProof` proof or
    non-:class:`AggregateSignature` signature element, a signature count
    other than ``len(proofs) + 1``, or an illegal nested proof or key
    structure raises TypeError/ValueError, exactly as the structural
    checks of :func:`encode_audit_extension_checkpoint_chain` and
    :func:`check_extension` do. The function is stateless.
    """
    _proof_count, proofs, signatures = (
        _check_audit_extension_checkpoint_chain_fields(chain)
    )

    result = True
    previous_leaves = None
    for index, proof in enumerate(proofs):
        if not check_extension(
            proof, signatures[index], signatures[index + 1], key
        ):
            result = False
        if previous_leaves is not None:
            old_n = proof.old_n
            if (
                len(previous_leaves) != old_n
                or previous_leaves != proof.leaves[:old_n]
            ):
                result = False
        previous_leaves = proof.leaves
    return result


# ---------------------------------------------------------------------------
# Incremental audit-extension checkpoint chains: a space-saving delta form of
# AuditExtensionCheckpointChain that stores the first hop's proof in full and
# then only the leaves each later hop appends, so the historical leaf digests
# shared by every hop are carried exactly once. The two conversion entry
# points expand the delta form into a plain checkpoint chain (verified by the
# existing verify_audit_extension_checkpoint_chain) and compact a linking
# checkpoint chain back into delta form; neither verifies any signature and
# neither keeps hidden state.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuditExtensionDeltaCheckpointChain:
    """An incremental checkpoint chain that never repeats historical leaves.

    The fields, in order, are ``first`` (the :class:`AuditExtensionProof`
    covering the first hop, carried in full), ``additions`` (the tuple of
    non-empty batches of new 32-byte leaf digests, in chain order — batch
    ``i`` holds exactly the leaves hop ``i + 1`` appends on top of every
    previous leaf) and ``signatures`` (the tuple of
    :class:`AggregateSignature` checkpoint root signatures, exactly
    ``len(additions) + 2`` long): the first proof is bracketed by signatures
    ``0`` and ``1``, and batch ``i`` produces the successor checkpoint
    bracketed by signatures ``i + 1`` and ``i + 2``, so the new-root
    signature of one hop is the old-root signature of the next, stored once.
    The expanded chain has ``len(additions) + 1`` proofs; hop ``i + 1`` has
    ``old_n`` equal to the cumulative leaf count before batch ``i`` and its
    leaves are that prefix followed by batch ``i`` in order. The dataclass is
    frozen, positionally constructible and compared by value, and carries no
    network, storage or hidden state. Field types and bounds are not checked
    at construction time — :func:`expand_audit_extension_delta_checkpoint_chain`
    checks the structure and
    :func:`verify_audit_extension_checkpoint_chain` remains the way to
    verify the expanded chain afterwards.
    """

    first: AuditExtensionProof
    additions: tuple[tuple[bytes, ...], ...]
    signatures: tuple[AggregateSignature, ...]


def _check_audit_extension_delta_checkpoint_chain_fields(
    chain: object,
) -> tuple[
    int,
    AuditExtensionProof,
    tuple[tuple[bytes, ...], ...],
    tuple[AggregateSignature, ...],
]:
    """Type- and structure-check a delta checkpoint chain's fields.

    ``first`` must be an :class:`AuditExtensionProof`, ``additions`` a tuple
    of non-empty tuples of 32-byte ``bytes`` digests and ``signatures`` a
    tuple of :class:`AggregateSignature` values exactly
    ``len(additions) + 2`` long; the nested proof and signatures are not
    validated here (the conversion entry points do that). Wrong field or
    element types raise TypeError; an empty batch, a digest of the wrong
    width or a signature count other than ``len(additions) + 2`` raises
    ValueError. Returns ``(batch_count, first, additions, signatures)``.
    """
    if not isinstance(chain, AuditExtensionDeltaCheckpointChain):
        raise TypeError(
            "chain must be an AuditExtensionDeltaCheckpointChain instance"
        )
    first = chain.first
    additions = chain.additions
    signatures = chain.signatures
    if not isinstance(first, AuditExtensionProof):
        raise TypeError("chain.first must be an AuditExtensionProof instance")
    if not isinstance(additions, tuple):
        raise TypeError("chain.additions must be a tuple")
    if not isinstance(signatures, tuple):
        raise TypeError("chain.signatures must be a tuple")
    for batch in additions:
        if not isinstance(batch, tuple):
            raise TypeError("each chain addition batch must be a tuple")
        for digest in batch:
            if not isinstance(digest, bytes):
                raise TypeError("each chain addition digest must be bytes")
    for signature in signatures:
        if not isinstance(signature, AggregateSignature):
            raise TypeError(
                "each chain signature must be an AggregateSignature instance"
            )
    try:
        batch_count = len(additions)
        signature_count = len(signatures)
    except OverflowError:
        raise ValueError("too many chain items") from None
    for batch in additions:
        if len(batch) == 0:
            raise ValueError("each chain addition batch must be non-empty")
        for digest in batch:
            if len(digest) != AUDIT_PROOF_DIGEST_SIZE:
                raise ValueError(
                    "chain addition digests must be exactly 32 bytes"
                )
    if signature_count != batch_count + 2:
        raise ValueError(
            "chain.signatures must contain exactly len(chain.additions) + 2 "
            "signatures"
        )
    return batch_count, first, additions, signatures


def expand_audit_extension_delta_checkpoint_chain(
    chain: AuditExtensionDeltaCheckpointChain,
) -> AuditExtensionCheckpointChain:
    """Expand a delta checkpoint chain into a plain checkpoint chain.

    The first proof is kept as-is; batch ``i`` of ``chain.additions`` then
    produces hop ``i + 1`` whose ``old_n`` is the cumulative leaf count
    before the batch and whose leaves are that whole prefix followed by the
    batch's digests in their original order, so every historical leaf is
    stored once in the delta form instead of being repeated by every hop.
    The ``len(additions) + 2`` checkpoint signatures are reused in their
    original order: hop ``i`` of the result is bracketed by signatures
    ``i`` and ``i + 1``. No signature is verified here — the expanded
    :class:`AuditExtensionCheckpointChain` is checked by the existing
    :func:`verify_audit_extension_checkpoint_chain`.

    A non-:class:`AuditExtensionDeltaCheckpointChain` argument or a wrong
    field or element type (non-:class:`AuditExtensionProof` ``first``,
    non-tuple fields or batches, non-``bytes`` digests,
    non-:class:`AggregateSignature` signatures) raises TypeError. An empty
    batch, a digest that is not exactly 32 bytes, a signature count other
    than ``len(additions) + 2``, an illegal nested proof or signature, or a
    cumulative leaf count above ``2**64 - 1`` raises ValueError. The
    function is stateless.
    """
    _batch_count, first, additions, signatures = (
        _check_audit_extension_delta_checkpoint_chain_fields(chain)
    )
    _validate_audit_extension_structure(first)
    for index, signature in enumerate(signatures):
        _check_history_proof_bundle_signature(
            signature, field=f"chain.signatures[{index}]"
        )

    proofs = [first]
    leaves = first.leaves
    for batch in additions:
        old_n = len(leaves)
        leaves = leaves + batch
        if len(leaves) > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("too many leaves")
        proofs.append(AuditExtensionProof(old_n=old_n, leaves=leaves))
    return AuditExtensionCheckpointChain(
        proofs=tuple(proofs), signatures=signatures
    )


def compact_audit_extension_delta_checkpoint_chain(
    chain: AuditExtensionCheckpointChain,
) -> AuditExtensionDeltaCheckpointChain:
    """Compact a linking checkpoint chain into its incremental delta form.

    The first hop's proof is kept in full as ``first``; for every later hop
    the batch of newly appended leaves — ``proof.leaves[proof.old_n:]`` — is
    extracted in chain order, so the historical leaves every hop repeats are
    dropped and each leaf digest is stored exactly once. The ``len(proofs) +
    1`` checkpoint signatures are carried over in their original order. No
    signature is verified here — verification stays with
    :func:`verify_audit_extension_checkpoint_chain` on the expanded form.

    A non-:class:`AuditExtensionCheckpointChain` argument or a wrong field
    or element type raises TypeError, exactly as the structural checks of
    :func:`encode_audit_extension_checkpoint_chain` do. An empty chain, a
    signature count other than ``len(proofs) + 1``, an illegal nested proof
    or signature, or a broken prefix between adjacent hops — the
    predecessor's leaves not exactly equal to the successor's first
    ``old_n`` leaves — raises ValueError. The function is stateless.
    """
    _proof_count, proofs, signatures = (
        _check_audit_extension_checkpoint_chain_fields(chain)
    )
    for proof in proofs:
        _validate_audit_extension_structure(proof)
    for index, signature in enumerate(signatures):
        _check_history_proof_bundle_signature(
            signature, field=f"chain.signatures[{index}]"
        )

    additions = []
    previous = proofs[0]
    for proof in proofs[1:]:
        old_n = proof.old_n
        if (
            len(previous.leaves) != old_n
            or previous.leaves != proof.leaves[:old_n]
        ):
            raise ValueError(
                "chain proofs do not link: the predecessor's leaves must be "
                "the successor's old prefix"
            )
        additions.append(proof.leaves[old_n:])
        previous = proof
    return AuditExtensionDeltaCheckpointChain(
        first=proofs[0], additions=tuple(additions), signatures=signatures
    )


def _check_segment_bound(value: object, name: str) -> int:
    """Type-check one half-open segment bound (``start`` or ``stop``).

    The bound must be an integer and, like every other index in the
    library, must not be a boolean; out-of-range values are reported by
    the segment entry points themselves as ValueError.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an integer")
    return value


def slice_audit_extension_delta_checkpoint_chain(
    chain: AuditExtensionDeltaCheckpointChain,
    start: int,
    stop: int,
) -> AuditExtensionDeltaCheckpointChain:
    """Take a non-empty half-open hop segment of a delta checkpoint chain.

    The chain is first expanded into a plain
    :class:`AuditExtensionCheckpointChain`; the segment keeps expanded
    proofs ``start:stop`` and the bracketing signatures
    ``start:stop + 1`` — proof ``i`` stays bracketed by signatures ``i``
    and ``i + 1`` — and the segment is then compacted back into an
    :class:`AuditExtensionDeltaCheckpointChain`. The result is therefore
    exactly the delta form of the plain chain's corresponding interval:
    single-hop, head and tail segments all match it value by value. No
    signature is verified here and no state is kept — verification stays
    with :func:`verify_audit_extension_delta_checkpoint_chain` on the
    result.

    A non-:class:`AuditExtensionDeltaCheckpointChain` chain argument or
    any wrong field or element type raises TypeError, exactly as
    :func:`expand_audit_extension_delta_checkpoint_chain` does; a
    non-integer ``start`` or ``stop`` — booleans included — also raises
    TypeError. A negative or otherwise out-of-range bound or an empty
    interval (``start >= stop``) raises ValueError, as does any
    structural error the expanded chain or its nested proofs or
    signatures would raise on their own.
    """
    start = _check_segment_bound(start, "start")
    stop = _check_segment_bound(stop, "stop")
    expanded = expand_audit_extension_delta_checkpoint_chain(chain)
    proof_count = len(expanded.proofs)
    if start < 0 or stop < 0 or start > proof_count or stop > proof_count:
        raise ValueError("slice bounds out of range")
    if start >= stop:
        raise ValueError("slice interval must be non-empty")
    segment = AuditExtensionCheckpointChain(
        proofs=expanded.proofs[start:stop],
        signatures=expanded.signatures[start:stop + 1],
    )
    return compact_audit_extension_delta_checkpoint_chain(segment)


def concatenate_audit_extension_delta_checkpoint_chains(
    left: AuditExtensionDeltaCheckpointChain,
    right: AuditExtensionDeltaCheckpointChain,
) -> AuditExtensionDeltaCheckpointChain:
    """Concatenate two adjacent delta checkpoint chains into one chain.

    Both chains are first expanded into plain
    :class:`AuditExtensionCheckpointChain` values; the proof sequences
    are joined left then right and the checkpoint signature at the seam
    is kept exactly once — the left chain's last new-root signature and
    the right chain's first old-root signature must be the very same
    value. The left chain's last proof must additionally end on the
    exact tree the right chain's first proof starts from: the left
    proof's ``leaves`` must equal the first ``old_n`` leaves of the
    right proof. The joined plain chain is then compacted back into an
    :class:`AuditExtensionDeltaCheckpointChain`, so the result is the
    delta form of the two expanded chains joined in order and
    round-trips through the canonical encoding byte for byte. No
    signature is verified here and no state is kept — verification
    stays with :func:`verify_audit_extension_delta_checkpoint_chain` on
    the result.

    A non-:class:`AuditExtensionDeltaCheckpointChain` argument or any
    wrong field or element type raises TypeError, exactly as
    :func:`expand_audit_extension_delta_checkpoint_chain` does. A leaf
    prefix mismatch at the seam (a gap or overlap between the last left
    hop and the first right hop) or a mismatch between the two shared
    checkpoint signatures raises ValueError, as does any structural
    error either chain or its nested proofs or signatures would raise on
    its own.
    """
    left_expanded = expand_audit_extension_delta_checkpoint_chain(left)
    right_expanded = expand_audit_extension_delta_checkpoint_chain(right)

    left_last = left_expanded.proofs[-1]
    right_first = right_expanded.proofs[0]
    old_n = right_first.old_n
    if len(left_last.leaves) != old_n or left_last.leaves != right_first.leaves[:old_n]:
        raise ValueError(
            "chains do not link: the left chain's last leaves must be the "
            "right chain's first proof old prefix"
        )
    if left_expanded.signatures[-1] != right_expanded.signatures[0]:
        raise ValueError(
            "chains do not link: the shared checkpoint signature must be "
            "identical by value"
        )

    joined = AuditExtensionCheckpointChain(
        proofs=left_expanded.proofs + right_expanded.proofs,
        signatures=(
            left_expanded.signatures + right_expanded.signatures[1:]
        ),
    )
    result = compact_audit_extension_delta_checkpoint_chain(joined)

    # Defence in depth: the returned delta chain must expand back into
    # exactly the two expanded chains joined in order, and its canonical
    # encoding must round-trip byte for byte; refuse anything else.
    reexpanded = expand_audit_extension_delta_checkpoint_chain(result)
    if reexpanded != joined:
        raise ValueError("concatenated chain does not match the joined chains")
    encoded = encode_audit_extension_delta_checkpoint_chain(result)
    if decode_audit_extension_delta_checkpoint_chain(encoded) != result:
        raise ValueError("concatenated chain does not encode byte for byte")
    return result


def partition_delta_chain(
    chain: AuditExtensionDeltaCheckpointChain,
    cuts: tuple[int, ...],
) -> tuple[AuditExtensionDeltaCheckpointChain, ...]:
    """Split a delta checkpoint chain into consecutive hop segments.

    ``cuts`` is a tuple of boundary indices into the expanded chain's
    ``proofs`` sequence: cut ``c`` ends one segment just before expanded
    proof ``c`` and starts the next segment at it, exactly as repeated
    :func:`slice_audit_extension_delta_checkpoint_chain` calls over the
    intervals ``[0, cuts[0])``, ``[cuts[0], cuts[1])``, ...,
    ``[cuts[-1], len(proofs))`` would. The cuts must be strictly
    increasing (hence unique) and each must lie in
    ``1..len(proofs) - 1``, so every segment is non-empty; an empty
    ``cuts`` tuple returns the whole chain as the single segment. The
    segments are returned in chain order as a tuple of
    :class:`AuditExtensionDeltaCheckpointChain` values, each the delta
    form of its expanded interval. No signature is verified here and no
    state is kept — verification stays with
    :func:`verify_audit_extension_delta_checkpoint_chain` on each
    segment, and :func:`join_delta_chain_segments` folds the segments
    back into the original chain.

    A non-:class:`AuditExtensionDeltaCheckpointChain` chain argument or
    any wrong field or element type raises TypeError, exactly as
    :func:`expand_audit_extension_delta_checkpoint_chain` does; a
    non-tuple ``cuts`` or a non-integer cut — booleans included — also
    raises TypeError. A repeated, non-increasing or out-of-range cut
    raises ValueError, as does any structural error the expanded chain
    or its nested proofs or signatures would raise on their own.
    """
    expanded = expand_audit_extension_delta_checkpoint_chain(chain)
    if not isinstance(cuts, tuple):
        raise TypeError("cuts must be a tuple")
    proof_count = len(expanded.proofs)
    previous = 0
    for cut in cuts:
        _check_segment_bound(cut, "each cut")
        if cut < 1 or cut > proof_count - 1:
            raise ValueError(
                "each cut must lie in 1..len(proofs) - 1"
            )
        if cut <= previous:
            raise ValueError("cuts must be strictly increasing and unique")
        previous = cut

    bounds = (0,) + cuts + (proof_count,)
    segments = []
    for index in range(len(bounds) - 1):
        start = bounds[index]
        stop = bounds[index + 1]
        if start >= stop:
            raise ValueError("partition segments must be non-empty")
        segment = AuditExtensionCheckpointChain(
            proofs=expanded.proofs[start:stop],
            signatures=expanded.signatures[start:stop + 1],
        )
        segments.append(
            compact_audit_extension_delta_checkpoint_chain(segment)
        )
    return tuple(segments)


def join_delta_chain_segments(
    segments: tuple[AuditExtensionDeltaCheckpointChain, ...],
) -> AuditExtensionDeltaCheckpointChain:
    """Fold an ordered tuple of delta chain segments into one chain.

    ``segments`` must be a non-empty tuple of
    :class:`AuditExtensionDeltaCheckpointChain` values in chain order;
    they are joined left to right by repeated
    :func:`concatenate_audit_extension_delta_checkpoint_chains` calls,
    so each seam must satisfy the same two link conditions as that
    pairwise splice: the left segment's last expanded leaves must equal
    the old prefix of the right segment's first expanded proof, and the
    two shared checkpoint signatures at the seam must be identical by
    value. A single segment is returned as the chain itself. In
    particular, joining the tuple produced by
    :func:`partition_delta_chain` for any legal cuts restores the
    original chain value by value, and its canonical encoding matches
    the original byte for byte. No signature is verified here and no
    state is kept — verification stays with
    :func:`verify_audit_extension_delta_checkpoint_chain` on the
    result.

    A non-tuple ``segments`` argument or a
    non-:class:`AuditExtensionDeltaCheckpointChain` element raises
    TypeError, as does any wrong field or element type inside a
    segment, exactly as
    :func:`expand_audit_extension_delta_checkpoint_chain` does. An
    empty ``segments`` tuple raises ValueError, as does any leaf prefix
    or shared signature mismatch at a seam and any structural error a
    segment or its nested proofs or signatures would raise on its own.
    """
    if not isinstance(segments, tuple):
        raise TypeError("segments must be a tuple")
    for segment in segments:
        if not isinstance(segment, AuditExtensionDeltaCheckpointChain):
            raise TypeError(
                "each segment must be an "
                "AuditExtensionDeltaCheckpointChain instance"
            )
    if len(segments) == 0:
        raise ValueError("segments must be a non-empty tuple")
    for segment in segments:
        _check_audit_extension_delta_checkpoint_chain_fields(segment)

    joined = segments[0]
    for segment in segments[1:]:
        joined = concatenate_audit_extension_delta_checkpoint_chains(
            joined, segment
        )
    return joined


# ---------------------------------------------------------------------------
# Canonical incremental checkpoint-chain transport: a fixed-width,
# byte-for-byte reproducible encoding of an AuditExtensionDeltaCheckpointChain
# for cross-implementation exchange and persistence. Decoding restores
# structure only — the nested first proof goes through decode_extension, its
# leaf digests stay opaque and no signature is checked — so
# verify_audit_extension_delta_checkpoint_chain remains the sole verifier
# afterwards; it expands into a plain AuditExtensionCheckpointChain and reuses
# verify_audit_extension_checkpoint_chain.
# ---------------------------------------------------------------------------

AUDIT_EXTENSION_DELTA_CHECKPOINT_CHAIN_WIRE_TAG = b"ts/aepdcc/v1"


def encode_audit_extension_delta_checkpoint_chain(
    chain: AuditExtensionDeltaCheckpointChain,
) -> bytes:
    """Canonically encode an incremental checkpoint chain for transport or
    persistence.

    The encoding is, in order, the tag ``b"ts/aepdcc/v1"``, the 4-byte
    unsigned big-endian length ``len(P)`` followed by
    ``P = encode_extension(chain.first)`` (never empty), the 4-byte unsigned
    big-endian batch count ``b = len(chain.additions)`` (possibly zero), then
    one frame per addition batch in chain order — each the 4-byte unsigned
    big-endian digest count ``m`` (always non-zero) followed by exactly ``m``
    raw 32-byte leaf digests in their original order, with no further
    separators — and finally the ``b + 2`` checkpoint signature frames in
    order: the first proof is bracketed by frames ``0`` and ``1`` and batch
    ``i`` is bracketed by frames ``i + 1`` and ``i + 2``. Every signature
    frame is exactly the signature frame of
    :func:`encode_audit_proof_bundle`: ``VARINT(R)``, ``VARINT(z)``, the
    4-byte unsigned big-endian signer count ``k`` and one ``VARINT(id)`` per
    ascending signer id.

    Only the chain container and the nested proof and signature structures
    are checked — the prefix linkage is not verified and no signature is
    checked against any root:
    :func:`verify_audit_extension_delta_checkpoint_chain` stays the way to
    verify a chain afterwards. A non-chain argument, a non-tuple field or
    batch, or a non-``bytes`` digest raises TypeError, and a
    non-:class:`AggregateSignature` signature element raises TypeError
    exactly as :func:`encode_extension` and
    :func:`encode_audit_extension_proof_bundle` do for their fields. An
    empty addition batch, a digest that is not exactly 32 bytes, a signature
    count other than ``b + 2``, an over-long count or frame, or an illegal
    nested proof or signature raises ValueError. The output for a given
    chain is unique and the encoding carries no network, storage or hidden
    state.
    """
    batch_count, first, additions, signatures = (
        _check_audit_extension_delta_checkpoint_chain_fields(chain)
    )
    if batch_count > 0xFFFFFFFF:
        raise ValueError("too many chain addition batches")

    encoded_first = encode_extension(first)
    if len(encoded_first) > 0xFFFFFFFF:
        raise ValueError("audit extension proof encoding too long")

    batch_counts = []
    for batch in additions:
        if len(batch) > 0xFFFFFFFF:
            raise ValueError("too many chain addition digests")
        batch_counts.append(len(batch))

    signer_counts = []
    for index, signature in enumerate(signatures):
        signer_count = _check_history_proof_bundle_signature(
            signature, field=f"chain.signatures[{index}]"
        )
        if signer_count > 0xFFFFFFFF:
            raise ValueError("too many signer ids")
        signer_counts.append(signer_count)

    buffer = bytearray(AUDIT_EXTENSION_DELTA_CHECKPOINT_CHAIN_WIRE_TAG)
    buffer += len(encoded_first).to_bytes(4, "big", signed=False)
    buffer += encoded_first
    buffer += batch_count.to_bytes(4, "big", signed=False)
    for batch, digest_count in zip(additions, batch_counts):
        buffer += digest_count.to_bytes(4, "big", signed=False)
        for digest in batch:
            buffer += digest
    for signature, signer_count in zip(signatures, signer_counts):
        buffer += _encode_varint(signature.R)
        buffer += _encode_varint(signature.z)
        buffer += signer_count.to_bytes(4, "big", signed=False)
        for signer_id in signature.signer_ids:
            buffer += _encode_varint(signer_id)
    return bytes(buffer)


def decode_audit_extension_delta_checkpoint_chain(
    blob: bytes,
) -> AuditExtensionDeltaCheckpointChain:
    """Decode the canonical encoding produced by
    :func:`encode_audit_extension_delta_checkpoint_chain`.

    Accepts only the single canonical form: the tag
    ``b"ts/aepdcc/v1"``, a 4-byte unsigned big-endian non-zero length
    followed by bytes that :func:`decode_extension` accepts as the first
    proof, the 4-byte unsigned big-endian batch count ``b`` (possibly
    zero), then exactly ``b`` addition batches, each a 4-byte unsigned
    big-endian non-zero digest count ``m`` followed by exactly ``m`` raw
    32-byte leaf digests, and finally exactly ``b + 2`` signature frames,
    each the length-prefixed integers ``R`` and ``z``, the 4-byte
    non-zero signer count ``k`` and exactly ``k`` strictly increasing
    positive signer ids. A non-bytes argument raises TypeError; a wrong
    or missing tag, a zero or over-long first-proof frame length, a
    non-canonical nested proof or signature integer, a zero ``m`` (an
    empty addition batch), a digest that is not exactly 32 bytes, a zero
    ``R``, a zero signer count, a non-positive or non-increasing signer
    id, a count mismatch, truncation, or trailing bytes raises
    ValueError. A successfully decoded chain re-encodes to exactly the
    input bytes.

    Decoding only restores the structure: the nested first proof goes
    through :func:`decode_extension`, whose leaf digests stay opaque, no
    signature frame is checked and the prefix linkage between the first
    proof and the batches is not checked either. A structurally legal
    chain whose signatures do not match or whose batches do not link is
    returned normally, and
    :func:`verify_audit_extension_delta_checkpoint_chain` reports it as
    ``False``.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not blob.startswith(AUDIT_EXTENSION_DELTA_CHECKPOINT_CHAIN_WIRE_TAG):
        raise ValueError("bad audit extension delta checkpoint chain tag")
    offset = len(AUDIT_EXTENSION_DELTA_CHECKPOINT_CHAIN_WIRE_TAG)

    encoded_first, offset = _read_audit_proof_block(
        blob, offset, what="audit extension delta checkpoint chain first proof"
    )
    first = decode_extension(encoded_first)

    if offset + 4 > len(blob):
        raise ValueError(
            "truncated audit extension delta checkpoint chain batch count"
        )
    batch_count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4

    additions = []
    for batch_index in range(batch_count):
        if offset + 4 > len(blob):
            raise ValueError(
                "truncated audit extension delta checkpoint chain addition "
                f"batch {batch_index + 1} digest count"
            )
        digest_count = int.from_bytes(blob[offset:offset + 4], "big")
        offset += 4
        if digest_count == 0:
            raise ValueError(
                "audit extension delta checkpoint chain addition batches "
                "must be non-empty"
            )
        batch_size = digest_count * AUDIT_PROOF_DIGEST_SIZE
        if offset + batch_size > len(blob):
            raise ValueError(
                "truncated audit extension delta checkpoint chain addition "
                f"batch {batch_index + 1}"
            )
        batch = tuple(
            bytes(
                blob[
                    offset
                    + digest_index * AUDIT_PROOF_DIGEST_SIZE:
                    offset
                    + (digest_index + 1) * AUDIT_PROOF_DIGEST_SIZE
                ]
            )
            for digest_index in range(digest_count)
        )
        additions.append(batch)
        offset += batch_size

    signatures = []
    for index in range(batch_count + 2):
        signature, offset = _read_bundle_signature_frame(
            blob,
            offset,
            what=(
                "audit extension delta checkpoint chain signature "
                f"{index + 1}"
            ),
        )
        signatures.append(signature)
    if offset != len(blob):
        raise ValueError(
            "trailing bytes after audit extension delta checkpoint chain"
        )

    chain = AuditExtensionDeltaCheckpointChain(
        first=first,
        additions=tuple(additions),
        signatures=tuple(signatures),
    )
    if encode_audit_extension_delta_checkpoint_chain(chain) != blob:
        raise ValueError(
            "non-canonical audit extension delta checkpoint chain encoding"
        )
    return chain


def verify_audit_extension_delta_checkpoint_chain(
    chain: AuditExtensionDeltaCheckpointChain, key: SigningDKGResult
) -> bool:
    """Verify an incremental checkpoint chain after expanding it.

    The chain is first expanded into a plain
    :class:`AuditExtensionCheckpointChain` with
    :func:`expand_audit_extension_delta_checkpoint_chain` — the first
    proof kept in full and every addition batch appended on top of the
    cumulative leaves — and the result is checked by the existing
    :func:`verify_audit_extension_checkpoint_chain`: every hop is
    verified with :func:`check_extension` and every adjacent pair must
    link, the predecessor's leaves exactly equal to the successor's
    first ``old_n`` leaves. Returns ``True`` only when every hop
    verifies and every linkage holds; a well-formed chain with a
    mismatched signature, tampered leaves or digests, a gap or overlap
    between neighbours, or one presented under another key returns
    ``False``.

    A non-:class:`AuditExtensionDeltaCheckpointChain` argument raises
    TypeError; a non-tuple field or batch, a non-``bytes`` digest, a
    non-:class:`AggregateSignature` signature element, an empty
    addition batch, a digest that is not exactly 32 bytes, a signature
    count other than ``len(additions) + 2``, or an illegal nested
    proof, signature or key structure raises TypeError/ValueError,
    exactly as the structural checks of
    :func:`encode_audit_extension_delta_checkpoint_chain` and
    :func:`check_extension` do. The function is stateless.
    """
    expanded = expand_audit_extension_delta_checkpoint_chain(chain)
    return verify_audit_extension_checkpoint_chain(expanded, key)


# ---------------------------------------------------------------------------
# Canonical delta-chain segment-set transport: a self-delimiting envelope
# around one or more whole AuditExtensionDeltaCheckpointChain frames so that
# several consecutive segments can be archived or cross-implementation
# transferred as a single object. Like the single-chain codec this restores
# structure only — no signature is checked, seams are not inspected and no
# state is kept — and join_delta_chain_segments remains the sole place that
# judges order continuity and the seams between neighbours.
# ---------------------------------------------------------------------------

DELTA_CHAIN_SEGMENTS_WIRE_TAG = b"thresholdsign/delta-chain-segments/v1"


def encode_delta_chain_segments(
    segments: tuple[AuditExtensionDeltaCheckpointChain, ...],
) -> bytes:
    """Canonically encode a non-empty ordered tuple of delta chain
    segments as one self-delimiting object for archiving or transport.

    The encoding is, in order, the tag
    ``b"thresholdsign/delta-chain-segments/v1"``, the 4-byte unsigned
    big-endian segment count (never zero), then one frame per segment in
    tuple order — each the 4-byte unsigned big-endian byte length
    followed by the exact bytes of
    :func:`encode_audit_extension_delta_checkpoint_chain` for that
    segment, with no further separators.

    Only the tuple container and the structural legality of each
    segment (via its own canonical encoder) are checked — the segments
    are not sorted, no seam between neighbours is inspected and no
    signature is checked: :func:`join_delta_chain_segments` stays the
    way to judge order continuity and the seams, and
    :func:`verify_audit_extension_delta_checkpoint_chain` the way to
    verify the joined result afterwards. A non-tuple ``segments``
    argument or a non-:class:`AuditExtensionDeltaCheckpointChain`
    element raises TypeError, as does any wrong field or element type
    inside a segment, exactly as
    :func:`encode_audit_extension_delta_checkpoint_chain` does. An empty
    tuple, an over-long count or frame, or any structural error a
    segment or its nested proofs or signatures would raise on its own
    raises ValueError. The output for a given tuple is unique and the
    encoding carries no network, storage or hidden state.
    """
    if not isinstance(segments, tuple):
        raise TypeError("segments must be a tuple")
    for segment in segments:
        if not isinstance(segment, AuditExtensionDeltaCheckpointChain):
            raise TypeError(
                "each segment must be an "
                "AuditExtensionDeltaCheckpointChain instance"
            )
    segment_count = len(segments)
    if segment_count == 0:
        raise ValueError("segments must be a non-empty tuple")
    if segment_count > 0xFFFFFFFF:
        raise ValueError("too many delta chain segments")

    frames = []
    for index, segment in enumerate(segments):
        frame = encode_audit_extension_delta_checkpoint_chain(segment)
        if len(frame) > 0xFFFFFFFF:
            raise ValueError(f"delta chain segment {index + 1} too long")
        frames.append(frame)

    buffer = bytearray(DELTA_CHAIN_SEGMENTS_WIRE_TAG)
    buffer += segment_count.to_bytes(4, "big", signed=False)
    for frame in frames:
        buffer += len(frame).to_bytes(4, "big", signed=False)
        buffer += frame
    return bytes(buffer)


def decode_delta_chain_segments(
    blob: bytes,
) -> tuple[AuditExtensionDeltaCheckpointChain, ...]:
    """Decode the canonical segment set produced by
    :func:`encode_delta_chain_segments`.

    Accepts only the single canonical form: the tag
    ``b"thresholdsign/delta-chain-segments/v1"``, a 4-byte unsigned
    big-endian non-zero segment count, then exactly that many frames,
    each a 4-byte unsigned big-endian non-zero byte length followed by
    the exact canonical encoding of one
    :class:`AuditExtensionDeltaCheckpointChain` accepted by
    :func:`decode_audit_extension_delta_checkpoint_chain`. The segments
    are restored in their original order as a tuple; they are not
    sorted, no seam between neighbours is checked and no signature is
    verified — :func:`join_delta_chain_segments` judges order and seams
    afterwards. A non-bytes argument raises TypeError; a wrong or
    missing tag, a zero segment count, a zero or over-long frame length,
    a count mismatch, truncation, trailing bytes, or a frame whose
    nested chain encoding is illegal or non-canonical (including a
    frame that would not re-encode byte for byte) raises ValueError. A
    successfully decoded tuple re-encodes to exactly the input bytes.

    Decoding only restores structure: a set of individually legal but
    mutually incompatible segments is returned normally, and
    :func:`join_delta_chain_segments` reports the mismatch.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not blob.startswith(DELTA_CHAIN_SEGMENTS_WIRE_TAG):
        raise ValueError("bad delta chain segments tag")
    offset = len(DELTA_CHAIN_SEGMENTS_WIRE_TAG)

    if offset + 4 > len(blob):
        raise ValueError("truncated delta chain segments count")
    segment_count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    if segment_count == 0:
        raise ValueError("delta chain segments must be non-empty")

    segments = []
    for index in range(segment_count):
        frame, offset = _read_audit_proof_block(
            blob,
            offset,
            what=f"delta chain segment {index + 1}",
        )
        segments.append(
            decode_audit_extension_delta_checkpoint_chain(frame)
        )
    if offset != len(blob):
        raise ValueError("trailing bytes after delta chain segments")

    segments_tuple = tuple(segments)
    if encode_delta_chain_segments(segments_tuple) != blob:
        raise ValueError("non-canonical delta chain segments encoding")
    return segments_tuple


def verify_delta_chain_segments(
    segments: tuple[AuditExtensionDeltaCheckpointChain, ...],
    key: SigningDKGResult,
) -> bool:
    """Verify an ordered tuple of delta chain segments as one whole chain.

    ``segments`` must be a non-empty tuple of
    :class:`AuditExtensionDeltaCheckpointChain` values in chain order;
    the tuple is checked exactly as it lies — the segments are never
    sorted or otherwise reordered. Each segment is first checked against
    the existing single-chain structural boundary (the same checks
    :func:`expand_audit_extension_delta_checkpoint_chain` performs), the
    segments are then folded left to right with
    :func:`join_delta_chain_segments` — so every seam must satisfy that
    splice's two link conditions: the left segment's last expanded
    leaves must equal the old prefix of the right segment's first
    expanded proof, and the two shared checkpoint signatures at the seam
    must be identical by value — and the joined chain is verified with
    :func:`verify_audit_extension_delta_checkpoint_chain` under ``key``.
    Returns ``True`` only when every segment is structurally legal,
    every seam links and every hop signature of the joined chain
    verifies under ``key``; a structurally legal set presented in the
    wrong order, with a leaf prefix gap or overlap at a seam, with a
    mismatched shared checkpoint signature, with tampered leaf digests
    or checkpoint signatures, or one presented under another key returns
    ``False`` instead of raising. Because the verdict depends only on
    the segment values, round-tripping the tuple through
    :func:`encode_delta_chain_segments` and
    :func:`decode_delta_chain_segments` never changes it.

    A non-tuple ``segments`` argument, a
    non-:class:`AuditExtensionDeltaCheckpointChain` element, a
    non-:class:`SigningDKGResult` ``key`` or any wrong field or element
    type inside a segment raises TypeError, exactly as
    :func:`join_delta_chain_segments` and the structural checks of
    :func:`verify_audit_extension_delta_checkpoint_chain` do. An empty
    ``segments`` tuple or any structural error a segment or its nested
    proofs or signatures would raise on its own — an empty addition
    batch, a digest that is not exactly 32 bytes, a signature count
    other than ``len(additions) + 2``, an illegal nested proof or
    signature — raises ValueError along the existing single-chain
    boundary; only the seam link failures of a structurally legal set
    are reported as ``False``. The function is stateless and keeps no
    hidden state.
    """
    if not isinstance(segments, tuple):
        raise TypeError("segments must be a tuple")
    for segment in segments:
        if not isinstance(segment, AuditExtensionDeltaCheckpointChain):
            raise TypeError(
                "each segment must be an "
                "AuditExtensionDeltaCheckpointChain instance"
            )
    if not isinstance(key, SigningDKGResult):
        raise TypeError("key must be a SigningDKGResult instance")
    if len(segments) == 0:
        raise ValueError("segments must be a non-empty tuple")

    # Structural validation of each segment up front, along the existing
    # single-chain boundary: expansion raises TypeError/ValueError for
    # any illegal nested proof, batch, digest or signature, so the join
    # below can only fail on the seam link conditions of an otherwise
    # legal set — exactly the failures that must surface as False.
    for segment in segments:
        expand_audit_extension_delta_checkpoint_chain(segment)

    try:
        joined = join_delta_chain_segments(segments)
    except ValueError:
        return False
    return verify_audit_extension_delta_checkpoint_chain(joined, key)


# ---------------------------------------------------------------------------
# Stateless failure diagnosis for delta chain segment sets: a companion to
# verify_delta_chain_segments that reports where the first failure lies —
# which segment, which hop inside it, or which seam between neighbours —
# instead of a bare False. The diagnosis only locates the failing check; it
# never guesses at the cryptographic cause behind a mismatch. No state is
# kept and verify_delta_chain_segments is unchanged.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DeltaDiagnosis:
    """The located first failure of a delta chain segment set diagnosis.

    The fields, in order, are ``ok`` (the verdict, exactly the value
    :func:`verify_delta_chain_segments` returns for the same segment tuple
    and key), ``kind`` (one of ``"ok"``, ``"segment"``, ``"leaf"``,
    ``"sig"`` or ``"proof"``), ``segment`` (the zero-based index of the
    segment the first failure was found in, or ``None`` when ``ok`` is
    ``True``) and ``proof`` (the zero-based index of the failing proof hop
    within that segment, or ``None`` when the failure sits at a seam
    between two segments or when ``ok`` is ``True``). A successful
    diagnosis is always ``DeltaDiagnosis(True, "ok", None, None)``. The
    dataclass is frozen, positionally constructible and compared by value,
    and carries no network, storage or hidden state.
    """

    ok: bool
    kind: str
    segment: int | None
    proof: int | None


def diagnose_delta_chain_segments(
    segments: tuple[AuditExtensionDeltaCheckpointChain, ...],
    key: SigningDKGResult,
) -> DeltaDiagnosis:
    """Locate the first failure of a segment set, in input segment order.

    ``segments`` must be a non-empty tuple of
    :class:`AuditExtensionDeltaCheckpointChain` values in chain order,
    checked exactly as it lies — the segments are never sorted or
    otherwise reordered. The diagnosis is the stateless companion of
    :func:`verify_delta_chain_segments`: the returned
    :class:`DeltaDiagnosis`'s ``ok`` field is always exactly the boolean
    that verifier returns for the same arguments, but a failing diagnosis
    additionally pinpoints the first failing check instead of guessing at
    the cryptographic cause behind the mismatch.

    Every segment's structure is fully validated up front, exactly as
    :func:`verify_delta_chain_segments` does — so the checks below only
    ever run on structurally legal segments. The segments are then
    scanned in input order; for each segment the checks run in a fixed
    order: first the adjacent prefix links between the segment's expanded
    proofs, then every proof hop with :func:`check_extension`, then the
    seam to the next segment. The reported ``kind`` is:

    - ``"segment"`` — an adjacent prefix link inside the segment is
      broken: ``proof`` is the zero-based index of the right-hand proof
      of the first broken pair within the segment.
    - ``"proof"`` — :func:`check_extension` rejected a hop:
      ``proof`` is the zero-based index of that hop within the segment.
    - ``"leaf"`` — at the seam to the next segment the left segment's
      last expanded leaves do not equal the old prefix of the right
      segment's first expanded proof; ``proof`` is ``None``. The leaf
      prefix is always checked before the shared signature.
    - ``"sig"`` — the leaf prefix linked but the two shared checkpoint
      signatures at the seam differ by value; ``proof`` is ``None``.

    A fully verifying set returns ``DeltaDiagnosis(True, "ok", None,
    None)``.

    A non-tuple ``segments`` argument, a
    non-:class:`AuditExtensionDeltaCheckpointChain` element, a
    non-:class:`SigningDKGResult` ``key`` or any wrong field or element
    type inside a segment raises TypeError, exactly as
    :func:`verify_delta_chain_segments` does. An empty ``segments`` tuple
    or any structural error a segment or its nested proofs or signatures
    would raise on its own raises ValueError along the same boundary.
    The function is stateless and keeps no hidden state.
    """
    if not isinstance(segments, tuple):
        raise TypeError("segments must be a tuple")
    for segment in segments:
        if not isinstance(segment, AuditExtensionDeltaCheckpointChain):
            raise TypeError(
                "each segment must be an "
                "AuditExtensionDeltaCheckpointChain instance"
            )
    if not isinstance(key, SigningDKGResult):
        raise TypeError("key must be a SigningDKGResult instance")
    if len(segments) == 0:
        raise ValueError("segments must be a non-empty tuple")

    # Full structural validation of every segment up front, along the
    # existing single-chain boundary — exactly as
    # verify_delta_chain_segments does — so the scan below only ever sees
    # structurally legal segments.
    expanded = tuple(
        expand_audit_extension_delta_checkpoint_chain(segment)
        for segment in segments
    )

    for index, chain in enumerate(expanded):
        proofs = chain.proofs
        signatures = chain.signatures

        # Adjacent prefix links between the segment's own expanded proofs.
        previous = proofs[0]
        for proof_index in range(1, len(proofs)):
            proof = proofs[proof_index]
            old_n = proof.old_n
            if (
                len(previous.leaves) != old_n
                or previous.leaves != proof.leaves[:old_n]
            ):
                return DeltaDiagnosis(False, "segment", index, proof_index)
            previous = proof

        # Every proof hop of the segment, bracketed by its signatures.
        for proof_index, proof in enumerate(proofs):
            if not check_extension(
                proof,
                signatures[proof_index],
                signatures[proof_index + 1],
                key,
            ):
                return DeltaDiagnosis(False, "proof", index, proof_index)

        # The seam to the next segment: leaf prefix first, and only once
        # it links the shared checkpoint signature.
        if index + 1 < len(expanded):
            right = expanded[index + 1].proofs[0]
            left_last = proofs[-1]
            old_n = right.old_n
            if (
                len(left_last.leaves) != old_n
                or left_last.leaves != right.leaves[:old_n]
            ):
                return DeltaDiagnosis(False, "leaf", index, None)
            if signatures[-1] != expanded[index + 1].signatures[0]:
                return DeltaDiagnosis(False, "sig", index, None)

    return DeltaDiagnosis(True, "ok", None, None)


# ---------------------------------------------------------------------------
# Frozen delta reports: a threshold Schnorr AggregateSignature over a
# canonical message that binds a DeltaDiagnosis, the SHA256 digest of the
# exact canonical encoding of the diagnosed segment set and the verifying
# public key. DeltaReport is a plain value with no network, storage or
# hidden state; dr_message builds the signed message, encode_dr / decode_dr
# move it over the wire, and verify_dr recomputes the diagnosis and checks
# the signature.
# ---------------------------------------------------------------------------

DELTA_REPORT_TAG = b"ts/dr/v1"
DELTA_REPORT_WIRE_TAG = b"ts/dr/w1"

# Fixed-width big-endian encoding of a DeltaDiagnosis: the verdict first
# (ok -> 1, failure -> 0), then the kind (ok, segment, leaf, sig, proof),
# then the two zero-based indices, each as an unsigned 64-bit big-endian
# integer; an absent index (None) is the all-ones sentinel 2**64 - 1.
_DELTA_REPORT_OK = (0, 1)
_DELTA_REPORT_KINDS = ("ok", "segment", "leaf", "sig", "proof")
_DELTA_REPORT_ABSENT = (1 << 64) - 1


@dataclass(frozen=True)
class DeltaReport:
    """A delta-chain segment diagnosis sealed by one threshold signature.

    ``diagnosis`` is the sealed :class:`DeltaDiagnosis`, ``public_key``
    the verifying public key the report is presented under and
    ``signature`` the threshold Schnorr :class:`AggregateSignature` on
    :func:`dr_message` of the diagnosed segment set, the diagnosis and
    the public key. The dataclass is frozen, positionally constructible
    and compared by value; it carries no network, storage or hidden
    state. Neither field is checked at construction time —
    :func:`encode_dr` requires structural legality and
    :func:`verify_dr` is the way to test a report against a segment set
    afterwards.
    """

    diagnosis: DeltaDiagnosis
    public_key: int
    signature: AggregateSignature


def _encode_delta_diagnosis(diagnosis: DeltaDiagnosis) -> bytes:
    """Encode a DeltaDiagnosis as four unsigned big-endian 64-bit integers.

    In order: the verdict (``1`` for ``ok=True``, ``0`` otherwise), the
    kind index (``"ok"``, ``"segment"``, ``"leaf"``, ``"sig"``,
    ``"proof"`` -> ``0``..``4``), the zero-based segment index and the
    zero-based proof index; an absent index (``None``) is the all-ones
    sentinel ``2**64 - 1``.
    """
    if not isinstance(diagnosis, DeltaDiagnosis):
        raise TypeError("diagnosis must be a DeltaDiagnosis instance")
    if not isinstance(diagnosis.ok, bool):
        raise TypeError("diagnosis.ok must be a boolean")
    if not isinstance(diagnosis.kind, str):
        raise TypeError("diagnosis.kind must be a string")
    if diagnosis.kind not in _DELTA_REPORT_KINDS:
        raise ValueError("diagnosis.kind must be one of ok, segment, leaf, sig, proof")
    kind_code = _DELTA_REPORT_KINDS.index(diagnosis.kind)

    fields = []
    for name, value in (
        ("segment", diagnosis.segment),
        ("proof", diagnosis.proof),
    ):
        if value is None:
            fields.append(_DELTA_REPORT_ABSENT)
        else:
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError(f"diagnosis.{name} must be an integer or None")
            if not 0 <= value < _DELTA_REPORT_ABSENT:
                raise ValueError(
                    f"diagnosis.{name} must fit in an unsigned 64-bit integer"
                )
            fields.append(value)
    segment_code, proof_code = fields

    # The kind fixes which slots must be empty: "ok" carries neither
    # index, "leaf" and "sig" carry only the segment index, and
    # "segment" and "proof" carry both.
    if diagnosis.kind == "ok":
        expected_ok = True
        expected_present = (False, False)
    elif diagnosis.kind in ("leaf", "sig"):
        expected_ok = False
        expected_present = (True, False)
    else:
        expected_ok = False
        expected_present = (True, True)
    if diagnosis.ok is not expected_ok:
        raise ValueError(
            f"diagnosis kind {diagnosis.kind!r} requires ok={expected_ok}"
        )
    if (diagnosis.segment is not None) is not expected_present[0]:
        raise ValueError(
            f"diagnosis kind {diagnosis.kind!r} fixes the segment slot"
        )
    if (diagnosis.proof is not None) is not expected_present[1]:
        raise ValueError(
            f"diagnosis kind {diagnosis.kind!r} fixes the proof slot"
        )

    return b"".join(
        value.to_bytes(8, "big", signed=False)
        for value in (
            _DELTA_REPORT_OK[diagnosis.ok],
            kind_code,
            segment_code,
            proof_code,
        )
    )


def _decode_delta_diagnosis(blob: bytes) -> DeltaDiagnosis:
    """Invert :func:`_encode_delta_diagnosis` on exactly 32 canonical bytes."""
    if len(blob) != 32:
        raise ValueError("delta diagnosis must be exactly 32 bytes")
    ok_code = int.from_bytes(blob[0:8], "big")
    kind_code = int.from_bytes(blob[8:16], "big")
    segment_code = int.from_bytes(blob[16:24], "big")
    proof_code = int.from_bytes(blob[24:32], "big")
    if ok_code not in _DELTA_REPORT_OK:
        raise ValueError("bad delta diagnosis verdict")
    if kind_code >= len(_DELTA_REPORT_KINDS):
        raise ValueError("bad delta diagnosis kind")
    kind = _DELTA_REPORT_KINDS[kind_code]
    ok = ok_code == 1

    segment = None if segment_code == _DELTA_REPORT_ABSENT else segment_code
    proof = None if proof_code == _DELTA_REPORT_ABSENT else proof_code

    if kind == "ok":
        expected = (True, False, False)
    elif kind in ("leaf", "sig"):
        expected = (False, True, False)
    else:
        expected = (False, True, True)
    expected_ok, segment_present, proof_present = expected
    if ok is not expected_ok:
        raise ValueError("delta diagnosis verdict/kind mismatch")
    if (segment is not None) is not segment_present:
        raise ValueError("delta diagnosis segment slot mismatch")
    if (proof is not None) is not proof_present:
        raise ValueError("delta diagnosis proof slot mismatch")

    return DeltaDiagnosis(ok, kind, segment, proof)


def dr_message(
    segments: tuple[AuditExtensionDeltaCheckpointChain, ...],
    diagnosis: DeltaDiagnosis,
    public_key: int,
) -> bytes:
    """Encode the canonical message the threshold key signs for a delta report.

    The message is, in order, the tag ``b"ts/dr/v1"``, the 32-byte
    ``SHA256`` digest of :func:`encode_delta_chain_segments` output ``S``
    for ``segments``, ``VARINT(public_key)`` and the fixed-width
    diagnosis block ``D`` — four unsigned big-endian 64-bit integers:
    the verdict (``ok`` -> ``1``, failure -> ``0``), the kind index
    (``"ok"``, ``"segment"``, ``"leaf"``, ``"sig"``, ``"proof"`` ->
    ``0``..``4``), the segment index and the proof index, with an absent
    index encoded as the all-ones sentinel ``2**64 - 1``. ``VARINT`` is
    the same 4-byte unsigned big-endian length followed by the shortest
    unsigned big-endian value used throughout the canonical transport
    encodings (zero is the single body byte ``00``). The message carries
    no signature and keeps no state.

    ``segments`` must be a non-empty tuple of
    :class:`AuditExtensionDeltaCheckpointChain` values exactly as
    :func:`encode_delta_chain_segments` requires, ``diagnosis`` a
    structurally legal :class:`DeltaDiagnosis` whose kind agrees with its
    verdict and index slots, and ``public_key`` a non-boolean
    non-negative integer. Wrong field types raise TypeError; an empty
    segment tuple, an illegal segment or diagnosis, a negative or
    boolean public key, or an over-long encoding raises ValueError.
    """
    if not isinstance(segments, tuple):
        raise TypeError("segments must be a tuple")
    for segment in segments:
        if not isinstance(segment, AuditExtensionDeltaCheckpointChain):
            raise TypeError(
                "each segment must be an "
                "AuditExtensionDeltaCheckpointChain instance"
            )
    if not isinstance(diagnosis, DeltaDiagnosis):
        raise TypeError("diagnosis must be a DeltaDiagnosis instance")
    if not isinstance(public_key, int) or isinstance(public_key, bool):
        raise TypeError("public_key must be an integer")

    # Raises TypeError/ValueError for an illegal segment set, exactly as
    # the encoder itself; the diagnosis block is validated the same way.
    encoded_segments = encode_delta_chain_segments(segments)
    encoded_diagnosis = _encode_delta_diagnosis(diagnosis)
    encoded_key = _encode_varint(public_key)
    return (
        DELTA_REPORT_TAG
        + hashlib.sha256(encoded_segments).digest()
        + encoded_key
        + encoded_diagnosis
    )


def _check_delta_report_fields(report: object) -> None:
    """Type- and structure-check a DeltaReport value's non-signature fields."""
    if not isinstance(report, DeltaReport):
        raise TypeError("report must be a DeltaReport instance")
    # Validates the whole diagnosis block, including the kind/verdict and
    # kind/index-slot agreement.
    _encode_delta_diagnosis(report.diagnosis)
    if not isinstance(report.public_key, int) or isinstance(report.public_key, bool):
        raise TypeError("public_key must be an integer")
    if report.public_key < 0:
        raise ValueError("public_key must be non-negative")
    _check_history_proof_bundle_signature(
        report.signature, field="report.signature"
    )


def encode_dr(report: DeltaReport) -> bytes:
    """Canonically encode a delta report for transport or persistence.

    The encoding is, in order, the tag ``b"ts/dr/w1"``, the fixed-width
    diagnosis block ``D`` (four unsigned big-endian 64-bit integers,
    exactly as :func:`dr_message` writes it), ``VARINT(public_key)`` —
    the 4-byte unsigned big-endian length followed by the shortest
    unsigned big-endian value (zero is the single body byte ``00``) —
    and then the signature frame: ``VARINT(R)``, ``VARINT(z)``, the
    4-byte unsigned big-endian signer count ``k`` and one ``VARINT(id)``
    per ascending signer id, exactly the signature frame of
    :func:`encode_audit_extension_delta_checkpoint_chain` and
    :func:`encode_seal`.

    Only the structure of the report is checked — the diagnosis is not
    recomputed over any segment set and the signature is not checked:
    :func:`verify_dr` is the way to test a report afterwards. A
    non-:class:`DeltaReport` argument or a wrong field type raises
    TypeError; an illegal diagnosis or public key, an illegal signature
    structure, or an over-long frame raises ValueError. The output for a
    given report is unique and the encoding carries no network, storage
    or hidden state.
    """
    _check_delta_report_fields(report)
    encoded_diagnosis = _encode_delta_diagnosis(report.diagnosis)
    encoded_key = _encode_varint(report.public_key)
    signature = report.signature
    signer_count = len(signature.signer_ids)
    if signer_count > 0xFFFFFFFF:
        raise ValueError("too many signer ids")

    buffer = bytearray(DELTA_REPORT_WIRE_TAG)
    buffer += encoded_diagnosis
    buffer += encoded_key
    buffer += _encode_varint(signature.R)
    buffer += _encode_varint(signature.z)
    buffer += signer_count.to_bytes(4, "big", signed=False)
    for signer_id in signature.signer_ids:
        buffer += _encode_varint(signer_id)
    return bytes(buffer)


def decode_dr(blob: bytes) -> DeltaReport:
    """Decode the canonical encoding produced by :func:`encode_dr`.

    Accepts only the single canonical form: the tag ``b"ts/dr/w1"``, the
    32-byte diagnosis block ``D`` (four unsigned big-endian 64-bit
    integers whose verdict, kind and index slots all agree, with absent
    indices the all-ones sentinel ``2**64 - 1``), the length-prefixed
    public key (zero is the single body byte ``00``), and then the
    signature frame: the length-prefixed integers ``R`` and ``z``, the
    4-byte non-zero signer count ``k`` and exactly ``k`` strictly
    increasing positive signer ids. A non-bytes argument raises
    TypeError; a wrong or missing tag, truncation, a bad verdict or kind,
    a verdict/kind or index-slot mismatch, a non-canonical integer
    (leading zero or over-long length), a zero ``R``, a zero or
    mismatched signer count, or trailing bytes raises ValueError. A
    successfully decoded report re-encodes to exactly the input bytes.

    Decoding only restores the structure: the diagnosis is not
    recomputed and the signature is not checked. A structurally legal
    report whose diagnosis does not match a segment set or whose
    signature does not seal it is returned normally, and
    :func:`verify_dr` reports it as ``False``.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not blob.startswith(DELTA_REPORT_WIRE_TAG):
        raise ValueError("bad delta report tag")
    offset = len(DELTA_REPORT_WIRE_TAG)

    if offset + 32 > len(blob):
        raise ValueError("truncated delta report diagnosis")
    diagnosis = _decode_delta_diagnosis(blob[offset:offset + 32])
    offset += 32

    public_key, offset = _read_varint(
        blob, offset, what="delta report public key"
    )

    R, offset = _read_varint(blob, offset, what="delta report signature R")
    z, offset = _read_varint(blob, offset, what="delta report signature z")
    if R == 0:
        raise ValueError("delta report signature R must be positive")

    if offset + 4 > len(blob):
        raise ValueError("truncated delta report signer count")
    signer_count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    if signer_count == 0:
        raise ValueError("delta report must name at least one signer")

    signer_ids = []
    for _ in range(signer_count):
        signer_id, offset = _read_varint(
            blob, offset, what="delta report signer id"
        )
        if signer_id == 0:
            raise ValueError("delta report signer ids must be positive")
        if signer_ids and signer_id <= signer_ids[-1]:
            raise ValueError(
                "delta report signer ids must be strictly increasing and unique"
            )
        signer_ids.append(signer_id)
    if offset != len(blob):
        raise ValueError("trailing bytes after delta report")

    report = DeltaReport(
        diagnosis=diagnosis,
        public_key=public_key,
        signature=AggregateSignature(
            R=R, z=z, signer_ids=tuple(signer_ids)
        ),
    )
    if encode_dr(report) != blob:
        raise ValueError("non-canonical delta report encoding")
    return report


def verify_dr(
    report: DeltaReport,
    segments: tuple[AuditExtensionDeltaCheckpointChain, ...],
    key: SigningDKGResult,
) -> bool:
    """Verify a delta report against a segment set and the threshold key.

    ``report`` must be a structurally legal :class:`DeltaReport` exactly
    as :func:`encode_dr` requires, ``segments`` a non-empty tuple of
    :class:`AuditExtensionDeltaCheckpointChain` values exactly as
    :func:`diagnose_delta_chain_segments` requires, and ``key`` a legal
    :class:`SigningDKGResult`. Wrong field types raise TypeError; an
    illegal report, an empty or structurally illegal segment set or an
    illegal key structure raises ValueError.

    The diagnosis is recomputed with
    :func:`diagnose_delta_chain_segments` over the exact ``segments``
    and ``key``; the report verifies only when the recomputed diagnosis
    equals the sealed one by value, the report's ``public_key`` equals
    ``key.public_key``, and the signature checks on
    :func:`dr_message` of the segments, the diagnosis and that public
    key via :func:`verify_signature` with the key's group parameters.
    A structurally legal report whose diagnosis does not match, which
    names another public key, whose signature was tampered with, or
    which seals another segment set returns ``False``. The function is
    stateless.
    """
    _check_delta_report_fields(report)
    if not isinstance(segments, tuple):
        raise TypeError("segments must be a tuple")
    for segment in segments:
        if not isinstance(segment, AuditExtensionDeltaCheckpointChain):
            raise TypeError(
                "each segment must be an "
                "AuditExtensionDeltaCheckpointChain instance"
            )
    _result, public_key, field_prime, group_prime, generator = _check_signing_setup(key)
    _check_signing_dkg_structure(key)

    diagnosis = diagnose_delta_chain_segments(segments, key)
    if report.diagnosis != diagnosis:
        return False
    if report.public_key != public_key:
        return False
    message = dr_message(segments, report.diagnosis, public_key)
    return verify_signature(
        message,
        report.signature,
        public_key,
        group_prime=group_prime,
        generator=generator,
        prime=field_prime,
    )


# ---------------------------------------------------------------------------
# Self-contained delta report bundles: a DeltaReport together with the exact
# segment set it diagnoses, so a verifier needs no separately archived copy
# of the segments. Like the other codecs the bundle encoding restores
# structure only — the diagnosis is not recomputed, no seam is inspected and
# no signature is checked — and verify_delta_report_bundle simply delegates
# to verify_dr over the carried segments, so it keeps no state of its own.
# ---------------------------------------------------------------------------

DELTA_REPORT_BUNDLE_WIRE_TAG = b"thresholdsign/delta-report-bundle/v1"


@dataclass(frozen=True)
class DeltaReportBundle:
    """A delta report bundled with the exact segment set it diagnoses.

    The fields, in order, are ``segments`` (a non-empty tuple of
    :class:`AuditExtensionDeltaCheckpointChain` values in chain order,
    exactly the tuple :func:`verify_dr` takes) and ``report`` (the
    :class:`DeltaReport` over those segments). The dataclass is frozen,
    positionally constructible and compared by value; the segments keep
    their order and the bundle carries no network, storage or hidden
    state. Field types and the non-empty bound are not checked at
    construction time — :func:`encode_delta_report_bundle` checks the
    structure and :func:`verify_delta_report_bundle` is the way to test a
    bundle against a key afterwards.
    """

    segments: tuple[AuditExtensionDeltaCheckpointChain, ...]
    report: DeltaReport


def encode_delta_report_bundle(bundle: DeltaReportBundle) -> bytes:
    """Canonically encode a self-contained delta report bundle.

    The encoding is, in order, the tag
    ``b"thresholdsign/delta-report-bundle/v1"``, the 4-byte unsigned
    big-endian segment count (never zero), one frame per segment in
    tuple order — each the 4-byte unsigned big-endian byte length
    followed by the exact bytes of
    :func:`encode_audit_extension_delta_checkpoint_chain` for that
    segment, exactly the layout of
    :func:`encode_delta_chain_segments` — and finally one frame for the
    report: the 4-byte unsigned big-endian length ``len(R)`` followed by
    ``R = encode_dr(bundle.report)`` (never empty). Every U32 is a
    4-byte unsigned big-endian integer.

    Only the bundle container, the segment structures and the report
    structure are checked — the diagnosis is not recomputed over the
    segments, no seam between neighbours is inspected and no signature
    is checked: :func:`verify_delta_report_bundle` is the way to test a
    bundle afterwards. A non-:class:`DeltaReportBundle` argument, a
    non-tuple ``segments`` field, a
    non-:class:`AuditExtensionDeltaCheckpointChain` segment or a
    non-:class:`DeltaReport` report raises TypeError, as does any wrong
    field or element type nested inside a segment or the report. An
    empty segment tuple, an over-long count or frame, or any structural
    error a segment or the report would raise on its own raises
    ValueError. The output for a given bundle is unique and the
    encoding carries no network, storage or hidden state.
    """
    if not isinstance(bundle, DeltaReportBundle):
        raise TypeError("bundle must be a DeltaReportBundle instance")
    # Raises TypeError/ValueError for a non-tuple, empty or structurally
    # illegal segment set, exactly as the segments codec does.
    encoded_segments = encode_delta_chain_segments(bundle.segments)
    # Raises TypeError/ValueError for an illegal report or nested
    # signature, exactly as encode_dr does.
    encoded_report = encode_dr(bundle.report)
    if len(encoded_report) > 0xFFFFFFFF:
        raise ValueError("delta report encoding too long")

    # Re-frame the segment set body (everything after its own tag) rather
    # than re-encoding the frames: the count and frames are exactly the
    # layout the bundle writes.
    buffer = bytearray(DELTA_REPORT_BUNDLE_WIRE_TAG)
    buffer += encoded_segments[len(DELTA_CHAIN_SEGMENTS_WIRE_TAG):]
    buffer += len(encoded_report).to_bytes(4, "big", signed=False)
    buffer += encoded_report
    return bytes(buffer)


def decode_delta_report_bundle(blob: bytes) -> DeltaReportBundle:
    """Decode the canonical encoding produced by
    :func:`encode_delta_report_bundle`.

    Accepts only the single canonical form: the tag
    ``b"thresholdsign/delta-report-bundle/v1"``, a 4-byte unsigned
    big-endian non-zero segment count, then exactly that many frames,
    each a 4-byte unsigned big-endian non-zero byte length followed by
    the exact canonical encoding of one
    :class:`AuditExtensionDeltaCheckpointChain`, and finally one
    non-empty frame that :func:`decode_dr` accepts as the report. The
    segments are restored in their original order as a tuple and the
    report as a :class:`DeltaReport`; they are not matched against each
    other, no seam between neighbours is checked, the diagnosis is not
    recomputed and no signature is verified —
    :func:`verify_delta_report_bundle` judges the bundle afterwards. A
    non-bytes argument raises TypeError; a wrong or missing tag, a zero
    segment count, a zero or over-long frame length, a count mismatch,
    truncation, trailing bytes, or a frame whose nested chain or report
    encoding is illegal or non-canonical (including a frame that would
    not re-encode byte for byte) raises ValueError. A successfully
    decoded bundle re-encodes to exactly the input bytes.

    Decoding only restores structure: a bundle whose report does not
    diagnose the carried segment set or whose signature does not seal
    it is returned normally, and
    :func:`verify_delta_report_bundle` reports it as ``False``.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not blob.startswith(DELTA_REPORT_BUNDLE_WIRE_TAG):
        raise ValueError("bad delta report bundle tag")
    offset = len(DELTA_REPORT_BUNDLE_WIRE_TAG)

    if offset + 4 > len(blob):
        raise ValueError("truncated delta report bundle segment count")
    segment_count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    if segment_count == 0:
        raise ValueError("delta report bundle segments must be non-empty")

    segments = []
    for index in range(segment_count):
        frame, offset = _read_audit_proof_block(
            blob,
            offset,
            what=f"delta report bundle segment {index + 1}",
        )
        segments.append(
            decode_audit_extension_delta_checkpoint_chain(frame)
        )

    report_frame, offset = _read_audit_proof_block(
        blob, offset, what="delta report bundle report"
    )
    report = decode_dr(report_frame)

    if offset != len(blob):
        raise ValueError("trailing bytes after delta report bundle")

    bundle = DeltaReportBundle(segments=tuple(segments), report=report)
    if encode_delta_report_bundle(bundle) != blob:
        raise ValueError("non-canonical delta report bundle encoding")
    return bundle


def verify_delta_report_bundle(
    bundle: DeltaReportBundle, key: SigningDKGResult
) -> bool:
    """Verify a self-contained delta report bundle against the threshold key.

    ``bundle`` must be a structurally legal :class:`DeltaReportBundle`
    exactly as :func:`encode_delta_report_bundle` requires and ``key`` a
    legal :class:`SigningDKGResult`; the carried segment tuple and
    report are passed straight to :func:`verify_dr`, so the verdict is
    exactly that verifier's: the diagnosis is recomputed over the
    bundle's own segments with
    :func:`diagnose_delta_chain_segments`, the report's
    ``public_key`` must equal ``key.public_key`` and the signature must
    check on :func:`dr_message` of the segments, the diagnosis and that
    public key. Returns ``True`` only when all of these agree; a
    structurally legal bundle whose diagnosis does not match the carried
    segments, whose segments' summaries do not match the sealed set,
    whose signature was tampered with, or one presented under another
    key returns ``False`` instead of raising. The function keeps no
    state of its own.

    A non-:class:`DeltaReportBundle` argument or a
    non-:class:`SigningDKGResult` ``key`` raises TypeError; an empty
    segment tuple or any structurally illegal nested segment or report
    raises ValueError, exactly along the boundaries of
    :func:`verify_dr` and :func:`encode_delta_report_bundle`.
    """
    if not isinstance(bundle, DeltaReportBundle):
        raise TypeError("bundle must be a DeltaReportBundle instance")
    return verify_dr(bundle.report, bundle.segments, key)


# ---------------------------------------------------------------------------
# Archives of whole delta report bundles: a non-empty, order-preserving
# batch of DeltaReportBundle values archived as one self-delimiting object.
# Like the other codecs the archive encoding restores structure only — the
# bundles are neither sorted nor matched against one another and no signature
# is checked — and verify_delta_report_bundle_archive simply delegates to
# verify_delta_report_bundle per item, so it keeps no state of its own.
# ---------------------------------------------------------------------------

DELTA_REPORT_BUNDLE_ARCHIVE_WIRE_TAG = (
    b"thresholdsign/delta-report-bundle-archive/v1"
)


@dataclass(frozen=True)
class DeltaReportBundleArchive:
    """A non-empty, order-preserving archive of delta report bundles.

    The single field ``items`` is a non-empty tuple of
    :class:`DeltaReportBundle` values in archive order. The dataclass is
    frozen, positionally constructible and compared by value; the items
    keep their order and the archive carries no network, storage or
    hidden state. Field and element types and the non-empty bound are
    not checked at construction time —
    :func:`encode_delta_report_bundle_archive` checks the structure and
    :func:`verify_delta_report_bundle_archive` is the way to test an
    archive against a key afterwards.
    """

    items: tuple[DeltaReportBundle, ...]


def encode_delta_report_bundle_archive(
    archive: DeltaReportBundleArchive,
) -> bytes:
    """Canonically encode a non-empty ordered archive of delta report
    bundles as one self-delimiting object.

    The encoding is, in order, the tag
    ``b"thresholdsign/delta-report-bundle-archive/v1"``, the 4-byte
    unsigned big-endian item count (never zero), then one frame per
    bundle in tuple order — each the 4-byte unsigned big-endian byte
    length followed by the exact bytes of
    :func:`encode_delta_report_bundle` for that item, with no further
    separators. Every U32 is a 4-byte unsigned big-endian integer.

    Only the archive container and the structure of each individual
    bundle are checked — the items are not sorted or otherwise
    reordered, they are not matched against one another and no
    signature is checked:
    :func:`verify_delta_report_bundle_archive` is the way to test an
    archive afterwards. A non-:class:`DeltaReportBundleArchive`
    argument, a non-tuple ``items`` field or a
    non-:class:`DeltaReportBundle` element raises TypeError, as does
    any wrong field or element type nested inside a bundle, its
    segments or its report. An empty items tuple, an over-long count
    or frame, or any structural error a bundle would raise on its own
    raises ValueError. The output for a given archive is unique and the
    encoding carries no network, storage or hidden state.
    """
    if not isinstance(archive, DeltaReportBundleArchive):
        raise TypeError(
            "archive must be a DeltaReportBundleArchive instance"
        )
    items = archive.items
    if not isinstance(items, tuple):
        raise TypeError("items must be a tuple")
    for item in items:
        if not isinstance(item, DeltaReportBundle):
            raise TypeError(
                "each archive item must be a DeltaReportBundle instance"
            )
    item_count = len(items)
    if item_count == 0:
        raise ValueError("archive items must be a non-empty tuple")
    if item_count > 0xFFFFFFFF:
        raise ValueError("too many delta report bundle archive items")

    # Encode every item first — each call raises TypeError/ValueError
    # for an illegal bundle exactly as the single-bundle codec does —
    # and only then frame the results, so a single illegal item aborts
    # the whole archive.
    frames = []
    for index, item in enumerate(items):
        encoded = encode_delta_report_bundle(item)
        if len(encoded) > 0xFFFFFFFF:
            raise ValueError(
                f"delta report bundle archive item {index + 1} "
                "encoding too long"
            )
        frames.append(encoded)

    buffer = bytearray(DELTA_REPORT_BUNDLE_ARCHIVE_WIRE_TAG)
    buffer += item_count.to_bytes(4, "big", signed=False)
    for encoded in frames:
        buffer += len(encoded).to_bytes(4, "big", signed=False)
        buffer += encoded
    return bytes(buffer)


def decode_delta_report_bundle_archive(
    blob: bytes,
) -> DeltaReportBundleArchive:
    """Decode the canonical encoding produced by
    :func:`encode_delta_report_bundle_archive`.

    Accepts only the single canonical form: the tag
    ``b"thresholdsign/delta-report-bundle-archive/v1"``, a 4-byte
    unsigned big-endian non-zero item count, then exactly that many
    frames, each a 4-byte unsigned big-endian non-zero byte length
    followed by the exact canonical encoding of one
    :class:`DeltaReportBundle` that
    :func:`decode_delta_report_bundle` accepts. The bundles are
    restored in their original order as a tuple; they are neither
    sorted nor matched against one another and no signature is
    verified — :func:`verify_delta_report_bundle_archive` judges the
    archive afterwards. A non-bytes argument raises TypeError; a wrong
    or missing tag, a zero item count, a zero or over-long frame
    length, a count mismatch, truncation, trailing bytes, or a frame
    whose nested bundle, segment or report encoding is illegal or
    non-canonical (including a frame that would not re-encode byte for
    byte) raises ValueError. A successfully decoded archive
    re-encodes to exactly the input bytes.

    Decoding only restores structure: an archive whose bundles do not
    diagnose their carried segment sets or whose signatures do not
    seal them is returned normally, and
    :func:`verify_delta_report_bundle_archive` reports it as
    ``False``.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not blob.startswith(DELTA_REPORT_BUNDLE_ARCHIVE_WIRE_TAG):
        raise ValueError("bad delta report bundle archive tag")
    offset = len(DELTA_REPORT_BUNDLE_ARCHIVE_WIRE_TAG)

    if offset + 4 > len(blob):
        raise ValueError("truncated delta report bundle archive item count")
    item_count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    if item_count == 0:
        raise ValueError("delta report bundle archive items must be non-empty")

    items = []
    for index in range(item_count):
        frame, offset = _read_audit_proof_block(
            blob,
            offset,
            what=f"delta report bundle archive item {index + 1}",
        )
        items.append(decode_delta_report_bundle(frame))

    if offset != len(blob):
        raise ValueError("trailing bytes after delta report bundle archive")

    archive = DeltaReportBundleArchive(items=tuple(items))
    if encode_delta_report_bundle_archive(archive) != blob:
        raise ValueError("non-canonical delta report bundle archive encoding")
    return archive


def verify_delta_report_bundle_archive(
    archive: DeltaReportBundleArchive, key: SigningDKGResult
) -> bool:
    """Verify an archive of delta report bundles against the threshold key.

    ``archive`` must be a structurally legal
    :class:`DeltaReportBundleArchive` exactly as
    :func:`encode_delta_report_bundle_archive` requires and ``key`` a
    legal :class:`SigningDKGResult`; every item is passed to
    :func:`verify_delta_report_bundle` in archive order, so the
    archive verifies only when every single bundle verifies under
    ``key``. The items are neither sorted nor reordered and the
    function keeps no state of its own. A structurally legal archive
    containing one bundle whose diagnosis does not match its carried
    segments, whose signature was tampered with, or which is presented
    under another key returns ``False`` instead of raising.

    A non-:class:`DeltaReportBundleArchive` argument, a non-tuple
    ``items`` field, a non-:class:`DeltaReportBundle` element or a
    non-:class:`SigningDKGResult` ``key`` raises TypeError; an empty
    items tuple or any structurally illegal nested bundle, segment or
    report raises ValueError, exactly along the boundaries of
    :func:`verify_delta_report_bundle` and
    :func:`encode_delta_report_bundle_archive`.
    """
    if not isinstance(archive, DeltaReportBundleArchive):
        raise TypeError(
            "archive must be a DeltaReportBundleArchive instance"
        )
    items = archive.items
    if not isinstance(items, tuple):
        raise TypeError("items must be a tuple")
    for item in items:
        if not isinstance(item, DeltaReportBundle):
            raise TypeError(
                "each archive item must be a DeltaReportBundle instance"
            )
    # Structurally validate every item before any cryptographic verdict,
    # so an empty archive or an illegal bundle at any position raises
    # exactly as the encoder does, independent of an earlier item that
    # is structurally legal but merely fails verification.
    encode_delta_report_bundle_archive(archive)
    return all(
        verify_delta_report_bundle(item, key) for item in items
    )


# ---------------------------------------------------------------------------
# Sealed archives: one threshold Schnorr signature over the canonical
# encoding of a whole DeltaReportBundleArchive. The signed message commits to
# the verifying public key and to the digest of the exact archive encoding,
# so deleting, inserting, reordering or substituting a bundle — or presenting
# the archive under another key — all invalidate the signature. The library
# keeps no state: the seal is a plain value and the archive, like every seal
# it contains, is re-checked on verification.
# ---------------------------------------------------------------------------

DELTA_REPORT_BUNDLE_ARCHIVE_SEAL_TAG = b"ts/dra/v1"
DELTA_REPORT_BUNDLE_ARCHIVE_SEAL_WIRE_TAG = b"ts/dra/w1"


@dataclass(frozen=True)
class DeltaReportBundleArchiveSeal:
    """A whole delta report bundle archive sealed by one threshold signature.

    ``archive`` is the sealed :class:`DeltaReportBundleArchive`;
    ``signature`` is the threshold Schnorr :class:`AggregateSignature` on
    :func:`archive_seal_message` of the archive and the verifying public
    key. The dataclass is frozen, positionally constructible and compared
    by value; it carries no network, storage or hidden state. Neither
    field is checked at construction time —
    :func:`encode_delta_report_bundle_archive_seal` checks the structure
    and :func:`verify_delta_report_bundle_archive_seal` is the way to test
    a seal afterwards.
    """

    archive: DeltaReportBundleArchive
    signature: AggregateSignature


def archive_seal_message(
    archive: DeltaReportBundleArchive, public_key: int
) -> bytes:
    """Encode the canonical message the threshold key signs to seal an archive.

    The message is, in order, the tag ``b"ts/dra/v1"``, the 32-byte
    ``SHA256`` digest of :func:`encode_delta_report_bundle_archive`
    output ``E`` for ``archive``, and ``VARINT(public_key)`` — a 4-byte
    unsigned big-endian length followed by the shortest unsigned
    big-endian value (zero is the single byte ``00``, positive values
    carry no leading zero). It carries no signature and keeps no state.

    ``archive`` must be a structurally legal
    :class:`DeltaReportBundleArchive` exactly as
    :func:`encode_delta_report_bundle_archive` requires and
    ``public_key`` a non-boolean non-negative integer. Wrong field types
    raise TypeError; an illegal archive, a negative or boolean public
    key, or an over-long key encoding raises ValueError.
    """
    if not isinstance(archive, DeltaReportBundleArchive):
        raise TypeError(
            "archive must be a DeltaReportBundleArchive instance"
        )
    if not isinstance(public_key, int) or isinstance(public_key, bool):
        raise TypeError("public_key must be an integer")
    # Raises TypeError/ValueError for an illegal archive, exactly like
    # the encoder itself.
    encoded_archive = encode_delta_report_bundle_archive(archive)
    encoded_key = _encode_varint(public_key)
    return (
        DELTA_REPORT_BUNDLE_ARCHIVE_SEAL_TAG
        + hashlib.sha256(encoded_archive).digest()
        + encoded_key
    )


def encode_delta_report_bundle_archive_seal(
    seal: DeltaReportBundleArchiveSeal,
) -> bytes:
    """Canonically encode a sealed archive for transport or persistence.

    The encoding is, in order, the tag ``b"ts/dra/w1"``, the 4-byte
    unsigned big-endian length ``len(E)`` followed by the raw archive
    encoding ``E = encode_delta_report_bundle_archive(seal.archive)``
    (never empty), and then the same signature frame an
    :class:`AuditProofBundle` carries: ``VARINT(R)``, ``VARINT(z)``, the
    4-byte unsigned big-endian signer count ``k`` and one
    ``VARINT(id)`` per ascending signer id. A ``VARINT`` is a 4-byte
    unsigned big-endian body length followed by the shortest unsigned
    big-endian value (zero is the single byte ``00``, positive values
    carry no leading zero); ``R`` must be positive and ``z`` may be
    zero.

    Only a structurally legal :class:`DeltaReportBundleArchiveSeal` is
    accepted: the archive must be encodable by
    :func:`encode_delta_report_bundle_archive` and the signature an
    :class:`AggregateSignature` with a positive ``R``, a non-negative
    ``z`` and a non-empty tuple of strictly increasing positive ids,
    exactly the structural bounds an :class:`AuditProofBundle` places on
    its own signature. The signature is not checked against the archive
    and the bundled bundles are not verified: the output for a given
    seal is unique and the encoding carries no network, storage or
    hidden state. Wrong field types raise TypeError; an illegal archive
    or signature structure or an over-long frame raises ValueError.
    """
    if not isinstance(seal, DeltaReportBundleArchiveSeal):
        raise TypeError(
            "seal must be a DeltaReportBundleArchiveSeal instance"
        )
    if not isinstance(seal.archive, DeltaReportBundleArchive):
        raise TypeError(
            "seal.archive must be a DeltaReportBundleArchive instance"
        )
    encoded_archive = encode_delta_report_bundle_archive(seal.archive)
    signer_count = _check_history_proof_bundle_signature(seal.signature)
    if len(encoded_archive) > 0xFFFFFFFF:
        raise ValueError("delta report bundle archive encoding too long")
    if signer_count > 0xFFFFFFFF:
        raise ValueError("too many signer ids")

    buffer = bytearray(DELTA_REPORT_BUNDLE_ARCHIVE_SEAL_WIRE_TAG)
    buffer += len(encoded_archive).to_bytes(4, "big", signed=False)
    buffer += encoded_archive
    buffer += _encode_varint(seal.signature.R)
    buffer += _encode_varint(seal.signature.z)
    buffer += signer_count.to_bytes(4, "big", signed=False)
    for signer_id in seal.signature.signer_ids:
        buffer += _encode_varint(signer_id)
    return bytes(buffer)


def decode_delta_report_bundle_archive_seal(
    blob: bytes,
) -> DeltaReportBundleArchiveSeal:
    """Decode the canonical encoding produced by
    :func:`encode_delta_report_bundle_archive_seal`.

    Accepts only the single canonical form: the tag ``b"ts/dra/w1"``, a
    4-byte non-zero archive frame length followed by bytes that
    :func:`decode_delta_report_bundle_archive` accepts, the
    length-prefixed integers ``R`` and ``z``, the 4-byte non-zero
    signer count ``k`` and then exactly ``k`` strictly increasing
    positive signer ids — the exact signature frame layout an
    :class:`AuditProofBundle` uses. A non-bytes argument raises
    TypeError; a wrong or missing tag, a zero or over-long archive
    frame length, a non-canonical nested archive, a zero ``R``, a
    negative value, a zero or mismatched signer count, a non-canonical
    integer (leading zero or over-long length), truncation, or trailing
    bytes raises ValueError. A successfully decoded seal re-encodes to
    exactly the input bytes.

    Decoding only restores the structure: the nested archive is decoded
    with :func:`decode_delta_report_bundle_archive` (which verifies no
    bundle and checks no signature) and the seal signature is not
    checked. A structurally legal seal whose archive does not verify or
    whose signature does not seal it is returned normally, and
    :func:`verify_delta_report_bundle_archive_seal` reports it as
    ``False``.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not blob.startswith(DELTA_REPORT_BUNDLE_ARCHIVE_SEAL_WIRE_TAG):
        raise ValueError("bad delta report bundle archive seal tag")
    offset = len(DELTA_REPORT_BUNDLE_ARCHIVE_SEAL_WIRE_TAG)

    encoded_archive, offset = _read_audit_proof_block(
        blob, offset, what="sealed delta report bundle archive"
    )
    archive = decode_delta_report_bundle_archive(encoded_archive)

    R, offset = _read_varint(
        blob, offset, what="delta report bundle archive seal signature R"
    )
    z, offset = _read_varint(
        blob, offset, what="delta report bundle archive seal signature z"
    )
    if R == 0:
        raise ValueError(
            "delta report bundle archive seal signature R must be positive"
        )

    if offset + 4 > len(blob):
        raise ValueError(
            "truncated delta report bundle archive seal signer count"
        )
    signer_count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    if signer_count == 0:
        raise ValueError(
            "delta report bundle archive seal must name at least one signer"
        )

    signer_ids = []
    for _ in range(signer_count):
        signer_id, offset = _read_varint(
            blob,
            offset,
            what="delta report bundle archive seal signer id",
        )
        if signer_id == 0:
            raise ValueError(
                "delta report bundle archive seal signer ids must be positive"
            )
        if signer_ids and signer_id <= signer_ids[-1]:
            raise ValueError(
                "delta report bundle archive seal signer ids must be "
                "strictly increasing and unique"
            )
        signer_ids.append(signer_id)
    if offset != len(blob):
        raise ValueError(
            "trailing bytes after delta report bundle archive seal"
        )

    seal = DeltaReportBundleArchiveSeal(
        archive=archive,
        signature=AggregateSignature(
            R=R, z=z, signer_ids=tuple(signer_ids)
        ),
    )
    if encode_delta_report_bundle_archive_seal(seal) != blob:
        raise ValueError(
            "non-canonical delta report bundle archive seal encoding"
        )
    return seal


def verify_delta_report_bundle_archive_seal(
    seal: DeltaReportBundleArchiveSeal, key: SigningDKGResult
) -> bool:
    """Verify a sealed archive against its archive and the threshold key.

    ``seal`` must be a structurally legal
    :class:`DeltaReportBundleArchiveSeal` — its archive encodable by
    :func:`encode_delta_report_bundle_archive` and its signature an
    :class:`AggregateSignature` with a positive ``R``, a non-negative
    ``z`` and a non-empty tuple of strictly increasing positive signer
    ids — and ``key`` a legal :class:`SigningDKGResult`. Wrong field
    types raise TypeError; an illegal archive, signature or key
    structure raises ValueError.

    The sealed archive is first checked with
    :func:`verify_delta_report_bundle_archive` against ``key``, so every
    bundled bundle must itself verify; the canonical
    :func:`archive_seal_message` of the archive and ``key.public_key``
    is then checked as the signature's threshold Schnorr message via
    :func:`verify_signature` with the key's group parameters. Returns
    ``True`` only when both checks pass; a well-formed seal whose
    archive contains a bad bundle, whose signature was tampered with,
    or which seals another archive or key returns ``False``. Deleting,
    inserting, reordering or substituting a bundle therefore fails
    verification rather than raising. The function is stateless.
    """
    if not isinstance(seal, DeltaReportBundleArchiveSeal):
        raise TypeError(
            "seal must be a DeltaReportBundleArchiveSeal instance"
        )
    if not isinstance(seal.archive, DeltaReportBundleArchive):
        raise TypeError(
            "seal.archive must be a DeltaReportBundleArchive instance"
        )
    _check_history_proof_bundle_signature(seal.signature)
    _result, public_key, field_prime, group_prime, generator = _check_signing_setup(key)
    _check_signing_dkg_structure(key)

    if not verify_delta_report_bundle_archive(seal.archive, key):
        return False
    message = archive_seal_message(seal.archive, public_key)
    return verify_signature(
        message,
        seal.signature,
        public_key,
        group_prime=group_prime,
        generator=generator,
        prime=field_prime,
    )


# ---------------------------------------------------------------------------
# Chains of sealed archives: a non-empty, order-preserving batch of whole
# DeltaReportBundleArchiveSeal values authenticated by one more threshold
# Schnorr signature. The outer signature binds the digest of a canonical
# framing C over the existing per-seal transport encodings and the verifying
# public key, so deleting, inserting, reordering or substituting a seal — or
# presenting the chain under another key — invalidates it. The chain carries
# no state of its own: every seal (and, through it, every bundle) is re-checked
# on verification before the outer signature is examined.
# ---------------------------------------------------------------------------

DELTA_REPORT_BUNDLE_ARCHIVE_SEAL_CHAIN_TAG = b"dc/m1"
DELTA_REPORT_BUNDLE_ARCHIVE_SEAL_CHAIN_WIRE_TAG = b"ts/drasc/w1"


@dataclass(frozen=True)
class DeltaReportBundleArchiveSealChain:
    """A non-empty ordered chain of sealed archives with one outer signature.

    The fields, in order, are ``items`` — a non-empty tuple of
    :class:`DeltaReportBundleArchiveSeal` values in chain order — and
    ``signature`` — the threshold Schnorr :class:`AggregateSignature` on
    :func:`drasc_message` of the items and the verifying public key. The
    dataclass is frozen, positionally constructible and compared by
    value; the items keep their order and the chain carries no network,
    storage or hidden state. Neither field is checked at construction
    time — :func:`drasc_message` requires structurally legal items and
    :func:`verify_dc` is the way to test a chain against a key
    afterwards.
    """

    items: tuple[DeltaReportBundleArchiveSeal, ...]
    signature: AggregateSignature


def drasc_message(
    items: tuple[DeltaReportBundleArchiveSeal, ...], public_key: int
) -> bytes:
    """Encode the canonical message the threshold key signs for a seal chain.

    The message is, in order, the tag ``b"dc/m1"``, the 32-byte
    ``SHA256`` digest of the canonical framing ``C`` and
    ``VARINT(public_key)`` — a 4-byte unsigned big-endian length followed
    by the shortest unsigned big-endian value (zero is the single byte
    ``00``, positive values carry no leading zero). ``C`` is, in order,
    the 4-byte unsigned big-endian item count followed by, for every
    seal in tuple order, the 4-byte unsigned big-endian byte length and
    the exact bytes ``E`` of
    :func:`encode_delta_report_bundle_archive_seal` for that seal; every
    U32 is a 4-byte unsigned big-endian integer and ``E`` is the existing
    canonical encoding of the archive seal. The message carries no
    signature and keeps no state.

    ``items`` must be a non-empty tuple of structurally legal
    :class:`DeltaReportBundleArchiveSeal` values exactly as
    :func:`encode_delta_report_bundle_archive_seal` requires and
    ``public_key`` a non-boolean non-negative integer. Wrong field or
    nested field types raise TypeError; an empty items tuple, an
    illegal nested seal, a negative public key or an over-long encoding
    raises ValueError.
    """
    if not isinstance(items, tuple):
        raise TypeError("items must be a tuple")
    for item in items:
        if not isinstance(item, DeltaReportBundleArchiveSeal):
            raise TypeError(
                "each chain item must be a "
                "DeltaReportBundleArchiveSeal instance"
            )
    if not isinstance(public_key, int) or isinstance(public_key, bool):
        raise TypeError("public_key must be an integer")

    item_count = len(items)
    if item_count == 0:
        raise ValueError("chain items must be a non-empty tuple")
    if item_count > 0xFFFFFFFF:
        raise ValueError("too many delta report bundle archive seal chain items")

    # Encode every seal first — each call raises TypeError/ValueError
    # for an illegal seal exactly as the single-seal codec does — and
    # only then frame the results, so a single illegal item aborts the
    # whole message.
    frames = []
    for index, item in enumerate(items):
        encoded = encode_delta_report_bundle_archive_seal(item)
        if len(encoded) > 0xFFFFFFFF:
            raise ValueError(
                f"delta report bundle archive seal chain item {index + 1} "
                "encoding too long"
            )
        frames.append(encoded)

    framing = bytearray(item_count.to_bytes(4, "big", signed=False))
    for encoded in frames:
        framing += len(encoded).to_bytes(4, "big", signed=False)
        framing += encoded
    return (
        DELTA_REPORT_BUNDLE_ARCHIVE_SEAL_CHAIN_TAG
        + hashlib.sha256(bytes(framing)).digest()
        + _encode_varint(public_key)
    )


def verify_dc(
    chain: DeltaReportBundleArchiveSealChain, key: SigningDKGResult
) -> bool:
    """Verify a chain of sealed archives against the threshold key.

    ``chain`` must be a structurally legal
    :class:`DeltaReportBundleArchiveSealChain` and ``key`` a legal
    :class:`SigningDKGResult`. The outer signature and the key
    structure are checked first, as is the structure of every item, so
    an illegal outer signature or key is never masked by a bad nested
    archive: a non-:class:`DeltaReportBundleArchiveSealChain` argument,
    a non-tuple ``items`` field, a
    non-:class:`DeltaReportBundleArchiveSeal` element or a
    non-:class:`SigningDKGResult` ``key`` raises TypeError, and an empty
    items tuple, an illegal outer signature structure, an illegal key
    structure or any structurally illegal nested seal raises
    ValueError.

    Every seal is then passed to
    :func:`verify_delta_report_bundle_archive_seal` in chain order, so
    its archive bundles and its own seal signature must all verify
    under ``key``; the canonical :func:`drasc_message` of the items and
    ``key.public_key`` is finally checked as the outer signature's
    threshold Schnorr message via :func:`verify_signature` with the
    key's group parameters. Returns ``True`` only when every per-seal
    check and the outer signature check pass; a structurally legal
    chain whose nested archive, per-seal signature or outer signature
    does not match — including deleting, inserting, reordering or
    substituting a seal, or presenting the chain under another key —
    returns ``False`` rather than raising. The function is stateless.
    """
    if not isinstance(chain, DeltaReportBundleArchiveSealChain):
        raise TypeError(
            "chain must be a DeltaReportBundleArchiveSealChain instance"
        )
    items = chain.items
    if not isinstance(items, tuple):
        raise TypeError("items must be a tuple")
    for item in items:
        if not isinstance(item, DeltaReportBundleArchiveSeal):
            raise TypeError(
                "each chain item must be a "
                "DeltaReportBundleArchiveSeal instance"
            )
    # Check the outer signature and the key before any nested archive is
    # examined, so a bad archive can never mask an illegal outer
    # signature or key; structurally validate every nested seal too,
    # exactly as the single-seal verifier validates its archive.
    _check_history_proof_bundle_signature(chain.signature)
    _result, public_key, field_prime, group_prime, generator = _check_signing_setup(key)
    _check_signing_dkg_structure(key)
    if len(items) == 0:
        raise ValueError("chain items must be a non-empty tuple")
    for item in items:
        encode_delta_report_bundle_archive_seal(item)

    if not all(
        verify_delta_report_bundle_archive_seal(item, key) for item in items
    ):
        return False
    message = drasc_message(items, public_key)
    return verify_signature(
        message,
        chain.signature,
        public_key,
        group_prime=group_prime,
        generator=generator,
        prime=field_prime,
    )


def encode_delta_report_bundle_archive_seal_chain(
    chain: DeltaReportBundleArchiveSealChain,
) -> bytes:
    """Canonically encode a chain of sealed archives for transport or
    persistence.

    The encoding is, in order, the tag ``b"ts/drasc/w1"``, the item count
    ``n = len(chain.items)`` as a 4-byte unsigned big-endian integer, then
    one frame per item strictly in chain order: the 4-byte unsigned
    big-endian length ``len(E)`` followed by
    ``E = encode_delta_report_bundle_archive_seal(item)``, the existing
    canonical single-seal encoding (never empty), and finally one outer
    signature frame, exactly the signature frame an
    :class:`AuditProofBundle` carries: ``VARINT(R)``, ``VARINT(z)``, the
    4-byte unsigned big-endian signer count ``k`` and one ``VARINT(id)``
    per ascending signer id. A ``VARINT`` is a 4-byte unsigned big-endian
    body length followed by the shortest unsigned big-endian value (zero
    is the single byte ``00``, positive values carry no leading zero);
    ``R`` must be positive and ``z`` may be zero.

    Only a structurally legal :class:`DeltaReportBundleArchiveSealChain`
    is accepted: the items must be a non-empty tuple of seals each
    encodable by :func:`encode_delta_report_bundle_archive_seal` and the
    outer signature an :class:`AggregateSignature` with a positive ``R``,
    a non-negative ``z`` and a non-empty tuple of strictly increasing
    positive ids, exactly the structural bounds an
    :class:`AuditProofBundle` places on its own signature. Neither the
    outer signature nor any nested seal signature is checked and the
    sealed archives are not verified: the output for a given chain is
    unique and the encoding carries no network, storage or hidden state.
    A non-chain argument, a non-tuple ``items`` field or a
    non-:class:`DeltaReportBundleArchiveSeal` element raises TypeError;
    an empty chain, an illegal nested seal, an illegal outer signature,
    an over-long count or frame or an over-long signer id list raises
    ValueError.
    """
    if not isinstance(chain, DeltaReportBundleArchiveSealChain):
        raise TypeError(
            "chain must be a DeltaReportBundleArchiveSealChain instance"
        )
    items = chain.items
    if not isinstance(items, tuple):
        raise TypeError("items must be a tuple")
    for item in items:
        if not isinstance(item, DeltaReportBundleArchiveSeal):
            raise TypeError(
                "each chain item must be a "
                "DeltaReportBundleArchiveSeal instance"
            )
    count = len(items)
    if count == 0:
        raise ValueError("chain items must be a non-empty tuple")
    if count > 0xFFFFFFFF:
        raise ValueError(
            "too many delta report bundle archive seal chain items"
        )

    # Encode every seal first — each call raises TypeError/ValueError for
    # an illegal seal exactly as the single-seal codec does — and only
    # then frame the results, so a single illegal item aborts the whole
    # encoding.
    frames = []
    for index, item in enumerate(items):
        encoded = encode_delta_report_bundle_archive_seal(item)
        if len(encoded) > 0xFFFFFFFF:
            raise ValueError(
                f"delta report bundle archive seal chain item {index + 1} "
                "encoding too long"
            )
        frames.append(encoded)

    signer_count = _check_history_proof_bundle_signature(chain.signature)
    if signer_count > 0xFFFFFFFF:
        raise ValueError("too many signer ids")

    buffer = bytearray(DELTA_REPORT_BUNDLE_ARCHIVE_SEAL_CHAIN_WIRE_TAG)
    buffer += count.to_bytes(4, "big", signed=False)
    for encoded in frames:
        buffer += len(encoded).to_bytes(4, "big", signed=False)
        buffer += encoded
    buffer += _encode_varint(chain.signature.R)
    buffer += _encode_varint(chain.signature.z)
    buffer += signer_count.to_bytes(4, "big", signed=False)
    for signer_id in chain.signature.signer_ids:
        buffer += _encode_varint(signer_id)
    return bytes(buffer)


def decode_delta_report_bundle_archive_seal_chain(
    blob: bytes,
) -> DeltaReportBundleArchiveSealChain:
    """Decode the canonical encoding produced by
    :func:`encode_delta_report_bundle_archive_seal_chain`.

    Accepts only the single canonical form: the tag ``b"ts/drasc/w1"``,
    the 4-byte unsigned big-endian non-zero item count ``n``, then
    exactly ``n`` seal frames in order — each a 4-byte unsigned
    big-endian non-zero length followed by bytes that
    :func:`decode_delta_report_bundle_archive_seal` accepts — and finally
    one outer signature frame, the length-prefixed integers ``R`` and
    ``z``, the 4-byte non-zero signer count ``k`` and exactly ``k``
    strictly increasing positive signer ids, the exact signature frame
    layout an :class:`AuditProofBundle` uses. A non-bytes argument raises
    TypeError; a wrong or missing tag, an empty chain, a zero-length or
    over-long seal frame, a count that does not match the number of
    frames, a non-canonical nested seal, a zero ``R``, a non-canonical
    integer (leading zero or over-long length), a zero signer count, a
    non-positive or non-increasing signer id, truncation, or trailing
    bytes raises ValueError. A successfully decoded chain re-encodes to
    exactly the input bytes.

    Decoding only restores the structure: every nested seal goes through
    :func:`decode_delta_report_bundle_archive_seal` (which verifies no
    archive and checks no signature) and the outer signature is not
    checked. A structurally legal chain whose nested seals or outer
    signature do not match is returned normally, and :func:`verify_dc`
    reports it as ``False``.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not blob.startswith(
        DELTA_REPORT_BUNDLE_ARCHIVE_SEAL_CHAIN_WIRE_TAG
    ):
        raise ValueError("bad delta report bundle archive seal chain tag")
    offset = len(DELTA_REPORT_BUNDLE_ARCHIVE_SEAL_CHAIN_WIRE_TAG)

    if offset + 4 > len(blob):
        raise ValueError(
            "truncated delta report bundle archive seal chain item count"
        )
    count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    if count == 0:
        raise ValueError(
            "delta report bundle archive seal chain must be non-empty"
        )

    items = []
    for index in range(count):
        encoded_seal, offset = _read_audit_proof_block(
            blob,
            offset,
            what=(
                "delta report bundle archive seal chain item "
                f"{index + 1}"
            ),
        )
        items.append(decode_delta_report_bundle_archive_seal(encoded_seal))

    signature, offset = _read_bundle_signature_frame(
        blob,
        offset,
        what="delta report bundle archive seal chain outer signature",
    )
    if offset != len(blob):
        raise ValueError(
            "trailing bytes after delta report bundle archive seal chain"
        )

    chain = DeltaReportBundleArchiveSealChain(
        items=tuple(items), signature=signature
    )
    if encode_delta_report_bundle_archive_seal_chain(chain) != blob:
        raise ValueError(
            "non-canonical delta report bundle archive seal chain encoding"
        )
    return chain


# ---------------------------------------------------------------------------
# Compact multi-seal inclusion proofs over a chain of sealed archives: one
# root signature certifies that several disclosed
# DeltaReportBundleArchiveSeal values belong, at fixed positions, to the
# exact non-empty seal sequence a DeltaReportBundleArchiveSealChain
# carries. The tree is SHA256 with its own domain-separated leaf/node
# prefixes over the existing canonical seal encodings; the root statement
# to sign is ``b"ds/r1" || U64(n) || root``. Like the audit multi-proof,
# an SMP carries only the companion digests that are not themselves
# disclosed (and never the odd-tail self-pair), so the whole set can be
# audited from one signature without hidden state, and check_smp re-runs
# verify_delta_report_bundle_archive_seal on every disclosed seal and
# verify_signature on the root signature afterwards.
# ---------------------------------------------------------------------------

SMP_LEAF_TAG = b"ds/l1"
SMP_NODE_TAG = b"ds/n1"
SMP_ROOT_TAG = b"ds/r1"

SMP_DIGEST_SIZE = 32  # SHA256 output width; every tree node is this wide


def _smp_u64(value: int) -> bytes:
    """8-byte unsigned big-endian encoding of a non-negative integer < 2**64."""
    return value.to_bytes(8, "big", signed=False)


def _smp_leaf(index: int, encoded_seal: bytes) -> bytes:
    """The index-bound leaf digest ``H(b"ds/l1" || U64(j) || H(E_j))``."""
    return hashlib.sha256(
        SMP_LEAF_TAG + _smp_u64(index) + hashlib.sha256(encoded_seal).digest()
    ).digest()


def _smp_node(left: bytes, right: bytes) -> bytes:
    """The ordered internal digest ``H(b"ds/n1" || left || right)``."""
    return hashlib.sha256(SMP_NODE_TAG + left + right).digest()


def _smp_levels(encoded_seals: tuple[bytes, ...]) -> list[tuple[bytes, ...]]:
    """Build the leaf level and every internal level up to the single root.

    A level with an odd tail width is paired with its own last node
    duplicated, so every level above the leaves has an even width.
    """
    levels: list[tuple[bytes, ...]] = [
        tuple(
            _smp_leaf(index, encoded_seal)
            for index, encoded_seal in enumerate(encoded_seals)
        )
    ]
    current = levels[0]
    while len(current) > 1:
        if len(current) % 2 == 1:
            current = current + current[-1:]
        current = tuple(
            _smp_node(current[index], current[index + 1])
            for index in range(0, len(current), 2)
        )
        levels.append(current)
    return levels


@dataclass(frozen=True)
class SMP:
    """A compact Merkle inclusion proof for several seals of a seal chain.

    The fields, in order, are ``i`` (the proven leaf positions as a
    non-empty tuple of strictly increasing, unique non-negative integers),
    ``n`` (the total, non-empty chain item count), ``s`` (the proven
    :class:`DeltaReportBundleArchiveSeal` values, one per entry of ``i``
    in the same order) and ``p`` (the 32-byte companion digests consumed
    from the leaf level up to the root, level by level from the leaves
    upward and left to right within a level; the tuple is empty when no
    companion digests are needed). A companion that is itself a disclosed
    node, and an odd-width level's last node (which the tree pairs with
    itself), are never put in ``p``; the order and number of entries are
    therefore fixed uniquely by ``n`` and ``i``. The dataclass is frozen,
    positionally constructible and compared by value, and carries no
    network, storage or hidden state. Field types and bounds are not
    checked at construction time — :func:`check_smp` is the way to test a
    proof afterwards.
    """

    i: tuple[int, ...]
    n: int
    s: tuple[DeltaReportBundleArchiveSeal, ...]
    p: tuple[bytes, ...]


def _required_smp_siblings(count: int, indices: tuple[int, ...]) -> int:
    """Number of 32-byte companion digests an SMP for ``count`` leaves must carry.

    Replays :func:`make_smp`'s level walk structurally: at each level a
    proven node needs a sibling unless it is the odd-width tail (paired
    with itself) or its companion is itself a proven node at that level.
    The answer depends only on ``n`` and the disclosed positions — never
    on the seals or the digests — so it is the unique sibling count both
    the prover and the verifier can demand.
    """
    required = 0
    positions = set(indices)
    width = count
    while width > 1:
        next_positions = set()
        for position in sorted(positions):
            if width % 2 == 1 and position == width - 1:
                # Odd tail with no companion: the tree pairs it with itself.
                pass
            elif (position ^ 1) in positions:
                # The companion is itself a disclosed node; nothing to send.
                pass
            else:
                required += 1
            next_positions.add(position // 2)
        positions = next_positions
        width = (width + 1) // 2
    return required


def make_smp(
    chain: DeltaReportBundleArchiveSealChain,
    indices: tuple[int, ...],
) -> tuple[bytes, SMP]:
    """Build the root statement and a compact inclusion proof for several seals.

    ``chain`` must be an existing
    :class:`DeltaReportBundleArchiveSealChain`, with ``n ==
    len(chain.items)`` a non-empty chain below the 64-bit counter, and
    ``indices`` a non-empty tuple of leaf positions to prove. Every chain
    item is a structurally legal
    :class:`DeltaReportBundleArchiveSeal`, exactly as
    :func:`encode_delta_report_bundle_archive_seal` requires; its
    canonical encoding ``E_j`` is the existing single-seal transport
    encoding. The tree uses SHA256 with leaves
    ``H(b"ds/l1" || U64(j) || H(E_j))`` and internal nodes
    ``H(b"ds/n1" || left || right)``; a level with an odd tail width
    duplicates its last node for pairing. Returns ``(message, proof)``
    where ``message`` is ``b"ds/r1" || U64(n) || root`` (the 8-byte
    unsigned big-endian item count followed by the 32-byte root) — the
    bytes to be threshold-signed — and ``proof`` is the :class:`SMP`
    whose ``n`` is the chain item count and whose ``s`` takes the chain
    items at ``indices``, one to one. Its ``p`` is collected level by
    level from the leaves upward, left to right within a level: when a
    companion position is itself a disclosed node carried in the proof,
    or the node is the last member of an odd-width level (which the tree
    pairs with itself), no companion is appended, and each remaining
    companion digest is appended exactly once. The order and number of
    ``p`` entries are therefore fixed uniquely by ``n`` and ``indices``.

    Wrong argument types raise TypeError: a
    non-:class:`DeltaReportBundleArchiveSealChain` argument, a non-tuple
    ``chain.items`` field, a non-:class:`DeltaReportBundleArchiveSeal`
    element, a non-tuple index sequence or a non-integer (including
    boolean) index. An empty chain or index tuple, a chain length at or
    above ``2**64``, indices that are not strictly increasing and unique,
    or an index outside ``0 <= i < n`` raises ValueError, as does any
    structurally illegal nested seal, exactly as its encoder would.
    """
    if not isinstance(chain, DeltaReportBundleArchiveSealChain):
        raise TypeError(
            "chain must be a DeltaReportBundleArchiveSealChain instance"
        )
    items = chain.items
    if not isinstance(items, tuple):
        raise TypeError("chain.items must be a tuple")
    for item in items:
        if not isinstance(item, DeltaReportBundleArchiveSeal):
            raise TypeError(
                "each chain item must be a DeltaReportBundleArchiveSeal instance"
            )
    if not isinstance(indices, tuple):
        raise TypeError("indices must be a tuple")

    count = len(items)
    if count == 0:
        raise ValueError("chain items must be a non-empty tuple")
    if count > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("too many delta report bundle archive seal chain items")
    if len(indices) == 0:
        raise ValueError("indices must be non-empty")
    previous = -1
    for index in indices:
        if not isinstance(index, int) or isinstance(index, bool):
            raise TypeError("each index must be an integer")
        if index <= previous:
            raise ValueError("indices must be strictly increasing and unique")
        if index < 0 or index >= count:
            raise ValueError("index out of range")
        previous = index

    # Encode every seal first — each call raises TypeError/ValueError for
    # an illegal seal exactly as the single-seal codec does — so the
    # leaves commit to the existing canonical encodings of all items.
    encoded_seals = tuple(
        encode_delta_report_bundle_archive_seal(item) for item in items
    )
    levels = _smp_levels(encoded_seals)

    siblings: list[bytes] = []
    positions = set(indices)
    for level in levels[:-1]:
        width = len(level)
        padded = level if width % 2 == 0 else level + level[-1:]
        next_positions = set()
        for position in sorted(positions):
            if width % 2 == 1 and position == width - 1:
                # Odd tail with no companion: the tree pairs it with itself.
                pass
            elif (position ^ 1) in positions:
                # The companion is itself a disclosed node; nothing to send.
                pass
            else:
                siblings.append(padded[position ^ 1])
            next_positions.add(position // 2)
        positions = next_positions

    root = levels[-1][0]
    proof = SMP(
        i=tuple(indices),
        n=count,
        s=tuple(items[index] for index in indices),
        p=tuple(siblings),
    )
    return SMP_ROOT_TAG + _smp_u64(count) + root, proof


def _validate_smp_structure(
    proof: object,
) -> tuple[tuple[int, ...], int, tuple[DeltaReportBundleArchiveSeal, ...], tuple[bytes, ...]]:
    """Type- and structure-check an :class:`SMP`, returning its fields.

    Only the container structure is checked: the seals are neither
    verified nor decoded here (that is
    :func:`verify_delta_report_bundle_archive_seal`'s job during
    verification) and the companions are kept opaque. The bounds are
    ``0 < n < 2**64``, a non-empty ``i``/``s`` pair of equal length with
    strictly increasing indices in ``0 <= i < n``, structurally legal
    seals in ``s`` exactly as
    :func:`encode_delta_report_bundle_archive_seal` requires, and a
    ``p`` tuple whose entries are exactly 32 bytes. Wrong field types
    raise TypeError; illegal bounds or shapes raise ValueError. The
    number of companions is derived uniquely from ``n`` and ``i`` (the
    compact walk sends one companion per proven node that is neither an
    odd tail nor paired with another proven node), so a missing or extra
    entry raises ValueError here — before any root is rebuilt.
    """
    if not isinstance(proof, SMP):
        raise TypeError("proof must be an SMP instance")
    indices = proof.i
    count = proof.n
    seals = proof.s
    siblings = proof.p
    if not isinstance(indices, tuple):
        raise TypeError("proof.i must be a tuple")
    if not isinstance(count, int) or isinstance(count, bool):
        raise TypeError("proof.n must be an integer")
    if not isinstance(seals, tuple):
        raise TypeError("proof.s must be a tuple")
    if not isinstance(siblings, tuple):
        raise TypeError("proof.p must be a tuple")

    if count <= 0:
        raise ValueError("proof.n must be positive")
    if count > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("too many records")
    if len(indices) == 0:
        raise ValueError("proof.i must be non-empty")
    if len(indices) != len(seals):
        raise ValueError("proof.s must pair one-to-one with proof.i")

    previous = -1
    for index in indices:
        if not isinstance(index, int) or isinstance(index, bool):
            raise TypeError("proof.i entries must be integers")
        if index <= previous:
            raise ValueError("proof.i must be strictly increasing and unique")
        if index < 0 or index >= count:
            raise ValueError("proof.i entry out of range")
        previous = index

    for seal in seals:
        if not isinstance(seal, DeltaReportBundleArchiveSeal):
            raise TypeError(
                "proof.s entries must be DeltaReportBundleArchiveSeal instances"
            )
    # Every disclosed seal must carry the existing canonical encoding, so
    # an empty archive or an illegal signature frame is a structural
    # ValueError rather than a failed verification.
    for seal in seals:
        encode_delta_report_bundle_archive_seal(seal)

    for sibling in siblings:
        if not isinstance(sibling, bytes):
            raise TypeError("proof.p entries must be bytes")
    for sibling in siblings:
        if len(sibling) != SMP_DIGEST_SIZE:
            raise ValueError("proof.p entries must be exactly 32 bytes")
    required_siblings = _required_smp_siblings(count, indices)
    if len(siblings) != required_siblings:
        raise ValueError("proof.p count is not the one determined by n and i")
    return indices, count, seals, siblings


def check_smp(
    proof: SMP,
    signature: AggregateSignature,
    key: SigningDKGResult,
) -> bool:
    """Rebuild an SMP's Merkle root and verify its seals and root signature.

    Every disclosed seal's leaf digest is recomputed from its position
    and the existing canonical encoding ``E`` of its seal exactly as in
    :func:`make_smp`. The root is rebuilt level by level while consuming
    ``proof.p`` in order — levels from the leaves upward, entries left to
    right within a level: the current level holds the digests of the
    proven nodes at their current positions, paired left to right; when
    a companion is itself a current-level node its digest is used
    directly, when the node is the last member of an odd-width level it
    is paired with itself, and otherwise the next 32-byte entry of ``p``
    is consumed. The current width contracts as ``(width + 1) // 2``.
    Every disclosed seal is then re-checked with
    :func:`verify_delta_report_bundle_archive_seal` against ``key`` (in
    index order, so each sealed archive's bundles must themselves
    verify), and the statement ``b"ds/r1" || U64(n) || root`` is checked
    as ``signature``'s threshold Schnorr message via
    :func:`verify_signature`. Returns ``True`` only when the rebuild
    consumes every companion exactly and reaches the single signed root,
    every seal verifies under ``key``, and the signature verifies; a
    well-formed proof whose seals, indices, companions, root or
    signature was tampered with — seals swapped or altered, a missing,
    extra or misplaced companion — or which is presented under another
    key, returns ``False``.

    A non-:class:`SMP` or non-:class:`AggregateSignature` argument or any
    wrong field type (non-tuple ``i``/``s``/``p``, a non-integer ``n`` or
    index including booleans, a non-:class:`DeltaReportBundleArchiveSeal`
    seal or a non-bytes companion) raises TypeError; a non-positive or
    over-64-bit ``n``, empty indices, an index out of range or not
    strictly increasing, an ``s`` tuple that does not pair one-to-one
    with the indices, a structurally illegal seal, an illegal signature
    or key structure, a companion that is not exactly 32 bytes, or too
    few or too many companions for the indicated positions raises
    ValueError, exactly as
    :func:`verify_delta_report_bundle_archive_seal` and
    :func:`verify_signature` would.
    """
    indices, count, seals, siblings = _validate_smp_structure(proof)
    if not isinstance(signature, AggregateSignature):
        raise TypeError("signature must be an AggregateSignature instance")

    # Check the root signature and the key before any leaf is rebuilt, so
    # a bad seal can never mask an illegal signature or key.
    _check_history_proof_bundle_signature(signature)
    _result, public_key, field_prime, group_prime, generator = _check_signing_setup(key)
    _check_signing_dkg_structure(key)

    nodes = {
        index: _smp_leaf(
            index, encode_delta_report_bundle_archive_seal(seal)
        )
        for index, seal in zip(indices, seals)
    }
    pending = iter(siblings)
    width = count
    while width > 1:
        next_nodes = {}
        for position in sorted(nodes):
            parent = position // 2
            if parent in next_nodes:
                continue
            if width % 2 == 1 and position == width - 1:
                # Odd tail with no companion: pair the node with itself.
                next_nodes[parent] = _smp_node(nodes[position], nodes[position])
            elif (position ^ 1) in nodes:
                left = position if position % 2 == 0 else position ^ 1
                next_nodes[parent] = _smp_node(nodes[left], nodes[left ^ 1])
            else:
                try:
                    sibling = next(pending)
                except StopIteration:
                    raise ValueError("proof.p is missing entries") from None
                if position % 2 == 0:
                    next_nodes[parent] = _smp_node(nodes[position], sibling)
                else:
                    next_nodes[parent] = _smp_node(sibling, nodes[position])
        nodes = next_nodes
        width = (width + 1) // 2

    try:
        next(pending)
    except StopIteration:
        pass
    else:
        raise ValueError("proof.p has extra entries")

    signed_message = SMP_ROOT_TAG + _smp_u64(count) + nodes[0]
    if not all(
        verify_delta_report_bundle_archive_seal(seal, key) for seal in seals
    ):
        return False
    return verify_signature(
        signed_message,
        signature,
        public_key,
        group_prime=group_prime,
        generator=generator,
        prime=field_prime,
    )


# ---------------------------------------------------------------------------
# Canonical SMP bundle transport: a self-delimiting, byte-for-byte
# reproducible encoding of an SMP together with the AggregateSignature on its
# b"ds/r1" || U64(n) || root statement, for cross-implementation exchange and
# persistence. Decoding restores structure only — the nested seals go through
# decode_delta_report_bundle_archive_seal, nothing is verified and no state is
# kept, so verify_smp_bundle remains the sole verifier afterwards.
# ---------------------------------------------------------------------------

SMP_BUNDLE_WIRE_TAG = b"ts/smpb/v1"


@dataclass(frozen=True)
class SMPBundle:
    """A compact multi-seal inclusion proof together with its root signature.

    The fields, in order, are ``proof`` (an :class:`SMP`) and
    ``signature`` (the :class:`AggregateSignature` on the proof's
    ``b"ds/r1" || U64(n) || root`` statement). The dataclass is frozen,
    positionally constructible and compared by value, and carries no
    network, storage or hidden state. Field types and bounds are not
    checked at construction time — :func:`encode_smp_bundle` checks the
    structure and :func:`verify_smp_bundle` is the way to test a bundle
    afterwards.
    """

    proof: SMP
    signature: AggregateSignature


def encode_smp_bundle(bundle: SMPBundle) -> bytes:
    """Canonically encode an SMP bundle for transport or persistence.

    The encoding is, in order, the tag ``b"ts/smpb/v1"``, ``VARINT(n)``,
    the 4-byte unsigned big-endian index count ``k`` and one
    ``VARINT(index)`` per strictly increasing disclosed position, the
    4-byte unsigned big-endian seal count (which must equal ``k``) and
    one frame per disclosed seal — a 4-byte unsigned big-endian length
    followed by the existing canonical encoding
    ``E = encode_delta_report_bundle_archive_seal(seal)`` — then the
    4-byte unsigned big-endian companion count and the raw 32-byte
    companion digests in the proof's leaf-to-root, left-to-right order,
    and finally the same signature frame an :class:`AuditProofBundle`
    carries: ``VARINT(R)``, ``VARINT(z)``, the 4-byte unsigned
    big-endian signer count and one ``VARINT(id)`` per ascending signer
    id. A ``VARINT`` is a 4-byte unsigned big-endian body length followed
    by the shortest unsigned big-endian value (zero is the single byte
    ``00``, positive values carry no leading zero); ``R`` must be
    positive and ``z`` may be zero.

    Only a structurally legal :class:`SMPBundle` is accepted — a
    non-bundle or non-:class:`SMP` proof argument, or wrong
    proof/signature field types, raise TypeError and illegal proof or
    signature structure (the exact bounds of :func:`check_smp`:
    ``0 < n < 2**64``, a non-empty strictly increasing index tuple in
    ``0 <= i < n`` with one structurally legal seal each, exactly the
    number of 32-byte companions ``n`` and the indices determine, a
    non-positive ``R``, a negative ``z``, an empty or
    non-strictly-increasing signer id tuple) or an over-long frame
    raises ValueError — but the seals are not verified and the signature
    is not checked against the root: :func:`verify_smp_bundle` stays the
    way to verify a bundle afterwards. The output for a given bundle is
    unique and the encoding carries no network, storage or hidden state.
    """
    if not isinstance(bundle, SMPBundle):
        raise TypeError("bundle must be an SMPBundle instance")
    if not isinstance(bundle.proof, SMP):
        raise TypeError("bundle.proof must be an SMP instance")
    indices, count, seals, siblings = _validate_smp_structure(bundle.proof)
    signer_count = _check_history_proof_bundle_signature(bundle.signature)
    if len(indices) > 0xFFFFFFFF:
        raise ValueError("too many disclosed indices")
    if len(siblings) > 0xFFFFFFFF:
        raise ValueError("too many companion digests")
    encoded_seals = []
    for seal in seals:
        encoded_seal = encode_delta_report_bundle_archive_seal(seal)
        if len(encoded_seal) > 0xFFFFFFFF:
            raise ValueError("seal encoding too long")
        encoded_seals.append(encoded_seal)
    if signer_count > 0xFFFFFFFF:
        raise ValueError("too many signer ids")

    buffer = bytearray(SMP_BUNDLE_WIRE_TAG)
    buffer += _encode_varint(count)
    buffer += len(indices).to_bytes(4, "big", signed=False)
    for index in indices:
        buffer += _encode_varint(index)
    buffer += len(encoded_seals).to_bytes(4, "big", signed=False)
    for encoded_seal in encoded_seals:
        buffer += len(encoded_seal).to_bytes(4, "big", signed=False)
        buffer += encoded_seal
    buffer += len(siblings).to_bytes(4, "big", signed=False)
    for sibling in siblings:
        buffer += sibling
    buffer += _encode_varint(bundle.signature.R)
    buffer += _encode_varint(bundle.signature.z)
    buffer += signer_count.to_bytes(4, "big", signed=False)
    for signer_id in bundle.signature.signer_ids:
        buffer += _encode_varint(signer_id)
    return bytes(buffer)


def decode_smp_bundle(blob: bytes) -> SMPBundle:
    """Decode the canonical encoding produced by :func:`encode_smp_bundle`.

    Accepts only the single canonical form: the tag
    ``b"ts/smpb/v1"``, the length-prefixed integer ``n`` with
    ``0 < n < 2**64``, the 4-byte non-zero index count ``k`` followed by
    ``k`` strictly increasing canonical ``VARINT`` indices in
    ``0 <= i < n``, the 4-byte seal count (which must equal ``k``)
    followed by that many frames — a 4-byte non-zero length followed by
    bytes that :func:`decode_delta_report_bundle_archive_seal` accepts —
    the 4-byte companion count followed by exactly that many raw
    32-byte digests, where the count must be the unique one derived from
    ``n`` and the indices, and finally the signature frame an
    :class:`AuditProofBundle` uses: the length-prefixed integers ``R``
    and ``z`` with ``R`` positive, the 4-byte non-zero signer count and
    then exactly that many strictly increasing positive signer ids. A
    non-bytes argument raises TypeError; a wrong or missing tag, a zero
    or out-of-range ``n``, a zero index count, an out-of-range,
    duplicate or non-increasing index, a seal count that does not equal
    the index count, a zero or over-long seal frame length, a
    non-canonical nested seal, a missing or extra companion relative to
    what ``n`` and the indices require, a companion that is not exactly
    32 bytes, a zero ``R``, a non-canonical integer (leading zero or
    over-long length), a zero signer count, a non-positive or
    non-increasing signer id, truncation, or trailing bytes raises
    ValueError. A successfully decoded bundle re-encodes to exactly the
    input bytes.

    Decoding only restores the structure: every nested seal is decoded
    with :func:`decode_delta_report_bundle_archive_seal` (which verifies
    no bundle and checks no signature) and the root signature is not
    checked. A structurally legal bundle whose seals do not verify or
    whose signature does not sign the root is returned normally, and
    :func:`verify_smp_bundle` reports it as ``False``.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not blob.startswith(SMP_BUNDLE_WIRE_TAG):
        raise ValueError("bad SMP bundle tag")
    offset = len(SMP_BUNDLE_WIRE_TAG)

    count, offset = _read_varint(blob, offset, what="SMP bundle n")
    if count <= 0:
        raise ValueError("SMP bundle n must be positive")
    if count > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("SMP bundle n too large")

    if offset + 4 > len(blob):
        raise ValueError("truncated SMP bundle index count")
    index_count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    if index_count == 0:
        raise ValueError("SMP bundle indices must be non-empty")
    indices = []
    for _ in range(index_count):
        index, offset = _read_varint(
            blob, offset, what="SMP bundle index"
        )
        if indices and index <= indices[-1]:
            raise ValueError(
                "SMP bundle indices must be strictly increasing and unique"
            )
        if index < 0 or index >= count:
            raise ValueError("SMP bundle index out of range")
        indices.append(index)

    if offset + 4 > len(blob):
        raise ValueError("truncated SMP bundle seal count")
    seal_count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    if seal_count != index_count:
        raise ValueError(
            "SMP bundle seal count must match the index count"
        )
    seals = []
    for _ in range(seal_count):
        encoded_seal, offset = _read_audit_proof_block(
            blob, offset, what="SMP bundle seal"
        )
        seals.append(decode_delta_report_bundle_archive_seal(encoded_seal))

    if offset + 4 > len(blob):
        raise ValueError("truncated SMP bundle companion count")
    companion_count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    required_companions = _required_smp_siblings(count, tuple(indices))
    if companion_count != required_companions:
        raise ValueError(
            "SMP bundle companion count is not the one determined by n and i"
        )
    companions = []
    for _ in range(companion_count):
        if offset + SMP_DIGEST_SIZE > len(blob):
            raise ValueError("truncated SMP bundle companion")
        companions.append(
            bytes(blob[offset:offset + SMP_DIGEST_SIZE])
        )
        offset += SMP_DIGEST_SIZE

    R, offset = _read_varint(
        blob, offset, what="SMP bundle signature R"
    )
    z, offset = _read_varint(
        blob, offset, what="SMP bundle signature z"
    )
    if R == 0:
        raise ValueError("SMP bundle signature R must be positive")

    if offset + 4 > len(blob):
        raise ValueError("truncated SMP bundle signer count")
    signer_count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    if signer_count == 0:
        raise ValueError("SMP bundle must name at least one signer")

    signer_ids = []
    for _ in range(signer_count):
        signer_id, offset = _read_varint(
            blob,
            offset,
            what="SMP bundle signer id",
        )
        if signer_id == 0:
            raise ValueError("SMP bundle signer ids must be positive")
        if signer_ids and signer_id <= signer_ids[-1]:
            raise ValueError(
                "SMP bundle signer ids must be strictly increasing and unique"
            )
        signer_ids.append(signer_id)
    if offset != len(blob):
        raise ValueError("trailing bytes after SMP bundle")

    bundle = SMPBundle(
        proof=SMP(
            i=tuple(indices),
            n=count,
            s=tuple(seals),
            p=tuple(companions),
        ),
        signature=AggregateSignature(
            R=R, z=z, signer_ids=tuple(signer_ids)
        ),
    )
    if encode_smp_bundle(bundle) != blob:
        raise ValueError("non-canonical SMP bundle encoding")
    return bundle


def verify_smp_bundle(bundle: SMPBundle, key: SigningDKGResult) -> bool:
    """Verify a bundle exactly as :func:`check_smp` would.

    This is a convenience wrapper over
    ``check_smp(bundle.proof, bundle.signature, key)``: the Merkle root
    is rebuilt from the proof while every disclosed seal is re-checked
    with :func:`verify_delta_report_bundle_archive_seal`, and the
    signature is verified on ``b"ds/r1" || U64(n) || root``. Returns
    ``True`` only when all of them hold; a well-formed bundle with
    tampered seals, indices, companions or signature, or one presented
    under another key, returns ``False``.

    A non-:class:`SMPBundle` argument raises TypeError; illegal nested
    proof, signature or key structure raises TypeError/ValueError,
    exactly as :func:`check_smp` does.
    """
    if not isinstance(bundle, SMPBundle):
        raise TypeError("bundle must be an SMPBundle instance")
    return check_smp(bundle.proof, bundle.signature, key)


# ---------------------------------------------------------------------------
# Archives of SMP bundles: a non-empty, order-preserving batch of whole
# SMPBundle values authenticated by one more threshold Schnorr signature.
# The outer signature binds the digest of a canonical framing C over the
# existing per-bundle transport encodings and the verifying public key, so
# deleting, inserting, reordering or substituting a bundle — or presenting
# the archive under another key — invalidates it. The archive carries no
# state of its own: every bundle is re-checked with verify_smp_bundle (and,
# through it, every disclosed seal) on verification before the outer
# signature is examined via verify_signature.
# ---------------------------------------------------------------------------

SMP_BUNDLE_ARCHIVE_TAG = b"ts/smpba/m1"
SMP_BUNDLE_ARCHIVE_WIRE_TAG = (
    b"thresholdsign/smp-bundle-archive/v1"
)


@dataclass(frozen=True)
class SMPBundleArchive:
    """A non-empty ordered archive of SMP bundles with one outer signature.

    The fields, in order, are ``items`` — a non-empty tuple of
    :class:`SMPBundle` values in archive order — and ``signature`` — the
    threshold Schnorr :class:`AggregateSignature` on
    :func:`smp_bundle_archive_message` of the items and the verifying
    public key. The dataclass is frozen, positionally constructible and
    compared by value; the items keep their order and the archive carries
    no network, storage or hidden state. Neither field is checked at
    construction time — :func:`smp_bundle_archive_message` requires
    structurally legal items and :func:`verify_smp_bundle_archive` is the
    way to test an archive against a key afterwards.
    """

    items: tuple[SMPBundle, ...]
    signature: AggregateSignature


def smp_bundle_archive_message(
    items: tuple[SMPBundle, ...], public_key: int
) -> bytes:
    """Encode the canonical message the threshold key signs for an archive.

    The message is, in order, the tag ``b"ts/smpba/m1"``, the 32-byte
    ``SHA256`` digest of the canonical framing ``C`` and
    ``V(public_key)`` — a 4-byte unsigned big-endian length followed by
    the shortest unsigned big-endian value (zero is the single byte
    ``00``, positive values carry no leading zero). With
    ``E_i = encode_smp_bundle(items[i])`` and ``n`` the item count, ``C``
    is built in tuple order as ``U32(n) || Σ(U32(len(E_i)) || E_i)``;
    every ``U32`` is a 4-byte unsigned big-endian integer and ``E_i`` is
    the existing canonical transport encoding of the bundle. The message
    carries no signature and keeps no state.

    ``items`` must be a non-empty tuple of structurally legal
    :class:`SMPBundle` values exactly as :func:`encode_smp_bundle`
    requires and ``public_key`` a non-boolean non-negative integer.
    Wrong field or nested field types raise TypeError — a non-tuple
    items sequence, an item that is not an :class:`SMPBundle`, or a
    non-integer (including boolean) public key; an empty items tuple,
    an illegal nested bundle, a negative public key or an over-long
    encoding raises ValueError.
    """
    if not isinstance(items, tuple):
        raise TypeError("items must be a tuple")
    for item in items:
        if not isinstance(item, SMPBundle):
            raise TypeError("each archive item must be an SMPBundle instance")
    if not isinstance(public_key, int) or isinstance(public_key, bool):
        raise TypeError("public_key must be an integer")

    item_count = len(items)
    if item_count == 0:
        raise ValueError("archive items must be a non-empty tuple")
    if item_count > 0xFFFFFFFF:
        raise ValueError("too many SMP bundle archive items")

    # Encode every bundle first — each call raises TypeError/ValueError
    # for an illegal bundle exactly as the bundle codec does — and only
    # then frame the results, so a single illegal item aborts the whole
    # message.
    frames = []
    for index, item in enumerate(items):
        encoded = encode_smp_bundle(item)
        if len(encoded) > 0xFFFFFFFF:
            raise ValueError(
                f"SMP bundle archive item {index + 1} encoding too long"
            )
        frames.append(encoded)

    framing = bytearray(item_count.to_bytes(4, "big", signed=False))
    for encoded in frames:
        framing += len(encoded).to_bytes(4, "big", signed=False)
        framing += encoded
    return (
        SMP_BUNDLE_ARCHIVE_TAG
        + hashlib.sha256(bytes(framing)).digest()
        + _encode_varint(public_key)
    )


def verify_smp_bundle_archive(
    archive: SMPBundleArchive, key: SigningDKGResult
) -> bool:
    """Verify an archive of SMP bundles against the threshold key.

    ``archive`` must be a structurally legal :class:`SMPBundleArchive`
    and ``key`` a legal :class:`SigningDKGResult`. The outer signature
    and the key structure are checked first, as is the structure of
    every item, so an illegal outer signature or key is never masked by
    a bad nested bundle: a non-:class:`SMPBundleArchive` argument, a
    non-tuple ``items`` field, a non-:class:`SMPBundle` element or a
    non-:class:`SigningDKGResult` ``key`` raises TypeError, and an empty
    items tuple, an illegal outer signature structure, an illegal key
    structure or any structurally illegal nested bundle raises
    ValueError.

    Every bundle is then passed to :func:`verify_smp_bundle` in archive
    order, so each disclosed seal and each root signature must verify
    under ``key``; the canonical :func:`smp_bundle_archive_message` of
    the items and ``key.public_key`` is finally checked as the outer
    signature's threshold Schnorr message via :func:`verify_signature`
    with the key's group parameters. Returns ``True`` only when every
    per-bundle check and the outer signature check pass; a structurally
    legal archive whose nested bundle or outer signature does not match
    — including deleting, inserting, reordering or substituting a
    bundle, or presenting the archive under another key — returns
    ``False`` rather than raising. The function is stateless.
    """
    if not isinstance(archive, SMPBundleArchive):
        raise TypeError(
            "archive must be an SMPBundleArchive instance"
        )
    items = archive.items
    if not isinstance(items, tuple):
        raise TypeError("items must be a tuple")
    for item in items:
        if not isinstance(item, SMPBundle):
            raise TypeError("each archive item must be an SMPBundle instance")
    # Check the outer signature and the key before any nested bundle is
    # examined, so a bad bundle can never mask an illegal outer
    # signature or key; structurally validate every nested bundle too,
    # exactly as the single-bundle verifier validates its proof.
    _check_history_proof_bundle_signature(archive.signature)
    _result, public_key, field_prime, group_prime, generator = _check_signing_setup(key)
    _check_signing_dkg_structure(key)
    if len(items) == 0:
        raise ValueError("archive items must be a non-empty tuple")
    for item in items:
        encode_smp_bundle(item)

    if not all(verify_smp_bundle(item, key) for item in items):
        return False
    message = smp_bundle_archive_message(items, public_key)
    return verify_signature(
        message,
        archive.signature,
        public_key,
        group_prime=group_prime,
        generator=generator,
        prime=field_prime,
    )


def encode_smp_bundle_archive(archive: SMPBundleArchive) -> bytes:
    """Canonically encode a non-empty ordered archive of SMP bundles as
    one self-delimiting object for transport or persistence.

    The encoding is, in order, the tag
    ``b"thresholdsign/smp-bundle-archive/v1"``, the 4-byte unsigned
    big-endian item count (never zero), then one frame per bundle in
    tuple order — each the 4-byte unsigned big-endian byte length
    followed by the exact bytes of :func:`encode_smp_bundle` for that
    item, with no further separators — and finally the outer signature
    frame an :class:`AuditProofBundle` carries: ``VARINT(R)``,
    ``VARINT(z)``, the 4-byte unsigned big-endian signer count ``k`` and
    one ``VARINT(id)`` per ascending signer id. Every U32 is a 4-byte
    unsigned big-endian integer; a ``VARINT`` is a 4-byte unsigned
    big-endian body length followed by the shortest unsigned big-endian
    value (zero is the single byte ``00``, positive values carry no
    leading zero); ``R`` must be positive, ``z`` may be zero and the
    signer ids are a non-empty strictly increasing tuple of positive
    integers.

    Only the archive container, each individual bundle and the outer
    signature are checked structurally — the items are not sorted or
    otherwise reordered, the outer signature is not matched against the
    bundles, no inner or outer signature is checked and no state is
    read: :func:`verify_smp_bundle_archive` stays the way to test an
    archive against a key afterwards. A non-:class:`SMPBundleArchive`
    argument, a non-tuple ``items`` field or a non-:class:`SMPBundle`
    element raises TypeError, as do wrong field types nested inside a
    bundle and a non-:class:`AggregateSignature` outer signature or one
    with wrong field types. An empty items tuple, an over-long count or
    frame, any structural error a bundle would raise on its own, or an
    illegal outer signature structure raises ValueError. The output for
    a given archive is unique and the encoding carries no network,
    storage or hidden state.
    """
    if not isinstance(archive, SMPBundleArchive):
        raise TypeError(
            "archive must be an SMPBundleArchive instance"
        )
    items = archive.items
    if not isinstance(items, tuple):
        raise TypeError("items must be a tuple")
    for item in items:
        if not isinstance(item, SMPBundle):
            raise TypeError("each archive item must be an SMPBundle instance")
    item_count = len(items)
    if item_count == 0:
        raise ValueError("archive items must be a non-empty tuple")
    if item_count > 0xFFFFFFFF:
        raise ValueError("too many SMP bundle archive items")
    signer_count = _check_history_proof_bundle_signature(archive.signature)
    if signer_count > 0xFFFFFFFF:
        raise ValueError("too many signer ids")

    # Encode every item first — each call raises TypeError/ValueError
    # for an illegal bundle exactly as the single-bundle codec does —
    # and only then frame the results, so a single illegal item aborts
    # the whole archive.
    frames = []
    for index, item in enumerate(items):
        encoded = encode_smp_bundle(item)
        if len(encoded) > 0xFFFFFFFF:
            raise ValueError(
                f"SMP bundle archive item {index + 1} encoding too long"
            )
        frames.append(encoded)

    buffer = bytearray(SMP_BUNDLE_ARCHIVE_WIRE_TAG)
    buffer += item_count.to_bytes(4, "big", signed=False)
    for encoded in frames:
        buffer += len(encoded).to_bytes(4, "big", signed=False)
        buffer += encoded
    buffer += _encode_varint(archive.signature.R)
    buffer += _encode_varint(archive.signature.z)
    buffer += signer_count.to_bytes(4, "big", signed=False)
    for signer_id in archive.signature.signer_ids:
        buffer += _encode_varint(signer_id)
    return bytes(buffer)


def decode_smp_bundle_archive(blob: bytes) -> SMPBundleArchive:
    """Decode the canonical encoding produced by
    :func:`encode_smp_bundle_archive`.

    Accepts only the single canonical form: the tag
    ``b"thresholdsign/smp-bundle-archive/v1"``, a 4-byte unsigned
    big-endian non-zero item count ``n``, then exactly ``n`` frames,
    each a 4-byte unsigned big-endian non-zero byte length followed by
    the exact canonical encoding of one :class:`SMPBundle` that
    :func:`decode_smp_bundle` accepts, and finally the outer signature
    frame: the length-prefixed integers ``R`` and ``z`` with ``R``
    positive, the 4-byte non-zero signer count ``k`` and then exactly
    ``k`` strictly increasing positive signer ids. The bundles are
    restored in their original order as a tuple; they are neither
    sorted nor matched against one another or against the outer
    signature, and no signature is verified —
    :func:`verify_smp_bundle_archive` judges the archive afterwards. A
    non-bytes argument raises TypeError; a wrong or missing tag, a zero
    item count, a zero or over-long frame length, a count mismatch, a
    nested bundle encoding that is illegal or non-canonical (including a
    frame that would not re-encode byte for byte), a zero ``R``, a
    non-canonical integer (leading zero or over-long length), a zero
    signer count, a non-positive or non-increasing signer id,
    truncation, or trailing bytes raises ValueError. A successfully
    decoded archive re-encodes to exactly the input bytes.

    Decoding only restores structure: every nested bundle is decoded
    with :func:`decode_smp_bundle` (which verifies no seal and checks no
    signature) and the outer signature is not checked. A structurally
    legal archive whose bundles do not verify or whose outer signature
    does not sign the bundles is returned normally, and
    :func:`verify_smp_bundle_archive` reports it as ``False``.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not blob.startswith(SMP_BUNDLE_ARCHIVE_WIRE_TAG):
        raise ValueError("bad SMP bundle archive tag")
    offset = len(SMP_BUNDLE_ARCHIVE_WIRE_TAG)

    if offset + 4 > len(blob):
        raise ValueError("truncated SMP bundle archive item count")
    item_count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    if item_count == 0:
        raise ValueError("SMP bundle archive items must be non-empty")

    items = []
    for index in range(item_count):
        frame, offset = _read_audit_proof_block(
            blob,
            offset,
            what=f"SMP bundle archive item {index + 1}",
        )
        items.append(decode_smp_bundle(frame))

    signature, offset = _read_bundle_signature_frame(
        blob, offset, what="SMP bundle archive"
    )
    if offset != len(blob):
        raise ValueError("trailing bytes after SMP bundle archive")

    archive = SMPBundleArchive(items=tuple(items), signature=signature)
    if encode_smp_bundle_archive(archive) != blob:
        raise ValueError("non-canonical SMP bundle archive encoding")
    return archive


# ---------------------------------------------------------------------------
# Seal histories: a non-empty, order-preserving batch of whole-report seals
# authenticated by one threshold Schnorr signature. The signed history
# message commits to the verifying public key and to the digest of the exact
# canonical encoding of the seal sequence, so deleting, inserting, reordering
# or substituting a seal — or presenting the history under another key — all
# invalidate the signature. The library keeps no state: the history is a
# plain value and every seal is re-checked on verification.
# ---------------------------------------------------------------------------

SEAL_HISTORY_TAG = b"ts/sh/v1"
SEAL_HISTORY_WIRE_TAG = b"thresholdsign/seal-history/v1"


@dataclass(frozen=True)
class SealHistory:
    """A non-empty, order-preserving batch of whole-report seals.

    ``items`` is the non-empty tuple of :class:`ReportSeal` values in
    history order; a separate threshold Schnorr
    :class:`AggregateSignature` on :func:`history_message` of the items
    and the verifying public key authenticates the batch. The dataclass
    is frozen, positionally constructible and compared by value; the
    items keep their order and the history carries no network, storage
    or hidden state. The items are not checked at construction time —
    :func:`check_history` is the way to test a history afterwards.
    """

    items: tuple[ReportSeal, ...]


def _check_seal_history_items(items: object) -> int:
    """Type- and structure-check the items container of a seal history.

    Items must be a non-empty tuple of :class:`ReportSeal` values; the
    seals themselves are not decoded or verified here (that is
    :func:`verify_seal`'s job during verification). Returns the item
    count.
    """
    if not isinstance(items, tuple):
        raise TypeError("items must be a tuple")
    try:
        count = len(items)
    except OverflowError:
        raise ValueError("too many history items") from None
    if count == 0:
        raise ValueError("items must be non-empty")
    for item in items:
        if not isinstance(item, ReportSeal):
            raise TypeError("each history item must be a ReportSeal instance")
    return count


def history_message(history: SealHistory, public_key: int) -> bytes:
    """Encode the canonical history message the threshold key signs.

    ``history`` must be a structurally legal :class:`SealHistory` — a
    non-empty tuple of :class:`ReportSeal` values each encodable by
    :func:`encode_seal` — and ``public_key`` the positive integer
    verification key the history is sealed for. Wrong types raise
    TypeError — a non-:class:`SealHistory` history, a non-tuple item
    sequence, an item that is not a :class:`ReportSeal`, or a
    non-integer (including boolean) public key; an empty history, a
    structurally illegal seal, a non-positive public key or an over-long
    key encoding raises ValueError.

    The message is, in order: the tag ``b"ts/sh/v1"``, the 32-byte
    ``SHA256`` digest of :func:`encode_history` of the history, and
    ``VARINT(public_key)`` — the 4-byte unsigned big-endian length
    followed by the shortest unsigned big-endian value used throughout
    the canonical transport encodings (positive values carry no leading
    zero). It carries no signature and keeps no state, and is meant to
    be used as the ``SigningRound.message`` of the sealing threshold
    signing protocol.
    """
    if not isinstance(history, SealHistory):
        raise TypeError("history must be a SealHistory instance")
    if not isinstance(public_key, int) or isinstance(public_key, bool):
        raise TypeError("public_key must be an integer")
    # Raises TypeError/ValueError for an illegal history, exactly like the
    # encoder itself.
    encoded = encode_history(history)
    if public_key <= 0:
        raise ValueError("public_key must be positive")
    return SEAL_HISTORY_TAG + hashlib.sha256(encoded).digest() + _encode_varint(
        public_key
    )


def check_history(
    history: SealHistory, signature: AggregateSignature, key: SigningDKGResult
) -> bool:
    """Verify a seal history against its items and the threshold key.

    ``history`` must be a structurally legal :class:`SealHistory` — a
    non-empty tuple of :class:`ReportSeal` values each encodable by
    :func:`encode_seal` — ``signature`` a structurally legal
    :class:`AggregateSignature` and ``key`` a legal
    :class:`SigningDKGResult`. Wrong field types raise TypeError; an
    empty history, a structurally illegal seal, signature or key raises
    ValueError, exactly as :func:`verify_seal` and
    :func:`verify_signature` would.

    Every seal of ``history.items`` is first re-checked in history order
    with :func:`verify_seal` against ``key``, and the canonical
    :func:`history_message` of the history and ``key.public_key`` is
    then checked as ``signature``'s threshold Schnorr message via
    :func:`verify_signature` with the key's group parameters. Returns
    ``True`` only when every seal verifies and the signature seals the
    exact item sequence; deleting or inserting a seal, reordering the
    items, tampering with a seal or the signature, or presenting the
    history under another key all return ``False`` for well-formed
    inputs. The function is stateless.
    """
    if not isinstance(history, SealHistory):
        raise TypeError("history must be a SealHistory instance")
    if not isinstance(signature, AggregateSignature):
        raise TypeError("signature must be an AggregateSignature instance")
    _check_seal_history_items(history.items)
    _result, public_key, field_prime, group_prime, generator = _check_signing_setup(key)
    _check_signing_dkg_structure(key)

    for item in history.items:
        if not verify_seal(item, key):
            return False

    message = history_message(history, public_key)
    return verify_signature(
        message,
        signature,
        public_key,
        group_prime=group_prime,
        generator=generator,
        prime=field_prime,
    )


def encode_history(history: SealHistory) -> bytes:
    """Canonically encode a seal history for transport or persistence.

    The encoding is, in order, the tag
    ``b"thresholdsign/seal-history/v1"``, the item count ``n`` as a
    4-byte unsigned big-endian integer, and then one frame per item
    strictly in ``items`` tuple order: the 4-byte unsigned big-endian
    length ``len(E)`` followed by the raw seal encoding
    ``E = encode_seal(item)``. A history must hold at least one item.

    Only a structurally legal :class:`SealHistory` is accepted — the
    items must be a non-empty tuple of :class:`ReportSeal` values each
    encodable by :func:`encode_seal` — but neither the seals' reports
    nor their signatures are required to match anything:
    :func:`check_history` stays the way to test a history afterwards.
    Wrong field types raise TypeError; an empty history, a structurally
    illegal seal or an over-long frame (including an item count that
    does not fit the 4-byte counter) raises ValueError. The output for
    a given history is unique and the encoding carries no network,
    storage or hidden state.
    """
    if not isinstance(history, SealHistory):
        raise TypeError("history must be a SealHistory instance")
    count = _check_seal_history_items(history.items)
    if count > 0xFFFFFFFF:
        raise ValueError("too many history items")

    buffer = bytearray(SEAL_HISTORY_WIRE_TAG)
    buffer += count.to_bytes(4, "big", signed=False)
    for index, item in enumerate(history.items):
        encoded_item = encode_seal(item)
        if len(encoded_item) > 0xFFFFFFFF:
            raise ValueError(f"history item {index + 1} encoding too long")
        buffer += len(encoded_item).to_bytes(4, "big", signed=False)
        buffer += encoded_item
    return bytes(buffer)


def decode_history(blob: bytes) -> SealHistory:
    """Decode the canonical encoding produced by :func:`encode_history`.

    Accepts only the single canonical form: the tag
    ``b"thresholdsign/seal-history/v1"``, the 4-byte unsigned big-endian
    item count (never zero), and then exactly that many item frames in
    order — each a 4-byte unsigned big-endian non-zero length followed
    by bytes that :func:`decode_seal` accepts. A non-bytes argument
    raises TypeError; a wrong or missing tag, a zero item count, a
    zero-length or truncated frame, a count that does not match the
    number of frames, truncation, trailing bytes, or a non-canonical
    nested seal raises ValueError. A successfully decoded history
    re-encodes to exactly the input bytes.

    Decoding only restores the structure: each frame is decoded with
    :func:`decode_seal` (which verifies no finding and checks no
    signature) and nothing else is verified. A structurally legal
    history whose seals do not verify or whose signature does not seal
    it is returned normally, and :func:`check_history` reports it as
    ``False``.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not blob.startswith(SEAL_HISTORY_WIRE_TAG):
        raise ValueError("bad seal history tag")
    offset = len(SEAL_HISTORY_WIRE_TAG)

    if offset + 4 > len(blob):
        raise ValueError("truncated seal history item count")
    count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    if count == 0:
        raise ValueError("items must be non-empty")

    items = []
    for index in range(count):
        encoded_item, offset = _read_audit_proof_block(
            blob, offset, what=f"history item {index + 1}"
        )
        items.append(decode_seal(encoded_item))
    if offset != len(blob):
        raise ValueError("trailing bytes after seal history")

    history = SealHistory(items=tuple(items))
    if encode_history(history) != blob:
        raise ValueError("non-canonical seal history encoding")
    return history


# ---------------------------------------------------------------------------
# Single-item inclusion proofs for seal histories: one threshold signature on
# a Merkle root lets a third party confirm that one ReportSeal sits at a fixed
# position in the exact sealed history without fetching the history itself.
# The tree is SHA256 over the canonical seal encodings with domain-separated
# leaf/node prefixes; the root statement to sign is
# ``b"sh/r" || U64(total) || root``. No state is kept and
# check_history_proof re-runs verify_seal on the proven seal and
# verify_signature on the root signature, so a proof certifies both membership
# and the seal itself.
# ---------------------------------------------------------------------------

SEAL_HISTORY_PROOF_LEAF_TAG = b"sh/l"
SEAL_HISTORY_PROOF_NODE_TAG = b"sh/n"
SEAL_HISTORY_PROOF_ROOT_TAG = b"sh/r"

SEAL_HISTORY_PROOF_DIGEST_SIZE = 32  # SHA256 output width; every tree node is this wide


def _history_proof_u64(value: int) -> bytes:
    """8-byte unsigned big-endian encoding of a non-negative integer < 2**64."""
    return value.to_bytes(8, "big", signed=False)


def _history_proof_leaf(index: int, seal: ReportSeal) -> bytes:
    """The index-bound leaf digest ``H(b"sh/l" || U64(i) || H(encode_seal(seal)))``."""
    return hashlib.sha256(
        SEAL_HISTORY_PROOF_LEAF_TAG
        + _history_proof_u64(index)
        + hashlib.sha256(encode_seal(seal)).digest()
    ).digest()


def _history_proof_node(left: bytes, right: bytes) -> bytes:
    """The ordered internal digest ``H(b"sh/n" || left || right)``."""
    return hashlib.sha256(
        SEAL_HISTORY_PROOF_NODE_TAG + left + right
    ).digest()


def _history_proof_levels(
    items: tuple[ReportSeal, ...],
) -> list[tuple[bytes, ...]]:
    """Build the leaf level and every internal level up to the single root.

    A level with an odd tail width is paired with its own last node
    duplicated, so every level above the leaves has an even width.
    """
    levels: list[tuple[bytes, ...]] = [
        tuple(
            _history_proof_leaf(index, seal)
            for index, seal in enumerate(items)
        )
    ]
    current = levels[0]
    while len(current) > 1:
        if len(current) % 2 == 1:
            current = current + current[-1:]
        current = tuple(
            _history_proof_node(current[index], current[index + 1])
            for index in range(0, len(current), 2)
        )
        levels.append(current)
    return levels


@dataclass(frozen=True)
class SealHistoryProof:
    """A Merkle inclusion proof for one seal of a seal history.

    The fields, in order, are ``index`` (the non-negative leaf position),
    ``total`` (the total, non-empty history item count), ``seal`` (the
    proven :class:`ReportSeal`) and ``siblings`` (the sibling digests on
    the path from the leaf level up to — but not including — the root,
    each exactly 32 bytes, ordered from the leaf level upward; the tuple
    is empty for a one-item history). At a level whose width is odd, the
    last node pairs with itself, and the corresponding path entry is the
    node's own digest. The dataclass is frozen, positionally constructible
    and compared by value, and carries no network, storage or hidden
    state. Field types and bounds are not checked at construction time —
    :func:`check_history_proof` is the way to test a proof afterwards.
    """

    index: int
    total: int
    seal: ReportSeal
    siblings: tuple[bytes, ...]


def make_history_proof(
    history: SealHistory, index: int
) -> tuple[bytes, SealHistoryProof]:
    """Build the root statement and a seal inclusion proof for one item.

    ``history`` must be a structurally legal :class:`SealHistory` — a
    non-empty tuple of :class:`ReportSeal` values each encodable by
    :func:`encode_seal` — and ``index`` the leaf position to prove. The
    tree is built in history item order with SHA256: leaves are
    ``H(b"sh/l" || U64(i) || H(encode_seal(item)))`` and internal nodes
    ``H(b"sh/n" || left || right)``; a level with an odd tail width
    duplicates its last node for pairing, and the sibling carried for
    that level is the node's own digest. Returns ``(message, proof)``
    where ``message`` is ``b"sh/r" || U64(total) || root`` (the 8-byte
    unsigned big-endian item count followed by the 32-byte root) — the
    bytes to be threshold-signed — and ``proof`` is the
    :class:`SealHistoryProof` for ``index`` whose ``siblings`` list the
    32-byte digests from the leaf level up to the root.

    Wrong argument types raise TypeError: a non-:class:`SealHistory`
    history or a non-integer (including boolean) index. An empty
    history, a structurally illegal item seal, a count that does not
    fit ``0 < total < 2**64``, or an index outside ``0 <= i < total``
    raises ValueError.
    """
    if not isinstance(history, SealHistory):
        raise TypeError("history must be a SealHistory instance")
    if not isinstance(index, int) or isinstance(index, bool):
        raise TypeError("index must be an integer")
    total = _check_seal_history_items(history.items)
    if total > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("too many history items")
    if index < 0 or index >= total:
        raise ValueError("index out of range")

    levels = _history_proof_levels(history.items)

    path = []
    position = index
    for level in levels[:-1]:
        width = len(level)
        padded = level if width % 2 == 0 else level + level[-1:]
        # At an odd tail the companion position is the duplicated last
        # node, so the carried sibling equals the current node itself.
        path.append(padded[position ^ 1])
        position //= 2

    root = levels[-1][0]
    proof = SealHistoryProof(
        index=index,
        total=total,
        seal=history.items[index],
        siblings=tuple(path),
    )
    return SEAL_HISTORY_PROOF_ROOT_TAG + _history_proof_u64(total) + root, proof


def _validate_history_proof_structure(
    proof: object,
) -> tuple[int, int, ReportSeal, tuple[bytes, ...]]:
    """Type- and structure-check a SealHistoryProof, returning its fields.

    Only the container structure is checked: the seal itself is neither
    encoded nor verified here (that is :func:`verify_seal`'s job during
    verification). The bounds are ``0 < total < 2**64`` and
    ``0 <= index < total``; the sibling tuple must hold exactly
    ``(total - 1).bit_length()`` entries, each 32 bytes. Wrong field
    types raise TypeError; illegal bounds or a bad path shape raise
    ValueError.
    """
    if not isinstance(proof, SealHistoryProof):
        raise TypeError("proof must be a SealHistoryProof instance")
    index = proof.index
    total = proof.total
    seal = proof.seal
    siblings = proof.siblings
    if not isinstance(index, int) or isinstance(index, bool):
        raise TypeError("proof.index must be an integer")
    if not isinstance(total, int) or isinstance(total, bool):
        raise TypeError("proof.total must be an integer")
    if not isinstance(seal, ReportSeal):
        raise TypeError("proof.seal must be a ReportSeal instance")
    if not isinstance(siblings, tuple):
        raise TypeError("proof.siblings must be a tuple")
    for sibling in siblings:
        if not isinstance(sibling, bytes):
            raise TypeError("proof.siblings entries must be bytes")

    if total <= 0:
        raise ValueError("proof.total must be positive")
    if total > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("too many history items")
    if index < 0 or index >= total:
        raise ValueError("proof.index out of range")
    expected_depth = (total - 1).bit_length()
    if len(siblings) != expected_depth:
        raise ValueError("proof.siblings has the wrong length for proof.total")
    for sibling in siblings:
        if len(sibling) != SEAL_HISTORY_PROOF_DIGEST_SIZE:
            raise ValueError("proof.siblings entries must be exactly 32 bytes")
    return index, total, seal, siblings


def check_history_proof(
    proof: SealHistoryProof,
    signature: AggregateSignature,
    key: SigningDKGResult,
) -> bool:
    """Rebuild a proof's Merkle root and verify its seal and root signature.

    The proven seal is first re-checked with :func:`verify_seal` against
    ``key``. The leaf digest is then recomputed from ``proof.index`` and
    ``proof.seal`` exactly as in :func:`make_history_proof`, and the
    root is rebuilt level by level while tracking the current level's
    width. At each level the current position is paired by its parity —
    an even position is hashed on the left, an odd position on the
    right — except for an odd tail: when the level has odd width and the
    current node is its last member it has no companion, so it is paired
    with itself (``H(node, node)``), exactly the last-node duplication
    the tree builder uses; the supplied sibling at that level must equal
    the current node. The width for the next level is
    ``(width + 1) // 2``. The statement ``b"sh/r" || U64(total) || root``
    is finally checked as ``signature``'s threshold Schnorr message via
    :func:`verify_signature` with the key's group parameters. Returns
    ``True`` only when the seal verifies, the rebuilt root matches the
    signed statement and the signature verifies; a well-formed proof
    whose seal, sibling digests or signature were tampered with, or
    which is presented under another key, returns ``False``.

    A non-:class:`SealHistoryProof` or non-:class:`AggregateSignature`
    argument or any wrong field type (non-integer ``index``/``total``
    including booleans, a non-:class:`ReportSeal` seal, a non-tuple
    sibling path or non-bytes path entry) raises TypeError; a
    non-positive or not-less-than-``2**64`` total, an out-of-range
    index, a sibling entry that is not exactly 32 bytes, a path whose
    length does not fit total, or a structurally illegal seal,
    signature or key raises ValueError, exactly as :func:`verify_seal`
    and :func:`verify_signature` would.
    """
    index, total, seal, siblings = _validate_history_proof_structure(proof)
    if not isinstance(signature, AggregateSignature):
        raise TypeError("signature must be an AggregateSignature instance")

    _result, public_key, field_prime, group_prime, generator = _check_signing_setup(key)
    _check_signing_dkg_structure(key)

    if not verify_seal(seal, key):
        return False

    node = _history_proof_leaf(index, seal)
    position = index
    width = total
    for sibling in siblings:
        if width % 2 == 1 and position == width - 1:
            # Odd tail with no companion: the tree builder duplicated
            # the last node, so the carried sibling must be this node.
            if sibling != node:
                return False
            node = _history_proof_node(node, node)
        elif position % 2 == 0:
            node = _history_proof_node(node, sibling)
        else:
            node = _history_proof_node(sibling, node)
        position //= 2
        width = (width + 1) // 2

    signed_message = (
        SEAL_HISTORY_PROOF_ROOT_TAG + _history_proof_u64(total) + node
    )
    return verify_signature(
        signed_message,
        signature,
        public_key,
        group_prime=group_prime,
        generator=generator,
        prime=field_prime,
    )


# ---------------------------------------------------------------------------
# Compact multi-seal inclusion proofs for seal histories: one threshold
# signature on the same Merkle root statement lets a third party confirm that
# several ReportSeal values each sit at a fixed position in the exact sealed
# history without fetching the history itself. The tree, leaf/node tags and
# root statement are identical to the single-seal SealHistoryProof; the compact
# walk sends each companion digest at most once, level by level left to right,
# omitting companions that are themselves disclosed and odd tails. No state is
# kept and check_history_multi_proof re-runs verify_seal on every proven seal
# and verify_signature on the root signature, so a proof certifies both the
# memberships and the seals themselves.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SealHistoryMultiProof:
    """A compact Merkle inclusion proof for several seals of a seal history.

    The fields, in order, are ``indices`` (the proven leaf positions as a
    non-empty tuple of strictly increasing, unique non-negative integers),
    ``total`` (the total, non-empty history item count), ``seals`` (the
    proven :class:`ReportSeal` values, one per entry of ``indices``, in the
    same order) and ``siblings`` (the 32-byte sibling digests consumed from
    the leaf level up to the root, in ascending level order; the tuple is
    empty when no companion digests are needed). At a level whose width is
    odd, the last node pairs with itself and no sibling is carried for it.
    The dataclass is frozen, positionally constructible and compared by
    value, and carries no network, storage or hidden state. Field types and
    bounds are not checked at construction time —
    :func:`check_history_multi_proof` is the way to test a proof afterwards.
    """

    indices: tuple[int, ...]
    total: int
    seals: tuple[ReportSeal, ...]
    siblings: tuple[bytes, ...]


def make_history_multi_proof(
    history: SealHistory, indices: tuple[int, ...]
) -> tuple[bytes, SealHistoryMultiProof]:
    """Build the root statement and a compact multi-seal inclusion proof.

    ``history`` must be a structurally legal :class:`SealHistory` — a
    non-empty tuple of :class:`ReportSeal` values each encodable by
    :func:`encode_seal` — and ``indices`` a non-empty tuple of leaf
    positions to prove. The tree is exactly :func:`make_history_proof`'s
    tree: leaves are ``H(b"sh/l" || U64(i) || H(encode_seal(item)))`` and
    internal nodes ``H(b"sh/n" || left || right)``; a level with an odd
    tail width duplicates its last node for pairing. Returns
    ``(message, proof)`` where ``message`` is
    ``b"sh/r" || U64(total) || root`` — the same bytes
    :func:`make_history_proof` signs — and ``proof`` is the
    :class:`SealHistoryMultiProof` whose ``seals`` pair one to one with
    ``indices``. Its ``siblings`` are collected level by level, in
    ascending level order (leaves upward) and left to right within a
    level, one entry per needed companion: when the companion position is
    itself a proven node carried in the proof, or the node is the last
    member of an odd-width level (paired with itself), no sibling is
    appended; otherwise the companion digest is. Proven nodes from lower
    levels feed the level above exactly as in the tree, so no digest is
    sent twice.

    Wrong argument types raise TypeError: a non-:class:`SealHistory`
    history, a non-tuple index sequence or a non-integer (including
    boolean) index. An empty history or index tuple, a structurally
    illegal item seal, a count that does not fit ``0 < total < 2**64``,
    indices that are not strictly increasing and unique, or an index
    outside ``0 <= i < total`` raises ValueError.
    """
    if not isinstance(history, SealHistory):
        raise TypeError("history must be a SealHistory instance")
    if not isinstance(indices, tuple):
        raise TypeError("indices must be a tuple")
    total = _check_seal_history_items(history.items)
    if total > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("too many history items")
    if len(indices) == 0:
        raise ValueError("indices must be non-empty")
    previous = -1
    for index in indices:
        if not isinstance(index, int) or isinstance(index, bool):
            raise TypeError("each index must be an integer")
        if index <= previous:
            raise ValueError("indices must be strictly increasing and unique")
        if index < 0 or index >= total:
            raise ValueError("index out of range")
        previous = index

    levels = _history_proof_levels(history.items)

    siblings: list[bytes] = []
    positions = set(indices)
    for level in levels[:-1]:
        width = len(level)
        padded = level if width % 2 == 0 else level + level[-1:]
        next_positions = set()
        for position in sorted(positions):
            if width % 2 == 1 and position == width - 1:
                # Odd tail with no companion: the tree pairs it with itself.
                pass
            elif (position ^ 1) in positions:
                # The companion is itself a disclosed node; nothing to send.
                pass
            else:
                siblings.append(padded[position ^ 1])
            next_positions.add(position // 2)
        positions = next_positions

    root = levels[-1][0]
    proof_seals = tuple(history.items[index] for index in indices)
    proof = SealHistoryMultiProof(
        indices=tuple(indices),
        total=total,
        seals=proof_seals,
        siblings=tuple(siblings),
    )
    return SEAL_HISTORY_PROOF_ROOT_TAG + _history_proof_u64(total) + root, proof


def _required_history_multi_proof_siblings(
    total: int, indices: tuple[int, ...]
) -> int:
    """Number of 32-byte companion digests a multi-proof must carry.

    Replays :func:`make_history_multi_proof`'s level walk structurally: at
    each level a proven node needs a sibling unless it is the odd-width
    tail (paired with itself) or its companion is itself a proven node at
    that level. The answer depends only on ``total`` and the disclosed
    positions — never on the seals or the digests — so it is the unique
    sibling count both makers and checkers can demand.
    """
    required = 0
    positions = set(indices)
    width = total
    while width > 1:
        next_positions = set()
        for position in sorted(positions):
            if width % 2 == 1 and position == width - 1:
                # Odd tail with no companion: the tree pairs it with itself.
                pass
            elif (position ^ 1) in positions:
                # The companion is itself a disclosed node; nothing to send.
                pass
            else:
                required += 1
            next_positions.add(position // 2)
        positions = next_positions
        width = (width + 1) // 2
    return required


def _validate_history_multi_proof_structure(
    proof: object,
) -> tuple[tuple[int, ...], int, tuple[ReportSeal, ...], tuple[bytes, ...]]:
    """Type- and structure-check a SealHistoryMultiProof, returning its fields.

    Only the container structure is checked: the seals themselves are
    neither encoded nor verified here (that is :func:`verify_seal`'s job
    during verification). The bounds are ``0 < total < 2**64``, a
    non-empty ``indices``/``seals`` pair of equal length with strictly
    increasing indices in ``0 <= i < total`` and a siblings tuple whose
    entries are exactly 32 bytes. Wrong field types raise TypeError;
    illegal bounds or shapes raise ValueError. The number of siblings is
    derived uniquely from ``total`` and ``indices`` (the compact walk
    sends one companion per proven node that is neither an odd tail nor
    paired with another proven node), so a missing or extra sibling
    raises ValueError here — before any root is rebuilt.
    """
    if not isinstance(proof, SealHistoryMultiProof):
        raise TypeError(
            "proof must be a SealHistoryMultiProof instance"
        )
    indices = proof.indices
    total = proof.total
    seals = proof.seals
    siblings = proof.siblings
    if not isinstance(indices, tuple):
        raise TypeError("proof.indices must be a tuple")
    if not isinstance(total, int) or isinstance(total, bool):
        raise TypeError("proof.total must be an integer")
    if not isinstance(seals, tuple):
        raise TypeError("proof.seals must be a tuple")
    if not isinstance(siblings, tuple):
        raise TypeError("proof.siblings must be a tuple")

    if total <= 0:
        raise ValueError("proof.total must be positive")
    if total > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("too many history items")
    if len(indices) == 0:
        raise ValueError("proof.indices must be non-empty")
    if len(indices) != len(seals):
        raise ValueError("proof.seals must pair one-to-one with proof.indices")

    previous = -1
    for index in indices:
        if not isinstance(index, int) or isinstance(index, bool):
            raise TypeError("proof.indices entries must be integers")
        if index <= previous:
            raise ValueError(
                "proof.indices must be strictly increasing and unique"
            )
        if index < 0 or index >= total:
            raise ValueError("proof.indices entry out of range")
        previous = index

    for seal in seals:
        if not isinstance(seal, ReportSeal):
            raise TypeError("proof.seals entries must be ReportSeal instances")

    for sibling in siblings:
        if not isinstance(sibling, bytes):
            raise TypeError("proof.siblings entries must be bytes")
    for sibling in siblings:
        if len(sibling) != SEAL_HISTORY_PROOF_DIGEST_SIZE:
            raise ValueError("proof.siblings entries must be exactly 32 bytes")
    required_siblings = _required_history_multi_proof_siblings(total, indices)
    if len(siblings) != required_siblings:
        raise ValueError(
            "proof.siblings count is not the one determined by total and indices"
        )
    return indices, total, seals, siblings


def check_history_multi_proof(
    proof: SealHistoryMultiProof,
    signature: AggregateSignature,
    key: SigningDKGResult,
) -> bool:
    """Rebuild a multi-proof's Merkle root and verify its seals and signature.

    Every disclosed seal is first re-checked with :func:`verify_seal`
    against ``key`` in index order. Each seal's leaf digest is then
    recomputed from its position and the seal exactly as in
    :func:`make_history_proof`, and the root is rebuilt level by level
    while consuming ``proof.siblings`` in ascending level order and left
    to right within a level: the current level holds the digests of the
    proven nodes at their current positions, paired left to right; when a
    companion is itself a current-level node its digest is used directly,
    when the node is the last member of an odd-width level it is paired
    with itself, and otherwise the next 32-byte entry of ``siblings`` is
    consumed. The current width contracts as ``(width + 1) // 2``. The
    statement ``b"sh/r" || U64(total) || root`` is finally checked as
    ``signature``'s threshold Schnorr message via :func:`verify_signature`
    with the key's group parameters. Returns ``True`` only when every seal
    verifies against the key, the rebuild consumes every sibling exactly
    and reaches the single signed root, and the signature verifies; a
    well-formed proof whose seals, indices, siblings, root or signature
    was tampered with — seals swapped or altered, a missing, extra or
    misplaced sibling — or which is presented under another key, returns
    ``False``.

    A non-:class:`SealHistoryMultiProof` or non-:class:`AggregateSignature`
    argument or any wrong field type (non-tuple indices/seals/siblings, a
    non-integer ``total`` or index including booleans, a
    non-:class:`ReportSeal` seal or non-bytes sibling) raises TypeError; a
    non-positive or over-64-bit total, empty indices, an index out of
    range or not strictly increasing, a seals tuple that does not pair
    one-to-one with the indices, a sibling that is not exactly 32 bytes,
    too few or too many siblings for the indicated positions, or a
    structurally illegal seal, signature or ``key`` raises ValueError,
    exactly as :func:`verify_seal` and :func:`verify_signature` would.
    """
    indices, total, seals, siblings = _validate_history_multi_proof_structure(proof)
    if not isinstance(signature, AggregateSignature):
        raise TypeError("signature must be an AggregateSignature instance")

    _result, public_key, field_prime, group_prime, generator = _check_signing_setup(key)
    _check_signing_dkg_structure(key)

    for seal in seals:
        if not verify_seal(seal, key):
            return False

    nodes = {
        index: _history_proof_leaf(index, seal)
        for index, seal in zip(indices, seals)
    }
    pending = iter(siblings)
    width = total
    while width > 1:
        next_nodes = {}
        for position in sorted(nodes):
            parent = position // 2
            if parent in next_nodes:
                continue
            if width % 2 == 1 and position == width - 1:
                # Odd tail with no companion: pair the node with itself.
                next_nodes[parent] = _history_proof_node(
                    nodes[position], nodes[position]
                )
            elif (position ^ 1) in nodes:
                left = position if position % 2 == 0 else position ^ 1
                next_nodes[parent] = _history_proof_node(
                    nodes[left], nodes[left ^ 1]
                )
            else:
                try:
                    sibling = next(pending)
                except StopIteration:
                    raise ValueError(
                        "proof.siblings is missing entries"
                    ) from None
                if position % 2 == 0:
                    next_nodes[parent] = _history_proof_node(
                        nodes[position], sibling
                    )
                else:
                    next_nodes[parent] = _history_proof_node(
                        sibling, nodes[position]
                    )
        nodes = next_nodes
        width = (width + 1) // 2

    try:
        next(pending)
    except StopIteration:
        pass
    else:
        raise ValueError("proof.siblings has extra entries")

    signed_message = (
        SEAL_HISTORY_PROOF_ROOT_TAG + _history_proof_u64(total) + nodes[0]
    )
    return verify_signature(
        signed_message,
        signature,
        public_key,
        group_prime=group_prime,
        generator=generator,
        prime=field_prime,
    )


# ---------------------------------------------------------------------------
# Canonical seal-history-multi-proof transport: a self-delimiting,
# byte-for-byte reproducible encoding of a SealHistoryMultiProof for
# cross-implementation exchange and persistence. Decoding restores structure
# only — the nested seals go through decode_seal, no seal or signature is
# checked and no state is kept, so check_history_multi_proof remains the sole
# verifier afterwards.
# ---------------------------------------------------------------------------

SEAL_HISTORY_MULTI_PROOF_WIRE_TAG = (
    b"thresholdsign/seal-history-multi-proof/v1"
)


def encode_history_multi_proof(proof: SealHistoryMultiProof) -> bytes:
    """Canonically encode a multi-seal history proof for transport/storage.

    The encoding is the direct concatenation, in order, of the tag
    ``b"thresholdsign/seal-history-multi-proof/v1"``, ``VARINT(total)``,
    the index count as a 4-byte unsigned big-endian integer, one
    ``VARINT(index)`` per proven leaf in the proof's strictly increasing
    order, the seal count as a 4-byte unsigned big-endian integer, one
    frame per seal — the 4-byte unsigned big-endian length ``len(E)``
    followed by the raw seal bytes ``E = encode_seal(seal)`` (never
    empty) — and finally the sibling count as a 4-byte unsigned
    big-endian integer followed by the raw 32-byte sibling digests in
    their original leaf-to-root, left-to-right order. A ``VARINT`` is a
    4-byte unsigned big-endian body length followed by the shortest
    unsigned big-endian value (zero is the single byte ``00`` and
    positive values carry no leading zero). The indices must be
    non-empty, strictly increasing, unique and within
    ``0 <= i < total``, the seal count must equal the index count, and
    the sibling count must be the unique one derived from ``total`` and
    the indices by the compact multi-proof walk.

    Only a structurally legal :class:`SealHistoryMultiProof` is accepted
    — a non-proof or wrong field/entry types raise TypeError and illegal
    bounds, an empty index tuple, a seal tuple that does not pair
    one-to-one with the indices, a sibling that is not exactly 32 bytes,
    a sibling count other than the one ``total`` and the indices
    determine, a structurally illegal nested seal or an over-long frame
    raise ValueError, exactly as :func:`check_history_multi_proof`'s
    structural checks do — but the seals are not verified and no
    signature is checked: :func:`check_history_multi_proof` stays the
    way to verify a proof afterwards. The output for a given proof is
    unique and the encoding carries no network, storage or hidden
    state.
    """
    if not isinstance(proof, SealHistoryMultiProof):
        raise TypeError(
            "proof must be a SealHistoryMultiProof instance"
        )
    indices, total, seals, siblings = _validate_history_multi_proof_structure(
        proof
    )
    if len(indices) > 0xFFFFFFFF:
        raise ValueError("too many indices")
    if len(siblings) > 0xFFFFFFFF:
        raise ValueError("too many siblings")

    encoded_seals = []
    for position, seal in enumerate(seals):
        encoded_seal = encode_seal(seal)
        if len(encoded_seal) > 0xFFFFFFFF:
            raise ValueError(
                f"history multi-proof seal {position + 1} encoding too long"
            )
        encoded_seals.append(encoded_seal)

    buffer = bytearray(SEAL_HISTORY_MULTI_PROOF_WIRE_TAG)
    buffer += _encode_varint(total)
    buffer += len(indices).to_bytes(4, "big", signed=False)
    for index in indices:
        buffer += _encode_varint(index)
    buffer += len(encoded_seals).to_bytes(4, "big", signed=False)
    for encoded_seal in encoded_seals:
        buffer += len(encoded_seal).to_bytes(4, "big", signed=False)
        buffer += encoded_seal
    buffer += len(siblings).to_bytes(4, "big", signed=False)
    for sibling in siblings:
        buffer += sibling
    return bytes(buffer)


def decode_history_multi_proof(blob: bytes) -> SealHistoryMultiProof:
    """Decode the canonical encoding produced by :func:`encode_history_multi_proof`.

    Accepts only the single canonical form: the tag
    ``b"thresholdsign/seal-history-multi-proof/v1"``, the length-prefixed
    integer ``total`` (a 4-byte unsigned big-endian length followed by
    its shortest unsigned big-endian value, zero encoded as the single
    byte ``00``), the 4-byte non-zero index count followed by one
    canonical ``VARINT`` per strictly increasing index, the 4-byte seal
    count (which must equal the index count) followed by that many
    non-empty seal frames (a 4-byte non-zero length followed by bytes
    that :func:`decode_seal` accepts), and finally the 4-byte sibling
    count followed by exactly that many raw 32-byte sibling digests,
    where the count must be the unique one derived from ``total`` and
    the disclosed indices. A non-bytes argument raises TypeError; a
    wrong or missing tag, an empty index list, a non-positive or
    over-64-bit ``total``, an index outside ``0 <= i < total``, indices
    that are not strictly increasing and unique, a seal count that does
    not match the index count, an empty, truncated or non-canonical
    seal frame, a missing or extra sibling relative to the count
    ``total`` and the indices require, a sibling that is not exactly 32
    bytes, truncation, trailing bytes, or a non-canonical integer
    (leading zero or over-long length) raises ValueError. A
    successfully decoded proof re-encodes to exactly the input bytes.

    Decoding only restores the structure: each nested seal is decoded
    with :func:`decode_seal` (which verifies no finding and checks no
    signature) and nothing else is verified. A structurally legal proof
    whose seals do not verify or whose root signature is invalid is
    returned normally, and :func:`check_history_multi_proof` reports it
    as ``False``.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not blob.startswith(SEAL_HISTORY_MULTI_PROOF_WIRE_TAG):
        raise ValueError("bad seal history multi-proof tag")
    offset = len(SEAL_HISTORY_MULTI_PROOF_WIRE_TAG)

    total, offset = _read_varint(
        blob, offset, what="seal history multi-proof total"
    )
    if total <= 0:
        raise ValueError("seal history multi-proof total must be positive")
    if total > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("seal history multi-proof total too large")

    if offset + 4 > len(blob):
        raise ValueError("truncated seal history multi-proof index count")
    index_count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    if index_count == 0:
        raise ValueError("seal history multi-proof indices must be non-empty")
    indices = []
    for _ in range(index_count):
        index, offset = _read_varint(
            blob, offset, what="seal history multi-proof index"
        )
        indices.append(index)

    if offset + 4 > len(blob):
        raise ValueError("truncated seal history multi-proof seal count")
    seal_count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    if seal_count != index_count:
        raise ValueError(
            "seal history multi-proof seal count must match the index count"
        )
    seals = []
    for position in range(seal_count):
        encoded_seal, offset = _read_audit_proof_block(
            blob,
            offset,
            what=f"seal history multi-proof seal {position + 1}",
        )
        seals.append(decode_seal(encoded_seal))

    if offset + 4 > len(blob):
        raise ValueError("truncated seal history multi-proof sibling count")
    sibling_count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    siblings = []
    for _ in range(sibling_count):
        if offset + SEAL_HISTORY_PROOF_DIGEST_SIZE > len(blob):
            raise ValueError("truncated seal history multi-proof sibling")
        siblings.append(
            bytes(
                blob[
                    offset:offset + SEAL_HISTORY_PROOF_DIGEST_SIZE
                ]
            )
        )
        offset += SEAL_HISTORY_PROOF_DIGEST_SIZE
    if offset != len(blob):
        raise ValueError("trailing bytes after seal history multi-proof")

    proof = SealHistoryMultiProof(
        indices=tuple(indices),
        total=total,
        seals=tuple(seals),
        siblings=tuple(siblings),
    )
    _validate_history_multi_proof_structure(proof)
    if encode_history_multi_proof(proof) != blob:
        raise ValueError("non-canonical seal history multi-proof encoding")
    return proof


# ---------------------------------------------------------------------------
# Canonical seal-history-multi-proof bundle transport: a self-delimiting,
# byte-for-byte reproducible encoding of a SealHistoryMultiProof together with
# the AggregateSignature on its b"sh/r" || U64(total) || root statement, for
# cross-implementation exchange and persistence. Decoding restores structure
# only — the nested proof goes through decode_history_multi_proof and no seal
# or signature is checked, so verify_history_multi_proof_bundle remains the
# sole verifier afterwards.
# ---------------------------------------------------------------------------

SEAL_HISTORY_MULTI_PROOF_BUNDLE_WIRE_TAG = b"ts/shmpb/v1"


@dataclass(frozen=True)
class SealHistoryMultiProofBundle:
    """A compact multi-seal history proof together with its root signature.

    The fields, in order, are ``proof`` (a
    :class:`SealHistoryMultiProof`) and ``signature`` (the
    :class:`AggregateSignature` on the proof's
    ``b"sh/r" || U64(total) || root`` statement). The dataclass is frozen,
    positionally constructible and compared by value, and carries no
    network, storage or hidden state. Field types and bounds are not
    checked at construction time — :func:`encode_history_multi_proof_bundle`
    checks the structure and :func:`verify_history_multi_proof_bundle` is
    the way to test a bundle afterwards.
    """

    proof: SealHistoryMultiProof
    signature: AggregateSignature


def _check_history_proof_bundle_signature(
    signature: object, *, field: str = "bundle.signature"
) -> int:
    """Type- and structure-check a proof bundle's root signature, returning its id count.

    Shared by the single-, multi- and extension-proof bundles: the
    integers and signer set are checked only as the unsigned, ordered
    structures the wire framing needs; nothing here places ``R``/``z`` in
    a group (that takes group parameters and is
    :func:`verify_signature`'s job during verification). ``R`` must be
    strictly positive (a real commitment is never the identity, and the
    same value is illegal under :func:`verify_signature`), while ``z``
    may be zero and then encodes as the single body byte ``00``.
    ``field`` names the offending attribute in the TypeError message.
    """
    if not isinstance(signature, AggregateSignature):
        raise TypeError(f"{field} must be an AggregateSignature instance")
    if not isinstance(signature.R, int) or isinstance(signature.R, bool):
        raise TypeError("signature.R must be an integer")
    if not isinstance(signature.z, int) or isinstance(signature.z, bool):
        raise TypeError("signature.z must be an integer")
    if not isinstance(signature.signer_ids, tuple):
        raise TypeError("signature.signer_ids must be a tuple")
    try:
        signer_count = len(signature.signer_ids)
    except OverflowError:
        raise ValueError("too many signer ids") from None
    for signer_id in signature.signer_ids:
        if not isinstance(signer_id, int) or isinstance(signer_id, bool):
            raise TypeError("signer ids must be integers")

    if signature.R <= 0:
        raise ValueError("signature R must be positive")
    if signature.z < 0:
        raise ValueError("signature z must be non-negative")
    if signer_count == 0:
        raise ValueError("at least one signer is required")
    for signer_id in signature.signer_ids:
        if signer_id <= 0:
            raise ValueError("signer ids must be positive")
    if any(
        previous >= next_
        for previous, next_ in zip(
            signature.signer_ids, signature.signer_ids[1:]
        )
    ):
        raise ValueError("signer ids must be strictly increasing and unique")
    return signer_count


def encode_history_multi_proof_bundle(
    bundle: SealHistoryMultiProofBundle,
) -> bytes:
    """Canonically encode a multi-proof bundle for transport or persistence.

    The encoding is, in order, the tag ``b"ts/shmpb/v1"``, the 4-byte
    unsigned big-endian length ``len(P)`` followed by
    ``P = encode_history_multi_proof(bundle.proof)`` (never empty), and
    then the signature frame: ``VARINT(R)``, ``VARINT(z)``, the 4-byte
    unsigned big-endian signer count ``k`` and one ``VARINT(id)`` per
    ascending signer id. A ``VARINT`` is a 4-byte unsigned big-endian
    body length followed by the shortest unsigned big-endian value (zero
    is the single byte ``00``, positive values carry no leading zero);
    ``R`` must be positive and ``z`` may be zero.

    Only a structurally legal :class:`SealHistoryMultiProofBundle` is
    accepted — a non-bundle or non-:class:`SealHistoryMultiProof` proof
    argument, or wrong proof/signature field types, raise TypeError and
    illegal proof or signature structure (the exact bounds of
    :func:`encode_history_multi_proof`, a non-positive ``R``, a negative
    ``z``, an empty or non-strictly-increasing signer id tuple) or an
    over-long frame raises ValueError, exactly as
    :func:`check_history_multi_proof`'s structural checks do — but the
    seals are not verified and the signature is not checked against the
    root: :func:`verify_history_multi_proof_bundle` stays the way to
    verify a bundle afterwards. The output for a given bundle is unique
    and the encoding carries no network, storage or hidden state.
    """
    if not isinstance(bundle, SealHistoryMultiProofBundle):
        raise TypeError(
            "bundle must be a SealHistoryMultiProofBundle instance"
        )
    if not isinstance(bundle.proof, SealHistoryMultiProof):
        raise TypeError(
            "bundle.proof must be a SealHistoryMultiProof instance"
        )
    encoded_proof = encode_history_multi_proof(bundle.proof)
    signer_count = _check_history_proof_bundle_signature(
        bundle.signature
    )
    if len(encoded_proof) > 0xFFFFFFFF:
        raise ValueError("history multi-proof encoding too long")
    if signer_count > 0xFFFFFFFF:
        raise ValueError("too many signer ids")

    buffer = bytearray(SEAL_HISTORY_MULTI_PROOF_BUNDLE_WIRE_TAG)
    buffer += len(encoded_proof).to_bytes(4, "big", signed=False)
    buffer += encoded_proof
    buffer += _encode_varint(bundle.signature.R)
    buffer += _encode_varint(bundle.signature.z)
    buffer += signer_count.to_bytes(4, "big", signed=False)
    for signer_id in bundle.signature.signer_ids:
        buffer += _encode_varint(signer_id)
    return bytes(buffer)


def decode_history_multi_proof_bundle(
    blob: bytes,
) -> SealHistoryMultiProofBundle:
    """Decode the canonical encoding produced by :func:`encode_history_multi_proof_bundle`.

    Accepts only the single canonical form: the tag ``b"ts/shmpb/v1"``, a
    4-byte non-zero frame length followed by bytes that
    :func:`decode_history_multi_proof` accepts, the length-prefixed
    integers ``R`` and ``z``, the 4-byte non-zero signer count ``k`` and
    then exactly ``k`` strictly increasing positive signer ids. A
    non-bytes argument raises TypeError; a wrong or missing tag, a zero
    or over-long proof frame length, a non-canonical nested proof, a zero
    ``R``, a non-canonical integer (leading zero or over-long length), a
    zero signer count, a non-positive or non-increasing signer id,
    truncation, or trailing bytes raises ValueError. A successfully
    decoded bundle re-encodes to exactly the input bytes.

    Decoding only restores the structure: the nested proof is decoded
    with :func:`decode_history_multi_proof` (which verifies no seal) and
    the signature is not checked. A structurally legal bundle whose seals
    do not verify or whose signature does not sign the root is returned
    normally, and :func:`verify_history_multi_proof_bundle` reports it as
    ``False``.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not blob.startswith(SEAL_HISTORY_MULTI_PROOF_BUNDLE_WIRE_TAG):
        raise ValueError("bad seal history multi-proof bundle tag")
    offset = len(SEAL_HISTORY_MULTI_PROOF_BUNDLE_WIRE_TAG)

    encoded_proof, offset = _read_audit_proof_block(
        blob, offset, what="seal history multi-proof bundle proof"
    )
    proof = decode_history_multi_proof(encoded_proof)

    R, offset = _read_varint(
        blob, offset, what="seal history multi-proof bundle signature R"
    )
    z, offset = _read_varint(
        blob, offset, what="seal history multi-proof bundle signature z"
    )
    if R == 0:
        raise ValueError(
            "seal history multi-proof bundle signature R must be positive"
        )

    if offset + 4 > len(blob):
        raise ValueError(
            "truncated seal history multi-proof bundle signer count"
        )
    signer_count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    if signer_count == 0:
        raise ValueError(
            "seal history multi-proof bundle must name at least one signer"
        )

    signer_ids = []
    for _ in range(signer_count):
        signer_id, offset = _read_varint(
            blob,
            offset,
            what="seal history multi-proof bundle signer id",
        )
        if signer_id == 0:
            raise ValueError(
                "seal history multi-proof bundle signer ids must be positive"
            )
        if signer_ids and signer_id <= signer_ids[-1]:
            raise ValueError(
                "seal history multi-proof bundle signer ids must be strictly "
                "increasing and unique"
            )
        signer_ids.append(signer_id)
    if offset != len(blob):
        raise ValueError(
            "trailing bytes after seal history multi-proof bundle"
        )

    bundle = SealHistoryMultiProofBundle(
        proof=proof,
        signature=AggregateSignature(
            R=R, z=z, signer_ids=tuple(signer_ids)
        ),
    )
    if encode_history_multi_proof_bundle(bundle) != blob:
        raise ValueError(
            "non-canonical seal history multi-proof bundle encoding"
        )
    return bundle


def verify_history_multi_proof_bundle(
    bundle: SealHistoryMultiProofBundle, key: SigningDKGResult
) -> bool:
    """Verify a bundle exactly as :func:`check_history_multi_proof` would.

    This is a convenience wrapper over
    ``check_history_multi_proof(bundle.proof, bundle.signature, key)``:
    every disclosed seal is re-checked with :func:`verify_seal`, the
    Merkle root is rebuilt from the proof and the signature verified on
    ``b"sh/r" || U64(total) || root``. Returns ``True`` only when all of
    them hold; a well-formed bundle with tampered seals, indices,
    siblings or signature, or one presented under another key, returns
    ``False``.

    A non-:class:`SealHistoryMultiProofBundle` argument raises
    TypeError; illegal nested proof, signature or key structure raises
    TypeError/ValueError, exactly as
    :func:`check_history_multi_proof` does.
    """
    if not isinstance(bundle, SealHistoryMultiProofBundle):
        raise TypeError(
            "bundle must be a SealHistoryMultiProofBundle instance"
        )
    return check_history_multi_proof(bundle.proof, bundle.signature, key)


# ---------------------------------------------------------------------------
# Canonical seal-history-proof transport: a self-delimiting,
# byte-for-byte
# reproducible encoding of a SealHistoryProof for cross-implementation
# exchange and persistence. Decoding restores structure only — the nested
# seal goes through decode_seal, no seal or signature is checked and no state
# is kept, so check_history_proof remains the sole verifier afterwards.
# ---------------------------------------------------------------------------

SEAL_HISTORY_PROOF_WIRE_TAG = b"thresholdsign/seal-history-proof/v1"


def encode_history_proof(proof: SealHistoryProof) -> bytes:
    """Canonically encode a seal history proof for transport or persistence.

    The encoding is the direct concatenation, in order, of the tag
    ``b"thresholdsign/seal-history-proof/v1"``, ``VARINT(index)`` and
    ``VARINT(total)``, the seal frame — the 4-byte unsigned big-endian
    length ``len(E)`` followed by ``E = encode_seal(proof.seal)`` — the
    path count as a 4-byte unsigned big-endian integer and then the raw
    32-byte sibling digests in the proof's leaf-to-root order. A
    ``VARINT`` is a 4-byte unsigned big-endian body length followed by
    the shortest unsigned big-endian value (zero is the single byte
    ``00`` and positive values carry no leading zero). The bounds are
    ``0 < total < 2**64`` and ``0 <= index < total``; the path count
    must be ``(total - 1).bit_length()`` entries of exactly 32 bytes.

    Only a structurally legal :class:`SealHistoryProof` is accepted —
    wrong field or entry types raise TypeError and illegal bounds, a bad
    path shape, a structurally illegal nested seal or an over-long frame
    raise ValueError, exactly as :func:`check_history_proof`'s
    structural checks do — but neither the seal nor any signature is
    verified: :func:`check_history_proof` stays the way to verify the
    proof afterwards. The output for a given proof is unique and the
    encoding carries no network, storage or hidden state.
    """
    index, total, seal, siblings = _validate_history_proof_structure(proof)
    encoded_seal = encode_seal(seal)
    if len(encoded_seal) > 0xFFFFFFFF:
        raise ValueError("history proof seal encoding too long")

    buffer = bytearray(SEAL_HISTORY_PROOF_WIRE_TAG)
    buffer += _encode_varint(index)
    buffer += _encode_varint(total)
    buffer += len(encoded_seal).to_bytes(4, "big", signed=False)
    buffer += encoded_seal
    buffer += len(siblings).to_bytes(4, "big", signed=False)
    for sibling in siblings:
        buffer += sibling
    return bytes(buffer)


def decode_history_proof(blob: bytes) -> SealHistoryProof:
    """Decode the canonical encoding produced by :func:`encode_history_proof`.

    Accepts only the single canonical form: the tag
    ``b"thresholdsign/seal-history-proof/v1"``, the length-prefixed
    integers ``index`` and ``total`` (each a 4-byte unsigned big-endian
    length followed by its shortest unsigned big-endian value, zero
    encoded as the single byte ``00``), the seal frame (a 4-byte
    non-zero length followed by bytes that :func:`decode_seal` accepts),
    the 4-byte path count and then exactly that many raw 32-byte sibling
    digests in leaf-to-root order. A non-bytes argument raises
    TypeError; a wrong or missing tag, an empty or over-long seal frame,
    a non-canonical nested seal or integer, an out-of-range value
    (``0 < total < 2**64`` and ``0 <= index < total``), a path count
    that does not equal ``(total - 1).bit_length()``, a sibling that is
    not exactly 32 bytes, truncation, or trailing bytes raises
    ValueError. A successfully decoded proof re-encodes to exactly the
    input bytes.

    Decoding only restores the structure: the nested seal is decoded
    with :func:`decode_seal` (which verifies no finding and checks no
    signature) and nothing else is verified. A structurally legal proof
    whose seal does not verify or whose root signature is invalid is
    returned normally, and :func:`check_history_proof` reports it as
    ``False``.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not blob.startswith(SEAL_HISTORY_PROOF_WIRE_TAG):
        raise ValueError("bad seal history proof tag")
    offset = len(SEAL_HISTORY_PROOF_WIRE_TAG)

    index, offset = _read_varint(blob, offset, what="seal history proof index")
    total, offset = _read_varint(blob, offset, what="seal history proof total")
    if total <= 0:
        raise ValueError("seal history proof total must be positive")
    if total > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("seal history proof total too large")
    if index < 0 or index >= total:
        raise ValueError("seal history proof index out of range")

    encoded_seal, offset = _read_audit_proof_block(
        blob, offset, what="seal history proof seal"
    )
    seal = decode_seal(encoded_seal)

    if offset + 4 > len(blob):
        raise ValueError("truncated seal history proof path count")
    path_count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    expected_depth = (total - 1).bit_length()
    if path_count != expected_depth:
        raise ValueError(
            "seal history proof path count does not match total"
        )

    siblings = []
    for _ in range(path_count):
        if offset + SEAL_HISTORY_PROOF_DIGEST_SIZE > len(blob):
            raise ValueError("truncated seal history proof path")
        siblings.append(
            bytes(
                blob[
                    offset:offset + SEAL_HISTORY_PROOF_DIGEST_SIZE
                ]
            )
        )
        offset += SEAL_HISTORY_PROOF_DIGEST_SIZE
    if offset != len(blob):
        raise ValueError("trailing bytes after seal history proof")

    proof = SealHistoryProof(
        index=index,
        total=total,
        seal=seal,
        siblings=tuple(siblings),
    )
    if encode_history_proof(proof) != blob:
        raise ValueError("non-canonical seal history proof encoding")
    return proof


# ---------------------------------------------------------------------------
# Canonical seal-history-proof bundle transport: a self-delimiting,
# byte-for-byte reproducible encoding of a SealHistoryProof together with the
# AggregateSignature on its b"sh/r" || U64(total) || root statement, for
# cross-implementation exchange and persistence. Decoding restores structure
# only — the nested proof goes through decode_history_proof and no seal or
# signature is checked, so verify_history_proof_bundle remains the sole
# verifier afterwards.
# ---------------------------------------------------------------------------

SEAL_HISTORY_PROOF_BUNDLE_WIRE_TAG = b"ts/shpb/v1"


@dataclass(frozen=True)
class SealHistoryProofBundle:
    """A single-seal history proof together with its root signature.

    The fields, in order, are ``proof`` (a :class:`SealHistoryProof`) and
    ``signature`` (the :class:`AggregateSignature` on the proof's
    ``b"sh/r" || U64(total) || root`` statement). The dataclass is frozen,
    positionally constructible and compared by value, and carries no
    network, storage or hidden state. Field types and bounds are not
    checked at construction time — :func:`encode_history_proof_bundle`
    checks the structure and :func:`verify_history_proof_bundle` is the
    way to test a bundle afterwards.
    """

    proof: SealHistoryProof
    signature: AggregateSignature


def encode_history_proof_bundle(bundle: SealHistoryProofBundle) -> bytes:
    """Canonically encode a history proof bundle for transport or persistence.

    The encoding is, in order, the tag ``b"ts/shpb/v1"``, the 4-byte
    unsigned big-endian length ``len(P)`` followed by
    ``P = encode_history_proof(bundle.proof)`` (never empty), and then the
    signature frame: ``VARINT(R)``, ``VARINT(z)``, the 4-byte unsigned
    big-endian signer count ``k`` and one ``VARINT(id)`` per ascending
    signer id. A ``VARINT`` is a 4-byte unsigned big-endian body length
    followed by the shortest unsigned big-endian value (zero is the
    single byte ``00``, positive values carry no leading zero); ``R``
    must be positive and ``z`` may be zero.

    Only a structurally legal :class:`SealHistoryProofBundle` is accepted
    — a non-bundle or non-:class:`SealHistoryProof` proof argument, or
    wrong proof/signature field types, raise TypeError and illegal proof
    or signature structure (the exact bounds of
    :func:`encode_history_proof`, a non-positive ``R``, a negative ``z``,
    an empty or non-strictly-increasing signer id tuple) or an over-long
    frame raises ValueError, exactly as :func:`check_history_proof`'s
    structural checks do — but the seal is not verified and the signature
    is not checked against the root:
    :func:`verify_history_proof_bundle` stays the way to verify a bundle
    afterwards. The output for a given bundle is unique and the encoding
    carries no network, storage or hidden state.
    """
    if not isinstance(bundle, SealHistoryProofBundle):
        raise TypeError("bundle must be a SealHistoryProofBundle instance")
    if not isinstance(bundle.proof, SealHistoryProof):
        raise TypeError("bundle.proof must be a SealHistoryProof instance")
    encoded_proof = encode_history_proof(bundle.proof)
    signer_count = _check_history_proof_bundle_signature(bundle.signature)
    if len(encoded_proof) > 0xFFFFFFFF:
        raise ValueError("history proof encoding too long")
    if signer_count > 0xFFFFFFFF:
        raise ValueError("too many signer ids")

    buffer = bytearray(SEAL_HISTORY_PROOF_BUNDLE_WIRE_TAG)
    buffer += len(encoded_proof).to_bytes(4, "big", signed=False)
    buffer += encoded_proof
    buffer += _encode_varint(bundle.signature.R)
    buffer += _encode_varint(bundle.signature.z)
    buffer += signer_count.to_bytes(4, "big", signed=False)
    for signer_id in bundle.signature.signer_ids:
        buffer += _encode_varint(signer_id)
    return bytes(buffer)


def decode_history_proof_bundle(
    blob: bytes,
) -> SealHistoryProofBundle:
    """Decode the canonical encoding produced by :func:`encode_history_proof_bundle`.

    Accepts only the single canonical form: the tag ``b"ts/shpb/v1"``, a
    4-byte non-zero frame length followed by bytes that
    :func:`decode_history_proof` accepts, the length-prefixed integers
    ``R`` and ``z``, the 4-byte non-zero signer count ``k`` and then
    exactly ``k`` strictly increasing positive signer ids. A non-bytes
    argument raises TypeError; a wrong or missing tag, a zero or
    over-long proof frame length, a non-canonical nested proof, a zero
    ``R``, a non-canonical integer (leading zero or over-long length), a
    zero signer count, a non-positive or non-increasing signer id,
    truncation, or trailing bytes raises ValueError. A successfully
    decoded bundle re-encodes to exactly the input bytes.

    Decoding only restores the structure: the nested proof is decoded
    with :func:`decode_history_proof` (which verifies no seal) and the
    signature is not checked. A structurally legal bundle whose seal
    does not verify or whose signature does not sign the root is
    returned normally, and :func:`verify_history_proof_bundle` reports
    it as ``False``.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not blob.startswith(SEAL_HISTORY_PROOF_BUNDLE_WIRE_TAG):
        raise ValueError("bad seal history proof bundle tag")
    offset = len(SEAL_HISTORY_PROOF_BUNDLE_WIRE_TAG)

    encoded_proof, offset = _read_audit_proof_block(
        blob, offset, what="seal history proof bundle proof"
    )
    proof = decode_history_proof(encoded_proof)

    R, offset = _read_varint(
        blob, offset, what="seal history proof bundle signature R"
    )
    z, offset = _read_varint(
        blob, offset, what="seal history proof bundle signature z"
    )
    if R == 0:
        raise ValueError("seal history proof bundle signature R must be positive")

    if offset + 4 > len(blob):
        raise ValueError("truncated seal history proof bundle signer count")
    signer_count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    if signer_count == 0:
        raise ValueError("seal history proof bundle must name at least one signer")

    signer_ids = []
    for _ in range(signer_count):
        signer_id, offset = _read_varint(
            blob,
            offset,
            what="seal history proof bundle signer id",
        )
        if signer_id == 0:
            raise ValueError("seal history proof bundle signer ids must be positive")
        if signer_ids and signer_id <= signer_ids[-1]:
            raise ValueError(
                "seal history proof bundle signer ids must be strictly "
                "increasing and unique"
            )
        signer_ids.append(signer_id)
    if offset != len(blob):
        raise ValueError("trailing bytes after seal history proof bundle")

    bundle = SealHistoryProofBundle(
        proof=proof,
        signature=AggregateSignature(R=R, z=z, signer_ids=tuple(signer_ids)),
    )
    if encode_history_proof_bundle(bundle) != blob:
        raise ValueError("non-canonical seal history proof bundle encoding")
    return bundle


def verify_history_proof_bundle(
    bundle: SealHistoryProofBundle, key: SigningDKGResult
) -> bool:
    """Verify a bundle exactly as :func:`check_history_proof` would.

    This is a convenience wrapper over
    ``check_history_proof(bundle.proof, bundle.signature, key)``: the
    proven seal is re-checked with :func:`verify_seal`, the Merkle root
    is rebuilt from the proof and the signature verified on
    ``b"sh/r" || U64(total) || root``. Returns ``True`` only when all of
    them hold; a well-formed bundle with a tampered seal, sibling path
    or signature, or one presented under another key, returns
    ``False``.

    A non-:class:`SealHistoryProofBundle` argument raises TypeError;
    illegal nested proof, signature or key structure raises
    TypeError/ValueError, exactly as :func:`check_history_proof` does.
    """
    if not isinstance(bundle, SealHistoryProofBundle):
        raise TypeError("bundle must be a SealHistoryProofBundle instance")
    return check_history_proof(bundle.proof, bundle.signature, key)


# ---------------------------------------------------------------------------
# Append-only consistency (extension) proofs over the same seal-history
# Merkle tree: a compact statement that the first ``old_total`` items of a
# seal history are exactly the items of an older, shorter history. The proof
# carries only the leaf digests — never a ReportSeal — and both the old and
# the new statement are the ordinary root messages
# ``b"sh/r" || U64(total) || root`` of the shared SealHistoryProof tree
# rules, so an observer needs nothing but the two threshold signatures to
# check the prefix relation. No state is kept.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SealHistoryExtension:
    """An append-only consistency proof between two seal-history roots.

    The fields, in order, are ``old_total`` (the non-empty old item count,
    strictly smaller than the new total) and ``leaves`` (the 32-byte leaf
    digests of the full new history item sequence, in order, each exactly
    ``H(b"sh/l" || U64(i) || H(encode_seal(item)))`` as in
    :func:`make_history_proof`; the tuple is non-empty). The first
    ``old_total`` leaves rebuild the old root and all of them rebuild the
    new root, so the proof discloses no seal — only its digest. The
    dataclass is frozen, positionally constructible and compared by value,
    and carries no network, storage or hidden state. Field types and
    bounds are not checked at construction time —
    :func:`check_history_extension` is the way to test a proof afterwards.
    """

    old_total: int
    leaves: tuple[bytes, ...]


def _history_extension_root(leaves: tuple[bytes, ...]) -> bytes:
    """Root digest of the SealHistoryProof tree rebuilt from leaf digests.

    The pairing rules are exactly those of :func:`_history_proof_levels`:
    a level with an odd tail width duplicates its last node, and internal
    nodes are ``H(b"sh/n" || left || right)``.
    """
    current = leaves
    while len(current) > 1:
        if len(current) % 2 == 1:
            current = current + current[-1:]
        current = tuple(
            _history_proof_node(current[index], current[index + 1])
            for index in range(0, len(current), 2)
        )
    return current[0]


def make_history_extension(
    history: SealHistory, old_total: int
) -> tuple[bytes, bytes, SealHistoryExtension]:
    """Build the old and new root statements and a consistency proof.

    ``history`` must be a structurally legal :class:`SealHistory` — a
    non-empty tuple of :class:`ReportSeal` values each encodable by
    :func:`encode_seal` — and ``old_total`` the old item count, which must
    be non-zero and strictly smaller than the total item count ``n``; both
    counts fit ``0 < old_total < n < 2**64``. The tree rules are exactly
    those of :func:`make_history_proof`: leaves are
    ``H(b"sh/l" || U64(i) || H(encode_seal(item)))`` and internal nodes
    ``H(b"sh/n" || left || right)``; a level with an odd tail width
    duplicates its last node for pairing. The first ``old_total`` leaves
    give the old root and all leaves give the new root. Returns
    ``(old_message, new_message, proof)`` where both messages are
    ``b"sh/r" || U64(total) || root`` with ``total`` the old count and the
    total count respectively — the bytes to be threshold-signed — and
    ``proof`` is the :class:`SealHistoryExtension` carrying every leaf
    digest and disclosing no seal.

    Wrong argument types raise TypeError: a non-:class:`SealHistory`
    history or a non-integer (including boolean) ``old_total``. An empty
    history, a structurally illegal item seal, a count that does not fit
    the 8-byte counter, or an ``old_total`` outside
    ``0 < old_total < n`` raises ValueError.
    """
    if not isinstance(history, SealHistory):
        raise TypeError("history must be a SealHistory instance")
    if not isinstance(old_total, int) or isinstance(old_total, bool):
        raise TypeError("old_total must be an integer")
    total = _check_seal_history_items(history.items)
    if total > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("too many history items")
    if old_total <= 0 or old_total >= total:
        raise ValueError("old_total out of range")

    leaves = tuple(
        _history_proof_leaf(index, seal)
        for index, seal in enumerate(history.items)
    )
    old_root = _history_extension_root(leaves[:old_total])
    new_root = _history_extension_root(leaves)
    old_message = (
        SEAL_HISTORY_PROOF_ROOT_TAG + _history_proof_u64(old_total) + old_root
    )
    new_message = (
        SEAL_HISTORY_PROOF_ROOT_TAG + _history_proof_u64(total) + new_root
    )
    proof = SealHistoryExtension(old_total=old_total, leaves=leaves)
    return old_message, new_message, proof


def _validate_history_extension_structure(
    proof: object,
) -> tuple[int, tuple[bytes, ...]]:
    """Type- and structure-check a SealHistoryExtension, returning its fields.

    Only the container structure is checked: nothing is encoded or
    verified against a key here. The bounds are
    ``0 < old_total < len(leaves)`` and ``len(leaves) <= 2**64 - 1``; the
    leaf tuple must be non-empty and every entry exactly 32 bytes. Wrong
    field types raise TypeError; illegal bounds, an empty leaf tuple or a
    leaf of the wrong width raise ValueError.
    """
    if not isinstance(proof, SealHistoryExtension):
        raise TypeError("proof must be a SealHistoryExtension instance")
    old_total = proof.old_total
    leaves = proof.leaves
    if not isinstance(old_total, int) or isinstance(old_total, bool):
        raise TypeError("proof.old_total must be an integer")
    if not isinstance(leaves, tuple):
        raise TypeError("proof.leaves must be a tuple")
    for leaf in leaves:
        if not isinstance(leaf, bytes):
            raise TypeError("proof.leaves entries must be bytes")

    try:
        count = len(leaves)
    except OverflowError:
        raise ValueError("too many leaves") from None
    if count == 0:
        raise ValueError("proof.leaves must be non-empty")
    if count > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("too many leaves")
    if old_total <= 0 or old_total >= count:
        raise ValueError("proof.old_total out of range")
    for leaf in leaves:
        if len(leaf) != SEAL_HISTORY_PROOF_DIGEST_SIZE:
            raise ValueError("proof.leaves entries must be exactly 32 bytes")
    return old_total, leaves


def check_history_extension(
    proof: SealHistoryExtension,
    old_sig: AggregateSignature,
    new_sig: AggregateSignature,
    key: SigningDKGResult,
) -> bool:
    """Verify a consistency proof against its two threshold signatures.

    The old root is rebuilt from the first ``proof.old_total`` leaves of
    ``proof.leaves`` and the new root from all of them, exactly as in
    :func:`make_history_extension` with the :func:`make_history_proof`
    tree rules (odd tails pair with themselves); the statements
    ``b"sh/r" || U64(old_total) || old_root`` and
    ``b"sh/r" || U64(n) || new_root`` are then checked as ``old_sig``'s
    and ``new_sig``'s threshold Schnorr messages via
    :func:`verify_signature` under ``key``. Returns ``True`` only when both
    signatures verify: an observer learns nothing but the two signatures
    and the leaf digests — no seal is disclosed — yet is convinced the old
    sealed item sequence is a prefix of the new one. A well-formed proof
    whose leaves or ``old_total`` were tampered with, a swapped or
    mismatched signature pair, or a proof presented under another key
    returns ``False``.

    A non-:class:`SealHistoryExtension` proof, a
    non-:class:`AggregateSignature` signature or any wrong field type
    (non-integer ``old_total`` including booleans, a non-tuple leaf
    sequence or non-bytes leaf) raises TypeError; an empty leaf tuple, a
    leaf that is not exactly 32 bytes, a total over ``2**64 - 1``, an
    ``old_total`` outside ``0 < old_total < n``, or a structurally illegal
    signature or ``key`` raises ValueError, exactly as
    :func:`verify_signature` would.
    """
    old_total, leaves = _validate_history_extension_structure(proof)
    if not isinstance(old_sig, AggregateSignature):
        raise TypeError("old_sig must be an AggregateSignature instance")
    if not isinstance(new_sig, AggregateSignature):
        raise TypeError("new_sig must be an AggregateSignature instance")

    _result, public_key, field_prime, group_prime, generator = _check_signing_setup(key)
    _check_signing_dkg_structure(key)

    old_root = _history_extension_root(leaves[:old_total])
    new_root = _history_extension_root(leaves)
    old_message = (
        SEAL_HISTORY_PROOF_ROOT_TAG + _history_proof_u64(old_total) + old_root
    )
    new_message = (
        SEAL_HISTORY_PROOF_ROOT_TAG
        + _history_proof_u64(len(leaves))
        + new_root
    )
    if not verify_signature(
        old_message,
        old_sig,
        public_key,
        group_prime=group_prime,
        generator=generator,
        prime=field_prime,
    ):
        return False
    return verify_signature(
        new_message,
        new_sig,
        public_key,
        group_prime=group_prime,
        generator=generator,
        prime=field_prime,
    )


# ---------------------------------------------------------------------------
# Canonical SealHistoryExtension transport: a self-delimiting (via the fixed
# tag and the leaf count), byte-for-byte reproducible encoding of an
# append-only consistency proof for cross-implementation exchange and
# persistence. Decoding restores the frozen structure only — no signature is
# checked and a leaf digest's cryptographic meaning is never inspected, so
# check_history_extension remains the sole verifier afterwards and no state
# is kept.
# ---------------------------------------------------------------------------

SEAL_HISTORY_EXTENSION_WIRE_TAG = (
    b"thresholdsign/seal-history-extension/v1"
)


def encode_history_extension(proof: SealHistoryExtension) -> bytes:
    """Canonically encode a seal-history consistency proof for transport.

    The encoding is the direct concatenation, in order with no separators
    or padding, of the tag ``b"thresholdsign/seal-history-extension/v1"``,
    ``old_total`` as an 8-byte unsigned big-endian integer, the leaf total
    ``n`` as an 8-byte unsigned big-endian integer, and then all ``n``
    leaf digests in their original order, each exactly 32 raw bytes. The
    total length is therefore fixed by the tag and the leaf count:
    ``len(tag) + 16 + 32 * n``. The bounds are
    ``0 < old_total < n < 2**64``; the leaf tuple must be non-empty and
    every entry exactly 32 bytes.

    Only the container structure is checked — no signature is verified and
    the cryptographic meaning of any leaf digest is never inspected — so a
    proof whose leaves do not rebuild the signed roots still encodes:
    :func:`check_history_extension` stays the way to verify a proof
    afterwards. A non-:class:`SealHistoryExtension` argument or a wrong
    field type (a non-integer ``old_total`` including booleans, a
    non-tuple leaf sequence or a non-bytes leaf entry) raises TypeError;
    an empty leaf tuple, ``old_total`` zero or not smaller than the leaf
    total, a leaf total of ``2**64 - 1``, or a leaf that is not exactly
    32 bytes raises ValueError. The encoding carries no signature, key,
    seal or other private material, keeps no state, and the same proof
    object always encodes to the same unique bytes.
    """
    old_total, leaves = _validate_history_extension_structure(proof)
    if len(leaves) >= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("too many leaves")
    buffer = bytearray(SEAL_HISTORY_EXTENSION_WIRE_TAG)
    buffer += _history_proof_u64(old_total)
    buffer += _history_proof_u64(len(leaves))
    for leaf in leaves:
        buffer += leaf
    return bytes(buffer)


def decode_history_extension(blob: bytes) -> SealHistoryExtension:
    """Decode the canonical encoding produced by :func:`encode_history_extension`.

    Accepts only the single canonical form: the tag
    ``b"thresholdsign/seal-history-extension/v1"`` followed by two
    8-byte unsigned big-endian counts, ``old_total`` and the leaf total
    ``n``, and then exactly ``n`` consecutive raw 32-byte leaf digests in
    order, with nothing trailing. A non-bytes argument raises TypeError; a
    wrong or missing tag, fewer than the 16 count bytes, an empty or
    maximal (``2**64 - 1``) leaf total, an ``old_total`` outside
    ``0 < old_total < n``, fewer leaf bytes than the count requires,
    truncation, or trailing bytes raises ValueError. A successfully
    decoded proof re-encodes to exactly the input bytes.

    Decoding only restores the frozen proof object: the leaf digests are
    not parsed for cryptographic meaning and no signature, key or seal is
    checked. A structurally legal proof whose roots do not verify is
    returned normally, and :func:`check_history_extension` reports it as
    ``False``.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not blob.startswith(SEAL_HISTORY_EXTENSION_WIRE_TAG):
        raise ValueError("bad seal history extension tag")
    offset = len(SEAL_HISTORY_EXTENSION_WIRE_TAG)
    if offset + 16 > len(blob):
        raise ValueError("truncated seal history extension counts")
    old_total = int.from_bytes(blob[offset:offset + 8], "big", signed=False)
    leaf_count = int.from_bytes(blob[offset + 8:offset + 16], "big")
    offset += 16
    if leaf_count == 0:
        raise ValueError("seal history extension leaves must be non-empty")
    if leaf_count >= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("seal history extension leaf count too large")
    if old_total <= 0 or old_total >= leaf_count:
        raise ValueError("seal history extension old_total out of range")

    expected_width = leaf_count * SEAL_HISTORY_PROOF_DIGEST_SIZE
    leaf_bytes = blob[offset:]
    if len(leaf_bytes) < expected_width:
        raise ValueError("truncated seal history extension leaves")
    if len(leaf_bytes) > expected_width:
        raise ValueError("trailing bytes after seal history extension")
    leaves = tuple(
        bytes(
            leaf_bytes[
                index: index + SEAL_HISTORY_PROOF_DIGEST_SIZE
            ]
        )
        for index in range(
            0,
            expected_width,
            SEAL_HISTORY_PROOF_DIGEST_SIZE,
        )
    )

    proof = SealHistoryExtension(old_total=old_total, leaves=leaves)
    if encode_history_extension(proof) != blob:
        raise ValueError("non-canonical seal history extension encoding")
    return proof


# ---------------------------------------------------------------------------
# Self-contained seal-history extension transport: a SealHistoryExtension
# bundled with the old and new root signatures, so an append-only
# consistency proof no longer needs its caller to pair the two signatures
# out of band. The proof frame is the existing canonical extension encoding
# and the two trailing frames reuse the canonical bundle signature rules
# verbatim — no new wire idiom is introduced. Decoding restores the frozen
# structure only (no signature is checked and leaf digests stay opaque), so
# verify_history_extension_bundle remains the sole verifier afterwards and
# no state is kept.
# ---------------------------------------------------------------------------

SEAL_HISTORY_EXTENSION_BUNDLE_WIRE_TAG = b"ts/sheb/v1"


@dataclass(frozen=True)
class SealHistoryExtensionBundle:
    """A consistency proof together with its two root signatures.

    The fields, in order, are ``extension`` (a
    :class:`SealHistoryExtension` carrying the full new history's leaf
    digests), ``old_sig`` (the :class:`AggregateSignature` on the old
    ``b"sh/r" || U64(old_total) || old_root`` statement) and ``new_sig``
    (the :class:`AggregateSignature` on the new
    ``b"sh/r" || U64(n) || new_root`` statement). The dataclass is frozen,
    positionally constructible and compared by value, has no field
    defaults, and carries no network, storage or hidden state. Field types
    and bounds are not checked at construction time —
    :func:`encode_history_extension_bundle` checks the structure and
    :func:`verify_history_extension_bundle` is the way to test a bundle
    afterwards.
    """

    extension: SealHistoryExtension
    old_sig: AggregateSignature
    new_sig: AggregateSignature


def encode_history_extension_bundle(
    bundle: SealHistoryExtensionBundle,
) -> bytes:
    """Canonically encode a self-contained consistency-proof bundle.

    The encoding is, in order, the tag ``b"ts/sheb/v1"``, the 4-byte
    unsigned big-endian length ``len(P)`` followed by
    ``P = encode_history_extension(bundle.extension)`` (the existing
    canonical extension encoding, never empty), and then the old and new
    signature frames, each exactly the canonical signature frame of
    :func:`encode_history_proof_bundle`: ``VARINT(R)``, ``VARINT(z)``, the
    4-byte unsigned big-endian signer count and one ``VARINT(id)`` per
    ascending signer id. A ``VARINT`` is a 4-byte unsigned big-endian body
    length followed by the shortest unsigned big-endian value (zero is the
    single byte ``00``, positive values carry no leading zero); ``R`` must
    be positive and ``z`` may be zero.

    Only a structurally legal :class:`SealHistoryExtensionBundle` is
    accepted — a non-bundle argument or wrong field types (a
    non-:class:`SealHistoryExtension` extension, a
    non-:class:`AggregateSignature` signature, non-integer ``R``/``z``
    including booleans, a non-tuple or non-integer signer id sequence)
    raises TypeError and an illegal extension or signature structure (the
    exact bounds of :func:`encode_history_extension`, a non-positive
    ``R``, a negative ``z``, an empty or non-strictly-increasing signer id
    tuple) or an over-long frame raises ValueError — but neither signature
    is checked against a root and the leaf digests are never parsed:
    :func:`verify_history_extension_bundle` stays the way to verify a
    bundle afterwards. The output for a given bundle is unique and the
    encoding carries no key, seal or other private material and keeps no
    state.
    """
    if not isinstance(bundle, SealHistoryExtensionBundle):
        raise TypeError(
            "bundle must be a SealHistoryExtensionBundle instance"
        )
    encoded_extension = encode_history_extension(bundle.extension)
    old_signer_count = _check_history_proof_bundle_signature(
        bundle.old_sig, field="bundle.old_sig"
    )
    new_signer_count = _check_history_proof_bundle_signature(
        bundle.new_sig, field="bundle.new_sig"
    )
    if len(encoded_extension) > 0xFFFFFFFF:
        raise ValueError("seal history extension encoding too long")
    if old_signer_count > 0xFFFFFFFF or new_signer_count > 0xFFFFFFFF:
        raise ValueError("too many signer ids")

    buffer = bytearray(SEAL_HISTORY_EXTENSION_BUNDLE_WIRE_TAG)
    buffer += len(encoded_extension).to_bytes(4, "big", signed=False)
    buffer += encoded_extension
    for signature, signer_count in (
        (bundle.old_sig, old_signer_count),
        (bundle.new_sig, new_signer_count),
    ):
        buffer += _encode_varint(signature.R)
        buffer += _encode_varint(signature.z)
        buffer += signer_count.to_bytes(4, "big", signed=False)
        for signer_id in signature.signer_ids:
            buffer += _encode_varint(signer_id)
    return bytes(buffer)


def decode_history_extension_bundle(
    blob: bytes,
) -> SealHistoryExtensionBundle:
    """Decode the canonical encoding produced by :func:`encode_history_extension_bundle`.

    Accepts only the single canonical form: the tag ``b"ts/sheb/v1"``, a
    4-byte non-zero frame length followed by bytes that
    :func:`decode_history_extension` accepts, and then the old and new
    signature frames, each the length-prefixed integers ``R`` and ``z``,
    the 4-byte non-zero signer count and exactly that many strictly
    increasing positive signer ids. A non-bytes argument raises
    TypeError; a wrong or missing tag, a zero or over-long frame length,
    any encoding :func:`decode_history_extension` rejects (bad nested tag,
    truncated counts or leaves, an out-of-range ``old_total``, trailing
    bytes), a zero ``R``, a non-canonical integer (leading zero or
    over-long length), a zero signer count, a non-positive or
    non-increasing signer id, truncation, or trailing bytes raises
    ValueError. A successfully decoded bundle re-encodes to exactly the
    input bytes.

    Decoding only restores the frozen structure: the nested extension is
    decoded with :func:`decode_history_extension` (which keeps the leaf
    digests opaque and verifies nothing), neither signature is checked and
    no state is kept. A structurally legal bundle whose leaves or
    signatures do not match the signed roots is returned normally, and
    :func:`verify_history_extension_bundle` reports it as ``False``.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not blob.startswith(SEAL_HISTORY_EXTENSION_BUNDLE_WIRE_TAG):
        raise ValueError("bad seal history extension bundle tag")
    offset = len(SEAL_HISTORY_EXTENSION_BUNDLE_WIRE_TAG)

    encoded_extension, offset = _read_audit_proof_block(
        blob, offset, what="seal history extension bundle extension"
    )
    extension = decode_history_extension(encoded_extension)

    old_sig, offset = _read_bundle_signature_frame(
        blob, offset, what="seal history extension bundle old"
    )
    new_sig, offset = _read_bundle_signature_frame(
        blob, offset, what="seal history extension bundle new"
    )
    if offset != len(blob):
        raise ValueError("trailing bytes after seal history extension bundle")

    bundle = SealHistoryExtensionBundle(
        extension=extension,
        old_sig=old_sig,
        new_sig=new_sig,
    )
    if encode_history_extension_bundle(bundle) != blob:
        raise ValueError(
            "non-canonical seal history extension bundle encoding"
        )
    return bundle


def verify_history_extension_bundle(
    bundle: SealHistoryExtensionBundle, key: SigningDKGResult
) -> bool:
    """Verify a bundle exactly as :func:`check_history_extension` would.

    This is a convenience wrapper over
    ``check_history_extension(bundle.extension, bundle.old_sig,
    bundle.new_sig, key)``: the old root is rebuilt from the extension's
    first ``old_total`` leaves and the new root from all of them, and each
    signature is verified on its ``b"sh/r" || U64(total) || root``
    statement. Returns ``True`` only when both hold; a well-formed bundle
    with tampered leaves or ``old_total``, a swapped or mismatched
    signature pair, or one presented under another key returns ``False``.

    A non-:class:`SealHistoryExtensionBundle` argument raises TypeError;
    illegal nested extension, signature or key structure raises
    TypeError/ValueError, exactly as :func:`check_history_extension` does.
    """
    if not isinstance(bundle, SealHistoryExtensionBundle):
        raise TypeError(
            "bundle must be a SealHistoryExtensionBundle instance"
        )
    return check_history_extension(
        bundle.extension, bundle.old_sig, bundle.new_sig, key
    )


# ---------------------------------------------------------------------------
# Canonical seal-history extension bundle chain transport: a self-delimiting,
# byte-for-byte reproducible encoding of a non-empty, order-preserving
# sequence of SealHistoryExtensionBundle values, so a run of consecutive
# history extensions can be archived and checked as one object. Adjacent
# bundles link when the predecessor's full leaf sequence is exactly the
# successor's old prefix. Decoding restores structure only and neither the
# per-bundle signatures nor the linkage are checked, so
# verify_history_extension_bundle_chain remains the sole verifier afterwards.
# ---------------------------------------------------------------------------

SEAL_HISTORY_EXTENSION_BUNDLE_CHAIN_WIRE_TAG = b"ts/shebc/v1"


@dataclass(frozen=True)
class SealHistoryExtensionBundleChain:
    """A non-empty, order-preserving chain of extension bundles.

    ``items`` is the non-empty tuple of
    :class:`SealHistoryExtensionBundle` values in chain order: for every
    adjacent pair the predecessor's leaf total must equal the successor's
    ``extension.old_total`` and the predecessor's ``extension.leaves``
    must equal the successor's ``extension.leaves[:old_total]`` (enforced
    by :func:`verify_history_extension_bundle_chain`, not by
    construction). The dataclass is frozen, positionally constructible and
    compared by value, and carries no network, storage or hidden state.
    Item types and the non-empty bound are not checked at construction
    time — :func:`encode_history_extension_bundle_chain` checks the
    structure and :func:`verify_history_extension_bundle_chain` is the way
    to test a chain afterwards.
    """

    items: tuple[SealHistoryExtensionBundle, ...]


def _check_history_extension_bundle_chain_items(items: object) -> int:
    """Type- and structure-check a chain's items container, without verifying.

    Items must be a non-empty tuple of
    :class:`SealHistoryExtensionBundle` values; the bundles themselves are
    neither encoded nor verified here (that is
    :func:`verify_history_extension_bundle`'s job during verification).
    Returns the item count.
    """
    if not isinstance(items, tuple):
        raise TypeError("items must be a tuple")
    try:
        count = len(items)
    except OverflowError:
        raise ValueError("too many chain items") from None
    if count == 0:
        raise ValueError("items must be non-empty")
    for item in items:
        if not isinstance(item, SealHistoryExtensionBundle):
            raise TypeError(
                "each chain item must be a SealHistoryExtensionBundle instance"
            )
    return count


def encode_history_extension_bundle_chain(
    chain: SealHistoryExtensionBundleChain,
) -> bytes:
    """Canonically encode a chain of self-contained consistency-proof bundles.

    The encoding is, in order, the tag ``b"ts/shebc/v1"``, the item count
    ``n = len(chain.items)`` as a 4-byte unsigned big-endian integer, and
    then one frame per item in chain order: each frame is the 4-byte
    unsigned big-endian length ``len(E)`` followed by
    ``E = encode_history_extension_bundle(item)``, the existing canonical
    single-bundle encoding (never empty).

    Only the chain container and the bundle structures are checked — the
    prefix linkage is not verified and neither signature is checked:
    :func:`verify_history_extension_bundle_chain` stays the way to verify
    a chain afterwards. A non-chain argument or a non-tuple item sequence
    raises TypeError, and a non-:class:`SealHistoryExtensionBundle`
    element raises TypeError exactly as
    :func:`encode_history_extension_bundle` does for its extension and
    signature fields. An empty chain, an over-long count or frame, or an
    illegal nested bundle raises ValueError. The output for a given chain
    is unique and the encoding carries no network, storage or hidden
    state.
    """
    if not isinstance(chain, SealHistoryExtensionBundleChain):
        raise TypeError(
            "chain must be a SealHistoryExtensionBundleChain instance"
        )
    count = _check_history_extension_bundle_chain_items(chain.items)
    if count > 0xFFFFFFFF:
        raise ValueError("too many chain items")

    bodies = []
    for item in chain.items:
        body = encode_history_extension_bundle(item)
        if len(body) > 0xFFFFFFFF:
            raise ValueError("seal history extension bundle encoding too long")
        bodies.append(body)

    buffer = bytearray(SEAL_HISTORY_EXTENSION_BUNDLE_CHAIN_WIRE_TAG)
    buffer += count.to_bytes(4, "big", signed=False)
    for body in bodies:
        buffer += len(body).to_bytes(4, "big", signed=False)
        buffer += body
    return bytes(buffer)


def decode_history_extension_bundle_chain(
    blob: bytes,
) -> SealHistoryExtensionBundleChain:
    """Decode the canonical encoding produced by :func:`encode_history_extension_bundle_chain`.

    Accepts only the single canonical form: the tag ``b"ts/shebc/v1"``,
    the 4-byte unsigned big-endian non-zero item count ``n``, and then
    exactly ``n`` frames, each a 4-byte unsigned big-endian non-zero
    length followed by bytes that :func:`decode_history_extension_bundle`
    accepts. A non-bytes argument raises TypeError; a wrong or missing
    tag, an empty chain, a zero or over-long frame length, an illegal
    nested bundle, a count mismatch, truncation, or trailing bytes raises
    ValueError. A successfully decoded chain re-encodes to exactly the
    input bytes.

    Decoding only restores the structure: every nested bundle goes
    through :func:`decode_history_extension_bundle`, whose leaf digests
    stay opaque and whose signatures are not checked, and the prefix
    linkage between adjacent bundles is not checked either. A
    structurally legal chain whose signatures do not match or whose
    bundles do not link is returned normally, and
    :func:`verify_history_extension_bundle_chain` reports it as
    ``False``.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not blob.startswith(SEAL_HISTORY_EXTENSION_BUNDLE_CHAIN_WIRE_TAG):
        raise ValueError("bad seal history extension bundle chain tag")
    offset = len(SEAL_HISTORY_EXTENSION_BUNDLE_CHAIN_WIRE_TAG)

    if offset + 4 > len(blob):
        raise ValueError("truncated seal history extension bundle chain count")
    count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    if count == 0:
        raise ValueError(
            "seal history extension bundle chain must be non-empty"
        )

    items = []
    for index in range(count):
        body, offset = _read_audit_proof_block(
            blob,
            offset,
            what=(
                "seal history extension bundle chain item " + str(index + 1)
            ),
        )
        items.append(decode_history_extension_bundle(body))
    if offset != len(blob):
        raise ValueError(
            "trailing bytes after seal history extension bundle chain"
        )

    chain = SealHistoryExtensionBundleChain(items=tuple(items))
    if encode_history_extension_bundle_chain(chain) != blob:
        raise ValueError(
            "non-canonical seal history extension bundle chain encoding"
        )
    return chain


def verify_history_extension_bundle_chain(
    chain: SealHistoryExtensionBundleChain, key: SigningDKGResult
) -> bool:
    """Verify every bundle of a chain and the prefix linkage between neighbours.

    Each item is verified with
    :func:`verify_history_extension_bundle` against ``key``, and for
    every adjacent pair the predecessor's leaf total must equal the
    successor's ``extension.old_total`` and the predecessor's
    ``extension.leaves`` must equal the first ``old_total`` leaves of the
    successor's ``extension.leaves`` — the old history of each hop is
    exactly the new history of the previous one. Returns ``True`` only
    when every single bundle verifies and every linkage holds; a
    well-formed chain with a mismatched signature pair, tampered leaves,
    a gap or overlap between neighbours, or one presented under another
    key returns ``False`` without raising.

    A non-:class:`SealHistoryExtensionBundleChain` argument raises
    TypeError; an empty chain, a non-tuple item sequence, a
    non-:class:`SealHistoryExtensionBundle` element, or an illegal nested
    bundle or key structure raises TypeError/ValueError, exactly as the
    structural checks of :func:`encode_history_extension_bundle_chain`
    and :func:`verify_history_extension_bundle` do. The function is
    stateless.
    """
    if not isinstance(chain, SealHistoryExtensionBundleChain):
        raise TypeError(
            "chain must be a SealHistoryExtensionBundleChain instance"
        )
    _check_history_extension_bundle_chain_items(chain.items)

    result = True
    previous = None
    for bundle in chain.items:
        if not verify_history_extension_bundle(bundle, key):
            result = False
        if previous is not None:
            previous_leaves = previous.extension.leaves
            old_total = bundle.extension.old_total
            if (
                len(previous_leaves) != old_total
                or previous_leaves != bundle.extension.leaves[:old_total]
            ):
                result = False
        previous = bundle
    return result


# ---------------------------------------------------------------------------
# Incremental seal-history extension chains: a space-saving delta form of
# SealHistoryExtensionBundleChain that stores the first hop's
# SealHistoryExtension in full and then only the 32-byte leaf digests each
# later hop appends, so the historical leaves shared by every hop are carried
# exactly once. The two conversion entry points expand the delta form into a
# plain self-contained bundle chain (verified by the existing
# verify_history_extension_bundle_chain) and compact a linking bundle chain
# back into delta form; neither verifies any signature and neither keeps
# hidden state.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SealHistoryExtensionDeltaChain:
    """An incremental extension chain that never repeats historical leaves.

    The fields, in order, are ``first`` (the :class:`SealHistoryExtension`
    covering the first hop, carried in full with every leaf of the first
    hop's new history), ``additions`` (the tuple of non-empty batches of new
    32-byte leaf digests, in chain order — batch ``i`` holds exactly the
    leaves hop ``i + 1`` appends on top of every previous leaf) and
    ``signatures`` (the tuple of :class:`AggregateSignature` checkpoint root
    signatures, exactly ``len(additions) + 2`` long): the first proof is
    bracketed by signatures ``0`` and ``1``, and batch ``i`` produces the
    successor proof bracketed by signatures ``i + 1`` and ``i + 2``, so the
    new-root signature of one hop is the old-root signature of the next,
    stored once. The expanded chain has ``len(additions) + 1`` hops; hop
    ``i + 1`` has ``old_total`` equal to the cumulative leaf count before
    batch ``i`` and its leaves are that prefix followed by batch ``i`` in
    order. The dataclass is frozen, positionally constructible and compared
    by value, has no field defaults, and carries no network, storage or
    hidden state. Field types and bounds are not checked at construction
    time — :func:`expand_history_delta` checks the structure and
    :func:`verify_history_delta` remains the way to verify an expanded
    chain afterwards.
    """

    first: SealHistoryExtension
    additions: tuple[tuple[bytes, ...], ...]
    signatures: tuple[AggregateSignature, ...]


def _check_history_extension_delta_chain_fields(
    chain: object,
) -> tuple[
    int,
    SealHistoryExtension,
    tuple[tuple[bytes, ...], ...],
    tuple[AggregateSignature, ...],
]:
    """Type- and structure-check a delta chain's fields, without verifying.

    ``first`` must be a :class:`SealHistoryExtension`, ``additions`` a
    tuple of non-empty tuples of 32-byte ``bytes`` digests and
    ``signatures`` a tuple of :class:`AggregateSignature` values exactly
    ``len(additions) + 2`` long; the nested proof and signatures are not
    validated here (the conversion entry points do that). Wrong field or
    element types raise TypeError; an empty batch, a digest of the wrong
    width or a signature count other than ``len(additions) + 2`` raises
    ValueError. Returns ``(batch_count, first, additions, signatures)``.
    """
    if not isinstance(chain, SealHistoryExtensionDeltaChain):
        raise TypeError(
            "chain must be a SealHistoryExtensionDeltaChain instance"
        )
    first = chain.first
    additions = chain.additions
    signatures = chain.signatures
    if not isinstance(first, SealHistoryExtension):
        raise TypeError(
            "chain.first must be a SealHistoryExtension instance"
        )
    if not isinstance(additions, tuple):
        raise TypeError("chain.additions must be a tuple")
    if not isinstance(signatures, tuple):
        raise TypeError("chain.signatures must be a tuple")
    for batch in additions:
        if not isinstance(batch, tuple):
            raise TypeError("each chain addition batch must be a tuple")
        for digest in batch:
            if not isinstance(digest, bytes):
                raise TypeError("each chain addition digest must be bytes")
    for signature in signatures:
        if not isinstance(signature, AggregateSignature):
            raise TypeError(
                "each chain signature must be an AggregateSignature instance"
            )
    try:
        batch_count = len(additions)
        signature_count = len(signatures)
    except OverflowError:
        raise ValueError("too many chain items") from None
    for batch in additions:
        if len(batch) == 0:
            raise ValueError("each chain addition batch must be non-empty")
        for digest in batch:
            if len(digest) != SEAL_HISTORY_PROOF_DIGEST_SIZE:
                raise ValueError(
                    "chain addition digests must be exactly 32 bytes"
                )
    if signature_count != batch_count + 2:
        raise ValueError(
            "chain.signatures must contain exactly len(chain.additions) + 2 "
            "signatures"
        )
    return batch_count, first, additions, signatures


def expand_history_delta(
    chain: SealHistoryExtensionDeltaChain,
) -> SealHistoryExtensionBundleChain:
    """Expand an incremental delta chain into a self-contained bundle chain.

    The first hop keeps ``chain.first`` as its extension and is bracketed by
    the first two signatures; batch ``i`` of ``chain.additions`` then
    produces hop ``i + 1`` whose ``old_total`` is the cumulative leaf count
    before the batch and whose leaves are that whole prefix followed by the
    batch's digests in their original order, so every historical leaf is
    stored once in the delta form instead of being repeated by every hop.
    The ``len(additions) + 2`` signatures are reused in their original
    order: hop ``i`` of the result is bracketed by signatures ``i`` and
    ``i + 1``. No signature is verified here — the resulting
    :class:`SealHistoryExtensionBundleChain` is checked by the existing
    :func:`verify_history_extension_bundle_chain`.

    A non-:class:`SealHistoryExtensionDeltaChain` argument or a wrong field
    or element type (non-:class:`SealHistoryExtension` ``first``, non-tuple
    fields or batches, non-``bytes`` digests, non-:class:`AggregateSignature`
    signatures) raises TypeError. An empty batch, a digest that is not
    exactly 32 bytes, a signature count other than ``len(additions) + 2``,
    an illegal nested proof or signature, or a cumulative leaf count above
    ``2**64 - 1`` raises ValueError. The function is stateless.
    """
    _batch_count, first, additions, signatures = (
        _check_history_extension_delta_chain_fields(chain)
    )
    _validate_history_extension_structure(first)
    for index, signature in enumerate(signatures):
        _check_history_proof_bundle_signature(
            signature, field=f"chain.signatures[{index}]"
        )

    bundles = [
        SealHistoryExtensionBundle(
            extension=first, old_sig=signatures[0], new_sig=signatures[1]
        )
    ]
    leaves = first.leaves
    for index, batch in enumerate(additions):
        old_total = len(leaves)
        leaves = leaves + batch
        if len(leaves) > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("too many leaves")
        extension = SealHistoryExtension(
            old_total=old_total, leaves=leaves
        )
        bundles.append(
            SealHistoryExtensionBundle(
                extension=extension,
                old_sig=signatures[index + 1],
                new_sig=signatures[index + 2],
            )
        )
    return SealHistoryExtensionBundleChain(items=tuple(bundles))


def compact_history_delta(
    chain: SealHistoryExtensionBundleChain,
) -> SealHistoryExtensionDeltaChain:
    """Compact a linking bundle chain into its incremental delta form.

    The first hop's extension is kept in full as ``first``; for every later
    hop the batch of newly appended leaves —
    ``extension.leaves[extension.old_total:]`` — is extracted in chain
    order, so the historical leaves every hop repeats are dropped and each
    leaf digest is stored exactly once. The shared checkpoint signature at
    every seam must be identical by value — the predecessor bundle's
    ``new_sig`` must equal the successor bundle's ``old_sig`` — and is
    carried exactly once, giving the ``len(items) + 1`` signatures in their
    original order. No signature is verified here — verification stays with
    :func:`verify_history_extension_bundle_chain` on the expanded form.

    A non-:class:`SealHistoryExtensionBundleChain` argument or a wrong
    field or element type raises TypeError, exactly as the structural
    checks of :func:`encode_history_extension_bundle_chain` do. An empty
    chain, an illegal nested extension or signature, a broken prefix
    between adjacent hops (the predecessor's leaves not exactly equal to
    the successor's first ``old_total`` leaves — a gap or overlap), or a
    shared checkpoint signature that differs by value raises ValueError.
    The function is stateless.
    """
    if not isinstance(chain, SealHistoryExtensionBundleChain):
        raise TypeError(
            "chain must be a SealHistoryExtensionBundleChain instance"
        )
    _check_history_extension_bundle_chain_items(chain.items)
    for index, bundle in enumerate(chain.items):
        _validate_history_extension_structure(bundle.extension)
        _check_history_proof_bundle_signature(
            bundle.old_sig, field=f"chain.items[{index}].old_sig"
        )
        _check_history_proof_bundle_signature(
            bundle.new_sig, field=f"chain.items[{index}].new_sig"
        )

    additions = []
    previous = chain.items[0]
    for bundle in chain.items[1:]:
        old_total = bundle.extension.old_total
        if (
            len(previous.extension.leaves) != old_total
            or previous.extension.leaves
            != bundle.extension.leaves[:old_total]
        ):
            raise ValueError(
                "chain bundles do not link: the predecessor's leaves must "
                "be the successor's old prefix"
            )
        if previous.new_sig != bundle.old_sig:
            raise ValueError(
                "chain bundles do not link: the shared checkpoint signature "
                "must be identical by value"
            )
        additions.append(bundle.extension.leaves[old_total:])
        previous = bundle

    signatures = (chain.items[0].old_sig,) + tuple(
        bundle.new_sig for bundle in chain.items
    )
    return SealHistoryExtensionDeltaChain(
        first=chain.items[0].extension,
        additions=tuple(additions),
        signatures=signatures,
    )


# ---------------------------------------------------------------------------
# Canonical incremental seal-history extension chain transport: a
# self-delimiting, byte-for-byte reproducible encoding of a
# SealHistoryExtensionDeltaChain for cross-implementation exchange and
# persistence. Decoding restores structure only — the nested first extension
# goes through decode_history_extension, its leaf digests stay opaque and no
# signature is checked — so verify_history_delta remains the sole verifier
# afterwards; it expands into a SealHistoryExtensionBundleChain and reuses
# verify_history_extension_bundle_chain.
# ---------------------------------------------------------------------------

SEAL_HISTORY_EXTENSION_DELTA_CHAIN_WIRE_TAG = b"ts/shed/v1"


def encode_history_delta(chain: SealHistoryExtensionDeltaChain) -> bytes:
    """Canonically encode an incremental extension chain for transport or
    persistence.

    The encoding is, in order, the tag ``b"ts/shed/v1"``, the 4-byte
    unsigned big-endian length ``len(P)`` followed by
    ``P = encode_history_extension(chain.first)`` (the existing canonical
    extension encoding, never empty), the 4-byte unsigned big-endian batch
    count ``b = len(chain.additions)`` (possibly zero), then one frame per
    addition batch in chain order — each the 4-byte unsigned big-endian
    leaf count ``m`` (always non-zero) followed by exactly ``m`` raw
    32-byte leaf digests in their original order, with no further
    separators — and finally the ``b + 2`` canonical signature frames in
    order: the first proof is bracketed by frames ``0`` and ``1`` and
    batch ``i`` is bracketed by frames ``i + 1`` and ``i + 2``. Every
    signature frame is exactly the canonical signature frame of
    :func:`encode_history_extension_bundle`: ``VARINT(R)``, ``VARINT(z)``,
    the 4-byte unsigned big-endian signer count and one ``VARINT(id)`` per
    ascending signer id.

    Only the chain container and the nested extension and signature
    structures are checked — the prefix linkage is not verified and no
    signature is checked against any root: :func:`verify_history_delta`
    stays the way to verify a chain afterwards. A non-chain argument, a
    non-tuple field or batch, or a non-``bytes`` digest raises TypeError,
    and a non-:class:`SealHistoryExtension` first extension or a
    non-:class:`AggregateSignature` signature element raises TypeError
    exactly as :func:`encode_history_extension` and
    :func:`encode_history_extension_bundle` do for their fields. An empty
    addition batch, a digest that is not exactly 32 bytes, a signature
    count other than ``b + 2``, an over-long count or frame, or an illegal
    nested extension or signature raises ValueError. The output for a
    given chain is unique and the encoding carries no network, storage or
    hidden state.
    """
    batch_count, first, additions, signatures = (
        _check_history_extension_delta_chain_fields(chain)
    )
    if batch_count > 0xFFFFFFFF:
        raise ValueError("too many chain addition batches")

    encoded_first = encode_history_extension(first)
    if len(encoded_first) > 0xFFFFFFFF:
        raise ValueError("seal history extension encoding too long")

    batch_counts = []
    for batch in additions:
        if len(batch) > 0xFFFFFFFF:
            raise ValueError("too many chain addition leaves")
        batch_counts.append(len(batch))

    signer_counts = []
    for index, signature in enumerate(signatures):
        signer_count = _check_history_proof_bundle_signature(
            signature, field=f"chain.signatures[{index}]"
        )
        if signer_count > 0xFFFFFFFF:
            raise ValueError("too many signer ids")
        signer_counts.append(signer_count)

    buffer = bytearray(SEAL_HISTORY_EXTENSION_DELTA_CHAIN_WIRE_TAG)
    buffer += len(encoded_first).to_bytes(4, "big", signed=False)
    buffer += encoded_first
    buffer += batch_count.to_bytes(4, "big", signed=False)
    for batch, leaf_count in zip(additions, batch_counts):
        buffer += leaf_count.to_bytes(4, "big", signed=False)
        for digest in batch:
            buffer += digest
    for signature, signer_count in zip(signatures, signer_counts):
        buffer += _encode_varint(signature.R)
        buffer += _encode_varint(signature.z)
        buffer += signer_count.to_bytes(4, "big", signed=False)
        for signer_id in signature.signer_ids:
            buffer += _encode_varint(signer_id)
    return bytes(buffer)


def decode_history_delta(blob: bytes) -> SealHistoryExtensionDeltaChain:
    """Decode the canonical encoding produced by :func:`encode_history_delta`.

    Accepts only the single canonical form: the tag ``b"ts/shed/v1"``, a
    4-byte unsigned big-endian non-zero length followed by bytes that
    :func:`decode_history_extension` accepts as the first hop's extension,
    the 4-byte unsigned big-endian batch count ``b`` (possibly zero), then
    exactly ``b`` addition batches, each a 4-byte unsigned big-endian
    non-zero leaf count ``m`` followed by exactly ``m`` raw 32-byte leaf
    digests, and finally exactly ``b + 2`` signature frames, each the
    length-prefixed integers ``R`` and ``z``, the 4-byte non-zero signer
    count and exactly that many strictly increasing positive signer ids.
    A non-bytes argument raises TypeError; a wrong or missing tag, a zero
    or over-long first-extension frame length, a non-canonical nested
    extension or signature integer, a zero ``m`` (an empty addition
    batch), a count mismatch, truncation, trailing bytes, or an encoding
    :func:`decode_history_extension` rejects (bad nested tag, truncated
    counts or leaves, an out-of-range ``old_total``) raises ValueError, as
    does a zero ``R``, a zero signer count or a non-positive or
    non-increasing signer id. A successfully decoded chain re-encodes to
    exactly the input bytes.

    Decoding only restores the structure: the nested first extension goes
    through :func:`decode_history_extension`, whose leaf digests stay
    opaque, no signature frame is checked and the prefix linkage between
    the first extension and the batches is not checked either. A
    structurally legal chain whose signatures do not match or whose
    batches do not link is returned normally, and
    :func:`verify_history_delta` reports it as ``False``.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not blob.startswith(SEAL_HISTORY_EXTENSION_DELTA_CHAIN_WIRE_TAG):
        raise ValueError("bad seal history extension delta chain tag")
    offset = len(SEAL_HISTORY_EXTENSION_DELTA_CHAIN_WIRE_TAG)

    encoded_first, offset = _read_audit_proof_block(
        blob, offset, what="seal history extension delta chain first proof"
    )
    first = decode_history_extension(encoded_first)

    if offset + 4 > len(blob):
        raise ValueError(
            "truncated seal history extension delta chain batch count"
        )
    batch_count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4

    additions = []
    for batch_index in range(batch_count):
        if offset + 4 > len(blob):
            raise ValueError(
                "truncated seal history extension delta chain addition "
                f"batch {batch_index + 1} leaf count"
            )
        leaf_count = int.from_bytes(blob[offset:offset + 4], "big")
        offset += 4
        if leaf_count == 0:
            raise ValueError(
                "seal history extension delta chain addition batches must "
                "be non-empty"
            )
        batch_size = leaf_count * SEAL_HISTORY_PROOF_DIGEST_SIZE
        if offset + batch_size > len(blob):
            raise ValueError(
                "truncated seal history extension delta chain addition "
                f"batch {batch_index + 1}"
            )
        batch = tuple(
            bytes(
                blob[
                    offset
                    + leaf_index * SEAL_HISTORY_PROOF_DIGEST_SIZE:
                    offset
                    + (leaf_index + 1) * SEAL_HISTORY_PROOF_DIGEST_SIZE
                ]
            )
            for leaf_index in range(leaf_count)
        )
        additions.append(batch)
        offset += batch_size

    signatures = []
    for index in range(batch_count + 2):
        signature, offset = _read_bundle_signature_frame(
            blob,
            offset,
            what=(
                "seal history extension delta chain signature "
                f"{index + 1}"
            ),
        )
        signatures.append(signature)
    if offset != len(blob):
        raise ValueError(
            "trailing bytes after seal history extension delta chain"
        )

    chain = SealHistoryExtensionDeltaChain(
        first=first,
        additions=tuple(additions),
        signatures=tuple(signatures),
    )
    if encode_history_delta(chain) != blob:
        raise ValueError(
            "non-canonical seal history extension delta chain encoding"
        )
    return chain


def verify_history_delta(
    chain: SealHistoryExtensionDeltaChain, key: SigningDKGResult
) -> bool:
    """Verify an incremental extension chain after expanding it.

    The chain is first expanded into a
    :class:`SealHistoryExtensionBundleChain` with
    :func:`expand_history_delta` — the first hop's extension kept in full
    and every addition batch appended on top of the cumulative leaves —
    and the result is checked by the existing
    :func:`verify_history_extension_bundle_chain`: every hop is verified
    with :func:`verify_history_extension_bundle` and every adjacent pair
    must link, the predecessor's leaves exactly equal to the successor's
    first ``old_total`` leaves. Returns ``True`` only when every hop
    verifies and every linkage holds; a well-formed chain with a
    mismatched root signature, tampered leaves or ``old_total``, a leaf
    prefix gap or overlap between neighbours, or one presented under
    another key returns ``False`` without raising.

    A non-:class:`SealHistoryExtensionDeltaChain` argument raises
    TypeError; a non-tuple field or batch, a non-``bytes`` digest, a
    non-:class:`AggregateSignature` signature element, an empty addition
    batch, a digest that is not exactly 32 bytes, a signature count other
    than ``len(additions) + 2``, or an illegal nested extension, signature
    or key structure raises TypeError/ValueError, exactly as the
    structural checks of :func:`encode_history_delta` and
    :func:`verify_history_extension_bundle_chain` do. The function is
    stateless.
    """
    expanded = expand_history_delta(chain)
    return verify_history_extension_bundle_chain(expanded, key)


# ---------------------------------------------------------------------------
# Continuous-interval slicing and adjacent-chain splicing of incremental
# seal-history extension chains: a long delta chain can be cut into hop
# segments for piecewise transport and archiving and the segments spliced
# back into one chain afterwards. Both entry points work on expanded bundle
# chains and compact the result back into delta form, so slicing and
# concatenation are inverses; neither verifies any signature and neither
# keeps hidden state.
# ---------------------------------------------------------------------------


def slice_history_delta(
    chain: SealHistoryExtensionDeltaChain,
    start: int,
    stop: int,
) -> SealHistoryExtensionDeltaChain:
    """Take a non-empty half-open hop segment of an incremental extension chain.

    The chain is first expanded into a self-contained
    :class:`SealHistoryExtensionBundleChain`; the segment keeps expanded
    bundles ``start:stop`` and the bracketing signatures
    ``start:stop + 1`` — hop ``i`` stays bracketed by signatures ``i`` and
    ``i + 1`` — and the segment is then compacted back into a
    :class:`SealHistoryExtensionDeltaChain`. The result is therefore
    exactly the delta form of the self-contained chain's corresponding
    interval: it expands value by value into that interval, and single-hop
    (empty ``additions``), head and tail segments all match it value by
    value. No signature is verified here and no state is kept — verification
    stays with :func:`verify_history_delta` on the result.

    A non-:class:`SealHistoryExtensionDeltaChain` chain argument or any
    wrong field or element type — a non-:class:`SealHistoryExtension`
    ``first``, non-tuple field or batch, non-``bytes`` digest,
    non-:class:`AggregateSignature` signature, or a wrong nested proof or
    signature field type — raises TypeError, exactly as
    :func:`expand_history_delta` does; a non-integer ``start`` or ``stop``
    — booleans included — also raises TypeError. A negative or otherwise
    out-of-range bound, an empty interval (``start >= stop``), an empty
    addition batch, a digest that is not exactly 32 bytes, a signature count
    other than ``len(additions) + 2``, or an illegal nested proof or
    signature raises ValueError. The function is stateless.
    """
    start = _check_segment_bound(start, "start")
    stop = _check_segment_bound(stop, "stop")
    expanded = expand_history_delta(chain)
    hop_count = len(expanded.items)
    if start < 0 or stop < 0 or start > hop_count or stop > hop_count:
        raise ValueError("slice bounds out of range")
    if start >= stop:
        raise ValueError("slice interval must be non-empty")
    segment = SealHistoryExtensionBundleChain(
        items=expanded.items[start:stop]
    )
    return compact_history_delta(segment)


def concatenate_history_delta(
    left: SealHistoryExtensionDeltaChain,
    right: SealHistoryExtensionDeltaChain,
) -> SealHistoryExtensionDeltaChain:
    """Concatenate two adjacent incremental extension chains into one chain.

    Both chains are first expanded into self-contained
    :class:`SealHistoryExtensionBundleChain` values; the bundles are joined
    left then right and the checkpoint signature at the seam is kept
    exactly once — the left chain's last new-root signature and the right
    chain's first old-root signature must be the very same value. The left
    chain's last hop must additionally end on the exact tree the right
    chain's first hop starts from: the left hop's ``extension.leaves``
    must equal the first ``old_total`` leaves of the right hop, with the
    leaf counts fitting exactly — a gap or overlap is rejected. The joined
    self-contained chain is then compacted back into a
    :class:`SealHistoryExtensionDeltaChain`, so the result is the delta
    form of the two expanded chains joined in order and round-trips through
    the canonical encoding byte for byte. No signature is verified here and
    no state is kept — verification stays with :func:`verify_history_delta`
    on the result.

    A non-:class:`SealHistoryExtensionDeltaChain` argument or any wrong
    field or element type — including a wrong nested proof or signature
    field type — raises TypeError, exactly as :func:`expand_history_delta`
    does. A leaf prefix mismatch at the seam (a gap or overlap between the
    last left hop and the first right hop) or a mismatch between the two
    shared checkpoint signatures by value raises ValueError, as does any
    structural error either chain or its nested extension or signatures
    would raise on its own. The function is stateless.
    """
    left_expanded = expand_history_delta(left)
    right_expanded = expand_history_delta(right)

    left_last = left_expanded.items[-1].extension
    right_first = right_expanded.items[0].extension
    old_total = right_first.old_total
    if (
        len(left_last.leaves) != old_total
        or left_last.leaves != right_first.leaves[:old_total]
    ):
        raise ValueError(
            "chains do not link: the left chain's last leaves must be the "
            "right chain's first hop old prefix"
        )
    if left_expanded.items[-1].new_sig != right_expanded.items[0].old_sig:
        raise ValueError(
            "chains do not link: the shared checkpoint signature must be "
            "identical by value"
        )

    joined = SealHistoryExtensionBundleChain(
        items=left_expanded.items + right_expanded.items
    )
    result = compact_history_delta(joined)

    # Defence in depth: the returned delta chain must expand back into
    # exactly the two expanded chains joined in order, and its canonical
    # encoding must round-trip byte for byte; refuse anything else.
    reexpanded = expand_history_delta(result)
    if reexpanded != joined:
        raise ValueError("concatenated chain does not match the joined chains")
    encoded = encode_history_delta(result)
    if decode_history_delta(encoded) != result:
        raise ValueError("concatenated chain does not encode byte for byte")
    return result


# ---------------------------------------------------------------------------
# Multi-cut batch partitioning and reassembly of incremental seal-history
# extension chains: a long delta chain is split into consecutive hop
# segments at once, or an ordered tuple of segments is folded back into one
# chain, on top of the interval slice and the adjacent-chain splice. Both
# entry points are pure structural transforms: no signature is verified and
# no state is kept — verification stays with verify_history_delta.
# ---------------------------------------------------------------------------


def partition_history_delta(
    chain: SealHistoryExtensionDeltaChain,
    cuts: tuple[int, ...],
) -> tuple[SealHistoryExtensionDeltaChain, ...]:
    """Split an incremental extension chain into consecutive hop segments.

    ``cuts`` is a tuple of boundary indices into the expanded chain's
    hop sequence: cut ``c`` ends one segment just before expanded hop
    ``c`` and starts the next segment at it, exactly as repeated
    :func:`slice_history_delta` calls over the intervals
    ``[0, cuts[0])``, ``[cuts[0], cuts[1])``, ...,
    ``[cuts[-1], len(hops))`` would. The cuts must be strictly
    increasing (hence unique) and each must lie in
    ``1..len(hops) - 1``, so every segment is non-empty; an empty
    ``cuts`` tuple returns the whole chain as the single segment. The
    segments are returned in chain order as a tuple of
    :class:`SealHistoryExtensionDeltaChain` values, each the delta form
    of its expanded interval. No signature is verified here and no
    state is kept — verification stays with :func:`verify_history_delta`
    on each segment, and :func:`join_history_delta_segments` folds the
    segments back into the original chain.

    A non-:class:`SealHistoryExtensionDeltaChain` chain argument or any
    wrong field or element type raises TypeError, exactly as
    :func:`expand_history_delta` does; a non-tuple ``cuts`` or a
    non-integer cut — booleans included — also raises TypeError. A
    repeated, non-increasing or out-of-range cut raises ValueError, as
    does any structural error the expanded chain or its nested extension
    or signatures would raise on their own.
    """
    expanded = expand_history_delta(chain)
    if not isinstance(cuts, tuple):
        raise TypeError("cuts must be a tuple")
    hop_count = len(expanded.items)
    previous = 0
    for cut in cuts:
        _check_segment_bound(cut, "each cut")
        if cut < 1 or cut > hop_count - 1:
            raise ValueError("each cut must lie in 1..len(hops) - 1")
        if cut <= previous:
            raise ValueError("cuts must be strictly increasing and unique")
        previous = cut

    bounds = (0,) + cuts + (hop_count,)
    segments = []
    for index in range(len(bounds) - 1):
        start = bounds[index]
        stop = bounds[index + 1]
        if start >= stop:
            raise ValueError("partition segments must be non-empty")
        segment = SealHistoryExtensionBundleChain(
            items=expanded.items[start:stop]
        )
        segments.append(compact_history_delta(segment))
    return tuple(segments)


def join_history_delta_segments(
    segments: tuple[SealHistoryExtensionDeltaChain, ...],
) -> SealHistoryExtensionDeltaChain:
    """Fold an ordered tuple of incremental extension chain segments into one.

    ``segments`` must be a non-empty tuple of
    :class:`SealHistoryExtensionDeltaChain` values in chain order; they
    are joined left to right by repeated
    :func:`concatenate_history_delta` calls, so each seam must satisfy
    the same two link conditions as that pairwise splice: the left
    segment's last expanded hop's ``extension.leaves`` must equal the
    first ``old_total`` leaves of the right segment's first expanded hop
    (a gap or overlap is rejected), and the two shared checkpoint
    signatures at the seam must be identical by value. A single segment
    is returned as the chain itself. In particular, joining the tuple
    produced by :func:`partition_history_delta` for any legal cuts
    restores the original chain value by value, and its canonical
    encoding matches the original byte for byte. No signature is
    verified here and no state is kept — verification stays with
    :func:`verify_history_delta` on the result.

    A non-tuple ``segments`` argument or a
    non-:class:`SealHistoryExtensionDeltaChain` element raises
    TypeError, as does any wrong field or element type inside a segment,
    exactly as :func:`expand_history_delta` does. An empty ``segments``
    tuple raises ValueError, as does any leaf prefix or shared signature
    mismatch at a seam and any structural error a segment or its nested
    extension or signatures would raise on its own.
    """
    if not isinstance(segments, tuple):
        raise TypeError("segments must be a tuple")
    for segment in segments:
        if not isinstance(segment, SealHistoryExtensionDeltaChain):
            raise TypeError(
                "each segment must be a SealHistoryExtensionDeltaChain "
                "instance"
            )
    if len(segments) == 0:
        raise ValueError("segments must be a non-empty tuple")
    for segment in segments:
        _check_history_extension_delta_chain_fields(segment)

    joined = segments[0]
    for segment in segments[1:]:
        joined = concatenate_history_delta(joined, segment)
    return joined


# ---------------------------------------------------------------------------
# Canonical seal-history delta-chain segment-set transport: a
# self-delimiting envelope around one or more whole
# SealHistoryExtensionDeltaChain frames so that several consecutive segments
# can be archived or cross-implementation transferred as a single object.
# Like the single-chain codec this restores structure only — no signature is
# checked, seams are not inspected and no state is kept — and
# join_history_delta_segments remains the sole place that judges order
# continuity and the seams between neighbours.
# ---------------------------------------------------------------------------

HISTORY_DELTA_SEGMENTS_WIRE_TAG = (
    b"thresholdsign/history-delta-segments/v1"
)


def encode_history_delta_segments(
    segments: tuple[SealHistoryExtensionDeltaChain, ...],
) -> bytes:
    """Canonically encode a non-empty ordered tuple of incremental
    extension chain segments as one self-delimiting object.

    The encoding is, in order, the tag
    ``b"thresholdsign/history-delta-segments/v1"``, the 4-byte unsigned
    big-endian segment count (never zero), then one frame per segment in
    tuple order — each the 4-byte unsigned big-endian byte length
    followed by the exact bytes of :func:`encode_history_delta` for that
    segment (never empty), with no further separators.

    Only the tuple container and the structural legality of each
    segment (via its own canonical encoder) are checked — the segments
    are not sorted, no seam between neighbours is inspected and no
    signature is checked: :func:`join_history_delta_segments` stays the
    way to judge order continuity and the seams, and
    :func:`verify_history_delta` the way to verify the joined result
    afterwards. A non-tuple ``segments`` argument or a
    non-:class:`SealHistoryExtensionDeltaChain` element raises
    TypeError, as does any wrong field or element type inside a segment,
    exactly as :func:`encode_history_delta` does. An empty tuple, an
    over-long count or frame, or any structural error a segment or its
    nested extension or signatures would raise on its own raises
    ValueError. The output for a given tuple is unique and the encoding
    carries no network, storage or hidden state.
    """
    if not isinstance(segments, tuple):
        raise TypeError("segments must be a tuple")
    for segment in segments:
        if not isinstance(segment, SealHistoryExtensionDeltaChain):
            raise TypeError(
                "each segment must be a SealHistoryExtensionDeltaChain "
                "instance"
            )
    segment_count = len(segments)
    if segment_count == 0:
        raise ValueError("segments must be a non-empty tuple")
    if segment_count > 0xFFFFFFFF:
        raise ValueError("too many seal history delta chain segments")

    frames = []
    for index, segment in enumerate(segments):
        frame = encode_history_delta(segment)
        if len(frame) > 0xFFFFFFFF:
            raise ValueError(
                f"seal history delta chain segment {index + 1} too long"
            )
        frames.append(frame)

    buffer = bytearray(HISTORY_DELTA_SEGMENTS_WIRE_TAG)
    buffer += segment_count.to_bytes(4, "big", signed=False)
    for frame in frames:
        buffer += len(frame).to_bytes(4, "big", signed=False)
        buffer += frame
    return bytes(buffer)


def decode_history_delta_segments(
    blob: bytes,
) -> tuple[SealHistoryExtensionDeltaChain, ...]:
    """Decode the canonical segment set produced by
    :func:`encode_history_delta_segments`.

    Accepts only the single canonical form: the tag
    ``b"thresholdsign/history-delta-segments/v1"``, a 4-byte unsigned
    big-endian non-zero segment count, then exactly that many frames,
    each a 4-byte unsigned big-endian non-zero byte length followed by
    the exact canonical encoding of one
    :class:`SealHistoryExtensionDeltaChain` accepted by
    :func:`decode_history_delta`. The segments are restored in their
    original order as a tuple; they are not sorted, no seam between
    neighbours is checked and no signature is verified —
    :func:`join_history_delta_segments` judges order and seams
    afterwards. A non-bytes argument raises TypeError; a wrong or
    missing tag, a zero segment count, a zero or over-long frame length,
    a count mismatch, truncation, trailing bytes, or a frame whose
    nested chain encoding is illegal or non-canonical (including a
    frame that would not re-encode byte for byte) raises ValueError. A
    successfully decoded tuple re-encodes to exactly the input bytes.

    Decoding only restores structure: a set of individually legal but
    mutually incompatible segments is returned normally, and
    :func:`join_history_delta_segments` reports the mismatch.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not blob.startswith(HISTORY_DELTA_SEGMENTS_WIRE_TAG):
        raise ValueError("bad seal history delta chain segments tag")
    offset = len(HISTORY_DELTA_SEGMENTS_WIRE_TAG)

    if offset + 4 > len(blob):
        raise ValueError("truncated seal history delta chain segments count")
    segment_count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    if segment_count == 0:
        raise ValueError("seal history delta chain segments must be non-empty")

    segments = []
    for index in range(segment_count):
        frame, offset = _read_audit_proof_block(
            blob,
            offset,
            what=f"seal history delta chain segment {index + 1}",
        )
        segments.append(decode_history_delta(frame))
    if offset != len(blob):
        raise ValueError(
            "trailing bytes after seal history delta chain segments"
        )

    segments_tuple = tuple(segments)
    if encode_history_delta_segments(segments_tuple) != blob:
        raise ValueError(
            "non-canonical seal history delta chain segments encoding"
        )
    return segments_tuple


# ---------------------------------------------------------------------------
# Sealed segment-set archives: one threshold Schnorr signature over the
# canonical segment-set encoding produced by encode_history_delta_segments.
# The signed message commits to the verifying public key and to the digest of
# the exact segment-set bytes, so deleting, inserting, reordering or
# substituting a segment — or presenting the archive under another key —
# all invalidate the signature. The seal keeps no state: the segments are
# only structure-checked here and the seam/order judgement stays with
# join_history_delta_segments, exactly as for the unsigned segment set.
# ---------------------------------------------------------------------------

HDS_MESSAGE_TAG = b"ts/hds/m1"
HDS_WIRE_TAG = b"ts/hds/w1"


@dataclass(frozen=True)
class HistoryDeltaSegmentsSeal:
    """A whole segment-set archive sealed by one threshold signature.

    The fields, in order, are ``segments`` — a non-empty, order-preserving
    tuple of :class:`SealHistoryExtensionDeltaChain` values, each a
    structurally legal incremental append chain — and ``signature`` — the
    threshold Schnorr :class:`AggregateSignature` on :func:`hds_message` of
    the segments and the verifying public key. The dataclass is frozen,
    positionally constructible and compared by value; the segments keep
    their order and the seal carries no network, storage or hidden state.
    Neither field is checked at construction time — :func:`encode_hds`
    checks the structure and :func:`verify_hds` is the way to test a seal
    afterwards. Segment order and the seams between neighbours are not
    judged here: :func:`join_history_delta_segments` remains the sole place
    that does that.
    """

    segments: tuple[SealHistoryExtensionDeltaChain, ...]
    signature: AggregateSignature


def _check_history_delta_segments(
    segments: object,
) -> tuple[SealHistoryExtensionDeltaChain, ...]:
    """Type- and structure-check a non-empty ordered segment tuple.

    Mirrors the container and per-segment checks of
    :func:`encode_history_delta_segments`: a tuple of
    :class:`SealHistoryExtensionDeltaChain` instances, non-empty, each
    structurally legal through its own canonical encoder. Nothing here
    inspects the seams or verifies a signature.
    """
    if not isinstance(segments, tuple):
        raise TypeError("segments must be a tuple")
    for segment in segments:
        if not isinstance(segment, SealHistoryExtensionDeltaChain):
            raise TypeError(
                "each segment must be a SealHistoryExtensionDeltaChain "
                "instance"
            )
    if len(segments) == 0:
        raise ValueError("segments must be a non-empty tuple")
    if len(segments) > 0xFFFFFFFF:
        raise ValueError("too many seal history delta chain segments")
    for index, segment in enumerate(segments):
        frame = encode_history_delta(segment)
        if len(frame) > 0xFFFFFFFF:
            raise ValueError(
                f"seal history delta chain segment {index + 1} too long"
            )
    return segments


def hds_message(
    segments: tuple[SealHistoryExtensionDeltaChain, ...], public_key: int
) -> bytes:
    """Encode the canonical message the threshold key signs to seal a segment set.

    The message is, in order, the tag ``b"ts/hds/m1"``, the 32-byte
    ``SHA256`` digest of the canonical
    :func:`encode_history_delta_segments` output ``E`` for ``segments``,
    and ``VARINT(public_key)`` — a 4-byte unsigned big-endian length
    followed by the shortest unsigned big-endian value (zero is the single
    byte ``00``, positive values carry no leading zero). It carries no
    signature and keeps no state.

    ``segments`` must be a non-empty tuple of structurally legal
    :class:`SealHistoryExtensionDeltaChain` values exactly as
    :func:`encode_history_delta_segments` requires and ``public_key`` a
    non-boolean non-negative integer. Wrong element or field types raise
    TypeError; an empty segment tuple, an illegal segment, a negative or
    boolean public key, or an over-long key encoding raises ValueError.
    """
    _check_history_delta_segments(segments)
    if not isinstance(public_key, int) or isinstance(public_key, bool):
        raise TypeError("public_key must be an integer")
    encoded_segments = encode_history_delta_segments(segments)
    encoded_key = _encode_varint(public_key)
    return (
        HDS_MESSAGE_TAG
        + hashlib.sha256(encoded_segments).digest()
        + encoded_key
    )


def _check_hds_fields(
    seal: object,
) -> tuple[tuple[SealHistoryExtensionDeltaChain, ...], AggregateSignature]:
    """Type- and structure-check a HistoryDeltaSegmentsSeal value."""
    if not isinstance(seal, HistoryDeltaSegmentsSeal):
        raise TypeError(
            "seal must be a HistoryDeltaSegmentsSeal instance"
        )
    segments = _check_history_delta_segments(seal.segments)
    signer_count = _check_history_proof_bundle_signature(seal.signature)
    if signer_count > 0xFFFFFFFF:
        raise ValueError("too many signer ids")
    return segments, seal.signature


def encode_hds(seal: HistoryDeltaSegmentsSeal) -> bytes:
    """Canonically encode a sealed segment-set archive for transport or persistence.

    The encoding is, in order, the tag ``b"ts/hds/w1"``, the 4-byte
    unsigned big-endian length ``len(E)`` followed by the raw segment-set
    encoding ``E = encode_history_delta_segments(seal.segments)`` (never
    empty), and then the same signature frame an
    :class:`AuditProofBundle` carries: ``VARINT(R)``, ``VARINT(z)``, the
    4-byte unsigned big-endian signer count ``k`` and one
    ``VARINT(id)`` per ascending signer id. A ``VARINT`` is a 4-byte
    unsigned big-endian body length followed by the shortest unsigned
    big-endian value (zero is the single byte ``00``, positive values
    carry no leading zero); ``R`` must be positive and ``z`` may be zero.

    Only a structurally legal :class:`HistoryDeltaSegmentsSeal` is
    accepted: the segments must be a non-empty tuple encodable by
    :func:`encode_history_delta_segments` (each segment by
    :func:`encode_history_delta`) and the signature an
    :class:`AggregateSignature` with a positive ``R``, a non-negative
    ``z`` and a non-empty tuple of strictly increasing positive ids. The
    segments are not sorted, no seam is inspected and the signature is
    not checked: :func:`join_history_delta_segments` stays the way to
    judge order and seams and :func:`verify_hds` the way to verify the
    seal afterwards. The output for a given seal is unique and the
    encoding carries no network, storage or hidden state. Wrong field
    types raise TypeError; an empty segment tuple, an illegal nested
    segment or signature structure, or an over-long frame raises
    ValueError.
    """
    segments, signature = _check_hds_fields(seal)
    encoded_segments = encode_history_delta_segments(segments)
    if len(encoded_segments) > 0xFFFFFFFF:
        raise ValueError("seal history delta chain segments encoding too long")

    buffer = bytearray(HDS_WIRE_TAG)
    buffer += len(encoded_segments).to_bytes(4, "big", signed=False)
    buffer += encoded_segments
    buffer += _encode_varint(signature.R)
    buffer += _encode_varint(signature.z)
    buffer += len(signature.signer_ids).to_bytes(4, "big", signed=False)
    for signer_id in signature.signer_ids:
        buffer += _encode_varint(signer_id)
    return bytes(buffer)


def decode_hds(blob: bytes) -> HistoryDeltaSegmentsSeal:
    """Decode the canonical encoding produced by :func:`encode_hds`.

    Accepts only the single canonical form: the tag ``b"ts/hds/w1"``, a
    4-byte non-zero segment-set frame length followed by bytes that
    :func:`decode_history_delta_segments` accepts, the length-prefixed
    integers ``R`` and ``z``, the 4-byte non-zero signer count ``k`` and
    then exactly ``k`` strictly increasing positive signer ids — the
    exact signature frame layout an :class:`AuditProofBundle` uses. A
    non-bytes argument raises TypeError; a wrong or missing tag, a zero
    or over-long segment-set frame length, a declared segment count that
    does not match its frames, a non-canonical nested segment-set (or
    nested chain) encoding, a zero ``R``, a negative value, a zero or
    mismatched signer count, an illegal signature structure, a
    non-canonical integer (leading zero or over-long length),
    truncation, or trailing bytes raises ValueError. A successfully
    decoded seal re-encodes to exactly the input bytes.

    Decoding only restores the structure: the nested segment set is
    decoded with :func:`decode_history_delta_segments` (which verifies no
    signature and checks no seam) and the seal signature is not checked.
    A structurally legal seal whose segments do not join, whose
    signatures do not verify, or whose seal signature does not bind them
    is returned normally, and :func:`verify_hds` reports it as ``False``.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not blob.startswith(HDS_WIRE_TAG):
        raise ValueError("bad history delta segments seal tag")
    offset = len(HDS_WIRE_TAG)

    encoded_segments, offset = _read_audit_proof_block(
        blob, offset, what="sealed history delta chain segments"
    )
    segments = decode_history_delta_segments(encoded_segments)

    signature, offset = _read_bundle_signature_frame(
        blob, offset, what="history delta segments seal"
    )
    if offset != len(blob):
        raise ValueError("trailing bytes after history delta segments seal")

    seal = HistoryDeltaSegmentsSeal(
        segments=segments,
        signature=signature,
    )
    if encode_hds(seal) != blob:
        raise ValueError("non-canonical history delta segments seal encoding")
    return seal


def verify_hds(seal: HistoryDeltaSegmentsSeal, key: SigningDKGResult) -> bool:
    """Verify a sealed segment-set archive against its segments and the threshold key.

    ``seal`` must be a structurally legal
    :class:`HistoryDeltaSegmentsSeal` — its segments a non-empty tuple
    encodable by :func:`encode_history_delta_segments` and its signature
    an :class:`AggregateSignature` with a positive ``R``, a non-negative
    ``z`` and a non-empty tuple of strictly increasing positive ids — and
    ``key`` a legal :class:`SigningDKGResult`. Wrong field types raise
    TypeError; an empty segment tuple, an illegal segment, signature or
    key structure raises ValueError.

    The canonical :func:`hds_message` of the segments and
    ``key.public_key`` is recomputed and checked as the signature's
    threshold Schnorr message via :func:`verify_signature` with the key's
    group parameters. Returns ``True`` only when the signature verifies
    over exactly the sealed segments and key: a well-formed seal whose
    segments are deleted from, inserted into, substituted or reordered,
    whose signature was tampered with, or which is checked under another
    key returns ``False`` without raising. The segments' own root
    signatures and the seams between segments are not re-judged here;
    :func:`verify_history_delta` and
    :func:`join_history_delta_segments` stay the entries for those
    checks. The function is stateless.
    """
    segments, signature = _check_hds_fields(seal)
    _result, public_key, field_prime, group_prime, generator = _check_signing_setup(key)
    _check_signing_dkg_structure(key)

    message = hds_message(segments, public_key)
    return verify_signature(
        message,
        signature,
        public_key,
        group_prime=group_prime,
        generator=generator,
        prime=field_prime,
    )


    message = hdsc_message(seals, public_key)
    return verify_signature(
        message,
        signature,
        public_key,
        group_prime=group_prime,
        generator=generator,
        prime=field_prime,
    )


# ---------------------------------------------------------------------------
# Chains of sealed segment sets: a non-empty, order-preserving batch of whole
# HistoryDeltaSegmentsSeal values authenticated by one more threshold
# Schnorr signature. The outer signature binds the digest of a canonical
# framing C over the existing per-seal transport encodings and the verifying
# public key, so deleting, inserting, reordering or substituting a seal — or
# presenting the chain under another key — invalidates it. The chain carries
# no state of its own: every seal (and, through it, its segment set) is
# re-checked on verification before the outer signature is examined.
# ---------------------------------------------------------------------------

HDSC_MESSAGE_TAG = b"ts/hdsc/m1"
HDSC_WIRE_TAG = b"ts/hdsc/w1"


@dataclass(frozen=True)
class HistoryDeltaSegmentsSealChain:
    """A non-empty ordered chain of sealed segment sets with one outer signature.

    The fields, in order, are ``seals`` — a non-empty tuple of
    :class:`HistoryDeltaSegmentsSeal` values in chain order — and
    ``signature`` — the threshold Schnorr :class:`AggregateSignature` on
    :func:`hdsc_message` of the seals and the verifying public key. The
    dataclass is frozen, positionally constructible and compared by
    value; the seals keep their order and the chain carries no network,
    storage or hidden state. Neither field is checked at construction
    time — :func:`hdsc_message` requires structurally legal seals and
    :func:`verify_hdsc` is the way to test a chain against a key
    afterwards. Each seal's own segment order and the seams between its
    neighbours are not judged here: :func:`join_history_delta_segments`
    remains the sole place that does that.
    """

    seals: tuple[HistoryDeltaSegmentsSeal, ...]
    signature: AggregateSignature


def _check_hdsc_seals(
    seals: object,
) -> tuple[HistoryDeltaSegmentsSeal, ...]:
    """Type- and structure-check a non-empty ordered tuple of segment-set seals.

    Mirrors the container and per-seal checks of :func:`encode_hdsc`: a
    tuple of :class:`HistoryDeltaSegmentsSeal` instances, non-empty, each
    structurally legal through its own canonical encoder. Nothing here
    verifies a signature or judges a seam.
    """
    if not isinstance(seals, tuple):
        raise TypeError("seals must be a tuple")
    for seal in seals:
        if not isinstance(seal, HistoryDeltaSegmentsSeal):
            raise TypeError(
                "each seal must be a HistoryDeltaSegmentsSeal instance"
            )
    if len(seals) == 0:
        raise ValueError("seals must be a non-empty tuple")
    if len(seals) > 0xFFFFFFFF:
        raise ValueError(
            "too many history delta segments seal chain seals"
        )
    for index, seal in enumerate(seals):
        encoded = encode_hds(seal)
        if len(encoded) > 0xFFFFFFFF:
            raise ValueError(
                f"history delta segments seal chain seal {index + 1} "
                "encoding too long"
            )
    return seals


def hdsc_message(
    seals: tuple[HistoryDeltaSegmentsSeal, ...], public_key: int
) -> bytes:
    """Encode the canonical message the threshold key signs for a seal chain.

    The message is, in order, the tag ``b"ts/hdsc/m1"``, the 32-byte
    ``SHA256`` digest of the canonical framing ``C`` and
    ``VARINT(public_key)`` — a 4-byte unsigned big-endian length followed
    by the shortest unsigned big-endian value (zero is the single byte
    ``00``, positive values carry no leading zero). ``C`` is, in order,
    the 4-byte unsigned big-endian seal count followed by, for every
    seal in tuple order, the 4-byte unsigned big-endian byte length and
    the exact bytes ``E`` of :func:`encode_hds` for that seal; every
    count is a 4-byte unsigned big-endian integer and ``E`` is the
    existing canonical single-seal encoding (its own tag, sealed
    segment-set frame and signature frame). The message carries no
    signature and keeps no state.

    ``seals`` must be a non-empty tuple of structurally legal
    :class:`HistoryDeltaSegmentsSeal` values exactly as
    :func:`encode_hds` requires and ``public_key`` a non-boolean
    non-negative integer. Wrong element or field types raise TypeError;
    an empty seals tuple, an illegal nested seal, a negative or boolean
    public key, or an over-long key encoding raises ValueError.
    """
    seals = _check_hdsc_seals(seals)
    if not isinstance(public_key, int) or isinstance(public_key, bool):
        raise TypeError("public_key must be an integer")
    if public_key < 0:
        raise ValueError("public_key must be non-negative")

    framing = bytearray(len(seals).to_bytes(4, "big", signed=False))
    for seal in seals:
        encoded = encode_hds(seal)
        framing += len(encoded).to_bytes(4, "big", signed=False)
        framing += encoded
    return (
        HDSC_MESSAGE_TAG
        + hashlib.sha256(bytes(framing)).digest()
        + _encode_varint(public_key)
    )


def _check_hdsc_fields(
    chain: object,
) -> tuple[tuple[HistoryDeltaSegmentsSeal, ...], AggregateSignature]:
    """Type- and structure-check a HistoryDeltaSegmentsSealChain value."""
    if not isinstance(chain, HistoryDeltaSegmentsSealChain):
        raise TypeError(
            "chain must be a HistoryDeltaSegmentsSealChain instance"
        )
    seals = _check_hdsc_seals(chain.seals)
    signer_count = _check_history_proof_bundle_signature(chain.signature)
    if signer_count > 0xFFFFFFFF:
        raise ValueError("too many signer ids")
    return seals, chain.signature


def encode_hdsc(chain: HistoryDeltaSegmentsSealChain) -> bytes:
    """Canonically encode a chain of sealed segment sets for transport or persistence.

    The encoding is, in order, the tag ``b"ts/hdsc/w1"``, the seal count
    ``n = len(chain.seals)`` as a 4-byte unsigned big-endian integer,
    then one frame per seal strictly in chain order: the 4-byte unsigned
    big-endian length ``len(E)`` followed by ``E = encode_hds(seal)``,
    the existing canonical single-seal encoding (never empty), and
    finally one outer signature frame, exactly the signature frame an
    :class:`AuditProofBundle` carries: ``VARINT(R)``, ``VARINT(z)``, the
    4-byte unsigned big-endian signer count ``k`` and one
    ``VARINT(id)`` per ascending signer id. A ``VARINT`` is a 4-byte
    unsigned big-endian body length followed by the shortest unsigned
    big-endian value (zero is the single byte ``00``, positive values
    carry no leading zero); ``R`` must be positive and ``z`` may be
    zero.

    Only a structurally legal :class:`HistoryDeltaSegmentsSealChain` is
    accepted: the seals must be a non-empty tuple each encodable by
    :func:`encode_hds` and the outer signature an
    :class:`AggregateSignature` with a positive ``R``, a non-negative
    ``z`` and a non-empty tuple of strictly increasing positive ids.
    The seals are not sorted, no seam is inspected and neither the
    outer signature nor any nested seal signature is checked:
    :func:`join_history_delta_segments` stays the way to judge order
    and seams and :func:`verify_hdsc` the way to verify the chain
    afterwards. The output for a given chain is unique and the
    encoding carries no network, storage or hidden state. Wrong field
    types raise TypeError; an empty chain, an illegal nested seal, an
    illegal outer signature, or an over-long count or frame raises
    ValueError.
    """
    seals, signature = _check_hdsc_fields(chain)

    buffer = bytearray(HDSC_WIRE_TAG)
    buffer += len(seals).to_bytes(4, "big", signed=False)
    for seal in seals:
        encoded = encode_hds(seal)
        buffer += len(encoded).to_bytes(4, "big", signed=False)
        buffer += encoded
    buffer += _encode_varint(signature.R)
    buffer += _encode_varint(signature.z)
    buffer += len(signature.signer_ids).to_bytes(4, "big", signed=False)
    for signer_id in signature.signer_ids:
        buffer += _encode_varint(signer_id)
    return bytes(buffer)


def decode_hdsc(blob: bytes) -> HistoryDeltaSegmentsSealChain:
    """Decode the canonical encoding produced by :func:`encode_hdsc`.

    Accepts only the single canonical form: the tag ``b"ts/hdsc/w1"``,
    the 4-byte unsigned big-endian non-zero seal count ``n``, then
    exactly ``n`` seal frames in order — each a 4-byte unsigned
    big-endian non-zero length followed by bytes that
    :func:`decode_hds` accepts — and finally one outer signature
    frame, the length-prefixed integers ``R`` and ``z``, the 4-byte
    non-zero signer count ``k`` and exactly ``k`` strictly increasing
    positive signer ids, the exact signature frame layout an
    :class:`AuditProofBundle` uses. A non-bytes argument raises
    TypeError; a wrong or missing tag, an empty chain, a zero-length
    or over-long seal frame, a count that does not match the number
    of frames, a non-canonical nested seal (or one whose nested
    segment set is non-canonical), a zero ``R``, a non-canonical
    integer (leading zero or over-long length), a zero signer count,
    a non-positive or non-increasing signer id, an illegal signature
    structure, truncation, or trailing bytes raises ValueError. A
    successfully decoded chain re-encodes to exactly the input bytes.

    Decoding only restores the structure: every nested seal goes
    through :func:`decode_hds` (which verifies no signature and
    checks no seam) and the outer signature is not checked. A
    structurally legal chain whose nested seals or outer signature do
    not match is returned normally, and :func:`verify_hdsc` reports it
    as ``False``.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not blob.startswith(HDSC_WIRE_TAG):
        raise ValueError("bad history delta segments seal chain tag")
    offset = len(HDSC_WIRE_TAG)

    if offset + 4 > len(blob):
        raise ValueError(
            "truncated history delta segments seal chain seal count"
        )
    count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    if count == 0:
        raise ValueError(
            "history delta segments seal chain must be non-empty"
        )

    seals = []
    for index in range(count):
        encoded_seal, offset = _read_audit_proof_block(
            blob,
            offset,
            what=f"history delta segments seal chain seal {index + 1}",
        )
        seals.append(decode_hds(encoded_seal))

    signature, offset = _read_bundle_signature_frame(
        blob,
        offset,
        what="history delta segments seal chain outer signature",
    )
    if offset != len(blob):
        raise ValueError(
            "trailing bytes after history delta segments seal chain"
        )

    chain = HistoryDeltaSegmentsSealChain(
        seals=tuple(seals), signature=signature
    )
    if encode_hdsc(chain) != blob:
        raise ValueError(
            "non-canonical history delta segments seal chain encoding"
        )
    return chain


def verify_hdsc(
    chain: HistoryDeltaSegmentsSealChain, key: SigningDKGResult
) -> bool:
    """Verify a chain of sealed segment sets against its seals and the threshold key.

    ``chain`` must be a structurally legal
    :class:`HistoryDeltaSegmentsSealChain` — its seals a non-empty
    tuple each encodable by :func:`encode_hds` and its signature an
    :class:`AggregateSignature` with a positive ``R``, a non-negative
    ``z`` and a non-empty tuple of strictly increasing positive ids —
    and ``key`` a legal :class:`SigningDKGResult`. Wrong field types
    raise TypeError; an empty seals tuple, an illegal seal, signature
    or key structure raises ValueError.

    Every seal is first passed to :func:`verify_hds` in chain order,
    so its sealed segment set and its own seal signature must all
    verify under ``key``; the canonical :func:`hdsc_message` of the
    seals and ``key.public_key`` is then checked as the outer
    signature's threshold Schnorr message via
    :func:`verify_signature` with the key's group parameters. Returns
    ``True`` only when every per-seal check and the outer signature
    check pass; a structurally legal chain whose nested seal or outer
    signature does not match — including deleting, inserting,
    reordering or substituting a seal, tampering with the outer
    signature, or presenting the chain under another key — returns
    ``False`` rather than raising. The segments' seams between seals
    are not re-judged here; :func:`join_history_delta_segments`
    stays the entry for that check. The function is stateless.
    """
    seals, signature = _check_hdsc_fields(chain)
    _result, public_key, field_prime, group_prime, generator = _check_signing_setup(key)
    _check_signing_dkg_structure(key)

    if not all(verify_hds(seal, key) for seal in seals):
        return False
    message = hdsc_message(seals, public_key)
    return verify_signature(
        message,
        signature,
        public_key,
        group_prime=group_prime,
        generator=generator,
        prime=field_prime,
    )


# ---------------------------------------------------------------------------
# Compact multi-seal membership proofs for chains of sealed segment sets: one
# threshold signature on a Merkle root statement lets a third party confirm
# that several HistoryDeltaSegmentsSeal values each sit at a fixed position
# in the exact seal chain without fetching the chain itself. The tree is
# isomorphic to the existing seal-history membership proofs — SHA256 over
# domain-separated leaf/node prefixes with the odd tail of every level
# paired with itself — but the leaves bind each position to the existing
# canonical whole-seal encoding encode_hds and the signed root statement is
# b"ts/hdscp/r1" || U64(total) || root. The compact walk sends each
# companion digest at most once, level by level left to right, omitting
# companions that are themselves disclosed and odd tails, so the sibling
# count and order are derived from the total and the indices alone. No state
# is kept and check_hdsc_proof rebuilds the root from the disclosed seals
# and siblings, then re-runs verify_hds on every disclosed seal and
# verify_signature on the root signature, so a proof certifies both the
# memberships and the seals themselves.
# ---------------------------------------------------------------------------

HDSC_PROOF_LEAF_TAG = b"ts/hdscp/l1"
HDSC_PROOF_NODE_TAG = b"ts/hdscp/n1"
HDSC_PROOF_ROOT_TAG = b"ts/hdscp/r1"
HDSC_PROOF_WIRE_TAG = b"ts/hdscp/w1"

HDSC_PROOF_DIGEST_SIZE = 32  # SHA256 output width; every tree node is this wide


def _hdsc_proof_u64(value: int) -> bytes:
    """8-byte unsigned big-endian encoding of a non-negative integer < 2**64."""
    return value.to_bytes(8, "big", signed=False)


def _hdsc_proof_leaf(index: int, seal: HistoryDeltaSegmentsSeal) -> bytes:
    """The index-bound leaf digest ``H(b"ts/hdscp/l1" || U64(i) || H(encode_hds(seal)))``."""
    return hashlib.sha256(
        HDSC_PROOF_LEAF_TAG
        + _hdsc_proof_u64(index)
        + hashlib.sha256(encode_hds(seal)).digest()
    ).digest()


def _hdsc_proof_node(left: bytes, right: bytes) -> bytes:
    """The ordered internal digest ``H(b"ts/hdscp/n1" || left || right)``."""
    return hashlib.sha256(
        HDSC_PROOF_NODE_TAG + left + right
    ).digest()


def _hdsc_proof_levels(
    seals: tuple[HistoryDeltaSegmentsSeal, ...],
) -> list[tuple[bytes, ...]]:
    """Build the leaf level and every internal level up to the single root.

    A level with an odd tail width is paired with its own last node
    duplicated, so every level above the leaves has an even width.
    """
    levels: list[tuple[bytes, ...]] = [
        tuple(
            _hdsc_proof_leaf(index, seal)
            for index, seal in enumerate(seals)
        )
    ]
    current = levels[0]
    while len(current) > 1:
        if len(current) % 2 == 1:
            current = current + current[-1:]
        current = tuple(
            _hdsc_proof_node(current[index], current[index + 1])
            for index in range(0, len(current), 2)
        )
        levels.append(current)
    return levels


@dataclass(frozen=True)
class HDSCProof:
    """A compact Merkle membership proof for several seals of a seal chain.

    The fields, in order, are ``indices`` (the proven leaf positions as a
    non-empty tuple of strictly increasing, unique non-negative integers),
    ``total`` (the total, non-empty chain seal count), ``seals`` (the
    proven :class:`HistoryDeltaSegmentsSeal` values, one per entry of
    ``indices``, in the same order) and ``siblings`` (the 32-byte sibling
    digests consumed from the leaf level up to the root, in ascending
    level order; the tuple is empty when no companion digests are
    needed). At a level whose width is odd, the last node pairs with
    itself and no sibling is carried for it. The dataclass is frozen,
    positionally constructible and compared by value, and carries no
    network, storage or hidden state. Field types and bounds are not
    checked at construction time — :func:`check_hdsc_proof` is the way
    to test a proof afterwards.
    """

    indices: tuple[int, ...]
    total: int
    seals: tuple[HistoryDeltaSegmentsSeal, ...]
    siblings: tuple[bytes, ...]


def make_hdsc_proof(
    chain: HistoryDeltaSegmentsSealChain, indices: tuple[int, ...]
) -> tuple[bytes, HDSCProof]:
    """Build the root statement and a compact multi-seal membership proof.

    ``chain`` must be a :class:`HistoryDeltaSegmentsSealChain` whose
    seals are a non-empty tuple of structurally legal
    :class:`HistoryDeltaSegmentsSeal` values exactly as
    :func:`encode_hds` requires, and ``indices`` a non-empty tuple of
    leaf positions to prove. The tree is built in chain order with
    SHA256: leaves are ``H(b"ts/hdscp/l1" || U64(i) ||
    H(encode_hds(seal)))`` and internal nodes ``H(b"ts/hdscp/n1" || left
    || right)``; a level with an odd tail width duplicates its last node
    for pairing. Returns ``(message, proof)`` where ``message`` is
    ``b"ts/hdscp/r1" || U64(total) || root`` (the 8-byte unsigned
    big-endian seal count followed by the 32-byte root) — the bytes to
    be threshold-signed — and ``proof`` is the :class:`HDSCProof` whose
    ``seals`` pair one to one with ``indices``. Its ``siblings`` are
    collected level by level, in ascending level order (leaves upward)
    and left to right within a level, one entry per needed companion:
    when the companion position is itself a proven node carried in the
    proof, or the node is the last member of an odd-width level (paired
    with itself), no sibling is appended; otherwise the companion digest
    is. Proven nodes from lower levels feed the level above exactly as
    in the tree, so no digest is sent twice. The chain's own outer
    signature is not consulted: the proof is built from the seals alone
    and the returned statement needs a fresh threshold signature.

    Wrong argument types raise TypeError: a
    non-:class:`HistoryDeltaSegmentsSealChain` chain, a non-tuple index
    sequence or a non-integer (including boolean) index. An empty chain
    or index tuple, a structurally illegal seal, a count that does not
    fit ``0 < total < 2**64``, indices that are not strictly increasing
    and unique, or an index outside ``0 <= i < total`` raises
    ValueError.
    """
    if not isinstance(chain, HistoryDeltaSegmentsSealChain):
        raise TypeError(
            "chain must be a HistoryDeltaSegmentsSealChain instance"
        )
    if not isinstance(indices, tuple):
        raise TypeError("indices must be a tuple")
    seals = _check_hdsc_seals(chain.seals)
    total = len(seals)
    if total > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("too many history delta segments seal chain seals")
    if len(indices) == 0:
        raise ValueError("indices must be non-empty")
    previous = -1
    for index in indices:
        if not isinstance(index, int) or isinstance(index, bool):
            raise TypeError("each index must be an integer")
        if index <= previous:
            raise ValueError("indices must be strictly increasing and unique")
        if index < 0 or index >= total:
            raise ValueError("index out of range")
        previous = index

    levels = _hdsc_proof_levels(seals)

    siblings: list[bytes] = []
    positions = set(indices)
    for level in levels[:-1]:
        width = len(level)
        padded = level if width % 2 == 0 else level + level[-1:]
        next_positions = set()
        for position in sorted(positions):
            if width % 2 == 1 and position == width - 1:
                # Odd tail with no companion: the tree pairs it with itself.
                pass
            elif (position ^ 1) in positions:
                # The companion is itself a disclosed node; nothing to send.
                pass
            else:
                siblings.append(padded[position ^ 1])
            next_positions.add(position // 2)
        positions = next_positions

    root = levels[-1][0]
    proof_seals = tuple(seals[index] for index in indices)
    proof = HDSCProof(
        indices=tuple(indices),
        total=total,
        seals=proof_seals,
        siblings=tuple(siblings),
    )
    return HDSC_PROOF_ROOT_TAG + _hdsc_proof_u64(total) + root, proof


def _validate_hdsc_proof_structure(
    proof: object,
) -> tuple[
    tuple[int, ...],
    int,
    tuple[HistoryDeltaSegmentsSeal, ...],
    tuple[bytes, ...],
]:
    """Type- and structure-check an HDSCProof, returning its fields.

    Only the container structure is checked: the seals themselves are
    neither encoded nor verified here (encoding happens in the leaf
    recomputation and verification is :func:`verify_hds`'s job). The
    bounds are ``0 < total < 2**64``, a non-empty ``indices`` tuple of
    strictly increasing indices in ``0 <= i < total`` and a siblings
    tuple whose entries are exactly 32 bytes. Wrong field types raise
    TypeError; illegal bounds or shapes raise ValueError. The two count
    couplings — seals pairing one-to-one with indices and the sibling
    count the compact walk derives from ``total`` and ``indices`` — are
    not judged here: the codec rejects their mismatch with ValueError
    while :func:`check_hdsc_proof` reports it as ``False``.
    """
    if not isinstance(proof, HDSCProof):
        raise TypeError("proof must be an HDSCProof instance")
    indices = proof.indices
    total = proof.total
    seals = proof.seals
    siblings = proof.siblings
    if not isinstance(indices, tuple):
        raise TypeError("proof.indices must be a tuple")
    if not isinstance(total, int) or isinstance(total, bool):
        raise TypeError("proof.total must be an integer")
    if not isinstance(seals, tuple):
        raise TypeError("proof.seals must be a tuple")
    if not isinstance(siblings, tuple):
        raise TypeError("proof.siblings must be a tuple")

    if total <= 0:
        raise ValueError("proof.total must be positive")
    if total > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("too many history delta segments seal chain seals")
    if len(indices) == 0:
        raise ValueError("proof.indices must be non-empty")

    previous = -1
    for index in indices:
        if not isinstance(index, int) or isinstance(index, bool):
            raise TypeError("proof.indices entries must be integers")
        if index <= previous:
            raise ValueError(
                "proof.indices must be strictly increasing and unique"
            )
        if index < 0 or index >= total:
            raise ValueError("proof.indices entry out of range")
        previous = index

    for seal in seals:
        if not isinstance(seal, HistoryDeltaSegmentsSeal):
            raise TypeError(
                "proof.seals entries must be "
                "HistoryDeltaSegmentsSeal instances"
            )

    for sibling in siblings:
        if not isinstance(sibling, bytes):
            raise TypeError("proof.siblings entries must be bytes")
    for sibling in siblings:
        if len(sibling) != HDSC_PROOF_DIGEST_SIZE:
            raise ValueError(
                "proof.siblings entries must be exactly 32 bytes"
            )
    return indices, total, seals, siblings


def check_hdsc_proof(
    proof: HDSCProof,
    signature: AggregateSignature,
    key: SigningDKGResult,
) -> bool:
    """Rebuild a proof's Merkle root and verify its seals and root signature.

    The root ``signature`` and ``key`` structures are checked first.
    Each disclosed seal's leaf digest is then recomputed from its
    position and the seal exactly as in :func:`make_hdsc_proof`, and the
    root is rebuilt level by level while consuming ``proof.siblings`` in
    ascending level order and left to right within a level: the current
    level holds the digests of the proven nodes at their current
    positions, paired left to right; when a companion is itself a
    current-level node its digest is used directly, when the node is the
    last member of an odd-width level it is paired with itself, and
    otherwise the next 32-byte entry of ``siblings`` is consumed. The
    current width contracts as ``(width + 1) // 2`` and the rebuild must
    consume every sibling exactly. Every disclosed seal is then
    re-checked with :func:`verify_hds` against ``key`` in index order,
    and the statement ``b"ts/hdscp/r1" || U64(total) || root`` is
    finally checked as ``signature``'s threshold Schnorr message via
    :func:`verify_signature` with the key's group parameters. Returns
    ``True`` only when the rebuild consumes every sibling exactly and
    reaches the single signed root, every seal verifies against the key
    and the signature verifies; a well-formed proof whose seals,
    indices, siblings, root or signature was tampered with — seals
    swapped or altered, a seal, index or sibling missing or extra, a
    misplaced sibling — or which is presented under another key, returns
    ``False`` rather than raising.

    A non-:class:`HDSCProof` or non-:class:`AggregateSignature` argument
    or any wrong field type (non-tuple indices/seals/siblings, a
    non-integer ``total`` or index including booleans, a
    non-:class:`HistoryDeltaSegmentsSeal` seal or non-bytes sibling)
    raises TypeError; a non-positive or over-64-bit ``total``, empty
    indices, an index out of range or not strictly increasing, a sibling
    entry that is not exactly 32 bytes, or a structurally illegal seal,
    signature or ``key`` raises ValueError, exactly as
    :func:`verify_hds` and :func:`verify_signature` would.
    """
    indices, total, seals, siblings = _validate_hdsc_proof_structure(proof)
    if not isinstance(signature, AggregateSignature):
        raise TypeError("signature must be an AggregateSignature instance")
    _check_history_proof_bundle_signature(signature)

    _result, public_key, field_prime, group_prime, generator = _check_signing_setup(key)
    _check_signing_dkg_structure(key)

    if len(seals) != len(indices):
        return False

    nodes = {
        index: _hdsc_proof_leaf(index, seal)
        for index, seal in zip(indices, seals)
    }
    pending = iter(siblings)
    width = total
    while width > 1:
        next_nodes = {}
        for position in sorted(nodes):
            parent = position // 2
            if parent in next_nodes:
                continue
            if width % 2 == 1 and position == width - 1:
                # Odd tail with no companion: pair the node with itself.
                next_nodes[parent] = _hdsc_proof_node(
                    nodes[position], nodes[position]
                )
            elif (position ^ 1) in nodes:
                left = position if position % 2 == 0 else position ^ 1
                next_nodes[parent] = _hdsc_proof_node(
                    nodes[left], nodes[left ^ 1]
                )
            else:
                sibling = next(pending, None)
                if sibling is None:
                    # A sibling the walk needs is missing.
                    return False
                if position % 2 == 0:
                    next_nodes[parent] = _hdsc_proof_node(
                        nodes[position], sibling
                    )
                else:
                    next_nodes[parent] = _hdsc_proof_node(
                        sibling, nodes[position]
                    )
        nodes = next_nodes
        width = (width + 1) // 2

    if next(pending, None) is not None:
        # The rebuild must consume every sibling exactly.
        return False

    for seal in seals:
        if not verify_hds(seal, key):
            return False

    signed_message = (
        HDSC_PROOF_ROOT_TAG + _hdsc_proof_u64(total) + nodes[0]
    )
    return verify_signature(
        signed_message,
        signature,
        public_key,
        group_prime=group_prime,
        generator=generator,
        prime=field_prime,
    )


# ---------------------------------------------------------------------------
# Canonical HDSCProof transport: a self-delimiting, byte-for-byte
# reproducible encoding of a compact multi-seal chain membership proof for
# cross-implementation exchange and persistence. Decoding restores structure
# only — the nested seals go through decode_hds, no seal or signature is
# checked and no state is kept, so check_hdsc_proof remains the sole
# verifier afterwards.
# ---------------------------------------------------------------------------


def encode_hdsc_proof(proof: HDSCProof) -> bytes:
    """Canonically encode a multi-seal chain membership proof for transport/storage.

    The encoding is the direct concatenation, in order, of the tag
    ``b"ts/hdscp/w1"``, ``VARINT(total)``, the index count as a 4-byte
    unsigned big-endian integer, one ``VARINT(index)`` per proven leaf
    in the proof's strictly increasing order, the seal count as a 4-byte
    unsigned big-endian integer, one frame per seal — the 4-byte
    unsigned big-endian length ``len(E)`` followed by the raw seal bytes
    ``E = encode_hds(seal)`` (never empty) — and finally the sibling
    count as a 4-byte unsigned big-endian integer followed by the raw
    32-byte sibling digests in their original leaf-to-root, left-to-right
    order. A ``VARINT`` is a 4-byte unsigned big-endian body length
    followed by the shortest unsigned big-endian value (zero is the
    single byte ``00`` and positive values carry no leading zero). The
    indices must be non-empty, strictly increasing, unique and within
    ``0 <= i < total``, the seal count must equal the index count, and
    the sibling count must be the unique one derived from ``total`` and
    the indices by the compact multi-proof walk.

    Only a structurally legal :class:`HDSCProof` is accepted — a
    non-proof or wrong field/entry types raise TypeError and illegal
    bounds, an empty index tuple, a seal tuple that does not pair
    one-to-one with the indices, a sibling that is not exactly 32 bytes,
    a sibling count other than the one ``total`` and the indices
    determine, a structurally illegal nested seal or an over-long frame
    raise ValueError — but the seals are not verified and no signature
    is checked: :func:`check_hdsc_proof` stays the way to verify a proof
    afterwards. The output for a given proof is unique and the encoding
    carries no network, storage or hidden state.
    """
    indices, total, seals, siblings = _validate_hdsc_proof_structure(proof)
    if len(seals) != len(indices):
        raise ValueError(
            "proof.seals must pair one-to-one with proof.indices"
        )
    required_siblings = _required_history_multi_proof_siblings(
        total, indices
    )
    if len(siblings) != required_siblings:
        raise ValueError(
            "proof.siblings count is not the one determined by total "
            "and indices"
        )
    if len(indices) > 0xFFFFFFFF:
        raise ValueError("too many indices")
    if len(siblings) > 0xFFFFFFFF:
        raise ValueError("too many siblings")

    encoded_seals = []
    for position, seal in enumerate(seals):
        encoded_seal = encode_hds(seal)
        if len(encoded_seal) > 0xFFFFFFFF:
            raise ValueError(
                f"hdsc proof seal {position + 1} encoding too long"
            )
        encoded_seals.append(encoded_seal)

    buffer = bytearray(HDSC_PROOF_WIRE_TAG)
    buffer += _encode_varint(total)
    buffer += len(indices).to_bytes(4, "big", signed=False)
    for index in indices:
        buffer += _encode_varint(index)
    buffer += len(encoded_seals).to_bytes(4, "big", signed=False)
    for encoded_seal in encoded_seals:
        buffer += len(encoded_seal).to_bytes(4, "big", signed=False)
        buffer += encoded_seal
    buffer += len(siblings).to_bytes(4, "big", signed=False)
    for sibling in siblings:
        buffer += sibling
    return bytes(buffer)


def decode_hdsc_proof(blob: bytes) -> HDSCProof:
    """Decode the canonical encoding produced by :func:`encode_hdsc_proof`.

    Accepts only the single canonical form: the tag ``b"ts/hdscp/w1"``,
    the length-prefixed integer ``total`` (a 4-byte unsigned big-endian
    length followed by its shortest unsigned big-endian value, zero
    encoded as the single byte ``00``), the 4-byte non-zero index count
    followed by one canonical ``VARINT`` per strictly increasing index,
    the 4-byte seal count (which must equal the index count) followed by
    that many non-empty seal frames (a 4-byte non-zero length followed
    by bytes that :func:`decode_hds` accepts), and finally the 4-byte
    sibling count followed by exactly that many raw 32-byte sibling
    digests, where the count must be the unique one derived from
    ``total`` and the disclosed indices. A non-bytes argument raises
    TypeError; a wrong or missing tag, an empty index list, a
    non-positive or over-64-bit ``total``, an index outside
    ``0 <= i < total``, indices that are not strictly increasing and
    unique, a seal count that does not match the index count, an empty,
    truncated or non-canonical seal frame, a missing or extra sibling
    relative to the count ``total`` and the indices require, a sibling
    that is not exactly 32 bytes, truncation, trailing bytes, or a
    non-canonical integer (leading zero or over-long length) raises
    ValueError. A successfully decoded proof re-encodes to exactly the
    input bytes.

    Decoding only restores the structure: each nested seal is decoded
    with :func:`decode_hds` (which verifies no signature and judges no
    seam) and nothing else is verified. A structurally legal proof whose
    seals do not verify or whose root signature is invalid is returned
    normally, and :func:`check_hdsc_proof` reports it as ``False``.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not blob.startswith(HDSC_PROOF_WIRE_TAG):
        raise ValueError("bad hdsc proof tag")
    offset = len(HDSC_PROOF_WIRE_TAG)

    total, offset = _read_varint(blob, offset, what="hdsc proof total")
    if total <= 0:
        raise ValueError("hdsc proof total must be positive")
    if total > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("hdsc proof total too large")

    if offset + 4 > len(blob):
        raise ValueError("truncated hdsc proof index count")
    index_count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    if index_count == 0:
        raise ValueError("hdsc proof indices must be non-empty")
    indices = []
    for _ in range(index_count):
        index, offset = _read_varint(
            blob, offset, what="hdsc proof index"
        )
        indices.append(index)

    if offset + 4 > len(blob):
        raise ValueError("truncated hdsc proof seal count")
    seal_count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    if seal_count != index_count:
        raise ValueError(
            "hdsc proof seal count must match the index count"
        )
    seals = []
    for position in range(seal_count):
        encoded_seal, offset = _read_audit_proof_block(
            blob,
            offset,
            what=f"hdsc proof seal {position + 1}",
        )
        seals.append(decode_hds(encoded_seal))

    if offset + 4 > len(blob):
        raise ValueError("truncated hdsc proof sibling count")
    sibling_count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    siblings = []
    for _ in range(sibling_count):
        if offset + HDSC_PROOF_DIGEST_SIZE > len(blob):
            raise ValueError("truncated hdsc proof sibling")
        siblings.append(
            bytes(
                blob[
                    offset:offset + HDSC_PROOF_DIGEST_SIZE
                ]
            )
        )
        offset += HDSC_PROOF_DIGEST_SIZE
    if offset != len(blob):
        raise ValueError("trailing bytes after hdsc proof")

    proof = HDSCProof(
        indices=tuple(indices),
        total=total,
        seals=tuple(seals),
        siblings=tuple(siblings),
    )
    _validate_hdsc_proof_structure(proof)
    if encode_hdsc_proof(proof) != blob:
        raise ValueError("non-canonical hdsc proof encoding")
    return proof


# ---------------------------------------------------------------------------
# Canonical HDSCProofBundle transport: an HDSCProof carried together with the
# aggregate threshold-Schnorr signature over its root statement as one
# self-delimiting, byte-for-byte reproducible byte string, mirroring the
# single-proof bundles. Decoding restores structure only — the nested proof
# goes through decode_hdsc_proof, its seals are not parsed for verification
# and no signature is checked, so verify_hdsc_proof_bundle remains the sole
# verifier afterwards.
# ---------------------------------------------------------------------------

HDSC_PROOF_BUNDLE_WIRE_TAG = b"ts/hdscpb/v1"


@dataclass(frozen=True)
class HDSCProofBundle:
    """A compact multi-seal chain membership proof together with its root signature.

    The fields, in order, are ``proof`` (an :class:`HDSCProof`) and
    ``signature`` (the :class:`AggregateSignature` on the proof's
    ``b"ts/hdscp/r1" || U64(total) || root`` statement). The dataclass
    is frozen, positionally constructible and compared by value, and
    carries no network, storage or hidden state. Field types and bounds
    are not checked at construction time —
    :func:`encode_hdsc_proof_bundle` checks the structure and
    :func:`verify_hdsc_proof_bundle` is the way to test a bundle
    afterwards.
    """

    proof: HDSCProof
    signature: AggregateSignature


def encode_hdsc_proof_bundle(bundle: HDSCProofBundle) -> bytes:
    """Canonically encode an hdsc proof bundle for transport or persistence.

    The encoding is, in order, the tag ``b"ts/hdscpb/v1"``, the 4-byte
    unsigned big-endian length ``len(P)`` followed by
    ``P = encode_hdsc_proof(bundle.proof)`` (never empty), and then the
    signature frame: ``VARINT(R)``, ``VARINT(z)``, the 4-byte unsigned
    big-endian signer count ``k`` and one ``VARINT(id)`` per ascending
    signer id. A ``VARINT`` is a 4-byte unsigned big-endian body length
    followed by the shortest unsigned big-endian value (zero is the
    single byte ``00``, positive values carry no leading zero); ``R``
    must be positive and ``z`` may be zero.

    Only a structurally legal :class:`HDSCProofBundle` is accepted — a
    non-bundle or non-:class:`HDSCProof` proof argument, or wrong
    proof/signature field types, raise TypeError and illegal proof or
    signature structure (the exact bounds of
    :func:`encode_hdsc_proof`, a non-positive ``R``, a negative ``z``,
    an empty or non-strictly-increasing signer id tuple) or an
    over-long frame raises ValueError, exactly as
    :func:`check_hdsc_proof`'s structural checks do — but the seals are
    not verified and the signature is not checked against the root:
    :func:`verify_hdsc_proof_bundle` stays the way to verify a bundle
    afterwards. The output for a given bundle is unique and the
    encoding carries no network, storage or hidden state.
    """
    if not isinstance(bundle, HDSCProofBundle):
        raise TypeError("bundle must be an HDSCProofBundle instance")
    if not isinstance(bundle.proof, HDSCProof):
        raise TypeError("bundle.proof must be an HDSCProof instance")
    encoded_proof = encode_hdsc_proof(bundle.proof)
    signer_count = _check_history_proof_bundle_signature(bundle.signature)
    if len(encoded_proof) > 0xFFFFFFFF:
        raise ValueError("hdsc proof encoding too long")
    if signer_count > 0xFFFFFFFF:
        raise ValueError("too many signer ids")

    buffer = bytearray(HDSC_PROOF_BUNDLE_WIRE_TAG)
    buffer += len(encoded_proof).to_bytes(4, "big", signed=False)
    buffer += encoded_proof
    buffer += _encode_varint(bundle.signature.R)
    buffer += _encode_varint(bundle.signature.z)
    buffer += signer_count.to_bytes(4, "big", signed=False)
    for signer_id in bundle.signature.signer_ids:
        buffer += _encode_varint(signer_id)
    return bytes(buffer)


def decode_hdsc_proof_bundle(blob: bytes) -> HDSCProofBundle:
    """Decode the canonical encoding produced by :func:`encode_hdsc_proof_bundle`.

    Accepts only the single canonical form: the tag
    ``b"ts/hdscpb/v1"``, a 4-byte non-zero frame length followed by
    bytes that :func:`decode_hdsc_proof` accepts, the length-prefixed
    integers ``R`` and ``z``, the 4-byte non-zero signer count ``k``
    and then exactly ``k`` strictly increasing positive signer ids. A
    non-bytes argument raises TypeError; a wrong or missing tag, a zero
    or over-long proof frame length, a non-canonical nested proof, a
    zero ``R``, a non-canonical integer (leading zero or over-long
    length), a zero signer count, a non-positive or non-increasing
    signer id, truncation, or trailing bytes raises ValueError. A
    successfully decoded bundle re-encodes to exactly the input bytes.

    Decoding only restores the structure: the nested proof is decoded
    with :func:`decode_hdsc_proof` (which verifies no seal and judges
    no signature) and the root signature is not checked. A
    structurally legal bundle whose seals do not verify or whose
    signature does not sign the root is returned normally, and
    :func:`verify_hdsc_proof_bundle` reports it as ``False``.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not blob.startswith(HDSC_PROOF_BUNDLE_WIRE_TAG):
        raise ValueError("bad hdsc proof bundle tag")
    offset = len(HDSC_PROOF_BUNDLE_WIRE_TAG)

    encoded_proof, offset = _read_audit_proof_block(
        blob, offset, what="hdsc proof bundle proof"
    )
    proof = decode_hdsc_proof(encoded_proof)

    R, offset = _read_varint(
        blob, offset, what="hdsc proof bundle signature R"
    )
    z, offset = _read_varint(
        blob, offset, what="hdsc proof bundle signature z"
    )
    if R == 0:
        raise ValueError("hdsc proof bundle signature R must be positive")

    if offset + 4 > len(blob):
        raise ValueError("truncated hdsc proof bundle signer count")
    signer_count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    if signer_count == 0:
        raise ValueError("hdsc proof bundle must name at least one signer")

    signer_ids = []
    for _ in range(signer_count):
        signer_id, offset = _read_varint(
            blob,
            offset,
            what="hdsc proof bundle signer id",
        )
        if signer_id == 0:
            raise ValueError("hdsc proof bundle signer ids must be positive")
        if signer_ids and signer_id <= signer_ids[-1]:
            raise ValueError(
                "hdsc proof bundle signer ids must be strictly "
                "increasing and unique"
            )
        signer_ids.append(signer_id)
    if offset != len(blob):
        raise ValueError("trailing bytes after hdsc proof bundle")

    bundle = HDSCProofBundle(
        proof=proof,
        signature=AggregateSignature(R=R, z=z, signer_ids=tuple(signer_ids)),
    )
    if encode_hdsc_proof_bundle(bundle) != blob:
        raise ValueError("non-canonical hdsc proof bundle encoding")
    return bundle


def verify_hdsc_proof_bundle(
    bundle: HDSCProofBundle, key: SigningDKGResult
) -> bool:
    """Verify a bundle exactly as :func:`check_hdsc_proof` would.

    This is a convenience wrapper over
    ``check_hdsc_proof(bundle.proof, bundle.signature, key)``: the
    Merkle root is rebuilt from the proof, every disclosed seal
    re-checked with :func:`verify_hds` against ``key`` and the
    signature verified on
    ``b"ts/hdscp/r1" || U64(total) || root``. Returns ``True`` only
    when all of them hold; a well-formed bundle with a tampered seal,
    index, sibling or signature, or one presented under another key,
    returns ``False``.

    A non-:class:`HDSCProofBundle` argument raises TypeError; illegal
    nested proof, signature or key structure raises TypeError/ValueError,
    exactly as :func:`check_hdsc_proof` does.
    """
    if not isinstance(bundle, HDSCProofBundle):
        raise TypeError("bundle must be an HDSCProofBundle instance")
    return check_hdsc_proof(bundle.proof, bundle.signature, key)


# ---------------------------------------------------------------------------
# Archives of HDSC proof bundles: a non-empty, order-preserving batch of
# whole HDSCProofBundle values authenticated by one more threshold Schnorr
# signature. The outer signature binds the digest of a canonical framing C
# over the existing per-bundle transport encodings and the verifying public
# key, so deleting, inserting, reordering or substituting a bundle — or
# presenting the archive under another key — invalidates it. The archive
# carries no state of its own: every bundle is re-checked with
# verify_hdsc_proof_bundle (and, through it, every disclosed seal) on
# verification before the outer signature is examined via verify_signature.
# ---------------------------------------------------------------------------

HDSC_PROOF_BUNDLE_ARCHIVE_TAG = b"ts/hdscpa/m1"
HDSC_PROOF_BUNDLE_ARCHIVE_WIRE_TAG = b"ts/hdscpa/w1"


@dataclass(frozen=True)
class HDSCProofBundleArchive:
    """A non-empty ordered archive of HDSC proof bundles with one outer signature.

    The fields, in order, are ``items`` — a non-empty tuple of
    :class:`HDSCProofBundle` values in archive order — and ``signature`` —
    the threshold Schnorr :class:`AggregateSignature` on
    :func:`hdsc_proof_bundle_archive_message` of the items and the
    verifying public key. The dataclass is frozen, positionally
    constructible and compared by value; the items keep their order and
    the archive carries no network, storage or hidden state. Neither
    field is checked at construction time —
    :func:`hdsc_proof_bundle_archive_message` requires structurally legal
    items and :func:`verify_hdsc_proof_bundle_archive` is the way to test
    an archive against a key afterwards.
    """

    items: tuple[HDSCProofBundle, ...]
    signature: AggregateSignature


def hdsc_proof_bundle_archive_message(
    items: tuple[HDSCProofBundle, ...], public_key: int
) -> bytes:
    """Encode the canonical message the threshold key signs for an archive.

    The message is, in order, the tag ``b"ts/hdscpa/m1"``, the 32-byte
    ``SHA256`` digest of the canonical framing ``C`` and
    ``V(public_key)`` — a 4-byte unsigned big-endian length followed by
    the shortest unsigned big-endian value (zero is the single byte
    ``00``, positive values carry no leading zero). With
    ``E_i = encode_hdsc_proof_bundle(items[i])`` and ``n`` the item
    count, ``C`` is built in tuple order as
    ``U32(n) || Σ(U32(len(E_i)) || E_i)``; every ``U32`` is a 4-byte
    unsigned big-endian integer and ``E_i`` is the existing canonical
    transport encoding of the bundle. The message carries no signature
    and keeps no state.

    ``items`` must be a non-empty tuple of structurally legal
    :class:`HDSCProofBundle` values exactly as
    :func:`encode_hdsc_proof_bundle` requires and ``public_key`` a
    non-boolean non-negative integer. Wrong field or nested field types
    raise TypeError — a non-tuple items sequence, an item that is not an
    :class:`HDSCProofBundle`, or a non-integer (including boolean) public
    key; an empty items tuple, an illegal nested bundle, a negative
    public key or an over-long encoding raises ValueError.
    """
    if not isinstance(items, tuple):
        raise TypeError("items must be a tuple")
    for item in items:
        if not isinstance(item, HDSCProofBundle):
            raise TypeError(
                "each archive item must be an HDSCProofBundle instance"
            )
    if not isinstance(public_key, int) or isinstance(public_key, bool):
        raise TypeError("public_key must be an integer")

    item_count = len(items)
    if item_count == 0:
        raise ValueError("archive items must be a non-empty tuple")
    if item_count > 0xFFFFFFFF:
        raise ValueError("too many HDSC proof bundle archive items")

    # Encode every bundle first — each call raises TypeError/ValueError
    # for an illegal bundle exactly as the bundle codec does — and only
    # then frame the results, so a single illegal item aborts the whole
    # message.
    frames = []
    for index, item in enumerate(items):
        encoded = encode_hdsc_proof_bundle(item)
        if len(encoded) > 0xFFFFFFFF:
            raise ValueError(
                f"HDSC proof bundle archive item {index + 1} encoding too long"
            )
        frames.append(encoded)

    framing = bytearray(item_count.to_bytes(4, "big", signed=False))
    for encoded in frames:
        framing += len(encoded).to_bytes(4, "big", signed=False)
        framing += encoded
    return (
        HDSC_PROOF_BUNDLE_ARCHIVE_TAG
        + hashlib.sha256(bytes(framing)).digest()
        + _encode_varint(public_key)
    )


def verify_hdsc_proof_bundle_archive(
    archive: HDSCProofBundleArchive, key: SigningDKGResult
) -> bool:
    """Verify an archive of HDSC proof bundles against the threshold key.

    ``archive`` must be a structurally legal
    :class:`HDSCProofBundleArchive` and ``key`` a legal
    :class:`SigningDKGResult`. The outer signature and the key structure
    are checked first, as is the structure of every item, so an illegal
    outer signature or key is never masked by a bad nested bundle: a
    non-:class:`HDSCProofBundleArchive` argument, a non-tuple ``items``
    field, a non-:class:`HDSCProofBundle` element or a
    non-:class:`SigningDKGResult` ``key`` raises TypeError, and an empty
    items tuple, an illegal outer signature structure, an illegal key
    structure or any structurally illegal nested bundle raises
    ValueError.

    Every bundle is then passed to :func:`verify_hdsc_proof_bundle` in
    archive order, so each disclosed seal and each root signature must
    verify under ``key``; the canonical
    :func:`hdsc_proof_bundle_archive_message` of the items and
    ``key.public_key`` is finally checked as the outer signature's
    threshold Schnorr message via :func:`verify_signature` with the
    key's group parameters. Returns ``True`` only when every
    per-bundle check and the outer signature check pass; a structurally
    legal archive whose nested bundle or outer signature does not match
    — including deleting, inserting, reordering or substituting a
    bundle, or presenting the archive under another key — returns
    ``False`` rather than raising. The function is stateless.
    """
    if not isinstance(archive, HDSCProofBundleArchive):
        raise TypeError(
            "archive must be an HDSCProofBundleArchive instance"
        )
    items = archive.items
    if not isinstance(items, tuple):
        raise TypeError("items must be a tuple")
    for item in items:
        if not isinstance(item, HDSCProofBundle):
            raise TypeError(
                "each archive item must be an HDSCProofBundle instance"
            )
    # Check the outer signature and the key before any nested bundle is
    # examined, so a bad bundle can never mask an illegal outer
    # signature or key; structurally validate every nested bundle too,
    # exactly as the single-bundle verifier validates its proof.
    _check_history_proof_bundle_signature(archive.signature)
    _result, public_key, field_prime, group_prime, generator = _check_signing_setup(key)
    _check_signing_dkg_structure(key)
    if len(items) == 0:
        raise ValueError("archive items must be a non-empty tuple")
    for item in items:
        encode_hdsc_proof_bundle(item)

    if not all(verify_hdsc_proof_bundle(item, key) for item in items):
        return False
    message = hdsc_proof_bundle_archive_message(items, public_key)
    return verify_signature(
        message,
        archive.signature,
        public_key,
        group_prime=group_prime,
        generator=generator,
        prime=field_prime,
    )


def encode_hdsc_proof_bundle_archive(archive: HDSCProofBundleArchive) -> bytes:
    """Canonically encode a non-empty ordered archive of HDSC proof bundles
    as one self-delimiting object for transport or persistence.

    The encoding is, in order, the tag ``b"ts/hdscpa/w1"``, the 4-byte
    unsigned big-endian item count (never zero), then one frame per
    bundle in tuple order — each the 4-byte unsigned big-endian byte
    length followed by the exact bytes of
    :func:`encode_hdsc_proof_bundle` for that item, with no further
    separators — and finally the outer signature frame an
    :class:`AuditProofBundle` carries: ``VARINT(R)``, ``VARINT(z)``, the
    4-byte unsigned big-endian signer count ``k`` and one
    ``VARINT(id)`` per ascending signer id. Every U32 is a 4-byte
    unsigned big-endian integer; a ``VARINT`` is a 4-byte unsigned
    big-endian body length followed by the shortest unsigned big-endian
    value (zero is the single byte ``00``, positive values carry no
    leading zero); ``R`` must be positive, ``z`` may be zero and the
    signer ids are a non-empty strictly increasing tuple of positive
    integers.

    Only the archive container, each individual bundle and the outer
    signature are checked structurally — the items are not sorted or
    otherwise reordered, the outer signature is not matched against the
    bundles, no inner or outer signature is checked and no state is
    read: :func:`verify_hdsc_proof_bundle_archive` stays the way to test
    an archive against a key afterwards. A
    non-:class:`HDSCProofBundleArchive` argument, a non-tuple ``items``
    field or a non-:class:`HDSCProofBundle` element raises TypeError, as
    do wrong field types nested inside a bundle and a
    non-:class:`AggregateSignature` outer signature or one with wrong
    field types. An empty items tuple, an over-long count or frame, any
    structural error a bundle would raise on its own, or an illegal
    outer signature structure raises ValueError. The output for a given
    archive is unique and the encoding carries no network, storage or
    hidden state.
    """
    if not isinstance(archive, HDSCProofBundleArchive):
        raise TypeError(
            "archive must be an HDSCProofBundleArchive instance"
        )
    items = archive.items
    if not isinstance(items, tuple):
        raise TypeError("items must be a tuple")
    for item in items:
        if not isinstance(item, HDSCProofBundle):
            raise TypeError(
                "each archive item must be an HDSCProofBundle instance"
            )
    item_count = len(items)
    if item_count == 0:
        raise ValueError("archive items must be a non-empty tuple")
    if item_count > 0xFFFFFFFF:
        raise ValueError("too many HDSC proof bundle archive items")
    signer_count = _check_history_proof_bundle_signature(archive.signature)
    if signer_count > 0xFFFFFFFF:
        raise ValueError("too many signer ids")

    # Encode every item first — each call raises TypeError/ValueError
    # for an illegal bundle exactly as the single-bundle codec does —
    # and only then frame the results, so a single illegal item aborts
    # the whole archive.
    frames = []
    for index, item in enumerate(items):
        encoded = encode_hdsc_proof_bundle(item)
        if len(encoded) > 0xFFFFFFFF:
            raise ValueError(
                f"HDSC proof bundle archive item {index + 1} encoding too long"
            )
        frames.append(encoded)

    buffer = bytearray(HDSC_PROOF_BUNDLE_ARCHIVE_WIRE_TAG)
    buffer += item_count.to_bytes(4, "big", signed=False)
    for encoded in frames:
        buffer += len(encoded).to_bytes(4, "big", signed=False)
        buffer += encoded
    buffer += _encode_varint(archive.signature.R)
    buffer += _encode_varint(archive.signature.z)
    buffer += signer_count.to_bytes(4, "big", signed=False)
    for signer_id in archive.signature.signer_ids:
        buffer += _encode_varint(signer_id)
    return bytes(buffer)


def decode_hdsc_proof_bundle_archive(blob: bytes) -> HDSCProofBundleArchive:
    """Decode the canonical encoding produced by
    :func:`encode_hdsc_proof_bundle_archive`.

    Accepts only the single canonical form: the tag
    ``b"ts/hdscpa/w1"``, a 4-byte unsigned big-endian non-zero item
    count ``n``, then exactly ``n`` frames, each a 4-byte unsigned
    big-endian non-zero byte length followed by the exact canonical
    encoding of one :class:`HDSCProofBundle` that
    :func:`decode_hdsc_proof_bundle` accepts, and finally the outer
    signature frame: the length-prefixed integers ``R`` and ``z`` with
    ``R`` positive, the 4-byte non-zero signer count ``k`` and then
    exactly ``k`` strictly increasing positive signer ids. The bundles
    are restored in their original order as a tuple; they are neither
    sorted nor matched against one another or against the outer
    signature, and no signature is verified —
    :func:`verify_hdsc_proof_bundle_archive` judges the archive
    afterwards. A non-bytes argument raises TypeError; a wrong or
    missing tag, a zero item count, a zero or over-long frame length, a
    count mismatch, a nested bundle encoding that is illegal or
    non-canonical (including a frame that would not re-encode byte for
    byte), a zero ``R``, a non-canonical integer (leading zero or
    over-long length), a zero signer count, a non-positive or
    non-increasing signer id, truncation, or trailing bytes raises
    ValueError. A successfully decoded archive re-encodes to exactly the
    input bytes.

    Decoding only restores structure: every nested bundle is decoded
    with :func:`decode_hdsc_proof_bundle` (which verifies no seal and
    checks no signature) and the outer signature is not checked. A
    structurally legal archive whose bundles do not verify or whose
    outer signature does not sign the bundles is returned normally, and
    :func:`verify_hdsc_proof_bundle_archive` reports it as ``False``.
    """
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    if not blob.startswith(HDSC_PROOF_BUNDLE_ARCHIVE_WIRE_TAG):
        raise ValueError("bad HDSC proof bundle archive tag")
    offset = len(HDSC_PROOF_BUNDLE_ARCHIVE_WIRE_TAG)

    if offset + 4 > len(blob):
        raise ValueError("truncated HDSC proof bundle archive item count")
    item_count = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    if item_count == 0:
        raise ValueError("HDSC proof bundle archive items must be non-empty")

    items = []
    for index in range(item_count):
        frame, offset = _read_audit_proof_block(
            blob,
            offset,
            what=f"HDSC proof bundle archive item {index + 1}",
        )
        items.append(decode_hdsc_proof_bundle(frame))

    signature, offset = _read_bundle_signature_frame(
        blob, offset, what="HDSC proof bundle archive"
    )
    if offset != len(blob):
        raise ValueError("trailing bytes after HDSC proof bundle archive")

    archive = HDSCProofBundleArchive(items=tuple(items), signature=signature)
    if encode_hdsc_proof_bundle_archive(archive) != blob:
        raise ValueError("non-canonical HDSC proof bundle archive encoding")
    return archive


# ---------------------------------------------------------------------------
# Compact multi-package membership proofs for archives of HDSC proof bundles:
# one threshold signature on a Merkle root statement lets a third party confirm
# that several HDSCProofBundle values each sit at a fixed position in the exact
# archive without fetching the archive itself. The tree is isomorphic to the
# existing membership proofs — SHA256 over domain-separated leaf/node prefixes
# with the odd tail of every level paired with itself — but the leaves bind
# each position to the existing canonical whole-bundle encoding
# encode_hdsc_proof_bundle and the signed root statement is
# b"ts/hdscba/r1" || U64(total) || root. The compact walk sends each companion
# digest at most once, level by level left to right, omitting companions that
# are themselves disclosed and odd tails, so the sibling count and order are
# derived from the total and the indices alone. No state is kept and the
# archive's own outer signature is not consulted at construction;
# check_hdsc_archive_proof rebuilds the root from the disclosed bundles and
# siblings, re-runs verify_hdsc_proof_bundle on every disclosed bundle (and,
# through it, every inner proof and seal) and verify_signature on the root
# signature, so a proof certifies both the memberships and the bundles.
# No transport encoding is provided for these proofs and no proof-plus-root-
# signature bundle type: the root message is signed by the caller through the
# usual two-round threshold flow and handed over out of band.
# ---------------------------------------------------------------------------

HDSC_ARCHIVE_PROOF_LEAF_TAG = b"ts/hdscba/l1"
HDSC_ARCHIVE_PROOF_NODE_TAG = b"ts/hdscba/n1"
HDSC_ARCHIVE_PROOF_ROOT_TAG = b"ts/hdscba/r1"

HDSC_ARCHIVE_PROOF_DIGEST_SIZE = 32  # SHA256 output width; every tree node is this wide


def _hdsc_archive_proof_u64(value: int) -> bytes:
    """8-byte unsigned big-endian encoding of a non-negative integer < 2**64."""
    return value.to_bytes(8, "big", signed=False)


def _hdsc_archive_proof_leaf(index: int, bundle: HDSCProofBundle) -> bytes:
    """The index-bound leaf digest for one archive bundle.

    ``H(b"ts/hdscba/l1" || U64(i) ||
    H(encode_hdsc_proof_bundle(bundle)))``.
    """
    return hashlib.sha256(
        HDSC_ARCHIVE_PROOF_LEAF_TAG
        + _hdsc_archive_proof_u64(index)
        + hashlib.sha256(encode_hdsc_proof_bundle(bundle)).digest()
    ).digest()


def _hdsc_archive_proof_node(left: bytes, right: bytes) -> bytes:
    """The ordered internal digest ``H(b"ts/hdscba/n1" || left || right)``."""
    return hashlib.sha256(
        HDSC_ARCHIVE_PROOF_NODE_TAG + left + right
    ).digest()


def _hdsc_archive_proof_levels(
    bundles: tuple[HDSCProofBundle, ...],
) -> list[tuple[bytes, ...]]:
    """Build the leaf level and every internal level up to the single root.

    A level with an odd tail width is paired with its own last node
    duplicated, so every level above the leaves has an even width.
    """
    levels: list[tuple[bytes, ...]] = [
        tuple(
            _hdsc_archive_proof_leaf(index, bundle)
            for index, bundle in enumerate(bundles)
        )
    ]
    current = levels[0]
    while len(current) > 1:
        if len(current) % 2 == 1:
            current = current + current[-1:]
        current = tuple(
            _hdsc_archive_proof_node(current[index], current[index + 1])
            for index in range(0, len(current), 2)
        )
        levels.append(current)
    return levels


def _check_hdsc_archive_proof_items(
    items: object,
) -> tuple[HDSCProofBundle, ...]:
    """Type- and structure-check a non-empty ordered tuple of archive bundles.

    Mirrors the container and per-item checks the archive applies: a tuple
    of :class:`HDSCProofBundle` instances, non-empty, each structurally
    legal through its own canonical encoder. Nothing here verifies a
    signature — neither the per-bundle root signatures nor the archive's
    outer signature.
    """
    if not isinstance(items, tuple):
        raise TypeError("items must be a tuple")
    for item in items:
        if not isinstance(item, HDSCProofBundle):
            raise TypeError(
                "each archive item must be an HDSCProofBundle instance"
            )
    if len(items) == 0:
        raise ValueError("archive items must be a non-empty tuple")
    if len(items) > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("too many HDSC proof bundle archive items")
    for item in items:
        encode_hdsc_proof_bundle(item)
    return items


@dataclass(frozen=True)
class HDSCArchiveProof:
    """A compact Merkle membership proof for several bundles of an archive.

    The fields, in order, are ``indices`` (the proven leaf positions as a
    non-empty tuple of strictly increasing, unique non-negative integers),
    ``total`` (the total, non-empty archive item count), ``bundles`` (the
    proven :class:`HDSCProofBundle` values, one per entry of ``indices``,
    in the same order) and ``siblings`` (the 32-byte sibling digests
    consumed from the leaf level up to the root, in ascending level order;
    the tuple is empty when no companion digests are needed). At a level
    whose width is odd, the last node pairs with itself and no sibling is
    carried for it. The dataclass is frozen, positionally constructible
    and compared by value, and carries no network, storage or hidden
    state. Field types and bounds are not checked at construction time —
    :func:`check_hdsc_archive_proof` is the way to test a proof
    afterwards.
    """

    indices: tuple[int, ...]
    total: int
    bundles: tuple[HDSCProofBundle, ...]
    siblings: tuple[bytes, ...]


def make_hdsc_archive_proof(
    archive: HDSCProofBundleArchive, indices: tuple[int, ...]
) -> tuple[bytes, HDSCArchiveProof]:
    """Build the root statement and a compact multi-package membership proof.

    ``archive`` must be an :class:`HDSCProofBundleArchive` whose items are
    a non-empty tuple of structurally legal :class:`HDSCProofBundle`
    values exactly as :func:`encode_hdsc_proof_bundle` requires, and
    ``indices`` a non-empty tuple of leaf positions to prove. The tree is
    built in archive order with SHA256: leaves are
    ``H(b"ts/hdscba/l1" || U64(i) || H(encode_hdsc_proof_bundle(bundle)))``
    and internal nodes ``H(b"ts/hdscba/n1" || left || right)``; a level
    with an odd tail width duplicates its last node for pairing. Returns
    ``(message, proof)`` where ``message`` is
    ``b"ts/hdscba/r1" || U64(total) || root`` (the 8-byte unsigned
    big-endian item count followed by the 32-byte root) — the bytes to be
    threshold-signed — and ``proof`` is the :class:`HDSCArchiveProof`
    whose ``bundles`` pair one to one with ``indices``. Its ``siblings``
    are collected level by level, in ascending level order (leaves
    upward) and left to right within a level, one entry per needed
    companion: when the companion position is itself a proven node
    carried in the proof, or the node is the last member of an
    odd-width level (paired with itself), no sibling is appended;
    otherwise the companion digest is. Proven nodes from lower levels
    feed the level above exactly as in the tree, so no digest is sent
    twice. Only the structure is consulted: the archive's own outer
    signature is not verified and no state is kept; the returned
    statement needs a fresh threshold signature from the caller's
    two-round threshold flow, and one signature over the root covers any
    index subset of the same archive.

    Wrong argument types raise TypeError: a
    non-:class:`HDSCProofBundleArchive` archive, a non-tuple index
    sequence or a non-integer (including boolean) index, as do a
    non-tuple ``items`` field, a non-:class:`HDSCProofBundle` element and
    wrong nested field types. An empty archive or index tuple, a
    structurally illegal bundle, a count that does not fit
    ``0 < total < 2**64``, indices that are not strictly increasing and
    unique, or an index outside ``0 <= i < total`` raises ValueError.
    """
    if not isinstance(archive, HDSCProofBundleArchive):
        raise TypeError(
            "archive must be an HDSCProofBundleArchive instance"
        )
    if not isinstance(indices, tuple):
        raise TypeError("indices must be a tuple")
    bundles = _check_hdsc_archive_proof_items(archive.items)
    total = len(bundles)
    if total > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("too many HDSC proof bundle archive items")
    if len(indices) == 0:
        raise ValueError("indices must be non-empty")
    previous = -1
    for index in indices:
        if not isinstance(index, int) or isinstance(index, bool):
            raise TypeError("each index must be an integer")
        if index <= previous:
            raise ValueError("indices must be strictly increasing and unique")
        if index < 0 or index >= total:
            raise ValueError("index out of range")
        previous = index

    levels = _hdsc_archive_proof_levels(bundles)

    siblings: list[bytes] = []
    positions = set(indices)
    for level in levels[:-1]:
        width = len(level)
        padded = level if width % 2 == 0 else level + level[-1:]
        next_positions = set()
        for position in sorted(positions):
            if width % 2 == 1 and position == width - 1:
                # Odd tail with no companion: the tree pairs it with itself.
                pass
            elif (position ^ 1) in positions:
                # The companion is itself a disclosed node; nothing to send.
                pass
            else:
                siblings.append(padded[position ^ 1])
            next_positions.add(position // 2)
        positions = next_positions

    root = levels[-1][0]
    proof_bundles = tuple(bundles[index] for index in indices)
    proof = HDSCArchiveProof(
        indices=tuple(indices),
        total=total,
        bundles=proof_bundles,
        siblings=tuple(siblings),
    )
    return HDSC_ARCHIVE_PROOF_ROOT_TAG + _hdsc_archive_proof_u64(total) + root, proof


def _validate_hdsc_archive_proof_structure(
    proof: object,
) -> tuple[
    tuple[int, ...],
    int,
    tuple[HDSCProofBundle, ...],
    tuple[bytes, ...],
]:
    """Type- and structure-check an HDSCArchiveProof, returning its fields.

    Only the container structure is checked: the bundles themselves are
    neither encoded nor verified here (encoding happens in the leaf
    recomputation and verification is :func:`verify_hdsc_proof_bundle`'s
    job). The bounds are ``0 < total < 2**64``, a non-empty ``indices``
    tuple of strictly increasing indices in ``0 <= i < total`` and a
    siblings tuple whose entries are exactly 32 bytes. Wrong field or
    element types raise TypeError; illegal bounds or shapes raise
    ValueError. The two count couplings — bundles pairing one-to-one with
    indices and the sibling count the compact walk derives from ``total``
    and the indices — are not judged here: :func:`check_hdsc_archive_proof`
    reports a mismatch as ``False``.
    """
    if not isinstance(proof, HDSCArchiveProof):
        raise TypeError("proof must be an HDSCArchiveProof instance")
    indices = proof.indices
    total = proof.total
    bundles = proof.bundles
    siblings = proof.siblings
    if not isinstance(indices, tuple):
        raise TypeError("proof.indices must be a tuple")
    if not isinstance(total, int) or isinstance(total, bool):
        raise TypeError("proof.total must be an integer")
    if not isinstance(bundles, tuple):
        raise TypeError("proof.bundles must be a tuple")
    if not isinstance(siblings, tuple):
        raise TypeError("proof.siblings must be a tuple")

    if total <= 0:
        raise ValueError("proof.total must be positive")
    if total > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("too many HDSC proof bundle archive items")
    if len(indices) == 0:
        raise ValueError("proof.indices must be non-empty")

    previous = -1
    for index in indices:
        if not isinstance(index, int) or isinstance(index, bool):
            raise TypeError("proof.indices entries must be integers")
        if index <= previous:
            raise ValueError(
                "proof.indices must be strictly increasing and unique"
            )
        if index < 0 or index >= total:
            raise ValueError("proof.indices entry out of range")
        previous = index

    for bundle in bundles:
        if not isinstance(bundle, HDSCProofBundle):
            raise TypeError(
                "proof.bundles entries must be HDSCProofBundle instances"
            )

    for sibling in siblings:
        if not isinstance(sibling, bytes):
            raise TypeError("proof.siblings entries must be bytes")
    for sibling in siblings:
        if len(sibling) != HDSC_ARCHIVE_PROOF_DIGEST_SIZE:
            raise ValueError(
                "proof.siblings entries must be exactly 32 bytes"
            )
    return indices, total, bundles, siblings


def check_hdsc_archive_proof(
    proof: HDSCArchiveProof,
    signature: AggregateSignature,
    key: SigningDKGResult,
) -> bool:
    """Rebuild a proof's Merkle root and verify its bundles and root signature.

    The root ``signature`` and ``key`` structures are checked first.
    Each disclosed bundle's leaf digest is then recomputed from its
    position and the bundle exactly as in
    :func:`make_hdsc_archive_proof`, and the root is rebuilt level by
    level while consuming ``proof.siblings`` in ascending level order
    and left to right within a level: the current level holds the
    digests of the proven nodes at their current positions, paired left
    to right; when a companion is itself a current-level node its digest
    is used directly, when the node is the last member of an odd-width
    level it is paired with itself, and otherwise the next 32-byte entry
    of ``siblings`` is consumed. The current width contracts as
    ``(width + 1) // 2`` and the rebuild must consume every sibling
    exactly. Every disclosed bundle is then re-checked with
    :func:`verify_hdsc_proof_bundle` against ``key`` in index order — so
    each inner proof, each disclosed seal and each inner root signature
    must verify — and the statement
    ``b"ts/hdscba/r1" || U64(total) || root`` is finally checked as
    ``signature``'s threshold Schnorr message via
    :func:`verify_signature` with the key's group parameters. Returns
    ``True`` only when the rebuild consumes every sibling exactly and
    reaches the single signed root, every bundle verifies against the
    key and the signature verifies; a well-formed proof whose bundles,
    indices, siblings, root or signature was tampered with — bundles
    swapped or altered, an index, bundle or sibling missing or extra, a
    misplaced sibling, an inner proof or seal that does not verify — or
    which is presented under another key, returns ``False`` rather than
    raising.

    A non-:class:`HDSCArchiveProof` or non-:class:`AggregateSignature`
    argument or any wrong field type (non-tuple indices/bundles/siblings,
    a non-integer ``total`` or index including booleans, a
    non-:class:`HDSCProofBundle` bundle or non-bytes sibling) raises
    TypeError; a non-positive or over-64-bit ``total``, empty indices,
    an index out of range or not strictly increasing, a sibling entry
    that is not exactly 32 bytes, or a structurally illegal bundle,
    signature or ``key`` raises ValueError, exactly as
    :func:`verify_hdsc_proof_bundle` and :func:`verify_signature` would.
    """
    indices, total, bundles, siblings = _validate_hdsc_archive_proof_structure(proof)
    if not isinstance(signature, AggregateSignature):
        raise TypeError("signature must be an AggregateSignature instance")
    _check_history_proof_bundle_signature(signature)

    _result, public_key, field_prime, group_prime, generator = _check_signing_setup(key)
    _check_signing_dkg_structure(key)

    if len(bundles) != len(indices):
        return False

    nodes = {
        index: _hdsc_archive_proof_leaf(index, bundle)
        for index, bundle in zip(indices, bundles)
    }
    pending = iter(siblings)
    width = total
    while width > 1:
        next_nodes = {}
        for position in sorted(nodes):
            parent = position // 2
            if parent in next_nodes:
                continue
            if width % 2 == 1 and position == width - 1:
                # Odd tail with no companion: pair the node with itself.
                next_nodes[parent] = _hdsc_archive_proof_node(
                    nodes[position], nodes[position]
                )
            elif (position ^ 1) in nodes:
                left = position if position % 2 == 0 else position ^ 1
                next_nodes[parent] = _hdsc_archive_proof_node(
                    nodes[left], nodes[left ^ 1]
                )
            else:
                sibling = next(pending, None)
                if sibling is None:
                    # A sibling the walk needs is missing.
                    return False
                if position % 2 == 0:
                    next_nodes[parent] = _hdsc_archive_proof_node(
                        nodes[position], sibling
                    )
                else:
                    next_nodes[parent] = _hdsc_archive_proof_node(
                        sibling, nodes[position]
                    )
        nodes = next_nodes
        width = (width + 1) // 2

    if next(pending, None) is not None:
        # The rebuild must consume every sibling exactly.
        return False

    for bundle in bundles:
        if not verify_hdsc_proof_bundle(bundle, key):
            return False

    signed_message = (
        HDSC_ARCHIVE_PROOF_ROOT_TAG + _hdsc_archive_proof_u64(total) + nodes[0]
    )
    return verify_signature(
        signed_message,
        signature,
        public_key,
        group_prime=group_prime,
        generator=generator,
        prime=field_prime,
    )


# ---------------------------------------------------------------------------
# Cross-key append-only proofs: a seal-history consistency statement whose
# old and new root signatures come from different threshold keys, linked by a
# non-empty RotationChain proving the path from the old key to the new one.
# The extension body E carries only the fixed-width tree statement
# ``U64(old_total) || U64(n) || leaves`` and C is the existing canonical
# rotation-chain encoding; both root signatures are the existing canonical
# bundle signature frames. The value is frozen and keeps no state —
# verify_rotation_chain authorizes the key path and the two root checks
# certify the prefix relation under each endpoint's own group parameters.
# ---------------------------------------------------------------------------

RHE_WIRE_TAG = b"ts/rhe/v1"


@dataclass(frozen=True)
class RHE:
    """A cross-key seal-history append proof.

    The fields, in order, are ``extension`` (a :class:`SealHistoryExtension`
    carrying the full new history's leaf digests), ``rotations`` (a
    non-empty, order-preserving :class:`RotationChain` from the old signing
    key to the new one), ``old_sig`` (the old key's
    :class:`AggregateSignature` on the old
    ``b"sh/r" || U64(old_total) || old_root`` statement) and ``new_sig``
    (the new key's :class:`AggregateSignature` on the new
    ``b"sh/r" || U64(n) || new_root`` statement). The dataclass is frozen,
    positionally constructible and compared by value, has no field
    defaults, and carries no network, storage or hidden state. Field types
    and bounds are not checked at construction time —
    :func:`encode_rhe` checks the structure and :func:`check_rhe` is the
    way to test a proof afterwards.
    """

    extension: SealHistoryExtension
    rotations: RotationChain
    old_sig: AggregateSignature
    new_sig: AggregateSignature


def _rhe_extension_body(
    old_total: int, leaves: tuple[bytes, ...]
) -> bytes:
    """The fixed-width extension body ``E = U64(old_total) || U64(n) || leaves``."""
    buffer = bytearray(_history_proof_u64(old_total))
    buffer += _history_proof_u64(len(leaves))
    for leaf in leaves:
        buffer += leaf
    return bytes(buffer)


def _check_rhe_fields(
    x: object,
) -> tuple[
    SealHistoryExtension,
    RotationChain,
    AggregateSignature,
    AggregateSignature,
    int,
    tuple[bytes, ...],
]:
    """Type- and structure-check an :class:`RHE`, returning its parts.

    The extension goes through the same structural checks as
    :func:`check_history_extension`, the chain through those of
    :func:`verify_rotation_chain` (without verifying any certificate), and
    both signatures through the bundle signature structure checks. Nothing
    here verifies a signature or a linkage.
    """
    if not isinstance(x, RHE):
        raise TypeError("x must be an RHE instance")
    old_total, leaves = _validate_history_extension_structure(x.extension)
    if not isinstance(x.rotations, RotationChain):
        raise TypeError("x.rotations must be a RotationChain instance")
    _check_rotation_chain_fields(x.rotations.anchor, x.rotations.certificates)
    _check_history_proof_bundle_signature(x.old_sig, field="x.old_sig")
    _check_history_proof_bundle_signature(x.new_sig, field="x.new_sig")
    return x.extension, x.rotations, x.old_sig, x.new_sig, old_total, leaves


def encode_rhe(x: RHE) -> bytes:
    """Canonically encode a cross-key append proof for transport or persistence.

    The encoding is, in order, the tag ``b"ts/rhe/v1"``, the 4-byte unsigned
    big-endian length ``len(E)`` followed by the fixed-width extension body
    ``E = U64(old_total) || U64(n) || leaf_1 || ... || leaf_n`` where both
    counts are 8-byte unsigned big-endian and the leaves are the extension's
    32-byte digests in order, the 4-byte unsigned big-endian length
    ``len(C)`` followed by ``C = encode_rotation_chain(x.rotations)``, and
    then the old and new signature frames, each exactly the canonical
    signature frame of :func:`encode_history_proof_bundle`:
    ``VARINT(R)``, ``VARINT(z)``, the 4-byte unsigned big-endian signer
    count and one ``VARINT(id)`` per ascending signer id.

    Only structure is checked: the extension and chain must be well formed
    (the exact bounds of :func:`check_history_extension` and
    :func:`encode_rotation_chain`) and both signatures structurally legal,
    but the rotation chain is not verified, neither signature is checked
    against a root and the two signatures may belong to unrelated groups —
    :func:`check_rhe` stays the way to verify a proof afterwards. Wrong
    argument or field types raise TypeError; an empty rotation chain, an
    empty or mis-sized leaf set, an out-of-range ``old_total``, a leaf that
    is not exactly 32 bytes, a negative chain anchor, an illegal chain
    certificate, an illegal signature, or an over-long frame raises
    ValueError. The output for a given proof is unique and the encoding
    carries no network, storage or hidden state.
    """
    extension, rotations, old_sig, new_sig, old_total, leaves = (
        _check_rhe_fields(x)
    )

    extension_body = _rhe_extension_body(old_total, leaves)
    chain_body = encode_rotation_chain(rotations)
    old_signer_count = _check_history_proof_bundle_signature(
        old_sig, field="x.old_sig"
    )
    new_signer_count = _check_history_proof_bundle_signature(
        new_sig, field="x.new_sig"
    )
    if len(extension_body) > 0xFFFFFFFF:
        raise ValueError("rhe extension encoding too long")
    if len(chain_body) > 0xFFFFFFFF:
        raise ValueError("rhe rotation chain encoding too long")
    if old_signer_count > 0xFFFFFFFF or new_signer_count > 0xFFFFFFFF:
        raise ValueError("too many signer ids")

    buffer = bytearray(RHE_WIRE_TAG)
    buffer += len(extension_body).to_bytes(4, "big", signed=False)
    buffer += extension_body
    buffer += len(chain_body).to_bytes(4, "big", signed=False)
    buffer += chain_body
    for signature in (old_sig, new_sig):
        buffer += _encode_varint(signature.R)
        buffer += _encode_varint(signature.z)
        buffer += len(signature.signer_ids).to_bytes(4, "big", signed=False)
        for signer_id in signature.signer_ids:
            buffer += _encode_varint(signer_id)
    return bytes(buffer)


def decode_rhe(b: bytes) -> RHE:
    """Decode the canonical encoding produced by :func:`encode_rhe`.

    Accepts only the single canonical form: the tag ``b"ts/rhe/v1"``, a
    4-byte non-zero frame length followed by the extension body
    ``U64(old_total) || U64(n)`` and exactly ``n`` consecutive 32-byte leaf
    digests, a 4-byte non-zero frame length followed by bytes that
    :func:`decode_rotation_chain` accepts, and then the old and new
    signature frames, each the length-prefixed integers ``R`` and ``z``,
    the 4-byte non-zero signer count and exactly that many strictly
    increasing positive signer ids. A non-bytes argument raises TypeError;
    a wrong or missing tag, a zero or over-long frame length, a leaf count
    that does not match the body width, a non-32-byte leaf, an empty
    rotation chain, an illegal chain certificate, a zero ``R``, a
    non-canonical integer (leading zero or over-long length), a zero
    signer count, a non-positive or non-increasing signer id, truncation,
    or trailing bytes raises ValueError, as does any chain encoding that
    :func:`decode_rotation_chain` rejects. A successfully decoded proof
    re-encodes to exactly the input bytes.

    Decoding never verifies anything: the rotation chain certificates and
    the old and new root signatures are not checked and the two signatures
    need not belong to the chain's endpoint groups. A structurally legal
    proof whose chain or signatures do not verify is returned normally,
    and :func:`check_rhe` reports it as ``False``.
    """
    if not isinstance(b, bytes):
        raise TypeError("b must be bytes")
    if not b.startswith(RHE_WIRE_TAG):
        raise ValueError("bad rhe tag")
    offset = len(RHE_WIRE_TAG)

    extension_body, offset = _read_audit_proof_block(
        b, offset, what="rhe extension body"
    )
    if len(extension_body) < 16:
        raise ValueError("truncated rhe extension body")
    old_total = int.from_bytes(extension_body[:8], "big", signed=False)
    leaf_count = int.from_bytes(extension_body[8:16], "big", signed=False)
    leaf_bytes = extension_body[16:]
    if leaf_count == 0:
        raise ValueError("rhe extension leaves must be non-empty")
    if old_total <= 0 or old_total >= leaf_count:
        raise ValueError("rhe extension old_total out of range")
    if len(leaf_bytes) != leaf_count * SEAL_HISTORY_PROOF_DIGEST_SIZE:
        raise ValueError("rhe extension leaf width does not match count")
    leaves = tuple(
        leaf_bytes[
            index: index + SEAL_HISTORY_PROOF_DIGEST_SIZE
        ]
        for index in range(
            0,
            len(leaf_bytes),
            SEAL_HISTORY_PROOF_DIGEST_SIZE,
        )
    )
    extension = SealHistoryExtension(old_total=old_total, leaves=leaves)

    chain_body, offset = _read_audit_proof_block(
        b, offset, what="rhe rotation chain"
    )
    rotations = decode_rotation_chain(chain_body)

    old_sig, offset = _read_bundle_signature_frame(
        b, offset, what="rhe old"
    )
    new_sig, offset = _read_bundle_signature_frame(
        b, offset, what="rhe new"
    )
    if offset != len(b):
        raise ValueError("trailing bytes after rhe")

    proof = RHE(
        extension=extension,
        rotations=rotations,
        old_sig=old_sig,
        new_sig=new_sig,
    )
    if encode_rhe(proof) != b:
        raise ValueError("non-canonical rhe encoding")
    return proof


def check_rhe(x: RHE) -> bool:
    """Verify a cross-key append proof from nothing but its own contents.

    The two roots are rebuilt from ``x.extension`` with the ordinary seal
    history tree rules (the first ``old_total`` leaves give the old root
    and all leaves the new one, odd tails pairing with themselves). The
    rotation chain is first checked with :func:`verify_rotation_chain`;
    only if that holds are the root signatures checked: ``x.old_sig`` is
    verified on ``b"sh/r" || U64(old_total) || old_root`` under the first
    certificate's group parameters and key
    ``(q0, p0, g0, certificates[0].old)``, and ``x.new_sig`` on
    ``b"sh/r" || U64(n) || new_root`` under the last certificate's group
    parameters and key ``(qm, pm, gm, certificates[-1].new)``. Returns
    ``True`` only when the chain verifies and both endpoint root
    signatures verify; a well-formed proof with a broken chain, a
    mismatched or wrong-group signature, tampered leaves or a swapped
    signature pair returns ``False``.

    A non-:class:`RHE` argument or wrong field types raise TypeError; an
    empty rotation chain, an empty or mis-sized leaf set, an out-of-range
    ``old_total``, a structurally illegal chain certificate or signature,
    or a signature whose values do not fit its endpoint group raises
    TypeError/ValueError, exactly as :func:`verify_rotation_chain`,
    :func:`_validate_history_extension_structure` and
    :func:`verify_signature` do.
    """
    _extension, rotations, old_sig, new_sig, old_total, leaves = (
        _check_rhe_fields(x)
    )

    if not verify_rotation_chain(rotations):
        return False

    first = rotations.certificates[0]
    last = rotations.certificates[-1]
    old_root = _history_extension_root(leaves[:old_total])
    new_root = _history_extension_root(leaves)
    old_message = (
        SEAL_HISTORY_PROOF_ROOT_TAG + _history_proof_u64(old_total) + old_root
    )
    new_message = (
        SEAL_HISTORY_PROOF_ROOT_TAG
        + _history_proof_u64(len(leaves))
        + new_root
    )

    result = True
    if not verify_signature(
        old_message,
        old_sig,
        first.old,
        group_prime=first.p,
        generator=first.g,
        prime=first.q,
    ):
        result = False
    if not verify_signature(
        new_message,
        new_sig,
        last.new,
        group_prime=last.p,
        generator=last.g,
        prime=last.q,
    ):
        result = False
    return result
