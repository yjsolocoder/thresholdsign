"""Tests for the threshold-Schnorr-authenticated whole-report seal:
ReportSeal / seal_message / encode_seal / decode_seal / verify_seal."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    NonceLeak,
    NonceLeakReport,
    ReportSeal,
    SigningAudit,
    aggregate_signature,
    create_signature_share,
    create_signing_nonce_commitment,
    create_signing_round,
    decode_seal,
    encode_nonce_leak_report,
    encode_seal,
    seal_message,
    verify_nonce_leak_report,
    verify_seal,
)

from test_nonce_reuse import (
    FIELD_PRIME,
    GENERATOR,
    GROUP_PRIME,
    MESSAGE_A,
    MESSAGE_B,
    fixed_random,
    make_key,
    make_record,
)
from test_nonce_leak_codec import make_leak, make_other_key
from thresholdsign import recover_leaks

SEAL_TAG = b"ts/nlrs/v1"
WIRE_TAG = b"ts/nlrs/w1"
NLR_WIRE_TAG = b"thresholdsign/nlr/v1"


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def build_message(report: NonceLeakReport, public_key: int) -> bytes:
    """Independently build the sealed message straight from the spec."""
    encoded = encode_nonce_leak_report(report)
    return SEAL_TAG + hashlib.sha256(encoded).digest() + varint(public_key)


def build_wire(seal: ReportSeal) -> bytes:
    """Independently build the report-seal wire format straight from the spec."""
    encoded_report = encode_nonce_leak_report(seal.report)
    signature = seal.signature
    out = bytearray(WIRE_TAG)
    out += u32(len(encoded_report))
    out += encoded_report
    out += varint(signature.R)
    out += varint(signature.z)
    out += u32(len(signature.signer_ids))
    for signer_id in signature.signer_ids:
        out += varint(signer_id)
    return bytes(out)


def make_seal(report: NonceLeakReport, key, signer_ids=(1, 3), seed=500) -> ReportSeal:
    """Seal ``report`` with a real threshold signature of ``key``."""
    message = seal_message(report, key.public_key)
    commitments = []
    nonce_map = {}
    for index, signer_id in enumerate(signer_ids):
        commitment, nonce = create_signing_nonce_commitment(
            signer_id,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            randbelow=fixed_random(seed + index),
        )
        commitments.append(commitment)
        nonce_map[signer_id] = nonce
    round_info = create_signing_round(message, signer_ids, commitments, key)
    shares = [
        create_signature_share(
            signer_id,
            key.result.shares[key.result.participant_ids.index(signer_id)].y,
            nonce_map[signer_id],
            round_info,
            key,
        )
        for signer_id in signer_ids
    ]
    signature = aggregate_signature(shares, round_info, key)
    assert isinstance(signature, AggregateSignature)
    return ReportSeal(report, signature)


def make_other_leak(key, nonce=888):
    """A second real NonceLeak for signer 1 under a different reused nonce."""
    record_a = make_record(
        key, MESSAGE_A + b"/other", seed=300, nonces={1: nonce}
    )
    record_b = make_record(
        key, MESSAGE_B + b"/other", seed=400, nonces={1: nonce}
    )
    return recover_leaks([record_a, record_b], key)[0]


def synthetic(signer_id, commitment, share=7):
    return NonceLeak(
        signer_id,
        commitment,
        share,
        (
            SigningAudit(f"a-{signer_id}-{commitment}".encode()),
            SigningAudit(f"b-{signer_id}-{commitment}".encode()),
        ),
    )


class ReportSealValueTest(unittest.TestCase):
    def test_frozen_fields_value_equality(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(ReportSeal)],
            ["report", "signature"],
        )
        report = NonceLeakReport((synthetic(1, 10),))
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        seal = ReportSeal(report, signature)  # positional construction
        self.assertEqual(seal, ReportSeal(report, signature))
        self.assertEqual(
            seal,
            ReportSeal(report=report, signature=signature),
        )
        self.assertEqual(seal.report, report)
        self.assertEqual(seal.signature, signature)
        self.assertNotEqual(
            seal, ReportSeal(NonceLeakReport((synthetic(2, 20),)), signature)
        )
        self.assertNotEqual(
            seal, ReportSeal(report, AggregateSignature(5, 8, (1, 3)))
        )
        self.assertEqual(hash(seal), hash(ReportSeal(report, signature)))
        with self.assertRaises(FrozenInstanceError):
            seal.report = report

    def test_construction_does_not_validate(self):
        # The container is a plain value: an illegal report or signature
        # both construct; the codec and verifier reject them.
        ReportSeal(NonceLeakReport(()), AggregateSignature(0, -1, ()))
        ReportSeal("not-a-report", "not-a-signature")


class SealMessageTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.report = NonceLeakReport((make_leak(self.key),))

    def test_matches_independent_builder(self):
        self.assertEqual(
            seal_message(self.report, self.key.public_key),
            build_message(self.report, self.key.public_key),
        )

    def test_layout(self):
        message = seal_message(self.report, self.key.public_key)
        self.assertTrue(message.startswith(SEAL_TAG))
        offset = len(SEAL_TAG)
        encoded = encode_nonce_leak_report(self.report)
        self.assertEqual(
            message[offset:offset + 32], hashlib.sha256(encoded).digest()
        )
        offset += 32
        length = int.from_bytes(message[offset:offset + 4], "big")
        self.assertEqual(
            message[offset + 4:],
            self.key.public_key.to_bytes(length, "big"),
        )

    def test_zero_public_key_encodes_as_single_zero_byte(self):
        message = seal_message(self.report, 0)
        self.assertEqual(message[len(SEAL_TAG) + 32:], u32(1) + b"\x00")

    def test_message_is_unique_and_stateless(self):
        first = seal_message(self.report, self.key.public_key)
        second = seal_message(self.report, self.key.public_key)
        self.assertEqual(first, second)
        self.assertNotEqual(
            first, seal_message(self.report, self.key.public_key + 1)
        )

    def test_binds_the_report_encoding(self):
        other = NonceLeakReport((synthetic(1, 10),))
        self.assertNotEqual(
            seal_message(self.report, self.key.public_key),
            seal_message(other, self.key.public_key),
        )

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            seal_message((make_leak(self.key),), self.key.public_key)
        with self.assertRaises(TypeError):
            seal_message("report", self.key.public_key)
        with self.assertRaises(TypeError):
            seal_message(self.report, "key")
        with self.assertRaises(TypeError):
            seal_message(self.report, True)

    def test_structure_errors(self):
        with self.assertRaises(ValueError):
            seal_message(NonceLeakReport(()), self.key.public_key)
        with self.assertRaises(ValueError):
            seal_message(self.report, -1)


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.leak = make_leak(self.key)
        self.report = NonceLeakReport((self.leak,))
        self.seal = make_seal(self.report, self.key)

    def test_round_trip_real_seal(self):
        wire = encode_seal(self.seal)
        decoded = decode_seal(wire)
        self.assertEqual(decoded, self.seal)
        self.assertEqual(encode_seal(decoded), wire)
        self.assertIsInstance(decoded, ReportSeal)
        self.assertIsInstance(decoded.report, NonceLeakReport)
        self.assertIsInstance(decoded.signature, AggregateSignature)

    def test_encoding_matches_independent_builder(self):
        self.assertEqual(encode_seal(self.seal), build_wire(self.seal))

    def test_starts_with_tag_and_layout(self):
        wire = encode_seal(self.seal)
        self.assertTrue(wire.startswith(WIRE_TAG))
        offset = len(WIRE_TAG)
        encoded = encode_nonce_leak_report(self.report)
        self.assertEqual(wire[offset:offset + 4], u32(len(encoded)))
        offset += 4
        self.assertEqual(wire[offset:offset + len(encoded)], encoded)

    def test_multi_finding_report_round_trip(self):
        # A synthetic second finding keeps the ordering structure valid
        # without needing a second real reused-nonce pair; encode/decode
        # never verifies findings.
        second = synthetic(self.leak.signer_id + 2, self.leak.commitment + 1)
        report = NonceLeakReport((self.leak, second))
        seal = ReportSeal(
            report,
            AggregateSignature(R=486, z=1858, signer_ids=(1, 3)),
        )
        wire = encode_seal(seal)
        self.assertEqual(decode_seal(wire), seal)
        self.assertEqual(encode_seal(decode_seal(wire)), wire)

    def test_large_signature_integers_round_trip(self):
        signature = AggregateSignature(
            R=(1 << 256) - 77,
            z=(1 << 200) + 9,
            signer_ids=(1, 3, (1 << 64) + 5),
        )
        seal = ReportSeal(self.report, signature)
        decoded = decode_seal(encode_seal(seal))
        self.assertEqual(decoded, seal)

    def test_zero_z_round_trips(self):
        seal = ReportSeal(
            self.report, AggregateSignature(R=486, z=0, signer_ids=(1, 3))
        )
        wire = encode_seal(seal)
        self.assertEqual(decode_seal(wire), seal)

    def test_encoding_is_structure_only(self):
        # Opaque findings and a signature that seals nothing are both
        # transported verbatim; verify_seal remains the sole verifier.
        item = NonceLeak(
            9,
            3,
            11,
            (SigningAudit(b"not-an-audit"), SigningAudit(b"still-not")),
        )
        seal = ReportSeal(
            NonceLeakReport((item,)),
            AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
        )
        decoded = decode_seal(encode_seal(seal))
        self.assertEqual(decoded, seal)
        self.assertEqual(decoded.report.items[0].receipts[0].payload, b"not-an-audit")


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.report = NonceLeakReport((make_leak(self.key),))
        self.signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))

    def test_non_seal_type_error(self):
        with self.assertRaises(TypeError):
            encode_seal((self.report, self.signature))
        with self.assertRaises(TypeError):
            encode_seal(self.report)

    def test_field_type_errors(self):
        for bad_seal in (
            ReportSeal("report", self.signature),
            ReportSeal(self.report, "signature"),
            ReportSeal(self.report, AggregateSignature(True, 7, (1, 3))),
            ReportSeal(self.report, AggregateSignature(5, True, (1, 3))),
            ReportSeal(self.report, AggregateSignature(5, 7, [1, 3])),
            ReportSeal(self.report, AggregateSignature(5, 7, (1, True))),
        ):
            with self.assertRaises(TypeError, msg=repr(bad_seal)):
                encode_seal(bad_seal)

    def test_report_structure_value_error(self):
        with self.assertRaises(ValueError):
            encode_seal(ReportSeal(NonceLeakReport(()), self.signature))
        first = synthetic(2, 20)
        second = synthetic(1, 10)
        with self.assertRaises(ValueError):
            encode_seal(
                ReportSeal(NonceLeakReport((first, second)), self.signature)
            )

    def test_signature_structure_value_error(self):
        for bad_signature in (
            AggregateSignature(0, 7, (1, 3)),      # R must be positive
            AggregateSignature(-1, 7, (1, 3)),
            AggregateSignature(5, -1, (1, 3)),     # z non-negative
            AggregateSignature(5, 7, ()),          # at least one signer
            AggregateSignature(5, 7, (0, 3)),      # positive ids
            AggregateSignature(5, 7, (3, 1)),      # ascending
            AggregateSignature(5, 7, (1, 1)),      # unique
        ):
            with self.assertRaises(ValueError, msg=repr(bad_signature)):
                encode_seal(ReportSeal(self.report, bad_signature))


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.report = NonceLeakReport((make_leak(self.key),))
        self.seal = make_seal(self.report, self.key)
        self.wire = encode_seal(self.seal)

    def test_non_bytes_type_error(self):
        with self.assertRaises(TypeError):
            decode_seal("not bytes")
        with self.assertRaises(TypeError):
            decode_seal(bytearray(self.wire))

    def test_bad_tag(self):
        with self.assertRaises(ValueError):
            decode_seal(b"ts/nlrs/w2" + self.wire[len(WIRE_TAG):])
        with self.assertRaises(ValueError):
            decode_seal(b"x" + self.wire[1:])

    def test_truncation(self):
        for cut in range(len(WIRE_TAG), len(self.wire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_seal(self.wire[:cut])

    def test_header_truncation(self):
        with self.assertRaises(ValueError):
            decode_seal(WIRE_TAG)
        with self.assertRaises(ValueError):
            decode_seal(WIRE_TAG + b"\x00\x00")

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_seal(self.wire + b"\x00")

    def test_zero_or_oversized_report_length(self):
        offset = len(WIRE_TAG)
        with self.assertRaises(ValueError):
            decode_seal(self.wire[:offset] + u32(0))
        with self.assertRaises(ValueError):
            decode_seal(self.wire[:offset] + u32(0xFFFFFFFF) + b"a")

    def test_report_frame_truncated(self):
        offset = len(WIRE_TAG) + 4
        encoded = encode_nonce_leak_report(self.report)
        with self.assertRaises(ValueError):
            decode_seal(
                self.wire[:len(WIRE_TAG)]
                + u32(len(encoded))
                + encoded[:-1]
            )

    def test_nested_report_bad_tag_rejected(self):
        with self.assertRaises(ValueError):
            decode_seal(WIRE_TAG + frame(b"thresholdsign/nlr/v2"))

    def test_nested_report_non_canonical_rejected(self):
        encoded = encode_nonce_leak_report(self.report)
        # Flip the report item count so the nested framing no longer
        # round-trips canonically.
        count_offset = len(NLR_WIRE_TAG)
        bad = (
            encoded[:count_offset]
            + u32(99)
            + encoded[count_offset + 4:]
        )
        with self.assertRaises(ValueError):
            decode_seal(WIRE_TAG + frame(bad))

    def test_zero_R_rejected(self):
        encoded = encode_nonce_leak_report(self.report)
        bad = (
            WIRE_TAG
            + frame(encoded)
            + varint(0)
            + varint(7)
            + u32(2)
            + varint(1)
            + varint(3)
        )
        with self.assertRaises(ValueError):
            decode_seal(bad)

    def test_non_canonical_varint_rejected(self):
        encoded = encode_nonce_leak_report(self.report)
        # A two-byte R body starting with 00 carries a forbidden leading zero.
        bad = (
            WIRE_TAG
            + frame(encoded)
            + u32(2) + b"\x00\x05"
            + varint(7)
            + u32(1)
            + varint(1)
        )
        with self.assertRaises(ValueError):
            decode_seal(bad)

    def test_zero_signer_count_rejected(self):
        encoded = encode_nonce_leak_report(self.report)
        bad = (
            WIRE_TAG
            + frame(encoded)
            + varint(5)
            + varint(7)
            + u32(0)
        )
        with self.assertRaises(ValueError):
            decode_seal(bad)

    def test_signer_count_mismatch_rejected(self):
        encoded = encode_nonce_leak_report(self.report)
        head = WIRE_TAG + frame(encoded) + varint(5) + varint(7)
        # Declares two ids, one follows.
        with self.assertRaises(ValueError):
            decode_seal(head + u32(2) + varint(1))
        # Declares one id, two follow (the second varint becomes trailing).
        with self.assertRaises(ValueError):
            decode_seal(head + u32(1) + varint(1) + varint(3))

    def test_unordered_duplicate_or_zero_ids_rejected(self):
        encoded = encode_nonce_leak_report(self.report)
        head = WIRE_TAG + frame(encoded) + varint(5) + varint(7)
        for ids in ((3, 1), (1, 1), (0, 3)):
            body = head + u32(len(ids)) + b"".join(varint(i) for i in ids)
            with self.assertRaises(ValueError, msg=repr(ids)):
                decode_seal(body)


class VerifySealTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.leak = make_leak(self.key)
        self.report = NonceLeakReport((self.leak,))
        self.seal = make_seal(self.report, self.key)

    def test_real_seal_verifies(self):
        self.assertTrue(verify_seal(self.seal, self.key))

    def test_decoded_seal_verifies(self):
        decoded = decode_seal(encode_seal(self.seal))
        self.assertTrue(verify_seal(decoded, self.key))

    def test_seal_message_is_what_the_signature_covers(self):
        from thresholdsign import verify_signature

        self.assertTrue(
            verify_signature(
                seal_message(self.report, self.key.public_key),
                self.seal.signature,
                self.key.public_key,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            )
        )

    def test_tampered_finding_returns_false(self):
        tampered = dataclasses.replace(
            self.leak, share=(self.leak.share + 1) % FIELD_PRIME
        )
        self.assertFalse(
            verify_seal(
                ReportSeal(NonceLeakReport((tampered,)), self.seal.signature),
                self.key,
            )
        )

    def test_tampered_signature_returns_false(self):
        tampered = dataclasses.replace(
            self.seal.signature, z=(self.seal.signature.z + 1) % FIELD_PRIME
        )
        self.assertFalse(
            verify_seal(ReportSeal(self.report, tampered), self.key)
        )

    def test_signature_over_another_report_returns_false(self):
        # A different, genuinely verifying report: the report check passes
        # but the signature binds the original report's digest.
        other_report = NonceLeakReport((make_other_leak(self.key),))
        self.assertTrue(verify_nonce_leak_report(other_report, self.key))
        self.assertFalse(
            verify_seal(
                ReportSeal(other_report, self.seal.signature), self.key
            )
        )

    def test_foreign_key_returns_false(self):
        other_key = make_other_key()
        self.assertNotEqual(other_key.public_key, self.key.public_key)
        self.assertFalse(verify_seal(self.seal, other_key))

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            verify_seal((self.report, self.seal.signature), self.key)
        with self.assertRaises(TypeError):
            verify_seal("seal", self.key)
        with self.assertRaises(TypeError):
            verify_seal(
                ReportSeal(self.report, "signature"), self.key
            )
        with self.assertRaises(TypeError):
            verify_seal(self.seal, "key")
        with self.assertRaises(TypeError):
            verify_seal(self.seal, None)

    def test_structure_errors(self):
        with self.assertRaises(ValueError):
            verify_seal(
                ReportSeal(NonceLeakReport(()), self.seal.signature),
                self.key,
            )
        with self.assertRaises(ValueError):
            verify_seal(
                ReportSeal(
                    self.report, AggregateSignature(0, 7, (1, 3))
                ),
                self.key,
            )
        with self.assertRaises(ValueError):
            verify_seal(
                ReportSeal(self.report, AggregateSignature(5, 7, ())),
                self.key,
            )


if __name__ == "__main__":
    unittest.main()
