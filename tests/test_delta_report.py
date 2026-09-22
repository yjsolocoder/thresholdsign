"""Tests for the threshold-Schnorr-authenticated delta chain diagnosis
statement: DeltaReport / dr_message / encode_dr / decode_dr / verify_dr."""

import dataclasses
import hashlib
import unittest

from thresholdsign import (
    AggregateSignature,
    AuditExtensionDeltaCheckpointChain,
    DeltaDiagnosis,
    DeltaReport,
    decode_dr,
    diagnose_delta_chain_segments,
    dr_message,
    encode_delta_chain_segments,
    encode_dr,
    partition_delta_chain,
    verify_dr,
)

from test_audit_chain import make_key, sign_message
from test_audit_extension_proof_bundle_codec import (
    make_other_key,
    make_records,
)
from test_audit_extension_delta_checkpoint_chain_segment import make_delta

MESSAGE_TAG = b"ts/dr/v1"
WIRE_TAG = b"ts/dr/w1"
EMPTY_U64 = (1 << 64) - 1
KIND_CODES = {"ok": 0, "segment": 1, "leaf": 2, "sig": 3, "proof": 4}


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def diagnosis_frame(diagnosis) -> bytes:
    """Independently build the D frame straight from the spec."""
    words = (
        1 if diagnosis.ok else 0,
        KIND_CODES[diagnosis.kind],
        EMPTY_U64 if diagnosis.segment is None else diagnosis.segment,
        EMPTY_U64 if diagnosis.proof is None else diagnosis.proof,
    )
    return b"".join(word.to_bytes(8, "big") for word in words)


def build_message(segments, diagnosis, public_key) -> bytes:
    """Independently build the dr message straight from the spec."""
    return (
        MESSAGE_TAG
        + hashlib.sha256(encode_delta_chain_segments(segments)).digest()
        + varint(public_key)
        + diagnosis_frame(diagnosis)
    )


def build_wire(report) -> bytes:
    """Independently build the dr wire format straight from the spec."""
    out = bytearray(WIRE_TAG)
    out += diagnosis_frame(report.diagnosis)
    out += varint(report.public_key)
    out += varint(report.signature.R)
    out += varint(report.signature.z)
    out += len(report.signature.signer_ids).to_bytes(4, "big")
    for signer_id in report.signature.signer_ids:
        out += varint(signer_id)
    return bytes(out)


def build_segments(cuts=(1, 3)):
    key = make_key()
    records = make_records(key, 7)
    splits = [(2, 3), (3, 5), (5, 6), (6, 7)]
    delta = make_delta(key, records, splits)
    return key, records, splits, delta, partition_delta_chain(delta, cuts)


def make_report(segments, key, *, diagnosis=None, public_key=None, seed=300):
    """Sign the set's diagnosis (or an explicitly given one) into a report."""
    if diagnosis is None:
        diagnosis = diagnose_delta_chain_segments(segments, key)
    if public_key is None:
        public_key = key.public_key
    signature = sign_message(
        key, dr_message(segments, diagnosis, public_key), seed=seed
    )
    return DeltaReport(diagnosis, public_key, signature)


class DeltaReportShapeTest(unittest.TestCase):
    def test_fields_in_order(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(DeltaReport)],
            ["diagnosis", "public_key", "signature"],
        )

    def test_frozen_positional_and_value_equal(self):
        diagnosis = DeltaDiagnosis(False, "leaf", 1, None)
        signature = AggregateSignature(R=11, z=22, signer_ids=(1, 3))
        report = DeltaReport(diagnosis, 77, signature)
        self.assertEqual(
            report,
            DeltaReport(
                diagnosis=diagnosis, public_key=77, signature=signature
            ),
        )
        self.assertEqual(
            (report.diagnosis, report.public_key, report.signature),
            (diagnosis, 77, signature),
        )
        self.assertNotEqual(report, DeltaReport(diagnosis, 78, signature))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            report.public_key = 78


class DrMessageTest(unittest.TestCase):
    def setUp(self):
        (
            self.key,
            self.records,
            self.splits,
            self.delta,
            self.segments,
        ) = build_segments()

    def test_message_matches_independent_spec_build(self):
        for diagnosis in (
            DeltaDiagnosis(True, "ok", None, None),
            DeltaDiagnosis(False, "segment", 0, 2),
            DeltaDiagnosis(False, "leaf", 1, None),
            DeltaDiagnosis(False, "sig", 2, None),
            DeltaDiagnosis(False, "proof", 3, 4),
        ):
            for public_key in (0, 1, self.key.public_key, 2**64):
                with self.subTest(diagnosis=diagnosis, public_key=public_key):
                    self.assertEqual(
                        dr_message(self.segments, diagnosis, public_key),
                        build_message(self.segments, diagnosis, public_key),
                    )

    def test_message_layout(self):
        diagnosis = DeltaDiagnosis(False, "proof", 1, 2)
        message = dr_message(self.segments, diagnosis, self.key.public_key)
        self.assertTrue(message.startswith(MESSAGE_TAG))
        body = message[len(MESSAGE_TAG):]
        self.assertEqual(
            body[:32],
            hashlib.sha256(
                encode_delta_chain_segments(self.segments)
            ).digest(),
        )
        # V(public_key) then the fixed 32-byte D frame at the tail.
        self.assertEqual(body[-32:], diagnosis_frame(diagnosis))
        self.assertEqual(len(message), len(build_message(
            self.segments, diagnosis, self.key.public_key
        )))

    def test_d_frame_words(self):
        self.assertEqual(
            diagnosis_frame(DeltaDiagnosis(True, "ok", None, None)),
            (1).to_bytes(8, "big")
            + (0).to_bytes(8, "big")
            + EMPTY_U64.to_bytes(8, "big")
            + EMPTY_U64.to_bytes(8, "big"),
        )
        self.assertEqual(
            diagnosis_frame(DeltaDiagnosis(False, "sig", 5, None)),
            (0).to_bytes(8, "big")
            + (3).to_bytes(8, "big")
            + (5).to_bytes(8, "big")
            + EMPTY_U64.to_bytes(8, "big"),
        )

    def test_zero_public_key_encodes_as_single_zero_byte(self):
        message = dr_message(
            self.segments, DeltaDiagnosis(True, "ok", None, None), 0
        )
        # tag || 32-byte digest || 04 00 00 00 01? no: V(0) = 00000001 00.
        self.assertEqual(
            message[len(MESSAGE_TAG) + 32: len(MESSAGE_TAG) + 32 + 5],
            b"\x00\x00\x00\x01\x00",
        )

    def test_type_errors(self):
        diagnosis = DeltaDiagnosis(True, "ok", None, None)
        for bad_segments in (
            list(self.segments),
            self.segments[0],
            "not segments",
            None,
            42,
        ):
            with self.assertRaises(TypeError, msg=repr(bad_segments)):
                dr_message(bad_segments, diagnosis, self.key.public_key)
        for bad_element in ("not a chain", None, 42, b"x"):
            with self.assertRaises(TypeError, msg=repr(bad_element)):
                dr_message((bad_element,), diagnosis, self.key.public_key)
        for bad_diagnosis in ("not a diagnosis", None, 42, b"x"):
            with self.assertRaises(TypeError, msg=repr(bad_diagnosis)):
                dr_message(
                    self.segments, bad_diagnosis, self.key.public_key
                )
        for bad_key in ("not a key", None, 1.5, True, b"x"):
            with self.assertRaises(TypeError, msg=repr(bad_key)):
                dr_message(self.segments, diagnosis, bad_key)

    def test_value_errors(self):
        diagnosis = DeltaDiagnosis(True, "ok", None, None)
        with self.assertRaises(ValueError):
            dr_message((), diagnosis, self.key.public_key)
        with self.assertRaises(ValueError):
            dr_message(self.segments, diagnosis, -1)
        for bad_diagnosis in (
            DeltaDiagnosis(True, "unknown", None, None),
            DeltaDiagnosis(True, "ok", -1, None),
            DeltaDiagnosis(True, "ok", None, EMPTY_U64),
            DeltaDiagnosis(False, "proof", EMPTY_U64, 0),
        ):
            with self.assertRaises(ValueError, msg=repr(bad_diagnosis)):
                dr_message(self.segments, bad_diagnosis, self.key.public_key)

    def test_diagnosis_field_type_errors(self):
        for bad in (
            DeltaDiagnosis(1, "ok", None, None),
            DeltaDiagnosis(True, 0, None, None),
            DeltaDiagnosis(True, "ok", "0", None),
            DeltaDiagnosis(True, "ok", None, True),
            DeltaDiagnosis(True, "ok", 1.5, None),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dr_message(self.segments, bad, self.key.public_key)


class EncodeDecodeDrTest(unittest.TestCase):
    def setUp(self):
        (
            self.key,
            self.records,
            self.splits,
            self.delta,
            self.segments,
        ) = build_segments()
        self.report = make_report(self.segments, self.key)

    def test_wire_matches_independent_spec_build(self):
        self.assertEqual(encode_dr(self.report), build_wire(self.report))

    def test_wire_layout(self):
        blob = encode_dr(self.report)
        self.assertTrue(blob.startswith(WIRE_TAG))
        self.assertEqual(
            blob[len(WIRE_TAG): len(WIRE_TAG) + 32],
            diagnosis_frame(self.report.diagnosis),
        )

    def test_round_trip_every_kind(self):
        cases = (
            (self.segments, DeltaDiagnosis(True, "ok", None, None)),
            ((self.segments[1], self.segments[0]),
             DeltaDiagnosis(False, "leaf", 0, None)),
        )
        for segments, diagnosis in cases:
            report = make_report(segments, self.key, diagnosis=diagnosis)
            with self.subTest(diagnosis=diagnosis):
                blob = encode_dr(report)
                decoded = decode_dr(blob)
                self.assertEqual(decoded, report)
                self.assertEqual(encode_dr(decoded), blob)

    def test_round_trip_all_diagnosis_shapes(self):
        signature = AggregateSignature(R=11, z=0, signer_ids=(1,))
        for diagnosis in (
            DeltaDiagnosis(True, "ok", None, None),
            DeltaDiagnosis(False, "segment", 0, 1),
            DeltaDiagnosis(False, "leaf", 2, None),
            DeltaDiagnosis(False, "sig", 3, None),
            DeltaDiagnosis(False, "proof", 4, 5),
            DeltaDiagnosis(False, "proof", EMPTY_U64 - 1, EMPTY_U64 - 1),
        ):
            for public_key in (0, 1, self.key.public_key, 2**64):
                report = DeltaReport(diagnosis, public_key, signature)
                with self.subTest(report=report):
                    self.assertEqual(decode_dr(encode_dr(report)), report)

    def test_encode_type_errors(self):
        for bad in ("not a report", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_dr(bad)
        good = self.report
        for bad_report in (
            DeltaReport("not a diagnosis", 1, good.signature),
            DeltaReport(good.diagnosis, "1", good.signature),
            DeltaReport(good.diagnosis, True, good.signature),
            DeltaReport(good.diagnosis, 1, "not a signature"),
            DeltaReport(good.diagnosis, 1, AggregateSignature("r", 0, (1,))),
            DeltaReport(
                good.diagnosis, 1, AggregateSignature(1, 0, [1, 2])
            ),
        ):
            with self.assertRaises(TypeError, msg=repr(bad_report)):
                encode_dr(bad_report)

    def test_encode_value_errors(self):
        good = self.report
        for bad_report in (
            DeltaReport(good.diagnosis, -1, good.signature),
            DeltaReport(
                DeltaDiagnosis(True, "bogus", None, None),
                1,
                good.signature,
            ),
            DeltaReport(
                DeltaDiagnosis(True, "ok", EMPTY_U64, None),
                1,
                good.signature,
            ),
            DeltaReport(
                good.diagnosis, 1, AggregateSignature(0, 0, (1,))
            ),
            DeltaReport(
                good.diagnosis, 1, AggregateSignature(1, -1, (1,))
            ),
            DeltaReport(
                good.diagnosis, 1, AggregateSignature(1, 0, ())
            ),
            DeltaReport(
                good.diagnosis, 1, AggregateSignature(1, 0, (0,))
            ),
            DeltaReport(
                good.diagnosis, 1, AggregateSignature(1, 0, (2, 2))
            ),
            DeltaReport(
                good.diagnosis, 1, AggregateSignature(1, 0, (3, 1))
            ),
        ):
            with self.assertRaises(ValueError, msg=repr(bad_report)):
                encode_dr(bad_report)

    def test_decode_type_error(self):
        for bad in ("not bytes", None, 42, bytearray(b"x"), object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                decode_dr(bad)

    def test_decode_value_errors(self):
        blob = encode_dr(self.report)
        bad_blobs = [
            b"",
            b"ts/dr/w2" + blob[len(WIRE_TAG):],
            blob[: len(WIRE_TAG) + 31],  # truncated D frame
            blob[:-1],  # truncated tail
            blob + b"\x00",  # trailing bytes
            # ok word out of range
            WIRE_TAG + (2).to_bytes(8, "big") + blob[len(WIRE_TAG) + 8:],
            # kind word out of range
            WIRE_TAG
            + blob[len(WIRE_TAG): len(WIRE_TAG) + 8]
            + (5).to_bytes(8, "big")
            + blob[len(WIRE_TAG) + 16:],
        ]
        for bad in bad_blobs:
            with self.assertRaises(ValueError, msg=repr(bad[:20])):
                decode_dr(bad)

    def test_decode_bad_signature_frame(self):
        good = encode_dr(self.report)
        prefix_len = len(WIRE_TAG) + 32 + len(varint(self.report.public_key))
        head = good[:prefix_len]
        # R == 0
        with self.assertRaises(ValueError):
            decode_dr(head + varint(0) + good[prefix_len + len(varint(self.report.signature.R)):])
        # zero signer count
        with self.assertRaises(ValueError):
            decode_dr(
                head
                + varint(self.report.signature.R)
                + varint(self.report.signature.z)
                + (0).to_bytes(4, "big")
            )
        # non-increasing signer ids
        with self.assertRaises(ValueError):
            decode_dr(
                head
                + varint(self.report.signature.R)
                + varint(self.report.signature.z)
                + (2).to_bytes(4, "big")
                + varint(2)
                + varint(2)
            )
        # non-positive signer id
        with self.assertRaises(ValueError):
            decode_dr(
                head
                + varint(self.report.signature.R)
                + varint(self.report.signature.z)
                + (1).to_bytes(4, "big")
                + varint(0)
            )
        # non-canonical integer (leading zero)
        with self.assertRaises(ValueError):
            decode_dr(head + b"\x00\x00\x00\x02\x00\x01" + b"\x00" * 8)

    def test_decode_restores_structure_only(self):
        # A structurally legal report whose diagnosis does not match the
        # segments still decodes; verify_dr is the judge.
        diagnosis = DeltaDiagnosis(False, "proof", 9, 9)
        report = DeltaReport(
            diagnosis, self.key.public_key, self.report.signature
        )
        blob = encode_dr(report)
        self.assertEqual(decode_dr(blob), report)
        self.assertIs(verify_dr(decode_dr(blob), self.segments, self.key), False)


class VerifyDrTest(unittest.TestCase):
    def setUp(self):
        (
            self.key,
            self.records,
            self.splits,
            self.delta,
            self.segments,
        ) = build_segments()
        self.diagnosis = diagnose_delta_chain_segments(self.segments, self.key)
        self.report = make_report(self.segments, self.key)

    def test_ok_report_verifies(self):
        self.assertEqual(self.diagnosis, DeltaDiagnosis(True, "ok", None, None))
        self.assertIs(verify_dr(self.report, self.segments, self.key), True)

    def test_failing_diagnosis_report_verifies(self):
        bad_segments = (self.segments[1], self.segments[0])
        diagnosis = diagnose_delta_chain_segments(bad_segments, self.key)
        self.assertEqual(diagnosis, DeltaDiagnosis(False, "leaf", 0, None))
        report = make_report(bad_segments, self.key)
        self.assertIs(verify_dr(report, bad_segments, self.key), True)

    def test_every_cut_position_report_verifies(self):
        n = len(self.delta.additions) + 1
        for mask in range(1 << (n - 1)):
            cuts = tuple(
                cut for cut in range(1, n) if mask & (1 << (cut - 1))
            )
            segments = partition_delta_chain(self.delta, cuts)
            report = make_report(segments, self.key, seed=300 + mask)
            with self.subTest(cuts=cuts):
                self.assertIs(verify_dr(report, segments, self.key), True)

    def test_restated_diagnosis_is_false(self):
        for wrong in (
            DeltaDiagnosis(False, "leaf", 0, None),
            DeltaDiagnosis(False, "proof", 0, 0),
            DeltaDiagnosis(False, "segment", 1, 1),
            DeltaDiagnosis(False, "sig", 2, None),
        ):
            report = make_report(self.segments, self.key, diagnosis=wrong)
            with self.subTest(diagnosis=wrong):
                self.assertIs(
                    verify_dr(report, self.segments, self.key), False
                )

    def test_other_segments_are_false(self):
        other = (self.segments[1], self.segments[0])
        self.assertIs(verify_dr(self.report, other, self.key), False)
        self.assertIs(
            verify_dr(self.report, (self.delta,), self.key), False
        )

    def test_other_key_is_false(self):
        self.assertIs(
            verify_dr(self.report, self.segments, make_other_key()), False
        )

    def test_wrong_public_key_is_false(self):
        other_public_key = make_other_key().public_key
        # Signed by self.key but declaring another key.
        report = make_report(
            self.segments, self.key, public_key=other_public_key
        )
        self.assertIs(verify_dr(report, self.segments, self.key), False)
        # The valid report with its public key swapped after signing.
        swapped = DeltaReport(
            self.report.diagnosis, other_public_key, self.report.signature
        )
        self.assertIs(verify_dr(swapped, self.segments, self.key), False)

    def test_tampered_signature_is_false(self):
        good = self.report.signature
        other = sign_message(self.key, b"unrelated", seed=5)
        field_prime = self.key.result.commitment.field_prime
        for bad_signature in (
            # Every value stays structurally legal for the group.
            AggregateSignature(other.R, good.z, good.signer_ids),
            AggregateSignature(
                good.R, (good.z + 1) % field_prime, good.signer_ids
            ),
            AggregateSignature(good.R, good.z, (2,)),
            other,
        ):
            report = DeltaReport(
                self.report.diagnosis, self.report.public_key, bad_signature
            )
            with self.subTest(signature=bad_signature):
                self.assertIs(
                    verify_dr(report, self.segments, self.key), False
                )

    def test_decoded_report_still_verifies(self):
        self.assertIs(
            verify_dr(
                decode_dr(encode_dr(self.report)), self.segments, self.key
            ),
            True,
        )

    def test_type_errors(self):
        for bad in ("not a report", None, 42, b"x"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_dr(bad, self.segments, self.key)
        for bad_segments in (list(self.segments), self.segments[0], None, 42):
            with self.assertRaises(TypeError, msg=repr(bad_segments)):
                verify_dr(self.report, bad_segments, self.key)
        for bad_key in ("not a key", None, 42, b"x"):
            with self.assertRaises(TypeError, msg=repr(bad_key)):
                verify_dr(self.report, self.segments, bad_key)

    def test_value_errors(self):
        with self.assertRaises(ValueError):
            verify_dr(self.report, (), self.key)
        bad_report = DeltaReport(
            DeltaDiagnosis(True, "bogus", None, None),
            self.key.public_key,
            self.report.signature,
        )
        with self.assertRaises(ValueError):
            verify_dr(bad_report, self.segments, self.key)
        bad_report = DeltaReport(
            self.report.diagnosis, -1, self.report.signature
        )
        with self.assertRaises(ValueError):
            verify_dr(bad_report, self.segments, self.key)


if __name__ == "__main__":
    unittest.main()
