"""Tests for the self-contained delta report bundle transport:
DeltaReportBundle / encode_delta_report_bundle /
decode_delta_report_bundle / verify_delta_report_bundle."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    AuditExtensionDeltaCheckpointChain,
    DeltaDiagnosis,
    DeltaReport,
    DeltaReportBundle,
    decode_delta_report_bundle,
    decode_dr,
    diagnose_delta_chain_segments,
    dr_message,
    encode_audit_extension_delta_checkpoint_chain,
    encode_delta_report_bundle,
    encode_dr,
    partition_delta_chain,
    verify_delta_report_bundle,
)

from test_audit_chain import make_key, sign_message
from test_audit_extension_proof_bundle_codec import (
    make_other_key,
    make_records,
)
from test_audit_extension_delta_checkpoint_chain_segment import make_delta

TAG = b"thresholdsign/delta-report-bundle/v1"


def u32(value):
    return value.to_bytes(4, "big")


def build_wire(bundle):
    """Independently build the bundle wire format straight from the spec."""
    out = bytearray(TAG)
    out += u32(len(bundle.segments))
    for segment in bundle.segments:
        frame = encode_audit_extension_delta_checkpoint_chain(segment)
        out += u32(len(frame))
        out += frame
    report_frame = encode_dr(bundle.report)
    out += u32(len(report_frame))
    out += report_frame
    return bytes(out)


def build_segments(cuts=(1, 3)):
    key = make_key()
    records = make_records(key, 7)
    splits = [(2, 3), (3, 5), (5, 6), (6, 7)]
    delta = make_delta(key, records, splits)
    return key, delta, partition_delta_chain(delta, cuts)


def make_report(segments, diagnosis, key, *, seed=100):
    message = dr_message(segments, diagnosis, key.public_key)
    return DeltaReport(
        diagnosis, key.public_key, sign_message(key, message, seed=seed)
    )


def make_bundle(segments, key, *, seed=100):
    diagnosis = diagnose_delta_chain_segments(segments, key)
    return DeltaReportBundle(segments, make_report(segments, diagnosis, key, seed=seed))


class DeltaReportBundleShapeTest(unittest.TestCase):
    def test_fields_in_order(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(DeltaReportBundle)],
            ["segments", "report"],
        )

    def test_frozen_positional_and_value_equal(self):
        key, _delta, segments = build_segments()
        report = make_report(segments, DeltaDiagnosis(True, "ok", None, None), key)
        bundle = DeltaReportBundle(segments, report)
        self.assertEqual(
            bundle, DeltaReportBundle(segments=segments, report=report)
        )
        self.assertEqual((bundle.segments, bundle.report), (segments, report))
        self.assertEqual(bundle, DeltaReportBundle(segments, report))
        self.assertNotEqual(
            bundle, DeltaReportBundle(segments[::-1], report)
        )
        self.assertEqual(
            {bundle, DeltaReportBundle(segments, report)},
            {DeltaReportBundle(segments, report)},
        )
        with self.assertRaises(FrozenInstanceError):
            bundle.report = report


class EncodeDecodeBundleTest(unittest.TestCase):
    def setUp(self):
        self.key, self.delta, self.segments = build_segments()
        self.report = make_report(
            self.segments, DeltaDiagnosis(True, "ok", None, None), self.key
        )
        self.bundle = DeltaReportBundle(self.segments, self.report)

    def test_wire_matches_independent_spec_build(self):
        self.assertEqual(encode_delta_report_bundle(self.bundle), build_wire(self.bundle))
        self.assertTrue(encode_delta_report_bundle(self.bundle).startswith(TAG))

    def test_wire_layout_is_tag_count_frames_then_report_frame(self):
        blob = encode_delta_report_bundle(self.bundle)
        offset = len(TAG)
        self.assertEqual(blob[offset:offset + 4], u32(len(self.segments)))
        offset += 4
        for segment in self.segments:
            frame = encode_audit_extension_delta_checkpoint_chain(segment)
            self.assertEqual(blob[offset:offset + 4], u32(len(frame)))
            offset += 4
            self.assertEqual(blob[offset:offset + len(frame)], frame)
            offset += len(frame)
        report_frame = encode_dr(self.report)
        self.assertEqual(blob[offset:offset + 4], u32(len(report_frame)))
        offset += 4
        self.assertEqual(blob[offset:offset + len(report_frame)], report_frame)
        offset += len(report_frame)
        self.assertEqual(offset, len(blob))

    def test_round_trip_byte_for_byte(self):
        cases = (
            self.bundle,
            DeltaReportBundle((self.segments[0],), self.report),
            DeltaReportBundle(tuple(reversed(self.segments)), self.report),
            DeltaReportBundle(
                self.segments,
                DeltaReport(
                    DeltaDiagnosis(False, "proof", 1, 2),
                    self.key.public_key,
                    self.report.signature,
                ),
            ),
            DeltaReportBundle(
                self.segments,
                DeltaReport(
                    DeltaDiagnosis(True, "ok", None, None),
                    0,
                    self.report.signature,
                ),
            ),
        )
        for bundle in cases:
            with self.subTest(bundle=bundle.report.diagnosis.kind):
                blob = encode_delta_report_bundle(bundle)
                decoded = decode_delta_report_bundle(blob)
                self.assertEqual(decoded, bundle)
                self.assertEqual(encode_delta_report_bundle(decoded), blob)

    def test_order_is_preserved(self):
        shuffled = DeltaReportBundle(
            (self.segments[2], self.segments[0]), self.report
        )
        restored = decode_delta_report_bundle(
            encode_delta_report_bundle(shuffled)
        )
        self.assertEqual(restored.segments, shuffled.segments)
        self.assertNotEqual(restored.segments, self.segments)

    def test_report_frame_decodes_standalone(self):
        blob = encode_delta_report_bundle(self.bundle)
        offset = len(TAG) + 4
        for _ in self.segments:
            length = int.from_bytes(blob[offset:offset + 4], "big")
            offset += 4 + length
        length = int.from_bytes(blob[offset:offset + 4], "big")
        frame = blob[offset + 4:offset + 4 + length]
        self.assertEqual(decode_dr(bytes(frame)), self.report)

    def test_encode_non_bundle_type_error(self):
        for bad in ("x", None, 42, b"x", object(), (self.segments, self.report)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_delta_report_bundle(bad)

    def test_encode_bad_field_types(self):
        report = self.report
        for bad in (
            DeltaReportBundle(list(self.segments), report),
            DeltaReportBundle(self.segments[0], report),
            DeltaReportBundle("x", report),
            DeltaReportBundle(None, report),
            DeltaReportBundle(("x",), report),
            DeltaReportBundle((None,), report),
            DeltaReportBundle((self.segments[0], 42), report),
            DeltaReportBundle(self.segments, "x"),
            DeltaReportBundle(self.segments, None),
            DeltaReportBundle(self.segments, 42),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_delta_report_bundle(bad)

    def test_encode_empty_segments_value_error(self):
        with self.assertRaises(ValueError):
            encode_delta_report_bundle(
                DeltaReportBundle((), self.report)
            )

    def test_encode_nested_segment_value_error(self):
        good = self.segments[0]
        bad_segment = AuditExtensionDeltaCheckpointChain(
            good.first, ((),) + good.additions[1:], good.signatures
        )
        with self.assertRaises(ValueError):
            encode_delta_report_bundle(
                DeltaReportBundle((bad_segment,), self.report)
            )

    def test_encode_nested_segment_type_error(self):
        good = self.segments[0]
        bad_segment = AuditExtensionDeltaCheckpointChain(
            "not a proof", good.additions, good.signatures
        )
        with self.assertRaises(TypeError):
            encode_delta_report_bundle(
                DeltaReportBundle((bad_segment,), self.report)
            )

    def test_encode_nested_report_value_error(self):
        bad_report = DeltaReport(
            DeltaDiagnosis(False, "ok", None, None),
            self.report.public_key,
            self.report.signature,
        )
        with self.assertRaises(ValueError):
            encode_delta_report_bundle(
                DeltaReportBundle(self.segments, bad_report)
            )

    def test_encode_nested_report_type_error(self):
        bad_report = DeltaReport(
            self.report.diagnosis, True, self.report.signature
        )
        with self.assertRaises(TypeError):
            encode_delta_report_bundle(
                DeltaReportBundle(self.segments, bad_report)
            )


class DecodeBundleErrorTest(unittest.TestCase):
    def setUp(self):
        self.key, self.delta, self.segments = build_segments()
        self.report = make_report(
            self.segments, DeltaDiagnosis(True, "ok", None, None), self.key
        )
        self.bundle = DeltaReportBundle(self.segments, self.report)
        self.blob = encode_delta_report_bundle(self.bundle)

    def test_non_bytes_type_error(self):
        for bad in ("x", bytearray(self.blob), None, 42, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                decode_delta_report_bundle(bad)

    def test_bad_tag(self):
        bad = b"thresholdsign/delta-report-bundle/v0" + self.blob[len(TAG):]
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(bad)
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(b"")
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(self.blob[5:])

    def test_zero_count_is_illegal(self):
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(TAG + u32(0))

    def test_truncated_count(self):
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(TAG)
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(
                TAG + self.blob[len(TAG):len(TAG) + 2]
            )

    def test_truncated_frame_or_report(self):
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(self.blob[:-1])
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(self.blob[: len(TAG) + 4 + 2])
        # Whole report frame missing.
        report_frame = encode_dr(self.report)
        self.assertTrue(self.blob.endswith(u32(len(report_frame)) + report_frame))
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(
                self.blob[: len(self.blob) - len(report_frame) - 4]
            )

    def test_zero_frame_length(self):
        frame0 = encode_audit_extension_delta_checkpoint_chain(
            self.segments[0]
        )
        report_frame = encode_dr(self.report)
        bad = (
            TAG
            + u32(1)
            + u32(0)
            + u32(len(report_frame))
            + report_frame
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(bad)
        # Zero-length report frame.
        bad = TAG + u32(1) + u32(len(frame0)) + frame0 + u32(0)
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(bad)

    def test_overlong_frame(self):
        frame0 = encode_audit_extension_delta_checkpoint_chain(
            self.segments[0]
        )
        bad = TAG + u32(1) + u32(len(frame0) + 1) + frame0
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(bad)

    def test_count_mismatch(self):
        frame0 = encode_audit_extension_delta_checkpoint_chain(
            self.segments[0]
        )
        report_frame = encode_dr(self.report)
        # Declared more segments than present: the report frame is
        # swallowed as a segment frame and rejected.
        bad = (
            TAG
            + u32(2)
            + u32(len(frame0))
            + frame0
            + u32(len(report_frame))
            + report_frame
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(bad)
        # Declared fewer: a segment frame is read as the report frame.
        bad = (
            TAG
            + u32(1)
            + u32(len(frame0))
            + frame0
            + u32(len(frame0))
            + frame0
            + u32(len(report_frame))
            + report_frame
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(bad)

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(self.blob + b"\x00")

    def test_illegal_nested_segment_frame(self):
        frame0 = bytearray(
            encode_audit_extension_delta_checkpoint_chain(self.segments[0])
        )
        frame0[0] ^= 0x01
        report_frame = encode_dr(self.report)
        bad = (
            TAG
            + u32(1)
            + u32(len(frame0))
            + bytes(frame0)
            + u32(len(report_frame))
            + report_frame
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(bad)

    def test_illegal_nested_report_frame(self):
        frame0 = encode_audit_extension_delta_checkpoint_chain(
            self.segments[0]
        )
        report_frame = bytearray(encode_dr(self.report))
        report_frame[0] ^= 0x01
        bad = (
            TAG
            + u32(1)
            + u32(len(frame0))
            + frame0
            + u32(len(report_frame))
            + bytes(report_frame)
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(bad)

    def test_short_garbage_frame(self):
        bad = TAG + u32(1) + u32(5) + b"xxxxx"
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(bad)


class VerifyBundleTest(unittest.TestCase):
    def setUp(self):
        self.key, self.delta, self.segments = build_segments()
        self.bundle = make_bundle(self.segments, self.key)

    def test_verifying_bundle_is_true(self):
        self.assertTrue(verify_delta_report_bundle(self.bundle, self.key))

    def test_report_for_failing_set_is_true(self):
        failing = (self.segments[1], self.segments[0])
        bundle = make_bundle(failing, self.key)
        self.assertFalse(bundle.report.diagnosis.ok)
        self.assertTrue(verify_delta_report_bundle(bundle, self.key))
        # The same report presented over the verifying set is False.
        swapped = DeltaReportBundle(self.segments, bundle.report)
        self.assertFalse(verify_delta_report_bundle(swapped, self.key))

    def test_diagnosis_mismatch_is_false(self):
        report = DeltaReport(
            DeltaDiagnosis(False, "sig", 0, None),
            self.bundle.report.public_key,
            self.bundle.report.signature,
        )
        bundle = DeltaReportBundle(self.segments, report)
        self.assertFalse(verify_delta_report_bundle(bundle, self.key))

    def test_tampered_segments_is_false(self):
        segment = self.segments[1]
        batch = segment.additions[0]
        tampered_segment = AuditExtensionDeltaCheckpointChain(
            segment.first,
            ((b"\x00" * 32,) + batch[1:],) + segment.additions[1:],
            segment.signatures,
        )
        tampered = (self.segments[0], tampered_segment) + self.segments[2:]
        bundle = DeltaReportBundle(tampered, self.bundle.report)
        self.assertFalse(verify_delta_report_bundle(bundle, self.key))

    def test_tampered_signature_is_false(self):
        foreign = sign_message(self.key, b"unrelated", seed=7)
        report = DeltaReport(
            self.bundle.report.diagnosis,
            self.bundle.report.public_key,
            foreign,
        )
        bundle = DeltaReportBundle(self.segments, report)
        self.assertFalse(verify_delta_report_bundle(bundle, self.key))

    def test_other_key_is_false(self):
        self.assertFalse(
            verify_delta_report_bundle(self.bundle, make_other_key())
        )

    def test_public_key_mismatch_is_false(self):
        report = DeltaReport(
            self.bundle.report.diagnosis,
            self.bundle.report.public_key + 1,
            self.bundle.report.signature,
        )
        bundle = DeltaReportBundle(self.segments, report)
        self.assertFalse(verify_delta_report_bundle(bundle, self.key))

    def test_round_trip_keeps_verdict(self):
        blob = encode_delta_report_bundle(self.bundle)
        restored = decode_delta_report_bundle(blob)
        self.assertTrue(verify_delta_report_bundle(restored, self.key))

    def test_non_bundle_type_error(self):
        for bad in ("x", None, 42, object(), (self.segments, self.bundle.report)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_delta_report_bundle(bad, self.key)

    def test_non_key_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_delta_report_bundle(self.bundle, bad)

    def test_empty_segments_value_error(self):
        bundle = DeltaReportBundle((), self.bundle.report)
        with self.assertRaises(ValueError):
            verify_delta_report_bundle(bundle, self.key)

    def test_illegal_report_value_error(self):
        report = DeltaReport(
            DeltaDiagnosis(False, "ok", None, None),
            self.bundle.report.public_key,
            self.bundle.report.signature,
        )
        bundle = DeltaReportBundle(self.segments, report)
        with self.assertRaises(ValueError):
            verify_delta_report_bundle(bundle, self.key)


if __name__ == "__main__":
    unittest.main()
