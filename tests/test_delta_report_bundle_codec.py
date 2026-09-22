"""Tests for the self-contained delta report bundle:
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
    decode_audit_extension_delta_checkpoint_chain,
    decode_delta_report_bundle,
    decode_dr,
    diagnose_delta_chain_segments,
    dr_message,
    encode_audit_extension_delta_checkpoint_chain,
    encode_delta_report_bundle,
    encode_dr,
    partition_delta_chain,
    verify_delta_report_bundle,
    verify_dr,
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


def build_segments(cuts=(1, 3)):
    key = make_key()
    records = make_records(key, 7)
    splits = [(2, 3), (3, 5), (5, 6), (6, 7)]
    delta = make_delta(key, records, splits)
    return key, records, splits, delta, partition_delta_chain(delta, cuts)


def make_report(segments, diagnosis, key, *, seed=100):
    message = dr_message(segments, diagnosis, key.public_key)
    return DeltaReport(
        diagnosis, key.public_key, sign_message(key, message, seed=seed)
    )


def build_wire(bundle):
    """Independently build the bundle wire format straight from the spec."""
    out = bytearray(TAG)
    out += u32(len(bundle.segments))
    for segment in bundle.segments:
        frame = encode_audit_extension_delta_checkpoint_chain(segment)
        out += u32(len(frame))
        out += frame
    report_blob = encode_dr(bundle.report)
    out += u32(len(report_blob))
    out += report_blob
    return bytes(out)


class DeltaReportBundleShapeTest(unittest.TestCase):
    def test_fields_in_order(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(DeltaReportBundle)],
            ["segments", "report"],
        )

    def test_frozen_positional_and_value_equal(self):
        key, _r, _s, _d, segments = build_segments()
        report = make_report(
            segments, DeltaDiagnosis(True, "ok", None, None), key
        )
        bundle = DeltaReportBundle(segments, report)
        self.assertEqual(
            bundle,
            DeltaReportBundle(segments=segments, report=report),
        )
        self.assertEqual((bundle.segments, bundle.report), (segments, report))
        self.assertEqual(bundle, DeltaReportBundle(segments, report))
        self.assertNotEqual(bundle, DeltaReportBundle(segments[:1], report))
        self.assertNotEqual(
            bundle,
            DeltaReportBundle(
                segments,
                DeltaReport(
                    DeltaDiagnosis(False, "sig", 0, None),
                    report.public_key,
                    report.signature,
                ),
            ),
        )
        self.assertEqual(
            {bundle, DeltaReportBundle(segments, report)},
            {DeltaReportBundle(segments, report)},
        )
        with self.assertRaises(FrozenInstanceError):
            bundle.report = report


class EncodeDecodeBundleTest(unittest.TestCase):
    def setUp(self):
        self.key, _r, _s, _d, self.segments = build_segments()
        self.diagnosis = DeltaDiagnosis(True, "ok", None, None)
        self.report = make_report(self.segments, self.diagnosis, self.key)

    def _bundles(self):
        signature = self.report.signature
        return (
            DeltaReportBundle(self.segments, self.report),
            DeltaReportBundle((self.segments[0],), self.report),
            DeltaReportBundle(
                self.segments,
                DeltaReport(
                    DeltaDiagnosis(False, "proof", 1, 2),
                    self.key.public_key,
                    signature,
                ),
            ),
            DeltaReportBundle(
                self.segments,
                DeltaReport(self.diagnosis, 0, signature),
            ),
        )

    def test_wire_matches_independent_spec_build(self):
        for bundle in self._bundles():
            with self.subTest(kind=bundle.report.diagnosis.kind):
                blob = encode_delta_report_bundle(bundle)
                self.assertEqual(blob, build_wire(bundle))
                self.assertTrue(blob.startswith(TAG))

    def test_wire_layout_is_tag_count_frames_then_report_frame(self):
        bundle = DeltaReportBundle(self.segments, self.report)
        blob = encode_delta_report_bundle(bundle)
        offset = len(TAG)
        self.assertEqual(blob[offset:offset + 4], u32(len(self.segments)))
        offset += 4
        for segment in self.segments:
            frame = encode_audit_extension_delta_checkpoint_chain(segment)
            self.assertEqual(blob[offset:offset + 4], u32(len(frame)))
            offset += 4
            self.assertEqual(blob[offset:offset + len(frame)], frame)
            offset += len(frame)
        report_blob = encode_dr(self.report)
        self.assertEqual(
            blob[offset:offset + 4], u32(len(report_blob))
        )
        offset += 4
        self.assertEqual(blob[offset:offset + len(report_blob)], report_blob)
        offset += len(report_blob)
        self.assertEqual(offset, len(blob))

    def test_segment_frames_share_existing_segments_encoding(self):
        bundle = DeltaReportBundle(self.segments, self.report)
        blob = encode_delta_report_bundle(bundle)
        # The count plus every segment frame is exactly the body of
        # encode_delta_chain_segments with its tag stripped.
        from thresholdsign import (
            DELTA_CHAIN_SEGMENTS_WIRE_TAG,
            encode_delta_chain_segments,
        )

        body = encode_delta_chain_segments(self.segments)[
            len(DELTA_CHAIN_SEGMENTS_WIRE_TAG):
        ]
        self.assertEqual(
            blob[len(TAG):len(TAG) + len(body)], body
        )

    def test_round_trip_byte_for_byte(self):
        for bundle in self._bundles():
            with self.subTest(kind=bundle.report.diagnosis.kind):
                blob = encode_delta_report_bundle(bundle)
                restored = decode_delta_report_bundle(blob)
                self.assertIsInstance(restored, DeltaReportBundle)
                self.assertEqual(restored, bundle)
                self.assertEqual(
                    encode_delta_report_bundle(restored), blob
                )

    def test_frames_decode_standalone(self):
        bundle = DeltaReportBundle(self.segments, self.report)
        blob = encode_delta_report_bundle(bundle)
        offset = len(TAG) + 4
        for segment in self.segments:
            length = int.from_bytes(blob[offset:offset + 4], "big")
            offset += 4
            frame = blob[offset:offset + length]
            offset += length
            self.assertEqual(
                decode_audit_extension_delta_checkpoint_chain(bytes(frame)),
                segment,
            )
        length = int.from_bytes(blob[offset:offset + 4], "big")
        offset += 4
        self.assertEqual(
            decode_dr(bytes(blob[offset:offset + length])), self.report
        )

    def test_order_is_preserved(self):
        reversed_segments = tuple(reversed(self.segments))
        bundle = DeltaReportBundle(reversed_segments, self.report)
        restored = decode_delta_report_bundle(
            encode_delta_report_bundle(bundle)
        )
        self.assertEqual(restored.segments, reversed_segments)
        self.assertNotEqual(restored.segments, self.segments)

    def test_encoding_is_deterministic_and_unique(self):
        bundle = DeltaReportBundle(self.segments, self.report)
        self.assertEqual(
            encode_delta_report_bundle(bundle),
            encode_delta_report_bundle(bundle),
        )
        other = DeltaReportBundle(self.segments[:1], self.report)
        self.assertNotEqual(
            encode_delta_report_bundle(bundle),
            encode_delta_report_bundle(other),
        )

    def test_seams_and_diagnosis_not_checked_on_decode(self):
        # Two individually legal segments that do not sit in chain order
        # still decode, together with a structurally legal report that
        # does not diagnose them; verify is what rejects the bundle.
        shuffled = (self.segments[2], self.segments[0])
        bundle = DeltaReportBundle(shuffled, self.report)
        restored = decode_delta_report_bundle(
            encode_delta_report_bundle(bundle)
        )
        self.assertEqual(restored, bundle)
        self.assertFalse(
            verify_delta_report_bundle(restored, self.key)
        )


class EncodeBundleErrorTest(unittest.TestCase):
    def setUp(self):
        self.key, _r, _s, _d, self.segments = build_segments()
        self.report = make_report(
            self.segments, DeltaDiagnosis(True, "ok", None, None), self.key
        )

    def test_non_bundle_type_error(self):
        for bad in (
            "x",
            None,
            42,
            b"x",
            object(),
            (self.segments, self.report),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_delta_report_bundle(bad)

    def test_non_tuple_segments_type_error(self):
        segment = self.segments[0]
        for bad in (
            list(self.segments),
            iter(self.segments),
            [segment],
            segment,
            "segments",
            None,
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_delta_report_bundle(
                    DeltaReportBundle(bad, self.report)
                )

    def test_non_segment_element_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_delta_report_bundle(
                    DeltaReportBundle((bad,), self.report)
                )

    def test_non_report_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_delta_report_bundle(
                    DeltaReportBundle(self.segments, bad)
                )

    def test_empty_segments_value_error(self):
        with self.assertRaises(ValueError):
            encode_delta_report_bundle(
                DeltaReportBundle((), self.report)
            )

    def test_nested_segment_type_error(self):
        bad_segment = AuditExtensionDeltaCheckpointChain(
            "not a proof",
            self.segments[0].additions,
            self.segments[0].signatures,
        )
        with self.assertRaises(TypeError):
            encode_delta_report_bundle(
                DeltaReportBundle((bad_segment,), self.report)
            )

    def test_nested_segment_value_error(self):
        bad_segment = AuditExtensionDeltaCheckpointChain(
            self.segments[0].first,
            self.segments[0].additions,
            self.segments[0].signatures[:-1],
        )
        with self.assertRaises(ValueError):
            encode_delta_report_bundle(
                DeltaReportBundle((bad_segment,), self.report)
            )

    def test_bad_report_structure_value_error(self):
        bad_report = DeltaReport(
            self.report.diagnosis,
            self.report.public_key,
            AggregateSignature(R=0, z=1, signer_ids=(1,)),
        )
        with self.assertRaises(ValueError):
            encode_delta_report_bundle(
                DeltaReportBundle(self.segments, bad_report)
            )


class DecodeBundleErrorTest(unittest.TestCase):
    def setUp(self):
        self.key, _r, _s, _d, self.segments = build_segments()
        self.report = make_report(
            self.segments, DeltaDiagnosis(True, "ok", None, None), self.key
        )
        self.blob = encode_delta_report_bundle(
            DeltaReportBundle(self.segments, self.report)
        )
        self.frame0 = encode_audit_extension_delta_checkpoint_chain(
            self.segments[0]
        )
        self.report_blob = encode_dr(self.report)

    def test_non_bytes_type_error(self):
        for bad in (
            self.blob.decode("latin1"),
            bytearray(self.blob),
            None,
            42,
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                decode_delta_report_bundle(bad)

    def test_bad_tag(self):
        swap = b"thresholdsign/delta-report-bundle/v0"
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(swap + self.blob[len(TAG):])
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(b"")
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(self.blob[5:])

    def test_zero_count_is_illegal(self):
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(TAG + u32(0))

    def test_truncated_count_or_frames(self):
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(TAG)
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(self.blob[:-1])
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(self.blob[: len(TAG) + 4 + 2])

    def test_zero_segment_frame_length(self):
        bad = (
            TAG
            + u32(1)
            + u32(0)
            + u32(len(self.report_blob))
            + self.report_blob
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(bad)

    def test_overlong_segment_frame(self):
        bad = (
            TAG
            + u32(1)
            + u32(len(self.frame0) + 1)
            + self.frame0
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(bad)

    def test_count_mismatch_declared_more_than_frames(self):
        bad = (
            TAG
            + u32(2)
            + u32(len(self.frame0))
            + self.frame0
            + u32(len(self.report_blob))
            + self.report_blob
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(bad)

    def test_missing_report_frame(self):
        bad = TAG + u32(1) + u32(len(self.frame0)) + self.frame0
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(bad)
        # Length declared but body missing.
        bad += u32(len(self.report_blob))
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(bad)

    def test_zero_report_frame_length(self):
        bad = (
            TAG
            + u32(1)
            + u32(len(self.frame0))
            + self.frame0
            + u32(0)
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(bad)

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(self.blob + b"\x00")

    def test_illegal_nested_segment_frame(self):
        tampered = bytearray(self.frame0)
        tampered[0] ^= 0x01
        bad = (
            TAG
            + u32(1)
            + u32(len(tampered))
            + bytes(tampered)
            + u32(len(self.report_blob))
            + self.report_blob
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(bad)

    def test_illegal_report_frame(self):
        # The outer framing lines up but the report body is not a legal
        # encode_dr output.
        bad = (
            TAG
            + u32(1)
            + u32(len(self.frame0))
            + self.frame0
            + u32(5)
            + b"xxxxx"
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(bad)

    def test_report_frame_with_bad_tag(self):
        tampered = bytearray(self.report_blob)
        tampered[0] ^= 0x01
        bad = (
            TAG
            + u32(1)
            + u32(len(self.frame0))
            + self.frame0
            + u32(len(tampered))
            + bytes(tampered)
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(bad)

    def test_short_garbage(self):
        with self.assertRaises(ValueError):
            decode_delta_report_bundle(TAG + u32(1) + u32(5) + b"xxxxx")


class VerifyBundleTest(unittest.TestCase):
    def setUp(self):
        self.key, _r, _s, _d, self.segments = build_segments()
        self.diagnosis = DeltaDiagnosis(True, "ok", None, None)
        self.report = make_report(self.segments, self.diagnosis, self.key)
        self.bundle = DeltaReportBundle(self.segments, self.report)

    def test_verifying_bundle_is_true(self):
        self.assertTrue(
            verify_delta_report_bundle(self.bundle, self.key)
        )

    def test_delegates_to_verify_dr(self):
        self.assertIs(
            verify_delta_report_bundle(self.bundle, self.key),
            verify_dr(self.report, self.segments, self.key),
        )

    def test_decoded_bundle_keeps_verdict(self):
        restored = decode_delta_report_bundle(
            encode_delta_report_bundle(self.bundle)
        )
        self.assertTrue(verify_delta_report_bundle(restored, self.key))

    def test_bundle_for_failing_set_verifies_for_exact_set(self):
        failing = (self.segments[1], self.segments[0])
        diagnosis = diagnose_delta_chain_segments(failing, self.key)
        self.assertEqual(
            diagnosis, DeltaDiagnosis(False, "leaf", 0, None)
        )
        report = make_report(failing, diagnosis, self.key)
        bundle = DeltaReportBundle(failing, report)
        self.assertTrue(verify_delta_report_bundle(bundle, self.key))
        # The same report bundled with the verifying segment set is False.
        mismatched = DeltaReportBundle(self.segments, report)
        self.assertFalse(
            verify_delta_report_bundle(mismatched, self.key)
        )

    def test_diagnosis_mismatch_is_false(self):
        for claimed in (
            DeltaDiagnosis(False, "sig", 0, None),
            DeltaDiagnosis(False, "leaf", 0, None),
            DeltaDiagnosis(False, "proof", 0, 0),
        ):
            with self.subTest(kind=claimed.kind):
                bundle = DeltaReportBundle(
                    self.segments,
                    DeltaReport(
                        claimed,
                        self.report.public_key,
                        self.report.signature,
                    ),
                )
                self.assertFalse(
                    verify_delta_report_bundle(bundle, self.key)
                )

    def test_other_key_is_false(self):
        self.assertFalse(
            verify_delta_report_bundle(self.bundle, make_other_key())
        )

    def test_public_key_mismatch_is_false(self):
        report = DeltaReport(
            self.report.diagnosis,
            self.report.public_key + 1,
            self.report.signature,
        )
        self.assertFalse(
            verify_delta_report_bundle(
                DeltaReportBundle(self.segments, report), self.key
            )
        )

    def test_tampered_signature_is_false(self):
        foreign = sign_message(self.key, b"unrelated", seed=7)
        bundle = DeltaReportBundle(
            self.segments,
            DeltaReport(
                self.report.diagnosis, self.report.public_key, foreign
            ),
        )
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
        bundle = DeltaReportBundle(tampered, self.report)
        self.assertFalse(verify_delta_report_bundle(bundle, self.key))
        # A report freshly built over the tampered set verifies inside a
        # bundle carrying that same set.
        diagnosis = diagnose_delta_chain_segments(tampered, self.key)
        good_bundle = DeltaReportBundle(
            tampered, make_report(tampered, diagnosis, self.key)
        )
        self.assertTrue(
            verify_delta_report_bundle(good_bundle, self.key)
        )

    def test_non_bundle_type_error(self):
        for bad in ("x", None, 42, object(), (self.segments, self.report)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_delta_report_bundle(bad, self.key)

    def test_non_key_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_delta_report_bundle(self.bundle, bad)

    def test_empty_segments_value_error(self):
        bundle = DeltaReportBundle((), self.report)
        with self.assertRaises(ValueError):
            verify_delta_report_bundle(bundle, self.key)

    def test_illegal_segment_value_error(self):
        good = self.segments[0]
        bad_segment = AuditExtensionDeltaCheckpointChain(
            good.first, ((),) + good.additions[1:], good.signatures
        )
        bundle = DeltaReportBundle((bad_segment,), self.report)
        with self.assertRaises(ValueError):
            verify_delta_report_bundle(bundle, self.key)

    def test_illegal_report_value_error(self):
        bad_report = DeltaReport(
            DeltaDiagnosis(False, "ok", None, None),
            self.report.public_key,
            self.report.signature,
        )
        bundle = DeltaReportBundle(self.segments, bad_report)
        with self.assertRaises(ValueError):
            verify_delta_report_bundle(bundle, self.key)


if __name__ == "__main__":
    unittest.main()
