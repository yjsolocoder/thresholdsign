"""Tests for the delta report bundle archive:
DeltaReportBundleArchive / encode_delta_report_bundle_archive /
decode_delta_report_bundle_archive / verify_delta_report_bundle_archive."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    DeltaDiagnosis,
    DeltaReport,
    DeltaReportBundle,
    DeltaReportBundleArchive,
    decode_delta_report_bundle_archive,
    encode_delta_report_bundle,
    encode_delta_report_bundle_archive,
    verify_delta_report_bundle,
    verify_delta_report_bundle_archive,
)

from test_audit_chain import sign_message
from test_audit_extension_proof_bundle_codec import make_other_key
from test_delta_report_bundle_codec import (
    TAG as BUNDLE_TAG,
    build_segments,
    make_report,
)

TAG = b"thresholdsign/delta-report-bundle-archive/v1"


def u32(value):
    return value.to_bytes(4, "big")


def build_bundles():
    key, _r, _s, _d, segments = build_segments()
    diagnosis = DeltaDiagnosis(True, "ok", None, None)
    report = make_report(segments, diagnosis, key)
    bundles = (
        DeltaReportBundle(segments, report),
        DeltaReportBundle(segments[:1], report),
        DeltaReportBundle(
            segments,
            DeltaReport(
                DeltaDiagnosis(False, "proof", 1, 2),
                key.public_key,
                report.signature,
            ),
        ),
    )
    return key, segments, report, bundles


def build_wire(archive):
    """Independently build the archive wire format straight from the spec."""
    out = bytearray(TAG)
    out += u32(len(archive.items))
    for item in archive.items:
        frame = encode_delta_report_bundle(item)
        out += u32(len(frame))
        out += frame
    return bytes(out)


class DeltaReportBundleArchiveShapeTest(unittest.TestCase):
    def test_fields_in_order(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(DeltaReportBundleArchive)],
            ["items"],
        )

    def test_frozen_positional_and_value_equal(self):
        _key, _s, _r, bundles = build_bundles()
        archive = DeltaReportBundleArchive(bundles)
        self.assertEqual(archive, DeltaReportBundleArchive(items=bundles))
        self.assertEqual(archive.items, bundles)
        self.assertEqual(archive, DeltaReportBundleArchive(bundles))
        self.assertNotEqual(archive, DeltaReportBundleArchive(bundles[:1]))
        self.assertNotEqual(
            archive, DeltaReportBundleArchive(tuple(reversed(bundles)))
        )
        self.assertEqual(
            {archive, DeltaReportBundleArchive(bundles)},
            {DeltaReportBundleArchive(bundles)},
        )
        with self.assertRaises(FrozenInstanceError):
            archive.items = bundles


class EncodeDecodeArchiveTest(unittest.TestCase):
    def setUp(self):
        self.key, self.segments, self.report, self.bundles = build_bundles()

    def test_wire_matches_independent_spec_build(self):
        for items in (self.bundles, self.bundles[:1], tuple(reversed(self.bundles))):
            archive = DeltaReportBundleArchive(items)
            with self.subTest(count=len(items)):
                blob = encode_delta_report_bundle_archive(archive)
                self.assertEqual(blob, build_wire(archive))
                self.assertTrue(blob.startswith(TAG))

    def test_wire_layout_is_tag_count_then_frames(self):
        archive = DeltaReportBundleArchive(self.bundles)
        blob = encode_delta_report_bundle_archive(archive)
        offset = len(TAG)
        self.assertEqual(blob[offset:offset + 4], u32(len(self.bundles)))
        offset += 4
        for item in self.bundles:
            frame = encode_delta_report_bundle(item)
            self.assertEqual(blob[offset:offset + 4], u32(len(frame)))
            offset += 4
            self.assertEqual(blob[offset:offset + len(frame)], frame)
            offset += len(frame)
        self.assertEqual(offset, len(blob))

    def test_round_trip_byte_for_byte(self):
        for items in (self.bundles, self.bundles[:1], tuple(reversed(self.bundles))):
            archive = DeltaReportBundleArchive(items)
            with self.subTest(count=len(items)):
                blob = encode_delta_report_bundle_archive(archive)
                restored = decode_delta_report_bundle_archive(blob)
                self.assertIsInstance(restored, DeltaReportBundleArchive)
                self.assertEqual(restored, archive)
                self.assertEqual(
                    encode_delta_report_bundle_archive(restored), blob
                )

    def test_order_is_preserved(self):
        reversed_items = tuple(reversed(self.bundles))
        archive = DeltaReportBundleArchive(reversed_items)
        restored = decode_delta_report_bundle_archive(
            encode_delta_report_bundle_archive(archive)
        )
        self.assertEqual(restored.items, reversed_items)
        self.assertNotEqual(restored.items, self.bundles)

    def test_encoding_is_deterministic_and_unique(self):
        archive = DeltaReportBundleArchive(self.bundles)
        self.assertEqual(
            encode_delta_report_bundle_archive(archive),
            encode_delta_report_bundle_archive(archive),
        )
        other = DeltaReportBundleArchive(self.bundles[:1])
        self.assertNotEqual(
            encode_delta_report_bundle_archive(archive),
            encode_delta_report_bundle_archive(other),
        )

    def test_signatures_not_checked_on_decode(self):
        # A structurally legal archive whose bundles do not verify still
        # decodes; verify is what rejects it.
        foreign = DeltaReport(
            DeltaDiagnosis(True, "ok", None, None),
            self.report.public_key,
            sign_message(self.key, b"unrelated", seed=7),
        )
        archive = DeltaReportBundleArchive(
            (DeltaReportBundle(self.segments, foreign),)
        )
        restored = decode_delta_report_bundle_archive(
            encode_delta_report_bundle_archive(archive)
        )
        self.assertEqual(restored, archive)
        self.assertFalse(
            verify_delta_report_bundle_archive(restored, self.key)
        )


class EncodeArchiveErrorTest(unittest.TestCase):
    def setUp(self):
        self.key, self.segments, self.report, self.bundles = build_bundles()

    def test_non_archive_type_error(self):
        for bad in ("x", None, 42, b"x", object(), self.bundles):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_delta_report_bundle_archive(bad)

    def test_non_tuple_items_type_error(self):
        for bad in (list(self.bundles), iter(self.bundles), "items", None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_delta_report_bundle_archive(
                    DeltaReportBundleArchive(bad)
                )

    def test_non_bundle_item_type_error(self):
        for bad in ("x", None, 42, b"x", object(), self.report):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_delta_report_bundle_archive(
                    DeltaReportBundleArchive((bad,))
                )

    def test_empty_items_value_error(self):
        with self.assertRaises(ValueError):
            encode_delta_report_bundle_archive(DeltaReportBundleArchive(()))

    def test_nested_bundle_type_error(self):
        bad_bundle = DeltaReportBundle("not a tuple", self.report)
        with self.assertRaises(TypeError):
            encode_delta_report_bundle_archive(
                DeltaReportBundleArchive((bad_bundle,))
            )

    def test_nested_bundle_value_error(self):
        bad_bundle = DeltaReportBundle((), self.report)
        with self.assertRaises(ValueError):
            encode_delta_report_bundle_archive(
                DeltaReportBundleArchive((bad_bundle,))
            )


class DecodeArchiveErrorTest(unittest.TestCase):
    def setUp(self):
        self.key, self.segments, self.report, self.bundles = build_bundles()
        self.archive = DeltaReportBundleArchive(self.bundles)
        self.blob = encode_delta_report_bundle_archive(self.archive)
        self.frame0 = encode_delta_report_bundle(self.bundles[0])

    def test_non_bytes_type_error(self):
        for bad in (
            self.blob.decode("latin1"),
            bytearray(self.blob),
            None,
            42,
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                decode_delta_report_bundle_archive(bad)

    def test_bad_tag(self):
        swap = b"thresholdsign/delta-report-bundle-archive/v0"
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive(swap + self.blob[len(TAG):])
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive(b"")
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive(self.blob[5:])

    def test_zero_count_is_illegal(self):
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive(TAG + u32(0))

    def test_truncated_count_or_frames(self):
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive(TAG)
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive(self.blob[:-1])
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive(self.blob[: len(TAG) + 4 + 2])

    def test_zero_frame_length(self):
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive(TAG + u32(1) + u32(0))

    def test_overlong_frame(self):
        bad = TAG + u32(1) + u32(len(self.frame0) + 1) + self.frame0
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive(bad)

    def test_count_mismatch_declared_more_than_frames(self):
        bad = TAG + u32(2) + u32(len(self.frame0)) + self.frame0
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive(bad)

    def test_count_mismatch_declared_fewer_than_frames(self):
        bad = TAG + u32(1) + self.blob[len(TAG) + 4:]
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive(bad)

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive(self.blob + b"\x00")

    def test_illegal_nested_bundle_frame(self):
        tampered = bytearray(self.frame0)
        tampered[0] ^= 0x01
        bad = TAG + u32(1) + u32(len(tampered)) + bytes(tampered)
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive(bad)

    def test_non_canonical_nested_bundle_frame(self):
        # A frame that carries a legal bundle body wrapped in the wrong
        # tag is not a canonical encode_delta_report_bundle output.
        body = self.frame0[len(BUNDLE_TAG):]
        bad_frame = b"thresholdsign/delta-report-bundle/v0" + body
        bad = TAG + u32(1) + u32(len(bad_frame)) + bad_frame
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive(bad)

    def test_short_garbage(self):
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive(TAG + u32(1) + u32(5) + b"xxxxx")


class VerifyArchiveTest(unittest.TestCase):
    def setUp(self):
        self.key, self.segments, self.report, self.bundles = build_bundles()
        self.good = DeltaReportBundle(self.segments, self.report)

    def test_all_verifying_archive_is_true(self):
        archive = DeltaReportBundleArchive((self.good, self.good))
        self.assertTrue(verify_delta_report_bundle_archive(archive, self.key))

    def test_single_verifying_item_is_true(self):
        archive = DeltaReportBundleArchive((self.good,))
        self.assertTrue(verify_delta_report_bundle_archive(archive, self.key))

    def test_decoded_archive_keeps_verdict(self):
        archive = DeltaReportBundleArchive((self.good,))
        restored = decode_delta_report_bundle_archive(
            encode_delta_report_bundle_archive(archive)
        )
        self.assertTrue(verify_delta_report_bundle_archive(restored, self.key))

    def test_any_failing_item_is_false(self):
        foreign = DeltaReport(
            self.report.diagnosis,
            self.report.public_key,
            sign_message(self.key, b"unrelated", seed=7),
        )
        bad = DeltaReportBundle(self.segments, foreign)
        for items in ((bad,), (self.good, bad), (bad, self.good)):
            with self.subTest(items=len(items)):
                archive = DeltaReportBundleArchive(items)
                self.assertFalse(
                    verify_delta_report_bundle_archive(archive, self.key)
                )

    def test_delegates_to_verify_delta_report_bundle(self):
        archive = DeltaReportBundleArchive((self.good,))
        self.assertIs(
            verify_delta_report_bundle_archive(archive, self.key),
            verify_delta_report_bundle(self.good, self.key),
        )

    def test_other_key_is_false(self):
        archive = DeltaReportBundleArchive((self.good,))
        self.assertFalse(
            verify_delta_report_bundle_archive(archive, make_other_key())
        )

    def test_non_archive_type_error(self):
        for bad in ("x", None, 42, object(), (self.good,)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_delta_report_bundle_archive(bad, self.key)

    def test_non_tuple_items_type_error(self):
        archive = DeltaReportBundleArchive([self.good])
        with self.assertRaises(TypeError):
            verify_delta_report_bundle_archive(archive, self.key)

    def test_non_bundle_item_type_error(self):
        archive = DeltaReportBundleArchive(("x",))
        with self.assertRaises(TypeError):
            verify_delta_report_bundle_archive(archive, self.key)

    def test_non_key_type_error(self):
        archive = DeltaReportBundleArchive((self.good,))
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_delta_report_bundle_archive(archive, bad)

    def test_empty_items_value_error(self):
        archive = DeltaReportBundleArchive(())
        with self.assertRaises(ValueError):
            verify_delta_report_bundle_archive(archive, self.key)

    def test_illegal_nested_bundle_value_error(self):
        bad_bundle = DeltaReportBundle((), self.report)
        archive = DeltaReportBundleArchive((bad_bundle,))
        with self.assertRaises(ValueError):
            verify_delta_report_bundle_archive(archive, self.key)


if __name__ == "__main__":
    unittest.main()
