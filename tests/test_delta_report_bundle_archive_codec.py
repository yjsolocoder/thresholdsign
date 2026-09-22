"""Tests for the non-empty order-preserving archive of delta report
bundles: DeltaReportBundleArchive /
encode_delta_report_bundle_archive / decode_delta_report_bundle_archive
/ verify_delta_report_bundle_archive."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AuditExtensionDeltaCheckpointChain,
    DeltaDiagnosis,
    DeltaReport,
    DeltaReportBundle,
    DeltaReportBundleArchive,
    decode_delta_report_bundle,
    decode_delta_report_bundle_archive,
    diagnose_delta_chain_segments,
    encode_delta_report_bundle,
    encode_delta_report_bundle_archive,
    verify_delta_report_bundle,
    verify_delta_report_bundle_archive,
)

from test_audit_extension_proof_bundle_codec import make_other_key
from test_delta_report_bundle_codec import (
    build_segments,
    make_report,
    u32,
)

TAG = b"thresholdsign/delta-report-bundle-archive/v1"


def build_archives():
    """A key and several structurally legal archives of valid bundles."""
    key, _records, _splits, _delta, segments = build_segments()

    def bundle_for(part, *, seed):
        diagnosis = diagnose_delta_chain_segments(part, key)
        return DeltaReportBundle(
            part, make_report(part, diagnosis, key, seed=seed)
        )

    full = bundle_for(segments, seed=100)
    first = bundle_for((segments[0],), seed=101)
    second = bundle_for((segments[1],), seed=102)
    archives = (
        DeltaReportBundleArchive((full,)),
        DeltaReportBundleArchive((first, second)),
        DeltaReportBundleArchive((full, first, second)),
        DeltaReportBundleArchive((second, full)),
    )
    return key, segments, full, first, second, archives


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
            [
                field.name
                for field in dataclasses.fields(DeltaReportBundleArchive)
            ],
            ["items"],
        )

    def test_frozen_positional_and_value_equal(self):
        key, _s, full, first, _second, _archives = build_archives()
        items = (full, first)
        archive = DeltaReportBundleArchive(items)
        self.assertEqual(archive, DeltaReportBundleArchive(items=items))
        self.assertEqual(archive.items, items)
        self.assertEqual(archive, DeltaReportBundleArchive(items))
        self.assertNotEqual(archive, DeltaReportBundleArchive((full,)))
        self.assertNotEqual(
            archive, DeltaReportBundleArchive((first, full))
        )
        self.assertEqual(
            {archive, DeltaReportBundleArchive(items)},
            {DeltaReportBundleArchive(items)},
        )
        with self.assertRaises(FrozenInstanceError):
            archive.items = items


class EncodeDecodeArchiveTest(unittest.TestCase):
    def setUp(self):
        (
            self.key,
            self.segments,
            self.full,
            self.first,
            self.second,
            self.archives,
        ) = build_archives()

    def test_wire_matches_independent_spec_build(self):
        for archive in self.archives:
            with self.subTest(n=len(archive.items)):
                blob = encode_delta_report_bundle_archive(archive)
                self.assertEqual(blob, build_wire(archive))
                self.assertTrue(blob.startswith(TAG))

    def test_wire_layout_is_tag_count_then_frames(self):
        archive = DeltaReportBundleArchive((self.full, self.first))
        blob = encode_delta_report_bundle_archive(archive)
        offset = len(TAG)
        self.assertEqual(blob[offset:offset + 4], u32(2))
        offset += 4
        for item in archive.items:
            frame = encode_delta_report_bundle(item)
            self.assertEqual(blob[offset:offset + 4], u32(len(frame)))
            offset += 4
            self.assertEqual(blob[offset:offset + len(frame)], frame)
            offset += len(frame)
        self.assertEqual(offset, len(blob))

    def test_round_trip_byte_for_byte(self):
        for archive in self.archives:
            with self.subTest(n=len(archive.items)):
                blob = encode_delta_report_bundle_archive(archive)
                restored = decode_delta_report_bundle_archive(blob)
                self.assertIsInstance(restored, DeltaReportBundleArchive)
                self.assertEqual(restored, archive)
                self.assertEqual(
                    encode_delta_report_bundle_archive(restored), blob
                )

    def test_frames_decode_standalone(self):
        archive = DeltaReportBundleArchive((self.full, self.second))
        blob = encode_delta_report_bundle_archive(archive)
        offset = len(TAG) + 4
        for item in archive.items:
            length = int.from_bytes(blob[offset:offset + 4], "big")
            offset += 4
            frame = blob[offset:offset + length]
            offset += length
            self.assertEqual(
                decode_delta_report_bundle(bytes(frame)), item
            )
        self.assertEqual(offset, len(blob))

    def test_order_is_preserved(self):
        forward = DeltaReportBundleArchive((self.first, self.second))
        reverse = DeltaReportBundleArchive((self.second, self.first))
        restored = decode_delta_report_bundle_archive(
            encode_delta_report_bundle_archive(forward)
        )
        self.assertEqual(restored.items, (self.first, self.second))
        self.assertNotEqual(restored, reverse)
        self.assertEqual(
            decode_delta_report_bundle_archive(
                encode_delta_report_bundle_archive(reverse)
            ).items,
            (self.second, self.first),
        )

    def test_encoding_is_deterministic_and_unique(self):
        archive = DeltaReportBundleArchive((self.full, self.first))
        other = DeltaReportBundleArchive((self.first, self.full))
        single = DeltaReportBundleArchive((self.full,))
        self.assertEqual(
            encode_delta_report_bundle_archive(archive),
            encode_delta_report_bundle_archive(archive),
        )
        self.assertNotEqual(
            encode_delta_report_bundle_archive(archive),
            encode_delta_report_bundle_archive(other),
        )
        self.assertNotEqual(
            encode_delta_report_bundle_archive(archive),
            encode_delta_report_bundle_archive(single),
        )

    def test_structurally_legal_but_failing_bundles_decode(self):
        # Bundles which carry segments their report does not diagnose are
        # restored as-is; verify is what rejects the archive afterwards.
        diagnosis = DeltaDiagnosis(False, "sig", 0, None)
        bad_report = DeltaReport(
            diagnosis,
            self.full.report.public_key,
            self.full.report.signature,
        )
        bad_bundle = DeltaReportBundle(
            self.full.segments, bad_report
        )
        archive = DeltaReportBundleArchive((self.first, bad_bundle))
        restored = decode_delta_report_bundle_archive(
            encode_delta_report_bundle_archive(archive)
        )
        self.assertEqual(restored, archive)
        self.assertFalse(
            verify_delta_report_bundle_archive(restored, self.key)
        )


class EncodeArchiveErrorTest(unittest.TestCase):
    def setUp(self):
        (
            self.key,
            self.segments,
            self.full,
            self.first,
            _second,
            _archives,
        ) = build_archives()

    def test_non_archive_type_error(self):
        for bad in (
            "x",
            None,
            42,
            b"x",
            object(),
            (self.full,),
            self.full,
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_delta_report_bundle_archive(bad)

    def test_non_tuple_items_type_error(self):
        for bad in (
            [self.full],
            iter((self.full,)),
            self.full,
            "items",
            None,
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_delta_report_bundle_archive(
                    DeltaReportBundleArchive(bad)
                )

    def test_non_bundle_element_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_delta_report_bundle_archive(
                    DeltaReportBundleArchive((bad,))
                )
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_delta_report_bundle_archive(
                    DeltaReportBundleArchive((self.full, bad))
                )

    def test_empty_archive_value_error(self):
        with self.assertRaises(ValueError):
            encode_delta_report_bundle_archive(
                DeltaReportBundleArchive(())
            )

    def test_nested_bundle_type_error(self):
        bad_segment = AuditExtensionDeltaCheckpointChain(
            "not a proof",
            self.segments[0].additions,
            self.segments[0].signatures,
        )
        bad_bundle = DeltaReportBundle(
            (bad_segment,), self.full.report
        )
        with self.assertRaises(TypeError):
            encode_delta_report_bundle_archive(
                DeltaReportBundleArchive((self.first, bad_bundle))
            )

    def test_nested_bundle_value_error(self):
        # A bundle whose own segment tuple is empty is structurally
        # illegal even though the archive container itself is well-typed.
        bad_bundle = DeltaReportBundle((), self.full.report)
        with self.assertRaises(ValueError):
            encode_delta_report_bundle_archive(
                DeltaReportBundleArchive((self.first, bad_bundle))
            )


class DecodeArchiveErrorTest(unittest.TestCase):
    def setUp(self):
        (
            self.key,
            _segments,
            self.full,
            self.first,
            _second,
            _archives,
        ) = build_archives()
        self.bundle_blob = encode_delta_report_bundle(self.full)
        self.blob = encode_delta_report_bundle_archive(
            DeltaReportBundleArchive((self.full, self.first))
        )

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
            decode_delta_report_bundle_archive(
                swap + self.blob[len(TAG):]
            )
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
        bad = TAG + u32(1) + u32(0)
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive(bad)

    def test_overlong_frame(self):
        bad = (
            TAG
            + u32(1)
            + u32(len(self.bundle_blob) + 1)
            + self.bundle_blob
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive(bad)

    def test_count_mismatch_declared_more_than_frames(self):
        bad = (
            TAG
            + u32(2)
            + u32(len(self.bundle_blob))
            + self.bundle_blob
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive(bad)

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive(self.blob + b"\x00")

    def test_illegal_nested_bundle_frame(self):
        tampered = bytearray(self.bundle_blob)
        tampered[0] ^= 0x01
        bad = (
            TAG
            + u32(1)
            + u32(len(tampered))
            + bytes(tampered)
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive(bad)

    def test_frame_body_that_is_not_a_bundle(self):
        bad = TAG + u32(1) + u32(5) + b"xxxxx"
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive(bad)

    def test_nested_bundle_with_illegal_structure(self):
        # A structurally legal bundle frame must itself be a canonical
        # encode_delta_report_bundle output; a delta-report-bundle/v0
        # frame is rejected even though the outer framing lines up.
        tampered = bytearray(self.bundle_blob)
        tampered[len(b"thresholdsign/")] ^= 0x01
        bad = (
            TAG
            + u32(1)
            + u32(len(tampered))
            + bytes(tampered)
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive(bad)

    def test_short_garbage(self):
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive(
                TAG + u32(1) + u32(5) + b"xxxxx"
            )


class VerifyArchiveTest(unittest.TestCase):
    def setUp(self):
        (
            self.key,
            _segments,
            self.full,
            self.first,
            self.second,
            _archives,
        ) = build_archives()
        self.archive = DeltaReportBundleArchive(
            (self.full, self.first, self.second)
        )

    def test_verifying_archive_is_true(self):
        self.assertTrue(
            verify_delta_report_bundle_archive(self.archive, self.key)
        )

    def test_delegates_to_each_bundle_verifier(self):
        self.assertIs(
            verify_delta_report_bundle_archive(self.archive, self.key),
            all(
                verify_delta_report_bundle(item, self.key)
                for item in self.archive.items
            ),
        )

    def test_decoded_archive_keeps_verdict(self):
        restored = decode_delta_report_bundle_archive(
            encode_delta_report_bundle_archive(self.archive)
        )
        self.assertTrue(
            verify_delta_report_bundle_archive(restored, self.key)
        )

    def test_one_failing_bundle_makes_the_archive_false(self):
        diagnosis = DeltaDiagnosis(False, "sig", 0, None)
        bad_bundle = DeltaReportBundle(
            self.full.segments,
            DeltaReport(
                diagnosis,
                self.full.report.public_key,
                self.full.report.signature,
            ),
        )
        self.assertTrue(
            verify_delta_report_bundle_archive(
                DeltaReportBundleArchive((self.first,)), self.key
            )
        )
        self.assertFalse(
            verify_delta_report_bundle_archive(
                DeltaReportBundleArchive((self.first, bad_bundle)), self.key
            )
        )
        self.assertFalse(
            verify_delta_report_bundle_archive(
                DeltaReportBundleArchive((bad_bundle, self.first)), self.key
            )
        )

    def test_other_key_is_false(self):
        self.assertFalse(
            verify_delta_report_bundle_archive(
                self.archive, make_other_key()
            )
        )

    def test_non_archive_type_error(self):
        for bad in (
            "x",
            None,
            42,
            object(),
            (self.full,),
            self.full,
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_delta_report_bundle_archive(bad, self.key)

    def test_non_tuple_items_type_error(self):
        for bad in ([self.full], iter((self.full,)), None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_delta_report_bundle_archive(
                    DeltaReportBundleArchive(bad), self.key
                )

    def test_non_bundle_element_type_error(self):
        for bad in ("x", None, 42, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_delta_report_bundle_archive(
                    DeltaReportBundleArchive((bad,)), self.key
                )

    def test_non_key_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_delta_report_bundle_archive(self.archive, bad)

    def test_empty_archive_value_error(self):
        with self.assertRaises(ValueError):
            verify_delta_report_bundle_archive(
                DeltaReportBundleArchive(()), self.key
            )

    def test_illegal_nested_bundle_value_error(self):
        bad_bundle = DeltaReportBundle((), self.full.report)
        with self.assertRaises(ValueError):
            verify_delta_report_bundle_archive(
                DeltaReportBundleArchive((self.first, bad_bundle)),
                self.key,
            )

    def test_illegal_later_item_raises_even_after_failing_item(self):
        # Structural validation of every item precedes the cryptographic
        # verdicts: a failing first item must not mask a structurally
        # illegal second one as a plain False.
        diagnosis = DeltaDiagnosis(False, "sig", 0, None)
        failing_bundle = DeltaReportBundle(
            self.full.segments,
            DeltaReport(
                diagnosis,
                self.full.report.public_key,
                self.full.report.signature,
            ),
        )
        illegal_bundle = DeltaReportBundle((), self.full.report)
        with self.assertRaises(ValueError):
            verify_delta_report_bundle_archive(
                DeltaReportBundleArchive(
                    (failing_bundle, illegal_bundle)
                ),
                self.key,
            )


if __name__ == "__main__":
    unittest.main()
