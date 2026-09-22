"""Tests for the canonical segment-set transport encoding of incremental
audit-extension checkpoint chains: encode_delta_chain_segments and
decode_delta_chain_segments."""

import unittest

from thresholdsign import (
    AuditExtensionDeltaCheckpointChain,
    decode_audit_extension_delta_checkpoint_chain,
    decode_delta_chain_segments,
    encode_audit_extension_delta_checkpoint_chain,
    encode_delta_chain_segments,
    join_delta_chain_segments,
    partition_delta_chain,
    slice_audit_extension_delta_checkpoint_chain,
)

from test_audit_extension_delta_checkpoint_chain_segment import make_delta
from test_audit_chain import make_key
from test_audit_extension_proof_bundle_codec import make_records

TAG = b"thresholdsign/delta-chain-segments/v1"


def u32(value):
    return value.to_bytes(4, "big")


def build_segments():
    key = make_key()
    records = make_records(key, 7)
    splits = [(2, 3), (3, 5), (5, 6), (6, 7)]
    delta = make_delta(key, records, splits)
    return key, delta, partition_delta_chain(delta, (1, 3))


class EncodeDecodeRoundTripTest(unittest.TestCase):
    def test_roundtrip_partitioned_segments_in_order(self):
        key, delta, segments = build_segments()
        blob = encode_delta_chain_segments(segments)
        restored = decode_delta_chain_segments(blob)
        self.assertIsInstance(restored, tuple)
        self.assertEqual(restored, segments)
        # Order matters: reversing must not compare equal.
        self.assertNotEqual(
            decode_delta_chain_segments(
                encode_delta_chain_segments(tuple(reversed(segments)))
            ),
            segments,
        )

    def test_single_segment_roundtrip(self):
        key, delta, segments = build_segments()
        single = (segments[0],)
        restored = decode_delta_chain_segments(
            encode_delta_chain_segments(single)
        )
        self.assertEqual(restored, single)

    def test_wire_layout_is_tag_count_then_length_prefixed_frames(self):
        key, delta, segments = build_segments()
        blob = encode_delta_chain_segments(segments)
        self.assertTrue(blob.startswith(TAG))
        offset = len(TAG)
        self.assertEqual(blob[offset:offset + 4], u32(len(segments)))
        offset += 4
        for segment in segments:
            frame = encode_audit_extension_delta_checkpoint_chain(segment)
            self.assertEqual(blob[offset:offset + 4], u32(len(frame)))
            offset += 4
            self.assertEqual(blob[offset:offset + len(frame)], frame)
            offset += len(frame)
        self.assertEqual(offset, len(blob))

    def test_reencode_is_byte_for_byte(self):
        key, delta, segments = build_segments()
        blob = encode_delta_chain_segments(segments)
        restored = decode_delta_chain_segments(blob)
        self.assertEqual(encode_delta_chain_segments(restored), blob)

    def test_frames_are_existing_delta_chain_encoding(self):
        key, delta, segments = build_segments()
        blob = encode_delta_chain_segments(segments)
        # Pull the frames out manually and check each one standalone.
        offset = len(TAG) + 4
        for segment in segments:
            length = int.from_bytes(blob[offset:offset + 4], "big")
            offset += 4
            frame = blob[offset:offset + length]
            offset += length
            self.assertEqual(
                decode_audit_extension_delta_checkpoint_chain(bytes(frame)),
                segment,
            )

    def test_archive_and_reassemble_through_join(self):
        key, delta, segments = build_segments()
        blob = encode_delta_chain_segments(segments)
        restored = decode_delta_chain_segments(blob)
        self.assertEqual(join_delta_chain_segments(restored), delta)

    def test_seams_are_not_checked_on_decode(self):
        # Two individually legal segments that do not sit in chain order
        # still decode; join_delta_chain_segments is what rejects them.
        key, delta, segments = build_segments()
        shuffled = (segments[2], segments[0])
        restored = decode_delta_chain_segments(
            encode_delta_chain_segments(shuffled)
        )
        self.assertEqual(restored, shuffled)
        with self.assertRaises(ValueError):
            join_delta_chain_segments(restored)


class EncodeErrorTest(unittest.TestCase):
    def setUp(self):
        self.key, self.delta, self.segments = build_segments()

    def test_non_tuple_container_type_error(self):
        for bad in (
            list(self.segments),
            iter(self.segments),
            [self.segments[0]],
            self.segments[0],
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_delta_chain_segments(bad)

    def test_non_segment_element_type_error(self):
        for bad in ("not a chain", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_delta_chain_segments((bad,))
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_delta_chain_segments(
                    (self.segments[0], bad, self.segments[1])
                )

    def test_empty_tuple_value_error(self):
        with self.assertRaises(ValueError):
            encode_delta_chain_segments(())

    def test_nested_field_type_error(self):
        bad_segment = AuditExtensionDeltaCheckpointChain(
            "not a proof",
            self.segments[0].additions,
            self.segments[0].signatures,
        )
        with self.assertRaises(TypeError):
            encode_delta_chain_segments((bad_segment,))

    def test_nested_field_value_error(self):
        bad_segment = AuditExtensionDeltaCheckpointChain(
            self.segments[0].first,
            self.segments[0].additions,
            self.segments[0].signatures[:-1],
        )
        with self.assertRaises(ValueError):
            encode_delta_chain_segments((bad_segment,))


class DecodeErrorTest(unittest.TestCase):
    def setUp(self):
        self.key, self.delta, self.segments = build_segments()
        self.blob = encode_delta_chain_segments(self.segments)

    def test_non_bytes_type_error(self):
        for bad in (self.blob.decode("latin1"), bytearray(self.blob), None, 42):
            with self.assertRaises(TypeError, msg=repr(bad)):
                decode_delta_chain_segments(bad)

    def test_bad_tag(self):
        bad = b"thresholdsign/delta-chain-segments/v0" + self.blob[len(TAG):]
        with self.assertRaises(ValueError):
            decode_delta_chain_segments(bad)
        with self.assertRaises(ValueError):
            decode_delta_chain_segments(b"")
        with self.assertRaises(ValueError):
            decode_delta_chain_segments(self.blob[5:])

    def test_zero_count_is_illegal(self):
        bad = TAG + u32(0)
        with self.assertRaises(ValueError):
            decode_delta_chain_segments(bad)

    def test_truncated_count(self):
        with self.assertRaises(ValueError):
            decode_delta_chain_segments(TAG)
        with self.assertRaises(ValueError):
            decode_delta_chain_segments(TAG + self.blob[len(TAG):len(TAG) + 2])

    def test_truncated_frame_length_or_body(self):
        # Count says 3 but the blob is cut off.
        with self.assertRaises(ValueError):
            decode_delta_chain_segments(self.blob[:-1])
        with self.assertRaises(ValueError):
            decode_delta_chain_segments(self.blob[: len(TAG) + 4 + 2])

    def test_zero_frame_length(self):
        frame0 = encode_audit_extension_delta_checkpoint_chain(
            self.segments[0]
        )
        bad = TAG + u32(2) + u32(0) + u32(len(frame0)) + frame0
        with self.assertRaises(ValueError):
            decode_delta_chain_segments(bad)

    def test_overlong_frame(self):
        frame0 = encode_audit_extension_delta_checkpoint_chain(
            self.segments[0]
        )
        # Claimed length exceeds what is present.
        bad = (
            TAG
            + u32(1)
            + u32(len(frame0) + 1)
            + frame0
        )
        with self.assertRaises(ValueError):
            decode_delta_chain_segments(bad)

    def test_count_mismatch_declared_more_than_frames(self):
        frame0 = encode_audit_extension_delta_checkpoint_chain(
            self.segments[0]
        )
        bad = TAG + u32(2) + u32(len(frame0)) + frame0
        with self.assertRaises(ValueError):
            decode_delta_chain_segments(bad)

    def test_trailing_bytes(self):
        frame0 = encode_audit_extension_delta_checkpoint_chain(
            self.segments[0]
        )
        good = TAG + u32(1) + u32(len(frame0)) + frame0
        with self.assertRaises(ValueError):
            decode_delta_chain_segments(good + b"\x00")

    def test_illegal_nested_frame(self):
        frame0 = encode_audit_extension_delta_checkpoint_chain(
            self.segments[0]
        )
        # Corrupt the nested frame's own tag; the per-frame decoder must
        # reject it while the outer length framing still lines up.
        tampered = bytearray(frame0)
        tampered[0] ^= 0x01
        bad = TAG + u32(1) + u32(len(tampered)) + bytes(tampered)
        with self.assertRaises(ValueError):
            decode_delta_chain_segments(bytes(bad))

    def test_short_garbage_frame(self):
        bad = TAG + u32(1) + u32(5) + b"xxxxx"
        with self.assertRaises(ValueError):
            decode_delta_chain_segments(bad)


if __name__ == "__main__":
    unittest.main()
