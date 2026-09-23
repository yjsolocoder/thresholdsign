"""Tests for the canonical transport/persistence encoding of a whole
SMP bundle archive: encode_smp_bundle_archive /
decode_smp_bundle_archive. The archive value, its signed message and
its verifier are covered by test_smp_bundle_archive.py."""

import unittest

from thresholdsign import (
    AggregateSignature,
    SMP,
    SMPBundle,
    SMPBundleArchive,
    decode_smp_bundle,
    decode_smp_bundle_archive,
    encode_smp_bundle,
    encode_smp_bundle_archive,
    smp_bundle_archive_message,
    verify_smp_bundle_archive,
)

from test_smp_bundle_archive import (
    build_bundles,
    make_archive,
    u32,
    varint,
)

TAG = b"thresholdsign/smp-bundle-archive/v1"


def sig_frame(R, z, signer_ids):
    """Build an outer signature frame straight from the spec."""
    out = bytearray(varint(R))
    out += varint(z)
    out += u32(len(signer_ids))
    for signer_id in signer_ids:
        out += varint(signer_id)
    return bytes(out)


def build_wire(archive):
    """Independently build the archive wire format straight from the spec."""
    out = bytearray(TAG)
    out += u32(len(archive.items))
    for item in archive.items:
        frame = encode_smp_bundle(item)
        out += u32(len(frame))
        out += frame
    signature = archive.signature
    out += sig_frame(signature.R, signature.z, signature.signer_ids)
    return bytes(out)


def items_body(items):
    out = bytearray(u32(len(items)))
    for item in items:
        frame = encode_smp_bundle(item)
        out += u32(len(frame))
        out += frame
    return bytes(out)


class EncodeDecodeArchiveTest(unittest.TestCase):
    def setUp(self):
        self.key = _make_key()
        self.items = build_bundles(self.key)

    def test_wire_matches_independent_spec_build(self):
        for count in (1, 2, 3):
            items = self.items[:count]
            archive = make_archive(items, self.key, seed=4100 + count)
            with self.subTest(n=count):
                blob = encode_smp_bundle_archive(archive)
                self.assertEqual(blob, build_wire(archive))
                self.assertTrue(blob.startswith(TAG))

    def test_wire_layout_is_tag_count_frames_then_signature(self):
        key = _make_key()
        items = build_bundles(key)[:2]
        archive = make_archive(items, key, seed=4110)
        blob = encode_smp_bundle_archive(archive)
        offset = 0
        self.assertEqual(blob[offset:len(TAG)], TAG)
        offset += len(TAG)
        self.assertEqual(blob[offset:offset + 4], u32(2))
        offset += 4
        for item in items:
            frame = encode_smp_bundle(item)
            self.assertEqual(blob[offset:offset + 4], u32(len(frame)))
            offset += 4
            self.assertEqual(blob[offset:offset + len(frame)], frame)
            offset += len(frame)
        signature = archive.signature
        expected_tail = sig_frame(
            signature.R, signature.z, signature.signer_ids
        )
        self.assertEqual(blob[offset:], expected_tail)
        self.assertEqual(offset + len(expected_tail), len(blob))

    def test_round_trip_byte_for_byte(self):
        for count in (1, 2, 3):
            items = self.items[:count]
            archive = make_archive(items, self.key, seed=4120 + count)
            with self.subTest(n=count):
                blob = encode_smp_bundle_archive(archive)
                restored = decode_smp_bundle_archive(blob)
                self.assertIsInstance(restored, SMPBundleArchive)
                self.assertEqual(restored, archive)
                self.assertEqual(
                    encode_smp_bundle_archive(restored), blob
                )

    def test_frames_decode_standalone(self):
        key = _make_key()
        items = build_bundles(key)
        blob = encode_smp_bundle_archive(
            make_archive(items, key, seed=4130)
        )
        offset = len(TAG) + 4
        for item in items:
            length = int.from_bytes(blob[offset:offset + 4], "big")
            offset += 4
            frame = blob[offset:offset + length]
            offset += length
            self.assertEqual(decode_smp_bundle(bytes(frame)), item)
        # Only the signature frame remains.
        self.assertLess(offset, len(blob))

    def test_order_is_preserved(self):
        key = _make_key()
        items = build_bundles(key)
        forward = make_archive((items[0], items[1]), key, seed=4140)
        reverse = make_archive((items[1], items[0]), key, seed=4141)
        restored = decode_smp_bundle_archive(
            encode_smp_bundle_archive(forward)
        )
        self.assertEqual(restored.items, (items[0], items[1]))
        self.assertNotEqual(restored, reverse)
        self.assertEqual(
            decode_smp_bundle_archive(
                encode_smp_bundle_archive(reverse)
            ).items,
            (items[1], items[0]),
        )

    def test_encoding_is_deterministic_and_unique(self):
        key = _make_key()
        items = build_bundles(key)
        archive = make_archive((items[0], items[1]), key, seed=4150)
        other = make_archive((items[1], items[0]), key, seed=4151)
        single = make_archive((items[0],), key, seed=4152)
        self.assertEqual(
            encode_smp_bundle_archive(archive),
            encode_smp_bundle_archive(archive),
        )
        self.assertNotEqual(
            encode_smp_bundle_archive(archive),
            encode_smp_bundle_archive(other),
        )
        self.assertNotEqual(
            encode_smp_bundle_archive(archive),
            encode_smp_bundle_archive(single),
        )

    def test_decoded_verifying_archive_still_verifies(self):
        key = _make_key()
        archive = make_archive(build_bundles(key), key, seed=4160)
        restored = decode_smp_bundle_archive(
            encode_smp_bundle_archive(archive)
        )
        self.assertTrue(verify_smp_bundle_archive(restored, key))

    def test_mismatched_outer_signature_still_round_trips(self):
        # A structurally legal outer signature over a different message
        # encodes and decodes unchanged; only verification rejects it.
        from test_audit_chain import sign_message

        key = _make_key()
        items = build_bundles(key)[:2]
        message = smp_bundle_archive_message(items[:1], key.public_key)
        foreign = sign_message(key, message, seed=4180)
        archive = SMPBundleArchive(items, foreign)
        blob = encode_smp_bundle_archive(archive)
        self.assertEqual(blob, build_wire(archive))
        restored = decode_smp_bundle_archive(blob)
        self.assertEqual(restored, archive)
        self.assertFalse(verify_smp_bundle_archive(restored, key))

    def test_mismatched_nested_bundle_still_round_trips(self):
        # A bundle signed under another key is structurally legal: the
        # archive codec keeps it byte for byte and verify says False.
        from test_audit_extension_proof_bundle_codec import make_other_key

        key = _make_key()
        other = make_other_key()
        foreign = build_bundles(other)[:1]
        own = build_bundles(key)[:1]
        archive = make_archive(
            (own[0], foreign[0]), key, seed=4170
        )
        restored = decode_smp_bundle_archive(
            encode_smp_bundle_archive(archive)
        )
        self.assertEqual(restored, archive)
        self.assertFalse(verify_smp_bundle_archive(restored, key))

    def test_z_zero_encodes_as_single_00(self):
        # z = 0 is structurally legal for the codec (it never checks the
        # signature against a group); keep the real R and force z = 0.
        from test_audit_chain import sign_message

        message = smp_bundle_archive_message(self.items[:1], self.key.public_key)
        signed = sign_message(self.key, message, signer_ids=(1, 3), seed=4190)
        signature = AggregateSignature(
            R=signed.R, z=0, signer_ids=signed.signer_ids
        )
        items = self.items[:1]
        archive = SMPBundleArchive(items, signature)
        blob = encode_smp_bundle_archive(archive)
        # The signature frame ends with z = length 1 / body 00, one
        # signer count and one signer id.
        expected_tail = (
            varint(signature.R)
            + varint(0)
            + u32(len(signature.signer_ids))
            + b"".join(varint(signer_id) for signer_id in signature.signer_ids)
        )
        self.assertTrue(blob.endswith(expected_tail))
        self.assertEqual(
            decode_smp_bundle_archive(blob).signature.z, 0
        )

    def test_large_signature_integers_round_trip(self):
        # Arbitrary positive integers are structurally legal for the
        # codec; the signature is never checked against a group.
        R = 2 ** 256 + 17
        z = 2 ** 200 - 1
        archive = SMPBundleArchive(
            self.items[:1],
            AggregateSignature(R=R, z=z, signer_ids=(1, 2 ** 64)),
        )
        blob = encode_smp_bundle_archive(archive)
        restored = decode_smp_bundle_archive(blob)
        self.assertEqual(restored, archive)
        self.assertEqual(
            encode_smp_bundle_archive(restored), blob
        )


class EncodeArchiveErrorTest(unittest.TestCase):
    def setUp(self):
        self.key = _make_key()
        self.items = build_bundles(self.key)
        self.archive = make_archive(self.items, self.key, seed=4200)

    def test_non_archive_type_error(self):
        for bad in (
            "x",
            None,
            42,
            b"x",
            object(),
            (self.items, self.archive.signature),
            self.items[0],
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_smp_bundle_archive(bad)

    def test_non_tuple_items_type_error(self):
        signature = self.archive.signature
        for bad in (
            list(self.items),
            iter(self.items),
            self.items[0],
            "items",
            None,
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_smp_bundle_archive(
                    SMPBundleArchive(bad, signature)
                )

    def test_non_bundle_element_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_smp_bundle_archive(
                    SMPBundleArchive((bad,), self.archive.signature)
                )
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_smp_bundle_archive(
                    SMPBundleArchive(
                        (self.items[0], bad), self.archive.signature
                    )
                )
        # An SMP proof is not an SMP bundle.
        with self.assertRaises(TypeError):
            encode_smp_bundle_archive(
                SMPBundleArchive(
                    (self.items[0].proof,), self.archive.signature
                )
            )

    def test_empty_archive_value_error(self):
        with self.assertRaises(ValueError):
            encode_smp_bundle_archive(
                SMPBundleArchive((), self.archive.signature)
            )

    def test_nested_bundle_field_type_error(self):
        bad_bundle = SMPBundle(
            "not-a-proof",
            AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
        )
        with self.assertRaises(TypeError):
            encode_smp_bundle_archive(
                SMPBundleArchive(
                    (bad_bundle,), self.archive.signature
                )
            )

    def test_illegal_nested_bundle_structure_value_error(self):
        bad_bundle = SMPBundle(
            SMP(i=(), n=0, s=(), p=()),
            AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
        )
        with self.assertRaises(ValueError):
            encode_smp_bundle_archive(
                SMPBundleArchive(
                    (bad_bundle,), self.archive.signature
                )
            )
        with self.assertRaises(ValueError):
            encode_smp_bundle_archive(
                SMPBundleArchive(
                    (self.items[0], bad_bundle), self.archive.signature
                )
            )

    def test_bad_outer_signature_field_type_error(self):
        for bad in ("x", None, 5.0, True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_smp_bundle_archive(
                    SMPBundleArchive(self.items, bad)
                )

    def test_illegal_outer_signature_structure_value_error(self):
        for bad in (
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=-1, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=7, signer_ids=()),
            AggregateSignature(R=5, z=7, signer_ids=(3, 1)),
            AggregateSignature(R=5, z=7, signer_ids=(0, 2)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                encode_smp_bundle_archive(
                    SMPBundleArchive(self.items, bad)
                )


class DecodeArchiveErrorTest(unittest.TestCase):
    def setUp(self):
        self.key = _make_key()
        self.items = build_bundles(self.key)
        self.archive = make_archive(self.items, self.key, seed=4300)
        self.blob = encode_smp_bundle_archive(self.archive)
        self.single_frame = encode_smp_bundle(self.items[0])

    def test_non_bytes_type_error(self):
        for bad in (
            self.blob.decode("latin1"),
            bytearray(self.blob),
            None,
            42,
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                decode_smp_bundle_archive(bad)

    def test_bad_tag(self):
        swap = b"thresholdsign/smp-bundle-archive/v0"
        with self.assertRaises(ValueError):
            decode_smp_bundle_archive(
                swap + self.blob[len(TAG):]
            )
        with self.assertRaises(ValueError):
            decode_smp_bundle_archive(b"")
        with self.assertRaises(ValueError):
            decode_smp_bundle_archive(self.blob[5:])

    def test_zero_count_is_illegal(self):
        with self.assertRaises(ValueError):
            decode_smp_bundle_archive(TAG + u32(0))

    def test_truncated_count_or_frames_or_signature(self):
        with self.assertRaises(ValueError):
            decode_smp_bundle_archive(TAG)
        with self.assertRaises(ValueError):
            decode_smp_bundle_archive(self.blob[:-1])
        with self.assertRaises(ValueError):
            decode_smp_bundle_archive(self.blob[:len(TAG) + 4 + 2])

    def test_zero_frame_length(self):
        bad = TAG + u32(1) + u32(0)
        with self.assertRaises(ValueError):
            decode_smp_bundle_archive(bad)

    def test_overlong_frame(self):
        bad = (
            TAG
            + u32(1)
            + u32(len(self.single_frame) + 1)
            + self.single_frame
        )
        with self.assertRaises(ValueError):
            decode_smp_bundle_archive(bad)

    def test_count_mismatch_declared_more_than_frames(self):
        bad = (
            TAG
            + u32(2)
            + u32(len(self.single_frame))
            + self.single_frame
            + sig_frame(5, 7, (1, 3))
        )
        with self.assertRaises(ValueError):
            decode_smp_bundle_archive(bad)

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_smp_bundle_archive(self.blob + b"\x00")

    def test_illegal_nested_bundle_frame(self):
        tampered = bytearray(self.single_frame)
        tampered[0] ^= 0x01
        bad = (
            TAG
            + u32(1)
            + u32(len(tampered))
            + bytes(tampered)
            + sig_frame(5, 7, (1, 3))
        )
        with self.assertRaises(ValueError):
            decode_smp_bundle_archive(bad)

    def test_frame_body_that_is_not_a_bundle(self):
        bad = (
            TAG
            + u32(1)
            + u32(5)
            + b"xxxxx"
            + sig_frame(5, 7, (1, 3))
        )
        with self.assertRaises(ValueError):
            decode_smp_bundle_archive(bad)

    def test_zero_R_is_illegal(self):
        bad = (
            TAG
            + items_body((self.items[0],))
            + sig_frame(0, 7, (1, 3))
        )
        with self.assertRaises(ValueError):
            decode_smp_bundle_archive(bad)

    def test_non_canonical_integer_leading_zero(self):
        body = items_body((self.items[0],))
        # R with a two-byte body starting with 00 is non-canonical.
        bad = (
            TAG
            + body
            + u32(2)
            + b"\x00\x05"
            + varint(7)
            + u32(1)
            + varint(1)
        )
        with self.assertRaises(ValueError):
            decode_smp_bundle_archive(bad)

    def test_overlong_integer_length(self):
        body = items_body((self.items[0],))
        bad = TAG + body + (999999).to_bytes(4, "big")
        with self.assertRaises(ValueError):
            decode_smp_bundle_archive(bad)

    def test_zero_signer_count_is_illegal(self):
        bad = (
            TAG
            + items_body((self.items[0],))
            + varint(5)
            + varint(7)
            + u32(0)
        )
        with self.assertRaises(ValueError):
            decode_smp_bundle_archive(bad)

    def test_zero_or_non_increasing_signer_ids(self):
        for ids in ((0,), (0, 1), (3, 1), (2, 2)):
            bad = (
                TAG
                + items_body((self.items[0],))
                + sig_frame(5, 7, ids)
            )
            with self.assertRaises(ValueError, msg=repr(ids)):
                decode_smp_bundle_archive(bad)


def _make_key():
    # Local import to avoid pulling key-building helpers at module scope.
    from test_audit_chain import make_key

    return make_key()


if __name__ == "__main__":
    unittest.main()
