"""Tests for the canonical HBPBArchive transport encoding:
encode_hbpba / decode_hbpba."""

import unittest

from thresholdsign import (
    AggregateSignature,
    HBPB,
    HBPBArchive,
    decode_hbpb,
    decode_hbpba,
    encode_audit_proof_bundle,
    encode_audit_proof,
    encode_hbpb,
    encode_hbpba,
    AuditProofBundle,
    make_proof,
    verify_hbpba,
)

from test_audit_chain import make_key
from test_audit_extension_proof_bundle_codec import make_other_key
from test_audit_extension_proof_bundle_codec import make_records
from test_hbpb_archive import build_bundles, make_archive

TAG = b"ts/hbpba/w1"
BUNDLE_TAG = b"ts/hbpb/v1"
APB_TAG = b"ts/apb/v1"


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def signature_frame(signature: AggregateSignature) -> bytes:
    out = bytearray(varint(signature.R))
    out += varint(signature.z)
    out += u32(len(signature.signer_ids))
    for signer_id in signature.signer_ids:
        out += varint(signer_id)
    return bytes(out)


def build_wire(archive: HBPBArchive) -> bytes:
    """Independently build the archive wire format straight from the spec."""
    out = bytearray(TAG)
    out += u32(len(archive.items))
    for item in archive.items:
        encoded = encode_hbpb(item)
        out += u32(len(encoded))
        out += encoded
    out += signature_frame(archive.signature)
    return bytes(out)


def signature_start(blob: bytes, item_count: int) -> int:
    """Offset where the outer signature frame begins in an archive blob."""
    offset = len(TAG) + 4
    for _ in range(item_count):
        length = int.from_bytes(blob[offset:offset + 4], "big")
        offset += 4 + length
    return offset


class EncodeDecodeArchiveTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.items = build_bundles(self.key)
        self.archives = (
            make_archive(self.items[:1], self.key, seed=6000),
            make_archive(self.items[:2], self.key, seed=6001),
            make_archive(self.items, self.key, seed=6002),
            make_archive(
                (self.items[3], self.items[1]), self.key, seed=6003
            ),
        )

    def test_wire_matches_independent_spec_build(self):
        for archive in self.archives:
            with self.subTest(n=len(archive.items)):
                blob = encode_hbpba(archive)
                self.assertEqual(blob, build_wire(archive))
                self.assertTrue(blob.startswith(TAG))

    def test_wire_layout_is_tag_count_frames_then_signature(self):
        archive = self.archives[1]
        blob = encode_hbpba(archive)
        offset = 0
        self.assertEqual(blob[offset:len(TAG)], TAG)
        offset += len(TAG)
        self.assertEqual(blob[offset:offset + 4], u32(2))
        offset += 4
        for item in archive.items:
            encoded = encode_hbpb(item)
            self.assertEqual(blob[offset:offset + 4], u32(len(encoded)))
            offset += 4
            self.assertEqual(blob[offset:offset + len(encoded)], encoded)
            offset += len(encoded)
        self.assertEqual(
            blob[offset:], signature_frame(archive.signature)
        )

    def test_frames_are_existing_hbpb_transport_encodings(self):
        archive = self.archives[2]
        blob = encode_hbpba(archive)
        self.assertIn(BUNDLE_TAG, blob)
        offset = len(TAG) + 4
        for item in archive.items:
            length = int.from_bytes(blob[offset:offset + 4], "big")
            offset += 4
            frame = blob[offset:offset + length]
            self.assertEqual(frame, encode_hbpb(item))
            self.assertTrue(bytes(frame).startswith(BUNDLE_TAG))
            offset += length

    def test_frames_decode_standalone(self):
        archive = self.archives[1]
        blob = encode_hbpba(archive)
        offset = len(TAG) + 4
        for item in archive.items:
            length = int.from_bytes(blob[offset:offset + 4], "big")
            offset += 4
            frame = blob[offset:offset + length]
            self.assertEqual(decode_hbpb(bytes(frame)), item)
            offset += length

    def test_outer_signature_frame_matches_audit_proof_bundle_frame(self):
        # The bytes after the item frames are exactly the signature frame
        # encode_audit_proof_bundle writes for the same signature.
        archive = self.archives[0]
        records = make_records(self.key, 1)
        _message, proof = make_proof(records, 0)
        bundle = AuditProofBundle(proof, archive.signature)
        bundle_blob = encode_audit_proof_bundle(bundle)
        proof_body = encode_audit_proof(proof)
        bundle_tail = bundle_blob[len(APB_TAG) + 4 + len(proof_body):]

        archive_blob = encode_hbpba(archive)
        tail_start = signature_start(archive_blob, len(archive.items))
        self.assertEqual(archive_blob[tail_start:], bundle_tail)

    def test_round_trip_byte_for_byte(self):
        for archive in self.archives:
            with self.subTest(n=len(archive.items)):
                blob = encode_hbpba(archive)
                restored = decode_hbpba(blob)
                self.assertIsInstance(restored, HBPBArchive)
                self.assertEqual(restored, archive)
                self.assertEqual(
                    encode_hbpba(restored), blob
                )

    def test_order_is_preserved(self):
        forward = make_archive(
            (self.items[0], self.items[1]), self.key, seed=6010
        )
        reverse = make_archive(
            (self.items[1], self.items[0]), self.key, seed=6011
        )
        restored = decode_hbpba(
            encode_hbpba(forward)
        )
        self.assertEqual(restored.items, (self.items[0], self.items[1]))
        self.assertNotEqual(restored, reverse)
        self.assertEqual(
            decode_hbpba(
                encode_hbpba(reverse)
            ).items,
            (self.items[1], self.items[0]),
        )

    def test_encoding_is_deterministic_and_unique(self):
        archive = make_archive(
            (self.items[0], self.items[1]), self.key, seed=6020
        )
        other = make_archive(
            (self.items[1], self.items[0]), self.key, seed=6021
        )
        single = make_archive(self.items[:1], self.key, seed=6022)
        self.assertEqual(
            encode_hbpba(archive),
            encode_hbpba(archive),
        )
        self.assertNotEqual(
            encode_hbpba(archive),
            encode_hbpba(other),
        )
        self.assertNotEqual(
            encode_hbpba(archive),
            encode_hbpba(single),
        )

    def test_z_zero_is_structurally_legal_and_round_trips(self):
        # z may be zero and encodes as the single body byte 00; such an
        # outer signature is structurally legal for the codec even
        # though no real signature is carried.
        archive = HBPBArchive(
            self.items[:1],
            AggregateSignature(R=5, z=0, signer_ids=(1,)),
        )
        blob = encode_hbpba(archive)
        restored = decode_hbpba(blob)
        self.assertEqual(restored, archive)
        self.assertEqual(encode_hbpba(restored), blob)

    def test_mismatched_outer_signature_still_encodes_and_decodes(self):
        # The codec matches nothing: an outer signature over a different
        # item set encodes, decodes byte for byte, and verify reports
        # False afterwards.
        foreign = make_archive(
            (self.items[3], self.items[0]), self.key, seed=6030
        )
        mismatched = HBPBArchive(
            self.items[:2], foreign.signature
        )
        blob = encode_hbpba(mismatched)
        restored = decode_hbpba(blob)
        self.assertEqual(restored, mismatched)
        self.assertEqual(encode_hbpba(restored), blob)
        self.assertFalse(
            verify_hbpba(restored, self.key)
        )

    def test_decoded_verifying_archive_still_verifies(self):
        for archive in self.archives:
            with self.subTest(n=len(archive.items)):
                restored = decode_hbpba(
                    encode_hbpba(archive)
                )
                self.assertTrue(
                    verify_hbpba(restored, self.key)
                )

    def test_decoded_under_other_key_is_false(self):
        archive = self.archives[0]
        restored = decode_hbpba(
            encode_hbpba(archive)
        )
        self.assertFalse(
            verify_hbpba(restored, make_other_key())
        )


class EncodeArchiveErrorTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.items = build_bundles(self.key)
        self.signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))

    def test_non_archive_type_error(self):
        for bad in (
            "x",
            None,
            42,
            b"x",
            object(),
            self.items,
            (self.items, self.signature),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_hbpba(bad)

    def test_non_tuple_items_type_error(self):
        for bad in (
            list(self.items),
            iter(self.items),
            self.items[0],
            "items",
            None,
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_hbpba(
                    HBPBArchive(bad, self.signature)
                )

    def test_non_bundle_element_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_hbpba(
                    HBPBArchive((bad,), self.signature)
                )
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_hbpba(
                    HBPBArchive(
                        (self.items[0], bad), self.signature
                    )
                )
        # An inner HBP is not an HBPB archive member.
        with self.assertRaises(TypeError):
            encode_hbpba(
                HBPBArchive(
                    (self.items[0].proof,), self.signature
                )
            )

    def test_non_signature_field_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_hbpba(
                    HBPBArchive(self.items, bad)
                )

    def test_empty_archive_value_error(self):
        with self.assertRaises(ValueError):
            encode_hbpba(
                HBPBArchive((), self.signature)
            )

    def test_illegal_nested_bundle_value_error(self):
        from dataclasses import replace
        bad_bundle = HBPB(
            replace(self.items[0].proof, total=2 ** 64 + 1),
            self.signature,
        )
        with self.assertRaises(ValueError):
            encode_hbpba(
                HBPBArchive((bad_bundle,), self.signature)
            )
        with self.assertRaises(ValueError):
            encode_hbpba(
                HBPBArchive(
                    (self.items[0], bad_bundle), self.signature
                )
            )

    def test_nested_bundle_field_type_error(self):
        bad_bundle = HBPB("not-a-proof", self.signature)
        with self.assertRaises(TypeError):
            encode_hbpba(
                HBPBArchive((bad_bundle,), self.signature)
            )

    def test_illegal_outer_signature_value_error(self):
        bad_signatures = (
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=-1, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=-1, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=7, signer_ids=()),
            AggregateSignature(R=5, z=7, signer_ids=(0, 1)),
            AggregateSignature(R=5, z=7, signer_ids=(3, 1)),
            AggregateSignature(R=5, z=7, signer_ids=(1, 1)),
        )
        for bad in bad_signatures:
            with self.assertRaises(ValueError, msg=repr(bad)):
                encode_hbpba(
                    HBPBArchive(self.items, bad)
                )

    def test_bad_outer_signature_nested_field_type_error(self):
        for bad in ("x", None, 5.0, True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_hbpba(
                    HBPBArchive(
                        self.items,
                        AggregateSignature(
                            R=bad, z=7, signer_ids=(1, 3)
                        ),
                    )
                )
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_hbpba(
                    HBPBArchive(
                        self.items,
                        AggregateSignature(
                            R=5, z=bad, signer_ids=(1, 3)
                        ),
                    )
                )
        with self.assertRaises(TypeError):
            encode_hbpba(
                HBPBArchive(
                    self.items,
                    AggregateSignature(R=5, z=7, signer_ids=[1, 3]),
                )
            )
        with self.assertRaises(TypeError):
            encode_hbpba(
                HBPBArchive(
                    self.items,
                    AggregateSignature(R=5, z=7, signer_ids=(1, "3")),
                )
            )

    def test_count_overflow_raises_value_error(self):
        class HugeTuple(tuple):
            def __len__(self):
                return 2 ** 64

        with self.assertRaises(ValueError):
            encode_hbpba(
                HBPBArchive(HugeTuple((self.items[0],)), self.signature)
            )


class DecodeArchiveErrorTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.items = build_bundles(self.key)
        self.archive = make_archive(self.items[:2], self.key, seed=6100)
        self.blob = encode_hbpba(self.archive)
        self.bundle_blob = encode_hbpb(self.items[0])
        self.sig_start = signature_start(self.blob, len(self.archive.items))

    def test_non_bytes_type_error(self):
        for bad in (
            self.blob.decode("latin1"),
            bytearray(self.blob),
            None,
            42,
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                decode_hbpba(bad)

    def test_bad_tag(self):
        swap = b"ts/hbpba/w0"
        with self.assertRaises(ValueError):
            decode_hbpba(
                swap + self.blob[len(TAG):]
            )
        with self.assertRaises(ValueError):
            decode_hbpba(b"")
        with self.assertRaises(ValueError):
            decode_hbpba(self.blob[5:])

    def test_zero_count_is_illegal(self):
        with self.assertRaises(ValueError):
            decode_hbpba(
                TAG
                + u32(0)
                + signature_frame(self.archive.signature)
            )

    def test_zero_frame_length(self):
        bad = (
            TAG
            + u32(1)
            + u32(0)
            + signature_frame(self.archive.signature)
        )
        with self.assertRaises(ValueError):
            decode_hbpba(bad)

    def test_overlong_frame(self):
        bad = (
            TAG
            + u32(1)
            + u32(len(self.bundle_blob) + 1)
            + self.bundle_blob
            + signature_frame(self.archive.signature)
        )
        with self.assertRaises(ValueError):
            decode_hbpba(bad)

    def test_count_mismatch_declared_more_than_frames(self):
        bad = (
            TAG
            + u32(2)
            + u32(len(self.bundle_blob))
            + self.bundle_blob
            + signature_frame(self.archive.signature)
        )
        with self.assertRaises(ValueError):
            decode_hbpba(bad)

    def test_truncation(self):
        with self.assertRaises(ValueError):
            decode_hbpba(TAG)
        with self.assertRaises(ValueError):
            decode_hbpba(self.blob[:-1])
        with self.assertRaises(ValueError):
            decode_hbpba(self.blob[:len(TAG) + 4 + 2])
        with self.assertRaises(ValueError):
            decode_hbpba(self.blob[:self.sig_start + 2])

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_hbpba(self.blob + b"\x00")

    def test_frame_body_that_is_not_a_bundle(self):
        bad = (
            TAG
            + u32(1)
            + u32(5)
            + b"xxxxx"
            + signature_frame(self.archive.signature)
        )
        with self.assertRaises(ValueError):
            decode_hbpba(bad)

    def test_tampered_nested_bundle_frame(self):
        tampered = bytearray(self.blob)
        # First byte of the first frame body is the nested bundle tag.
        tampered[len(TAG) + 4 + 5] ^= 0x01
        with self.assertRaises(ValueError):
            decode_hbpba(bytes(tampered))

    def test_nested_bundle_with_illegal_structure(self):
        # The body framing lines up but the nested bytes themselves must
        # be a canonical encode_hbpb output.
        tampered = bytearray(self.bundle_blob)
        tampered[0] ^= 0x01
        bad = (
            TAG
            + u32(1)
            + u32(len(tampered))
            + bytes(tampered)
            + signature_frame(self.archive.signature)
        )
        with self.assertRaises(ValueError):
            decode_hbpba(bad)

    def test_short_garbage(self):
        with self.assertRaises(ValueError):
            decode_hbpba(TAG + u32(1) + b"x")

    def test_zero_R_is_illegal(self):
        bad = bytearray(self.blob)
        length = int.from_bytes(
            bad[self.sig_start:self.sig_start + 4], "big"
        )
        end = self.sig_start + 4 + length
        self.assertEqual(
            bytes(bad[self.sig_start:end]),
            varint(self.archive.signature.R),
        )
        bad[self.sig_start:end] = varint(0)
        with self.assertRaises(ValueError):
            decode_hbpba(bytes(bad))

    def test_non_canonical_leading_zero_integer(self):
        # Lengthen the R body to two bytes with a forbidden leading 00.
        bad = bytearray(self.blob)
        body = bytes(bad[self.sig_start + 4:self.sig_start + 5])
        bad[self.sig_start:self.sig_start + 5] = (
            u32(2) + b"\x00" + body
        )
        with self.assertRaises(ValueError):
            decode_hbpba(bytes(bad))

    def test_zero_signer_count_is_illegal(self):
        bad = (
            TAG
            + u32(1)
            + u32(len(self.bundle_blob))
            + self.bundle_blob
            + varint(self.archive.signature.R)
            + varint(self.archive.signature.z)
            + u32(0)
        )
        with self.assertRaises(ValueError):
            decode_hbpba(bad)

    def test_signer_count_mismatch(self):
        bad = (
            TAG
            + u32(1)
            + u32(len(self.bundle_blob))
            + self.bundle_blob
            + varint(self.archive.signature.R)
            + varint(self.archive.signature.z)
            + u32(2)
            + varint(1)
        )
        with self.assertRaises(ValueError):
            decode_hbpba(bad)

    def test_zero_signer_id_is_illegal(self):
        bad = (
            TAG
            + u32(1)
            + u32(len(self.bundle_blob))
            + self.bundle_blob
            + varint(self.archive.signature.R)
            + varint(self.archive.signature.z)
            + u32(1)
            + varint(0)
        )
        with self.assertRaises(ValueError):
            decode_hbpba(bad)

    def test_non_increasing_signer_ids(self):
        bad = (
            TAG
            + u32(1)
            + u32(len(self.bundle_blob))
            + self.bundle_blob
            + varint(self.archive.signature.R)
            + varint(self.archive.signature.z)
            + u32(2)
            + varint(3)
            + varint(1)
        )
        with self.assertRaises(ValueError):
            decode_hbpba(bad)


if __name__ == "__main__":
    unittest.main()
