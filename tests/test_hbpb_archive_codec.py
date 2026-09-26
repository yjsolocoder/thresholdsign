"""Tests for the canonical HBPB archive transport encoding:
encode_hbpba / decode_hbpba."""

import unittest

from thresholdsign import (
    AggregateSignature,
    HBP,
    HBPB,
    HBPBArchive,
    encode_hbpb,
    encode_hbpba,
    decode_hbpba,
    verify_hbpba,
)

from test_audit_chain import sign_message
from test_audit_extension_proof_bundle_codec import make_other_key
from test_nonce_reuse import make_key
from test_hbp import archive_of_size, signed_hbpb

ARCHIVE_TAG = b"ts/hbpba/w1"

DUMMY_SIGNATURE = AggregateSignature(R=5, z=7, signer_ids=(1, 3))


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def signed_bundle(n, indices, key, *, seed_base, seed):
    """One key-verifying HBPB over a fresh HBAPB archive of ``n`` bundles."""
    source = archive_of_size(n, key, seed_base=seed_base)
    return signed_hbpb(source, indices, key, seed=seed)


def build_bundles(key):
    """Several distinct structurally legal, key-verifying HBPB bundles."""
    return (
        signed_bundle(4, (0, 2), key, seed_base=51100, seed=51200),
        signed_bundle(5, (1, 3), key, seed_base=51110, seed=51210),
        signed_bundle(6, (0, 2, 4), key, seed_base=51120, seed=51220),
    )


def build_wire(archive: HBPBArchive) -> bytes:
    """Independently build the archive wire format straight from the spec.

    Serializes the fields verbatim without structural validation, so
    archives the encoder rejects can still be rendered into bytes to
    probe the decoder.
    """
    out = bytearray(ARCHIVE_TAG)
    out += u32(len(archive.items))
    for item in archive.items:
        encoded = encode_hbpb(item)
        out += frame(encoded)
    signature = archive.signature
    out += varint(signature.R)
    out += varint(signature.z)
    out += u32(len(signature.signer_ids))
    for signer_id in signature.signer_ids:
        out += varint(signer_id)
    return bytes(out)


def make_archive(items, key, *, seed=51300):
    from thresholdsign import hbpba_message

    message = hbpba_message(items, key.public_key)
    signature = sign_message(key, message, seed=seed)
    return HBPBArchive(items, signature)


def signature_offset(wire: bytes, signature: AggregateSignature) -> int:
    """Start of the trailing signature frame in an independently built wire."""
    tail = (
        len(varint(signature.R))
        + len(varint(signature.z))
        + 4
        + sum(len(varint(signer_id)) for signer_id in signature.signer_ids)
    )
    return len(wire) - tail


class EncodeHBPBATest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.items = build_bundles(self.key)

    def test_layout_matches_independent_builder(self):
        for n in range(1, len(self.items) + 1):
            archive = HBPBArchive(self.items[:n], DUMMY_SIGNATURE)
            self.assertEqual(
                encode_hbpba(archive),
                build_wire(archive),
                msg=f"n={n}",
            )

    def test_wire_prefix_is_tag(self):
        archive = HBPBArchive(self.items[:1], DUMMY_SIGNATURE)
        self.assertTrue(encode_hbpba(archive).startswith(ARCHIVE_TAG))

    def test_deterministic_and_unique_output(self):
        archive = make_archive(self.items, self.key, seed=51400)
        self.assertEqual(encode_hbpba(archive), encode_hbpba(archive))
        other = make_archive(self.items[:2], self.key, seed=51401)
        self.assertNotEqual(
            encode_hbpba(archive), encode_hbpba(other)
        )

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            encode_hbpba("not-an-archive")
        with self.assertRaises(TypeError):
            encode_hbpba(None)
        signature = DUMMY_SIGNATURE
        for bad_items in (
            list(self.items),
            iter(self.items),
            self.items[0],
            "items",
            None,
            42,
        ):
            with self.assertRaises(TypeError, msg=repr(bad_items)):
                encode_hbpba(HBPBArchive(bad_items, signature))
        for bad in ("x", None, 42, b"x", object(), self.items[0].proof):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_hbpba(HBPBArchive((bad,), signature))
        with self.assertRaises(TypeError):
            encode_hbpba(HBPBArchive(self.items, "not-a-signature"))

    def test_empty_archive_value_error(self):
        with self.assertRaises(ValueError):
            encode_hbpba(HBPBArchive((), DUMMY_SIGNATURE))

    def test_illegal_nested_bundle_value_error(self):
        bad_proof = HBP(
            indices=(), total=0, bundles=(), siblings=()
        )
        bad_bundle = HBPB(bad_proof, DUMMY_SIGNATURE)
        with self.assertRaises(ValueError):
            encode_hbpba(HBPBArchive((bad_bundle,), DUMMY_SIGNATURE))
        with self.assertRaises(ValueError):
            encode_hbpba(
                HBPBArchive(
                    (self.items[0], bad_bundle), DUMMY_SIGNATURE
                )
            )

    def test_signature_structure_value_errors(self):
        for bad_signature in (
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=-1, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=-1, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=7, signer_ids=()),
            AggregateSignature(R=5, z=7, signer_ids=(0, 3)),
            AggregateSignature(R=5, z=7, signer_ids=(3, 1)),
            AggregateSignature(R=5, z=7, signer_ids=(1, 1)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad_signature)):
                encode_hbpba(HBPBArchive(self.items, bad_signature))

    def test_does_not_verify(self):
        # A structurally legal archive whose outer signature signs
        # nothing valid still encodes: encoding checks structure, never
        # signatures.
        archive = HBPBArchive(self.items, DUMMY_SIGNATURE)
        self.assertEqual(encode_hbpba(archive), build_wire(archive))


class DecodeHBPBATest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.items = build_bundles(self.key)

    def test_roundtrip_for_each_prefix(self):
        for n in range(1, len(self.items) + 1):
            archive = make_archive(self.items[:n], self.key, seed=51500 + n)
            blob = encode_hbpba(archive)
            restored = decode_hbpba(blob)
            self.assertEqual(restored, archive, msg=f"n={n}")
            self.assertEqual(encode_hbpba(restored), blob)

    def test_roundtrip_with_placeholder_signature(self):
        # Structure only: a mismatched outer signature round-trips too.
        archive = HBPBArchive(self.items, DUMMY_SIGNATURE)
        blob = encode_hbpba(archive)
        restored = decode_hbpba(blob)
        self.assertEqual(restored, archive)
        self.assertEqual(encode_hbpba(restored), blob)

    def test_non_bytes_type_error(self):
        for bad in ("x", b"x".hex(), 42, None, bytearray(b"x")):
            with self.assertRaises(TypeError, msg=repr(bad)):
                decode_hbpba(bad)

    def test_bad_tag_and_truncation(self):
        archive = make_archive(self.items, self.key, seed=51600)
        blob = encode_hbpba(archive)
        with self.assertRaises(ValueError):
            decode_hbpba(b"ts/hbpba/w2" + blob[len(ARCHIVE_TAG):])
        with self.assertRaises(ValueError):
            decode_hbpba(blob[: len(ARCHIVE_TAG) - 1])
        # Exhaustively probe every cut on a compact single-item
        # archive — a three-item HBPB frame runs to tens of thousands
        # of bytes because every nested bundle is itself a multi-proof.
        source = archive_of_size(1, self.key, seed_base=51601)
        bundle = signed_hbpb(source, (0,), self.key, seed=51602)
        small = encode_hbpba(HBPBArchive((bundle,), DUMMY_SIGNATURE))
        for cut in range(len(ARCHIVE_TAG), len(small)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_hbpba(small[:cut])

    def test_trailing_bytes(self):
        archive = make_archive(self.items, self.key, seed=51610)
        blob = encode_hbpba(archive)
        with self.assertRaises(ValueError):
            decode_hbpba(blob + b"\x00")

    def test_zero_item_count(self):
        archive = HBPBArchive(self.items, DUMMY_SIGNATURE)
        blob = encode_hbpba(archive)
        with self.assertRaises(ValueError):
            decode_hbpba(ARCHIVE_TAG + u32(0) + blob[len(ARCHIVE_TAG) + 4:])

    def test_declared_count_greater_than_frames(self):
        archive = HBPBArchive(self.items, DUMMY_SIGNATURE)
        blob = encode_hbpba(archive)
        with self.assertRaises(ValueError):
            decode_hbpba(
                ARCHIVE_TAG + u32(len(self.items) + 1)
                + blob[len(ARCHIVE_TAG) + 4:]
            )

    def test_zero_length_frame(self):
        archive = HBPBArchive(self.items, DUMMY_SIGNATURE)
        blob = encode_hbpba(archive)
        # Replace the first item frame's length with zero.
        first_frame_at = len(ARCHIVE_TAG) + 4
        tampered = (
            blob[:first_frame_at]
            + u32(0)
            + blob[first_frame_at + 4:]
        )
        with self.assertRaises(ValueError):
            decode_hbpba(tampered)

    def test_overlong_frame_declared_length(self):
        archive = HBPBArchive(self.items, DUMMY_SIGNATURE)
        blob = encode_hbpba(archive)
        first_frame_at = len(ARCHIVE_TAG) + 4
        real_length = int.from_bytes(
            blob[first_frame_at:first_frame_at + 4], "big"
        )
        tampered = (
            blob[:first_frame_at]
            + u32(real_length + 1)
            + blob[first_frame_at + 4:]
        )
        with self.assertRaises(ValueError):
            decode_hbpba(tampered)

    def test_bad_nested_frame(self):
        archive = HBPBArchive(self.items, DUMMY_SIGNATURE)
        blob = encode_hbpba(archive)
        first_frame_at = len(ARCHIVE_TAG) + 4
        real_length = int.from_bytes(
            blob[first_frame_at:first_frame_at + 4], "big"
        )
        # A frame whose bytes are not a canonical HBPB bundle.
        tampered = (
            blob[:first_frame_at]
            + frame(b"garbage")
            + blob[first_frame_at + 4 + real_length:]
        )
        with self.assertRaises(ValueError):
            decode_hbpba(tampered)

    def test_signature_frame_errors(self):
        archive = HBPBArchive(self.items, DUMMY_SIGNATURE)
        blob = encode_hbpba(archive)
        sig_at = signature_offset(build_wire(archive), DUMMY_SIGNATURE)
        head = blob[:sig_at]
        # Zero R.
        with self.assertRaises(ValueError):
            decode_hbpba(
                head + varint(0)
                + blob[sig_at + len(varint(DUMMY_SIGNATURE.R)):]
            )
        # Non-canonical R: leading zero in the body.
        with self.assertRaises(ValueError):
            decode_hbpba(
                head + u32(2) + b"\x00\x05"
                + blob[sig_at + len(varint(DUMMY_SIGNATURE.R)):]
            )
        tail = blob[sig_at:]
        r_and_z = tail[: len(varint(DUMMY_SIGNATURE.R)) + len(varint(DUMMY_SIGNATURE.z))]
        # Zero signer count.
        with self.assertRaises(ValueError):
            decode_hbpba(
                head + r_and_z + u32(0) + tail[len(r_and_z) + 4:]
            )
        # Non-increasing signer ids.
        with self.assertRaises(ValueError):
            decode_hbpba(
                head + r_and_z + u32(2) + varint(3) + varint(1)
            )
        # Zero signer id.
        with self.assertRaises(ValueError):
            decode_hbpba(head + r_and_z + u32(1) + varint(0))

    def test_mismatched_signature_still_decodes(self):
        # Structure is restored, never verified: a signature from
        # another key over the same message decodes and round-trips,
        # and verify reports False.
        from thresholdsign import hbpba_message

        archive = make_archive(self.items, self.key, seed=51700)
        message = hbpba_message(self.items, self.key.public_key)
        mismatched = sign_message(make_other_key(), message, seed=51701)
        foreign = HBPBArchive(self.items, mismatched)
        blob = encode_hbpba(foreign)
        restored = decode_hbpba(blob)
        self.assertEqual(restored, foreign)
        self.assertFalse(verify_hbpba(restored, self.key))

    def test_decoded_archive_verifies(self):
        archive = make_archive(self.items, self.key, seed=51710)
        restored = decode_hbpba(encode_hbpba(archive))
        self.assertTrue(verify_hbpba(restored, self.key))


if __name__ == "__main__":
    unittest.main()
