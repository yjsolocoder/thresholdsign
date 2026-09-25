"""Tests for the canonical HAMPB archive transport encoding:
encode_hampba / decode_hampba."""

import unittest

from thresholdsign import (
    AggregateSignature,
    HAMPB,
    HAMPBArchive,
    HAMP,
    encode_hampb,
    encode_hampba,
    decode_hampba,
    verify_hampba,
)

from test_audit_chain import sign_message
from test_audit_extension_proof_bundle_codec import make_other_key
from test_nonce_reuse import make_key
from test_hamp import archive_of_size, signed_proof

ARCHIVE_TAG = b"ts/hampba/w1"

DUMMY_SIGNATURE = AggregateSignature(R=5, z=7, signer_ids=(1, 3))


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def signed_bundle(n, indices, key, *, seed_base, seed):
    """One key-verifying HAMPB over a fresh archive of ``n`` bundles."""
    archive = archive_of_size(n, key, seed_base=seed_base)
    proof, signature = signed_proof(archive, indices, key, seed=seed)
    return HAMPB(proof, signature)


def build_bundles(key):
    """Several distinct structurally legal, key-verifying HAMPB bundles."""
    return (
        signed_bundle(4, (0, 2), key, seed_base=21100, seed=21200),
        signed_bundle(5, (1, 3), key, seed_base=21110, seed=21210),
        signed_bundle(6, (0, 2, 4), key, seed_base=21120, seed=21220),
    )


def build_wire(archive: HAMPBArchive) -> bytes:
    """Independently build the archive wire format straight from the spec.

    Serializes the fields verbatim without structural validation, so
    archives the encoder rejects can still be rendered into bytes to
    probe the decoder.
    """
    out = bytearray(ARCHIVE_TAG)
    out += u32(len(archive.items))
    for item in archive.items:
        encoded = encode_hampb(item)
        out += frame(encoded)
    signature = archive.signature
    out += varint(signature.R)
    out += varint(signature.z)
    out += u32(len(signature.signer_ids))
    for signer_id in signature.signer_ids:
        out += varint(signer_id)
    return bytes(out)


def make_archive(items, key, *, seed=21300):
    from thresholdsign import hampba_message

    message = hampba_message(items, key.public_key)
    signature = sign_message(key, message, seed=seed)
    return HAMPBArchive(items, signature)


def signature_offset(wire: bytes, signature: AggregateSignature) -> int:
    """Start of the trailing signature frame in an independently built wire."""
    tail = (
        len(varint(signature.R))
        + len(varint(signature.z))
        + 4
        + sum(len(varint(signer_id)) for signer_id in signature.signer_ids)
    )
    return len(wire) - tail


class EncodeHAMPBATest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.items = build_bundles(self.key)

    def test_layout_matches_independent_builder(self):
        for n in range(1, len(self.items) + 1):
            archive = HAMPBArchive(self.items[:n], DUMMY_SIGNATURE)
            self.assertEqual(
                encode_hampba(archive),
                build_wire(archive),
                msg=f"n={n}",
            )

    def test_wire_prefix_is_tag(self):
        archive = HAMPBArchive(self.items[:1], DUMMY_SIGNATURE)
        self.assertTrue(encode_hampba(archive).startswith(ARCHIVE_TAG))

    def test_deterministic_and_unique_output(self):
        archive = make_archive(self.items, self.key, seed=21400)
        self.assertEqual(encode_hampba(archive), encode_hampba(archive))
        other = make_archive(self.items[:2], self.key, seed=21401)
        self.assertNotEqual(
            encode_hampba(archive), encode_hampba(other)
        )

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            encode_hampba("not-an-archive")
        with self.assertRaises(TypeError):
            encode_hampba(None)
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
                encode_hampba(HAMPBArchive(bad_items, signature))
        for bad in ("x", None, 42, b"x", object(), self.items[0].proof):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_hampba(HAMPBArchive((bad,), signature))
        with self.assertRaises(TypeError):
            encode_hampba(HAMPBArchive(self.items, "not-a-signature"))

    def test_empty_archive_value_error(self):
        with self.assertRaises(ValueError):
            encode_hampba(HAMPBArchive((), DUMMY_SIGNATURE))

    def test_illegal_nested_bundle_value_error(self):
        bad_proof = HAMP(
            indices=(), total=0, bundles=(), siblings=()
        )
        bad_bundle = HAMPB(bad_proof, DUMMY_SIGNATURE)
        with self.assertRaises(ValueError):
            encode_hampba(HAMPBArchive((bad_bundle,), DUMMY_SIGNATURE))
        with self.assertRaises(ValueError):
            encode_hampba(
                HAMPBArchive(
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
                encode_hampba(HAMPBArchive(self.items, bad_signature))

    def test_does_not_verify(self):
        # A structurally legal archive whose outer signature signs
        # nothing valid still encodes: encoding checks structure, never
        # signatures.
        archive = HAMPBArchive(self.items, DUMMY_SIGNATURE)
        self.assertEqual(encode_hampba(archive), build_wire(archive))


class DecodeHAMPBATest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.items = build_bundles(self.key)

    def test_roundtrip_for_each_prefix(self):
        for n in range(1, len(self.items) + 1):
            archive = make_archive(self.items[:n], self.key, seed=21500 + n)
            blob = encode_hampba(archive)
            restored = decode_hampba(blob)
            self.assertEqual(restored, archive, msg=f"n={n}")
            self.assertEqual(encode_hampba(restored), blob)

    def test_roundtrip_with_placeholder_signature(self):
        # Structure only: a mismatched outer signature round-trips too.
        archive = HAMPBArchive(self.items, DUMMY_SIGNATURE)
        blob = encode_hampba(archive)
        restored = decode_hampba(blob)
        self.assertEqual(restored, archive)
        self.assertEqual(encode_hampba(restored), blob)

    def test_non_bytes_type_error(self):
        for bad in ("x", b"x".hex(), 42, None, bytearray(b"x")):
            with self.assertRaises(TypeError, msg=repr(bad)):
                decode_hampba(bad)

    def test_bad_tag_and_truncation(self):
        archive = make_archive(self.items, self.key, seed=21600)
        blob = encode_hampba(archive)
        with self.assertRaises(ValueError):
            decode_hampba(b"ts/hampba/w2" + blob[len(ARCHIVE_TAG):])
        with self.assertRaises(ValueError):
            decode_hampba(blob[: len(ARCHIVE_TAG) - 1])
        for cut in range(len(ARCHIVE_TAG), len(blob)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_hampba(blob[:cut])

    def test_trailing_bytes(self):
        archive = make_archive(self.items, self.key, seed=21610)
        blob = encode_hampba(archive)
        with self.assertRaises(ValueError):
            decode_hampba(blob + b"\x00")

    def test_zero_item_count(self):
        archive = HAMPBArchive(self.items, DUMMY_SIGNATURE)
        blob = encode_hampba(archive)
        with self.assertRaises(ValueError):
            decode_hampba(ARCHIVE_TAG + u32(0) + blob[len(ARCHIVE_TAG) + 4:])

    def test_declared_count_greater_than_frames(self):
        archive = HAMPBArchive(self.items, DUMMY_SIGNATURE)
        blob = encode_hampba(archive)
        with self.assertRaises(ValueError):
            decode_hampba(
                ARCHIVE_TAG + u32(len(self.items) + 1)
                + blob[len(ARCHIVE_TAG) + 4:]
            )

    def test_zero_length_frame(self):
        archive = HAMPBArchive(self.items, DUMMY_SIGNATURE)
        blob = encode_hampba(archive)
        # Replace the first item frame's length with zero.
        first_frame_at = len(ARCHIVE_TAG) + 4
        tampered = (
            blob[:first_frame_at]
            + u32(0)
            + blob[first_frame_at + 4:]
        )
        with self.assertRaises(ValueError):
            decode_hampba(tampered)

    def test_overlong_frame_declared_length(self):
        archive = HAMPBArchive(self.items, DUMMY_SIGNATURE)
        blob = encode_hampba(archive)
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
            decode_hampba(tampered)

    def test_bad_nested_frame(self):
        archive = HAMPBArchive(self.items, DUMMY_SIGNATURE)
        blob = encode_hampba(archive)
        first_frame_at = len(ARCHIVE_TAG) + 4
        real_length = int.from_bytes(
            blob[first_frame_at:first_frame_at + 4], "big"
        )
        # A frame whose bytes are not a canonical HAMPB bundle.
        tampered = (
            blob[:first_frame_at]
            + frame(b"garbage")
            + blob[first_frame_at + 4 + real_length:]
        )
        with self.assertRaises(ValueError):
            decode_hampba(tampered)

    def test_signature_frame_errors(self):
        archive = HAMPBArchive(self.items, DUMMY_SIGNATURE)
        blob = encode_hampba(archive)
        sig_at = signature_offset(build_wire(archive), DUMMY_SIGNATURE)
        head = blob[:sig_at]
        # Zero R.
        with self.assertRaises(ValueError):
            decode_hampba(
                head + varint(0)
                + blob[sig_at + len(varint(DUMMY_SIGNATURE.R)):]
            )
        # Non-canonical R: leading zero in the body.
        with self.assertRaises(ValueError):
            decode_hampba(
                head + u32(2) + b"\x00\x05"
                + blob[sig_at + len(varint(DUMMY_SIGNATURE.R)):]
            )
        tail = blob[sig_at:]
        r_and_z = tail[: len(varint(DUMMY_SIGNATURE.R)) + len(varint(DUMMY_SIGNATURE.z))]
        # Zero signer count.
        with self.assertRaises(ValueError):
            decode_hampba(
                head + r_and_z + u32(0) + tail[len(r_and_z) + 4:]
            )
        # Non-increasing signer ids.
        with self.assertRaises(ValueError):
            decode_hampba(
                head + r_and_z + u32(2) + varint(3) + varint(1)
            )
        # Zero signer id.
        with self.assertRaises(ValueError):
            decode_hampba(head + r_and_z + u32(1) + varint(0))

    def test_mismatched_signature_still_decodes(self):
        # Structure is restored, never verified: a signature from
        # another key over the same message decodes and round-trips,
        # and verify reports False.
        from thresholdsign import hampba_message

        archive = make_archive(self.items, self.key, seed=21700)
        message = hampba_message(self.items, self.key.public_key)
        mismatched = sign_message(make_other_key(), message, seed=21701)
        foreign = HAMPBArchive(self.items, mismatched)
        blob = encode_hampba(foreign)
        restored = decode_hampba(blob)
        self.assertEqual(restored, foreign)
        self.assertFalse(verify_hampba(restored, self.key))

    def test_decoded_archive_verifies(self):
        archive = make_archive(self.items, self.key, seed=21710)
        restored = decode_hampba(encode_hampba(archive))
        self.assertTrue(verify_hampba(restored, self.key))


if __name__ == "__main__":
    unittest.main()
