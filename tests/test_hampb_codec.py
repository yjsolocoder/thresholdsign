"""Tests for the canonical HAMPB transport encoding:
encode_hampb / decode_hampb / verify_hampb."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    HAMP,
    HAMPB,
    HDSCArchiveProof,
    HDSCArchiveProofBundle,
    HDSCArchiveProofBundleArchive,
    check_hamp,
    decode_hampb,
    encode_hampb,
    encode_hdsc_archive_proof_bundle,
    make_hamp,
    verify_hampb,
)

from test_audit_chain import sign_message
from test_audit_extension_proof_bundle_codec import make_other_key
from test_nonce_reuse import make_key
from test_hamp import archive_of_size, signed_proof

BUNDLE_TAG = b"ts/hampb/v1"

DUMMY_SIGNATURE = AggregateSignature(R=5, z=7, signer_ids=(1, 3))


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def build_wire(bundle: HAMPB) -> bytes:
    """Independently build the bundle wire format straight from the spec.

    Serializes the fields verbatim without structural validation, so
    proofs the encoder rejects can still be rendered into bytes to probe
    the decoder.
    """
    proof = bundle.proof
    signature = bundle.signature
    out = bytearray(BUNDLE_TAG)
    out += varint(proof.total)
    out += u32(len(proof.indices))
    for index in proof.indices:
        out += varint(index)
    out += u32(len(proof.bundles))
    for inner in proof.bundles:
        out += frame(encode_hdsc_archive_proof_bundle(inner))
    out += u32(len(proof.siblings))
    for sibling in proof.siblings:
        out += sibling
    out += varint(signature.R)
    out += varint(signature.z)
    out += u32(len(signature.signer_ids))
    for signer_id in signature.signer_ids:
        out += varint(signer_id)
    return bytes(out)


def signed_bundle(archive, indices, key, *, seed=10000):
    """Return a signed HAMPB for the given indices."""
    proof, signature = signed_proof(archive, indices, key, seed=seed)
    return HAMPB(proof, signature)


def prefix_archive(archive, n):
    """A truncated view of a shared archive with its placeholder signature."""
    return HDSCArchiveProofBundleArchive(
        archive.items[:n], archive.signature
    )


def signature_offset(wire: bytes, signature: AggregateSignature) -> int:
    """Start of the trailing signature frame in an independently built wire."""
    tail = (
        len(varint(signature.R))
        + len(varint(signature.z))
        + 4
        + sum(len(varint(signer_id)) for signer_id in signature.signer_ids)
    )
    return len(wire) - tail


class HAMPBDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(HAMPB)],
            ["proof", "signature"],
        )
        key = make_key()
        archive = archive_of_size(3, key, seed_base=10100)
        proof, signature = signed_proof(archive, (0, 2), key)
        bundle = HAMPB(proof, signature)
        self.assertIs(bundle.proof, proof)
        self.assertIs(bundle.signature, signature)

    def test_frozen_value_equality_and_hash(self):
        key = make_key()
        archive = archive_of_size(3, key, seed_base=10200)
        proof, signature = signed_proof(archive, (1,), key)
        bundle = HAMPB(proof, signature)
        same = HAMPB(proof=proof, signature=signature)
        self.assertEqual(bundle, same)
        self.assertEqual(hash(bundle), hash(same))
        other_proof, _ = signed_proof(archive, (0, 2), key, seed=10300)
        self.assertNotEqual(bundle, HAMPB(other_proof, signature))
        self.assertNotEqual(
            bundle,
            HAMPB(proof, AggregateSignature(R=6, z=7, signer_ids=(1, 3))),
        )
        with self.assertRaises(FrozenInstanceError):
            bundle.signature = signature

    def test_construction_does_not_validate(self):
        HAMPB("not-a-proof", "not-a-signature")
        HAMPB(None, None)


class EncodeHAMPBTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(6, self.key, seed_base=10400)

    def test_layout_matches_independent_builder(self):
        cases = (
            (1, (0,)),
            (2, (0, 1)),
            (3, (0, 2)),
            (4, (1, 3)),
            (5, (0, 2, 4)),
            (6, (0, 1, 2, 3, 4, 5)),
            (6, (3, 5)),
        )
        for n, indices in cases:
            archive = prefix_archive(self.archive, n)
            bundle = signed_bundle(archive, indices, self.key)
            self.assertEqual(
                encode_hampb(bundle),
                build_wire(bundle),
                msg=f"n={n} indices={indices}",
            )

    def test_deterministic_and_unique_output(self):
        bundle = signed_bundle(self.archive, (0, 2, 4), self.key)
        self.assertEqual(encode_hampb(bundle), encode_hampb(bundle))
        other = signed_bundle(self.archive, (0, 2, 5), self.key)
        self.assertNotEqual(encode_hampb(bundle), encode_hampb(other))

    def test_type_errors(self):
        bundle = signed_bundle(self.archive, (0, 2), self.key)
        with self.assertRaises(TypeError):
            encode_hampb("not-a-bundle")
        with self.assertRaises(TypeError):
            encode_hampb(None)
        with self.assertRaises(TypeError):
            encode_hampb(HAMPB("not-a-proof", bundle.signature))
        proof = bundle.proof
        for bad in (
            HAMP([0, 2], proof.total, proof.bundles, proof.siblings),
            HAMP((0, 2), "6", proof.bundles, proof.siblings),
            HAMP((0, 2), proof.total, list(proof.bundles), proof.siblings),
            HAMP((0, 2), proof.total, proof.bundles, list(proof.siblings)),
            HAMP((0, True), proof.total, proof.bundles, proof.siblings),
            HAMP((0, 2), proof.total, ("x",) * 2, proof.siblings),
            HAMP((0, 2), proof.total, proof.bundles, (b"x" * 32, 9)),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_hampb(HAMPB(bad, bundle.signature))
        with self.assertRaises(TypeError):
            encode_hampb(HAMPB(proof, "not-a-signature"))

    def test_structure_value_errors(self):
        bundle = signed_bundle(self.archive, (0, 2, 4), self.key)
        proof = bundle.proof
        for bad_proof in (
            HAMP((), proof.total, (), ()),
            HAMP((0, 2), 0, proof.bundles[:2], proof.siblings),
            HAMP((0, 6), proof.total, proof.bundles[:2], proof.siblings),
            HAMP((2, 0), proof.total, proof.bundles[:2], proof.siblings),
            HAMP((1, 1), proof.total, proof.bundles[:2], proof.siblings),
            # A bundle tuple that does not pair one-to-one with indices.
            HAMP(proof.indices, proof.total, proof.bundles[:2], proof.siblings),
            HAMP(
                proof.indices,
                proof.total,
                proof.bundles + (proof.bundles[0],),
                proof.siblings,
            ),
            # A sibling that is not exactly 32 bytes.
            HAMP(proof.indices, proof.total, proof.bundles, (b"short",)),
            # A sibling count other than the one total and indices determine.
            HAMP(
                proof.indices,
                proof.total,
                proof.bundles,
                proof.siblings + (b"x" * 32,),
            ),
            HAMP(proof.indices, proof.total, proof.bundles, proof.siblings[:-1]),
        ):
            with self.assertRaises(ValueError, msg=repr(bad_proof)):
                encode_hampb(HAMPB(bad_proof, bundle.signature))

    def test_signature_structure_value_errors(self):
        bundle = signed_bundle(self.archive, (0, 2), self.key)
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
                encode_hampb(HAMPB(bundle.proof, bad_signature))

    def test_illegal_nested_bundle_value_error(self):
        bundle = signed_bundle(self.archive, (0, 2), self.key)
        bad_inner = HDSCArchiveProofBundle(
            HDSCArchiveProof(indices=(), total=0, bundles=(), siblings=()),
            DUMMY_SIGNATURE,
        )
        bad_proof = HAMP(
            bundle.proof.indices,
            bundle.proof.total,
            (bad_inner, bundle.proof.bundles[1]),
            bundle.proof.siblings,
        )
        with self.assertRaises(ValueError):
            encode_hampb(HAMPB(bad_proof, bundle.signature))

    def test_does_not_verify(self):
        # A structurally legal bundle whose signature signs nothing valid
        # still encodes: encoding checks structure, never signatures.
        key = self.key
        proof, _ = signed_proof(self.archive, (0, 2), key)
        bundle = HAMPB(proof, DUMMY_SIGNATURE)
        self.assertEqual(encode_hampb(bundle), build_wire(bundle))


class DecodeHAMPBTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(6, self.key, seed_base=10500)

    def test_roundtrip_for_every_size_and_subset(self):
        for n in range(1, 7):
            archive = prefix_archive(self.archive, n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                bundle = signed_bundle(archive, indices, self.key)
                blob = encode_hampb(bundle)
                restored = decode_hampb(blob)
                self.assertEqual(restored, bundle)
                self.assertEqual(encode_hampb(restored), blob)

    def test_non_bytes_type_error(self):
        for bad in ("x", b"x".hex(), 42, None, bytearray(b"x")):
            with self.assertRaises(TypeError, msg=repr(bad)):
                decode_hampb(bad)

    def test_bad_tag_and_truncation(self):
        bundle = signed_bundle(self.archive, (0, 2), self.key)
        blob = encode_hampb(bundle)
        with self.assertRaises(ValueError):
            decode_hampb(b"ts/hampb/v2" + blob[len(BUNDLE_TAG):])
        with self.assertRaises(ValueError):
            decode_hampb(blob[: len(BUNDLE_TAG) - 1])
        for cut in range(len(BUNDLE_TAG), len(blob)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_hampb(blob[:cut])

    def test_trailing_bytes(self):
        bundle = signed_bundle(self.archive, (0, 2), self.key)
        blob = encode_hampb(bundle)
        with self.assertRaises(ValueError):
            decode_hampb(blob + b"\x00")

    def test_zero_and_overlarge_total(self):
        bundle = signed_bundle(self.archive, (0, 2), self.key)
        blob = encode_hampb(bundle)
        rest = blob[len(BUNDLE_TAG):]
        rest = rest[len(varint(bundle.proof.total)):]
        with self.assertRaises(ValueError):
            decode_hampb(BUNDLE_TAG + varint(0) + rest)
        with self.assertRaises(ValueError):
            decode_hampb(BUNDLE_TAG + varint(1 << 64) + rest)

    def test_empty_and_mismatched_counts(self):
        bundle = signed_bundle(self.archive, (0, 2), self.key)
        blob = encode_hampb(bundle)
        head = BUNDLE_TAG + varint(bundle.proof.total)
        rest = blob[len(head):]
        with self.assertRaises(ValueError):
            decode_hampb(head + u32(0) + rest[4:])
        # Index count 2 but bundle count 3.
        indices = rest[:4]
        indices += rest[4:4 + len(varint(0)) + len(varint(2))]
        tail = rest[4 + len(varint(0)) + len(varint(2)):]
        with self.assertRaises(ValueError):
            decode_hampb(head + indices + u32(3) + tail[4:])

    def test_non_increasing_and_out_of_range_indices(self):
        bundle = signed_bundle(self.archive, (0, 2), self.key)
        proof = bundle.proof
        for bad_indices in ((2, 0), (1, 1), (0, 6), (9,)):
            wire = bytearray(BUNDLE_TAG)
            wire += varint(proof.total)
            wire += u32(len(bad_indices))
            for index in bad_indices:
                wire += varint(index)
            wire += u32(len(proof.bundles))
            for inner in proof.bundles:
                wire += frame(encode_hdsc_archive_proof_bundle(inner))
            wire += u32(len(proof.siblings))
            for sibling in proof.siblings:
                wire += sibling
            wire += varint(bundle.signature.R)
            wire += varint(bundle.signature.z)
            wire += u32(len(bundle.signature.signer_ids))
            for signer_id in bundle.signature.signer_ids:
                wire += varint(signer_id)
            with self.assertRaises(ValueError, msg=f"indices={bad_indices}"):
                decode_hampb(bytes(wire))

    def test_bad_nested_frame(self):
        bundle = signed_bundle(self.archive, (0, 2), self.key)
        blob = encode_hampb(bundle)
        head = BUNDLE_TAG + varint(bundle.proof.total)
        head += u32(2) + varint(0) + varint(2) + u32(2)
        # Zero-length nested frame.
        with self.assertRaises(ValueError):
            decode_hampb(head + u32(0) + blob[len(head) + 4:])
        # A nested frame whose bytes are not a canonical bundle.
        with self.assertRaises(ValueError):
            decode_hampb(head + frame(b"garbage") + blob[len(head) + 4:])

    def test_sibling_count_mismatch(self):
        bundle = signed_bundle(self.archive, (0, 3), self.key)
        self.assertGreater(len(bundle.proof.siblings), 0)
        blob = encode_hampb(bundle)
        # Locate the sibling count: after tag, total, indices and bundles.
        offset = len(BUNDLE_TAG)
        offset += len(varint(bundle.proof.total))
        offset += 4
        for index in bundle.proof.indices:
            offset += len(varint(index))
        offset += 4
        for inner in bundle.proof.bundles:
            encoded = encode_hdsc_archive_proof_bundle(inner)
            offset += 4 + len(encoded)
        count_at = offset
        wrong = blob[:count_at] + u32(len(bundle.proof.siblings) + 1)
        wrong += blob[count_at + 4:]
        with self.assertRaises(ValueError):
            decode_hampb(wrong)

    def test_signature_frame_errors(self):
        bundle = signed_bundle(self.archive, (0, 2), self.key)
        blob = encode_hampb(bundle)
        sig_at = signature_offset(build_wire(bundle), bundle.signature)
        head = blob[:sig_at]
        # Zero R.
        with self.assertRaises(ValueError):
            decode_hampb(head + varint(0) + blob[sig_at + len(varint(bundle.signature.R)):])
        # Non-canonical R: leading zero in the body.
        with self.assertRaises(ValueError):
            decode_hampb(head + u32(2) + b"\x00\x05" + blob[sig_at + len(varint(bundle.signature.R)):])
        # Zero signer count.
        tail = blob[sig_at:]
        r_and_z = tail[: len(varint(bundle.signature.R)) + len(varint(bundle.signature.z))]
        with self.assertRaises(ValueError):
            decode_hampb(head + r_and_z + u32(0) + tail[len(r_and_z) + 4:])
        # Non-increasing signer ids.
        with self.assertRaises(ValueError):
            decode_hampb(head + r_and_z + u32(2) + varint(3) + varint(1))
        # Zero signer id.
        with self.assertRaises(ValueError):
            decode_hampb(head + r_and_z + u32(1) + varint(0))

    def test_mismatched_signature_still_decodes(self):
        # Structure is restored, never verified: a signature from another
        # key over the same statement decodes and round-trips, and verify
        # reports False.
        proof, _ = signed_proof(self.archive, (0, 2), self.key)
        message, _ = make_hamp(self.archive, (0, 2))
        mismatched = sign_message(make_other_key(), message, seed=10700)
        bundle = HAMPB(proof, mismatched)
        blob = encode_hampb(bundle)
        restored = decode_hampb(blob)
        self.assertEqual(restored, bundle)
        self.assertFalse(verify_hampb(restored, self.key))


class VerifyHAMPBTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(6, self.key, seed_base=10600)

    def test_signed_bundles_verify(self):
        for n, indices in (
            (1, (0,)),
            (3, (0, 2)),
            (5, (0, 2, 4)),
            (6, tuple(range(6))),
        ):
            archive = prefix_archive(self.archive, n)
            bundle = signed_bundle(archive, indices, self.key)
            self.assertTrue(verify_hampb(bundle, self.key))
            restored = decode_hampb(encode_hampb(bundle))
            self.assertTrue(verify_hampb(restored, self.key))

    def test_tampered_and_wrong_key_return_false(self):
        bundle = signed_bundle(self.archive, (0, 2, 4), self.key)
        proof = bundle.proof
        moved = HAMPB(
            HAMP((0, 2, 5), proof.total, proof.bundles, proof.siblings),
            bundle.signature,
        )
        self.assertFalse(verify_hampb(moved, self.key))
        swapped = HAMPB(
            HAMP(
                proof.indices,
                proof.total,
                (proof.bundles[1], proof.bundles[0], proof.bundles[2]),
                proof.siblings,
            ),
            bundle.signature,
        )
        self.assertFalse(verify_hampb(swapped, self.key))
        self.assertFalse(verify_hampb(bundle, make_other_key()))

    def test_matches_check_hamp(self):
        bundle = signed_bundle(self.archive, (1, 4), self.key)
        self.assertEqual(
            verify_hampb(bundle, self.key),
            check_hamp(bundle.proof, bundle.signature, self.key),
        )

    def test_type_errors(self):
        bundle = signed_bundle(self.archive, (0,), self.key)
        with self.assertRaises(TypeError):
            verify_hampb("not-a-bundle", self.key)
        with self.assertRaises(TypeError):
            verify_hampb(HAMPB("not-a-proof", bundle.signature), self.key)


if __name__ == "__main__":
    unittest.main()
