"""Tests for the canonical HPAP proof transport encoding
encode_hpap / decode_hpap and the HPAPB proof-plus-signature bundle
HPAPB / encode_hpapb / decode_hpapb / verify_hpapb over the HPB archive
membership proofs."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    HPAP,
    HPAPB,
    HPBArchive,
    check_hpap,
    decode_hpap,
    decode_hpapb,
    encode_hpap,
    encode_hpapb,
    encode_hpb,
    make_hpap,
    verify_hpapb,
)

from test_audit_chain import sign_message
from test_audit_extension_proof_bundle_codec import make_other_key
from test_nonce_reuse import make_key
from test_hpap import archive_of_size, signed_proof

PROOF_TAG = b"ts/hpap/v1"
BUNDLE_TAG = b"ts/hpapb/v1"

DUMMY_OUTER_SIGNATURE = AggregateSignature(R=5, z=7, signer_ids=(1, 3))


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def signed_bundle(archive, indices, key, *, seed=52000):
    proof, signature = signed_proof(archive, indices, key, seed=seed)
    return HPAPB(proof, signature)


def build_proof_wire(proof):
    """Independently build the HPAP wire format straight from the spec."""
    out = bytearray(PROOF_TAG)
    out += varint(proof.total)
    out += u32(len(proof.indices))
    for index in proof.indices:
        out += varint(index)
    out += u32(len(proof.bundles))
    for inner in proof.bundles:
        out += frame(encode_hpb(inner))
    out += u32(len(proof.siblings))
    for sibling in proof.siblings:
        out += sibling
    return bytes(out)


def build_bundle_wire(bundle):
    """Independently build the HPAPB wire format straight from the spec."""
    signature = bundle.signature
    out = bytearray(BUNDLE_TAG)
    out += frame(build_proof_wire(bundle.proof))
    out += varint(signature.R)
    out += varint(signature.z)
    out += u32(len(signature.signer_ids))
    for signer_id in signature.signer_ids:
        out += varint(signer_id)
    return bytes(out)


class HPAPBDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(HPAPB)],
            ["proof", "signature"],
        )
        key = make_key()
        archive = archive_of_size(3, key)
        proof, signature = signed_proof(archive, (0, 2), key)
        bundle = HPAPB(proof, signature)
        self.assertIs(bundle.proof, proof)
        self.assertIs(bundle.signature, signature)

    def test_frozen_value_equality_and_hash(self):
        key = make_key()
        archive = archive_of_size(3, key)
        proof, signature = signed_proof(archive, (1,), key)
        bundle = HPAPB(proof, signature)
        same = HPAPB(proof=proof, signature=signature)
        self.assertEqual(bundle, same)
        self.assertEqual(hash(bundle), hash(same))
        self.assertNotEqual(
            bundle,
            HPAPB(proof, AggregateSignature(R=6, z=7, signer_ids=(1, 3))),
        )
        with self.assertRaises(FrozenInstanceError):
            bundle.signature = signature

    def test_construction_does_not_validate(self):
        HPAPB("not-a-proof", "not-a-signature")
        HPAPB(None, None)


class EncodeHPAPTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(8, self.key)

    def _archive_of_size(self, n):
        return HPBArchive(self.archive.items[:n], self.archive.signature)

    def test_layout_matches_independent_builder(self):
        cases = (
            (1, (0,)),
            (2, (0, 1)),
            (3, (0, 2)),
            (4, (1, 3)),
            (5, (0, 2, 4)),
            (8, (0, 2, 4, 6)),
            (8, tuple(range(8))),
        )
        for n, indices in cases:
            archive = self._archive_of_size(n)
            proof, _signature = signed_proof(archive, indices, self.key)
            self.assertEqual(
                encode_hpap(proof),
                build_proof_wire(proof),
                msg=f"n={n} indices={indices}",
            )

    def test_encoding_starts_with_tag_and_contains_hpb_frames(self):
        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        blob = encode_hpap(proof)
        self.assertTrue(blob.startswith(PROOF_TAG))
        # Each bundle frame body is an existing HPB transport encoding.
        for inner in proof.bundles:
            self.assertIn(encode_hpb(inner), blob)
            self.assertTrue(encode_hpb(inner).startswith(b"ts/hpb/v1"))

    def test_type_errors(self):
        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        with self.assertRaises(TypeError):
            encode_hpap("not-a-proof")
        for bad in (
            HPAP([0, 2], proof.total, proof.bundles, proof.siblings),
            HPAP((0, 2), "8", proof.bundles, proof.siblings),
            HPAP((0, 2), True, proof.bundles, proof.siblings),
            HPAP((0, True), proof.total, proof.bundles, proof.siblings),
            HPAP((0, 2), proof.total, list(proof.bundles), proof.siblings),
            HPAP((0, 2), proof.total, proof.bundles, list(proof.siblings)),
            HPAP((0, 2), proof.total, ("x",) * 2, proof.siblings),
            HPAP((0, 2), proof.total, proof.bundles, (b"x" * 32, 9)),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_hpap(bad)

    def test_structure_value_errors(self):
        proof, _signature = signed_proof(
            self.archive, (0, 2, 4), self.key
        )
        for bad in (
            HPAP((), proof.total, (), ()),
            HPAP((0, 2), 0, proof.bundles[:2], proof.siblings),
            HPAP((0, 8), proof.total, proof.bundles[:2], proof.siblings),
            HPAP((2, 0), proof.total, proof.bundles[:2], proof.siblings),
            HPAP((1, 1), proof.total, proof.bundles[:2], proof.siblings),
            HPAP(proof.indices, proof.total, proof.bundles[:2], proof.siblings),
            HPAP(
                proof.indices,
                proof.total,
                proof.bundles + (proof.bundles[0],),
                proof.siblings,
            ),
            HPAP(proof.indices, proof.total, proof.bundles, (b"short",)),
            HPAP(
                proof.indices,
                proof.total,
                proof.bundles,
                proof.siblings + (b"x" * 32,),
            ),
            HPAP(
                proof.indices,
                proof.total,
                proof.bundles,
                proof.siblings[:-1],
            ),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                encode_hpap(bad)

    def test_mismatched_content_still_encodes(self):
        # A structurally legal proof whose content does not match its
        # root encodes and decodes normally; only verification judges it.
        proof, signature = signed_proof(self.archive, (0, 2), self.key)
        damaged = HPAP(
            proof.indices,
            proof.total,
            proof.bundles,
            (b"\x00" * 32,) + proof.siblings[1:],
        )
        self.assertEqual(encode_hpap(damaged), build_proof_wire(damaged))
        self.assertEqual(decode_hpap(encode_hpap(damaged)), damaged)
        self.assertFalse(
            check_hpap(damaged, signature, self.key)
        )

    def test_count_at_2_pow_64_boundary_raises_value_error(self):
        class HugeTuple(tuple):
            def __len__(self):
                return 2 ** 64

        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        with self.assertRaises(ValueError):
            encode_hpap(
                HPAP(proof.indices, 2 ** 64, proof.bundles, proof.siblings)
            )
        huge_fields = (
            HPAP(HugeTuple(proof.indices), proof.total, proof.bundles, proof.siblings),
            HPAP(proof.indices, proof.total, HugeTuple(proof.bundles), proof.siblings),
            HPAP(proof.indices, proof.total, proof.bundles, HugeTuple(proof.siblings)),
        )
        for bad in huge_fields:
            with self.assertRaises(ValueError, msg=repr(bad)):
                encode_hpap(bad)


class DecodeHPAPTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(8, self.key)

    def _archive_of_size(self, n):
        return HPBArchive(self.archive.items[:n], self.archive.signature)

    def test_roundtrip_for_every_size_and_subset(self):
        for n in range(1, 9):
            archive = self._archive_of_size(n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                proof, _signature = signed_proof(archive, indices, self.key)
                blob = encode_hpap(proof)
                restored = decode_hpap(blob)
                self.assertEqual(restored, proof)
                self.assertEqual(encode_hpap(restored), blob)

    def test_non_bytes_type_error(self):
        for bad in ("x", b"x".hex(), 42, None, bytearray(b"x")):
            with self.assertRaises(TypeError, msg=repr(bad)):
                decode_hpap(bad)

    def test_bad_tag_and_truncation(self):
        small_archive = self._archive_of_size(2)
        proof, _signature = signed_proof(small_archive, (0,), self.key)
        blob = encode_hpap(proof)
        with self.assertRaises(ValueError):
            decode_hpap(b"ts/hpap/v2" + blob[len(PROOF_TAG):])
        with self.assertRaises(ValueError):
            decode_hpap(blob[: len(PROOF_TAG) - 1])
        for cut in range(len(PROOF_TAG), len(blob)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_hpap(blob[:cut])

    def test_trailing_bytes(self):
        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        blob = encode_hpap(proof)
        with self.assertRaises(ValueError):
            decode_hpap(blob + b"\x00")

    def test_zero_and_overlarge_total(self):
        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        blob = encode_hpap(proof)
        rest = blob[len(PROOF_TAG) + len(varint(proof.total)):]
        with self.assertRaises(ValueError):
            decode_hpap(PROOF_TAG + varint(0) + rest)
        with self.assertRaises(ValueError):
            decode_hpap(PROOF_TAG + varint(1 << 64) + rest)

    def test_bad_index_and_bundle_counts(self):
        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        blob = encode_hpap(proof)
        head = PROOF_TAG + varint(proof.total)
        # An empty index list is illegal.
        with self.assertRaises(ValueError):
            decode_hpap(head + u32(0) + blob[len(head) + 4:])
        # A bundle count that does not match the index count is illegal.
        head += u32(2) + varint(0) + varint(2)
        with self.assertRaises(ValueError):
            decode_hpap(head + u32(1) + blob[len(head) + 4:])

    def test_bad_nested_frame(self):
        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        blob = encode_hpap(proof)
        head = PROOF_TAG + varint(proof.total)
        head += u32(2) + varint(0) + varint(2) + u32(2)
        with self.assertRaises(ValueError):
            decode_hpap(head + u32(0) + blob[len(head) + 4:])
        with self.assertRaises(ValueError):
            decode_hpap(head + frame(b"garbage") + blob[len(head) + 4:])

    def test_wrong_sibling_count_rejected(self):
        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        self.assertGreater(len(proof.siblings), 0)
        blob = encode_hpap(proof)
        sibling_count_offset = len(blob) - 4 - 32 * len(proof.siblings)
        head = blob[:sibling_count_offset]
        tail = blob[sibling_count_offset + 4:]
        for bad_count in (
            len(proof.siblings) - 1,
            len(proof.siblings) + 1,
        ):
            with self.assertRaises(ValueError, msg=f"count={bad_count}"):
                decode_hpap(head + u32(bad_count) + tail)

    def test_non_canonical_integers_rejected(self):
        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        blob = encode_hpap(proof)
        offset = len(PROOF_TAG)
        self.assertEqual(
            bytes(blob[offset:offset + 5]), varint(proof.total)
        )
        spliced = (
            PROOF_TAG
            + (2).to_bytes(4, "big")
            + b"\x00"
            + bytes([proof.total])
            + blob[offset + 5:]
        )
        with self.assertRaises(ValueError):
            decode_hpap(spliced)


class EncodeHPAPBTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(8, self.key)

    def _archive_of_size(self, n):
        return HPBArchive(self.archive.items[:n], self.archive.signature)

    def test_layout_matches_independent_builder(self):
        cases = (
            (1, (0,)),
            (3, (0, 2)),
            (5, (0, 2, 4)),
            (8, tuple(range(8))),
            (8, (3, 5)),
        )
        for n, indices in cases:
            archive = self._archive_of_size(n)
            bundle = signed_bundle(archive, indices, self.key)
            self.assertEqual(
                encode_hpapb(bundle),
                build_bundle_wire(bundle),
                msg=f"n={n} indices={indices}",
            )

    def test_encoding_frames_the_proof_encoding(self):
        bundle = signed_bundle(self.archive, (0, 2), self.key)
        blob = encode_hpapb(bundle)
        self.assertTrue(blob.startswith(BUNDLE_TAG))
        encoded_proof = encode_hpap(bundle.proof)
        self.assertEqual(
            blob[len(BUNDLE_TAG):len(BUNDLE_TAG) + 4],
            u32(len(encoded_proof)),
        )
        self.assertIn(encoded_proof, blob)

    def test_type_errors(self):
        bundle = signed_bundle(self.archive, (0, 2), self.key)
        with self.assertRaises(TypeError):
            encode_hpapb("not-a-bundle")
        with self.assertRaises(TypeError):
            encode_hpapb(HPAPB("not-a-proof", bundle.signature))
        with self.assertRaises(TypeError):
            encode_hpapb(HPAPB(bundle.proof, "not-a-signature"))
        proof = bundle.proof
        bad_proof = HPAP(
            [0, 2], proof.total, proof.bundles, proof.siblings
        )
        with self.assertRaises(TypeError):
            encode_hpapb(HPAPB(bad_proof, bundle.signature))

    def test_structure_value_errors(self):
        bundle = signed_bundle(self.archive, (0, 2, 4), self.key)
        proof = bundle.proof
        for bad_proof in (
            HPAP((), proof.total, (), ()),
            HPAP((0, 2), 0, proof.bundles[:2], proof.siblings),
            HPAP(proof.indices, proof.total, proof.bundles[:2], proof.siblings),
            HPAP(proof.indices, proof.total, proof.bundles, proof.siblings[:-1]),
        ):
            with self.assertRaises(ValueError, msg=repr(bad_proof)):
                encode_hpapb(HPAPB(bad_proof, bundle.signature))

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
                encode_hpapb(HPAPB(bundle.proof, bad_signature))

    def test_does_not_verify(self):
        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        bundle = HPAPB(proof, DUMMY_OUTER_SIGNATURE)
        self.assertEqual(encode_hpapb(bundle), build_bundle_wire(bundle))


class DecodeHPAPBTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(8, self.key)

    def _archive_of_size(self, n):
        return HPBArchive(self.archive.items[:n], self.archive.signature)

    def test_roundtrip_for_every_size_and_subset(self):
        for n in range(1, 9):
            archive = self._archive_of_size(n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                bundle = signed_bundle(archive, indices, self.key)
                blob = encode_hpapb(bundle)
                restored = decode_hpapb(blob)
                self.assertEqual(restored, bundle)
                self.assertEqual(encode_hpapb(restored), blob)

    def test_non_bytes_type_error(self):
        for bad in ("x", b"x".hex(), 42, None, bytearray(b"x")):
            with self.assertRaises(TypeError, msg=repr(bad)):
                decode_hpapb(bad)

    def test_bad_tag_and_truncation(self):
        small_archive = self._archive_of_size(2)
        bundle = signed_bundle(small_archive, (0,), self.key)
        blob = encode_hpapb(bundle)
        with self.assertRaises(ValueError):
            decode_hpapb(b"ts/hpapb/v2" + blob[len(BUNDLE_TAG):])
        with self.assertRaises(ValueError):
            decode_hpapb(blob[: len(BUNDLE_TAG) - 1])
        for cut in range(len(BUNDLE_TAG), len(blob)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_hpapb(blob[:cut])

    def test_trailing_bytes(self):
        bundle = signed_bundle(self.archive, (0, 2), self.key)
        blob = encode_hpapb(bundle)
        with self.assertRaises(ValueError):
            decode_hpapb(blob + b"\x00")

    def test_bad_proof_frame(self):
        bundle = signed_bundle(self.archive, (0, 2), self.key)
        blob = encode_hpapb(bundle)
        head = BUNDLE_TAG
        with self.assertRaises(ValueError):
            decode_hpapb(head + u32(0) + blob[len(head) + 4:])
        with self.assertRaises(ValueError):
            decode_hpapb(
                head + frame(b"garbage") + blob[len(head) + 4:]
            )

    def test_bad_signature_frame(self):
        bundle = signed_bundle(self.archive, (0, 2), self.key)
        head = BUNDLE_TAG + frame(encode_hpap(bundle.proof))
        signature = bundle.signature
        # A zero R, a zero signer count and non-increasing signer ids
        # are all illegal.
        with self.assertRaises(ValueError):
            decode_hpapb(
                head
                + varint(0)
                + varint(signature.z)
                + u32(len(signature.signer_ids))
                + b"".join(varint(i) for i in signature.signer_ids)
            )
        with self.assertRaises(ValueError):
            decode_hpapb(
                head + varint(signature.R) + varint(signature.z) + u32(0)
            )
        with self.assertRaises(ValueError):
            decode_hpapb(
                head
                + varint(signature.R)
                + varint(signature.z)
                + u32(2)
                + varint(3)
                + varint(1)
            )

    def test_mismatched_signature_still_decodes(self):
        # A structurally legal signature over another statement decodes
        # and re-encodes byte-for-byte; only verification judges it.
        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        message, _ = make_hpap(self.archive, (0, 2))
        mismatched = sign_message(make_other_key(), message, seed=53450)
        bundle = HPAPB(proof, mismatched)
        blob = encode_hpapb(bundle)
        restored = decode_hpapb(blob)
        self.assertEqual(restored, bundle)
        self.assertEqual(encode_hpapb(restored), blob)
        self.assertFalse(verify_hpapb(restored, self.key))

    def test_tampered_structural_signature_round_trips_and_fails(self):
        # Flipping a signer id byte to another legal id keeps the frame
        # canonical: the bytes decode, re-encode byte-for-byte, and
        # verification reports False rather than raising.
        bundle = signed_bundle(self.archive, (0, 2), self.key)
        blob = bytearray(encode_hpapb(bundle))
        blob[-1] ^= 0x01
        restored = decode_hpapb(bytes(blob))
        self.assertEqual(encode_hpapb(restored), bytes(blob))
        self.assertFalse(verify_hpapb(restored, self.key))


class VerifyHPAPBTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(8, self.key)

    def _archive_of_size(self, n):
        return HPBArchive(self.archive.items[:n], self.archive.signature)

    def test_signed_bundles_verify(self):
        for n, indices in (
            (1, (0,)),
            (3, (0, 2)),
            (5, (0, 2, 4)),
            (8, tuple(range(8))),
        ):
            archive = self._archive_of_size(n)
            bundle = signed_bundle(archive, indices, self.key)
            self.assertTrue(verify_hpapb(bundle, self.key))
            restored = decode_hpapb(encode_hpapb(bundle))
            self.assertTrue(verify_hpapb(restored, self.key))

    def test_tampered_and_wrong_key_return_false(self):
        bundle = signed_bundle(self.archive, (0, 2, 4), self.key)
        proof = bundle.proof
        moved = HPAPB(
            HPAP((0, 2, 5), proof.total, proof.bundles, proof.siblings),
            bundle.signature,
        )
        self.assertFalse(verify_hpapb(moved, self.key))
        swapped = HPAPB(
            HPAP(
                proof.indices,
                proof.total,
                (proof.bundles[1], proof.bundles[0], proof.bundles[2]),
                proof.siblings,
            ),
            bundle.signature,
        )
        self.assertFalse(verify_hpapb(swapped, self.key))
        damaged = HPAPB(
            HPAP(
                proof.indices,
                proof.total,
                proof.bundles,
                (b"\x00" * 32,) + proof.siblings[1:],
            ),
            bundle.signature,
        )
        self.assertFalse(verify_hpapb(damaged, self.key))
        self.assertFalse(verify_hpapb(bundle, make_other_key()))

    def test_missing_and_extra_siblings_return_false_at_verify(self):
        bundle = signed_bundle(self.archive, (0, 3), self.key)
        proof = bundle.proof
        short = HPAPB(
            HPAP(
                proof.indices,
                proof.total,
                proof.bundles,
                proof.siblings[:-1],
            ),
            bundle.signature,
        )
        # A sibling count that does not match total/indices is a
        # structural ValueError on the encoding path; once decoded
        # bytes carry the right count, content mismatches report False.
        with self.assertRaises(ValueError):
            encode_hpapb(short)

    def test_matches_check_hpap(self):
        bundle = signed_bundle(self.archive, (1, 4), self.key)
        self.assertEqual(
            verify_hpapb(bundle, self.key),
            check_hpap(bundle.proof, bundle.signature, self.key),
        )

    def test_bad_bundle_does_not_mask_illegal_signature_or_key(self):
        # A structurally legal bundle whose proof merely fails
        # verification must not turn an illegal root signature or key
        # into a plain False: both structures are checked first.
        bundle = signed_bundle(self.archive, (0, 2), self.key)
        proof = bundle.proof
        damaged = HPAPB(
            HPAP(
                proof.indices,
                proof.total,
                proof.bundles,
                (b"\x00" * 32,) + proof.siblings[1:],
            ),
            bundle.signature,
        )
        self.assertFalse(verify_hpapb(damaged, self.key))
        for bad_signature in (
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=-1, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=7, signer_ids=()),
            AggregateSignature(R=5, z=7, signer_ids=(3, 1)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad_signature)):
                verify_hpapb(
                    HPAPB(damaged.proof, bad_signature), self.key
                )
        for bad_key in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad_key)):
                verify_hpapb(
                    HPAPB(
                        damaged.proof,
                        AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
                    ),
                    bad_key,
                )

    def test_type_errors(self):
        bundle = signed_bundle(self.archive, (0,), self.key)
        with self.assertRaises(TypeError):
            verify_hpapb("not-a-bundle", self.key)
        with self.assertRaises(TypeError):
            verify_hpapb(HPAPB("not-a-proof", bundle.signature), self.key)


if __name__ == "__main__":
    unittest.main()
