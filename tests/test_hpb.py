"""Tests for the canonical HP proof transport encoding
encode_hp / decode_hp and the HPB proof-plus-signature bundle
HPB / encode_hpb / decode_hpb / verify_hpb over the HBPB archive
membership proofs."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    HP,
    HPB,
    HBPBArchive,
    check_hp,
    decode_hp,
    decode_hpb,
    encode_hp,
    encode_hbpb,
    encode_hpb,
    make_hp,
    verify_hpb,
)

from test_audit_chain import sign_message
from test_audit_extension_proof_bundle_codec import make_other_key
from test_nonce_reuse import make_key
from test_hp import archive_of_size, signed_proof

PROOF_TAG = b"ts/hp/v1"
BUNDLE_TAG = b"ts/hpb/v1"

DUMMY_OUTER_SIGNATURE = AggregateSignature(R=5, z=7, signer_ids=(1, 3))


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def signed_hpb(archive, indices, key, *, seed=52000):
    proof, signature = signed_proof(archive, indices, key, seed=seed)
    return HPB(proof, signature)


def build_proof_wire(proof):
    """Independently build the HP wire format straight from the spec."""
    out = bytearray(PROOF_TAG)
    out += varint(proof.total)
    out += u32(len(proof.indices))
    for index in proof.indices:
        out += varint(index)
    out += u32(len(proof.bundles))
    for inner in proof.bundles:
        out += frame(encode_hbpb(inner))
    out += u32(len(proof.siblings))
    for sibling in proof.siblings:
        out += sibling
    return bytes(out)


def build_bundle_wire(bundle):
    """Independently build the HPB wire format straight from the spec."""
    signature = bundle.signature
    out = bytearray(BUNDLE_TAG)
    out += frame(build_proof_wire(bundle.proof))
    out += varint(signature.R)
    out += varint(signature.z)
    out += u32(len(signature.signer_ids))
    for signer_id in signature.signer_ids:
        out += varint(signer_id)
    return bytes(out)


class HPBDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(HPB)],
            ["proof", "signature"],
        )
        key = make_key()
        archive = archive_of_size(3, key, seed_base=53000)
        proof, signature = signed_proof(archive, (0, 2), key)
        bundle = HPB(proof, signature)
        self.assertIs(bundle.proof, proof)
        self.assertIs(bundle.signature, signature)

    def test_frozen_value_equality_and_hash(self):
        key = make_key()
        archive = archive_of_size(3, key, seed_base=53020)
        proof, signature = signed_proof(archive, (1,), key)
        bundle = HPB(proof, signature)
        same = HPB(proof=proof, signature=signature)
        self.assertEqual(bundle, same)
        self.assertEqual(hash(bundle), hash(same))
        self.assertNotEqual(
            bundle, HPB(proof, AggregateSignature(R=6, z=7, signer_ids=(1, 3)))
        )
        with self.assertRaises(FrozenInstanceError):
            bundle.signature = signature

    def test_construction_does_not_validate(self):
        HPB("not-a-proof", "not-a-signature")
        HPB(None, None)


class EncodeHPTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(6, self.key, seed_base=53100)

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
            archive = HBPBArchive(
                self.archive.items[:n], self.archive.signature
            )
            proof, _signature = signed_proof(archive, indices, self.key)
            self.assertEqual(
                encode_hp(proof),
                build_proof_wire(proof),
                msg=f"n={n} indices={indices}",
            )

    def test_encoding_starts_with_tag_and_contains_hbpb_frames(self):
        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        blob = encode_hp(proof)
        self.assertTrue(blob.startswith(PROOF_TAG))
        # Each bundle frame body is an existing HBPB transport encoding.
        for inner in proof.bundles:
            self.assertIn(encode_hbpb(inner), blob)
            self.assertTrue(encode_hbpb(inner).startswith(b"ts/hbpb/v1"))

    def test_type_errors(self):
        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        with self.assertRaises(TypeError):
            encode_hp("not-a-proof")
        for bad in (
            HP([0, 2], proof.total, proof.bundles, proof.siblings),
            HP((0, 2), "6", proof.bundles, proof.siblings),
            HP((0, 2), True, proof.bundles, proof.siblings),
            HP((0, True), proof.total, proof.bundles, proof.siblings),
            HP((0, 2), proof.total, list(proof.bundles), proof.siblings),
            HP((0, 2), proof.total, proof.bundles, list(proof.siblings)),
            HP((0, 2), proof.total, ("x",) * 2, proof.siblings),
            HP((0, 2), proof.total, proof.bundles, (b"x" * 32, 9)),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_hp(bad)

    def test_structure_value_errors(self):
        proof, _signature = signed_proof(self.archive, (0, 2, 4), self.key)
        for bad in (
            HP((), proof.total, (), ()),
            HP((0, 2), 0, proof.bundles[:2], proof.siblings),
            HP((0, 6), proof.total, proof.bundles[:2], proof.siblings),
            HP((2, 0), proof.total, proof.bundles[:2], proof.siblings),
            HP((1, 1), proof.total, proof.bundles[:2], proof.siblings),
            HP(proof.indices, proof.total, proof.bundles[:2], proof.siblings),
            HP(
                proof.indices,
                proof.total,
                proof.bundles + (proof.bundles[0],),
                proof.siblings,
            ),
            HP(proof.indices, proof.total, proof.bundles, (b"short",)),
            HP(
                proof.indices,
                proof.total,
                proof.bundles,
                proof.siblings + (b"x" * 32,),
            ),
            HP(proof.indices, proof.total, proof.bundles, proof.siblings[:-1]),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                encode_hp(bad)

    def test_mismatched_content_still_encodes(self):
        # A structurally legal proof whose content does not match its
        # root encodes and decodes normally; only verification judges it.
        proof, signature = signed_proof(self.archive, (0, 2), self.key)
        damaged = HP(
            proof.indices,
            proof.total,
            proof.bundles,
            (b"\x00" * 32,) + proof.siblings[1:],
        )
        self.assertEqual(encode_hp(damaged), build_proof_wire(damaged))
        self.assertEqual(decode_hp(encode_hp(damaged)), damaged)
        self.assertFalse(verify_hpb(HPB(damaged, signature), self.key))

    def test_count_at_2_pow_64_boundary_raises_value_error(self):
        # An over-64-bit count is a plain ValueError on the encode path,
        # whether it arrives through the integer field or a tuple
        # subclass whose len() reports 2**64.
        class HugeTuple(tuple):
            def __len__(self):
                return 2 ** 64

        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        integer_boundary = HP(
            proof.indices, 2 ** 64, proof.bundles, proof.siblings
        )
        with self.assertRaises(ValueError):
            encode_hp(integer_boundary)
        huge_fields = (
            HP(HugeTuple(proof.indices), proof.total, proof.bundles, proof.siblings),
            HP(proof.indices, proof.total, HugeTuple(proof.bundles), proof.siblings),
            HP(proof.indices, proof.total, proof.bundles, HugeTuple(proof.siblings)),
        )
        for bad in huge_fields:
            with self.assertRaises(ValueError, msg=repr(bad)):
                encode_hp(bad)


class DecodeHPTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(6, self.key, seed_base=53200)

    def test_roundtrip_for_every_size_and_subset(self):
        for n in range(1, 7):
            archive = HBPBArchive(
                self.archive.items[:n], self.archive.signature
            )
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                proof, _signature = signed_proof(archive, indices, self.key)
                blob = encode_hp(proof)
                restored = decode_hp(blob)
                self.assertEqual(restored, proof)
                self.assertEqual(encode_hp(restored), blob)

    def test_non_bytes_type_error(self):
        for bad in ("x", b"x".hex(), 42, None, bytearray(b"x")):
            with self.assertRaises(TypeError, msg=repr(bad)):
                decode_hp(bad)

    def test_bad_tag_and_truncation(self):
        small_archive = HBPBArchive(
            self.archive.items[:2], self.archive.signature
        )
        proof, _signature = signed_proof(small_archive, (0,), self.key)
        blob = encode_hp(proof)
        with self.assertRaises(ValueError):
            decode_hp(b"ts/hp/v2" + blob[len(PROOF_TAG):])
        with self.assertRaises(ValueError):
            decode_hp(blob[: len(PROOF_TAG) - 1])
        for cut in range(len(PROOF_TAG), len(blob)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_hp(blob[:cut])

    def test_trailing_bytes(self):
        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        blob = encode_hp(proof)
        with self.assertRaises(ValueError):
            decode_hp(blob + b"\x00")

    def test_zero_and_overlarge_total(self):
        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        blob = encode_hp(proof)
        rest = blob[len(PROOF_TAG):]
        rest = rest[len(varint(proof.total)):]
        with self.assertRaises(ValueError):
            decode_hp(PROOF_TAG + varint(0) + rest)
        with self.assertRaises(ValueError):
            decode_hp(PROOF_TAG + varint(1 << 64) + rest)

    def test_bad_index_and_bundle_counts(self):
        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        blob = encode_hp(proof)
        head = PROOF_TAG + varint(proof.total)
        # An empty index list is illegal.
        with self.assertRaises(ValueError):
            decode_hp(head + u32(0) + blob[len(head) + 4:])
        # A bundle count that does not match the index count is illegal.
        head += u32(2) + varint(0) + varint(2)
        with self.assertRaises(ValueError):
            decode_hp(head + u32(1) + blob[len(head) + 4:])

    def test_bad_nested_frame(self):
        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        blob = encode_hp(proof)
        head = PROOF_TAG + varint(proof.total)
        head += u32(2) + varint(0) + varint(2) + u32(2)
        with self.assertRaises(ValueError):
            decode_hp(head + u32(0) + blob[len(head) + 4:])
        with self.assertRaises(ValueError):
            decode_hp(head + frame(b"garbage") + blob[len(head) + 4:])

    def test_wrong_sibling_count_rejected(self):
        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        self.assertGreater(len(proof.siblings), 0)
        blob = encode_hp(proof)
        sibling_count_offset = len(blob) - 4 - 32 * len(proof.siblings)
        head = blob[:sibling_count_offset]
        tail = blob[sibling_count_offset + 4:]
        for bad_count in (
            len(proof.siblings) - 1,
            len(proof.siblings) + 1,
        ):
            with self.assertRaises(ValueError, msg=f"count={bad_count}"):
                decode_hp(head + u32(bad_count) + tail)

    def test_non_canonical_integers_rejected(self):
        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        blob = encode_hp(proof)
        offset = len(PROOF_TAG)
        self.assertEqual(
            bytes(blob[offset:offset + 5]), varint(proof.total)
        )
        # A two-byte body starting with 00 for a small total is a
        # forbidden leading zero rather than the shortest encoding.
        spliced = (
            PROOF_TAG
            + (2).to_bytes(4, "big")
            + b"\x00"
            + bytes([proof.total])
            + blob[offset + 5:]
        )
        with self.assertRaises(ValueError):
            decode_hp(spliced)


class EncodeHPBTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(6, self.key, seed_base=53300)

    def test_layout_matches_independent_builder(self):
        cases = (
            (1, (0,)),
            (3, (0, 2)),
            (5, (0, 2, 4)),
            (6, tuple(range(6))),
            (6, (3, 5)),
        )
        for n, indices in cases:
            archive = HBPBArchive(
                self.archive.items[:n], self.archive.signature
            )
            bundle = signed_hpb(archive, indices, self.key)
            self.assertEqual(
                encode_hpb(bundle),
                build_bundle_wire(bundle),
                msg=f"n={n} indices={indices}",
            )

    def test_encoding_frames_the_proof_encoding(self):
        bundle = signed_hpb(self.archive, (0, 2), self.key)
        blob = encode_hpb(bundle)
        self.assertTrue(blob.startswith(BUNDLE_TAG))
        encoded_proof = encode_hp(bundle.proof)
        self.assertEqual(
            blob[len(BUNDLE_TAG):len(BUNDLE_TAG) + 4],
            u32(len(encoded_proof)),
        )
        self.assertIn(encoded_proof, blob)

    def test_type_errors(self):
        bundle = signed_hpb(self.archive, (0, 2), self.key)
        with self.assertRaises(TypeError):
            encode_hpb("not-a-bundle")
        with self.assertRaises(TypeError):
            encode_hpb(HPB("not-a-proof", bundle.signature))
        with self.assertRaises(TypeError):
            encode_hpb(HPB(bundle.proof, "not-a-signature"))
        proof = bundle.proof
        bad_proof = HP([0, 2], proof.total, proof.bundles, proof.siblings)
        with self.assertRaises(TypeError):
            encode_hpb(HPB(bad_proof, bundle.signature))

    def test_structure_value_errors(self):
        bundle = signed_hpb(self.archive, (0, 2, 4), self.key)
        proof = bundle.proof
        for bad_proof in (
            HP((), proof.total, (), ()),
            HP((0, 2), 0, proof.bundles[:2], proof.siblings),
            HP(proof.indices, proof.total, proof.bundles[:2], proof.siblings),
            HP(proof.indices, proof.total, proof.bundles, proof.siblings[:-1]),
        ):
            with self.assertRaises(ValueError, msg=repr(bad_proof)):
                encode_hpb(HPB(bad_proof, bundle.signature))

    def test_signature_structure_value_errors(self):
        bundle = signed_hpb(self.archive, (0, 2), self.key)
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
                encode_hpb(HPB(bundle.proof, bad_signature))

    def test_does_not_verify(self):
        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        bundle = HPB(proof, DUMMY_OUTER_SIGNATURE)
        self.assertEqual(encode_hpb(bundle), build_bundle_wire(bundle))


class DecodeHPBTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(6, self.key, seed_base=53400)

    def test_roundtrip_for_every_size_and_subset(self):
        for n in range(1, 7):
            archive = HBPBArchive(
                self.archive.items[:n], self.archive.signature
            )
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                bundle = signed_hpb(archive, indices, self.key)
                blob = encode_hpb(bundle)
                restored = decode_hpb(blob)
                self.assertEqual(restored, bundle)
                self.assertEqual(encode_hpb(restored), blob)

    def test_non_bytes_type_error(self):
        for bad in ("x", b"x".hex(), 42, None, bytearray(b"x")):
            with self.assertRaises(TypeError, msg=repr(bad)):
                decode_hpb(bad)

    def test_bad_tag_and_truncation(self):
        small_archive = HBPBArchive(
            self.archive.items[:2], self.archive.signature
        )
        bundle = signed_hpb(small_archive, (0,), self.key)
        blob = encode_hpb(bundle)
        with self.assertRaises(ValueError):
            decode_hpb(b"ts/hpb/v2" + blob[len(BUNDLE_TAG):])
        with self.assertRaises(ValueError):
            decode_hpb(blob[: len(BUNDLE_TAG) - 1])
        for cut in range(len(BUNDLE_TAG), len(blob)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_hpb(blob[:cut])

    def test_trailing_bytes(self):
        bundle = signed_hpb(self.archive, (0, 2), self.key)
        blob = encode_hpb(bundle)
        with self.assertRaises(ValueError):
            decode_hpb(blob + b"\x00")

    def test_bad_proof_frame(self):
        bundle = signed_hpb(self.archive, (0, 2), self.key)
        blob = encode_hpb(bundle)
        head = BUNDLE_TAG
        with self.assertRaises(ValueError):
            decode_hpb(head + u32(0) + blob[len(head) + 4:])
        with self.assertRaises(ValueError):
            decode_hpb(head + frame(b"garbage") + blob[len(head) + 4:])

    def test_bad_signature_frame(self):
        bundle = signed_hpb(self.archive, (0, 2), self.key)
        blob = encode_hpb(bundle)
        encoded_proof = frame(encode_hp(bundle.proof))
        head = BUNDLE_TAG + encoded_proof
        signature = bundle.signature
        # A zero R, a zero signer count and non-increasing signer ids
        # are all illegal.
        with self.assertRaises(ValueError):
            decode_hpb(
                head
                + varint(0)
                + varint(signature.z)
                + u32(len(signature.signer_ids))
                + b"".join(varint(i) for i in signature.signer_ids)
            )
        with self.assertRaises(ValueError):
            decode_hpb(
                head
                + varint(signature.R)
                + varint(signature.z)
                + u32(0)
            )
        with self.assertRaises(ValueError):
            decode_hpb(
                head
                + varint(signature.R)
                + varint(signature.z)
                + u32(2)
                + varint(3)
                + varint(1)
            )

    def test_mismatched_signature_still_decodes(self):
        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        message, _ = make_hp(self.archive, (0, 2))
        mismatched = sign_message(make_other_key(), message, seed=53450)
        bundle = HPB(proof, mismatched)
        blob = encode_hpb(bundle)
        restored = decode_hpb(blob)
        self.assertEqual(restored, bundle)
        self.assertFalse(verify_hpb(restored, self.key))


class VerifyHPBTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(6, self.key, seed_base=53500)

    def test_signed_bundles_verify(self):
        for n, indices in (
            (1, (0,)),
            (3, (0, 2)),
            (5, (0, 2, 4)),
            (6, tuple(range(6))),
        ):
            archive = HBPBArchive(
                self.archive.items[:n], self.archive.signature
            )
            bundle = signed_hpb(archive, indices, self.key)
            self.assertTrue(verify_hpb(bundle, self.key))
            restored = decode_hpb(encode_hpb(bundle))
            self.assertTrue(verify_hpb(restored, self.key))

    def test_tampered_and_wrong_key_return_false(self):
        bundle = signed_hpb(self.archive, (0, 2, 4), self.key)
        proof = bundle.proof
        moved = HPB(
            HP((0, 2, 5), proof.total, proof.bundles, proof.siblings),
            bundle.signature,
        )
        self.assertFalse(verify_hpb(moved, self.key))
        swapped = HPB(
            HP(
                proof.indices,
                proof.total,
                (proof.bundles[1], proof.bundles[0], proof.bundles[2]),
                proof.siblings,
            ),
            bundle.signature,
        )
        self.assertFalse(verify_hpb(swapped, self.key))
        self.assertFalse(verify_hpb(bundle, make_other_key()))

    def test_matches_check_hp(self):
        bundle = signed_hpb(self.archive, (1, 4), self.key)
        self.assertEqual(
            verify_hpb(bundle, self.key),
            check_hp(bundle.proof, bundle.signature, self.key),
        )

    def test_bad_bundle_does_not_mask_illegal_signature_or_key(self):
        # A structurally legal bundle whose proof merely fails
        # verification must not turn an illegal root signature or key
        # into a plain False: both structures are checked first.
        bundle = signed_hpb(self.archive, (0, 2), self.key)
        proof = bundle.proof
        damaged = HPB(
            HP(
                proof.indices,
                proof.total,
                proof.bundles,
                (b"\x00" * 32,) + proof.siblings[1:],
            ),
            bundle.signature,
        )
        self.assertFalse(verify_hpb(damaged, self.key))
        for bad_signature in (
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=-1, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=7, signer_ids=()),
            AggregateSignature(R=5, z=7, signer_ids=(3, 1)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad_signature)):
                verify_hpb(
                    HPB(damaged.proof, bad_signature), self.key
                )
        for bad_key in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad_key)):
                verify_hpb(
                    HPB(
                        damaged.proof,
                        AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
                    ),
                    bad_key,
                )

    def test_type_errors(self):
        bundle = signed_hpb(self.archive, (0,), self.key)
        with self.assertRaises(TypeError):
            verify_hpb("not-a-bundle", self.key)
        with self.assertRaises(TypeError):
            verify_hpb(HPB("not-a-proof", bundle.signature), self.key)


if __name__ == "__main__":
    unittest.main()
