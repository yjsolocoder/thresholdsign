"""Tests for the non-empty order-preserving archive of whole HPB
membership-proof bundles and its outer threshold-Schnorr signature:
HPBArchive / hpba_message / verify_hpba."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    HP,
    HPB,
    HPBArchive,
    encode_hpb,
    hpba_message,
    verify_hpb,
    verify_hpba,
)

from test_audit_chain import sign_message
from test_audit_extension_proof_bundle_codec import make_other_key
from test_nonce_reuse import make_key
from test_hp import archive_of_size
from test_hpb import signed_hpb

ARCHIVE_TAG = b"ts/hpba/m1"

# Distinct (index subset, seed) pairs so every bundle encodes differently.
BUNDLE_SPECS = (
    ((0, 2, 5), 72000, 71000),
    ((1, 3), 72097, 75000),
    ((0, 1, 2, 3, 4, 5), 72194, 79000),
    ((4,), 72291, 83000),
)


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def build_bundles(key):
    """Four distinct structurally legal, key-verifying HPB bundles."""
    return tuple(
        signed_hpb(
            archive_of_size(6, key, seed_base=seed_base),
            indices,
            key,
            seed=seed,
        )
        for indices, seed, seed_base in BUNDLE_SPECS
    )


def build_framing(items) -> bytes:
    """Independently build C straight from the spec."""
    out = bytearray(u32(len(items)))
    for item in items:
        encoded = encode_hpb(item)
        out += u32(len(encoded))
        out += encoded
    return bytes(out)


def build_message(items, public_key: int) -> bytes:
    """Independently build the archive message straight from the spec."""
    framing = build_framing(items)
    return ARCHIVE_TAG + hashlib.sha256(framing).digest() + varint(public_key)


def make_archive(items, key, *, signer_ids=(1, 3), seed=7300):
    """Seal a tuple of HPB bundles with one outer signature of ``key``."""
    message = hpba_message(items, key.public_key)
    signature = sign_message(key, message, signer_ids=signer_ids, seed=seed)
    return HPBArchive(items, signature)


class ArchiveShapeTest(unittest.TestCase):
    def test_fields_in_order(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(HPBArchive)],
            ["items", "signature"],
        )

    def test_frozen_positional_and_value_equal(self):
        key = make_key()
        items = build_bundles(key)[:2]
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        archive = HPBArchive(items, signature)
        self.assertIs(archive.items, items)
        self.assertIs(archive.signature, signature)
        self.assertEqual(
            archive,
            HPBArchive(items=items, signature=signature),
        )
        self.assertEqual(
            hash(archive),
            hash(HPBArchive(items, signature)),
        )
        self.assertNotEqual(
            archive,
            HPBArchive(items[:1], signature),
        )
        self.assertNotEqual(
            archive,
            HPBArchive(
                items, AggregateSignature(R=6, z=7, signer_ids=(1, 3))
            ),
        )
        self.assertEqual(
            {archive, HPBArchive(items, signature)},
            {HPBArchive(items, signature)},
        )
        with self.assertRaises(FrozenInstanceError):
            archive.items = items

    def test_construction_does_not_validate(self):
        # A plain frozen value: non-tuple items and non-signature fields
        # construct; hpba_message and the verifier reject them.
        HPBArchive("not-a-tuple", "not-a-signature")
        HPBArchive(None, None)


class ArchiveMessageTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.items_a = build_bundles(self.key)[:2]
        self.items_b = build_bundles(self.key)[2:]

    def test_matches_independent_spec_build(self):
        for items in (self.items_a[:1], self.items_a, self.items_b):
            with self.subTest(n=len(items)):
                message = hpba_message(items, self.key.public_key)
                self.assertEqual(
                    message, build_message(items, self.key.public_key)
                )
                self.assertTrue(message.startswith(ARCHIVE_TAG))

    def test_layout_is_tag_digest_of_framing_then_key_varint(self):
        message = hpba_message(self.items_a, self.key.public_key)
        framing = build_framing(self.items_a)
        offset = 0
        self.assertEqual(message[offset:len(ARCHIVE_TAG)], ARCHIVE_TAG)
        offset += len(ARCHIVE_TAG)
        self.assertEqual(
            message[offset:offset + 32],
            hashlib.sha256(framing).digest(),
        )
        offset += 32
        length = int.from_bytes(message[offset:offset + 4], "big")
        self.assertEqual(
            message[offset + 4:offset + 4 + length],
            varint(self.key.public_key)[4:],
        )
        self.assertEqual(offset + 4 + length, len(message))

    def test_framing_is_count_then_per_bundle_frames_no_separators(self):
        framing = build_framing(self.items_a)
        offset = 0
        self.assertEqual(framing[offset:offset + 4], u32(2))
        offset += 4
        for item in self.items_a:
            encoded = encode_hpb(item)
            self.assertEqual(framing[offset:offset + 4], u32(len(encoded)))
            offset += 4
            self.assertEqual(framing[offset:offset + len(encoded)], encoded)
            offset += len(encoded)
        self.assertEqual(offset, len(framing))

    def test_frames_are_existing_hpb_transport_encodings(self):
        framing = build_framing(self.items_a)
        self.assertIn(b"ts/hpb/v1", framing)
        for item in self.items_a:
            self.assertTrue(encode_hpb(item).startswith(b"ts/hpb/v1"))

    def test_commits_to_items_order_and_key(self):
        forward = self.items_a
        reverse = tuple(reversed(forward))
        single = forward[:1]
        message = hpba_message(forward, self.key.public_key)
        self.assertNotEqual(
            message,
            hpba_message(reverse, self.key.public_key),
        )
        self.assertNotEqual(
            message,
            hpba_message(single, self.key.public_key),
        )
        self.assertNotEqual(
            message,
            hpba_message(forward, self.key.public_key + 1),
        )
        self.assertEqual(
            hpba_message(forward, self.key.public_key),
            message,
        )

    def test_zero_public_key_encodes_as_single_00(self):
        message = hpba_message(self.items_b, 0)
        framing = build_framing(self.items_b)
        self.assertEqual(
            message,
            ARCHIVE_TAG + hashlib.sha256(framing).digest()
            + b"\x00\x00\x00\x01\x00",
        )

    def test_non_tuple_items_type_error(self):
        for bad in (
            list(self.items_a),
            iter(self.items_a),
            self.items_a[0],
            "items",
            None,
            42,
            b"x",
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                hpba_message(bad, self.key.public_key)

    def test_non_bundle_element_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                hpba_message((bad,), self.key.public_key)
            with self.assertRaises(TypeError, msg=repr(bad)):
                hpba_message(
                    (self.items_a[0], bad), self.key.public_key
                )
        # An inner HP is not an HPB archive member.
        with self.assertRaises(TypeError):
            hpba_message(
                (self.items_a[0].proof,), self.key.public_key
            )

    def test_empty_items_value_error(self):
        with self.assertRaises(ValueError):
            hpba_message((), self.key.public_key)

    def test_illegal_nested_bundle_value_error(self):
        bad_bundle = HPB(
            self.items_a[0].proof,
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
        )
        with self.assertRaises(ValueError):
            hpba_message((bad_bundle,), self.key.public_key)
        with self.assertRaises(ValueError):
            hpba_message(
                (self.items_a[0], bad_bundle), self.key.public_key
            )

    def test_nested_bundle_field_type_error(self):
        bad_bundle = HPB(
            "not-a-proof",
            AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
        )
        with self.assertRaises(TypeError):
            hpba_message((bad_bundle,), self.key.public_key)

    def test_bad_public_key_type_or_value(self):
        for bad in ("x", None, b"x", 1.5, True, False):
            with self.assertRaises(TypeError, msg=repr(bad)):
                hpba_message(self.items_a, bad)
        with self.assertRaises(ValueError):
            hpba_message(self.items_a, -1)

    def test_deterministic_and_stateless(self):
        self.assertEqual(
            hpba_message(self.items_a, self.key.public_key),
            hpba_message(self.items_a, self.key.public_key),
        )


class VerifyArchiveShapeAndErrorTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.items = build_bundles(self.key)
        self.archive = make_archive(self.items, self.key, seed=7400)

    def test_non_archive_type_error(self):
        for bad in (
            "x", None, 42, b"x", object(), self.items,
            (self.items, self.archive.signature),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_hpba(bad, self.key)

    def test_non_tuple_items_type_error(self):
        signature = self.archive.signature
        for bad in (list(self.items), iter(self.items), None, "items"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_hpba(HPBArchive(bad, signature), self.key)

    def test_non_bundle_element_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_hpba(
                    HPBArchive((bad,), self.archive.signature),
                    self.key,
                )

    def test_non_key_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_hpba(self.archive, bad)

    def test_empty_archive_value_error(self):
        with self.assertRaises(ValueError):
            verify_hpba(
                HPBArchive(
                    (),
                    AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
                ),
                self.key,
            )

    def test_illegal_nested_bundle_structure_value_error(self):
        # An out-of-range proof total makes the framed bundle structurally
        # illegal regardless of any signature; build the archive directly
        # (hpba_message itself rejects the item) so the ValueError comes
        # from verify_hpba.
        broken = HPB(
            dataclasses.replace(self.items[0].proof, total=-1),
            self.archive.signature,
        )
        with self.assertRaises(ValueError):
            verify_hpba(
                HPBArchive((self.items[0], broken), self.archive.signature),
                self.key,
            )

    def test_illegal_outer_signature_value_error(self):
        bad_signatures = (
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=-1, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=7, signer_ids=()),
            AggregateSignature(R=5, z=7, signer_ids=(3, 1)),
        )
        for bad in bad_signatures:
            with self.assertRaises(ValueError, msg=repr(bad)):
                verify_hpba(HPBArchive(self.items, bad), self.key)

    def test_bad_outer_signature_field_type_error(self):
        for bad in ("x", None, 5.0, True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_hpba(
                    HPBArchive(self.items, bad),
                    self.key,
                )


class VerifyArchiveVerdictTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.other = make_other_key()
        self.items = build_bundles(self.key)
        self.archive = make_archive(self.items, self.key, seed=7500)

    def test_verifying_archive_is_true(self):
        self.assertTrue(verify_hpba(self.archive, self.key))

    def test_single_item_archive_is_true(self):
        archive = make_archive(self.items[:1], self.key, seed=7510)
        self.assertTrue(verify_hpba(archive, self.key))

    def test_each_bundle_is_rechecked_individually(self):
        # Every item verifies standalone before the outer signature is
        # examined.
        for item in self.items:
            self.assertTrue(verify_hpb(item, self.key))

    def test_one_failing_nested_bundle_is_false(self):
        # A structurally legal bundle signed under another key encodes
        # fine but verify_hpb reports False under self.key.
        foreign_bundle = signed_hpb(
            archive_of_size(6, self.other, seed_base=81000),
            (0, 2, 5),
            self.other,
            seed=81001,
        )
        self.assertFalse(verify_hpb(foreign_bundle, self.key))
        archive = make_archive(
            (self.items[0], foreign_bundle), self.key, seed=7520
        )
        self.assertFalse(verify_hpba(archive, self.key))
        # And the same with the failing bundle first.
        archive = make_archive(
            (foreign_bundle, self.items[0]), self.key, seed=7521
        )
        self.assertFalse(verify_hpba(archive, self.key))

    def test_tampered_inner_root_signature_is_false(self):
        good = self.items[0]
        tampered_inner = AggregateSignature(
            R=good.signature.R,
            z=good.signature.z + 1,
            signer_ids=good.signature.signer_ids,
        )
        bad_bundle = HPB(good.proof, tampered_inner)
        archive = make_archive(
            (bad_bundle,) + self.items[1:], self.key, seed=7530
        )
        self.assertFalse(verify_hpba(archive, self.key))

    def test_tampered_inner_proof_is_false(self):
        # A structurally legal but content-damaged HP (one sibling zeroed)
        # keeps the archive encodable, but the per-bundle re-check fails.
        good = self.items[0]
        proof = good.proof
        damaged_proof = HP(
            proof.indices,
            proof.total,
            proof.bundles,
            (b"\x00" * 32,) + proof.siblings[1:],
        )
        bad_bundle = HPB(damaged_proof, good.signature)
        archive = make_archive(
            (bad_bundle,) + self.items[1:], self.key, seed=7531
        )
        self.assertFalse(verify_hpba(archive, self.key))

    def _outer_signature_over(self, items, seed):
        message = hpba_message(items, self.key.public_key)
        return sign_message(self.key, message, seed=seed)

    def test_outer_signature_over_another_item_set_is_false(self):
        foreign = self._outer_signature_over(
            (self.items[2], self.items[0]), seed=7540
        )
        self.assertFalse(
            verify_hpba(
                HPBArchive(self.items[:2], foreign),
                self.key,
            )
        )

    def test_deleting_an_item_is_false(self):
        # The outer signature commits to the exact count and ordered
        # bundle frames, so presenting a signed sub-archive fails.
        foreign = self._outer_signature_over(self.items[:2], seed=7550)
        self.assertFalse(
            verify_hpba(
                HPBArchive(self.items, foreign),
                self.key,
            )
        )

    def test_inserting_an_item_is_false(self):
        extra = signed_hpb(
            archive_of_size(6, self.key, seed_base=82000),
            (2, 5),
            self.key,
            seed=82001,
        )
        foreign = self._outer_signature_over(
            self.items + (extra,), seed=7561
        )
        self.assertFalse(
            verify_hpba(
                HPBArchive(self.items, foreign),
                self.key,
            )
        )

    def test_reordering_items_is_false(self):
        foreign = self._outer_signature_over(
            tuple(reversed(self.items)), seed=7570
        )
        self.assertFalse(
            verify_hpba(
                HPBArchive(self.items, foreign),
                self.key,
            )
        )

    def test_replacing_an_item_is_false(self):
        replacement = signed_hpb(
            archive_of_size(6, self.key, seed_base=83000),
            (0, 1, 2),
            self.key,
            seed=83001,
        )
        swapped = (self.items[0], self.items[1], self.items[2], replacement)
        # The outer signature stays the one over the original items.
        self.assertFalse(
            verify_hpba(
                HPBArchive(swapped, self.archive.signature),
                self.key,
            )
        )

    def test_tampered_outer_signature_is_false(self):
        signature = self.archive.signature
        tampered = AggregateSignature(
            R=signature.R,
            z=signature.z,
            signer_ids=signature.signer_ids[:-1]
            + (signature.signer_ids[-1] ^ 0xFF,),
        )
        self.assertFalse(
            verify_hpba(
                HPBArchive(self.items, tampered),
                self.key,
            )
        )

    def test_other_key_is_false(self):
        self.assertFalse(
            verify_hpba(self.archive, self.other)
        )

    def test_bad_bundle_does_not_mask_illegal_outer_signature(self):
        # A structurally legal archive whose nested bundle merely fails
        # verification must not turn an illegal outer signature into a
        # plain False: the outer signature structure is checked first.
        bad_bundle = signed_hpb(
            archive_of_size(6, self.other, seed_base=84000),
            (0, 2, 5),
            self.other,
            seed=84001,
        )
        items = (bad_bundle, self.items[0])
        for bad_signature in (
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=-1, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=7, signer_ids=()),
            AggregateSignature(R=5, z=7, signer_ids=(3, 1)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad_signature)):
                verify_hpba(
                    HPBArchive(items, bad_signature),
                    self.key,
                )

    def test_bad_bundle_does_not_mask_illegal_key(self):
        bad_bundle = signed_hpb(
            archive_of_size(6, self.other, seed_base=85000),
            (0, 2, 5),
            self.other,
            seed=85001,
        )
        archive = make_archive(
            (bad_bundle, self.items[0]), self.key, seed=7601
        )
        for bad_key in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad_key)):
                verify_hpba(archive, bad_key)
        # A SigningDKGResult-shaped key with an illegal public key is a
        # ValueError from the structure check, not a False verdict.
        broken_key = dataclasses.replace(self.key, public_key=0)
        with self.assertRaises(ValueError):
            verify_hpba(archive, broken_key)


if __name__ == "__main__":
    unittest.main()
