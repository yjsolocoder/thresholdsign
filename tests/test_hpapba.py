"""Tests for the non-empty order-preserving archive of whole HPAPB
membership-proof bundles and its outer threshold-Schnorr signature:
HPAPBArchive / hpapba_message / verify_hpapba."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    HPAP,
    HPAPB,
    HPAPBArchive,
    encode_hpapb,
    hpapba_message,
    verify_hpapb,
    verify_hpapba,
)

from test_audit_chain import sign_message
from test_audit_extension_proof_bundle_codec import make_other_key
from test_nonce_reuse import make_key
from test_hpapb import (
    minimal_archive,
    prefix_archive,
    signed_hpapb,
)

ARCHIVE_TAG = b"ts/hpapba/m1"

# Distinct (archive prefix size, index subset, seed) triples so every
# bundle's proof, and therefore its canonical encoding, differs.
BUNDLE_SPECS = (
    (2, (0, 1), 61000),
    (3, (0, 2), 61100),
    (5, (0, 2, 4), 61200),
    (6, (1, 3, 5), 61300),
)


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def build_bundles(key):
    """Four distinct structurally legal, key-verifying HPAPB bundles."""
    source = minimal_archive(6, key)
    return tuple(
        signed_hpapb(
            prefix_archive(source, size),
            indices,
            key,
            seed=seed,
        )
        for size, indices, seed in BUNDLE_SPECS
    )


def build_framing(items) -> bytes:
    """Independently build C straight from the spec."""
    out = bytearray(u32(len(items)))
    for item in items:
        encoded = encode_hpapb(item)
        out += u32(len(encoded))
        out += encoded
    return bytes(out)


def build_message(items, public_key: int) -> bytes:
    """Independently build the archive message straight from the spec."""
    framing = build_framing(items)
    return ARCHIVE_TAG + hashlib.sha256(framing).digest() + varint(public_key)


def make_archive(items, key, *, signer_ids=(1, 3), seed=62000):
    """Seal a tuple of HPAPB bundles with one outer signature of ``key``."""
    message = hpapba_message(items, key.public_key)
    signature = sign_message(key, message, signer_ids=signer_ids, seed=seed)
    return HPAPBArchive(items, signature)


class ArchiveShapeTest(unittest.TestCase):
    def test_fields_in_order(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(HPAPBArchive)],
            ["items", "signature"],
        )

    def test_frozen_positional_and_value_equal(self):
        key = make_key()
        items = build_bundles(key)[:2]
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        archive = HPAPBArchive(items, signature)
        self.assertIs(archive.items, items)
        self.assertIs(archive.signature, signature)
        self.assertEqual(
            archive,
            HPAPBArchive(items=items, signature=signature),
        )
        self.assertEqual(
            hash(archive),
            hash(HPAPBArchive(items, signature)),
        )
        self.assertNotEqual(
            archive,
            HPAPBArchive(items[:1], signature),
        )
        self.assertNotEqual(
            archive,
            HPAPBArchive(
                items, AggregateSignature(R=6, z=7, signer_ids=(1, 3))
            ),
        )
        self.assertEqual(
            {archive, HPAPBArchive(items, signature)},
            {HPAPBArchive(items, signature)},
        )
        with self.assertRaises(FrozenInstanceError):
            archive.items = items

    def test_construction_does_not_validate(self):
        # A plain frozen value: non-tuple items and non-signature fields
        # construct; hpapba_message and the verifier reject them.
        HPAPBArchive("not-a-tuple", "not-a-signature")
        HPAPBArchive(None, None)


class ArchiveMessageTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.items_a = build_bundles(self.key)[:2]
        self.items_b = build_bundles(self.key)[2:]

    def test_matches_independent_spec_build(self):
        for items in (self.items_a[:1], self.items_a, self.items_b):
            with self.subTest(n=len(items)):
                message = hpapba_message(items, self.key.public_key)
                self.assertEqual(
                    message, build_message(items, self.key.public_key)
                )
                self.assertTrue(message.startswith(ARCHIVE_TAG))

    def test_layout_is_tag_digest_of_framing_then_key_varint(self):
        message = hpapba_message(self.items_a, self.key.public_key)
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
            encoded = encode_hpapb(item)
            self.assertEqual(framing[offset:offset + 4], u32(len(encoded)))
            offset += 4
            self.assertEqual(framing[offset:offset + len(encoded)], encoded)
            offset += len(encoded)
        self.assertEqual(offset, len(framing))

    def test_frames_are_existing_hpapb_transport_encodings(self):
        framing = build_framing(self.items_a)
        self.assertIn(b"ts/hpapb/v1", framing)
        for item in self.items_a:
            self.assertTrue(encode_hpapb(item).startswith(b"ts/hpapb/v1"))

    def test_commits_to_items_order_and_key(self):
        forward = self.items_a
        reverse = tuple(reversed(forward))
        single = forward[:1]
        message = hpapba_message(forward, self.key.public_key)
        self.assertNotEqual(
            message,
            hpapba_message(reverse, self.key.public_key),
        )
        self.assertNotEqual(
            message,
            hpapba_message(single, self.key.public_key),
        )
        self.assertNotEqual(
            message,
            hpapba_message(forward, self.key.public_key + 1),
        )
        self.assertEqual(
            hpapba_message(forward, self.key.public_key),
            message,
        )

    def test_zero_public_key_encodes_as_single_00(self):
        message = hpapba_message(self.items_b, 0)
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
                hpapba_message(bad, self.key.public_key)

    def test_non_bundle_element_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                hpapba_message((bad,), self.key.public_key)
            with self.assertRaises(TypeError, msg=repr(bad)):
                hpapba_message(
                    (self.items_a[0], bad), self.key.public_key
                )
        # An inner HPAP is not an HPAPB archive member.
        with self.assertRaises(TypeError):
            hpapba_message(
                (self.items_a[0].proof,), self.key.public_key
            )

    def test_empty_items_value_error(self):
        with self.assertRaises(ValueError):
            hpapba_message((), self.key.public_key)

    def test_illegal_nested_bundle_value_error(self):
        bad_bundle = HPAPB(
            self.items_a[0].proof,
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
        )
        with self.assertRaises(ValueError):
            hpapba_message((bad_bundle,), self.key.public_key)
        with self.assertRaises(ValueError):
            hpapba_message(
                (self.items_a[0], bad_bundle), self.key.public_key
            )

    def test_nested_bundle_field_type_error(self):
        bad_bundle = HPAPB(
            "not-a-proof",
            AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
        )
        with self.assertRaises(TypeError):
            hpapba_message((bad_bundle,), self.key.public_key)

    def test_bad_public_key_type_or_value(self):
        for bad in ("x", None, b"x", 1.5, True, False):
            with self.assertRaises(TypeError, msg=repr(bad)):
                hpapba_message(self.items_a, bad)
        with self.assertRaises(ValueError):
            hpapba_message(self.items_a, -1)

    def test_deterministic_and_stateless(self):
        self.assertEqual(
            hpapba_message(self.items_a, self.key.public_key),
            hpapba_message(self.items_a, self.key.public_key),
        )


class VerifyArchiveShapeAndErrorTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.items = build_bundles(self.key)
        self.archive = make_archive(self.items, self.key, seed=62100)

    def test_non_archive_type_error(self):
        for bad in (
            "x", None, 42, b"x", object(), self.items,
            (self.items, self.archive.signature),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_hpapba(bad, self.key)

    def test_non_tuple_items_type_error(self):
        signature = self.archive.signature
        for bad in (list(self.items), iter(self.items), None, "items"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_hpapba(HPAPBArchive(bad, signature), self.key)

    def test_non_bundle_element_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_hpapba(
                    HPAPBArchive((bad,), self.archive.signature),
                    self.key,
                )

    def test_non_key_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_hpapba(self.archive, bad)

    def test_empty_archive_value_error(self):
        with self.assertRaises(ValueError):
            verify_hpapba(
                HPAPBArchive(
                    (),
                    AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
                ),
                self.key,
            )

    def test_illegal_nested_bundle_structure_value_error(self):
        # An out-of-range proof total makes the framed bundle structurally
        # illegal regardless of any signature; build the archive directly
        # (hpapba_message itself rejects the item) so the ValueError comes
        # from verify_hpapba.
        broken = HPAPB(
            dataclasses.replace(self.items[0].proof, total=-1),
            self.archive.signature,
        )
        with self.assertRaises(ValueError):
            verify_hpapba(
                HPAPBArchive((self.items[0], broken), self.archive.signature),
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
                verify_hpapba(HPAPBArchive(self.items, bad), self.key)

    def test_bad_outer_signature_field_type_error(self):
        for bad in ("x", None, 5.0, True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_hpapba(
                    HPAPBArchive(self.items, bad),
                    self.key,
                )


class VerifyArchiveVerdictTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.other = make_other_key()
        self.items = build_bundles(self.key)
        self.archive = make_archive(self.items, self.key, seed=62200)

    def test_verifying_archive_is_true(self):
        self.assertTrue(verify_hpapba(self.archive, self.key))

    def test_single_item_archive_is_true(self):
        archive = make_archive(self.items[:1], self.key, seed=62210)
        self.assertTrue(verify_hpapba(archive, self.key))

    def test_each_bundle_is_rechecked_individually(self):
        # Every item verifies standalone before the outer signature is
        # examined.
        for item in self.items:
            self.assertTrue(verify_hpapb(item, self.key))

    def test_one_failing_nested_bundle_is_false(self):
        # A structurally legal bundle signed under another key encodes
        # fine but verify_hpapb reports False under self.key.
        foreign_bundle = signed_hpapb(
            minimal_archive(6, self.other),
            (0, 2),
            self.other,
            seed=62220,
        )
        self.assertFalse(verify_hpapb(foreign_bundle, self.key))
        archive = make_archive(
            (self.items[0], foreign_bundle), self.key, seed=62221
        )
        self.assertFalse(verify_hpapba(archive, self.key))
        # And the same with the failing bundle first.
        archive = make_archive(
            (foreign_bundle, self.items[0]), self.key, seed=62222
        )
        self.assertFalse(verify_hpapba(archive, self.key))

    def test_tampered_inner_root_signature_is_false(self):
        good = self.items[0]
        tampered_inner = AggregateSignature(
            R=good.signature.R,
            z=good.signature.z + 1,
            signer_ids=good.signature.signer_ids,
        )
        bad_bundle = HPAPB(good.proof, tampered_inner)
        archive = make_archive(
            (bad_bundle,) + self.items[1:], self.key, seed=62230
        )
        self.assertFalse(verify_hpapba(archive, self.key))

    def test_tampered_inner_proof_is_false(self):
        # A structurally legal but content-damaged HPAP (one sibling
        # zeroed) keeps the archive encodable, but the per-bundle
        # re-check fails. self.items[1] proves (0, 2) of three and so
        # carries at least one sibling digest.
        good = self.items[1]
        proof = good.proof
        self.assertGreater(len(proof.siblings), 0)
        damaged_proof = HPAP(
            proof.indices,
            proof.total,
            proof.bundles,
            (b"\x00" * 32,) + proof.siblings[1:],
        )
        bad_bundle = HPAPB(damaged_proof, good.signature)
        archive = make_archive(
            (bad_bundle,) + self.items[1:], self.key, seed=62231
        )
        self.assertFalse(verify_hpapba(archive, self.key))

    def _outer_signature_over(self, items, seed):
        message = hpapba_message(items, self.key.public_key)
        return sign_message(self.key, message, seed=seed)

    def test_outer_signature_over_another_item_set_is_false(self):
        foreign = self._outer_signature_over(
            (self.items[2], self.items[0]), seed=62240
        )
        self.assertFalse(
            verify_hpapba(
                HPAPBArchive(self.items[:2], foreign),
                self.key,
            )
        )

    def test_deleting_an_item_is_false(self):
        # The outer signature commits to the exact count and ordered
        # bundle frames, so presenting a signed sub-archive fails.
        foreign = self._outer_signature_over(self.items[:2], seed=62250)
        self.assertFalse(
            verify_hpapba(
                HPAPBArchive(self.items, foreign),
                self.key,
            )
        )

    def test_inserting_an_item_is_false(self):
        source = minimal_archive(6, self.key)
        extra = signed_hpapb(
            prefix_archive(source, 4), (0, 3), self.key, seed=62260
        )
        foreign = self._outer_signature_over(
            self.items + (extra,), seed=62261
        )
        self.assertFalse(
            verify_hpapba(
                HPAPBArchive(self.items, foreign),
                self.key,
            )
        )

    def test_reordering_items_is_false(self):
        foreign = self._outer_signature_over(
            tuple(reversed(self.items)), seed=62270
        )
        self.assertFalse(
            verify_hpapba(
                HPAPBArchive(self.items, foreign),
                self.key,
            )
        )

    def test_replacing_an_item_is_false(self):
        source = minimal_archive(6, self.key)
        replacement = signed_hpapb(
            prefix_archive(source, 4), (0, 1, 3), self.key, seed=62280
        )
        swapped = (self.items[0], self.items[1], self.items[2], replacement)
        # The outer signature stays the one over the original items.
        self.assertFalse(
            verify_hpapba(
                HPAPBArchive(swapped, self.archive.signature),
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
            verify_hpapba(
                HPAPBArchive(self.items, tampered),
                self.key,
            )
        )

    def test_other_key_is_false(self):
        self.assertFalse(
            verify_hpapba(self.archive, self.other)
        )

    def test_bad_bundle_does_not_mask_illegal_outer_signature(self):
        # A structurally legal archive whose nested bundle merely fails
        # verification must not turn an illegal outer signature into a
        # plain False: the outer signature structure is checked first.
        bad_bundle = signed_hpapb(
            minimal_archive(6, self.other),
            (0, 2),
            self.other,
            seed=62290,
        )
        items = (bad_bundle, self.items[0])
        for bad_signature in (
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=-1, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=7, signer_ids=()),
            AggregateSignature(R=5, z=7, signer_ids=(3, 1)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad_signature)):
                verify_hpapba(
                    HPAPBArchive(items, bad_signature),
                    self.key,
                )

    def test_bad_bundle_does_not_mask_illegal_key(self):
        bad_bundle = signed_hpapb(
            minimal_archive(6, self.other),
            (0, 2),
            self.other,
            seed=62300,
        )
        archive = make_archive(
            (bad_bundle, self.items[0]), self.key, seed=62301
        )
        for bad_key in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad_key)):
                verify_hpapba(archive, bad_key)
        # A SigningDKGResult-shaped key with an illegal public key is a
        # ValueError from the structure check, not a False verdict.
        broken_key = dataclasses.replace(self.key, public_key=0)
        with self.assertRaises(ValueError):
            verify_hpapba(archive, broken_key)


if __name__ == "__main__":
    unittest.main()
