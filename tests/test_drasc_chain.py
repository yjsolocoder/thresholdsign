"""Tests for a non-empty, order-preserving chain of whole-archive
seals: DeltaReportBundleArchiveSealChain / drasc_message / verify_dc."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    DeltaReportBundleArchive,
    DeltaReportBundleArchiveSeal,
    DeltaReportBundleArchiveSealChain,
    drasc_message,
    encode_delta_report_bundle_archive_seal,
    verify_dc,
    verify_signature,
)

from test_audit_chain import make_key, sign_message
from test_audit_extension_proof_bundle_codec import make_other_key
from test_delta_report_bundle_archive_codec import build_archives
from test_delta_report_bundle_archive_seal_codec import make_seal

MESSAGE_TAG = b"dc/m1"


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def build_message(items, public_key: int) -> bytes:
    """Independently build the chain message straight from the spec."""
    committed = bytearray(u32(len(items)))
    for item in items:
        encoded = encode_delta_report_bundle_archive_seal(item)
        committed += u32(len(encoded))
        committed += encoded
    return MESSAGE_TAG + hashlib.sha256(bytes(committed)).digest() + varint(
        public_key
    )


def make_chain(items, key, *, signer_ids=(1, 3), seed=4000):
    """Seal the item sequence with a real threshold signature of ``key``."""
    message = drasc_message(items, key.public_key)
    signature = sign_message(key, message, signer_ids=signer_ids, seed=seed)
    return DeltaReportBundleArchiveSealChain(items, signature)


class ChainShapeTest(unittest.TestCase):
    def setUp(self):
        (
            self.key,
            _segments,
            self.full,
            self.first,
            self.second,
            _archives,
        ) = build_archives()

    def test_fields_in_order(self):
        self.assertEqual(
            [
                field.name
                for field in dataclasses.fields(
                    DeltaReportBundleArchiveSealChain
                )
            ],
            ["items", "signature"],
        )

    def test_frozen_positional_and_value_equal(self):
        items = (
            make_seal(DeltaReportBundleArchive((self.full,)), self.key,
                      seed=4100),
            make_seal(
                DeltaReportBundleArchive((self.first, self.second)), self.key,
                seed=4101,
            ),
        )
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        chain = DeltaReportBundleArchiveSealChain(items, signature)
        self.assertIs(chain.items, items)
        self.assertIs(chain.signature, signature)
        self.assertEqual(
            chain,
            DeltaReportBundleArchiveSealChain(
                items=items, signature=signature
            ),
        )
        self.assertEqual(
            hash(chain),
            hash(DeltaReportBundleArchiveSealChain(items, signature)),
        )
        self.assertNotEqual(
            chain,
            DeltaReportBundleArchiveSealChain(items[:1], signature),
        )
        self.assertNotEqual(
            chain,
            DeltaReportBundleArchiveSealChain(
                items, AggregateSignature(R=6, z=7, signer_ids=(1, 3))
            ),
        )
        self.assertEqual(
            {chain, DeltaReportBundleArchiveSealChain(items, signature)},
            {DeltaReportBundleArchiveSealChain(items, signature)},
        )
        with self.assertRaises(FrozenInstanceError):
            chain.items = items

    def test_construction_does_not_validate(self):
        # A plain frozen value: non-tuple and non-signature fields
        # construct; drasc_message and verify_dc reject them.
        DeltaReportBundleArchiveSealChain("not-items", "not-a-signature")
        DeltaReportBundleArchiveSealChain(None, None)


class DrascMessageTest(unittest.TestCase):
    def setUp(self):
        (
            self.key,
            _segments,
            self.full,
            self.first,
            self.second,
            _archives,
        ) = build_archives()
        self.items_one = (
            make_seal(
                DeltaReportBundleArchive((self.full, self.first)), self.key,
                seed=4200,
            ),
        )
        self.items_two = (
            make_seal(
                DeltaReportBundleArchive((self.full,)), self.key, seed=4201
            ),
            make_seal(
                DeltaReportBundleArchive((self.first, self.second)), self.key,
                seed=4202,
            ),
        )

    def test_matches_independent_spec_build(self):
        for items in (self.items_one, self.items_two):
            with self.subTest(n=len(items)):
                message = drasc_message(items, self.key.public_key)
                self.assertEqual(
                    message, build_message(items, self.key.public_key)
                )
                self.assertTrue(message.startswith(MESSAGE_TAG))

    def test_layout_is_tag_digest_of_C_then_key_varint(self):
        items = self.items_two
        message = drasc_message(items, self.key.public_key)

        # Independently reconstruct C: U32 count, then U32(len(E)) || E.
        committed = bytearray(u32(len(items)))
        for item in items:
            encoded = encode_delta_report_bundle_archive_seal(item)
            committed += u32(len(encoded))
            committed += encoded
        committed = bytes(committed)

        offset = 0
        self.assertEqual(message[offset:len(MESSAGE_TAG)], MESSAGE_TAG)
        offset += len(MESSAGE_TAG)
        self.assertEqual(
            message[offset:offset + 32],
            hashlib.sha256(committed).digest(),
        )
        offset += 32
        length = int.from_bytes(message[offset:offset + 4], "big")
        self.assertEqual(
            message[offset + 4:offset + 4 + length],
            varint(self.key.public_key)[4:],
        )
        self.assertEqual(offset + 4 + length, len(message))

    def test_C_starts_with_u32_count_and_preserves_order(self):
        committed = bytearray()
        frames = [
            encode_delta_report_bundle_archive_seal(item)
            for item in self.items_two
        ]
        committed += u32(2)
        for frame in frames:
            committed += u32(len(frame))
            committed += frame
        # The digest in the message is the digest of exactly that C.
        message = drasc_message(self.items_two, self.key.public_key)
        self.assertEqual(
            message[len(MESSAGE_TAG):len(MESSAGE_TAG) + 32],
            hashlib.sha256(bytes(committed)).digest(),
        )

    def test_commits_to_items_and_key(self):
        message = drasc_message(self.items_two, self.key.public_key)
        reordered = tuple(reversed(self.items_two))
        self.assertNotEqual(
            message, drasc_message(reordered, self.key.public_key)
        )
        self.assertNotEqual(
            message, drasc_message(self.items_two[:1], self.key.public_key)
        )
        self.assertNotEqual(
            message, drasc_message(self.items_two, self.key.public_key + 1)
        )
        self.assertEqual(
            drasc_message(self.items_two, self.key.public_key), message
        )

    def test_zero_public_key_encodes_as_single_00(self):
        message = drasc_message(self.items_one, 0)
        committed = bytearray(u32(1))
        encoded = encode_delta_report_bundle_archive_seal(self.items_one[0])
        committed += u32(len(encoded))
        committed += encoded
        self.assertEqual(
            message,
            MESSAGE_TAG
            + hashlib.sha256(bytes(committed)).digest()
            + b"\x00\x00\x00\x01\x00",
        )

    def test_items_non_tuple_type_error(self):
        for bad in (
            list(self.items_two),
            self.items_two[0],
            b"x",
            "x",
            None,
            42,
            object(),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                drasc_message(bad, self.key.public_key)

    def test_empty_items_value_error(self):
        with self.assertRaises(ValueError):
            drasc_message((), self.key.public_key)

    def test_non_seal_element_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                drasc_message((self.items_one[0], bad), self.key.public_key)

    def test_illegal_nested_seal_value_error(self):
        bad_seal = DeltaReportBundleArchiveSeal(
            DeltaReportBundleArchive(()),
            AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
        )
        with self.assertRaises(ValueError):
            drasc_message((bad_seal,), self.key.public_key)
        bad_signature_seal = DeltaReportBundleArchiveSeal(
            self.items_one[0].archive,
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
        )
        with self.assertRaises(ValueError):
            drasc_message(
                (self.items_one[0], bad_signature_seal), self.key.public_key
            )

    def test_nested_seal_field_type_error(self):
        bad_seal = DeltaReportBundleArchiveSeal(
            "not-an-archive",
            AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
        )
        with self.assertRaises(TypeError):
            drasc_message((bad_seal,), self.key.public_key)
        bad_signature_seal = DeltaReportBundleArchiveSeal(
            self.items_one[0].archive, "not-a-signature"
        )
        with self.assertRaises(TypeError):
            drasc_message((bad_signature_seal,), self.key.public_key)

    def test_bad_public_key_type_or_value(self):
        for bad in ("x", None, b"x", 1.5, True, False):
            with self.assertRaises(TypeError, msg=repr(bad)):
                drasc_message(self.items_one, bad)
        with self.assertRaises(ValueError):
            drasc_message(self.items_one, -1)


class VerifyDcTest(unittest.TestCase):
    def setUp(self):
        (
            self.key,
            _segments,
            self.full,
            self.first,
            self.second,
            _archives,
        ) = build_archives()
        self.items = (
            make_seal(
                DeltaReportBundleArchive((self.full, self.first)), self.key,
                seed=4300,
            ),
            make_seal(
                DeltaReportBundleArchive((self.second,)), self.key, seed=4301
            ),
            make_seal(
                DeltaReportBundleArchive((self.first, self.second, self.full)),
                self.key,
                seed=4302,
            ),
        )
        self.chain = make_chain(self.items, self.key, seed=4310)

    def test_verifying_chain_is_true(self):
        self.assertTrue(verify_dc(self.chain, self.key))

    def test_single_item_chain_verifies(self):
        chain = make_chain(self.items[:1], self.key, seed=4320)
        self.assertTrue(verify_dc(chain, self.key))

    def test_outer_signature_mismatch_is_false(self):
        chain = DeltaReportBundleArchiveSealChain(
            self.items,
            make_chain(self.items[:1], self.key, seed=4321).signature,
        )
        self.assertFalse(verify_dc(chain, self.key))

    def test_deleting_a_seal_is_false(self):
        self.assertFalse(
            verify_dc(
                DeltaReportBundleArchiveSealChain(
                    self.items[:2], self.chain.signature
                ),
                self.key,
            )
        )

    def test_inserting_a_seal_is_false(self):
        extra = make_seal(
            DeltaReportBundleArchive((self.full,)), self.key, seed=4330
        )
        self.assertFalse(
            verify_dc(
                DeltaReportBundleArchiveSealChain(
                    self.items + (extra,), self.chain.signature
                ),
                self.key,
            )
        )

    def test_reordering_seals_is_false(self):
        self.assertFalse(
            verify_dc(
                DeltaReportBundleArchiveSealChain(
                    tuple(reversed(self.items)), self.chain.signature
                ),
                self.key,
            )
        )

    def test_substituting_a_seal_is_false(self):
        replacement = make_seal(
            DeltaReportBundleArchive((self.full, self.second)), self.key,
            seed=4340,
        )
        substituted = (self.items[0], replacement, self.items[2])
        self.assertFalse(
            verify_dc(
                DeltaReportBundleArchiveSealChain(
                    substituted, self.chain.signature
                ),
                self.key,
            )
        )

    def test_bad_inner_seal_is_false(self):
        # The same outer signature over items, but one inner seal seals a
        # strict sub-archive: its own verification fails, so the chain is
        # False even though the outer signature matches the item bytes.
        good = self.items[0]
        weakened = DeltaReportBundleArchiveSeal(
            DeltaReportBundleArchive((self.full,)), good.signature
        )
        tampered_items = (good, weakened, self.items[2])
        chain = make_chain(tampered_items, self.key, seed=4350)
        self.assertTrue(
            # The outer signature really does seal this item sequence...
            verify_signature(
                drasc_message(tampered_items, self.key.public_key),
                chain.signature,
                self.key.public_key,
                group_prime=self.key.result.commitment.group_prime,
                generator=self.key.result.commitment.generator,
                prime=self.key.result.commitment.field_prime,
            )
        )
        self.assertFalse(verify_dc(chain, self.key))

    def test_other_key_is_false(self):
        self.assertFalse(verify_dc(self.chain, make_other_key()))

    def test_non_chain_type_error(self):
        for bad in ("x", None, 42, b"x", object(), self.items):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_dc(bad, self.key)

    def test_non_signature_field_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_dc(
                    DeltaReportBundleArchiveSealChain(self.items, bad),
                    self.key,
                )

    def test_items_non_tuple_type_error(self):
        for bad in (list(self.items), self.items[0], None, 42):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_dc(
                    DeltaReportBundleArchiveSealChain(
                        bad, self.chain.signature
                    ),
                    self.key,
                )

    def test_non_seal_element_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_dc(
                    DeltaReportBundleArchiveSealChain(
                        (self.items[0], bad), self.chain.signature
                    ),
                    self.key,
                )

    def test_non_key_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_dc(self.chain, bad)

    def test_empty_items_value_error(self):
        with self.assertRaises(ValueError):
            verify_dc(
                DeltaReportBundleArchiveSealChain((), self.chain.signature),
                self.key,
            )

    def test_illegal_nested_seal_value_error(self):
        bad_seal = DeltaReportBundleArchiveSeal(
            DeltaReportBundleArchive(()),
            AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
        )
        with self.assertRaises(ValueError):
            verify_dc(
                DeltaReportBundleArchiveSealChain(
                    (bad_seal,), self.chain.signature
                ),
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
                verify_dc(
                    DeltaReportBundleArchiveSealChain(self.items, bad),
                    self.key,
                )

    def test_illegal_key_value_error(self):
        bad_key = dataclasses.replace(self.key, public_key=0)
        with self.assertRaises(ValueError):
            verify_dc(self.chain, bad_key)

    def test_bad_archive_does_not_mask_illegal_signature(self):
        # A bad inner archive must not mask an illegal outer signature:
        # the structural signature error surfaces as ValueError.
        weakened = DeltaReportBundleArchiveSeal(
            DeltaReportBundleArchive((self.full,)),
            self.items[0].signature,
        )
        items = (weakened, self.items[1])
        illegal_signature = AggregateSignature(
            R=0, z=7, signer_ids=(1, 3)
        )
        with self.assertRaises(ValueError):
            verify_dc(
                DeltaReportBundleArchiveSealChain(items, illegal_signature),
                self.key,
            )

    def test_bad_archive_does_not_mask_illegal_key(self):
        # Likewise, a bad inner archive must not mask an illegal key.
        weakened = DeltaReportBundleArchiveSeal(
            DeltaReportBundleArchive((self.full,)),
            self.items[0].signature,
        )
        items = (weakened, self.items[1])
        bad_key = dataclasses.replace(self.key, public_key=0)
        with self.assertRaises(ValueError):
            verify_dc(
                DeltaReportBundleArchiveSealChain(
                    items, self.chain.signature
                ),
                bad_key,
            )

    def test_bad_archive_does_not_mask_signature_type_error(self):
        weakened = DeltaReportBundleArchiveSeal(
            DeltaReportBundleArchive((self.full,)),
            self.items[0].signature,
        )
        items = (weakened, self.items[1])
        with self.assertRaises(TypeError):
            verify_dc(
                DeltaReportBundleArchiveSealChain(items, "not-a-signature"),
                self.key,
            )


if __name__ == "__main__":
    unittest.main()
