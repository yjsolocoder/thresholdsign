"""Tests for the non-empty order-preserving chain of whole history delta
segments seals and its outer threshold-Schnorr signature:
HistoryDeltaSegmentsSealChain / hdsc_message / verify_hdsc."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    HistoryDeltaSegmentsSeal,
    HistoryDeltaSegmentsSealChain,
    encode_hds,
    hdsc_message,
    verify_hdsc,
)

from test_audit_chain import sign_message
from test_history_delta_segments_codec import build_segments
from test_history_delta_segments_seal import make_seal
from test_nonce_leak_codec import make_other_key

MESSAGE_TAG = b"ts/hdsc/m1"


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def build_framing(items) -> bytes:
    """Independently build C straight from the spec."""
    out = bytearray(u32(len(items)))
    for item in items:
        encoded = encode_hds(item)
        out += u32(len(encoded))
        out += encoded
    return bytes(out)


def build_message(items, public_key: int) -> bytes:
    """Independently build the chain message straight from the spec."""
    framing = build_framing(items)
    return MESSAGE_TAG + hashlib.sha256(framing).digest() + varint(public_key)


def make_chain(items, key, *, signer_ids=(1, 3), seed=1100):
    """Seal a tuple of segment-set seals with one outer signature of ``key``."""
    message = hdsc_message(items, key.public_key)
    signature = sign_message(key, message, signer_ids=signer_ids, seed=seed)
    return HistoryDeltaSegmentsSealChain(items, signature)


def make_items(key, segments, seed=1200):
    """Three distinct seals over derived segment sets of one partition."""
    return (
        make_seal(segments[:1], key, seed=seed),
        make_seal(segments[1:], key, seed=seed + 1),
        make_seal(segments, key, seed=seed + 2),
    )


class SealChainShapeTest(unittest.TestCase):
    def test_fields_in_order(self):
        self.assertEqual(
            [
                field.name
                for field in dataclasses.fields(HistoryDeltaSegmentsSealChain)
            ],
            ["items", "signature"],
        )

    def test_frozen_positional_and_value_equal(self):
        key, _delta, segments = build_segments()
        items = make_items(key, segments)[:2]
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        chain = HistoryDeltaSegmentsSealChain(items, signature)
        self.assertIs(chain.items, items)
        self.assertIs(chain.signature, signature)
        self.assertEqual(
            chain,
            HistoryDeltaSegmentsSealChain(items=items, signature=signature),
        )
        self.assertEqual(
            hash(chain),
            hash(HistoryDeltaSegmentsSealChain(items, signature)),
        )
        self.assertNotEqual(
            chain,
            HistoryDeltaSegmentsSealChain(items[:1], signature),
        )
        self.assertNotEqual(
            chain,
            HistoryDeltaSegmentsSealChain(
                items, AggregateSignature(R=6, z=7, signer_ids=(1, 3))
            ),
        )
        self.assertEqual(
            {chain, HistoryDeltaSegmentsSealChain(items, signature)},
            {HistoryDeltaSegmentsSealChain(items, signature)},
        )
        with self.assertRaises(FrozenInstanceError):
            chain.items = items

    def test_construction_does_not_validate(self):
        # A plain frozen value: non-tuple items and non-signature fields
        # construct; hdsc_message and verify_hdsc reject them.
        HistoryDeltaSegmentsSealChain("not-a-tuple", "not-a-signature")
        HistoryDeltaSegmentsSealChain(None, None)


class HdscMessageTest(unittest.TestCase):
    def setUp(self):
        self.key, _delta, self.segments = build_segments()
        self.items_a = make_items(self.key, self.segments, seed=1300)[:2]
        self.items_b = make_items(self.key, self.segments, seed=1302)[2:]

    def test_matches_independent_spec_build(self):
        for items in (self.items_a, self.items_b):
            with self.subTest(n=len(items)):
                message = hdsc_message(items, self.key.public_key)
                self.assertEqual(
                    message, build_message(items, self.key.public_key)
                )
                self.assertTrue(message.startswith(MESSAGE_TAG))

    def test_layout_is_tag_digest_of_framing_then_key_varint(self):
        message = hdsc_message(self.items_a, self.key.public_key)
        framing = build_framing(self.items_a)
        offset = 0
        self.assertEqual(message[offset:len(MESSAGE_TAG)], MESSAGE_TAG)
        offset += len(MESSAGE_TAG)
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

    def test_framing_is_count_then_per_seal_frames(self):
        framing = build_framing(self.items_a)
        offset = 0
        self.assertEqual(framing[offset:offset + 4], u32(2))
        offset += 4
        for item in self.items_a:
            encoded = encode_hds(item)
            self.assertEqual(framing[offset:offset + 4], u32(len(encoded)))
            offset += 4
            self.assertEqual(
                framing[offset:offset + len(encoded)], encoded
            )
            offset += len(encoded)
        self.assertEqual(offset, len(framing))

    def test_commits_to_items_order_and_key(self):
        forward = self.items_a
        reverse = tuple(reversed(forward))
        single = forward[:1]
        message = hdsc_message(forward, self.key.public_key)
        self.assertNotEqual(
            message, hdsc_message(reverse, self.key.public_key)
        )
        self.assertNotEqual(
            message, hdsc_message(single, self.key.public_key)
        )
        self.assertNotEqual(
            message, hdsc_message(forward, self.key.public_key + 1)
        )
        self.assertEqual(
            hdsc_message(forward, self.key.public_key), message
        )

    def test_zero_public_key_encodes_as_single_00(self):
        message = hdsc_message(self.items_b, 0)
        framing = build_framing(self.items_b)
        self.assertEqual(
            message,
            MESSAGE_TAG + hashlib.sha256(framing).digest()
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
                hdsc_message(bad, self.key.public_key)

    def test_non_seal_element_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                hdsc_message((bad,), self.key.public_key)
            with self.assertRaises(TypeError, msg=repr(bad)):
                hdsc_message(
                    (self.items_a[0], bad), self.key.public_key
                )
        # The bare segment tuple is not one of its own seals.
        with self.assertRaises(TypeError):
            hdsc_message((self.segments,), self.key.public_key)

    def test_empty_items_value_error(self):
        with self.assertRaises(ValueError):
            hdsc_message((), self.key.public_key)

    def test_illegal_nested_seal_value_error(self):
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        bad_seal = HistoryDeltaSegmentsSeal((), signature)
        with self.assertRaises(ValueError):
            hdsc_message((bad_seal,), self.key.public_key)
        with self.assertRaises(ValueError):
            hdsc_message(
                (self.items_a[0], bad_seal), self.key.public_key
            )

    def test_nested_seal_field_type_error(self):
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        bad_seal = HistoryDeltaSegmentsSeal("not-segments", signature)
        with self.assertRaises(TypeError):
            hdsc_message((bad_seal,), self.key.public_key)

    def test_bad_public_key_type_or_value(self):
        for bad in ("x", None, b"x", 1.5, True, False):
            with self.assertRaises(TypeError, msg=repr(bad)):
                hdsc_message(self.items_a, bad)
        with self.assertRaises(ValueError):
            hdsc_message(self.items_a, -1)


class VerifyHdscShapeAndErrorTest(unittest.TestCase):
    def setUp(self):
        self.key, _delta, self.segments = build_segments()
        self.items = make_items(self.key, self.segments, seed=1400)[:2]
        self.chain = make_chain(self.items, self.key, seed=1402)

    def test_non_chain_type_error(self):
        for bad in ("x", None, 42, b"x", object(), self.items):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_hdsc(bad, self.key)

    def test_non_tuple_items_type_error(self):
        signature = self.chain.signature
        for bad in (list(self.items), iter(self.items), None, "items"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_hdsc(
                    HistoryDeltaSegmentsSealChain(bad, signature),
                    self.key,
                )

    def test_non_seal_element_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_hdsc(
                    HistoryDeltaSegmentsSealChain(
                        (bad,), self.chain.signature
                    ),
                    self.key,
                )

    def test_non_key_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_hdsc(self.chain, bad)

    def test_empty_chain_value_error(self):
        with self.assertRaises(ValueError):
            verify_hdsc(
                HistoryDeltaSegmentsSealChain(
                    (),
                    AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
                ),
                self.key,
            )

    def test_illegal_nested_seal_structure_value_error(self):
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        bad_seal = HistoryDeltaSegmentsSeal((), signature)
        with self.assertRaises(ValueError):
            verify_hdsc(
                HistoryDeltaSegmentsSealChain(
                    (self.items[0], bad_seal), self.chain.signature
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
                verify_hdsc(
                    HistoryDeltaSegmentsSealChain(self.items, bad),
                    self.key,
                )

    def test_bad_outer_signature_field_type_error(self):
        for bad in ("x", None, 5.0, True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_hdsc(
                    HistoryDeltaSegmentsSealChain(self.items, bad),
                    self.key,
                )


class VerifyHdscVerdictTest(unittest.TestCase):
    def setUp(self):
        self.key, _delta, self.segments = build_segments()
        self.items = make_items(self.key, self.segments, seed=1500)
        self.chain = make_chain(self.items, self.key, seed=1503)

    def test_verifying_chain_is_true(self):
        self.assertTrue(verify_hdsc(self.chain, self.key))

    def test_single_item_chain_is_true(self):
        chain = make_chain(self.items[:1], self.key, seed=1510)
        self.assertTrue(verify_hdsc(chain, self.key))

    def test_one_failing_nested_seal_is_false(self):
        # A seal whose signature covers another segment set structurally
        # encodes, but its own verification is False, which makes the
        # whole chain False.
        bad_seal = HistoryDeltaSegmentsSeal(
            self.segments[:1], self.items[1].signature
        )
        self.assertFalse(
            verify_hdsc(
                make_chain((self.items[0], bad_seal), self.key, seed=1521),
                self.key,
            )
        )
        # And the same with the failing seal first in the chain.
        self.assertFalse(
            verify_hdsc(
                make_chain((bad_seal, self.items[0]), self.key, seed=1522),
                self.key,
            )
        )

    def _outer_signature_over(self, items, seed):
        message = hdsc_message(items, self.key.public_key)
        return sign_message(self.key, message, seed=seed)

    def test_deleted_seal_is_false(self):
        # The same items minus one: the outer signature commits to the
        # exact count and ordered seal frames, so deletion fails.
        self.assertFalse(
            verify_hdsc(
                HistoryDeltaSegmentsSealChain(
                    self.items[:2], self.chain.signature
                ),
                self.key,
            )
        )

    def test_inserted_seal_is_false(self):
        self.assertFalse(
            verify_hdsc(
                HistoryDeltaSegmentsSealChain(
                    self.items + (self.items[0],), self.chain.signature
                ),
                self.key,
            )
        )

    def test_reordered_seals_is_false(self):
        self.assertFalse(
            verify_hdsc(
                HistoryDeltaSegmentsSealChain(
                    tuple(reversed(self.items)), self.chain.signature
                ),
                self.key,
            )
        )

    def test_substituted_seal_is_false(self):
        other = make_seal(self.segments[::-1], self.key, seed=1530)
        substituted = (self.items[0], other) + self.items[2:]
        self.assertFalse(
            verify_hdsc(
                HistoryDeltaSegmentsSealChain(
                    substituted, self.chain.signature
                ),
                self.key,
            )
        )

    def test_outer_signature_over_another_item_set_is_false(self):
        foreign = self._outer_signature_over(
            (self.items[2], self.items[0]), seed=1531
        )
        self.assertFalse(
            verify_hdsc(
                HistoryDeltaSegmentsSealChain(self.items[:2], foreign),
                self.key,
            )
        )

    def test_outer_signature_over_reordered_items_is_false(self):
        foreign = self._outer_signature_over(
            tuple(reversed(self.items)), seed=1532
        )
        self.assertFalse(
            verify_hdsc(
                HistoryDeltaSegmentsSealChain(self.items, foreign),
                self.key,
            )
        )

    def test_tampered_outer_signature_is_false(self):
        signature = self.chain.signature
        tampered = AggregateSignature(
            R=signature.R,
            z=signature.z,
            signer_ids=signature.signer_ids[:-1]
            + (signature.signer_ids[-1] ^ 0xFF,),
        )
        self.assertFalse(
            verify_hdsc(
                HistoryDeltaSegmentsSealChain(self.items, tampered),
                self.key,
            )
        )

    def test_other_key_is_false(self):
        other_key = make_other_key()
        self.assertNotEqual(other_key.public_key, self.key.public_key)
        self.assertFalse(verify_hdsc(self.chain, other_key))

    def test_bad_seal_does_not_mask_illegal_outer_signature(self):
        # A structurally legal chain whose nested seal merely fails
        # verification must not turn an illegal outer signature into a
        # plain False: the outer signature structure is checked first.
        bad_seal = HistoryDeltaSegmentsSeal(
            self.segments[:1], self.items[1].signature
        )
        items = (bad_seal, self.items[0])
        for bad_signature in (
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=-1, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=7, signer_ids=()),
            AggregateSignature(R=5, z=7, signer_ids=(3, 1)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad_signature)):
                verify_hdsc(
                    HistoryDeltaSegmentsSealChain(items, bad_signature),
                    self.key,
                )

    def test_bad_seal_does_not_mask_illegal_key(self):
        bad_seal = HistoryDeltaSegmentsSeal(
            self.segments[:1], self.items[1].signature
        )
        chain = make_chain((bad_seal, self.items[0]), self.key, seed=1551)
        for bad_key in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad_key)):
                verify_hdsc(chain, bad_key)
        # A SigningDKGResult-shaped key with an illegal public key is a
        # ValueError from the structure check, not a False verdict.
        broken_key = dataclasses.replace(self.key, public_key=0)
        with self.assertRaises(ValueError):
            verify_hdsc(chain, broken_key)


if __name__ == "__main__":
    unittest.main()
