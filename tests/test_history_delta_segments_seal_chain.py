"""Tests for the non-empty order-preserving chain of whole
history-delta-segments seals and its outer threshold-Schnorr signature:
HistoryDeltaSegmentsSealChain / hdsc_message / verify_hdsc."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    HistoryDeltaSegmentsSeal,
    HistoryDeltaSegmentsSealChain,
    decode_hdsc,
    encode_hdsc,
    encode_hds,
    hdsc_message,
    verify_hdsc,
    verify_signature,
)

from test_nonce_reuse import FIELD_PRIME, GENERATOR, GROUP_PRIME
from test_nonce_leak_codec import make_other_key
from test_audit_chain import sign_message
from test_history_delta_segments_codec import build_segments
from test_history_delta_segments_seal import make_seal

MESSAGE_TAG = b"ts/hdsc/m1"


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def build_framing(seals) -> bytes:
    """Independently build C straight from the spec."""
    out = bytearray(u32(len(seals)))
    for seal in seals:
        encoded = encode_hds(seal)
        out += u32(len(encoded))
        out += encoded
    return bytes(out)


def build_message(seals, public_key: int) -> bytes:
    """Independently build the chain message straight from the spec."""
    framing = build_framing(seals)
    return MESSAGE_TAG + hashlib.sha256(framing).digest() + varint(public_key)


def make_chain(seals, key, *, signer_ids=(1, 3), seed=2000):
    """Seal a tuple of segment-set seals with one outer signature of ``key``."""
    message = hdsc_message(seals, key.public_key)
    signature = sign_message(key, message, signer_ids=signer_ids, seed=seed)
    return HistoryDeltaSegmentsSealChain(seals, signature)


class HistoryDeltaSegmentsSealChainValueTest(unittest.TestCase):
    def setUp(self):
        self.key, _delta, segments = build_segments()
        self.seals = (
            make_seal((segments[0],), self.key, seed=2100),
            make_seal((segments[1], segments[2]), self.key, seed=2101),
        )

    def test_fields_in_order(self):
        self.assertEqual(
            [
                field.name
                for field in dataclasses.fields(HistoryDeltaSegmentsSealChain)
            ],
            ["seals", "signature"],
        )

    def test_frozen_positional_and_value_equal(self):
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        chain = HistoryDeltaSegmentsSealChain(self.seals, signature)
        self.assertIs(chain.seals, self.seals)
        self.assertIs(chain.signature, signature)
        self.assertEqual(
            chain,
            HistoryDeltaSegmentsSealChain(
                seals=self.seals, signature=signature
            ),
        )
        self.assertEqual(
            hash(chain),
            hash(HistoryDeltaSegmentsSealChain(self.seals, signature)),
        )
        # Order matters.
        self.assertNotEqual(
            chain,
            HistoryDeltaSegmentsSealChain(tuple(reversed(self.seals)), signature),
        )
        self.assertNotEqual(
            chain,
            HistoryDeltaSegmentsSealChain(
                self.seals, AggregateSignature(R=6, z=7, signer_ids=(1, 3))
            ),
        )
        self.assertEqual(
            {chain, HistoryDeltaSegmentsSealChain(self.seals, signature)},
            {HistoryDeltaSegmentsSealChain(self.seals, signature)},
        )
        with self.assertRaises(FrozenInstanceError):
            chain.seals = self.seals

    def test_construction_does_not_validate(self):
        # A plain frozen value: non-tuple seals and non-signature fields
        # construct; hdsc_message and verify_hdsc reject them.
        HistoryDeltaSegmentsSealChain(
            (), AggregateSignature(0, -1, ())
        )
        HistoryDeltaSegmentsSealChain("not-a-tuple", "not-a-signature")


class HdscMessageTest(unittest.TestCase):
    def setUp(self):
        self.key, _delta, segments = build_segments()
        self.seals_a = (
            make_seal((segments[0],), self.key, seed=2200),
            make_seal((segments[1], segments[2]), self.key, seed=2201),
        )
        self.seals_b = (
            make_seal(segments, self.key, seed=2202),
        )

    def test_matches_independent_spec_build(self):
        for seals in (self.seals_a, self.seals_b):
            with self.subTest(n=len(seals)):
                message = hdsc_message(seals, self.key.public_key)
                self.assertEqual(
                    message, build_message(seals, self.key.public_key)
                )
                self.assertTrue(message.startswith(MESSAGE_TAG))

    def test_layout_is_tag_digest_of_framing_then_key_varint(self):
        message = hdsc_message(self.seals_a, self.key.public_key)
        framing = build_framing(self.seals_a)
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
        framing = build_framing(self.seals_a)
        offset = 0
        self.assertEqual(framing[offset:offset + 4], u32(2))
        offset += 4
        for seal in self.seals_a:
            encoded = encode_hds(seal)
            self.assertEqual(framing[offset:offset + 4], u32(len(encoded)))
            offset += 4
            self.assertEqual(framing[offset:offset + len(encoded)], encoded)
            offset += len(encoded)
        self.assertEqual(offset, len(framing))

    def test_commits_to_seals_order_and_key(self):
        forward = self.seals_a
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
        message = hdsc_message(self.seals_b, 0)
        framing = build_framing(self.seals_b)
        self.assertEqual(
            message,
            MESSAGE_TAG
            + hashlib.sha256(framing).digest()
            + b"\x00\x00\x00\x01\x00",
        )

    def test_non_tuple_seals_type_error(self):
        for bad in (
            list(self.seals_a),
            iter(self.seals_a),
            self.seals_a[0],
            "seals",
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
                    (self.seals_a[0], bad), self.key.public_key
                )

    def test_empty_seals_value_error(self):
        with self.assertRaises(ValueError):
            hdsc_message((), self.key.public_key)

    def test_illegal_nested_seal_value_error(self):
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        bad_seal = HistoryDeltaSegmentsSeal((), signature)
        with self.assertRaises(ValueError):
            hdsc_message((bad_seal,), self.key.public_key)
        with self.assertRaises(ValueError):
            hdsc_message(
                (self.seals_a[0], bad_seal), self.key.public_key
            )

    def test_nested_seal_field_type_error(self):
        bad_seal = HistoryDeltaSegmentsSeal(
            "not-segments",
            AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
        )
        with self.assertRaises(TypeError):
            hdsc_message((bad_seal,), self.key.public_key)

    def test_bad_public_key_type_or_value(self):
        for bad in ("x", None, b"x", 1.5, True, False):
            with self.assertRaises(TypeError, msg=repr(bad)):
                hdsc_message(self.seals_a, bad)
        with self.assertRaises(ValueError):
            hdsc_message(self.seals_a, -1)


class VerifyHdscShapeAndErrorTest(unittest.TestCase):
    def setUp(self):
        self.key, _delta, segments = build_segments()
        self.seals = (
            make_seal((segments[0],), self.key, seed=2300),
            make_seal((segments[1], segments[2]), self.key, seed=2301),
        )
        self.chain = make_chain(self.seals, self.key, seed=2302)

    def test_non_chain_type_error(self):
        for bad in ("x", None, 42, b"x", object(), self.seals):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_hdsc(bad, self.key)

    def test_non_tuple_seals_type_error(self):
        signature = self.chain.signature
        for bad in (list(self.seals), iter(self.seals), None, "seals"):
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
                    (self.seals[0], bad_seal), self.chain.signature
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
                    HistoryDeltaSegmentsSealChain(self.seals, bad),
                    self.key,
                )

    def test_bad_outer_signature_field_type_error(self):
        for bad in ("x", None, 5.0, True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_hdsc(
                    HistoryDeltaSegmentsSealChain(self.seals, bad),
                    self.key,
                )


class VerifyHdscVerdictTest(unittest.TestCase):
    def setUp(self):
        self.key, _delta, segments = build_segments()
        self.seals = (
            make_seal((segments[0],), self.key, seed=2400),
            make_seal((segments[1],), self.key, seed=2401),
            make_seal((segments[2],), self.key, seed=2402),
        )
        self.chain = make_chain(self.seals, self.key, seed=2403)

    def test_verifying_chain_is_true(self):
        self.assertTrue(verify_hdsc(self.chain, self.key))

    def test_single_seal_chain_is_true(self):
        chain = make_chain(self.seals[:1], self.key, seed=2410)
        self.assertTrue(verify_hdsc(chain, self.key))

    def test_decoded_verifying_chain_still_verifies(self):
        restored = decode_hdsc(encode_hdsc(self.chain))
        self.assertTrue(verify_hdsc(restored, self.key))

    def test_hdsc_message_is_what_the_outer_signature_covers(self):
        self.assertTrue(
            verify_signature(
                hdsc_message(self.seals, self.key.public_key),
                self.chain.signature,
                self.key.public_key,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            )
        )

    def test_one_failing_nested_seal_is_false(self):
        # A structurally legal seal whose own seal signature was
        # tampered with fails verify_hds, which makes the chain False.
        tampered_signature = dataclasses.replace(
            self.seals[1].signature,
            z=(self.seals[1].signature.z + 1) % FIELD_PRIME,
        )
        bad_seal = HistoryDeltaSegmentsSeal(
            self.seals[1].segments, tampered_signature
        )
        chain = HistoryDeltaSegmentsSealChain(
            (self.seals[0], bad_seal, self.seals[2]),
            self.chain.signature,
        )
        self.assertFalse(verify_hdsc(chain, self.key))
        # And the same with the failing seal first in the chain.
        chain = HistoryDeltaSegmentsSealChain(
            (bad_seal, self.seals[0]), self.chain.signature
        )
        self.assertFalse(verify_hdsc(chain, self.key))

    def test_nested_seal_sealed_under_another_key_is_false(self):
        foreign_seal = make_seal(
            self.seals[0].segments, make_other_key(), seed=2420
        )
        chain = HistoryDeltaSegmentsSealChain(
            (self.seals[0], foreign_seal), self.chain.signature
        )
        self.assertFalse(verify_hdsc(chain, self.key))

    def _outer_signature_over(self, seals, seed):
        message = hdsc_message(seals, self.key.public_key)
        return sign_message(self.key, message, seed=seed)

    def test_deleted_seal_returns_false(self):
        foreign = self._outer_signature_over(self.seals[:2], seed=2430)
        self.assertFalse(
            verify_hdsc(
                HistoryDeltaSegmentsSealChain(self.seals, foreign),
                self.key,
            )
        )

    def test_inserted_seal_returns_false(self):
        extra = self.seals + self.seals[:1]
        foreign = self._outer_signature_over(extra, seed=2431)
        self.assertFalse(
            verify_hdsc(
                HistoryDeltaSegmentsSealChain(self.seals, foreign),
                self.key,
            )
        )

    def test_reordered_seals_returns_false(self):
        foreign = self._outer_signature_over(
            tuple(reversed(self.seals)), seed=2432
        )
        self.assertFalse(
            verify_hdsc(
                HistoryDeltaSegmentsSealChain(self.seals, foreign),
                self.key,
            )
        )

    def test_substituted_seal_returns_false(self):
        foreign = self._outer_signature_over(
            (self.seals[0], self.seals[0], self.seals[2]), seed=2433
        )
        self.assertFalse(
            verify_hdsc(
                HistoryDeltaSegmentsSealChain(self.seals, foreign),
                self.key,
            )
        )

    def test_tampered_outer_signature_returns_false(self):
        signature = self.chain.signature
        tampered = AggregateSignature(
            R=signature.R,
            z=signature.z,
            signer_ids=signature.signer_ids[:-1]
            + (signature.signer_ids[-1] ^ 0xFF,),
        )
        self.assertFalse(
            verify_hdsc(
                HistoryDeltaSegmentsSealChain(self.seals, tampered),
                self.key,
            )
        )

    def test_other_key_is_false(self):
        self.assertFalse(verify_hdsc(self.chain, make_other_key()))

    def test_bad_nested_seal_does_not_mask_illegal_outer_signature(self):
        # A structurally legal chain whose nested seal merely fails
        # verification must not turn an illegal outer signature into a
        # plain False: the outer signature structure is checked first.
        tampered_signature = dataclasses.replace(
            self.seals[0].signature,
            z=(self.seals[0].signature.z + 1) % FIELD_PRIME,
        )
        bad_seal = HistoryDeltaSegmentsSeal(
            self.seals[0].segments, tampered_signature
        )
        items = (bad_seal, self.seals[1])
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

    def test_bad_nested_seal_does_not_mask_illegal_key(self):
        tampered_signature = dataclasses.replace(
            self.seals[0].signature,
            z=(self.seals[0].signature.z + 1) % FIELD_PRIME,
        )
        bad_seal = HistoryDeltaSegmentsSeal(
            self.seals[0].segments, tampered_signature
        )
        chain = HistoryDeltaSegmentsSealChain(
            (bad_seal, self.seals[1]), self.chain.signature
        )
        for bad_key in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad_key)):
                verify_hdsc(chain, bad_key)
        broken_key = dataclasses.replace(self.key, public_key=0)
        with self.assertRaises(ValueError):
            verify_hdsc(chain, broken_key)


if __name__ == "__main__":
    unittest.main()
