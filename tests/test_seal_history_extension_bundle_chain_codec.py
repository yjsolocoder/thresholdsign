"""Tests for the canonical SealHistoryExtensionBundleChain transport encoding:
encode_history_extension_bundle_chain /
decode_history_extension_bundle_chain /
verify_history_extension_bundle_chain."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    SealHistory,
    SealHistoryExtension,
    SealHistoryExtensionBundle,
    SealHistoryExtensionBundleChain,
    decode_history_extension_bundle_chain,
    encode_history_extension_bundle,
    encode_history_extension_bundle_chain,
    verify_history_extension_bundle_chain,
)

from test_nonce_reuse import make_key
from test_nonce_leak_codec import make_other_key
from test_seal_history import make_history
from test_seal_history_extension import history_of_size
from test_seal_history_extension_bundle_codec import signed_bundle, u32

CHAIN_TAG = b"ts/shebc/v1"
BUNDLE_TAG = b"ts/sheb/v1"


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def build_wire(chain: SealHistoryExtensionBundleChain) -> bytes:
    """Independently build the chain wire format straight from the spec."""
    out = bytearray(CHAIN_TAG)
    out += u32(len(chain.items))
    for item in chain.items:
        out += frame(encode_history_extension_bundle(item))
    return bytes(out)


def linked_chain(key, items, splits, *, seed=9000):
    """Build a chain whose bundles link along the given growing split points."""
    bundles = []
    for old_total, new_total in splits:
        bundles.append(
            signed_bundle(
                key, SealHistory(items[:new_total]), old_total, seed=seed
            )
        )
        seed += 10
    return SealHistoryExtensionBundleChain(tuple(bundles))


class ChainDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [
                field.name
                for field in dataclasses.fields(SealHistoryExtensionBundleChain)
            ],
            ["items"],
        )
        extension = SealHistoryExtension(1, (b"a" * 32, b"b" * 32))
        sig = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        bundle = SealHistoryExtensionBundle(extension, sig, sig)
        items = (bundle,)
        chain = SealHistoryExtensionBundleChain(items)
        self.assertIs(chain.items, items)
        self.assertEqual(SealHistoryExtensionBundleChain(items=items), chain)

    def test_frozen_value_equality_and_hash(self):
        extension = SealHistoryExtension(1, (b"a" * 32, b"b" * 32))
        sig = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        a = SealHistoryExtensionBundle(extension, sig, sig)
        b = SealHistoryExtensionBundle(
            extension, AggregateSignature(R=6, z=7, signer_ids=(1, 3)), sig
        )
        chain = SealHistoryExtensionBundleChain((a, b))
        same = SealHistoryExtensionBundleChain((a, b))
        self.assertEqual(chain, same)
        self.assertEqual(hash(chain), hash(same))
        self.assertNotEqual(chain, SealHistoryExtensionBundleChain((a,)))
        self.assertNotEqual(chain, SealHistoryExtensionBundleChain((b, a)))
        with self.assertRaises(FrozenInstanceError):
            chain.items = (a,)

    def test_construction_does_not_validate(self):
        # A plain frozen value: codec and verifier do the checking.
        SealHistoryExtensionBundleChain(())
        SealHistoryExtensionBundleChain(("not-a-bundle",))
        SealHistoryExtensionBundleChain(None)


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = history_of_size(self.key, 8).items

    def test_honest_chains_round_trip_at_every_length(self):
        seed = 10000
        # Every prefix chain 1 -> 2 -> ... -> m for m in 2..8.
        for m in range(2, 9):
            splits = tuple((i, i + 1) for i in range(1, m))
            chain = linked_chain(self.key, self.history[:m], splits, seed=seed)
            seed += 100
            wire = encode_history_extension_bundle_chain(chain)
            decoded = decode_history_extension_bundle_chain(wire)
            self.assertEqual(decoded, chain, msg=f"m={m}")
            self.assertEqual(
                encode_history_extension_bundle_chain(decoded), wire
            )
            self.assertTrue(
                verify_history_extension_bundle_chain(decoded, self.key),
                msg=f"m={m}",
            )

    def test_wider_splits_round_trip_and_verify(self):
        splits = ((1, 3), (3, 5), (5, 8))
        chain = linked_chain(self.key, self.history, splits, seed=11000)
        wire = encode_history_extension_bundle_chain(chain)
        self.assertEqual(decode_history_extension_bundle_chain(wire), chain)
        self.assertTrue(
            verify_history_extension_bundle_chain(chain, self.key)
        )

    def test_single_item_chain_round_trips(self):
        bundle = signed_bundle(
            self.key, history_of_size(self.key, 4), 2, seed=11100
        )
        chain = SealHistoryExtensionBundleChain((bundle,))
        wire = encode_history_extension_bundle_chain(chain)
        decoded = decode_history_extension_bundle_chain(wire)
        self.assertEqual(decoded, chain)
        self.assertTrue(
            verify_history_extension_bundle_chain(decoded, self.key)
        )

    def test_encoding_matches_independent_builder(self):
        splits = ((1, 2), (2, 4), (4, 7))
        chain = linked_chain(self.key, self.history, splits, seed=12000)
        wire = encode_history_extension_bundle_chain(chain)
        self.assertEqual(wire, build_wire(chain))
        self.assertTrue(wire.startswith(CHAIN_TAG))
        self.assertEqual(wire[len(CHAIN_TAG):len(CHAIN_TAG) + 4], u32(3))

    def test_frames_are_existing_single_bundle_encodings(self):
        splits = ((1, 3), (3, 6))
        chain = linked_chain(self.key, self.history, splits, seed=12100)
        wire = encode_history_extension_bundle_chain(chain)
        offset = len(CHAIN_TAG) + 4
        for item in chain.items:
            encoded = encode_history_extension_bundle(item)
            self.assertEqual(wire[offset:offset + 4], u32(len(encoded)))
            offset += 4
            self.assertTrue(
                wire[offset:offset + len(BUNDLE_TAG)] == BUNDLE_TAG
            )
            self.assertEqual(wire[offset:offset + len(encoded)], encoded)
            offset += len(encoded)
        self.assertEqual(offset, len(wire))

    def test_encoding_is_unique_and_stateless(self):
        chain = linked_chain(
            self.key, self.history, ((1, 3), (3, 5)), seed=12200
        )
        self.assertEqual(
            encode_history_extension_bundle_chain(chain),
            encode_history_extension_bundle_chain(chain),
        )


class StructureOnlyTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = history_of_size(self.key, 6).items

    def test_decode_does_not_check_signatures_or_linkage(self):
        # Two individually honest bundles over unrelated histories:
        # every signature verifies on its own, but the leaf sets do not
        # link — decode restores the chain unchanged and the verifier
        # reports the broken linkage as False.
        first = signed_bundle(
            self.key, history_of_size(self.key, 4), 2, seed=13100
        )
        other_history = make_history(self.key, nonces=(51, 52, 53, 54, 55))
        second = signed_bundle(self.key, other_history, 2, seed=13110)
        chain = SealHistoryExtensionBundleChain((first, second))
        decoded = decode_history_extension_bundle_chain(
            encode_history_extension_bundle_chain(chain)
        )
        self.assertEqual(decoded, chain)
        self.assertFalse(
            verify_history_extension_bundle_chain(decoded, self.key)
        )

    def test_honest_bundle_wrong_key_decodes_but_fails_verification(self):
        other = make_other_key()
        chain = linked_chain(
            self.key, self.history, ((1, 3), (3, 5)), seed=13000
        )
        self.assertTrue(encode_history_extension_bundle_chain(chain))
        self.assertFalse(
            verify_history_extension_bundle_chain(chain, other)
        )


class LinkageTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = history_of_size(self.key, 8).items

    def _chain(self, splits, seed=14000):
        return linked_chain(self.key, self.history, splits, seed=seed)

    def test_matching_prefixes_link(self):
        chain = self._chain(((2, 4), (4, 6), (6, 8)))
        self.assertTrue(
            verify_history_extension_bundle_chain(chain, self.key)
        )

    def test_gap_between_neighbours_returns_false(self):
        # 2 -> 4 then 5 -> 8: the predecessor has 4 leaves but the
        # successor's old_total is 5.
        chain = self._chain(((2, 4), (5, 8)))
        self.assertFalse(
            verify_history_extension_bundle_chain(chain, self.key)
        )

    def test_overlap_between_neighbours_returns_false(self):
        chain = self._chain(((2, 5), (3, 8)))
        self.assertFalse(
            verify_history_extension_bundle_chain(chain, self.key)
        )

    def test_same_count_but_different_leaves_returns_false(self):
        first = signed_bundle(
            self.key, history_of_size(self.key, 4), 2, seed=14100
        )
        # A successor over a different history with matching counts.
        other_history = make_history(
            self.key, nonces=(51, 52, 53, 54, 55, 56)
        )
        second = signed_bundle(self.key, other_history, 4, seed=14110)
        chain = SealHistoryExtensionBundleChain((first, second))
        # Both bundles individually verify, but the leaves do not link.
        self.assertEqual(
            len(first.extension.leaves), second.extension.old_total
        )
        self.assertFalse(
            verify_history_extension_bundle_chain(chain, self.key)
        )

    def test_one_bad_bundle_returns_false_even_when_counts_line_up(self):
        other = make_other_key()
        first = signed_bundle(
            self.key, history_of_size(self.key, 4), 2, seed=14200
        )
        second_ours = signed_bundle(
            self.key, history_of_size(self.key, 6), 4, seed=14210
        )
        second_foreign = signed_bundle(
            other, history_of_size(self.key, 6), 4, seed=14220
        )
        chain = SealHistoryExtensionBundleChain((first, second_foreign))
        # Linkage holds structurally; the foreign signature fails.
        self.assertEqual(
            len(first.extension.leaves), second_foreign.extension.old_total
        )
        self.assertEqual(
            first.extension.leaves,
            second_foreign.extension.leaves[:4],
        )
        self.assertFalse(
            verify_history_extension_bundle_chain(chain, self.key)
        )
        # Sanity: the all-ours variant verifies.
        self.assertTrue(
            verify_history_extension_bundle_chain(
                SealHistoryExtensionBundleChain((first, second_ours)),
                self.key,
            )
        )


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.bundle = signed_bundle(
            self.key, history_of_size(self.key, 5), 2, seed=15000
        )

    def test_non_chain_type_error(self):
        for bad in (("x",), [self.bundle], None, self.bundle, "chain"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_history_extension_bundle_chain(bad)

    def test_non_tuple_items_type_error(self):
        with self.assertRaises(TypeError):
            encode_history_extension_bundle_chain(
                SealHistoryExtensionBundleChain([self.bundle])
            )

    def test_non_bundle_element_type_error(self):
        for bad in (
            (self.bundle, "x"),
            (None,),
            (self.bundle.extension,),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_history_extension_bundle_chain(
                    SealHistoryExtensionBundleChain(bad)
                )

    def test_empty_chain_value_error(self):
        with self.assertRaises(ValueError):
            encode_history_extension_bundle_chain(
                SealHistoryExtensionBundleChain(())
            )

    def test_illegal_nested_bundle_value_error(self):
        bad_extension = SealHistoryExtension(0, (b"a" * 32, b"b" * 32))
        sig = self.bundle.old_sig
        bad_bundle = SealHistoryExtensionBundle(bad_extension, sig, sig)
        with self.assertRaises(ValueError):
            encode_history_extension_bundle_chain(
                SealHistoryExtensionBundleChain((self.bundle, bad_bundle))
            )


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.chain = linked_chain(
            self.key,
            history_of_size(self.key, 6).items,
            ((1, 3), (3, 5)),
            seed=16000,
        )
        self.wire = encode_history_extension_bundle_chain(self.chain)

    def test_non_bytes_type_error(self):
        with self.assertRaises(TypeError):
            decode_history_extension_bundle_chain("not bytes")
        with self.assertRaises(TypeError):
            decode_history_extension_bundle_chain(bytearray(self.wire))

    def test_bad_tag(self):
        rest = self.wire[len(CHAIN_TAG):]
        with self.assertRaises(ValueError):
            decode_history_extension_bundle_chain(b"ts/shebc/v2" + rest)
        with self.assertRaises(ValueError):
            decode_history_extension_bundle_chain(b"x" + self.wire[1:])

    def test_truncation(self):
        for cut in range(len(CHAIN_TAG), len(self.wire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_history_extension_bundle_chain(self.wire[:cut])

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_history_extension_bundle_chain(self.wire + b"\x00")

    def test_zero_count_rejected(self):
        bad = CHAIN_TAG + u32(0)
        with self.assertRaises(ValueError):
            decode_history_extension_bundle_chain(bad)

    def test_declared_count_too_large_then_truncated(self):
        body = self.wire[len(CHAIN_TAG) + 4:]
        bad = CHAIN_TAG + u32(3) + body
        with self.assertRaises(ValueError):
            decode_history_extension_bundle_chain(bad)

    def test_declared_count_too_small_leaves_trailing_frame(self):
        # Rebuild with count 1 but both frames present.
        bodies = [
            frame(encode_history_extension_bundle(item))
            for item in self.chain.items
        ]
        bad = CHAIN_TAG + u32(1) + b"".join(bodies)
        with self.assertRaises(ValueError):
            decode_history_extension_bundle_chain(bad)

    def test_zero_frame_length_rejected(self):
        first_body = encode_history_extension_bundle(self.chain.items[0])
        rest = self.wire[len(CHAIN_TAG) + 4 + 4 + len(first_body):]
        bad = CHAIN_TAG + u32(2) + u32(0) + first_body + rest
        with self.assertRaises(ValueError):
            decode_history_extension_bundle_chain(bad)

    def test_junk_nested_frame_rejected(self):
        bad = CHAIN_TAG + u32(1) + frame(b"not-a-bundle")
        with self.assertRaises(ValueError):
            decode_history_extension_bundle_chain(bad)

    def test_declared_frame_length_mismatch(self):
        first_body = encode_history_extension_bundle(self.chain.items[0])
        rest = self.wire[len(CHAIN_TAG) + 4 + 4 + len(first_body):]
        bad = (
            CHAIN_TAG
            + u32(2)
            + u32(len(first_body) - 1)
            + first_body
            + rest
        )
        with self.assertRaises(ValueError):
            decode_history_extension_bundle_chain(bad)

    def test_nested_non_canonical_encoding_rejected(self):
        # Flip a byte inside the nested bundle tag: the nested decoder
        # must reject it rather than the chain swallowing the error.
        bundle_body = encode_history_extension_bundle(self.chain.items[0])
        tampered = b"x" + bundle_body[1:]
        bad = CHAIN_TAG + u32(1) + frame(tampered)
        with self.assertRaises(ValueError):
            decode_history_extension_bundle_chain(bad)


class VerifyValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.bundle = signed_bundle(
            self.key, history_of_size(self.key, 5), 2, seed=17000
        )

    def test_non_chain_type_error(self):
        for bad in ((self.bundle,), None, self.bundle, "chain"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_history_extension_bundle_chain(bad, self.key)

    def test_empty_chain_value_error(self):
        with self.assertRaises(ValueError):
            verify_history_extension_bundle_chain(
                SealHistoryExtensionBundleChain(()), self.key
            )

    def test_non_tuple_items_type_error(self):
        with self.assertRaises(TypeError):
            verify_history_extension_bundle_chain(
                SealHistoryExtensionBundleChain([self.bundle]), self.key
            )

    def test_non_bundle_element_type_error(self):
        with self.assertRaises(TypeError):
            verify_history_extension_bundle_chain(
                SealHistoryExtensionBundleChain((self.bundle, "x")), self.key
            )

    def test_bad_key_type_error(self):
        chain = SealHistoryExtensionBundleChain((self.bundle,))
        with self.assertRaises(TypeError):
            verify_history_extension_bundle_chain(chain, "key")

    def test_illegal_nested_structure_value_error(self):
        bad_extension = SealHistoryExtension(0, (b"a" * 32, b"b" * 32))
        sig = self.bundle.old_sig
        bad_bundle = SealHistoryExtensionBundle(bad_extension, sig, sig)
        with self.assertRaises(ValueError):
            verify_history_extension_bundle_chain(
                SealHistoryExtensionBundleChain((bad_bundle,)), self.key
            )


if __name__ == "__main__":
    unittest.main()
