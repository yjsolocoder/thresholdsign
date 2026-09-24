"""Tests for the incremental SealHistoryExtensionDeltaChain and the
expand_history_delta / compact_history_delta conversions."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    SealHistory,
    SealHistoryExtension,
    SealHistoryExtensionBundle,
    SealHistoryExtensionBundleChain,
    SealHistoryExtensionDeltaChain,
    compact_history_delta,
    expand_history_delta,
    make_history_extension,
    verify_history_extension_bundle_chain,
)

from test_nonce_reuse import make_key
from test_nonce_leak_codec import make_other_key
from test_seal_history import make_history, sign_message
from test_seal_history_extension import history_of_size


def linked_chain(key, history, splits, *, seed=9000):
    """Build a bundle chain whose hops link along the growing split points.

    Each checkpoint root statement is signed deterministically; the shared
    checkpoint between two hops is signed by the successor with the very
    seed the predecessor used for its new-root signature, producing a
    distinct object that is nevertheless equal by value — exactly the
    reuse-by-value condition compact_history_delta enforces.
    """
    items = []
    shared_seed = None
    for old_n, new_n in splits:
        prefix = SealHistory(history.items[:new_n])
        old_message, new_message, proof = make_history_extension(prefix, old_n)
        old_seed = seed if shared_seed is None else shared_seed
        old_sig = sign_message(old_message, key, seed=old_seed)
        shared_seed = seed + 1
        new_sig = sign_message(new_message, key, seed=shared_seed)
        items.append(
            SealHistoryExtensionBundle(
                extension=proof, old_sig=old_sig, new_sig=new_sig
            )
        )
        seed += 10
    return SealHistoryExtensionBundleChain(items=tuple(items))


def make_delta(key, history, splits, *, seed=9000):
    """Build a delta chain equivalent to linked_chain(key, history, splits)."""
    chain = linked_chain(key, history, splits, seed=seed)
    return compact_history_delta(chain)


class DeltaChainDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [
                field.name
                for field in dataclasses.fields(SealHistoryExtensionDeltaChain)
            ],
            ["first", "additions", "signatures"],
        )
        first = SealHistoryExtension(1, (b"a" * 32, b"b" * 32))
        additions = ((b"c" * 32,), (b"d" * 32, b"e" * 32))
        signatures = tuple(
            AggregateSignature(R=5 + 2 * i, z=7 + 2 * i, signer_ids=(1, 3))
            for i in range(4)
        )
        chain = SealHistoryExtensionDeltaChain(first, additions, signatures)
        self.assertEqual(chain.first, first)
        self.assertEqual(chain.additions, additions)
        self.assertEqual(chain.signatures, signatures)
        self.assertEqual(
            SealHistoryExtensionDeltaChain(
                first=first, additions=additions, signatures=signatures
            ),
            chain,
        )

    def test_no_field_defaults(self):
        for field in dataclasses.fields(SealHistoryExtensionDeltaChain):
            self.assertIs(
                field.default,
                dataclasses.MISSING,
                msg=field.name,
            )

    def test_frozen_value_equality_and_hash(self):
        first = SealHistoryExtension(1, (b"a" * 32, b"b" * 32))
        signatures = (
            AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=9, z=11, signer_ids=(1, 3)),
        )
        left = SealHistoryExtensionDeltaChain(first, (), signatures)
        right = SealHistoryExtensionDeltaChain(first, (), signatures)
        self.assertEqual(left, right)
        self.assertEqual(hash(left), hash(right))
        with self.assertRaises(FrozenInstanceError):
            left.first = first
        other = SealHistoryExtensionDeltaChain(
            first, ((b"c" * 32,),), signatures + (signatures[0],)
        )
        self.assertNotEqual(left, other)

    def test_construction_does_not_validate(self):
        # A plain frozen value: expand/compact and the codec do the checking.
        SealHistoryExtensionDeltaChain("not a proof", (), ())
        SealHistoryExtensionDeltaChain(None, None, None)


class ExpandTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = history_of_size(self.key, 8)

    def test_expand_round_trip_matches_plain_chain(self):
        splits = [(2, 4), (4, 5), (5, 8)]
        plain = linked_chain(self.key, self.history, splits)
        delta = make_delta(self.key, self.history, splits)
        self.assertEqual(delta.first, plain.items[0].extension)
        self.assertEqual(
            delta.additions,
            tuple(
                bundle.extension.leaves[bundle.extension.old_total:]
                for bundle in plain.items[1:]
            ),
        )
        self.assertEqual(
            delta.signatures,
            (plain.items[0].old_sig,)
            + tuple(bundle.new_sig for bundle in plain.items),
        )
        expanded = expand_history_delta(delta)
        self.assertEqual(expanded, plain)
        self.assertTrue(
            verify_history_extension_bundle_chain(expanded, self.key)
        )

    def test_shared_checkpoint_signatures_are_reused_by_value(self):
        plain = linked_chain(
            self.key, self.history, [(2, 4), (4, 6), (6, 8)]
        )
        for previous, successor in zip(plain.items, plain.items[1:]):
            # Distinct objects ...
            self.assertIsNot(previous.new_sig, successor.old_sig)
            # ... equal by value, and stored exactly once in the delta form.
            self.assertEqual(previous.new_sig, successor.old_sig)
        delta = compact_history_delta(plain)
        self.assertEqual(len(delta.signatures), len(plain.items) + 1)

    def test_expand_empty_additions_single_hop(self):
        plain = linked_chain(self.key, self.history, [(2, 4)])
        delta = make_delta(self.key, self.history, [(2, 4)])
        self.assertEqual(delta.additions, ())
        self.assertEqual(len(delta.signatures), 2)
        expanded = expand_history_delta(delta)
        self.assertEqual(expanded, plain)
        self.assertTrue(
            verify_history_extension_bundle_chain(expanded, self.key)
        )

    def test_expand_cumulative_old_total(self):
        delta = make_delta(
            self.key, self.history, [(2, 3), (3, 5), (5, 8)]
        )
        expanded = expand_history_delta(delta)
        self.assertEqual(
            [bundle.extension.old_total for bundle in expanded.items],
            [2, 3, 5],
        )
        self.assertEqual(
            [len(bundle.extension.leaves) for bundle in expanded.items],
            [3, 5, 8],
        )
        for previous, bundle in zip(expanded.items, expanded.items[1:]):
            old_total = bundle.extension.old_total
            self.assertEqual(
                bundle.extension.leaves[:old_total],
                previous.extension.leaves,
            )

    def test_expand_brackets_each_hop_with_adjacent_signatures(self):
        delta = make_delta(
            self.key, self.history, [(1, 3), (3, 5), (5, 8)]
        )
        expanded = expand_history_delta(delta)
        for index, bundle in enumerate(expanded.items):
            self.assertIs(bundle.old_sig, delta.signatures[index])
            self.assertIs(bundle.new_sig, delta.signatures[index + 1])

    def test_expand_does_not_verify_signatures(self):
        # Structurally legal but root-mismatched signatures expand fine;
        # verification is left to verify_history_extension_bundle_chain.
        delta = make_delta(self.key, self.history, [(2, 4), (4, 6)])
        other = make_other_key()
        bad = sign_message(b"unrelated", other, seed=5)
        tampered = SealHistoryExtensionDeltaChain(
            delta.first, delta.additions, (bad,) + delta.signatures[1:]
        )
        expanded = expand_history_delta(tampered)
        self.assertFalse(
            verify_history_extension_bundle_chain(expanded, self.key)
        )

    def test_expand_type_errors(self):
        delta = make_delta(self.key, self.history, [(2, 4), (4, 6)])
        good_first = delta.first
        good_additions = delta.additions
        good_signatures = delta.signatures
        bad_cases = [
            SealHistoryExtensionDeltaChain(
                "not a proof", good_additions, good_signatures
            ),
            SealHistoryExtensionDeltaChain(
                good_first, list(good_additions), good_signatures
            ),
            SealHistoryExtensionDeltaChain(
                good_first, (list(good_additions[0]),), good_signatures
            ),
            SealHistoryExtensionDeltaChain(
                good_first, ((1, 2),), good_signatures
            ),
            SealHistoryExtensionDeltaChain(
                good_first, good_additions, list(good_signatures)
            ),
            SealHistoryExtensionDeltaChain(
                good_first, good_additions,
                good_signatures[:-1] + ("x",),
            ),
        ]
        for chain in bad_cases:
            with self.assertRaises(TypeError, msg=repr(chain)):
                expand_history_delta(chain)
        with self.assertRaises(TypeError):
            expand_history_delta("not a chain")
        with self.assertRaises(TypeError):
            expand_history_delta(None)

    def test_expand_nested_field_type_errors(self):
        delta = make_delta(self.key, self.history, [(2, 4)])
        # old_total of the wrong type inside the nested first extension.
        bad_first = SealHistoryExtension("1", delta.first.leaves)
        chain = SealHistoryExtensionDeltaChain(
            bad_first, (), delta.signatures[:2]
        )
        with self.assertRaises(TypeError):
            expand_history_delta(chain)
        # Non-integer R inside a nested signature.
        bad_sig = AggregateSignature(R="r", z=1, signer_ids=(1, 3))
        chain = SealHistoryExtensionDeltaChain(
            delta.first, (), (bad_sig, delta.signatures[1])
        )
        with self.assertRaises(TypeError):
            expand_history_delta(chain)

    def test_expand_value_errors(self):
        delta = make_delta(self.key, self.history, [(2, 4), (4, 6)])
        first = delta.first
        additions = delta.additions
        signatures = delta.signatures
        # Empty batch.
        with self.assertRaises(ValueError):
            expand_history_delta(
                SealHistoryExtensionDeltaChain(first, ((),), signatures)
            )
        # Digest of the wrong width.
        with self.assertRaises(ValueError):
            expand_history_delta(
                SealHistoryExtensionDeltaChain(
                    first, ((b"x" * 31,),), signatures
                )
            )
        # Signature count mismatch (both directions).
        with self.assertRaises(ValueError):
            expand_history_delta(
                SealHistoryExtensionDeltaChain(
                    first, additions, signatures[:-1]
                )
            )
        with self.assertRaises(ValueError):
            expand_history_delta(
                SealHistoryExtensionDeltaChain(
                    first, additions, signatures + (signatures[0],)
                )
            )
        # Illegal nested extension: old_total out of range.
        with self.assertRaises(ValueError):
            expand_history_delta(
                SealHistoryExtensionDeltaChain(
                    SealHistoryExtension(0, first.leaves),
                    (),
                    signatures[:2],
                )
            )
        # Illegal nested extension: empty leaves.
        with self.assertRaises(ValueError):
            expand_history_delta(
                SealHistoryExtensionDeltaChain(
                    SealHistoryExtension(1, ()), (), signatures[:2]
                )
            )
        # Illegal nested signature: non-positive R.
        bad_sig = AggregateSignature(R=0, z=1, signer_ids=(1, 3))
        with self.assertRaises(ValueError):
            expand_history_delta(
                SealHistoryExtensionDeltaChain(
                    first, (), (bad_sig, signatures[1])
                )
            )
        # Illegal nested signature: unordered signer ids.
        bad_sig = AggregateSignature(R=5, z=1, signer_ids=(3, 1))
        with self.assertRaises(ValueError):
            expand_history_delta(
                SealHistoryExtensionDeltaChain(
                    first, (), (bad_sig, signatures[1])
                )
            )


class CompactTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = history_of_size(self.key, 8)

    def test_compact_round_trip(self):
        splits = [(2, 4), (4, 5), (5, 8)]
        plain = linked_chain(self.key, self.history, splits)
        delta = compact_history_delta(plain)
        self.assertEqual(delta.first, plain.items[0].extension)
        self.assertEqual(
            delta.additions,
            tuple(
                bundle.extension.leaves[bundle.extension.old_total:]
                for bundle in plain.items[1:]
            ),
        )
        self.assertEqual(
            delta.signatures,
            (plain.items[0].old_sig,)
            + tuple(bundle.new_sig for bundle in plain.items),
        )
        self.assertEqual(expand_history_delta(delta), plain)
        # Compacting the expansion again is a fixed point.
        self.assertEqual(
            compact_history_delta(expand_history_delta(delta)), delta
        )

    def test_compact_single_hop_chain(self):
        plain = linked_chain(self.key, self.history, [(3, 6)])
        delta = compact_history_delta(plain)
        self.assertEqual(delta.additions, ())
        self.assertEqual(
            delta.signatures,
            (plain.items[0].old_sig, plain.items[0].new_sig),
        )
        self.assertEqual(expand_history_delta(delta), plain)

    def test_compact_does_not_verify_signatures(self):
        # A structurally legal chain whose first signature does not match
        # its root still compacts; verification stays with the expanded form.
        plain = linked_chain(self.key, self.history, [(2, 4), (4, 6)])
        other = make_other_key()
        bad = sign_message(b"unrelated", other, seed=7)
        first = plain.items[0]
        tampered_first = SealHistoryExtensionBundle(
            first.extension, bad, first.new_sig
        )
        tampered = SealHistoryExtensionBundleChain(
            (tampered_first,) + plain.items[1:]
        )
        delta = compact_history_delta(tampered)
        self.assertIs(delta.signatures[0], bad)
        self.assertFalse(
            verify_history_extension_bundle_chain(
                expand_history_delta(delta), self.key
            )
        )

    def test_compact_type_errors(self):
        plain = linked_chain(self.key, self.history, [(2, 4), (4, 6)])
        with self.assertRaises(TypeError):
            compact_history_delta("not a chain")
        with self.assertRaises(TypeError):
            compact_history_delta(None)
        with self.assertRaises(TypeError):
            compact_history_delta(
                SealHistoryExtensionBundleChain(list(plain.items))
            )
        with self.assertRaises(TypeError):
            compact_history_delta(
                SealHistoryExtensionBundleChain(("x",) + plain.items[1:])
            )
        # A non-signature inside a bundle surfaces as TypeError.
        first = plain.items[0]
        bad_bundle = SealHistoryExtensionBundle(
            first.extension, "not-a-sig", first.new_sig
        )
        rest = plain.items[1:]
        with self.assertRaises(TypeError):
            compact_history_delta(
                SealHistoryExtensionBundleChain((bad_bundle,) + rest)
            )
        # A non-extension inside a bundle surfaces as TypeError.
        bad_bundle = SealHistoryExtensionBundle(
            "not-an-extension", first.old_sig, first.new_sig
        )
        rest = plain.items[1:]
        with self.assertRaises(TypeError):
            compact_history_delta(
                SealHistoryExtensionBundleChain((bad_bundle,) + rest)
            )

    def test_compact_value_errors(self):
        plain = linked_chain(self.key, self.history, [(2, 4), (4, 6)])
        signatures = (
            plain.items[0].old_sig,
            plain.items[0].new_sig,
            plain.items[1].new_sig,
        )
        # Empty chain.
        with self.assertRaises(ValueError):
            compact_history_delta(SealHistoryExtensionBundleChain(()))
        # Illegal nested extension: leaf of the wrong width.
        second = plain.items[1]
        bad_extension = SealHistoryExtension(
            second.extension.old_total,
            second.extension.leaves[:-1] + (b"x" * 31,),
        )
        bad_bundle = SealHistoryExtensionBundle(
            bad_extension, second.old_sig, second.new_sig
        )
        with self.assertRaises(ValueError):
            compact_history_delta(
                SealHistoryExtensionBundleChain(
                    (plain.items[0], bad_bundle)
                )
            )
        # Illegal nested signature: negative z.
        bad_sig = AggregateSignature(R=5, z=-1, signer_ids=(1, 3))
        first = plain.items[0]
        bad_first = SealHistoryExtensionBundle(
            first.extension, bad_sig, first.new_sig
        )
        with self.assertRaises(ValueError):
            compact_history_delta(
                SealHistoryExtensionBundleChain(
                    (bad_first,) + plain.items[1:]
                )
            )
        # Defence in depth: the signature tuple built internally has the
        # expected length for every non-empty input chain.
        self.assertEqual(len(signatures), len(plain.items) + 1)

    def test_compact_broken_prefix(self):
        # Gap: the second hop's old_total does not match the first hop's
        # leaf count.
        first_bundle = linked_chain(
            self.key, self.history, [(2, 4)]
        ).items[0]
        gap_prefix = SealHistory(self.history.items[:6])
        _old_message, _new_message, gap_proof = make_history_extension(
            gap_prefix, 5
        )
        gap_bundle = SealHistoryExtensionBundle(
            gap_proof,
            sign_message(_old_message, self.key, seed=9500),
            sign_message(_new_message, self.key, seed=9501),
        )
        with self.assertRaises(ValueError):
            compact_history_delta(
                SealHistoryExtensionBundleChain((first_bundle, gap_bundle))
            )

        # Overlap: old_total matches but the shared leaves differ.
        other_history = make_history(self.key, nonces=tuple(range(900, 910)))
        other_prefix = SealHistory(other_history.items[:6])
        _old_message, _new_message, other_proof = make_history_extension(
            other_prefix, 4
        )
        overlap_bundle = SealHistoryExtensionBundle(
            other_proof,
            # Reuse the predecessor's new_sig value to pass the signature
            # check; the leaves themselves must still be rejected.
            first_bundle.new_sig,
            sign_message(_new_message, self.key, seed=9511),
        )
        with self.assertRaises(ValueError):
            compact_history_delta(
                SealHistoryExtensionBundleChain(
                    (first_bundle, overlap_bundle)
                )
            )

    def test_compact_mismatched_shared_signature(self):
        # Both hops individually verify and the leaf prefixes link, but the
        # successor's old_sig is a different valid signature of the very
        # same shared checkpoint statement: equal roots, unequal signature
        # values must be rejected.
        plain = linked_chain(self.key, self.history, [(2, 4), (4, 6)])
        first, second = plain.items
        # Same checkpoint statement, different signing nonces -> a distinct
        # valid signature of the very same root message.
        _old_message, shared_message, _proof = make_history_extension(
            SealHistory(self.history.items[:4]), 2
        )
        different_sig = sign_message(shared_message, self.key, seed=9700)
        self.assertNotEqual(different_sig, first.new_sig)
        self.assertEqual(second.old_sig, first.new_sig)
        reseamed = SealHistoryExtensionBundle(
            second.extension, different_sig, second.new_sig
        )
        with self.assertRaises(ValueError):
            compact_history_delta(
                SealHistoryExtensionBundleChain((first, reseamed))
            )


if __name__ == "__main__":
    unittest.main()
