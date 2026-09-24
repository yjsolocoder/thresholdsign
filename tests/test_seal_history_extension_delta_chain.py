"""Tests for the incremental SealHistoryExtensionDeltaChain and the
expand_history_delta / compact_history_delta conversions and the
expand-then-verify verify_history_delta entry point."""

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
    encode_history_delta,
    expand_history_delta,
    make_history_extension,
    verify_history_delta,
    verify_history_extension_bundle_chain,
)

from test_nonce_reuse import make_key
from test_nonce_leak_codec import make_other_key
from test_seal_history import sign_message
from test_seal_history_extension import history_of_size


def linked_chain(key, history, splits, *, seed=9000):
    """Build a bundle chain whose bundles link along the growing splits.

    Every checkpoint root statement is signed exactly once and the same
    signature value is reused as the predecessor's new-root and the
    successor's old-root signature, the way a real archiving run does it.
    """
    signed = {}

    def sig_for(message):
        if message not in signed:
            signed[message] = sign_message(message, key, seed=seed)
        return signed[message]

    items = []
    for old_n, new_n in splits:
        prefix = SealHistory(history.items[:new_n])
        old_message, new_message, proof = make_history_extension(prefix, old_n)
        old_sig = sig_for(old_message)
        new_sig = sig_for(new_message)
        items.append(SealHistoryExtensionBundle(proof, old_sig, new_sig))
        seed += 10
    return SealHistoryExtensionBundleChain(tuple(items))


def linked_delta(key, history, splits, *, seed=9000):
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
            self.assertIs(field.default, dataclasses.MISSING)
            self.assertIs(field.default_factory, dataclasses.MISSING)

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
            SealHistoryExtension(1, (b"a" * 32, b"c" * 32)),
            (),
            signatures,
        )
        self.assertNotEqual(left, other)

    def test_construction_does_not_validate(self):
        # A plain frozen value: the conversions and codec do the checking.
        SealHistoryExtensionDeltaChain("x", (), ())
        SealHistoryExtensionDeltaChain(None, None, None)


class ExpandTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = history_of_size(self.key, 8)

    def test_expand_round_trip_matches_plain_chain(self):
        splits = ((2, 4), (4, 5), (5, 8))
        plain = linked_chain(self.key, self.history, splits)
        delta = linked_delta(self.key, self.history, splits)
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

    def test_expand_empty_additions_single_hop(self):
        plain = linked_chain(self.key, self.history, ((2, 4),))
        delta = linked_delta(self.key, self.history, ((2, 4),))
        self.assertEqual(delta.additions, ())
        self.assertEqual(len(delta.signatures), 2)
        self.assertEqual(expand_history_delta(delta), plain)

    def test_expand_cumulative_old_total(self):
        delta = linked_delta(
            self.key, self.history, ((2, 3), (3, 5), (5, 8))
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

    def test_same_signature_instance_brackets_each_hop(self):
        delta = linked_delta(
            self.key, self.history, ((1, 3), (3, 5), (5, 8))
        )
        expanded = expand_history_delta(delta)
        for index, bundle in enumerate(expanded.items):
            self.assertIs(bundle.old_sig, delta.signatures[index])
            self.assertIs(bundle.new_sig, delta.signatures[index + 1])
        for previous, bundle in zip(expanded.items, expanded.items[1:]):
            self.assertIs(previous.new_sig, bundle.old_sig)
            self.assertEqual(previous.new_sig, bundle.old_sig)

    def test_expand_does_not_verify_signatures(self):
        # Structurally legal but root-mismatched signatures expand fine;
        # verification is left to verify_history_extension_bundle_chain.
        delta = linked_delta(
            self.key, self.history, ((2, 4), (4, 6))
        )
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
        delta = linked_delta(
            self.key, self.history, ((2, 4), (4, 6))
        )
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
                good_first, good_additions, good_signatures[:-1] + ("x",)
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
        delta = linked_delta(self.key, self.history, ((2, 4),))
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
        # Non-tuple leaves inside the nested first extension.
        chain = SealHistoryExtensionDeltaChain(
            SealHistoryExtension(1, list(delta.first.leaves)),
            (),
            delta.signatures[:2],
        )
        with self.assertRaises(TypeError):
            expand_history_delta(chain)

    def test_expand_value_errors(self):
        delta = linked_delta(
            self.key, self.history, ((2, 4), (4, 6))
        )
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
                    SealHistoryExtension(0, first.leaves), (), signatures[:2]
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
        # Illegal nested signature: negative z.
        bad_sig = AggregateSignature(R=5, z=-1, signer_ids=(1, 3))
        with self.assertRaises(ValueError):
            expand_history_delta(
                SealHistoryExtensionDeltaChain(
                    first, additions, (bad_sig,) + signatures[1:]
                )
            )


class CompactTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = history_of_size(self.key, 8)

    def test_compact_round_trip(self):
        splits = ((2, 4), (4, 5), (5, 8))
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

    def test_compact_single_hop_chain(self):
        plain = linked_chain(self.key, self.history, ((3, 6),))
        delta = compact_history_delta(plain)
        self.assertEqual(delta.additions, ())
        self.assertEqual(len(delta.signatures), 2)
        self.assertEqual(expand_history_delta(delta), plain)

    def test_compact_does_not_verify_signatures(self):
        # A structurally legal chain whose signatures do not match the roots
        # still compacts; verification stays with the expanded form.
        plain = linked_chain(
            self.key, self.history, ((2, 4), (4, 6))
        )
        other = make_other_key()
        bad = sign_message(b"unrelated", other, seed=7)
        tampered_items = (
            SealHistoryExtensionBundle(
                plain.items[0].extension,
                bad,
                plain.items[0].new_sig,
            ),
        ) + plain.items[1:]
        tampered = SealHistoryExtensionBundleChain(tampered_items)
        delta = compact_history_delta(tampered)
        self.assertEqual(delta.signatures[0], bad)
        self.assertFalse(
            verify_history_extension_bundle_chain(
                expand_history_delta(delta), self.key
            )
        )

    def test_compact_type_errors(self):
        plain = linked_chain(
            self.key, self.history, ((2, 4), (4, 6))
        )
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
                SealHistoryExtensionBundleChain(
                    ("x",) + plain.items[1:]
                )
            )

    def test_compact_value_errors(self):
        plain = linked_chain(
            self.key, self.history, ((2, 4), (4, 6))
        )
        # Empty chain.
        with self.assertRaises(ValueError):
            compact_history_delta(SealHistoryExtensionBundleChain(()))
        # Illegal nested extension: leaf of the wrong width.
        middle = plain.items[1]
        bad_extension = SealHistoryExtension(
            middle.extension.old_total,
            middle.extension.leaves[:-1] + (b"x" * 31,),
        )
        bad_bundle = SealHistoryExtensionBundle(
            bad_extension, middle.old_sig, middle.new_sig
        )
        with self.assertRaises(ValueError):
            compact_history_delta(
                SealHistoryExtensionBundleChain(
                    (plain.items[0], bad_bundle)
                )
            )
        # Illegal nested signature: negative z.
        bad_sig = AggregateSignature(R=5, z=-1, signer_ids=(1, 3))
        bad_bundle = SealHistoryExtensionBundle(
            plain.items[0].extension,
            bad_sig,
            plain.items[0].new_sig,
        )
        with self.assertRaises(ValueError):
            compact_history_delta(
                SealHistoryExtensionBundleChain((bad_bundle,))
            )

    def test_compact_broken_prefix_gap(self):
        # 2 -> 4 then 5 -> 8: the predecessor has 4 leaves but the
        # successor's old_total is 5.
        plain = linked_chain(
            self.key, self.history, ((2, 4), (5, 8))
        )
        with self.assertRaises(ValueError):
            compact_history_delta(plain)

    def test_compact_broken_prefix_overlap(self):
        plain = linked_chain(
            self.key, self.history, ((2, 5), (3, 8))
        )
        with self.assertRaises(ValueError):
            compact_history_delta(plain)

    def test_compact_same_count_but_different_leaves(self):
        from test_seal_history import make_history

        first_chain = linked_chain(
            self.key, self.history, ((2, 4),)
        )
        # A successor over different seals with matching counts: its first
        # four leaves differ from the predecessor's leaves.
        other_history = make_history(self.key, nonces=tuple(range(900, 906)))
        second_bundle = linked_chain(
            self.key, other_history, ((2, 4), (4, 6)), seed=9900
        ).items[1]
        chain = SealHistoryExtensionBundleChain(
            (first_chain.items[0], second_bundle)
        )
        with self.assertRaises(ValueError):
            compact_history_delta(chain)

    def test_compact_shared_signature_mismatch_raises_value_error(self):
        # Linkage holds and every signature verifies on its own statement,
        # but the seam carries two different signatures of the shared
        # checkpoint statement instead of one shared value.
        plain = linked_chain(
            self.key, self.history, ((2, 4), (4, 6))
        )
        middle = plain.items[0]
        successor = plain.items[1]
        # Re-sign the shared old-root statement with a different seed:
        # valid by itself, but not equal by value to the predecessor's
        # new_sig.
        resig = sign_message(
            make_history_extension(
                SealHistory(self.history.items[:4]), 2
            )[1],
            self.key,
            seed=424242,
        )
        self.assertNotEqual(resig, middle.new_sig)
        resealed_successor = SealHistoryExtensionBundle(
            successor.extension, resig, successor.new_sig
        )
        chain = SealHistoryExtensionBundleChain(
            (middle, resealed_successor)
        )
        with self.assertRaises(ValueError):
            compact_history_delta(chain)


class ExpandCompactConsistencyTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = history_of_size(self.key, 9)

    def test_expand_compact_inverses_at_every_length(self):
        seed = 20000
        for m in range(2, 10):
            splits = tuple((i, i + 1) for i in range(1, m))
            plain = linked_chain(
                self.key,
                self.history,
                splits,
                seed=seed,
            )
            seed += 100
            delta = compact_history_delta(plain)
            self.assertEqual(expand_history_delta(delta), plain, msg=f"m={m}")
            # compact(expand(delta)) restores the delta value by value.
            self.assertEqual(
                compact_history_delta(expand_history_delta(delta)), delta
            )
            # The delta wire is shorter than the self-contained chain wire:
            # shared leaves occur in one place only.
            from thresholdsign import (
                encode_history_extension_bundle_chain,
                encode_history_delta,
            )
            self.assertLess(
                len(encode_history_delta(delta)),
                len(encode_history_extension_bundle_chain(plain)),
            )

    def test_wider_splits_round_trip(self):
        for splits in (
            ((1, 3), (3, 5), (5, 9)),
            ((1, 9),),
            ((4, 5), (5, 6), (6, 9)),
        ):
            plain = linked_chain(self.key, self.history, splits, seed=21000)
            delta = compact_history_delta(plain)
            self.assertEqual(expand_history_delta(delta), plain)
            self.assertTrue(verify_history_delta(delta, self.key))


class VerifyHistoryDeltaTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = history_of_size(self.key, 8)

    def test_honest_delta_chains_verify(self):
        for splits in (
            ((2, 4),),
            ((1, 3), (3, 5), (5, 8)),
            ((2, 4), (4, 6), (6, 8)),
        ):
            delta = linked_delta(self.key, self.history, splits, seed=22000)
            self.assertTrue(
                verify_history_delta(delta, self.key), msg=str(splits)
            )

    def test_wrong_key_returns_false(self):
        other = make_other_key()
        delta = linked_delta(
            self.key, self.history, ((1, 3), (3, 5)), seed=22100
        )
        self.assertFalse(verify_history_delta(delta, other))

    def test_tampered_batch_leaf_returns_false(self):
        delta = linked_delta(
            self.key, self.history, ((2, 4), (4, 6), (6, 8)), seed=22200
        )
        flipped = bytearray(delta.additions[0][0])
        flipped[0] ^= 1
        bad_additions = (
            ((bytes(flipped),) + delta.additions[0][1:]),
        ) + delta.additions[1:]
        tampered = SealHistoryExtensionDeltaChain(
            delta.first, bad_additions, delta.signatures
        )
        self.assertFalse(verify_history_delta(tampered, self.key))

    def test_tampered_first_leaf_returns_false(self):
        delta = linked_delta(
            self.key, self.history, ((2, 4), (4, 6)), seed=22300
        )
        flipped = bytearray(delta.first.leaves[0])
        flipped[0] ^= 1
        bad_first = SealHistoryExtension(
            delta.first.old_total,
            (bytes(flipped),) + delta.first.leaves[1:],
        )
        tampered = SealHistoryExtensionDeltaChain(
            bad_first, delta.additions, delta.signatures
        )
        self.assertFalse(verify_history_delta(tampered, self.key))

    def test_tampered_old_total_returns_false(self):
        delta = linked_delta(
            self.key, self.history, ((2, 4), (4, 6)), seed=22400
        )
        bad_first = SealHistoryExtension(1, delta.first.leaves)
        tampered = SealHistoryExtensionDeltaChain(
            bad_first, delta.additions, delta.signatures
        )
        # The structure is still legal; the old root statement no longer
        # matches the first signature.
        self.assertFalse(verify_history_delta(tampered, self.key))

    def test_bad_signature_returns_false(self):
        delta = linked_delta(
            self.key, self.history, ((2, 4), (4, 6)), seed=22500
        )
        bad_sig = AggregateSignature(
            R=delta.signatures[1].R,
            z=(delta.signatures[1].z + 1),
            signer_ids=delta.signatures[1].signer_ids,
        )
        tampered = SealHistoryExtensionDeltaChain(
            delta.first,
            delta.additions,
            delta.signatures[:1] + (bad_sig,) + delta.signatures[2:],
        )
        self.assertFalse(verify_history_delta(tampered, self.key))

    def test_non_delta_type_error(self):
        for bad in (("x",), None, "chain", 42):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_history_delta(bad, self.key)

    def test_bad_key_type_error(self):
        delta = linked_delta(self.key, self.history, ((2, 4),))
        with self.assertRaises(TypeError):
            verify_history_delta(delta, "key")

    def test_structural_errors_raise_not_false(self):
        delta = linked_delta(
            self.key, self.history, ((2, 4), (4, 6))
        )
        # Empty batch: ValueError, not a False verdict.
        with self.assertRaises(ValueError):
            verify_history_delta(
                SealHistoryExtensionDeltaChain(
                    delta.first, ((),), delta.signatures[:2]
                ),
                self.key,
            )
        # Wrong-width digest: ValueError.
        with self.assertRaises(ValueError):
            verify_history_delta(
                SealHistoryExtensionDeltaChain(
                    delta.first,
                    ((b"x" * 31,),),
                    delta.signatures[:3],
                ),
                self.key,
            )
        # Signature count mismatch: ValueError.
        with self.assertRaises(ValueError):
            verify_history_delta(
                SealHistoryExtensionDeltaChain(
                    delta.first, delta.additions, delta.signatures[:-1]
                ),
                self.key,
            )


if __name__ == "__main__":
    unittest.main()
