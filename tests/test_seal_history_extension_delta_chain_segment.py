"""Tests for continuous-interval slicing and adjacent-chain splicing of
incremental seal-history extension chains: slice_history_delta and
concatenate_history_delta."""

import itertools
import unittest

from thresholdsign import (
    AggregateSignature,
    SealHistoryExtension,
    SealHistoryExtensionBundleChain,
    SealHistoryExtensionDeltaChain,
    compact_history_delta,
    concatenate_history_delta,
    decode_history_delta,
    encode_history_delta,
    expand_history_delta,
    slice_history_delta,
    verify_history_delta,
)

from test_nonce_leak_codec import make_other_key
from test_seal_history import sign_message
from test_seal_history_extension import history_of_size
from test_seal_history_extension_delta_chain import (
    linked_chain,
    linked_delta,
)
from test_nonce_reuse import make_key


class SliceTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = history_of_size(self.key, 7)
        self.splits = [(2, 3), (3, 5), (5, 6), (6, 7)]
        self.plain = linked_chain(self.key, self.history, self.splits)
        self.delta = compact_history_delta(self.plain)

    def test_slice_matches_plain_interval_for_every_range(self):
        n = len(self.plain.items)
        for start in range(n):
            for stop in range(start + 1, n + 1):
                with self.subTest(start=start, stop=stop):
                    segment = slice_history_delta(self.delta, start, stop)
                    expected_plain_segment = SealHistoryExtensionBundleChain(
                        items=self.plain.items[start:stop]
                    )
                    # The segment expands value by value into the
                    # self-contained chain's corresponding interval.
                    self.assertEqual(
                        expand_history_delta(segment),
                        expected_plain_segment,
                    )
                    # And the delta fields are the compaction of exactly
                    # that interval.
                    expected_delta = compact_history_delta(
                        expected_plain_segment
                    )
                    self.assertEqual(segment, expected_delta)
                    self.assertEqual(
                        segment.first, self.plain.items[start].extension
                    )
                    self.assertEqual(
                        tuple(
                            bundle.old_sig for bundle in self.plain.items[start:stop]
                        )
                        + (self.plain.items[stop - 1].new_sig,),
                        segment.signatures,
                    )

    def test_slice_single_hop_has_no_additions(self):
        for index in range(len(self.plain.items)):
            segment = slice_history_delta(self.delta, index, index + 1)
            self.assertEqual(segment.additions, ())
            self.assertEqual(
                segment.first, self.plain.items[index].extension
            )
            self.assertEqual(len(segment.signatures), 2)
            self.assertEqual(
                expand_history_delta(segment),
                SealHistoryExtensionBundleChain(
                    items=(self.plain.items[index],)
                ),
            )

    def test_slice_head_and_tail_segments(self):
        n = len(self.plain.items)
        head = slice_history_delta(self.delta, 0, 2)
        tail = slice_history_delta(self.delta, 2, n)
        self.assertEqual(
            expand_history_delta(head),
            SealHistoryExtensionBundleChain(items=self.plain.items[:2]),
        )
        self.assertEqual(
            expand_history_delta(tail),
            SealHistoryExtensionBundleChain(items=self.plain.items[2:]),
        )

    def test_slice_full_interval_is_the_original_chain(self):
        n = len(self.plain.items)
        self.assertEqual(slice_history_delta(self.delta, 0, n), self.delta)

    def test_sliced_segments_verify_independently(self):
        for start, stop in [(0, 1), (1, 3), (0, 2), (2, 4), (0, 4)]:
            segment = slice_history_delta(self.delta, start, stop)
            self.assertTrue(
                verify_history_delta(segment, self.key),
                msg=(start, stop),
            )

    def test_slice_does_not_verify_signatures(self):
        # A structurally legal chain whose signatures do not match the
        # roots still slices; verification stays with verify_history_delta.
        other = make_other_key()
        bad = sign_message(b"unrelated", other, seed=5)
        tampered = SealHistoryExtensionDeltaChain(
            self.delta.first,
            self.delta.additions,
            (bad,) + self.delta.signatures[1:],
        )
        segment = slice_history_delta(tampered, 0, 2)
        self.assertEqual(segment.signatures[0], bad)
        self.assertFalse(
            verify_history_delta(segment, self.key)
        )
        self.assertFalse(
            verify_history_delta(segment, other)
        )

    def test_slice_chain_type_errors(self):
        for bad_chain in ("not a chain", None, 42, object()):
            with self.assertRaises(TypeError, msg=repr(bad_chain)):
                slice_history_delta(bad_chain, 0, 1)

    def test_slice_bound_type_errors_booleans_included(self):
        for bad_bound in (
            True,
            False,
            0.0,
            1.5,
            "1",
            (1,),
            [1],
            None,
            object(),
        ):
            with self.assertRaises(TypeError, msg=repr(bad_bound)):
                slice_history_delta(self.delta, bad_bound, 2)
            with self.assertRaises(TypeError, msg=repr(bad_bound)):
                slice_history_delta(self.delta, 0, bad_bound)

    def test_slice_nested_field_type_errors(self):
        # additions as a list.
        bad = SealHistoryExtensionDeltaChain(
            self.delta.first,
            list(self.delta.additions),
            self.delta.signatures,
        )
        with self.assertRaises(TypeError):
            slice_history_delta(bad, 0, 1)
        # Non-integer old_total inside the nested first extension.
        bad = SealHistoryExtensionDeltaChain(
            SealHistoryExtension("1", self.delta.first.leaves),
            (),
            self.delta.signatures[:2],
        )
        with self.assertRaises(TypeError):
            slice_history_delta(bad, 0, 1)
        # Non-integer R inside a nested signature.
        bad_sig = AggregateSignature(R="r", z=1, signer_ids=(1, 3))
        bad = SealHistoryExtensionDeltaChain(
            self.delta.first,
            (),
            (bad_sig, self.delta.signatures[1]),
        )
        with self.assertRaises(TypeError):
            slice_history_delta(bad, 0, 1)

    def test_slice_value_errors(self):
        n = len(self.plain.items)
        # Empty intervals: touching and reversed.
        for start, stop in [(0, 0), (1, 1), (n, n), (3, 2), (2, 0)]:
            with self.subTest(start=start, stop=stop):
                with self.assertRaises(ValueError):
                    slice_history_delta(self.delta, start, stop)
        # Out of range on either side.
        for start, stop in [
            (-1, 1),
            (0, -1),
            (-1, -1),
            (0, n + 1),
            (1, n + 1),
            (n + 1, n + 2),
            (n, n + 1),
        ]:
            with self.subTest(start=start, stop=stop):
                with self.assertRaises(ValueError):
                    slice_history_delta(self.delta, start, stop)

    def test_slice_nested_value_errors(self):
        # Signature count wrong.
        bad = SealHistoryExtensionDeltaChain(
            self.delta.first,
            self.delta.additions,
            self.delta.signatures[:-1],
        )
        with self.assertRaises(ValueError):
            slice_history_delta(bad, 0, 1)
        # Empty addition batch.
        bad = SealHistoryExtensionDeltaChain(
            self.delta.first,
            ((),) + self.delta.additions[1:],
            self.delta.signatures,
        )
        with self.assertRaises(ValueError):
            slice_history_delta(bad, 0, 1)
        # Illegal nested signature: non-positive R.
        bad_sig = AggregateSignature(R=0, z=1, signer_ids=(1, 3))
        bad = SealHistoryExtensionDeltaChain(
            self.delta.first,
            (),
            (bad_sig, self.delta.signatures[1]),
        )
        with self.assertRaises(ValueError):
            slice_history_delta(bad, 0, 1)


class ConcatenateTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = history_of_size(self.key, 7)
        self.splits = [(2, 3), (3, 5), (5, 6), (6, 7)]
        self.plain = linked_chain(self.key, self.history, self.splits)
        self.delta = compact_history_delta(self.plain)

    def _slice(self, start, stop):
        return slice_history_delta(self.delta, start, stop)

    def test_concatenate_two_segments_reassembles_the_chain(self):
        head = self._slice(0, 2)
        tail = self._slice(2, 4)
        joined = concatenate_history_delta(head, tail)
        self.assertEqual(joined, self.delta)
        # Expanded form is the two expanded chains in order, with the
        # shared checkpoint signature kept once.
        head_plain = expand_history_delta(head)
        tail_plain = expand_history_delta(tail)
        joined_plain = expand_history_delta(joined)
        self.assertEqual(
            joined_plain.items, head_plain.items + tail_plain.items
        )
        self.assertEqual(
            len(joined_plain.items),
            len(head_plain.items) + len(tail_plain.items),
        )
        self.assertEqual(joined_plain, self.plain)

    def test_concatenate_four_single_hop_segments(self):
        pieces = [self._slice(i, i + 1) for i in range(4)]
        joined = pieces[0]
        for piece in pieces[1:]:
            joined = concatenate_history_delta(joined, piece)
        self.assertEqual(joined, self.delta)
        self.assertTrue(verify_history_delta(joined, self.key))

    def test_concatenate_splits_at_every_seam(self):
        for cut in range(1, 4):
            left = self._slice(0, cut)
            right = self._slice(cut, 4)
            joined = concatenate_history_delta(left, right)
            self.assertEqual(joined, self.delta, msg=cut)

    def test_concatenate_result_encodes_byte_for_byte(self):
        joined = concatenate_history_delta(
            self._slice(0, 2), self._slice(2, 4)
        )
        blob = encode_history_delta(joined)
        self.assertEqual(blob, encode_history_delta(self.delta))
        self.assertEqual(decode_history_delta(blob), joined)

    def test_segmented_transport_and_archive_reassembly(self):
        pieces = [self._slice(0, 1), self._slice(1, 3), self._slice(3, 4)]
        # Each piece travels on its own as canonical bytes.
        blobs = [encode_history_delta(piece) for piece in pieces]
        decoded = [decode_history_delta(blob) for blob in blobs]
        joined = decoded[0]
        for piece in decoded[1:]:
            joined = concatenate_history_delta(joined, piece)
        self.assertEqual(joined, self.delta)
        self.assertEqual(
            encode_history_delta(joined),
            encode_history_delta(self.delta),
        )

    def test_every_partition_round_trips_value_and_bytes(self):
        # Slice and concatenate are inverses for every legal cut set: each
        # segment is independently encoded and decoded, and folding the
        # decoded segments restores the original chain byte for byte.
        n = len(self.plain.items)
        cuts = tuple(range(1, n))
        for chosen in itertools.chain.from_iterable(
            itertools.combinations(cuts, r) for r in range(len(cuts) + 1)
        ):
            bounds = (0,) + chosen + (n,)
            pieces = [
                decode_history_delta(
                    encode_history_delta(
                        self._slice(bounds[index], bounds[index + 1])
                    )
                )
                for index in range(len(bounds) - 1)
            ]
            joined = pieces[0]
            for piece in pieces[1:]:
                joined = concatenate_history_delta(joined, piece)
            self.assertEqual(joined, self.delta, msg=chosen)
            self.assertEqual(
                encode_history_delta(joined),
                encode_history_delta(self.delta),
                msg=chosen,
            )

    def test_concatenate_does_not_verify_signatures(self):
        bad = sign_message(b"unrelated", make_other_key(), seed=7)
        tampered = SealHistoryExtensionDeltaChain(
            self.delta.first,
            self.delta.additions,
            self.delta.signatures[:-1] + (bad,),
        )
        head = self._slice(0, 2)
        bad_tail = slice_history_delta(tampered, 2, 4)
        # The seam signature is still shared by value; only the final
        # checkpoint signature is wrong, which concatenation ignores.
        joined = concatenate_history_delta(head, bad_tail)
        self.assertEqual(joined.signatures[-1], bad)
        self.assertFalse(verify_history_delta(joined, self.key))

    def test_concatenate_type_errors(self):
        head = self._slice(0, 2)
        tail = self._slice(2, 4)
        for bad in ("not a chain", None, 42, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                concatenate_history_delta(bad, tail)
            with self.assertRaises(TypeError, msg=repr(bad)):
                concatenate_history_delta(head, bad)

    def test_concatenate_nested_field_type_errors(self):
        head = self._slice(0, 2)
        sliced_tail = self._slice(2, 4)
        bad_tail = SealHistoryExtensionDeltaChain(
            "not an extension",
            sliced_tail.additions,
            sliced_tail.signatures,
        )
        with self.assertRaises(TypeError):
            concatenate_history_delta(head, bad_tail)

    def test_concatenate_rejects_leaf_prefix_gap(self):
        # The right chain's first hop claims an old_total one short of the
        # left chain's last leaf count.
        left = self._slice(0, 3)
        right = self._slice(3, 4)
        right_first = right.first
        bad_right = SealHistoryExtensionDeltaChain(
            SealHistoryExtension(
                right_first.old_total - 1, right_first.leaves
            ),
            right.additions,
            right.signatures,
        )
        with self.assertRaises(ValueError):
            concatenate_history_delta(left, bad_right)

    def test_concatenate_rejects_leaf_prefix_overlap_tamper(self):
        # Same old_total as the seam, but the shared prefix leaves differ.
        left = self._slice(0, 3)
        right = self._slice(3, 4)
        right_first = right.first
        bad_right = SealHistoryExtensionDeltaChain(
            SealHistoryExtension(
                right_first.old_total,
                (b"z" * 32,) + right_first.leaves[1:],
            ),
            right.additions,
            right.signatures,
        )
        with self.assertRaises(ValueError):
            concatenate_history_delta(left, bad_right)

    def test_concatenate_rejects_shared_signature_mismatch(self):
        left = self._slice(0, 2)
        right = self._slice(2, 4)
        bad_sig = AggregateSignature(R=70001, z=70002, signer_ids=(1, 3))
        bad_right = SealHistoryExtensionDeltaChain(
            right.first,
            right.additions,
            (bad_sig,) + right.signatures[1:],
        )
        with self.assertRaises(ValueError):
            concatenate_history_delta(left, bad_right)

    def test_concatenate_nested_value_errors(self):
        left = self._slice(0, 2)
        right = self._slice(2, 4)
        bad_right = SealHistoryExtensionDeltaChain(
            right.first, right.additions, right.signatures[:-1]
        )
        with self.assertRaises(ValueError):
            concatenate_history_delta(left, bad_right)

    def test_concatenate_rejects_unrelated_chains(self):
        # Two individually legal chains that share no checkpoint: the
        # second covers a disjoint range of a larger seal history.
        left = self._slice(0, 1)
        other_history = history_of_size(self.key, 9)
        other_plain = linked_chain(
            self.key, other_history, [(1, 4), (4, 8)], seed=9900
        )
        other_delta = compact_history_delta(other_plain)
        right = slice_history_delta(other_delta, 0, 1)
        with self.assertRaises(ValueError):
            concatenate_history_delta(left, right)


class WiderSplitsTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = history_of_size(self.key, 9)

    def test_wider_splits_slice_and_splice_round_trip(self):
        for splits in (
            ((1, 3), (3, 5), (5, 9)),
            ((1, 9),),
            ((4, 5), (5, 6), (6, 9)),
        ):
            with self.subTest(splits=splits):
                plain = linked_chain(
                    self.key, self.history, splits, seed=31000
                )
                delta = linked_delta(
                    self.key, self.history, splits, seed=31000
                )
                n = len(plain.items)
                if n == 1:
                    self.assertEqual(
                        slice_history_delta(delta, 0, 1), delta
                    )
                    continue
                left = slice_history_delta(delta, 0, n - 1)
                right = slice_history_delta(delta, n - 1, n)
                joined = concatenate_history_delta(left, right)
                self.assertEqual(joined, delta)
                self.assertEqual(
                    encode_history_delta(joined),
                    encode_history_delta(delta),
                )
                self.assertTrue(verify_history_delta(joined, self.key))


if __name__ == "__main__":
    unittest.main()
