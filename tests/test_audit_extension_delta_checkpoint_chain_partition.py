"""Tests for multi-cut partitioning and batch reassembly of incremental
audit-extension checkpoint chains: partition_delta_chain and
join_delta_chain_segments."""

import unittest

from thresholdsign import (
    AggregateSignature,
    AuditExtensionDeltaCheckpointChain,
    AuditExtensionProof,
    compact_audit_extension_delta_checkpoint_chain,
    decode_audit_extension_delta_checkpoint_chain,
    encode_audit_extension_delta_checkpoint_chain,
    expand_audit_extension_delta_checkpoint_chain,
    join_delta_chain_segments,
    partition_delta_chain,
    slice_audit_extension_delta_checkpoint_chain,
    verify_audit_extension_delta_checkpoint_chain,
)

from test_audit_chain import make_key, sign_message
from test_audit_extension_checkpoint_chain_codec import linked_chain
from test_audit_extension_proof_bundle_codec import (
    make_other_key,
    make_records,
)


def make_delta(key, records, splits, *, seed=9000):
    """Build a delta chain equivalent to linked_chain(key, records, splits)."""
    return compact_audit_extension_delta_checkpoint_chain(
        linked_chain(key, records, splits, seed=seed)
    )


class PartitionTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = make_records(self.key, 7)
        self.splits = [(2, 3), (3, 5), (5, 6), (6, 7)]
        self.plain = linked_chain(self.key, self.records, self.splits)
        self.delta = compact_audit_extension_delta_checkpoint_chain(self.plain)
        self.n = len(self.plain.proofs)

    def test_empty_cuts_returns_whole_chain_single_segment(self):
        segments = partition_delta_chain(self.delta, ())
        self.assertIsInstance(segments, tuple)
        self.assertEqual(segments, (self.delta,))

    def test_partition_matches_repeated_slicing(self):
        for cuts in [(1,), (2,), (3,), (1, 2), (1, 3), (2, 3), (1, 2, 3)]:
            with self.subTest(cuts=cuts):
                segments = partition_delta_chain(self.delta, cuts)
                bounds = (0,) + cuts + (self.n,)
                expected = tuple(
                    slice_audit_extension_delta_checkpoint_chain(
                        self.delta, bounds[index], bounds[index + 1]
                    )
                    for index in range(len(bounds) - 1)
                )
                self.assertEqual(segments, expected)

    def test_partition_returns_non_empty_segments_in_chain_order(self):
        segments = partition_delta_chain(self.delta, (1, 2, 3))
        self.assertEqual(len(segments), 4)
        offset = 0
        for segment in segments:
            expanded = expand_audit_extension_delta_checkpoint_chain(segment)
            self.assertGreaterEqual(len(expanded.proofs), 1)
            self.assertEqual(
                expanded.proofs,
                self.plain.proofs[offset:offset + len(expanded.proofs)],
            )
            offset += len(expanded.proofs)
        self.assertEqual(offset, self.n)

    def test_partition_every_cut_position(self):
        for cut in range(1, self.n):
            with self.subTest(cut=cut):
                head, tail = partition_delta_chain(self.delta, (cut,))
                self.assertEqual(
                    head,
                    slice_audit_extension_delta_checkpoint_chain(
                        self.delta, 0, cut
                    ),
                )
                self.assertEqual(
                    tail,
                    slice_audit_extension_delta_checkpoint_chain(
                        self.delta, cut, self.n
                    ),
                )

    def test_partitioned_segments_verify_independently(self):
        for segment in partition_delta_chain(self.delta, (1, 3)):
            self.assertTrue(
                verify_audit_extension_delta_checkpoint_chain(
                    segment, self.key
                )
            )

    def test_partition_does_not_verify_signatures(self):
        bad_sig = sign_message(make_other_key(), b"unrelated", seed=5)
        tampered = AuditExtensionDeltaCheckpointChain(
            self.delta.first,
            self.delta.additions,
            (bad_sig,) + self.delta.signatures[1:],
        )
        segments = partition_delta_chain(tampered, (2,))
        self.assertEqual(segments[0].signatures[0], bad_sig)
        self.assertFalse(
            verify_audit_extension_delta_checkpoint_chain(
                segments[0], self.key
            )
        )

    def test_partition_chain_type_errors(self):
        for bad_chain in ("not a chain", None, 42, object()):
            with self.assertRaises(TypeError, msg=repr(bad_chain)):
                partition_delta_chain(bad_chain, (1,))

    def test_partition_cuts_type_errors(self):
        for bad_cuts in ("1", [1], {1}, 1, None, object()):
            with self.assertRaises(TypeError, msg=repr(bad_cuts)):
                partition_delta_chain(self.delta, bad_cuts)

    def test_partition_cut_element_type_errors_booleans_included(self):
        for bad_cut in (True, False, 0.0, 1.5, "1", (1,), [1], None,
                        object()):
            with self.assertRaises(TypeError, msg=repr(bad_cut)):
                partition_delta_chain(self.delta, (bad_cut,))
            with self.assertRaises(TypeError, msg=repr(bad_cut)):
                partition_delta_chain(self.delta, (1, bad_cut))

    def test_partition_nested_field_type_errors(self):
        bad = AuditExtensionDeltaCheckpointChain(
            self.delta.first,
            list(self.delta.additions),
            self.delta.signatures,
        )
        with self.assertRaises(TypeError):
            partition_delta_chain(bad, (1,))

    def test_partition_cut_value_errors(self):
        # Out of range on either side: 0, negatives and len(proofs) or more.
        for cuts in [(0,), (-1,), (self.n,), (self.n + 1,), (1, self.n)]:
            with self.subTest(cuts=cuts):
                with self.assertRaises(ValueError):
                    partition_delta_chain(self.delta, cuts)
        # Repeated and non-increasing cuts.
        for cuts in [(1, 1), (2, 2, 3), (2, 1), (3, 1, 2), (1, 3, 3)]:
            with self.subTest(cuts=cuts):
                with self.assertRaises(ValueError):
                    partition_delta_chain(self.delta, cuts)

    def test_partition_nested_value_errors(self):
        # Signature count wrong.
        bad = AuditExtensionDeltaCheckpointChain(
            self.delta.first,
            self.delta.additions,
            self.delta.signatures[:-1],
        )
        with self.assertRaises(ValueError):
            partition_delta_chain(bad, (1,))
        # Empty addition batch.
        bad = AuditExtensionDeltaCheckpointChain(
            self.delta.first,
            ((),) + self.delta.additions[1:],
            self.delta.signatures,
        )
        with self.assertRaises(ValueError):
            partition_delta_chain(bad, (1,))


class JoinTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = make_records(self.key, 7)
        self.splits = [(2, 3), (3, 5), (5, 6), (6, 7)]
        self.plain = linked_chain(self.key, self.records, self.splits)
        self.delta = compact_audit_extension_delta_checkpoint_chain(self.plain)
        self.n = len(self.plain.proofs)

    def test_join_partition_restores_original_for_every_legal_cuts(self):
        all_cuts = [()]
        # Every subset of the legal cut positions, in increasing order.
        for mask in range(1 << (self.n - 1)):
            cuts = tuple(
                cut for cut in range(1, self.n) if mask & (1 << (cut - 1))
            )
            all_cuts.append(cuts)
        for cuts in all_cuts:
            with self.subTest(cuts=cuts):
                segments = partition_delta_chain(self.delta, cuts)
                joined = join_delta_chain_segments(segments)
                self.assertEqual(joined, self.delta)

    def test_join_restores_encoding_byte_for_byte(self):
        segments = partition_delta_chain(self.delta, (1, 3))
        # Each segment travels on its own as canonical bytes.
        decoded = tuple(
            decode_audit_extension_delta_checkpoint_chain(
                encode_audit_extension_delta_checkpoint_chain(segment)
            )
            for segment in segments
        )
        joined = join_delta_chain_segments(decoded)
        self.assertEqual(joined, self.delta)
        self.assertEqual(
            encode_audit_extension_delta_checkpoint_chain(joined),
            encode_audit_extension_delta_checkpoint_chain(self.delta),
        )

    def test_join_single_segment_returns_the_chain(self):
        only = slice_audit_extension_delta_checkpoint_chain(self.delta, 1, 3)
        self.assertEqual(join_delta_chain_segments((only,)), only)
        self.assertEqual(
            join_delta_chain_segments((self.delta,)), self.delta
        )

    def test_join_single_hop_segments(self):
        segments = tuple(
            slice_audit_extension_delta_checkpoint_chain(
                self.delta, index, index + 1
            )
            for index in range(self.n)
        )
        joined = join_delta_chain_segments(segments)
        self.assertEqual(joined, self.delta)
        self.assertTrue(
            verify_audit_extension_delta_checkpoint_chain(joined, self.key)
        )

    def test_join_does_not_verify_signatures(self):
        bad_sig = sign_message(make_other_key(), b"unrelated", seed=7)
        tampered = AuditExtensionDeltaCheckpointChain(
            self.delta.first,
            self.delta.additions,
            self.delta.signatures[:-1] + (bad_sig,),
        )
        segments = partition_delta_chain(tampered, (2,))
        joined = join_delta_chain_segments(segments)
        self.assertEqual(joined.signatures[-1], bad_sig)
        self.assertFalse(
            verify_audit_extension_delta_checkpoint_chain(joined, self.key)
        )

    def test_join_segments_type_errors(self):
        segment = slice_audit_extension_delta_checkpoint_chain(
            self.delta, 0, 2
        )
        for bad in ("not segments", None, 42, [segment], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                join_delta_chain_segments(bad)

    def test_join_element_type_errors(self):
        segment = slice_audit_extension_delta_checkpoint_chain(
            self.delta, 0, 2
        )
        for bad in ("not a chain", None, 42, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                join_delta_chain_segments((bad,))
            with self.assertRaises(TypeError, msg=repr(bad)):
                join_delta_chain_segments((segment, bad))

    def test_join_nested_field_type_errors(self):
        good = slice_audit_extension_delta_checkpoint_chain(
            self.delta, 0, 2
        )
        bad = AuditExtensionDeltaCheckpointChain(
            "not a proof", good.additions, good.signatures
        )
        with self.assertRaises(TypeError):
            join_delta_chain_segments((bad,))
        with self.assertRaises(TypeError):
            join_delta_chain_segments((good, bad))

    def test_join_empty_segments_value_error(self):
        with self.assertRaises(ValueError):
            join_delta_chain_segments(())

    def test_join_nested_value_errors(self):
        good = slice_audit_extension_delta_checkpoint_chain(
            self.delta, 0, 2
        )
        bad = AuditExtensionDeltaCheckpointChain(
            good.first, good.additions, good.signatures[:-1]
        )
        with self.assertRaises(ValueError):
            join_delta_chain_segments((bad,))
        with self.assertRaises(ValueError):
            join_delta_chain_segments((good, bad))

    def test_join_rejects_leaf_prefix_mismatch_at_seam(self):
        left = slice_audit_extension_delta_checkpoint_chain(
            self.delta, 0, 3
        )
        right = slice_audit_extension_delta_checkpoint_chain(
            self.delta, 3, 4
        )
        right_first = right.first
        bad_right = AuditExtensionDeltaCheckpointChain(
            AuditExtensionProof(
                right_first.old_n - 1, right_first.leaves
            ),
            right.additions,
            right.signatures,
        )
        with self.assertRaises(ValueError):
            join_delta_chain_segments((left, bad_right))

    def test_join_rejects_shared_signature_mismatch_at_seam(self):
        left = slice_audit_extension_delta_checkpoint_chain(
            self.delta, 0, 2
        )
        right = slice_audit_extension_delta_checkpoint_chain(
            self.delta, 2, 4
        )
        bad_sig = AggregateSignature(R=70001, z=70002, signer_ids=(1, 3))
        bad_right = AuditExtensionDeltaCheckpointChain(
            right.first,
            right.additions,
            (bad_sig,) + right.signatures[1:],
        )
        with self.assertRaises(ValueError):
            join_delta_chain_segments((left, bad_right))

    def test_join_rejects_out_of_order_segments(self):
        segments = partition_delta_chain(self.delta, (1, 3))
        with self.assertRaises(ValueError):
            join_delta_chain_segments((segments[1], segments[0]))
        with self.assertRaises(ValueError):
            join_delta_chain_segments(
                (segments[0], segments[2], segments[1])
            )


if __name__ == "__main__":
    unittest.main()
