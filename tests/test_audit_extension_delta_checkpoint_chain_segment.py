"""Tests for segmented transport and archive reassembly of incremental
audit-extension checkpoint chains:
slice_audit_extension_delta_checkpoint_chain /
concatenate_audit_extension_delta_checkpoint_chains."""

import unittest

from thresholdsign import (
    AggregateSignature,
    AuditExtensionCheckpointChain,
    AuditExtensionDeltaCheckpointChain,
    AuditExtensionProof,
    compact_audit_extension_delta_checkpoint_chain,
    concatenate_audit_extension_delta_checkpoint_chains,
    decode_audit_extension_delta_checkpoint_chain,
    encode_audit_extension_delta_checkpoint_chain,
    expand_audit_extension_delta_checkpoint_chain,
    slice_audit_extension_delta_checkpoint_chain,
    verify_audit_extension_delta_checkpoint_chain,
)

from test_audit_chain import make_key, make_record
from test_audit_extension_checkpoint_chain_codec import linked_chain
from test_audit_extension_proof_bundle_codec import make_other_key, make_records


def make_delta(key, records, splits, *, seed=9000):
    chain = linked_chain(key, records, splits, seed=seed)
    return chain, compact_audit_extension_delta_checkpoint_chain(chain)


class SliceTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = make_records(self.key, 8)
        self.splits = [(2, 3), (3, 5), (5, 6), (6, 8)]
        self.plain, self.delta = make_delta(
            self.key, self.records, self.splits
        )

    def test_every_non_empty_interval_matches_plain_chain(self):
        count = len(self.plain.proofs)
        for start in range(count):
            for stop in range(start + 1, count + 1):
                segment = slice_audit_extension_delta_checkpoint_chain(
                    self.delta, start, stop
                )
                self.assertIsInstance(
                    segment, AuditExtensionDeltaCheckpointChain
                )
                expanded = expand_audit_extension_delta_checkpoint_chain(
                    segment
                )
                self.assertEqual(
                    expanded.proofs, self.plain.proofs[start:stop]
                )
                self.assertEqual(
                    expanded.signatures,
                    self.plain.signatures[start:stop + 1],
                )

    def test_single_hop_segments(self):
        for index in range(len(self.plain.proofs)):
            segment = slice_audit_extension_delta_checkpoint_chain(
                self.delta, index, index + 1
            )
            expanded = expand_audit_extension_delta_checkpoint_chain(segment)
            self.assertEqual(expanded.proofs, self.plain.proofs[index:index + 1])
            self.assertEqual(
                expanded.signatures,
                self.plain.signatures[index:index + 2],
            )
            # A one-hop delta chain carries no addition batches.
            self.assertEqual(segment.additions, ())
            self.assertEqual(len(segment.signatures), 2)
            self.assertTrue(
                verify_audit_extension_delta_checkpoint_chain(
                    segment, self.key
                )
            )

    def test_prefix_and_suffix_segments(self):
        count = len(self.plain.proofs)
        prefix = slice_audit_extension_delta_checkpoint_chain(
            self.delta, 0, 2
        )
        suffix = slice_audit_extension_delta_checkpoint_chain(
            self.delta, 2, count
        )
        self.assertEqual(
            expand_audit_extension_delta_checkpoint_chain(prefix),
            AuditExtensionCheckpointChain(
                self.plain.proofs[:2], self.plain.signatures[:3]
            ),
        )
        self.assertEqual(
            expand_audit_extension_delta_checkpoint_chain(suffix),
            AuditExtensionCheckpointChain(
                self.plain.proofs[2:], self.plain.signatures[2:]
            ),
        )
        self.assertTrue(
            verify_audit_extension_delta_checkpoint_chain(prefix, self.key)
        )
        self.assertTrue(
            verify_audit_extension_delta_checkpoint_chain(suffix, self.key)
        )

    def test_full_interval_is_original_chain(self):
        count = len(self.plain.proofs)
        self.assertEqual(
            slice_audit_extension_delta_checkpoint_chain(
                self.delta, 0, count
            ),
            self.delta,
        )

    def test_slice_does_not_mutate_input(self):
        before = encode_audit_extension_delta_checkpoint_chain(self.delta)
        slice_audit_extension_delta_checkpoint_chain(self.delta, 1, 3)
        self.assertEqual(
            encode_audit_extension_delta_checkpoint_chain(self.delta), before
        )

    def test_slice_does_not_verify_signatures(self):
        # A structurally legal chain with mismatched signatures still slices;
        # verification stays with verify_audit_extension_delta_checkpoint_chain.
        other = make_other_key()
        from test_audit_chain import sign_message

        bad = sign_message(other, b"unrelated", seed=11)
        tampered = AuditExtensionDeltaCheckpointChain(
            self.delta.first,
            self.delta.additions,
            (bad,) + self.delta.signatures[1:],
        )
        segment = slice_audit_extension_delta_checkpoint_chain(tampered, 0, 2)
        self.assertFalse(
            verify_audit_extension_delta_checkpoint_chain(segment, self.key)
        )

    def test_slice_type_errors(self):
        with self.assertRaises(TypeError):
            slice_audit_extension_delta_checkpoint_chain("not a chain", 0, 1)
        with self.assertRaises(TypeError):
            slice_audit_extension_delta_checkpoint_chain(None, 0, 1)
        for bad_start in (True, False, 1.0, "0", None):
            with self.assertRaises(TypeError, msg=repr(bad_start)):
                slice_audit_extension_delta_checkpoint_chain(
                    self.delta, bad_start, 2
                )
        for bad_stop in (True, False, 2.0, "2", None):
            with self.assertRaises(TypeError, msg=repr(bad_stop)):
                slice_audit_extension_delta_checkpoint_chain(
                    self.delta, 0, bad_stop
                )

    def test_slice_bad_chain_structure_errors(self):
        # Structural errors in the expanded chain propagate unchanged.
        bad = AuditExtensionDeltaCheckpointChain(
            self.delta.first,
            ((),),
            self.delta.signatures[:1]
            + self.delta.signatures[1:3],
        )
        with self.assertRaises(ValueError):
            slice_audit_extension_delta_checkpoint_chain(bad, 0, 1)

    def test_slice_value_errors(self):
        count = len(self.plain.proofs)
        empty_cases = [
            (0, 0),
            (1, 1),
            (2, 1),
            (count, count),
        ]
        for start, stop in empty_cases:
            with self.assertRaises(ValueError, msg=(start, stop)):
                slice_audit_extension_delta_checkpoint_chain(
                    self.delta, start, stop
                )
        out_of_range = [
            (-1, 1),
            (0, -1),
            (-count - 1, -1),
            (0, count + 1),
            (count, count + 1),
            (count + 1, count + 2),
        ]
        for start, stop in out_of_range:
            with self.assertRaises(ValueError, msg=(start, stop)):
                slice_audit_extension_delta_checkpoint_chain(
                    self.delta, start, stop
                )


class ConcatenateTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = make_records(self.key, 8)
        self.splits = [(2, 3), (3, 5), (5, 6), (6, 8)]
        self.plain, self.delta = make_delta(
            self.key, self.records, self.splits
        )
        self.count = len(self.plain.proofs)

    def test_concatenate_at_every_boundary(self):
        for boundary in range(1, self.count):
            left = slice_audit_extension_delta_checkpoint_chain(
                self.delta, 0, boundary
            )
            right = slice_audit_extension_delta_checkpoint_chain(
                self.delta, boundary, self.count
            )
            joined = concatenate_audit_extension_delta_checkpoint_chains(
                left, right
            )
            self.assertIsInstance(joined, AuditExtensionDeltaCheckpointChain)
            self.assertEqual(joined, self.delta)
            self.assertTrue(
                verify_audit_extension_delta_checkpoint_chain(joined, self.key)
            )

    def test_shared_signature_kept_once(self):
        left = slice_audit_extension_delta_checkpoint_chain(self.delta, 0, 2)
        right = slice_audit_extension_delta_checkpoint_chain(
            self.delta, 2, self.count
        )
        joined = concatenate_audit_extension_delta_checkpoint_chains(
            left, right
        )
        # len(additions) + 2 == left hops + right hops + 1 total signatures.
        self.assertEqual(
            len(joined.signatures),
            len(left.signatures) + len(right.signatures) - 1,
        )
        expanded = expand_audit_extension_delta_checkpoint_chain(joined)
        self.assertEqual(
            expanded.signatures,
            expand_audit_extension_delta_checkpoint_chain(left).signatures
            + expand_audit_extension_delta_checkpoint_chain(
                right
            ).signatures[1:],
        )

    def test_concatenate_three_segments_round_trip(self):
        first = slice_audit_extension_delta_checkpoint_chain(self.delta, 0, 1)
        middle = slice_audit_extension_delta_checkpoint_chain(
            self.delta, 1, 3
        )
        last = slice_audit_extension_delta_checkpoint_chain(
            self.delta, 3, self.count
        )
        joined = concatenate_audit_extension_delta_checkpoint_chains(
            concatenate_audit_extension_delta_checkpoint_chains(first, middle),
            last,
        )
        self.assertEqual(joined, self.delta)
        # Byte-for-byte canonical encoding round trip of the reassembly.
        blob = encode_audit_extension_delta_checkpoint_chain(joined)
        self.assertEqual(
            decode_audit_extension_delta_checkpoint_chain(blob), joined
        )

    def test_concatenate_single_hop_chains(self):
        left = slice_audit_extension_delta_checkpoint_chain(self.delta, 0, 1)
        right = slice_audit_extension_delta_checkpoint_chain(self.delta, 1, 2)
        joined = concatenate_audit_extension_delta_checkpoint_chains(
            left, right
        )
        self.assertEqual(
            expand_audit_extension_delta_checkpoint_chain(joined),
            AuditExtensionCheckpointChain(
                self.plain.proofs[:2], self.plain.signatures[:3]
            ),
        )

    def test_concatenate_does_not_verify_signatures(self):
        other = make_other_key()
        from test_audit_chain import sign_message

        bad = sign_message(other, b"unrelated", seed=13)
        left = slice_audit_extension_delta_checkpoint_chain(self.delta, 0, 2)
        right = slice_audit_extension_delta_checkpoint_chain(
            self.delta, 2, self.count
        )
        # Replace an internal signature identically on both sides: the chains
        # still link by value, but verification fails afterwards.
        inner_left = AuditExtensionDeltaCheckpointChain(
            left.first,
            left.additions,
            left.signatures[:-1] + (bad,),
        )
        inner_right = AuditExtensionDeltaCheckpointChain(
            right.first, right.additions, (bad,) + right.signatures[1:]
        )
        joined = concatenate_audit_extension_delta_checkpoint_chains(
            inner_left, inner_right
        )
        self.assertFalse(
            verify_audit_extension_delta_checkpoint_chain(joined, self.key)
        )

    def test_concatenate_type_errors(self):
        left = slice_audit_extension_delta_checkpoint_chain(self.delta, 0, 2)
        right = slice_audit_extension_delta_checkpoint_chain(
            self.delta, 2, self.count
        )
        with self.assertRaises(TypeError):
            concatenate_audit_extension_delta_checkpoint_chains("x", right)
        with self.assertRaises(TypeError):
            concatenate_audit_extension_delta_checkpoint_chains(left, None)
        # A malformed nested field in either operand.
        bad_field = AuditExtensionDeltaCheckpointChain(
            AuditExtensionProof("1", left.first.leaves),
            left.additions,
            left.signatures,
        )
        with self.assertRaises(TypeError):
            concatenate_audit_extension_delta_checkpoint_chains(
                bad_field, right
            )
        with self.assertRaises(TypeError):
            concatenate_audit_extension_delta_checkpoint_chains(
                left, bad_field
            )

    def test_concatenate_leaf_prefix_mismatch(self):
        left = slice_audit_extension_delta_checkpoint_chain(self.delta, 0, 2)
        # A different record sequence produces different shared leaves.
        other_records = tuple(
            make_record(self.key, b"other-%d" % i, seed=200 + i)
            for i in range(8)
        )
        _other_plain, other_delta = make_delta(
            self.key,
            other_records,
            [(2, 3), (3, 6), (6, 8)],
            seed=2000,
        )
        right = slice_audit_extension_delta_checkpoint_chain(
            other_delta, 0, 2
        )
        with self.assertRaises(ValueError):
            concatenate_audit_extension_delta_checkpoint_chains(left, right)

    def test_concatenate_gap_and_overlap(self):
        left = slice_audit_extension_delta_checkpoint_chain(self.delta, 0, 1)
        # Skips the boundary checkpoint: right starts one hop later.
        gap = slice_audit_extension_delta_checkpoint_chain(
            self.delta, 2, self.count
        )
        with self.assertRaises(ValueError):
            concatenate_audit_extension_delta_checkpoint_chains(left, gap)
        # Overlaps by one hop: right starts before left ends.
        overlap = slice_audit_extension_delta_checkpoint_chain(
            self.delta, 0, 2
        )
        with self.assertRaises(ValueError):
            concatenate_audit_extension_delta_checkpoint_chains(left, overlap)

    def test_concatenate_shared_signature_mismatch(self):
        left = slice_audit_extension_delta_checkpoint_chain(self.delta, 0, 2)
        right = slice_audit_extension_delta_checkpoint_chain(
            self.delta, 2, self.count
        )
        tampered = AuditExtensionDeltaCheckpointChain(
            right.first,
            right.additions,
            (AggregateSignature(R=9999, z=8888, signer_ids=(1, 3)),)
            + right.signatures[1:],
        )
        with self.assertRaises(ValueError):
            concatenate_audit_extension_delta_checkpoint_chains(left, tampered)


if __name__ == "__main__":
    unittest.main()
