"""Tests for segmented transport and archive reassembly of incremental
audit-extension checkpoint chains:
slice_audit_extension_delta_checkpoint_chain and
concatenate_audit_extension_delta_checkpoint_chains."""

import unittest

from thresholdsign import (
    AggregateSignature,
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


class SliceTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = make_records(self.key, 7)
        self.splits = [(2, 3), (3, 5), (5, 6), (6, 7)]
        self.plain = linked_chain(self.key, self.records, self.splits)
        self.delta = compact_audit_extension_delta_checkpoint_chain(self.plain)

    def test_slice_matches_plain_interval_for_every_range(self):
        n = len(self.plain.proofs)
        for start in range(n):
            for stop in range(start + 1, n + 1):
                with self.subTest(start=start, stop=stop):
                    segment = slice_audit_extension_delta_checkpoint_chain(
                        self.delta, start, stop
                    )
                    expected_plain_segment = type(self.plain)(
                        proofs=self.plain.proofs[start:stop],
                        signatures=self.plain.signatures[start:stop + 1],
                    )
                    # The segment expands value by value into the plain
                    # chain's corresponding interval.
                    self.assertEqual(
                        expand_audit_extension_delta_checkpoint_chain(segment),
                        expected_plain_segment,
                    )
                    # And the delta fields are the compaction of exactly
                    # that interval.
                    expected_delta = (
                        compact_audit_extension_delta_checkpoint_chain(
                            expected_plain_segment
                        )
                    )
                    self.assertEqual(segment, expected_delta)
                    self.assertEqual(segment.first, self.plain.proofs[start])
                    self.assertEqual(
                        segment.signatures,
                        self.plain.signatures[start:stop + 1],
                    )

    def test_slice_single_hop_has_no_additions(self):
        for index in range(len(self.plain.proofs)):
            segment = slice_audit_extension_delta_checkpoint_chain(
                self.delta, index, index + 1
            )
            self.assertEqual(segment.additions, ())
            self.assertEqual(segment.first, self.plain.proofs[index])
            self.assertEqual(
                segment.signatures,
                self.plain.signatures[index:index + 2],
            )
            self.assertEqual(
                expand_audit_extension_delta_checkpoint_chain(segment),
                type(self.plain)(
                    proofs=(self.plain.proofs[index],),
                    signatures=self.plain.signatures[index:index + 2],
                ),
            )

    def test_slice_head_and_tail_segments(self):
        n = len(self.plain.proofs)
        head = slice_audit_extension_delta_checkpoint_chain(self.delta, 0, 2)
        tail = slice_audit_extension_delta_checkpoint_chain(
            self.delta, 2, n
        )
        self.assertEqual(
            expand_audit_extension_delta_checkpoint_chain(head),
            type(self.plain)(
                proofs=self.plain.proofs[:2],
                signatures=self.plain.signatures[:3],
            ),
        )
        self.assertEqual(
            expand_audit_extension_delta_checkpoint_chain(tail),
            type(self.plain)(
                proofs=self.plain.proofs[2:],
                signatures=self.plain.signatures[2:],
            ),
        )

    def test_slice_full_interval_is_the_original_chain(self):
        n = len(self.plain.proofs)
        self.assertEqual(
            slice_audit_extension_delta_checkpoint_chain(self.delta, 0, n),
            self.delta,
        )

    def test_sliced_segments_verify_independently(self):
        for start, stop in [(0, 1), (1, 3), (0, 2), (2, 4), (0, 4)]:
            segment = slice_audit_extension_delta_checkpoint_chain(
                self.delta, start, stop
            )
            self.assertTrue(
                verify_audit_extension_delta_checkpoint_chain(
                    segment, self.key
                ),
                msg=(start, stop),
            )

    def test_slice_does_not_verify_signatures(self):
        # A structurally legal chain whose signatures do not match the
        # roots still slices; verification stays with the delta verifier.
        other_key = make_other_key()
        bad_sig = sign_message(other_key, b"unrelated", seed=5)
        tampered = AuditExtensionDeltaCheckpointChain(
            self.delta.first,
            self.delta.additions,
            (bad_sig,) + self.delta.signatures[1:],
        )
        # The slice entry point itself must not complain.
        segment = slice_audit_extension_delta_checkpoint_chain(tampered, 0, 2)
        self.assertEqual(segment.signatures[0], bad_sig)
        self.assertFalse(
            verify_audit_extension_delta_checkpoint_chain(segment, self.key)
        )
        self.assertFalse(
            verify_audit_extension_delta_checkpoint_chain(segment, other_key)
        )

    def test_slice_chain_type_errors(self):
        for bad_chain in ("not a chain", None, 42, object()):
            with self.assertRaises(TypeError, msg=repr(bad_chain)):
                slice_audit_extension_delta_checkpoint_chain(
                    bad_chain, 0, 1
                )

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
                slice_audit_extension_delta_checkpoint_chain(
                    self.delta, bad_bound, 2
                )
            with self.assertRaises(TypeError, msg=repr(bad_bound)):
                slice_audit_extension_delta_checkpoint_chain(
                    self.delta, 0, bad_bound
                )

    def test_slice_nested_field_type_errors(self):
        bad = AuditExtensionDeltaCheckpointChain(
            self.delta.first,
            list(self.delta.additions),
            self.delta.signatures,
        )
        with self.assertRaises(TypeError):
            slice_audit_extension_delta_checkpoint_chain(bad, 0, 1)

    def test_slice_value_errors(self):
        n = len(self.plain.proofs)
        # Empty intervals: touching and reversed.
        for start, stop in [(0, 0), (1, 1), (n, n), (3, 2), (2, 0)]:
            with self.subTest(start=start, stop=stop):
                with self.assertRaises(ValueError):
                    slice_audit_extension_delta_checkpoint_chain(
                        self.delta, start, stop
                    )
        # Out of range on either side.
        for start, stop in [(-1, 1), (0, -1), (-1, -1), (0, n + 1),
                            (1, n + 1), (n + 1, n + 2), (n, n + 1)]:
            with self.subTest(start=start, stop=stop):
                with self.assertRaises(ValueError):
                    slice_audit_extension_delta_checkpoint_chain(
                        self.delta, start, stop
                    )

    def test_slice_nested_value_errors(self):
        # Signature count wrong.
        bad = AuditExtensionDeltaCheckpointChain(
            self.delta.first,
            self.delta.additions,
            self.delta.signatures[:-1],
        )
        with self.assertRaises(ValueError):
            slice_audit_extension_delta_checkpoint_chain(bad, 0, 1)
        # Empty addition batch.
        bad = AuditExtensionDeltaCheckpointChain(
            self.delta.first,
            ((),) + self.delta.additions[1:],
            self.delta.signatures,
        )
        with self.assertRaises(ValueError):
            slice_audit_extension_delta_checkpoint_chain(bad, 0, 1)


class ConcatenateTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = make_records(self.key, 7)
        self.splits = [(2, 3), (3, 5), (5, 6), (6, 7)]
        self.plain = linked_chain(self.key, self.records, self.splits)
        self.delta = compact_audit_extension_delta_checkpoint_chain(self.plain)

    def _slice(self, start, stop):
        return slice_audit_extension_delta_checkpoint_chain(
            self.delta, start, stop
        )

    def test_concatenate_two_segments_reassembles_the_chain(self):
        head = self._slice(0, 2)
        tail = self._slice(2, 4)
        joined = concatenate_audit_extension_delta_checkpoint_chains(
            head, tail
        )
        self.assertEqual(joined, self.delta)
        # Expanded form is the two expanded chains in order, with the
        # shared checkpoint signature kept once.
        head_plain = expand_audit_extension_delta_checkpoint_chain(head)
        tail_plain = expand_audit_extension_delta_checkpoint_chain(tail)
        joined_plain = expand_audit_extension_delta_checkpoint_chain(joined)
        self.assertEqual(
            joined_plain.proofs, head_plain.proofs + tail_plain.proofs
        )
        self.assertEqual(
            joined_plain.signatures,
            head_plain.signatures + tail_plain.signatures[1:],
        )
        self.assertEqual(joined_plain, self.plain)

    def test_concatenate_four_single_hop_segments(self):
        pieces = [self._slice(i, i + 1) for i in range(4)]
        joined = pieces[0]
        for piece in pieces[1:]:
            joined = concatenate_audit_extension_delta_checkpoint_chains(
                joined, piece
            )
        self.assertEqual(joined, self.delta)
        self.assertTrue(
            verify_audit_extension_delta_checkpoint_chain(joined, self.key)
        )

    def test_concatenate_splits_at_every_seam(self):
        for cut in range(1, 4):
            left = self._slice(0, cut)
            right = self._slice(cut, 4)
            joined = concatenate_audit_extension_delta_checkpoint_chains(
                left, right
            )
            self.assertEqual(joined, self.delta, msg=cut)

    def test_concatenate_result_encodes_byte_for_byte(self):
        joined = concatenate_audit_extension_delta_checkpoint_chains(
            self._slice(0, 2), self._slice(2, 4)
        )
        blob = encode_audit_extension_delta_checkpoint_chain(joined)
        self.assertEqual(
            blob,
            encode_audit_extension_delta_checkpoint_chain(self.delta),
        )
        self.assertEqual(
            decode_audit_extension_delta_checkpoint_chain(blob), joined
        )

    def test_segmented_transport_and_archive_reassembly(self):
        pieces = [self._slice(0, 1), self._slice(1, 3), self._slice(3, 4)]
        # Each piece travels on its own as canonical bytes.
        blobs = [
            encode_audit_extension_delta_checkpoint_chain(piece)
            for piece in pieces
        ]
        decoded = [
            decode_audit_extension_delta_checkpoint_chain(blob)
            for blob in blobs
        ]
        joined = decoded[0]
        for piece in decoded[1:]:
            joined = concatenate_audit_extension_delta_checkpoint_chains(
                joined, piece
            )
        self.assertEqual(joined, self.delta)
        self.assertEqual(
            encode_audit_extension_delta_checkpoint_chain(joined),
            encode_audit_extension_delta_checkpoint_chain(self.delta),
        )

    def test_concatenate_does_not_verify_signatures(self):
        bad_sig = sign_message(make_other_key(), b"unrelated", seed=7)
        tampered = AuditExtensionDeltaCheckpointChain(
            self.delta.first,
            self.delta.additions,
            self.delta.signatures[:-1] + (bad_sig,),
        )
        head = self._slice(0, 2)
        bad_tail = slice_audit_extension_delta_checkpoint_chain(tampered, 2, 4)
        # The seam signature is still shared by value; only the final
        # checkpoint signature is wrong, which concatenation ignores.
        joined = concatenate_audit_extension_delta_checkpoint_chains(
            head, bad_tail
        )
        self.assertEqual(joined.signatures[-1], bad_sig)
        self.assertFalse(
            verify_audit_extension_delta_checkpoint_chain(joined, self.key)
        )

    def test_concatenate_type_errors(self):
        head = self._slice(0, 2)
        tail = self._slice(2, 4)
        for bad in ("not a chain", None, 42, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                concatenate_audit_extension_delta_checkpoint_chains(bad, tail)
            with self.assertRaises(TypeError, msg=repr(bad)):
                concatenate_audit_extension_delta_checkpoint_chains(head, bad)

    def test_concatenate_nested_field_type_errors(self):
        head = self._slice(0, 2)
        bad_tail = AuditExtensionDeltaCheckpointChain(
            "not a proof",
            self._slice(2, 4).additions,
            self._slice(2, 4).signatures,
        )
        with self.assertRaises(TypeError):
            concatenate_audit_extension_delta_checkpoint_chains(head, bad_tail)

    def test_concatenate_rejects_leaf_prefix_gap(self):
        # The right chain's first proof claims an old_n one short of the
        # left chain's last leaf count.
        left = self._slice(0, 3)
        right = self._slice(3, 4)
        right_first = right.first
        bad_right = AuditExtensionDeltaCheckpointChain(
            AuditExtensionProof(
                right_first.old_n - 1, right_first.leaves
            ),
            right.additions,
            right.signatures,
        )
        with self.assertRaises(ValueError):
            concatenate_audit_extension_delta_checkpoint_chains(
                left, bad_right
            )

    def test_concatenate_rejects_leaf_prefix_overlap_tamper(self):
        # Same old_n as the seam, but the shared prefix leaves differ.
        left = self._slice(0, 3)
        right = self._slice(3, 4)
        right_first = right.first
        bad_right = AuditExtensionDeltaCheckpointChain(
            AuditExtensionProof(
                right_first.old_n,
                (b"z" * 32,) + right_first.leaves[1:],
            ),
            right.additions,
            right.signatures,
        )
        with self.assertRaises(ValueError):
            concatenate_audit_extension_delta_checkpoint_chains(
                left, bad_right
            )

    def test_concatenate_rejects_shared_signature_mismatch(self):
        left = self._slice(0, 2)
        right = self._slice(2, 4)
        bad_sig = AggregateSignature(R=70001, z=70002, signer_ids=(1, 3))
        bad_right = AuditExtensionDeltaCheckpointChain(
            right.first,
            right.additions,
            (bad_sig,) + right.signatures[1:],
        )
        with self.assertRaises(ValueError):
            concatenate_audit_extension_delta_checkpoint_chains(
                left, bad_right
            )

    def test_concatenate_nested_value_errors(self):
        left = self._slice(0, 2)
        right = self._slice(2, 4)
        bad_right = AuditExtensionDeltaCheckpointChain(
            right.first, right.additions, right.signatures[:-1]
        )
        with self.assertRaises(ValueError):
            concatenate_audit_extension_delta_checkpoint_chains(
                left, bad_right
            )

    def test_concatenate_rejects_unrelated_chains(self):
        # Two individually legal chains that share no checkpoint: the
        # second covers a disjoint range of a larger record set.
        left = self._slice(0, 1)
        other_records = make_records(self.key, 9)
        other_plain = linked_chain(
            self.key, other_records, [(1, 4), (4, 8)]
        )
        other_delta = compact_audit_extension_delta_checkpoint_chain(
            other_plain
        )
        right = slice_audit_extension_delta_checkpoint_chain(
            other_delta, 0, 1
        )
        with self.assertRaises(ValueError):
            concatenate_audit_extension_delta_checkpoint_chains(left, right)


if __name__ == "__main__":
    unittest.main()
