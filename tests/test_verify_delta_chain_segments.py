"""Tests for the stateless whole-set verification of an ordered delta
chain segment tuple: verify_delta_chain_segments."""

import unittest

from thresholdsign import (
    AggregateSignature,
    AuditExtensionDeltaCheckpointChain,
    AuditExtensionProof,
    decode_delta_chain_segments,
    encode_delta_chain_segments,
    join_delta_chain_segments,
    partition_delta_chain,
    slice_audit_extension_delta_checkpoint_chain,
    verify_audit_extension_delta_checkpoint_chain,
    verify_delta_chain_segments,
)

from test_audit_chain import make_key
from test_audit_extension_delta_checkpoint_chain_segment import make_delta
from test_audit_extension_proof_bundle_codec import (
    make_other_key,
    make_records,
)


def build_segments():
    key = make_key()
    records = make_records(key, 7)
    splits = [(2, 3), (3, 5), (5, 6), (6, 7)]
    delta = make_delta(key, records, splits)
    return key, delta, partition_delta_chain(delta, (1, 3))


class VerifyDeltaChainSegmentsTest(unittest.TestCase):
    def setUp(self):
        self.key, self.delta, self.segments = build_segments()

    def test_partitioned_segments_verify_true(self):
        self.assertTrue(verify_delta_chain_segments(self.segments, self.key))

    def test_single_segment_whole_chain_verifies_true(self):
        self.assertTrue(verify_delta_chain_segments((self.delta,), self.key))

    def test_every_legal_cut_pattern_verifies_true(self):
        proof_count = len(self.delta.additions) + 1
        for cut in range(1, proof_count):
            with self.subTest(cut=cut):
                segments = partition_delta_chain(self.delta, (cut,))
                self.assertTrue(
                    verify_delta_chain_segments(segments, self.key)
                )

    def test_agrees_with_join_then_verify(self):
        joined = join_delta_chain_segments(self.segments)
        self.assertEqual(
            verify_delta_chain_segments(self.segments, self.key),
            verify_audit_extension_delta_checkpoint_chain(joined, self.key),
        )

    def test_codec_roundtrip_preserves_conclusion(self):
        blob = encode_delta_chain_segments(self.segments)
        restored = decode_delta_chain_segments(blob)
        self.assertEqual(restored, self.segments)
        self.assertEqual(
            verify_delta_chain_segments(restored, self.key),
            verify_delta_chain_segments(self.segments, self.key),
        )

    def test_out_of_order_segments_return_false(self):
        segments = self.segments
        self.assertFalse(
            verify_delta_chain_segments(
                (segments[1], segments[0], segments[2]), self.key
            )
        )
        self.assertFalse(
            verify_delta_chain_segments(tuple(reversed(segments)), self.key)
        )

    def test_leaf_prefix_gap_at_seam_returns_false(self):
        left = slice_audit_extension_delta_checkpoint_chain(self.delta, 0, 3)
        right = slice_audit_extension_delta_checkpoint_chain(self.delta, 3, 4)
        right_first = right.first
        gapped_right = AuditExtensionDeltaCheckpointChain(
            AuditExtensionProof(right_first.old_n - 1, right_first.leaves),
            right.additions,
            right.signatures,
        )
        self.assertFalse(
            verify_delta_chain_segments((left, gapped_right), self.key)
        )

    def test_leaf_prefix_overlap_at_seam_returns_false(self):
        left = slice_audit_extension_delta_checkpoint_chain(self.delta, 0, 2)
        right = slice_audit_extension_delta_checkpoint_chain(self.delta, 1, 3)
        right_first = right.first
        # The first hop appends two leaves, so old_n + 1 stays a legal
        # structure while overlapping the left segment's last leaf.
        overlap_right = AuditExtensionDeltaCheckpointChain(
            AuditExtensionProof(right_first.old_n + 1, right_first.leaves),
            right.additions,
            right.signatures,
        )
        self.assertFalse(
            verify_delta_chain_segments((left, overlap_right), self.key)
        )

    def test_shared_signature_mismatch_at_seam_returns_false(self):
        left = slice_audit_extension_delta_checkpoint_chain(self.delta, 0, 2)
        right = slice_audit_extension_delta_checkpoint_chain(self.delta, 2, 4)
        bad_sig = AggregateSignature(R=70001, z=70002, signer_ids=(1, 3))
        bad_right = AuditExtensionDeltaCheckpointChain(
            right.first,
            right.additions,
            (bad_sig,) + right.signatures[1:],
        )
        self.assertFalse(
            verify_delta_chain_segments((left, bad_right), self.key)
        )

    def test_tampered_leaf_digest_returns_false(self):
        segment = self.segments[1]
        tampered_batch = (b"\x00" * 32,) + segment.additions[0][1:]
        tampered = AuditExtensionDeltaCheckpointChain(
            segment.first,
            (tampered_batch,) + segment.additions[1:],
            segment.signatures,
        )
        segments = (
            self.segments[0],
            tampered,
        ) + self.segments[2:]
        self.assertFalse(verify_delta_chain_segments(segments, self.key))

    def test_tampered_signature_returns_false(self):
        segment = self.segments[0]
        bad_sig = AggregateSignature(R=90001, z=90002, signer_ids=(1, 3))
        tampered = AuditExtensionDeltaCheckpointChain(
            segment.first,
            segment.additions,
            segment.signatures[:-1] + (bad_sig,),
        )
        segments = (tampered,) + self.segments[1:]
        self.assertFalse(verify_delta_chain_segments(segments, self.key))

    def test_other_key_returns_false(self):
        self.assertFalse(
            verify_delta_chain_segments(self.segments, make_other_key())
        )

    def test_segments_type_errors(self):
        segment = self.segments[0]
        for bad in ("not segments", None, 42, [segment], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_delta_chain_segments(bad, self.key)

    def test_element_type_errors(self):
        segment = self.segments[0]
        for bad in ("not a chain", None, 42, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_delta_chain_segments((bad,), self.key)
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_delta_chain_segments((segment, bad), self.key)

    def test_key_type_errors(self):
        for bad in ("not a key", None, 42, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_delta_chain_segments(self.segments, bad)

    def test_nested_field_type_errors(self):
        good = self.segments[0]
        bad = AuditExtensionDeltaCheckpointChain(
            "not a proof", good.additions, good.signatures
        )
        with self.assertRaises(TypeError):
            verify_delta_chain_segments((bad,), self.key)
        with self.assertRaises(TypeError):
            verify_delta_chain_segments((good, bad), self.key)

    def test_empty_segments_value_error(self):
        with self.assertRaises(ValueError):
            verify_delta_chain_segments((), self.key)

    def test_nested_value_errors(self):
        good = self.segments[0]
        bad = AuditExtensionDeltaCheckpointChain(
            good.first, good.additions, good.signatures[:-1]
        )
        with self.assertRaises(ValueError):
            verify_delta_chain_segments((bad,), self.key)
        with self.assertRaises(ValueError):
            verify_delta_chain_segments((good, bad), self.key)

    def test_stateless_repeated_calls(self):
        first = verify_delta_chain_segments(self.segments, self.key)
        second = verify_delta_chain_segments(self.segments, self.key)
        self.assertTrue(first)
        self.assertEqual(first, second)
        # A failing call in between must not change later conclusions.
        verify_delta_chain_segments(tuple(reversed(self.segments)), self.key)
        self.assertTrue(verify_delta_chain_segments(self.segments, self.key))


if __name__ == "__main__":
    unittest.main()
