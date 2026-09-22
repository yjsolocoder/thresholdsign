"""Tests for the stateless whole-set verifier of incremental
audit-extension checkpoint chain segment sets: verify_delta_chain_segments."""

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

from test_audit_chain import make_key, sign_message
from test_audit_extension_checkpoint_chain_codec import linked_chain
from test_audit_extension_proof_bundle_codec import (
    make_other_key,
    make_records,
)
from test_audit_extension_delta_checkpoint_chain_segment import make_delta


def build_segments(cuts=(1, 3)):
    key = make_key()
    records = make_records(key, 7)
    splits = [(2, 3), (3, 5), (5, 6), (6, 7)]
    delta = make_delta(key, records, splits)
    return key, records, splits, delta, partition_delta_chain(delta, cuts)


class VerifyValidSetTest(unittest.TestCase):
    def setUp(self):
        (
            self.key,
            self.records,
            self.splits,
            self.delta,
            self.segments,
        ) = build_segments()

    def test_partitioned_segments_verify_true(self):
        self.assertTrue(
            verify_delta_chain_segments(self.segments, self.key)
        )

    def test_every_cut_position_verifies_true(self):
        n = len(self.delta.additions) + 1
        for mask in range(1 << (n - 1)):
            cuts = tuple(
                cut for cut in range(1, n) if mask & (1 << (cut - 1))
            )
            with self.subTest(cuts=cuts):
                segments = partition_delta_chain(self.delta, cuts)
                self.assertTrue(
                    verify_delta_chain_segments(segments, self.key)
                )

    def test_single_segment_whole_chain_verifies_true(self):
        self.assertTrue(
            verify_delta_chain_segments((self.delta,), self.key)
        )

    def test_single_hop_segments_verify_true(self):
        n = len(self.delta.additions) + 1
        segments = tuple(
            slice_audit_extension_delta_checkpoint_chain(
                self.delta, index, index + 1
            )
            for index in range(n)
        )
        self.assertTrue(verify_delta_chain_segments(segments, self.key))

    def test_result_is_a_plain_bool(self):
        self.assertIs(
            verify_delta_chain_segments(self.segments, self.key), True
        )
        self.assertIs(
            verify_delta_chain_segments(
                tuple(reversed(self.segments)), self.key
            ),
            False,
        )

    def test_codec_roundtrip_does_not_change_verdict(self):
        for segments, expected in (
            (self.segments, True),
            (tuple(reversed(self.segments)), False),
            ((self.segments[0], self.segments[0]), False),
        ):
            with self.subTest(expected=expected):
                restored = decode_delta_chain_segments(
                    encode_delta_chain_segments(segments)
                )
                self.assertIs(
                    verify_delta_chain_segments(restored, self.key),
                    expected,
                )
                self.assertIs(
                    verify_delta_chain_segments(segments, self.key),
                    expected,
                )

    def test_verification_is_stateless_and_repeatable(self):
        first = verify_delta_chain_segments(self.segments, self.key)
        second = verify_delta_chain_segments(self.segments, self.key)
        self.assertIs(first, second)
        # The segments themselves are untouched by verification.
        self.assertEqual(
            join_delta_chain_segments(self.segments), self.delta
        )


class VerifyFalseCasesTest(unittest.TestCase):
    def setUp(self):
        (
            self.key,
            self.records,
            self.splits,
            self.delta,
            self.segments,
        ) = build_segments()

    def test_out_of_order_segments_return_false(self):
        self.assertFalse(
            verify_delta_chain_segments(
                (self.segments[1], self.segments[0]), self.key
            )
        )
        self.assertFalse(
            verify_delta_chain_segments(
                (
                    self.segments[0],
                    self.segments[2],
                    self.segments[1],
                ),
                self.key,
            )
        )

    def test_duplicated_segment_returns_false(self):
        self.assertFalse(
            verify_delta_chain_segments(
                (self.segments[0], self.segments[0]), self.key
            )
        )

    def test_leaf_prefix_gap_at_seam_returns_false(self):
        left = slice_audit_extension_delta_checkpoint_chain(self.delta, 0, 3)
        right = slice_audit_extension_delta_checkpoint_chain(self.delta, 3, 4)
        right_first = right.first
        # The right segment starts one leaf later than the left one ends:
        # a gap between the hops.
        gapped_right = AuditExtensionDeltaCheckpointChain(
            AuditExtensionProof(
                right_first.old_n + 1,
                right_first.leaves[: right_first.old_n]
                + (b"\x07" * 32,)
                + right_first.leaves[right_first.old_n:],
            ),
            right.additions,
            right.signatures,
        )
        self.assertFalse(
            verify_delta_chain_segments((left, gapped_right), self.key)
        )

    def test_leaf_prefix_overlap_at_seam_returns_false(self):
        left = slice_audit_extension_delta_checkpoint_chain(self.delta, 0, 3)
        right = slice_audit_extension_delta_checkpoint_chain(self.delta, 3, 4)
        right_first = right.first
        # The right segment claims to start one leaf earlier: an overlap.
        overlapping_right = AuditExtensionDeltaCheckpointChain(
            AuditExtensionProof(
                right_first.old_n - 1, right_first.leaves
            ),
            right.additions,
            right.signatures,
        )
        self.assertFalse(
            verify_delta_chain_segments((left, overlapping_right), self.key)
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
        batch = segment.additions[0]
        tampered_batch = (b"\x00" * 32,) + batch[1:]
        tampered = AuditExtensionDeltaCheckpointChain(
            segment.first,
            (tampered_batch,) + segment.additions[1:],
            segment.signatures,
        )
        segments = (
            self.segments[0],
            tampered,
        ) + self.segments[2:]
        self.assertFalse(
            verify_delta_chain_segments(segments, self.key)
        )

    def test_tampered_first_proof_leaf_returns_false(self):
        segment = self.segments[0]
        first = segment.first
        tampered_first = AuditExtensionProof(
            first.old_n,
            (b"\x01" * 32,) + first.leaves[1:],
        )
        segments = (
            AuditExtensionDeltaCheckpointChain(
                tampered_first, segment.additions, segment.signatures
            ),
        ) + self.segments[1:]
        self.assertFalse(
            verify_delta_chain_segments(segments, self.key)
        )

    def test_tampered_checkpoint_signature_returns_false(self):
        bad_sig = sign_message(make_other_key(), b"unrelated", seed=5)
        segment = self.segments[0]
        tampered = AuditExtensionDeltaCheckpointChain(
            segment.first,
            segment.additions,
            (bad_sig,) + segment.signatures[1:],
        )
        segments = (tampered,) + self.segments[1:]
        self.assertFalse(
            verify_delta_chain_segments(segments, self.key)
        )

    def test_other_key_returns_false(self):
        self.assertFalse(
            verify_delta_chain_segments(self.segments, make_other_key())
        )

    def test_single_tampered_chain_returns_false(self):
        bad_sig = sign_message(make_other_key(), b"unrelated", seed=7)
        tampered = AuditExtensionDeltaCheckpointChain(
            self.delta.first,
            self.delta.additions,
            self.delta.signatures[:-1] + (bad_sig,),
        )
        self.assertFalse(
            verify_delta_chain_segments((tampered,), self.key)
        )
        self.assertFalse(
            verify_audit_extension_delta_checkpoint_chain(
                tampered, self.key
            )
        )


class VerifyTypeErrorTest(unittest.TestCase):
    def setUp(self):
        (
            self.key,
            self.records,
            self.splits,
            self.delta,
            self.segments,
        ) = build_segments()

    def test_non_tuple_segments_type_error(self):
        for bad in (
            list(self.segments),
            iter(self.segments),
            [self.segments[0]],
            self.segments[0],
            "not segments",
            None,
            42,
            object(),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_delta_chain_segments(bad, self.key)

    def test_non_segment_element_type_error(self):
        for bad in ("not a chain", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_delta_chain_segments((bad,), self.key)
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_delta_chain_segments(
                    (self.segments[0], bad, self.segments[1]), self.key
                )

    def test_non_key_type_error(self):
        for bad in ("not a key", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_delta_chain_segments(self.segments, bad)

    def test_nested_field_type_error(self):
        good = self.segments[0]
        bad = AuditExtensionDeltaCheckpointChain(
            "not a proof", good.additions, good.signatures
        )
        with self.assertRaises(TypeError):
            verify_delta_chain_segments((bad,), self.key)
        with self.assertRaises(TypeError):
            verify_delta_chain_segments((good, bad), self.key)
        bad = AuditExtensionDeltaCheckpointChain(
            good.first, list(good.additions), good.signatures
        )
        with self.assertRaises(TypeError):
            verify_delta_chain_segments((bad,), self.key)
        bad = AuditExtensionDeltaCheckpointChain(
            good.first,
            good.additions,
            ("not a signature",) + good.signatures[1:],
        )
        with self.assertRaises(TypeError):
            verify_delta_chain_segments((bad,), self.key)


class VerifyValueErrorTest(unittest.TestCase):
    def setUp(self):
        (
            self.key,
            self.records,
            self.splits,
            self.delta,
            self.segments,
        ) = build_segments()

    def test_empty_segments_value_error(self):
        with self.assertRaises(ValueError):
            verify_delta_chain_segments((), self.key)

    def test_nested_signature_count_value_error(self):
        good = self.segments[0]
        bad = AuditExtensionDeltaCheckpointChain(
            good.first, good.additions, good.signatures[:-1]
        )
        with self.assertRaises(ValueError):
            verify_delta_chain_segments((bad,), self.key)
        with self.assertRaises(ValueError):
            verify_delta_chain_segments((good, bad), self.key)

    def test_nested_empty_batch_value_error(self):
        good = self.segments[1]
        bad = AuditExtensionDeltaCheckpointChain(
            good.first, ((),) + good.additions[1:], good.signatures
        )
        with self.assertRaises(ValueError):
            verify_delta_chain_segments((bad,), self.key)

    def test_nested_digest_width_value_error(self):
        good = self.segments[1]
        batch = good.additions[0]
        bad = AuditExtensionDeltaCheckpointChain(
            good.first,
            ((b"\x00" * 31,) + batch[1:],) + good.additions[1:],
            good.signatures,
        )
        with self.assertRaises(ValueError):
            verify_delta_chain_segments((bad,), self.key)

    def test_nested_illegal_proof_value_error(self):
        good = self.segments[0]
        first = good.first
        bad = AuditExtensionDeltaCheckpointChain(
            AuditExtensionProof(0, first.leaves),
            good.additions,
            good.signatures,
        )
        with self.assertRaises(ValueError):
            verify_delta_chain_segments((bad,), self.key)


if __name__ == "__main__":
    unittest.main()
