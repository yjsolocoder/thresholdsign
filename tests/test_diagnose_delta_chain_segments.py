"""Tests for the stateless failure diagnoser of incremental
audit-extension checkpoint chain segment sets:
diagnose_delta_chain_segments and its DeltaDiagnosis result."""

import dataclasses
import unittest

from thresholdsign import (
    AggregateSignature,
    AuditExtensionDeltaCheckpointChain,
    AuditExtensionProof,
    DeltaDiagnosis,
    diagnose_delta_chain_segments,
    partition_delta_chain,
    slice_audit_extension_delta_checkpoint_chain,
    verify_delta_chain_segments,
)

from test_audit_chain import make_key, sign_message
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


class DiagnosisResultShapeTest(unittest.TestCase):
    def test_success_is_the_fixed_ok_value(self):
        key, _records, _splits, _delta, segments = build_segments()
        diagnosis = diagnose_delta_chain_segments(segments, key)
        self.assertEqual(diagnosis, DeltaDiagnosis(True, "ok", None, None))
        self.assertEqual(
            diagnosis,
            DeltaDiagnosis(ok=True, kind="ok", segment=None, proof=None),
        )

    def test_result_is_frozen_positional_and_value_equal(self):
        diagnosis = DeltaDiagnosis(False, "leaf", 1, None)
        self.assertEqual(diagnosis, DeltaDiagnosis(False, "leaf", 1, None))
        self.assertEqual(
            diagnosis,
            DeltaDiagnosis(ok=False, kind="leaf", segment=1, proof=None),
        )
        self.assertNotEqual(
            diagnosis, DeltaDiagnosis(False, "sig", 1, None)
        )
        self.assertEqual(
            (diagnosis.ok, diagnosis.kind, diagnosis.segment, diagnosis.proof),
            (False, "leaf", 1, None),
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            diagnosis.kind = "sig"

    def test_fields_in_order(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(DeltaDiagnosis)],
            ["ok", "kind", "segment", "proof"],
        )


class DiagnoseValidSetTest(unittest.TestCase):
    def setUp(self):
        (
            self.key,
            self.records,
            self.splits,
            self.delta,
            self.segments,
        ) = build_segments()

    def test_partitioned_segments_diagnose_ok(self):
        self.assertEqual(
            diagnose_delta_chain_segments(self.segments, self.key),
            DeltaDiagnosis(True, "ok", None, None),
        )

    def test_every_cut_position_diagnoses_ok(self):
        n = len(self.delta.additions) + 1
        for mask in range(1 << (n - 1)):
            cuts = tuple(
                cut for cut in range(1, n) if mask & (1 << (cut - 1))
            )
            with self.subTest(cuts=cuts):
                segments = partition_delta_chain(self.delta, cuts)
                self.assertEqual(
                    diagnose_delta_chain_segments(segments, self.key),
                    DeltaDiagnosis(True, "ok", None, None),
                )

    def test_single_segment_whole_chain_diagnoses_ok(self):
        self.assertEqual(
            diagnose_delta_chain_segments((self.delta,), self.key),
            DeltaDiagnosis(True, "ok", None, None),
        )

    def test_single_hop_segments_diagnose_ok(self):
        n = len(self.delta.additions) + 1
        segments = tuple(
            slice_audit_extension_delta_checkpoint_chain(
                self.delta, index, index + 1
            )
            for index in range(n)
        )
        self.assertEqual(
            diagnose_delta_chain_segments(segments, self.key),
            DeltaDiagnosis(True, "ok", None, None),
        )

    def test_diagnosis_is_stateless_and_repeatable(self):
        first = diagnose_delta_chain_segments(self.segments, self.key)
        second = diagnose_delta_chain_segments(self.segments, self.key)
        self.assertEqual(first, second)


class DiagnoseOkMatchesVerifierTest(unittest.TestCase):
    def setUp(self):
        (
            self.key,
            self.records,
            self.splits,
            self.delta,
            self.segments,
        ) = build_segments()

    def test_ok_matches_verify_delta_chain_segments(self):
        segment = self.segments[1]
        batch = segment.additions[0]
        tampered = AuditExtensionDeltaCheckpointChain(
            segment.first,
            ((b"\x00" * 32,) + batch[1:],) + segment.additions[1:],
            segment.signatures,
        )
        cases = (
            self.segments,
            (self.delta,),
            tuple(reversed(self.segments)),
            (self.segments[0], self.segments[0]),
            (self.segments[0], tampered) + self.segments[2:],
        )
        for segments in cases:
            with self.subTest(segments=len(segments)):
                diagnosis = diagnose_delta_chain_segments(segments, self.key)
                self.assertIs(
                    diagnosis.ok,
                    verify_delta_chain_segments(segments, self.key),
                )
                self.assertIs(
                    diagnosis.ok, diagnosis.kind == "ok"
                )

    def test_other_key_ok_matches_and_locates_first_hop(self):
        diagnosis = diagnose_delta_chain_segments(
            self.segments, make_other_key()
        )
        self.assertIs(
            diagnosis.ok,
            verify_delta_chain_segments(self.segments, make_other_key()),
        )
        self.assertEqual(diagnosis, DeltaDiagnosis(False, "proof", 0, 0))


class DiagnoseFailureLocationTest(unittest.TestCase):
    def setUp(self):
        (
            self.key,
            self.records,
            self.splits,
            self.delta,
            self.segments,
        ) = build_segments()

    def test_out_of_order_segments_locate_seam_leaf(self):
        self.assertEqual(
            diagnose_delta_chain_segments(
                (self.segments[1], self.segments[0]), self.key
            ),
            DeltaDiagnosis(False, "leaf", 0, None),
        )
        self.assertEqual(
            diagnose_delta_chain_segments(
                (
                    self.segments[0],
                    self.segments[2],
                    self.segments[1],
                ),
                self.key,
            ),
            DeltaDiagnosis(False, "leaf", 0, None),
        )

    def test_duplicated_segment_locates_seam_leaf(self):
        self.assertEqual(
            diagnose_delta_chain_segments(
                (self.segments[0], self.segments[0]), self.key
            ),
            DeltaDiagnosis(False, "leaf", 0, None),
        )

    def test_leaf_prefix_gap_at_seam_locates_leaf(self):
        left = slice_audit_extension_delta_checkpoint_chain(self.delta, 0, 3)
        right = slice_audit_extension_delta_checkpoint_chain(self.delta, 3, 4)
        right_first = right.first
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
        self.assertEqual(
            diagnose_delta_chain_segments((left, gapped_right), self.key),
            DeltaDiagnosis(False, "leaf", 0, None),
        )

    def test_leaf_prefix_overlap_at_seam_locates_leaf(self):
        left = slice_audit_extension_delta_checkpoint_chain(self.delta, 0, 3)
        right = slice_audit_extension_delta_checkpoint_chain(self.delta, 3, 4)
        right_first = right.first
        overlapping_right = AuditExtensionDeltaCheckpointChain(
            AuditExtensionProof(
                right_first.old_n - 1, right_first.leaves
            ),
            right.additions,
            right.signatures,
        )
        self.assertEqual(
            diagnose_delta_chain_segments((left, overlapping_right), self.key),
            DeltaDiagnosis(False, "leaf", 0, None),
        )

    def test_shared_signature_mismatch_at_seam_locates_sig(self):
        left = slice_audit_extension_delta_checkpoint_chain(self.delta, 0, 2)
        right = slice_audit_extension_delta_checkpoint_chain(self.delta, 2, 4)
        bad_sig = AggregateSignature(R=70001, z=70002, signer_ids=(1, 3))
        bad_right = AuditExtensionDeltaCheckpointChain(
            right.first,
            right.additions,
            (bad_sig,) + right.signatures[1:],
        )
        self.assertEqual(
            diagnose_delta_chain_segments((left, bad_right), self.key),
            DeltaDiagnosis(False, "sig", 0, None),
        )

    def test_seam_leaf_is_checked_before_seam_signature(self):
        left = slice_audit_extension_delta_checkpoint_chain(self.delta, 0, 2)
        right = slice_audit_extension_delta_checkpoint_chain(self.delta, 2, 4)
        right_first = right.first
        bad_sig = AggregateSignature(R=70001, z=70002, signer_ids=(1, 3))
        # Both seam conditions broken: the leaf prefix wins.
        bad_right = AuditExtensionDeltaCheckpointChain(
            AuditExtensionProof(
                right_first.old_n + 1,
                right_first.leaves[: right_first.old_n]
                + (b"\x07" * 32,)
                + right_first.leaves[right_first.old_n:],
            ),
            right.additions,
            (bad_sig,) + right.signatures[1:],
        )
        self.assertEqual(
            diagnose_delta_chain_segments((left, bad_right), self.key),
            DeltaDiagnosis(False, "leaf", 0, None),
        )

    def test_tampered_leaf_digest_locates_proof_hop(self):
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
        self.assertEqual(
            diagnose_delta_chain_segments(segments, self.key),
            DeltaDiagnosis(False, "proof", 1, 1),
        )

    def test_tampered_first_proof_leaf_locates_first_hop(self):
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
        # The hop check of the segment precedes the seam check.
        self.assertEqual(
            diagnose_delta_chain_segments(segments, self.key),
            DeltaDiagnosis(False, "proof", 0, 0),
        )

    def test_tampered_checkpoint_signature_locates_proof_hop(self):
        bad_sig = sign_message(make_other_key(), b"unrelated", seed=5)
        segment = self.segments[0]
        tampered = AuditExtensionDeltaCheckpointChain(
            segment.first,
            segment.additions,
            (bad_sig,) + segment.signatures[1:],
        )
        segments = (tampered,) + self.segments[1:]
        self.assertEqual(
            diagnose_delta_chain_segments(segments, self.key),
            DeltaDiagnosis(False, "proof", 0, 0),
        )

    def test_first_failure_in_input_order_wins(self):
        bad_sig = sign_message(make_other_key(), b"unrelated", seed=7)
        first_tampered = AuditExtensionDeltaCheckpointChain(
            self.segments[0].first,
            self.segments[0].additions,
            self.segments[0].signatures[:-1] + (bad_sig,),
        )
        last = self.segments[2]
        last_batch = last.additions[0] if last.additions else None
        if last_batch is not None:
            last_tampered = AuditExtensionDeltaCheckpointChain(
                last.first,
                ((b"\x00" * 32,) + last_batch[1:],) + last.additions[1:],
                last.signatures,
            )
        else:
            last_tampered = last
        segments = (first_tampered, self.segments[1], last_tampered)
        diagnosis = diagnose_delta_chain_segments(segments, self.key)
        self.assertEqual(diagnosis.kind, "proof")
        self.assertEqual(diagnosis.segment, 0)

    def test_single_tampered_chain_locates_proof_hop(self):
        bad_sig = sign_message(make_other_key(), b"unrelated", seed=7)
        tampered = AuditExtensionDeltaCheckpointChain(
            self.delta.first,
            self.delta.additions,
            self.delta.signatures[:-1] + (bad_sig,),
        )
        # The last hop of the only segment carries the bad signature.
        self.assertEqual(
            diagnose_delta_chain_segments((tampered,), self.key),
            DeltaDiagnosis(False, "proof", 0, len(self.delta.additions)),
        )


class DiagnoseTypeErrorTest(unittest.TestCase):
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
                diagnose_delta_chain_segments(bad, self.key)

    def test_non_segment_element_type_error(self):
        for bad in ("not a chain", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                diagnose_delta_chain_segments((bad,), self.key)
            with self.assertRaises(TypeError, msg=repr(bad)):
                diagnose_delta_chain_segments(
                    (self.segments[0], bad, self.segments[1]), self.key
                )

    def test_non_key_type_error(self):
        for bad in ("not a key", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                diagnose_delta_chain_segments(self.segments, bad)

    def test_nested_field_type_error(self):
        good = self.segments[0]
        bad = AuditExtensionDeltaCheckpointChain(
            "not a proof", good.additions, good.signatures
        )
        with self.assertRaises(TypeError):
            diagnose_delta_chain_segments((bad,), self.key)
        with self.assertRaises(TypeError):
            diagnose_delta_chain_segments((good, bad), self.key)
        bad = AuditExtensionDeltaCheckpointChain(
            good.first, list(good.additions), good.signatures
        )
        with self.assertRaises(TypeError):
            diagnose_delta_chain_segments((bad,), self.key)
        bad = AuditExtensionDeltaCheckpointChain(
            good.first,
            good.additions,
            ("not a signature",) + good.signatures[1:],
        )
        with self.assertRaises(TypeError):
            diagnose_delta_chain_segments((bad,), self.key)


class DiagnoseValueErrorTest(unittest.TestCase):
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
            diagnose_delta_chain_segments((), self.key)

    def test_nested_signature_count_value_error(self):
        good = self.segments[0]
        bad = AuditExtensionDeltaCheckpointChain(
            good.first, good.additions, good.signatures[:-1]
        )
        with self.assertRaises(ValueError):
            diagnose_delta_chain_segments((bad,), self.key)
        with self.assertRaises(ValueError):
            diagnose_delta_chain_segments((good, bad), self.key)

    def test_nested_empty_batch_value_error(self):
        good = self.segments[1]
        bad = AuditExtensionDeltaCheckpointChain(
            good.first, ((),) + good.additions[1:], good.signatures
        )
        with self.assertRaises(ValueError):
            diagnose_delta_chain_segments((bad,), self.key)

    def test_nested_digest_width_value_error(self):
        good = self.segments[1]
        batch = good.additions[0]
        bad = AuditExtensionDeltaCheckpointChain(
            good.first,
            ((b"\x00" * 31,) + batch[1:],) + good.additions[1:],
            good.signatures,
        )
        with self.assertRaises(ValueError):
            diagnose_delta_chain_segments((bad,), self.key)

    def test_nested_illegal_proof_value_error(self):
        good = self.segments[0]
        first = good.first
        bad = AuditExtensionDeltaCheckpointChain(
            AuditExtensionProof(0, first.leaves),
            good.additions,
            good.signatures,
        )
        with self.assertRaises(ValueError):
            diagnose_delta_chain_segments((bad,), self.key)


if __name__ == "__main__":
    unittest.main()
