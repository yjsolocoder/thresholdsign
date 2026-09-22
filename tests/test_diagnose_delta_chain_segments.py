"""Tests for the stateless failure diagnosis of incremental
audit-extension checkpoint chain segment sets: DeltaDiagnosis and
diagnose_delta_chain_segments."""

import dataclasses
import unittest
from unittest import mock

import thresholdsign
from thresholdsign import (
    AggregateSignature,
    AuditExtensionCheckpointChain,
    AuditExtensionDeltaCheckpointChain,
    AuditExtensionProof,
    DeltaDiagnosis,
    decode_delta_chain_segments,
    diagnose_delta_chain_segments,
    encode_delta_chain_segments,
    join_delta_chain_segments,
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


class DeltaDiagnosisValueTest(unittest.TestCase):
    def test_positional_construction_and_field_order(self):
        diagnosis = DeltaDiagnosis(False, "leaf", 2, None)
        self.assertEqual(diagnosis.ok, False)
        self.assertEqual(diagnosis.kind, "leaf")
        self.assertEqual(diagnosis.segment, 2)
        self.assertIsNone(diagnosis.proof)
        self.assertEqual(
            dataclasses.astuple(diagnosis), (False, "leaf", 2, None)
        )

    def test_equality_is_by_value(self):
        self.assertEqual(
            DeltaDiagnosis(True, "ok", None, None),
            DeltaDiagnosis(True, "ok", None, None),
        )
        self.assertNotEqual(
            DeltaDiagnosis(False, "leaf", 0, None),
            DeltaDiagnosis(False, "sig", 0, None),
        )
        self.assertNotEqual(
            DeltaDiagnosis(False, "proof", 1, 0),
            DeltaDiagnosis(False, "proof", 1, 1),
        )

    def test_frozen(self):
        diagnosis = DeltaDiagnosis(True, "ok", None, None)
        for field in ("ok", "kind", "segment", "proof"):
            with self.assertRaises(
                dataclasses.FrozenInstanceError, msg=field
            ):
                setattr(diagnosis, field, None)


class DiagnoseValidSetTest(unittest.TestCase):
    def setUp(self):
        (
            self.key,
            self.records,
            self.splits,
            self.delta,
            self.segments,
        ) = build_segments()

    def test_success_is_fixed_to_ok_none_none(self):
        diagnosis = diagnose_delta_chain_segments(self.segments, self.key)
        self.assertEqual(
            diagnosis, DeltaDiagnosis(True, "ok", None, None)
        )
        self.assertIs(diagnosis.ok, True)
        self.assertEqual(diagnosis.kind, "ok")
        self.assertIsNone(diagnosis.segment)
        self.assertIsNone(diagnosis.proof)

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

    def test_ok_matches_the_boolean_entry_for_valid_sets(self):
        diagnosis = diagnose_delta_chain_segments(self.segments, self.key)
        self.assertIs(
            diagnosis.ok,
            verify_delta_chain_segments(self.segments, self.key),
        )

    def test_codec_roundtrip_does_not_change_diagnosis(self):
        restored = decode_delta_chain_segments(
            encode_delta_chain_segments(self.segments)
        )
        self.assertEqual(
            diagnose_delta_chain_segments(restored, self.key),
            diagnose_delta_chain_segments(self.segments, self.key),
        )

    def test_diagnosis_is_stateless_and_repeatable(self):
        first = diagnose_delta_chain_segments(self.segments, self.key)
        second = diagnose_delta_chain_segments(self.segments, self.key)
        self.assertEqual(first, second)
        # The segments themselves are untouched by diagnosis.
        self.assertEqual(
            join_delta_chain_segments(self.segments), self.delta
        )


class DiagnoseFalseCasesTest(unittest.TestCase):
    def setUp(self):
        (
            self.key,
            self.records,
            self.splits,
            self.delta,
            self.segments,
        ) = build_segments()

    def assert_diagnosis(self, segments, key, expected):
        diagnosis = diagnose_delta_chain_segments(segments, key)
        self.assertEqual(diagnosis, expected)
        # The diagnosis ok must be the boolean entry's verdict.
        self.assertIs(
            diagnosis.ok, verify_delta_chain_segments(segments, key)
        )
        self.assertFalse(diagnosis.ok)

    def test_out_of_order_segments_locate_leaf_at_first_seam(self):
        self.assert_diagnosis(
            (self.segments[1], self.segments[0]),
            self.key,
            DeltaDiagnosis(False, "leaf", 0, None),
        )
        self.assert_diagnosis(
            (self.segments[0], self.segments[2], self.segments[1]),
            self.key,
            DeltaDiagnosis(False, "leaf", 0, None),
        )

    def test_duplicated_segment_locates_leaf_at_first_seam(self):
        self.assert_diagnosis(
            (self.segments[0], self.segments[0]),
            self.key,
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
        self.assert_diagnosis(
            (left, gapped_right),
            self.key,
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
        self.assert_diagnosis(
            (left, overlapping_right),
            self.key,
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
        self.assert_diagnosis(
            (left, bad_right),
            self.key,
            DeltaDiagnosis(False, "sig", 0, None),
        )

    def test_seam_leaf_is_reported_before_seam_signature(self):
        # Both seam conditions broken: the leaf prefix is checked first.
        left = slice_audit_extension_delta_checkpoint_chain(self.delta, 0, 2)
        right = slice_audit_extension_delta_checkpoint_chain(self.delta, 2, 4)
        right_first = right.first
        bad_sig = AggregateSignature(R=70001, z=70002, signer_ids=(1, 3))
        bad_right = AuditExtensionDeltaCheckpointChain(
            AuditExtensionProof(
                right_first.old_n - 1, right_first.leaves
            ),
            right.additions,
            (bad_sig,) + right.signatures[1:],
        )
        self.assert_diagnosis(
            (left, bad_right),
            self.key,
            DeltaDiagnosis(False, "leaf", 0, None),
        )

    def test_tampered_leaf_digest_locates_proof_in_its_segment(self):
        segment = self.segments[1]
        batch = segment.additions[0]
        tampered_batch = (b"\x00" * 32,) + batch[1:]
        tampered = AuditExtensionDeltaCheckpointChain(
            segment.first,
            (tampered_batch,) + segment.additions[1:],
            segment.signatures,
        )
        segments = (self.segments[0], tampered) + self.segments[2:]
        # Segment 1 holds expanded hops 1 and 2; the tampered batch is
        # the leaves hop 1 (its second hop) appends, so that hop's
        # extension check fails.
        self.assert_diagnosis(
            segments,
            self.key,
            DeltaDiagnosis(False, "proof", 1, 1),
        )

    def test_tampered_first_proof_leaf_locates_proof_hop_zero(self):
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
        self.assert_diagnosis(
            segments,
            self.key,
            DeltaDiagnosis(False, "proof", 0, 0),
        )

    def test_tampered_checkpoint_signature_locates_proof(self):
        bad_sig = sign_message(make_other_key(), b"unrelated", seed=5)
        segment = self.segments[0]
        tampered = AuditExtensionDeltaCheckpointChain(
            segment.first,
            segment.additions,
            (bad_sig,) + segment.signatures[1:],
        )
        segments = (tampered,) + self.segments[1:]
        self.assert_diagnosis(
            segments,
            self.key,
            DeltaDiagnosis(False, "proof", 0, 0),
        )

    def test_other_key_locates_proof_without_explaining(self):
        # A wrong key fails the very first hop's extension check; the
        # diagnosis never guesses the cryptographic reason.
        self.assert_diagnosis(
            self.segments,
            make_other_key(),
            DeltaDiagnosis(False, "proof", 0, 0),
        )

    def test_single_tampered_chain_locates_proof(self):
        bad_sig = sign_message(make_other_key(), b"unrelated", seed=7)
        tampered = AuditExtensionDeltaCheckpointChain(
            self.delta.first,
            self.delta.additions,
            self.delta.signatures[:-1] + (bad_sig,),
        )
        self.assert_diagnosis(
            (tampered,),
            self.key,
            DeltaDiagnosis(
                False, "proof", 0, len(self.delta.additions)
            ),
        )

    def test_first_failure_is_reported_in_segment_order(self):
        # Tamper the first hop of segment 0 and the seam signature of
        # the first seam: the earlier hop failure wins.
        bad_sig = sign_message(make_other_key(), b"unrelated", seed=11)
        segment0 = self.segments[0]
        tampered0 = AuditExtensionDeltaCheckpointChain(
            segment0.first,
            segment0.additions,
            (bad_sig,) + segment0.signatures[1:],
        )
        segment1 = self.segments[1]
        tampered1 = AuditExtensionDeltaCheckpointChain(
            segment1.first,
            segment1.additions,
            (bad_sig,) + segment1.signatures[1:],
        )
        segments = (tampered0, tampered1) + self.segments[2:]
        self.assert_diagnosis(
            segments,
            self.key,
            DeltaDiagnosis(False, "proof", 0, 0),
        )

    def test_broken_intra_segment_prefix_locates_segment_kind(self):
        # A structurally legal delta chain always expands with linked
        # hops, so the intra-segment prefix check is a defensive first
        # pass; drive it with a stubbed expansion whose second hop does
        # not extend the first. The right-hand hop's index is reported.
        segment = self.segments[1]
        expanded = thresholdsign.expand_audit_extension_delta_checkpoint_chain(
            segment
        )
        self.assertGreaterEqual(len(expanded.proofs), 2)
        second = expanded.proofs[1]
        broken_second = AuditExtensionProof(
            second.old_n,
            (b"\x03" * 32,) + second.leaves[1:],
        )
        broken = AuditExtensionCheckpointChain(
            proofs=(expanded.proofs[0], broken_second)
            + expanded.proofs[2:],
            signatures=expanded.signatures,
        )
        original = thresholdsign.expand_audit_extension_delta_checkpoint_chain

        def stubbed(chain):
            if chain is segment:
                return broken
            return original(chain)

        with mock.patch.object(
            thresholdsign,
            "expand_audit_extension_delta_checkpoint_chain",
            side_effect=stubbed,
        ):
            diagnosis = diagnose_delta_chain_segments(
                self.segments, self.key
            )
        self.assertEqual(
            diagnosis, DeltaDiagnosis(False, "segment", 1, 1)
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

    def test_later_segment_structure_raises_before_earlier_failure(self):
        # Structure of every segment is validated completely before any
        # relationship is inspected: an illegal later segment raises
        # even though the first segment alone would already fail.
        bad_sig = sign_message(make_other_key(), b"unrelated", seed=13)
        segment0 = self.segments[0]
        tampered0 = AuditExtensionDeltaCheckpointChain(
            segment0.first,
            segment0.additions,
            (bad_sig,) + segment0.signatures[1:],
        )
        good = self.segments[1]
        illegal = AuditExtensionDeltaCheckpointChain(
            good.first, good.additions, good.signatures[:-1]
        )
        with self.assertRaises(ValueError):
            diagnose_delta_chain_segments(
                (tampered0, illegal) + self.segments[2:], self.key
            )


if __name__ == "__main__":
    unittest.main()
