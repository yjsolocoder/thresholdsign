"""Tests for the signature-share pre-aggregation diagnoser."""

import copy
import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    SignatureShare,
    SignatureShareFault,
    SignatureShareRejection,
    SigningRound,
    aggregate_signature,
    create_audit,
    check_audit,
    diagnose_signature_shares,
)

from tests.test_signing import (
    FIELD_PRIME,
    LARGE_FIELD,
    LARGE_G,
    LARGE_GROUP,
    LARGE_H,
    MESSAGE,
    make_round,
    make_shares,
    make_signing_dkg,
)


def tamper_z(share, delta=1):
    return dataclasses.replace(share, z=(share.z + delta) % FIELD_PRIME)


def tamper_commitment(share, replacement):
    return dataclasses.replace(share, nonce_commitment=replacement)


class SignatureShareFaultValueTest(unittest.TestCase):
    def test_positionally_constructible(self):
        fault = SignatureShareFault(2, "commitment")
        self.assertEqual((fault.signer_id, fault.check), (2, "commitment"))

    def test_fields_in_declared_order(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(SignatureShareFault)],
            ["signer_id", "check"],
        )

    def test_compared_by_value(self):
        self.assertEqual(
            SignatureShareFault(1, "equation"), SignatureShareFault(1, "equation")
        )
        self.assertNotEqual(
            SignatureShareFault(1, "equation"), SignatureShareFault(1, "commitment")
        )
        self.assertNotEqual(
            SignatureShareFault(1, "equation"), SignatureShareFault(2, "equation")
        )
        self.assertEqual(
            {
                SignatureShareFault(1, "commitment"),
                SignatureShareFault(1, "commitment"),
            },
            {SignatureShareFault(1, "commitment")},
        )

    def test_frozen(self):
        fault = SignatureShareFault(1, "equation")
        with self.assertRaises(FrozenInstanceError):
            fault.check = "commitment"  # type: ignore[misc]

    def test_immutable_fields(self):
        fault = SignatureShareFault(1, "equation")
        with self.assertRaises(FrozenInstanceError):
            fault.signer_id = 2  # type: ignore[misc]


class DiagnoseSuccessTest(unittest.TestCase):
    def setUp(self):
        self.dkg = make_signing_dkg()
        self.round_info, _commitments, self.nonces = make_round(self.dkg, (1, 2))
        self.shares = make_shares(self.dkg, self.round_info, self.nonces)

    def test_valid_batch_returns_empty_tuple(self):
        faults = diagnose_signature_shares(self.shares, self.round_info, self.dkg)
        self.assertEqual(faults, ())
        self.assertIsInstance(faults, tuple)

    def test_empty_faults_exactly_when_aggregation_succeeds(self):
        self.assertIsInstance(
            aggregate_signature(self.shares, self.round_info, self.dkg),
            AggregateSignature,
        )
        self.assertEqual(
            diagnose_signature_shares(self.shares, self.round_info, self.dkg), ()
        )

    def test_full_participant_set(self):
        round_info, _commitments, nonces = make_round(self.dkg, (1, 2, 3))
        shares = make_shares(self.dkg, round_info, nonces)
        self.assertEqual(diagnose_signature_shares(shares, round_info, self.dkg), ())

    def test_accepts_any_iterable_and_input_order_does_not_matter(self):
        forward = diagnose_signature_shares(
            self.shares, self.round_info, self.dkg
        )
        reversed_ = diagnose_signature_shares(
            reversed(self.shares), self.round_info, self.dkg
        )
        iterator = diagnose_signature_shares(
            iter(list(reversed(self.shares))), self.round_info, self.dkg
        )
        self.assertEqual(forward, reversed_)
        self.assertEqual(forward, iterator)


class DiagnoseFaultTest(unittest.TestCase):
    def setUp(self):
        self.dkg = make_signing_dkg()
        self.round_info, _commitments, self.nonces = make_round(self.dkg, (1, 2))
        self.shares = make_shares(self.dkg, self.round_info, self.nonces)

    def test_tampered_z_is_equation_fault(self):
        bad = tamper_z(self.shares[0])
        faults = diagnose_signature_shares(
            [bad, self.shares[1]], self.round_info, self.dkg
        )
        self.assertEqual(faults, (SignatureShareFault(1, "equation"),))

    def test_tampered_commitment_is_commitment_fault(self):
        # Another signer's public commitment is a structurally legal value.
        bad = tamper_commitment(self.shares[0], self.shares[1].nonce_commitment)
        faults = diagnose_signature_shares(
            [self.shares[1], bad], self.round_info, self.dkg
        )
        self.assertEqual(faults, (SignatureShareFault(1, "commitment"),))

    def test_commitment_fault_takes_precedence_even_when_z_is_also_bad(self):
        bad = tamper_commitment(
            tamper_z(self.shares[0]), self.shares[1].nonce_commitment
        )
        faults = diagnose_signature_shares(
            [bad, self.shares[1]], self.round_info, self.dkg
        )
        self.assertEqual(faults, (SignatureShareFault(1, "commitment"),))

    def test_one_fault_per_signer(self):
        bad = tamper_commitment(
            tamper_z(self.shares[1]), self.shares[0].nonce_commitment
        )
        faults = diagnose_signature_shares(
            [bad, self.shares[0]], self.round_info, self.dkg
        )
        self.assertEqual(faults, (SignatureShareFault(2, "commitment"),))
        self.assertEqual(len({fault.signer_id for fault in faults}), len(faults))

    def test_multiple_faulty_signers_all_reported_sorted(self):
        bad_first = tamper_commitment(
            self.shares[0], self.shares[1].nonce_commitment
        )
        bad_second = tamper_z(self.shares[1])
        expected = (
            SignatureShareFault(1, "commitment"),
            SignatureShareFault(2, "equation"),
        )
        self.assertEqual(
            diagnose_signature_shares(
                [bad_second, bad_first], self.round_info, self.dkg
            ),
            expected,
        )
        self.assertEqual(
            diagnose_signature_shares(
                [bad_first, bad_second], self.round_info, self.dkg
            ),
            expected,
        )

    def test_faults_match_aggregator_rejection_senders(self):
        bad_first = tamper_z(self.shares[0])
        bad_second = tamper_commitment(
            self.shares[1], self.shares[0].nonce_commitment
        )
        batch = [bad_second, bad_first]
        outcome = aggregate_signature(batch, self.round_info, self.dkg)
        self.assertEqual(
            outcome,
            [
                SignatureShareRejection(signer_id=1),
                SignatureShareRejection(signer_id=2),
            ],
        )
        faults = diagnose_signature_shares(batch, self.round_info, self.dkg)
        self.assertEqual(
            [fault.signer_id for fault in faults],
            [rejection.signer_id for rejection in outcome],
        )

    def test_fault_order_independent_of_input_order(self):
        round3, _commitments, nonces3 = make_round(self.dkg, (1, 2, 3))
        shares3 = make_shares(self.dkg, round3, nonces3)
        bad1 = tamper_z(shares3[0])
        bad3 = tamper_commitment(shares3[2], shares3[1].nonce_commitment)
        batch = [shares3[1], bad3, bad1]
        expected = (
            SignatureShareFault(1, "equation"),
            SignatureShareFault(3, "commitment"),
        )
        self.assertEqual(
            diagnose_signature_shares(batch, round3, self.dkg), expected
        )
        self.assertEqual(
            diagnose_signature_shares(list(reversed(batch)), round3, self.dkg),
            expected,
        )


class DiagnoseValidationTest(unittest.TestCase):
    def setUp(self):
        self.dkg = make_signing_dkg()
        self.round_info, _commitments, self.nonces = make_round(self.dkg, (1, 2))
        self.shares = make_shares(self.dkg, self.round_info, self.nonces)

    def assert_aggregator_and_diagnoser_raise(self, shares, error):
        with self.assertRaises(error):
            aggregate_signature(list(shares), self.round_info, self.dkg)
        with self.assertRaises(error):
            diagnose_signature_shares(shares, self.round_info, self.dkg)

    def test_empty_batch_is_value_error(self):
        self.assert_aggregator_and_diagnoser_raise([], ValueError)

    def test_missing_round_signer_is_value_error(self):
        self.assert_aggregator_and_diagnoser_raise(self.shares[:1], ValueError)

    def test_duplicate_submission_is_value_error(self):
        self.assert_aggregator_and_diagnoser_raise(
            [self.shares[0], self.shares[0]], ValueError
        )

    def test_signer_outside_round_is_value_error(self):
        round3, _commitments, nonces3 = make_round(self.dkg, (1, 2, 3))
        shares3 = make_shares(self.dkg, round3, nonces3)
        # A valid share for signer 3 in the three-signer round is outside
        # the two-signer round the batch claims to belong to.
        self.assert_aggregator_and_diagnoser_raise(
            [self.shares[0], shares3[2]], ValueError
        )

    def test_wrong_element_type_is_type_error(self):
        self.assert_aggregator_and_diagnoser_raise(["nope"], TypeError)

    def test_integer_like_tuple_is_type_error(self):
        self.assert_aggregator_and_diagnoser_raise(
            [(self.shares[0].signer_id, 1, 0)], TypeError
        )

    def test_wrong_share_field_types_are_type_error(self):
        for field_name, value in (
            ("signer_id", "1"),
            ("z", 1.5),
            ("nonce_commitment", "2"),
        ):
            with self.subTest(field=field_name):
                bad = dataclasses.replace(self.shares[0], **{field_name: value})
                with self.assertRaises(TypeError):
                    aggregate_signature([bad, self.shares[1]], self.round_info, self.dkg)
                with self.assertRaises(TypeError):
                    diagnose_signature_shares(
                        [bad, self.shares[1]], self.round_info, self.dkg
                    )

    def test_bool_is_not_an_integer_id(self):
        bad = dataclasses.replace(self.shares[0], signer_id=True)
        with self.assertRaises(TypeError):
            diagnose_signature_shares([bad, self.shares[1]], self.round_info, self.dkg)

    def test_wrong_round_type_is_type_error(self):
        with self.assertRaises(TypeError):
            diagnose_signature_shares(self.shares, "round", self.dkg)

    def test_wrong_dkg_type_is_type_error(self):
        with self.assertRaises(TypeError):
            diagnose_signature_shares(self.shares, self.round_info, "dkg")

    def test_out_of_range_z_is_value_error(self):
        bad = dataclasses.replace(
            self.shares[0], z=FIELD_PRIME
        )
        with self.assertRaises(ValueError):
            diagnose_signature_shares([bad, self.shares[1]], self.round_info, self.dkg)

    def test_out_of_range_commitment_is_value_error(self):
        bad = dataclasses.replace(self.shares[0], nonce_commitment=1)
        with self.assertRaises(ValueError):
            diagnose_signature_shares([bad, self.shares[1]], self.round_info, self.dkg)

    def test_structurally_illegal_round_is_value_error(self):
        bad_round = SigningRound(
            message=self.round_info.message,
            signer_ids=(2, 1),
            nonce_commitments=self.round_info.nonce_commitments,
            R=self.round_info.R,
            challenge=self.round_info.challenge,
        )
        with self.assertRaises(ValueError):
            diagnose_signature_shares(self.shares, bad_round, self.dkg)

    def test_round_from_another_group_is_value_error(self):
        # A round assembled for a DKG over the larger toy group cannot be
        # paired with this batch's small-group DKG: its commitments do not
        # lie in the small order-field_prime subgroup.
        from thresholdsign import create_signing_round, create_signing_nonce_commitment
        from tests.test_signing import fixed_random

        large_dkg = make_signing_dkg(
            field_prime=LARGE_FIELD,
            group_prime=LARGE_GROUP,
            generator=LARGE_G,
            blinding_generator=LARGE_H,
        )
        commitments = [
            create_signing_nonce_commitment(
                signer_id,
                prime=LARGE_FIELD,
                group_prime=LARGE_GROUP,
                generator=LARGE_G,
                randbelow=fixed_random(77 + signer_id),
            )[0]
            for signer_id in (1, 2)
        ]
        large_round = create_signing_round(
            MESSAGE, (1, 2), commitments, large_dkg
        )
        with self.assertRaises(ValueError):
            diagnose_signature_shares(self.shares, large_round, self.dkg)
        with self.assertRaises(ValueError):
            aggregate_signature(self.shares, large_round, self.dkg)


class DiagnoseNoMutationTest(unittest.TestCase):
    def setUp(self):
        self.dkg = make_signing_dkg()
        self.round_info, _commitments, self.nonces = make_round(self.dkg, (1, 2))
        self.shares = make_shares(self.dkg, self.round_info, self.nonces)

    def test_input_list_unchanged_on_success(self):
        batch = list(reversed(self.shares))
        snapshot = copy.deepcopy(batch)
        diagnose_signature_shares(batch, self.round_info, self.dkg)
        self.assertEqual(batch, snapshot)

    def test_input_list_unchanged_with_faults(self):
        batch = [tamper_z(self.shares[0]), self.shares[1]]
        snapshot = copy.deepcopy(batch)
        diagnose_signature_shares(batch, self.round_info, self.dkg)
        self.assertEqual(batch, snapshot)

    def test_input_unchanged_on_value_error(self):
        batch = [self.shares[0]]
        snapshot = copy.deepcopy(batch)
        with self.assertRaises(ValueError):
            diagnose_signature_shares(batch, self.round_info, self.dkg)
        self.assertEqual(batch, snapshot)

    def test_generator_input_is_consumed_but_not_modified(self):
        batch = list(self.shares)
        snapshot = copy.deepcopy(batch)
        diagnose_signature_shares(iter(batch), self.round_info, self.dkg)
        self.assertEqual(batch, snapshot)


class AggregatorAndAuditCompatibilityTest(unittest.TestCase):
    def setUp(self):
        self.dkg = make_signing_dkg()
        self.round_info, _commitments, self.nonces = make_round(self.dkg, (1, 2))
        self.shares = make_shares(self.dkg, self.round_info, self.nonces)

    def test_aggregator_still_returns_aggregate_for_valid_batch(self):
        result = aggregate_signature(self.shares, self.round_info, self.dkg)
        self.assertIsInstance(result, AggregateSignature)

    def test_aggregator_still_returns_sorted_rejections_for_bad_batch(self):
        bad_first = tamper_z(self.shares[0])
        bad_second = tamper_commitment(
            self.shares[1], self.shares[0].nonce_commitment
        )
        for batch in (
            [bad_first, bad_second],
            [bad_second, bad_first],
            list(reversed([bad_first, bad_second])),
        ):
            result = aggregate_signature(batch, self.round_info, self.dkg)
            self.assertEqual(
                result,
                [
                    SignatureShareRejection(signer_id=1),
                    SignatureShareRejection(signer_id=2),
                ],
            )

    def test_empty_faults_exactly_when_aggregate_signature_succeeds(self):
        bad = tamper_z(self.shares[0])
        batch = [bad, self.shares[1]]
        self.assertIsInstance(
            aggregate_signature(list(batch), self.round_info, self.dkg), list
        )
        self.assertNotEqual(
            diagnose_signature_shares(batch, self.round_info, self.dkg), ()
        )
        self.assertIsInstance(
            aggregate_signature(list(self.shares), self.round_info, self.dkg),
            AggregateSignature,
        )
        self.assertEqual(
            diagnose_signature_shares(self.shares, self.round_info, self.dkg), ()
        )

    def test_audit_receipt_contents_and_verification_unchanged(self):
        receipt = create_audit(
            MESSAGE, self.shares, self.round_info, self.dkg
        )
        self.assertTrue(check_audit(MESSAGE, receipt, self.dkg))

        bad = tamper_z(self.shares[0])
        bad_receipt = create_audit(
            MESSAGE, [bad, self.shares[1]], self.round_info, self.dkg
        )
        self.assertTrue(check_audit(MESSAGE, bad_receipt, self.dkg))
        self.assertFalse(check_audit(b"other message", receipt, self.dkg))

        # Diagnosing must not influence a receipt created afterwards.
        diagnose_signature_shares(self.shares, self.round_info, self.dkg)
        diagnose_signature_shares([bad, self.shares[1]], self.round_info, self.dkg)
        receipt_again = create_audit(
            MESSAGE, self.shares, self.round_info, self.dkg
        )
        self.assertEqual(receipt_again.payload, receipt.payload)
        self.assertTrue(check_audit(MESSAGE, receipt_again, self.dkg))


if __name__ == "__main__":
    unittest.main()
