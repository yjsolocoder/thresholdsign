"""Tests for diagnose_signing_contributions and ContributionFault."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    ContributionFault,
    DKGRejection,
    Share,
    SigningDKGResult,
    aggregate_signing_dkg,
    diagnose_signing_contributions,
)

from test_signing import (
    FIELD_PRIME,
    LARGE_GROUP,
    make_signing_contributions,
)


def tamper_share_y(contribution, index, delta=1):
    """Return a copy whose secret share at ``index`` is shifted by ``delta``."""
    dealing = contribution.contribution
    share = dealing.shares[index]
    shares = dealing.shares[:index] + (
        Share(share.x, (share.y + delta) % FIELD_PRIME),
    ) + dealing.shares[index + 1:]
    return dataclasses.replace(
        contribution, contribution=dataclasses.replace(dealing, shares=shares)
    )


def tamper_blinding_y(contribution, index, delta=1):
    """Return a copy whose blinding share at ``index`` is shifted by ``delta``."""
    dealing = contribution.contribution
    blinding = dealing.blinding_shares[index]
    blinding_shares = dealing.blinding_shares[:index] + (
        Share(blinding.x, (blinding.y + delta) % FIELD_PRIME),
    ) + dealing.blinding_shares[index + 1:]
    return dataclasses.replace(
        contribution,
        contribution=dataclasses.replace(dealing, blinding_shares=blinding_shares),
    )


class ContributionFaultTest(unittest.TestCase):
    def test_fields_in_order_and_value_equality(self):
        fault = ContributionFault(2, 3, "pedersen")
        self.assertEqual(fault.sender_id, 2)
        self.assertEqual(fault.receiver_id, 3)
        self.assertEqual(fault.check, "pedersen")
        self.assertEqual(
            fault, ContributionFault(sender_id=2, receiver_id=3, check="pedersen")
        )
        self.assertNotEqual(fault, ContributionFault(2, 3, "feldman"))
        self.assertEqual(
            [f.name for f in dataclasses.fields(ContributionFault)],
            ["sender_id", "receiver_id", "check"],
        )

    def test_frozen(self):
        fault = ContributionFault(1, 2, "feldman")
        with self.assertRaises(FrozenInstanceError):
            fault.check = "pedersen"


class DiagnoseValidTest(unittest.TestCase):
    def setUp(self):
        self.contributions = make_signing_contributions()

    def test_all_valid_returns_empty_tuple(self):
        outcome = diagnose_signing_contributions(self.contributions)
        self.assertIsInstance(outcome, tuple)
        self.assertEqual(outcome, ())

    def test_input_order_does_not_matter(self):
        shuffled = [self.contributions[2], self.contributions[0], self.contributions[1]]
        self.assertEqual(diagnose_signing_contributions(shuffled), ())

    def test_threshold_one_and_five_participants(self):
        contributions = make_signing_contributions(
            participant_ids=(1, 2, 3, 4, 5), threshold=1
        )
        self.assertEqual(diagnose_signing_contributions(contributions), ())

    def test_non_sequential_participant_ids(self):
        contributions = make_signing_contributions(participant_ids=(2, 3, 5))
        self.assertEqual(diagnose_signing_contributions(contributions), ())

    def test_input_not_modified(self):
        snapshot = list(self.contributions)
        tampered = tamper_blinding_y(self.contributions[1], 0)
        diagnose_signing_contributions(
            [self.contributions[0], tampered, self.contributions[2]]
        )
        self.assertEqual(self.contributions, snapshot)


class DiagnoseFaultsTest(unittest.TestCase):
    def setUp(self):
        self.contributions = make_signing_contributions()

    def test_tampered_blinding_yields_single_pedersen_fault(self):
        # The blinding share is covered by the Pedersen commitment only, so
        # tampering it fails exactly one check at exactly one position.
        bad = tamper_blinding_y(self.contributions[1], 0)
        outcome = diagnose_signing_contributions(
            [self.contributions[0], bad, self.contributions[2]]
        )
        self.assertEqual(outcome, (ContributionFault(2, 1, "pedersen"),))

    def test_tampered_share_yields_pedersen_and_feldman_at_same_position(self):
        # The secret share is covered by both commitments; shifting it breaks
        # both checks at that position.
        bad = tamper_share_y(self.contributions[0], 2)
        outcome = diagnose_signing_contributions(
            [bad, self.contributions[1], self.contributions[2]]
        )
        self.assertEqual(
            outcome,
            (
                ContributionFault(1, 3, "pedersen"),
                ContributionFault(1, 3, "feldman"),
            ),
        )

    def test_one_sender_multiple_failing_positions(self):
        bad = tamper_blinding_y(self.contributions[2], 0)
        bad = tamper_blinding_y(bad, 2)
        outcome = diagnose_signing_contributions(
            [self.contributions[0], self.contributions[1], bad]
        )
        self.assertEqual(
            outcome,
            (
                ContributionFault(3, 1, "pedersen"),
                ContributionFault(3, 3, "pedersen"),
            ),
        )

    def test_swapped_feldman_commitment_yields_feldman_faults_only(self):
        # A structurally legal Feldman commitment from another dealing fails
        # at every position of this sender, while Pedersen still verifies.
        bad = dataclasses.replace(
            self.contributions[0],
            feldman_commitment=self.contributions[1].feldman_commitment,
        )
        outcome = diagnose_signing_contributions(
            [bad, self.contributions[1], self.contributions[2]]
        )
        self.assertEqual(
            outcome,
            (
                ContributionFault(1, 1, "feldman"),
                ContributionFault(1, 2, "feldman"),
                ContributionFault(1, 3, "feldman"),
            ),
        )

    def test_multiple_senders_sorted_and_order_independent(self):
        bad_one = tamper_blinding_y(self.contributions[0], 1)
        bad_three = tamper_share_y(self.contributions[2], 0)
        expected = (
            ContributionFault(1, 2, "pedersen"),
            ContributionFault(3, 1, "pedersen"),
            ContributionFault(3, 1, "feldman"),
        )
        first_order = [bad_one, self.contributions[1], bad_three]
        second_order = [bad_three, self.contributions[1], bad_one]
        self.assertEqual(diagnose_signing_contributions(first_order), expected)
        self.assertEqual(diagnose_signing_contributions(second_order), expected)

    def test_receiver_positions_follow_participant_ids_order(self):
        contributions = make_signing_contributions(participant_ids=(2, 3, 5))
        bad_two = tamper_blinding_y(contributions[0], 2)
        bad_five = tamper_blinding_y(contributions[2], 0)
        outcome = diagnose_signing_contributions(
            [bad_five, contributions[1], bad_two]
        )
        self.assertEqual(
            outcome,
            (
                ContributionFault(2, 5, "pedersen"),
                ContributionFault(5, 2, "pedersen"),
            ),
        )

    def test_diagnosis_does_not_change_aggregate_signing_dkg(self):
        bad = tamper_blinding_y(self.contributions[1], 0)
        mixed = [self.contributions[0], bad, self.contributions[2]]
        before = aggregate_signing_dkg(mixed)
        diagnose_signing_contributions(mixed)
        after = aggregate_signing_dkg(mixed)
        self.assertEqual(before, after)
        self.assertEqual(after, [DKGRejection(sender_id=2)])

    def test_diagnosis_then_clean_aggregation_unchanged(self):
        diagnose_signing_contributions(self.contributions)
        outcome = aggregate_signing_dkg(self.contributions)
        self.assertIsInstance(outcome, SigningDKGResult)


class DiagnoseValidationTest(unittest.TestCase):
    def setUp(self):
        self.contributions = make_signing_contributions()

    def test_empty_input_rejected(self):
        with self.assertRaises(ValueError):
            diagnose_signing_contributions([])

    def test_wrong_element_types_raise_type_error(self):
        with self.assertRaises(TypeError):
            diagnose_signing_contributions(
                [c.contribution for c in self.contributions]
            )
        with self.assertRaises(TypeError):
            diagnose_signing_contributions(["nope"])
        bad = dataclasses.replace(self.contributions[0], feldman_commitment=(1, 1))
        with self.assertRaises(TypeError):
            diagnose_signing_contributions(
                [bad, self.contributions[1], self.contributions[2]]
            )

    def test_missing_and_duplicate_participants_rejected(self):
        with self.assertRaises(ValueError):
            diagnose_signing_contributions(self.contributions[:2])
        with self.assertRaises(ValueError):
            diagnose_signing_contributions(
                [self.contributions[0], self.contributions[0], self.contributions[2]]
            )

    def test_inconsistent_participant_ids_rejected(self):
        others = make_signing_contributions(participant_ids=(1, 2, 4))
        with self.assertRaises(ValueError):
            diagnose_signing_contributions(
                [self.contributions[0], self.contributions[1], others[2]]
            )

    def test_inconsistent_threshold_rejected(self):
        others = make_signing_contributions(threshold=3)
        with self.assertRaises(ValueError):
            diagnose_signing_contributions(
                [self.contributions[0], self.contributions[1], others[2]]
            )

    def test_inconsistent_group_parameters_rejected(self):
        others = make_signing_contributions(generator=625)
        with self.assertRaises(ValueError):
            diagnose_signing_contributions(
                [self.contributions[0], self.contributions[1], others[2]]
            )

    def test_structurally_illegal_feldman_rejected_not_diagnosed(self):
        longer = self.contributions[0].feldman_commitment.values + (
            self.contributions[0].feldman_commitment.values[0],
        )
        bad_feldman = dataclasses.replace(
            self.contributions[0].feldman_commitment, values=longer
        )
        bad = dataclasses.replace(self.contributions[0], feldman_commitment=bad_feldman)
        with self.assertRaises(ValueError):
            diagnose_signing_contributions(
                [bad, self.contributions[1], self.contributions[2]]
            )

    def test_illegal_feldman_group_rejected(self):
        bad_feldman = dataclasses.replace(
            self.contributions[0].feldman_commitment, group_prime=LARGE_GROUP
        )
        bad = dataclasses.replace(self.contributions[0], feldman_commitment=bad_feldman)
        with self.assertRaises(ValueError):
            diagnose_signing_contributions(
                [bad, self.contributions[1], self.contributions[2]]
            )

    def test_out_of_range_share_value_rejected_not_diagnosed(self):
        dealing = self.contributions[1].contribution
        share = dealing.shares[0]
        shares = (Share(share.x, FIELD_PRIME),) + dealing.shares[1:]
        bad = dataclasses.replace(
            self.contributions[1],
            contribution=dataclasses.replace(dealing, shares=shares),
        )
        with self.assertRaises(ValueError):
            diagnose_signing_contributions(
                [self.contributions[0], bad, self.contributions[2]]
            )

    def test_unsorted_participant_ids_rejected(self):
        dealing = self.contributions[0].contribution
        bad = dataclasses.replace(
            self.contributions[0],
            contribution=dataclasses.replace(
                dealing, participant_ids=(3, 2, 1)
            ),
        )
        with self.assertRaises(ValueError):
            diagnose_signing_contributions(
                [bad, self.contributions[1], self.contributions[2]]
            )


if __name__ == "__main__":
    unittest.main()
