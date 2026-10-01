"""Tests for the signing contribution pre-aggregation diagnoser."""

import copy
import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    ContributionFault,
    DKGRejection,
    Share,
    SigningDKGResult,
    aggregate_signing_dkg,
    create_signing_contribution,
    diagnose_signing_contributions,
)

# Same toy group as the signing tests: 8069 = 4 * 2017 + 1 is prime, 16 and
# 256 = 16 ** 2 are distinct generators of the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

PARTICIPANT_IDS = (1, 2, 3)
THRESHOLD = 2


def fixed_random(seed=1):
    """Deterministic stand-in for secrets.randbelow (same LCG as DKG tests)."""
    state = {"value": seed}

    def randbelow(upper: int) -> int:
        state["value"] = (
            state["value"] * 6364136223846793005 + 1442695040888963407
        ) % upper
        return state["value"]

    return randbelow


def make_contributions(participant_ids=PARTICIPANT_IDS, threshold=THRESHOLD):
    return [
        create_signing_contribution(
            pid,
            participant_ids,
            threshold,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            blinding_generator=BLINDING_GENERATOR,
            randbelow=fixed_random(pid),
        )
        for pid in participant_ids
    ]


def tamper_sharing_share(contribution, index):
    """Break the sharing share at ``index`` (Pedersen and Feldman both fail)."""
    dealing = contribution.contribution
    share = dealing.shares[index]
    tampered_dealing = dataclasses.replace(
        dealing,
        shares=dealing.shares[:index]
        + (Share(share.x, (share.y + 1) % FIELD_PRIME),)
        + dealing.shares[index + 1 :],
    )
    return dataclasses.replace(contribution, contribution=tampered_dealing)


def tamper_blinding_share(contribution, index):
    """Break the blinding share at ``index`` (Pedersen only; Feldman passes)."""
    dealing = contribution.contribution
    share = dealing.blinding_shares[index]
    tampered_dealing = dataclasses.replace(
        dealing,
        blinding_shares=dealing.blinding_shares[:index]
        + (Share(share.x, (share.y + 1) % FIELD_PRIME),)
        + dealing.blinding_shares[index + 1 :],
    )
    return dataclasses.replace(contribution, contribution=tampered_dealing)


class ContributionFaultValueTest(unittest.TestCase):
    def test_positionally_constructible(self):
        fault = ContributionFault(2, 3, "pedersen")
        self.assertEqual(
            (fault.sender_id, fault.receiver_id, fault.check), (2, 3, "pedersen")
        )

    def test_fields_in_declared_order(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(ContributionFault)],
            ["sender_id", "receiver_id", "check"],
        )

    def test_compared_by_value(self):
        self.assertEqual(
            ContributionFault(1, 2, "feldman"), ContributionFault(1, 2, "feldman")
        )
        self.assertNotEqual(
            ContributionFault(1, 2, "feldman"), ContributionFault(1, 2, "pedersen")
        )
        self.assertNotEqual(
            ContributionFault(1, 2, "feldman"), ContributionFault(1, 3, "feldman")
        )
        self.assertNotEqual(
            ContributionFault(1, 2, "feldman"), ContributionFault(2, 2, "feldman")
        )
        self.assertEqual(
            {
                ContributionFault(1, 2, "pedersen"),
                ContributionFault(1, 2, "pedersen"),
            },
            {ContributionFault(1, 2, "pedersen")},
        )

    def test_frozen(self):
        fault = ContributionFault(1, 2, "pedersen")
        with self.assertRaises(FrozenInstanceError):
            fault.check = "feldman"  # type: ignore[misc]


class DiagnoseSuccessTest(unittest.TestCase):
    def test_valid_set_returns_empty_tuple(self):
        faults = diagnose_signing_contributions(make_contributions())
        self.assertEqual(faults, ())
        self.assertIsInstance(faults, tuple)

    def test_empty_faults_exactly_when_aggregation_succeeds(self):
        contributions = make_contributions()
        self.assertIsInstance(
            aggregate_signing_dkg(list(contributions)), SigningDKGResult
        )
        self.assertEqual(diagnose_signing_contributions(contributions), ())

    def test_threshold_one(self):
        contributions = make_contributions((1, 2), threshold=1)
        self.assertEqual(diagnose_signing_contributions(contributions), ())

    def test_accepts_any_iterable(self):
        contributions = make_contributions()
        self.assertEqual(
            diagnose_signing_contributions(iter(reversed(contributions))),
            diagnose_signing_contributions(contributions),
        )


class DiagnoseFaultTest(unittest.TestCase):
    def setUp(self):
        self.contributions = make_contributions()

    def test_tampered_blinding_share_is_pedersen_fault_only(self):
        bad = tamper_blinding_share(self.contributions[1], 0)
        faults = diagnose_signing_contributions(
            [self.contributions[0], bad, self.contributions[2]]
        )
        self.assertEqual(
            faults,
            (ContributionFault(2, 1, "pedersen"),),
        )

    def test_tampered_sharing_share_is_both_faults_pedersen_first(self):
        bad = tamper_sharing_share(self.contributions[1], 0)
        faults = diagnose_signing_contributions(
            [self.contributions[0], bad, self.contributions[2]]
        )
        self.assertEqual(
            faults,
            (
                ContributionFault(2, 1, "pedersen"),
                ContributionFault(2, 1, "feldman"),
            ),
        )

    def test_several_positions_of_one_sender_all_reported(self):
        bad = tamper_sharing_share(self.contributions[0], 0)
        bad = tamper_sharing_share(bad, 2)
        faults = diagnose_signing_contributions(
            [bad, self.contributions[1], self.contributions[2]]
        )
        self.assertEqual(
            faults,
            (
                ContributionFault(1, 1, "pedersen"),
                ContributionFault(1, 1, "feldman"),
                ContributionFault(1, 3, "pedersen"),
                ContributionFault(1, 3, "feldman"),
            ),
        )

    def test_unbound_feldman_commitment_is_feldman_fault_at_every_position(self):
        # Swapping in another sender's (structurally legal) Feldman
        # commitment is the case aggregate_signing_dkg raises ValueError on;
        # the diagnoser reports every mismatching position instead.
        bad = dataclasses.replace(
            self.contributions[0],
            feldman_commitment=self.contributions[1].feldman_commitment,
        )
        faults = diagnose_signing_contributions(
            [bad, self.contributions[1], self.contributions[2]]
        )
        self.assertEqual(
            faults,
            (
                ContributionFault(1, 1, "feldman"),
                ContributionFault(1, 2, "feldman"),
                ContributionFault(1, 3, "feldman"),
            ),
        )
        with self.assertRaises(ValueError):
            aggregate_signing_dkg([bad, self.contributions[1], self.contributions[2]])

    def test_pedersen_and_feldman_failures_in_different_senders(self):
        pedersen_bad = tamper_blinding_share(self.contributions[0], 1)
        feldman_bad = dataclasses.replace(
            self.contributions[2],
            feldman_commitment=self.contributions[1].feldman_commitment,
        )
        faults = diagnose_signing_contributions(
            [feldman_bad, self.contributions[1], pedersen_bad]
        )
        self.assertEqual(
            faults,
            (
                ContributionFault(1, 2, "pedersen"),
                ContributionFault(3, 1, "feldman"),
                ContributionFault(3, 2, "feldman"),
                ContributionFault(3, 3, "feldman"),
            ),
        )

    def test_fault_order_is_sender_then_position_then_check(self):
        bad_first = tamper_sharing_share(self.contributions[2], 1)
        bad_second = tamper_sharing_share(self.contributions[0], 0)
        one_order = [bad_first, self.contributions[1], bad_second]
        other_order = [bad_second, bad_first, self.contributions[1]]
        expected = (
            ContributionFault(1, 1, "pedersen"),
            ContributionFault(1, 1, "feldman"),
            ContributionFault(3, 2, "pedersen"),
            ContributionFault(3, 2, "feldman"),
        )
        self.assertEqual(diagnose_signing_contributions(one_order), expected)
        self.assertEqual(diagnose_signing_contributions(other_order), expected)
        self.assertEqual(
            diagnose_signing_contributions(reversed(one_order)), expected
        )

    def test_one_bad_position_does_not_mask_others(self):
        bad = tamper_sharing_share(self.contributions[1], 0)
        bad = tamper_blinding_share(bad, 2)
        faults = diagnose_signing_contributions(
            [self.contributions[0], bad, self.contributions[2]]
        )
        self.assertEqual(
            faults,
            (
                ContributionFault(2, 1, "pedersen"),
                ContributionFault(2, 1, "feldman"),
                ContributionFault(2, 3, "pedersen"),
            ),
        )

    def test_pedersen_fault_matches_aggregator_rejection_senders(self):
        bad = tamper_blinding_share(self.contributions[1], 0)
        contributions = [self.contributions[0], bad, self.contributions[2]]
        outcome = aggregate_signing_dkg(contributions)
        self.assertEqual(outcome, [DKGRejection(sender_id=2)])
        faults = diagnose_signing_contributions(contributions)
        self.assertEqual(
            sorted({fault.sender_id for fault in faults if fault.check == "pedersen"}),
            [rejection.sender_id for rejection in outcome],
        )


class DiagnoseValidationTest(unittest.TestCase):
    def setUp(self):
        self.contributions = make_contributions()

    def assert_aggregator_and_diagnoser_raise(self, contributions, error):
        with self.assertRaises(error):
            aggregate_signing_dkg(list(contributions))
        with self.assertRaises(error):
            diagnose_signing_contributions(contributions)

    def test_empty_input_is_value_error(self):
        self.assert_aggregator_and_diagnoser_raise([], ValueError)

    def test_missing_participant_is_value_error(self):
        self.assert_aggregator_and_diagnoser_raise(self.contributions[:2], ValueError)

    def test_duplicate_sender_is_value_error(self):
        self.assert_aggregator_and_diagnoser_raise(
            [self.contributions[0], self.contributions[0], self.contributions[2]],
            ValueError,
        )

    def test_inconsistent_participant_ids_is_value_error(self):
        other = create_signing_contribution(
            4,
            (1, 2, 4),
            THRESHOLD,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            blinding_generator=BLINDING_GENERATOR,
            randbelow=fixed_random(4),
        )
        self.assert_aggregator_and_diagnoser_raise(
            [self.contributions[0], self.contributions[1], other], ValueError
        )

    def test_inconsistent_threshold_is_value_error(self):
        other = make_contributions((1, 2, 3), threshold=3)[0]
        self.assert_aggregator_and_diagnoser_raise(
            [other, self.contributions[1], self.contributions[2]], ValueError
        )

    def test_inconsistent_group_parameters_is_value_error(self):
        other = create_signing_contribution(
            3,
            PARTICIPANT_IDS,
            THRESHOLD,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=BLINDING_GENERATOR,
            blinding_generator=GENERATOR,
            randbelow=fixed_random(3),
        )
        self.assert_aggregator_and_diagnoser_raise(
            [self.contributions[0], self.contributions[1], other], ValueError
        )

    def test_illegal_feldman_value_is_value_error(self):
        bad_feldman = dataclasses.replace(
            self.contributions[0].feldman_commitment, values=(0, 1)
        )
        bad = dataclasses.replace(self.contributions[0], feldman_commitment=bad_feldman)
        self.assert_aggregator_and_diagnoser_raise(
            [bad, self.contributions[1], self.contributions[2]], ValueError
        )

    def test_feldman_wrong_threshold_is_value_error(self):
        longer = self.contributions[0].feldman_commitment.values + (
            self.contributions[0].feldman_commitment.values[0],
        )
        bad_feldman = dataclasses.replace(
            self.contributions[0].feldman_commitment, values=longer
        )
        bad = dataclasses.replace(self.contributions[0], feldman_commitment=bad_feldman)
        self.assert_aggregator_and_diagnoser_raise(
            [bad, self.contributions[1], self.contributions[2]], ValueError
        )

    def test_feldman_other_group_is_value_error(self):
        bad_feldman = dataclasses.replace(
            self.contributions[0].feldman_commitment, group_prime=2000303
        )
        bad = dataclasses.replace(self.contributions[0], feldman_commitment=bad_feldman)
        self.assert_aggregator_and_diagnoser_raise(
            [bad, self.contributions[1], self.contributions[2]], ValueError
        )

    def test_illegal_share_coordinate_is_value_error(self):
        dealing = self.contributions[0].contribution
        bad_dealing = dataclasses.replace(
            dealing,
            shares=(Share(0, dealing.shares[0].y),) + dealing.shares[1:],
        )
        bad = dataclasses.replace(self.contributions[0], contribution=bad_dealing)
        self.assert_aggregator_and_diagnoser_raise(
            [bad, self.contributions[1], self.contributions[2]], ValueError
        )

    def test_sender_outside_participants_is_value_error(self):
        bad_dealing = dataclasses.replace(
            self.contributions[0].contribution, sender_id=4
        )
        bad = dataclasses.replace(self.contributions[0], contribution=bad_dealing)
        self.assert_aggregator_and_diagnoser_raise(
            [bad, self.contributions[1], self.contributions[2]], ValueError
        )

    def test_unsorted_participant_ids_is_value_error(self):
        bad_dealing = dataclasses.replace(
            self.contributions[0].contribution, participant_ids=(2, 1, 3)
        )
        bad = dataclasses.replace(self.contributions[0], contribution=bad_dealing)
        self.assert_aggregator_and_diagnoser_raise(
            [bad, self.contributions[1], self.contributions[2]], ValueError
        )

    def test_wrong_element_type_is_type_error(self):
        self.assert_aggregator_and_diagnoser_raise(["nope"], TypeError)

    def test_plain_dkg_contribution_element_is_type_error(self):
        self.assert_aggregator_and_diagnoser_raise(
            [contribution.contribution for contribution in self.contributions],
            TypeError,
        )

    def test_wrong_feldman_type_is_type_error(self):
        bad = dataclasses.replace(
            self.contributions[0], feldman_commitment=(1, 1)
        )
        self.assert_aggregator_and_diagnoser_raise(
            [bad, self.contributions[1], self.contributions[2]], TypeError
        )

    def test_wrong_nested_field_type_is_type_error(self):
        bad_dealing = dataclasses.replace(
            self.contributions[0].contribution,
            shares=list(self.contributions[0].contribution.shares),
        )
        bad = dataclasses.replace(self.contributions[0], contribution=bad_dealing)
        self.assert_aggregator_and_diagnoser_raise(
            [bad, self.contributions[1], self.contributions[2]], TypeError
        )


class DiagnoseNoMutationTest(unittest.TestCase):
    def setUp(self):
        self.contributions = make_contributions()

    def test_input_list_unchanged_on_success(self):
        contributions = self.contributions
        snapshot = copy.deepcopy(contributions)
        diagnose_signing_contributions(contributions)
        self.assertEqual(contributions, snapshot)

    def test_input_list_unchanged_with_faults(self):
        bad = tamper_sharing_share(self.contributions[1], 0)
        contributions = [self.contributions[0], bad, self.contributions[2]]
        snapshot = copy.deepcopy(contributions)
        diagnose_signing_contributions(contributions)
        self.assertEqual(contributions, snapshot)

    def test_input_unchanged_on_value_error(self):
        bad_feldman = dataclasses.replace(
            self.contributions[0].feldman_commitment, values=(0, 1)
        )
        bad = dataclasses.replace(self.contributions[0], feldman_commitment=bad_feldman)
        contributions = [bad, self.contributions[1], self.contributions[2]]
        snapshot = copy.deepcopy(contributions)
        with self.assertRaises(ValueError):
            diagnose_signing_contributions(contributions)
        self.assertEqual(contributions, snapshot)


if __name__ == "__main__":
    unittest.main()
