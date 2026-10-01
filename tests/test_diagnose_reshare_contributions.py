"""Tests for the resharing contribution pre-aggregation diagnoser."""

import copy
import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    DKGRejection,
    FeldmanCommitment,
    ReshareFault,
    Share,
    SigningDKGResult,
    aggregate_signing_dkg,
    create_reshare,
    create_signing_contribution,
    diagnose_reshare_contributions,
    reshare,
)

# Same toy group as the reshare tests: 8069 = 4 * 2017 + 1 is prime and
# 16, 256 = 16 ** 2 generate the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

LARGE_FIELD = 1000151
LARGE_GROUP = 2000303
LARGE_G = 9
LARGE_H = 81


def fixed_random(seed=1):
    """Deterministic stand-in for secrets.randbelow (same LCG as reshare tests)."""
    state = {"value": seed}

    def randbelow(upper: int) -> int:
        state["value"] = (
            state["value"] * 6364136223846793005 + 1442695040888963407
        ) % upper
        return state["value"]

    return randbelow


def make_key(
    participant_ids=(1, 2, 3),
    threshold=2,
    field_prime=FIELD_PRIME,
    group_prime=GROUP_PRIME,
    generator=GENERATOR,
    blinding_generator=BLINDING_GENERATOR,
    seed_base=0,
):
    contributions = [
        create_signing_contribution(
            pid,
            participant_ids,
            threshold,
            prime=field_prime,
            group_prime=group_prime,
            generator=generator,
            blinding_generator=blinding_generator,
            randbelow=fixed_random(pid + seed_base),
        )
        for pid in participant_ids
    ]
    outcome = aggregate_signing_dkg(contributions)
    assert isinstance(outcome, SigningDKGResult), outcome
    return outcome


def secret_share_of(key, participant_id):
    index = key.result.participant_ids.index(participant_id)
    return key.result.shares[index].y


def make_reshare_contributions(key, dealers, members, threshold, seed_base=100):
    return [
        create_reshare(
            dealer,
            secret_share_of(key, dealer),
            dealers,
            members,
            threshold,
            key,
            rng=fixed_random(dealer + seed_base),
        )
        for dealer in dealers
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


class ReshareFaultValueTest(unittest.TestCase):
    def test_positionally_constructible(self):
        fault = ReshareFault(2, "pedersen", 3)
        self.assertEqual(
            (fault.sender_id, fault.check, fault.receiver_id), (2, "pedersen", 3)
        )

    def test_fields_in_declared_order(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(ReshareFault)],
            ["sender_id", "check", "receiver_id"],
        )

    def test_compared_by_value(self):
        self.assertEqual(
            ReshareFault(1, "binding", None), ReshareFault(1, "binding", None)
        )
        self.assertNotEqual(
            ReshareFault(1, "pedersen", 2), ReshareFault(1, "feldman", 2)
        )
        self.assertNotEqual(
            ReshareFault(1, "pedersen", 2), ReshareFault(1, "pedersen", 3)
        )
        self.assertNotEqual(
            ReshareFault(1, "pedersen", 2), ReshareFault(2, "pedersen", 2)
        )
        self.assertNotEqual(
            ReshareFault(1, "pedersen", 2), ReshareFault(1, "binding", 2)
        )
        self.assertEqual(
            {
                ReshareFault(1, "binding", None),
                ReshareFault(1, "binding", None),
            },
            {ReshareFault(1, "binding", None)},
        )

    def test_hashable_with_none_receiver(self):
        self.assertEqual(
            hash(ReshareFault(1, "binding", None)),
            hash(ReshareFault(1, "binding", None)),
        )

    def test_frozen(self):
        fault = ReshareFault(1, "pedersen", 2)
        with self.assertRaises(FrozenInstanceError):
            fault.check = "binding"  # type: ignore[misc]
        binding = ReshareFault(1, "binding", None)
        with self.assertRaises(FrozenInstanceError):
            binding.receiver_id = 2  # type: ignore[misc]


class DiagnoseReshareSuccessTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.dealers = (1, 2)
        self.members = (1, 2, 4, 5)
        self.threshold = 3

    def test_valid_set_returns_empty_tuple(self):
        contributions = make_reshare_contributions(
            self.key, self.dealers, self.members, self.threshold
        )
        faults = diagnose_reshare_contributions(contributions, self.dealers, self.key)
        self.assertEqual(faults, ())
        self.assertIsInstance(faults, tuple)

    def test_empty_faults_exactly_when_reshare_succeeds(self):
        contributions = make_reshare_contributions(
            self.key, self.dealers, self.members, self.threshold
        )
        self.assertIsInstance(
            reshare(list(contributions), self.dealers, self.key), SigningDKGResult
        )
        self.assertEqual(
            diagnose_reshare_contributions(contributions, self.dealers, self.key),
            (),
        )

    def test_threshold_one(self):
        contributions = make_reshare_contributions(
            self.key, self.dealers, self.members, 1
        )
        self.assertEqual(
            diagnose_reshare_contributions(contributions, self.dealers, self.key),
            (),
        )

    def test_more_dealers_than_old_threshold(self):
        dealers = (1, 2, 3)
        members = (1, 2, 3, 4)
        contributions = make_reshare_contributions(self.key, dealers, members, 2)
        self.assertEqual(
            diagnose_reshare_contributions(contributions, dealers, self.key), ()
        )

    def test_accepts_any_input_order(self):
        contributions = make_reshare_contributions(
            self.key, self.dealers, self.members, self.threshold
        )
        self.assertEqual(
            diagnose_reshare_contributions(
                iter(reversed(contributions)), self.dealers, self.key
            ),
            diagnose_reshare_contributions(contributions, self.dealers, self.key),
        )


class DiagnoseReshareFaultTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.dealers = (1, 2)
        self.members = (1, 2, 4)
        self.threshold = 2
        self.contributions = make_reshare_contributions(
            self.key, self.dealers, self.members, self.threshold
        )

    def test_tampered_blinding_share_is_pedersen_fault_only(self):
        bad = tamper_blinding_share(self.contributions[1], 0)
        faults = diagnose_reshare_contributions(
            [self.contributions[0], bad], self.dealers, self.key
        )
        self.assertEqual(faults, (ReshareFault(2, "pedersen", 1),))

    def test_tampered_sharing_share_is_both_faults_pedersen_first(self):
        bad = tamper_sharing_share(self.contributions[1], 0)
        faults = diagnose_reshare_contributions(
            [self.contributions[0], bad], self.dealers, self.key
        )
        self.assertEqual(
            faults,
            (
                ReshareFault(2, "pedersen", 1),
                ReshareFault(2, "feldman", 1),
            ),
        )

    def test_several_positions_of_one_dealer_all_reported(self):
        bad = tamper_sharing_share(self.contributions[0], 0)
        bad = tamper_sharing_share(bad, 2)
        faults = diagnose_reshare_contributions(
            [bad, self.contributions[1]], self.dealers, self.key
        )
        self.assertEqual(
            faults,
            (
                ReshareFault(1, "pedersen", 1),
                ReshareFault(1, "feldman", 1),
                ReshareFault(1, "pedersen", 4),
                ReshareFault(1, "feldman", 4),
            ),
        )

    def test_one_bad_position_does_not_mask_others(self):
        bad = tamper_sharing_share(self.contributions[1], 0)
        bad = tamper_blinding_share(bad, 2)
        faults = diagnose_reshare_contributions(
            [self.contributions[0], bad], self.dealers, self.key
        )
        self.assertEqual(
            faults,
            (
                ReshareFault(2, "pedersen", 1),
                ReshareFault(2, "feldman", 1),
                ReshareFault(2, "pedersen", 4),
            ),
        )

    def test_wrong_feldman_constant_is_binding_fault_last(self):
        contribution = self.contributions[0]
        feldman = contribution.feldman_commitment
        shifted = dataclasses.replace(
            contribution,
            feldman_commitment=FeldmanCommitment(
                values=(feldman.values[0] * GENERATOR % GROUP_PRIME,)
                + feldman.values[1:],
                field_prime=feldman.field_prime,
                group_prime=feldman.group_prime,
                generator=feldman.generator,
            ),
        )
        faults = diagnose_reshare_contributions(
            [shifted, self.contributions[1]], self.dealers, self.key
        )
        # The shifted constant also breaks the Feldman evaluation at every
        # position; those position faults precede the single binding fault.
        self.assertEqual(
            faults,
            (
                ReshareFault(1, "feldman", 1),
                ReshareFault(1, "feldman", 2),
                ReshareFault(1, "feldman", 4),
                ReshareFault(1, "binding", None),
            ),
        )
        self.assertEqual(
            reshare([shifted, self.contributions[1]], self.dealers, self.key),
            [DKGRejection(sender_id=1)],
        )

    def test_self_consistent_wrong_constant_is_binding_fault_only(self):
        # An ordinary signing contribution addressed to the new members is
        # internally consistent (every position passes both commitments) but
        # its constant is random, so only the binding check fails.
        ordinary = create_signing_contribution(
            1,
            self.members,
            self.threshold,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            blinding_generator=BLINDING_GENERATOR,
            randbelow=fixed_random(42),
        )
        faults = diagnose_reshare_contributions(
            [ordinary, self.contributions[1]], self.dealers, self.key
        )
        self.assertEqual(faults, (ReshareFault(1, "binding", None),))
        self.assertEqual(
            reshare([ordinary, self.contributions[1]], self.dealers, self.key),
            [DKGRejection(sender_id=1)],
        )

    def test_fault_order_is_dealer_then_receiver_then_check_binding_last(self):
        other_dealers = (1, 2, 3)
        other_members = (1, 2, 3, 4)
        contributions = make_reshare_contributions(
            self.key, other_dealers, other_members, 2
        )
        bad_first = tamper_sharing_share(contributions[2], 1)
        bad_second = tamper_sharing_share(contributions[0], 0)
        one_order = [bad_first, contributions[1], bad_second]
        other_order = [bad_second, bad_first, contributions[1]]
        expected = (
            ReshareFault(1, "pedersen", 1),
            ReshareFault(1, "feldman", 1),
            ReshareFault(3, "pedersen", 2),
            ReshareFault(3, "feldman", 2),
        )
        self.assertEqual(
            diagnose_reshare_contributions(one_order, other_dealers, self.key),
            expected,
        )
        self.assertEqual(
            diagnose_reshare_contributions(other_order, other_dealers, self.key),
            expected,
        )
        self.assertEqual(
            diagnose_reshare_contributions(
                reversed(one_order), other_dealers, self.key
            ),
            expected,
        )

    def test_position_and_binding_failures_of_one_dealer_all_returned(self):
        # Tamper a blinding share (Pedersen fails, the share still matches the
        # Feldman commitment) AND shift the Feldman constant of the same
        # dealer (Feldman fails at every position plus the binding check).
        bad = tamper_blinding_share(self.contributions[0], 0)
        feldman = bad.feldman_commitment
        bad = dataclasses.replace(
            bad,
            feldman_commitment=FeldmanCommitment(
                values=(feldman.values[0] * GENERATOR % GROUP_PRIME,)
                + feldman.values[1:],
                field_prime=feldman.field_prime,
                group_prime=feldman.group_prime,
                generator=feldman.generator,
            ),
        )
        faults = diagnose_reshare_contributions(
            [bad, self.contributions[1]], self.dealers, self.key
        )
        self.assertEqual(
            faults,
            (
                ReshareFault(1, "pedersen", 1),
                ReshareFault(1, "feldman", 1),
                ReshareFault(1, "feldman", 2),
                ReshareFault(1, "feldman", 4),
                ReshareFault(1, "binding", None),
            ),
        )

    def test_fault_senders_match_reshare_rejections(self):
        other_dealers = (1, 2, 3)
        other_members = (1, 2, 3, 4)
        contributions = make_reshare_contributions(
            self.key, other_dealers, other_members, 2
        )
        bad_1 = tamper_blinding_share(contributions[0], 0)
        bad_3 = tamper_sharing_share(contributions[2], 1)
        used = [bad_1, contributions[1], bad_3]
        outcome = reshare(used, other_dealers, self.key)
        self.assertEqual(
            outcome, [DKGRejection(sender_id=1), DKGRejection(sender_id=3)]
        )
        faults = diagnose_reshare_contributions(used, other_dealers, self.key)
        self.assertEqual(
            sorted({fault.sender_id for fault in faults}),
            [rejection.sender_id for rejection in outcome],
        )


class DiagnoseReshareValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.dealers = (1, 2)
        self.members = (1, 2, 4)
        self.threshold = 2
        self.contributions = make_reshare_contributions(
            self.key, self.dealers, self.members, self.threshold
        )

    def assert_reshare_and_diagnoser_raise(self, contributions, dealers, error):
        with self.assertRaises(error):
            reshare(list(contributions), dealers, self.key)
        with self.assertRaises(error):
            diagnose_reshare_contributions(contributions, dealers, self.key)

    def test_wrong_key_type_is_type_error(self):
        for bad_key in ("not a key", None):
            with self.assertRaises(TypeError):
                diagnose_reshare_contributions(
                    self.contributions, self.dealers, bad_key
                )

    def test_wrong_element_type_is_type_error(self):
        self.assert_reshare_and_diagnoser_raise(["nope"], self.dealers, TypeError)

    def test_plain_dkg_contribution_element_is_type_error(self):
        self.assert_reshare_and_diagnoser_raise(
            [contribution.contribution for contribution in self.contributions],
            self.dealers,
            TypeError,
        )

    def test_empty_input_is_value_error(self):
        self.assert_reshare_and_diagnoser_raise([], self.dealers, ValueError)

    def test_dealer_list_validation(self):
        self.assert_reshare_and_diagnoser_raise(
            self.contributions, (), ValueError
        )
        self.assert_reshare_and_diagnoser_raise(
            self.contributions, (1,), ValueError
        )
        self.assert_reshare_and_diagnoser_raise(
            self.contributions, (2, 1), ValueError
        )
        self.assert_reshare_and_diagnoser_raise(
            self.contributions, (1, 1), ValueError
        )
        self.assert_reshare_and_diagnoser_raise(
            self.contributions, (1, 9), ValueError
        )
        self.assert_reshare_and_diagnoser_raise(
            self.contributions, "12", TypeError
        )
        self.assert_reshare_and_diagnoser_raise(
            self.contributions, (1, "2"), TypeError
        )

    def test_missing_and_duplicate_dealers(self):
        self.assert_reshare_and_diagnoser_raise(
            self.contributions[:1], self.dealers, ValueError
        )
        self.assert_reshare_and_diagnoser_raise(
            [self.contributions[0], self.contributions[0]], self.dealers, ValueError
        )

    def test_member_set_mismatch_is_value_error(self):
        other = make_reshare_contributions(self.key, self.dealers, (1, 2, 5), 2)
        self.assert_reshare_and_diagnoser_raise(
            [self.contributions[0], other[1]], self.dealers, ValueError
        )

    def test_threshold_mismatch_is_value_error(self):
        other = make_reshare_contributions(
            self.key, self.dealers, self.members, 1
        )
        self.assert_reshare_and_diagnoser_raise(
            [self.contributions[0], other[1]], self.dealers, ValueError
        )

    def test_group_parameter_mismatch_is_value_error(self):
        other_key = make_key(
            (1, 2, 3), 2,
            field_prime=LARGE_FIELD, group_prime=LARGE_GROUP,
            generator=LARGE_G, blinding_generator=LARGE_H,
        )
        other = make_reshare_contributions(
            other_key, (1, 2), (1, 2, 4), 2
        )
        self.assert_reshare_and_diagnoser_raise(
            [self.contributions[0], other[1]], self.dealers, ValueError
        )

    def test_illegal_share_value_is_value_error(self):
        dealing = self.contributions[0].contribution
        share = dealing.shares[0]
        bad_dealing = dataclasses.replace(
            dealing,
            shares=dealing.shares[:1]
            + (Share(share.x, FIELD_PRIME),)
            + dealing.shares[2:],
        )
        bad = dataclasses.replace(self.contributions[0], contribution=bad_dealing)
        self.assert_reshare_and_diagnoser_raise(
            [bad, self.contributions[1]], self.dealers, ValueError
        )

    def test_illegal_commitment_value_is_value_error(self):
        bad_feldman = dataclasses.replace(
            self.contributions[0].feldman_commitment, values=(0, 1)
        )
        bad = dataclasses.replace(
            self.contributions[0], feldman_commitment=bad_feldman
        )
        self.assert_reshare_and_diagnoser_raise(
            [bad, self.contributions[1]], self.dealers, ValueError
        )

    def test_malformed_key_is_type_error(self):
        bad_key = dataclasses.replace(self.key, public_key="1")
        with self.assertRaises(TypeError):
            diagnose_reshare_contributions(
                self.contributions, self.dealers, bad_key
            )


class DiagnoseReshareNoMutationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.dealers = (1, 2)
        self.members = (1, 2, 4)
        self.contributions = make_reshare_contributions(
            self.key, self.dealers, self.members, 2
        )

    def test_input_unchanged_on_success(self):
        snapshot = copy.deepcopy(self.contributions)
        diagnose_reshare_contributions(self.contributions, self.dealers, self.key)
        self.assertEqual(self.contributions, snapshot)

    def test_input_unchanged_with_faults(self):
        bad = tamper_sharing_share(self.contributions[1], 0)
        contributions = [self.contributions[0], bad]
        snapshot = copy.deepcopy(contributions)
        diagnose_reshare_contributions(contributions, self.dealers, self.key)
        self.assertEqual(contributions, snapshot)

    def test_input_unchanged_on_value_error(self):
        contributions = self.contributions[:1]
        snapshot = copy.deepcopy(contributions)
        with self.assertRaises(ValueError):
            diagnose_reshare_contributions(contributions, self.dealers, self.key)
        self.assertEqual(contributions, snapshot)


if __name__ == "__main__":
    unittest.main()
