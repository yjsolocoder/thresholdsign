"""Tests for the refresh contribution pre-aggregation diagnoser."""

import copy
import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    DKGRejection,
    FeldmanCommitment,
    RefreshFault,
    Share,
    SigningDKGResult,
    aggregate_signing_dkg,
    create_refresh,
    create_signing_contribution,
    decode_signing_contribution,
    diagnose_refresh_contributions,
    encode_signing_contribution,
    refresh,
)

# Same toy group as the refresh tests: 8069 = 4 * 2017 + 1 is prime and
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
    """Deterministic stand-in for secrets.randbelow (same LCG as refresh tests)."""
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


def make_refresh_contributions(key, seed_base=100):
    return [
        create_refresh(pid, key, randbelow=fixed_random(pid + seed_base))
        for pid in key.result.participant_ids
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


def shift_feldman_constant(contribution):
    """Multiply the Feldman constant-term commitment by the generator."""
    feldman = contribution.feldman_commitment
    return dataclasses.replace(
        contribution,
        feldman_commitment=FeldmanCommitment(
            values=(feldman.values[0] * GENERATOR % GROUP_PRIME,)
            + feldman.values[1:],
            field_prime=feldman.field_prime,
            group_prime=feldman.group_prime,
            generator=feldman.generator,
        ),
    )


class RefreshFaultValueTest(unittest.TestCase):
    def test_positionally_constructible(self):
        fault = RefreshFault(2, "pedersen", 3)
        self.assertEqual(
            (fault.sender_id, fault.check, fault.receiver_id), (2, "pedersen", 3)
        )

    def test_fields_in_declared_order(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(RefreshFault)],
            ["sender_id", "check", "receiver_id"],
        )

    def test_compared_by_value(self):
        self.assertEqual(
            RefreshFault(1, "constant", None), RefreshFault(1, "constant", None)
        )
        self.assertNotEqual(
            RefreshFault(1, "pedersen", 2), RefreshFault(1, "feldman", 2)
        )
        self.assertNotEqual(
            RefreshFault(1, "pedersen", 2), RefreshFault(1, "pedersen", 3)
        )
        self.assertNotEqual(
            RefreshFault(1, "pedersen", 2), RefreshFault(2, "pedersen", 2)
        )
        self.assertNotEqual(
            RefreshFault(1, "pedersen", 2), RefreshFault(1, "constant", None)
        )
        self.assertEqual(
            {
                RefreshFault(1, "constant", None),
                RefreshFault(1, "constant", None),
            },
            {RefreshFault(1, "constant", None)},
        )

    def test_hashable_with_none_receiver(self):
        self.assertEqual(
            hash(RefreshFault(1, "constant", None)),
            hash(RefreshFault(1, "constant", None)),
        )

    def test_frozen(self):
        fault = RefreshFault(1, "pedersen", 2)
        with self.assertRaises(FrozenInstanceError):
            fault.check = "constant"  # type: ignore[misc]
        constant = RefreshFault(1, "constant", None)
        with self.assertRaises(FrozenInstanceError):
            constant.receiver_id = 2  # type: ignore[misc]


class DiagnoseRefreshSuccessTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.contributions = make_refresh_contributions(self.key)

    def test_valid_set_returns_empty_tuple(self):
        faults = diagnose_refresh_contributions(self.contributions, self.key)
        self.assertEqual(faults, ())
        self.assertIsInstance(faults, tuple)

    def test_empty_faults_exactly_when_refresh_succeeds(self):
        self.assertIsInstance(
            refresh(list(self.contributions), self.key), SigningDKGResult
        )
        self.assertEqual(
            diagnose_refresh_contributions(self.contributions, self.key), ()
        )

    def test_threshold_one(self):
        key = make_key((1, 2), 1)
        contributions = make_refresh_contributions(key)
        self.assertEqual(diagnose_refresh_contributions(contributions, key), ())

    def test_non_consecutive_participant_ids(self):
        key = make_key((2, 5, 9), 2)
        contributions = make_refresh_contributions(key)
        self.assertEqual(diagnose_refresh_contributions(contributions, key), ())
        self.assertIsInstance(refresh(list(contributions), key), SigningDKGResult)

    def test_accepts_any_input_order_and_one_shot_iterators(self):
        self.assertEqual(
            diagnose_refresh_contributions(
                iter(list(reversed(self.contributions))), self.key
            ),
            diagnose_refresh_contributions(self.contributions, self.key),
        )
        self.assertEqual(
            diagnose_refresh_contributions(
                (item for item in self.contributions), self.key
            ),
            (),
        )

    def test_codec_round_tripped_contributions(self):
        restored = [
            decode_signing_contribution(encode_signing_contribution(contribution))
            for contribution in self.contributions
        ]
        self.assertEqual(diagnose_refresh_contributions(restored, self.key), ())


class DiagnoseRefreshFaultTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.contributions = make_refresh_contributions(self.key)

    def test_tampered_blinding_share_is_pedersen_fault_only(self):
        bad = tamper_blinding_share(self.contributions[1], 0)
        faults = diagnose_refresh_contributions(
            [self.contributions[0], bad, self.contributions[2]], self.key
        )
        self.assertEqual(faults, (RefreshFault(2, "pedersen", 1),))

    def test_tampered_sharing_share_is_both_faults_pedersen_first(self):
        bad = tamper_sharing_share(self.contributions[1], 0)
        faults = diagnose_refresh_contributions(
            [self.contributions[0], bad, self.contributions[2]], self.key
        )
        self.assertEqual(
            faults,
            (
                RefreshFault(2, "pedersen", 1),
                RefreshFault(2, "feldman", 1),
            ),
        )

    def test_several_positions_of_one_sender_all_reported(self):
        bad = tamper_sharing_share(self.contributions[0], 0)
        bad = tamper_sharing_share(bad, 2)
        faults = diagnose_refresh_contributions(
            [bad, self.contributions[1], self.contributions[2]], self.key
        )
        self.assertEqual(
            faults,
            (
                RefreshFault(1, "pedersen", 1),
                RefreshFault(1, "feldman", 1),
                RefreshFault(1, "pedersen", 3),
                RefreshFault(1, "feldman", 3),
            ),
        )

    def test_one_bad_position_does_not_mask_others(self):
        bad = tamper_sharing_share(self.contributions[1], 0)
        bad = tamper_blinding_share(bad, 2)
        faults = diagnose_refresh_contributions(
            [self.contributions[0], bad, self.contributions[2]], self.key
        )
        self.assertEqual(
            faults,
            (
                RefreshFault(2, "pedersen", 1),
                RefreshFault(2, "feldman", 1),
                RefreshFault(2, "pedersen", 3),
            ),
        )

    def test_wrong_feldman_constant_is_constant_fault_last(self):
        shifted = shift_feldman_constant(self.contributions[0])
        faults = diagnose_refresh_contributions(
            [shifted, self.contributions[1], self.contributions[2]], self.key
        )
        # The shifted constant also breaks the Feldman evaluation at every
        # position; those position faults precede the single constant fault.
        self.assertEqual(
            faults,
            (
                RefreshFault(1, "feldman", 1),
                RefreshFault(1, "feldman", 2),
                RefreshFault(1, "feldman", 3),
                RefreshFault(1, "constant", None),
            ),
        )
        self.assertEqual(
            refresh([shifted, self.contributions[1], self.contributions[2]], self.key),
            [DKGRejection(sender_id=1)],
        )

    def test_self_consistent_wrong_constant_is_constant_fault_only(self):
        # An ordinary signing contribution is internally consistent (every
        # position passes both commitments) but its constant term is random,
        # so only the constant check fails.
        ordinary = create_signing_contribution(
            1,
            (1, 2, 3),
            2,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            blinding_generator=BLINDING_GENERATOR,
            randbelow=fixed_random(42),
        )
        faults = diagnose_refresh_contributions(
            [ordinary, self.contributions[1], self.contributions[2]], self.key
        )
        self.assertEqual(faults, (RefreshFault(1, "constant", None),))
        self.assertEqual(
            refresh([ordinary, self.contributions[1], self.contributions[2]], self.key),
            [DKGRejection(sender_id=1)],
        )

    def test_position_and_constant_failures_of_one_sender_all_returned(self):
        # Tamper a blinding share (Pedersen fails, the share still matches the
        # Feldman commitment) AND shift the Feldman constant of the same
        # sender (Feldman fails at every position plus the constant check).
        bad = shift_feldman_constant(tamper_blinding_share(self.contributions[0], 0))
        faults = diagnose_refresh_contributions(
            [bad, self.contributions[1], self.contributions[2]], self.key
        )
        self.assertEqual(
            faults,
            (
                RefreshFault(1, "pedersen", 1),
                RefreshFault(1, "feldman", 1),
                RefreshFault(1, "feldman", 2),
                RefreshFault(1, "feldman", 3),
                RefreshFault(1, "constant", None),
            ),
        )

    def test_fault_order_is_sender_then_receiver_then_check_constant_last(self):
        bad_first = tamper_sharing_share(self.contributions[2], 1)
        bad_second = shift_feldman_constant(self.contributions[0])
        one_order = [bad_first, self.contributions[1], bad_second]
        other_order = [bad_second, bad_first, self.contributions[1]]
        expected = (
            RefreshFault(1, "feldman", 1),
            RefreshFault(1, "feldman", 2),
            RefreshFault(1, "feldman", 3),
            RefreshFault(1, "constant", None),
            RefreshFault(3, "pedersen", 2),
            RefreshFault(3, "feldman", 2),
        )
        self.assertEqual(
            diagnose_refresh_contributions(one_order, self.key), expected
        )
        self.assertEqual(
            diagnose_refresh_contributions(other_order, self.key), expected
        )
        self.assertEqual(
            diagnose_refresh_contributions(reversed(one_order), self.key), expected
        )

    def test_fault_senders_match_refresh_rejections(self):
        bad_1 = tamper_blinding_share(self.contributions[0], 0)
        bad_3 = tamper_sharing_share(self.contributions[2], 1)
        used = [bad_1, self.contributions[1], bad_3]
        outcome = refresh(list(used), self.key)
        self.assertEqual(
            outcome, [DKGRejection(sender_id=1), DKGRejection(sender_id=3)]
        )
        faults = diagnose_refresh_contributions(used, self.key)
        self.assertEqual(
            sorted({fault.sender_id for fault in faults}),
            [rejection.sender_id for rejection in outcome],
        )


class DiagnoseRefreshValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.contributions = make_refresh_contributions(self.key)

    def assert_refresh_and_diagnoser_raise(self, contributions, error):
        with self.assertRaises(error):
            refresh(list(contributions), self.key)
        with self.assertRaises(error):
            diagnose_refresh_contributions(contributions, self.key)

    def test_wrong_key_type_is_type_error(self):
        for bad_key in ("not a key", None):
            with self.assertRaises(TypeError):
                diagnose_refresh_contributions(self.contributions, bad_key)

    def test_wrong_element_type_is_type_error(self):
        self.assert_refresh_and_diagnoser_raise(["nope"], TypeError)

    def test_plain_dkg_contribution_element_is_type_error(self):
        self.assert_refresh_and_diagnoser_raise(
            [contribution.contribution for contribution in self.contributions],
            TypeError,
        )

    def test_empty_input_is_value_error(self):
        self.assert_refresh_and_diagnoser_raise([], ValueError)

    def test_missing_and_duplicate_senders(self):
        self.assert_refresh_and_diagnoser_raise(self.contributions[:2], ValueError)
        self.assert_refresh_and_diagnoser_raise(
            [self.contributions[0], self.contributions[0], self.contributions[2]],
            ValueError,
        )

    def test_participant_set_mismatch_is_value_error(self):
        other_key = make_key((1, 2, 4))
        other = make_refresh_contributions(other_key)
        self.assert_refresh_and_diagnoser_raise(
            [other[0], self.contributions[1], other[2]], ValueError
        )

    def test_threshold_mismatch_is_value_error(self):
        other_key = make_key((1, 2, 3), threshold=1)
        other = make_refresh_contributions(other_key)
        self.assert_refresh_and_diagnoser_raise(other, ValueError)

    def test_group_parameter_mismatch_is_value_error(self):
        other_key = make_key(
            (1, 2, 3), 2,
            field_prime=LARGE_FIELD, group_prime=LARGE_GROUP,
            generator=LARGE_G, blinding_generator=LARGE_H,
        )
        other = make_refresh_contributions(other_key)
        self.assert_refresh_and_diagnoser_raise(
            [self.contributions[0], other[1], self.contributions[2]], ValueError
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
        self.assert_refresh_and_diagnoser_raise(
            [bad, self.contributions[1], self.contributions[2]], ValueError
        )

    def test_illegal_commitment_value_is_value_error(self):
        bad_feldman = dataclasses.replace(
            self.contributions[0].feldman_commitment, values=(0, 1)
        )
        bad = dataclasses.replace(
            self.contributions[0], feldman_commitment=bad_feldman
        )
        self.assert_refresh_and_diagnoser_raise(
            [bad, self.contributions[1], self.contributions[2]], ValueError
        )

    def test_malformed_key_is_type_error(self):
        bad_key = dataclasses.replace(self.key, public_key="1")
        with self.assertRaises(TypeError):
            diagnose_refresh_contributions(self.contributions, bad_key)


class DiagnoseRefreshNoMutationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.contributions = make_refresh_contributions(self.key)

    def test_input_unchanged_on_success(self):
        snapshot = copy.deepcopy(self.contributions)
        diagnose_refresh_contributions(self.contributions, self.key)
        self.assertEqual(self.contributions, snapshot)

    def test_input_unchanged_with_faults(self):
        bad = tamper_sharing_share(self.contributions[1], 0)
        contributions = [self.contributions[0], bad, self.contributions[2]]
        snapshot = copy.deepcopy(contributions)
        diagnose_refresh_contributions(contributions, self.key)
        self.assertEqual(contributions, snapshot)

    def test_input_unchanged_on_value_error(self):
        contributions = self.contributions[:2]
        snapshot = copy.deepcopy(contributions)
        with self.assertRaises(ValueError):
            diagnose_refresh_contributions(contributions, self.key)
        self.assertEqual(contributions, snapshot)


if __name__ == "__main__":
    unittest.main()
