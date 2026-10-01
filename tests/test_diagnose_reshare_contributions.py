"""Tests for the resharing contribution pre-aggregation diagnoser."""

import copy
import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    DKGRejection,
    ReshareFault,
    Share,
    SigningDKGResult,
    create_reshare,
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


def make_key(participant_ids=(1, 2, 3), threshold=2, seed_base=0):
    from thresholdsign import aggregate_signing_dkg, create_signing_contribution

    contributions = [
        create_signing_contribution(
            pid,
            participant_ids,
            threshold,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            blinding_generator=BLINDING_GENERATOR,
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


def shift_feldman_constant(contribution, factor):
    """Multiply the Feldman constant term by ``factor`` (binding breaks)."""
    feldman = contribution.feldman_commitment
    shifted = dataclasses.replace(
        feldman,
        values=(feldman.values[0] * factor % GROUP_PRIME,) + feldman.values[1:],
    )
    return dataclasses.replace(contribution, feldman_commitment=shifted)


def shift_dealt_constant(contribution, delta):
    """Add ``delta`` to the dealer's whole sharing polynomial, consistently.

    Every sharing share gains ``delta`` and both commitment constant terms
    gain ``g ** delta``, so every position still verifies against both
    commitments but the Feldman constant is no longer ``Y_i ** lambda_i``:
    a binding-only fault.
    """
    dealing = contribution.contribution
    new_shares = tuple(
        Share(share.x, (share.y + delta) % FIELD_PRIME) for share in dealing.shares
    )
    group_factor = pow(GENERATOR, delta, GROUP_PRIME)
    new_pedersen = dataclasses.replace(
        dealing.commitment,
        values=(dealing.commitment.values[0] * group_factor % GROUP_PRIME,)
        + dealing.commitment.values[1:],
    )
    new_feldman = dataclasses.replace(
        contribution.feldman_commitment,
        values=(contribution.feldman_commitment.values[0] * group_factor % GROUP_PRIME,)
        + contribution.feldman_commitment.values[1:],
    )
    new_dealing = dataclasses.replace(
        dealing, shares=new_shares, commitment=new_pedersen
    )
    return dataclasses.replace(
        contribution, contribution=new_dealing, feldman_commitment=new_feldman
    )


class ReshareFaultValueTest(unittest.TestCase):
    def test_positionally_constructible(self):
        fault = ReshareFault(2, "pedersen", 4)
        self.assertEqual(
            (fault.sender_id, fault.check, fault.receiver_id), (2, "pedersen", 4)
        )

    def test_fields_in_declared_order(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(ReshareFault)],
            ["sender_id", "check", "receiver_id"],
        )

    def test_binding_fault_uses_none_receiver(self):
        fault = ReshareFault(3, "binding", None)
        self.assertIsNone(fault.receiver_id)

    def test_compared_by_value(self):
        self.assertEqual(ReshareFault(1, "feldman", 2), ReshareFault(1, "feldman", 2))
        self.assertNotEqual(
            ReshareFault(1, "feldman", 2), ReshareFault(1, "pedersen", 2)
        )
        self.assertNotEqual(
            ReshareFault(1, "feldman", 2), ReshareFault(1, "feldman", 3)
        )
        self.assertNotEqual(
            ReshareFault(1, "feldman", 2), ReshareFault(2, "feldman", 2)
        )
        self.assertNotEqual(
            ReshareFault(1, "binding", None), ReshareFault(1, "feldman", None)
        )
        self.assertEqual(
            {ReshareFault(1, "binding", None), ReshareFault(1, "binding", None)},
            {ReshareFault(1, "binding", None)},
        )

    def test_frozen(self):
        fault = ReshareFault(1, "pedersen", 2)
        with self.assertRaises(FrozenInstanceError):
            fault.check = "binding"  # type: ignore[misc]


class DiagnoseSuccessTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.dealers = (1, 2)
        self.members = (1, 2, 4)
        self.threshold = 2
        self.contributions = make_reshare_contributions(
            self.key, self.dealers, self.members, self.threshold
        )

    def test_valid_set_returns_empty_tuple(self):
        faults = diagnose_reshare_contributions(
            self.contributions, self.dealers, self.key
        )
        self.assertEqual(faults, ())
        self.assertIsInstance(faults, tuple)

    def test_empty_faults_exactly_when_reshare_succeeds(self):
        self.assertIsInstance(
            reshare(list(self.contributions), self.dealers, self.key),
            SigningDKGResult,
        )
        self.assertEqual(
            diagnose_reshare_contributions(self.contributions, self.dealers, self.key),
            (),
        )

    def test_threshold_one(self):
        contributions = make_reshare_contributions(
            self.key, self.dealers, self.members, 1
        )
        self.assertEqual(
            diagnose_reshare_contributions(contributions, self.dealers, self.key), ()
        )

    def test_more_dealers_than_old_threshold(self):
        dealers = (1, 2, 3)
        members = (1, 2, 3, 4)
        contributions = make_reshare_contributions(self.key, dealers, members, 2)
        self.assertEqual(
            diagnose_reshare_contributions(contributions, dealers, self.key), ()
        )

    def test_accepts_any_iterable_and_any_input_order(self):
        shuffled = [self.contributions[1], self.contributions[0]]
        self.assertEqual(
            diagnose_reshare_contributions(
                iter(reversed(self.contributions)), self.dealers, self.key
            ),
            diagnose_reshare_contributions(shuffled, iter(self.dealers), self.key),
        )


class DiagnoseFaultTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.dealers = (1, 2)
        self.members = (1, 2, 4)
        self.threshold = 2
        self.contributions = make_reshare_contributions(
            self.key, self.dealers, self.members, self.threshold
        )

    def diagnose(self, contributions, dealers=None):
        return diagnose_reshare_contributions(
            contributions, self.dealers if dealers is None else dealers, self.key
        )

    def test_tampered_blinding_share_is_pedersen_fault_only(self):
        bad = tamper_blinding_share(self.contributions[1], 0)
        self.assertEqual(
            self.diagnose([self.contributions[0], bad]),
            (ReshareFault(2, "pedersen", 1),),
        )

    def test_tampered_sharing_share_is_both_faults_pedersen_first(self):
        bad = tamper_sharing_share(self.contributions[1], 0)
        self.assertEqual(
            self.diagnose([self.contributions[0], bad]),
            (
                ReshareFault(2, "pedersen", 1),
                ReshareFault(2, "feldman", 1),
            ),
        )

    def test_several_positions_of_one_dealer_all_reported(self):
        bad = tamper_sharing_share(self.contributions[0], 0)
        bad = tamper_sharing_share(bad, 2)
        self.assertEqual(
            self.diagnose([bad, self.contributions[1]]),
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
        self.assertEqual(
            self.diagnose([self.contributions[0], bad]),
            (
                ReshareFault(2, "pedersen", 1),
                ReshareFault(2, "feldman", 1),
                ReshareFault(2, "pedersen", 4),
            ),
        )

    def test_unbound_feldman_is_feldman_fault_at_every_position_no_binding(self):
        # Another resharing Feldman commitment of the same dealer keeps the
        # same (deterministic) constant term, so only the positions fail.
        other = make_reshare_contributions(
            self.key, self.dealers, self.members, self.threshold, seed_base=900
        )
        bad = dataclasses.replace(
            self.contributions[0],
            feldman_commitment=other[0].feldman_commitment,
        )
        self.assertEqual(
            self.diagnose([bad, self.contributions[1]]),
            (
                ReshareFault(1, "feldman", 1),
                ReshareFault(1, "feldman", 2),
                ReshareFault(1, "feldman", 4),
            ),
        )
        self.assertEqual(
            reshare([bad, self.contributions[1]], self.dealers, self.key),
            [DKGRejection(sender_id=1)],
        )

    def test_wrong_constant_gives_position_faults_and_then_binding_fault(self):
        bad = shift_feldman_constant(self.contributions[0], GENERATOR)
        self.assertEqual(
            self.diagnose([bad, self.contributions[1]]),
            (
                ReshareFault(1, "feldman", 1),
                ReshareFault(1, "feldman", 2),
                ReshareFault(1, "feldman", 4),
                ReshareFault(1, "binding", None),
            ),
        )
        self.assertEqual(
            reshare([bad, self.contributions[1]], self.dealers, self.key),
            [DKGRejection(sender_id=1)],
        )

    def test_consistent_polynomial_with_wrong_constant_is_binding_fault_only(self):
        bad = shift_dealt_constant(self.contributions[0], 7)
        self.assertEqual(
            self.diagnose([bad, self.contributions[1]]),
            (ReshareFault(1, "binding", None),),
        )
        self.assertEqual(
            reshare([bad, self.contributions[1]], self.dealers, self.key),
            [DKGRejection(sender_id=1)],
        )

    def test_position_faults_in_two_dealers_with_binding_last_each(self):
        bad_first = shift_feldman_constant(self.contributions[1], GENERATOR)
        bad_second = tamper_blinding_share(self.contributions[0], 1)
        expected = (
            ReshareFault(1, "pedersen", 2),
            ReshareFault(2, "feldman", 1),
            ReshareFault(2, "feldman", 2),
            ReshareFault(2, "feldman", 4),
            ReshareFault(2, "binding", None),
        )
        one_order = [bad_first, bad_second]
        other_order = [bad_second, bad_first]
        self.assertEqual(self.diagnose(one_order), expected)
        self.assertEqual(self.diagnose(other_order), expected)
        self.assertEqual(self.diagnose(list(reversed(one_order))), expected)

    def test_fault_order_is_sender_receiver_check_binding(self):
        bad = tamper_sharing_share(self.contributions[0], 2)
        bad = shift_dealt_constant(bad, 3)
        expected = (
            ReshareFault(1, "pedersen", 4),
            ReshareFault(1, "feldman", 4),
            ReshareFault(1, "binding", None),
        )
        self.assertEqual(self.diagnose([bad, self.contributions[1]]), expected)
        self.assertEqual(
            self.diagnose([self.contributions[1], bad]), expected
        )

    def test_rejected_dealer_lists_all_failures(self):
        # Position faults at two receivers plus a binding fault: all appear,
        # even though reshare names the dealer only once.
        bad = tamper_sharing_share(self.contributions[1], 0)
        bad = tamper_sharing_share(bad, 2)
        bad = shift_dealt_constant(bad, 5)
        contributions = [self.contributions[0], bad]
        self.assertEqual(
            reshare(contributions, self.dealers, self.key),
            [DKGRejection(sender_id=2)],
        )
        self.assertEqual(
            self.diagnose(contributions),
            (
                ReshareFault(2, "pedersen", 1),
                ReshareFault(2, "feldman", 1),
                ReshareFault(2, "pedersen", 4),
                ReshareFault(2, "feldman", 4),
                ReshareFault(2, "binding", None),
            ),
        )

    def test_fault_senders_match_reshare_rejection_senders(self):
        bad_1 = tamper_blinding_share(self.contributions[0], 0)
        bad_2 = shift_dealt_constant(self.contributions[1], 9)
        contributions = [bad_2, bad_1]
        outcome = reshare(contributions, self.dealers, self.key)
        self.assertEqual(
            outcome, [DKGRejection(sender_id=1), DKGRejection(sender_id=2)]
        )
        faults = self.diagnose(contributions)
        self.assertEqual(
            sorted({fault.sender_id for fault in faults}),
            [rejection.sender_id for rejection in outcome],
        )


class DiagnoseValidationTest(unittest.TestCase):
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

    def test_wrong_key_type_raises_type_error(self):
        for bad_key in ("not a key", None):
            with self.assertRaises(TypeError):
                diagnose_reshare_contributions(self.contributions, self.dealers, bad_key)

    def test_malformed_key_raises_type_error(self):
        bad_key = dataclasses.replace(self.key, public_key="1")
        with self.assertRaises(TypeError):
            diagnose_reshare_contributions(
                self.contributions, self.dealers, bad_key
            )

    def test_plain_dkg_contribution_element_raises_type_error(self):
        self.assert_reshare_and_diagnoser_raise(
            [c.contribution for c in self.contributions], self.dealers, TypeError
        )
        self.assert_reshare_and_diagnoser_raise(["nope"], self.dealers, TypeError)

    def test_wrong_nested_field_type_raises_type_error(self):
        bad_dealing = dataclasses.replace(
            self.contributions[0].contribution,
            shares=list(self.contributions[0].contribution.shares),
        )
        bad = dataclasses.replace(self.contributions[0], contribution=bad_dealing)
        self.assert_reshare_and_diagnoser_raise(
            [bad, self.contributions[1]], self.dealers, TypeError
        )

    def test_empty_input_raises_value_error(self):
        self.assert_reshare_and_diagnoser_raise([], self.dealers, ValueError)

    def test_dealer_list_validation(self):
        for dealers in ((), (1,), (2, 1), (1, 1), (1, 9)):
            self.assert_reshare_and_diagnoser_raise(
                self.contributions, dealers, ValueError
            )

    def test_dealer_list_wrong_types_raise_type_error(self):
        self.assert_reshare_and_diagnoser_raise(
            self.contributions, "12", TypeError
        )
        self.assert_reshare_and_diagnoser_raise(
            self.contributions, (1, "2"), TypeError
        )

    def test_missing_and_duplicate_dealers_raise_value_error(self):
        self.assert_reshare_and_diagnoser_raise(
            self.contributions[:1], self.dealers, ValueError
        )
        self.assert_reshare_and_diagnoser_raise(
            [self.contributions[0], self.contributions[0]], self.dealers, ValueError
        )
        extra = create_reshare(
            3,
            secret_share_of(self.key, 3),
            (1, 2, 3),
            (1, 2, 3),
            2,
            self.key,
            rng=fixed_random(3),
        )
        self.assert_reshare_and_diagnoser_raise(
            [self.contributions[0], extra], self.dealers, ValueError
        )

    def test_member_set_mismatch_raises_value_error(self):
        other = make_reshare_contributions(self.key, self.dealers, (1, 2, 5), 2)
        self.assert_reshare_and_diagnoser_raise(
            [self.contributions[0], other[1]], self.dealers, ValueError
        )

    def test_threshold_mismatch_raises_value_error(self):
        other = make_reshare_contributions(
            self.key, self.dealers, self.members, 1
        )
        self.assert_reshare_and_diagnoser_raise(
            [self.contributions[0], other[1]], self.dealers, ValueError
        )

    def test_group_parameter_mismatch_raises_value_error(self):
        # A contribution over a different (large) group cannot be mixed with
        # the toy-group old key.
        large_old = _make_large_key()
        other = make_reshare_contributions(large_old, (1, 2), (1, 2, 4), 2)
        self.assert_reshare_and_diagnoser_raise(
            [self.contributions[0], other[1]], self.dealers, ValueError
        )

    def test_illegal_feldman_value_raises_value_error(self):
        bad_feldman = dataclasses.replace(
            self.contributions[0].feldman_commitment, values=(0, 1)
        )
        bad = dataclasses.replace(self.contributions[0], feldman_commitment=bad_feldman)
        self.assert_reshare_and_diagnoser_raise(
            [bad, self.contributions[1]], self.dealers, ValueError
        )

    def test_feldman_wrong_threshold_raises_value_error(self):
        feldman = self.contributions[0].feldman_commitment
        bad_feldman = dataclasses.replace(
            feldman, values=feldman.values + (feldman.values[0],)
        )
        bad = dataclasses.replace(self.contributions[0], feldman_commitment=bad_feldman)
        self.assert_reshare_and_diagnoser_raise(
            [bad, self.contributions[1]], self.dealers, ValueError
        )

    def test_illegal_share_coordinate_raises_value_error(self):
        dealing = self.contributions[0].contribution
        bad_dealing = dataclasses.replace(
            dealing,
            shares=(Share(0, dealing.shares[0].y),) + dealing.shares[1:],
        )
        bad = dataclasses.replace(self.contributions[0], contribution=bad_dealing)
        self.assert_reshare_and_diagnoser_raise(
            [bad, self.contributions[1]], self.dealers, ValueError
        )

    def test_unsorted_participant_ids_raises_value_error(self):
        dealing = self.contributions[0].contribution
        bad_dealing = dataclasses.replace(
            dealing, participant_ids=(2, 1, 4)
        )
        bad = dataclasses.replace(self.contributions[0], contribution=bad_dealing)
        self.assert_reshare_and_diagnoser_raise(
            [bad, self.contributions[1]], self.dealers, ValueError
        )


def _make_large_key():
    from thresholdsign import aggregate_signing_dkg, create_signing_contribution

    contributions = [
        create_signing_contribution(
            pid,
            (1, 2, 3),
            2,
            prime=LARGE_FIELD,
            group_prime=LARGE_GROUP,
            generator=LARGE_G,
            blinding_generator=LARGE_H,
            randbelow=fixed_random(pid),
        )
        for pid in (1, 2, 3)
    ]
    outcome = aggregate_signing_dkg(contributions)
    assert isinstance(outcome, SigningDKGResult), outcome
    return outcome


class DiagnoseNoMutationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.dealers = (1, 2)
        self.members = (1, 2, 4)
        self.threshold = 2
        self.contributions = make_reshare_contributions(
            self.key, self.dealers, self.members, self.threshold
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
        bad_feldman = dataclasses.replace(
            self.contributions[0].feldman_commitment, values=(0, 1)
        )
        bad = dataclasses.replace(self.contributions[0], feldman_commitment=bad_feldman)
        contributions = [bad, self.contributions[1]]
        snapshot = copy.deepcopy(contributions)
        with self.assertRaises(ValueError):
            diagnose_reshare_contributions(contributions, self.dealers, self.key)
        self.assertEqual(contributions, snapshot)


class DiagnoseParityTest(unittest.TestCase):
    """Empty-faults-iff-success over a battery of legal but tampered inputs."""

    def setUp(self):
        self.key = make_key()
        self.dealers = (1, 2)
        self.members = (1, 2, 4)
        self.contributions = make_reshare_contributions(
            self.key, self.dealers, self.members, 2
        )

    def test_parity_across_tamperings(self):
        variants = [
            self.contributions,
            [tamper_blinding_share(self.contributions[0], 0), self.contributions[1]],
            [tamper_sharing_share(self.contributions[0], 1), self.contributions[1]],
            [self.contributions[0], tamper_sharing_share(self.contributions[1], 2)],
            [
                shift_dealt_constant(self.contributions[0], 4),
                self.contributions[1],
            ],
            [
                self.contributions[0],
                shift_feldman_constant(self.contributions[1], GENERATOR),
            ],
        ]
        for contributions in variants:
            outcome = reshare(list(contributions), self.dealers, self.key)
            faults = diagnose_reshare_contributions(
                contributions, self.dealers, self.key
            )
            if isinstance(outcome, SigningDKGResult):
                self.assertEqual(faults, ())
            else:
                self.assertTrue(faults)
                rejected = {item.sender_id for item in outcome}
                blamed = {fault.sender_id for fault in faults}
                self.assertEqual(blamed, rejected)


if __name__ == "__main__":
    unittest.main()
