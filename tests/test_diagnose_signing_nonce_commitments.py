"""Tests for the round-one nonce commitment batch diagnoser."""

import copy
import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    SigningCommitmentFault,
    SigningNonceCommitment,
    SigningDKGResult,
    aggregate_signing_dkg,
    create_signing_contribution,
    create_signing_nonce_commitment,
    create_signing_round,
    diagnose_signing_nonce_commitments,
)

# Same toy group as the signing tests: 8069 = 4 * 2017 + 1 is prime, 16 and
# 256 = 16 ** 2 are distinct generators of the order-2017 element.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

PARTICIPANT_IDS = (1, 2, 3)
THRESHOLD = 2
MESSAGE = b"diagnose nonce commitments test message"


def fixed_random(seed=1):
    """Deterministic stand-in for secrets.randbelow (same LCG as DKG tests)."""
    state = {"value": seed}

    def randbelow(upper: int) -> int:
        state["value"] = (
            state["value"] * 6364136223846793005 + 1442695040888963407
        ) % upper
        return state["value"]

    return randbelow


def make_dkg(participant_ids=PARTICIPANT_IDS, threshold=THRESHOLD):
    contributions = [
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
    outcome = aggregate_signing_dkg(contributions)
    assert isinstance(outcome, SigningDKGResult), outcome
    return outcome


def commitments_for(dkg_result, signer_ids, seed=10):
    """Return a fresh valid commitment per requested signer, distinct R_i."""
    commitments = []
    for offset, signer_id in enumerate(signer_ids):
        commitment, _nonce = create_signing_nonce_commitment(
            signer_id,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            randbelow=fixed_random(seed + 100 * offset + signer_id),
        )
        commitments.append(commitment)
    return commitments


class SigningCommitmentFaultValueTest(unittest.TestCase):
    def test_positionally_constructible(self):
        fault = SigningCommitmentFault(2, "missing")
        self.assertEqual((fault.signer_id, fault.check), (2, "missing"))

    def test_fields_in_declared_order(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(SigningCommitmentFault)],
            ["signer_id", "check"],
        )

    def test_compared_by_value(self):
        self.assertEqual(
            SigningCommitmentFault(1, "range"),
            SigningCommitmentFault(1, "range"),
        )
        self.assertNotEqual(
            SigningCommitmentFault(1, "range"),
            SigningCommitmentFault(1, "subgroup"),
        )
        self.assertNotEqual(
            SigningCommitmentFault(1, "range"),
            SigningCommitmentFault(2, "range"),
        )
        self.assertEqual(
            {
                SigningCommitmentFault(1, "range"),
                SigningCommitmentFault(1, "range"),
            },
            {SigningCommitmentFault(1, "range")},
        )

    def test_frozen(self):
        fault = SigningCommitmentFault(1, "missing")
        with self.assertRaises(FrozenInstanceError):
            fault.check = "range"  # type: ignore[misc]


class DiagnoseSuccessTest(unittest.TestCase):
    def test_valid_batch_returns_empty_tuple(self):
        dkg_result = make_dkg()
        commitments = commitments_for(dkg_result, (1, 2))
        faults = diagnose_signing_nonce_commitments((1, 2), commitments, dkg_result)
        self.assertEqual(faults, ())
        self.assertIsInstance(faults, tuple)

    def test_empty_faults_exactly_when_round_creation_succeeds(self):
        dkg_result = make_dkg()
        commitments = commitments_for(dkg_result, (1, 2))
        round_info = create_signing_round(
            MESSAGE, (1, 2), commitments, dkg_result
        )
        self.assertIsNotNone(round_info)
        self.assertEqual(
            diagnose_signing_nonce_commitments((1, 2), commitments, dkg_result),
            (),
        )

    def test_threshold_one_single_signer(self):
        dkg_result = make_dkg((1, 2), threshold=1)
        commitments = commitments_for(dkg_result, (1,))
        self.assertEqual(
            diagnose_signing_nonce_commitments((1,), commitments, dkg_result),
            (),
        )

    def test_full_participant_set(self):
        dkg_result = make_dkg()
        commitments = commitments_for(dkg_result, (1, 2, 3))
        self.assertEqual(
            diagnose_signing_nonce_commitments((1, 2, 3), commitments, dkg_result),
            (),
        )

    def test_accepts_any_iterable_and_any_commitment_order(self):
        dkg_result = make_dkg()
        commitments = commitments_for(dkg_result, (1, 2, 3))
        shuffled = list(reversed(commitments))
        self.assertEqual(
            diagnose_signing_nonce_commitments(
                iter((1, 2, 3)), iter(shuffled), dkg_result
            ),
            (),
        )

    def test_inputs_not_consumed_for_repeated_calls(self):
        dkg_result = make_dkg()
        ids_iter = iter((1, 2))
        commitments = commitments_for(dkg_result, (1, 2))
        diagnose_signing_nonce_commitments(ids_iter, commitments, dkg_result)
        # Single-use iterator semantics are fine; this just checks a plain
        # re-call on a fresh iterator gives the same result.
        self.assertEqual(
            diagnose_signing_nonce_commitments(
                iter((1, 2)), commitments, dkg_result
            ),
            (),
        )


class DiagnoseFaultTest(unittest.TestCase):
    def setUp(self):
        self.dkg_result = make_dkg()
        self.commitments = commitments_for(self.dkg_result, (1, 2))

    def diagnose(self, signer_ids, commitments):
        return diagnose_signing_nonce_commitments(
            signer_ids, commitments, self.dkg_result
        )

    def test_missing_signer(self):
        faults = self.diagnose((1, 2), self.commitments[:1])
        self.assertEqual(faults, (SigningCommitmentFault(2, "missing"),))

    def test_all_missing(self):
        faults = self.diagnose((1, 2), [])
        self.assertEqual(
            faults,
            (
                SigningCommitmentFault(1, "missing"),
                SigningCommitmentFault(2, "missing"),
            ),
        )

    def test_unexpected_id(self):
        first, second = self.commitments
        # Commitment by participant 3, who is not in the expected signing set.
        three = commitments_for(self.dkg_result, (3,))[0]
        faults = self.diagnose((1, 2), [first, second, three])
        self.assertEqual(faults, (SigningCommitmentFault(3, "unexpected"),))

    def test_unexpected_id_alongside_missing(self):
        first = self.commitments[0]
        # Signer 2 publishes nothing; signer 3 publishes unexpectedly.
        three = commitments_for(self.dkg_result, (3,))[0]
        faults = self.diagnose((1, 2), [first, three])
        self.assertEqual(
            faults,
            (
                SigningCommitmentFault(2, "missing"),
                SigningCommitmentFault(3, "unexpected"),
            ),
        )

    def test_unexpected_id_sorted_after_valid_signers(self):
        bad = SigningNonceCommitment(signer_id=9, commitment=self.commitments[0].commitment)
        faults = self.diagnose(
            (1, 2), [bad, self.commitments[0], self.commitments[1]]
        )
        self.assertEqual(faults, (SigningCommitmentFault(9, "unexpected"),))

    def test_duplicate_id_all_items_named(self):
        first, second = self.commitments
        dup = SigningNonceCommitment(signer_id=1, commitment=second.commitment)
        faults = self.diagnose((1, 2), [first, dup, second])
        self.assertEqual(
            faults,
            (
                SigningCommitmentFault(1, "duplicate"),
                SigningCommitmentFault(1, "duplicate"),
            ),
        )

    def test_duplicate_id_takes_precedence_over_range(self):
        # Even if one of the duplicated items carries R_i = 1, the duplicate
        # check wins for both items.
        first, second = self.commitments
        bad_value = SigningNonceCommitment(signer_id=1, commitment=1)
        faults = self.diagnose((1, 2), [first, bad_value, second])
        self.assertEqual(
            faults,
            (
                SigningCommitmentFault(1, "duplicate"),
                SigningCommitmentFault(1, "duplicate"),
            ),
        )

    def test_duplicate_id_does_not_add_missing(self):
        first, second = self.commitments
        dup = SigningNonceCommitment(signer_id=1, commitment=second.commitment)
        faults = self.diagnose((1, 2), [first, dup])
        self.assertEqual(
            faults,
            (
                SigningCommitmentFault(1, "duplicate"),
                SigningCommitmentFault(1, "duplicate"),
                SigningCommitmentFault(2, "missing"),
            ),
        )

    def test_range_fault_R_i_is_one(self):
        first, second = self.commitments
        bad = SigningNonceCommitment(signer_id=1, commitment=1)
        faults = self.diagnose((1, 2), [bad, second])
        self.assertEqual(faults, (SigningCommitmentFault(1, "range"),))

    def test_range_fault_R_i_zero_and_group_prime(self):
        second = self.commitments[1]
        for value in (0, GROUP_PRIME, GROUP_PRIME + 1, -1):
            with self.subTest(value=value):
                bad = SigningNonceCommitment(signer_id=1, commitment=value)
                faults = self.diagnose((1, 2), [bad, second])
                self.assertEqual(
                    faults, (SigningCommitmentFault(1, "range"),)
                )

    def test_subgroup_fault_for_in_range_outside_element(self):
        second = self.commitments[1]
        # 2 is a valid residue mod 8069 but not in the order-2017 element.
        bad = SigningNonceCommitment(signer_id=1, commitment=2)
        faults = self.diagnose((1, 2), [bad, second])
        self.assertEqual(faults, (SigningCommitmentFault(1, "subgroup"),))

    def test_range_takes_precedence_over_subgroup(self):
        second = self.commitments[1]
        for value in (0, 1, GROUP_PRIME):
            with self.subTest(value=value):
                bad = SigningNonceCommitment(signer_id=1, commitment=value)
                faults = self.diagnose((1, 2), [bad, second])
                self.assertEqual(
                    faults, (SigningCommitmentFault(1, "range"),)
                )

    def test_duplicate_value_both_sides_named(self):
        first, second = self.commitments
        copied = SigningNonceCommitment(
            signer_id=2, commitment=first.commitment
        )
        faults = self.diagnose((1, 2), [first, copied])
        self.assertEqual(
            faults,
            (
                SigningCommitmentFault(1, "duplicate_value"),
                SigningCommitmentFault(2, "duplicate_value"),
            ),
        )

    def test_duplicate_value_does_not_fire_for_same_signer(self):
        # Two items with the same id and same R_i are "duplicate", never
        # duplicate_value.
        first = self.commitments[0]
        dup = SigningNonceCommitment(
            signer_id=1, commitment=first.commitment
        )
        faults = self.diagnose((1, 2), [first, dup])
        self.assertEqual(
            faults,
            (
                SigningCommitmentFault(1, "duplicate"),
                SigningCommitmentFault(1, "duplicate"),
                SigningCommitmentFault(2, "missing"),
            ),
        )

    def test_subgroup_item_not_part_of_duplicate_value(self):
        # A shared value that fails the subgroup check is reported as
        # subgroup for both, never as duplicate_value.
        bad1 = SigningNonceCommitment(signer_id=1, commitment=2)
        bad2 = SigningNonceCommitment(signer_id=2, commitment=2)
        faults = self.diagnose((1, 2), [bad1, bad2])
        self.assertEqual(
            faults,
            (
                SigningCommitmentFault(1, "subgroup"),
                SigningCommitmentFault(2, "subgroup"),
            ),
        )

    def test_mixed_faults_sorted_by_signer(self):
        first, second = self.commitments
        range_bad = SigningNonceCommitment(signer_id=1, commitment=1)
        subgroup_bad = SigningNonceCommitment(signer_id=2, commitment=2)
        unexpected = SigningNonceCommitment(
            signer_id=3, commitment=second.commitment
        )
        faults = self.diagnose((1, 2), [unexpected, subgroup_bad, range_bad])
        self.assertEqual(
            faults,
            (
                SigningCommitmentFault(1, "range"),
                SigningCommitmentFault(2, "subgroup"),
                SigningCommitmentFault(3, "unexpected"),
            ),
        )

    def test_one_fault_per_item_even_when_several_rules_apply(self):
        first, second = self.commitments
        # Duplicated unexpected id with a bad R value: only "unexpected"
        # survives per item.
        bad1 = SigningNonceCommitment(signer_id=7, commitment=1)
        bad2 = SigningNonceCommitment(signer_id=7, commitment=2)
        faults = self.diagnose(
            (1, 2), [bad1, bad2, first, second]
        )
        self.assertEqual(
            faults,
            (
                SigningCommitmentFault(7, "unexpected"),
                SigningCommitmentFault(7, "unexpected"),
            ),
        )

    def test_result_independent_of_input_order(self):
        first, second = self.commitments
        range_bad = SigningNonceCommitment(signer_id=1, commitment=1)
        missing_setup = [range_bad, second]
        expected = (SigningCommitmentFault(1, "range"),)
        self.assertEqual(self.diagnose((1, 2), list(reversed(missing_setup))), expected)
        self.assertEqual(
            self.diagnose((1, 2), iter(list(reversed(missing_setup)))), expected
        )

    def test_duplicate_value_faults_sorted_regardless_of_order(self):
        first, second = self.commitments
        copied = SigningNonceCommitment(
            signer_id=2, commitment=first.commitment
        )
        expected = (
            SigningCommitmentFault(1, "duplicate_value"),
            SigningCommitmentFault(2, "duplicate_value"),
        )
        self.assertEqual(self.diagnose((1, 2), [copied, first]), expected)
        self.assertEqual(self.diagnose((1, 2), [first, copied]), expected)


class DiagnoseEquivalenceTest(unittest.TestCase):
    """Empty faults iff create_signing_round accepts the same commitments."""

    def setUp(self):
        self.dkg_result = make_dkg()

    def assert_equivalent(self, signer_ids, commitments):
        faults = diagnose_signing_nonce_commitments(
            signer_ids, commitments, self.dkg_result
        )
        try:
            create_signing_round(
                MESSAGE, signer_ids, commitments, self.dkg_result
            )
        except (TypeError, ValueError):
            self.assertNotEqual(faults, ())
        else:
            self.assertEqual(faults, ())

    def test_missing(self):
        self.assert_equivalent(
            (1, 2), commitments_for(self.dkg_result, (1,))
        )

    def test_unexpected(self):
        commitments = commitments_for(self.dkg_result, (1, 2, 3))
        self.assert_equivalent((1, 2), commitments)

    def test_duplicate_id(self):
        commitments = commitments_for(self.dkg_result, (1, 2))
        commitments.append(commitments[0])
        self.assert_equivalent((1, 2), commitments)

    def test_range_one(self):
        commitments = commitments_for(self.dkg_result, (2,))
        commitments = [
            SigningNonceCommitment(1, 1)
        ] + commitments
        self.assert_equivalent((1, 2), commitments)

    def test_subgroup(self):
        commitments = commitments_for(self.dkg_result, (2,))
        commitments = [
            SigningNonceCommitment(1, 2)
        ] + commitments
        self.assert_equivalent((1, 2), commitments)

    def test_duplicate_value(self):
        commitments = commitments_for(self.dkg_result, (1, 2))
        commitments[1] = SigningNonceCommitment(
            2, commitments[0].commitment
        )
        self.assert_equivalent((1, 2), commitments)

    def test_valid_batch(self):
        self.assert_equivalent(
            (1, 2, 3), commitments_for(self.dkg_result, (1, 2, 3))
        )


class DiagnoseValidationTest(unittest.TestCase):
    def setUp(self):
        self.dkg_result = make_dkg()
        self.commitments = commitments_for(self.dkg_result, (1, 2))

    def assert_round_and_diagnoser_raise(self, signer_ids, commitments, error):
        with self.assertRaises(error):
            create_signing_round(
                MESSAGE, signer_ids, commitments, self.dkg_result
            )
        with self.assertRaises(error):
            diagnose_signing_nonce_commitments(
                signer_ids, commitments, self.dkg_result
            )

    def test_empty_signer_ids_is_value_error(self):
        self.assert_round_and_diagnoser_raise((), [], ValueError)

    def test_unsorted_signer_ids_is_value_error(self):
        self.assert_round_and_diagnoser_raise(
            (2, 1), list(reversed(self.commitments)), ValueError
        )

    def test_duplicate_signer_ids_is_value_error(self):
        self.assert_round_and_diagnoser_raise(
            (1, 1), self.commitments, ValueError
        )

    def test_non_participant_signer_id_is_value_error(self):
        commitments = commitments_for(self.dkg_result, (2, 3))
        self.assert_round_and_diagnoser_raise((2, 7), commitments, ValueError)

    def test_below_threshold_is_value_error(self):
        commitments = commitments_for(self.dkg_result, (3,))
        self.assert_round_and_diagnoser_raise((3,), commitments, ValueError)

    def test_non_iterable_signer_ids_is_type_error(self):
        with self.assertRaises(TypeError):
            diagnose_signing_nonce_commitments(
                1, self.commitments, self.dkg_result
            )

    def test_non_iterable_commitments_is_type_error(self):
        with self.assertRaises(TypeError):
            diagnose_signing_nonce_commitments(
                (1, 2), 7, self.dkg_result
            )

    def test_string_commitments_is_type_error(self):
        with self.assertRaises(TypeError):
            diagnose_signing_nonce_commitments(
                (1, 2), "not commitments", self.dkg_result
            )

    def test_wrong_element_type_is_type_error(self):
        with self.assertRaises(TypeError):
            diagnose_signing_nonce_commitments(
                (1, 2), ["nope"], self.dkg_result
            )

    def test_tuple_instead_of_commitment_is_type_error(self):
        with self.assertRaises(TypeError):
            diagnose_signing_nonce_commitments(
                (1, 2), [(1, self.commitments[0].commitment)], self.dkg_result
            )

    def test_wrong_commitment_field_type_is_type_error(self):
        bad = dataclasses.replace(self.commitments[0], commitment="5")
        with self.assertRaises(TypeError):
            diagnose_signing_nonce_commitments(
                (1, 2), [bad, self.commitments[1]], self.dkg_result
            )

    def test_wrong_commitment_id_field_type_is_type_error(self):
        bad = dataclasses.replace(self.commitments[0], signer_id="1")
        with self.assertRaises(TypeError):
            diagnose_signing_nonce_commitments(
                (1, 2), [bad, self.commitments[1]], self.dkg_result
            )

    def test_bool_impersonating_signer_id_in_ids_is_type_error(self):
        with self.assertRaises(TypeError):
            diagnose_signing_nonce_commitments(
                (True, 2), self.commitments, self.dkg_result
            )

    def test_bool_impersonating_commitment_id_is_type_error(self):
        bad = dataclasses.replace(self.commitments[0], signer_id=True)
        with self.assertRaises(TypeError):
            diagnose_signing_nonce_commitments(
                (1, 2), [bad, self.commitments[1]], self.dkg_result
            )

    def test_bool_impersonating_commitment_value_is_type_error(self):
        bad = dataclasses.replace(self.commitments[0], commitment=True)
        with self.assertRaises(TypeError):
            diagnose_signing_nonce_commitments(
                (1, 2), [bad, self.commitments[1]], self.dkg_result
            )

    def test_string_signer_ids_is_type_error(self):
        with self.assertRaises(TypeError):
            diagnose_signing_nonce_commitments(
                "\x01\x02", self.commitments, self.dkg_result
            )

    def test_wrong_dkg_type_is_type_error(self):
        with self.assertRaises(TypeError):
            diagnose_signing_nonce_commitments(
                (1, 2), self.commitments, object()
            )

    def test_signer_id_out_of_field_range_is_value_error(self):
        # Mirrors create_signing_round: ids must be in 1..field_prime - 1.
        with self.assertRaises(ValueError):
            diagnose_signing_nonce_commitments(
                (0, 2), self.commitments, self.dkg_result
            )
        with self.assertRaises(ValueError):
            diagnose_signing_nonce_commitments(
                (FIELD_PRIME, 2), self.commitments, self.dkg_result
            )


class DiagnoseNoMutationTest(unittest.TestCase):
    def setUp(self):
        self.dkg_result = make_dkg()

    def test_inputs_unchanged_on_success(self):
        commitments = commitments_for(self.dkg_result, (1, 2))
        snapshot = copy.deepcopy(commitments)
        diagnose_signing_nonce_commitments((1, 2), commitments, self.dkg_result)
        self.assertEqual(commitments, snapshot)

    def test_inputs_unchanged_with_faults(self):
        commitments = commitments_for(self.dkg_result, (1, 2))
        commitments.append(
            SigningNonceCommitment(1, 1)
        )
        snapshot = copy.deepcopy(commitments)
        diagnose_signing_nonce_commitments((1, 2), commitments, self.dkg_result)
        self.assertEqual(commitments, snapshot)

    def test_inputs_unchanged_on_value_error(self):
        commitments = commitments_for(self.dkg_result, (1, 2))
        snapshot = copy.deepcopy(commitments)
        with self.assertRaises(ValueError):
            diagnose_signing_nonce_commitments(
                (2, 1), commitments, self.dkg_result
            )
        self.assertEqual(commitments, snapshot)


class ExistingEntryPointsUnchangedTest(unittest.TestCase):
    def test_create_signing_round_still_assembles_valid_round(self):
        dkg_result = make_dkg()
        commitments = commitments_for(dkg_result, (1, 2))
        round_info = create_signing_round(
            MESSAGE, (1, 2), commitments, dkg_result
        )
        self.assertEqual(
            round_info.signer_ids, (1, 2)
        )
        self.assertEqual(round_info.nonce_commitments, tuple(commitments))
        expected_R = 1
        for commitment in commitments:
            expected_R = expected_R * commitment.commitment % GROUP_PRIME
        self.assertEqual(round_info.R, expected_R)

    def test_create_signing_round_still_rejects_faulty_batch(self):
        dkg_result = make_dkg()
        commitments = commitments_for(dkg_result, (1, 2))
        bad = SigningNonceCommitment(1, 1)
        with self.assertRaises(ValueError):
            create_signing_round(
                MESSAGE, (1, 2), [bad, commitments[1]], dkg_result
            )


if __name__ == "__main__":
    unittest.main()
