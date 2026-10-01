"""Tests for the round-one nonce commitment batch diagnoser."""

import copy
import dataclasses
import itertools
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    SigningCommitmentFault,
    SigningDKGResult,
    SigningNonceCommitment,
    aggregate_signature,
    aggregate_signing_dkg,
    check_audit,
    create_audit,
    create_signature_share,
    create_signing_contribution,
    create_signing_nonce_commitment,
    create_signing_round,
    diagnose_signing_nonce_commitments,
)

# Same toy group as the signing tests: 8069 = 4 * 2017 + 1 is prime, 16 and
# 256 = 16 ** 2 are distinct generators of the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

# An in-range element outside the order-2017 subgroup.
NON_SUBGROUP = 2

PARTICIPANT_IDS = (1, 2, 3)
THRESHOLD = 2
MESSAGE = b"diagnose signing nonce commitments test message"


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


def make_commitments(signer_ids=(1, 2), seed=10):
    commitments = []
    nonces = {}
    for offset, signer_id in enumerate(signer_ids):
        commitment, nonce = create_signing_nonce_commitment(
            signer_id,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            randbelow=fixed_random(seed + 100 * offset + signer_id),
        )
        commitments.append(commitment)
        nonces[signer_id] = nonce
    return commitments, nonces


def make_batch(signer_ids=(1, 2)):
    dkg_result = make_dkg()
    commitments, nonces = make_commitments(signer_ids)
    return dkg_result, commitments, nonces


def set_value(commitment, value):
    return dataclasses.replace(commitment, commitment=value)


def set_signer(commitment, signer_id):
    return dataclasses.replace(commitment, signer_id=signer_id)


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
            SigningCommitmentFault(1, "range"), SigningCommitmentFault(1, "range")
        )
        self.assertNotEqual(
            SigningCommitmentFault(1, "range"), SigningCommitmentFault(1, "subgroup")
        )
        self.assertNotEqual(
            SigningCommitmentFault(1, "range"), SigningCommitmentFault(2, "range")
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

    def test_named_check_strings(self):
        checks = {
            "unexpected",
            "duplicate",
            "range",
            "subgroup",
            "duplicate_value",
            "missing",
        }
        for check in checks:
            self.assertEqual(SigningCommitmentFault(1, check).check, check)


class DiagnoseSuccessTest(unittest.TestCase):
    def test_valid_batch_returns_empty_tuple(self):
        dkg_result, commitments, _nonces = make_batch()
        faults = diagnose_signing_nonce_commitments((1, 2), commitments, dkg_result)
        self.assertEqual(faults, ())
        self.assertIsInstance(faults, tuple)

    def test_empty_faults_exactly_when_round_creation_accepts(self):
        dkg_result, commitments, _nonces = make_batch()
        round_info = create_signing_round(
            MESSAGE, (1, 2), commitments, dkg_result
        )
        self.assertEqual(
            diagnose_signing_nonce_commitments((1, 2), commitments, dkg_result),
            (),
        )
        self.assertEqual(round_info.signer_ids, (1, 2))

    def test_threshold_one(self):
        dkg_result = make_dkg((1, 2), threshold=1)
        commitments, _ = make_commitments((1,))
        self.assertEqual(
            diagnose_signing_nonce_commitments((1,), commitments, dkg_result),
            (),
        )

    def test_full_signing_set(self):
        dkg_result = make_dkg()
        commitments, _ = make_commitments((1, 2, 3))
        self.assertEqual(
            diagnose_signing_nonce_commitments((1, 2, 3), commitments, dkg_result),
            (),
        )

    def test_accepts_any_iterable_and_any_commitment_order(self):
        dkg_result, commitments, _nonces = make_batch()
        canonical = diagnose_signing_nonce_commitments(
            (1, 2), commitments, dkg_result
        )
        self.assertEqual(
            diagnose_signing_nonce_commitments(
                iter((1, 2)), reversed(commitments), dkg_result
            ),
            canonical,
        )
        self.assertEqual(
            diagnose_signing_nonce_commitments(
                (1, 2), list(reversed(commitments)), dkg_result
            ),
            canonical,
        )


class DiagnoseFaultTest(unittest.TestCase):
    def setUp(self):
        self.dkg_result, self.commitments, self.nonces = make_batch()

    def test_unexpected_commitment_from_non_signer(self):
        # Signer 3 is a DKG participant but not in signer_ids; both expected
        # signers submitted, so only the stray item faults.
        stray = SigningNonceCommitment(3, self.commitments[0].commitment)
        faults = diagnose_signing_nonce_commitments(
            (1, 2), self.commitments + [stray], self.dkg_result
        )
        self.assertEqual(
            faults, (SigningCommitmentFault(3, "unexpected"),)
        )

    def test_unexpected_from_unknown_id_with_expected_missing(self):
        # An id outside the signing set faults unexpected; the expected ids
        # that sent nothing are independently missing.
        faults = diagnose_signing_nonce_commitments(
            (1, 2), [SigningNonceCommitment(9, GENERATOR)], self.dkg_result
        )
        self.assertEqual(
            faults,
            (
                SigningCommitmentFault(1, "missing"),
                SigningCommitmentFault(2, "missing"),
                SigningCommitmentFault(9, "unexpected"),
            ),
        )

    def test_duplicate_submission_from_same_id(self):
        second = set_value(self.commitments[0], BLINDING_GENERATOR)
        faults = diagnose_signing_nonce_commitments(
            (1, 2), self.commitments + [second], self.dkg_result
        )
        self.assertEqual(
            faults, (SigningCommitmentFault(1, "duplicate"),)
        )

    def test_duplicate_takes_precedence_over_value_collision(self):
        # Both signer-1 submissions use signer 2's R_i; with the duplicate
        # rule first, signer 1 is named once as duplicate and never masked
        # by the value collision. Signer 2 is still valid.
        copied = set_value(self.commitments[0], self.commitments[1].commitment)
        faults = diagnose_signing_nonce_commitments(
            (1, 2), [self.commitments[1], self.commitments[0], copied],
            self.dkg_result,
        )
        self.assertEqual(
            faults, (SigningCommitmentFault(1, "duplicate"),)
        )

    def test_identity_commitment_is_range_fault(self):
        bad = set_value(self.commitments[0], 1)
        faults = diagnose_signing_nonce_commitments(
            (1, 2), [bad, self.commitments[1]], self.dkg_result
        )
        self.assertEqual(faults, (SigningCommitmentFault(1, "range"),))

    def test_zero_commitment_is_range_fault(self):
        bad = set_value(self.commitments[0], 0)
        faults = diagnose_signing_nonce_commitments(
            (1, 2), [bad, self.commitments[1]], self.dkg_result
        )
        self.assertEqual(faults, (SigningCommitmentFault(1, "range"),))

    def test_commitment_equal_to_group_prime_is_range_fault(self):
        bad = set_value(self.commitments[0], GROUP_PRIME)
        faults = diagnose_signing_nonce_commitments(
            (1, 2), [bad, self.commitments[1]], self.dkg_result
        )
        self.assertEqual(faults, (SigningCommitmentFault(1, "range"),))

    def test_negative_commitment_is_range_fault(self):
        bad = set_value(self.commitments[0], -1)
        faults = diagnose_signing_nonce_commitments(
            (1, 2), [bad, self.commitments[1]], self.dkg_result
        )
        self.assertEqual(faults, (SigningCommitmentFault(1, "range"),))

    def test_non_subgroup_commitment_is_subgroup_fault(self):
        bad = set_value(self.commitments[0], NON_SUBGROUP)
        faults = diagnose_signing_nonce_commitments(
            (1, 2), [bad, self.commitments[1]], self.dkg_result
        )
        self.assertEqual(faults, (SigningCommitmentFault(1, "subgroup"),))

    def test_range_takes_precedence_over_subgroup(self):
        # R_i = 1 satisfies R_i ** q == 1 but fails the range check first.
        bad = set_value(self.commitments[0], 1)
        faults = diagnose_signing_nonce_commitments(
            (1, 2), [bad, self.commitments[1]], self.dkg_result
        )
        self.assertEqual(faults, (SigningCommitmentFault(1, "range"),))

    def test_copied_commitment_value_marks_both_signers(self):
        copied = set_value(self.commitments[1], self.commitments[0].commitment)
        faults = diagnose_signing_nonce_commitments(
            (1, 2), [self.commitments[0], copied], self.dkg_result
        )
        self.assertEqual(
            faults,
            (
                SigningCommitmentFault(1, "duplicate_value"),
                SigningCommitmentFault(2, "duplicate_value"),
            ),
        )

    def test_value_collision_names_every_sharing_signer(self):
        commitments, _ = make_commitments((1, 2, 3))
        copied = set_value(commitments[2], commitments[0].commitment)
        faults = diagnose_signing_nonce_commitments(
            (1, 2, 3), [commitments[0], commitments[1], copied], self.dkg_result
        )
        self.assertEqual(
            faults,
            (
                SigningCommitmentFault(1, "duplicate_value"),
                SigningCommitmentFault(3, "duplicate_value"),
            ),
        )

    def test_missing_commitment_is_missing_fault(self):
        faults = diagnose_signing_nonce_commitments(
            (1, 2, 3), self.commitments, self.dkg_result
        )
        self.assertEqual(faults, (SigningCommitmentFault(3, "missing"),))

    def test_every_expected_missing_when_nothing_submitted(self):
        faults = diagnose_signing_nonce_commitments(
            (1, 2), [], self.dkg_result
        )
        self.assertEqual(
            faults,
            (
                SigningCommitmentFault(1, "missing"),
                SigningCommitmentFault(2, "missing"),
            ),
        )

    def test_missing_and_bad_value_together(self):
        bad = set_value(self.commitments[0], NON_SUBGROUP)
        faults = diagnose_signing_nonce_commitments(
            (1, 2, 3), [bad, self.commitments[1]], self.dkg_result
        )
        self.assertEqual(
            faults,
            (
                SigningCommitmentFault(1, "subgroup"),
                SigningCommitmentFault(3, "missing"),
            ),
        )

    def test_mixed_faults_sorted_by_signer_id(self):
        range_bad = set_value(self.commitments[0], 1)
        subgroup_bad = set_value(self.commitments[1], NON_SUBGROUP)
        stray = SigningNonceCommitment(3, GENERATOR)
        faults = diagnose_signing_nonce_commitments(
            (1, 2), [stray, subgroup_bad, range_bad], self.dkg_result
        )
        self.assertEqual(
            faults,
            (
                SigningCommitmentFault(1, "range"),
                SigningCommitmentFault(2, "subgroup"),
                SigningCommitmentFault(3, "unexpected"),
            ),
        )

    def test_one_fault_per_submitting_id(self):
        # A signer with a duplicate submission that is also out of range and
        # non-subgroup keeps only the first (duplicate) fault.
        bad_range = set_value(self.commitments[0], GROUP_PRIME)
        bad_subgroup = set_value(self.commitments[0], NON_SUBGROUP)
        faults = diagnose_signing_nonce_commitments(
            (1, 2),
            [self.commitments[1], bad_range, bad_subgroup],
            self.dkg_result,
        )
        self.assertEqual(
            faults, (SigningCommitmentFault(1, "duplicate"),)
        )

    def test_fault_order_independent_of_input_order(self):
        range_bad = set_value(self.commitments[0], 1)
        subgroup_bad = set_value(self.commitments[1], NON_SUBGROUP)
        expected = (
            SigningCommitmentFault(1, "range"),
            SigningCommitmentFault(2, "subgroup"),
        )
        orderings = list(
            itertools.permutations([range_bad, subgroup_bad])
        )
        for ordering in orderings:
            self.assertEqual(
                diagnose_signing_nonce_commitments(
                    (1, 2), list(ordering), self.dkg_result
                ),
                expected,
            )
        self.assertEqual(
            diagnose_signing_nonce_commitments(
                (1, 2), iter([subgroup_bad, range_bad]), self.dkg_result
            ),
            expected,
        )


class DiagnoseRoundEquivalenceTest(unittest.TestCase):
    """Empty faults must match create_signing_round accepting the same set."""

    def setUp(self):
        self.dkg_result, self.commitments, _nonces = make_batch()

    def assert_round_raises(self, signer_ids, commitments):
        with self.assertRaises(ValueError):
            create_signing_round(MESSAGE, signer_ids, commitments, self.dkg_result)

    def test_valid_set_accepted_by_both(self):
        self.assertEqual(
            diagnose_signing_nonce_commitments(
                (1, 2), self.commitments, self.dkg_result
            ),
            (),
        )
        round_info = create_signing_round(
            MESSAGE, (1, 2), self.commitments, self.dkg_result
        )
        self.assertEqual(round_info.signer_ids, (1, 2))

    def test_each_fault_kind_corresponds_to_round_rejection(self):
        cases = [
            ((1, 2), self.commitments + [SigningNonceCommitment(3, GENERATOR)]),
            ((1, 2), self.commitments + [set_value(self.commitments[0], 256)]),
            ((1, 2), [set_value(self.commitments[0], 1), self.commitments[1]]),
            (
                (1, 2),
                [set_value(self.commitments[0], NON_SUBGROUP), self.commitments[1]],
            ),
            (
                (1, 2),
                [
                    self.commitments[0],
                    set_value(self.commitments[1], self.commitments[0].commitment),
                ],
            ),
            ((1, 2, 3), self.commitments),
        ]
        for signer_ids, commitments in cases:
            faults = diagnose_signing_nonce_commitments(
                signer_ids, commitments, self.dkg_result
            )
            self.assertTrue(faults, commitments)
            self.assert_round_raises(signer_ids, commitments)


class DiagnoseValidationTest(unittest.TestCase):
    def setUp(self):
        self.dkg_result, self.commitments, _nonces = make_batch()

    def test_non_iterable_commitments_is_type_error(self):
        with self.assertRaises(TypeError):
            diagnose_signing_nonce_commitments((1, 2), 7, self.dkg_result)

    def test_string_commitments_is_type_error(self):
        with self.assertRaises(TypeError):
            diagnose_signing_nonce_commitments((1, 2), "ab", self.dkg_result)

    def test_wrong_element_type_is_type_error(self):
        with self.assertRaises(TypeError):
            diagnose_signing_nonce_commitments(
                (1, 2), ["nope", self.commitments[1]], self.dkg_result
            )

    def test_tuple_instead_of_commitment_is_type_error(self):
        with self.assertRaises(TypeError):
            diagnose_signing_nonce_commitments(
                (1, 2), [(1, 16), self.commitments[1]], self.dkg_result
            )

    def test_wrong_commitment_signer_field_type_is_type_error(self):
        bad = set_signer(self.commitments[0], "1")
        with self.assertRaises(TypeError):
            diagnose_signing_nonce_commitments(
                (1, 2), [bad, self.commitments[1]], self.dkg_result
            )

    def test_bool_impersonating_commitment_signer_id_is_type_error(self):
        bad = set_signer(self.commitments[0], True)
        with self.assertRaises(TypeError):
            diagnose_signing_nonce_commitments(
                (1, 2), [bad, self.commitments[1]], self.dkg_result
            )

    def test_wrong_commitment_value_field_type_is_type_error(self):
        bad = set_value(self.commitments[0], "16")
        with self.assertRaises(TypeError):
            diagnose_signing_nonce_commitments(
                (1, 2), [bad, self.commitments[1]], self.dkg_result
            )

    def test_bool_impersonating_commitment_value_is_type_error(self):
        bad = set_value(self.commitments[0], True)
        with self.assertRaises(TypeError):
            diagnose_signing_nonce_commitments(
                (1, 2), [bad, self.commitments[1]], self.dkg_result
            )

    def test_wrong_signer_id_element_type_is_type_error(self):
        with self.assertRaises(TypeError):
            diagnose_signing_nonce_commitments(
                ("1", 2), self.commitments, self.dkg_result
            )

    def test_bool_impersonating_signer_id_is_type_error(self):
        with self.assertRaises(TypeError):
            diagnose_signing_nonce_commitments(
                (True, 2), self.commitments, self.dkg_result
            )

    def test_string_signer_ids_is_type_error(self):
        with self.assertRaises(TypeError):
            diagnose_signing_nonce_commitments(
                "12", self.commitments, self.dkg_result
            )

    def test_non_iterable_signer_ids_is_type_error(self):
        with self.assertRaises(TypeError):
            diagnose_signing_nonce_commitments(7, self.commitments, self.dkg_result)

    def test_wrong_dkg_type_is_type_error(self):
        with self.assertRaises(TypeError):
            diagnose_signing_nonce_commitments(
                (1, 2), self.commitments, object()
            )

    def test_dkg_with_wrong_field_type_is_type_error(self):
        bad = dataclasses.replace(self.dkg_result, public_key="1")
        with self.assertRaises(TypeError):
            diagnose_signing_nonce_commitments(
                (1, 2), self.commitments, bad
            )

    def test_empty_signer_ids_is_value_error(self):
        with self.assertRaises(ValueError):
            diagnose_signing_nonce_commitments(
                (), self.commitments, self.dkg_result
            )

    def test_unsorted_signer_ids_is_value_error(self):
        with self.assertRaises(ValueError):
            diagnose_signing_nonce_commitments(
                (2, 1), list(reversed(self.commitments)), self.dkg_result
            )

    def test_duplicate_signer_ids_is_value_error(self):
        with self.assertRaises(ValueError):
            diagnose_signing_nonce_commitments(
                (1, 1), self.commitments, self.dkg_result
            )

    def test_non_participant_signer_id_is_value_error(self):
        commitments, _ = make_commitments((2, 3))
        with self.assertRaises(ValueError):
            diagnose_signing_nonce_commitments(
                (2, 9), commitments, self.dkg_result
            )

    def test_too_few_signers_is_value_error(self):
        with self.assertRaises(ValueError):
            diagnose_signing_nonce_commitments(
                (1,), self.commitments[:1], self.dkg_result
            )

    def test_signer_id_out_of_field_is_value_error(self):
        with self.assertRaises(ValueError):
            diagnose_signing_nonce_commitments(
                (0, 2), self.commitments, self.dkg_result
            )
        with self.assertRaises(ValueError):
            diagnose_signing_nonce_commitments(
                (FIELD_PRIME, 2), self.commitments, self.dkg_result
            )

    def test_dkg_with_out_of_range_public_key_is_value_error(self):
        bad = dataclasses.replace(self.dkg_result, public_key=0)
        with self.assertRaises(ValueError):
            diagnose_signing_nonce_commitments(
                (1, 2), self.commitments, bad
            )

    def test_dkg_with_non_subgroup_verification_share_is_value_error(self):
        bad_shares = (NON_SUBGROUP,) + self.dkg_result.verification_shares[1:]
        bad = dataclasses.replace(
            self.dkg_result, verification_shares=bad_shares
        )
        with self.assertRaises(ValueError):
            diagnose_signing_nonce_commitments(
                (1, 2), self.commitments, bad
            )


class DiagnoseNoMutationTest(unittest.TestCase):
    def setUp(self):
        self.dkg_result, self.commitments, _nonces = make_batch()

    def test_input_list_unchanged_on_success(self):
        commitments = list(self.commitments)
        snapshot = copy.deepcopy(commitments)
        diagnose_signing_nonce_commitments((1, 2), commitments, self.dkg_result)
        self.assertEqual(commitments, snapshot)

    def test_input_list_unchanged_with_faults(self):
        commitments = [
            set_value(self.commitments[0], NON_SUBGROUP),
            self.commitments[1],
        ]
        snapshot = copy.deepcopy(commitments)
        diagnose_signing_nonce_commitments((1, 2), commitments, self.dkg_result)
        self.assertEqual(commitments, snapshot)

    def test_input_list_unchanged_on_value_error(self):
        commitments = list(self.commitments)
        snapshot = copy.deepcopy(commitments)
        with self.assertRaises(ValueError):
            diagnose_signing_nonce_commitments((), commitments, self.dkg_result)
        self.assertEqual(commitments, snapshot)

    def test_input_list_unchanged_on_type_error(self):
        commitments = ["nope"]
        snapshot = copy.deepcopy(commitments)
        with self.assertRaises(TypeError):
            diagnose_signing_nonce_commitments(
                (1, 2), commitments, self.dkg_result
            )
        self.assertEqual(commitments, snapshot)


class ExistingFlowUnchangedTest(unittest.TestCase):
    def test_full_signing_flow_still_runs_after_diagnosis(self):
        dkg_result = make_dkg()
        commitments, nonces = make_commitments((1, 2, 3))

        # The diagnoser is read-only: a clean batch still produces a round,
        # shares, an aggregate signature and a passing audit.
        self.assertEqual(
            diagnose_signing_nonce_commitments(
                (1, 2, 3), commitments, dkg_result
            ),
            (),
        )
        round_info = create_signing_round(
            MESSAGE, (1, 2, 3), commitments, dkg_result
        )
        shares = []
        for signer_id in round_info.signer_ids:
            index = dkg_result.result.participant_ids.index(signer_id)
            shares.append(
                create_signature_share(
                    signer_id,
                    dkg_result.result.shares[index].y,
                    nonces[signer_id],
                    round_info,
                    dkg_result,
                )
            )
        signature = aggregate_signature(shares, round_info, dkg_result)
        self.assertEqual(signature.signer_ids, (1, 2, 3))
        audit = create_audit(MESSAGE, shares, round_info, dkg_result)
        self.assertTrue(check_audit(MESSAGE, audit, dkg_result))

    def test_create_signing_round_still_validates_its_own_batch(self):
        dkg_result, commitments, _nonces = make_batch()
        # A faulty batch is reported by the diagnoser ...
        faults = diagnose_signing_nonce_commitments(
            (1, 2, 3), commitments, dkg_result
        )
        self.assertEqual(faults, (SigningCommitmentFault(3, "missing"),))
        # ... and the existing entry point keeps its own rejection boundary.
        with self.assertRaises(ValueError):
            create_signing_round(MESSAGE, (1, 2, 3), commitments, dkg_result)


if __name__ == "__main__":
    unittest.main()
