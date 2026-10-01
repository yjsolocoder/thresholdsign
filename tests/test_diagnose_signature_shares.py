"""Tests for the signature share pre-aggregation diagnoser."""

import copy
import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    SignatureShare,
    SignatureShareFault,
    SignatureShareRejection,
    SigningDKGResult,
    aggregate_signature,
    aggregate_signing_dkg,
    check_audit,
    create_audit,
    create_signature_share,
    create_signing_contribution,
    create_signing_nonce_commitment,
    create_signing_round,
    diagnose_signature_shares,
)

# Same toy group as the signing tests: 8069 = 4 * 2017 + 1 is prime, 16 and
# 256 = 16 ** 2 are distinct generators of the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

PARTICIPANT_IDS = (1, 2, 3)
THRESHOLD = 2
MESSAGE = b"diagnose signature shares test message"


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


def make_round(dkg_result, signer_ids=(1, 2), message=MESSAGE, seed=10):
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
    round_info = create_signing_round(
        message, tuple(signer_ids), commitments, dkg_result
    )
    return round_info, nonces


def make_shares(dkg_result, round_info, nonces):
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
    return shares


def make_batch(signer_ids=(1, 2)):
    dkg_result = make_dkg()
    round_info, nonces = make_round(dkg_result, signer_ids)
    shares = make_shares(dkg_result, round_info, nonces)
    return dkg_result, round_info, shares


def tamper_commitment(share):
    """Rebind the share to a commitment different from its round R_i."""
    return dataclasses.replace(
        share, nonce_commitment=(share.nonce_commitment % (GROUP_PRIME - 2)) + 2
    )


def tamper_z(share):
    return dataclasses.replace(share, z=(share.z + 1) % FIELD_PRIME)


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
            {SignatureShareFault(1, "equation"), SignatureShareFault(1, "equation")},
            {SignatureShareFault(1, "equation")},
        )

    def test_frozen(self):
        fault = SignatureShareFault(1, "commitment")
        with self.assertRaises(FrozenInstanceError):
            fault.check = "equation"  # type: ignore[misc]


class DiagnoseSuccessTest(unittest.TestCase):
    def test_valid_batch_returns_empty_tuple(self):
        dkg_result, round_info, shares = make_batch()
        faults = diagnose_signature_shares(shares, round_info, dkg_result)
        self.assertEqual(faults, ())
        self.assertIsInstance(faults, tuple)

    def test_empty_faults_exactly_when_aggregation_succeeds(self):
        dkg_result, round_info, shares = make_batch()
        self.assertIsInstance(
            aggregate_signature(list(shares), round_info, dkg_result),
            AggregateSignature,
        )
        self.assertEqual(diagnose_signature_shares(shares, round_info, dkg_result), ())

    def test_threshold_one(self):
        dkg_result = make_dkg((1, 2), threshold=1)
        round_info, nonces = make_round(dkg_result, (1,))
        shares = make_shares(dkg_result, round_info, nonces)
        self.assertEqual(diagnose_signature_shares(shares, round_info, dkg_result), ())

    def test_full_signing_set(self):
        dkg_result, round_info, shares = make_batch((1, 2, 3))
        self.assertEqual(diagnose_signature_shares(shares, round_info, dkg_result), ())

    def test_accepts_any_iterable(self):
        dkg_result, round_info, shares = make_batch()
        self.assertEqual(
            diagnose_signature_shares(iter(reversed(shares)), round_info, dkg_result),
            diagnose_signature_shares(shares, round_info, dkg_result),
        )


class DiagnoseFaultTest(unittest.TestCase):
    def setUp(self):
        self.dkg_result, self.round_info, self.shares = make_batch()

    def test_tampered_commitment_is_commitment_fault(self):
        bad = tamper_commitment(self.shares[0])
        faults = diagnose_signature_shares(
            [bad, self.shares[1]], self.round_info, self.dkg_result
        )
        self.assertEqual(faults, (SignatureShareFault(1, "commitment"),))

    def test_tampered_commitment_using_other_signers_R_i(self):
        bad = dataclasses.replace(
            self.shares[0], nonce_commitment=self.shares[1].nonce_commitment
        )
        faults = diagnose_signature_shares(
            [bad, self.shares[1]], self.round_info, self.dkg_result
        )
        self.assertEqual(faults, (SignatureShareFault(1, "commitment"),))

    def test_tampered_z_is_equation_fault(self):
        bad = tamper_z(self.shares[1])
        faults = diagnose_signature_shares(
            [self.shares[0], bad], self.round_info, self.dkg_result
        )
        self.assertEqual(faults, (SignatureShareFault(2, "equation"),))

    def test_commitment_and_equation_failures_in_different_signers(self):
        commitment_bad = tamper_commitment(self.shares[0])
        equation_bad = tamper_z(self.shares[1])
        faults = diagnose_signature_shares(
            [equation_bad, commitment_bad], self.round_info, self.dkg_result
        )
        self.assertEqual(
            faults,
            (
                SignatureShareFault(1, "commitment"),
                SignatureShareFault(2, "equation"),
            ),
        )

    def test_one_fault_per_signer_commitment_takes_precedence(self):
        # Both the commitment and z are tampered: only the commitment fault
        # survives for that signer.
        bad = tamper_z(tamper_commitment(self.shares[0]))
        faults = diagnose_signature_shares(
            [bad, self.shares[1]], self.round_info, self.dkg_result
        )
        self.assertEqual(faults, (SignatureShareFault(1, "commitment"),))

    def test_every_signer_failing_is_reported(self):
        faults = diagnose_signature_shares(
            [tamper_z(self.shares[0]), tamper_commitment(self.shares[1])],
            self.round_info,
            self.dkg_result,
        )
        self.assertEqual(
            faults,
            (
                SignatureShareFault(1, "equation"),
                SignatureShareFault(2, "commitment"),
            ),
        )

    def test_tampered_round_R_marks_every_share_equation(self):
        # A hand-edited round header cannot make a valid share diagnose clean:
        # the R is re-derived from the round's commitments.
        bad_round = dataclasses.replace(
            self.round_info, R=(self.round_info.R % (GROUP_PRIME - 2)) + 2
        )
        faults = diagnose_signature_shares(self.shares, bad_round, self.dkg_result)
        self.assertEqual(
            faults,
            (
                SignatureShareFault(1, "equation"),
                SignatureShareFault(2, "equation"),
            ),
        )

    def test_tampered_round_challenge_marks_every_share_equation(self):
        bad_round = dataclasses.replace(
            self.round_info, challenge=(self.round_info.challenge + 1) % FIELD_PRIME
        )
        faults = diagnose_signature_shares(self.shares, bad_round, self.dkg_result)
        self.assertEqual(
            faults,
            (
                SignatureShareFault(1, "equation"),
                SignatureShareFault(2, "equation"),
            ),
        )

    def test_fault_order_is_signer_sorted_independent_of_input_order(self):
        commitment_bad = tamper_commitment(self.shares[0])
        equation_bad = tamper_z(self.shares[1])
        expected = (
            SignatureShareFault(1, "commitment"),
            SignatureShareFault(2, "equation"),
        )
        one_order = [equation_bad, commitment_bad]
        other_order = [commitment_bad, equation_bad]
        self.assertEqual(
            diagnose_signature_shares(one_order, self.round_info, self.dkg_result),
            expected,
        )
        self.assertEqual(
            diagnose_signature_shares(other_order, self.round_info, self.dkg_result),
            expected,
        )
        self.assertEqual(
            diagnose_signature_shares(
                reversed(one_order), self.round_info, self.dkg_result
            ),
            expected,
        )

    def test_fault_senders_match_aggregator_rejections(self):
        commitment_bad = tamper_commitment(self.shares[0])
        equation_bad = tamper_z(self.shares[1])
        batch = [commitment_bad, equation_bad]
        outcome = aggregate_signature(batch, self.round_info, self.dkg_result)
        self.assertEqual(
            outcome,
            [SignatureShareRejection(1), SignatureShareRejection(2)],
        )
        faults = diagnose_signature_shares(batch, self.round_info, self.dkg_result)
        self.assertEqual(
            [fault.signer_id for fault in faults],
            [rejection.signer_id for rejection in outcome],
        )


class DiagnoseValidationTest(unittest.TestCase):
    def setUp(self):
        self.dkg_result, self.round_info, self.shares = make_batch()

    def assert_aggregator_and_diagnoser_raise(self, shares, error):
        with self.assertRaises(error):
            aggregate_signature(list(shares), self.round_info, self.dkg_result)
        with self.assertRaises(error):
            diagnose_signature_shares(shares, self.round_info, self.dkg_result)

    def test_empty_batch_is_value_error(self):
        self.assert_aggregator_and_diagnoser_raise([], ValueError)

    def test_missing_round_signer_is_value_error(self):
        self.assert_aggregator_and_diagnoser_raise(self.shares[:1], ValueError)

    def test_extra_off_round_signer_is_value_error(self):
        _, _, other_shares = make_batch((1, 3))
        # Signer 3 is a DKG participant but takes no part in this round.
        self.assert_aggregator_and_diagnoser_raise(
            [self.shares[0], other_shares[1]], ValueError
        )

    def test_duplicate_signer_is_value_error(self):
        self.assert_aggregator_and_diagnoser_raise(
            [self.shares[0], self.shares[0]], ValueError
        )

    def test_wrong_element_type_is_type_error(self):
        self.assert_aggregator_and_diagnoser_raise(["nope"], TypeError)

    def test_tuple_instead_of_share_is_type_error(self):
        self.assert_aggregator_and_diagnoser_raise(
            [(self.shares[0].signer_id,)], TypeError
        )

    def test_wrong_share_field_type_is_type_error(self):
        bad = dataclasses.replace(self.shares[0], z="1")
        self.assert_aggregator_and_diagnoser_raise([bad, self.shares[1]], TypeError)

    def test_bool_impersonating_signer_id_is_type_error(self):
        bad = dataclasses.replace(self.shares[0], signer_id=True)
        self.assert_aggregator_and_diagnoser_raise([bad, self.shares[1]], TypeError)

    def test_z_out_of_range_is_value_error(self):
        bad = dataclasses.replace(self.shares[0], z=FIELD_PRIME)
        self.assert_aggregator_and_diagnoser_raise([bad, self.shares[1]], ValueError)

    def test_commitment_out_of_range_is_value_error(self):
        bad = dataclasses.replace(self.shares[0], nonce_commitment=1)
        self.assert_aggregator_and_diagnoser_raise([bad, self.shares[1]], ValueError)

    def test_wrong_round_type_is_type_error(self):
        with self.assertRaises(TypeError):
            diagnose_signature_shares(self.shares, object(), self.dkg_result)

    def test_wrong_dkg_type_is_type_error(self):
        with self.assertRaises(TypeError):
            diagnose_signature_shares(self.shares, self.round_info, object())


class DiagnoseNoMutationTest(unittest.TestCase):
    def setUp(self):
        self.dkg_result, self.round_info, self.shares = make_batch()

    def test_input_list_unchanged_on_success(self):
        shares = list(self.shares)
        snapshot = copy.deepcopy(shares)
        diagnose_signature_shares(shares, self.round_info, self.dkg_result)
        self.assertEqual(shares, snapshot)

    def test_input_list_unchanged_with_faults(self):
        shares = [tamper_z(self.shares[0]), self.shares[1]]
        snapshot = copy.deepcopy(shares)
        diagnose_signature_shares(shares, self.round_info, self.dkg_result)
        self.assertEqual(shares, snapshot)

    def test_input_list_unchanged_on_value_error(self):
        shares = [self.shares[0]]
        snapshot = copy.deepcopy(shares)
        with self.assertRaises(ValueError):
            diagnose_signature_shares(shares, self.round_info, self.dkg_result)
        self.assertEqual(shares, snapshot)


class AggregatorAndAuditUnchangedTest(unittest.TestCase):
    def test_aggregator_still_aggregates_valid_batch(self):
        dkg_result, round_info, shares = make_batch()
        signature = aggregate_signature(shares, round_info, dkg_result)
        self.assertIsInstance(signature, AggregateSignature)
        self.assertEqual(signature.R, round_info.R)
        self.assertEqual(signature.signer_ids, round_info.signer_ids)

    def test_aggregator_still_rejects_bad_batch_sorted(self):
        dkg_result, round_info, shares = make_batch()
        batch = [tamper_z(shares[1]), tamper_commitment(shares[0])]
        outcome = aggregate_signature(batch, round_info, dkg_result)
        self.assertEqual(
            outcome,
            [SignatureShareRejection(1), SignatureShareRejection(2)],
        )

    def test_audit_receipt_content_and_check_unchanged(self):
        dkg_result, round_info, shares = make_batch()
        receipt = create_audit(MESSAGE, shares, round_info, dkg_result)
        self.assertTrue(check_audit(MESSAGE, receipt, dkg_result))
        bad_shares = [tamper_z(shares[0]), shares[1]]
        failed_receipt = create_audit(MESSAGE, bad_shares, round_info, dkg_result)
        self.assertTrue(check_audit(MESSAGE, failed_receipt, dkg_result))
        self.assertNotEqual(receipt.payload, failed_receipt.payload)


if __name__ == "__main__":
    unittest.main()
