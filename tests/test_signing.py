import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    DKGRejection,
    DKGResult,
    FeldmanCommitment,
    NonceCommitment,
    Share,
    Signature,
    SignatureShare,
    SigningContribution,
    SigningDKGResult,
    SigningRejection,
    aggregate_signatures,
    aggregate_signing_dkg,
    create_nonce_commitment,
    create_signature_share,
    create_signing_contribution,
    reconstruct_secret,
    verify_signature,
    verify_signature_share,
)

# Same toy group setup as the DKG tests: 8069 = 4 * 2017 + 1 is prime, 16 and
# 256 = 16 ** 2 are distinct generators of the order-2017 subgroup modulo 8069.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

MESSAGE = b"threshold schnorr demo"


def fixed_random(seed=1):
    """Deterministic stand-in for secrets.randbelow so tests are reproducible."""
    state = {"value": seed}

    def randbelow(upper: int) -> int:
        state["value"] = (state["value"] * 6364136223846793005 + 1442695040888963407) % upper
        return state["value"]

    return randbelow


def make_signing_contribution(sender_id, participant_ids=(1, 2, 3), threshold=2, **kwargs):
    options = {
        "group_prime": GROUP_PRIME,
        "generator": GENERATOR,
        "blinding_generator": BLINDING_GENERATOR,
        "prime": FIELD_PRIME,
        "randbelow": fixed_random(sender_id),
    }
    options.update(kwargs)
    return create_signing_contribution(sender_id, participant_ids, threshold, **options)


def make_signing_contributions(participant_ids=(1, 2, 3), threshold=2):
    return [make_signing_contribution(pid, participant_ids, threshold) for pid in participant_ids]


def make_result(participant_ids=(1, 2, 3), threshold=2):
    outcome = aggregate_signing_dkg(make_signing_contributions(participant_ids, threshold))
    assert isinstance(outcome, SigningDKGResult)
    return outcome


def make_nonce(signer_id, seed=None):
    return create_nonce_commitment(
        signer_id,
        prime=FIELD_PRIME,
        group_prime=GROUP_PRIME,
        generator=GENERATOR,
        randbelow=fixed_random(seed if seed is not None else 100 + signer_id),
    )


def make_session(result, signer_ids, message=MESSAGE, seed_offset=0):
    """A full signing session: (nonce_commitments, signature_shares)."""
    # Round 1: every signer publishes a nonce commitment.
    nonces = {}
    commitments = []
    for signer_id in signer_ids:
        nonce, commitment = make_nonce(
            signer_id, seed=1000 + seed_offset + signer_id
        )
        nonces[signer_id] = nonce
        commitments.append(commitment)
    # Round 2: every signer publishes a signature share.
    shares = []
    for signer_id in signer_ids:
        index = result.dkg_result.participant_ids.index(signer_id)
        shares.append(
            create_signature_share(
                signer_id,
                message,
                nonce=nonces[signer_id],
                share=result.dkg_result.shares[index],
                nonce_commitments=commitments,
                result=result,
            )
        )
    return commitments, shares


class CreateSigningContributionTest(unittest.TestCase):
    def test_returns_pedersen_contribution_and_feldman_commitment(self):
        contribution = make_signing_contribution(2)
        self.assertIsInstance(contribution, SigningContribution)
        self.assertEqual(contribution.dkg_contribution.sender_id, 2)
        self.assertEqual(contribution.dkg_contribution.participant_ids, (1, 2, 3))
        self.assertIsInstance(contribution.feldman_commitment, FeldmanCommitment)
        feldman = contribution.feldman_commitment
        self.assertEqual(
            (feldman.field_prime, feldman.group_prime, feldman.generator),
            (FIELD_PRIME, GROUP_PRIME, GENERATOR),
        )
        self.assertEqual(
            len(feldman.values), len(contribution.dkg_contribution.commitment.values)
        )

    def test_feldman_commitment_matches_shares(self):
        from thresholdsign import verify_share

        contribution = make_signing_contribution(1)
        for share in contribution.dkg_contribution.shares:
            self.assertTrue(verify_share(share, contribution.feldman_commitment))

    def test_contribution_is_frozen_and_stores_no_coefficients(self):
        contribution = make_signing_contribution(1)
        with self.assertRaises(FrozenInstanceError):
            contribution.feldman_commitment = None  # type: ignore[misc]
        self.assertEqual(
            {field.name for field in dataclasses.fields(contribution)},
            {"dkg_contribution", "feldman_commitment"},
        )
        self.assertFalse(hasattr(contribution, "coefficients"))
        self.assertFalse(hasattr(contribution, "secret"))

    def test_validation_matches_dkg_contribution(self):
        with self.assertRaises(ValueError):
            make_signing_contribution(4, (1, 2, 3))
        with self.assertRaises(ValueError):
            make_signing_contribution(1, (1, 2, 2))
        with self.assertRaises(ValueError):
            make_signing_contribution(1, (1, 2, 3), 0)
        with self.assertRaises(TypeError):
            make_signing_contribution("1")
        with self.assertRaises(ValueError):
            make_signing_contribution(1, (1, 2, 3), 2, generator=1)


class AggregateSigningDkgTest(unittest.TestCase):
    def test_success_returns_result_public_key_and_verification_shares(self):
        contributions = make_signing_contributions()
        outcome = aggregate_signing_dkg(contributions)
        self.assertIsInstance(outcome, SigningDKGResult)
        self.assertIsInstance(outcome.dkg_result, DKGResult)
        self.assertEqual(outcome.dkg_result.participant_ids, (1, 2, 3))
        self.assertEqual(len(outcome.verification_shares), 3)
        # Y is the joint public key and Y_i commits to each aggregated share.
        joint_secret = reconstruct_secret(outcome.dkg_result.shares[:2], prime=FIELD_PRIME)
        self.assertEqual(outcome.public_key, pow(GENERATOR, joint_secret, GROUP_PRIME))
        for share, verification_share in zip(
            outcome.dkg_result.shares, outcome.verification_shares
        ):
            self.assertEqual(
                verification_share, pow(GENERATOR, share.y, GROUP_PRIME)
            )

    def test_public_key_is_product_of_constant_term_commitments(self):
        contributions = make_signing_contributions()
        outcome = aggregate_signing_dkg(contributions)
        product = 1
        for contribution in contributions:
            product = product * contribution.feldman_commitment.values[0] % GROUP_PRIME
        self.assertEqual(outcome.public_key, product)

    def test_input_order_does_not_affect_result(self):
        contributions = make_signing_contributions()
        shuffled = [contributions[2], contributions[0], contributions[1]]
        self.assertEqual(
            aggregate_signing_dkg(contributions), aggregate_signing_dkg(shuffled)
        )

    def test_threshold_one(self):
        outcome = aggregate_signing_dkg(make_signing_contributions((1, 2), 1))
        self.assertIsInstance(outcome, SigningDKGResult)
        for share, verification_share in zip(
            outcome.dkg_result.shares, outcome.verification_shares
        ):
            self.assertEqual(verification_share, pow(GENERATOR, share.y, GROUP_PRIME))

    def test_result_is_frozen_and_stores_no_secret(self):
        outcome = aggregate_signing_dkg(make_signing_contributions())
        with self.assertRaises(FrozenInstanceError):
            outcome.public_key = 1  # type: ignore[misc]
        self.assertEqual(
            {field.name for field in dataclasses.fields(outcome)},
            {"dkg_result", "public_key", "verification_shares"},
        )
        self.assertFalse(hasattr(outcome, "secret"))
        self.assertFalse(hasattr(outcome, "coefficients"))

    def test_tampered_share_yields_rejection_naming_sender(self):
        contributions = make_signing_contributions()
        bad = contributions[1]
        tampered_dkg = dataclasses.replace(
            bad.dkg_contribution,
            shares=(
                Share(bad.dkg_contribution.shares[0].x,
                      (bad.dkg_contribution.shares[0].y + 1) % FIELD_PRIME),
            )
            + bad.dkg_contribution.shares[1:],
        )
        tampered = dataclasses.replace(bad, dkg_contribution=tampered_dkg)
        outcome = aggregate_signing_dkg([contributions[0], tampered, contributions[2]])
        self.assertEqual(outcome, [DKGRejection(sender_id=2)])

    def test_mismatched_feldman_commitment_yields_rejection(self):
        contributions = make_signing_contributions()
        other = make_signing_contribution(2)
        mismatched = dataclasses.replace(
            contributions[0], feldman_commitment=other.feldman_commitment
        )
        outcome = aggregate_signing_dkg(
            [mismatched, contributions[1], contributions[2]]
        )
        self.assertEqual(outcome, [DKGRejection(sender_id=1)])

    def test_rejection_order_does_not_depend_on_input_order(self):
        contributions = make_signing_contributions()
        # sender 3's Feldman commitment no longer matches its shares.
        mismatched = dataclasses.replace(
            contributions[2], feldman_commitment=contributions[0].feldman_commitment
        )
        outcome = aggregate_signing_dkg(
            [mismatched, contributions[0], contributions[1]]
        )
        self.assertEqual(outcome, [DKGRejection(sender_id=3)])

    def test_missing_and_duplicate_participants_rejected(self):
        contributions = make_signing_contributions()
        with self.assertRaises(ValueError):
            aggregate_signing_dkg(contributions[:2])
        with self.assertRaises(ValueError):
            aggregate_signing_dkg(
                [contributions[0], contributions[0], contributions[2]]
            )
        with self.assertRaises(ValueError):
            aggregate_signing_dkg([])

    def test_inconsistent_feldman_parameters_rejected(self):
        contributions = make_signing_contributions()
        bad_feldman = dataclasses.replace(
            contributions[0].feldman_commitment, generator=BLINDING_GENERATOR
        )
        bad = dataclasses.replace(contributions[0], feldman_commitment=bad_feldman)
        with self.assertRaises(ValueError):
            aggregate_signing_dkg([bad, contributions[1], contributions[2]])

    def test_illegal_feldman_commitment_rejected(self):
        contributions = make_signing_contributions()
        bad_feldman = dataclasses.replace(
            contributions[0].feldman_commitment, values=(0, 1)
        )
        bad = dataclasses.replace(contributions[0], feldman_commitment=bad_feldman)
        with self.assertRaises(ValueError):
            aggregate_signing_dkg([bad, contributions[1], contributions[2]])

    def test_wrong_types_raise_type_error(self):
        contributions = make_signing_contributions()
        with self.assertRaises(TypeError):
            aggregate_signing_dkg(["not a contribution"])
        with self.assertRaises(TypeError):
            aggregate_signing_dkg([contributions[0].dkg_contribution] * 3)
        bad = dataclasses.replace(contributions[0], feldman_commitment="x")
        with self.assertRaises(TypeError):
            aggregate_signing_dkg([bad, contributions[1], contributions[2]])


class CreateNonceCommitmentTest(unittest.TestCase):
    def test_nonce_is_nonzero_and_commitment_matches(self):
        nonce, commitment = make_nonce(1)
        self.assertIsInstance(commitment, NonceCommitment)
        self.assertEqual(commitment.signer_id, 1)
        self.assertTrue(1 <= nonce < FIELD_PRIME)
        self.assertEqual(commitment.value, pow(GENERATOR, nonce, GROUP_PRIME))

    def test_zero_draw_is_mapped_to_nonzero_nonce(self):
        nonce, commitment = create_nonce_commitment(
            1,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            randbelow=lambda upper: 0,
        )
        self.assertEqual(nonce, 1)
        self.assertEqual(commitment.value, GENERATOR % GROUP_PRIME)

    def test_commitment_is_frozen(self):
        _, commitment = make_nonce(1)
        with self.assertRaises(FrozenInstanceError):
            commitment.value = 1  # type: ignore[misc]

    def test_invalid_arguments(self):
        with self.assertRaises(TypeError):
            create_nonce_commitment(
                "1", prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR
            )
        with self.assertRaises(ValueError):
            create_nonce_commitment(
                0, prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR
            )
        with self.assertRaises(ValueError):
            create_nonce_commitment(
                1, prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=1
            )


class SigningSessionTest(unittest.TestCase):
    def setUp(self):
        self.result = make_result()
        self.commitments, self.shares = make_session(self.result, (1, 3))

    def test_signature_shares_verify(self):
        for share in self.shares:
            self.assertIs(
                verify_signature_share(
                    share,
                    MESSAGE,
                    nonce_commitments=self.commitments,
                    result=self.result,
                ),
                True,
            )

    def test_aggregated_signature_verifies(self):
        signature = aggregate_signatures(
            self.shares,
            MESSAGE,
            nonce_commitments=self.commitments,
            result=self.result,
        )
        self.assertIsInstance(signature, Signature)
        self.assertEqual(signature.signer_ids, (1, 3))
        self.assertIs(
            verify_signature(
                signature,
                MESSAGE,
                public_key=self.result.public_key,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            ),
            True,
        )

    def test_all_signer_subsets_of_threshold_size(self):
        for signers in ((1, 2), (1, 3), (2, 3), (1, 2, 3)):
            commitments, shares = make_session(self.result, signers, seed_offset=7)
            signature = aggregate_signatures(
                shares, MESSAGE, nonce_commitments=commitments, result=self.result
            )
            self.assertIsInstance(signature, Signature)
            self.assertEqual(signature.signer_ids, tuple(sorted(signers)))
            self.assertTrue(
                verify_signature(
                    signature,
                    MESSAGE,
                    public_key=self.result.public_key,
                    prime=FIELD_PRIME,
                    group_prime=GROUP_PRIME,
                    generator=GENERATOR,
                )
            )

    def test_threshold_one(self):
        result = make_result((1, 2), 1)
        commitments, shares = make_session(result, (2,))
        signature = aggregate_signatures(
            shares, MESSAGE, nonce_commitments=commitments, result=result
        )
        self.assertIsInstance(signature, Signature)
        self.assertTrue(
            verify_signature(
                signature,
                MESSAGE,
                public_key=result.public_key,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            )
        )

    def test_wrong_message_returns_false(self):
        signature = aggregate_signatures(
            self.shares,
            MESSAGE,
            nonce_commitments=self.commitments,
            result=self.result,
        )
        self.assertFalse(
            verify_signature(
                signature,
                b"another message",
                public_key=self.result.public_key,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            )
        )

    def test_wrong_public_key_returns_false(self):
        signature = aggregate_signatures(
            self.shares,
            MESSAGE,
            nonce_commitments=self.commitments,
            result=self.result,
        )
        other_key = self.result.public_key * GENERATOR % GROUP_PRIME
        self.assertFalse(
            verify_signature(
                signature,
                MESSAGE,
                public_key=other_key,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            )
        )

    def test_signature_is_frozen_and_stores_no_secret(self):
        signature = aggregate_signatures(
            self.shares,
            MESSAGE,
            nonce_commitments=self.commitments,
            result=self.result,
        )
        with self.assertRaises(FrozenInstanceError):
            signature.value = 0  # type: ignore[misc]
        self.assertEqual(
            {field.name for field in dataclasses.fields(signature)},
            {"signer_ids", "nonce", "value"},
        )


class SignatureShareRejectionTest(unittest.TestCase):
    def setUp(self):
        self.result = make_result()
        self.commitments, self.shares = make_session(self.result, (1, 3))

    def test_tampered_share_rejected_naming_signer(self):
        tampered = SignatureShare(
            signer_id=3, value=(self.shares[1].value + 1) % FIELD_PRIME
        )
        outcome = aggregate_signatures(
            [self.shares[0], tampered],
            MESSAGE,
            nonce_commitments=self.commitments,
            result=self.result,
        )
        self.assertEqual(outcome, [SigningRejection(signer_id=3)])

    def test_cross_message_share_rejected(self):
        # A share computed for a different message does not verify here.
        _, other_shares = make_session(
            self.result, (1, 3), message=b"other", seed_offset=50
        )
        outcome = aggregate_signatures(
            [other_shares[0], self.shares[1]],
            MESSAGE,
            nonce_commitments=self.commitments,
            result=self.result,
        )
        self.assertEqual(outcome, [SigningRejection(signer_id=1)])

    def test_cross_round_share_rejected(self):
        # Same message, but a share from a session with different nonces.
        _, other_shares = make_session(self.result, (1, 3), seed_offset=60)
        outcome = aggregate_signatures(
            [other_shares[0], self.shares[1]],
            MESSAGE,
            nonce_commitments=self.commitments,
            result=self.result,
        )
        self.assertEqual(outcome, [SigningRejection(signer_id=1)])

    def test_commitment_mismatch_rejected(self):
        # The shares were computed against a different nonce commitment set;
        # swapping one commitment changes the challenge for every signer.
        other_commitments, other_shares = make_session(
            self.result, (1, 3), seed_offset=70
        )
        outcome = aggregate_signatures(
            other_shares,
            MESSAGE,
            nonce_commitments=[self.commitments[0], other_commitments[1]],
            result=self.result,
        )
        self.assertEqual(
            outcome, [SigningRejection(signer_id=1), SigningRejection(signer_id=3)]
        )

    def test_every_failing_signer_reported_sorted(self):
        tampered = [
            SignatureShare(signer_id=1, value=(self.shares[0].value + 1) % FIELD_PRIME),
            SignatureShare(signer_id=3, value=(self.shares[1].value + 2) % FIELD_PRIME),
        ]
        outcome = aggregate_signatures(
            [tampered[1], tampered[0]],
            MESSAGE,
            nonce_commitments=self.commitments,
            result=self.result,
        )
        self.assertEqual(
            outcome, [SigningRejection(signer_id=1), SigningRejection(signer_id=3)]
        )

    def test_rejection_is_frozen(self):
        rejection = SigningRejection(signer_id=1)
        with self.assertRaises(FrozenInstanceError):
            rejection.signer_id = 2  # type: ignore[misc]

    def test_verify_share_returns_false_for_tampered_share(self):
        tampered = SignatureShare(
            signer_id=1, value=(self.shares[0].value + 1) % FIELD_PRIME
        )
        self.assertFalse(
            verify_signature_share(
                tampered,
                MESSAGE,
                nonce_commitments=self.commitments,
                result=self.result,
            )
        )


class SigningSessionValidationTest(unittest.TestCase):
    def setUp(self):
        self.result = make_result()
        self.commitments, self.shares = make_session(self.result, (1, 3))

    def test_duplicate_signer_rejected(self):
        with self.assertRaises(ValueError):
            aggregate_signatures(
                [self.shares[0], self.shares[0]],
                MESSAGE,
                nonce_commitments=self.commitments,
                result=self.result,
            )

    def test_missing_signer_rejected(self):
        with self.assertRaises(ValueError):
            aggregate_signatures(
                [self.shares[0]],
                MESSAGE,
                nonce_commitments=self.commitments,
                result=self.result,
            )

    def test_duplicate_nonce_commitment_rejected(self):
        with self.assertRaises(ValueError):
            aggregate_signatures(
                self.shares,
                MESSAGE,
                nonce_commitments=[self.commitments[0], self.commitments[0]],
                result=self.result,
            )

    def test_reused_nonce_value_rejected(self):
        # Two different signers presenting the same nonce value.
        reused = NonceCommitment(signer_id=3, value=self.commitments[0].value)
        with self.assertRaises(ValueError):
            aggregate_signatures(
                self.shares,
                MESSAGE,
                nonce_commitments=[self.commitments[0], reused],
                result=self.result,
            )

    def test_identity_nonce_commitment_rejected(self):
        identity = NonceCommitment(signer_id=3, value=1)
        with self.assertRaises(ValueError):
            aggregate_signatures(
                self.shares,
                MESSAGE,
                nonce_commitments=[self.commitments[0], identity],
                result=self.result,
            )

    def test_too_few_signers_rejected(self):
        with self.assertRaises(ValueError):
            aggregate_signatures(
                [self.shares[0]],
                MESSAGE,
                nonce_commitments=[self.commitments[0]],
                result=self.result,
            )

    def test_non_participant_signer_rejected(self):
        # Signer 9 is not one of the DKG participants.
        _, commitment = make_nonce(9, seed=5)
        with self.assertRaises(ValueError):
            aggregate_signatures(
                self.shares,
                MESSAGE,
                nonce_commitments=[self.commitments[0], commitment],
                result=self.result,
            )

    def test_wrong_types_raise_type_error(self):
        with self.assertRaises(TypeError):
            aggregate_signatures(
                ["not a share"],
                MESSAGE,
                nonce_commitments=self.commitments,
                result=self.result,
            )
        with self.assertRaises(TypeError):
            aggregate_signatures(
                self.shares,
                "not bytes",
                nonce_commitments=self.commitments,
                result=self.result,
            )
        with self.assertRaises(TypeError):
            aggregate_signatures(
                self.shares,
                MESSAGE,
                nonce_commitments=["not a commitment"],
                result=self.result,
            )
        with self.assertRaises(TypeError):
            verify_signature_share(
                "not a share",
                MESSAGE,
                nonce_commitments=self.commitments,
                result=self.result,
            )
        with self.assertRaises(TypeError):
            verify_signature(
                "not a signature",
                MESSAGE,
                public_key=self.result.public_key,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            )

    def test_signature_share_out_of_range_rejected(self):
        with self.assertRaises(ValueError):
            verify_signature_share(
                SignatureShare(signer_id=1, value=FIELD_PRIME),
                MESSAGE,
                nonce_commitments=self.commitments,
                result=self.result,
            )

    def test_verify_signature_rejects_malformed_signature(self):
        signature = aggregate_signatures(
            self.shares,
            MESSAGE,
            nonce_commitments=self.commitments,
            result=self.result,
        )
        with self.assertRaises(ValueError):
            verify_signature(
                dataclasses.replace(signature, value=FIELD_PRIME),
                MESSAGE,
                public_key=self.result.public_key,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            )
        with self.assertRaises(ValueError):
            verify_signature(
                dataclasses.replace(signature, signer_ids=(3, 1)),
                MESSAGE,
                public_key=self.result.public_key,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            )
        with self.assertRaises(ValueError):
            verify_signature(
                signature,
                MESSAGE,
                public_key=1 + GROUP_PRIME,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            )

    def test_create_signature_share_validation(self):
        nonce, commitment = make_nonce(1, seed=42)
        own_share = self.result.dkg_result.shares[0]
        commitments = [commitment, self.commitments[1]]
        with self.assertRaises(ValueError):
            create_signature_share(
                1,
                MESSAGE,
                nonce=0,
                share=own_share,
                nonce_commitments=commitments,
                result=self.result,
            )
        with self.assertRaises(ValueError):
            create_signature_share(
                1,
                MESSAGE,
                nonce=nonce,
                share=self.result.dkg_result.shares[1],
                nonce_commitments=commitments,
                result=self.result,
            )
        with self.assertRaises(ValueError):
            # nonce does not match the published commitment
            create_signature_share(
                1,
                MESSAGE,
                nonce=(nonce + 1) % FIELD_PRIME,
                share=own_share,
                nonce_commitments=commitments,
                result=self.result,
            )
        with self.assertRaises(TypeError):
            create_signature_share(
                1,
                MESSAGE,
                nonce="1",
                share=own_share,
                nonce_commitments=commitments,
                result=self.result,
            )


if __name__ == "__main__":
    unittest.main()
