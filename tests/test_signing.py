"""Tests for the signing DKG and the two-round threshold Schnorr protocol."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    DKGContribution,
    DKGRejection,
    FeldmanCommitment,
    SigningDKGResult,
    SigningContribution,
    SigningNonceCommitment,
    SigningRound,
    SignatureShare,
    SignatureShareRejection,
    aggregate_signature,
    aggregate_signing_dkg,
    create_refresh,
    create_signature_share,
    create_signing_contribution,
    create_signing_nonce_commitment,
    create_signing_round,
    reconstruct_secret,
    refresh,
    schnorr_challenge,
    verify_signature,
    verify_signature_share,
)

# Same toy group as the DKG tests: 8069 = 4 * 2017 + 1 is prime, 16 and
# 256 = 16 ** 2 are distinct generators of the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

# A 3-byte group prime (L = 3) for encoding tests: 2000303 = 2 * 1000151 + 1
# is a safe prime, 9 = 3 ** 2 and 81 = 9 ** 2 generate the order-1000151
# subgroup.
LARGE_FIELD = 1000151
LARGE_GROUP = 2000303
LARGE_G = 9
LARGE_H = 81

MESSAGE = b"threshold schnorr test message"


def fixed_random(seed=1):
    """Deterministic stand-in for secrets.randbelow (same LCG as DKG tests)."""
    state = {"value": seed}

    def randbelow(upper: int) -> int:
        state["value"] = (
            state["value"] * 6364136223846793005 + 1442695040888963407
        ) % upper
        return state["value"]

    return randbelow


def make_signing_contributions(
    participant_ids=(1, 2, 3),
    threshold=2,
    field_prime=FIELD_PRIME,
    group_prime=GROUP_PRIME,
    generator=GENERATOR,
    blinding_generator=BLINDING_GENERATOR,
    seed_base=0,
):
    return [
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


def make_signing_dkg(
    participant_ids=(1, 2, 3),
    threshold=2,
    field_prime=FIELD_PRIME,
    group_prime=GROUP_PRIME,
    generator=GENERATOR,
    blinding_generator=BLINDING_GENERATOR,
    seed_base=0,
):
    outcome = aggregate_signing_dkg(
        make_signing_contributions(
            participant_ids,
            threshold,
            field_prime,
            group_prime,
            generator,
            blinding_generator,
            seed_base,
        )
    )
    assert isinstance(outcome, SigningDKGResult), outcome
    return outcome


def nonce_standin(value):
    """randbelow stand-in for nonce creation; the drawn nonce is value + 1."""
    return lambda upper: value % upper


def make_round(dkg_result, signer_ids=(1, 2), message=MESSAGE, seed=10):
    """Run round one for the given signers with deterministic nonces."""
    commitments = []
    nonces = {}
    for offset, signer_id in enumerate(signer_ids):
        commitment, nonce = create_signing_nonce_commitment(
            signer_id,
            prime=dkg_result.result.commitment.field_prime,
            group_prime=dkg_result.result.commitment.group_prime,
            generator=dkg_result.result.commitment.generator,
            randbelow=fixed_random(seed + 100 * offset + signer_id),
        )
        commitments.append(commitment)
        nonces[signer_id] = nonce
    round_info = create_signing_round(message, tuple(signer_ids), commitments, dkg_result)
    return round_info, commitments, nonces


def make_shares(dkg_result, round_info, nonces):
    shares = []
    for signer_id in round_info.signer_ids:
        index = dkg_result.result.participant_ids.index(signer_id)
        secret_share = dkg_result.result.shares[index].y
        shares.append(
            create_signature_share(
                signer_id, secret_share, nonces[signer_id], round_info, dkg_result
            )
        )
    return shares


def sign_full(dkg_result, signer_ids=(1, 2), message=MESSAGE):
    round_info, commitments, nonces = make_round(dkg_result, signer_ids, message)
    shares = make_shares(dkg_result, round_info, nonces)
    return round_info, shares


class CreateSigningContributionTest(unittest.TestCase):
    def test_nested_contribution_is_unchanged_dkg_contribution(self):
        contribution = make_signing_contributions((1, 2, 3), 2)[0]
        self.assertIsInstance(contribution, SigningContribution)
        dealing = contribution.contribution
        self.assertIsInstance(dealing, DKGContribution)
        self.assertEqual(dealing.sender_id, 1)
        self.assertEqual(dealing.participant_ids, (1, 2, 3))
        self.assertEqual(len(dealing.shares), 3)
        self.assertEqual(len(dealing.blinding_shares), 3)
        self.assertEqual(len(dealing.commitment.values), 2)

    def test_feldman_commits_to_same_polynomial_as_pedersen_shares(self):
        contribution = make_signing_contributions((1, 2, 3), 2)[0]
        # A SigningContribution can be aggregated by the plain DKG API and
        # the plain shares verify against the Feldman commitment too.
        from thresholdsign import verify_share

        for share in contribution.contribution.shares:
            self.assertTrue(verify_share(share, contribution.feldman_commitment))
        self.assertEqual(
            (
                contribution.feldman_commitment.field_prime,
                contribution.feldman_commitment.group_prime,
                contribution.feldman_commitment.generator,
            ),
            (FIELD_PRIME, GROUP_PRIME, GENERATOR),
        )
        self.assertEqual(len(contribution.feldman_commitment.values), 2)

    def test_pedersen_shares_verify(self):
        from thresholdsign import verify_pedersen_share

        for contribution in make_signing_contributions():
            for share, blinding_share in zip(
                contribution.contribution.shares,
                contribution.contribution.blinding_shares,
            ):
                self.assertTrue(
                    verify_pedersen_share(
                        share, blinding_share, contribution.contribution.commitment
                    )
                )

    def test_all_zero_source_allowed(self):
        contribution = create_signing_contribution(
            1, (1, 2, 3), 2,
            prime=FIELD_PRIME, group_prime=GROUP_PRIME,
            generator=GENERATOR, blinding_generator=BLINDING_GENERATOR,
            randbelow=lambda upper: 0,
        )
        self.assertEqual(contribution.feldman_commitment.values, (1, 1))
        self.assertEqual(contribution.contribution.commitment.values, (1, 1))

    def test_threshold_one(self):
        contributions = make_signing_contributions((1, 2), 1)
        self.assertEqual(len(contributions[0].feldman_commitment.values), 1)

    def test_contribution_is_frozen(self):
        contribution = make_signing_contributions()[0]
        with self.assertRaises(FrozenInstanceError):
            contribution.feldman_commitment = None  # type: ignore[misc]

    def test_does_not_store_secrets_or_coefficients(self):
        contribution = make_signing_contributions()[0]
        self.assertEqual(
            {f.name for f in dataclasses.fields(contribution)},
            {"contribution", "feldman_commitment"},
        )
        self.assertFalse(hasattr(contribution, "coefficients"))
        self.assertFalse(hasattr(contribution, "secret"))
        self.assertFalse(hasattr(contribution, "blinding_coefficients"))

    def test_validation_matches_plain_dkg(self):
        with self.assertRaises(ValueError):
            create_signing_contribution(
                1, (1, 2, 2), 2,
                prime=FIELD_PRIME, group_prime=GROUP_PRIME,
                generator=GENERATOR, blinding_generator=BLINDING_GENERATOR,
            )
        with self.assertRaises(ValueError):
            create_signing_contribution(
                4, (1, 2, 3), 2,
                prime=FIELD_PRIME, group_prime=GROUP_PRIME,
                generator=GENERATOR, blinding_generator=BLINDING_GENERATOR,
            )
        with self.assertRaises(ValueError):
            create_signing_contribution(
                1, (1, 2, 3), 4,
                prime=FIELD_PRIME, group_prime=GROUP_PRIME,
                generator=GENERATOR, blinding_generator=BLINDING_GENERATOR,
            )
        with self.assertRaises(TypeError):
            create_signing_contribution(
                "1", (1, 2, 3), 2,
                prime=FIELD_PRIME, group_prime=GROUP_PRIME,
                generator=GENERATOR, blinding_generator=BLINDING_GENERATOR,
            )
        with self.assertRaises(TypeError):
            create_signing_contribution(
                1, (1, "2", 3), 2,
                prime=FIELD_PRIME, group_prime=GROUP_PRIME,
                generator=GENERATOR, blinding_generator=BLINDING_GENERATOR,
            )
        with self.assertRaises(ValueError):
            create_signing_contribution(
                1, (1, 2, 3), 2,
                prime=FIELD_PRIME, group_prime=GROUP_PRIME,
                generator=1, blinding_generator=BLINDING_GENERATOR,
            )


class AggregateSigningDkgTest(unittest.TestCase):
    def setUp(self):
        self.contributions = make_signing_contributions()

    def test_success_fields(self):
        outcome = aggregate_signing_dkg(self.contributions)
        self.assertIsInstance(outcome, SigningDKGResult)
        self.assertEqual(outcome.result.participant_ids, (1, 2, 3))
        self.assertEqual(len(outcome.verification_shares), 3)
        self.assertTrue(0 < outcome.public_key < GROUP_PRIME)

    def test_result_equals_plain_dkg_result(self):
        from thresholdsign import aggregate_dkg

        outcome = aggregate_signing_dkg(self.contributions)
        plain = aggregate_dkg([c.contribution for c in self.contributions])
        self.assertEqual(outcome.result, plain)

    def test_verification_shares_equal_g_to_aggregated_shares(self):
        outcome = aggregate_signing_dkg(self.contributions)
        for share, Y_i in zip(outcome.result.shares, outcome.verification_shares):
            self.assertEqual(pow(GENERATOR, share.y, GROUP_PRIME), Y_i)

    def test_public_key_is_g_to_joint_secret(self):
        outcome = aggregate_signing_dkg(self.contributions)
        secret = reconstruct_secret(outcome.result.shares[:2], prime=FIELD_PRIME)
        self.assertEqual(pow(GENERATOR, secret, GROUP_PRIME), outcome.public_key)

    def test_public_key_is_product_of_constant_feldman_commitments(self):
        outcome = aggregate_signing_dkg(self.contributions)
        expected = 1
        for contribution in self.contributions:
            expected = (
                expected * contribution.feldman_commitment.values[0]
            ) % GROUP_PRIME
        self.assertEqual(outcome.public_key, expected)

    def test_verification_share_is_product_of_feldman_evaluations(self):
        outcome = aggregate_signing_dkg(self.contributions)
        for index, participant_id in enumerate((1, 2, 3)):
            expected = 1
            for contribution in self.contributions:
                evaluation = 1
                x_power = 1
                for value in contribution.feldman_commitment.values:
                    evaluation = evaluation * pow(value, x_power, GROUP_PRIME) % GROUP_PRIME
                    x_power = x_power * participant_id % FIELD_PRIME
                expected = expected * evaluation % GROUP_PRIME
            self.assertEqual(outcome.verification_shares[index], expected)

    def test_threshold_one_and_five_participants(self):
        ids = tuple(range(1, 6))
        outcome = make_signing_dkg(ids, 1)
        secret = reconstruct_secret([outcome.result.shares[0]], prime=FIELD_PRIME)
        self.assertEqual(pow(GENERATOR, secret, GROUP_PRIME), outcome.public_key)

    def test_large_group(self):
        ids = (1, 2, 3)
        outcome = make_signing_dkg(
            ids, 2,
            field_prime=LARGE_FIELD, group_prime=LARGE_GROUP,
            generator=LARGE_G, blinding_generator=LARGE_H,
        )
        secret = reconstruct_secret(outcome.result.shares[:2], prime=LARGE_FIELD)
        self.assertEqual(pow(LARGE_G, secret, LARGE_GROUP), outcome.public_key)

    def test_input_order_does_not_matter(self):
        shuffled = [self.contributions[2], self.contributions[0], self.contributions[1]]
        self.assertEqual(
            aggregate_signing_dkg(self.contributions),
            aggregate_signing_dkg(shuffled),
        )

    def test_result_is_frozen(self):
        outcome = aggregate_signing_dkg(self.contributions)
        with self.assertRaises(FrozenInstanceError):
            outcome.public_key = 1  # type: ignore[misc]

    def test_no_secret_fields(self):
        outcome = aggregate_signing_dkg(self.contributions)
        self.assertEqual(
            {f.name for f in dataclasses.fields(outcome)},
            {"result", "public_key", "verification_shares"},
        )
        self.assertFalse(hasattr(outcome, "secret"))


class AggregateSigningDkgFailureTest(unittest.TestCase):
    def setUp(self):
        self.contributions = make_signing_contributions()

    def test_tampered_pedersen_share_yields_sorted_rejection(self):
        bad = self.contributions[1]
        dealing = bad.contribution
        tampered_dealing = dataclasses.replace(
            dealing,
            shares=(ShareLike(dealing.shares[0].x, dealing.shares[0].y + 1),)
            + dealing.shares[1:],
        )
        tampered = dataclasses.replace(bad, contribution=tampered_dealing)
        outcome = aggregate_signing_dkg(
            [self.contributions[0], tampered, self.contributions[2]]
        )
        self.assertEqual(outcome, [DKGRejection(sender_id=2)])

    def test_multiple_failures_sorted_and_order_independent(self):
        tampered = []
        for contribution in (self.contributions[0], self.contributions[2]):
            dealing = contribution.contribution
            tampered_dealing = dataclasses.replace(
                dealing,
                shares=(ShareLike(dealing.shares[0].x, dealing.shares[0].y + 1),)
                + dealing.shares[1:],
                # keep Feldman on the same polynomial: break Pedersen only
            )
            tampered.append(
                dataclasses.replace(contribution, contribution=tampered_dealing)
            )
        first_order = [tampered[0], self.contributions[1], tampered[1]]
        second_order = [tampered[1], self.contributions[1], tampered[0]]
        expected = [DKGRejection(sender_id=1), DKGRejection(sender_id=3)]
        self.assertEqual(aggregate_signing_dkg(first_order), expected)
        self.assertEqual(aggregate_signing_dkg(second_order), expected)

    def test_feldman_not_bound_to_shares_is_value_error(self):
        # Swap the Feldman commitment in from another participant's dealing:
        # structurally legal but a different sharing polynomial.
        bad = dataclasses.replace(
            self.contributions[0],
            feldman_commitment=self.contributions[1].feldman_commitment,
        )
        with self.assertRaises(ValueError):
            aggregate_signing_dkg([bad, self.contributions[1], self.contributions[2]])

    def test_feldman_illegal_value_is_value_error(self):
        bad_feldman = dataclasses.replace(
            self.contributions[0].feldman_commitment, values=(0, 1)
        )
        bad = dataclasses.replace(self.contributions[0], feldman_commitment=bad_feldman)
        with self.assertRaises(ValueError):
            aggregate_signing_dkg([bad, self.contributions[1], self.contributions[2]])

    def test_feldman_wrong_threshold_is_value_error(self):
        longer = self.contributions[0].feldman_commitment.values + (
            self.contributions[0].feldman_commitment.values[0],
        )
        bad_feldman = dataclasses.replace(
            self.contributions[0].feldman_commitment, values=longer
        )
        bad = dataclasses.replace(self.contributions[0], feldman_commitment=bad_feldman)
        with self.assertRaises(ValueError):
            aggregate_signing_dkg([bad, self.contributions[1], self.contributions[2]])

    def test_feldman_other_group_is_value_error(self):
        bad_feldman = dataclasses.replace(
            self.contributions[0].feldman_commitment, group_prime=LARGE_GROUP
        )
        bad = dataclasses.replace(self.contributions[0], feldman_commitment=bad_feldman)
        with self.assertRaises(ValueError):
            aggregate_signing_dkg([bad, self.contributions[1], self.contributions[2]])

    def test_wrong_types_raise_type_error(self):
        with self.assertRaises(TypeError):
            aggregate_signing_dkg(
                [c.contribution for c in self.contributions]  # plain DKG objects
            )
        with self.assertRaises(TypeError):
            aggregate_signing_dkg(["nope"])
        bad = dataclasses.replace(self.contributions[0], feldman_commitment=(1, 1))
        with self.assertRaises(TypeError):
            aggregate_signing_dkg([bad, self.contributions[1], self.contributions[2]])

    def test_missing_and_duplicate_participants(self):
        with self.assertRaises(ValueError):
            aggregate_signing_dkg(self.contributions[:2])
        with self.assertRaises(ValueError):
            aggregate_signing_dkg(
                [self.contributions[0], self.contributions[0], self.contributions[2]]
            )

    def test_empty_input(self):
        with self.assertRaises(ValueError):
            aggregate_signing_dkg([])


def ShareLike(x, y):
    from thresholdsign import Share
    return Share(x, y % FIELD_PRIME)


class NonceCommitmentTest(unittest.TestCase):
    def test_returns_commitment_and_nonzero_nonce(self):
        commitment, nonce = create_signing_nonce_commitment(
            1, prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
            randbelow=nonce_standin(0),
        )
        self.assertIsInstance(commitment, SigningNonceCommitment)
        self.assertEqual(commitment.signer_id, 1)
        self.assertEqual(nonce, 1)
        self.assertEqual(commitment.commitment, GENERATOR)

    def test_commitment_is_g_to_nonce(self):
        for value in (1, 2, 500, FIELD_PRIME - 2):
            commitment, nonce = create_signing_nonce_commitment(
                2, prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
                randbelow=nonce_standin(value),
            )
            self.assertEqual(nonce, value + 1)
            self.assertEqual(commitment.commitment, pow(GENERATOR, value + 1, GROUP_PRIME))

    def test_injected_randbelow_range_is_prime_minus_one(self):
        seen = []
        create_signing_nonce_commitment(
            1, prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
            randbelow=lambda upper: seen.append(upper) or 0,
        )
        self.assertEqual(seen, [FIELD_PRIME - 1])

    def test_randbelow_out_of_range_rejected(self):
        with self.assertRaises(ValueError):
            create_signing_nonce_commitment(
                1, prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
                randbelow=lambda upper: upper,  # == prime - 1, out of range
            )
        with self.assertRaises(ValueError):
            create_signing_nonce_commitment(
                1, prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
                randbelow=lambda upper: -1,
            )

    def test_randbelow_wrong_return_type_rejected(self):
        with self.assertRaises(TypeError):
            create_signing_nonce_commitment(
                1, prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
                randbelow=lambda upper: 1.0,
            )

    def test_bad_signer_id_and_group(self):
        with self.assertRaises(ValueError):
            create_signing_nonce_commitment(
                0, prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
            )
        with self.assertRaises(ValueError):
            create_signing_nonce_commitment(
                FIELD_PRIME, prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
            )
        with self.assertRaises(TypeError):
            create_signing_nonce_commitment(
                "1", prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
            )

    def test_commitment_is_frozen_and_has_no_nonce_field(self):
        commitment, _nonce = create_signing_nonce_commitment(
            1, prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
        )
        with self.assertRaises(FrozenInstanceError):
            commitment.commitment = 1  # type: ignore[misc]
        self.assertEqual(
            {f.name for f in dataclasses.fields(commitment)},
            {"signer_id", "commitment"},
        )


class SigningRoundTest(unittest.TestCase):
    def setUp(self):
        self.dkg = make_signing_dkg()

    def _commitments(self, signer_ids=(1, 2)):
        return [
            create_signing_nonce_commitment(
                signer_id,
                prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
                randbelow=fixed_random(signer_id * 31 + 7),
            )
            for signer_id in signer_ids
        ]

    def test_round_fields_and_R_product(self):
        pairs = self._commitments()
        commitments = [commitment for commitment, _ in pairs]
        round_info = create_signing_round(MESSAGE, (1, 2), commitments, self.dkg)
        self.assertIsInstance(round_info, SigningRound)
        self.assertEqual(round_info.message, MESSAGE)
        self.assertEqual(round_info.signer_ids, (1, 2))
        expected_R = commitments[0].commitment * commitments[1].commitment % GROUP_PRIME
        self.assertEqual(round_info.R, expected_R)
        self.assertTrue(0 <= round_info.challenge < FIELD_PRIME)

    def test_accepts_nonconsecutive_and_superset_signer_ids(self):
        dkg = make_signing_dkg((1, 2, 3, 4), 2)
        pairs = []
        for signer_id in (2, 4):
            pairs.append(
                create_signing_nonce_commitment(
                    signer_id, prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
                    randbelow=fixed_random(signer_id),
                )
            )
        round_info = create_signing_round(
            MESSAGE, (2, 4), [c for c, _ in pairs], dkg
        )
        self.assertEqual(round_info.signer_ids, (2, 4))

    def test_unsorted_signer_ids_rejected(self):
        commitments = [c for c, _ in self._commitments((1, 2))]
        with self.assertRaises(ValueError):
            create_signing_round(MESSAGE, (2, 1), list(reversed(commitments)), self.dkg)

    def test_duplicate_signer_ids_rejected(self):
        commitments = [c for c, _ in self._commitments((1, 2))]
        with self.assertRaises(ValueError):
            create_signing_round(MESSAGE, (1, 1), commitments, self.dkg)

    def test_too_few_signers_rejected(self):
        commitments = [self._commitments()[0][0]]
        with self.assertRaises(ValueError):
            create_signing_round(MESSAGE, (1,), commitments, self.dkg)

    def test_threshold_one_round(self):
        dkg = make_signing_dkg((1, 2), 1)
        commitment, _ = create_signing_nonce_commitment(
            1, prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
        )
        round_info = create_signing_round(MESSAGE, (1,), [commitment], dkg)
        self.assertEqual(round_info.signer_ids, (1,))
        self.assertEqual(round_info.R, commitment.commitment)

    def test_non_participant_signer_rejected(self):
        commitments = [
            create_signing_nonce_commitment(
                signer_id, prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
            )[0]
            for signer_id in (2, 9)
        ]
        with self.assertRaises(ValueError):
            create_signing_round(MESSAGE, (2, 9), commitments, self.dkg)

    def test_commitment_input_order_is_canonicalized(self):
        good = [commitment for commitment, _ in self._commitments()]
        swapped = [good[1], good[0]]
        round_a = create_signing_round(MESSAGE, (1, 2), good, self.dkg)
        round_b = create_signing_round(MESSAGE, (1, 2), swapped, self.dkg)
        self.assertEqual(round_a, round_b)

    def test_commitment_with_unknown_signer_rejected(self):
        good = self._commitments()
        stray = dataclasses.replace(good[0][0], signer_id=9)
        with self.assertRaises(ValueError):
            create_signing_round(MESSAGE, (1, 2), [stray, good[1][0]], self.dkg)

    def test_swapped_commitment_values_fail_share_verification(self):
        # R values swapped between signer slots cannot be detected at round
        # creation (they are bare group elements) but invalidate the shares.
        good = self._commitments()
        commitments = [
            dataclasses.replace(good[0][0], commitment=good[1][0].commitment),
            dataclasses.replace(good[1][0], commitment=good[0][0].commitment),
        ]
        round_info = create_signing_round(MESSAGE, (1, 2), commitments, self.dkg)
        # The honest signer recomputes g^r_i and finds it differs from the
        # value published under its id: producing a share is refused.
        with self.assertRaises(ValueError):
            create_signature_share(
                1, self.dkg.result.shares[0].y, good[0][1], round_info, self.dkg
            )
        # Forging a share object with the correct signer id still fails the
        # public g^z_i = R_i Y_i^(c lambda_i) check.
        forged = SignatureShare(signer_id=1, nonce_commitment=commitments[0].commitment, z=1)
        self.assertFalse(verify_signature_share(forged, round_info, self.dkg))

    def test_missing_or_extra_commitment_rejected(self):
        commitments = [c for c, _ in self._commitments()]
        with self.assertRaises(ValueError):
            create_signing_round(MESSAGE, (1, 2), commitments[:1], self.dkg)
        with self.assertRaises(ValueError):
            create_signing_round(
                MESSAGE, (1, 2), commitments + [commitments[0]], self.dkg
            )

    def test_duplicate_commitment_value_rejected(self):
        commitment, _ = create_signing_nonce_commitment(
            1, prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
            randbelow=nonce_standin(10),
        )
        copied = dataclasses.replace(commitment, signer_id=2)
        with self.assertRaises(ValueError):
            create_signing_round(MESSAGE, (1, 2), [commitment, copied], self.dkg)

    def test_identity_commitment_rejected(self):
        commitment, _ = self._commitments()[0]
        bad = dataclasses.replace(commitment, commitment=1)
        with self.assertRaises(ValueError):
            create_signing_round(
                MESSAGE, (1, 2),
                [bad, self._commitments()[1][0]], self.dkg,
            )

    def test_round_is_frozen(self):
        commitments = [c for c, _ in self._commitments()]
        round_info = create_signing_round(MESSAGE, (1, 2), commitments, self.dkg)
        with self.assertRaises(FrozenInstanceError):
            round_info.R = 1  # type: ignore[misc]

    def test_wrong_types(self):
        commitments = [c for c, _ in self._commitments()]
        with self.assertRaises(TypeError):
            create_signing_round("not bytes", (1, 2), commitments, self.dkg)
        with self.assertRaises(TypeError):
            create_signing_round(MESSAGE, "12", commitments, self.dkg)
        with self.assertRaises(TypeError):
            create_signing_round(MESSAGE, (1, 2), [(1, 2)], self.dkg)
        with self.assertRaises(TypeError):
            create_signing_round(
                MESSAGE, (1, 2), commitments,
                dataclasses.replace(self.dkg, public_key="1"),
            )


class ChallengeEncodingTest(unittest.TestCase):
    def _expected(self, message, public_key, R, signer_ids, field_prime, group_prime):
        length = (group_prime.bit_length() + 7) // 8
        buffer = b"thresholdsign/schnorr/v1" + hashlib.sha256(message).digest()
        buffer += public_key.to_bytes(length, "big")
        buffer += R.to_bytes(length, "big")
        for signer_id in signer_ids:
            buffer += signer_id.to_bytes(length, "big")
        return int.from_bytes(hashlib.sha256(buffer).digest(), "big") % field_prime

    def test_toy_group_two_byte_length(self):
        self.assertEqual((GROUP_PRIME.bit_length() + 7) // 8, 2)
        dkg = make_signing_dkg()
        round_info, _shares = sign_full(dkg)
        expected = self._expected(
            MESSAGE, dkg.public_key, round_info.R, (1, 2), FIELD_PRIME, GROUP_PRIME
        )
        self.assertEqual(round_info.challenge, expected)

    def test_large_group_three_byte_length(self):
        self.assertEqual((LARGE_GROUP.bit_length() + 7) // 8, 3)
        dkg = make_signing_dkg(
            (1, 2, 3), 2,
            field_prime=LARGE_FIELD, group_prime=LARGE_GROUP,
            generator=LARGE_G, blinding_generator=LARGE_H,
        )
        commitments = [
            create_signing_nonce_commitment(
                signer_id,
                prime=LARGE_FIELD, group_prime=LARGE_GROUP, generator=LARGE_G,
                randbelow=fixed_random(signer_id + 99),
            )[0]
            for signer_id in (1, 3)
        ]
        round_info = create_signing_round(MESSAGE, (1, 3), commitments, dkg)
        expected = self._expected(
            MESSAGE, dkg.public_key, round_info.R, (1, 3), LARGE_FIELD, LARGE_GROUP
        )
        self.assertEqual(round_info.challenge, expected)

    def test_challenge_changes_with_message(self):
        dkg = make_signing_dkg()
        r1, _ = sign_full(dkg, message=b"message one")
        r2, _ = sign_full(dkg, message=b"message two")
        self.assertNotEqual(r1.challenge, r2.challenge)

    def test_challenge_changes_with_signer_set(self):
        dkg = make_signing_dkg((1, 2, 3), 2)
        r12, _ = sign_full(dkg, (1, 2))
        r13, _ = sign_full(dkg, (1, 3))
        self.assertNotEqual(r12.challenge, r13.challenge)
        # And the standalone helper matches the round computation.
        self.assertEqual(
            r12.challenge,
            schnorr_challenge(
                MESSAGE, dkg.public_key, r12.R, (1, 2),
                field_prime=FIELD_PRIME, group_prime=GROUP_PRIME,
            ),
        )


class SignatureShareTest(unittest.TestCase):
    def setUp(self):
        self.dkg = make_signing_dkg()
        self.round_info, self.commitments, self.nonces = make_round(self.dkg, (1, 2))
        self.shares = make_shares(self.dkg, self.round_info, self.nonces)

    def test_shares_verify(self):
        for share in self.shares:
            self.assertIs(verify_signature_share(share, self.round_info, self.dkg), True)

    def test_z_formula(self):
        for signer_id, share in zip((1, 2), self.shares):
            ids = (1, 2)
            numerator = 1
            denominator = 1
            for other in ids:
                if other == signer_id:
                    continue
                numerator = numerator * (-other) % FIELD_PRIME
                denominator = denominator * (signer_id - other) % FIELD_PRIME
            weight = numerator * pow(denominator, -1, FIELD_PRIME) % FIELD_PRIME
            secret = self.dkg.result.shares[signer_id - 1].y
            expected_z = (
                self.nonces[signer_id] + self.round_info.challenge * weight * secret
            ) % FIELD_PRIME
            self.assertEqual(share.z, expected_z)
            self.assertEqual(share.nonce_commitment, self.commitments[signer_id - 1].commitment)

    def test_lagrange_weights_at_zero(self):
        # {1,2}: lambda_1 = -2/(1-2) = 2, lambda_2 = -1/(2-1) = -1 = 2016
        self.assertEqual(self.shares[0].z, self.shares[0].z)  # weights tested above
        dkg = make_signing_dkg((1, 2, 3), 2)
        round_info, _, nonces = make_round(dkg, (1, 3))
        shares = make_shares(dkg, round_info, nonces)
        # lambda_1 = -3/(1-3) = 3*inv(2) = 3*1009 mod 2017 = 1010
        # lambda_3 = -1/(3-1) = -1*1009 = 1008
        w1 = (-3) * pow(1 - 3, -1, FIELD_PRIME) % FIELD_PRIME
        w3 = (-1) * pow(3 - 1, -1, FIELD_PRIME) % FIELD_PRIME
        self.assertEqual((w1, w3), (1010, 1008))
        expected_1 = (nonces[1] + round_info.challenge * w1 * dkg.result.shares[0].y) % FIELD_PRIME
        expected_3 = (nonces[3] + round_info.challenge * w3 * dkg.result.shares[2].y) % FIELD_PRIME
        self.assertEqual(shares[0].z, expected_1)
        self.assertEqual(shares[1].z, expected_3)

    def test_tampered_z_returns_false(self):
        bad = dataclasses.replace(self.shares[0], z=(self.shares[0].z + 1) % FIELD_PRIME)
        self.assertFalse(verify_signature_share(bad, self.round_info, self.dkg))

    def test_tampered_commitment_returns_false(self):
        bad = dataclasses.replace(self.shares[0], nonce_commitment=self.commitments[1].commitment)
        self.assertFalse(verify_signature_share(bad, self.round_info, self.dkg))

    def test_share_from_other_message_returns_false(self):
        other_round, _, _ = make_round(self.dkg, (1, 2), message=b"a different message")
        self.assertFalse(verify_signature_share(self.shares[0], other_round, self.dkg))

    def test_share_from_other_round_same_message_returns_false(self):
        # A second round with fresh nonces: the old share must not carry over.
        other_round, _, _ = make_round(self.dkg, (1, 2), message=MESSAGE, seed=77)
        self.assertFalse(verify_signature_share(self.shares[0], other_round, self.dkg))

    def test_share_from_other_signer_set_returns_false(self):
        other_round, _, other_nonces = make_round(self.dkg, (1, 3))
        foreign = make_shares(self.dkg, other_round, other_nonces)[0]
        self.assertFalse(verify_signature_share(foreign, self.round_info, self.dkg))

    def test_edited_round_challenge_returns_false(self):
        bad_round = dataclasses.replace(
            self.round_info, challenge=(self.round_info.challenge + 1) % FIELD_PRIME
        )
        self.assertFalse(verify_signature_share(self.shares[0], bad_round, self.dkg))

    def test_edited_round_R_returns_false(self):
        bad_round = dataclasses.replace(
            self.round_info,
            R=(self.round_info.R + 1) % GROUP_PRIME,
        )
        self.assertFalse(verify_signature_share(self.shares[0], bad_round, self.dkg))

    def test_wrong_verification_share_context_returns_false(self):
        other_dkg = make_signing_dkg(participant_ids=(1, 2, 3), threshold=2, seed_base=5000)
        self.assertFalse(
            verify_signature_share(self.shares[0], self.round_info, other_dkg)
        )

    def test_signer_not_in_round_is_value_error(self):
        with self.assertRaises(ValueError):
            create_signature_share(
                3, self.dkg.result.shares[2].y, 5, self.round_info, self.dkg
            )

    def test_zero_nonce_rejected(self):
        with self.assertRaises(ValueError):
            create_signature_share(
                1, self.dkg.result.shares[0].y, 0, self.round_info, self.dkg
            )

    def test_nonce_not_matching_commitment_rejected(self):
        with self.assertRaises(ValueError):
            create_signature_share(
                1, self.dkg.result.shares[0].y,
                self.nonces[2], self.round_info, self.dkg,
            )

    def test_share_out_of_range_rejected(self):
        with self.assertRaises(ValueError):
            create_signature_share(
                1, FIELD_PRIME, self.nonces[1], self.round_info, self.dkg
            )

    def test_wrong_types_raise_type_error(self):
        with self.assertRaises(TypeError):
            verify_signature_share((1, 2), self.round_info, self.dkg)
        with self.assertRaises(TypeError):
            verify_signature_share(self.shares[0], "round", self.dkg)
        with self.assertRaises(TypeError):
            create_signature_share(
                "1", self.dkg.result.shares[0].y, self.nonces[1], self.round_info, self.dkg
            )

    def test_illegal_share_values_raise_value_error(self):
        bad = dataclasses.replace(self.shares[0], z=FIELD_PRIME)
        with self.assertRaises(ValueError):
            verify_signature_share(bad, self.round_info, self.dkg)
        bad = dataclasses.replace(self.shares[0], signer_id=0)
        with self.assertRaises(ValueError):
            verify_signature_share(bad, self.round_info, self.dkg)

    def test_share_is_frozen_with_no_secret_fields(self):
        with self.assertRaises(FrozenInstanceError):
            self.shares[0].z = 1  # type: ignore[misc]
        self.assertEqual(
            {f.name for f in dataclasses.fields(self.shares[0])},
            {"signer_id", "nonce_commitment", "z"},
        )
        self.assertFalse(hasattr(self.shares[0], "nonce"))
        self.assertFalse(hasattr(self.shares[0], "secret_share"))


class AggregateSignatureTest(unittest.TestCase):
    def setUp(self):
        self.dkg = make_signing_dkg()
        self.round_info, _commitments, self.nonces = make_round(self.dkg, (1, 2))
        self.shares = make_shares(self.dkg, self.round_info, self.nonces)

    def test_success(self):
        signature = aggregate_signature(self.shares, self.round_info, self.dkg)
        self.assertIsInstance(signature, AggregateSignature)
        self.assertEqual(signature.R, self.round_info.R)
        self.assertEqual(signature.signer_ids, (1, 2))
        self.assertEqual(
            signature.z, sum(share.z for share in self.shares) % FIELD_PRIME
        )

    def test_final_verification_equation(self):
        signature = aggregate_signature(self.shares, self.round_info, self.dkg)
        left = pow(GENERATOR, signature.z, GROUP_PRIME)
        right = signature.R * pow(self.dkg.public_key, self.round_info.challenge, GROUP_PRIME) % GROUP_PRIME
        self.assertEqual(left, right)

    def test_input_order_does_not_matter(self):
        signature = aggregate_signature(self.shares, self.round_info, self.dkg)
        reversed_signature = aggregate_signature(
            list(reversed(self.shares)), self.round_info, self.dkg
        )
        self.assertEqual(signature, reversed_signature)

    def test_all_three_of_three_with_threshold_two(self):
        dkg = make_signing_dkg((1, 2, 3), 2)
        round_info, _commitments, nonces = make_round(dkg, (1, 2, 3))
        shares = make_shares(dkg, round_info, nonces)
        signature = aggregate_signature(shares, round_info, dkg)
        self.assertIsInstance(signature, AggregateSignature)
        self.assertTrue(
            verify_signature(
                MESSAGE, signature, dkg.public_key,
                prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
            )
        )

    def test_nonconsecutive_signer_subset(self):
        dkg = make_signing_dkg((1, 2, 3, 4), 2)
        round_info, _commitments, nonces = make_round(dkg, (2, 4))
        shares = make_shares(dkg, round_info, nonces)
        signature = aggregate_signature(shares, round_info, dkg)
        self.assertTrue(
            verify_signature(
                MESSAGE, signature, dkg.public_key,
                prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
            )
        )

    def test_threshold_one(self):
        dkg = make_signing_dkg((1, 2), 1)
        round_info, _commitments, nonces = make_round(dkg, (1,))
        shares = make_shares(dkg, round_info, nonces)
        signature = aggregate_signature(shares, round_info, dkg)
        self.assertTrue(
            verify_signature(
                MESSAGE, signature, dkg.public_key,
                prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
            )
        )

    def test_large_group_end_to_end(self):
        dkg = make_signing_dkg(
            (1, 2, 3), 2,
            field_prime=LARGE_FIELD, group_prime=LARGE_GROUP,
            generator=LARGE_G, blinding_generator=LARGE_H,
        )
        commitments = [
            create_signing_nonce_commitment(
                signer_id, prime=LARGE_FIELD, group_prime=LARGE_GROUP, generator=LARGE_G,
                randbelow=fixed_random(signer_id + 5),
            )
            for signer_id in (1, 2)
        ]
        nonces = {signer_id: nonce for signer_id, (_commitment, nonce) in zip((1, 2), commitments)}
        commitments = [commitment for commitment, _ in commitments]
        round_info = create_signing_round(MESSAGE, (1, 2), commitments, dkg)
        shares = make_shares(dkg, round_info, nonces)
        signature = aggregate_signature(shares, round_info, dkg)
        self.assertTrue(
            verify_signature(
                MESSAGE, signature, dkg.public_key,
                prime=LARGE_FIELD, group_prime=LARGE_GROUP, generator=LARGE_G,
            )
        )

    def test_tampered_share_yields_sorted_rejection(self):
        bad = dataclasses.replace(self.shares[1], z=(self.shares[1].z + 1) % FIELD_PRIME)
        self.assertEqual(
            aggregate_signature([self.shares[0], bad], self.round_info, self.dkg),
            [SignatureShareRejection(signer_id=2)],
        )
        self.assertEqual(
            aggregate_signature([bad, self.shares[0]], self.round_info, self.dkg),
            [SignatureShareRejection(signer_id=2)],
        )

    def test_multiple_bad_shares_all_reported_sorted(self):
        bad = [
            dataclasses.replace(share, z=(share.z + 1) % FIELD_PRIME)
            for share in self.shares
        ]
        self.assertEqual(
            aggregate_signature(list(reversed(bad)), self.round_info, self.dkg),
            [SignatureShareRejection(signer_id=1), SignatureShareRejection(signer_id=2)],
        )

    def test_missing_share_is_value_error(self):
        with self.assertRaises(ValueError):
            aggregate_signature(self.shares[:1], self.round_info, self.dkg)

    def test_duplicate_share_is_value_error(self):
        with self.assertRaises(ValueError):
            aggregate_signature(
                [self.shares[0], self.shares[0], self.shares[1]],
                self.round_info, self.dkg,
            )

    def test_extra_share_is_value_error(self):
        dkg = make_signing_dkg((1, 2, 3), 2)
        round_info, _commitments, nonces = make_round(dkg, (1, 2, 3))
        shares = make_shares(dkg, round_info, nonces)
        with self.assertRaises(ValueError):
            aggregate_signature(shares[:2], round_info, dkg)

    def test_empty_input(self):
        with self.assertRaises(ValueError):
            aggregate_signature([], self.round_info, self.dkg)

    def test_wrong_types(self):
        with self.assertRaises(TypeError):
            aggregate_signature(["nope"], self.round_info, self.dkg)
        with self.assertRaises(TypeError):
            aggregate_signature(self.shares, "round", self.dkg)

    def test_signature_is_frozen(self):
        signature = aggregate_signature(self.shares, self.round_info, self.dkg)
        with self.assertRaises(FrozenInstanceError):
            signature.z = 1  # type: ignore[misc]
        self.assertEqual(
            {f.name for f in dataclasses.fields(signature)},
            {"R", "z", "signer_ids"},
        )

    def test_rejection_is_frozen(self):
        rejection = SignatureShareRejection(signer_id=1)
        with self.assertRaises(FrozenInstanceError):
            rejection.signer_id = 2  # type: ignore[misc]


class VerifySignatureTest(unittest.TestCase):
    def setUp(self):
        self.dkg = make_signing_dkg()
        self.round_info, _commitments, self.nonces = make_round(self.dkg, (1, 2))
        self.shares = make_shares(self.dkg, self.round_info, self.nonces)
        self.signature = aggregate_signature(self.shares, self.round_info, self.dkg)

    def _verify(self, message=MESSAGE, signature=None, public_key=None):
        return verify_signature(
            message,
            signature if signature is not None else self.signature,
            public_key if public_key is not None else self.dkg.public_key,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
        )

    def test_valid_signature(self):
        self.assertIs(self._verify(), True)

    def test_wrong_message_is_false(self):
        self.assertFalse(self._verify(message=b"another message"))

    def test_wrong_key_is_false(self):
        self.assertFalse(self._verify(public_key=(self.dkg.public_key + 1) % GROUP_PRIME))
        self.assertFalse(self._verify(public_key=1))

    def test_tampered_z_is_false(self):
        bad = dataclasses.replace(self.signature, z=(self.signature.z + 1) % FIELD_PRIME)
        self.assertFalse(self._verify(signature=bad))

    def test_wrong_R_is_false(self):
        bad = dataclasses.replace(
            self.signature, R=(self.signature.R % (GROUP_PRIME - 1)) + 2
        )
        if bad.R == self.signature.R:
            bad = dataclasses.replace(self.signature, R=self.signature.R - 1)
        self.assertFalse(self._verify(signature=bad))

    def test_wrong_signer_set_is_false(self):
        bad = dataclasses.replace(self.signature, signer_ids=(1, 3))
        self.assertFalse(self._verify(signature=bad))
        self.assertTrue(self._verify())  # unmodified signature still valid

    def test_two_distinct_signing_instances_both_verify(self):
        round_a, _, nonces_a = make_round(self.dkg, (1, 2), message=b"aaa", seed=11)
        round_b, _, nonces_b = make_round(self.dkg, (2, 3), message=b"bbb", seed=12)
        sig_a = aggregate_signature(make_shares(self.dkg, round_a, nonces_a), round_a, self.dkg)
        sig_b = aggregate_signature(make_shares(self.dkg, round_b, nonces_b), round_b, self.dkg)
        self.assertTrue(self._verify(message=b"aaa", signature=sig_a))
        self.assertTrue(self._verify(message=b"bbb", signature=sig_b))
        # Cross-checking one signature against the other message fails.
        self.assertFalse(self._verify(message=b"aaa", signature=sig_b))
        self.assertFalse(self._verify(message=b"bbb", signature=sig_a))

    def test_identity_R_is_well_formed_but_does_not_verify(self):
        self.assertFalse(
            self._verify(signature=dataclasses.replace(self.signature, R=1))
        )

    def test_malformed_arguments_raise(self):
        with self.assertRaises(TypeError):
            self._verify(message="not bytes")
        with self.assertRaises(TypeError):
            self._verify(signature=(self.signature.R, self.signature.z))
        with self.assertRaises(TypeError):
            self._verify(public_key="1")
        bad = dataclasses.replace(self.signature, z="1")
        with self.assertRaises(TypeError):
            self._verify(signature=bad)
        with self.assertRaises(ValueError):
            self._verify(signature=dataclasses.replace(self.signature, R=0))
        with self.assertRaises(ValueError):
            self._verify(signature=dataclasses.replace(self.signature, R=GROUP_PRIME))
        with self.assertRaises(ValueError):
            self._verify(signature=dataclasses.replace(self.signature, z=FIELD_PRIME))
        with self.assertRaises(ValueError):
            self._verify(signature=dataclasses.replace(self.signature, signer_ids=(0, 2)))
        with self.assertRaises(ValueError):
            self._verify(signature=dataclasses.replace(self.signature, signer_ids=(2, 1)))
        with self.assertRaises(ValueError):
            self._verify(public_key=0)


class NonceReuseSafetyTest(unittest.TestCase):
    def test_same_nonce_in_two_rounds_is_caller_choice_but_supported(self):
        # The library cannot stop two parties drawing the same nonce value;
        # round one rejects copied commitments, and each share still binds to
        # its own R_i. This documents the boundary: reuse prevention is out
        # of scope (no state is kept).
        dkg = make_signing_dkg((1, 2, 3), 2)
        c1, r1 = create_signing_nonce_commitment(
            1, prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
            randbelow=nonce_standin(42),
        )
        c2, r2 = create_signing_nonce_commitment(
            2, prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
            randbelow=nonce_standin(43),
        )
        self.assertNotEqual(r1, r2)
        self.assertNotEqual(c1.commitment, c2.commitment)


def make_refresh_contributions(key, participant_ids=None, seed_base=1000):
    ids = participant_ids or key.result.participant_ids
    return [
        create_refresh(pid, key, randbelow=fixed_random(pid + seed_base))
        for pid in ids
    ]


class CreateRefreshTest(unittest.TestCase):
    def setUp(self):
        self.key = make_signing_dkg((1, 2, 3), 2)

    def test_returns_signing_contribution_on_key_parameters(self):
        contribution = create_refresh(2, self.key, randbelow=fixed_random(5))
        self.assertIsInstance(contribution, SigningContribution)
        dealing = contribution.contribution
        self.assertEqual(dealing.sender_id, 2)
        self.assertEqual(dealing.participant_ids, (1, 2, 3))
        self.assertEqual(len(dealing.shares), 3)
        self.assertEqual(len(dealing.blinding_shares), 3)
        self.assertEqual(len(dealing.commitment.values), 2)
        self.assertEqual(len(contribution.feldman_commitment.values), 2)
        for commitment in (dealing.commitment, contribution.feldman_commitment):
            self.assertEqual(commitment.field_prime, FIELD_PRIME)
            self.assertEqual(commitment.group_prime, GROUP_PRIME)
            self.assertEqual(commitment.generator, GENERATOR)
        self.assertEqual(dealing.commitment.blinding_generator, BLINDING_GENERATOR)

    def test_feldman_constant_commitment_is_identity(self):
        # The sharing constant term is fixed at zero and never sampled, so
        # its Feldman commitment is the group identity.
        for contribution in make_refresh_contributions(self.key):
            self.assertEqual(contribution.feldman_commitment.values[0], 1)

    def test_double_shares_verify_against_both_commitments(self):
        from thresholdsign import verify_pedersen_share, verify_share

        for contribution in make_refresh_contributions(self.key):
            dealing = contribution.contribution
            for share, blinding_share in zip(
                dealing.shares, dealing.blinding_shares
            ):
                self.assertTrue(
                    verify_pedersen_share(
                        share, blinding_share, dealing.commitment
                    )
                )
                self.assertTrue(verify_share(share, contribution.feldman_commitment))

    def test_generation_order_matches_signing_contribution_except_constant(self):
        # With the same random stream, a refresh contribution must equal a
        # signing contribution whose first drawn sharing coefficient is zero:
        # the constant is skipped and every later draw keeps the same order.
        sequence = fixed_random(77)
        refresh_contribution = create_refresh(1, self.key, randbelow=sequence)

        calls = {"count": 0}
        base = fixed_random(77)

        def zero_first_then_stream(upper):
            if calls["count"] == 0:
                calls["count"] += 1
                return 0
            calls["count"] += 1
            return base(upper)

        signing_contribution = create_signing_contribution(
            1, (1, 2, 3), 2,
            prime=FIELD_PRIME, group_prime=GROUP_PRIME,
            generator=GENERATOR, blinding_generator=BLINDING_GENERATOR,
            randbelow=zero_first_then_stream,
        )
        self.assertEqual(refresh_contribution, signing_contribution)

    def test_threshold_one_sharing_polynomial_is_zero(self):
        key = make_signing_dkg((1, 2), 1)
        contribution = create_refresh(1, key, randbelow=fixed_random(9))
        self.assertEqual(contribution.feldman_commitment.values, (1,))
        # The only sharing coefficient is the fixed zero, so every share is 0.
        self.assertTrue(all(share.y == 0 for share in contribution.contribution.shares))
        # Blinding shares still use the one random blinding coefficient.
        self.assertTrue(
            any(share.y != 0 for share in contribution.contribution.blinding_shares)
        )

    def test_does_not_mutate_key_and_keeps_no_state(self):
        before = dataclasses.asdict(self.key)
        create_refresh(1, self.key, randbelow=fixed_random(3))
        self.assertEqual(dataclasses.asdict(self.key), before)
        # The same inputs reproduce the same contribution: nothing is stored.
        first = create_refresh(1, self.key, randbelow=fixed_random(3))
        second = create_refresh(1, self.key, randbelow=fixed_random(3))
        self.assertEqual(first, second)

    def test_bad_sender_and_key(self):
        with self.assertRaises(ValueError):
            create_refresh(4, self.key)
        with self.assertRaises(TypeError):
            create_refresh("1", self.key)
        with self.assertRaises(TypeError):
            create_refresh(1, "not a key")
        with self.assertRaises(TypeError):
            create_refresh(1, aggregate_signing_dkg(make_signing_contributions()).result)

    def test_large_group_parameters_taken_from_key(self):
        key = make_signing_dkg(
            (1, 2, 3), 2,
            field_prime=LARGE_FIELD, group_prime=LARGE_GROUP,
            generator=LARGE_G, blinding_generator=LARGE_H,
        )
        contribution = create_refresh(2, key, randbelow=fixed_random(4))
        self.assertEqual(
            contribution.contribution.commitment.group_prime, LARGE_GROUP
        )
        self.assertEqual(contribution.feldman_commitment.values[0], 1)


class RefreshTest(unittest.TestCase):
    def setUp(self):
        self.key = make_signing_dkg((1, 2, 3), 2)
        self.contributions = make_refresh_contributions(self.key)

    def _refresh(self):
        outcome = refresh(self.contributions, self.key)
        self.assertIsInstance(outcome, SigningDKGResult)
        return outcome

    def test_success_shape(self):
        new_key = self._refresh()
        self.assertEqual(new_key.result.participant_ids, (1, 2, 3))
        self.assertEqual(len(new_key.result.shares), 3)
        self.assertEqual(len(new_key.result.blinding_shares), 3)
        self.assertEqual(len(new_key.result.commitment.values), 2)
        self.assertEqual(len(new_key.verification_shares), 3)

    def test_shares_added_fieldwise_and_commitments_multiplied(self):
        from thresholdsign import verify_pedersen_share

        new_key = self._refresh()
        delta = aggregate_signing_dkg(self.contributions)
        assert isinstance(delta, SigningDKGResult)
        for index, participant_id in enumerate((1, 2, 3)):
            old_share = self.key.result.shares[index]
            self.assertEqual(
                new_key.result.shares[index].y,
                (old_share.y + delta.result.shares[index].y) % FIELD_PRIME,
            )
            self.assertEqual(
                new_key.result.blinding_shares[index].y,
                (
                    self.key.result.blinding_shares[index].y
                    + delta.result.blinding_shares[index].y
                )
                % FIELD_PRIME,
            )
            self.assertTrue(
                verify_pedersen_share(
                    new_key.result.shares[index],
                    new_key.result.blinding_shares[index],
                    new_key.result.commitment,
                )
            )
        for position in range(2):
            self.assertEqual(
                new_key.result.commitment.values[position],
                self.key.result.commitment.values[position]
                * delta.result.commitment.values[position]
                % GROUP_PRIME,
            )

    def test_verification_shares_recomputed(self):
        new_key = self._refresh()
        for share, Y_i in zip(new_key.result.shares, new_key.verification_shares):
            self.assertEqual(pow(GENERATOR, share.y, GROUP_PRIME), Y_i)

    def test_joint_secret_and_public_key_unchanged(self):
        new_key = self._refresh()
        self.assertEqual(new_key.public_key, self.key.public_key)
        first_pair = reconstruct_secret(new_key.result.shares[:2], prime=FIELD_PRIME)
        second_pair = reconstruct_secret(new_key.result.shares[1:], prime=FIELD_PRIME)
        old_secret = reconstruct_secret(self.key.result.shares[:2], prime=FIELD_PRIME)
        self.assertEqual(first_pair, second_pair)
        self.assertEqual(first_pair, old_secret)

    def test_shares_actually_change(self):
        new_key = self._refresh()
        self.assertNotEqual(
            [share.y for share in new_key.result.shares],
            [share.y for share in self.key.result.shares],
        )

    def test_old_aggregate_signature_still_verifies(self):
        round_info, shares = sign_full(self.key, signer_ids=(2, 3))
        signature = aggregate_signature(shares, round_info, self.key)
        self.assertIsInstance(signature, AggregateSignature)
        new_key = self._refresh()
        self.assertTrue(
            verify_signature(
                round_info.message,
                signature,
                new_key.public_key,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            )
        )

    def test_refreshed_key_still_signs(self):
        new_key = self._refresh()
        round_info, shares = sign_full(new_key, signer_ids=(1, 3))
        self.assertTrue(
            all(verify_signature_share(share, round_info, new_key) for share in shares)
        )
        signature = aggregate_signature(shares, round_info, new_key)
        self.assertIsInstance(signature, AggregateSignature)
        self.assertTrue(
            verify_signature(
                round_info.message,
                signature,
                self.key.public_key,  # the public key survives the refresh
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            )
        )

    def test_double_refresh(self):
        first = self._refresh()
        second_contributions = make_refresh_contributions(first, seed_base=2000)
        second = refresh(second_contributions, first)
        self.assertIsInstance(second, SigningDKGResult)
        self.assertEqual(second.public_key, self.key.public_key)
        secret = reconstruct_secret(second.result.shares[1:], prime=FIELD_PRIME)
        self.assertEqual(
            secret, reconstruct_secret(self.key.result.shares[:2], prime=FIELD_PRIME)
        )

    def test_threshold_one(self):
        key = make_signing_dkg((1, 2), 1)
        contributions = make_refresh_contributions(key)
        new_key = refresh(contributions, key)
        self.assertIsInstance(new_key, SigningDKGResult)
        self.assertEqual(new_key.public_key, key.public_key)
        self.assertEqual(
            reconstruct_secret([new_key.result.shares[0]], prime=FIELD_PRIME),
            reconstruct_secret([key.result.shares[0]], prime=FIELD_PRIME),
        )

    def test_large_group(self):
        key = make_signing_dkg(
            (1, 2, 3), 2,
            field_prime=LARGE_FIELD, group_prime=LARGE_GROUP,
            generator=LARGE_G, blinding_generator=LARGE_H,
        )
        contributions = make_refresh_contributions(key)
        new_key = refresh(contributions, key)
        self.assertIsInstance(new_key, SigningDKGResult)
        self.assertEqual(new_key.public_key, key.public_key)

    def test_input_order_does_not_matter(self):
        shuffled = [self.contributions[2], self.contributions[0], self.contributions[1]]
        self.assertEqual(
            refresh(self.contributions, self.key),
            refresh(shuffled, self.key),
        )

    def test_key_is_not_modified(self):
        before = dataclasses.asdict(self.key)
        self._refresh()
        self.assertEqual(dataclasses.asdict(self.key), before)


class RefreshFailureTest(unittest.TestCase):
    def setUp(self):
        self.key = make_signing_dkg((1, 2, 3), 2)
        self.contributions = make_refresh_contributions(self.key)

    def test_tampered_pedersen_share_is_rejected(self):
        dealing = self.contributions[1].contribution
        tampered_dealing = dataclasses.replace(
            dealing,
            shares=(ShareLike(dealing.shares[0].x, dealing.shares[0].y + 1),)
            + dealing.shares[1:],
        )
        tampered = dataclasses.replace(
            self.contributions[1], contribution=tampered_dealing
        )
        outcome = refresh(
            [self.contributions[0], tampered, self.contributions[2]], self.key
        )
        self.assertEqual(outcome, [DKGRejection(sender_id=2)])

    def test_nonzero_constant_feldman_commitment_is_rejected(self):
        # An ordinary signing contribution has a random (non-zero) constant;
        # its shares match both commitments, only the refresh rule fails.
        ordinary = make_signing_contributions()[1]
        outcome = refresh(
            [self.contributions[0], ordinary, self.contributions[2]], self.key
        )
        self.assertEqual(outcome, [DKGRejection(sender_id=2)])

    def test_feldman_bound_to_other_polynomial_is_rejected(self):
        swapped = dataclasses.replace(
            self.contributions[0],
            feldman_commitment=self.contributions[1].feldman_commitment,
        )
        first = refresh([swapped, self.contributions[1], self.contributions[2]], self.key)
        second = refresh(
            [self.contributions[2], self.contributions[1], swapped], self.key
        )
        self.assertEqual(first, [DKGRejection(sender_id=1)])
        self.assertEqual(second, [DKGRejection(sender_id=1)])

    def test_multiple_failures_sorted_and_order_independent(self):
        tampered = []
        for contribution in (self.contributions[0], self.contributions[2]):
            dealing = contribution.contribution
            tampered_dealing = dataclasses.replace(
                dealing,
                shares=(ShareLike(dealing.shares[0].x, dealing.shares[0].y + 1),)
                + dealing.shares[1:],
            )
            tampered.append(
                dataclasses.replace(contribution, contribution=tampered_dealing)
            )
        expected = [DKGRejection(sender_id=1), DKGRejection(sender_id=3)]
        first = refresh(
            [tampered[0], self.contributions[1], tampered[1]], self.key
        )
        second = refresh(
            [tampered[1], self.contributions[1], tampered[0]], self.key
        )
        self.assertEqual(first, expected)
        self.assertEqual(second, expected)

    def test_missing_and_duplicate_participants(self):
        with self.assertRaises(ValueError):
            refresh(self.contributions[:2], self.key)
        with self.assertRaises(ValueError):
            refresh(
                [self.contributions[0], self.contributions[0], self.contributions[2]],
                self.key,
            )

    def test_empty_input(self):
        with self.assertRaises(ValueError):
            refresh([], self.key)

    def test_wrong_types_raise_type_error(self):
        with self.assertRaises(TypeError):
            refresh(
                [c.contribution for c in self.contributions],  # plain DKG objects
                self.key,
            )
        with self.assertRaises(TypeError):
            refresh(["nope"], self.key)
        with self.assertRaises(TypeError):
            refresh(self.contributions, "not a key")
        with self.assertRaises(TypeError):
            refresh(self.contributions, self.key.result)

    def test_participant_ids_mismatch(self):
        other = make_signing_dkg((1, 2, 4), 2)
        other_contributions = make_refresh_contributions(other)
        with self.assertRaises(ValueError):
            refresh(other_contributions, self.key)

    def test_threshold_mismatch(self):
        other = make_signing_dkg((1, 2, 3), 1)
        other_contributions = make_refresh_contributions(other)
        with self.assertRaises(ValueError):
            refresh(other_contributions, self.key)

    def test_group_parameters_mismatch(self):
        other = make_signing_dkg(
            (1, 2, 3), 2,
            field_prime=LARGE_FIELD, group_prime=LARGE_GROUP,
            generator=LARGE_G, blinding_generator=LARGE_H,
        )
        other_contributions = make_refresh_contributions(other)
        with self.assertRaises(ValueError):
            refresh(other_contributions, self.key)

    def test_malformed_key_structure_raises_value_error(self):
        broken = dataclasses.replace(
            self.key, result=dataclasses.replace(self.key.result, shares=())
        )
        with self.assertRaises(ValueError):
            create_refresh(1, broken)
        with self.assertRaises(ValueError):
            refresh(self.contributions, broken)


if __name__ == "__main__":
    unittest.main()
