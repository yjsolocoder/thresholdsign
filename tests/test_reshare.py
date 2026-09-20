"""Tests for member resharing (create_reshare / reshare)."""

import dataclasses
import unittest

from thresholdsign import (
    DKGRejection,
    Share,
    SigningDKGResult,
    SigningContribution,
    aggregate_signature,
    aggregate_signing_dkg,
    create_reshare,
    create_signature_share,
    create_signing_contribution,
    create_signing_nonce_commitment,
    create_signing_round,
    reconstruct_secret,
    reshare,
    verify_signature,
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

MESSAGE = b"member resharing test message"


def fixed_random(seed=1):
    """Deterministic stand-in for secrets.randbelow (same LCG as signing tests)."""
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


def lagrange_weight(signer_id, ids, prime):
    numerator = 1
    denominator = 1
    for other in ids:
        if other == signer_id:
            continue
        numerator = numerator * (-other) % prime
        denominator = denominator * (signer_id - other) % prime
    return numerator * pow(denominator, -1, prime) % prime


def sign_once(key, signer_ids, message=MESSAGE, seed=10):
    """Run both Schnorr rounds with deterministic nonces; return the signature."""
    commitments = []
    nonces = {}
    for offset, signer_id in enumerate(signer_ids):
        commitment, nonce = create_signing_nonce_commitment(
            signer_id,
            prime=key.result.commitment.field_prime,
            group_prime=key.result.commitment.group_prime,
            generator=key.result.commitment.generator,
            randbelow=fixed_random(seed + 100 * offset + signer_id),
        )
        commitments.append(commitment)
        nonces[signer_id] = nonce
    round_info = create_signing_round(message, tuple(signer_ids), commitments, key)
    shares = [
        create_signature_share(
            signer_id,
            key.result.shares[key.result.participant_ids.index(signer_id)].y,
            nonces[signer_id],
            round_info,
            key,
        )
        for signer_id in signer_ids
    ]
    outcome = aggregate_signature(shares, round_info, key)
    assert not isinstance(outcome, list), outcome
    return outcome


class CreateReshareTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.dealers = (1, 2)
        self.members = (1, 2, 4, 5)
        self.threshold = 3

    def create(self, sender=1, share=None, **overrides):
        arguments = {
            "dealers": self.dealers,
            "members": self.members,
            "threshold": self.threshold,
            "key": self.key,
        }
        arguments.update(overrides)
        if share is None:
            if isinstance(sender, int) and sender in self.key.result.participant_ids:
                share = secret_share_of(self.key, sender)
            else:
                share = 0
        return create_reshare(sender, share, **arguments)

    def test_returns_signing_contribution(self):
        contribution = self.create()
        self.assertIsInstance(contribution, SigningContribution)
        dealing = contribution.contribution
        self.assertEqual(dealing.sender_id, 1)
        self.assertEqual(dealing.participant_ids, (1, 2, 4, 5))
        self.assertEqual(len(dealing.shares), 4)
        self.assertEqual(len(dealing.blinding_shares), 4)
        self.assertEqual(len(dealing.commitment.values), 3)
        self.assertEqual(len(contribution.feldman_commitment.values), 3)

    def test_feldman_constant_is_weighted_old_verification_share(self):
        for dealer in self.dealers:
            contribution = self.create(sender=dealer)
            index = self.key.result.participant_ids.index(dealer)
            weight = lagrange_weight(dealer, self.dealers, FIELD_PRIME)
            expected = pow(self.key.verification_shares[index], weight, GROUP_PRIME)
            self.assertEqual(contribution.feldman_commitment.values[0], expected)

    def test_constant_term_is_lagrange_weighted_share_not_drawn(self):
        # threshold 3: the constant is lambda_i * share (no draw), then two
        # sharing coefficients and three blinding coefficients come from rng.
        seen = []
        self.create(rng=lambda upper: seen.append(upper) or 0)
        self.assertEqual(seen, [FIELD_PRIME] * 5)

    def test_threshold_one_draws_only_blinding_coefficients(self):
        seen = []
        contribution = self.create(threshold=1, rng=lambda upper: seen.append(upper) or 0)
        self.assertEqual(seen, [FIELD_PRIME])
        self.assertEqual(len(contribution.feldman_commitment.values), 1)

    def test_shares_verify_against_both_commitments(self):
        from thresholdsign import verify_pedersen_share, verify_share

        for contribution in make_reshare_contributions(
            self.key, self.dealers, self.members, self.threshold
        ):
            for share, blinding_share in zip(
                contribution.contribution.shares,
                contribution.contribution.blinding_shares,
            ):
                self.assertTrue(
                    verify_pedersen_share(
                        share, blinding_share, contribution.contribution.commitment
                    )
                )
                self.assertTrue(verify_share(share, contribution.feldman_commitment))

    def test_members_are_sorted(self):
        contribution = self.create(members=(5, 2, 4, 1))
        self.assertEqual(contribution.contribution.participant_ids, (1, 2, 4, 5))

    def test_share_mismatching_old_verification_share_raises(self):
        share = secret_share_of(self.key, 1)
        with self.assertRaises(ValueError):
            self.create(share=(share + 1) % FIELD_PRIME)
        # Another participant's share is equally wrong for this sender.
        with self.assertRaises(ValueError):
            self.create(share=secret_share_of(self.key, 2))

    def test_share_out_of_range_raises(self):
        with self.assertRaises(ValueError):
            self.create(share=FIELD_PRIME)
        with self.assertRaises(ValueError):
            self.create(share=-1)

    def test_dealer_constraints(self):
        # Fewer dealers than the old threshold.
        with self.assertRaises(ValueError):
            self.create(sender=1, dealers=(1,))
        # Duplicate dealers.
        with self.assertRaises(ValueError):
            self.create(dealers=(1, 1, 2))
        # Not strictly increasing.
        with self.assertRaises(ValueError):
            self.create(dealers=(2, 1))
        # A dealer outside the old key.
        with self.assertRaises(ValueError):
            self.create(dealers=(1, 9), members=(1, 2, 9))
        # A dealer outside the new members.
        with self.assertRaises(ValueError):
            self.create(dealers=(1, 3), members=(1, 2, 4))
        # Sender must be a dealer.
        with self.assertRaises(ValueError):
            self.create(sender=3, dealers=(1, 2), members=(1, 2, 3))

    def test_wrong_types_raise_type_error(self):
        with self.assertRaises(TypeError):
            self.create(sender="1")
        with self.assertRaises(TypeError):
            self.create(share="1")
        with self.assertRaises(TypeError):
            self.create(dealers="12")
        with self.assertRaises(TypeError):
            self.create(dealers=(1, "2"))
        with self.assertRaises(TypeError):
            self.create(members="1245")
        with self.assertRaises(TypeError):
            self.create(threshold="3")
        with self.assertRaises(TypeError):
            self.create(key="not a key")
        with self.assertRaises(TypeError):
            self.create(key=None)

    def test_malformed_key_raises(self):
        bad_key = dataclasses.replace(self.key, public_key="1")
        with self.assertRaises(TypeError):
            self.create(key=bad_key)


class ReshareSuccessTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.dealers = (1, 3)
        self.members = (1, 3, 4, 5)
        self.threshold = 3
        self.contributions = make_reshare_contributions(
            self.key, self.dealers, self.members, self.threshold
        )

    def test_returns_signing_dkg_result_over_new_members(self):
        outcome = reshare(self.contributions, self.dealers, self.key)
        self.assertIsInstance(outcome, SigningDKGResult)
        self.assertEqual(outcome.result.participant_ids, self.members)
        self.assertEqual(len(outcome.result.shares), len(self.members))
        self.assertEqual(len(outcome.result.commitment.values), self.threshold)
        self.assertEqual(len(outcome.verification_shares), len(self.members))

    def test_any_new_threshold_subset_rebuilds_old_secret(self):
        outcome = reshare(self.contributions, self.dealers, self.key)
        old_secret = reconstruct_secret(self.key.result.shares[:2], prime=FIELD_PRIME)
        shares = outcome.result.shares
        for subset in ((0, 1, 2), (0, 2, 3), (1, 2, 3), (1, 3, 0)):
            picked = [shares[index] for index in subset]
            self.assertEqual(
                reconstruct_secret(picked, prime=FIELD_PRIME), old_secret
            )

    def test_public_key_is_unchanged(self):
        outcome = reshare(self.contributions, self.dealers, self.key)
        self.assertEqual(outcome.public_key, self.key.public_key)

    def test_double_shares_added_fieldwise(self):
        outcome = reshare(self.contributions, self.dealers, self.key)
        ordered = sorted(self.contributions, key=lambda c: c.contribution.sender_id)
        for index, share in enumerate(outcome.result.shares):
            y = 0
            yb = 0
            for contribution in ordered:
                y = (y + contribution.contribution.shares[index].y) % FIELD_PRIME
                yb = (
                    yb + contribution.contribution.blinding_shares[index].y
                ) % FIELD_PRIME
            self.assertEqual(share.y, y)
            self.assertEqual(outcome.result.blinding_shares[index].y, yb)

    def test_commitments_multiplied_groupwise(self):
        outcome = reshare(self.contributions, self.dealers, self.key)
        ordered = sorted(self.contributions, key=lambda c: c.contribution.sender_id)
        for position in range(self.threshold):
            expected = 1
            for contribution in ordered:
                expected = (
                    expected
                    * contribution.contribution.commitment.values[position]
                ) % GROUP_PRIME
            self.assertEqual(outcome.result.commitment.values[position], expected)

    def test_verification_shares_match_new_shares(self):
        outcome = reshare(self.contributions, self.dealers, self.key)
        for share, Y_i in zip(outcome.result.shares, outcome.verification_shares):
            self.assertEqual(pow(GENERATOR, share.y, GROUP_PRIME), Y_i)

    def test_input_order_does_not_matter(self):
        shuffled = [self.contributions[1], self.contributions[0]]
        self.assertEqual(
            reshare(self.contributions, self.dealers, self.key),
            reshare(shuffled, self.dealers, self.key),
        )

    def test_new_key_signs_and_old_signature_still_verifies(self):
        old_signature = sign_once(self.key, (1, 2))
        outcome = reshare(self.contributions, self.dealers, self.key)
        assert isinstance(outcome, SigningDKGResult)
        # The reshared key signs under any new threshold quorum.
        new_signature = sign_once(outcome, (3, 4, 5))
        for signature in (old_signature, new_signature):
            self.assertTrue(
                verify_signature(
                    MESSAGE,
                    signature,
                    self.key.public_key,
                    prime=FIELD_PRIME,
                    group_prime=GROUP_PRIME,
                    generator=GENERATOR,
                )
            )

    def test_reshare_is_chainable(self):
        first = reshare(self.contributions, self.dealers, self.key)
        assert isinstance(first, SigningDKGResult)
        # Reshare again from the new key: dealers (3, 4, 5), members (3, 4, 5, 6).
        second_contributions = make_reshare_contributions(
            first, (3, 4, 5), (3, 4, 5, 6), 2, seed_base=200
        )
        second = reshare(second_contributions, (3, 4, 5), first)
        assert isinstance(second, SigningDKGResult)
        self.assertEqual(second.public_key, self.key.public_key)
        old_secret = reconstruct_secret(self.key.result.shares[:2], prime=FIELD_PRIME)
        self.assertEqual(
            reconstruct_secret(second.result.shares[:2], prime=FIELD_PRIME), old_secret
        )

    def test_threshold_one(self):
        contributions = make_reshare_contributions(
            self.key, self.dealers, self.members, 1
        )
        outcome = reshare(contributions, self.dealers, self.key)
        assert isinstance(outcome, SigningDKGResult)
        self.assertEqual(outcome.public_key, self.key.public_key)
        old_secret = reconstruct_secret(self.key.result.shares[:2], prime=FIELD_PRIME)
        for share in outcome.result.shares:
            self.assertEqual(
                reconstruct_secret([share], prime=FIELD_PRIME), old_secret
            )

    def test_more_dealers_than_old_threshold(self):
        dealers = (1, 2, 3)
        members = (1, 2, 3, 4)
        contributions = make_reshare_contributions(
            self.key, dealers, members, self.threshold
        )
        outcome = reshare(contributions, dealers, self.key)
        assert isinstance(outcome, SigningDKGResult)
        self.assertEqual(outcome.public_key, self.key.public_key)
        old_secret = reconstruct_secret(self.key.result.shares[:2], prime=FIELD_PRIME)
        self.assertEqual(
            reconstruct_secret(outcome.result.shares[:3], prime=FIELD_PRIME),
            old_secret,
        )

    def test_same_members_same_threshold(self):
        # Resharing onto the very same set and threshold still rerandomises.
        contributions = make_reshare_contributions(self.key, (1, 2), (1, 2, 3), 2)
        outcome = reshare(contributions, (1, 2), self.key)
        assert isinstance(outcome, SigningDKGResult)
        self.assertEqual(outcome.public_key, self.key.public_key)
        self.assertNotEqual(
            [share.y for share in outcome.result.shares],
            [share.y for share in self.key.result.shares],
        )

    def test_large_group(self):
        key = make_key(
            (1, 2, 3), 2,
            field_prime=LARGE_FIELD, group_prime=LARGE_GROUP,
            generator=LARGE_G, blinding_generator=LARGE_H,
        )
        contributions = make_reshare_contributions(key, (1, 2), (1, 2, 4), 2)
        outcome = reshare(contributions, (1, 2), key)
        assert isinstance(outcome, SigningDKGResult)
        self.assertEqual(outcome.public_key, key.public_key)
        self.assertEqual(
            reconstruct_secret(outcome.result.shares[:2], prime=LARGE_FIELD),
            reconstruct_secret(key.result.shares[:2], prime=LARGE_FIELD),
        )


class ReshareRejectionTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.dealers = (1, 2)
        self.members = (1, 2, 4)
        self.threshold = 2
        self.contributions = make_reshare_contributions(
            self.key, self.dealers, self.members, self.threshold
        )

    def test_tampered_pedersen_share_yields_rejection(self):
        dealing = self.contributions[1].contribution
        tampered_dealing = dataclasses.replace(
            dealing,
            shares=(Share(dealing.shares[0].x, dealing.shares[0].y + 1),)
            + dealing.shares[1:],
        )
        tampered = dataclasses.replace(self.contributions[1], contribution=tampered_dealing)
        outcome = reshare([self.contributions[0], tampered], self.dealers, self.key)
        self.assertEqual(outcome, [DKGRejection(sender_id=2)])

    def test_tampered_feldman_match_yields_rejection(self):
        # Swap in another reshare Feldman commitment: the shares no longer
        # match it -> rejection, not error.
        other = make_reshare_contributions(
            self.key, self.dealers, self.members, self.threshold, seed_base=900
        )
        swapped = dataclasses.replace(
            self.contributions[0],
            feldman_commitment=other[0].feldman_commitment,
        )
        outcome = reshare([swapped, self.contributions[1]], self.dealers, self.key)
        self.assertEqual(outcome, [DKGRejection(sender_id=1)])

    def test_wrong_feldman_constant_yields_rejection(self):
        # A refresh-style zero-constant Feldman commitment does not equal
        # Y_i ** lambda_i -> rejection.
        from thresholdsign import FeldmanCommitment

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
        outcome = reshare([shifted, self.contributions[1]], self.dealers, self.key)
        self.assertEqual(outcome, [DKGRejection(sender_id=1)])

    def test_multiple_failures_sorted_and_order_independent(self):
        def tamper(contribution):
            dealing = contribution.contribution
            tampered_dealing = dataclasses.replace(
                dealing,
                shares=(Share(dealing.shares[0].x, dealing.shares[0].y + 1),)
                + dealing.shares[1:],
            )
            return dataclasses.replace(contribution, contribution=tampered_dealing)

        extra_key = make_key(seed_base=500)
        dealers = (1, 2, 3)
        members = (1, 2, 3, 4)
        contributions = make_reshare_contributions(extra_key, dealers, members, 2)
        bad_1 = tamper(contributions[0])
        bad_3 = tamper(contributions[2])
        expected = [DKGRejection(sender_id=1), DKGRejection(sender_id=3)]
        self.assertEqual(
            reshare([bad_1, contributions[1], bad_3], dealers, extra_key), expected
        )
        self.assertEqual(
            reshare([bad_3, contributions[1], bad_1], dealers, extra_key), expected
        )


class ReshareInputValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.dealers = (1, 2)
        self.members = (1, 2, 4)
        self.threshold = 2
        self.contributions = make_reshare_contributions(
            self.key, self.dealers, self.members, self.threshold
        )

    def test_wrong_key_type_raises_type_error(self):
        with self.assertRaises(TypeError):
            reshare(self.contributions, self.dealers, "not a key")
        with self.assertRaises(TypeError):
            reshare(self.contributions, self.dealers, None)

    def test_plain_dkg_contributions_raise_type_error(self):
        with self.assertRaises(TypeError):
            reshare(
                [c.contribution for c in self.contributions], self.dealers, self.key
            )
        with self.assertRaises(TypeError):
            reshare(["nope"], self.dealers, self.key)

    def test_empty_input_raises_value_error(self):
        with self.assertRaises(ValueError):
            reshare([], self.dealers, self.key)

    def test_dealer_list_validation(self):
        with self.assertRaises(ValueError):
            reshare(self.contributions, (), self.key)
        with self.assertRaises(ValueError):
            reshare(self.contributions, (1,), self.key)
        with self.assertRaises(ValueError):
            reshare(self.contributions, (2, 1), self.key)
        with self.assertRaises(ValueError):
            reshare(self.contributions, (1, 1), self.key)
        with self.assertRaises(ValueError):
            reshare(self.contributions, (1, 9), self.key)
        with self.assertRaises(TypeError):
            reshare(self.contributions, "12", self.key)
        with self.assertRaises(TypeError):
            reshare(self.contributions, (1, "2"), self.key)

    def test_missing_and_duplicate_dealers(self):
        with self.assertRaises(ValueError):
            reshare(self.contributions[:1], self.dealers, self.key)
        with self.assertRaises(ValueError):
            reshare(
                [self.contributions[0], self.contributions[0]],
                self.dealers,
                self.key,
            )
        # A contribution from a non-dealer participant.
        extra = create_reshare(
            3,
            secret_share_of(self.key, 3),
            (1, 2, 3),
            (1, 2, 3),
            2,
            self.key,
            rng=fixed_random(3),
        )
        with self.assertRaises(ValueError):
            reshare([self.contributions[0], extra], self.dealers, self.key)

    def test_member_set_mismatch_raises_value_error(self):
        other = make_reshare_contributions(self.key, self.dealers, (1, 2, 5), 2)
        with self.assertRaises(ValueError):
            reshare([self.contributions[0], other[1]], self.dealers, self.key)

    def test_threshold_mismatch_raises_value_error(self):
        other = make_reshare_contributions(self.key, self.dealers, self.members, 1)
        with self.assertRaises(ValueError):
            reshare([self.contributions[0], other[1]], self.dealers, self.key)

    def test_group_parameter_mismatch_raises_value_error(self):
        other_key = make_key(
            (1, 2, 3), 2,
            field_prime=LARGE_FIELD, group_prime=LARGE_GROUP,
            generator=LARGE_G, blinding_generator=LARGE_H,
        )
        other = make_reshare_contributions(other_key, (1, 2), (1, 2, 4), 2)
        with self.assertRaises(ValueError):
            reshare([self.contributions[0], other[1]], self.dealers, self.key)

    def test_malformed_key_raises(self):
        bad_key = dataclasses.replace(self.key, public_key="1")
        with self.assertRaises(TypeError):
            reshare(self.contributions, self.dealers, bad_key)


if __name__ == "__main__":
    unittest.main()
