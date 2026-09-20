"""Tests for member re-sharing (create_reshare / reshare)."""

import dataclasses
import unittest

from thresholdsign import (
    DKGRejection,
    Share,
    SigningContribution,
    SigningDKGResult,
    aggregate_signature,
    aggregate_signing_dkg,
    create_refresh,
    create_reshare,
    create_signature_share,
    create_signing_contribution,
    create_signing_nonce_commitment,
    create_signing_round,
    reconstruct_secret,
    reshare,
    verify_pedersen_share,
    verify_share,
    verify_signature,
)

# Same toy group as the signing/refresh tests: 8069 = 4 * 2017 + 1 is prime
# and 16, 256 = 16 ** 2 generate the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

LARGE_FIELD = 1000151
LARGE_GROUP = 2000303
LARGE_G = 9
LARGE_H = 81

MESSAGE = b"member reshare test message"


def fixed_random(seed=1):
    """Deterministic stand-in for secrets.randbelow (same LCG as the suite)."""
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


def lagrange_weight(index, indices, prime=FIELD_PRIME):
    numerator = 1
    denominator = 1
    for other in indices:
        if other == index:
            continue
        numerator = numerator * (-other) % prime
        denominator = denominator * (index - other) % prime
    return numerator * pow(denominator, -1, prime) % prime


def make_reshare_contributions(key, dealers, members, threshold, seed_base=100):
    return [
        create_reshare(
            dealer,
            key.result.shares[key.result.participant_ids.index(dealer)],
            dealers,
            members,
            threshold,
            key,
            rng=fixed_random(dealer + seed_base),
        )
        for dealer in dealers
    ]


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

    def test_returns_signing_contribution(self):
        contribution = create_reshare(
            1, self.key.result.shares[0], (1, 2), (1, 2, 4), 2, self.key
        )
        self.assertIsInstance(contribution, SigningContribution)
        dealing = contribution.contribution
        self.assertEqual(dealing.sender_id, 1)
        self.assertEqual(dealing.participant_ids, (1, 2, 4))
        self.assertEqual(len(dealing.shares), 3)
        self.assertEqual(len(dealing.blinding_shares), 3)
        self.assertEqual(len(dealing.commitment.values), 2)
        self.assertEqual(len(contribution.feldman_commitment.values), 2)

    def test_shares_verify_against_both_commitments(self):
        members = (1, 2, 4)
        for contribution in make_reshare_contributions(
            self.key, (1, 2), members, 2
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

    def test_feldman_constant_is_old_verification_share_to_the_lambda(self):
        dealers = (1, 2)
        members = (1, 2, 4)
        for position, dealer in enumerate(dealers):
            contribution = create_reshare(
                dealer,
                self.key.result.shares[position],
                dealers,
                members,
                2,
                self.key,
            )
            weight = lagrange_weight(dealer, dealers)
            expected = pow(
                self.key.verification_shares[position], weight, GROUP_PRIME
            )
            self.assertEqual(
                contribution.feldman_commitment.values[0], expected
            )

    def test_constant_term_is_lambda_times_share(self):
        dealers = (1, 2)
        contribution = create_reshare(
            2,
            self.key.result.shares[1],
            dealers,
            (1, 2, 4),
            2,
            self.key,
            rng=lambda upper: 0,
        )
        weight = lagrange_weight(2, dealers)
        expected_constant = weight * self.key.result.shares[1].y % FIELD_PRIME
        # With every higher coefficient zero, every share equals the constant.
        for share in contribution.contribution.shares:
            self.assertEqual(share.y, expected_constant)
        self.assertEqual(
            contribution.feldman_commitment.values[0],
            pow(GENERATOR, expected_constant, GROUP_PRIME),
        )

    def test_draw_order_constant_then_sharing_then_blinding(self):
        # t = 2: the constant term is fixed, then one sharing coefficient and
        # two blinding coefficients are drawn: three q-bounded draws.
        seen = []
        create_reshare(
            1,
            self.key.result.shares[0],
            (1, 2),
            (1, 2, 4),
            2,
            self.key,
            rng=lambda upper: seen.append(upper) or 0,
        )
        self.assertEqual(seen, [FIELD_PRIME, FIELD_PRIME, FIELD_PRIME])

        # t = 3: two sharing draws then three blinding draws.
        key3 = make_key((1, 2, 3, 4), threshold=3)
        seen = []
        create_reshare(
            1,
            key3.result.shares[0],
            (1, 2, 3),
            (1, 2, 3, 9),
            3,
            key3,
            rng=lambda upper: seen.append(upper) or 0,
        )
        self.assertEqual(seen, [FIELD_PRIME] * 5)

    def test_threshold_one_draws_only_the_blinding_constant(self):
        # t = 1: no sharing coefficient draw at all; one blinding draw.
        seen = []
        contribution = create_reshare(
            2,
            self.key.result.shares[1],
            (2, 3),
            (2, 3, 4),
            1,
            self.key,
            rng=lambda upper: seen.append(upper) or 0,
        )
        self.assertEqual(seen, [FIELD_PRIME])
        self.assertEqual(len(contribution.feldman_commitment.values), 1)
        weight = lagrange_weight(2, (2, 3))
        expected_constant = weight * self.key.result.shares[1].y % FIELD_PRIME
        for share in contribution.contribution.shares:
            self.assertEqual(share.y, expected_constant)

    def test_members_may_be_given_out_of_order_but_come_out_sorted(self):
        contribution = create_reshare(
            1, self.key.result.shares[0], (1, 2), (4, 1, 2), 2, self.key
        )
        self.assertEqual(contribution.contribution.participant_ids, (1, 2, 4))

    def test_more_than_old_threshold_dealers_allowed(self):
        key = make_key((1, 2, 3, 4, 5), threshold=2)
        contribution = create_reshare(
            1,
            key.result.shares[0],
            (1, 2, 3),
            (1, 2, 3, 6),
            2,
            key,
        )
        self.assertEqual(contribution.contribution.sender_id, 1)

    def test_share_must_belong_to_sender_wrong_holder(self):
        with self.assertRaises(ValueError):
            create_reshare(
                1, self.key.result.shares[1], (1, 2), (1, 2, 4), 2, self.key
            )

    def test_share_must_belong_to_sender_wrong_coordinate(self):
        other_y = self.key.result.shares[0].y
        with self.assertRaises(ValueError):
            create_reshare(
                1, Share(2, other_y), (1, 2), (1, 2, 4), 2, self.key
            )

    def test_share_with_tampered_value_is_rejected(self):
        share = self.key.result.shares[0]
        with self.assertRaises(ValueError):
            create_reshare(
                1,
                Share(share.x, (share.y + 1) % FIELD_PRIME),
                (1, 2),
                (1, 2, 4),
                2,
                self.key,
            )

    def test_dealers_must_be_strictly_increasing(self):
        with self.assertRaises(ValueError):
            create_reshare(
                2, self.key.result.shares[1], (2, 1), (1, 2, 4), 2, self.key
            )

    def test_dealer_ids_must_be_unique(self):
        with self.assertRaises(ValueError):
            create_reshare(
                1, self.key.result.shares[0], (1, 1), (1, 2, 4), 2, self.key
            )

    def test_dealer_count_must_reach_old_threshold(self):
        with self.assertRaises(ValueError):
            create_reshare(
                1, self.key.result.shares[0], (1,), (1, 2, 4), 2, self.key
            )

    def test_dealers_must_be_old_key_holders(self):
        # 4 is not an old participant (old set is 1,2,3).
        with self.assertRaises(ValueError):
            create_reshare(
                2,
                self.key.result.shares[1],
                (2, 4),
                (2, 4, 5),
                2,
                self.key,
            )

    def test_dealers_must_be_among_members(self):
        with self.assertRaises(ValueError):
            create_reshare(
                1, self.key.result.shares[0], (1, 2), (2, 4, 5), 2, self.key
            )

    def test_sender_must_be_a_dealer(self):
        with self.assertRaises(ValueError):
            create_reshare(
                3, self.key.result.shares[2], (1, 2), (1, 2, 4), 2, self.key
            )

    def test_threshold_bounds(self):
        with self.assertRaises(ValueError):
            create_reshare(
                1, self.key.result.shares[0], (1, 2), (1, 2, 4), 0, self.key
            )
        with self.assertRaises(ValueError):
            create_reshare(
                1, self.key.result.shares[0], (1, 2), (1, 2, 4), 4, self.key
            )

    def test_member_ids_validated(self):
        with self.assertRaises(ValueError):
            create_reshare(
                1, self.key.result.shares[0], (1, 2), (1, 1, 4), 2, self.key
            )
        with self.assertRaises(ValueError):
            create_reshare(
                1, self.key.result.shares[0], (1, 2), (), 2, self.key
            )
        with self.assertRaises(ValueError):
            create_reshare(
                1, self.key.result.shares[0], (1, 2), (0, 1, 2), 2, self.key
            )

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            create_reshare(
                "1", self.key.result.shares[0], (1, 2), (1, 2, 4), 2, self.key
            )
        with self.assertRaises(TypeError):
            create_reshare(1, (1, 2), (1, 2), (1, 2, 4), 2, self.key)
        with self.assertRaises(TypeError):
            create_reshare(
                1, self.key.result.shares[0], (1, 2), (1, 2, 4), "2", self.key
            )
        with self.assertRaises(TypeError):
            create_reshare(
                1, self.key.result.shares[0], (1, 2), (1, 2, 4), 2, "not a key"
            )
        with self.assertRaises(TypeError):
            create_reshare(
                1,
                self.key.result.shares[0],
                ("1", 2),
                (1, 2, 4),
                2,
                self.key,
            )


class ReshareSuccessTest(unittest.TestCase):
    def test_returns_signing_dkg_result_for_same_set(self):
        key = make_key()
        members = key.result.participant_ids
        dealers = (1, 2)
        contributions = make_reshare_contributions(key, dealers, members, 2)
        outcome = reshare(contributions, dealers, key)
        self.assertIsInstance(outcome, SigningDKGResult)
        self.assertEqual(outcome.result.participant_ids, members)
        self.assertEqual(len(outcome.verification_shares), 3)

    def test_double_shares_are_the_sum_of_the_dealings_alone(self):
        key = make_key()
        members = key.result.participant_ids
        dealers = (1, 2)
        contributions = make_reshare_contributions(key, dealers, members, 2)
        outcome = reshare(contributions, dealers, key)
        ordered = sorted(contributions, key=lambda c: c.contribution.sender_id)
        # The new shares are the reshare dealings summed from zero; the old
        # shares are inputs to the constant terms, not an added summand.
        for index, share in enumerate(outcome.result.shares):
            y = 0
            y_blinding = 0
            for contribution in ordered:
                y = (y + contribution.contribution.shares[index].y) % FIELD_PRIME
                y_blinding = (
                    y_blinding
                    + contribution.contribution.blinding_shares[index].y
                ) % FIELD_PRIME
            self.assertEqual(share.y, y)
            self.assertEqual(outcome.result.blinding_shares[index].y, y_blinding)

    def test_commitments_multiplied_groupwise(self):
        key = make_key()
        members = key.result.participant_ids
        dealers = (1, 2)
        contributions = make_reshare_contributions(key, dealers, members, 2)
        outcome = reshare(contributions, dealers, key)
        ordered = sorted(contributions, key=lambda c: c.contribution.sender_id)
        for position in range(2):
            expected = 1
            for contribution in ordered:
                expected = (
                    expected
                    * contribution.contribution.commitment.values[position]
                ) % GROUP_PRIME
            self.assertEqual(outcome.result.commitment.values[position], expected)

    def test_joint_secret_rebuilt_by_new_threshold_subsets(self):
        key = make_key()
        old_secret = reconstruct_secret(key.result.shares[:2], prime=FIELD_PRIME)
        members = (1, 3, 4)
        dealers = (1, 3)
        contributions = make_reshare_contributions(key, dealers, members, 2)
        outcome = reshare(contributions, dealers, key)
        self.assertIsInstance(outcome, SigningDKGResult)
        self.assertEqual(
            reconstruct_secret(outcome.result.shares[:2], prime=FIELD_PRIME),
            old_secret,
        )
        self.assertEqual(
            reconstruct_secret(outcome.result.shares[1:], prime=FIELD_PRIME),
            old_secret,
        )

    def test_public_key_is_unchanged(self):
        key = make_key()
        members = (1, 2, 4)
        dealers = (1, 2)
        contributions = make_reshare_contributions(key, dealers, members, 2)
        outcome = reshare(contributions, dealers, key)
        self.assertEqual(outcome.public_key, key.public_key)

    def test_verification_shares_match_new_shares(self):
        key = make_key()
        members = (1, 2, 4)
        dealers = (1, 2)
        contributions = make_reshare_contributions(key, dealers, members, 2)
        outcome = reshare(contributions, dealers, key)
        for share, value in zip(outcome.result.shares, outcome.verification_shares):
            self.assertEqual(pow(GENERATOR, share.y, GROUP_PRIME), value)

    def test_new_threshold_takes_effect(self):
        key = make_key((1, 2, 3), threshold=2)
        old_secret = reconstruct_secret(key.result.shares[:2], prime=FIELD_PRIME)
        # Raise the threshold to 3 over a four-member set.
        members = (1, 2, 3, 4)
        dealers = (1, 2)
        contributions = make_reshare_contributions(key, dealers, members, 3)
        outcome = reshare(contributions, dealers, key)
        self.assertIsInstance(outcome, SigningDKGResult)
        self.assertEqual(len(outcome.result.commitment.values), 3)
        # Two new shares no longer rebuild the secret ...
        self.assertNotEqual(
            reconstruct_secret(outcome.result.shares[:2], prime=FIELD_PRIME),
            old_secret,
        )
        # ... but any three do.
        self.assertEqual(
            reconstruct_secret(outcome.result.shares[:3], prime=FIELD_PRIME),
            old_secret,
        )
        self.assertEqual(
            reconstruct_secret(outcome.result.shares[1:], prime=FIELD_PRIME),
            old_secret,
        )

    def test_threshold_may_be_lowered(self):
        key = make_key((1, 2, 3, 4), threshold=3)
        old_secret = reconstruct_secret(key.result.shares[:3], prime=FIELD_PRIME)
        members = (1, 2, 3, 4, 5)
        dealers = (1, 2, 4)
        contributions = make_reshare_contributions(key, dealers, members, 2)
        outcome = reshare(contributions, dealers, key)
        self.assertIsInstance(outcome, SigningDKGResult)
        self.assertEqual(
            reconstruct_secret(outcome.result.shares[:2], prime=FIELD_PRIME),
            old_secret,
        )

    def test_more_than_old_threshold_dealers(self):
        key = make_key((1, 2, 3, 4, 5), threshold=3)
        old_secret = reconstruct_secret(key.result.shares[:3], prime=FIELD_PRIME)
        members = (1, 2, 4, 5, 6, 7)
        dealers = (1, 2, 4, 5)
        contributions = make_reshare_contributions(key, dealers, members, 2)
        outcome = reshare(contributions, dealers, key)
        self.assertIsInstance(outcome, SigningDKGResult)
        self.assertEqual(outcome.public_key, key.public_key)
        self.assertEqual(
            reconstruct_secret(outcome.result.shares[:2], prime=FIELD_PRIME),
            old_secret,
        )
        self.assertEqual(
            reconstruct_secret(outcome.result.shares[4:], prime=FIELD_PRIME),
            old_secret,
        )

    def test_new_members_can_sign(self):
        key = make_key((1, 2, 3), threshold=2)
        members = (1, 2, 3, 4, 5)
        dealers = (1, 3)
        contributions = make_reshare_contributions(key, dealers, members, 3)
        new_key = reshare(contributions, dealers, key)
        self.assertIsInstance(new_key, SigningDKGResult)
        signature = sign_once(new_key, (2, 4, 5))
        self.assertTrue(
            verify_signature(
                MESSAGE,
                signature,
                key.public_key,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            )
        )

    def test_old_signature_still_verifies(self):
        key = make_key((1, 2, 3), threshold=2)
        signature = sign_once(key, (1, 2))
        members = (1, 2, 4)
        dealers = (1, 2)
        reshare(make_reshare_contributions(key, dealers, members, 2), dealers, key)
        self.assertTrue(
            verify_signature(
                MESSAGE,
                signature,
                key.public_key,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            )
        )

    def test_input_order_does_not_matter(self):
        key = make_key()
        members = (1, 2, 4)
        dealers = (1, 2)
        contributions = make_reshare_contributions(key, dealers, members, 2)
        shuffled = [contributions[1], contributions[0]]
        self.assertEqual(
            reshare(contributions, dealers, key),
            reshare(shuffled, dealers, key),
        )

    def test_reshare_is_chainable(self):
        key = make_key((1, 2, 3), threshold=2)
        old_secret = reconstruct_secret(key.result.shares[:2], prime=FIELD_PRIME)

        members_one = (1, 2, 4)
        dealers_one = (1, 2)
        key_one = reshare(
            make_reshare_contributions(key, dealers_one, members_one, 2, seed_base=10),
            dealers_one,
            key,
        )
        self.assertIsInstance(key_one, SigningDKGResult)

        members_two = (2, 4, 5, 6)
        dealers_two = (2, 4)
        key_two = reshare(
            make_reshare_contributions(
                key_one, dealers_two, members_two, 3, seed_base=20
            ),
            dealers_two,
            key_one,
        )
        self.assertIsInstance(key_two, SigningDKGResult)
        self.assertEqual(key_two.public_key, key.public_key)
        self.assertEqual(
            reconstruct_secret(key_two.result.shares[:3], prime=FIELD_PRIME),
            old_secret,
        )

    def test_threshold_one(self):
        key = make_key((1, 2, 3), threshold=2)
        old_secret = reconstruct_secret(key.result.shares[:2], prime=FIELD_PRIME)
        members = (1, 3, 5)
        dealers = (1, 3)
        contributions = make_reshare_contributions(key, dealers, members, 1)
        outcome = reshare(contributions, dealers, key)
        self.assertIsInstance(outcome, SigningDKGResult)
        self.assertEqual(outcome.public_key, key.public_key)
        for share in outcome.result.shares:
            self.assertEqual(
                reconstruct_secret([share], prime=FIELD_PRIME), old_secret
            )

    def test_large_group(self):
        key = make_key(
            (1, 2, 3), 2,
            field_prime=LARGE_FIELD, group_prime=LARGE_GROUP,
            generator=LARGE_G, blinding_generator=LARGE_H,
        )
        old_secret = reconstruct_secret(key.result.shares[:2], prime=LARGE_FIELD)
        members = (1, 2, 4)
        dealers = (1, 2)
        contributions = make_reshare_contributions(key, dealers, members, 2)
        outcome = reshare(contributions, dealers, key)
        self.assertIsInstance(outcome, SigningDKGResult)
        self.assertEqual(outcome.public_key, key.public_key)
        self.assertEqual(
            reconstruct_secret(outcome.result.shares[:2], prime=LARGE_FIELD),
            old_secret,
        )


class ReshareRejectionTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.members = (1, 2, 4)
        self.dealers = (1, 2)
        self.contributions = make_reshare_contributions(
            self.key, self.dealers, self.members, 2
        )

    def test_tampered_pedersen_share_yields_sorted_rejection(self):
        dealing = self.contributions[1].contribution
        tampered_dealing = dataclasses.replace(
            dealing,
            shares=(Share(dealing.shares[0].x, dealing.shares[0].y + 1),)
            + dealing.shares[1:],
        )
        tampered = dataclasses.replace(
            self.contributions[1], contribution=tampered_dealing
        )
        outcome = reshare([self.contributions[0], tampered], self.dealers, self.key)
        self.assertEqual(outcome, [DKGRejection(sender_id=2)])

    def test_tampered_feldman_match_yields_rejection(self):
        swapped = dataclasses.replace(
            self.contributions[0],
            feldman_commitment=self.contributions[1].feldman_commitment,
        )
        outcome = reshare([swapped, self.contributions[1]], self.dealers, self.key)
        self.assertEqual(outcome, [DKGRejection(sender_id=1)])

    def test_wrong_constant_term_is_rejected(self):
        # Internally consistent ordinary signing contributions (random
        # constant term) satisfy the DKG checks but have a Feldman constant
        # commitment different from Y_i ** lambda_i.
        ordinary = [
            create_signing_contribution(
                dealer,
                self.members,
                2,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
                blinding_generator=BLINDING_GENERATOR,
            )
            for dealer in self.dealers
        ]
        outcome = reshare(ordinary, self.dealers, self.key)
        self.assertEqual(outcome, [DKGRejection(1), DKGRejection(2)])

    def test_refresh_contribution_constant_one_is_rejected(self):
        # A refresh dealing commits to constant 0 (Feldman constant 1), which
        # only matches if lambda_i * s_i == 0; here it does not.
        members = (1, 2, 3)
        dealers = (1, 2)
        refresh_dealings = [create_refresh(dealer, self.key) for dealer in dealers]
        outcome = reshare(refresh_dealings, dealers, self.key)
        self.assertEqual(outcome, [DKGRejection(1), DKGRejection(2)])

    def test_contribution_for_another_dealer_set_is_rejected(self):
        # Sender 1's dealing is internally consistent but built against dealer
        # set (1,3): its Feldman constant is Y_1 ** lambda_1^{(1,3)}, which
        # cannot equal the expected Y_1 ** lambda_1^{(1,2)}.
        members = (1, 2, 3)
        other = make_reshare_contributions(
            self.key, (1, 3), members, 2, seed_base=50
        )
        mixed = [other[0], self._valid_sender_two(members)]
        outcome = reshare(mixed, (1, 2), self.key)
        self.assertEqual(outcome, [DKGRejection(sender_id=1)])

    def _valid_sender_two(self, members):
        return create_reshare(
            2,
            self.key.result.shares[1],
            (1, 2),
            members,
            2,
            self.key,
            rng=fixed_random(202),
        )

    def test_multiple_failures_sorted_and_order_independent(self):
        def tamper(contribution):
            dealing = contribution.contribution
            tampered_dealing = dataclasses.replace(
                dealing,
                shares=(Share(dealing.shares[0].x, dealing.shares[0].y + 1),)
                + dealing.shares[1:],
            )
            return dataclasses.replace(contribution, contribution=tampered_dealing)

        key = make_key((1, 2, 3, 4), threshold=2)
        members = (1, 2, 3, 4)
        dealers = (1, 2, 3)
        contributions = make_reshare_contributions(key, dealers, members, 2)
        bad_1 = tamper(contributions[0])
        bad_3 = tamper(contributions[2])
        expected = [DKGRejection(sender_id=1), DKGRejection(sender_id=3)]
        self.assertEqual(
            reshare([bad_1, contributions[1], bad_3], dealers, key), expected
        )
        self.assertEqual(
            reshare([bad_3, contributions[1], bad_1], dealers, key), expected
        )


class ReshareInputValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.members = (1, 2, 4)
        self.dealers = (1, 2)
        self.contributions = make_reshare_contributions(
            self.key, self.dealers, self.members, 2
        )

    def test_wrong_key_type_raises_type_error(self):
        with self.assertRaises(TypeError):
            reshare(self.contributions, self.dealers, "not a key")
        with self.assertRaises(TypeError):
            reshare(self.contributions, self.dealers, None)

    def test_wrong_contribution_type_raises_type_error(self):
        with self.assertRaises(TypeError):
            reshare(
                [c.contribution for c in self.contributions], self.dealers, self.key
            )
        with self.assertRaises(TypeError):
            reshare(["nope", self.contributions[1]], self.dealers, self.key)

    def test_empty_input_raises_value_error(self):
        with self.assertRaises(ValueError):
            reshare([], self.dealers, self.key)

    def test_empty_or_duplicate_dealers(self):
        with self.assertRaises(ValueError):
            reshare(self.contributions, (), self.key)
        with self.assertRaises(ValueError):
            reshare(self.contributions, (1, 1), self.key)

    def test_dealer_argument_order_does_not_matter(self):
        # The dealer set fixes the Lagrange weights; its presentation order
        # must not change the result.
        forward = reshare(self.contributions, (1, 2), self.key)
        reverse = reshare(self.contributions, (2, 1), self.key)
        self.assertEqual(forward, reverse)

    def test_dealer_wrong_type_raises_type_error(self):
        with self.assertRaises(TypeError):
            reshare(self.contributions, ("1", 2), self.key)

    def test_too_few_dealers_raises_value_error(self):
        with self.assertRaises(ValueError):
            reshare(self.contributions, (1,), self.key)

    def test_dealers_must_be_old_holders(self):
        with self.assertRaises(ValueError):
            reshare(self.contributions, (1, 4), self.key)

    def test_missing_and_duplicate_contributions(self):
        with self.assertRaises(ValueError):
            reshare(self.contributions[:1], self.dealers, self.key)
        with self.assertRaises(ValueError):
            reshare(
                [self.contributions[0], self.contributions[0]], self.dealers, self.key
            )

    def test_dealer_set_must_match_contributors(self):
        with self.assertRaises(ValueError):
            # Dealers name a third party that supplied no contribution.
            reshare(self.contributions, (1, 3), self.key)

    def test_member_set_mismatch_between_contributions_raises(self):
        other = make_reshare_contributions(
            self.key, (1, 2), (1, 2, 5), 2, seed_base=9
        )
        with self.assertRaises(ValueError):
            reshare([other[0], self.contributions[1]], self.dealers, self.key)

    def test_threshold_mismatch_between_contributions_raises(self):
        other = make_reshare_contributions(
            self.key, (1, 2), (1, 2, 4), 1, seed_base=9
        )
        with self.assertRaises(ValueError):
            reshare([other[0], self.contributions[1]], self.dealers, self.key)

    def test_dealer_not_among_members_is_rejected_at_creation(self):
        # On the aggregate side every contributor is a dealer and the DKG
        # structure pins each sender to the contribution's member ids, so a
        # dealer outside the member set can only arise when *creating* a
        # dealing; create_reshare rejects it there.
        with self.assertRaises(ValueError):
            create_reshare(
                3,
                self.key.result.shares[2],
                (2, 3),
                (2, 4, 5),
                2,
                self.key,
            )

    def test_malformed_key_raises(self):
        bad_key = dataclasses.replace(self.key, public_key="1")
        with self.assertRaises(TypeError):
            reshare(self.contributions, self.dealers, bad_key)


if __name__ == "__main__":
    unittest.main()
