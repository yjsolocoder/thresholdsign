"""Tests for proactive share refresh (create_refresh / refresh)."""

import dataclasses
import unittest

from thresholdsign import (
    DKGRejection,
    Share,
    SigningDKGResult,
    SigningContribution,
    aggregate_signature,
    aggregate_signing_dkg,
    create_refresh,
    create_signature_share,
    create_signing_contribution,
    create_signing_nonce_commitment,
    create_signing_round,
    reconstruct_secret,
    refresh,
    verify_signature,
)

# Same toy group as the signing tests: 8069 = 4 * 2017 + 1 is prime and
# 16, 256 = 16 ** 2 generate the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

LARGE_FIELD = 1000151
LARGE_GROUP = 2000303
LARGE_G = 9
LARGE_H = 81

MESSAGE = b"proactive refresh test message"


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


def make_refresh_contributions(key, seed_base=100):
    return [
        create_refresh(pid, key, randbelow=fixed_random(pid + seed_base))
        for pid in key.result.participant_ids
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


class CreateRefreshTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()

    def test_returns_signing_contribution(self):
        contribution = create_refresh(1, self.key)
        self.assertIsInstance(contribution, SigningContribution)
        dealing = contribution.contribution
        self.assertEqual(dealing.sender_id, 1)
        self.assertEqual(dealing.participant_ids, (1, 2, 3))
        self.assertEqual(len(dealing.shares), 3)
        self.assertEqual(len(dealing.blinding_shares), 3)
        self.assertEqual(len(dealing.commitment.values), 2)

    def test_feldman_constant_commitment_is_one(self):
        # The sharing constant term is fixed at zero, so g ** 0 == 1.
        for pid in (1, 2, 3):
            contribution = create_refresh(pid, self.key)
            self.assertEqual(contribution.feldman_commitment.values[0], 1)
            self.assertEqual(len(contribution.feldman_commitment.values), 2)

    def test_pedersen_constant_commitment_is_still_hidden(self):
        # The blinding constant term stays random, so the Pedersen commitment
        # need not reveal the zero sharing constant term.
        seen_any_non_one = False
        for pid in (1, 2, 3):
            contribution = create_refresh(pid, self.key, randbelow=fixed_random(pid))
            if contribution.contribution.commitment.values[0] != 1:
                seen_any_non_one = True
        self.assertTrue(seen_any_non_one)

    def test_shares_verify_against_both_commitments(self):
        from thresholdsign import verify_pedersen_share, verify_share

        for contribution in make_refresh_contributions(self.key):
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

    def test_threshold_one_makes_no_random_sharing_draw(self):
        # threshold 1: the sharing polynomial is the constant zero alone, so
        # every secret share evaluates to 0; the single Feldman value is 1.
        key = make_key((1, 2), 1)
        contribution = create_refresh(1, key, randbelow=lambda upper: 123)
        self.assertEqual(contribution.feldman_commitment.values, (1,))
        self.assertEqual(
            [share.y for share in contribution.contribution.shares], [0, 0]
        )

    def test_constant_term_is_not_drawn_from_randbelow(self):
        # With threshold 2 exactly one sharing coefficient (j = 1) and two
        # blinding coefficients are drawn: three prime-bounded draws, no draw
        # is "skipped" before them but the constant never consumes one.
        seen = []
        create_refresh(1, self.key, randbelow=lambda upper: seen.append(upper) or 0)
        self.assertEqual(seen, [FIELD_PRIME, FIELD_PRIME, FIELD_PRIME])

    def test_uses_key_participants_and_sender_must_belong(self):
        with self.assertRaises(ValueError):
            create_refresh(9, self.key)
        with self.assertRaises(ValueError):
            create_refresh(0, self.key)

    def test_wrong_key_type_raises_type_error(self):
        with self.assertRaises(TypeError):
            create_refresh(1, "not a key")
        with self.assertRaises(TypeError):
            create_refresh(1, None)

    def test_sender_wrong_type_raises_type_error(self):
        with self.assertRaises(TypeError):
            create_refresh("1", self.key)


class RefreshSuccessTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.contributions = make_refresh_contributions(self.key)

    def test_returns_signing_dkg_result(self):
        outcome = refresh(self.contributions, self.key)
        self.assertIsInstance(outcome, SigningDKGResult)
        self.assertEqual(outcome.result.participant_ids, (1, 2, 3))
        self.assertEqual(len(outcome.verification_shares), 3)

    def test_shares_are_rerandomised(self):
        outcome = refresh(self.contributions, self.key)
        self.assertNotEqual(
            [share.y for share in outcome.result.shares],
            [share.y for share in self.key.result.shares],
        )

    def test_double_shares_added_fieldwise(self):
        outcome = refresh(self.contributions, self.key)
        ordered = sorted(self.contributions, key=lambda c: c.contribution.sender_id)
        for index, share in enumerate(outcome.result.shares):
            y = self.key.result.shares[index].y
            yb = self.key.result.blinding_shares[index].y
            for contribution in ordered:
                y = (y + contribution.contribution.shares[index].y) % FIELD_PRIME
                yb = (
                    yb + contribution.contribution.blinding_shares[index].y
                ) % FIELD_PRIME
            self.assertEqual(share.y, y)
            self.assertEqual(outcome.result.blinding_shares[index].y, yb)

    def test_commitments_multiplied_groupwise(self):
        outcome = refresh(self.contributions, self.key)
        ordered = sorted(self.contributions, key=lambda c: c.contribution.sender_id)
        for position in range(2):
            expected = self.key.result.commitment.values[position]
            for contribution in ordered:
                expected = (
                    expected
                    * contribution.contribution.commitment.values[position]
                ) % GROUP_PRIME
            self.assertEqual(outcome.result.commitment.values[position], expected)

    def test_joint_secret_is_unchanged(self):
        outcome = refresh(self.contributions, self.key)
        old_secret = reconstruct_secret(self.key.result.shares[:2], prime=FIELD_PRIME)
        new_secret = reconstruct_secret(outcome.result.shares[:2], prime=FIELD_PRIME)
        self.assertEqual(new_secret, old_secret)
        # Any threshold subset of the new shares rebuilds the same secret.
        new_secret_other = reconstruct_secret(outcome.result.shares[1:], prime=FIELD_PRIME)
        self.assertEqual(new_secret_other, old_secret)

    def test_public_key_is_unchanged(self):
        outcome = refresh(self.contributions, self.key)
        self.assertEqual(outcome.public_key, self.key.public_key)

    def test_verification_shares_match_new_shares(self):
        outcome = refresh(self.contributions, self.key)
        for share, Y_i in zip(outcome.result.shares, outcome.verification_shares):
            self.assertEqual(pow(GENERATOR, share.y, GROUP_PRIME), Y_i)
        # They have generally changed relative to the old key.
        self.assertNotEqual(
            list(outcome.verification_shares),
            list(self.key.verification_shares),
        )

    def test_old_signature_still_verifies_under_unchanged_public_key(self):
        signature = sign_once(self.key, (1, 2))
        refresh(self.contributions, self.key)
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

    def test_refreshed_key_still_signs(self):
        new_key = refresh(self.contributions, self.key)
        assert isinstance(new_key, SigningDKGResult)
        signature = sign_once(new_key, (2, 3))
        self.assertTrue(
            verify_signature(
                MESSAGE,
                signature,
                new_key.public_key,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            )
        )

    def test_input_order_does_not_matter(self):
        shuffled = [self.contributions[2], self.contributions[0], self.contributions[1]]
        self.assertEqual(
            refresh(self.contributions, self.key),
            refresh(shuffled, self.key),
        )

    def test_refresh_is_repeatable_but_keeps_the_key(self):
        first = refresh(self.contributions, self.key)
        assert isinstance(first, SigningDKGResult)
        second_contributions = make_refresh_contributions(first, seed_base=200)
        second = refresh(second_contributions, first)
        self.assertEqual(second.public_key, self.key.public_key)
        self.assertEqual(
            reconstruct_secret(second.result.shares[:2], prime=FIELD_PRIME),
            reconstruct_secret(self.key.result.shares[:2], prime=FIELD_PRIME),
        )

    def test_threshold_one(self):
        key = make_key((1, 2), 1)
        contributions = make_refresh_contributions(key)
        outcome = refresh(contributions, key)
        self.assertIsInstance(outcome, SigningDKGResult)
        self.assertEqual(outcome.public_key, key.public_key)
        old_secret = reconstruct_secret([key.result.shares[0]], prime=FIELD_PRIME)
        new_secret = reconstruct_secret([outcome.result.shares[0]], prime=FIELD_PRIME)
        self.assertEqual(new_secret, old_secret)

    def test_large_group(self):
        key = make_key(
            (1, 2, 3), 2,
            field_prime=LARGE_FIELD, group_prime=LARGE_GROUP,
            generator=LARGE_G, blinding_generator=LARGE_H,
        )
        contributions = make_refresh_contributions(key)
        outcome = refresh(contributions, key)
        self.assertIsInstance(outcome, SigningDKGResult)
        self.assertEqual(outcome.public_key, key.public_key)
        self.assertEqual(
            reconstruct_secret(outcome.result.shares[:2], prime=LARGE_FIELD),
            reconstruct_secret(key.result.shares[:2], prime=LARGE_FIELD),
        )


class RefreshRejectionTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.contributions = make_refresh_contributions(self.key)

    def test_tampered_pedersen_share_yields_sorted_rejection(self):
        dealing = self.contributions[1].contribution
        tampered_dealing = dataclasses.replace(
            dealing,
            shares=(Share(dealing.shares[0].x, dealing.shares[0].y + 1),)
            + dealing.shares[1:],
        )
        tampered = dataclasses.replace(self.contributions[1], contribution=tampered_dealing)
        outcome = refresh(
            [self.contributions[0], tampered, self.contributions[2]], self.key
        )
        self.assertEqual(outcome, [DKGRejection(sender_id=2)])

    def test_tampered_feldman_match_yields_rejection(self):
        # Swap in another zero-constant Feldman commitment: the constant is
        # still 1 but the shares no longer match it -> rejection, not error.
        swapped = dataclasses.replace(
            self.contributions[0],
            feldman_commitment=self.contributions[1].feldman_commitment,
        )
        outcome = refresh(
            [swapped, self.contributions[1], self.contributions[2]], self.key
        )
        self.assertEqual(outcome, [DKGRejection(sender_id=1)])

    def test_nonzero_constant_contribution_is_rejected(self):
        # Ordinary signing contributions (random constant term) are
        # well-formed but have a Feldman constant commitment != 1.
        ordinary = [
            create_signing_contribution(
                pid, (1, 2, 3), 2,
                prime=FIELD_PRIME, group_prime=GROUP_PRIME,
                generator=GENERATOR, blinding_generator=BLINDING_GENERATOR,
            )
            for pid in (1, 2, 3)
        ]
        outcome = refresh(ordinary, self.key)
        self.assertEqual(
            outcome,
            [DKGRejection(1), DKGRejection(2), DKGRejection(3)],
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

        bad_1 = tamper(self.contributions[0])
        bad_3 = tamper(self.contributions[2])
        expected = [DKGRejection(sender_id=1), DKGRejection(sender_id=3)]
        self.assertEqual(
            refresh([bad_1, self.contributions[1], bad_3], self.key), expected
        )
        self.assertEqual(
            refresh([bad_3, self.contributions[1], bad_1], self.key), expected
        )


class RefreshInputValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.contributions = make_refresh_contributions(self.key)

    def test_wrong_key_type_raises_type_error(self):
        with self.assertRaises(TypeError):
            refresh(self.contributions, "not a key")
        with self.assertRaises(TypeError):
            refresh(self.contributions, None)

    def test_plain_dkg_contributions_raise_type_error(self):
        with self.assertRaises(TypeError):
            refresh([c.contribution for c in self.contributions], self.key)
        with self.assertRaises(TypeError):
            refresh(["nope"], self.key)

    def test_empty_input_raises_value_error(self):
        with self.assertRaises(ValueError):
            refresh([], self.key)

    def test_missing_and_duplicate_participants(self):
        with self.assertRaises(ValueError):
            refresh(self.contributions[:2], self.key)
        with self.assertRaises(ValueError):
            refresh(
                [self.contributions[0], self.contributions[0], self.contributions[2]],
                self.key,
            )

    def test_participant_set_mismatch_raises_value_error(self):
        other_key = make_key((1, 2, 4))
        other_contributions = make_refresh_contributions(other_key)
        with self.assertRaises(ValueError):
            refresh(
                [other_contributions[0], self.contributions[1], other_contributions[2]],
                self.key,
            )

    def test_threshold_mismatch_raises_value_error(self):
        other_key = make_key((1, 2, 3), threshold=1)
        other_contributions = make_refresh_contributions(other_key)
        with self.assertRaises(ValueError):
            refresh(other_contributions, self.key)

    def test_malformed_key_raises(self):
        bad_key = dataclasses.replace(self.key, public_key="1")
        with self.assertRaises(TypeError):
            refresh(self.contributions, bad_key)


if __name__ == "__main__":
    unittest.main()
