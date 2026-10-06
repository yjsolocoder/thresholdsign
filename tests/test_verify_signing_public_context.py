"""Tests for verify_signing_public_context."""

import dataclasses
import unittest

from thresholdsign import (
    SigningDKGResult,
    SigningPublicContext,
    aggregate_signing_dkg,
    create_refresh,
    create_reshare,
    create_signing_contribution,
    evaluate_polynomial,
    export_signing_public_context,
    refresh,
    reshare,
    verify_signing_public_context,
)

# Same toy group as the signing tests: 8069 = 4 * 2017 + 1 is prime, 16 and
# 256 = 16 ** 2 are distinct generators of the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256


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
    seed_base=0,
):
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


def context_from_polynomial(coefficients, participant_ids, threshold=None):
    """Build a context whose shares come from one explicit polynomial."""
    if threshold is None:
        threshold = len(coefficients)
    return SigningPublicContext(
        participant_ids=tuple(participant_ids),
        threshold=threshold,
        field_prime=FIELD_PRIME,
        group_prime=GROUP_PRIME,
        generator=GENERATOR,
        public_key=pow(GENERATOR, coefficients[0] % FIELD_PRIME, GROUP_PRIME),
        verification_shares=tuple(
            pow(
                GENERATOR,
                evaluate_polynomial(coefficients, x, prime=FIELD_PRIME),
                GROUP_PRIME,
            )
            for x in participant_ids
        ),
    )


def subgroup_element(exponent):
    """A structurally legal subgroup element distinct from the identity."""
    return pow(GENERATOR, exponent % FIELD_PRIME, GROUP_PRIME)


class HonestContextTest(unittest.TestCase):
    """Contexts exported from honest DKG, refresh and reshare all verify."""

    def test_dkg_export_verifies(self):
        context = export_signing_public_context(make_key())
        self.assertIs(verify_signing_public_context(context), True)

    def test_directly_constructed_copy_verifies(self):
        key = make_key()
        context = SigningPublicContext(
            participant_ids=key.result.participant_ids,
            threshold=len(key.result.commitment.values),
            field_prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            public_key=key.public_key,
            verification_shares=key.verification_shares,
        )
        self.assertIs(verify_signing_public_context(context), True)

    def test_refresh_export_verifies(self):
        key = make_key()
        contributions = [
            create_refresh(pid, key, randbelow=fixed_random(pid + 100))
            for pid in key.result.participant_ids
        ]
        refreshed = refresh(contributions, key)
        self.assertIsInstance(refreshed, SigningDKGResult)
        context = export_signing_public_context(refreshed)
        self.assertIs(verify_signing_public_context(context), True)

    def test_reshare_export_verifies(self):
        key = make_key()
        dealers = (2, 3)
        contributions = [
            create_reshare(
                dealer,
                secret_share_of(key, dealer),
                dealers,
                (2, 3, 4),
                2,
                key,
                rng=fixed_random(dealer + 100),
            )
            for dealer in dealers
        ]
        reshared = reshare(contributions, dealers, key)
        self.assertIsInstance(reshared, SigningDKGResult)
        context = export_signing_public_context(reshared)
        self.assertEqual(context.participant_ids, (2, 3, 4))
        self.assertIs(verify_signing_public_context(context), True)

    def test_nonconsecutive_ids_verify(self):
        context = export_signing_public_context(make_key((2, 5, 9), 2))
        self.assertIs(verify_signing_public_context(context), True)

    def test_threshold_equal_to_member_count_verifies(self):
        context = export_signing_public_context(make_key((1, 2, 3), 3))
        self.assertIs(verify_signing_public_context(context), True)

    def test_threshold_one_verifies(self):
        context = export_signing_public_context(make_key((1, 2, 3), 1))
        self.assertIs(verify_signing_public_context(context), True)

    def test_single_member_context_verifies(self):
        context = export_signing_public_context(make_key((4,), 1))
        self.assertIs(verify_signing_public_context(context), True)


class PolynomialConstructionTest(unittest.TestCase):
    """Directly constructed contexts follow the mathematical condition."""

    def test_explicit_polynomial_verifies(self):
        context = context_from_polynomial([7, 11], (1, 2, 3, 5))
        self.assertIs(verify_signing_public_context(context), True)

    def test_degree_below_declared_threshold_verifies(self):
        # Constant and linear polynomials with threshold 3: the actual
        # degree is below the declared threshold and must still pass.
        constant = context_from_polynomial([9], (1, 2, 3), threshold=3)
        self.assertIs(verify_signing_public_context(constant), True)
        linear = context_from_polynomial([9, 4], (1, 2, 3), threshold=3)
        self.assertIs(verify_signing_public_context(linear), True)

    def test_zero_polynomial_gives_identity_key_and_shares(self):
        context = context_from_polynomial([0, 0], (1, 2, 3))
        self.assertEqual(context.public_key, 1)
        self.assertEqual(context.verification_shares, (1, 1, 1))
        self.assertIs(verify_signing_public_context(context), True)

    def test_threshold_one_requires_constant_shares(self):
        context = context_from_polynomial([5], (2, 5, 9), threshold=1)
        self.assertIs(verify_signing_public_context(context), True)
        shifted = dataclasses.replace(
            context,
            verification_shares=(
                context.verification_shares[0],
                subgroup_element(6),
                context.verification_shares[2],
            ),
        )
        self.assertIs(verify_signing_public_context(shifted), False)

    def test_single_member_share_must_equal_public_key(self):
        context = context_from_polynomial([3], (7,), threshold=1)
        self.assertIs(verify_signing_public_context(context), True)
        shifted = dataclasses.replace(
            context, verification_shares=(subgroup_element(4),)
        )
        self.assertIs(verify_signing_public_context(shifted), False)


class InconsistentContextTest(unittest.TestCase):
    """Structurally legal but inconsistent contexts return False."""

    def setUp(self):
        self.context = export_signing_public_context(make_key())

    def test_tampered_public_key_returns_false(self):
        # Multiplying by the generator shifts the exponent by one: still a
        # structurally legal subgroup element, but a different key.
        bad = dataclasses.replace(
            self.context,
            public_key=self.context.public_key * GENERATOR % GROUP_PRIME,
        )
        self.assertIs(verify_signing_public_context(bad), False)

    def test_shares_consistent_with_each_other_but_not_public_key(self):
        # Every share comes from one polynomial, but the public key is the
        # constant term of a different one.
        context = context_from_polynomial([7, 11], (1, 2, 3))
        bad = dataclasses.replace(context, public_key=subgroup_element(8))
        self.assertIs(verify_signing_public_context(bad), False)

    def test_only_some_shares_fit_public_key(self):
        # The public key and all but one share come from one polynomial;
        # the remaining share belongs to another.
        context = context_from_polynomial([7, 11], (1, 2, 3, 5))
        shares = list(context.verification_shares)
        shares[2] = subgroup_element(1000)
        bad = dataclasses.replace(context, verification_shares=tuple(shares))
        self.assertIs(verify_signing_public_context(bad), False)

    def test_last_share_beyond_any_threshold_subset_still_checked(self):
        # Corrupting only the last share must fail even though the first
        # threshold points (key plus earlier shares) still interpolate.
        context = context_from_polynomial([7, 11], (1, 2, 3, 5))
        shares = list(context.verification_shares)
        shares[-1] = subgroup_element(1000)
        bad = dataclasses.replace(context, verification_shares=tuple(shares))
        self.assertIs(verify_signing_public_context(bad), False)

    def test_first_share_still_checked(self):
        context = context_from_polynomial([7, 11], (1, 2, 3, 5))
        shares = list(context.verification_shares)
        shares[0] = subgroup_element(1000)
        bad = dataclasses.replace(context, verification_shares=tuple(shares))
        self.assertIs(verify_signing_public_context(bad), False)

    def test_degree_at_threshold_rejected(self):
        # A degree-2 polynomial over three shares with threshold 2: no
        # degree < 2 polynomial passes through the key and all shares.
        coefficients = [7, 11, 3]
        context = SigningPublicContext(
            participant_ids=(1, 2, 3),
            threshold=2,
            field_prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            public_key=subgroup_element(coefficients[0]),
            verification_shares=tuple(
                subgroup_element(
                    evaluate_polynomial(coefficients, x, prime=FIELD_PRIME)
                )
                for x in (1, 2, 3)
            ),
        )
        self.assertIs(verify_signing_public_context(context), False)


class StructuralBoundaryTest(unittest.TestCase):
    """Full structural validation runs before the consistency check."""

    def setUp(self):
        self.context = export_signing_public_context(make_key())

    def test_non_context_rejected(self):
        for value in (None, "context", 42, self.context.participant_ids):
            with self.assertRaises(TypeError, msg=value):
                verify_signing_public_context(value)

    def test_field_type_errors(self):
        type_errors = [
            {"participant_ids": [1, 2, 3]},
            {"participant_ids": (1, "2", 3)},
            {"participant_ids": (1, True, 3)},
            {"threshold": True},
            {"threshold": "2"},
            {"field_prime": True},
            {"field_prime": 2017.0},
            {"group_prime": False},
            {"generator": "16"},
            {"public_key": True},
            {"verification_shares": [1, 2, 3]},
            {"verification_shares": (1, True, 3)},
            {"verification_shares": (1, 2, "3")},
        ]
        for field in type_errors:
            context = dataclasses.replace(self.context, **field)
            with self.assertRaises(TypeError, msg=field):
                verify_signing_public_context(context)

    def test_participant_id_value_errors(self):
        for ids in ((), (2, 1, 3), (1, 1, 3), (0, 1, 2), (1, 2, FIELD_PRIME)):
            context = dataclasses.replace(self.context, participant_ids=ids)
            with self.assertRaises(ValueError, msg=ids):
                verify_signing_public_context(context)

    def test_threshold_value_errors(self):
        for threshold in (0, -1, 4):
            context = dataclasses.replace(self.context, threshold=threshold)
            with self.assertRaises(ValueError, msg=threshold):
                verify_signing_public_context(context)

    def test_verification_share_count_mismatch(self):
        shares = self.context.verification_shares
        for wrong in (shares[:2], shares + (1,)):
            context = dataclasses.replace(self.context, verification_shares=wrong)
            with self.assertRaises(ValueError, msg=wrong):
                verify_signing_public_context(context)

    def test_group_parameter_value_errors(self):
        replacements = [
            {"field_prime": 2018},  # not prime
            {"group_prime": 8070},  # not prime
            {"field_prime": 2017, "group_prime": 2 * 2017 + 2},
            {"generator": 1},
            {"generator": GROUP_PRIME},
            {"generator": GROUP_PRIME - 1},  # order 2, not 2017
        ]
        for field in replacements:
            context = dataclasses.replace(self.context, **field)
            with self.assertRaises(ValueError, msg=field):
                verify_signing_public_context(context)

    def test_public_key_value_errors(self):
        for public_key in (0, GROUP_PRIME, GROUP_PRIME - 1):
            context = dataclasses.replace(self.context, public_key=public_key)
            with self.assertRaises(ValueError, msg=public_key):
                verify_signing_public_context(context)

    def test_verification_share_value_errors(self):
        shares = self.context.verification_shares
        for wrong in (
            (0,) + shares[1:],
            (GROUP_PRIME,) + shares[1:],
            (GROUP_PRIME - 1,) + shares[1:],
        ):
            context = dataclasses.replace(self.context, verification_shares=wrong)
            with self.assertRaises(ValueError, msg=wrong):
                verify_signing_public_context(context)

    def test_invalid_input_never_masked_by_false(self):
        # A context that is both structurally illegal and inconsistent
        # raises instead of returning False.
        context = dataclasses.replace(self.context, threshold=0)
        with self.assertRaises(ValueError):
            verify_signing_public_context(context)


class PurityTest(unittest.TestCase):
    def test_repeated_calls_agree_and_do_not_mutate(self):
        good = export_signing_public_context(make_key())
        bad = dataclasses.replace(
            good, public_key=good.public_key * GENERATOR % GROUP_PRIME
        )
        for context, expected in ((good, True), (bad, False)):
            before = dataclasses.astuple(context)
            self.assertIs(verify_signing_public_context(context), expected)
            self.assertIs(verify_signing_public_context(context), expected)
            self.assertEqual(dataclasses.astuple(context), before)


if __name__ == "__main__":
    unittest.main()
