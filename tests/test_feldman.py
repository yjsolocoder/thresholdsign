import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    FeldmanCommitment,
    Share,
    reconstruct_secret,
    split_secret,
    split_secret_verifiable,
    verify_share,
)

# Small safe setup: 8069 = 4 * 2017 + 1 is prime and 16 has order 2017 in the
# multiplicative group modulo 8069.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
SECRET = 0x123


def fixed_random():
    """Deterministic stand-in for secrets.randbelow so tests are reproducible."""
    state = {"value": 1}

    def randbelow(upper: int) -> int:
        state["value"] = (state["value"] * 6364136223846793005 + 1442695040888963407) % upper
        return state["value"]

    return randbelow


def make_shares(secret=SECRET, threshold=3, share_count=5, **kwargs):
    options = {
        "group_prime": GROUP_PRIME,
        "generator": GENERATOR,
        "prime": FIELD_PRIME,
        "randbelow": fixed_random(),
    }
    options.update(kwargs)
    return split_secret_verifiable(secret, threshold, share_count, **options)


class SplitVerifiableTest(unittest.TestCase):
    def test_returns_shares_and_commitment(self):
        shares, commitment = make_shares()
        self.assertEqual(len(shares), 5)
        self.assertIsInstance(commitment, FeldmanCommitment)
        self.assertEqual(len(commitment.values), 3)
        self.assertEqual(
            (commitment.field_prime, commitment.group_prime, commitment.generator),
            (FIELD_PRIME, GROUP_PRIME, GENERATOR),
        )

    def test_every_share_verifies(self):
        shares, commitment = make_shares()
        for share in shares:
            self.assertTrue(verify_share(share, commitment))

    def test_constant_term_commitment_matches_secret(self):
        shares, commitment = make_shares()
        self.assertEqual(commitment.values[0], pow(GENERATOR, SECRET, GROUP_PRIME))

    def test_shares_reconstruct_with_existing_api(self):
        shares, commitment = make_shares()
        self.assertEqual(reconstruct_secret(shares[:3], prime=FIELD_PRIME), SECRET)

    def test_shares_match_plain_split_under_same_rule(self):
        verifiable, _ = make_shares()
        plain = split_secret(
            SECRET, 3, 5, prime=FIELD_PRIME, randbelow=fixed_random()
        )
        self.assertEqual(verifiable, plain)

    def test_threshold_one(self):
        shares, commitment = make_shares(threshold=1, share_count=3)
        self.assertEqual(len(commitment.values), 1)
        self.assertTrue(all(share.y == SECRET for share in shares))
        self.assertTrue(all(verify_share(share, commitment) for share in shares))

    def test_zero_secret_round_trips(self):
        shares, commitment = make_shares(secret=0, threshold=2, share_count=3)
        self.assertTrue(all(verify_share(share, commitment) for share in shares))
        self.assertEqual(commitment.values[0], 1)
        self.assertEqual(reconstruct_secret(shares[:2], prime=FIELD_PRIME), 0)

    def test_commitment_is_frozen(self):
        _, commitment = make_shares()
        with self.assertRaises(FrozenInstanceError):
            commitment.values = ()  # type: ignore[misc]

    def test_commitment_does_not_store_coefficients(self):
        _, commitment = make_shares()
        self.assertEqual(
            {field.name for field in dataclasses.fields(commitment)},
            {"values", "field_prime", "group_prime", "generator"},
        )
        self.assertFalse(hasattr(commitment, "coefficients"))


class VerifyShareTest(unittest.TestCase):
    def setUp(self):
        self.shares, self.commitment = make_shares()

    def test_tampered_value_returns_false(self):
        share = self.shares[0]
        tampered = Share(share.x, (share.y + 1) % FIELD_PRIME)
        self.assertFalse(verify_share(tampered, self.commitment))

    def test_share_from_other_polynomial_returns_false(self):
        other_shares, _ = make_shares(secret=SECRET + 1, threshold=1, share_count=3)
        _, constant_commitment = make_shares(secret=SECRET, threshold=1, share_count=3)
        for share in other_shares:
            self.assertFalse(verify_share(share, constant_commitment))

    def test_commitment_from_other_polynomial_returns_false(self):
        shares_a, commitment_a = make_shares(secret=10, threshold=2, share_count=3)
        _, commitment_b = make_shares(secret=20, threshold=2, share_count=3)
        # A pair of linear polynomials agrees at x = 0 at most, so every
        # positive coordinate mismatches.
        for share in shares_a:
            self.assertFalse(verify_share(share, commitment_b))
            self.assertTrue(verify_share(share, commitment_a))


class FeldmanParameterValidationTest(unittest.TestCase):
    def test_field_prime_must_be_prime(self):
        with self.assertRaises(ValueError):
            make_shares(prime=2021)

    def test_group_prime_must_be_prime(self):
        with self.assertRaises(ValueError):
            make_shares(group_prime=8067)

    def test_field_prime_must_divide_group_prime_minus_one(self):
        with self.assertRaises(ValueError):
            make_shares(prime=2011)  # 2011 prime, 8068 % 2011 != 0

    def test_generator_one_rejected(self):
        with self.assertRaises(ValueError):
            make_shares(generator=1)

    def test_generator_out_of_range_rejected(self):
        for bad in (0, -1, GROUP_PRIME):
            with self.assertRaises(ValueError):
                make_shares(generator=bad)

    def test_generator_wrong_order_rejected(self):
        with self.assertRaises(ValueError):
            make_shares(generator=GROUP_PRIME - 1)  # element of order 2

    def test_non_integer_parameters_raise_type_error(self):
        with self.assertRaises(TypeError):
            make_shares(prime=2017.0)
        with self.assertRaises(TypeError):
            make_shares(group_prime=8069.0)
        with self.assertRaises(TypeError):
            make_shares(generator="16")

    def test_plain_split_validation_still_applies(self):
        with self.assertRaises(ValueError):
            make_shares(threshold=0, share_count=3)
        with self.assertRaises(ValueError):
            make_shares(threshold=4, share_count=3)
        with self.assertRaises(TypeError):
            make_shares(threshold=2.5, share_count=3)


class VerifyShareValidationTest(unittest.TestCase):
    def setUp(self):
        self.shares, self.commitment = make_shares()
        self.good_share = self.shares[0]

    def test_share_wrong_type(self):
        with self.assertRaises(TypeError):
            verify_share((1, self.good_share.y), self.commitment)  # type: ignore[arg-type]

    def test_commitment_wrong_type(self):
        with self.assertRaises(TypeError):
            verify_share(self.good_share, (1, 2))  # type: ignore[arg-type]

    def test_empty_commitment_rejected(self):
        empty = FeldmanCommitment((), FIELD_PRIME, GROUP_PRIME, GENERATOR)
        with self.assertRaises(ValueError):
            verify_share(self.good_share, empty)

    def test_values_wrong_container_type(self):
        bad = FeldmanCommitment(
            list(self.commitment.values), FIELD_PRIME, GROUP_PRIME, GENERATOR  # type: ignore[arg-type]
        )
        with self.assertRaises(TypeError):
            verify_share(self.good_share, bad)

    def test_non_integer_commitment_value_rejected(self):
        values = (self.commitment.values[0], "1")
        bad = FeldmanCommitment(values, FIELD_PRIME, GROUP_PRIME, GENERATOR)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            verify_share(self.good_share, bad)

    def test_non_integer_share_fields_rejected(self):
        with self.assertRaises(TypeError):
            verify_share(Share("1", 2), self.commitment)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            verify_share(Share(1, 2.0), self.commitment)  # type: ignore[arg-type]

    def test_commitment_value_out_of_range_rejected(self):
        values = self.commitment.values
        for bad_value in (0, GROUP_PRIME):
            bad = FeldmanCommitment(
                (bad_value,) + values[1:], FIELD_PRIME, GROUP_PRIME, GENERATOR
            )
            with self.assertRaises(ValueError):
                verify_share(self.good_share, bad)

    def test_commitment_value_outside_subgroup_rejected(self):
        values = (GROUP_PRIME - 1,) + self.commitment.values[1:]
        bad = FeldmanCommitment(values, FIELD_PRIME, GROUP_PRIME, GENERATOR)
        with self.assertRaises(ValueError):
            verify_share(self.good_share, bad)

    def test_non_prime_commitment_moduli_rejected(self):
        bad = FeldmanCommitment(self.commitment.values, 2021, GROUP_PRIME, GENERATOR)
        with self.assertRaises(ValueError):
            verify_share(self.good_share, bad)
        bad = FeldmanCommitment(self.commitment.values, FIELD_PRIME, 8067, GENERATOR)
        with self.assertRaises(ValueError):
            verify_share(self.good_share, bad)

    def test_non_dividing_commitment_moduli_rejected(self):
        bad = FeldmanCommitment(self.commitment.values, 2011, GROUP_PRIME, GENERATOR)
        with self.assertRaises(ValueError):
            verify_share(self.good_share, bad)

    def test_illegal_commitment_generator_rejected(self):
        for generator in (1, GROUP_PRIME - 1):
            bad = FeldmanCommitment(
                self.commitment.values, FIELD_PRIME, GROUP_PRIME, generator
            )
            with self.assertRaises(ValueError):
                verify_share(self.good_share, bad)

    def test_coordinate_out_of_bounds_rejected(self):
        y = self.good_share.y
        for x in (0, -1, FIELD_PRIME):
            with self.assertRaises(ValueError):
                verify_share(Share(x, y), self.commitment)

    def test_value_out_of_bounds_rejected(self):
        x = self.good_share.x
        for y in (-1, FIELD_PRIME):
            with self.assertRaises(ValueError):
                verify_share(Share(x, y), self.commitment)

    def test_legal_mismatch_is_false_not_error(self):
        mismatch = Share(self.good_share.x, (self.good_share.y + 1) % FIELD_PRIME)
        self.assertIs(verify_share(mismatch, self.commitment), False)


if __name__ == "__main__":
    unittest.main()
