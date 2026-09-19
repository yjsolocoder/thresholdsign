import unittest
from itertools import combinations

from thresholdsign import (
    DEFAULT_PRIME,
    FeldmanCommitment,
    Share,
    evaluate_polynomial,
    reconstruct_secret,
    split_secret,
    split_secret_verifiable,
    verify_share,
)

PRIME = (1 << 61) - 1
SECRET = 0x1234567890ABCDEF

# Feldman group: GROUP_PRIME = 52 * PRIME + 1 (prime), GENERATOR has order PRIME.
GROUP_PRIME = 119903836479112085453
GENERATOR = 4503599627370496


def fixed_random():
    """Deterministic stand-in for secrets.randbelow so tests are reproducible."""
    state = {"value": 1}

    def randbelow(upper: int) -> int:
        state["value"] = (state["value"] * 6364136223846793005 + 1442695040888963407) % upper
        return state["value"]

    return randbelow


class PolynomialTest(unittest.TestCase):
    def test_constant_polynomial(self):
        self.assertEqual(evaluate_polynomial([7], 12345, prime=PRIME), 7)

    def test_matches_direct_evaluation(self):
        coefficients = [3, 5, 11]
        x = 9
        expected = (3 + 5 * x + 11 * x * x) % PRIME
        self.assertEqual(evaluate_polynomial(coefficients, x, prime=PRIME), expected)

    def test_rejects_empty_coefficients(self):
        with self.assertRaises(ValueError):
            evaluate_polynomial([], 1, prime=PRIME)


class SplitTest(unittest.TestCase):
    def test_share_count_and_indices(self):
        shares = split_secret(SECRET, 3, 5, prime=PRIME, randbelow=fixed_random())
        self.assertEqual(len(shares), 5)
        self.assertEqual([share.x for share in shares], [1, 2, 3, 4, 5])

    def test_threshold_one_uses_constant_polynomial(self):
        shares = split_secret(SECRET, 1, 3, prime=PRIME, randbelow=fixed_random())
        self.assertTrue(all(share.y == SECRET for share in shares))

    def test_shares_lie_on_one_polynomial(self):
        shares = split_secret(SECRET, 3, 5, prime=PRIME, randbelow=fixed_random())
        # Any three points determine the same interpolated constant.
        values = {reconstruct_secret(list(combo), prime=PRIME) for combo in combinations(shares, 3)}
        self.assertEqual(values, {SECRET})

    def test_threshold_above_share_count_rejected(self):
        with self.assertRaises(ValueError):
            split_secret(SECRET, 4, 3, prime=PRIME, randbelow=fixed_random())

    def test_zero_threshold_rejected(self):
        with self.assertRaises(ValueError):
            split_secret(SECRET, 0, 3, prime=PRIME, randbelow=fixed_random())

    def test_secret_out_of_range_rejected(self):
        with self.assertRaises(ValueError):
            split_secret(PRIME, 2, 3, prime=PRIME, randbelow=fixed_random())

    def test_negative_secret_rejected(self):
        with self.assertRaises(ValueError):
            split_secret(-1, 2, 3, prime=PRIME, randbelow=fixed_random())

    def test_non_integer_threshold_rejected(self):
        with self.assertRaises(TypeError):
            split_secret(SECRET, 2.5, 3, prime=PRIME)


class ReconstructTest(unittest.TestCase):
    def setUp(self):
        self.shares = split_secret(SECRET, 3, 5, prime=PRIME, randbelow=fixed_random())

    def test_all_subsets_of_threshold_size(self):
        for combo in combinations(self.shares, 3):
            self.assertEqual(reconstruct_secret(list(combo), prime=PRIME), SECRET)

    def test_more_than_threshold_still_works(self):
        self.assertEqual(reconstruct_secret(self.shares, prime=PRIME), SECRET)

    def test_zero_secret_round_trips(self):
        shares = split_secret(0, 2, 3, prime=PRIME, randbelow=fixed_random())
        self.assertEqual(reconstruct_secret(shares[:2], prime=PRIME), 0)

    def test_duplicate_index_rejected(self):
        duplicated = [self.shares[0], self.shares[0], self.shares[1]]
        with self.assertRaises(ValueError):
            reconstruct_secret(duplicated, prime=PRIME)

    def test_empty_shares_rejected(self):
        with self.assertRaises(ValueError):
            reconstruct_secret([], prime=PRIME)

    def test_wrong_type_rejected(self):
        with self.assertRaises(TypeError):
            reconstruct_secret([(1, 2)], prime=PRIME)

    def test_invalid_index_rejected(self):
        with self.assertRaises(ValueError):
            reconstruct_secret([Share(0, 5)], prime=PRIME)

    def test_default_prime_is_usable(self):
        shares = split_secret(SECRET, 2, 3, randbelow=fixed_random())
        self.assertEqual(reconstruct_secret(shares[:2]), SECRET)
        self.assertGreater(DEFAULT_PRIME, SECRET)


class FeldmanTest(unittest.TestCase):
    def split(self, secret=SECRET, threshold=3, share_count=5, **overrides):
        kwargs = dict(
            prime=PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            randbelow=fixed_random(),
        )
        kwargs.update(overrides)
        return split_secret_verifiable(secret, threshold, share_count, **kwargs)

    def test_round_trip_and_verification(self):
        shares, commitment = self.split()
        self.assertEqual(len(shares), 5)
        self.assertEqual(len(commitment.values), 3)
        self.assertEqual(commitment.field_prime, PRIME)
        self.assertEqual(commitment.group_prime, GROUP_PRIME)
        self.assertEqual(commitment.generator, GENERATOR)
        for share in shares:
            self.assertTrue(verify_share(share, commitment))
        for combo in combinations(shares, 3):
            self.assertEqual(reconstruct_secret(list(combo), prime=PRIME), SECRET)

    def test_commitment_hides_coefficients_but_binds_secret(self):
        shares, commitment = self.split()
        # C_0 commits to the secret; coefficients never appear in the clear.
        self.assertEqual(commitment.values[0], pow(GENERATOR, SECRET, GROUP_PRIME))
        self.assertNotIn(shares[0].y, commitment.values)

    def test_tampered_share_rejected(self):
        shares, commitment = self.split()
        tampered = Share(x=shares[0].x, y=(shares[0].y + 1) % PRIME)
        self.assertFalse(verify_share(tampered, commitment))

    def test_share_from_other_polynomial_rejected(self):
        shares, commitment = self.split()
        other_shares, _ = self.split(secret=SECRET + 1)
        self.assertFalse(verify_share(other_shares[0], commitment))
        self.assertTrue(verify_share(shares[0], commitment))

    def test_threshold_one_verifies(self):
        shares, commitment = self.split(threshold=1, share_count=3)
        self.assertEqual(len(commitment.values), 1)
        self.assertTrue(all(verify_share(share, commitment) for share in shares))

    def test_non_prime_moduli_rejected(self):
        with self.assertRaises(ValueError):
            self.split(prime=PRIME - 2)
        with self.assertRaises(ValueError):
            self.split(group_prime=GROUP_PRIME + 2)

    def test_non_dividing_prime_rejected(self):
        other_prime = (1 << 61) - 1
        bad_group = 3 * other_prime + 2  # (bad_group - 1) % other_prime == 1
        with self.assertRaises(ValueError):
            self.split(group_prime=bad_group)

    def test_bad_generator_rejected(self):
        with self.assertRaises(ValueError):
            self.split(generator=1)
        with self.assertRaises(ValueError):
            self.split(generator=2)  # order 52 * PRIME, not PRIME
        with self.assertRaises(ValueError):
            self.split(generator=GROUP_PRIME)

    def test_non_integer_parameters_rejected(self):
        with self.assertRaises(TypeError):
            self.split(group_prime=float(GROUP_PRIME))
        with self.assertRaises(TypeError):
            self.split(generator="g")

    def test_split_validation_still_applies(self):
        with self.assertRaises(ValueError):
            self.split(threshold=0)
        with self.assertRaises(TypeError):
            self.split(threshold=2.5)

    def test_verify_type_errors(self):
        shares, commitment = self.split()
        with self.assertRaises(TypeError):
            verify_share((shares[0].x, shares[0].y), commitment)
        with self.assertRaises(TypeError):
            verify_share(shares[0], (commitment.values, PRIME, GROUP_PRIME, GENERATOR))

    def test_verify_empty_commitment_rejected(self):
        shares, commitment = self.split()
        empty = FeldmanCommitment((), PRIME, GROUP_PRIME, GENERATOR)
        with self.assertRaises(ValueError):
            verify_share(shares[0], empty)

    def test_verify_out_of_range_coordinates_rejected(self):
        shares, commitment = self.split()
        with self.assertRaises(ValueError):
            verify_share(Share(0, shares[0].y), commitment)
        with self.assertRaises(ValueError):
            verify_share(Share(PRIME, shares[0].y), commitment)
        with self.assertRaises(ValueError):
            verify_share(Share(shares[0].x, PRIME), commitment)

    def test_verify_invalid_commitment_rejected(self):
        shares, commitment = self.split()
        with self.assertRaises(ValueError):
            verify_share(shares[0], FeldmanCommitment((0,) + commitment.values[1:], PRIME, GROUP_PRIME, GENERATOR))
        with self.assertRaises(ValueError):
            verify_share(shares[0], FeldmanCommitment(commitment.values, PRIME, GROUP_PRIME, 1))
        with self.assertRaises(TypeError):
            verify_share(shares[0], FeldmanCommitment(("x",) + commitment.values[1:], PRIME, GROUP_PRIME, GENERATOR))

    def test_commitment_is_frozen(self):
        _, commitment = self.split()
        with self.assertRaises(AttributeError):
            commitment.generator = 2


if __name__ == "__main__":
    unittest.main()
