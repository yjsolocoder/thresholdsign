import unittest
from itertools import combinations

from thresholdsign import (
    DEFAULT_PRIME,
    Share,
    evaluate_polynomial,
    reconstruct_secret,
    split_secret,
)

PRIME = (1 << 61) - 1
SECRET = 0x1234567890ABCDEF


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


if __name__ == "__main__":
    unittest.main()
