import unittest
from itertools import combinations

from thresholdsign import (
    DEFAULT_PRIME,
    RecoveryReport,
    Share,
    evaluate_polynomial,
    reconstruct_secret,
    recover_secret,
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


def tamper(shares, index, *, offset=1, prime=PRIME):
    return [
        share
        if share.x != index
        else Share(share.x, (share.y + offset) % prime)
        for share in shares
    ]


class RecoverHappyPathTest(unittest.TestCase):
    def setUp(self):
        self.shares = split_secret(SECRET, 3, 5, prime=PRIME, randbelow=fixed_random())

    def test_report_fields_in_order(self):
        report = recover_secret(self.shares, 3, prime=PRIME)
        self.assertEqual(
            (report.secret, report.accepted, report.rejected),
            (SECRET, tuple(self.shares), ()),
        )

    def test_secret_matches_reconstruct_secret(self):
        tampered = tamper(self.shares, 4)
        report = recover_secret(tampered, 3, prime=PRIME)
        self.assertEqual(report.secret, SECRET)
        self.assertEqual(
            report.secret, reconstruct_secret(report.accepted, prime=PRIME)
        )

    def test_single_tampered_share_is_the_only_rejected(self):
        tampered = tamper(self.shares, 4)
        report = recover_secret(tampered, 3, prime=PRIME)
        self.assertEqual([share.x for share in report.rejected], [4])
        self.assertEqual(
            [share.x for share in report.accepted], [1, 2, 3, 5]
        )
        self.assertEqual(report.rejected[0].y, (self.shares[3].y + 1) % PRIME)

    def test_each_single_tamper_location_recovers(self):
        for index in range(1, 6):
            with self.subTest(index=index):
                report = recover_secret(tamper(self.shares, index), 3, prime=PRIME)
                self.assertEqual(report.secret, SECRET)
                self.assertEqual([share.x for share in report.rejected], [index])
                self.assertEqual(len(report.accepted), 4)

    def test_accepts_tuple_and_list_inputs(self):
        tampered = tamper(self.shares, 2)
        from_list = recover_secret(list(reversed(tampered)), 3, prime=PRIME)
        from_tuple = recover_secret(tuple(reversed(tampered)), 3, prime=PRIME)
        self.assertEqual(from_list, from_tuple)
        self.assertEqual(from_list.secret, SECRET)
        self.assertEqual([share.x for share in from_list.rejected], [2])

    def test_order_independent(self):
        tampered = tamper(self.shares, 3)
        reference = recover_secret(tampered, 3, prime=PRIME)
        for permutation in (
            list(reversed(tampered)),
            [tampered[i] for i in (4, 0, 2, 1, 3)],
        ):
            self.assertEqual(recover_secret(permutation, 3, prime=PRIME), reference)

    def test_groups_sorted_by_coordinate(self):
        tampered = tamper(self.shares, 1)
        report = recover_secret(list(reversed(tampered)), 3, prime=PRIME)
        accepted_x = [share.x for share in report.accepted]
        rejected_x = [share.x for share in report.rejected]
        self.assertEqual(accepted_x, sorted(accepted_x))
        self.assertEqual(rejected_x, sorted(rejected_x))
        self.assertEqual(rejected_x, [1])

    def test_threshold_equal_to_share_count_with_all_honest(self):
        report = recover_secret(self.shares[:3], 3, prime=PRIME)
        self.assertEqual(report.secret, SECRET)
        self.assertEqual(len(report.accepted), 3)
        self.assertEqual(report.rejected, ())

    def test_more_shares_than_threshold_two_tampered(self):
        shares = split_secret(SECRET, 2, 6, prime=PRIME, randbelow=fixed_random())
        damaged = tamper(tamper(shares, 2), 5)
        report = recover_secret(damaged, 2, prime=PRIME)
        self.assertEqual(report.secret, SECRET)
        self.assertEqual([share.x for share in report.rejected], [2, 5])
        self.assertEqual([share.x for share in report.accepted], [1, 3, 4, 6])

    def test_default_prime_round_trip(self):
        shares = split_secret(SECRET, 2, 4, randbelow=fixed_random())
        report = recover_secret(tamper(shares, 3, prime=DEFAULT_PRIME), 2)
        self.assertEqual(report.secret, SECRET)
        self.assertEqual([share.x for share in report.rejected], [3])


LARGE_PRIME = 2017
LARGE_N = 64
LARGE_T = 32
LARGE_CAPACITY = (LARGE_N - LARGE_T) // 2  # 16


def _large_coefficients():
    # Deterministic dense degree-(t-1) coefficient vector over GF(2017).
    value = 1
    coefficients = []
    for _ in range(LARGE_T):
        value = (value * 45 + 7) % LARGE_PRIME
        coefficients.append(value)
    return coefficients


def _large_shares(coefficients):
    return [
        Share(x, evaluate_polynomial(coefficients, x, prime=LARGE_PRIME))
        for x in range(1, LARGE_N + 1)
    ]


def _damage(shares, positions, *, prime=LARGE_PRIME):
    damaged = list(shares)
    for position in positions:
        damaged[position] = Share(
            damaged[position].x, (damaged[position].y + 1009) % prime
        )
    return damaged


class PolynomialRecoveryScaleTest(unittest.TestCase):
    # Enumerating every C(64, 32) subset cannot finish at all, so merely
    # completing these cases pins recovery to polynomial field work.

    def test_zero_errors_dense_polynomial(self):
        coefficients = _large_coefficients()
        report = recover_secret(_large_shares(coefficients), LARGE_T, prime=LARGE_PRIME)
        self.assertEqual(report.secret, coefficients[0])
        self.assertEqual(len(report.rejected), 0)
        self.assertEqual(len(report.accepted), LARGE_N)

    def test_half_and_full_error_capacity_at_fixed_positions(self):
        coefficients = _large_coefficients()
        shares = _large_shares(coefficients)
        for error_count in (1, 8, LARGE_CAPACITY):
            with self.subTest(error_count=error_count):
                positions = tuple(range(error_count))
                report = recover_secret(
                    _damage(shares, positions), LARGE_T, prime=LARGE_PRIME
                )
                self.assertEqual(report.secret, coefficients[0])
                self.assertEqual(
                    [share.x for share in report.rejected],
                    [position + 1 for position in positions],
                )

    def test_every_sliding_window_of_sixteen_errors(self):
        coefficients = _large_coefficients()
        shares = _large_shares(coefficients)
        for start in range(LARGE_N):
            positions = [(start + offset) % LARGE_N for offset in range(LARGE_CAPACITY)]
            with self.subTest(start=start):
                report = recover_secret(
                    _damage(shares, positions), LARGE_T, prime=LARGE_PRIME
                )
                self.assertEqual(report.secret, coefficients[0])
                self.assertEqual(
                    sorted(share.x for share in report.rejected),
                    sorted(position + 1 for position in positions),
                )

    def test_lower_degree_polynomials_recover(self):
        for degree in (0, 1, 5, LARGE_T - 2):
            with self.subTest(degree=degree):
                coefficients = _large_coefficients()[: degree + 1]
                shares = _large_shares(coefficients)
                positions = tuple(range(LARGE_CAPACITY))
                report = recover_secret(
                    _damage(shares, positions), LARGE_T, prime=LARGE_PRIME
                )
                self.assertEqual(report.secret, coefficients[0])
                self.assertEqual(len(report.rejected), LARGE_CAPACITY)

    def test_does_not_mutate_input_and_reuses_share_objects(self):
        coefficients = _large_coefficients()
        shares = _large_shares(coefficients)
        damaged = _damage(shares, range(5))
        snapshot = [Share(share.x, share.y) for share in damaged]
        report = recover_secret(damaged, LARGE_T, prime=LARGE_PRIME)
        self.assertEqual(
            [Share(share.x, share.y) for share in damaged], snapshot
        )
        for share in (*report.accepted, *report.rejected):
            self.assertIn(share, damaged)


class BeyondCorrectionRadiusTest(unittest.TestCase):
    # Outside 2e <= n - t the global enumeration semantics still hold.

    def test_unique_best_beyond_radius_still_reported(self):
        coefficients = [SECRET % PRIME, 12345, 678901]
        shares = [
            Share(x, evaluate_polynomial(coefficients, x, prime=PRIME))
            for x in range(1, 13)
        ]
        positions = [1, 4, 6, 9, 11]  # 5 errors; radius is floor(9/2) = 4
        damaged = tamper_multi(shares, positions, prime=PRIME)
        report = recover_secret(damaged, 3, prime=PRIME)
        self.assertEqual(report.secret, SECRET % PRIME)
        self.assertEqual([share.x for share in report.rejected], positions)
        self.assertEqual(len(report.accepted), 7)

    def test_unique_best_with_low_degree_polynomial_beyond_radius(self):
        coefficients = [424242]  # constant polynomial, threshold 3
        shares = [
            Share(x, evaluate_polynomial(coefficients, x, prime=PRIME))
            for x in range(1, 13)
        ]
        positions = [1, 4, 6, 9, 11]
        damaged = tamper_multi(shares, positions, prime=PRIME)
        report = recover_secret(damaged, 3, prime=PRIME)
        self.assertEqual(report.secret, 424242)
        self.assertEqual([share.x for share in report.rejected], positions)

    def test_tie_with_identical_secret_still_raises(self):
        # Two distinct degree-2 polynomials with the same constant term each
        # fit three supplied points: tied candidates, even equal secrets,
        # must not be treated as unique.
        first = [1, 2, 0]
        second = [1, 3, 0]
        shares = [
            Share(x, evaluate_polynomial(first, x, prime=PRIME)) for x in (1, 2, 3)
        ] + [
            Share(x, evaluate_polynomial(second, x, prime=PRIME))
            for x in (4, 5, 6)
        ]
        with self.assertRaises(ValueError):
            recover_secret(shares, 3, prime=PRIME)


def tamper_multi(shares, positions, *, prime=PRIME, offset=999):
    damaged = list(shares)
    for x_coordinate in positions:
        index = x_coordinate - 1
        damaged[index] = Share(
            damaged[index].x, (damaged[index].y + offset) % prime
        )
    return damaged


class ThresholdOneTest(unittest.TestCase):
    def test_constant_polynomial_all_equal(self):
        shares = split_secret(SECRET, 1, 4, prime=PRIME, randbelow=fixed_random())
        report = recover_secret(shares, 1, prime=PRIME)
        self.assertEqual(
            report, RecoveryReport(SECRET, tuple(shares), ())
        )
        self.assertEqual(report.secret, reconstruct_secret(shares, prime=PRIME))

    def test_constant_polynomial_groups_equal_values(self):
        shares = [Share(1, 7), Share(2, 7), Share(5, 7), Share(6, 8)]
        report = recover_secret(shares, 1, prime=PRIME)
        self.assertEqual(report.secret, 7)
        self.assertEqual([share.x for share in report.accepted], [1, 2, 5])
        self.assertEqual([share.x for share in report.rejected], [6])

    def test_single_share_is_its_own_constant(self):
        report = recover_secret([Share(3, 55)], 1, prime=PRIME)
        self.assertEqual(report, RecoveryReport(55, (Share(3, 55),), ()))

    def test_tie_between_two_constants_raises(self):
        with self.assertRaises(ValueError):
            recover_secret([Share(1, 7), Share(2, 8)], 1, prime=PRIME)


class RecoveryReportTest(unittest.TestCase):
    def test_frozen_positionally_constructible_value_compared(self):
        first = RecoveryReport(9, (Share(1, 9), Share(2, 9)), (Share(3, 8),))
        second = RecoveryReport(9, (Share(1, 9), Share(2, 9)), (Share(3, 8),))
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        different = RecoveryReport(8, (Share(1, 9), Share(2, 9)), (Share(3, 8),))
        self.assertNotEqual(first, different)
        with self.assertRaises(Exception):
            first.secret = 10  # type: ignore[misc]

    def test_accepted_and_rejected_are_tuples(self):
        report = recover_secret(
            [Share(1, 4), Share(2, 4), Share(3, 5)], 1, prime=PRIME
        )
        self.assertIsInstance(report.accepted, tuple)
        self.assertIsInstance(report.rejected, tuple)
        self.assertIsInstance(report, RecoveryReport)


class UndecidableTest(unittest.TestCase):
    def test_tie_when_two_polynomials_each_fit_two(self):
        # threshold 3, four points: two from one degree-2 sharing polynomial
        # and two from another. Every three points span a degree-2 candidate
        # fitting those three, so several candidates tie with the same
        # maximum fit count and no decision is possible.
        shares_a = split_secret(11, 3, 4, prime=PRIME, randbelow=fixed_random())
        shares_b = split_secret(22, 3, 4, prime=PRIME, randbelow=fixed_random())
        points = [
            shares_a[0],
            shares_a[1],
            Share(3, shares_b[2].y),
            Share(4, shares_b[3].y),
        ]
        with self.assertRaises(ValueError):
            recover_secret(points, 3, prime=PRIME)

    def test_tie_between_two_dense_polynomials(self):
        # Four points on each of two distinct degree-2 polynomials: both
        # interpolants agree with four shares, every mixed candidate with at
        # most three.
        shares_a = split_secret(11, 3, 8, prime=PRIME, randbelow=fixed_random())
        shares_b = split_secret(22, 3, 8, prime=PRIME, randbelow=fixed_random())
        points = shares_a[:4] + [
            Share(share.x, shares_b[share.x - 1].y) for share in shares_a[4:]
        ]
        with self.assertRaises(ValueError):
            recover_secret(points, 3, prime=PRIME)

    def test_single_tamper_below_information_bound_raises(self):
        # n = 4, threshold = 3: one tampered share cannot be distinguished
        # from one honest share lying on the adversary's polynomial.
        shares = split_secret(SECRET, 3, 4, prime=PRIME, randbelow=fixed_random())
        with self.assertRaises(ValueError):
            recover_secret(tamper(shares, 4), 3, prime=PRIME)

    def test_exactly_threshold_shares_have_a_single_interpolant(self):
        # With no redundant shares there is exactly one degree-<threshold
        # candidate (the interpolant), which trivially agrees with every
        # supplied point: a tampered share cannot be detected, and the result
        # matches plain reconstruct_secret on those same points.
        shares = split_secret(SECRET, 3, 3, prime=PRIME, randbelow=fixed_random())
        damaged = tamper(shares, 2)
        report = recover_secret(damaged, 3, prime=PRIME)
        self.assertEqual(tuple(s.x for s in report.accepted), (1, 2, 3))
        self.assertEqual(report.rejected, ())
        self.assertEqual(report.secret, reconstruct_secret(damaged, prime=PRIME))


class RecoverValidationTest(unittest.TestCase):
    def setUp(self):
        self.shares = split_secret(SECRET, 2, 3, prime=PRIME, randbelow=fixed_random())

    def test_container_must_be_tuple_or_list(self):
        with self.assertRaises(TypeError):
            recover_secret(iter(self.shares), 2, prime=PRIME)
        with self.assertRaises(TypeError):
            recover_secret({share.x: share for share in self.shares}, 2, prime=PRIME)

    def test_elements_must_be_share_instances(self):
        with self.assertRaises(TypeError):
            recover_secret([(1, 2), (2, 3)], 1, prime=PRIME)
        with self.assertRaises(TypeError):
            recover_secret([self.shares[0], (2, 3)], 2, prime=PRIME)

    def test_threshold_and_prime_must_be_integers(self):
        with self.assertRaises(TypeError):
            recover_secret(self.shares, 2.0, prime=PRIME)
        with self.assertRaises(TypeError):
            recover_secret(self.shares, "2", prime=PRIME)
        with self.assertRaises(TypeError):
            recover_secret(self.shares, True, prime=PRIME)
        with self.assertRaises(TypeError):
            recover_secret(self.shares, 2, prime=101.0)
        with self.assertRaises(TypeError):
            recover_secret(self.shares, 2, prime=False)

    def test_share_fields_must_be_integers(self):
        with self.assertRaises(TypeError):
            recover_secret([Share(True, 1)], 1, prime=PRIME)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            recover_secret([Share(1, True)], 1, prime=PRIME)  # type: ignore[arg-type]

    def test_empty_shares_raise_value_error(self):
        with self.assertRaises(ValueError):
            recover_secret([], 1, prime=PRIME)

    def test_duplicate_index_raises_value_error(self):
        with self.assertRaises(ValueError):
            recover_secret([Share(1, 2), Share(1, 3)], 1, prime=PRIME)

    def test_index_out_of_range_raises_value_error(self):
        with self.assertRaises(ValueError):
            recover_secret([Share(0, 5), Share(2, 6)], 1, prime=PRIME)
        with self.assertRaises(ValueError):
            recover_secret([Share(PRIME, 5)], 1, prime=PRIME)
        with self.assertRaises(ValueError):
            recover_secret([Share(-1, 5)], 1, prime=PRIME)

    def test_value_out_of_range_raises_value_error(self):
        with self.assertRaises(ValueError):
            recover_secret([Share(1, PRIME)], 1, prime=PRIME)
        with self.assertRaises(ValueError):
            recover_secret([Share(1, -1)], 1, prime=PRIME)

    def test_threshold_bounds_raise_value_error(self):
        with self.assertRaises(ValueError):
            recover_secret(self.shares, 0, prime=PRIME)
        with self.assertRaises(ValueError):
            recover_secret(self.shares, 4, prime=PRIME)

    def test_composite_prime_raises_value_error(self):
        with self.assertRaises(ValueError):
            recover_secret(self.shares, 2, prime=9)
        with self.assertRaises(ValueError):
            recover_secret(self.shares, 2, prime=1)


if __name__ == "__main__":
    unittest.main()
