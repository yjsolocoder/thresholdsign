"""Systematic regression tests for recover_secret's unique-best-polynomial
decision rule.

README semantics under test: among all polynomials over GF(prime) with
degree below ``threshold``, the unique one agreeing with the most shares
decides; its constant term is the secret and agreeing/disagreeing shares
partition the input into ``accepted``/``rejected`` (both ascending in x).
A tie for the maximum raises ValueError, even when the tied polynomials
share the same constant term.

Every expectation in this file is derived by enumerating all
degree-<threshold polynomials over the field directly here; nothing is
borrowed from the package's recovery, interpolation, or evaluation code,
so a wrong answer from the implementation cannot masquerade as correct.
"""

import unittest
from itertools import combinations, product

from thresholdsign import RecoveryReport, Share, recover_secret

SMALL_PRIME = 5
SMALL_XS = (1, 2, 3, 4)
SHIFT = 3  # non-zero GF(5) element used for the uniform-y-shift checks


def evaluate(coefficients, x, prime):
    """Independent Horner evaluation over GF(prime)."""
    total = 0
    for coefficient in reversed(coefficients):
        total = (total * x + coefficient) % prime
    return total


def decide(xs, ys, threshold, prime):
    """Ground-truth decision by enumerating every degree-<threshold polynomial.

    Returns ``("ok", secret, accepted_xs, rejected_xs)`` when exactly one
    polynomial attains the maximal agreement count, ``("error",)`` when
    several distinct polynomials tie at the maximum (or, hypothetically,
    none reaches ``threshold`` agreements).
    """
    best_coefficients = None
    best_count = -1
    tied = False
    for coefficients in product(range(prime), repeat=threshold):
        count = sum(
            1
            for x, y in zip(xs, ys)
            if evaluate(coefficients, x, prime) == y
        )
        if count > best_count:
            best_coefficients = coefficients
            best_count = count
            tied = False
        elif count == best_count and coefficients != best_coefficients:
            tied = True
    if tied or best_count < threshold:
        return ("error",)
    accepted_xs = tuple(
        x
        for x, y in zip(xs, ys)
        if evaluate(best_coefficients, x, prime) == y
    )
    rejected_xs = tuple(x for x in xs if x not in accepted_xs)
    return ("ok", best_coefficients[0], accepted_xs, rejected_xs)


def _build_cases():
    """Every non-empty x-subset of SMALL_XS, every legal y combination and
    every threshold from 1 to the share count, with the oracle's decision.

    This covers the zero polynomial (all-zero y tuples), polynomials whose
    actual degree is below the threshold, and the no-redundancy boundary
    ``threshold == len(xs)`` as ordinary members of the same rule.
    """
    cases = []
    for width in range(1, len(SMALL_XS) + 1):
        for xs in combinations(SMALL_XS, width):
            for ys in product(range(SMALL_PRIME), repeat=width):
                for threshold in range(1, width + 1):
                    cases.append(
                        (xs, ys, threshold, decide(xs, ys, threshold, SMALL_PRIME))
                    )
    return cases


CASES = _build_cases()


def make_shares(xs, ys):
    return [Share(x, y) for x, y in zip(xs, ys)]


def expected_report(ys_of, expected):
    """Materialise an oracle decision as a RecoveryReport."""
    _, secret, accepted_xs, rejected_xs = expected
    return RecoveryReport(
        secret,
        tuple(Share(x, ys_of[x]) for x in accepted_xs),
        tuple(Share(x, ys_of[x]) for x in rejected_xs),
    )


class SmallFieldExhaustiveTest(unittest.TestCase):
    """GF(5) sweep: all 4320 (shares, threshold) inputs checked against
    direct enumeration of the degree-<threshold polynomials."""

    def _case_context(self, xs, ys, threshold):
        return self.subTest(
            prime=SMALL_PRIME, threshold=threshold, shares=list(zip(xs, ys))
        )

    def test_matches_polynomial_enumeration(self):
        for xs, ys, threshold, expected in CASES:
            with self._case_context(xs, ys, threshold):
                shares = make_shares(xs, ys)
                if expected[0] == "error":
                    with self.assertRaises(ValueError):
                        recover_secret(shares, threshold, prime=SMALL_PRIME)
                    continue
                report = recover_secret(shares, threshold, prime=SMALL_PRIME)
                self.assertEqual(report, expected_report(dict(zip(xs, ys)), expected))
                self.assertIsInstance(report.accepted, tuple)
                self.assertIsInstance(report.rejected, tuple)
                # accepted and rejected partition the input, both ascending in x
                self.assertEqual(
                    sorted(share.x for share in report.accepted + report.rejected),
                    list(xs),
                )

    def test_reversed_and_container_equivalence(self):
        for xs, ys, threshold, expected in CASES:
            with self._case_context(xs, ys, threshold):
                shares = make_shares(xs, ys)
                reversed_list = list(reversed(shares))
                reversed_tuple = tuple(reversed(shares))
                if expected[0] == "error":
                    with self.assertRaises(ValueError):
                        recover_secret(reversed_list, threshold, prime=SMALL_PRIME)
                    with self.assertRaises(ValueError):
                        recover_secret(reversed_tuple, threshold, prime=SMALL_PRIME)
                    continue
                forward = recover_secret(shares, threshold, prime=SMALL_PRIME)
                self.assertEqual(
                    recover_secret(reversed_list, threshold, prime=SMALL_PRIME),
                    forward,
                )
                self.assertEqual(
                    recover_secret(reversed_tuple, threshold, prime=SMALL_PRIME),
                    forward,
                )

    def test_uniform_y_shift_shifts_secret_only(self):
        for xs, ys, threshold, expected in CASES:
            with self._case_context(xs, ys, threshold):
                shifted_ys = tuple((y + SHIFT) % SMALL_PRIME for y in ys)
                shifted = make_shares(xs, shifted_ys)
                if expected[0] == "error":
                    # ambiguity is preserved under a uniform shift
                    with self.assertRaises(ValueError):
                        recover_secret(shifted, threshold, prime=SMALL_PRIME)
                    continue
                _, secret, _, _ = expected
                report = recover_secret(shifted, threshold, prime=SMALL_PRIME)
                shifted_expected = expected_report(
                    dict(zip(xs, shifted_ys)),
                    ("ok", (secret + SHIFT) % SMALL_PRIME, expected[2], expected[3]),
                )
                self.assertEqual(report, shifted_expected)

    def test_does_not_mutate_input(self):
        for xs, ys, threshold, expected in CASES:
            with self._case_context(xs, ys, threshold):
                shares = make_shares(xs, ys)
                snapshot = list(shares)
                try:
                    recover_secret(shares, threshold, prime=SMALL_PRIME)
                except ValueError:
                    pass
                self.assertEqual(shares, snapshot)
                for share, original in zip(shares, snapshot):
                    self.assertIs(share, original)


class BeyondRadiusUniqueBestTest(unittest.TestCase):
    """Deterministic GF(7) samples beyond the 2e <= n - threshold correction
    radius where a unique best polynomial still exists and must be reported;
    exceeding the radius is not by itself a failure."""

    PRIME = 7

    def _check_unique(self, xs, ys, threshold, secret, accepted_xs, rejected_xs):
        ys_of = dict(zip(xs, ys))
        expected = ("ok", secret, accepted_xs, rejected_xs)
        with self.subTest(prime=self.PRIME, threshold=threshold, shares=list(zip(xs, ys))):
            # genuinely outside the correction radius
            self.assertGreater(2 * len(rejected_xs), len(xs) - threshold)
            # the hard-coded expectation matches brute-force enumeration
            self.assertEqual(decide(xs, ys, threshold, self.PRIME), expected)
            report = recover_secret(make_shares(xs, ys), threshold, prime=self.PRIME)
            self.assertEqual(report, expected_report(ys_of, expected))

    def test_zero_polynomial_beyond_radius(self):
        # zero polynomial over GF(7), shares at x = 1..5 corrupted at x = 1, 2
        self._check_unique(
            xs=(1, 2, 3, 4, 5),
            ys=(1, 1, 0, 0, 0),
            threshold=2,
            secret=0,
            accepted_xs=(3, 4, 5),
            rejected_xs=(1, 2),
        )

    def test_dense_linear_polynomial_beyond_radius(self):
        # f(x) = 1 + x over GF(7), corrupted at x = 1, 2 (each y raised by 1)
        self._check_unique(
            xs=(1, 2, 3, 4, 5),
            ys=(3, 4, 4, 5, 6),
            threshold=2,
            secret=1,
            accepted_xs=(3, 4, 5),
            rejected_xs=(1, 2),
        )

    def test_actual_degree_below_threshold_beyond_radius(self):
        # constant polynomial 1 with threshold 3, corrupted at x = 1, 3
        self._check_unique(
            xs=(1, 2, 3, 4, 5, 6),
            ys=(2, 1, 5, 1, 1, 1),
            threshold=3,
            secret=1,
            accepted_xs=(2, 4, 5, 6),
            rejected_xs=(1, 3),
        )

    def test_beyond_radius_tie_still_raises(self):
        # constants 0 and 1 (and many lines) each fit exactly two shares
        xs, ys, threshold = (1, 2, 3, 4), (1, 1, 0, 0), 2
        with self.subTest(prime=self.PRIME, threshold=threshold, shares=list(zip(xs, ys))):
            self.assertGreater(2 * 2, len(xs) - threshold)
            self.assertEqual(decide(xs, ys, threshold, self.PRIME), ("error",))
            with self.assertRaises(ValueError):
                recover_secret(make_shares(xs, ys), threshold, prime=self.PRIME)


class ExactThresholdBoundaryTest(unittest.TestCase):
    """threshold == share count leaves a single candidate interpolant, so
    recovery always succeeds and accepts every share; per the README rule
    this is the same unique-best decision, not proof the shares are honest."""

    def test_tampered_share_with_no_redundancy_still_recovers(self):
        prime = 7
        # honest polynomial f(x) = 2 + 3x + 4x^2 over GF(7): f(1)=2, f(2)=3, f(3)=5
        xs = (1, 2, 3)
        ys = (2, 4, 5)  # x = 2 tampered from 3 to 4
        threshold = 3
        expected = decide(xs, ys, threshold, prime)
        self.assertEqual(expected, ("ok", 6, (1, 2, 3), ()))
        self.assertNotEqual(expected[1], 2)  # the tampering moved the secret
        with self.subTest(prime=prime, threshold=threshold, shares=list(zip(xs, ys))):
            report = recover_secret(make_shares(xs, ys), threshold, prime=prime)
            self.assertEqual(report, expected_report(dict(zip(xs, ys)), expected))


if __name__ == "__main__":
    unittest.main()
