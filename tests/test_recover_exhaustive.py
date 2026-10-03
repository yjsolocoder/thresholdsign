"""Exhaustive, independently-oracled regression tests for ``recover_secret``.

The decision contract (see README) is: among *all* polynomials of degree below
``threshold`` over ``GF(prime)``, recover the unique one that agrees with the
most supplied shares; a tie of distinct polynomials for that maximum, or a
maximum below ``threshold`` agreements, raises ``ValueError``.

These tests do not trust any production recovery or interpolation routine for
the expected answer. The oracle below enumerates every distinct polynomial
``a0 + a1*x + ... + a_(t-1)*x^(t-1)`` with coefficient vectors in
``GF(prime)^t`` and counts agreements directly with plain Horner evaluation.
That enumeration is the mathematical definition of the decision, not another
implementation path through the package: no result of ``recover_secret``,
``reconstruct_secret`` or any internal helper is used as an expectation.
"""

import unittest
from itertools import combinations, product

from thresholdsign import RecoveryReport, Share, recover_secret

GF5 = 5


def _evaluate_horner(coefficients, x, prime):
    """Independent Horner evaluation, written only for this test module."""
    value = 0
    for coefficient in reversed(coefficients):
        value = (value * x + coefficient) % prime
    return value


def _best_polynomials(coordinates, values, threshold, prime):
    """Return ``(best_count, winners)`` from exhaustive enumeration.

    ``winners`` is the list of every distinct degree-below-``threshold``
    polynomial (represented by its ascending coefficient tuple, including
    leading zero coefficients) attaining ``best_count`` agreements with the
    supplied points. Pure arithmetic over ``GF(prime)``; it never imports or
    calls the code under test.
    """
    best_count = -1
    winners = []
    for coefficients in product(range(prime), repeat=threshold):
        agreements = 0
        for x, y in zip(coordinates, values):
            if _evaluate_horner(coefficients, x, prime) == y:
                agreements += 1
        if agreements > best_count:
            best_count = agreements
            winners = [coefficients]
        elif agreements == best_count:
            winners.append(coefficients)
    return best_count, winners


def _case_label(coordinates, values, threshold, prime):
    points = ", ".join(f"({x},{y})" for x, y in zip(coordinates, values))
    return f"prime={prime} threshold={threshold} shares=[{points}]"


def _sorted_share_tuples(coordinates, values):
    return tuple(sorted((Share(x, y) for x, y in zip(coordinates, values)),
                        key=lambda share: share.x))


class ExhaustiveBestPolynomialTest(unittest.TestCase):
    # Every non-empty coordinate subset of {1,2,3,4}, every legal y-vector
    # (each y in 0..4), and every threshold 1..len(subset). 4,320 cases in
    # total. The enumeration of all 5^threshold polynomials by
    # _best_polynomials is the independent specification of each outcome.

    def test_all_cases_match_exhaustive_oracle(self):
        successes = 0
        ties = 0
        for subset_size in range(1, 5):
            for subset in combinations(range(1, 5), subset_size):
                for values in product(range(GF5), repeat=subset_size):
                    for threshold in range(1, subset_size + 1):
                        label = _case_label(subset, values, threshold, GF5)
                        shares = [
                            Share(x, y) for x, y in zip(subset, values)
                        ]
                        best_count, winners = _best_polynomials(
                            subset, values, threshold, GF5
                        )
                        # Any ``threshold`` of the supplied points interpolate
                        # to some degree-below-threshold polynomial, so the
                        # maximum is always at least the threshold; only a
                        # genuine tie is undecidable here.
                        self.assertGreaterEqual(best_count, threshold,
                                                msg=label)
                        if len(winners) > 1:
                            with self.assertRaises(ValueError, msg=label):
                                recover_secret(shares, threshold, prime=GF5)
                            ties += 1
                            continue

                        winner = winners[0]
                        report = recover_secret(shares, threshold, prime=GF5)
                        successes += 1

                        # The recovered secret is the winner's constant term.
                        self.assertEqual(
                            report.secret, winner[0], msg=label
                        )
                        # accepted/rejected partition every input share,
                        # each exactly once (compare as multisets).
                        expected_shares = _sorted_share_tuples(
                            subset, values
                        )
                        self.assertEqual(
                            tuple(
                                sorted(
                                    report.accepted + report.rejected,
                                    key=lambda share: share.x,
                                )
                            ),
                            expected_shares,
                            msg=label,
                        )
                        expected_accepted = tuple(
                            share
                            for share in expected_shares
                            if _evaluate_horner(
                                winner, share.x, GF5
                            ) == share.y
                        )
                        expected_rejected = tuple(
                            share
                            for share in expected_shares
                            if _evaluate_horner(
                                winner, share.x, GF5
                            ) != share.y
                        )
                        self.assertEqual(
                            report.accepted, expected_accepted, msg=label
                        )
                        self.assertEqual(
                            report.rejected, expected_rejected, msg=label
                        )
                        self.assertEqual(
                            len(report.accepted), best_count, msg=label
                        )
                        # Both groups are plain tuples.
                        self.assertIsInstance(report.accepted, tuple)
                        self.assertIsInstance(report.rejected, tuple)

        # Sanity totals from the independently enumerated specification:
        # prove the sweep exercised both branches. The figures are computed
        # by the oracle during this sweep, not imported from the code under
        # test.
        self.assertGreater(successes, 0)
        self.assertGreater(ties, 0)
        self.assertEqual(successes + ties, 4320)

    def test_special_polynomial_shapes_follow_the_same_rule(self):
        # Zero polynomial, below-threshold actual degree, and
        # share-count-equals-threshold must all be decided by the unique-best
        # rule alone.

        # Zero polynomial: shares all evaluate to 0.
        for subset_size in range(1, 5):
            subset = tuple(range(1, subset_size + 1))
            values = (0,) * subset_size
            for threshold in range(1, subset_size + 1):
                label = _case_label(subset, values, threshold, GF5)
                best_count, winners = _best_polynomials(
                    subset, values, threshold, GF5
                )
                # The zero polynomial is the unique maximiser for the full
                # zero vector (it fits all points), at every threshold.
                self.assertEqual(best_count, subset_size, msg=label)
                self.assertEqual(winners, [(0,) * threshold], msg=label)
                report = recover_secret(
                    [Share(x, 0) for x in subset], threshold, prime=GF5
                )
                self.assertEqual(report.secret, 0, msg=label)
                self.assertEqual(
                    [share.x for share in report.rejected], [], msg=label
                )

        # Actual degree strictly below the threshold (constant data fed to
        # threshold 2/3): the winner is the same constant polynomial padded
        # with zero high coefficients.
        for constant in range(GF5):
            values = (constant, constant, constant, constant)
            for threshold in (2, 3, 4):
                label = _case_label(
                    (1, 2, 3, 4), values, threshold, GF5
                )
                best_count, winners = _best_polynomials(
                    (1, 2, 3, 4), values, threshold, GF5
                )
                self.assertEqual(best_count, 4, msg=label)
                self.assertEqual(
                    winners, [(constant,) + (0,) * (threshold - 1)],
                    msg=label,
                )
                report = recover_secret(
                    [Share(x, constant) for x in (1, 2, 3, 4)],
                    threshold,
                    prime=GF5,
                )
                self.assertEqual(report.secret, constant, msg=label)
                self.assertEqual(len(report.accepted), 4, msg=label)

    def test_threshold_equal_to_share_count_is_not_an_integrity_proof(self):
        # With n == t there is exactly one degree-<t polynomial through the
        # points and it fits all of them: a tampered share silently joins the
        # interpolant. The unique-best rule recovers that interpolant with an
        # empty rejected group, never "detecting" corruption. Expected output
        # comes from enumerating the polynomials, not from interpolation.
        for n in (1, 2, 3, 4):
            subset = tuple(range(1, n + 1))
            for values in product(range(GF5), repeat=n):
                label = _case_label(subset, values, n, GF5)
                best_count, winners = _best_polynomials(
                    subset, values, n, GF5
                )
                self.assertEqual(best_count, n, msg=label)
                self.assertEqual(len(winners), 1, msg=label)
                report = recover_secret(
                    [Share(x, y) for x, y in zip(subset, values)],
                    n,
                    prime=GF5,
                )
                self.assertEqual(report.secret, winners[0][0], msg=label)
                self.assertEqual(
                    report.accepted,
                    _sorted_share_tuples(subset, values),
                    msg=label,
                )
                self.assertEqual(report.rejected, (), msg=label)

    def test_tie_with_shared_constant_term_still_raises(self):
        # Two distinct winning polynomials may carry the SAME constant term;
        # even so the decision is ambiguous and recovery must fail. The GF(5)
        # case below is certified by the exhaustive oracle: both lines
        # y = 0 and y = x are distinct winners (both constant term 0).
        coordinates = (1, 2, 3, 4)
        values = (0, 0, 3, 4)
        threshold = 2
        best_count, winners = _best_polynomials(
            coordinates, values, threshold, GF5
        )
        self.assertEqual(best_count, 2)
        self.assertIn((0, 0), winners)  # zero line
        self.assertIn((0, 1), winners)  # line y = x
        zero_constant_winners = {
            tuple(coefficients)
            for coefficients in winners
            if coefficients[0] == 0
        }
        self.assertIn((0, 0), zero_constant_winners)
        self.assertIn((0, 1), zero_constant_winners)
        self.assertGreaterEqual(len(zero_constant_winners), 2)
        with self.assertRaises(
            ValueError,
            msg=_case_label(coordinates, values, threshold, GF5),
        ):
            recover_secret(
                [Share(x, y) for x, y in zip(coordinates, values)],
                threshold,
                prime=GF5,
            )


GF7 = 7


class BeyondCorrectionRadiusTest(unittest.TestCase):
    # "Outside the radius" must not be conflated with "undecidable": the
    # README rule is global best-fit, and a unique best polynomial beyond the
    # usual 2e <= n - t bound is still recoverable. Each sample is certified
    # by independently enumerating all polynomials of degree < threshold.

    def test_unique_best_beyond_radius_dense_quadratic(self):
        # f(x) = 1 + x^2 over GF(7), shares at x = 1..6; shares at x = 1 and
        # x = 3 are corrupted. n = 6, t = 3: radius is floor((6-3)/2) = 1, so
        # two errors are beyond it, yet f is the unique best polynomial with
        # four agreements.
        coordinates = (1, 2, 3, 4, 5, 6)
        values = (3, 5, 0, 3, 5, 2)
        threshold = 3
        winner = (1, 0, 1)
        best_count, winners = _best_polynomials(
            coordinates, values, threshold, GF7
        )
        self.assertEqual(best_count, 4)
        self.assertEqual(winners, [winner])
        self.assertGreater(2 * (6 - best_count), 6 - threshold)

        report = recover_secret(
            [Share(x, y) for x, y in zip(coordinates, values)],
            threshold,
            prime=GF7,
        )
        self.assertEqual(report.secret, 1)
        self.assertEqual(
            [share.x for share in report.accepted], [2, 4, 5, 6]
        )
        self.assertEqual(
            [share.x for share in report.rejected], [1, 3]
        )

    def test_unique_best_beyond_radius_constant_polynomial(self):
        # f(x) = 6 constant (actual degree 0 < threshold 2); shares at
        # x = 1,2,3 corrupted. n = 6, t = 2: radius is 2, three errors are
        # beyond it, f still uniquely fits the last three shares.
        coordinates = (1, 2, 3, 4, 5, 6)
        values = (0, 3, 0, 6, 6, 6)
        threshold = 2
        winner = (6, 0)
        best_count, winners = _best_polynomials(
            coordinates, values, threshold, GF7
        )
        self.assertEqual(best_count, 3)
        self.assertEqual(winners, [winner])
        self.assertGreater(2 * (6 - best_count), 6 - threshold)

        report = recover_secret(
            [Share(x, y) for x, y in zip(coordinates, values)],
            threshold,
            prime=GF7,
        )
        self.assertEqual(report.secret, 6)
        self.assertEqual(
            [share.x for share in report.accepted], [4, 5, 6]
        )
        self.assertEqual(
            [share.x for share in report.rejected], [1, 2, 3]
        )

    def test_equal_constant_tie_beyond_radius_raises(self):
        # Over GF(7), points (1,0),(2,0),(3,1),(4,4) with threshold 2: the
        # oracle certifies the distinct lines y = 2x + 3 and y = 4x + 3 as
        # tied winners with the SAME constant term 3. n - t = 2, both fit only
        # 2 points, so this is also beyond the correction radius.
        coordinates = (1, 2, 3, 4)
        values = (0, 0, 1, 4)
        threshold = 2
        best_count, winners = _best_polynomials(
            coordinates, values, threshold, GF7
        )
        self.assertEqual(best_count, 2)
        self.assertIn((3, 2), winners)
        self.assertIn((3, 4), winners)
        self.assertGreater(2 * (4 - best_count), 4 - threshold)
        with self.assertRaises(
            ValueError,
            msg=_case_label(coordinates, values, threshold, GF7),
        ):
            recover_secret(
                [Share(x, y) for x, y in zip(coordinates, values)],
                threshold,
                prime=GF7,
            )


class OrderAndContainerEquivalenceTest(unittest.TestCase):
    # The decision depends only on share contents and threshold; reversing
    # order and switching between list and tuple containers must give the
    # same RecoveryReport. Certified against the exhaustive oracle on the
    # full GF(5) universe.

    def test_reversed_and_list_or_tuple_inputs_are_equivalent(self):
        for subset_size in range(1, 5):
            for subset in combinations(range(1, 5), subset_size):
                for values in product(range(GF5), repeat=subset_size):
                    for threshold in range(1, subset_size + 1):
                        label = _case_label(
                            subset, values, threshold, GF5
                        )
                        shares = [
                            Share(x, y)
                            for x, y in zip(subset, values)
                        ]
                        best_count, winners = _best_polynomials(
                            subset, values, threshold, GF5
                        )
                        self.assertGreaterEqual(
                            best_count, threshold, msg=label
                        )
                        undecidable = len(winners) > 1

                        variants = (
                            list(reversed(shares)),
                            tuple(reversed(shares)),
                            list(shares),
                            tuple(shares),
                        )
                        if undecidable:
                            for variant in variants:
                                with self.assertRaises(
                                    ValueError, msg=label
                                ):
                                    recover_secret(
                                        variant, threshold, prime=GF5
                                    )
                        else:
                            reports = [
                                recover_secret(
                                    variant, threshold, prime=GF5
                                )
                                for variant in variants
                            ]
                            for report in reports[1:]:
                                self.assertEqual(
                                    report, reports[0], msg=label
                                )
                            # Canonical expectation, independent of the
                            # implementation under test.
                            winner = winners[0]
                            expected = RecoveryReport(
                                winner[0],
                                tuple(
                                    share
                                    for share in sorted(
                                        shares, key=lambda s: s.x
                                    )
                                    if _evaluate_horner(
                                        winner, share.x, GF5
                                    ) == share.y
                                ),
                                tuple(
                                    share
                                    for share in sorted(
                                        shares, key=lambda s: s.x
                                    )
                                    if _evaluate_horner(
                                        winner, share.x, GF5
                                    ) != share.y
                                ),
                            )
                            self.assertEqual(
                                reports[0], expected, msg=label
                            )

    def test_call_does_not_mutate_input(self):
        for subset_size in range(1, 5):
            subset = tuple(range(1, subset_size + 1))
            for values in product(range(GF5), repeat=subset_size):
                for threshold in range(1, subset_size + 1):
                    label = _case_label(
                        subset, values, threshold, GF5
                    )
                    shares = [
                        Share(x, y)
                        for x, y in zip(subset, values)
                    ]
                    snapshot = tuple(shares)
                    try:
                        recover_secret(shares, threshold, prime=GF5)
                    except ValueError:
                        pass
                    # The list keeps its original contents and submission
                    # order; tuples are immutable by construction.
                    self.assertEqual(tuple(shares), snapshot, msg=label)
                    try:
                        recover_secret(snapshot, threshold, prime=GF5)
                    except ValueError:
                        pass


class ConstantShiftTest(unittest.TestCase):
    # Adding one field element c to every y changes a sharing polynomial f
    # into f + c: its constant term moves by c while every other coefficient
    # and the agreement pattern stay put, so accepted/rejected coordinates
    # must be unchanged. Ambiguity is invariant under this translation as
    # well: f + c is a bijection on the polynomial space. Certified by the
    # exhaustive oracle; shifts run over GF(5) and GF(7).

    def test_successes_shift_secret_but_keep_coordinates(self):
        # GF(5): every y-vector over coordinates 1..4 and every threshold,
        # restricted by the oracle to uniquely decidable base cases, shifted
        # by every field element.
        coordinates = (1, 2, 3, 4)
        for values in product(range(GF5), repeat=4):
            for threshold in range(1, 5):
                best_count, winners = _best_polynomials(
                    coordinates, values, threshold, GF5
                )
                if len(winners) > 1:
                    continue
                label = _case_label(coordinates, values, threshold, GF5)
                shares = [
                    Share(x, y) for x, y in zip(coordinates, values)
                ]
                report = recover_secret(shares, threshold, prime=GF5)
                for shift in range(GF5):
                    self._assert_shift(
                        coordinates, values, threshold, GF5,
                        shift, winners[0], best_count, report, label,
                    )

        # GF(7): deterministic certified cases — every constant vector at
        # thresholds 1 and 2, plus the two beyond-radius unique-best samples
        # checked in BeyondCorrectionRadiusTest — shifted by every field
        # element.
        gf7_cases = [
            ((1, 2, 3, 4), (constant,) * 4, threshold)
            for constant in range(GF7)
            for threshold in (1, 2)
        ]
        gf7_cases.extend([
            ((1, 2, 3, 4, 5, 6), (3, 5, 0, 3, 5, 2), 3),
            ((1, 2, 3, 4, 5, 6), (0, 3, 0, 6, 6, 6), 2),
        ])
        for coordinates, values, threshold in gf7_cases:
            best_count, winners = _best_polynomials(
                coordinates, values, threshold, GF7
            )
            label = _case_label(coordinates, values, threshold, GF7)
            self.assertEqual(len(winners), 1, msg=label)
            shares = [
                Share(x, y) for x, y in zip(coordinates, values)
            ]
            report = recover_secret(shares, threshold, prime=GF7)
            for shift in range(GF7):
                self._assert_shift(
                    coordinates, values, threshold, GF7,
                    shift, winners[0], best_count, report, label,
                )

    def _assert_shift(
        self, coordinates, values, threshold, prime,
        shift, winner, best_count, report, label,
    ):
        shifted = [
            Share(x, (y + shift) % prime)
            for x, y in zip(coordinates, values)
        ]
        shifted_values = tuple(share.y for share in shifted)
        shifted_best, shifted_winners = _best_polynomials(
            coordinates, shifted_values, threshold, prime
        )
        # Oracle confirms translation of the unique winner polynomial.
        expected_winner = (
            (winner[0] + shift) % prime,
            *winner[1:],
        )
        self.assertEqual(shifted_best, best_count, msg=label)
        self.assertEqual(shifted_winners, [expected_winner], msg=label)

        shifted_report = recover_secret(shifted, threshold, prime=prime)
        self.assertEqual(
            shifted_report.secret,
            (report.secret + shift) % prime,
            msg=label,
        )
        self.assertEqual(
            [share.x for share in shifted_report.accepted],
            [share.x for share in report.accepted],
            msg=label,
        )
        self.assertEqual(
            [share.x for share in shifted_report.rejected],
            [share.x for share in report.rejected],
            msg=label,
        )

    def test_ambiguities_remain_ambiguous_after_shift(self):
        ambiguous_cases = (
            (GF5, (1, 2, 3, 4), (0, 0, 3, 4), 2),
            (GF7, (1, 2, 3, 4), (0, 0, 1, 4), 2),
        )
        for prime, coordinates, values, threshold in ambiguous_cases:
            best_count, winners = _best_polynomials(
                coordinates, values, threshold, prime
            )
            self.assertGreater(len(winners), 1)
            for shift in range(prime):
                label = _case_label(
                    coordinates, values, threshold, prime
                ) + f" shift={shift}"
                shifted = [
                    Share(x, (y + shift) % prime)
                    for x, y in zip(coordinates, values)
                ]
                shifted_values = tuple(share.y for share in shifted)
                shifted_best, shifted_winners = _best_polynomials(
                    coordinates, shifted_values, threshold, prime
                )
                # The oracle still sees a genuine tie after translation.
                self.assertEqual(shifted_best, best_count, msg=label)
                self.assertGreater(
                    len(shifted_winners), 1, msg=label
                )
                with self.assertRaises(ValueError, msg=label):
                    recover_secret(shifted, threshold, prime=prime)


if __name__ == "__main__":
    unittest.main()
