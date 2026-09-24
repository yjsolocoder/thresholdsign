import dataclasses
import unittest
from itertools import combinations

from thresholdsign import (
    DEFAULT_PRIME,
    RecoveryReport,
    Share,
    recover_secret,
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


class RecoverSecretTest(unittest.TestCase):
    def setUp(self):
        self.shares = split_secret(SECRET, 3, 5, prime=PRIME, randbelow=fixed_random())

    def test_all_honest_shares_accepted(self):
        report = recover_secret(self.shares, 3, prime=PRIME)
        self.assertEqual(report.secret, SECRET)
        self.assertEqual(report.secret, reconstruct_secret(self.shares, prime=PRIME))
        self.assertEqual(report.accepted, tuple(sorted(self.shares, key=lambda s: s.x)))
        self.assertEqual(report.rejected, ())

    def test_tuple_input_accepted(self):
        report = recover_secret(tuple(self.shares), 3, prime=PRIME)
        self.assertEqual(report.secret, SECRET)
        self.assertEqual(len(report.accepted), 5)

    def test_single_tampered_share_is_rejected(self):
        tampered_share = self.shares[2]
        corrupted = Share(tampered_share.x, (tampered_share.y + 1) % PRIME)
        mixed = self.shares[:2] + [corrupted] + self.shares[3:]
        report = recover_secret(mixed, 3, prime=PRIME)
        self.assertEqual(report.secret, SECRET)
        self.assertEqual(report.rejected, (corrupted,))
        self.assertEqual(
            report.accepted,
            tuple(sorted(self.shares[:2] + self.shares[3:], key=lambda s: s.x)),
        )
        # The accepted shares alone rebuild the same secret.
        self.assertEqual(reconstruct_secret(report.accepted, prime=PRIME), report.secret)

    def test_tampered_share_with_threshold_plus_one_honest(self):
        # threshold+1 honest shares plus one corruption still decides
        # uniquely; with exactly threshold honest shares every corrupted
        # subset ties the honest polynomial and recovery must fail.
        honest = self.shares[:4]
        corrupted = Share(5, 424242)
        report = recover_secret(honest + [corrupted], 3, prime=PRIME)
        self.assertEqual(report.secret, SECRET)
        self.assertEqual(report.rejected, (corrupted,))
        self.assertEqual(len(report.accepted), 4)

    def test_too_few_honest_shares_is_a_tie(self):
        # threshold honest plus one corruption: no polynomial fits more
        # than threshold shares and several tie, so recovery is impossible.
        honest = self.shares[:3]
        corrupted = Share(4, 424242)
        with self.assertRaises(ValueError):
            recover_secret(honest + [corrupted], 3, prime=PRIME)

    def test_decision_is_order_independent(self):
        corrupted = Share(self.shares[0].x, self.shares[0].y ^ 0xDEADBEEF)
        mixed = [corrupted] + self.shares[1:]
        reference = recover_secret(mixed, 3, prime=PRIME)
        for permutation in (
            list(reversed(mixed)),
            [mixed[2], mixed[0], mixed[4], mixed[1], mixed[3]],
            tuple(mixed),
        ):
            self.assertEqual(recover_secret(permutation, 3, prime=PRIME), reference)

    def test_accepted_and_rejected_sorted_by_coordinate(self):
        corrupted = Share(self.shares[-1].x, self.shares[-1].y + 777)
        mixed = [corrupted] + list(reversed(self.shares[:-1]))
        report = recover_secret(mixed, 3, prime=PRIME)
        accepted_x = [share.x for share in report.accepted]
        rejected_x = [share.x for share in report.rejected]
        self.assertEqual(accepted_x, sorted(accepted_x))
        self.assertEqual(rejected_x, sorted(rejected_x))

    def test_tie_between_candidates_rejected(self):
        # Two shares on y = 2x + 1 and two on y = 3x + 2: distinct lines,
        # each fitting two shares, so no unique polynomial fits the most.
        shares = [Share(1, 3), Share(2, 5), Share(3, 11), Share(4, 14)]
        with self.assertRaises(ValueError):
            recover_secret(shares, 2, prime=2017)

    def test_threshold_one_constant_polynomial(self):
        shares = [Share(1, SECRET), Share(2, SECRET), Share(3, SECRET)]
        report = recover_secret(shares, 1, prime=PRIME)
        self.assertEqual(report.secret, SECRET)
        self.assertEqual(report.accepted, tuple(shares))
        self.assertEqual(report.rejected, ())

    def test_threshold_one_flags_lone_corruption(self):
        shares = [Share(1, SECRET), Share(2, SECRET), Share(3, SECRET - 1)]
        report = recover_secret(shares, 1, prime=PRIME)
        self.assertEqual(report.secret, SECRET)
        self.assertEqual(report.accepted, (Share(1, SECRET), Share(2, SECRET)))
        self.assertEqual(report.rejected, (Share(3, SECRET - 1),))

    def test_threshold_one_tie_rejected(self):
        with self.assertRaises(ValueError):
            recover_secret([Share(1, 5), Share(2, 6)], 1, prime=PRIME)

    def test_default_prime_usable(self):
        shares = split_secret(SECRET, 2, 4, randbelow=fixed_random())
        corrupted = Share(shares[3].x, shares[3].y + 1)
        report = recover_secret(shares[:3] + [corrupted], 2)
        self.assertEqual(report.secret, SECRET)
        self.assertEqual(report.rejected, (corrupted,))
        self.assertGreater(DEFAULT_PRIME, SECRET)


class RecoveryReportTest(unittest.TestCase):
    def test_positional_construction_and_value_equality(self):
        accepted = (Share(1, 2), Share(2, 4))
        first = RecoveryReport(7, accepted, (Share(3, 9),))
        second = RecoveryReport(7, (Share(1, 2), Share(2, 4)), (Share(3, 9),))
        self.assertEqual(first, second)
        self.assertEqual(first.secret, 7)
        self.assertEqual(first.accepted, accepted)

    def test_frozen(self):
        report = RecoveryReport(1, (), ())
        with self.assertRaises(dataclasses.FrozenInstanceError):
            report.secret = 2
        with self.assertRaises(dataclasses.FrozenInstanceError):
            report.accepted = (Share(1, 1),)

    def test_hashable_and_inequality(self):
        report = RecoveryReport(1, (Share(1, 1),), ())
        self.assertEqual(len({report, RecoveryReport(1, (Share(1, 1),), ())}), 1)
        self.assertNotEqual(report, RecoveryReport(2, (Share(1, 1),), ()))


class RecoverSecretValidationTest(unittest.TestCase):
    def setUp(self):
        self.shares = split_secret(SECRET, 3, 5, prime=PRIME, randbelow=fixed_random())

    def test_non_sequence_container_rejected(self):
        with self.assertRaises(TypeError):
            recover_secret(iter(self.shares), 3, prime=PRIME)
        with self.assertRaises(TypeError):
            recover_secret({self.shares[0]}, 1, prime=PRIME)
        with self.assertRaises(TypeError):
            recover_secret(123, 1, prime=PRIME)

    def test_non_share_element_rejected(self):
        with self.assertRaises(TypeError):
            recover_secret([(1, 2), (3, 4), (5, 6)], 3, prime=PRIME)

    def test_threshold_wrong_type_rejected(self):
        with self.assertRaises(TypeError):
            recover_secret(self.shares, 2.5, prime=PRIME)
        with self.assertRaises(TypeError):
            recover_secret(self.shares, True, prime=PRIME)

    def test_prime_wrong_type_rejected(self):
        with self.assertRaises(TypeError):
            recover_secret(self.shares, 3, prime=2.5)
        with self.assertRaises(TypeError):
            recover_secret(self.shares, 3, prime=True)

    def test_empty_shares_rejected(self):
        with self.assertRaises(ValueError):
            recover_secret([], 1, prime=PRIME)

    def test_duplicate_index_rejected(self):
        duplicated = [self.shares[0], Share(self.shares[0].x, 5), self.shares[1]]
        with self.assertRaises(ValueError):
            recover_secret(duplicated, 2, prime=PRIME)

    def test_index_out_of_range_rejected(self):
        with self.assertRaises(ValueError):
            recover_secret([Share(0, 5), Share(1, 6), Share(2, 7)], 2, prime=PRIME)
        with self.assertRaises(ValueError):
            recover_secret(
                [Share(PRIME, 5), Share(1, 6), Share(2, 7)], 2, prime=PRIME
            )

    def test_value_out_of_range_rejected_not_silently_dropped(self):
        shares = split_secret(SECRET, 2, 3, prime=PRIME, randbelow=fixed_random())
        # Two honest shares would suffice even with a third present, but an
        # out-of-range ordinate is an invalid input, not a rejected share.
        with self.assertRaises(ValueError):
            recover_secret([shares[0], shares[1], Share(4, PRIME)], 2, prime=PRIME)
        with self.assertRaises(ValueError):
            recover_secret([shares[0], shares[1], Share(4, -1)], 2, prime=PRIME)

    def test_threshold_below_one_rejected(self):
        with self.assertRaises(ValueError):
            recover_secret(self.shares, 0, prime=PRIME)

    def test_threshold_above_share_count_rejected(self):
        with self.assertRaises(ValueError):
            recover_secret(self.shares, 6, prime=PRIME)

    def test_non_prime_modulus_rejected(self):
        with self.assertRaises(ValueError):
            recover_secret([Share(1, 1), Share(2, 2)], 1, prime=4)


if __name__ == "__main__":
    unittest.main()
