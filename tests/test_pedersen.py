import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    PedersenCommitment,
    Share,
    reconstruct_secret,
    split_secret,
    split_secret_pedersen,
    verify_pedersen_share,
)

# Small safe setup: 8069 = 4 * 2017 + 1 is prime and both 16 and 256 = 16**2
# have order 2017 in the multiplicative group modulo 8069.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256
SECRET = 0x123


def fixed_random(seed=1):
    """Deterministic stand-in for secrets.randbelow so tests are reproducible."""
    state = {"value": seed}

    def randbelow(upper: int) -> int:
        state["value"] = (state["value"] * 6364136223846793005 + 1442695040888963407) % upper
        return state["value"]

    return randbelow


def make_shares(secret=SECRET, threshold=3, share_count=5, **kwargs):
    options = {
        "group_prime": GROUP_PRIME,
        "generator": GENERATOR,
        "blinding_generator": BLINDING_GENERATOR,
        "prime": FIELD_PRIME,
        "randbelow": fixed_random(),
    }
    options.update(kwargs)
    return split_secret_pedersen(secret, threshold, share_count, **options)


class SplitPedersenTest(unittest.TestCase):
    def test_returns_two_share_lists_and_commitment(self):
        shares, blinding_shares, commitment = make_shares()
        self.assertEqual(len(shares), 5)
        self.assertEqual(len(blinding_shares), 5)
        self.assertIsInstance(commitment, PedersenCommitment)
        self.assertEqual(len(commitment.values), 3)
        self.assertEqual(
            (
                commitment.field_prime,
                commitment.group_prime,
                commitment.generator,
                commitment.blinding_generator,
            ),
            (FIELD_PRIME, GROUP_PRIME, GENERATOR, BLINDING_GENERATOR),
        )

    def test_share_coordinates_match(self):
        shares, blinding_shares, _ = make_shares()
        self.assertEqual([s.x for s in shares], [b.x for b in blinding_shares])

    def test_every_share_verifies(self):
        shares, blinding_shares, commitment = make_shares()
        for share, blinding_share in zip(shares, blinding_shares):
            self.assertTrue(verify_pedersen_share(share, blinding_share, commitment))

    def test_shares_match_plain_split_under_same_rule(self):
        shares, _, _ = make_shares()
        plain = split_secret(SECRET, 3, 5, prime=FIELD_PRIME, randbelow=fixed_random())
        self.assertEqual(shares, plain)

    def test_shares_reconstruct_with_existing_api(self):
        shares, _, _ = make_shares()
        self.assertEqual(reconstruct_secret(shares[:3], prime=FIELD_PRIME), SECRET)

    def test_threshold_one(self):
        shares, blinding_shares, commitment = make_shares(threshold=1, share_count=3)
        self.assertEqual(len(commitment.values), 1)
        self.assertTrue(all(share.y == SECRET for share in shares))
        self.assertTrue(
            all(
                verify_pedersen_share(share, blinding_share, commitment)
                for share, blinding_share in zip(shares, blinding_shares)
            )
        )

    def test_zero_secret_round_trips(self):
        shares, blinding_shares, commitment = make_shares(secret=0, threshold=2, share_count=3)
        self.assertTrue(
            all(
                verify_pedersen_share(share, blinding_share, commitment)
                for share, blinding_share in zip(shares, blinding_shares)
            )
        )
        self.assertEqual(reconstruct_secret(shares[:2], prime=FIELD_PRIME), 0)

    def test_constant_term_commitment_hides_secret(self):
        # C_0 = g**secret * h**b_0 with a random b_0, so it is not a
        # deterministic function of the secret like Feldman's C_0.
        _, _, commitment = make_shares()
        self.assertNotEqual(commitment.values[0], pow(GENERATOR, SECRET, GROUP_PRIME))

    def test_commitment_is_frozen(self):
        _, _, commitment = make_shares()
        with self.assertRaises(FrozenInstanceError):
            commitment.values = ()  # type: ignore[misc]

    def test_commitment_does_not_store_coefficients(self):
        _, _, commitment = make_shares()
        self.assertEqual(
            {field.name for field in dataclasses.fields(commitment)},
            {"values", "field_prime", "group_prime", "generator", "blinding_generator"},
        )
        self.assertFalse(hasattr(commitment, "coefficients"))
        self.assertFalse(hasattr(commitment, "blinding_coefficients"))


class VerifyPedersenShareTest(unittest.TestCase):
    def setUp(self):
        self.shares, self.blinding_shares, self.commitment = make_shares()

    def test_tampered_share_returns_false(self):
        share = self.shares[0]
        tampered = Share(share.x, (share.y + 1) % FIELD_PRIME)
        self.assertFalse(
            verify_pedersen_share(tampered, self.blinding_shares[0], self.commitment)
        )

    def test_tampered_blinding_share_returns_false(self):
        blinding = self.blinding_shares[0]
        tampered = Share(blinding.x, (blinding.y + 1) % FIELD_PRIME)
        self.assertFalse(verify_pedersen_share(self.shares[0], tampered, self.commitment))

    def test_mismatched_coordinates_return_false(self):
        self.assertFalse(
            verify_pedersen_share(self.shares[0], self.blinding_shares[1], self.commitment)
        )

    def test_cross_combination_returns_false(self):
        # A different seed gives the other polynomial different blinding
        # coefficients, so shares, blinding shares and commitments are all
        # incompatible across the two splittings.
        other_shares, other_blinding, other_commitment = make_shares(
            secret=SECRET + 1, randbelow=fixed_random(seed=2)
        )
        self.assertFalse(
            verify_pedersen_share(self.shares[0], other_blinding[0], self.commitment)
        )
        self.assertFalse(
            verify_pedersen_share(self.shares[0], self.blinding_shares[0], other_commitment)
        )
        self.assertFalse(
            verify_pedersen_share(other_shares[0], other_blinding[0], self.commitment)
        )


class PedersenParameterValidationTest(unittest.TestCase):
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

    def test_generator_wrong_order_rejected(self):
        with self.assertRaises(ValueError):
            make_shares(generator=GROUP_PRIME - 1)  # element of order 2

    def test_blinding_generator_one_rejected(self):
        with self.assertRaises(ValueError):
            make_shares(blinding_generator=1)

    def test_blinding_generator_out_of_range_rejected(self):
        for bad in (0, -1, GROUP_PRIME):
            with self.assertRaises(ValueError):
                make_shares(blinding_generator=bad)

    def test_blinding_generator_wrong_order_rejected(self):
        with self.assertRaises(ValueError):
            make_shares(blinding_generator=GROUP_PRIME - 1)  # element of order 2

    def test_identical_generators_rejected(self):
        with self.assertRaises(ValueError):
            make_shares(blinding_generator=GENERATOR)

    def test_non_integer_parameters_raise_type_error(self):
        with self.assertRaises(TypeError):
            make_shares(prime=2017.0)
        with self.assertRaises(TypeError):
            make_shares(group_prime=8069.0)
        with self.assertRaises(TypeError):
            make_shares(generator="16")
        with self.assertRaises(TypeError):
            make_shares(blinding_generator="256")

    def test_plain_split_validation_still_applies(self):
        with self.assertRaises(ValueError):
            make_shares(threshold=0, share_count=3)
        with self.assertRaises(ValueError):
            make_shares(threshold=4, share_count=3)
        with self.assertRaises(TypeError):
            make_shares(threshold=2.5, share_count=3)


class VerifyPedersenShareValidationTest(unittest.TestCase):
    def setUp(self):
        self.shares, self.blinding_shares, self.commitment = make_shares()
        self.good_share = self.shares[0]
        self.good_blinding = self.blinding_shares[0]

    def make_commitment(self, **overrides):
        options = {
            "values": self.commitment.values,
            "field_prime": FIELD_PRIME,
            "group_prime": GROUP_PRIME,
            "generator": GENERATOR,
            "blinding_generator": BLINDING_GENERATOR,
        }
        options.update(overrides)
        return PedersenCommitment(**options)

    def test_share_wrong_type(self):
        with self.assertRaises(TypeError):
            verify_pedersen_share((1, 2), self.good_blinding, self.commitment)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            verify_pedersen_share(self.good_share, (1, 2), self.commitment)  # type: ignore[arg-type]

    def test_commitment_wrong_type(self):
        with self.assertRaises(TypeError):
            verify_pedersen_share(self.good_share, self.good_blinding, (1, 2))  # type: ignore[arg-type]

    def test_empty_commitment_rejected(self):
        with self.assertRaises(ValueError):
            verify_pedersen_share(
                self.good_share, self.good_blinding, self.make_commitment(values=())
            )

    def test_values_wrong_container_type(self):
        bad = self.make_commitment(values=list(self.commitment.values))  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            verify_pedersen_share(self.good_share, self.good_blinding, bad)

    def test_non_integer_commitment_value_rejected(self):
        values = (self.commitment.values[0], "1")
        bad = self.make_commitment(values=values)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            verify_pedersen_share(self.good_share, self.good_blinding, bad)

    def test_non_integer_share_fields_rejected(self):
        with self.assertRaises(TypeError):
            verify_pedersen_share(Share("1", 2), self.good_blinding, self.commitment)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            verify_pedersen_share(self.good_share, Share(1, 2.0), self.commitment)  # type: ignore[arg-type]

    def test_commitment_value_out_of_range_rejected(self):
        values = self.commitment.values
        for bad_value in (0, GROUP_PRIME):
            bad = self.make_commitment(values=(bad_value,) + values[1:])
            with self.assertRaises(ValueError):
                verify_pedersen_share(self.good_share, self.good_blinding, bad)

    def test_commitment_value_outside_subgroup_rejected(self):
        values = (GROUP_PRIME - 1,) + self.commitment.values[1:]
        bad = self.make_commitment(values=values)
        with self.assertRaises(ValueError):
            verify_pedersen_share(self.good_share, self.good_blinding, bad)

    def test_non_prime_commitment_moduli_rejected(self):
        with self.assertRaises(ValueError):
            verify_pedersen_share(
                self.good_share, self.good_blinding, self.make_commitment(field_prime=2021)
            )
        with self.assertRaises(ValueError):
            verify_pedersen_share(
                self.good_share, self.good_blinding, self.make_commitment(group_prime=8067)
            )

    def test_non_dividing_commitment_moduli_rejected(self):
        with self.assertRaises(ValueError):
            verify_pedersen_share(
                self.good_share, self.good_blinding, self.make_commitment(field_prime=2011)
            )

    def test_illegal_commitment_generators_rejected(self):
        for generator in (1, GROUP_PRIME - 1):
            with self.assertRaises(ValueError):
                verify_pedersen_share(
                    self.good_share, self.good_blinding, self.make_commitment(generator=generator)
                )
            with self.assertRaises(ValueError):
                verify_pedersen_share(
                    self.good_share,
                    self.good_blinding,
                    self.make_commitment(blinding_generator=generator),
                )

    def test_identical_commitment_generators_rejected(self):
        bad = self.make_commitment(blinding_generator=GENERATOR)
        with self.assertRaises(ValueError):
            verify_pedersen_share(self.good_share, self.good_blinding, bad)

    def test_coordinate_out_of_bounds_rejected(self):
        for x in (0, -1, FIELD_PRIME):
            with self.assertRaises(ValueError):
                verify_pedersen_share(
                    Share(x, self.good_share.y), self.good_blinding, self.commitment
                )
            with self.assertRaises(ValueError):
                verify_pedersen_share(
                    self.good_share, Share(x, self.good_blinding.y), self.commitment
                )

    def test_value_out_of_bounds_rejected(self):
        for y in (-1, FIELD_PRIME):
            with self.assertRaises(ValueError):
                verify_pedersen_share(
                    Share(self.good_share.x, y), self.good_blinding, self.commitment
                )
            with self.assertRaises(ValueError):
                verify_pedersen_share(
                    self.good_share, Share(self.good_blinding.x, y), self.commitment
                )

    def test_legal_mismatch_is_false_not_error(self):
        mismatch = Share(self.good_share.x, (self.good_share.y + 1) % FIELD_PRIME)
        self.assertIs(
            verify_pedersen_share(mismatch, self.good_blinding, self.commitment), False
        )


if __name__ == "__main__":
    unittest.main()
