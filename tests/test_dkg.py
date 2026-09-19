import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    DKGContribution,
    DKGReceivedShare,
    DKGRejection,
    DKGResult,
    PedersenCommitment,
    Share,
    aggregate_dkg,
    create_dkg_contribution,
    reconstruct_secret,
    verify_dkg_received_share,
    verify_pedersen_share,
)

# Same toy Pedersen setup as the Pedersen tests: 8069 = 4 * 2017 + 1 is
# prime, 16 and 256 = 16 ** 2 are distinct generators of the order-2017
# subgroup of the multiplicative group modulo 8069.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256


def fixed_random(seed=1):
    """Deterministic stand-in for secrets.randbelow so tests are reproducible."""
    state = {"value": seed}

    def randbelow(upper: int) -> int:
        state["value"] = (state["value"] * 6364136223846793005 + 1442695040888963407) % upper
        return state["value"]

    return randbelow


def make_contribution(sender_id, participant_ids=(1, 2, 3), threshold=2, **kwargs):
    options = {
        "group_prime": GROUP_PRIME,
        "generator": GENERATOR,
        "blinding_generator": BLINDING_GENERATOR,
        "prime": FIELD_PRIME,
        "randbelow": fixed_random(sender_id),
    }
    options.update(kwargs)
    return create_dkg_contribution(sender_id, participant_ids, threshold, **options)


def make_contributions(participant_ids=(1, 2, 3), threshold=2):
    return [make_contribution(pid, participant_ids, threshold) for pid in participant_ids]


def received_from(contribution, receiver_id):
    """The DKGReceivedShare ``receiver_id`` extracts from ``contribution``."""
    index = contribution.participant_ids.index(receiver_id)
    return DKGReceivedShare(
        sender_id=contribution.sender_id,
        receiver_id=receiver_id,
        share=contribution.shares[index],
        blinding_share=contribution.blinding_shares[index],
    )


def joint_secret(contributions, threshold, prime=FIELD_PRIME):
    """The joint secret a successful aggregation commits to (test oracle)."""
    return sum(
        reconstruct_secret(c.shares[:threshold], prime=prime) for c in contributions
    ) % prime


class CreateContributionTest(unittest.TestCase):
    def test_returns_contribution_with_aligned_fields(self):
        contribution = make_contribution(2, (1, 2, 3), 2)
        self.assertIsInstance(contribution, DKGContribution)
        self.assertEqual(contribution.sender_id, 2)
        self.assertEqual(contribution.participant_ids, (1, 2, 3))
        self.assertEqual(len(contribution.shares), 3)
        self.assertEqual(len(contribution.blinding_shares), 3)
        self.assertEqual(
            [share.x for share in contribution.shares], [1, 2, 3]
        )
        self.assertEqual(
            [share.x for share in contribution.blinding_shares], [1, 2, 3]
        )
        self.assertIsInstance(contribution.commitment, PedersenCommitment)
        self.assertEqual(len(contribution.commitment.values), 2)
        self.assertEqual(
            (
                contribution.commitment.field_prime,
                contribution.commitment.group_prime,
                contribution.commitment.generator,
                contribution.commitment.blinding_generator,
            ),
            (FIELD_PRIME, GROUP_PRIME, GENERATOR, BLINDING_GENERATOR),
        )

    def test_participant_ids_stored_strictly_increasing(self):
        contribution = make_contribution(3, (3, 1, 2), 2)
        self.assertEqual(contribution.participant_ids, (1, 2, 3))

    def test_non_sequential_participant_ids(self):
        contribution = make_contribution(5, (2, 5, 7), 2)
        self.assertEqual(contribution.participant_ids, (2, 5, 7))
        for receiver_id in (2, 5, 7):
            self.assertTrue(
                verify_dkg_received_share(
                    received_from(contribution, receiver_id), contribution.commitment
                )
            )

    def test_every_received_share_verifies(self):
        contribution = make_contribution(1, (1, 2, 3), 2)
        for receiver_id in (1, 2, 3):
            self.assertTrue(
                verify_dkg_received_share(
                    received_from(contribution, receiver_id), contribution.commitment
                )
            )

    def test_deterministic_zero_contribution_is_allowed(self):
        contribution = make_contribution(1, (1, 2, 3), 2, randbelow=lambda upper: 0)
        self.assertTrue(all(share.y == 0 for share in contribution.shares))
        self.assertTrue(all(share.y == 0 for share in contribution.blinding_shares))
        self.assertEqual(contribution.commitment.values, (1, 1))
        for receiver_id in (1, 2, 3):
            self.assertTrue(
                verify_dkg_received_share(
                    received_from(contribution, receiver_id), contribution.commitment
                )
            )

    def test_threshold_one(self):
        contribution = make_contribution(1, (1, 2), 1)
        self.assertEqual(len(contribution.commitment.values), 1)
        for receiver_id in (1, 2):
            self.assertTrue(
                verify_dkg_received_share(
                    received_from(contribution, receiver_id), contribution.commitment
                )
            )

    def test_two_to_five_participants(self):
        for count in range(2, 6):
            ids = tuple(range(1, count + 1))
            contribution = make_contribution(count, ids, min(2, count))
            self.assertEqual(contribution.participant_ids, ids)
            self.assertEqual(len(contribution.shares), count)

    def test_contribution_is_frozen(self):
        contribution = make_contribution(1)
        with self.assertRaises(FrozenInstanceError):
            contribution.sender_id = 2  # type: ignore[misc]

    def test_contribution_does_not_store_coefficients(self):
        contribution = make_contribution(1)
        self.assertEqual(
            {field.name for field in dataclasses.fields(contribution)},
            {"sender_id", "participant_ids", "shares", "blinding_shares", "commitment"},
        )
        self.assertFalse(hasattr(contribution, "coefficients"))
        self.assertFalse(hasattr(contribution, "secret"))


class CreateContributionValidationTest(unittest.TestCase):
    def test_participant_id_out_of_range_rejected(self):
        for bad in (0, -1, FIELD_PRIME, FIELD_PRIME + 1):
            with self.assertRaises(ValueError):
                make_contribution(1, (1, 2, bad))

    def test_duplicate_participant_ids_rejected(self):
        with self.assertRaises(ValueError):
            make_contribution(1, (1, 2, 2))

    def test_empty_participant_ids_rejected(self):
        with self.assertRaises(ValueError):
            make_contribution(1, ())

    def test_sender_must_be_a_participant(self):
        with self.assertRaises(ValueError):
            make_contribution(4, (1, 2, 3))

    def test_threshold_bounds(self):
        with self.assertRaises(ValueError):
            make_contribution(1, (1, 2, 3), 0)
        with self.assertRaises(ValueError):
            make_contribution(1, (1, 2, 3), 4)

    def test_non_integer_arguments_raise_type_error(self):
        with self.assertRaises(TypeError):
            make_contribution("1")
        with self.assertRaises(TypeError):
            make_contribution(1, (1, 2, 3), 2.0)
        with self.assertRaises(TypeError):
            make_contribution(1, (1, "2", 3))

    def test_group_parameters_still_validated(self):
        with self.assertRaises(ValueError):
            make_contribution(1, (1, 2, 3), 2, generator=1)
        with self.assertRaises(ValueError):
            make_contribution(1, (1, 2, 3), 2, blinding_generator=GENERATOR)
        with self.assertRaises(ValueError):
            make_contribution(1, (1, 2, 3), 2, prime=2021)
        with self.assertRaises(TypeError):
            make_contribution(1, (1, 2, 3), 2, generator="16")


class VerifyReceivedShareTest(unittest.TestCase):
    def setUp(self):
        self.contributions = make_contributions()
        self.contribution = self.contributions[0]

    def test_match_returns_true(self):
        received = received_from(self.contribution, 2)
        self.assertIs(
            verify_dkg_received_share(received, self.contribution.commitment), True
        )

    def test_tampered_share_returns_false(self):
        received = received_from(self.contribution, 2)
        tampered = dataclasses.replace(
            received, share=Share(received.share.x, (received.share.y + 1) % FIELD_PRIME)
        )
        self.assertFalse(
            verify_dkg_received_share(tampered, self.contribution.commitment)
        )

    def test_tampered_blinding_share_returns_false(self):
        received = received_from(self.contribution, 2)
        tampered = dataclasses.replace(
            received,
            blinding_share=Share(
                received.blinding_share.x, (received.blinding_share.y + 1) % FIELD_PRIME
            ),
        )
        self.assertFalse(
            verify_dkg_received_share(tampered, self.contribution.commitment)
        )

    def test_receiver_coordinate_mismatch_returns_false(self):
        # The double share addressed to participant 1 handed to participant 2.
        received = received_from(self.contribution, 1)
        misdelivered = dataclasses.replace(received, receiver_id=2)
        self.assertFalse(
            verify_dkg_received_share(misdelivered, self.contribution.commitment)
        )

    def test_share_coordinate_mismatch_returns_false(self):
        received = received_from(self.contribution, 2)
        mismatched = dataclasses.replace(
            received, blinding_share=self.contribution.blinding_shares[0]
        )
        self.assertFalse(
            verify_dkg_received_share(mismatched, self.contribution.commitment)
        )

    def test_commitment_from_other_sender_returns_false(self):
        received = received_from(self.contribution, 2)
        other = self.contributions[1]
        self.assertFalse(verify_dkg_received_share(received, other.commitment))

    def test_wrong_types_raise_type_error(self):
        received = received_from(self.contribution, 2)
        with self.assertRaises(TypeError):
            verify_dkg_received_share((1, 2), self.contribution.commitment)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            verify_dkg_received_share(received, "commitment")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            verify_dkg_received_share(
                dataclasses.replace(received, sender_id="1"), self.contribution.commitment
            )
        with self.assertRaises(TypeError):
            verify_dkg_received_share(
                dataclasses.replace(received, share=(2, 3)), self.contribution.commitment
            )

    def test_illegal_ids_raise_value_error(self):
        received = received_from(self.contribution, 2)
        for bad in (0, -1, FIELD_PRIME):
            with self.assertRaises(ValueError):
                verify_dkg_received_share(
                    dataclasses.replace(received, sender_id=bad),
                    self.contribution.commitment,
                )
            with self.assertRaises(ValueError):
                verify_dkg_received_share(
                    dataclasses.replace(received, receiver_id=bad),
                    self.contribution.commitment,
                )

    def test_illegal_share_coordinates_raise_value_error(self):
        received = received_from(self.contribution, 2)
        illegal = dataclasses.replace(
            received,
            share=Share(0, received.share.y),
            blinding_share=Share(0, received.blinding_share.y),
        )
        with self.assertRaises(ValueError):
            verify_dkg_received_share(illegal, self.contribution.commitment)


class AggregateDkgTest(unittest.TestCase):
    def test_success_returns_joint_result(self):
        contributions = make_contributions()
        result = aggregate_dkg(contributions)
        self.assertIsInstance(result, DKGResult)
        self.assertEqual(result.participant_ids, (1, 2, 3))
        self.assertEqual([share.x for share in result.shares], [1, 2, 3])
        self.assertEqual([share.x for share in result.blinding_shares], [1, 2, 3])
        self.assertEqual(len(result.commitment.values), 2)

    def test_aggregated_shares_verify_against_joint_commitment(self):
        result = aggregate_dkg(make_contributions())
        for share, blinding_share in zip(result.shares, result.blinding_shares):
            self.assertTrue(
                verify_pedersen_share(share, blinding_share, result.commitment)
            )

    def test_enough_receivers_reconstruct_joint_secret(self):
        contributions = make_contributions()
        result = aggregate_dkg(contributions)
        expected = joint_secret(contributions, 2)
        # Any two of the three receivers suffice.
        for positions in ((0, 1), (0, 2), (1, 2)):
            picked = [result.shares[i] for i in positions]
            self.assertEqual(
                reconstruct_secret(picked, prime=FIELD_PRIME), expected
            )

    def test_input_order_does_not_affect_result(self):
        contributions = make_contributions()
        shuffled = [contributions[2], contributions[0], contributions[1]]
        self.assertEqual(aggregate_dkg(contributions), aggregate_dkg(shuffled))
        self.assertEqual(
            aggregate_dkg(contributions), aggregate_dkg(list(reversed(contributions)))
        )

    def test_two_to_five_participants(self):
        for count in range(2, 6):
            ids = tuple(range(1, count + 1))
            contributions = make_contributions(ids, threshold=2)
            result = aggregate_dkg(contributions)
            self.assertIsInstance(result, DKGResult)
            self.assertEqual(result.participant_ids, ids)
            expected = joint_secret(contributions, 2)
            self.assertEqual(
                reconstruct_secret(result.shares[:2], prime=FIELD_PRIME), expected
            )

    def test_threshold_one(self):
        contributions = make_contributions((1, 2), threshold=1)
        result = aggregate_dkg(contributions)
        self.assertIsInstance(result, DKGResult)
        self.assertEqual(len(result.commitment.values), 1)
        expected = joint_secret(contributions, 1)
        for share in result.shares:
            self.assertEqual(
                reconstruct_secret([share], prime=FIELD_PRIME), expected
            )

    def test_all_zero_contributions_yield_zero_secret(self):
        contributions = [
            make_contribution(pid, (1, 2, 3), 2, randbelow=lambda upper: 0)
            for pid in (1, 2, 3)
        ]
        result = aggregate_dkg(contributions)
        self.assertIsInstance(result, DKGResult)
        self.assertEqual(result.commitment.values, (1, 1))
        self.assertEqual(reconstruct_secret(result.shares[:2], prime=FIELD_PRIME), 0)

    def test_result_does_not_store_secret_or_coefficients(self):
        result = aggregate_dkg(make_contributions())
        self.assertEqual(
            {field.name for field in dataclasses.fields(result)},
            {"participant_ids", "shares", "blinding_shares", "commitment"},
        )
        self.assertFalse(hasattr(result, "secret"))
        self.assertFalse(hasattr(result, "coefficients"))

    def test_result_is_frozen(self):
        result = aggregate_dkg(make_contributions())
        with self.assertRaises(FrozenInstanceError):
            result.shares = ()  # type: ignore[misc]


class AggregateDkgRejectionTest(unittest.TestCase):
    def setUp(self):
        self.contributions = make_contributions()

    def test_tampered_share_yields_rejection_naming_sender(self):
        bad = self.contributions[1]
        tampered = dataclasses.replace(
            bad,
            shares=(Share(bad.shares[0].x, (bad.shares[0].y + 1) % FIELD_PRIME),)
            + bad.shares[1:],
        )
        outcome = aggregate_dkg([self.contributions[0], tampered, self.contributions[2]])
        self.assertIsInstance(outcome, list)
        self.assertEqual(outcome, [DKGRejection(sender_id=2)])

    def test_every_failing_sender_is_reported(self):
        tampered = []
        for contribution in (self.contributions[0], self.contributions[2]):
            tampered.append(
                dataclasses.replace(
                    contribution,
                    shares=(
                        Share(
                            contribution.shares[0].x,
                            (contribution.shares[0].y + 1) % FIELD_PRIME,
                        ),
                    )
                    + contribution.shares[1:],
                )
            )
        outcome = aggregate_dkg([tampered[0], self.contributions[1], tampered[1]])
        self.assertEqual(
            outcome, [DKGRejection(sender_id=1), DKGRejection(sender_id=3)]
        )

    def test_misaddressed_share_yields_rejection(self):
        bad = self.contributions[0]
        moved = dataclasses.replace(
            bad, shares=(Share(2, bad.shares[0].y),) + bad.shares[1:]
        )
        outcome = aggregate_dkg([moved, self.contributions[1], self.contributions[2]])
        self.assertEqual(outcome, [DKGRejection(sender_id=1)])

    def test_rejection_order_does_not_depend_on_input_order(self):
        bad = self.contributions[1]
        tampered = dataclasses.replace(
            bad,
            shares=(Share(bad.shares[0].x, (bad.shares[0].y + 1) % FIELD_PRIME),)
            + bad.shares[1:],
        )
        self.assertEqual(
            aggregate_dkg([tampered, self.contributions[2], self.contributions[0]]),
            [DKGRejection(sender_id=2)],
        )

    def test_rejection_is_frozen(self):
        rejection = DKGRejection(sender_id=1)
        with self.assertRaises(FrozenInstanceError):
            rejection.sender_id = 2  # type: ignore[misc]


class AggregateDkgValidationTest(unittest.TestCase):
    def setUp(self):
        self.contributions = make_contributions()

    def test_missing_participant_rejected(self):
        with self.assertRaises(ValueError):
            aggregate_dkg(self.contributions[:2])

    def test_duplicate_participant_rejected(self):
        with self.assertRaises(ValueError):
            aggregate_dkg(
                [self.contributions[0], self.contributions[0], self.contributions[2]]
            )

    def test_empty_input_rejected(self):
        with self.assertRaises(ValueError):
            aggregate_dkg([])

    def test_inconsistent_participant_ids_rejected(self):
        other = make_contribution(4, (1, 2, 4), 2)
        with self.assertRaises(ValueError):
            aggregate_dkg([self.contributions[0], self.contributions[1], other])

    def test_inconsistent_threshold_rejected(self):
        other = make_contribution(3, (1, 2, 3), 3)
        with self.assertRaises(ValueError):
            aggregate_dkg([self.contributions[0], self.contributions[1], other])

    def test_inconsistent_group_parameters_rejected(self):
        other = make_contribution(
            3, (1, 2, 3), 2, generator=BLINDING_GENERATOR, blinding_generator=GENERATOR
        )
        with self.assertRaises(ValueError):
            aggregate_dkg([self.contributions[0], self.contributions[1], other])

    def test_sender_outside_participants_rejected(self):
        bad = dataclasses.replace(self.contributions[0], sender_id=4)
        with self.assertRaises(ValueError):
            aggregate_dkg([bad, self.contributions[1], self.contributions[2]])

    def test_unsorted_participant_ids_rejected(self):
        bad = dataclasses.replace(self.contributions[0], participant_ids=(2, 1, 3))
        with self.assertRaises(ValueError):
            aggregate_dkg([bad, self.contributions[1], self.contributions[2]])

    def test_illegal_commitment_rejected(self):
        bad_commitment = dataclasses.replace(
            self.contributions[0].commitment, values=(0, 1)
        )
        bad = dataclasses.replace(self.contributions[0], commitment=bad_commitment)
        with self.assertRaises(ValueError):
            aggregate_dkg([bad, self.contributions[1], self.contributions[2]])

    def test_illegal_share_coordinate_rejected(self):
        bad = dataclasses.replace(
            self.contributions[0],
            shares=(Share(0, self.contributions[0].shares[0].y),)
            + self.contributions[0].shares[1:],
        )
        with self.assertRaises(ValueError):
            aggregate_dkg([bad, self.contributions[1], self.contributions[2]])

    def test_wrong_types_raise_type_error(self):
        with self.assertRaises(TypeError):
            aggregate_dkg(["not a contribution"])
        with self.assertRaises(TypeError):
            aggregate_dkg([self.contributions[0], 2, self.contributions[2]])
        bad = dataclasses.replace(
            self.contributions[0], shares=list(self.contributions[0].shares)
        )
        with self.assertRaises(TypeError):
            aggregate_dkg([bad, self.contributions[1], self.contributions[2]])
        bad_ids = dataclasses.replace(
            self.contributions[0], participant_ids=list((1, 2, 3))
        )
        with self.assertRaises(TypeError):
            aggregate_dkg([bad_ids, self.contributions[1], self.contributions[2]])


if __name__ == "__main__":
    unittest.main()
