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

# Same toy Pedersen setup as the Pedersen VSS tests: 8069 = 4 * 2017 + 1 is
# prime, 16 and 256 = 16 ** 2 are distinct generators of the order-2017
# subgroup, and 4096 = 16 ** 3 is a third one for parameter-mismatch tests.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256
THIRD_GENERATOR = 4096


def fixed_random(seed=1):
    """Deterministic stand-in for secrets.randbelow so tests are reproducible."""
    state = {"value": seed}

    def randbelow(upper: int) -> int:
        state["value"] = (state["value"] * 6364136223846793005 + 1442695040888963407) % upper
        return state["value"]

    return randbelow


def make_contribution(sender_id=1, participant_ids=(1, 2, 3), threshold=2, **kwargs):
    options = {
        "group_prime": GROUP_PRIME,
        "generator": GENERATOR,
        "blinding_generator": BLINDING_GENERATOR,
        "prime": FIELD_PRIME,
        "randbelow": fixed_random(sender_id),
    }
    options.update(kwargs)
    return create_dkg_contribution(sender_id, participant_ids, threshold, **options)


def make_contributions(count=3, threshold=2, **kwargs):
    ids = tuple(range(1, count + 1))
    return [make_contribution(sender, ids, threshold, **kwargs) for sender in ids]


def tampered_contribution(contribution, index=0):
    """A copy of ``contribution`` with one share value legally altered."""
    shares = list(contribution.shares)
    received = shares[index]
    bad_share = Share(received.share.x, (received.share.y + 1) % FIELD_PRIME)
    shares[index] = DKGReceivedShare(
        received.sender_id, received.receiver_id, bad_share, received.blinding_share
    )
    return DKGContribution(
        contribution.sender_id,
        contribution.participant_ids,
        tuple(shares),
        contribution.commitment,
    )


def contribution_secret(contribution, threshold):
    shares = [received.share for received in contribution.shares[:threshold]]
    return reconstruct_secret(shares, prime=FIELD_PRIME)


class CreateDKGContributionTest(unittest.TestCase):
    def test_contribution_structure(self):
        contribution = make_contribution(sender_id=2, participant_ids=(1, 2, 3), threshold=2)
        self.assertEqual(contribution.sender_id, 2)
        self.assertEqual(contribution.participant_ids, (1, 2, 3))
        self.assertEqual(len(contribution.shares), 3)
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
        for received, receiver_id in zip(contribution.shares, (1, 2, 3)):
            self.assertIsInstance(received, DKGReceivedShare)
            self.assertEqual(received.sender_id, 2)
            self.assertEqual(received.receiver_id, receiver_id)
            self.assertEqual(received.share.x, receiver_id)
            self.assertEqual(received.blinding_share.x, receiver_id)

    def test_every_received_share_verifies(self):
        contribution = make_contribution()
        for received in contribution.shares:
            self.assertTrue(verify_dkg_received_share(received, contribution))

    def test_unsorted_ids_are_stored_strictly_increasing(self):
        contribution = make_contribution(participant_ids=(3, 1, 2))
        self.assertEqual(contribution.participant_ids, (1, 2, 3))
        self.assertEqual(
            [received.receiver_id for received in contribution.shares], [1, 2, 3]
        )

    def test_set_of_ids_accepted(self):
        contribution = make_contribution(participant_ids={1, 2, 3, 4, 5})
        self.assertEqual(contribution.participant_ids, (1, 2, 3, 4, 5))

    def test_zero_contribution_allowed(self):
        # A deterministic random source may draw nothing but zeros: the
        # secret contribution is then zero and every commitment value is the
        # identity, which is still a legal, verifiable contribution.
        contribution = make_contribution(randbelow=lambda upper: 0)
        self.assertTrue(all(received.share.y == 0 for received in contribution.shares))
        self.assertTrue(all(received.blinding_share.y == 0 for received in contribution.shares))
        self.assertEqual(contribution.commitment.values, (1, 1))
        for received in contribution.shares:
            self.assertTrue(verify_dkg_received_share(received, contribution))

    def test_threshold_one(self):
        contribution = make_contribution(threshold=1)
        self.assertEqual(len(contribution.commitment.values), 1)
        for received in contribution.shares:
            self.assertTrue(verify_dkg_received_share(received, contribution))

    def test_contribution_is_frozen(self):
        contribution = make_contribution()
        with self.assertRaises(FrozenInstanceError):
            contribution.shares = ()  # type: ignore[misc]

    def test_contribution_stores_no_coefficients(self):
        contribution = make_contribution()
        self.assertEqual(
            {field.name for field in dataclasses.fields(contribution)},
            {"sender_id", "participant_ids", "shares", "commitment"},
        )
        self.assertFalse(hasattr(contribution, "coefficients"))
        self.assertFalse(hasattr(contribution, "secret"))

    def test_duplicate_ids_rejected(self):
        with self.assertRaises(ValueError):
            make_contribution(participant_ids=(1, 2, 2))

    def test_id_out_of_range_rejected(self):
        for bad in (0, -1, FIELD_PRIME):
            with self.assertRaises(ValueError):
                make_contribution(participant_ids=(1, 2, bad))

    def test_sender_id_out_of_range_rejected(self):
        for bad in (0, -1, FIELD_PRIME):
            with self.assertRaises(ValueError):
                make_contribution(sender_id=bad)

    def test_empty_id_set_rejected(self):
        with self.assertRaises(ValueError):
            make_contribution(participant_ids=())

    def test_non_integer_ids_rejected(self):
        with self.assertRaises(TypeError):
            make_contribution(sender_id="1")
        with self.assertRaises(TypeError):
            make_contribution(participant_ids=(1, 2, 3.0))

    def test_threshold_validation(self):
        with self.assertRaises(ValueError):
            make_contribution(threshold=0)
        with self.assertRaises(ValueError):
            make_contribution(threshold=4)  # only 3 participants
        with self.assertRaises(TypeError):
            make_contribution(threshold=2.5)

    def test_group_parameters_validated(self):
        with self.assertRaises(ValueError):
            make_contribution(generator=1)
        with self.assertRaises(ValueError):
            make_contribution(blinding_generator=GENERATOR)
        with self.assertRaises(ValueError):
            make_contribution(prime=2021)
        with self.assertRaises(TypeError):
            make_contribution(group_prime=8069.0)


class VerifyDKGReceivedShareTest(unittest.TestCase):
    def setUp(self):
        self.contribution = make_contribution(sender_id=1)
        self.received = self.contribution.shares[0]

    def test_tampered_share_value_returns_false(self):
        tampered = DKGReceivedShare(
            self.received.sender_id,
            self.received.receiver_id,
            Share(self.received.share.x, (self.received.share.y + 1) % FIELD_PRIME),
            self.received.blinding_share,
        )
        self.assertFalse(verify_dkg_received_share(tampered, self.contribution))

    def test_tampered_blinding_value_returns_false(self):
        tampered = DKGReceivedShare(
            self.received.sender_id,
            self.received.receiver_id,
            self.received.share,
            Share(
                self.received.blinding_share.x,
                (self.received.blinding_share.y + 1) % FIELD_PRIME,
            ),
        )
        self.assertFalse(verify_dkg_received_share(tampered, self.contribution))

    def test_coordinate_mismatch_returns_false(self):
        # A pair dealt to participant 2 presented as belonging to 1.
        other = self.contribution.shares[1]
        mismatched = DKGReceivedShare(
            other.sender_id, self.received.receiver_id, other.share, other.blinding_share
        )
        self.assertFalse(verify_dkg_received_share(mismatched, self.contribution))

    def test_wrong_sender_returns_false(self):
        impostor = DKGReceivedShare(
            2, self.received.receiver_id, self.received.share, self.received.blinding_share
        )
        self.assertFalse(verify_dkg_received_share(impostor, self.contribution))

    def test_non_participant_receiver_returns_false(self):
        stranger = DKGReceivedShare(
            self.received.sender_id, 4, self.received.share, self.received.blinding_share
        )
        self.assertFalse(verify_dkg_received_share(stranger, self.contribution))

    def test_other_contribution_commitment_returns_false(self):
        other = make_contribution(sender_id=2)
        for received in self.contribution.shares:
            self.assertFalse(verify_dkg_received_share(received, other))

    def test_wrong_types_raise_type_error(self):
        with self.assertRaises(TypeError):
            verify_dkg_received_share((1, 2), self.contribution)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            verify_dkg_received_share(self.received, self.contribution.commitment)  # type: ignore[arg-type]

    def test_out_of_range_ids_raise_value_error(self):
        for bad in (0, FIELD_PRIME):
            received = DKGReceivedShare(
                self.received.sender_id, bad, self.received.share, self.received.blinding_share
            )
            with self.assertRaises(ValueError):
                verify_dkg_received_share(received, self.contribution)

    def test_illegal_commitment_raises_value_error(self):
        broken = DKGContribution(
            self.contribution.sender_id,
            self.contribution.participant_ids,
            self.contribution.shares,
            PedersenCommitment((), FIELD_PRIME, GROUP_PRIME, GENERATOR, BLINDING_GENERATOR),
        )
        with self.assertRaises(ValueError):
            verify_dkg_received_share(self.received, broken)

    def test_legal_mismatch_is_false_not_error(self):
        tampered = DKGReceivedShare(
            self.received.sender_id,
            self.received.receiver_id,
            Share(self.received.share.x, (self.received.share.y + 1) % FIELD_PRIME),
            self.received.blinding_share,
        )
        self.assertIs(verify_dkg_received_share(tampered, self.contribution), False)


class AggregateDKGTest(unittest.TestCase):
    def test_success_returns_one_result_per_participant(self):
        contributions = make_contributions(count=3, threshold=2)
        results = aggregate_dkg(contributions)
        self.assertIsInstance(results, list)
        self.assertEqual([result.receiver_id for result in results], [1, 2, 3])
        for result in results:
            self.assertIsInstance(result, DKGResult)
            self.assertEqual(result.participant_ids, (1, 2, 3))
            self.assertEqual(result.share.x, result.receiver_id)
            self.assertEqual(result.blinding_share.x, result.receiver_id)

    def test_aggregated_shares_verify_against_joint_commitment(self):
        contributions = make_contributions(count=3, threshold=2)
        results = aggregate_dkg(contributions)
        for result in results:
            self.assertTrue(
                verify_pedersen_share(result.share, result.blinding_share, result.commitment)
            )

    def test_joint_commitment_is_componentwise_product(self):
        contributions = make_contributions(count=3, threshold=2)
        results = aggregate_dkg(contributions)
        joint = results[0].commitment
        self.assertIsNot(joint, contributions[0].commitment)
        for position in range(2):
            product = 1
            for contribution in contributions:
                product = product * contribution.commitment.values[position] % GROUP_PRIME
            self.assertEqual(joint.values[position], product)
        self.assertEqual(
            (
                joint.field_prime,
                joint.group_prime,
                joint.generator,
                joint.blinding_generator,
            ),
            (FIELD_PRIME, GROUP_PRIME, GENERATOR, BLINDING_GENERATOR),
        )

    def test_aggregated_shares_are_componentwise_sums(self):
        contributions = make_contributions(count=3, threshold=2)
        results = aggregate_dkg(contributions)
        for position, result in enumerate(results):
            self.assertEqual(
                result.share.y,
                sum(c.shares[position].share.y for c in contributions) % FIELD_PRIME,
            )
            self.assertEqual(
                result.blinding_share.y,
                sum(c.shares[position].blinding_share.y for c in contributions) % FIELD_PRIME,
            )

    def test_enough_receivers_reconstruct_joint_secret(self):
        threshold = 2
        contributions = make_contributions(count=3, threshold=threshold)
        results = aggregate_dkg(contributions)
        joint_secret = sum(
            contribution_secret(c, threshold) for c in contributions
        ) % FIELD_PRIME
        rebuilt = reconstruct_secret(
            [result.share for result in results[:threshold]], prime=FIELD_PRIME
        )
        self.assertEqual(rebuilt, joint_secret)

    def test_input_order_does_not_matter(self):
        contributions = make_contributions(count=4, threshold=3)
        shuffled = [contributions[2], contributions[0], contributions[3], contributions[1]]
        self.assertEqual(aggregate_dkg(contributions), aggregate_dkg(shuffled))

    def test_threshold_one(self):
        contributions = make_contributions(count=3, threshold=1)
        results = aggregate_dkg(contributions)
        # With constant polynomials every receiver holds the joint secret.
        joint_secret = sum(
            contribution_secret(c, 1) for c in contributions
        ) % FIELD_PRIME
        for result in results:
            self.assertEqual(result.share.y, joint_secret)
            self.assertTrue(
                verify_pedersen_share(result.share, result.blinding_share, result.commitment)
            )

    def test_two_and_five_participants(self):
        for count in (2, 5):
            threshold = 2
            contributions = make_contributions(count=count, threshold=threshold)
            results = aggregate_dkg(contributions)
            self.assertEqual(len(results), count)
            joint_secret = sum(
                contribution_secret(c, threshold) for c in contributions
            ) % FIELD_PRIME
            rebuilt = reconstruct_secret(
                [result.share for result in results[:threshold]], prime=FIELD_PRIME
            )
            self.assertEqual(rebuilt, joint_secret)

    def test_tampered_contribution_returns_rejection_naming_sender(self):
        contributions = make_contributions(count=3, threshold=2)
        contributions[1] = tampered_contribution(contributions[1])
        outcome = aggregate_dkg(contributions)
        self.assertIsInstance(outcome, DKGRejection)
        self.assertEqual(outcome.sender_id, 2)

    def test_rejection_does_not_depend_on_input_order(self):
        contributions = make_contributions(count=3, threshold=2)
        contributions[2] = tampered_contribution(contributions[2])
        self.assertEqual(aggregate_dkg(contributions), aggregate_dkg(contributions[::-1]))

    def test_missing_participant_rejected(self):
        contributions = make_contributions(count=3, threshold=2)
        with self.assertRaises(ValueError):
            aggregate_dkg(contributions[:2])

    def test_duplicate_participant_rejected(self):
        contributions = make_contributions(count=3, threshold=2)
        with self.assertRaises(ValueError):
            aggregate_dkg([contributions[0], contributions[0], contributions[1]])

    def test_inconsistent_participant_ids_rejected(self):
        contributions = make_contributions(count=3, threshold=2)
        outsider = make_contribution(sender_id=4, participant_ids=(2, 3, 4), threshold=2)
        with self.assertRaises(ValueError):
            aggregate_dkg([contributions[0], contributions[1], outsider])

    def test_inconsistent_group_parameters_rejected(self):
        contributions = make_contributions(count=3, threshold=2)
        different = make_contribution(
            sender_id=3, threshold=2, blinding_generator=THIRD_GENERATOR
        )
        with self.assertRaises(ValueError):
            aggregate_dkg([contributions[0], contributions[1], different])

    def test_inconsistent_threshold_rejected(self):
        contributions = make_contributions(count=3, threshold=2)
        different = make_contribution(sender_id=3, threshold=3)
        with self.assertRaises(ValueError):
            aggregate_dkg([contributions[0], contributions[1], different])

    def test_wrong_contribution_type_raises_type_error(self):
        contributions = make_contributions(count=3, threshold=2)
        with self.assertRaises(TypeError):
            aggregate_dkg([contributions[0], contributions[1], "not a contribution"])

    def test_empty_input_rejected(self):
        with self.assertRaises(ValueError):
            aggregate_dkg([])

    def test_illegal_commitment_raises_value_error(self):
        contributions = make_contributions(count=3, threshold=2)
        broken = DKGContribution(
            3,
            (1, 2, 3),
            contributions[2].shares,
            PedersenCommitment((), FIELD_PRIME, GROUP_PRIME, GENERATOR, BLINDING_GENERATOR),
        )
        with self.assertRaises(ValueError):
            aggregate_dkg([contributions[0], contributions[1], broken])

    def test_result_is_frozen_and_stores_no_secret_or_coefficients(self):
        results = aggregate_dkg(make_contributions(count=3, threshold=2))
        result = results[0]
        with self.assertRaises(FrozenInstanceError):
            result.share = Share(1, 2)  # type: ignore[misc]
        self.assertEqual(
            {field.name for field in dataclasses.fields(result)},
            {"receiver_id", "share", "blinding_share", "commitment", "participant_ids"},
        )
        self.assertFalse(hasattr(result, "secret"))
        self.assertFalse(hasattr(result, "coefficients"))

    def test_rejection_is_frozen(self):
        rejection = DKGRejection(sender_id=1)
        with self.assertRaises(FrozenInstanceError):
            rejection.sender_id = 2  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
