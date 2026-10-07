"""Tests for aggregate_qualified_local_dkg."""

import dataclasses
import unittest

from thresholdsign import (
    AggregateSignature,
    DKGReceivedShare,
    DKGRejection,
    LocalDKGPacket,
    Share,
    SigningPublicContext,
    SigningRoundPacket,
    aggregate_local_dkg,
    aggregate_qualified_local_dkg,
    aggregate_signature,
    create_signing_contribution,
    create_signing_nonce_commitment,
    create_signing_round,
    sign_round_packet,
    verify_signature,
    verify_signature_share,
    verify_signing_public_context,
)

# Same toy Pedersen setup as the local DKG tests: 8069 = 4 * 2017 + 1 is
# prime, 16 and 256 = 16 ** 2 are distinct generators of the order-2017
# subgroup modulo 8069.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

MESSAGE = b"qualified local dkg test message"


def fixed_random(seed=1):
    """Deterministic stand-in for secrets.randbelow so tests are reproducible."""
    state = {"value": seed}

    def randbelow(upper: int) -> int:
        state["value"] = (state["value"] * 6364136223846793005 + 1442695040888963407) % upper
        return state["value"]

    return randbelow


def zero_random():
    """Deterministic source that draws only zeros (all-zero polynomials)."""
    return lambda upper: 0


def make_contributions(participant_ids=(1, 2, 3), threshold=2, randbelow=None):
    """One valid SigningContribution per participant."""
    return [
        create_signing_contribution(
            pid,
            participant_ids,
            threshold,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            blinding_generator=BLINDING_GENERATOR,
            randbelow=randbelow if randbelow is not None else fixed_random(pid),
        )
        for pid in participant_ids
    ]


def packet_for(contribution, receiver_id):
    """The LocalDKGPacket ``receiver_id`` extracts from ``contribution``."""
    dealing = contribution.contribution
    index = dealing.participant_ids.index(receiver_id)
    return LocalDKGPacket(
        participant_ids=dealing.participant_ids,
        received=DKGReceivedShare(
            sender_id=dealing.sender_id,
            receiver_id=receiver_id,
            share=dealing.shares[index],
            blinding_share=dealing.blinding_shares[index],
        ),
        commitment=dealing.commitment,
        feldman_commitment=contribution.feldman_commitment,
    )


def packets_for(contributions, receiver_id, sender_ids=None):
    if sender_ids is None:
        sender_ids = [item.contribution.sender_id for item in contributions]
    by_sender = {item.contribution.sender_id: item for item in contributions}
    return [packet_for(by_sender[sender_id], receiver_id) for sender_id in sender_ids]


def feldman_evaluation(contribution, participant_id):
    """Product C_j ** x ** j of one contribution's Feldman commitment."""
    feldman = contribution.feldman_commitment
    x_power = 1
    evaluation = 1
    for value in feldman.values:
        evaluation = evaluation * pow(value, x_power, GROUP_PRIME) % GROUP_PRIME
        x_power = x_power * participant_id % FIELD_PRIME
    return evaluation


def tamper_share(packet, delta=1):
    received = packet.received
    tampered = Share(
        x=received.share.x, y=(received.share.y + delta) % FIELD_PRIME
    )
    return dataclasses.replace(
        packet, received=dataclasses.replace(received, share=tampered)
    )


class AggregateQualifiedLocalDKGValidTest(unittest.TestCase):
    def setUp(self):
        self.contributions = make_contributions()
        self.by_sender = {
            item.contribution.sender_id: item for item in self.contributions
        }

    def test_returns_own_shares_and_public_context(self):
        outcome = aggregate_qualified_local_dkg(
            2, packets_for(self.contributions, 2, (1, 2)), (1, 2)
        )
        self.assertIsInstance(outcome, tuple)
        share, blinding_share, context = outcome
        self.assertIsInstance(share, Share)
        self.assertIsInstance(blinding_share, Share)
        self.assertIsInstance(context, SigningPublicContext)
        self.assertEqual(share.x, 2)
        self.assertEqual(blinding_share.x, 2)
        self.assertEqual(context.participant_ids, (1, 2, 3))
        self.assertEqual(context.threshold, 2)
        self.assertTrue(verify_signing_public_context(context))

    def test_share_values_are_subset_field_sums(self):
        qualified = (1, 3)
        packets = packets_for(self.contributions, 2, qualified)
        share, blinding_share, context = aggregate_qualified_local_dkg(
            2, packets, qualified
        )
        self.assertEqual(
            share.y,
            sum(packet.received.share.y for packet in packets) % FIELD_PRIME,
        )
        self.assertEqual(
            blinding_share.y,
            sum(packet.received.blinding_share.y for packet in packets) % FIELD_PRIME,
        )
        expected_public_key = 1
        for sender_id in qualified:
            expected_public_key = (
                expected_public_key
                * self.by_sender[sender_id].feldman_commitment.values[0]
            ) % GROUP_PRIME
        self.assertEqual(context.public_key, expected_public_key)
        for index, participant_id in enumerate((1, 2, 3)):
            expected_share = 1
            for sender_id in qualified:
                expected_share = (
                    expected_share
                    * feldman_evaluation(self.by_sender[sender_id], participant_id)
                ) % GROUP_PRIME
            self.assertEqual(context.verification_shares[index], expected_share)

    def test_receiver_need_not_be_qualified(self):
        # Member 3 aggregates the qualified set (1, 2): it keeps the share
        # addressed to it and g ** of that sum equals its verification share.
        qualified = (1, 2)
        share, blinding_share, context = aggregate_qualified_local_dkg(
            3, packets_for(self.contributions, 3, qualified), qualified
        )
        self.assertEqual(share.x, 3)
        self.assertEqual(blinding_share.x, 3)
        self.assertEqual(
            pow(GENERATOR, share.y, GROUP_PRIME),
            context.verification_shares[2],
        )

    def test_same_commitments_give_equal_contexts_for_every_receiver(self):
        qualified = (1, 2)
        contexts = []
        for receiver_id in (1, 2, 3):
            _share, _blinding, context = aggregate_qualified_local_dkg(
                receiver_id,
                packets_for(self.contributions, receiver_id, qualified),
                qualified,
            )
            contexts.append(context)
        self.assertEqual(contexts[0], contexts[1])
        self.assertEqual(contexts[1], contexts[2])

    def test_full_set_equals_aggregate_local_dkg(self):
        for receiver_id in (1, 2, 3):
            packets = packets_for(self.contributions, receiver_id)
            self.assertEqual(
                aggregate_qualified_local_dkg(receiver_id, packets, (1, 2, 3)),
                aggregate_local_dkg(receiver_id, packets),
            )

    def test_true_subset_counts_only_the_subset(self):
        full = aggregate_local_dkg(2, packets_for(self.contributions, 2))
        subset = aggregate_qualified_local_dkg(
            2, packets_for(self.contributions, 2, (1, 2)), (1, 2)
        )
        full_share, _full_blinding, full_context = full
        subset_share, _subset_blinding, subset_context = subset
        self.assertNotEqual(subset_share.y, full_share.y)
        self.assertNotEqual(subset_context.public_key, full_context.public_key)
        # Adding the omitted contributor's pieces reconstructs the full result.
        omitted = self.by_sender[3]
        omitted_packet = packet_for(omitted, 2)
        self.assertEqual(
            (subset_share.y + omitted_packet.received.share.y) % FIELD_PRIME,
            full_share.y,
        )
        self.assertEqual(
            subset_context.public_key
            * omitted.feldman_commitment.values[0]
            % GROUP_PRIME,
            full_context.public_key,
        )
        # The participant set and threshold never change.
        self.assertEqual(subset_context.participant_ids, full_context.participant_ids)
        self.assertEqual(subset_context.threshold, full_context.threshold)

    def test_input_order_does_not_matter(self):
        qualified = (1, 3)
        packets = packets_for(self.contributions, 2, qualified)
        forward = aggregate_qualified_local_dkg(2, packets, qualified)
        reversed_outcome = aggregate_qualified_local_dkg(
            2, list(reversed(packets)), qualified
        )
        self.assertEqual(forward, reversed_outcome)

    def test_accepts_single_pass_iterator(self):
        qualified = (2, 3)
        packets = packets_for(self.contributions, 2, qualified)
        outcome = aggregate_qualified_local_dkg(2, iter(packets), qualified)
        again = aggregate_qualified_local_dkg(
            2, (packet for packet in packets), qualified
        )
        self.assertEqual(outcome, again)

    def test_does_not_mutate_inputs_and_is_deterministic(self):
        qualified = (1, 2)
        packets = packets_for(self.contributions, 2, qualified)
        snapshot = list(packets)
        ids_snapshot = qualified
        first = aggregate_qualified_local_dkg(2, packets, qualified)
        second = aggregate_qualified_local_dkg(2, packets, qualified)
        self.assertEqual(first, second)
        self.assertEqual(packets, snapshot)
        self.assertEqual(qualified, ids_snapshot)

    def test_threshold_one_with_single_member_set(self):
        contributions = make_contributions((5,), 1)
        share, blinding_share, context = aggregate_qualified_local_dkg(
            5, packets_for(contributions, 5), (5,)
        )
        self.assertEqual(share.x, 5)
        self.assertEqual(blinding_share.x, 5)
        self.assertEqual(context.participant_ids, (5,))
        self.assertEqual(context.threshold, 1)
        self.assertEqual(
            share.y, contributions[0].contribution.shares[0].y
        )

    def test_threshold_one_accepts_a_single_qualified_sender(self):
        contributions = make_contributions((1, 2, 3), 1)
        qualified = (2,)
        share, _blinding, context = aggregate_qualified_local_dkg(
            3, packets_for(contributions, 3, qualified), qualified
        )
        contribution = contributions[1]
        index = contribution.contribution.participant_ids.index(3)
        self.assertEqual(share.y, contribution.contribution.shares[index].y)
        self.assertEqual(
            context.public_key, contribution.feldman_commitment.values[0]
        )

    def test_zero_shares_and_identity_commitments(self):
        contributions = make_contributions((1, 2, 3), 2, randbelow=zero_random())
        qualified = (1, 3)
        share, blinding_share, context = aggregate_qualified_local_dkg(
            2, packets_for(contributions, 2, qualified), qualified
        )
        self.assertEqual(share, Share(x=2, y=0))
        self.assertEqual(blinding_share, Share(x=2, y=0))
        self.assertEqual(context.public_key, 1)
        self.assertEqual(context.verification_shares, (1, 1, 1))

    def test_qualified_subset_result_signs_and_verifies_end_to_end(self):
        # With qualified set (1, 2) under threshold 2, the signing set may
        # even include non-qualified member 3: every original member received
        # the qualified senders' shares, so each holds the matching point of
        # the subset secret.
        qualified = (1, 2)
        local = {}
        contexts = set()
        for receiver_id in (1, 3):
            outcome = aggregate_qualified_local_dkg(
                receiver_id,
                packets_for(self.contributions, receiver_id, qualified),
                qualified,
            )
            local[receiver_id] = outcome
            contexts.add(outcome[2])
        self.assertEqual(len(contexts), 1)
        context = local[1][2]

        signer_ids = (1, 3)
        commitments = []
        nonces = {}
        for offset, signer_id in enumerate(signer_ids):
            commitment, nonce = create_signing_nonce_commitment(
                signer_id,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
                randbelow=fixed_random(100 + offset),
            )
            commitments.append(commitment)
            nonces[signer_id] = nonce
        round_info = create_signing_round(MESSAGE, signer_ids, commitments, context)
        packet = SigningRoundPacket(context=context, round_info=round_info)

        shares = [
            sign_round_packet(
                signer_id,
                local[signer_id][0].y,
                nonces[signer_id],
                packet,
                local[signer_id][2],
                MESSAGE,
            )
            for signer_id in signer_ids
        ]
        for signature_share in shares:
            self.assertTrue(
                verify_signature_share(signature_share, round_info, context)
            )
        signature = aggregate_signature(shares, round_info, context)
        self.assertIsInstance(signature, AggregateSignature)
        self.assertTrue(
            verify_signature(
                MESSAGE,
                signature,
                context.public_key,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            )
        )


class AggregateQualifiedLocalDKGRejectionTest(unittest.TestCase):
    def setUp(self):
        self.contributions = make_contributions()

    def test_tampered_qualified_packet_produces_rejection(self):
        packets = packets_for(self.contributions, 2, (1, 2))
        packets[0] = tamper_share(packets[0])
        outcome = aggregate_qualified_local_dkg(2, packets, (1, 2))
        self.assertEqual(outcome, [DKGRejection(sender_id=1)])

    def test_all_failures_listed_sorted_and_deduplicated(self):
        packets = packets_for(self.contributions, 2, (1, 3))
        packets = [tamper_share(packets[1]), tamper_share(packets[0])]
        outcome = aggregate_qualified_local_dkg(2, packets, (1, 3))
        self.assertEqual(
            outcome,
            [DKGRejection(sender_id=1), DKGRejection(sender_id=3)],
        )

    def test_full_set_rejections_equal_aggregate_local_dkg(self):
        packets = packets_for(self.contributions, 2)
        packets[0] = tamper_share(packets[0])
        packets[2] = tamper_share(packets[2])
        self.assertEqual(
            aggregate_qualified_local_dkg(2, packets, (1, 2, 3)),
            aggregate_local_dkg(2, packets),
        )

    def test_rejection_returns_no_partial_result(self):
        packets = packets_for(self.contributions, 2, (1, 2))
        packets[0] = tamper_share(packets[0])
        outcome = aggregate_qualified_local_dkg(2, packets, (1, 2))
        self.assertNotIsInstance(outcome, tuple)


class AggregateQualifiedLocalDKGTypeErrorTest(unittest.TestCase):
    def setUp(self):
        self.contributions = make_contributions()
        self.packets = packets_for(self.contributions, 2, (1, 2))

    def test_receiver_id_type(self):
        for bad in ("2", 2.0, None, True, False):
            with self.assertRaises(TypeError, msg=repr(bad)):
                aggregate_qualified_local_dkg(bad, self.packets, (1, 2))

    def test_qualified_ids_must_be_tuple(self):
        for bad in ([1, 2], (x for x in (1, 2)), {1, 2}, "12", None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                aggregate_qualified_local_dkg(2, self.packets, bad)

    def test_qualified_id_element_types(self):
        for bad in ((1, True), (True, 2), (1, "2"), (None,), (1, 2.0)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                aggregate_qualified_local_dkg(2, self.packets, bad)

    def test_packet_element_types_are_still_checked(self):
        packet = self.packets[0]
        for bad in ("packet", 7, packet.received, self.packets):
            with self.assertRaises(TypeError, msg=repr(bad)):
                aggregate_qualified_local_dkg(2, [bad], (1, 2))

    def test_nested_field_type_error(self):
        packet = self.packets[0]
        broken = dataclasses.replace(
            packet,
            received=dataclasses.replace(packet.received, sender_id=True),
        )
        with self.assertRaises(TypeError):
            aggregate_qualified_local_dkg(2, [broken, self.packets[1]], (1, 2))


class AggregateQualifiedLocalDKGValueErrorTest(unittest.TestCase):
    def setUp(self):
        self.contributions = make_contributions()

    def packets(self, receiver_id=2, sender_ids=(1, 2)):
        return packets_for(self.contributions, receiver_id, sender_ids)

    def test_empty_batch(self):
        with self.assertRaises(ValueError):
            aggregate_qualified_local_dkg(2, [], (1, 2))

    def test_empty_qualified_set(self):
        with self.assertRaises(ValueError):
            aggregate_qualified_local_dkg(2, self.packets(), ())

    def test_non_increasing_qualified_set(self):
        for bad in ((2, 1), (1, 1, 2), (3, 2, 1), (2, 2)):
            with self.assertRaises(ValueError, msg=repr(bad)):
                aggregate_qualified_local_dkg(2, self.packets(), bad)

    def test_qualified_id_outside_participant_set(self):
        with self.assertRaises(ValueError):
            aggregate_qualified_local_dkg(2, self.packets(sender_ids=(1, 2)), (1, 4))
        with self.assertRaises(ValueError):
            aggregate_qualified_local_dkg(2, self.packets(sender_ids=(2, 3)), (2, 9))

    def test_qualified_set_smaller_than_threshold(self):
        # Threshold 2 requires at least two qualified senders.
        with self.assertRaises(ValueError):
            aggregate_qualified_local_dkg(2, self.packets(sender_ids=(1,)), (1,))
        # A batch that merely omits senders but names the full qualified set
        # differently also fails: set mismatch below; here size fails first.
        contributions = make_contributions((1, 2, 3, 4), 3)
        with self.assertRaises(ValueError):
            aggregate_qualified_local_dkg(
                2,
                packets_for(contributions, 2, (1, 2)),
                (1, 2),
            )

    def test_missing_sender(self):
        # Qualified set (1, 2) but only sender 1's packet is present.
        with self.assertRaises(ValueError):
            aggregate_qualified_local_dkg(
                2, self.packets(sender_ids=(1,)), (1, 2)
            )

    def test_duplicate_sender(self):
        packets = self.packets()
        with self.assertRaises(ValueError):
            aggregate_qualified_local_dkg(
                2, [packets[0], packets[0]], (1, 2)
            )

    def test_extra_sender(self):
        packets = packets_for(self.contributions, 2, (1, 2, 3))
        with self.assertRaises(ValueError):
            aggregate_qualified_local_dkg(2, packets, (1, 2))

    def test_sender_outside_qualified_set(self):
        packets = packets_for(self.contributions, 2, (1, 3))
        with self.assertRaises(ValueError):
            aggregate_qualified_local_dkg(2, packets, (1, 2))

    def test_receiver_not_a_participant(self):
        for bad in (4, 0, FIELD_PRIME):
            with self.assertRaises(ValueError, msg=repr(bad)):
                aggregate_qualified_local_dkg(
                    bad,
                    packets_for(self.contributions, 2, (1, 2)),
                    (1, 2),
                )

    def test_receiver_addressing_mismatch_inherited(self):
        # Packets addressed to receiver 1 cannot be aggregated as receiver 2.
        packets = packets_for(self.contributions, 1, (1, 2))
        with self.assertRaises(ValueError):
            aggregate_qualified_local_dkg(2, packets, (1, 2))

    def test_packets_disagree_on_threshold(self):
        other = make_contributions(threshold=3)
        mixed = [
            packet_for(self.contributions[0], 2),
            packet_for(other[1], 2),
        ]
        with self.assertRaises(ValueError):
            aggregate_qualified_local_dkg(2, mixed, (1, 2))

    def test_packets_disagree_on_participant_ids(self):
        other = make_contributions(participant_ids=(1, 2, 4))
        mixed = [
            packet_for(self.contributions[0], 2),
            packet_for(other[1], 2),
        ]
        with self.assertRaises(ValueError):
            aggregate_qualified_local_dkg(2, mixed, (1, 2))

    def test_structural_failure_precedes_commitment_checks(self):
        # A tampered (mathematically bad) packet still raises ValueError, not
        # a rejection, when the qualified set is structurally too small.
        packets = packets_for(self.contributions, 2, (1, 2))
        packets[0] = tamper_share(packets[0])
        with self.assertRaises(ValueError):
            aggregate_qualified_local_dkg(2, packets, (1,))


if __name__ == "__main__":
    unittest.main()
