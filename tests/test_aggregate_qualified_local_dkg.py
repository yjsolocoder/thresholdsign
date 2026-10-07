"""Tests for aggregate_qualified_local_dkg."""

import dataclasses
import unittest

from thresholdsign import (
    AggregateSignature,
    DKGRejection,
    LocalDKGPacket,
    Share,
    SigningRoundPacket,
    aggregate_local_dkg,
    aggregate_qualified_local_dkg,
    aggregate_signature,
    create_signing_nonce_commitment,
    create_signing_round,
    sign_round_packet,
    verify_signature,
    verify_signature_share,
)
from tests.test_local_dkg import (
    BLINDING_GENERATOR,
    FIELD_PRIME,
    GENERATOR,
    GROUP_PRIME,
    MESSAGE,
    fixed_random,
    make_contributions,
    packet_for,
    packets_for,
    zero_random,
)


def qualified_packets(contributions, receiver_id, qualified_ids):
    """The packets addressed to receiver_id from the qualified senders."""
    by_sender = {
        contribution.contribution.sender_id: contribution
        for contribution in contributions
    }
    return [packet_for(by_sender[sender_id], receiver_id) for sender_id in qualified_ids]


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
        self.all_packets = {
            participant_id: packets_for(self.contributions, participant_id)
            for participant_id in (1, 2, 3)
        }

    def test_returns_own_shares_and_public_context(self):
        outcome = aggregate_qualified_local_dkg(
            2, qualified_packets(self.contributions, 2, (1, 2)), (1, 2)
        )
        self.assertIsInstance(outcome, tuple)
        share, blinding_share, context = outcome
        self.assertIsInstance(share, Share)
        self.assertIsInstance(blinding_share, Share)
        self.assertEqual(share.x, 2)
        self.assertEqual(blinding_share.x, 2)
        self.assertEqual(context.participant_ids, (1, 2, 3))
        self.assertEqual(context.threshold, 2)
        self.assertEqual(len(context.verification_shares), 3)

    def test_full_set_equals_aggregate_local_dkg_for_every_member(self):
        for participant_id in (1, 2, 3):
            packets = self.all_packets[participant_id]
            self.assertEqual(
                aggregate_qualified_local_dkg(participant_id, packets, (1, 2, 3)),
                aggregate_local_dkg(participant_id, packets),
            )

    def test_subset_share_values_are_field_sums_of_qualified_only(self):
        qualified = (1, 3)
        packets = qualified_packets(self.contributions, 2, qualified)
        share, blinding_share, _context = aggregate_qualified_local_dkg(
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
        full_share, full_blinding, _ = aggregate_local_dkg(
            2, self.all_packets[2]
        )
        self.assertNotEqual(share.y, full_share.y)
        self.assertNotEqual(blinding_share.y, full_blinding.y)

    def test_subset_public_key_is_product_of_qualified_constant_commitments(self):
        qualified = (1, 3)
        _share, _blinding, context = aggregate_qualified_local_dkg(
            2, qualified_packets(self.contributions, 2, qualified), qualified
        )
        by_sender = {
            contribution.contribution.sender_id: contribution
            for contribution in self.contributions
        }
        expected_key = (
            by_sender[1].feldman_commitment.values[0]
            * by_sender[3].feldman_commitment.values[0]
            % GROUP_PRIME
        )
        self.assertEqual(context.public_key, expected_key)
        _full_share, _full_blinding, full_context = aggregate_local_dkg(
            2, self.all_packets[2]
        )
        self.assertNotEqual(context.public_key, full_context.public_key)

    def test_same_qualified_set_gives_every_receiver_equal_context(self):
        qualified = (1, 2)
        contexts = []
        for participant_id in (1, 2, 3):
            _share, _blinding, context = aggregate_qualified_local_dkg(
                participant_id,
                qualified_packets(self.contributions, participant_id, qualified),
                qualified,
            )
            contexts.append(context)
        self.assertEqual(contexts[0], contexts[1])
        self.assertEqual(contexts[0], contexts[2])

    def test_receiver_need_not_be_qualified(self):
        # Member 3 aggregates only contributors 1 and 2, neither of which is
        # member 3; the share coordinate is still 3.
        packets = qualified_packets(self.contributions, 3, (1, 2))
        share, blinding_share, context = aggregate_qualified_local_dkg(
            3, packets, (1, 2)
        )
        self.assertEqual(share, Share(x=3, y=sum(p.received.share.y for p in packets) % FIELD_PRIME))
        self.assertEqual(blinding_share.x, 3)
        # The qualified context's verification share for member 3 matches.
        qualified = (1, 2)
        other_context = aggregate_qualified_local_dkg(
            1, qualified_packets(self.contributions, 1, qualified), qualified
        )[2]
        self.assertEqual(context, other_context)

    def test_non_qualified_receiver_share_verifies_and_signs(self):
        # A receiver outside the qualified set (member 3) keeps a share that
        # is valid against the qualified context, so a threshold-sized
        # signing set may include non-qualified members.
        qualified = (1, 2)
        local = {}
        context = None
        for participant_id in (1, 2, 3):
            share, blinding_share, member_context = aggregate_qualified_local_dkg(
                participant_id,
                qualified_packets(self.contributions, participant_id, qualified),
                qualified,
            )
            local[participant_id] = (share, blinding_share)
            context = member_context

        signer_ids = (2, 3)
        commitments = []
        nonces = {}
        for offset, signer_id in enumerate(signer_ids):
            commitment, nonce = create_signing_nonce_commitment(
                signer_id,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
                randbelow=fixed_random(200 + offset),
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
                context,
                MESSAGE,
            )
            for signer_id in signer_ids
        ]
        for signature_share in shares:
            self.assertTrue(verify_signature_share(signature_share, round_info, context))
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

    def test_end_to_end_signature_with_qualified_subset(self):
        qualified = (1, 3)
        local = {}
        context = None
        for participant_id in (1, 3):
            share, blinding_share, member_context = aggregate_qualified_local_dkg(
                participant_id,
                qualified_packets(self.contributions, participant_id, qualified),
                qualified,
            )
            local[participant_id] = (share, blinding_share)
            context = member_context

        signer_ids = (1, 3)
        commitments = []
        nonces = {}
        for offset, signer_id in enumerate(signer_ids):
            commitment, nonce = create_signing_nonce_commitment(
                signer_id,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
                randbelow=fixed_random(300 + offset),
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
                context,
                MESSAGE,
            )
            for signer_id in signer_ids
        ]
        signature = aggregate_signature(shares, round_info, context)
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

    def test_input_order_does_not_matter(self):
        qualified = (1, 3)
        packets = qualified_packets(self.contributions, 2, qualified)
        forward = aggregate_qualified_local_dkg(2, packets, qualified)
        reversed_outcome = aggregate_qualified_local_dkg(
            2, list(reversed(packets)), qualified
        )
        self.assertEqual(forward, reversed_outcome)

    def test_accepts_single_pass_iterator(self):
        qualified = (1, 2)
        packets = qualified_packets(self.contributions, 2, qualified)
        outcome = aggregate_qualified_local_dkg(2, iter(packets), qualified)
        again = aggregate_qualified_local_dkg(
            2, (packet for packet in packets), qualified
        )
        self.assertEqual(outcome, again)

    def test_more_than_threshold_qualified(self):
        contributions = make_contributions((1, 2, 3, 4), threshold=2)
        qualified = (2, 3, 4)
        packets = qualified_packets(contributions, 1, qualified)
        share, blinding_share, context = aggregate_qualified_local_dkg(
            1, packets, qualified
        )
        self.assertEqual(share.x, 1)
        self.assertEqual(context.participant_ids, (1, 2, 3, 4))
        self.assertEqual(context.threshold, 2)
        self.assertEqual(
            share.y, sum(packet.received.share.y for packet in packets) % FIELD_PRIME
        )

    def test_threshold_one_single_qualified_member(self):
        contributions = make_contributions((1, 2, 3), 1)
        qualified = (2,)
        share, blinding_share, context = aggregate_qualified_local_dkg(
            3, qualified_packets(contributions, 3, qualified), qualified
        )
        only = next(
            contribution
            for contribution in contributions
            if contribution.contribution.sender_id == 2
        )
        self.assertEqual(
            share.y,
            only.contribution.shares[
                only.contribution.participant_ids.index(3)
            ].y,
        )
        self.assertEqual(context.threshold, 1)
        self.assertEqual(context.public_key, only.feldman_commitment.values[0])

    def test_single_participant_full_set(self):
        contributions = make_contributions((5,), 1)
        share, blinding_share, context = aggregate_qualified_local_dkg(
            5, qualified_packets(contributions, 5, (5,)), (5,)
        )
        self.assertEqual(share.x, 5)
        self.assertEqual(blinding_share.x, 5)
        self.assertEqual(context.participant_ids, (5,))
        self.assertEqual(context.threshold, 1)

    def test_zero_shares_and_identity_commitments(self):
        contributions = make_contributions((1, 2, 3), 2, randbelow=zero_random())
        qualified = (1, 3)
        share, blinding_share, context = aggregate_qualified_local_dkg(
            2, qualified_packets(contributions, 2, qualified), qualified
        )
        self.assertEqual(share, Share(x=2, y=0))
        self.assertEqual(blinding_share, Share(x=2, y=0))
        self.assertEqual(context.public_key, 1)
        self.assertEqual(context.verification_shares, (1, 1, 1))

    def test_does_not_mutate_inputs_and_is_deterministic(self):
        qualified = (1, 2)
        packets = qualified_packets(self.contributions, 2, qualified)
        snapshot = list(packets)
        first = aggregate_qualified_local_dkg(2, packets, qualified)
        second = aggregate_qualified_local_dkg(2, packets, qualified)
        self.assertEqual(first, second)
        self.assertEqual(packets, snapshot)


class AggregateQualifiedLocalDKGRejectionTest(unittest.TestCase):
    def setUp(self):
        self.contributions = make_contributions()

    def test_tampered_share_produces_rejection(self):
        packets = qualified_packets(self.contributions, 2, (1, 3))
        packets[0] = tamper_share(packets[0])
        outcome = aggregate_qualified_local_dkg(2, packets, (1, 3))
        self.assertEqual(outcome, [DKGRejection(sender_id=1)])

    def test_all_failures_listed_sorted_and_deduplicated(self):
        packets = qualified_packets(self.contributions, 2, (1, 2, 3))
        packets[2] = tamper_share(packets[2])
        packets[0] = tamper_share(packets[0])
        outcome = aggregate_qualified_local_dkg(2, packets, (1, 2, 3))
        self.assertEqual(
            outcome,
            [DKGRejection(sender_id=1), DKGRejection(sender_id=3)],
        )

    def test_rejection_returns_no_partial_result(self):
        packets = qualified_packets(self.contributions, 2, (1, 2))
        packets[0] = tamper_share(packets[0])
        outcome = aggregate_qualified_local_dkg(2, packets, (1, 2))
        self.assertNotIsInstance(outcome, tuple)
        self.assertIsInstance(outcome, list)

    def test_full_set_rejections_equal_aggregate_local_dkg_by_value(self):
        packets = packets_for(self.contributions, 2)
        packets[0] = tamper_share(packets[0])
        packets[2] = tamper_share(packets[2])
        self.assertEqual(
            aggregate_qualified_local_dkg(2, packets, (1, 2, 3)),
            aggregate_local_dkg(2, packets),
        )


class AggregateQualifiedLocalDKGTypeErrorTest(unittest.TestCase):
    def setUp(self):
        self.packets = qualified_packets(self._contributions(), 2, (1, 2))

    def _contributions(self):
        return make_contributions()

    def test_receiver_id_type(self):
        for bad in ("2", 2.0, None, True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                aggregate_qualified_local_dkg(bad, self.packets, (1, 2))

    def test_qualified_ids_must_be_tuple(self):
        for bad in ([1, 2], {1, 2}, (x for x in (1, 2))):
            with self.assertRaises(TypeError, msg=repr(bad)):
                aggregate_qualified_local_dkg(2, self.packets, bad)

    def test_qualified_id_types(self):
        for bad in ((1, "2"), (1, 2.0), (True, 2), (1, False), (None,)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                aggregate_qualified_local_dkg(2, self.packets, bad)

    def test_packet_element_types(self):
        for bad in ("packet", 7, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                aggregate_qualified_local_dkg(2, [bad, self.packets[1]], (1, 2))

    def test_nested_packet_field_types_still_raise_type_error(self):
        packet = self.packets[0]
        broken = dataclasses.replace(packet, participant_ids=[1, 2, 3])
        with self.assertRaises(TypeError):
            aggregate_qualified_local_dkg(2, [broken, self.packets[1]], (1, 2))


class AggregateQualifiedLocalDKGValueErrorTest(unittest.TestCase):
    def setUp(self):
        self.contributions = make_contributions()

    def packets(self, receiver_id, qualified):
        return qualified_packets(self.contributions, receiver_id, qualified)

    def test_empty_batch(self):
        with self.assertRaises(ValueError):
            aggregate_qualified_local_dkg(2, [], (1, 2))

    def test_empty_qualified_set(self):
        with self.assertRaises(ValueError):
            aggregate_qualified_local_dkg(2, self.packets(2, (1,)), ())

    def test_non_increasing_or_duplicate_qualified_ids(self):
        for bad in ((2, 1), (1, 1), (3, 2, 1)):
            with self.assertRaises(ValueError, msg=repr(bad)):
                aggregate_qualified_local_dkg(
                    2, self.packets(2, tuple(sorted(bad))), bad
                )

    def test_qualified_id_outside_participant_set(self):
        for bad in ((0, 1), (1, 4), (FIELD_PRIME,)):
            with self.assertRaises(ValueError, msg=repr(bad)):
                aggregate_qualified_local_dkg(
                    2, self.packets(2, (1, 2)), bad
                )

    def test_fewer_than_threshold_qualified(self):
        with self.assertRaises(ValueError):
            aggregate_qualified_local_dkg(2, self.packets(2, (1,)), (1,))
        contributions = make_contributions((1, 2, 3), 3)
        with self.assertRaises(ValueError):
            aggregate_qualified_local_dkg(
                2, qualified_packets(contributions, 2, (1, 2)), (1, 2)
            )

    def test_missing_packet_for_qualified_member(self):
        with self.assertRaises(ValueError):
            aggregate_qualified_local_dkg(2, self.packets(2, (1,)), (1, 2))

    def test_duplicate_packet_sender(self):
        packets = self.packets(2, (1, 2))
        with self.assertRaises(ValueError):
            aggregate_qualified_local_dkg(
                2, [packets[0], packets[0]], (1, 2)
            )

    def test_extra_sender_outside_qualified_set(self):
        packets = self.packets(2, (1, 2, 3))
        with self.assertRaises(ValueError):
            aggregate_qualified_local_dkg(2, packets, (1, 2))
        with self.assertRaises(ValueError):
            aggregate_qualified_local_dkg(2, packets, (2, 3))

    def test_receiver_not_a_participant(self):
        for bad in (4, 0, FIELD_PRIME):
            with self.assertRaises(ValueError, msg=repr(bad)):
                aggregate_qualified_local_dkg(
                    bad, self.packets(2, (1, 2)), (1, 2)
                )

    def test_packet_not_addressed_to_receiver(self):
        packets = self.packets(2, (1, 2))
        foreign = packets_for(self.contributions, 1)
        with self.assertRaises(ValueError):
            aggregate_qualified_local_dkg(
                2, [foreign[0], packets[1]], (1, 2)
            )

    def test_packets_disagree_on_participant_ids(self):
        other_contributions = make_contributions(participant_ids=(1, 2, 4))
        foreign = packet_for(other_contributions[1], 2)
        packets = self.packets(2, (2,))
        with self.assertRaises(ValueError):
            aggregate_qualified_local_dkg(
                2, [packets[0], foreign], (1, 2)
            )

    def test_packets_disagree_on_threshold(self):
        other = make_contributions(threshold=3)
        foreign = packet_for(other[1], 2)
        packets = self.packets(2, (2,))
        with self.assertRaises(ValueError):
            aggregate_qualified_local_dkg(
                2, [packets[0], foreign], (1, 2)
            )

    def test_packets_disagree_on_group_parameters(self):
        packets = self.packets(2, (1, 2))
        moved = dataclasses.replace(
            packets[1],
            commitment=dataclasses.replace(
                packets[1].commitment, blinding_generator=4096
            ),
        )
        with self.assertRaises(ValueError):
            aggregate_qualified_local_dkg(2, [packets[0], moved], (1, 2))

    def test_illegal_commitment_value_raises_value_error(self):
        packets = self.packets(2, (1, 2))
        commitment = packets[0].commitment
        broken = dataclasses.replace(
            packets[0],
            commitment=dataclasses.replace(
                commitment, values=(0,) + commitment.values[1:]
            ),
        )
        with self.assertRaises(ValueError):
            aggregate_qualified_local_dkg(2, [broken, packets[1]], (1, 2))


if __name__ == "__main__":
    unittest.main()
