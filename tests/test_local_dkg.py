"""Tests for LocalDKGPacket and aggregate_local_dkg."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    DKGReceivedShare,
    DKGRejection,
    LocalDKGPacket,
    Share,
    SigningDKGResult,
    SigningRoundPacket,
    aggregate_local_dkg,
    aggregate_signature,
    aggregate_signing_dkg,
    create_signing_contribution,
    export_signing_public_context,
    sign_round_packet,
    verify_signature,
)
from tests.test_signing import (
    BLINDING_GENERATOR,
    FIELD_PRIME,
    GENERATOR,
    GROUP_PRIME,
    MESSAGE,
    fixed_random,
    make_round,
    make_signing_contributions,
    make_signing_dkg,
)


def make_packets(receiver_id, contributions):
    """The LocalDKGPacket list ``receiver_id`` extracts from the contributions."""
    packets = []
    for contribution in contributions:
        dealing = contribution.contribution
        index = dealing.participant_ids.index(receiver_id)
        packets.append(
            LocalDKGPacket(
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
        )
    return packets


def make_contributions(participant_ids=(1, 2, 3), threshold=2, **kwargs):
    return make_signing_contributions(participant_ids, threshold, **kwargs)


class LocalDKGPacketTest(unittest.TestCase):
    def setUp(self):
        self.contributions = make_contributions()
        self.packet = make_packets(2, self.contributions)[0]

    def test_fields_in_order(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(self.packet)],
            ["participant_ids", "received", "commitment", "feldman_commitment"],
        )
        self.assertEqual(self.packet.participant_ids, (1, 2, 3))
        self.assertIsInstance(self.packet.received, DKGReceivedShare)
        self.assertEqual(self.packet.received.receiver_id, 2)

    def test_positional_construction_and_value_equality(self):
        other = make_packets(2, make_contributions())[0]
        self.assertEqual(self.packet, other)
        rebuilt = LocalDKGPacket(
            self.packet.participant_ids,
            self.packet.received,
            self.packet.commitment,
            self.packet.feldman_commitment,
        )
        self.assertEqual(self.packet, rebuilt)
        different = make_packets(3, self.contributions)[0]
        self.assertNotEqual(self.packet, different)

    def test_frozen(self):
        with self.assertRaises(FrozenInstanceError):
            self.packet.participant_ids = ()  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            self.packet.received = None  # type: ignore[misc]


class AggregateLocalDkgTest(unittest.TestCase):
    def setUp(self):
        self.participant_ids = (1, 2, 3)
        self.contributions = make_contributions()
        self.key = aggregate_signing_dkg(self.contributions)
        assert isinstance(self.key, SigningDKGResult)

    def test_success_matches_full_aggregation_for_every_member(self):
        context = export_signing_public_context(self.key)
        for index, receiver_id in enumerate(self.participant_ids):
            outcome = aggregate_local_dkg(
                receiver_id, make_packets(receiver_id, self.contributions)
            )
            self.assertIsInstance(outcome, tuple)
            share, blinding_share, local_context = outcome
            self.assertEqual(share, self.key.result.shares[index])
            self.assertEqual(blinding_share, self.key.result.blinding_shares[index])
            self.assertEqual(share.x, receiver_id)
            self.assertEqual(blinding_share.x, receiver_id)
            self.assertEqual(local_context, context)

    def test_context_has_no_secret_material(self):
        _share, _blinding, context = aggregate_local_dkg(
            2, make_packets(2, self.contributions)
        )
        self.assertEqual(context.threshold, 2)
        self.assertEqual(context.participant_ids, (1, 2, 3))
        self.assertEqual(
            (context.field_prime, context.group_prime, context.generator),
            (FIELD_PRIME, GROUP_PRIME, GENERATOR),
        )

    def test_input_order_does_not_affect_result(self):
        packets = make_packets(1, self.contributions)
        shuffled = [packets[2], packets[0], packets[1]]
        self.assertEqual(
            aggregate_local_dkg(1, packets), aggregate_local_dkg(1, shuffled)
        )
        self.assertEqual(
            aggregate_local_dkg(1, packets),
            aggregate_local_dkg(1, list(reversed(packets))),
        )

    def test_single_pass_iterator(self):
        packets = make_packets(3, self.contributions)
        outcome = aggregate_local_dkg(3, iter(packets))
        self.assertIsInstance(outcome, tuple)
        self.assertEqual(outcome, aggregate_local_dkg(3, packets))

    def test_threshold_one(self):
        contributions = make_contributions((1, 2), threshold=1)
        key = aggregate_signing_dkg(contributions)
        assert isinstance(key, SigningDKGResult)
        for index, receiver_id in enumerate((1, 2)):
            share, blinding_share, context = aggregate_local_dkg(
                receiver_id, make_packets(receiver_id, contributions)
            )
            self.assertEqual(share, key.result.shares[index])
            self.assertEqual(blinding_share, key.result.blinding_shares[index])
            self.assertEqual(context, export_signing_public_context(key))
            self.assertEqual(context.threshold, 1)

    def test_all_zero_contributions(self):
        # Rebuild each contribution with an all-zero randbelow source: every
        # share is zero and every commitment value is the group identity.
        contributions = [
            create_signing_contribution(
                pid,
                (1, 2, 3),
                2,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
                blinding_generator=BLINDING_GENERATOR,
                randbelow=lambda upper: 0,
            )
            for pid in (1, 2, 3)
        ]
        key = aggregate_signing_dkg(contributions)
        assert isinstance(key, SigningDKGResult)
        share, blinding_share, context = aggregate_local_dkg(
            2, make_packets(2, contributions)
        )
        self.assertEqual(share, Share(2, 0))
        self.assertEqual(blinding_share, Share(2, 0))
        self.assertEqual(context.public_key, 1)
        self.assertEqual(context.verification_shares, (1, 1, 1))
        self.assertEqual(context, export_signing_public_context(key))

    def test_non_sequential_participant_ids(self):
        contributions = make_contributions((2, 5, 7), 2)
        key = aggregate_signing_dkg(contributions)
        assert isinstance(key, SigningDKGResult)
        for index, receiver_id in enumerate((2, 5, 7)):
            share, blinding_share, context = aggregate_local_dkg(
                receiver_id, make_packets(receiver_id, contributions)
            )
            self.assertEqual(share, key.result.shares[index])
            self.assertEqual(blinding_share, key.result.blinding_shares[index])
            self.assertEqual(context, export_signing_public_context(key))

    def test_local_result_completes_a_signing_round(self):
        # Each member aggregates locally; the local shares and context drive
        # sign_round_packet to a valid threshold signature.
        context = export_signing_public_context(self.key)
        round_info, _commitments, nonces = make_round(self.key, (1, 2), MESSAGE)
        packet = SigningRoundPacket(context=context, round_info=round_info)
        shares = []
        for signer_id in (1, 2):
            share, _blinding, local_context = aggregate_local_dkg(
                signer_id, make_packets(signer_id, self.contributions)
            )
            signature_share = sign_round_packet(
                signer_id, share.y, nonces[signer_id], packet, local_context, MESSAGE
            )
            shares.append(signature_share)
        signature = aggregate_signature(shares, round_info, context)
        self.assertEqual(signature.signer_ids, (1, 2))
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

    def test_input_not_mutated(self):
        packets = make_packets(2, self.contributions)
        snapshot = list(packets)
        aggregate_local_dkg(2, packets)
        self.assertEqual(packets, snapshot)


class AggregateLocalDkgRejectionTest(unittest.TestCase):
    def setUp(self):
        self.contributions = make_contributions()

    def packets(self, receiver_id=2):
        return make_packets(receiver_id, self.contributions)

    def test_tampered_share_yields_rejection_naming_sender(self):
        packets = self.packets()
        bad = packets[1]
        tampered_received = dataclasses.replace(
            bad.received,
            share=Share(bad.received.share.x, (bad.received.share.y + 1) % FIELD_PRIME),
        )
        packets[1] = dataclasses.replace(bad, received=tampered_received)
        outcome = aggregate_local_dkg(2, packets)
        self.assertIsInstance(outcome, list)
        self.assertEqual(outcome, [DKGRejection(sender_id=2)])

    def test_tampered_blinding_share_yields_rejection(self):
        packets = self.packets()
        bad = packets[0]
        tampered_received = dataclasses.replace(
            bad.received,
            blinding_share=Share(
                bad.received.blinding_share.x,
                (bad.received.blinding_share.y + 1) % FIELD_PRIME,
            ),
        )
        packets[0] = dataclasses.replace(bad, received=tampered_received)
        self.assertEqual(aggregate_local_dkg(2, packets), [DKGRejection(sender_id=1)])

    def test_feldman_mismatch_yields_rejection_not_error(self):
        packets = self.packets()
        bad = packets[2]
        other_feldman = make_contributions(seed_base=100)[2].feldman_commitment
        packets[2] = dataclasses.replace(bad, feldman_commitment=other_feldman)
        outcome = aggregate_local_dkg(2, packets)
        self.assertEqual(outcome, [DKGRejection(sender_id=3)])

    def test_every_failing_sender_is_reported_sorted_and_deduplicated(self):
        packets = self.packets()
        for position in (0, 2):
            bad = packets[position]
            tampered_received = dataclasses.replace(
                bad.received,
                share=Share(
                    bad.received.share.x, (bad.received.share.y + 1) % FIELD_PRIME
                ),
            )
            packets[position] = dataclasses.replace(bad, received=tampered_received)
        # A sender failing both the Pedersen and the Feldman check appears once.
        self.assertEqual(
            aggregate_local_dkg(2, packets),
            [DKGRejection(sender_id=1), DKGRejection(sender_id=3)],
        )
        self.assertEqual(
            aggregate_local_dkg(2, list(reversed(packets))),
            [DKGRejection(sender_id=1), DKGRejection(sender_id=3)],
        )

    def test_rejection_returns_no_partial_result(self):
        packets = self.packets()
        bad = packets[1]
        tampered_received = dataclasses.replace(
            bad.received,
            share=Share(bad.received.share.x, (bad.received.share.y + 1) % FIELD_PRIME),
        )
        packets[1] = dataclasses.replace(bad, received=tampered_received)
        outcome = aggregate_local_dkg(2, packets)
        self.assertIsInstance(outcome, list)
        self.assertNotIsInstance(outcome, tuple)


class AggregateLocalDkgValidationTest(unittest.TestCase):
    def setUp(self):
        self.contributions = make_contributions()

    def packets(self, receiver_id=2):
        return make_packets(receiver_id, self.contributions)

    def test_empty_input_rejected(self):
        with self.assertRaises(ValueError):
            aggregate_local_dkg(2, [])

    def test_missing_sender_rejected(self):
        with self.assertRaises(ValueError):
            aggregate_local_dkg(2, self.packets()[:2])

    def test_duplicate_sender_rejected(self):
        packets = self.packets()
        with self.assertRaises(ValueError):
            aggregate_local_dkg(2, [packets[0], packets[0], packets[2]])

    def test_sender_outside_participants_rejected(self):
        packets = self.packets()
        bad = packets[0]
        moved = dataclasses.replace(
            bad, received=dataclasses.replace(bad.received, sender_id=4)
        )
        with self.assertRaises(ValueError):
            aggregate_local_dkg(2, [moved] + packets[1:])

    def test_receiver_not_a_participant_rejected(self):
        with self.assertRaises(ValueError):
            aggregate_local_dkg(4, self.packets())

    def test_misaddressed_received_share_rejected(self):
        packets = self.packets()
        bad = packets[0]
        moved = dataclasses.replace(
            bad, received=dataclasses.replace(bad.received, receiver_id=1)
        )
        with self.assertRaises(ValueError):
            aggregate_local_dkg(2, [moved] + packets[1:])

    def test_share_coordinate_mismatch_rejected(self):
        packets = self.packets()
        bad = packets[0]
        moved = dataclasses.replace(
            bad,
            received=dataclasses.replace(
                bad.received,
                share=Share(1, bad.received.share.y),
                blinding_share=Share(1, bad.received.blinding_share.y),
            ),
        )
        with self.assertRaises(ValueError):
            aggregate_local_dkg(2, [moved] + packets[1:])

    def test_share_value_out_of_range_rejected(self):
        packets = self.packets()
        bad = packets[0]
        moved = dataclasses.replace(
            bad,
            received=dataclasses.replace(
                bad.received, share=Share(2, FIELD_PRIME)
            ),
        )
        with self.assertRaises(ValueError):
            aggregate_local_dkg(2, [moved] + packets[1:])

    def test_unsorted_participant_ids_rejected(self):
        packets = self.packets()
        bad = dataclasses.replace(packets[0], participant_ids=(2, 1, 3))
        with self.assertRaises(ValueError):
            aggregate_local_dkg(2, [bad] + packets[1:])

    def test_empty_participant_ids_rejected(self):
        packets = self.packets()
        bad = dataclasses.replace(packets[0], participant_ids=())
        with self.assertRaises(ValueError):
            aggregate_local_dkg(2, [bad] + packets[1:])

    def test_inconsistent_participant_ids_rejected(self):
        other = make_contributions((1, 2, 4), 2)
        packets = self.packets()[:2] + make_packets(2, other)[2:]
        with self.assertRaises(ValueError):
            aggregate_local_dkg(2, packets)

    def test_inconsistent_threshold_rejected(self):
        other = make_contributions((1, 2, 3), 3)
        packets = self.packets()[:2] + make_packets(2, other)[2:]
        with self.assertRaises(ValueError):
            aggregate_local_dkg(2, packets)

    def test_threshold_exceeding_participant_count_rejected(self):
        packets = self.packets()
        bad = packets[0]
        commitment = dataclasses.replace(
            bad.commitment,
            values=bad.commitment.values + (bad.commitment.values[0],),
        )
        feldman = dataclasses.replace(
            bad.feldman_commitment,
            values=bad.feldman_commitment.values
            + (bad.feldman_commitment.values[0],),
        )
        with self.assertRaises(ValueError):
            aggregate_local_dkg(
                2, [dataclasses.replace(bad, commitment=commitment, feldman_commitment=feldman)]
                + packets[1:]
            )

    def test_commitment_length_mismatch_rejected(self):
        packets = self.packets()
        bad = packets[0]
        feldman = dataclasses.replace(
            bad.feldman_commitment, values=bad.feldman_commitment.values[:1]
        )
        with self.assertRaises(ValueError):
            aggregate_local_dkg(
                2, [dataclasses.replace(bad, feldman_commitment=feldman)] + packets[1:]
            )

    def test_inconsistent_group_parameters_rejected(self):
        other = make_signing_contributions(
            (1, 2, 3),
            2,
            FIELD_PRIME,
            GROUP_PRIME,
            BLINDING_GENERATOR,
            GENERATOR,
        )
        packets = self.packets()[:2] + make_packets(2, other)[2:]
        with self.assertRaises(ValueError):
            aggregate_local_dkg(2, packets)

    def test_illegal_commitment_rejected(self):
        packets = self.packets()
        bad = packets[0]
        commitment = dataclasses.replace(bad.commitment, values=(0, 1))
        with self.assertRaises(ValueError):
            aggregate_local_dkg(
                2, [dataclasses.replace(bad, commitment=commitment)] + packets[1:]
            )

    def test_illegal_group_parameters_rejected(self):
        packets = self.packets()
        bad = packets[0]
        commitment = dataclasses.replace(bad.commitment, generator=1)
        with self.assertRaises(ValueError):
            aggregate_local_dkg(
                2, [dataclasses.replace(bad, commitment=commitment)] + packets[1:]
            )

    def test_wrong_types_raise_type_error(self):
        packets = self.packets()
        with self.assertRaises(TypeError):
            aggregate_local_dkg("2", packets)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            aggregate_local_dkg(True, packets)
        with self.assertRaises(TypeError):
            aggregate_local_dkg(2, ["not a packet"])  # type: ignore[list-item]
        with self.assertRaises(TypeError):
            aggregate_local_dkg(2, [packets[0], 2, packets[2]])  # type: ignore[list-item]
        bad = dataclasses.replace(packets[0], participant_ids=[1, 2, 3])
        with self.assertRaises(TypeError):
            aggregate_local_dkg(2, [bad] + packets[1:])
        bad = dataclasses.replace(packets[0], participant_ids=(1, True, 3))
        with self.assertRaises(TypeError):
            aggregate_local_dkg(2, [bad] + packets[1:])
        bad = dataclasses.replace(packets[0], received=(1, 2))
        with self.assertRaises(TypeError):
            aggregate_local_dkg(2, [bad] + packets[1:])
        bad = dataclasses.replace(
            packets[0],
            received=dataclasses.replace(packets[0].received, sender_id=True),
        )
        with self.assertRaises(TypeError):
            aggregate_local_dkg(2, [bad] + packets[1:])
        bad = dataclasses.replace(
            packets[0],
            received=dataclasses.replace(packets[0].received, share=(2, 3)),
        )
        with self.assertRaises(TypeError):
            aggregate_local_dkg(2, [bad] + packets[1:])
        bad = dataclasses.replace(packets[0], commitment="commitment")
        with self.assertRaises(TypeError):
            aggregate_local_dkg(2, [bad] + packets[1:])
        bad = dataclasses.replace(packets[0], feldman_commitment="feldman")
        with self.assertRaises(TypeError):
            aggregate_local_dkg(2, [bad] + packets[1:])
        bad = dataclasses.replace(
            packets[0],
            commitment=dataclasses.replace(
                packets[0].commitment, values=list(packets[0].commitment.values)
            ),
        )
        with self.assertRaises(TypeError):
            aggregate_local_dkg(2, [bad] + packets[1:])


if __name__ == "__main__":
    unittest.main()
