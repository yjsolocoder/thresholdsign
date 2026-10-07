"""Tests for the receiver-local DKG pre-aggregation diagnoser."""

import copy
import dataclasses
import unittest

from thresholdsign import (
    ContributionFault,
    DKGRejection,
    DKGReceivedShare,
    LocalDKGPacket,
    Share,
    aggregate_local_dkg,
    create_signing_contribution,
    diagnose_local_dkg,
    diagnose_signing_contributions,
)

# Same toy group as the local DKG tests: 8069 = 4 * 2017 + 1 is prime, 16
# and 256 = 16 ** 2 are distinct generators of the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

PARTICIPANT_IDS = (1, 2, 3)
THRESHOLD = 2
RECEIVER = 2


def fixed_random(seed=1):
    """Deterministic stand-in for secrets.randbelow (same LCG as DKG tests)."""
    state = {"value": seed}

    def randbelow(upper: int) -> int:
        state["value"] = (
            state["value"] * 6364136223846793005 + 1442695040888963407
        ) % upper
        return state["value"]

    return randbelow


def zero_random():
    """Deterministic source that draws only zeros (all-zero polynomials)."""
    return lambda upper: 0


def make_contributions(participant_ids=PARTICIPANT_IDS, threshold=THRESHOLD, randbelow=None):
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


def make_packets(receiver_id=RECEIVER, participant_ids=PARTICIPANT_IDS,
                 threshold=THRESHOLD, randbelow=None):
    contributions = make_contributions(participant_ids, threshold, randbelow)
    return [packet_for(contribution, receiver_id) for contribution in contributions]


def tamper_sharing_share(packet):
    """Break the received sharing share (Pedersen and Feldman both fail)."""
    received = packet.received
    share = received.share
    tampered = dataclasses.replace(
        received, share=Share(share.x, (share.y + 1) % FIELD_PRIME)
    )
    return dataclasses.replace(packet, received=tampered)


def tamper_blinding_share(packet):
    """Break the received blinding share (Pedersen only; Feldman passes)."""
    received = packet.received
    share = received.blinding_share
    tampered = dataclasses.replace(
        received, blinding_share=Share(share.x, (share.y + 1) % FIELD_PRIME)
    )
    return dataclasses.replace(packet, received=tampered)


class DiagnoseLocalDKGSuccessTest(unittest.TestCase):
    def test_valid_batch_returns_empty_tuple(self):
        faults = diagnose_local_dkg(RECEIVER, make_packets())
        self.assertEqual(faults, ())
        self.assertIsInstance(faults, tuple)

    def test_empty_faults_exactly_when_local_aggregation_succeeds(self):
        packets = make_packets()
        self.assertIsInstance(aggregate_local_dkg(RECEIVER, list(packets)), tuple)
        self.assertEqual(diagnose_local_dkg(RECEIVER, packets), ())

    def test_every_receiver_of_a_valid_batch_diagnoses_clean(self):
        contributions = make_contributions()
        for receiver_id in PARTICIPANT_IDS:
            packets = [packet_for(c, receiver_id) for c in contributions]
            self.assertEqual(diagnose_local_dkg(receiver_id, packets), ())

    def test_threshold_one(self):
        packets = make_packets(threshold=1)
        self.assertEqual(diagnose_local_dkg(RECEIVER, packets), ())

    def test_zero_shares_and_identity_commitments(self):
        packets = make_packets(randbelow=zero_random())
        self.assertEqual(diagnose_local_dkg(RECEIVER, packets), ())

    def test_single_participant(self):
        packets = make_packets(receiver_id=5, participant_ids=(5,), threshold=1)
        self.assertEqual(diagnose_local_dkg(5, packets), ())

    def test_accepts_single_pass_iterator(self):
        self.assertEqual(diagnose_local_dkg(RECEIVER, iter(make_packets())), ())
        again = (packet for packet in make_packets())
        self.assertEqual(diagnose_local_dkg(RECEIVER, again), ())

    def test_input_order_does_not_matter(self):
        packets = make_packets()
        forward = diagnose_local_dkg(RECEIVER, packets)
        self.assertEqual(diagnose_local_dkg(RECEIVER, list(reversed(packets))), forward)
        self.assertEqual(
            diagnose_local_dkg(RECEIVER, [packets[1], packets[2], packets[0]]),
            forward,
        )


class DiagnoseLocalDKGFaultTest(unittest.TestCase):
    def setUp(self):
        self.packets = make_packets()

    def test_tampered_blinding_share_is_pedersen_fault_only(self):
        bad = tamper_blinding_share(self.packets[0])
        faults = diagnose_local_dkg(RECEIVER, [bad, *self.packets[1:]])
        self.assertEqual(faults, (ContributionFault(1, RECEIVER, "pedersen"),))

    def test_tampered_sharing_share_is_both_faults_pedersen_first(self):
        bad = tamper_sharing_share(self.packets[1])
        faults = diagnose_local_dkg(
            RECEIVER, [self.packets[0], bad, self.packets[2]]
        )
        self.assertEqual(
            faults,
            (
                ContributionFault(2, RECEIVER, "pedersen"),
                ContributionFault(2, RECEIVER, "feldman"),
            ),
        )

    def test_unbound_feldman_commitment_is_feldman_fault_only(self):
        # Another sender's (structurally legal) Feldman commitment no longer
        # binds the received share, while the Pedersen pairing still holds.
        bad = dataclasses.replace(
            self.packets[0], feldman_commitment=self.packets[1].feldman_commitment
        )
        faults = diagnose_local_dkg(RECEIVER, [bad, *self.packets[1:]])
        self.assertEqual(faults, (ContributionFault(1, RECEIVER, "feldman"),))

    def test_one_failure_does_not_mask_the_other_check_or_other_senders(self):
        bad_first = tamper_sharing_share(self.packets[0])
        bad_third = tamper_blinding_share(self.packets[2])
        faults = diagnose_local_dkg(
            RECEIVER, [bad_third, self.packets[1], bad_first]
        )
        self.assertEqual(
            faults,
            (
                ContributionFault(1, RECEIVER, "pedersen"),
                ContributionFault(1, RECEIVER, "feldman"),
                ContributionFault(3, RECEIVER, "pedersen"),
            ),
        )

    def test_faults_sorted_by_sender_regardless_of_input_order(self):
        bad_first = tamper_sharing_share(self.packets[0])
        bad_third = tamper_sharing_share(self.packets[2])
        expected = (
            ContributionFault(1, RECEIVER, "pedersen"),
            ContributionFault(1, RECEIVER, "feldman"),
            ContributionFault(3, RECEIVER, "pedersen"),
            ContributionFault(3, RECEIVER, "feldman"),
        )
        self.assertEqual(
            diagnose_local_dkg(RECEIVER, [bad_first, self.packets[1], bad_third]),
            expected,
        )
        self.assertEqual(
            diagnose_local_dkg(RECEIVER, [bad_third, self.packets[1], bad_first]),
            expected,
        )

    def test_deduplicated_fault_senders_match_aggregator_rejections(self):
        bad_first = tamper_sharing_share(self.packets[0])
        bad_third = tamper_blinding_share(self.packets[2])
        packets = [bad_first, self.packets[1], bad_third]
        outcome = aggregate_local_dkg(RECEIVER, list(packets))
        self.assertEqual(
            outcome, [DKGRejection(sender_id=1), DKGRejection(sender_id=3)]
        )
        faults = diagnose_local_dkg(RECEIVER, packets)
        senders = []
        for fault in faults:
            if fault.sender_id not in senders:
                senders.append(fault.sender_id)
        self.assertEqual(
            senders, [rejection.sender_id for rejection in outcome]
        )

    def test_receiver_id_in_faults_is_the_target(self):
        contributions = make_contributions()
        packets = [packet_for(c, 3) for c in contributions]
        bad = tamper_sharing_share(packets[1])
        faults = diagnose_local_dkg(3, [packets[0], bad, packets[2]])
        self.assertEqual(
            faults,
            (
                ContributionFault(2, 3, "pedersen"),
                ContributionFault(2, 3, "feldman"),
            ),
        )

    def test_matches_full_contribution_diagnosis_for_the_receiver(self):
        contributions = make_contributions()
        # Damage one position addressed to RECEIVER and one addressed
        # elsewhere; only the receiver's own records may show up locally.
        dealing = contributions[1].contribution
        own_index = dealing.participant_ids.index(RECEIVER)
        other_index = (own_index + 1) % len(dealing.participant_ids)
        damaged = contributions[1]
        for index in (own_index, other_index):
            share = damaged.contribution.shares[index]
            damaged = dataclasses.replace(
                damaged,
                contribution=dataclasses.replace(
                    damaged.contribution,
                    shares=damaged.contribution.shares[:index]
                    + (Share(share.x, (share.y + 1) % FIELD_PRIME),)
                    + damaged.contribution.shares[index + 1:],
                ),
            )
        batch = [contributions[0], damaged, contributions[2]]
        full = diagnose_signing_contributions(batch)
        packets = [packet_for(c, RECEIVER) for c in batch]
        local = diagnose_local_dkg(RECEIVER, packets)
        self.assertEqual(
            local, tuple(f for f in full if f.receiver_id == RECEIVER)
        )
        self.assertEqual(
            local,
            (
                ContributionFault(2, RECEIVER, "pedersen"),
                ContributionFault(2, RECEIVER, "feldman"),
            ),
        )


class DiagnoseLocalDKGValidationTest(unittest.TestCase):
    def setUp(self):
        self.packets = make_packets()

    def assert_aggregator_and_diagnoser_raise(self, receiver_id, packets, error):
        with self.assertRaises(error):
            aggregate_local_dkg(receiver_id, list(packets))
        with self.assertRaises(error):
            diagnose_local_dkg(receiver_id, packets)

    def test_receiver_id_type(self):
        for bad in ("2", 2.0, None, True, False):
            with self.assertRaises(TypeError, msg=repr(bad)):
                diagnose_local_dkg(bad, self.packets)

    def test_non_iterable_packets(self):
        for bad in (7, None, True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                diagnose_local_dkg(RECEIVER, bad)

    def test_non_packet_elements(self):
        for bad in ("packet", 7, self.packets[0].received, self.packets):
            with self.assertRaises(TypeError, msg=repr(bad)):
                diagnose_local_dkg(RECEIVER, [bad])

    def test_nested_field_types(self):
        packet = self.packets[0]
        with self.assertRaises(TypeError):
            diagnose_local_dkg(
                RECEIVER, [dataclasses.replace(packet, participant_ids=[1, 2, 3])]
            )
        with self.assertRaises(TypeError):
            diagnose_local_dkg(
                RECEIVER,
                [dataclasses.replace(packet, participant_ids=(1, 2, True))],
            )
        with self.assertRaises(TypeError):
            diagnose_local_dkg(
                RECEIVER, [dataclasses.replace(packet, received="x")]
            )
        broken_received = dataclasses.replace(packet.received, sender_id=True)
        with self.assertRaises(TypeError):
            diagnose_local_dkg(
                RECEIVER, [dataclasses.replace(packet, received=broken_received)]
            )
        broken_share = dataclasses.replace(
            packet.received, share=Share(x=RECEIVER, y=False)
        )
        with self.assertRaises(TypeError):
            diagnose_local_dkg(
                RECEIVER, [dataclasses.replace(packet, received=broken_share)]
            )
        with self.assertRaises(TypeError):
            diagnose_local_dkg(
                RECEIVER, [dataclasses.replace(packet, commitment="c")]
            )
        with self.assertRaises(TypeError):
            diagnose_local_dkg(
                RECEIVER, [dataclasses.replace(packet, feldman_commitment=None)]
            )

    def test_empty_batch(self):
        self.assert_aggregator_and_diagnoser_raise(RECEIVER, [], ValueError)

    def test_empty_participant_ids(self):
        packet = dataclasses.replace(self.packets[0], participant_ids=())
        self.assert_aggregator_and_diagnoser_raise(RECEIVER, [packet], ValueError)

    def test_non_increasing_participant_ids(self):
        for ids in ((2, 1, 3), (1, 1, 2)):
            packet = dataclasses.replace(self.packets[0], participant_ids=ids)
            self.assert_aggregator_and_diagnoser_raise(
                RECEIVER, [packet], ValueError
            )

    def test_participant_id_out_of_range(self):
        for ids in ((0, 1, 2), (1, 2, FIELD_PRIME)):
            packet = dataclasses.replace(self.packets[0], participant_ids=ids)
            self.assert_aggregator_and_diagnoser_raise(
                RECEIVER, [packet], ValueError
            )

    def test_receiver_not_a_participant(self):
        for bad in (4, 0, FIELD_PRIME):
            self.assert_aggregator_and_diagnoser_raise(
                bad, self.packets, ValueError
            )

    def test_sender_not_a_participant(self):
        packet = self.packets[0]
        broken = dataclasses.replace(packet.received, sender_id=4)
        self.assert_aggregator_and_diagnoser_raise(
            RECEIVER, [dataclasses.replace(packet, received=broken)], ValueError
        )

    def test_duplicate_sender(self):
        packets = [self.packets[0], self.packets[0], self.packets[2]]
        self.assert_aggregator_and_diagnoser_raise(RECEIVER, packets, ValueError)

    def test_missing_sender(self):
        self.assert_aggregator_and_diagnoser_raise(
            RECEIVER, self.packets[:2], ValueError
        )

    def test_receiver_id_mismatch(self):
        packet = self.packets[0]
        broken = dataclasses.replace(packet.received, receiver_id=1)
        self.assert_aggregator_and_diagnoser_raise(
            RECEIVER, [dataclasses.replace(packet, received=broken)], ValueError
        )

    def test_share_coordinate_mismatch(self):
        packet = self.packets[0]
        received = packet.received
        for field in ("share", "blinding_share"):
            original = getattr(received, field)
            broken = dataclasses.replace(
                received, **{field: Share(x=1, y=original.y)}
            )
            self.assert_aggregator_and_diagnoser_raise(
                RECEIVER,
                [dataclasses.replace(packet, received=broken)],
                ValueError,
            )

    def test_share_value_out_of_range(self):
        packet = self.packets[0]
        received = packet.received
        for bad_y in (-1, FIELD_PRIME):
            broken = dataclasses.replace(
                received, share=Share(x=received.share.x, y=bad_y)
            )
            self.assert_aggregator_and_diagnoser_raise(
                RECEIVER,
                [dataclasses.replace(packet, received=broken)],
                ValueError,
            )

    def test_threshold_out_of_range(self):
        packet = self.packets[0]
        commitment = packet.commitment
        feldman = packet.feldman_commitment
        empty = dataclasses.replace(
            packet,
            commitment=dataclasses.replace(commitment, values=()),
            feldman_commitment=dataclasses.replace(feldman, values=()),
        )
        self.assert_aggregator_and_diagnoser_raise(RECEIVER, [empty], ValueError)
        too_long = (1,) * 4
        over = dataclasses.replace(
            packet,
            commitment=dataclasses.replace(commitment, values=too_long),
            feldman_commitment=dataclasses.replace(feldman, values=too_long),
        )
        self.assert_aggregator_and_diagnoser_raise(RECEIVER, [over], ValueError)

    def test_commitment_threshold_mismatch(self):
        packet = self.packets[0]
        broken = dataclasses.replace(
            packet,
            feldman_commitment=dataclasses.replace(
                packet.feldman_commitment,
                values=packet.feldman_commitment.values + (1,),
            ),
        )
        self.assert_aggregator_and_diagnoser_raise(RECEIVER, [broken], ValueError)

    def test_commitment_group_mismatch(self):
        packet = self.packets[0]
        broken = dataclasses.replace(
            packet,
            feldman_commitment=dataclasses.replace(
                packet.feldman_commitment, generator=BLINDING_GENERATOR
            ),
        )
        self.assert_aggregator_and_diagnoser_raise(RECEIVER, [broken], ValueError)

    def test_illegal_group_parameters(self):
        packet = self.packets[0]
        commitment = packet.commitment
        feldman = packet.feldman_commitment
        for broken_commitment in (
            dataclasses.replace(commitment, field_prime=4),
            dataclasses.replace(commitment, generator=1),
            dataclasses.replace(commitment, blinding_generator=GENERATOR),
        ):
            broken = dataclasses.replace(
                packet,
                commitment=broken_commitment,
                feldman_commitment=dataclasses.replace(
                    feldman,
                    field_prime=broken_commitment.field_prime,
                    group_prime=broken_commitment.group_prime,
                    generator=broken_commitment.generator,
                ),
            )
            self.assert_aggregator_and_diagnoser_raise(
                RECEIVER, [broken], ValueError
            )

    def test_commitment_value_out_of_range_or_subgroup(self):
        packet = self.packets[0]
        commitment = packet.commitment
        for bad_value in (0, GROUP_PRIME, 2):
            broken = dataclasses.replace(
                packet,
                commitment=dataclasses.replace(
                    commitment, values=(bad_value,) + commitment.values[1:]
                ),
            )
            self.assert_aggregator_and_diagnoser_raise(
                RECEIVER, [broken], ValueError
            )

    def test_packets_disagree_on_participant_ids(self):
        other = make_packets(participant_ids=(1, 2, 4))
        self.assert_aggregator_and_diagnoser_raise(
            RECEIVER,
            [self.packets[0], other[1], self.packets[2]],
            ValueError,
        )

    def test_packets_disagree_on_group_parameters(self):
        packet = self.packets[1]
        # 4096 = 16 ** 3 mod 8069 is another legal subgroup generator.
        moved = dataclasses.replace(
            packet,
            commitment=dataclasses.replace(
                packet.commitment, blinding_generator=4096
            ),
        )
        self.assert_aggregator_and_diagnoser_raise(
            RECEIVER,
            [self.packets[0], moved, self.packets[2]],
            ValueError,
        )

    def test_packets_disagree_on_threshold(self):
        other = make_packets(threshold=3)
        self.assert_aggregator_and_diagnoser_raise(
            RECEIVER,
            [self.packets[0], other[1], self.packets[2]],
            ValueError,
        )

    def test_structural_error_rejects_whole_call_without_partial_faults(self):
        # A tampered (faulty) packet plus a structurally illegal packet must
        # raise, never return the tampered packet's fault records.
        bad = tamper_sharing_share(self.packets[0])
        illegal = dataclasses.replace(self.packets[2], participant_ids=())
        with self.assertRaises(ValueError):
            diagnose_local_dkg(RECEIVER, [bad, self.packets[1], illegal])


class DiagnoseLocalDKGNoMutationTest(unittest.TestCase):
    def setUp(self):
        self.packets = make_packets()

    def test_input_unchanged_on_success(self):
        packets = self.packets
        snapshot = copy.deepcopy(packets)
        diagnose_local_dkg(RECEIVER, packets)
        self.assertEqual(packets, snapshot)

    def test_input_unchanged_with_faults(self):
        packets = [self.packets[0], tamper_sharing_share(self.packets[1]), self.packets[2]]
        snapshot = copy.deepcopy(packets)
        diagnose_local_dkg(RECEIVER, packets)
        self.assertEqual(packets, snapshot)

    def test_input_unchanged_on_value_error(self):
        packets = [self.packets[0], self.packets[0], self.packets[2]]
        snapshot = copy.deepcopy(packets)
        with self.assertRaises(ValueError):
            diagnose_local_dkg(RECEIVER, packets)
        self.assertEqual(packets, snapshot)

    def test_result_carries_no_secret_values(self):
        bad = tamper_sharing_share(self.packets[1])
        faults = diagnose_local_dkg(RECEIVER, [self.packets[0], bad, self.packets[2]])
        for fault in faults:
            self.assertEqual(
                [field.name for field in dataclasses.fields(fault)],
                ["sender_id", "receiver_id", "check"],
            )


if __name__ == "__main__":
    unittest.main()
