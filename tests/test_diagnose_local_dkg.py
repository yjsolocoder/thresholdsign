"""Tests for the receiver-local DKG diagnoser (diagnose_local_dkg)."""

import copy
import dataclasses
import itertools
import unittest

from thresholdsign import (
    ContributionFault,
    DKGReceivedShare,
    DKGRejection,
    FeldmanCommitment,
    LocalDKGPacket,
    PedersenCommitment,
    Share,
    SigningDKGResult,
    aggregate_local_dkg,
    aggregate_signing_dkg,
    create_signing_contribution,
    decode_local_dkg_packet,
    diagnose_local_dkg,
    diagnose_signing_contributions,
    encode_local_dkg_packet,
)

# Same toy Pedersen setup as the DKG, signing, refresh and reshare tests:
# 8069 = 4 * 2017 + 1 is prime, 16 and 256 = 16 ** 2 are distinct
# generators of the order-2017 subgroup of the multiplicative group mod 8069.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256


# Sentinel for the test helpers' "use the valid default" arguments.
_DEFAULT = object()


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


def packets_for(contributions, receiver_id):
    return [packet_for(contribution, receiver_id) for contribution in contributions]


def make_packets(receiver_id, participant_ids=(1, 2, 3), threshold=2, randbelow=None):
    return packets_for(
        make_contributions(participant_ids, threshold, randbelow), receiver_id
    )


def tamper_share(packet, delta=1):
    """Break the secret share (Pedersen and Feldman both fail)."""
    received = packet.received
    tampered = Share(x=received.share.x, y=(received.share.y + delta) % FIELD_PRIME)
    return dataclasses.replace(
        packet, received=dataclasses.replace(received, share=tampered)
    )


def tamper_blinding_share(packet, delta=1):
    """Break the blinding share (Pedersen only; Feldman passes)."""
    received = packet.received
    tampered = Share(
        x=received.blinding_share.x,
        y=(received.blinding_share.y + delta) % FIELD_PRIME,
    )
    return dataclasses.replace(
        packet, received=dataclasses.replace(received, blinding_share=tampered)
    )


def tamper_contribution_share(contribution, receiver_id, delta=1):
    """Break the secret share a contribution addresses to ``receiver_id``."""
    dealing = contribution.contribution
    index = dealing.participant_ids.index(receiver_id)
    shares = list(dealing.shares)
    shares[index] = Share(
        x=shares[index].x, y=(shares[index].y + delta) % FIELD_PRIME
    )
    return dataclasses.replace(
        contribution,
        contribution=dataclasses.replace(dealing, shares=tuple(shares)),
    )


def tamper_contribution_blinding_share(contribution, receiver_id, delta=1):
    """Break the blinding share a contribution addresses to ``receiver_id``."""
    dealing = contribution.contribution
    index = dealing.participant_ids.index(receiver_id)
    blinding_shares = list(dealing.blinding_shares)
    blinding_shares[index] = Share(
        x=blinding_shares[index].x,
        y=(blinding_shares[index].y + delta) % FIELD_PRIME,
    )
    return dataclasses.replace(
        contribution,
        contribution=dataclasses.replace(
            dealing, blinding_shares=tuple(blinding_shares)
        ),
    )


class DiagnoseLocalDKGSuccessTest(unittest.TestCase):
    def test_valid_packets_return_empty_tuple(self):
        contributions = make_contributions()
        for participant_id in (1, 2, 3):
            faults = diagnose_local_dkg(
                participant_id, packets_for(contributions, participant_id)
            )
            self.assertEqual(faults, ())
            self.assertIsInstance(faults, tuple)

    def test_empty_faults_exactly_when_aggregate_local_dkg_succeeds(self):
        contributions = make_contributions()
        packets = packets_for(contributions, 2)
        outcome = aggregate_local_dkg(2, list(packets))
        self.assertIsInstance(outcome, tuple)
        self.assertEqual(diagnose_local_dkg(2, packets), ())

    def test_input_order_does_not_matter(self):
        contributions = make_contributions()
        expected = diagnose_local_dkg(2, packets_for(contributions, 2))
        for permutation in itertools.permutations(contributions):
            self.assertEqual(
                diagnose_local_dkg(2, packets_for(permutation, 2)), expected
            )

    def test_single_pass_iterator(self):
        packets = make_packets(1)
        self.assertEqual(diagnose_local_dkg(1, iter(packets)), ())

    def test_threshold_one_zero_shares_and_identity_commitments(self):
        contributions = make_contributions(
            participant_ids=(1, 2), threshold=1, randbelow=zero_random()
        )
        for participant_id in (1, 2):
            self.assertEqual(
                diagnose_local_dkg(
                    participant_id, packets_for(contributions, participant_id)
                ),
                (),
            )

    def test_codec_roundtrip_packets_still_diagnose_clean(self):
        packets = [
            decode_local_dkg_packet(encode_local_dkg_packet(packet))
            for packet in make_packets(3)
        ]
        self.assertEqual(diagnose_local_dkg(3, packets), ())


class DiagnoseLocalDKGFaultTest(unittest.TestCase):
    def setUp(self):
        self.contributions = make_contributions()
        self.packets = packets_for(self.contributions, 2)

    def test_tampered_blinding_share_is_pedersen_fault_only(self):
        packets = [
            self.packets[0],
            tamper_blinding_share(self.packets[1]),
            self.packets[2],
        ]
        self.assertEqual(
            diagnose_local_dkg(2, packets),
            (ContributionFault(2, 2, "pedersen"),),
        )

    def test_tampered_share_is_both_faults_pedersen_first(self):
        packets = [tamper_share(self.packets[0]), self.packets[1], self.packets[2]]
        self.assertEqual(
            diagnose_local_dkg(2, packets),
            (
                ContributionFault(1, 2, "pedersen"),
                ContributionFault(1, 2, "feldman"),
            ),
        )

    def test_fault_receiver_id_is_the_target_receiver(self):
        packets = [tamper_share(packet) for packet in packets_for(self.contributions, 3)]
        self.assertEqual(
            diagnose_local_dkg(3, packets),
            (
                ContributionFault(1, 3, "pedersen"),
                ContributionFault(1, 3, "feldman"),
                ContributionFault(2, 3, "pedersen"),
                ContributionFault(2, 3, "feldman"),
                ContributionFault(3, 3, "pedersen"),
                ContributionFault(3, 3, "feldman"),
            ),
        )

    def test_several_senders_sorted_with_all_faults_kept(self):
        packets = [
            tamper_blinding_share(self.packets[2]),
            tamper_share(self.packets[0]),
            self.packets[1],
        ]
        expected = (
            ContributionFault(1, 2, "pedersen"),
            ContributionFault(1, 2, "feldman"),
            ContributionFault(3, 2, "pedersen"),
        )
        self.assertEqual(diagnose_local_dkg(2, packets), expected)
        self.assertEqual(diagnose_local_dkg(2, list(reversed(packets))), expected)

    def test_fault_senders_match_aggregate_local_dkg_rejections(self):
        packets = [
            tamper_blinding_share(self.packets[1]),
            tamper_share(self.packets[0]),
            self.packets[2],
        ]
        outcome = aggregate_local_dkg(2, list(packets))
        self.assertIsInstance(outcome, list)
        self.assertTrue(
            all(isinstance(rejection, DKGRejection) for rejection in outcome)
        )
        faults = diagnose_local_dkg(2, packets)
        self.assertEqual(
            [rejection.sender_id for rejection in outcome],
            sorted({fault.sender_id for fault in faults}),
        )

    def test_matches_full_contribution_diagnosis_for_each_receiver(self):
        contributions = [
            tamper_contribution_share(self.contributions[0], 2),
            tamper_contribution_blinding_share(self.contributions[1], 3),
            self.contributions[2],
        ]
        full = diagnose_signing_contributions(contributions)
        for receiver_id in (1, 2, 3):
            local = diagnose_local_dkg(
                receiver_id, packets_for(contributions, receiver_id)
            )
            self.assertEqual(
                local,
                tuple(fault for fault in full if fault.receiver_id == receiver_id),
                msg=f"receiver {receiver_id}",
            )


class DiagnoseLocalDKGTypeErrorTest(unittest.TestCase):
    def setUp(self):
        self.packets = make_packets(2)

    def diagnose(self, receiver_id=2, packets=_DEFAULT):
        return diagnose_local_dkg(
            receiver_id, self.packets if packets is _DEFAULT else packets
        )

    def assert_both_raise(self, error, receiver_id=2, packets=_DEFAULT):
        batch = self.packets if packets is _DEFAULT else packets
        with self.assertRaises(error):
            aggregate_local_dkg(receiver_id, list(batch))
        with self.assertRaises(error):
            diagnose_local_dkg(receiver_id, batch)

    def test_receiver_id_type(self):
        for bad in ("2", 2.0, None, True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.diagnose(receiver_id=bad)

    def test_non_iterable_packets(self):
        for bad in (7, 2.0, True, self.packets[0]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.diagnose(packets=bad)

    def test_non_packet_elements(self):
        for bad in ("packet", 7, self.packets[0].received, self.packets):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.diagnose(packets=[bad])

    def test_packet_field_types_match_aggregate_local_dkg(self):
        packet = self.packets[0]
        broken = dataclasses.replace(
            packet,
            received=dataclasses.replace(packet.received, share=Share(x=2, y=True)),
        )
        self.assert_both_raise(TypeError, packets=[broken] + self.packets[1:])

    def test_nested_field_types(self):
        packet = self.packets[0]
        cases = [
            dataclasses.replace(packet, participant_ids=[1, 2, 3]),
            dataclasses.replace(packet, participant_ids=(1, True, 3)),
            dataclasses.replace(packet, received="received"),
            dataclasses.replace(
                packet,
                received=dataclasses.replace(packet.received, sender_id=True),
            ),
            dataclasses.replace(packet, commitment="commitment"),
            dataclasses.replace(
                packet,
                commitment=dataclasses.replace(packet.commitment, field_prime=True),
            ),
            dataclasses.replace(
                packet,
                commitment=dataclasses.replace(
                    packet.commitment, values=list(packet.commitment.values)
                ),
            ),
            dataclasses.replace(packet, feldman_commitment="feldman"),
            dataclasses.replace(
                packet,
                feldman_commitment=dataclasses.replace(
                    packet.feldman_commitment, generator="g"
                ),
            ),
        ]
        for broken in cases:
            self.assert_both_raise(
                TypeError, packets=[broken] + self.packets[1:]
            )


class DiagnoseLocalDKGValueErrorTest(unittest.TestCase):
    def setUp(self):
        self.packets = make_packets(2)

    def diagnose(self, receiver_id=2, packets=_DEFAULT):
        return diagnose_local_dkg(
            receiver_id, self.packets if packets is _DEFAULT else packets
        )

    def assert_both_raise(self, error, receiver_id=2, packets=_DEFAULT):
        batch = self.packets if packets is _DEFAULT else packets
        with self.assertRaises(error):
            aggregate_local_dkg(receiver_id, list(batch))
        with self.assertRaises(error):
            diagnose_local_dkg(receiver_id, batch)

    def test_empty_batch(self):
        self.assert_both_raise(ValueError, packets=[])

    def test_receiver_not_a_participant(self):
        for bad in (4, 0, FIELD_PRIME):
            self.assert_both_raise(ValueError, receiver_id=bad)

    def test_missing_sender(self):
        self.assert_both_raise(ValueError, packets=self.packets[:2])

    def test_duplicate_sender(self):
        self.assert_both_raise(ValueError, packets=[self.packets[0]] + self.packets)

    def test_non_member_sender(self):
        other = make_packets(2, participant_ids=(1, 2, 4))
        self.assert_both_raise(
            ValueError, packets=self.packets[:2] + [other[2]]
        )

    def test_empty_participant_ids(self):
        broken = dataclasses.replace(self.packets[0], participant_ids=())
        self.assert_both_raise(ValueError, packets=[broken] + self.packets[1:])

    def test_non_increasing_participant_ids(self):
        broken = dataclasses.replace(self.packets[0], participant_ids=(2, 1, 3))
        self.assert_both_raise(ValueError, packets=[broken] + self.packets[1:])

    def test_out_of_range_participant_ids(self):
        broken = dataclasses.replace(
            self.packets[0], participant_ids=(1, 2, FIELD_PRIME)
        )
        self.assert_both_raise(ValueError, packets=[broken] + self.packets[1:])

    def test_packet_receiver_mismatch(self):
        packet = self.packets[0]
        received = packet.received
        broken = dataclasses.replace(
            packet,
            received=dataclasses.replace(
                received,
                receiver_id=3,
                share=Share(x=3, y=received.share.y),
                blinding_share=Share(x=3, y=received.blinding_share.y),
            ),
        )
        self.assert_both_raise(ValueError, packets=[broken] + self.packets[1:])

    def test_packet_share_coordinate_mismatch(self):
        packet = self.packets[0]
        received = packet.received
        broken = dataclasses.replace(
            packet,
            received=dataclasses.replace(
                received, share=Share(x=3, y=received.share.y)
            ),
        )
        self.assert_both_raise(ValueError, packets=[broken] + self.packets[1:])

    def test_packet_share_value_out_of_range(self):
        packet = self.packets[0]
        received = packet.received
        for bad_y in (FIELD_PRIME, -1):
            broken = dataclasses.replace(
                packet,
                received=dataclasses.replace(
                    received, share=Share(x=2, y=bad_y)
                ),
            )
            self.assert_both_raise(ValueError, packets=[broken] + self.packets[1:])

    def test_packets_disagree_on_participant_ids(self):
        broken = dataclasses.replace(self.packets[1], participant_ids=(1, 2, 4))
        self.assert_both_raise(
            ValueError, packets=[self.packets[0], broken, self.packets[2]]
        )

    def test_packets_disagree_on_threshold(self):
        other = make_packets(2, threshold=1)
        self.assert_both_raise(
            ValueError, packets=[self.packets[0], other[1], self.packets[2]]
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
        self.assert_both_raise(
            ValueError, packets=[self.packets[0], moved, self.packets[2]]
        )

    def test_commitments_disagree_within_one_packet(self):
        packet = self.packets[0]
        feldman = packet.feldman_commitment
        broken = dataclasses.replace(
            packet,
            feldman_commitment=dataclasses.replace(feldman, generator=4096),
        )
        self.assert_both_raise(ValueError, packets=[broken] + self.packets[1:])

    def test_commitment_threshold_mismatch_within_one_packet(self):
        packet = self.packets[0]
        feldman = packet.feldman_commitment
        broken = dataclasses.replace(
            packet,
            feldman_commitment=dataclasses.replace(
                feldman, values=feldman.values + (GENERATOR,)
            ),
        )
        self.assert_both_raise(ValueError, packets=[broken] + self.packets[1:])

    def test_threshold_out_of_range(self):
        packet = self.packets[0]
        commitment = packet.commitment
        feldman = packet.feldman_commitment
        extra = (GENERATOR,)
        broken = dataclasses.replace(
            packet,
            commitment=dataclasses.replace(
                commitment, values=commitment.values + extra
            ),
            feldman_commitment=dataclasses.replace(
                feldman, values=feldman.values + extra
            ),
        )
        self.assert_both_raise(ValueError, packets=[broken] + self.packets[1:])

    def test_illegal_commitment_values(self):
        packet = self.packets[0]
        for bad_value in (0, GROUP_PRIME, 2):
            broken = dataclasses.replace(
                packet,
                commitment=dataclasses.replace(
                    packet.commitment,
                    values=(bad_value,) + packet.commitment.values[1:],
                ),
            )
            self.assert_both_raise(ValueError, packets=[broken] + self.packets[1:])

    def test_illegal_group_parameters(self):
        packet = self.packets[0]
        broken = dataclasses.replace(
            packet,
            commitment=dataclasses.replace(packet.commitment, field_prime=4),
            feldman_commitment=dataclasses.replace(
                packet.feldman_commitment, field_prime=4
            ),
        )
        self.assert_both_raise(ValueError, packets=[broken] + self.packets[1:])


class DiagnoseLocalDKGNoMutationTest(unittest.TestCase):
    def setUp(self):
        self.packets = make_packets(2)

    def test_input_unchanged_on_success(self):
        snapshot = copy.deepcopy(self.packets)
        diagnose_local_dkg(2, self.packets)
        self.assertEqual(self.packets, snapshot)

    def test_input_unchanged_with_faults(self):
        packets = [tamper_share(self.packets[0])] + self.packets[1:]
        snapshot = copy.deepcopy(packets)
        diagnose_local_dkg(2, packets)
        self.assertEqual(packets, snapshot)

    def test_no_state_between_calls(self):
        bad = [tamper_share(self.packets[0])] + self.packets[1:]
        first = diagnose_local_dkg(2, bad)
        self.assertNotEqual(first, ())
        self.assertEqual(diagnose_local_dkg(2, self.packets), ())
        self.assertEqual(diagnose_local_dkg(2, bad), first)


if __name__ == "__main__":
    unittest.main()
