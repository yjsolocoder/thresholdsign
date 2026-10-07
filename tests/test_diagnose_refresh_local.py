"""Tests for the receiver-local refresh diagnoser (diagnose_refresh_local)."""

import copy
import dataclasses
import itertools
import unittest

from thresholdsign import (
    DKGReceivedShare,
    FeldmanCommitment,
    LocalDKGPacket,
    PedersenCommitment,
    RefreshFault,
    Share,
    SigningDKGResult,
    aggregate_signing_dkg,
    create_refresh,
    create_signing_contribution,
    decode_local_dkg_packet,
    diagnose_refresh_local,
    encode_local_dkg_packet,
    export_signing_public_context,
    refresh_local,
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


def make_key(participant_ids=(1, 2, 3), threshold=2, randbelow=None, seed_base=0):
    contributions = [
        create_signing_contribution(
            pid,
            participant_ids,
            threshold,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            blinding_generator=BLINDING_GENERATOR,
            randbelow=randbelow if randbelow is not None else fixed_random(pid + seed_base),
        )
        for pid in participant_ids
    ]
    outcome = aggregate_signing_dkg(contributions)
    assert isinstance(outcome, SigningDKGResult), outcome
    return outcome


def make_refresh_contributions(key, randbelow=None, seed_base=100):
    return [
        create_refresh(
            pid,
            key,
            randbelow=randbelow if randbelow is not None else fixed_random(pid + seed_base),
        )
        for pid in key.result.participant_ids
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


def shift_feldman_constant(packet):
    """Multiply the Feldman constant-term commitment by the generator."""
    feldman = packet.feldman_commitment
    return dataclasses.replace(
        packet,
        feldman_commitment=FeldmanCommitment(
            values=(feldman.values[0] * GENERATOR % GROUP_PRIME,) + feldman.values[1:],
            field_prime=feldman.field_prime,
            group_prime=feldman.group_prime,
            generator=feldman.generator,
        ),
    )


class DiagnoseRefreshLocalSuccessTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.contributions = make_refresh_contributions(self.key)
        self.context = export_signing_public_context(self.key)

    def old_material(self, receiver_id, key=None):
        key = self.key if key is None else key
        index = key.result.participant_ids.index(receiver_id)
        return (
            key.result.shares[index],
            key.result.blinding_shares[index],
            key.result.commitment,
        )

    def diagnose(self, receiver_id=2, packets=_DEFAULT, key=None,
                 context=_DEFAULT):
        share, blinding_share, commitment = self.old_material(receiver_id, key)
        return diagnose_refresh_local(
            receiver_id,
            share,
            blinding_share,
            commitment,
            self.context if context is _DEFAULT else context,
            packets_for(self.contributions, receiver_id)
            if packets is _DEFAULT else packets,
        )

    def test_valid_packets_return_empty_tuple(self):
        for participant_id in self.key.result.participant_ids:
            faults = self.diagnose(receiver_id=participant_id)
            self.assertEqual(faults, ())
            self.assertIsInstance(faults, tuple)

    def test_empty_faults_exactly_when_refresh_local_succeeds(self):
        share, blinding_share, commitment = self.old_material(2)
        packets = packets_for(self.contributions, 2)
        outcome = refresh_local(
            2, share, blinding_share, commitment, self.context, list(packets)
        )
        self.assertIsInstance(outcome, tuple)
        self.assertEqual(self.diagnose(2, packets=packets), ())

    def test_input_order_does_not_matter(self):
        expected = self.diagnose(2)
        for permutation in itertools.permutations(self.contributions):
            self.assertEqual(
                self.diagnose(2, packets=packets_for(permutation, 2)), expected
            )

    def test_single_pass_iterator(self):
        share, blinding_share, commitment = self.old_material(1)
        outcome = diagnose_refresh_local(
            1,
            share,
            blinding_share,
            commitment,
            self.context,
            iter(packets_for(self.contributions, 1)),
        )
        self.assertEqual(outcome, ())

    def test_threshold_one_zero_shares_and_identity_commitments(self):
        key = make_key(participant_ids=(1, 2), threshold=1, randbelow=zero_random())
        contributions = [
            create_refresh(pid, key, randbelow=zero_random())
            for pid in key.result.participant_ids
        ]
        context = export_signing_public_context(key)
        for participant_id in key.result.participant_ids:
            share, blinding_share, commitment = self.old_material(
                participant_id, key=key
            )
            faults = diagnose_refresh_local(
                participant_id,
                share,
                blinding_share,
                commitment,
                context,
                packets_for(contributions, participant_id),
            )
            self.assertEqual(faults, ())

    def test_codec_roundtrip_packets_still_diagnose_clean(self):
        packets = [
            decode_local_dkg_packet(encode_local_dkg_packet(packet))
            for packet in packets_for(self.contributions, 3)
        ]
        self.assertEqual(self.diagnose(3, packets=packets), ())


class DiagnoseRefreshLocalFaultTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.contributions = make_refresh_contributions(self.key)
        self.context = export_signing_public_context(self.key)
        self.packets = packets_for(self.contributions, 2)

    def diagnose(self, packets, receiver_id=2):
        index = self.key.result.participant_ids.index(receiver_id)
        return diagnose_refresh_local(
            receiver_id,
            self.key.result.shares[index],
            self.key.result.blinding_shares[index],
            self.key.result.commitment,
            self.context,
            packets,
        )

    def test_tampered_blinding_share_is_pedersen_fault_only(self):
        packets = [self.packets[0], tamper_blinding_share(self.packets[1]), self.packets[2]]
        self.assertEqual(self.diagnose(packets), (RefreshFault(2, "pedersen", 2),))

    def test_tampered_share_is_both_faults_pedersen_first(self):
        packets = [tamper_share(self.packets[0]), self.packets[1], self.packets[2]]
        self.assertEqual(
            self.diagnose(packets),
            (
                RefreshFault(1, "pedersen", 2),
                RefreshFault(1, "feldman", 2),
            ),
        )

    def test_fault_receiver_id_is_the_diagnosing_receiver(self):
        packets = [tamper_share(packet) for packet in packets_for(self.contributions, 3)]
        self.assertEqual(
            self.diagnose(packets, receiver_id=3),
            (
                RefreshFault(1, "pedersen", 3),
                RefreshFault(1, "feldman", 3),
                RefreshFault(2, "pedersen", 3),
                RefreshFault(2, "feldman", 3),
                RefreshFault(3, "pedersen", 3),
                RefreshFault(3, "feldman", 3),
            ),
        )

    def test_shifted_feldman_constant_is_feldman_then_constant(self):
        # The shifted constant breaks the Feldman evaluation of the share and
        # the zero-secret proof; Pedersen still passes.
        packets = [shift_feldman_constant(self.packets[0]), self.packets[1], self.packets[2]]
        self.assertEqual(
            self.diagnose(packets),
            (
                RefreshFault(1, "feldman", 2),
                RefreshFault(1, "constant", None),
            ),
        )

    def test_self_consistent_wrong_constant_is_constant_fault_only(self):
        # An ordinary signing contribution is internally consistent but its
        # constant term is random, so only the constant check fails.
        ordinary = create_signing_contribution(
            1,
            self.key.result.participant_ids,
            2,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            blinding_generator=BLINDING_GENERATOR,
            randbelow=fixed_random(42),
        )
        packets = [packet_for(ordinary, 2), self.packets[1], self.packets[2]]
        self.assertEqual(self.diagnose(packets), (RefreshFault(1, "constant", None),))

    def test_all_three_checks_of_one_sender_all_reported_in_order(self):
        # Tamper the blinding share (pedersen fails) and shift the Feldman
        # constant (feldman and constant fail) of the same sender's packet.
        bad = shift_feldman_constant(tamper_blinding_share(self.packets[0]))
        self.assertEqual(
            self.diagnose([bad, self.packets[1], self.packets[2]]),
            (
                RefreshFault(1, "pedersen", 2),
                RefreshFault(1, "feldman", 2),
                RefreshFault(1, "constant", None),
            ),
        )

    def test_several_senders_sorted_with_all_faults_kept(self):
        packets = [
            shift_feldman_constant(self.packets[2]),
            tamper_share(self.packets[0]),
            self.packets[1],
        ]
        expected = (
            RefreshFault(1, "pedersen", 2),
            RefreshFault(1, "feldman", 2),
            RefreshFault(3, "feldman", 2),
            RefreshFault(3, "constant", None),
        )
        self.assertEqual(self.diagnose(packets), expected)
        self.assertEqual(self.diagnose(list(reversed(packets))), expected)

    def test_fault_senders_match_refresh_local_rejections(self):
        packets = [
            tamper_blinding_share(self.packets[1]),
            tamper_share(self.packets[0]),
            self.packets[2],
        ]
        index = self.key.result.participant_ids.index(2)
        outcome = refresh_local(
            2,
            self.key.result.shares[index],
            self.key.result.blinding_shares[index],
            self.key.result.commitment,
            self.context,
            list(packets),
        )
        self.assertEqual(
            [rejection.sender_id for rejection in outcome],
            sorted({fault.sender_id for fault in self.diagnose(packets)}),
        )


class DiagnoseRefreshLocalTypeErrorTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.contributions = make_refresh_contributions(self.key)
        self.context = export_signing_public_context(self.key)
        self.packets = packets_for(self.contributions, 2)
        index = self.key.result.participant_ids.index(2)
        self.share = self.key.result.shares[index]
        self.blinding_share = self.key.result.blinding_shares[index]
        self.commitment = self.key.result.commitment

    def diagnose(self, receiver_id=2, share=_DEFAULT, blinding_share=_DEFAULT,
                 commitment=_DEFAULT, context=_DEFAULT, packets=_DEFAULT):
        return diagnose_refresh_local(
            receiver_id,
            self.share if share is _DEFAULT else share,
            self.blinding_share if blinding_share is _DEFAULT else blinding_share,
            self.commitment if commitment is _DEFAULT else commitment,
            self.context if context is _DEFAULT else context,
            self.packets if packets is _DEFAULT else packets,
        )

    def assert_both_raise(self, error, **overrides):
        receiver_id = overrides.get("receiver_id", 2)
        share = overrides.get("share", self.share)
        blinding_share = overrides.get("blinding_share", self.blinding_share)
        commitment = overrides.get("commitment", self.commitment)
        context = overrides.get("context", self.context)
        packets = overrides.get("packets", self.packets)
        with self.assertRaises(error):
            refresh_local(
                receiver_id, share, blinding_share, commitment, context, list(packets)
            )
        with self.assertRaises(error):
            diagnose_refresh_local(
                receiver_id, share, blinding_share, commitment, context, packets
            )

    def test_receiver_id_type(self):
        for bad in ("2", 2.0, None, True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.diagnose(receiver_id=bad)

    def test_share_type(self):
        for bad in ("share", 7, None, self.packets[0]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.diagnose(share=bad)
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.diagnose(blinding_share=bad)

    def test_share_field_types(self):
        for bad in (True, "2", 2.0):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.diagnose(share=Share(x=bad, y=self.share.y))
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.diagnose(blinding_share=Share(x=self.share.x, y=bad))

    def test_commitment_type(self):
        for bad in ("commitment", 7, None, self.context):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.diagnose(commitment=bad)

    def test_commitment_field_types(self):
        commitment = self.commitment
        for field in ("field_prime", "group_prime", "generator", "blinding_generator"):
            for bad in (True, "x"):
                broken = dataclasses.replace(commitment, **{field: bad})
                with self.assertRaises(TypeError, msg=f"{field}={bad!r}"):
                    self.diagnose(commitment=broken)
        with self.assertRaises(TypeError):
            self.diagnose(
                commitment=dataclasses.replace(
                    commitment, values=list(commitment.values)
                )
            )
        with self.assertRaises(TypeError):
            self.diagnose(
                commitment=dataclasses.replace(
                    commitment, values=(True,) + commitment.values[1:]
                )
            )

    def test_context_type(self):
        for bad in ("context", 7, None, self.commitment):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.diagnose(context=bad)

    def test_context_field_types(self):
        with self.assertRaises(TypeError):
            self.diagnose(context=dataclasses.replace(self.context, threshold=True))
        with self.assertRaises(TypeError):
            self.diagnose(
                context=dataclasses.replace(self.context, participant_ids=[1, 2, 3])
            )
        with self.assertRaises(TypeError):
            self.diagnose(
                context=dataclasses.replace(
                    self.context, verification_shares=(1, 2, "3")
                )
            )

    def test_non_packet_elements(self):
        for bad in ("packet", 7, self.packets[0].received, self.packets):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.diagnose(packets=[bad])

    def test_packet_field_types_match_refresh_local(self):
        packet = self.packets[0]
        broken = dataclasses.replace(
            packet,
            received=dataclasses.replace(packet.received, share=Share(x=2, y=True)),
        )
        self.assert_both_raise(TypeError, packets=[broken] + self.packets[1:])


class DiagnoseRefreshLocalValueErrorTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.contributions = make_refresh_contributions(self.key)
        self.context = export_signing_public_context(self.key)
        self.packets = packets_for(self.contributions, 2)
        index = self.key.result.participant_ids.index(2)
        self.share = self.key.result.shares[index]
        self.blinding_share = self.key.result.blinding_shares[index]
        self.commitment = self.key.result.commitment

    def diagnose(self, receiver_id=2, share=_DEFAULT, blinding_share=_DEFAULT,
                 commitment=_DEFAULT, context=_DEFAULT, packets=_DEFAULT):
        return diagnose_refresh_local(
            receiver_id,
            self.share if share is _DEFAULT else share,
            self.blinding_share if blinding_share is _DEFAULT else blinding_share,
            self.commitment if commitment is _DEFAULT else commitment,
            self.context if context is _DEFAULT else context,
            self.packets if packets is _DEFAULT else packets,
        )

    def assert_both_raise(self, error, **overrides):
        receiver_id = overrides.get("receiver_id", 2)
        share = overrides.get("share", self.share)
        blinding_share = overrides.get("blinding_share", self.blinding_share)
        commitment = overrides.get("commitment", self.commitment)
        context = overrides.get("context", self.context)
        packets = overrides.get("packets", self.packets)
        with self.assertRaises(error):
            refresh_local(
                receiver_id, share, blinding_share, commitment, context, list(packets)
            )
        with self.assertRaises(error):
            diagnose_refresh_local(
                receiver_id, share, blinding_share, commitment, context, packets
            )

    def test_empty_batch(self):
        self.assert_both_raise(ValueError, packets=[])

    def test_receiver_not_a_participant(self):
        for bad in (4, 0, FIELD_PRIME):
            self.assert_both_raise(ValueError, receiver_id=bad)

    def test_missing_sender(self):
        self.assert_both_raise(ValueError, packets=self.packets[:2])

    def test_duplicate_sender(self):
        self.assert_both_raise(
            ValueError, packets=[self.packets[0]] + self.packets
        )

    def test_non_member_sender(self):
        other = make_key(participant_ids=(1, 2, 4))
        other_contributions = make_refresh_contributions(other)
        packets = self.packets[:2] + [packets_for(other_contributions, 2)[2]]
        self.assert_both_raise(ValueError, packets=packets)

    def test_old_share_coordinate_mismatch(self):
        self.assert_both_raise(
            ValueError, share=Share(x=3, y=self.share.y)
        )
        self.assert_both_raise(
            ValueError, blinding_share=Share(x=1, y=self.blinding_share.y)
        )

    def test_old_share_value_out_of_range(self):
        self.assert_both_raise(
            ValueError, share=Share(x=2, y=FIELD_PRIME)
        )
        self.assert_both_raise(
            ValueError, blinding_share=Share(x=2, y=-1)
        )

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
        broken = dataclasses.replace(
            packet,
            received=dataclasses.replace(
                received, share=Share(x=2, y=FIELD_PRIME)
            ),
        )
        self.assert_both_raise(ValueError, packets=[broken] + self.packets[1:])

    def test_packets_disagree_on_participant_ids(self):
        broken = dataclasses.replace(self.packets[1], participant_ids=(1, 2, 4))
        self.assert_both_raise(
            ValueError, packets=[self.packets[0], broken, self.packets[2]]
        )

    def test_packets_disagree_on_threshold(self):
        other = make_key(participant_ids=(1, 2, 3), threshold=1)
        other_contributions = make_refresh_contributions(other)
        other_packet = packets_for(other_contributions, 2)[1]
        self.assert_both_raise(
            ValueError, packets=[self.packets[0], other_packet, self.packets[2]]
        )

    def test_packets_disagree_on_group_parameters(self):
        packet = self.packets[1]
        commitment = packet.commitment
        # 4096 = 16 ** 3 mod 8069 is another legal subgroup generator.
        moved = dataclasses.replace(
            packet,
            commitment=dataclasses.replace(commitment, blinding_generator=4096),
        )
        self.assert_both_raise(
            ValueError, packets=[self.packets[0], moved, self.packets[2]]
        )

    def test_commitment_group_mismatch_with_context(self):
        # 256 is a legal subgroup generator but not the context's generator.
        self.assert_both_raise(
            ValueError,
            commitment=dataclasses.replace(
                self.commitment,
                generator=BLINDING_GENERATOR,
                blinding_generator=GENERATOR,
            ),
        )

    def test_commitment_threshold_mismatch_with_context(self):
        self.assert_both_raise(
            ValueError,
            commitment=dataclasses.replace(
                self.commitment, values=self.commitment.values + (1,)
            ),
        )
        self.assert_both_raise(
            ValueError,
            commitment=dataclasses.replace(
                self.commitment, values=self.commitment.values[:1]
            ),
        )

    def test_illegal_old_commitment_values(self):
        for bad_value in (0, GROUP_PRIME, 2):
            broken = dataclasses.replace(
                self.commitment, values=(bad_value,) + self.commitment.values[1:]
            )
            self.assert_both_raise(ValueError, commitment=broken)

    def test_illegal_context_values(self):
        self.assert_both_raise(
            ValueError,
            context=dataclasses.replace(self.context, participant_ids=(2, 1, 3)),
        )
        self.assert_both_raise(
            ValueError, context=dataclasses.replace(self.context, threshold=4)
        )
        self.assert_both_raise(
            ValueError, context=dataclasses.replace(self.context, public_key=0)
        )

    def test_old_double_share_failing_pedersen_is_value_error_not_fault(self):
        # The caller's own old material is at fault, never a sender.
        self.assert_both_raise(
            ValueError,
            blinding_share=Share(
                x=2, y=(self.blinding_share.y + 1) % FIELD_PRIME
            ),
        )

    def test_old_share_mismatching_verification_share_is_value_error(self):
        # A double share from another key verifies against that key's
        # commitment but not against this context's verification share.
        other = make_key(seed_base=500)
        index = other.result.participant_ids.index(2)
        self.assert_both_raise(
            ValueError,
            share=other.result.shares[index],
            blinding_share=other.result.blinding_shares[index],
            commitment=other.result.commitment,
        )


class DiagnoseRefreshLocalNoMutationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.contributions = make_refresh_contributions(self.key)
        self.context = export_signing_public_context(self.key)
        self.packets = packets_for(self.contributions, 2)
        index = self.key.result.participant_ids.index(2)
        self.share = self.key.result.shares[index]
        self.blinding_share = self.key.result.blinding_shares[index]
        self.commitment = self.key.result.commitment

    def diagnose(self, packets):
        return diagnose_refresh_local(
            2,
            self.share,
            self.blinding_share,
            self.commitment,
            self.context,
            packets,
        )

    def test_input_unchanged_on_success(self):
        snapshot = copy.deepcopy(self.packets)
        self.diagnose(self.packets)
        self.assertEqual(self.packets, snapshot)

    def test_input_unchanged_with_faults(self):
        packets = [tamper_share(self.packets[0])] + self.packets[1:]
        snapshot = copy.deepcopy(packets)
        self.diagnose(packets)
        self.assertEqual(packets, snapshot)

    def test_input_unchanged_on_value_error(self):
        packets = self.packets[:2]
        snapshot = copy.deepcopy(packets)
        with self.assertRaises(ValueError):
            self.diagnose(packets)
        self.assertEqual(packets, snapshot)


if __name__ == "__main__":
    unittest.main()
