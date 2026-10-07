"""Tests for the receiver-local resharing diagnoser diagnose_reshare_local."""

import copy
import dataclasses
import unittest

from thresholdsign import (
    DKGReceivedShare,
    DKGRejection,
    LocalDKGPacket,
    ReshareFault,
    Share,
    SigningDKGResult,
    aggregate_signing_dkg,
    create_reshare,
    create_signing_contribution,
    decode_local_dkg_packet,
    diagnose_reshare_local,
    encode_local_dkg_packet,
    export_signing_public_context,
    reshare,
    reshare_local,
)

# Same toy group as the reshare tests: 8069 = 4 * 2017 + 1 is prime and
# 16, 256 = 16 ** 2 generate the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

_DEFAULT = object()


def fixed_random(seed=1):
    """Deterministic stand-in for secrets.randbelow (same LCG as reshare tests)."""
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


def secret_share_of(key, participant_id):
    index = key.result.participant_ids.index(participant_id)
    return key.result.shares[index].y


def make_reshare_contributions(key, dealers, members, threshold, seed_base=100):
    return [
        create_reshare(
            dealer,
            secret_share_of(key, dealer),
            dealers,
            members,
            threshold,
            key,
            rng=fixed_random(dealer + seed_base),
        )
        for dealer in dealers
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


class DiagnoseReshareLocalSuccessTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.dealers = (2, 3)
        self.members = (2, 3, 4)
        self.threshold = 2
        self.contributions = make_reshare_contributions(
            self.key, self.dealers, self.members, self.threshold
        )
        self.context = export_signing_public_context(self.key)
        self.commitment = self.key.result.commitment

    def diagnose(self, receiver_id=3, packets=_DEFAULT, dealers=_DEFAULT,
                 context=_DEFAULT, commitment=_DEFAULT):
        return diagnose_reshare_local(
            receiver_id,
            packets_for(self.contributions, receiver_id) if packets is _DEFAULT else packets,
            self.dealers if dealers is _DEFAULT else dealers,
            self.context if context is _DEFAULT else context,
            self.commitment if commitment is _DEFAULT else commitment,
        )

    def test_valid_batch_returns_empty_tuple(self):
        faults = self.diagnose()
        self.assertEqual(faults, ())
        self.assertIsInstance(faults, tuple)

    def test_empty_faults_exactly_when_local_aggregation_succeeds(self):
        packets = packets_for(self.contributions, 4)
        self.assertNotIsInstance(
            reshare_local(4, packets, self.dealers, self.context, self.commitment),
            list,
        )
        self.assertEqual(
            diagnose_reshare_local(
                4, packets, self.dealers, self.context, self.commitment
            ),
            (),
        )

    def test_every_receiver_sees_an_empty_tuple(self):
        for receiver_id in self.members:
            self.assertEqual(
                self.diagnose(receiver_id),
                (),
                receiver_id,
            )

    def test_threshold_one_zero_shares_and_identity_commitments(self):
        key = make_key(participant_ids=(1, 2), threshold=1, randbelow=zero_random())
        contributions = [
            create_reshare(
                1,
                secret_share_of(key, 1),
                (1,),
                (1, 2),
                1,
                key,
                rng=zero_random(),
            )
        ]
        context = export_signing_public_context(key)
        packets = packets_for(contributions, 2)
        self.assertEqual(
            diagnose_reshare_local(
                2, packets, (1,), context, key.result.commitment
            ),
            (),
        )

    def test_codec_round_trip_packets_still_diagnose_clean(self):
        packets = packets_for(self.contributions, 3)
        decoded = [
            decode_local_dkg_packet(encode_local_dkg_packet(packet))
            for packet in packets
        ]
        self.assertEqual(self.diagnose(packets=decoded), ())

    def test_single_pass_iterators(self):
        self.assertEqual(
            diagnose_reshare_local(
                3,
                iter(packets_for(self.contributions, 3)),
                iter(self.dealers),
                self.context,
                self.commitment,
            ),
            (),
        )

    def test_input_order_does_not_matter(self):
        packets = packets_for(self.contributions, 3)
        expected = ()
        self.assertEqual(
            diagnose_reshare_local(
                3, reversed(packets), self.dealers, self.context, self.commitment
            ),
            expected,
        )


class DiagnoseReshareLocalFaultTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.dealers = (2, 3)
        self.members = (2, 3, 4)
        self.threshold = 2
        self.contributions = make_reshare_contributions(
            self.key, self.dealers, self.members, self.threshold
        )
        self.context = export_signing_public_context(self.key)
        self.commitment = self.key.result.commitment
        self.packets = packets_for(self.contributions, 3)

    def diagnose(self, packets, receiver_id=3, dealers=_DEFAULT):
        return diagnose_reshare_local(
            receiver_id,
            packets,
            self.dealers if dealers is _DEFAULT else dealers,
            self.context,
            self.commitment,
        )

    def tamper_share(self, packet, delta=1):
        received = packet.received
        tampered = Share(x=received.share.x, y=(received.share.y + delta) % FIELD_PRIME)
        return dataclasses.replace(
            packet, received=dataclasses.replace(received, share=tampered)
        )

    def tamper_blinding_share(self, packet, delta=1):
        received = packet.received
        tampered = Share(
            x=received.blinding_share.x,
            y=(received.blinding_share.y + delta) % FIELD_PRIME,
        )
        return dataclasses.replace(
            packet, received=dataclasses.replace(received, blinding_share=tampered)
        )

    def shift_constant(self, packet):
        feldman = packet.feldman_commitment
        return dataclasses.replace(
            packet,
            feldman_commitment=dataclasses.replace(
                feldman,
                values=(feldman.values[0] * GENERATOR % GROUP_PRIME,)
                + feldman.values[1:],
            ),
        )

    def test_tampered_share_is_pedersen_then_feldman_with_receiver_id(self):
        bad = self.tamper_share(self.packets[0])
        self.assertEqual(
            self.diagnose([bad, self.packets[1]]),
            (
                ReshareFault(2, "pedersen", 3),
                ReshareFault(2, "feldman", 3),
            ),
        )

    def test_tampered_blinding_share_is_pedersen_only(self):
        bad = self.tamper_blinding_share(self.packets[1])
        self.assertEqual(
            self.diagnose([self.packets[0], bad]),
            (ReshareFault(3, "pedersen", 3),),
        )

    def test_shifted_constant_is_feldman_then_binding_with_none_receiver(self):
        bad = self.shift_constant(self.packets[0])
        self.assertEqual(
            self.diagnose([bad, self.packets[1]]),
            (
                ReshareFault(2, "feldman", 3),
                ReshareFault(2, "binding", None),
            ),
        )

    def test_all_three_failures_of_one_sender_are_kept_in_order(self):
        bad = self.shift_constant(self.tamper_blinding_share(self.packets[0]))
        self.assertEqual(
            self.diagnose([bad, self.packets[1]]),
            (
                ReshareFault(2, "pedersen", 3),
                ReshareFault(2, "feldman", 3),
                ReshareFault(2, "binding", None),
            ),
        )

    def test_self_consistent_wrong_constant_is_binding_only(self):
        # An ordinary signing contribution's packet is internally consistent
        # (both share checks pass) but its constant is random, so only the
        # binding check fails.
        ordinary = create_signing_contribution(
            2,
            self.members,
            self.threshold,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            blinding_generator=BLINDING_GENERATOR,
            randbelow=fixed_random(42),
        )
        packet = packet_for(ordinary, 3)
        self.assertEqual(
            self.diagnose([packet, self.packets[1]]),
            (ReshareFault(2, "binding", None),),
        )

    def test_faults_sorted_by_sender_then_fixed_check_order(self):
        bad_3 = self.tamper_share(self.packets[1])
        bad_2 = self.tamper_blinding_share(self.packets[0])
        expected = (
            ReshareFault(2, "pedersen", 3),
            ReshareFault(3, "pedersen", 3),
            ReshareFault(3, "feldman", 3),
        )
        for order in ([bad_3, bad_2], [bad_2, bad_3], list(reversed([bad_3, bad_2]))):
            self.assertEqual(self.diagnose(order), expected)

    def test_fault_senders_match_local_rejections(self):
        bad = self.tamper_share(self.packets[0])
        packets = [bad, self.packets[1]]
        outcome = reshare_local(
            3, packets, self.dealers, self.context, self.commitment
        )
        self.assertEqual(outcome, [DKGRejection(sender_id=2)])
        faults = self.diagnose(packets)
        self.assertEqual(
            sorted({fault.sender_id for fault in faults}),
            [rejection.sender_id for rejection in outcome],
        )

    def test_faults_suppress_constant_product_value_error(self):
        # With faults present the product-of-constants check is not reached,
        # so a wrong old public key never turns the fault tuple into an error.
        bad = self.tamper_share(self.packets[0])
        wrong_context = dataclasses.replace(
            self.context,
            public_key=self.context.public_key * GENERATOR % GROUP_PRIME,
        )
        faults = diagnose_reshare_local(
            3, [bad, self.packets[1]], self.dealers, wrong_context, self.commitment
        )
        self.assertEqual(
            faults,
            (
                ReshareFault(2, "pedersen", 3),
                ReshareFault(2, "feldman", 3),
            ),
        )

    def test_diagnosis_concerns_only_the_receivers_own_packet(self):
        # Tampering with this receiver's packet from dealer 2 is reported;
        # the diagnoser has no view on (and says nothing about) other members.
        bad = self.tamper_share(self.packets[0])
        faults = self.diagnose([bad, self.packets[1]])
        self.assertTrue(all(fault.receiver_id == 3 or fault.receiver_id is None
                            for fault in faults))

    def test_diagnosis_returns_no_secret_value(self):
        bad = self.tamper_share(self.packets[0])
        for fault in self.diagnose([bad, self.packets[1]]):
            self.assertEqual(
                set(field.name for field in dataclasses.fields(fault)),
                {"sender_id", "check", "receiver_id"},
            )


class DiagnoseReshareLocalValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.dealers = (2, 3)
        self.members = (2, 3, 4)
        self.contributions = make_reshare_contributions(
            self.key, self.dealers, self.members, 2
        )
        self.context = export_signing_public_context(self.key)
        self.commitment = self.key.result.commitment
        self.packets = packets_for(self.contributions, 3)

    def diagnose(self, receiver_id=3, packets=_DEFAULT, dealers=_DEFAULT,
                 context=_DEFAULT, commitment=_DEFAULT):
        return diagnose_reshare_local(
            receiver_id,
            self.packets if packets is _DEFAULT else packets,
            self.dealers if dealers is _DEFAULT else dealers,
            self.context if context is _DEFAULT else context,
            self.commitment if commitment is _DEFAULT else commitment,
        )

    def assert_local_and_diagnoser_raise(self, error, *, packets=_DEFAULT,
                                         dealers=_DEFAULT, context=_DEFAULT,
                                         commitment=_DEFAULT, receiver_id=3):
        with self.assertRaises(error):
            reshare_local(
                receiver_id,
                self.packets if packets is _DEFAULT else packets,
                self.dealers if dealers is _DEFAULT else dealers,
                self.context if context is _DEFAULT else context,
                self.commitment if commitment is _DEFAULT else commitment,
            )
        with self.assertRaises(error):
            self.diagnose(
                receiver_id=receiver_id,
                packets=packets,
                dealers=dealers,
                context=context,
                commitment=commitment,
            )

    def test_receiver_id_type(self):
        for bad in ("3", 3.0, None, True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.diagnose(receiver_id=bad)

    def test_context_type(self):
        for bad in ("context", 7, None, self.commitment):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.diagnose(context=bad)

    def test_context_field_types(self):
        with self.assertRaises(TypeError):
            self.diagnose(context=dataclasses.replace(self.context, threshold=True))
        with self.assertRaises(TypeError):
            self.diagnose(
                context=dataclasses.replace(self.context, participant_ids=[2, 3])
            )
        with self.assertRaises(TypeError):
            self.diagnose(
                context=dataclasses.replace(
                    self.context, verification_shares=(1, 2, "3")
                )
            )

    def test_commitment_type_and_field_types(self):
        for bad in ("commitment", 7, None, self.context):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.diagnose(commitment=bad)
        commitment = self.commitment
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

    def test_non_packet_elements_are_type_error(self):
        for bad in ("packet", 7, self.packets[0].received, self.packets):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.diagnose(packets=[bad])

    def test_dealers_type(self):
        for bad in ("23", b"23", [2, "3"], [2, True], [2, 3.0]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.diagnose(dealers=bad)

    def test_empty_batch(self):
        self.assert_local_and_diagnoser_raise(ValueError, packets=[])

    def test_empty_and_illegal_dealers(self):
        self.assert_local_and_diagnoser_raise(ValueError, dealers=[])
        self.assert_local_and_diagnoser_raise(ValueError, dealers=(3, 2))
        self.assert_local_and_diagnoser_raise(ValueError, dealers=(2, 2))
        self.assert_local_and_diagnoser_raise(ValueError, dealers=(2,))
        self.assert_local_and_diagnoser_raise(ValueError, dealers=(2, 4))
        self.assert_local_and_diagnoser_raise(ValueError, dealers=(1, 2))

    def test_receiver_not_a_new_member(self):
        for bad in (1, 5, 0, FIELD_PRIME):
            self.assert_local_and_diagnoser_raise(
                ValueError, receiver_id=bad
            )

    def test_missing_duplicate_and_extra_senders(self):
        self.assert_local_and_diagnoser_raise(
            ValueError, packets=self.packets[:1]
        )
        self.assert_local_and_diagnoser_raise(
            ValueError, packets=[self.packets[0], self.packets[0]]
        )
        extra_contribution = create_reshare(
            1,
            secret_share_of(self.key, 1),
            (1, 2, 3),
            (1, 2, 3),
            2,
            self.key,
            rng=fixed_random(901),
        )
        dealers = (1, 2)
        contributions = make_reshare_contributions(
            self.key, dealers, (1, 2, 3), 2
        )
        packets = packets_for(contributions, 3) + [packet_for(extra_contribution, 3)]
        self.assert_local_and_diagnoser_raise(
            ValueError, packets=packets, dealers=dealers
        )

    def test_packet_addressing_and_coordinate_mismatch(self):
        packet = self.packets[0]
        received = packet.received
        broken = dataclasses.replace(
            packet,
            received=dataclasses.replace(
                received,
                receiver_id=2,
                share=Share(x=2, y=received.share.y),
                blinding_share=Share(x=2, y=received.blinding_share.y),
            ),
        )
        self.assert_local_and_diagnoser_raise(
            ValueError, packets=[broken, self.packets[1]]
        )
        broken_coordinate = dataclasses.replace(
            packet,
            received=dataclasses.replace(
                received, share=Share(x=4, y=received.share.y)
            ),
        )
        self.assert_local_and_diagnoser_raise(
            ValueError, packets=[broken_coordinate, self.packets[1]]
        )

    def test_packet_share_value_out_of_range(self):
        packet = self.packets[0]
        received = packet.received
        broken = dataclasses.replace(
            packet,
            received=dataclasses.replace(received, share=Share(x=3, y=FIELD_PRIME)),
        )
        self.assert_local_and_diagnoser_raise(
            ValueError, packets=[broken, self.packets[1]]
        )

    def test_packets_disagree_on_members_or_threshold(self):
        packet = self.packets[1]
        broken = dataclasses.replace(packet, participant_ids=(2, 3, 5))
        self.assert_local_and_diagnoser_raise(
            ValueError, packets=[self.packets[0], broken]
        )
        other = make_reshare_contributions(
            self.key, self.dealers, self.members, 1, seed_base=800
        )
        other_packet = packets_for(other, 3)[1]
        self.assert_local_and_diagnoser_raise(
            ValueError, packets=[self.packets[0], other_packet]
        )

    def test_packets_do_not_reuse_old_group_parameters(self):
        packet = self.packets[1]
        commitment = packet.commitment
        moved = dataclasses.replace(
            packet,
            commitment=dataclasses.replace(commitment, blinding_generator=4096),
        )
        self.assert_local_and_diagnoser_raise(
            ValueError, packets=[self.packets[0], moved]
        )

    def test_old_commitment_mismatch_with_context(self):
        self.assert_local_and_diagnoser_raise(
            ValueError,
            commitment=dataclasses.replace(
                self.commitment,
                generator=BLINDING_GENERATOR,
                blinding_generator=GENERATOR,
            ),
        )
        self.assert_local_and_diagnoser_raise(
            ValueError,
            commitment=dataclasses.replace(
                self.commitment, values=self.commitment.values + (1,)
            ),
        )

    def test_illegal_old_commitment_values(self):
        for bad_value in (0, GROUP_PRIME, 2):
            broken = dataclasses.replace(
                self.commitment, values=(bad_value,) + self.commitment.values[1:]
            )
            self.assert_local_and_diagnoser_raise(ValueError, commitment=broken)

    def test_constant_product_mismatch_with_old_public_key(self):
        # All per-packet checks pass, but the public material is internally
        # inconsistent: the diagnoser raises ValueError exactly as the local
        # aggregation does, never reporting an empty or non-empty fault tuple.
        wrong_key = self.context.public_key * GENERATOR % GROUP_PRIME
        broken = dataclasses.replace(self.context, public_key=wrong_key)
        self.assert_local_and_diagnoser_raise(ValueError, context=broken)


class DiagnoseReshareLocalNoMutationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.dealers = (2, 3)
        self.members = (2, 3, 4)
        self.contributions = make_reshare_contributions(
            self.key, self.dealers, self.members, 2
        )
        self.context = export_signing_public_context(self.key)
        self.commitment = self.key.result.commitment

    def test_inputs_unchanged_on_success(self):
        packets = packets_for(self.contributions, 3)
        snapshot = copy.deepcopy(packets)
        dealers = list(self.dealers)
        diagnose_reshare_local(
            3, packets, dealers, self.context, self.commitment
        )
        self.assertEqual(packets, snapshot)
        self.assertEqual(dealers, list(self.dealers))

    def test_inputs_unchanged_with_faults(self):
        packets = packets_for(self.contributions, 3)
        received = packets[0].received
        packets[0] = dataclasses.replace(
            packets[0],
            received=dataclasses.replace(
                received, share=Share(received.share.x, (received.share.y + 1) % FIELD_PRIME)
            ),
        )
        snapshot = copy.deepcopy(packets)
        diagnose_reshare_local(
            3, packets, self.dealers, self.context, self.commitment
        )
        self.assertEqual(packets, snapshot)

    def test_inputs_unchanged_on_value_error(self):
        packets = packets_for(self.contributions, 3)
        snapshot = copy.deepcopy(packets)
        with self.assertRaises(ValueError):
            diagnose_reshare_local(
                3, packets[:1], self.dealers, self.context, self.commitment
            )
        self.assertEqual(packets, snapshot)


if __name__ == "__main__":
    unittest.main()
