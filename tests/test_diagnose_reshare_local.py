"""Tests for the receiver-local resharing diagnoser (diagnose_reshare_local)."""

import copy
import dataclasses
import itertools
import unittest

from thresholdsign import (
    DKGReceivedShare,
    FeldmanCommitment,
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
    reshare_local,
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

    def test_valid_packets_return_empty_tuple(self):
        for member_id in self.members:
            faults = self.diagnose(receiver_id=member_id)
            self.assertEqual(faults, ())
            self.assertIsInstance(faults, tuple)

    def test_empty_faults_exactly_when_reshare_local_succeeds(self):
        packets = packets_for(self.contributions, 3)
        outcome = reshare_local(
            3, list(packets), self.dealers, self.context, self.commitment
        )
        self.assertIsInstance(outcome, tuple)
        self.assertEqual(self.diagnose(3, packets=packets), ())

    def test_every_member_diagnoses_clean(self):
        for member_id in self.members:
            self.assertEqual(self.diagnose(receiver_id=member_id), ())

    def test_input_order_does_not_matter(self):
        expected = self.diagnose(3)
        for permutation in itertools.permutations(self.contributions):
            self.assertEqual(
                self.diagnose(3, packets=packets_for(permutation, 3)), expected
            )

    def test_single_pass_iterators(self):
        outcome = diagnose_reshare_local(
            3,
            iter(packets_for(self.contributions, 3)),
            iter(self.dealers),
            self.context,
            self.commitment,
        )
        self.assertEqual(outcome, ())

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
        for member_id in (1, 2):
            faults = diagnose_reshare_local(
                member_id,
                packets_for(contributions, member_id),
                (1,),
                export_signing_public_context(key),
                key.result.commitment,
            )
            self.assertEqual(faults, ())

    def test_codec_roundtrip_packets_still_diagnose_clean(self):
        packets = [
            decode_local_dkg_packet(encode_local_dkg_packet(packet))
            for packet in packets_for(self.contributions, 4)
        ]
        self.assertEqual(self.diagnose(4, packets=packets), ())

    def test_more_dealers_than_old_threshold(self):
        dealers = (1, 2, 3)
        members = (1, 2, 3, 4)
        contributions = make_reshare_contributions(self.key, dealers, members, 2)
        faults = diagnose_reshare_local(
            4,
            packets_for(contributions, 4),
            dealers,
            self.context,
            self.commitment,
        )
        self.assertEqual(faults, ())


class DiagnoseReshareLocalFaultTest(unittest.TestCase):
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

    def diagnose(self, packets, receiver_id=3, dealers=_DEFAULT, context=_DEFAULT):
        return diagnose_reshare_local(
            receiver_id,
            packets,
            self.dealers if dealers is _DEFAULT else dealers,
            self.context if context is _DEFAULT else context,
            self.commitment,
        )

    def test_tampered_blinding_share_is_pedersen_fault_only(self):
        packets = [self.packets[0], tamper_blinding_share(self.packets[1])]
        self.assertEqual(self.diagnose(packets), (ReshareFault(3, "pedersen", 3),))

    def test_tampered_share_is_both_faults_pedersen_first(self):
        packets = [tamper_share(self.packets[0]), self.packets[1]]
        self.assertEqual(
            self.diagnose(packets),
            (
                ReshareFault(2, "pedersen", 3),
                ReshareFault(2, "feldman", 3),
            ),
        )

    def test_fault_receiver_id_is_the_diagnosing_receiver(self):
        packets = [tamper_share(packet) for packet in packets_for(self.contributions, 4)]
        self.assertEqual(
            self.diagnose(packets, receiver_id=4),
            (
                ReshareFault(2, "pedersen", 4),
                ReshareFault(2, "feldman", 4),
                ReshareFault(3, "pedersen", 4),
                ReshareFault(3, "feldman", 4),
            ),
        )

    def test_shifted_feldman_constant_is_feldman_then_binding(self):
        # The shifted constant breaks the Feldman evaluation of the share and
        # the binding to the old verification share; Pedersen still passes.
        packets = [shift_feldman_constant(self.packets[0]), self.packets[1]]
        self.assertEqual(
            self.diagnose(packets),
            (
                ReshareFault(2, "feldman", 3),
                ReshareFault(2, "binding", None),
            ),
        )

    def test_self_consistent_wrong_constant_is_binding_fault_only(self):
        # An ordinary signing contribution addressed to the new members is
        # internally consistent but its constant is random, so only the
        # binding check fails.
        ordinary = create_signing_contribution(
            2,
            self.members,
            2,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            blinding_generator=BLINDING_GENERATOR,
            randbelow=fixed_random(42),
        )
        packets = [packet_for(ordinary, 3), self.packets[1]]
        self.assertEqual(self.diagnose(packets), (ReshareFault(2, "binding", None),))

    def test_all_three_checks_of_one_dealer_all_reported_in_order(self):
        # Tamper the blinding share (pedersen fails) and shift the Feldman
        # constant (feldman and binding fail) of the same dealer's packet.
        bad = shift_feldman_constant(tamper_blinding_share(self.packets[0]))
        self.assertEqual(
            self.diagnose([bad, self.packets[1]]),
            (
                ReshareFault(2, "pedersen", 3),
                ReshareFault(2, "feldman", 3),
                ReshareFault(2, "binding", None),
            ),
        )

    def test_several_dealers_sorted_by_sender_with_all_faults_kept(self):
        packets = [
            shift_feldman_constant(self.packets[1]),
            tamper_share(self.packets[0]),
        ]
        expected = (
            ReshareFault(2, "pedersen", 3),
            ReshareFault(2, "feldman", 3),
            ReshareFault(3, "feldman", 3),
            ReshareFault(3, "binding", None),
        )
        self.assertEqual(self.diagnose(packets), expected)
        self.assertEqual(self.diagnose(list(reversed(packets))), expected)

    def test_fault_senders_match_reshare_local_rejections(self):
        packets = [
            tamper_blinding_share(self.packets[1]),
            tamper_share(self.packets[0]),
        ]
        outcome = reshare_local(
            3, list(packets), self.dealers, self.context, self.commitment
        )
        self.assertEqual(
            [rejection.sender_id for rejection in outcome],
            sorted({fault.sender_id for fault in self.diagnose(packets)}),
        )

    def test_faults_returned_without_public_key_product_check(self):
        # The context's public key disagrees with the constant-term product,
        # which alone would raise ValueError after a clean scan; with faults
        # present the fault tuple is returned instead.
        wrong_key = self.context.public_key * GENERATOR % GROUP_PRIME
        broken = dataclasses.replace(self.context, public_key=wrong_key)
        packets = [tamper_share(self.packets[0]), self.packets[1]]
        self.assertEqual(
            self.diagnose(packets, context=broken),
            (
                ReshareFault(2, "pedersen", 3),
                ReshareFault(2, "feldman", 3),
            ),
        )

    def test_constant_product_mismatch_without_faults_raises(self):
        wrong_key = self.context.public_key * GENERATOR % GROUP_PRIME
        broken = dataclasses.replace(self.context, public_key=wrong_key)
        with self.assertRaises(ValueError):
            self.diagnose(self.packets, context=broken)


class DiagnoseReshareLocalTypeErrorTest(unittest.TestCase):
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

    def assert_both_raise(self, error, **overrides):
        receiver_id = overrides.get("receiver_id", 3)
        packets = overrides.get("packets", self.packets)
        dealers = overrides.get("dealers", self.dealers)
        context = overrides.get("context", self.context)
        commitment = overrides.get("commitment", self.commitment)
        with self.assertRaises(error):
            reshare_local(receiver_id, list(packets), list(dealers), context, commitment)
        with self.assertRaises(error):
            diagnose_reshare_local(receiver_id, packets, dealers, context, commitment)

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

    def test_non_packet_elements(self):
        for bad in ("packet", 7, self.packets[0].received, self.packets):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.diagnose(packets=[bad])

    def test_dealers_type(self):
        for bad in ("23", b"23", [2, "3"], [2, True], [2, 3.0]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.diagnose(dealers=bad)

    def test_packet_field_types_match_reshare_local(self):
        packet = self.packets[0]
        broken = dataclasses.replace(
            packet,
            received=dataclasses.replace(packet.received, share=Share(x=3, y=True)),
        )
        self.assert_both_raise(TypeError, packets=[broken, self.packets[1]])


class DiagnoseReshareLocalValueErrorTest(unittest.TestCase):
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

    def assert_both_raise(self, error, **overrides):
        receiver_id = overrides.get("receiver_id", 3)
        packets = overrides.get("packets", self.packets)
        dealers = overrides.get("dealers", self.dealers)
        context = overrides.get("context", self.context)
        commitment = overrides.get("commitment", self.commitment)
        with self.assertRaises(error):
            reshare_local(receiver_id, list(packets), list(dealers), context, commitment)
        with self.assertRaises(error):
            diagnose_reshare_local(receiver_id, packets, dealers, context, commitment)

    def test_empty_batch(self):
        self.assert_both_raise(ValueError, packets=[])

    def test_empty_dealers(self):
        self.assert_both_raise(ValueError, dealers=[])

    def test_dealers_not_increasing(self):
        self.assert_both_raise(ValueError, dealers=(3, 2))

    def test_dealers_not_unique(self):
        self.assert_both_raise(ValueError, dealers=(2, 2))

    def test_dealers_below_old_threshold(self):
        self.assert_both_raise(ValueError, dealers=(2,))

    def test_dealer_not_an_old_participant(self):
        self.assert_both_raise(ValueError, dealers=(2, 4))

    def test_dealer_not_a_new_member(self):
        self.assert_both_raise(ValueError, dealers=(1, 2))

    def test_receiver_not_a_new_member(self):
        for bad in (1, 5, 0, FIELD_PRIME):
            self.assert_both_raise(ValueError, receiver_id=bad)

    def test_missing_sender(self):
        self.assert_both_raise(ValueError, packets=self.packets[:1])

    def test_duplicate_sender(self):
        self.assert_both_raise(
            ValueError, packets=[self.packets[0], self.packets[0]]
        )

    def test_extra_sender(self):
        dealers = (1, 2)
        members = (1, 2, 3)
        contributions = make_reshare_contributions(self.key, dealers, members, 2)
        extra_contribution = create_reshare(
            1,
            secret_share_of(self.key, 1),
            (1, 2, 3),
            (1, 2, 3),
            2,
            self.key,
            rng=fixed_random(901),
        )
        packets = packets_for(contributions, 3) + [packet_for(extra_contribution, 3)]
        self.assert_both_raise(ValueError, packets=packets, dealers=dealers)

    def test_packet_receiver_mismatch(self):
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
        self.assert_both_raise(ValueError, packets=[broken, self.packets[1]])

    def test_packet_share_coordinate_mismatch(self):
        packet = self.packets[0]
        received = packet.received
        broken = dataclasses.replace(
            packet,
            received=dataclasses.replace(
                received, share=Share(x=4, y=received.share.y)
            ),
        )
        self.assert_both_raise(ValueError, packets=[broken, self.packets[1]])

    def test_packet_share_value_out_of_range(self):
        packet = self.packets[0]
        received = packet.received
        broken = dataclasses.replace(
            packet,
            received=dataclasses.replace(
                received, share=Share(x=3, y=FIELD_PRIME)
            ),
        )
        self.assert_both_raise(ValueError, packets=[broken, self.packets[1]])

    def test_packets_disagree_on_participant_ids(self):
        broken = dataclasses.replace(self.packets[1], participant_ids=(2, 3, 5))
        self.assert_both_raise(ValueError, packets=[self.packets[0], broken])

    def test_packets_disagree_on_threshold(self):
        other_contributions = make_reshare_contributions(
            self.key, self.dealers, self.members, 1, seed_base=800
        )
        other_packet = packets_for(other_contributions, 3)[1]
        self.assert_both_raise(
            ValueError, packets=[self.packets[0], other_packet]
        )

    def test_packets_do_not_reuse_old_group_parameters(self):
        packet = self.packets[1]
        commitment = packet.commitment
        # 4096 = 16 ** 3 mod 8069 is another legal subgroup generator.
        moved = dataclasses.replace(
            packet,
            commitment=dataclasses.replace(commitment, blinding_generator=4096),
        )
        self.assert_both_raise(ValueError, packets=[self.packets[0], moved])

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
        self.packets = packets_for(self.contributions, 3)

    def diagnose(self, packets, dealers=None):
        return diagnose_reshare_local(
            3,
            packets,
            self.dealers if dealers is None else dealers,
            self.context,
            self.commitment,
        )

    def test_input_unchanged_on_success(self):
        snapshot = copy.deepcopy(self.packets)
        dealers = list(self.dealers)
        self.diagnose(self.packets, dealers=dealers)
        self.assertEqual(self.packets, snapshot)
        self.assertEqual(dealers, list(self.dealers))

    def test_input_unchanged_with_faults(self):
        packets = [tamper_share(self.packets[0]), self.packets[1]]
        snapshot = copy.deepcopy(packets)
        self.diagnose(packets)
        self.assertEqual(packets, snapshot)

    def test_input_unchanged_on_value_error(self):
        packets = self.packets[:1]
        snapshot = copy.deepcopy(packets)
        with self.assertRaises(ValueError):
            self.diagnose(packets)
        self.assertEqual(packets, snapshot)


if __name__ == "__main__":
    unittest.main()
