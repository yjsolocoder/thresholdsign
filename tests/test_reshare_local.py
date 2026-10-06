"""Tests for receiver-local member resharing (reshare_local)."""

import dataclasses
import itertools
import unittest

from thresholdsign import (
    AggregateSignature,
    DKGReceivedShare,
    DKGRejection,
    LocalDKGPacket,
    PedersenCommitment,
    Share,
    SigningDKGResult,
    SigningPublicContext,
    SigningRoundPacket,
    aggregate_signature,
    aggregate_signing_dkg,
    create_refresh,
    create_reshare,
    create_signing_contribution,
    create_signing_nonce_commitment,
    create_signing_round,
    create_signature_share,
    export_signing_public_context,
    refresh_local,
    reshare,
    reshare_local,
    sign_round_packet,
    verify_signature,
    verify_signature_share,
)

# Same toy Pedersen setup as the DKG, signing, refresh and reshare tests:
# 8069 = 4 * 2017 + 1 is prime, 16 and 256 = 16 ** 2 are distinct
# generators of the order-2017 subgroup of the multiplicative group mod 8069.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

MESSAGE = b"local resharing test message"


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


class ReshareLocalValidTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.dealers = (2, 3)
        self.members = (2, 3, 4)
        self.threshold = 2
        self.contributions = make_reshare_contributions(
            self.key, self.dealers, self.members, self.threshold
        )
        self.reshared = reshare(self.contributions, self.dealers, self.key)
        assert isinstance(self.reshared, SigningDKGResult)
        self.old_context = export_signing_public_context(self.key)
        self.old_commitment = self.key.result.commitment

    def local(self, receiver_id, packets=None, dealers=None, context=None, commitment=None):
        return reshare_local(
            receiver_id,
            packets_for(self.contributions, receiver_id) if packets is None else packets,
            self.dealers if dealers is None else dealers,
            self.old_context if context is None else context,
            self.old_commitment if commitment is None else commitment,
        )

    def test_returns_four_tuple_with_own_coordinates(self):
        outcome = self.local(3)
        self.assertIsInstance(outcome, tuple)
        self.assertEqual(len(outcome), 4)
        share, blinding_share, commitment, context = outcome
        self.assertIsInstance(share, Share)
        self.assertIsInstance(blinding_share, Share)
        self.assertIsInstance(commitment, PedersenCommitment)
        self.assertIsInstance(context, SigningPublicContext)
        self.assertEqual(share.x, 3)
        self.assertEqual(blinding_share.x, 3)

    def test_matches_full_reshare_for_every_member(self):
        expected_context = export_signing_public_context(self.reshared)
        for index, member_id in enumerate(self.members):
            share, blinding_share, commitment, context = self.local(member_id)
            self.assertEqual(share, self.reshared.result.shares[index])
            self.assertEqual(blinding_share, self.reshared.result.blinding_shares[index])
            self.assertEqual(commitment, self.reshared.result.commitment)
            self.assertEqual(context, expected_context)

    def test_share_values_are_field_sums(self):
        packets = packets_for(self.contributions, 4)
        share, blinding_share, _commitment, _context = self.local(4)
        self.assertEqual(
            share.y, sum(p.received.share.y for p in packets) % FIELD_PRIME
        )
        self.assertEqual(
            blinding_share.y,
            sum(p.received.blinding_share.y for p in packets) % FIELD_PRIME,
        )

    def test_commitment_is_pointwise_group_product(self):
        packets = packets_for(self.contributions, 2)
        _share, _blinding, commitment, _context = self.local(2)
        for position in range(self.threshold):
            expected = 1
            for packet in packets:
                expected = expected * packet.commitment.values[position] % GROUP_PRIME
            self.assertEqual(commitment.values[position], expected)
        self.assertEqual(commitment.field_prime, FIELD_PRIME)
        self.assertEqual(commitment.group_prime, GROUP_PRIME)
        self.assertEqual(commitment.generator, GENERATOR)
        self.assertEqual(commitment.blinding_generator, BLINDING_GENERATOR)

    def test_context_keeps_public_key_and_updates_verification_shares(self):
        packets = packets_for(self.contributions, 3)
        _share, _blinding, _commitment, context = self.local(3)
        self.assertEqual(context.participant_ids, self.members)
        self.assertEqual(context.threshold, self.threshold)
        self.assertEqual(context.field_prime, self.old_context.field_prime)
        self.assertEqual(context.group_prime, self.old_context.group_prime)
        self.assertEqual(context.generator, self.old_context.generator)
        self.assertEqual(context.public_key, self.old_context.public_key)
        for index, member_id in enumerate(self.members):
            expected = 1
            for packet in packets:
                x_power = 1
                evaluation = 1
                for value in packet.feldman_commitment.values:
                    evaluation = evaluation * pow(value, x_power, GROUP_PRIME) % GROUP_PRIME
                    x_power = x_power * member_id % FIELD_PRIME
                expected = expected * evaluation % GROUP_PRIME
            self.assertEqual(context.verification_shares[index], expected)

    def test_member_set_and_threshold_come_from_packets(self):
        # A different new member set and threshold than the old ones.
        key = make_key()
        dealers = (1, 2, 3)
        members = (1, 2, 3, 4, 5)
        contributions = make_reshare_contributions(key, dealers, members, 3, seed_base=700)
        full = reshare(contributions, dealers, key)
        assert isinstance(full, SigningDKGResult)
        outcome = reshare_local(
            5,
            packets_for(contributions, 5),
            dealers,
            export_signing_public_context(key),
            key.result.commitment,
        )
        self.assertNotIsInstance(outcome, list)
        share, _blinding, commitment, context = outcome
        self.assertEqual(context.participant_ids, members)
        self.assertEqual(context.threshold, 3)
        self.assertEqual(share, full.result.shares[-1])
        self.assertEqual(commitment, full.result.commitment)
        self.assertEqual(context, export_signing_public_context(full))

    def test_input_order_does_not_matter(self):
        expected = self.local(3)
        for permutation in itertools.permutations(self.contributions):
            packets = packets_for(permutation, 3)
            self.assertEqual(self.local(3, packets=packets), expected)

    def test_single_pass_iterators(self):
        outcome = reshare_local(
            3,
            iter(packets_for(self.contributions, 3)),
            iter(self.dealers),
            self.old_context,
            self.old_commitment,
        )
        self.assertEqual(outcome, self.local(3))

    def test_does_not_mutate_inputs(self):
        packets = packets_for(self.contributions, 3)
        snapshot = list(packets)
        dealers = list(self.dealers)
        self.local(3, packets=packets, dealers=dealers)
        self.assertEqual(packets, snapshot)
        self.assertEqual(dealers, list(self.dealers))

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
        full = reshare(contributions, (1,), key)
        assert isinstance(full, SigningDKGResult)
        outcome = reshare_local(
            2,
            packets_for(contributions, 2),
            (1,),
            export_signing_public_context(key),
            key.result.commitment,
        )
        self.assertNotIsInstance(outcome, list)
        share, blinding_share, commitment, context = outcome
        self.assertEqual(share, full.result.shares[1])
        self.assertEqual(blinding_share, full.result.blinding_shares[1])
        self.assertEqual(commitment, full.result.commitment)
        self.assertEqual(context, export_signing_public_context(full))
        self.assertEqual(share.y, 0)
        self.assertEqual(context.public_key, 1)
        self.assertEqual(commitment.values, (1,))

    def test_local_reshare_signs_with_sign_round_packet(self):
        local = {member_id: self.local(member_id) for member_id in self.members}
        context = local[2][3]
        for _share, _blinding, _commitment, local_context in local.values():
            self.assertEqual(local_context, context)

        signer_ids = (2, 3)
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
                local[signer_id][3],
                MESSAGE,
            )
            for signer_id in signer_ids
        ]
        for share in shares:
            self.assertTrue(verify_signature_share(share, round_info, context))
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

    def test_old_signature_still_verifies_after_local_reshare(self):
        # The joint public key is unchanged, so a signature made under the
        # old shares remains valid after the local resharing.
        signer_ids = (1, 2)
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
        round_info = create_signing_round(MESSAGE, signer_ids, commitments, self.key)
        old_shares = [
            create_signature_share(
                signer_id,
                secret_share_of(self.key, signer_id),
                nonces[signer_id],
                round_info,
                self.key,
            )
            for signer_id in signer_ids
        ]
        signature = aggregate_signature(old_shares, round_info, self.key)
        self.assertIsInstance(signature, AggregateSignature)

        _share, _blinding, _commitment, new_context = self.local(4)
        self.assertEqual(new_context.public_key, self.old_context.public_key)
        self.assertTrue(
            verify_signature(
                MESSAGE,
                signature,
                new_context.public_key,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            )
        )

    def test_local_reshare_material_refreshes_with_refresh_local(self):
        share, blinding_share, commitment, context = self.local(3)
        refresh_contributions = [
            create_refresh(pid, self.reshared, randbelow=fixed_random(pid + 500))
            for pid in self.reshared.result.participant_ids
        ]
        outcome = refresh_local(
            3,
            share,
            blinding_share,
            commitment,
            context,
            packets_for(refresh_contributions, 3),
        )
        self.assertNotIsInstance(outcome, list)


class ReshareLocalRejectionTest(unittest.TestCase):
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

    def local(self, packets, receiver_id=3):
        return reshare_local(
            receiver_id, packets, self.dealers, self.context, self.commitment
        )

    def tamper_share(self, packet, delta=1):
        received = packet.received
        tampered = Share(x=received.share.x, y=(received.share.y + delta) % FIELD_PRIME)
        return dataclasses.replace(
            packet, received=dataclasses.replace(received, share=tampered)
        )

    def test_tampered_share_produces_rejection(self):
        packets = [self.tamper_share(self.packets[0]), self.packets[1]]
        self.assertEqual(self.local(packets), [DKGRejection(sender_id=2)])

    def test_tampered_blinding_share_produces_rejection(self):
        packet = self.packets[1]
        received = packet.received
        tampered = Share(
            x=received.blinding_share.x,
            y=(received.blinding_share.y + 1) % FIELD_PRIME,
        )
        packets = [
            self.packets[0],
            dataclasses.replace(
                packet,
                received=dataclasses.replace(received, blinding_share=tampered),
            ),
        ]
        self.assertEqual(self.local(packets), [DKGRejection(sender_id=3)])

    def test_mismatched_feldman_commitment_produces_rejection(self):
        packets = list(self.packets)
        packets[0] = dataclasses.replace(
            packets[0], feldman_commitment=self.packets[1].feldman_commitment
        )
        self.assertEqual(self.local(packets), [DKGRejection(sender_id=2)])

    def test_unbound_constant_term_produces_rejection(self):
        # The Feldman constant-term commitment must equal the dealer's old
        # verification share raised to its Lagrange weight over the dealers.
        packet = self.packets[0]
        feldman = packet.feldman_commitment
        moved = dataclasses.replace(
            packet,
            feldman_commitment=dataclasses.replace(
                feldman,
                values=(feldman.values[0] * GENERATOR % GROUP_PRIME,)
                + feldman.values[1:],
            ),
        )
        self.assertEqual(self.local([moved, self.packets[1]]), [DKGRejection(sender_id=2)])

    def test_all_failures_listed_sorted_and_deduplicated(self):
        packets = [
            self.tamper_share(self.packets[1]),
            self.tamper_share(self.packets[0]),
        ]
        outcome = self.local(packets)
        self.assertIsInstance(outcome, list)
        self.assertEqual(
            outcome,
            [DKGRejection(sender_id=2), DKGRejection(sender_id=3)],
        )
        sender_ids = [rejection.sender_id for rejection in outcome]
        self.assertEqual(sender_ids, sorted(set(sender_ids)))

    def test_rejection_returns_no_partial_result(self):
        packets = [self.tamper_share(self.packets[0]), self.packets[1]]
        self.assertNotIsInstance(self.local(packets), tuple)


class ReshareLocalTypeErrorTest(unittest.TestCase):
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

    def local(self, receiver_id=3, packets=_DEFAULT, dealers=_DEFAULT,
              context=_DEFAULT, commitment=_DEFAULT):
        return reshare_local(
            receiver_id,
            self.packets if packets is _DEFAULT else packets,
            self.dealers if dealers is _DEFAULT else dealers,
            self.context if context is _DEFAULT else context,
            self.commitment if commitment is _DEFAULT else commitment,
        )

    def test_receiver_id_type(self):
        for bad in ("3", 3.0, None, True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.local(receiver_id=bad)

    def test_context_type(self):
        for bad in ("context", 7, None, self.commitment):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.local(context=bad)

    def test_context_field_types(self):
        with self.assertRaises(TypeError):
            self.local(context=dataclasses.replace(self.context, threshold=True))
        with self.assertRaises(TypeError):
            self.local(
                context=dataclasses.replace(self.context, participant_ids=[2, 3])
            )
        with self.assertRaises(TypeError):
            self.local(
                context=dataclasses.replace(
                    self.context, verification_shares=(1, 2, "3")
                )
            )

    def test_commitment_type(self):
        for bad in ("commitment", 7, None, self.context):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.local(commitment=bad)

    def test_commitment_field_types(self):
        commitment = self.commitment
        for field in ("field_prime", "group_prime", "generator", "blinding_generator"):
            for bad in (True, "x"):
                broken = dataclasses.replace(commitment, **{field: bad})
                with self.assertRaises(TypeError, msg=f"{field}={bad!r}"):
                    self.local(commitment=broken)
        with self.assertRaises(TypeError):
            self.local(
                commitment=dataclasses.replace(
                    commitment, values=list(commitment.values)
                )
            )
        with self.assertRaises(TypeError):
            self.local(
                commitment=dataclasses.replace(
                    commitment, values=(True,) + commitment.values[1:]
                )
            )

    def test_non_packet_elements(self):
        for bad in ("packet", 7, self.packets[0].received, self.packets):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.local(packets=[bad])

    def test_dealers_type(self):
        for bad in ("23", b"23", [2, "3"], [2, True], [2, 3.0]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.local(dealers=bad)


class ReshareLocalValueErrorTest(unittest.TestCase):
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

    def local(self, receiver_id=3, packets=_DEFAULT, dealers=_DEFAULT,
              context=_DEFAULT, commitment=_DEFAULT):
        return reshare_local(
            receiver_id,
            self.packets if packets is _DEFAULT else packets,
            self.dealers if dealers is _DEFAULT else dealers,
            self.context if context is _DEFAULT else context,
            self.commitment if commitment is _DEFAULT else commitment,
        )

    def test_empty_batch(self):
        with self.assertRaises(ValueError):
            self.local(packets=[])

    def test_empty_dealers(self):
        with self.assertRaises(ValueError):
            self.local(dealers=[])

    def test_dealers_not_increasing(self):
        with self.assertRaises(ValueError):
            self.local(dealers=(3, 2))

    def test_dealers_not_unique(self):
        with self.assertRaises(ValueError):
            self.local(dealers=(2, 2))

    def test_dealers_below_old_threshold(self):
        with self.assertRaises(ValueError):
            self.local(dealers=(2,))

    def test_dealer_not_an_old_participant(self):
        with self.assertRaises(ValueError):
            self.local(dealers=(2, 4))

    def test_dealer_not_a_new_member(self):
        with self.assertRaises(ValueError):
            self.local(dealers=(1, 2))

    def test_receiver_not_a_new_member(self):
        for bad in (1, 5, 0, FIELD_PRIME):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.local(receiver_id=bad)

    def test_missing_sender(self):
        with self.assertRaises(ValueError):
            self.local(packets=self.packets[:1])

    def test_duplicate_sender(self):
        with self.assertRaises(ValueError):
            self.local(packets=[self.packets[0], self.packets[0]])

    def test_extra_sender(self):
        # A structurally legal packet from a non-dealer old participant.
        extra_contribution = create_reshare(
            1,
            secret_share_of(self.key, 1),
            (1, 2, 3),
            (1, 2, 3),
            2,
            self.key,
            rng=fixed_random(901),
        )
        members = (1, 2, 3)
        dealers = (1, 2)
        contributions = make_reshare_contributions(self.key, dealers, members, 2)
        packets = packets_for(contributions, 3) + [packet_for(extra_contribution, 3)]
        with self.assertRaises(ValueError):
            self.local(packets=packets, dealers=dealers)

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
        with self.assertRaises(ValueError):
            self.local(packets=[broken, self.packets[1]])

    def test_packet_share_coordinate_mismatch(self):
        packet = self.packets[0]
        received = packet.received
        broken = dataclasses.replace(
            packet,
            received=dataclasses.replace(
                received, share=Share(x=4, y=received.share.y)
            ),
        )
        with self.assertRaises(ValueError):
            self.local(packets=[broken, self.packets[1]])

    def test_packet_share_value_out_of_range(self):
        packet = self.packets[0]
        received = packet.received
        broken = dataclasses.replace(
            packet,
            received=dataclasses.replace(
                received, share=Share(x=3, y=FIELD_PRIME)
            ),
        )
        with self.assertRaises(ValueError):
            self.local(packets=[broken, self.packets[1]])

    def test_packets_disagree_on_participant_ids(self):
        packet = self.packets[1]
        broken = dataclasses.replace(packet, participant_ids=(2, 3, 5))
        with self.assertRaises(ValueError):
            self.local(packets=[self.packets[0], broken])

    def test_packets_disagree_on_threshold(self):
        other_contributions = make_reshare_contributions(
            self.key, self.dealers, self.members, 1, seed_base=800
        )
        other_packet = packets_for(other_contributions, 3)[1]
        with self.assertRaises(ValueError):
            self.local(packets=[self.packets[0], other_packet])

    def test_packets_do_not_reuse_old_group_parameters(self):
        packet = self.packets[1]
        commitment = packet.commitment
        # 4096 = 16 ** 3 mod 8069 is another legal subgroup generator.
        moved = dataclasses.replace(
            packet,
            commitment=dataclasses.replace(commitment, blinding_generator=4096),
        )
        with self.assertRaises(ValueError):
            self.local(packets=[self.packets[0], moved])

    def test_commitment_group_mismatch_with_context(self):
        # 256 is a legal subgroup generator but not the context's generator.
        with self.assertRaises(ValueError):
            self.local(
                commitment=dataclasses.replace(
                    self.commitment,
                    generator=BLINDING_GENERATOR,
                    blinding_generator=GENERATOR,
                )
            )

    def test_commitment_threshold_mismatch_with_context(self):
        with self.assertRaises(ValueError):
            self.local(
                commitment=dataclasses.replace(
                    self.commitment, values=self.commitment.values + (1,)
                )
            )
        with self.assertRaises(ValueError):
            self.local(
                commitment=dataclasses.replace(
                    self.commitment, values=self.commitment.values[:1]
                )
            )

    def test_illegal_old_commitment_values(self):
        for bad_value in (0, GROUP_PRIME, 2):
            broken = dataclasses.replace(
                self.commitment, values=(bad_value,) + self.commitment.values[1:]
            )
            with self.assertRaises(ValueError, msg=repr(bad_value)):
                self.local(commitment=broken)

    def test_illegal_context_values(self):
        with self.assertRaises(ValueError):
            self.local(
                context=dataclasses.replace(self.context, participant_ids=(2, 1, 3))
            )
        with self.assertRaises(ValueError):
            self.local(context=dataclasses.replace(self.context, threshold=4))
        with self.assertRaises(ValueError):
            self.local(context=dataclasses.replace(self.context, public_key=0))

    def test_constant_product_mismatch_with_old_public_key(self):
        # Every packet verifies against the context's verification shares,
        # but the context's public key does not match their product.
        wrong_key = self.context.public_key * GENERATOR % GROUP_PRIME
        broken = dataclasses.replace(self.context, public_key=wrong_key)
        with self.assertRaises(ValueError):
            self.local(context=broken)


if __name__ == "__main__":
    unittest.main()
