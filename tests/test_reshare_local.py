"""Tests for receiver-local member resharing (reshare_local)."""

import dataclasses
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
    refresh,
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

OLD_IDS = (1, 2, 3)
OLD_THRESHOLD = 2
DEALERS = (2, 3)
MEMBERS = (2, 3, 4, 5)
NEW_THRESHOLD = 3

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


def make_key(participant_ids=OLD_IDS, threshold=OLD_THRESHOLD, randbelow=None, seed_base=0):
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


def make_reshare_contributions(
    key, dealers=DEALERS, members=MEMBERS, threshold=NEW_THRESHOLD, seed_base=100
):
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
        self.contributions = make_reshare_contributions(self.key)
        self.full = reshare(self.contributions, DEALERS, self.key)
        assert isinstance(self.full, SigningDKGResult)
        self.old_context = export_signing_public_context(self.key)
        self.old_commitment = self.key.result.commitment

    def local(self, receiver_id, packets=_DEFAULT, dealers=_DEFAULT):
        return reshare_local(
            receiver_id,
            packets_for(self.contributions, receiver_id)
            if packets is _DEFAULT
            else packets,
            DEALERS if dealers is _DEFAULT else dealers,
            self.old_context,
            self.old_commitment,
        )

    def test_returns_four_tuple_with_own_coordinates(self):
        outcome = self.local(4)
        self.assertIsInstance(outcome, tuple)
        self.assertEqual(len(outcome), 4)
        share, blinding_share, commitment, context = outcome
        self.assertIsInstance(share, Share)
        self.assertIsInstance(blinding_share, Share)
        self.assertIsInstance(commitment, PedersenCommitment)
        self.assertIsInstance(context, SigningPublicContext)
        self.assertEqual(share.x, 4)
        self.assertEqual(blinding_share.x, 4)

    def test_matches_full_reshare_for_every_member(self):
        expected_context = export_signing_public_context(self.full)
        for index, member_id in enumerate(MEMBERS):
            share, blinding_share, commitment, context = self.local(member_id)
            self.assertEqual(share, self.full.result.shares[index])
            self.assertEqual(blinding_share, self.full.result.blinding_shares[index])
            self.assertEqual(commitment, self.full.result.commitment)
            self.assertEqual(context, expected_context)

    def test_share_values_are_field_sums_of_received_shares(self):
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
        for position in range(NEW_THRESHOLD):
            expected = 1
            for packet in packets:
                expected = expected * packet.commitment.values[position] % GROUP_PRIME
            self.assertEqual(commitment.values[position], expected)
        self.assertEqual(commitment.field_prime, FIELD_PRIME)
        self.assertEqual(commitment.group_prime, GROUP_PRIME)
        self.assertEqual(commitment.generator, GENERATOR)
        self.assertEqual(commitment.blinding_generator, BLINDING_GENERATOR)

    def test_context_keeps_old_public_key_and_group_parameters(self):
        _share, _blinding, _commitment, context = self.local(3)
        self.assertEqual(context.participant_ids, MEMBERS)
        self.assertEqual(context.threshold, NEW_THRESHOLD)
        self.assertEqual(context.field_prime, self.old_context.field_prime)
        self.assertEqual(context.group_prime, self.old_context.group_prime)
        self.assertEqual(context.generator, self.old_context.generator)
        self.assertEqual(context.public_key, self.old_context.public_key)
        for index, member_id in enumerate(MEMBERS):
            self.assertEqual(
                context.verification_shares[index],
                pow(GENERATOR, self.full.result.shares[index].y, GROUP_PRIME),
            )

    def test_input_order_does_not_matter(self):
        packets = packets_for(self.contributions, 5)
        forward = self.local(5, packets=packets)
        reversed_outcome = self.local(5, packets=list(reversed(packets)))
        self.assertEqual(forward, reversed_outcome)

    def test_accepts_single_pass_iterators(self):
        outcome = reshare_local(
            4,
            iter(packets_for(self.contributions, 4)),
            iter(DEALERS),
            self.old_context,
            self.old_commitment,
        )
        self.assertIsInstance(outcome, tuple)
        again = reshare_local(
            4,
            (p for p in packets_for(self.contributions, 4)),
            (d for d in DEALERS),
            self.old_context,
            self.old_commitment,
        )
        self.assertEqual(outcome, again)

    def test_threshold_one(self):
        contributions = make_reshare_contributions(self.key, threshold=1)
        full = reshare(contributions, DEALERS, self.key)
        assert isinstance(full, SigningDKGResult)
        for index, member_id in enumerate(MEMBERS):
            share, blinding_share, commitment, context = reshare_local(
                member_id,
                packets_for(contributions, member_id),
                DEALERS,
                self.old_context,
                self.old_commitment,
            )
            self.assertEqual(share, full.result.shares[index])
            self.assertEqual(blinding_share, full.result.blinding_shares[index])
            self.assertEqual(commitment, full.result.commitment)
            self.assertEqual(context, export_signing_public_context(full))
            self.assertEqual(context.threshold, 1)

    def test_more_dealers_than_old_threshold(self):
        dealers = (1, 2, 3)
        members = (1, 2, 3, 4)
        contributions = make_reshare_contributions(
            self.key, dealers=dealers, members=members, threshold=2
        )
        full = reshare(contributions, dealers, self.key)
        assert isinstance(full, SigningDKGResult)
        for index, member_id in enumerate(members):
            share, blinding_share, commitment, context = reshare_local(
                member_id,
                packets_for(contributions, member_id),
                dealers,
                self.old_context,
                self.old_commitment,
            )
            self.assertEqual(share, full.result.shares[index])
            self.assertEqual(blinding_share, full.result.blinding_shares[index])
            self.assertEqual(commitment, full.result.commitment)
            self.assertEqual(context, export_signing_public_context(full))

    def test_zero_shares_and_identity_commitments(self):
        # All-zero draws give all-zero sharing and blinding polynomials:
        # zero share values and identity commitment values stay legal.
        key = make_key(randbelow=zero_random())
        contributions = [
            create_reshare(
                dealer,
                secret_share_of(key, dealer),
                DEALERS,
                MEMBERS,
                NEW_THRESHOLD,
                key,
                rng=zero_random(),
            )
            for dealer in DEALERS
        ]
        full = reshare(contributions, DEALERS, key)
        assert isinstance(full, SigningDKGResult)
        share, blinding_share, commitment, context = reshare_local(
            4,
            packets_for(contributions, 4),
            DEALERS,
            export_signing_public_context(key),
            key.result.commitment,
        )
        self.assertEqual(share, Share(x=4, y=0))
        self.assertEqual(blinding_share, Share(x=4, y=0))
        self.assertEqual(commitment, full.result.commitment)
        self.assertEqual(commitment.values, (1, 1, 1))
        self.assertEqual(context, export_signing_public_context(full))
        self.assertEqual(context.public_key, 1)
        self.assertEqual(context.verification_shares, (1, 1, 1, 1))

    def test_does_not_mutate_inputs_and_is_deterministic(self):
        packets = packets_for(self.contributions, 4)
        snapshot = list(packets)
        first = self.local(4, packets=packets)
        second = self.local(4, packets=packets)
        self.assertEqual(first, second)
        self.assertEqual(packets, snapshot)

    def test_success_certifies_only_own_material(self):
        # A share addressed to another receiver is tampered inside one
        # contribution: the full resharing rejects the dealer, but receiver
        # 4's own packets are untouched and still migrate successfully.
        tampered_contributions = list(self.contributions)
        contribution = tampered_contributions[0]
        dealing = contribution.contribution
        index = dealing.participant_ids.index(3)
        shares = list(dealing.shares)
        shares[index] = Share(x=shares[index].x, y=(shares[index].y + 1) % FIELD_PRIME)
        tampered_contributions[0] = dataclasses.replace(
            contribution,
            contribution=dataclasses.replace(dealing, shares=tuple(shares)),
        )
        self.assertIsInstance(
            reshare(tampered_contributions, DEALERS, self.key), list
        )
        outcome = self.local(4)
        self.assertIsInstance(outcome, tuple)

    def test_local_reshare_signs_with_sign_round_packet(self):
        local = {member_id: self.local(member_id) for member_id in MEMBERS}
        context = local[MEMBERS[0]][3]
        for _share, _blinding, _commitment, local_context in local.values():
            self.assertEqual(local_context, context)

        signer_ids = MEMBERS[:NEW_THRESHOLD]
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

    def test_local_reshare_material_drops_into_refresh_local(self):
        # The migrated material of one new member refreshes locally against
        # the refresh contributions made for the fully reshared key.
        refresh_contributions = [
            create_refresh(pid, self.full, randbelow=fixed_random(pid + 500))
            for pid in MEMBERS
        ]
        refreshed = refresh(refresh_contributions, self.full)
        assert isinstance(refreshed, SigningDKGResult)
        share, blinding_share, commitment, context = self.local(4)
        share2, blinding2, commitment2, context2 = refresh_local(
            4,
            share,
            blinding_share,
            commitment,
            context,
            packets_for(refresh_contributions, 4),
        )
        index = MEMBERS.index(4)
        self.assertEqual(share2, refreshed.result.shares[index])
        self.assertEqual(blinding2, refreshed.result.blinding_shares[index])
        self.assertEqual(commitment2, refreshed.result.commitment)
        self.assertEqual(context2, export_signing_public_context(refreshed))


class ReshareLocalRejectionTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.contributions = make_reshare_contributions(self.key)
        self.old_context = export_signing_public_context(self.key)
        self.old_commitment = self.key.result.commitment
        self.packets = packets_for(self.contributions, 4)

    def local(self, packets):
        return reshare_local(
            4, packets, DEALERS, self.old_context, self.old_commitment
        )

    def tamper_share(self, packet, delta=1):
        received = packet.received
        tampered = Share(x=received.share.x, y=(received.share.y + delta) % FIELD_PRIME)
        return dataclasses.replace(
            packet, received=dataclasses.replace(received, share=tampered)
        )

    def test_tampered_share_produces_rejection(self):
        packets = [self.tamper_share(self.packets[0]), *self.packets[1:]]
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
        # A plain signing contribution is structurally legal and its double
        # share verifies against both of its commitments, but its Feldman
        # constant-term commitment is not Y_i ** lambda_i over the dealers.
        plain = create_signing_contribution(
            2,
            MEMBERS,
            NEW_THRESHOLD,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            blinding_generator=BLINDING_GENERATOR,
            randbelow=fixed_random(999),
        )
        packets = [packet_for(plain, 4), *self.packets[1:]]
        self.assertEqual(self.local(packets), [DKGRejection(sender_id=2)])

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
        packets = [self.tamper_share(self.packets[0]), *self.packets[1:]]
        self.assertNotIsInstance(self.local(packets), tuple)


class ReshareLocalTypeErrorTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.contributions = make_reshare_contributions(self.key)
        self.old_context = export_signing_public_context(self.key)
        self.old_commitment = self.key.result.commitment
        self.packets = packets_for(self.contributions, 4)

    def local(self, receiver_id=4, packets=_DEFAULT, dealers=_DEFAULT,
              old_context=_DEFAULT, old_commitment=_DEFAULT):
        return reshare_local(
            receiver_id,
            self.packets if packets is _DEFAULT else packets,
            DEALERS if dealers is _DEFAULT else dealers,
            self.old_context if old_context is _DEFAULT else old_context,
            self.old_commitment if old_commitment is _DEFAULT else old_commitment,
        )

    def test_receiver_id_type(self):
        for bad in ("4", 4.0, None, True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.local(receiver_id=bad)

    def test_dealers_type(self):
        for bad in ("23", 7, None, [2, "3"], [2, True], (2, 3.0)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.local(dealers=bad)

    def test_old_context_type(self):
        for bad in ("context", 7, None, self.key):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.local(old_context=bad)

    def test_old_context_field_types(self):
        for bad_context in (
            dataclasses.replace(self.old_context, threshold=True),
            dataclasses.replace(self.old_context, public_key="1"),
            dataclasses.replace(self.old_context, participant_ids=[2, 3]),
            dataclasses.replace(self.old_context, verification_shares=(1, True, 1)),
        ):
            with self.assertRaises(TypeError, msg=repr(bad_context)):
                self.local(old_context=bad_context)

    def test_old_commitment_type(self):
        for bad in ("commitment", 7, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.local(old_commitment=bad)

    def test_old_commitment_field_types(self):
        for bad_commitment in (
            dataclasses.replace(self.old_commitment, field_prime=True),
            dataclasses.replace(self.old_commitment, blinding_generator="256"),
            dataclasses.replace(self.old_commitment, values=[1, 1]),
            dataclasses.replace(self.old_commitment, values=(1, False)),
        ):
            with self.assertRaises(TypeError, msg=repr(bad_commitment)):
                self.local(old_commitment=bad_commitment)

    def test_non_packet_elements(self):
        for bad in ("packet", 7, None, self.contributions[0]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.local(packets=[*self.packets, bad])

    def test_packet_field_types(self):
        packet = self.packets[0]
        for bad_packet in (
            dataclasses.replace(packet, participant_ids=[2, 3, 4, 5]),
            dataclasses.replace(
                packet,
                received=dataclasses.replace(packet.received, sender_id=True),
            ),
            dataclasses.replace(packet, commitment="commitment"),
            dataclasses.replace(packet, feldman_commitment=None),
        ):
            with self.assertRaises(TypeError, msg=repr(bad_packet)):
                self.local(packets=[bad_packet, *self.packets[1:]])


class ReshareLocalValueErrorTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.contributions = make_reshare_contributions(self.key)
        self.old_context = export_signing_public_context(self.key)
        self.old_commitment = self.key.result.commitment
        self.packets = packets_for(self.contributions, 4)

    def local(self, receiver_id=4, packets=_DEFAULT, dealers=_DEFAULT,
              old_context=_DEFAULT, old_commitment=_DEFAULT):
        return reshare_local(
            receiver_id,
            self.packets if packets is _DEFAULT else packets,
            DEALERS if dealers is _DEFAULT else dealers,
            self.old_context if old_context is _DEFAULT else old_context,
            self.old_commitment if old_commitment is _DEFAULT else old_commitment,
        )

    def test_empty_batch(self):
        with self.assertRaises(ValueError):
            self.local(packets=[])

    def test_receiver_not_a_new_member(self):
        for bad_receiver in (1, 6):
            with self.assertRaises(ValueError, msg=repr(bad_receiver)):
                self.local(receiver_id=bad_receiver)

    def test_dealer_set_violations(self):
        for bad_dealers in (
            (),                # no dealers at all
            (2,),              # fewer than the old threshold
            (2, 2),            # duplicate
            (3, 2),            # not strictly increasing
            (2, 3, 7),         # 7 is not an old participant
            (1, 2, 3),         # 1 is not one of the new members
        ):
            with self.assertRaises(ValueError, msg=repr(bad_dealers)):
                self.local(dealers=bad_dealers)

    def test_missing_sender(self):
        with self.assertRaises(ValueError):
            self.local(packets=self.packets[1:])

    def test_duplicate_sender(self):
        with self.assertRaises(ValueError):
            self.local(packets=[*self.packets, self.packets[0]])

    def test_extra_sender(self):
        # A structurally legal packet from new member 5, who is no dealer.
        packet = self.packets[0]
        extra = dataclasses.replace(
            packet,
            received=dataclasses.replace(packet.received, sender_id=5),
        )
        with self.assertRaises(ValueError):
            self.local(packets=[*self.packets, extra])

    def test_sender_not_a_new_member(self):
        packet = self.packets[0]
        bad = dataclasses.replace(
            packet,
            received=dataclasses.replace(packet.received, sender_id=1),
        )
        with self.assertRaises(ValueError):
            self.local(packets=[bad, *self.packets[1:]])

    def test_received_address_mismatch(self):
        packet = self.packets[0]
        bad = dataclasses.replace(
            packet,
            received=dataclasses.replace(packet.received, receiver_id=5),
        )
        with self.assertRaises(ValueError):
            self.local(packets=[bad, *self.packets[1:]])

    def test_share_coordinate_mismatch(self):
        packet = self.packets[0]
        received = packet.received
        bad = dataclasses.replace(
            packet,
            received=dataclasses.replace(
                received, share=Share(x=5, y=received.share.y)
            ),
        )
        with self.assertRaises(ValueError):
            self.local(packets=[bad, *self.packets[1:]])

    def test_share_value_out_of_range(self):
        packet = self.packets[0]
        received = packet.received
        bad = dataclasses.replace(
            packet,
            received=dataclasses.replace(
                received, share=Share(x=4, y=FIELD_PRIME)
            ),
        )
        with self.assertRaises(ValueError):
            self.local(packets=[bad, *self.packets[1:]])

    def test_packets_disagree_on_members(self):
        packet = self.packets[0]
        bad = dataclasses.replace(packet, participant_ids=(2, 3, 4))
        with self.assertRaises(ValueError):
            self.local(packets=[bad, *self.packets[1:]])

    def test_packets_disagree_on_threshold(self):
        other = make_reshare_contributions(self.key, threshold=2, seed_base=700)
        packets = [packet_for(other[0], 4), *self.packets[1:]]
        with self.assertRaises(ValueError):
            self.local(packets=packets)

    def test_packets_commitment_length_mismatch(self):
        packet = self.packets[0]
        bad = dataclasses.replace(
            packet,
            commitment=dataclasses.replace(
                packet.commitment, values=packet.commitment.values[:2]
            ),
        )
        with self.assertRaises(ValueError):
            self.local(packets=[bad, *self.packets[1:]])

    def test_packets_with_foreign_group_parameters(self):
        # A resharing of a different key over a different (still legal)
        # blinding generator does not use the old group parameters:
        # 4096 = 16 ** 3 mod 8069 is a non-identity subgroup element
        # distinct from both 16 and 256.
        other_key = make_key_with_blinding(4096)
        other_contributions = [
            create_reshare(
                dealer,
                secret_share_of(other_key, dealer),
                (2, 3),
                MEMBERS,
                NEW_THRESHOLD,
                other_key,
                rng=fixed_random(dealer + 800),
            )
            for dealer in (2, 3)
        ]
        packets = [packet_for(other_contributions[0], 4), *self.packets[1:]]
        with self.assertRaises(ValueError):
            self.local(packets=packets)

    def test_illegal_packet_commitment_values(self):
        packet = self.packets[0]
        bad = dataclasses.replace(
            packet,
            commitment=dataclasses.replace(
                packet.commitment,
                values=(0, *packet.commitment.values[1:]),
            ),
        )
        with self.assertRaises(ValueError):
            self.local(packets=[bad, *self.packets[1:]])

    def test_old_commitment_group_mismatch_with_context(self):
        # A commitment from a key over a different (still legal) group does
        # not share the old context's group parameters.
        other_key = make_key_with_group()
        with self.assertRaises(ValueError):
            self.local(old_commitment=other_key.result.commitment)

    def test_old_commitment_threshold_mismatch_with_context(self):
        other_key = make_key(threshold=1, seed_base=600)
        with self.assertRaises(ValueError):
            self.local(old_commitment=other_key.result.commitment)

    def test_illegal_old_commitment_values(self):
        bad = dataclasses.replace(self.old_commitment, values=(0, 1))
        with self.assertRaises(ValueError):
            self.local(old_commitment=bad)

    def test_illegal_old_context_values(self):
        for bad_context in (
            dataclasses.replace(self.old_context, threshold=0),
            dataclasses.replace(self.old_context, public_key=0),
            dataclasses.replace(self.old_context, participant_ids=(1, 1, 3)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad_context)):
                self.local(old_context=bad_context)

    def test_constant_product_mismatching_old_public_key(self):
        # A structurally legal old context whose public key is not the
        # product of the dealers' weighted verification shares: every
        # per-dealer check passes, but the constant-term commitments do
        # not multiply to the claimed old public key.
        wrong_key_context = dataclasses.replace(
            self.old_context, public_key=pow(GENERATOR, 5, GROUP_PRIME)
        )
        with self.assertRaises(ValueError):
            self.local(old_context=wrong_key_context)


def make_key_with_blinding(blinding_generator):
    contributions = [
        create_signing_contribution(
            pid,
            OLD_IDS,
            OLD_THRESHOLD,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            blinding_generator=blinding_generator,
            randbelow=fixed_random(pid + 900),
        )
        for pid in OLD_IDS
    ]
    outcome = aggregate_signing_dkg(contributions)
    assert isinstance(outcome, SigningDKGResult), outcome
    return outcome


# A second, larger legal Schnorr group (same shape as the reshare tests):
# 2000303 = 2 * 1000151 + 1 is prime and 9, 81 = 9 ** 2 generate the
# order-1000151 subgroup.
def make_key_with_group():
    contributions = [
        create_signing_contribution(
            pid,
            OLD_IDS,
            OLD_THRESHOLD,
            prime=1000151,
            group_prime=2000303,
            generator=9,
            blinding_generator=81,
            randbelow=fixed_random(pid + 950),
        )
        for pid in OLD_IDS
    ]
    outcome = aggregate_signing_dkg(contributions)
    assert isinstance(outcome, SigningDKGResult), outcome
    return outcome


if __name__ == "__main__":
    unittest.main()
