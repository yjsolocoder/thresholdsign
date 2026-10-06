"""Tests for receiver-local proactive refresh (refresh_local)."""

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
    create_signing_contribution,
    create_signing_nonce_commitment,
    create_signing_round,
    create_signature_share,
    export_signing_public_context,
    refresh,
    refresh_local,
    sign_round_packet,
    verify_signature,
    verify_signature_share,
)

# Same toy Pedersen setup as the DKG, signing and refresh tests:
# 8069 = 4 * 2017 + 1 is prime, 16 and 256 = 16 ** 2 are distinct
# generators of the order-2017 subgroup of the multiplicative group mod 8069.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

MESSAGE = b"local refresh test message"


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


class RefreshLocalValidTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.contributions = make_refresh_contributions(self.key)
        self.refreshed = refresh(self.contributions, self.key)
        assert isinstance(self.refreshed, SigningDKGResult)
        self.context = export_signing_public_context(self.key)

    def local(self, receiver_id, key=None, contributions=None):
        key = self.key if key is None else key
        contributions = self.contributions if contributions is None else contributions
        index = key.result.participant_ids.index(receiver_id)
        return refresh_local(
            receiver_id,
            key.result.shares[index],
            key.result.blinding_shares[index],
            key.result.commitment,
            export_signing_public_context(key),
            packets_for(contributions, receiver_id),
        )

    def test_returns_four_tuple_with_own_coordinates(self):
        outcome = self.local(2)
        self.assertIsInstance(outcome, tuple)
        self.assertEqual(len(outcome), 4)
        share, blinding_share, commitment, context = outcome
        self.assertIsInstance(share, Share)
        self.assertIsInstance(blinding_share, Share)
        self.assertIsInstance(commitment, PedersenCommitment)
        self.assertIsInstance(context, SigningPublicContext)
        self.assertEqual(share.x, 2)
        self.assertEqual(blinding_share.x, 2)

    def test_matches_full_refresh_for_every_member(self):
        expected_context = export_signing_public_context(self.refreshed)
        for index, participant_id in enumerate(self.key.result.participant_ids):
            share, blinding_share, commitment, context = self.local(participant_id)
            self.assertEqual(share, self.refreshed.result.shares[index])
            self.assertEqual(blinding_share, self.refreshed.result.blinding_shares[index])
            self.assertEqual(commitment, self.refreshed.result.commitment)
            self.assertEqual(context, expected_context)

    def test_share_values_are_old_plus_field_sums(self):
        index = self.key.result.participant_ids.index(2)
        old_share = self.key.result.shares[index]
        old_blinding = self.key.result.blinding_shares[index]
        packets = packets_for(self.contributions, 2)
        share, blinding_share, _commitment, _context = self.local(2)
        self.assertEqual(
            share.y,
            (old_share.y + sum(p.received.share.y for p in packets)) % FIELD_PRIME,
        )
        self.assertEqual(
            blinding_share.y,
            (old_blinding.y + sum(p.received.blinding_share.y for p in packets))
            % FIELD_PRIME,
        )

    def test_commitment_is_pointwise_group_product(self):
        packets = packets_for(self.contributions, 1)
        _share, _blinding, commitment, _context = self.local(1)
        old_values = self.key.result.commitment.values
        for position, old_value in enumerate(old_values):
            expected = old_value
            for packet in packets:
                expected = expected * packet.commitment.values[position] % GROUP_PRIME
            self.assertEqual(commitment.values[position], expected)
        self.assertEqual(commitment.field_prime, FIELD_PRIME)
        self.assertEqual(commitment.group_prime, GROUP_PRIME)
        self.assertEqual(commitment.generator, GENERATOR)
        self.assertEqual(commitment.blinding_generator, BLINDING_GENERATOR)

    def test_context_keeps_public_parts_and_updates_verification_shares(self):
        packets = packets_for(self.contributions, 3)
        _share, _blinding, _commitment, context = self.local(3)
        self.assertEqual(context.participant_ids, self.context.participant_ids)
        self.assertEqual(context.threshold, self.context.threshold)
        self.assertEqual(context.field_prime, self.context.field_prime)
        self.assertEqual(context.group_prime, self.context.group_prime)
        self.assertEqual(context.generator, self.context.generator)
        self.assertEqual(context.public_key, self.context.public_key)
        for index, participant_id in enumerate(self.context.participant_ids):
            expected = self.context.verification_shares[index]
            for packet in packets:
                x_power = 1
                evaluation = 1
                for value in packet.feldman_commitment.values:
                    evaluation = evaluation * pow(value, x_power, GROUP_PRIME) % GROUP_PRIME
                    x_power = x_power * participant_id % FIELD_PRIME
                expected = expected * evaluation % GROUP_PRIME
            self.assertEqual(context.verification_shares[index], expected)

    def test_input_order_does_not_matter(self):
        packets = packets_for(self.contributions, 2)
        index = self.key.result.participant_ids.index(2)
        args = (
            self.key.result.shares[index],
            self.key.result.blinding_shares[index],
            self.key.result.commitment,
            self.context,
        )
        forward = refresh_local(2, *args, packets)
        reversed_outcome = refresh_local(2, *args, list(reversed(packets)))
        shuffled = refresh_local(2, *args, [packets[1], packets[2], packets[0]])
        self.assertEqual(forward, reversed_outcome)
        self.assertEqual(forward, shuffled)

    def test_accepts_single_pass_iterator(self):
        index = self.key.result.participant_ids.index(1)
        args = (
            self.key.result.shares[index],
            self.key.result.blinding_shares[index],
            self.key.result.commitment,
            self.context,
        )
        outcome = refresh_local(1, *args, iter(packets_for(self.contributions, 1)))
        self.assertIsInstance(outcome, tuple)
        again = refresh_local(
            1, *args, (p for p in packets_for(self.contributions, 1))
        )
        self.assertEqual(outcome, again)

    def test_threshold_one(self):
        key = make_key(threshold=1)
        contributions = make_refresh_contributions(key)
        refreshed = refresh(contributions, key)
        assert isinstance(refreshed, SigningDKGResult)
        for index, participant_id in enumerate((1, 2, 3)):
            share, blinding_share, commitment, context = refresh_local(
                participant_id,
                key.result.shares[index],
                key.result.blinding_shares[index],
                key.result.commitment,
                export_signing_public_context(key),
                packets_for(contributions, participant_id),
            )
            self.assertEqual(share, refreshed.result.shares[index])
            self.assertEqual(blinding_share, refreshed.result.blinding_shares[index])
            self.assertEqual(commitment, refreshed.result.commitment)
            self.assertEqual(context, export_signing_public_context(refreshed))
            self.assertEqual(context.threshold, 1)

    def test_zero_shares_and_identity_commitments(self):
        # All-zero draws give all-zero sharing and blinding polynomials:
        # zero share values and identity commitment values stay legal.
        key = make_key(randbelow=zero_random())
        contributions = make_refresh_contributions(key, randbelow=zero_random())
        refreshed = refresh(contributions, key)
        assert isinstance(refreshed, SigningDKGResult)
        share, blinding_share, commitment, context = refresh_local(
            2,
            key.result.shares[1],
            key.result.blinding_shares[1],
            key.result.commitment,
            export_signing_public_context(key),
            packets_for(contributions, 2),
        )
        self.assertEqual(share, Share(x=2, y=0))
        self.assertEqual(blinding_share, Share(x=2, y=0))
        self.assertEqual(commitment, refreshed.result.commitment)
        self.assertEqual(commitment.values, (1, 1))
        self.assertEqual(context, export_signing_public_context(refreshed))
        self.assertEqual(context.public_key, 1)
        self.assertEqual(context.verification_shares, (1, 1, 1))

    def test_does_not_mutate_inputs_and_is_deterministic(self):
        index = self.key.result.participant_ids.index(2)
        packets = packets_for(self.contributions, 2)
        snapshot = list(packets)
        args = (
            self.key.result.shares[index],
            self.key.result.blinding_shares[index],
            self.key.result.commitment,
            self.context,
        )
        first = refresh_local(2, *args, packets)
        second = refresh_local(2, *args, packets)
        self.assertEqual(first, second)
        self.assertEqual(packets, snapshot)

    def test_chained_local_refresh(self):
        # A locally refreshed member can refresh again from the next batch
        # of refresh contributions made against the fully refreshed key.
        second_contributions = make_refresh_contributions(self.refreshed, seed_base=200)
        twice = refresh(second_contributions, self.refreshed)
        assert isinstance(twice, SigningDKGResult)
        index = 1  # participant id 2
        share, blinding_share, commitment, context = self.local(2)
        share2, blinding2, commitment2, context2 = refresh_local(
            2,
            share,
            blinding_share,
            commitment,
            context,
            packets_for(second_contributions, 2),
        )
        self.assertEqual(share2, twice.result.shares[index])
        self.assertEqual(blinding2, twice.result.blinding_shares[index])
        self.assertEqual(commitment2, twice.result.commitment)
        self.assertEqual(context2, export_signing_public_context(twice))

    def test_local_refresh_signs_with_sign_round_packet(self):
        local = {
            participant_id: self.local(participant_id)
            for participant_id in (1, 2, 3)
        }
        context = local[1][3]
        for _share, _blinding, _commitment, local_context in local.values():
            self.assertEqual(local_context, context)

        signer_ids = (1, 2)
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

    def test_old_signature_still_verifies_after_local_refresh(self):
        # The joint public key is unchanged, so a signature made under the
        # old shares remains valid after the local refresh.
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
                self.key.result.shares[
                    self.key.result.participant_ids.index(signer_id)
                ].y,
                nonces[signer_id],
                round_info,
                self.key,
            )
            for signer_id in signer_ids
        ]
        signature = aggregate_signature(old_shares, round_info, self.key)
        self.assertIsInstance(signature, AggregateSignature)

        _share, _blinding, _commitment, new_context = self.local(1)
        self.assertEqual(new_context.public_key, self.context.public_key)
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


class RefreshLocalRejectionTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.contributions = make_refresh_contributions(self.key)
        self.context = export_signing_public_context(self.key)
        self.packets = packets_for(self.contributions, 2)

    def local(self, packets, receiver_id=2):
        index = self.key.result.participant_ids.index(receiver_id)
        return refresh_local(
            receiver_id,
            self.key.result.shares[index],
            self.key.result.blinding_shares[index],
            self.key.result.commitment,
            self.context,
            packets,
        )

    def tamper_share(self, packet, delta=1):
        received = packet.received
        tampered = Share(x=received.share.x, y=(received.share.y + delta) % FIELD_PRIME)
        return dataclasses.replace(
            packet, received=dataclasses.replace(received, share=tampered)
        )

    def test_tampered_share_produces_rejection(self):
        packets = [self.tamper_share(self.packets[0]), *self.packets[1:]]
        self.assertEqual(self.local(packets), [DKGRejection(sender_id=1)])

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
            self.packets[2],
        ]
        self.assertEqual(self.local(packets), [DKGRejection(sender_id=2)])

    def test_mismatched_feldman_commitment_produces_rejection(self):
        packets = list(self.packets)
        packets[0] = dataclasses.replace(
            packets[0], feldman_commitment=self.packets[1].feldman_commitment
        )
        self.assertEqual(self.local(packets), [DKGRejection(sender_id=1)])

    def test_nonzero_constant_term_produces_rejection(self):
        # A plain signing contribution is structurally legal but shares a
        # random secret, not zero: its Feldman constant-term commitment is
        # not 1.
        plain = create_signing_contribution(
            1,
            (1, 2, 3),
            2,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            blinding_generator=BLINDING_GENERATOR,
            randbelow=fixed_random(999),
        )
        packets = [packet_for(plain, 2), *self.packets[1:]]
        self.assertEqual(self.local(packets), [DKGRejection(sender_id=1)])

    def test_all_failures_listed_sorted_and_deduplicated(self):
        packets = [
            self.tamper_share(self.packets[2]),
            self.tamper_share(self.packets[0]),
            self.packets[1],
        ]
        outcome = self.local(packets)
        self.assertIsInstance(outcome, list)
        self.assertEqual(
            outcome,
            [DKGRejection(sender_id=1), DKGRejection(sender_id=3)],
        )
        sender_ids = [rejection.sender_id for rejection in outcome]
        self.assertEqual(sender_ids, sorted(set(sender_ids)))

    def test_rejection_returns_no_partial_result(self):
        packets = [self.tamper_share(self.packets[0]), *self.packets[1:]]
        self.assertNotIsInstance(self.local(packets), tuple)


class RefreshLocalTypeErrorTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.contributions = make_refresh_contributions(self.key)
        self.context = export_signing_public_context(self.key)
        self.packets = packets_for(self.contributions, 2)

    def local(self, receiver_id=2, share=_DEFAULT, blinding_share=_DEFAULT,
              commitment=_DEFAULT, context=_DEFAULT, packets=_DEFAULT):
        index = self.key.result.participant_ids.index(2)
        return refresh_local(
            receiver_id,
            self.key.result.shares[index] if share is _DEFAULT else share,
            self.key.result.blinding_shares[index]
            if blinding_share is _DEFAULT
            else blinding_share,
            self.key.result.commitment if commitment is _DEFAULT else commitment,
            self.context if context is _DEFAULT else context,
            self.packets if packets is _DEFAULT else packets,
        )

    def test_receiver_id_type(self):
        for bad in ("2", 2.0, None, True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.local(receiver_id=bad)

    def test_share_types(self):
        for bad in ("share", 7, None, (2, 3)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.local(share=bad)
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.local(blinding_share=bad)

    def test_share_coordinate_types(self):
        for bad_share in (Share(x=True, y=1), Share(x=2, y=False), Share(x="2", y=1)):
            with self.assertRaises(TypeError, msg=repr(bad_share)):
                self.local(share=bad_share)
            with self.assertRaises(TypeError, msg=repr(bad_share)):
                self.local(blinding_share=bad_share)

    def test_commitment_type(self):
        for bad in ("commitment", 7, None, self.context):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.local(commitment=bad)

    def test_commitment_field_types(self):
        commitment = self.key.result.commitment
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

    def test_context_type(self):
        for bad in ("context", 7, None, self.key.result.commitment):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.local(context=bad)

    def test_context_field_types(self):
        with self.assertRaises(TypeError):
            self.local(context=dataclasses.replace(self.context, threshold=True))
        with self.assertRaises(TypeError):
            self.local(
                context=dataclasses.replace(self.context, participant_ids=[1, 2, 3])
            )
        with self.assertRaises(TypeError):
            self.local(
                context=dataclasses.replace(
                    self.context, verification_shares=(1, 2, "3")
                )
            )

    def test_non_packet_elements(self):
        for bad in ("packet", 7, self.packets[0].received, self.packets):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.local(packets=[bad])


class RefreshLocalValueErrorTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.contributions = make_refresh_contributions(self.key)
        self.context = export_signing_public_context(self.key)
        self.packets = packets_for(self.contributions, 2)

    def local(self, receiver_id=2, share=_DEFAULT, blinding_share=_DEFAULT,
              commitment=_DEFAULT, context=_DEFAULT, packets=_DEFAULT):
        index = self.key.result.participant_ids.index(2)
        return refresh_local(
            receiver_id,
            self.key.result.shares[index] if share is _DEFAULT else share,
            self.key.result.blinding_shares[index]
            if blinding_share is _DEFAULT
            else blinding_share,
            self.key.result.commitment if commitment is _DEFAULT else commitment,
            self.context if context is _DEFAULT else context,
            self.packets if packets is _DEFAULT else packets,
        )

    def test_empty_batch(self):
        with self.assertRaises(ValueError):
            self.local(packets=[])

    def test_receiver_not_a_participant(self):
        for bad in (4, 0, FIELD_PRIME):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.local(receiver_id=bad)

    def test_old_share_coordinate_mismatch(self):
        index = self.key.result.participant_ids.index(2)
        share = self.key.result.shares[index]
        blinding_share = self.key.result.blinding_shares[index]
        with self.assertRaises(ValueError):
            self.local(share=Share(x=1, y=share.y))
        with self.assertRaises(ValueError):
            self.local(blinding_share=Share(x=3, y=blinding_share.y))

    def test_old_share_value_out_of_range(self):
        index = self.key.result.participant_ids.index(2)
        share = self.key.result.shares[index]
        for bad_y in (-1, FIELD_PRIME, FIELD_PRIME + 1):
            with self.assertRaises(ValueError, msg=repr(bad_y)):
                self.local(share=Share(x=share.x, y=bad_y))
        with self.assertRaises(ValueError):
            self.local(blinding_share=Share(x=2, y=FIELD_PRIME))

    def test_illegal_context_values(self):
        with self.assertRaises(ValueError):
            self.local(
                context=dataclasses.replace(self.context, participant_ids=(2, 1, 3))
            )
        with self.assertRaises(ValueError):
            self.local(context=dataclasses.replace(self.context, threshold=4))
        with self.assertRaises(ValueError):
            self.local(context=dataclasses.replace(self.context, public_key=0))

    def test_commitment_group_mismatch_with_context(self):
        commitment = self.key.result.commitment
        # 256 is a legal subgroup generator but not the context's generator.
        with self.assertRaises(ValueError):
            self.local(
                commitment=dataclasses.replace(
                    commitment, generator=BLINDING_GENERATOR
                )
            )

    def test_commitment_threshold_mismatch_with_context(self):
        commitment = self.key.result.commitment
        with self.assertRaises(ValueError):
            self.local(
                commitment=dataclasses.replace(
                    commitment, values=commitment.values + (1,)
                )
            )
        with self.assertRaises(ValueError):
            self.local(
                commitment=dataclasses.replace(
                    commitment, values=commitment.values[:1]
                )
            )

    def test_illegal_commitment_values(self):
        commitment = self.key.result.commitment
        for bad_value in (0, GROUP_PRIME, 2):
            broken = dataclasses.replace(
                commitment, values=(bad_value,) + commitment.values[1:]
            )
            with self.assertRaises(ValueError, msg=repr(bad_value)):
                self.local(commitment=broken)

    def test_old_double_share_fails_old_commitment(self):
        index = self.key.result.participant_ids.index(2)
        share = self.key.result.shares[index]
        blinding_share = self.key.result.blinding_shares[index]
        with self.assertRaises(ValueError):
            self.local(share=Share(x=2, y=(share.y + 1) % FIELD_PRIME))
        with self.assertRaises(ValueError):
            self.local(
                blinding_share=Share(x=2, y=(blinding_share.y + 1) % FIELD_PRIME)
            )

    def test_old_share_fails_context_verification_share(self):
        # A structurally legal context whose verification share for the
        # receiver does not match the old secret share.
        index = self.context.participant_ids.index(2)
        wrong = pow(GENERATOR, (self.key.result.shares[index].y + 1) % FIELD_PRIME, GROUP_PRIME)
        verification_shares = list(self.context.verification_shares)
        verification_shares[index] = wrong
        broken = dataclasses.replace(
            self.context, verification_shares=tuple(verification_shares)
        )
        with self.assertRaises(ValueError):
            self.local(context=broken)

    def test_missing_sender(self):
        with self.assertRaises(ValueError):
            self.local(packets=self.packets[:2])

    def test_duplicate_sender(self):
        packets = [self.packets[0], self.packets[0], self.packets[2]]
        with self.assertRaises(ValueError):
            self.local(packets=packets)

    def test_sender_not_a_participant(self):
        packet = self.packets[0]
        broken = dataclasses.replace(
            packet,
            received=dataclasses.replace(packet.received, sender_id=4),
        )
        with self.assertRaises(ValueError):
            self.local(packets=[broken, *self.packets[1:]])

    def test_packet_receiver_mismatch(self):
        packet = self.packets[0]
        received = packet.received
        broken = dataclasses.replace(
            packet,
            received=dataclasses.replace(
                received,
                receiver_id=1,
                share=Share(x=1, y=received.share.y),
                blinding_share=Share(x=1, y=received.blinding_share.y),
            ),
        )
        with self.assertRaises(ValueError):
            self.local(packets=[broken, *self.packets[1:]])

    def test_packets_disagree_on_participant_ids(self):
        packet = self.packets[1]
        broken = dataclasses.replace(packet, participant_ids=(1, 2, 4))
        with self.assertRaises(ValueError):
            self.local(packets=[self.packets[0], broken, self.packets[2]])

    def test_packets_disagree_on_group_parameters(self):
        packet = self.packets[1]
        commitment = packet.commitment
        # 4096 = 16 ** 3 mod 8069 is another legal subgroup generator.
        moved = dataclasses.replace(
            packet,
            commitment=dataclasses.replace(commitment, blinding_generator=4096),
        )
        with self.assertRaises(ValueError):
            self.local(packets=[self.packets[0], moved, self.packets[2]])

    def test_packets_disagree_on_threshold(self):
        other_key = make_key(threshold=3)
        other_contributions = make_refresh_contributions(other_key)
        other_packet = packets_for(other_contributions, 2)[1]
        with self.assertRaises(ValueError):
            self.local(packets=[self.packets[0], other_packet, self.packets[2]])


if __name__ == "__main__":
    unittest.main()
