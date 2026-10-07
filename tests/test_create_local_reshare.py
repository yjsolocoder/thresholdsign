"""Tests for dealer-side local resharing packets (create_local_reshare)."""

import dataclasses
import unittest

from thresholdsign import (
    AggregateSignature,
    DKGReceivedShare,
    LocalDKGPacket,
    PedersenCommitment,
    SigningDKGResult,
    SigningPublicContext,
    SigningRoundPacket,
    aggregate_signature,
    aggregate_signing_dkg,
    create_local_reshare,
    create_reshare,
    create_signing_contribution,
    create_signing_nonce_commitment,
    create_signing_round,
    create_signature_share,
    export_signing_public_context,
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

MESSAGE = b"create local reshare test message"


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


class CreateLocalReshareEquivalenceTest(unittest.TestCase):
    """The local packets must equal the create_reshare dealing, packet by packet."""

    def setUp(self):
        self.key = make_key()
        self.context = export_signing_public_context(self.key)
        self.old_commitment = self.key.result.commitment
        self.dealers = [1, 2, 3]
        self.members = [1, 2, 3, 4]
        self.threshold = 3

    def local_packets(self, dealer, **overrides):
        arguments = {
            "sender": dealer,
            "share": secret_share_of(self.key, dealer),
            "dealers": self.dealers,
            "members": self.members,
            "threshold": self.threshold,
            "context": self.context,
            "commitment": self.old_commitment,
            "rng": fixed_random(dealer + 100),
        }
        arguments.update(overrides)
        return create_local_reshare(**arguments)

    def test_packets_match_create_reshare_contribution(self):
        for dealer in self.dealers:
            contribution = create_reshare(
                dealer,
                secret_share_of(self.key, dealer),
                self.dealers,
                self.members,
                self.threshold,
                self.key,
                rng=fixed_random(dealer + 100),
            )
            packets = self.local_packets(dealer)
            expected = tuple(
                packet_for(contribution, receiver_id)
                for receiver_id in sorted(self.members)
            )
            self.assertEqual(packets, expected)

    def test_one_packet_per_member_sorted_by_receiver(self):
        packets = self.local_packets(1)
        self.assertIsInstance(packets, tuple)
        self.assertEqual(len(packets), len(self.members))
        self.assertEqual(
            [packet.received.receiver_id for packet in packets],
            sorted(self.members),
        )
        for packet in packets:
            receiver_id = packet.received.receiver_id
            self.assertEqual(packet.received.sender_id, 1)
            self.assertEqual(packet.received.share.x, receiver_id)
            self.assertEqual(packet.received.blinding_share.x, receiver_id)
            self.assertEqual(packet.participant_ids, tuple(sorted(self.members)))

    def test_packets_share_one_consistent_commitment_pair(self):
        packets = self.local_packets(2)
        first = packets[0]
        for packet in packets[1:]:
            self.assertEqual(packet.commitment, first.commitment)
            self.assertEqual(packet.feldman_commitment, first.feldman_commitment)
        self.assertEqual(
            len(first.commitment.values), len(first.feldman_commitment.values)
        )
        self.assertEqual(first.commitment.field_prime, FIELD_PRIME)
        self.assertEqual(first.commitment.group_prime, GROUP_PRIME)
        self.assertEqual(first.commitment.generator, GENERATOR)
        self.assertEqual(first.commitment.blinding_generator, BLINDING_GENERATOR)
        self.assertEqual(first.feldman_commitment.field_prime, FIELD_PRIME)
        self.assertEqual(first.feldman_commitment.group_prime, GROUP_PRIME)
        self.assertEqual(first.feldman_commitment.generator, GENERATOR)

    def test_unordered_members_are_normalised(self):
        ordered = self.local_packets(1)
        shuffled = self.local_packets(1, members=[4, 1, 3, 2], rng=fixed_random(101))
        self.assertEqual(ordered, shuffled)

    def test_single_pass_iterators_accepted(self):
        packets = create_local_reshare(
            1,
            secret_share_of(self.key, 1),
            iter(self.dealers),
            iter(self.members),
            self.threshold,
            self.context,
            self.old_commitment,
            rng=fixed_random(101),
        )
        self.assertEqual(packets, self.local_packets(1))

    def test_reshare_local_matches_full_reshare(self):
        contributions = [
            create_reshare(
                dealer,
                secret_share_of(self.key, dealer),
                self.dealers,
                self.members,
                self.threshold,
                self.key,
                rng=fixed_random(dealer + 100),
            )
            for dealer in self.dealers
        ]
        full = reshare(contributions, self.dealers, self.key)
        assert isinstance(full, SigningDKGResult)
        local_packets = {
            dealer: self.local_packets(dealer) for dealer in self.dealers
        }
        for index, receiver_id in enumerate(sorted(self.members)):
            batch = [local_packets[dealer][index] for dealer in self.dealers]
            outcome = reshare_local(
                receiver_id, batch, self.dealers, self.context, self.old_commitment
            )
            self.assertNotIsInstance(outcome, list)
            share, blinding_share, commitment, context = outcome
            self.assertEqual(share, full.result.shares[index])
            self.assertEqual(blinding_share, full.result.blinding_shares[index])
            self.assertEqual(commitment, full.result.commitment)
            self.assertEqual(context, export_signing_public_context(full))
            self.assertEqual(context.public_key, self.key.public_key)

    def test_threshold_one_old_and_new(self):
        key = make_key(participant_ids=(1, 2), threshold=1)
        context = export_signing_public_context(key)
        packets = create_local_reshare(
            1,
            secret_share_of(key, 1),
            (1,),
            (1, 2),
            1,
            context,
            key.result.commitment,
            rng=fixed_random(7),
        )
        self.assertEqual(len(packets), 2)
        outcome = reshare_local(
            2, [packets[1]], (1,), context, key.result.commitment
        )
        self.assertNotIsInstance(outcome, list)
        self.assertEqual(outcome[3].public_key, key.public_key)

    def test_zero_share_and_identity_commitments(self):
        key = make_key(participant_ids=(1, 2), threshold=1, randbelow=zero_random())
        self.assertEqual(secret_share_of(key, 1), 0)
        self.assertEqual(key.public_key, 1)
        context = export_signing_public_context(key)
        packets = create_local_reshare(
            1,
            0,
            (1,),
            (1, 2),
            1,
            context,
            key.result.commitment,
            rng=zero_random(),
        )
        self.assertEqual(len(packets), 2)
        for packet in packets:
            self.assertEqual(packet.commitment.values, (1,))
            self.assertEqual(packet.feldman_commitment.values, (1,))
            self.assertEqual(packet.received.share.y, 0)
        outcome = reshare_local(
            2, [packets[1]], (1,), context, key.result.commitment
        )
        self.assertNotIsInstance(outcome, list)
        self.assertEqual(outcome[0].y, 0)
        self.assertEqual(outcome[2].values, (1,))
        self.assertEqual(outcome[3].public_key, 1)

    def test_does_not_mutate_inputs(self):
        dealers = list(self.dealers)
        members = list(self.members)
        self.local_packets(1, dealers=dealers, members=members)
        self.assertEqual(dealers, self.dealers)
        self.assertEqual(members, self.members)

    def test_keeps_no_state_between_calls(self):
        first = self.local_packets(1)
        self.local_packets(2)
        self.assertEqual(self.local_packets(1), first)

    def test_default_rng_is_secure_source(self):
        # No rng argument: the default secrets.randbelow draws are accepted
        # and produce a fully aggregatable batch.
        batches = [
            create_local_reshare(
                dealer,
                secret_share_of(self.key, dealer),
                self.dealers,
                self.members,
                self.threshold,
                self.context,
                self.old_commitment,
            )
            for dealer in self.dealers
        ]
        receiver_index = sorted(self.members).index(4)
        outcome = reshare_local(
            4,
            [packets[receiver_index] for packets in batches],
            self.dealers,
            self.context,
            self.old_commitment,
        )
        self.assertNotIsInstance(outcome, list)
        self.assertEqual(outcome[3].public_key, self.key.public_key)

    def test_new_shares_sign_with_sign_round_packet(self):
        local = {}
        for receiver_index, receiver_id in enumerate(sorted(self.members)):
            batch = [
                self.local_packets(dealer)[receiver_index] for dealer in self.dealers
            ]
            outcome = reshare_local(
                receiver_id, batch, self.dealers, self.context, self.old_commitment
            )
            self.assertNotIsInstance(outcome, list)
            local[receiver_id] = outcome
        context = local[1][3]

        signer_ids = (1, 2, 4)
        nonce_commitments = []
        nonces = {}
        for offset, signer_id in enumerate(signer_ids):
            nonce_commitment, nonce = create_signing_nonce_commitment(
                signer_id,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
                randbelow=fixed_random(700 + offset),
            )
            nonce_commitments.append(nonce_commitment)
            nonces[signer_id] = nonce
        round_info = create_signing_round(MESSAGE, signer_ids, nonce_commitments, context)
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

    def test_old_signature_still_verifies(self):
        signer_ids = (1, 2)
        nonce_commitments = []
        nonces = {}
        for offset, signer_id in enumerate(signer_ids):
            nonce_commitment, nonce = create_signing_nonce_commitment(
                signer_id,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
                randbelow=fixed_random(900 + offset),
            )
            nonce_commitments.append(nonce_commitment)
            nonces[signer_id] = nonce
        round_info = create_signing_round(
            MESSAGE, signer_ids, nonce_commitments, self.key
        )
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

        # The joint public key is unchanged by the local resharing, so a
        # signature made under the old shares remains valid.
        receiver_index = sorted(self.members).index(4)
        batch = [
            self.local_packets(dealer)[receiver_index] for dealer in self.dealers
        ]
        outcome = reshare_local(
            4, batch, self.dealers, self.context, self.old_commitment
        )
        self.assertNotIsInstance(outcome, list)
        new_context = outcome[3]
        self.assertEqual(new_context.public_key, self.key.public_key)
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


class CreateLocalReshareTypeErrorTest(unittest.TestCase):
    """Wrong object, field, id, share or rng types raise TypeError."""

    def setUp(self):
        self.key = make_key()
        self.context = export_signing_public_context(self.key)
        self.commitment = self.key.result.commitment
        self.dealers = [1, 2, 3]
        self.members = [1, 2, 3, 4]
        self.threshold = 3

    def call(self, **overrides):
        arguments = {
            "sender": 1,
            "share": secret_share_of(self.key, 1),
            "dealers": self.dealers,
            "members": self.members,
            "threshold": self.threshold,
            "context": self.context,
            "commitment": self.commitment,
            "rng": fixed_random(101),
        }
        arguments.update(overrides)
        return create_local_reshare(**arguments)

    def assert_type_errors(self, **overrides):
        with self.assertRaises(TypeError):
            self.call(**overrides)

    def test_sender_types(self):
        for bad in ("1", 1.5, True, None):
            self.assert_type_errors(sender=bad)

    def test_share_types(self):
        for bad in ("0", 2.5, False, None):
            self.assert_type_errors(share=bad)

    def test_threshold_types(self):
        for bad in ("3", 3.0, True, None):
            self.assert_type_errors(threshold=bad)

    def test_context_types(self):
        self.assert_type_errors(context=self.key)
        self.assert_type_errors(context=None)
        replaced = dataclasses.replace(self.context, threshold=True)
        self.assert_type_errors(context=replaced)
        replaced = dataclasses.replace(self.context, participant_ids=[1, 2, 3])
        self.assert_type_errors(context=replaced)
        replaced = dataclasses.replace(
            self.context, verification_shares=(1, True, 1)
        )
        self.assert_type_errors(context=replaced)

    def test_commitment_types(self):
        self.assert_type_errors(commitment=None)
        self.assert_type_errors(commitment=self.context)
        replaced = dataclasses.replace(self.commitment, field_prime=True)
        self.assert_type_errors(commitment=replaced)
        replaced = dataclasses.replace(self.commitment, values=list(self.commitment.values))
        self.assert_type_errors(commitment=replaced)
        replaced = dataclasses.replace(self.commitment, values=(1, False))
        self.assert_type_errors(commitment=replaced)

    def test_members_types(self):
        self.assert_type_errors(members=5)
        self.assert_type_errors(members="1234")
        self.assert_type_errors(members=b"1234")
        self.assert_type_errors(members=[1, 2, "3", 4])
        self.assert_type_errors(members=[1, 2, True, 4])

    def test_dealers_types(self):
        self.assert_type_errors(dealers=5)
        self.assert_type_errors(dealers="123")
        self.assert_type_errors(dealers=[1, 2, "3"])
        self.assert_type_errors(dealers=[1, True, 3])

    def test_rng_not_callable(self):
        self.assert_type_errors(rng=5)
        self.assert_type_errors(rng=None)


class CreateLocalReshareValueErrorTest(unittest.TestCase):
    """Illegal values raise ValueError before anything is drawn."""

    def setUp(self):
        self.key = make_key()
        self.context = export_signing_public_context(self.key)
        self.commitment = self.key.result.commitment
        self.dealers = [1, 2, 3]
        self.members = [1, 2, 3, 4]
        self.threshold = 3

    def call(self, **overrides):
        arguments = {
            "sender": 1,
            "share": secret_share_of(self.key, 1),
            "dealers": self.dealers,
            "members": self.members,
            "threshold": self.threshold,
            "context": self.context,
            "commitment": self.commitment,
            "rng": fixed_random(101),
        }
        arguments.update(overrides)
        return create_local_reshare(**arguments)

    def assert_value_errors(self, **overrides):
        with self.assertRaises(ValueError):
            self.call(**overrides)

    def test_member_set_values(self):
        self.assert_value_errors(members=[])
        self.assert_value_errors(members=[1, 1, 2, 3])
        self.assert_value_errors(members=[0, 1, 2, 3])
        self.assert_value_errors(members=[1, 2, 3, FIELD_PRIME])

    def test_threshold_values(self):
        self.assert_value_errors(threshold=0)
        self.assert_value_errors(threshold=-1)
        self.assert_value_errors(threshold=len(self.members) + 1)

    def test_sender_must_be_member(self):
        self.assert_value_errors(sender=5, share=0)

    def test_dealer_quorum_values(self):
        self.assert_value_errors(dealers=[])
        self.assert_value_errors(dealers=[1, 1, 2])
        self.assert_value_errors(dealers=[2, 1, 3])
        self.assert_value_errors(dealers=[1, 2, 9])  # 9 is not an old participant
        self.assert_value_errors(dealers=[1, 2, 3, 5])  # 5 is not a new member

    def test_dealers_must_number_old_threshold(self):
        self.assert_value_errors(dealers=[1])

    def test_sender_must_be_dealer(self):
        self.assert_value_errors(sender=1, dealers=[2, 3])

    def test_share_range_and_match(self):
        self.assert_value_errors(share=-1)
        self.assert_value_errors(share=FIELD_PRIME)
        wrong = (secret_share_of(self.key, 1) + 1) % FIELD_PRIME
        self.assert_value_errors(share=wrong)

    def test_illegal_commitment_values(self):
        replaced = dataclasses.replace(self.commitment, values=())
        self.assert_value_errors(commitment=replaced)
        replaced = dataclasses.replace(self.commitment, values=(0, 1))
        self.assert_value_errors(commitment=replaced)
        replaced = dataclasses.replace(self.commitment, values=(1, GROUP_PRIME))
        self.assert_value_errors(commitment=replaced)
        # 2 is not in the order-FIELD_PRIME subgroup.
        replaced = dataclasses.replace(self.commitment, values=(1, 2))
        self.assert_value_errors(commitment=replaced)
        replaced = dataclasses.replace(self.commitment, field_prime=4)
        self.assert_value_errors(commitment=replaced)
        replaced = dataclasses.replace(
            self.commitment, blinding_generator=GENERATOR
        )
        self.assert_value_errors(commitment=replaced)

    def test_commitment_context_group_mismatch(self):
        other_generator = pow(GENERATOR, 3, GROUP_PRIME)
        replaced = dataclasses.replace(self.commitment, generator=other_generator)
        self.assert_value_errors(commitment=replaced)

    def test_commitment_context_threshold_mismatch(self):
        replaced = dataclasses.replace(
            self.commitment, values=self.commitment.values + (1,)
        )
        self.assert_value_errors(commitment=replaced)

    def test_inconsistent_public_context(self):
        # Structurally legal but not threshold-consistent: one verification
        # share is replaced by another subgroup element.
        shares = list(self.context.verification_shares)
        shares[0] = pow(GENERATOR, 7, GROUP_PRIME)
        if shares[0] == self.context.verification_shares[0]:
            shares[0] = pow(GENERATOR, 8, GROUP_PRIME)
        replaced = dataclasses.replace(
            self.context, verification_shares=tuple(shares)
        )
        self.assert_value_errors(context=replaced)

    def test_invalid_context_values(self):
        replaced = dataclasses.replace(self.context, threshold=0)
        self.assert_value_errors(context=replaced)
        replaced = dataclasses.replace(self.context, public_key=0)
        self.assert_value_errors(context=replaced)


class CreateLocalReshareRngTest(unittest.TestCase):
    """The injected rng is checked draw by draw, in create_reshare's order."""

    def setUp(self):
        self.key = make_key()
        self.context = export_signing_public_context(self.key)
        self.commitment = self.key.result.commitment
        self.dealers = [1, 2, 3]
        self.members = [1, 2, 3, 4]
        self.threshold = 3

    def call(self, rng, **overrides):
        arguments = {
            "sender": 1,
            "share": secret_share_of(self.key, 1),
            "dealers": self.dealers,
            "members": self.members,
            "threshold": self.threshold,
            "context": self.context,
            "commitment": self.commitment,
            "rng": rng,
        }
        arguments.update(overrides)
        return create_local_reshare(**arguments)

    def test_draw_count_and_bounds(self):
        bounds = []

        def recording(bound):
            bounds.append(bound)
            return 0

        self.call(recording)
        # t - 1 sharing coefficients, then t blinding coefficients.
        self.assertEqual(bounds, [FIELD_PRIME] * (2 * self.threshold - 1))

    def test_draw_count_threshold_one(self):
        bounds = []

        def recording(bound):
            bounds.append(bound)
            return 0

        key = make_key(participant_ids=(1, 2), threshold=1)
        create_local_reshare(
            1,
            secret_share_of(key, 1),
            (1,),
            (1, 2),
            1,
            export_signing_public_context(key),
            key.result.commitment,
            rng=recording,
        )
        self.assertEqual(bounds, [FIELD_PRIME])

    def test_non_integer_draw(self):
        for bad in ("x", 1.5, None):
            with self.assertRaises(TypeError):
                self.call(lambda bound: bad)

    def test_boolean_draw(self):
        with self.assertRaises(TypeError):
            self.call(lambda bound: True)

    def test_out_of_range_draw(self):
        with self.assertRaises(ValueError):
            self.call(lambda bound: bound)
        with self.assertRaises(ValueError):
            self.call(lambda bound: -1)

    def test_late_invalid_draw_returns_no_partial_packets(self):
        draws = []

        def bad_last(bound):
            draws.append(bound)
            if len(draws) == 2 * self.threshold - 1:
                return bound  # out of range on the final draw
            return 0

        with self.assertRaises(ValueError):
            self.call(bad_last)
        self.assertEqual(len(draws), 2 * self.threshold - 1)

    def test_rng_exception_propagates(self):
        class Boom(Exception):
            pass

        def exploding(bound):
            raise Boom("rng failure")

        with self.assertRaises(Boom):
            self.call(exploding)

    def test_inputs_checked_before_sampling(self):
        calls = []

        def recording(bound):
            calls.append(bound)
            return 0

        with self.assertRaises(ValueError):
            self.call(recording, share=FIELD_PRIME)
        with self.assertRaises(ValueError):
            self.call(recording, dealers=[2, 1, 3])
        with self.assertRaises(TypeError):
            self.call(recording, sender=True)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
