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
    aggregate_local_dkg,
    aggregate_signature,
    aggregate_signing_dkg,
    create_refresh,
    create_signing_contribution,
    create_signing_nonce_commitment,
    create_signing_round,
    export_signing_public_context,
    refresh,
    refresh_local,
    sign_round_packet,
    verify_signature,
    verify_signature_share,
)

# Same toy Pedersen setup as the local-DKG and refresh tests: 8069 =
# 4 * 2017 + 1 is prime, 16 and 256 = 16 ** 2 are distinct generators of
# the order-2017 subgroup of the multiplicative group modulo 8069.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

MESSAGE = b"local refresh test message"


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


def make_key(participant_ids=(1, 2, 3), threshold=2, randbelow=None):
    outcome = aggregate_signing_dkg(make_contributions(participant_ids, threshold, randbelow))
    assert isinstance(outcome, SigningDKGResult), outcome
    return outcome


def make_refresh_contributions(key, seed_base=100):
    return [
        create_refresh(pid, key, randbelow=fixed_random(pid + seed_base))
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


def local_args(key, receiver_id, packets):
    """Positional refresh_local arguments for ``receiver_id`` from ``key``."""
    index = key.result.participant_ids.index(receiver_id)
    return (
        receiver_id,
        key.result.shares[index],
        key.result.blinding_shares[index],
        key.result.commitment,
        export_signing_public_context(key),
        packets,
    )


class RefreshLocalValidTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.contributions = make_refresh_contributions(self.key)

    def test_returns_four_tuple_with_own_coordinates(self):
        outcome = refresh_local(*local_args(self.key, 2, packets_for(self.contributions, 2)))
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
        full = refresh(self.contributions, self.key)
        assert isinstance(full, SigningDKGResult)
        expected_context = export_signing_public_context(full)
        for index, participant_id in enumerate(full.result.participant_ids):
            outcome = refresh_local(
                *local_args(
                    self.key,
                    participant_id,
                    packets_for(self.contributions, participant_id),
                )
            )
            share, blinding_share, commitment, context = outcome
            self.assertEqual(share, full.result.shares[index])
            self.assertEqual(blinding_share, full.result.blinding_shares[index])
            self.assertEqual(commitment, full.result.commitment)
            self.assertEqual(context, expected_context)

    def test_share_values_are_field_sums(self):
        packets = packets_for(self.contributions, 1)
        share, blinding_share, _commitment, _context = refresh_local(
            *local_args(self.key, 1, packets)
        )
        expected_y = self.key.result.shares[0].y
        expected_yb = self.key.result.blinding_shares[0].y
        for packet in packets:
            expected_y = (expected_y + packet.received.share.y) % FIELD_PRIME
            expected_yb = (
                expected_yb + packet.received.blinding_share.y
            ) % FIELD_PRIME
        self.assertEqual(share, Share(x=1, y=expected_y))
        self.assertEqual(blinding_share, Share(x=1, y=expected_yb))

    def test_commitment_is_componentwise_group_product(self):
        _share, _blinding, commitment, _context = refresh_local(
            *local_args(self.key, 2, packets_for(self.contributions, 2))
        )
        ordered = sorted(self.contributions, key=lambda c: c.contribution.sender_id)
        for position in range(2):
            expected = self.key.result.commitment.values[position]
            for contribution in ordered:
                expected = (
                    expected
                    * contribution.contribution.commitment.values[position]
                ) % GROUP_PRIME
            self.assertEqual(commitment.values[position], expected)
        self.assertEqual(
            commitment.blinding_generator,
            self.key.result.commitment.blinding_generator,
        )

    def test_verification_shares_match_new_shares_and_public_key_unchanged(self):
        full = refresh(self.contributions, self.key)
        assert isinstance(full, SigningDKGResult)
        outcome = refresh_local(
            *local_args(self.key, 2, packets_for(self.contributions, 2))
        )
        _share, _blinding, _commitment, context = outcome
        self.assertEqual(context.public_key, self.key.public_key)
        for new_share, verification_share in zip(
            full.result.shares, context.verification_shares
        ):
            self.assertEqual(
                pow(GENERATOR, new_share.y, GROUP_PRIME), verification_share
            )

    def test_input_order_does_not_matter(self):
        packets = packets_for(self.contributions, 3)
        forward = refresh_local(*local_args(self.key, 3, packets))
        reversed_outcome = refresh_local(
            *local_args(self.key, 3, list(reversed(packets)))
        )
        shuffled = refresh_local(
            *local_args(self.key, 3, [packets[1], packets[2], packets[0]])
        )
        self.assertEqual(forward, reversed_outcome)
        self.assertEqual(forward, shuffled)

    def test_accepts_single_pass_iterator(self):
        packets = packets_for(self.contributions, 2)
        outcome = refresh_local(*local_args(self.key, 2, iter(packets)))
        again = refresh_local(
            *local_args(self.key, 2, (packet for packet in packets))
        )
        self.assertEqual(outcome, again)

    def test_refresh_can_be_repeated_locally(self):
        # A second local refresh on the first local output must equal the
        # full refresh applied twice, including the aggregated commitment.
        first_full = refresh(self.contributions, self.key)
        assert isinstance(first_full, SigningDKGResult)
        second_contributions = make_refresh_contributions(first_full, seed_base=200)
        second_full = refresh(second_contributions, first_full)
        assert isinstance(second_full, SigningDKGResult)

        first_local = refresh_local(
            *local_args(self.key, 2, packets_for(self.contributions, 2))
        )
        share, blinding_share, commitment, context = first_local
        second_local = refresh_local(
            2,
            share,
            blinding_share,
            commitment,
            context,
            packets_for(second_contributions, 2),
        )
        index = second_full.result.participant_ids.index(2)
        self.assertEqual(second_local[0], second_full.result.shares[index])
        self.assertEqual(second_local[1], second_full.result.blinding_shares[index])
        self.assertEqual(second_local[2], second_full.result.commitment)
        self.assertEqual(
            second_local[3], export_signing_public_context(second_full)
        )

    def test_threshold_one(self):
        key = make_key((1, 2), 1)
        contributions = make_refresh_contributions(key)
        full = refresh(contributions, key)
        assert isinstance(full, SigningDKGResult)
        for index, participant_id in enumerate((1, 2)):
            outcome = refresh_local(
                *local_args(
                    key, participant_id, packets_for(contributions, participant_id)
                )
            )
            self.assertEqual(outcome[0], full.result.shares[index])
            self.assertEqual(outcome[1], full.result.blinding_shares[index])
            self.assertEqual(outcome[2], full.result.commitment)
            self.assertEqual(outcome[3], export_signing_public_context(full))
            self.assertEqual(outcome[3].threshold, 1)

    def test_single_participant(self):
        key = make_key((5,), 1)
        contributions = make_refresh_contributions(key)
        outcome = refresh_local(
            *local_args(key, 5, packets_for(contributions, 5))
        )
        self.assertEqual(outcome[0].x, 5)
        self.assertEqual(outcome[1].x, 5)
        self.assertEqual(outcome[3].participant_ids, (5,))
        self.assertEqual(outcome[3].threshold, 1)

    def test_zero_shares_and_identity_refresh_commitments(self):
        # All-zero refresh draws: zero refresh shares and identity
        # commitments, so every refreshed value equals the old one.
        contributions = [
            create_refresh(pid, self.key, randbelow=zero_random())
            for pid in self.key.result.participant_ids
        ]
        old_context = export_signing_public_context(self.key)
        outcome = refresh_local(
            *local_args(self.key, 2, packets_for(contributions, 2))
        )
        share, blinding_share, commitment, context = outcome
        index = self.key.result.participant_ids.index(2)
        self.assertEqual(share, self.key.result.shares[index])
        self.assertEqual(blinding_share, self.key.result.blinding_shares[index])
        self.assertEqual(commitment, self.key.result.commitment)
        self.assertEqual(context, old_context)

    def test_non_default_prime(self):
        prime = 97
        group_prime = 389  # 389 = 4 * 97 + 1 is prime
        contributions = [
            create_signing_contribution(
                pid,
                (1, 2),
                2,
                prime=prime,
                group_prime=group_prime,
                generator=16,  # order 97 modulo 389
                blinding_generator=256,
                randbelow=fixed_random(pid),
            )
            for pid in (1, 2)
        ]
        key = aggregate_signing_dkg(contributions)
        assert isinstance(key, SigningDKGResult)
        refresh_contributions = make_refresh_contributions(key)
        full = refresh(refresh_contributions, key)
        assert isinstance(full, SigningDKGResult)
        for index, participant_id in enumerate((1, 2)):
            outcome = refresh_local(
                *local_args(
                    key,
                    participant_id,
                    packets_for(refresh_contributions, participant_id),
                )
            )
            self.assertEqual(outcome[0], full.result.shares[index])
            self.assertEqual(outcome[1], full.result.blinding_shares[index])
            self.assertEqual(outcome[2], full.result.commitment)
            self.assertEqual(outcome[3], export_signing_public_context(full))

    def test_does_not_mutate_inputs_and_is_deterministic(self):
        packets = packets_for(self.contributions, 2)
        args = local_args(self.key, 2, packets)
        snapshot = list(packets)
        first = refresh_local(*args)
        second = refresh_local(*args)
        self.assertEqual(first, second)
        self.assertEqual(packets, snapshot)

    def test_locally_refreshed_material_signs_and_old_signature_verifies(self):
        # An old signature made before the refresh...
        signer_ids = (1, 2)
        old_nonces = {}
        old_commitments = []
        for offset, signer_id in enumerate(signer_ids):
            commitment, nonce = create_signing_nonce_commitment(
                signer_id,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
                randbelow=fixed_random(100 + offset),
            )
            old_commitments.append(commitment)
            old_nonces[signer_id] = nonce
        old_context = export_signing_public_context(self.key)
        old_round = create_signing_round(
            MESSAGE, signer_ids, old_commitments, old_context
        )
        old_packet = SigningRoundPacket(context=old_context, round_info=old_round)
        old_shares = [
            sign_round_packet(
                signer_id,
                self.key.result.shares[
                    self.key.result.participant_ids.index(signer_id)
                ].y,
                old_nonces[signer_id],
                old_packet,
                old_context,
                MESSAGE,
            )
            for signer_id in signer_ids
        ]
        old_signature = aggregate_signature(old_shares, old_round, old_context)
        assert isinstance(old_signature, AggregateSignature)

        # ...each signing member refreshes purely from their own packets...
        refreshed = {}
        for signer_id in (1, 2, 3):
            refreshed[signer_id] = refresh_local(
                *local_args(
                    self.key,
                    signer_id,
                    packets_for(self.contributions, signer_id),
                )
            )
        new_context = refreshed[2][3]
        self.assertEqual(new_context, refreshed[1][3])

        # ...and signs a fresh round with the refreshed share and context.
        new_signer_ids = (2, 3)
        commitments = []
        nonces = {}
        for offset, signer_id in enumerate(new_signer_ids):
            commitment, nonce = create_signing_nonce_commitment(
                signer_id,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
                randbelow=fixed_random(200 + offset),
            )
            commitments.append(commitment)
            nonces[signer_id] = nonce
        round_info = create_signing_round(
            MESSAGE, new_signer_ids, commitments, new_context
        )
        packet = SigningRoundPacket(context=new_context, round_info=round_info)
        shares = [
            sign_round_packet(
                signer_id,
                refreshed[signer_id][0].y,
                nonces[signer_id],
                packet,
                new_context,
                MESSAGE,
            )
            for signer_id in new_signer_ids
        ]
        for share in shares:
            self.assertTrue(verify_signature_share(share, round_info, new_context))
        signature = aggregate_signature(shares, round_info, new_context)
        self.assertIsInstance(signature, AggregateSignature)
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
        # The joint public key is unchanged and the old signature verifies.
        self.assertEqual(new_context.public_key, old_context.public_key)
        self.assertTrue(
            verify_signature(
                MESSAGE,
                old_signature,
                old_context.public_key,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            )
        )


class RefreshLocalRejectionTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.contributions = make_refresh_contributions(self.key)
        self.packets = packets_for(self.contributions, 2)

    def tamper_share(self, packet, delta=1):
        received = packet.received
        tampered = Share(
            x=received.share.x, y=(received.share.y + delta) % FIELD_PRIME
        )
        return dataclasses.replace(
            packet, received=dataclasses.replace(received, share=tampered)
        )

    def test_tampered_share_produces_rejection(self):
        packets = [self.tamper_share(self.packets[0]), *self.packets[1:]]
        outcome = refresh_local(*local_args(self.key, 2, packets))
        self.assertEqual(outcome, [DKGRejection(sender_id=1)])

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
        outcome = refresh_local(*local_args(self.key, 2, packets))
        self.assertEqual(outcome, [DKGRejection(sender_id=2)])

    def test_mismatched_feldman_commitment_produces_rejection(self):
        # Another sender's zero-constant Feldman commitment keeps the
        # constant term at 1 but commits to a different polynomial.
        packets = list(self.packets)
        packets[0] = dataclasses.replace(
            packets[0], feldman_commitment=self.packets[1].feldman_commitment
        )
        outcome = refresh_local(*local_args(self.key, 2, packets))
        self.assertEqual(outcome, [DKGRejection(sender_id=1)])

    def test_nonzero_constant_packets_are_all_rejected(self):
        # Ordinary signing contributions carry random (non-zero) constant
        # terms while staying internally consistent: only the constant
        # check fails, for every sender.
        ordinary = make_contributions()
        packets = packets_for(ordinary, 2)
        for packet in packets:
            self.assertNotEqual(packet.feldman_commitment.values[0], 1)
        outcome = refresh_local(*local_args(self.key, 2, packets))
        self.assertEqual(
            outcome,
            [DKGRejection(1), DKGRejection(2), DKGRejection(3)],
        )

    def test_all_failures_listed_sorted_and_deduplicated(self):
        packets = [
            self.tamper_share(self.packets[2]),
            self.tamper_share(self.packets[0]),
            self.packets[1],
        ]
        expected = [DKGRejection(sender_id=1), DKGRejection(sender_id=3)]
        self.assertEqual(
            refresh_local(*local_args(self.key, 2, packets)), expected
        )
        self.assertEqual(
            refresh_local(*local_args(self.key, 2, list(reversed(packets)))),
            expected,
        )

    def test_rejection_returns_no_partial_result(self):
        packets = [self.tamper_share(self.packets[0]), *self.packets[1:]]
        outcome = refresh_local(*local_args(self.key, 2, packets))
        self.assertNotIsInstance(outcome, tuple)


class RefreshLocalOldMaterialTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.contributions = make_refresh_contributions(self.key)
        self.good_packets = packets_for(self.contributions, 2)
        self.context = export_signing_public_context(self.key)
        self.index = self.key.result.participant_ids.index(2)
        self.share = self.key.result.shares[self.index]
        self.blinding = self.key.result.blinding_shares[self.index]
        self.commitment = self.key.result.commitment

    def refresh_call(self, share=None, blinding=None, commitment=None,
                     context=None, packets=None):
        return refresh_local(
            2,
            self.share if share is None else share,
            self.blinding if blinding is None else blinding,
            self.commitment if commitment is None else commitment,
            self.context if context is None else context,
            self.good_packets if packets is None else packets,
        )

    def test_old_share_not_on_old_commitment_raises_value_error(self):
        bad_share = Share(
            x=2, y=(self.share.y + 1) % FIELD_PRIME
        )
        with self.assertRaises(ValueError):
            self.refresh_call(share=bad_share)

    def test_old_blinding_not_on_old_commitment_raises_value_error(self):
        bad_blinding = Share(
            x=2, y=(self.blinding.y + 1) % FIELD_PRIME
        )
        with self.assertRaises(ValueError):
            self.refresh_call(blinding=bad_blinding)

    def test_old_share_not_matching_verification_share_raises_value_error(self):
        # Swap in another member's verification share: the double share
        # still verifies against the old commitment, but g ** share.y no
        # longer equals this context's entry for member 2.
        verification_shares = self.context.verification_shares
        swapped_context = dataclasses.replace(
            self.context,
            verification_shares=(
                verification_shares[1],
                verification_shares[0],
                verification_shares[2],
            ),
        )
        with self.assertRaises(ValueError):
            self.refresh_call(context=swapped_context)

    def test_old_commitment_with_other_blinding_generator_raises_value_error(self):
        # 4096 = 16 ** 3 mod 8069 is another legal subgroup generator: the
        # commitment is structurally legal but the old double share fails.
        other = dataclasses.replace(
            self.commitment, blinding_generator=4096
        )
        with self.assertRaises(ValueError):
            self.refresh_call(commitment=other)

    def test_old_material_is_checked_before_packet_crypto_checks(self):
        # A bad old share raises even when a packet would also be rejected.
        packets = list(self.good_packets)
        received = packets[0].received
        packets[0] = dataclasses.replace(
            packets[0],
            received=dataclasses.replace(
                received,
                share=Share(x=2, y=(received.share.y + 1) % FIELD_PRIME),
            ),
        )
        bad_share = Share(x=2, y=(self.share.y + 1) % FIELD_PRIME)
        with self.assertRaises(ValueError):
            self.refresh_call(share=bad_share, packets=packets)


class RefreshLocalTypeErrorTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.contributions = make_refresh_contributions(self.key)
        self.packets = packets_for(self.contributions, 2)
        self.index = self.key.result.participant_ids.index(2)
        self.share = self.key.result.shares[self.index]
        self.blinding = self.key.result.blinding_shares[self.index]
        self.commitment = self.key.result.commitment
        self.context = export_signing_public_context(self.key)

    def call(self, receiver_id=2, share=None, blinding=None, commitment=None,
             context=None, packets=None):
        return refresh_local(
            receiver_id,
            self.share if share is None else share,
            self.blinding if blinding is None else blinding,
            self.commitment if commitment is None else commitment,
            self.context if context is None else context,
            self.packets if packets is None else packets,
        )

    def test_receiver_id_type(self):
        for bad in ("2", 2.0, None, True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.call(receiver_id=bad)

    def test_object_argument_types(self):
        with self.assertRaises(TypeError):
            self.call(share="share")
        with self.assertRaises(TypeError):
            self.call(blinding=7)
        with self.assertRaises(TypeError):
            self.call(commitment="commitment")
        with self.assertRaises(TypeError):
            self.call(context={"participant_ids": (1, 2, 3)})

    def test_share_coordinate_types(self):
        for bad_share in (
            Share(x=True, y=1),
            Share(x=2, y=False),
            Share(x="2", y=1),
        ):
            with self.assertRaises(TypeError, msg=repr(bad_share)):
                self.call(share=bad_share)
        bad_blinding = Share(x=True, y=self.blinding.y)
        with self.assertRaises(TypeError):
            self.call(blinding=bad_blinding)

    def test_commitment_field_types(self):
        for field in (
            "field_prime",
            "group_prime",
            "generator",
            "blinding_generator",
        ):
            broken = dataclasses.replace(self.commitment, **{field: True})
            with self.assertRaises(TypeError, msg=field):
                self.call(commitment=broken)
        with self.assertRaises(TypeError):
            self.call(
                commitment=dataclasses.replace(
                    self.commitment, values=list(self.commitment.values)
                )
            )
        with self.assertRaises(TypeError):
            self.call(
                commitment=dataclasses.replace(
                    self.commitment,
                    values=(True,) + self.commitment.values[1:],
                )
            )

    def test_context_field_types(self):
        for field in ("threshold", "field_prime", "group_prime",
                      "generator", "public_key"):
            broken = dataclasses.replace(self.context, **{field: "x"})
            with self.assertRaises(TypeError, msg=field):
                self.call(context=broken)
        with self.assertRaises(TypeError):
            self.call(
                context=dataclasses.replace(
                    self.context,
                    verification_shares=list(self.context.verification_shares),
                )
            )
        with self.assertRaises(TypeError):
            self.call(
                context=dataclasses.replace(self.context, public_key=True)
            )

    def test_non_packet_elements(self):
        for bad in ("packet", 7, self.packets[0].received, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.call(packets=[bad])


class RefreshLocalValueErrorTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.contributions = make_refresh_contributions(self.key)
        self.packets = packets_for(self.contributions, 2)
        self.index = self.key.result.participant_ids.index(2)
        self.share = self.key.result.shares[self.index]
        self.blinding = self.key.result.blinding_shares[self.index]
        self.commitment = self.key.result.commitment
        self.context = export_signing_public_context(self.key)

    def call(self, receiver_id=2, share=None, blinding=None, commitment=None,
             context=None, packets=None):
        return refresh_local(
            receiver_id,
            self.share if share is None else share,
            self.blinding if blinding is None else blinding,
            self.commitment if commitment is None else commitment,
            self.context if context is None else context,
            self.packets if packets is None else packets,
        )

    def test_empty_batch(self):
        with self.assertRaises(ValueError):
            self.call(packets=[])

    def test_receiver_not_a_participant(self):
        for bad in (4, 0, FIELD_PRIME):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.call(receiver_id=bad)

    def test_old_share_coordinate_mismatch(self):
        with self.assertRaises(ValueError):
            self.call(share=Share(x=1, y=self.share.y))
        with self.assertRaises(ValueError):
            self.call(
                blinding=Share(x=1, y=self.blinding.y)
            )

    def test_old_share_value_out_of_range(self):
        with self.assertRaises(ValueError):
            self.call(share=Share(x=2, y=-1))
        with self.assertRaises(ValueError):
            self.call(share=Share(x=2, y=FIELD_PRIME))
        with self.assertRaises(ValueError):
            self.call(
                blinding=Share(x=2, y=FIELD_PRIME)
            )

    def test_commitment_threshold_mismatch(self):
        other_key = make_key((1, 2, 3), threshold=1)
        with self.assertRaises(ValueError):
            self.call(commitment=other_key.result.commitment)

    def test_commitment_group_mismatch(self):
        broken = dataclasses.replace(self.commitment, generator=BLINDING_GENERATOR)
        with self.assertRaises(ValueError):
            self.call(commitment=broken)

    def test_context_threshold_out_of_range(self):
        broken = dataclasses.replace(self.context, threshold=0)
        with self.assertRaises(ValueError):
            self.call(context=broken)
        broken = dataclasses.replace(self.context, threshold=4)
        with self.assertRaises(ValueError):
            self.call(context=broken)

    def test_context_verification_share_count_mismatch(self):
        broken = dataclasses.replace(
            self.context,
            verification_shares=self.context.verification_shares[:2],
        )
        with self.assertRaises(ValueError):
            self.call(context=broken)

    def test_packet_receiver_mismatch(self):
        packet = self.packets[0]
        broken = dataclasses.replace(
            packet,
            received=dataclasses.replace(packet.received, receiver_id=1),
        )
        with self.assertRaises(ValueError):
            self.call(packets=[broken, *self.packets[1:]])

    def test_packet_share_coordinate_mismatch(self):
        packet = self.packets[0]
        received = packet.received
        broken = dataclasses.replace(
            packet,
            received=dataclasses.replace(
                received, share=Share(x=1, y=received.share.y)
            ),
        )
        with self.assertRaises(ValueError):
            self.call(packets=[broken, *self.packets[1:]])

    def test_duplicate_sender(self):
        with self.assertRaises(ValueError):
            self.call(packets=[self.packets[0], self.packets[0], self.packets[2]])

    def test_missing_sender(self):
        with self.assertRaises(ValueError):
            self.call(packets=self.packets[:2])

    def test_packets_disagree_on_participant_ids(self):
        other_key = make_key((1, 2, 4))
        other_contributions = make_refresh_contributions(other_key)
        other_packets = packets_for(other_contributions, 2)
        with self.assertRaises(ValueError):
            self.call(
                packets=[self.packets[0], other_packets[1], self.packets[2]]
            )

    def test_packets_disagree_on_threshold(self):
        other_key = make_key((1, 2, 3), threshold=3)
        other_contributions = make_refresh_contributions(other_key)
        other_packets = packets_for(other_contributions, 2)
        with self.assertRaises(ValueError):
            self.call(
                packets=[self.packets[0], other_packets[1], self.packets[2]]
            )

    def test_packets_disagree_on_blinding_generator(self):
        # A packet commitment using another legal blinding generator is
        # structurally legal but disagrees with the old commitment.
        packet = self.packets[1]
        moved = dataclasses.replace(
            packet,
            commitment=dataclasses.replace(
                packet.commitment, blinding_generator=4096
            ),
        )
        with self.assertRaises(ValueError):
            self.call(packets=[self.packets[0], moved, self.packets[2]])

    def test_packet_from_non_member_sender(self):
        # Build a structurally legal packet set for member set (1, 2, 4)
        # and mix one of its packets into a (1, 2, 3) batch: the packet is
        # rejected on participant-id disagreement before sender membership
        # could even matter.
        other_key = make_key((1, 2, 4))
        other_contributions = make_refresh_contributions(other_key)
        other_packets = packets_for(other_contributions, 2)
        with self.assertRaises(ValueError):
            self.call(
                packets=[self.packets[0], self.packets[1], other_packets[2]]
            )


if __name__ == "__main__":
    unittest.main()
