"""Tests for sender-local proactive refresh dealing (create_local_refresh)."""

import dataclasses
import unittest

from thresholdsign import (
    AggregateSignature,
    DKGReceivedShare,
    LocalDKGPacket,
    PedersenCommitment,
    Share,
    SigningDKGResult,
    SigningPublicContext,
    SigningRoundPacket,
    aggregate_signature,
    aggregate_signing_dkg,
    create_local_refresh,
    create_refresh,
    create_signing_contribution,
    create_signing_nonce_commitment,
    create_signing_round,
    create_signature_share,
    decode_local_dkg_packet,
    encode_local_dkg_packet,
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

MESSAGE = b"local refresh dealing test message"


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


def packet_for(contribution, receiver_id):
    """The LocalDKGPacket ``receiver_id`` extracts from a create_refresh output."""
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


class CreateLocalRefreshValidTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.context = export_signing_public_context(self.key)
        self.commitment = self.key.result.commitment

    def create(self, sender=1, randbelow=_DEFAULT):
        return create_local_refresh(
            sender,
            self.context,
            self.commitment,
            randbelow=fixed_random(sender + 100) if randbelow is _DEFAULT else randbelow,
        )

    def test_returns_tuple_of_one_packet_per_member_sorted(self):
        packets = self.create()
        self.assertIsInstance(packets, tuple)
        self.assertEqual(len(packets), len(self.context.participant_ids))
        receiver_ids = [packet.received.receiver_id for packet in packets]
        self.assertEqual(receiver_ids, sorted(self.context.participant_ids))
        for packet in packets:
            self.assertIsInstance(packet, LocalDKGPacket)

    def test_each_packet_carries_only_its_receiver_double_share(self):
        for packet in self.create(sender=2):
            receiver_id = packet.received.receiver_id
            self.assertEqual(packet.received.sender_id, 2)
            self.assertEqual(packet.received.receiver_id, receiver_id)
            self.assertEqual(
                packet.received.share, Share(x=receiver_id, y=packet.received.share.y)
            )
            self.assertEqual(packet.received.blinding_share.x, receiver_id)
            self.assertEqual(packet.participant_ids, self.context.participant_ids)
            # No other receiver's share is reachable from the packet.
            self.assertEqual(len(dataclasses.fields(packet.received.share)), 2)

    def test_packets_equal_packets_split_from_create_refresh(self):
        for sender in self.context.participant_ids:
            packets = self.create(sender=sender)
            contribution = create_refresh(
                sender, self.key, randbelow=fixed_random(sender + 100)
            )
            expected = tuple(
                packet_for(contribution, member_id)
                for member_id in sorted(self.context.participant_ids)
            )
            self.assertEqual(packets, expected)

    def test_draw_count_order_and_bounds_match_create_refresh(self):
        seen = []
        self.create(randbelow=lambda upper: seen.append(upper) or 0)
        # t - 1 sharing coefficients then t blinding coefficients, all mod q.
        self.assertEqual(seen, [FIELD_PRIME] * (1 + 2))
        seen.clear()
        key = make_key(threshold=3)
        create_local_refresh(
            1,
            export_signing_public_context(key),
            key.result.commitment,
            randbelow=lambda upper: seen.append(upper) or 0,
        )
        self.assertEqual(seen, [FIELD_PRIME] * (2 + 3))
        seen.clear()
        key = make_key(threshold=1)
        create_local_refresh(
            1,
            export_signing_public_context(key),
            key.result.commitment,
            randbelow=lambda upper: seen.append(upper) or 0,
        )
        self.assertEqual(seen, [FIELD_PRIME])

    def test_feldman_constant_term_commitment_is_one(self):
        for packet in self.create():
            self.assertEqual(packet.feldman_commitment.values[0], 1)

    def test_two_commitments_agree_on_group_and_threshold(self):
        threshold = self.context.threshold
        for packet in self.create():
            self.assertEqual(len(packet.commitment.values), threshold)
            self.assertEqual(len(packet.feldman_commitment.values), threshold)
            self.assertEqual(packet.commitment.field_prime, FIELD_PRIME)
            self.assertEqual(packet.feldman_commitment.field_prime, FIELD_PRIME)
            self.assertEqual(packet.commitment.group_prime, GROUP_PRIME)
            self.assertEqual(packet.feldman_commitment.group_prime, GROUP_PRIME)
            self.assertEqual(packet.commitment.generator, GENERATOR)
            self.assertEqual(packet.feldman_commitment.generator, GENERATOR)
            self.assertEqual(packet.commitment.blinding_generator, BLINDING_GENERATOR)

    def test_packets_verify_against_both_commitments(self):
        from thresholdsign import verify_pedersen_share, verify_share

        for packet in self.create():
            self.assertTrue(
                verify_pedersen_share(
                    packet.received.share,
                    packet.received.blinding_share,
                    packet.commitment,
                )
            )
            self.assertTrue(verify_share(packet.received.share, packet.feldman_commitment))

    def test_default_randbelow_produces_valid_packets(self):
        packets = create_local_refresh(1, self.context, self.commitment)
        self.assertEqual(len(packets), len(self.context.participant_ids))
        for packet in packets:
            self.assertEqual(packet.feldman_commitment.values[0], 1)

    def test_threshold_one_zero_shares_and_identity_commitments(self):
        key = make_key(participant_ids=(1, 2), threshold=1, randbelow=zero_random())
        context = export_signing_public_context(key)
        packets = create_local_refresh(
            2, context, key.result.commitment, randbelow=zero_random()
        )
        self.assertEqual([packet.received.receiver_id for packet in packets], [1, 2])
        for packet in packets:
            self.assertEqual(packet.commitment.values, (1,))
            self.assertEqual(packet.feldman_commitment.values, (1,))
            self.assertEqual(packet.received.share.y, 0)
            self.assertEqual(packet.received.blinding_share.y, 0)

    def test_packets_round_trip_through_local_packet_codec(self):
        for packet in self.create():
            self.assertEqual(decode_local_dkg_packet(encode_local_dkg_packet(packet)), packet)

    def test_does_not_mutate_inputs_and_keeps_no_state(self):
        context_fields = dataclasses.asdict(self.context)
        commitment_fields = dataclasses.asdict(self.commitment)
        first = self.create(randbelow=fixed_random(9))
        self.assertEqual(dataclasses.asdict(self.context), context_fields)
        self.assertEqual(dataclasses.asdict(self.commitment), commitment_fields)
        second = self.create(randbelow=fixed_random(9))
        self.assertEqual(first, second)


class CreateLocalRefreshIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.context = export_signing_public_context(self.key)
        self.commitment = self.key.result.commitment
        self.contributions = [
            create_refresh(pid, self.key, randbelow=fixed_random(pid + 700))
            for pid in self.context.participant_ids
        ]
        self.refreshed = refresh(self.contributions, self.key)
        assert isinstance(self.refreshed, SigningDKGResult)
        per_receiver = {}
        for pid in self.context.participant_ids:
            packets = create_local_refresh(
                pid,
                self.context,
                self.commitment,
                randbelow=fixed_random(pid + 700),
            )
            for packet in packets:
                per_receiver.setdefault(packet.received.receiver_id, []).append(packet)
        self.per_receiver = per_receiver

    def local(self, receiver_id):
        index = self.context.participant_ids.index(receiver_id)
        return refresh_local(
            receiver_id,
            self.key.result.shares[index],
            self.key.result.blinding_shares[index],
            self.commitment,
            self.context,
            self.per_receiver[receiver_id],
        )

    def test_refresh_local_matches_full_refresh_for_every_member(self):
        expected_context = export_signing_public_context(self.refreshed)
        for index, participant_id in enumerate(self.context.participant_ids):
            outcome = self.local(participant_id)
            self.assertNotIsInstance(outcome, list)
            share, blinding_share, commitment, context = outcome
            self.assertEqual(share, self.refreshed.result.shares[index])
            self.assertEqual(blinding_share, self.refreshed.result.blinding_shares[index])
            self.assertEqual(commitment, self.refreshed.result.commitment)
            self.assertEqual(context, expected_context)
        self.assertEqual(self.refreshed.public_key, self.key.public_key)

    def test_new_shares_sign_and_old_signature_remains_valid(self):
        local = {
            participant_id: self.local(participant_id)
            for participant_id in self.context.participant_ids
        }
        new_context = local[1][3]
        self.assertEqual(new_context.public_key, self.context.public_key)

        # A signature made under the old shares remains valid.
        old_round = create_signing_round(
            MESSAGE,
            (1, 2),
            [
                create_signing_nonce_commitment(
                    signer_id,
                    prime=FIELD_PRIME,
                    group_prime=GROUP_PRIME,
                    generator=GENERATOR,
                    randbelow=fixed_random(300 + signer_id),
                )[0]
                for signer_id in (1, 2)
            ],
            self.key,
        )
        old_nonces = {
            signer_id: create_signing_nonce_commitment(
                signer_id,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
                randbelow=fixed_random(300 + signer_id),
            )[1]
            for signer_id in (1, 2)
        }
        old_signature = aggregate_signature(
            [
                create_signature_share(
                    signer_id,
                    self.key.result.shares[
                        self.context.participant_ids.index(signer_id)
                    ].y,
                    old_nonces[signer_id],
                    old_round,
                    self.key,
                )
                for signer_id in (1, 2)
            ],
            old_round,
            self.key,
        )
        self.assertIsInstance(old_signature, AggregateSignature)
        self.assertTrue(
            verify_signature(
                MESSAGE,
                old_signature,
                new_context.public_key,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            )
        )

        # The refreshed shares sign through the public-round packet entries.
        signer_ids = (1, 2)
        nonce_commitments = []
        nonces = {}
        for signer_id in signer_ids:
            nonce_commitment, nonce = create_signing_nonce_commitment(
                signer_id,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
                randbelow=fixed_random(400 + signer_id),
            )
            nonce_commitments.append(nonce_commitment)
            nonces[signer_id] = nonce
        round_info = create_signing_round(
            MESSAGE, signer_ids, nonce_commitments, new_context
        )
        packet = SigningRoundPacket(context=new_context, round_info=round_info)
        shares = [
            sign_round_packet(
                signer_id,
                local[signer_id][0].y,
                nonces[signer_id],
                packet,
                new_context,
                MESSAGE,
            )
            for signer_id in signer_ids
        ]
        for share in shares:
            self.assertTrue(verify_signature_share(share, round_info, new_context))
        signature = aggregate_signature(shares, round_info, new_context)
        self.assertIsInstance(signature, AggregateSignature)
        self.assertTrue(
            verify_signature(
                MESSAGE,
                signature,
                self.context.public_key,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            )
        )


class CreateLocalRefreshTypeErrorTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.context = export_signing_public_context(self.key)
        self.commitment = self.key.result.commitment

    def call(self, *, sender=1, context=_DEFAULT, old_commitment=_DEFAULT, randbelow=_DEFAULT):
        return create_local_refresh(
            sender,
            self.context if context is _DEFAULT else context,
            self.commitment if old_commitment is _DEFAULT else old_commitment,
            randbelow=fixed_random(102) if randbelow is _DEFAULT else randbelow,
        )

    def test_sender_type(self):
        for bad in ("1", 1.0, None, True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.call(sender=bad)

    def test_object_types(self):
        for bad in ("context", 7, None, self.commitment, self.key):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.call(context=bad)
        for bad in ("commitment", 7, None, self.context):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.call(old_commitment=bad)

    def test_context_field_types(self):
        with self.assertRaises(TypeError):
            self.call(context=dataclasses.replace(self.context, threshold=True))
        with self.assertRaises(TypeError):
            self.call(
                context=dataclasses.replace(self.context, participant_ids=[1, 2, 3])
            )
        with self.assertRaises(TypeError):
            self.call(
                context=dataclasses.replace(
                    self.context, verification_shares=(1, 2, "3")
                )
            )

    def test_commitment_field_types(self):
        commitment = self.commitment
        for field in ("field_prime", "group_prime", "generator", "blinding_generator"):
            for bad in (True, "x"):
                with self.assertRaises(TypeError, msg=f"{field}={bad!r}"):
                    self.call(
                        old_commitment=dataclasses.replace(commitment, **{field: bad})
                    )
        with self.assertRaises(TypeError):
            self.call(
                old_commitment=dataclasses.replace(
                    commitment, values=list(commitment.values)
                )
            )
        with self.assertRaises(TypeError):
            self.call(
                old_commitment=dataclasses.replace(
                    commitment, values=(True,) + commitment.values[1:]
                )
            )

    def test_randbelow_must_be_callable(self):
        for bad in ("randbelow", 7, None, True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.call(randbelow=bad)

    def test_randbelow_return_type(self):
        for bad in ("0", 0.0, True, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.call(randbelow=lambda upper: bad)


class CreateLocalRefreshValueErrorTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.context = export_signing_public_context(self.key)
        self.commitment = self.key.result.commitment

    def call(self, *, sender=1, context=_DEFAULT, old_commitment=_DEFAULT, randbelow=_DEFAULT):
        return create_local_refresh(
            sender,
            self.context if context is _DEFAULT else context,
            self.commitment if old_commitment is _DEFAULT else old_commitment,
            randbelow=fixed_random(102) if randbelow is _DEFAULT else randbelow,
        )

    def test_sender_must_be_a_current_member(self):
        for bad in (4, 0, FIELD_PRIME - 1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.call(sender=bad)

    def test_context_field_values(self):
        with self.assertRaises(ValueError):
            self.call(
                context=dataclasses.replace(self.context, participant_ids=(1, 3, 2))
            )
        with self.assertRaises(ValueError):
            self.call(context=dataclasses.replace(self.context, threshold=4))
        with self.assertRaises(ValueError):
            self.call(context=dataclasses.replace(self.context, public_key=GROUP_PRIME))

    def test_threshold_inconsistent_context_rejected(self):
        broken = dataclasses.replace(
            self.context, public_key=self.context.public_key * GENERATOR % GROUP_PRIME
        )
        with self.assertRaises(ValueError):
            self.call(context=broken)

    def test_illegal_commitment_values(self):
        for bad in (0, GROUP_PRIME, 2):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.call(
                    old_commitment=dataclasses.replace(
                        self.commitment, values=(bad,) + self.commitment.values[1:]
                    )
                )

    def test_illegal_commitment_group_parameters(self):
        with self.assertRaises(ValueError):
            self.call(
                old_commitment=dataclasses.replace(self.commitment, field_prime=4)
            )
        with self.assertRaises(ValueError):
            self.call(
                old_commitment=dataclasses.replace(
                    self.commitment, blinding_generator=GENERATOR
                )
            )

    def test_commitment_context_group_mismatch(self):
        with self.assertRaises(ValueError):
            self.call(
                old_commitment=dataclasses.replace(
                    self.commitment,
                    generator=BLINDING_GENERATOR,
                    blinding_generator=GENERATOR,
                )
            )

    def test_commitment_context_threshold_mismatch(self):
        with self.assertRaises(ValueError):
            self.call(
                old_commitment=dataclasses.replace(
                    self.commitment, values=self.commitment.values + (1,)
                )
            )
        with self.assertRaises(ValueError):
            self.call(
                old_commitment=dataclasses.replace(
                    self.commitment, values=self.commitment.values[:1]
                )
            )

    def test_randbelow_out_of_range_return(self):
        for bad in (-1, FIELD_PRIME):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.call(randbelow=lambda upper: bad)

    def test_randbelow_own_exception_propagates(self):
        class Boom(Exception):
            pass

        def boom(upper):
            raise Boom()

        with self.assertRaises(Boom):
            self.call(randbelow=boom)

    def test_all_inputs_checked_before_sampling(self):
        calls = []

        def recording(upper):
            calls.append(upper)
            return 0

        with self.assertRaises(ValueError):
            self.call(sender=4, randbelow=recording)
        with self.assertRaises(ValueError):
            self.call(
                old_commitment=dataclasses.replace(
                    self.commitment, values=self.commitment.values[:1]
                ),
                randbelow=recording,
            )
        with self.assertRaises(ValueError):
            self.call(
                context=dataclasses.replace(
                    self.context,
                    public_key=self.context.public_key * GENERATOR % GROUP_PRIME,
                ),
                randbelow=recording,
            )
        self.assertEqual(calls, [])

    def test_no_partial_packets_on_randbelow_failure(self):
        counter = {"calls": 0}

        def failing(upper):
            counter["calls"] += 1
            if counter["calls"] == 2:
                raise RuntimeError("randbelow failed mid-dealing")
            return 0

        with self.assertRaises(RuntimeError):
            self.call(randbelow=failing)


if __name__ == "__main__":
    unittest.main()
