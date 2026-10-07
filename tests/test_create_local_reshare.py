"""Tests for sender-local resharing dealing (create_local_reshare)."""

import dataclasses
import itertools
import unittest

from thresholdsign import (
    AggregateSignature,
    DKGReceivedShare,
    LocalDKGPacket,
    PedersenCommitment,
    Share,
    SigningDKGResult,
    SigningRoundPacket,
    aggregate_signature,
    aggregate_signing_dkg,
    create_local_reshare,
    create_reshare,
    create_signing_contribution,
    create_signing_nonce_commitment,
    create_signing_round,
    export_signing_public_context,
    reshare,
    reshare_local,
    sign_round_packet,
    verify_signature,
    verify_signature_share,
)

# Same toy Pedersen setup as the reshare tests: 8069 = 4 * 2017 + 1 is prime,
# 16 and 256 = 16 ** 2 are distinct generators of the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

MESSAGE = b"local reshare dealing test message"

_DEFAULT = object()


def fixed_random(seed=1):
    """Deterministic stand-in for secrets.randbelow so tests are reproducible."""
    state = {"value": seed}

    def randbelow(upper: int) -> int:
        state["value"] = (
            state["value"] * 6364136223846793005 + 1442695040888963407
        ) % upper
        return state["value"]

    return randbelow


def zero_random():
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
    """The LocalDKGPacket ``receiver_id`` extracts from a create_reshare output."""
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


class CreateLocalReshareValidTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.dealers = (2, 3)
        self.members = (2, 3, 4)
        self.threshold = 2
        self.context = export_signing_public_context(self.key)
        self.commitment = self.key.result.commitment

    def create(self, dealer=None, members=_DEFAULT, threshold=_DEFAULT, rng=_DEFAULT):
        dealer = self.dealers[0] if dealer is None else dealer
        return create_local_reshare(
            dealer,
            secret_share_of(self.key, dealer),
            iter(self.dealers),
            iter(self.members if members is _DEFAULT else members),
            self.threshold if threshold is _DEFAULT else threshold,
            self.context,
            self.commitment,
            rng=fixed_random(dealer + 100) if rng is _DEFAULT else rng,
        )

    def test_returns_tuple_of_one_packet_per_member_sorted(self):
        packets = self.create()
        self.assertIsInstance(packets, tuple)
        self.assertEqual(len(packets), len(self.members))
        receiver_ids = [packet.received.receiver_id for packet in packets]
        self.assertEqual(receiver_ids, sorted(self.members))
        for packet in packets:
            self.assertIsInstance(packet, LocalDKGPacket)

    def test_each_packet_carries_only_its_receiver_double_share(self):
        for packet in self.create():
            receiver_id = packet.received.receiver_id
            self.assertEqual(packet.received.sender_id, self.dealers[0])
            self.assertEqual(packet.received.receiver_id, receiver_id)
            self.assertEqual(packet.received.share, Share(x=receiver_id, y=packet.received.share.y))
            self.assertEqual(packet.received.blinding_share.x, receiver_id)
            self.assertEqual(packet.participant_ids, tuple(sorted(self.members)))
            # No other receiver's share is reachable from the packet.
            self.assertEqual(
                len(dataclasses.fields(packet.received.share)), 2
            )

    def test_packets_equal_packets_split_from_create_reshare(self):
        for dealer in self.dealers:
            packets = create_local_reshare(
                dealer,
                secret_share_of(self.key, dealer),
                self.dealers,
                self.members,
                self.threshold,
                self.context,
                self.commitment,
                rng=fixed_random(dealer + 100),
            )
            contribution = create_reshare(
                dealer,
                secret_share_of(self.key, dealer),
                self.dealers,
                self.members,
                self.threshold,
                self.key,
                rng=fixed_random(dealer + 100),
            )
            expected = tuple(
                packet_for(contribution, member_id) for member_id in sorted(self.members)
            )
            self.assertEqual(packets, expected)

    def test_members_may_arrive_unsorted_and_are_normalised(self):
        ordered = self.create(members=(2, 3, 4))
        for permutation in set(itertools.permutations(self.members)):
            self.assertEqual(
                self.create(members=permutation),
                ordered,
                msg=repr(permutation),
            )

    def test_single_pass_iterables_accepted(self):
        packets = create_local_reshare(
            self.dealers[1],
            secret_share_of(self.key, self.dealers[1]),
            iter(self.dealers),
            (member for member in (4, 2, 3)),
            self.threshold,
            self.context,
            self.commitment,
            rng=fixed_random(self.dealers[1] + 100),
        )
        self.assertEqual(
            [packet.received.receiver_id for packet in packets],
            [2, 3, 4],
        )

    def test_two_commitments_agree_on_group_and_threshold(self):
        for packet in self.create():
            self.assertEqual(len(packet.commitment.values), self.threshold)
            self.assertEqual(len(packet.feldman_commitment.values), self.threshold)
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

    def test_feldman_constant_is_weighted_old_verification_share(self):
        from thresholdsign import _lagrange_weight

        for dealer in self.dealers:
            packets = create_local_reshare(
                dealer,
                secret_share_of(self.key, dealer),
                self.dealers,
                self.members,
                self.threshold,
                self.context,
                self.commitment,
                rng=fixed_random(dealer + 100),
            )
            weight = _lagrange_weight(dealer, self.dealers, FIELD_PRIME)
            index = self.key.result.participant_ids.index(dealer)
            expected = pow(self.context.verification_shares[index], weight, GROUP_PRIME)
            for packet in packets:
                self.assertEqual(packet.feldman_commitment.values[0], expected)

    def test_draw_count_and_order_match_create_reshare(self):
        seen = []
        self.create(threshold=3, members=(1, 2, 3, 4), rng=lambda upper: seen.append(upper) or 0)
        # t - 1 sharing coefficients then t blinding coefficients.
        self.assertEqual(seen, [FIELD_PRIME] * (2 + 3))
        seen.clear()
        self.create(threshold=1, rng=lambda upper: seen.append(upper) or 0)
        self.assertEqual(seen, [FIELD_PRIME])

    def test_default_rng_produces_valid_packets(self):
        packets = create_local_reshare(
            self.dealers[0],
            secret_share_of(self.key, self.dealers[0]),
            self.dealers,
            self.members,
            self.threshold,
            self.context,
            self.commitment,
        )
        outcome = reshare_local(
            self.members[0],
            list(packets[:1])
            + self._other_dealer_packets_for(self.members[0]),
            self.dealers,
            self.context,
            self.commitment,
        )
        self.assertNotIsInstance(outcome, list)

    def _other_dealer_packets_for(self, receiver_id):
        other = self.dealers[1]
        packets = create_local_reshare(
            other,
            secret_share_of(self.key, other),
            self.dealers,
            self.members,
            self.threshold,
            self.context,
            self.commitment,
        )
        return [packet for packet in packets if packet.received.receiver_id == receiver_id]

    def test_threshold_one_zero_shares_and_identity_commitments(self):
        key = make_key(participant_ids=(1, 2), threshold=1, randbelow=zero_random())
        context = export_signing_public_context(key)
        packets = create_local_reshare(
            1,
            secret_share_of(key, 1),
            (1,),
            (2, 1),
            1,
            context,
            key.result.commitment,
            rng=zero_random(),
        )
        self.assertEqual([packet.received.receiver_id for packet in packets], [1, 2])
        for packet in packets:
            self.assertEqual(packet.commitment.values, (1,))
            self.assertEqual(packet.feldman_commitment.values, (1,))
            self.assertEqual(packet.received.share.y, 0)
            self.assertEqual(packet.received.blinding_share.y, 0)

    def test_does_not_mutate_inputs_and_keeps_no_state(self):
        dealers = list(self.dealers)
        members = [4, 2, 3]
        share = secret_share_of(self.key, self.dealers[0])
        first = create_local_reshare(
            self.dealers[0],
            share,
            dealers,
            members,
            self.threshold,
            self.context,
            self.commitment,
            rng=fixed_random(9),
        )
        self.assertEqual(dealers, list(self.dealers))
        self.assertEqual(members, [4, 2, 3])
        second = create_local_reshare(
            self.dealers[0],
            share,
            dealers,
            members,
            self.threshold,
            self.context,
            self.commitment,
            rng=fixed_random(9),
        )
        self.assertEqual(first, second)


class CreateLocalReshareIntegrationTest(unittest.TestCase):
    def test_reshare_local_matches_full_reshare_for_every_member(self):
        key = make_key()
        dealers = (1, 2, 3)
        members = (5, 1, 4, 2, 3)
        threshold = 3
        context = export_signing_public_context(key)
        commitment = key.result.commitment

        full_contributions = [
            create_reshare(
                dealer,
                secret_share_of(key, dealer),
                dealers,
                members,
                threshold,
                key,
                rng=fixed_random(dealer + 700),
            )
            for dealer in dealers
        ]
        full = reshare(full_contributions, dealers, key)
        assert isinstance(full, SigningDKGResult)

        per_receiver = {}
        for dealer in dealers:
            packets = create_local_reshare(
                dealer,
                secret_share_of(key, dealer),
                dealers,
                members,
                threshold,
                context,
                commitment,
                rng=fixed_random(dealer + 700),
            )
            for packet in packets:
                per_receiver.setdefault(packet.received.receiver_id, []).append(packet)

        expected_context = export_signing_public_context(full)
        for index, member_id in enumerate(sorted(members)):
            outcome = reshare_local(
                member_id,
                per_receiver[member_id],
                dealers,
                context,
                commitment,
            )
            self.assertNotIsInstance(outcome, list)
            share, blinding_share, new_commitment, new_context = outcome
            self.assertEqual(share, full.result.shares[index])
            self.assertEqual(blinding_share, full.result.blinding_shares[index])
            self.assertEqual(new_commitment, full.result.commitment)
            self.assertEqual(new_context, expected_context)
        self.assertEqual(full.public_key, key.public_key)

    def test_new_shares_sign_and_old_signature_remains_valid(self):
        key = make_key()
        dealers = (2, 3)
        members = (2, 3, 4)
        context = export_signing_public_context(key)
        commitment = key.result.commitment

        per_receiver = {}
        for dealer in dealers:
            for packet in create_local_reshare(
                dealer,
                secret_share_of(key, dealer),
                dealers,
                members,
                2,
                context,
                commitment,
                rng=fixed_random(dealer + 100),
            ):
                per_receiver.setdefault(packet.received.receiver_id, []).append(packet)
        local = {
            member_id: reshare_local(
                member_id, per_receiver[member_id], dealers, context, commitment
            )
            for member_id in members
        }
        new_context = local[2][3]
        self.assertEqual(new_context.public_key, context.public_key)

        signer_ids = (2, 4)
        commitments = []
        nonces = {}
        for offset, signer_id in enumerate(signer_ids):
            nonce_commitment, nonce = create_signing_nonce_commitment(
                signer_id,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
                randbelow=fixed_random(400 + offset),
            )
            commitments.append(nonce_commitment)
            nonces[signer_id] = nonce
        round_info = create_signing_round(MESSAGE, signer_ids, commitments, new_context)
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
                context.public_key,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            )
        )


class CreateLocalReshareTypeErrorTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.dealers = (2, 3)
        self.members = (2, 3, 4)
        self.context = export_signing_public_context(self.key)
        self.commitment = self.key.result.commitment
        self.share = secret_share_of(self.key, 2)

    def call(self, *, sender=2, share=_DEFAULT, dealers=_DEFAULT, members=_DEFAULT,
             threshold=2, context=_DEFAULT, old_commitment=_DEFAULT, rng=_DEFAULT):
        return create_local_reshare(
            sender,
            self.share if share is _DEFAULT else share,
            self.dealers if dealers is _DEFAULT else dealers,
            self.members if members is _DEFAULT else members,
            threshold,
            self.context if context is _DEFAULT else context,
            self.commitment if old_commitment is _DEFAULT else old_commitment,
            rng=fixed_random(102) if rng is _DEFAULT else rng,
        )

    def test_scalar_types(self):
        for name, value in (
            ("sender", "2"),
            ("sender", 2.0),
            ("sender", None),
            ("sender", True),
            ("share", "2"),
            ("share", 2.0),
            ("share", None),
            ("share", True),
        ):
            with self.assertRaises(TypeError, msg=f"{name}={value!r}"):
                self.call(**{name: value})
        for bad in ("2", 2.0, None, True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.call(threshold=bad)

    def test_object_types(self):
        for bad in ("context", 7, None, self.commitment, self.key):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.call(context=bad)
        for bad in ("commitment", 7, None, self.context):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.call(old_commitment=bad)

    def test_iterable_types(self):
        for bad in ("23", b"23", 23, None, [2, "3"], [2, True], [2, 3.0]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.call(dealers=bad)
        for bad in ("234", b"234", 234, None, [2, "3"], [2, True]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.call(members=bad)

    def test_rng_must_be_callable(self):
        for bad in ("rng", 7, None, True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.call(rng=bad)

    def test_context_field_types(self):
        with self.assertRaises(TypeError):
            self.call(context=dataclasses.replace(self.context, threshold=True))
        with self.assertRaises(TypeError):
            self.call(
                context=dataclasses.replace(self.context, participant_ids=[2, 3, 4])
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
                    self.call(old_commitment=dataclasses.replace(commitment, **{field: bad}))
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

    def test_rng_return_type(self):
        for bad in ("0", 0.0, True, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.call(rng=lambda upper: bad)


class CreateLocalReshareValueErrorTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.dealers = (2, 3)
        self.members = (2, 3, 4)
        self.context = export_signing_public_context(self.key)
        self.commitment = self.key.result.commitment
        self.share = secret_share_of(self.key, 2)

    def call(self, *, sender=2, share=_DEFAULT, dealers=_DEFAULT, members=_DEFAULT,
             threshold=2, context=_DEFAULT, old_commitment=_DEFAULT, rng=_DEFAULT):
        return create_local_reshare(
            sender,
            self.share if share is _DEFAULT else share,
            self.dealers if dealers is _DEFAULT else dealers,
            self.members if members is _DEFAULT else members,
            threshold,
            self.context if context is _DEFAULT else context,
            self.commitment if old_commitment is _DEFAULT else old_commitment,
            rng=fixed_random(102) if rng is _DEFAULT else rng,
        )

    def test_empty_sets(self):
        with self.assertRaises(ValueError):
            self.call(dealers=())
        with self.assertRaises(ValueError):
            self.call(members=())

    def test_dealer_ordering_uniqueness_and_size(self):
        with self.assertRaises(ValueError):
            self.call(dealers=(3, 2))
        with self.assertRaises(ValueError):
            self.call(dealers=(2, 2))
        with self.assertRaises(ValueError):
            self.call(dealers=(2,))

    def test_dealer_membership(self):
        with self.assertRaises(ValueError):
            self.call(dealers=(2, 4))
        with self.assertRaises(ValueError):
            self.call(dealers=(1, 2))

    def test_sender_must_be_a_dealer(self):
        with self.assertRaises(ValueError):
            self.call(sender=1, share=secret_share_of(self.key, 1))

    def test_members_duplicate_or_out_of_range(self):
        with self.assertRaises(ValueError):
            self.call(members=(2, 2, 3))
        for bad in (0, FIELD_PRIME):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.call(members=(2, 3, bad))

    def test_threshold_bounds(self):
        with self.assertRaises(ValueError):
            self.call(threshold=0)
        with self.assertRaises(ValueError):
            self.call(threshold=4)

    def test_share_range_and_match(self):
        for bad in (-1, FIELD_PRIME):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.call(share=bad)
        with self.assertRaises(ValueError):
            self.call(share=(self.share + 1) % FIELD_PRIME)

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

    def test_illegal_commitment_values(self):
        for bad in (0, GROUP_PRIME, 2):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.call(
                    old_commitment=dataclasses.replace(
                        self.commitment, values=(bad,) + self.commitment.values[1:]
                    )
                )

    def test_threshold_inconsistent_context_rejected(self):
        broken = dataclasses.replace(
            self.context, public_key=self.context.public_key * GENERATOR % GROUP_PRIME
        )
        with self.assertRaises(ValueError):
            self.call(context=broken)

    def test_rng_out_of_range_return(self):
        for bad in (-1, FIELD_PRIME):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.call(rng=lambda upper: bad)

    def test_rng_own_exception_propagates(self):
        class Boom(Exception):
            pass

        def boom(upper):
            raise Boom()

        with self.assertRaises(Boom):
            self.call(rng=boom)

    def test_all_inputs_checked_before_sampling(self):
        # An illegal set and a bad rng return: validation wins, rng never runs.
        with self.assertRaises(ValueError):
            self.call(dealers=(2,), rng=lambda upper: "not sampled")

    def test_no_partial_packets_on_rng_failure(self):
        counter = {"calls": 0}

        def failing(upper):
            counter["calls"] += 1
            if counter["calls"] == 2:
                raise RuntimeError("rng failed mid-dealing")
            return 0

        with self.assertRaises(RuntimeError):
            self.call(rng=failing)


if __name__ == "__main__":
    unittest.main()
