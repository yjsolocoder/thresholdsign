"""Tests for LocalDKGPacket and aggregate_local_dkg."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    DKGReceivedShare,
    DKGRejection,
    FeldmanCommitment,
    LocalDKGPacket,
    PedersenCommitment,
    Share,
    SigningDKGResult,
    SigningPublicContext,
    SigningRoundPacket,
    aggregate_local_dkg,
    aggregate_signature,
    aggregate_signing_dkg,
    create_signing_contribution,
    create_signing_nonce_commitment,
    create_signing_round,
    export_signing_public_context,
    sign_round_packet,
    verify_signature,
    verify_signature_share,
)

# Same toy Pedersen setup as the DKG and signing tests: 8069 = 4 * 2017 + 1
# is prime, 16 and 256 = 16 ** 2 are distinct generators of the order-2017
# subgroup of the multiplicative group modulo 8069.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

MESSAGE = b"local dkg test message"


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


def make_packets(receiver_id, participant_ids=(1, 2, 3), threshold=2, randbelow=None):
    return packets_for(
        make_contributions(participant_ids, threshold, randbelow), receiver_id
    )


class LocalDKGPacketDataClassTest(unittest.TestCase):
    def test_positional_construction_and_value_equality(self):
        packets = make_packets(2)
        packet = packets[0]
        clone = LocalDKGPacket(
            packet.participant_ids,
            packet.received,
            packet.commitment,
            packet.feldman_commitment,
        )
        self.assertEqual(packet, clone)
        self.assertEqual(
            [field.name for field in dataclasses.fields(packet)],
            ["participant_ids", "received", "commitment", "feldman_commitment"],
        )

    def test_frozen(self):
        packet = make_packets(2)[0]
        with self.assertRaises(FrozenInstanceError):
            packet.received = packet.received
        with self.assertRaises(FrozenInstanceError):
            packet.participant_ids = (1, 2, 3)

    def test_inequality_across_senders(self):
        packets = make_packets(2)
        self.assertNotEqual(packets[0], packets[1])


class AggregateLocalDKGValidTest(unittest.TestCase):
    def setUp(self):
        self.contributions = make_contributions()
        self.key = aggregate_signing_dkg(self.contributions)
        assert isinstance(self.key, SigningDKGResult)

    def test_returns_own_shares_and_public_context(self):
        outcome = aggregate_local_dkg(2, make_packets(2))
        self.assertIsInstance(outcome, tuple)
        share, blinding_share, context = outcome
        self.assertIsInstance(share, Share)
        self.assertIsInstance(blinding_share, Share)
        self.assertIsInstance(context, SigningPublicContext)
        self.assertEqual(share.x, 2)
        self.assertEqual(blinding_share.x, 2)

    def test_matches_full_aggregation_for_every_member(self):
        expected_context = export_signing_public_context(self.key)
        for index, participant_id in enumerate(self.key.result.participant_ids):
            share, blinding_share, context = aggregate_local_dkg(
                participant_id, packets_for(self.contributions, participant_id)
            )
            self.assertEqual(share, self.key.result.shares[index])
            self.assertEqual(blinding_share, self.key.result.blinding_shares[index])
            self.assertEqual(context, expected_context)

    def test_share_values_are_field_sums(self):
        packets = make_packets(1)
        share, blinding_share, _context = aggregate_local_dkg(1, packets)
        self.assertEqual(
            share.y,
            sum(packet.received.share.y for packet in packets) % FIELD_PRIME,
        )
        self.assertEqual(
            blinding_share.y,
            sum(packet.received.blinding_share.y for packet in packets) % FIELD_PRIME,
        )

    def test_input_order_does_not_matter(self):
        packets = make_packets(3)
        forward = aggregate_local_dkg(3, packets)
        reversed_outcome = aggregate_local_dkg(3, list(reversed(packets)))
        shuffled = aggregate_local_dkg(3, [packets[1], packets[2], packets[0]])
        self.assertEqual(forward, reversed_outcome)
        self.assertEqual(forward, shuffled)

    def test_accepts_single_pass_iterator(self):
        outcome = aggregate_local_dkg(2, iter(make_packets(2)))
        self.assertIsInstance(outcome, tuple)
        again = aggregate_local_dkg(2, (packet for packet in make_packets(2)))
        self.assertEqual(outcome, again)

    def test_threshold_one(self):
        contributions = make_contributions((1, 2, 3), 1)
        key = aggregate_signing_dkg(contributions)
        assert isinstance(key, SigningDKGResult)
        for index, participant_id in enumerate((1, 2, 3)):
            share, blinding_share, context = aggregate_local_dkg(
                participant_id, packets_for(contributions, participant_id)
            )
            self.assertEqual(share, key.result.shares[index])
            self.assertEqual(blinding_share, key.result.blinding_shares[index])
            self.assertEqual(context, export_signing_public_context(key))
            self.assertEqual(context.threshold, 1)

    def test_single_participant(self):
        contributions = make_contributions((5,), 1)
        share, blinding_share, context = aggregate_local_dkg(
            5, packets_for(contributions, 5)
        )
        self.assertEqual(share.x, 5)
        self.assertEqual(blinding_share.x, 5)
        self.assertEqual(context.participant_ids, (5,))
        self.assertEqual(context.threshold, 1)

    def test_zero_shares_and_identity_commitments(self):
        # An all-zero randbelow draws all-zero sharing and blinding
        # polynomials: every share value is zero and every commitment value
        # is the group identity, both of which remain legal.
        contributions = make_contributions((1, 2, 3), 2, randbelow=zero_random())
        key = aggregate_signing_dkg(contributions)
        assert isinstance(key, SigningDKGResult)
        share, blinding_share, context = aggregate_local_dkg(
            2, packets_for(contributions, 2)
        )
        self.assertEqual(share, Share(x=2, y=0))
        self.assertEqual(blinding_share, Share(x=2, y=0))
        self.assertEqual(context, export_signing_public_context(key))
        self.assertEqual(context.public_key, 1)
        self.assertEqual(context.verification_shares, (1, 1, 1))

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
        for index, participant_id in enumerate((1, 2)):
            share, blinding_share, context = aggregate_local_dkg(
                participant_id, packets_for(contributions, participant_id)
            )
            self.assertEqual(share, key.result.shares[index])
            self.assertEqual(blinding_share, key.result.blinding_shares[index])
            self.assertEqual(context, export_signing_public_context(key))

    def test_does_not_mutate_inputs_and_is_deterministic(self):
        packets = make_packets(2)
        snapshot = list(packets)
        first = aggregate_local_dkg(2, packets)
        second = aggregate_local_dkg(2, packets)
        self.assertEqual(first, second)
        self.assertEqual(packets, snapshot)

    def test_local_result_signs_with_sign_round_packet(self):
        context = export_signing_public_context(self.key)
        local = {
            participant_id: aggregate_local_dkg(
                participant_id, packets_for(self.contributions, participant_id)
            )
            for participant_id in (1, 2, 3)
        }
        for _share, _blinding, local_context in local.values():
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
                local[signer_id][2],
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


class AggregateLocalDKGRejectionTest(unittest.TestCase):
    def setUp(self):
        self.contributions = make_contributions()
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
        outcome = aggregate_local_dkg(2, packets)
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
        outcome = aggregate_local_dkg(2, packets)
        self.assertEqual(outcome, [DKGRejection(sender_id=2)])

    def test_mismatched_feldman_commitment_produces_rejection(self):
        # Another sender's Feldman commitment is well-formed but commits to
        # a different sharing polynomial.
        packets = list(self.packets)
        packets[0] = dataclasses.replace(
            packets[0], feldman_commitment=self.packets[1].feldman_commitment
        )
        outcome = aggregate_local_dkg(2, packets)
        self.assertEqual(outcome, [DKGRejection(sender_id=1)])

    def test_all_failures_listed_sorted_and_deduplicated(self):
        packets = [
            self.tamper_share(self.packets[2]),
            self.tamper_share(self.packets[0]),
            self.packets[1],
        ]
        outcome = aggregate_local_dkg(2, packets)
        self.assertIsInstance(outcome, list)
        self.assertEqual(
            outcome,
            [DKGRejection(sender_id=1), DKGRejection(sender_id=3)],
        )
        sender_ids = [rejection.sender_id for rejection in outcome]
        self.assertEqual(sender_ids, sorted(set(sender_ids)))

    def test_rejection_returns_no_partial_result(self):
        packets = [self.tamper_share(self.packets[0]), *self.packets[1:]]
        outcome = aggregate_local_dkg(2, packets)
        self.assertNotIsInstance(outcome, tuple)


class AggregateLocalDKGTypeErrorTest(unittest.TestCase):
    def setUp(self):
        self.packets = make_packets(2)

    def test_receiver_id_type(self):
        for bad in ("2", 2.0, None, True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                aggregate_local_dkg(bad, self.packets)

    def test_non_packet_elements(self):
        for bad in ("packet", 7, self.packets[0].received, self.packets):
            with self.assertRaises(TypeError, msg=repr(bad)):
                aggregate_local_dkg(2, [bad])

    def test_participant_ids_type(self):
        packet = self.packets[0]
        with self.assertRaises(TypeError):
            aggregate_local_dkg(
                2, [dataclasses.replace(packet, participant_ids=[1, 2, 3])]
            )
        with self.assertRaises(TypeError):
            aggregate_local_dkg(
                2, [dataclasses.replace(packet, participant_ids=(1, 2, "3"))]
            )
        with self.assertRaises(TypeError):
            aggregate_local_dkg(
                2, [dataclasses.replace(packet, participant_ids=(1, 2, True))]
            )

    def test_received_type(self):
        packet = self.packets[0]
        with self.assertRaises(TypeError):
            aggregate_local_dkg(2, [dataclasses.replace(packet, received="x")])

    def test_received_field_types(self):
        packet = self.packets[0]
        received = packet.received
        for field, bad in (
            ("sender_id", True),
            ("sender_id", "1"),
            ("receiver_id", False),
            ("share", "share"),
            ("blinding_share", 7),
        ):
            broken = dataclasses.replace(received, **{field: bad})
            with self.assertRaises(TypeError, msg=field):
                aggregate_local_dkg(
                    2, [dataclasses.replace(packet, received=broken)]
                )

    def test_share_coordinate_types(self):
        packet = self.packets[0]
        received = packet.received
        for bad_share in (Share(x=True, y=1), Share(x=2, y=False), Share(x="2", y=1)):
            broken = dataclasses.replace(received, share=bad_share)
            with self.assertRaises(TypeError, msg=repr(bad_share)):
                aggregate_local_dkg(
                    2, [dataclasses.replace(packet, received=broken)]
                )

    def test_commitment_types(self):
        packet = self.packets[0]
        with self.assertRaises(TypeError):
            aggregate_local_dkg(2, [dataclasses.replace(packet, commitment="c")])
        with self.assertRaises(TypeError):
            aggregate_local_dkg(
                2, [dataclasses.replace(packet, feldman_commitment=None)]
            )

    def test_commitment_field_types(self):
        packet = self.packets[0]
        commitment = packet.commitment
        for field in ("field_prime", "group_prime", "generator", "blinding_generator"):
            for bad in (True, "x"):
                broken = dataclasses.replace(commitment, **{field: bad})
                with self.assertRaises(TypeError, msg=f"{field}={bad!r}"):
                    aggregate_local_dkg(
                        2, [dataclasses.replace(packet, commitment=broken)]
                    )
        with self.assertRaises(TypeError):
            aggregate_local_dkg(
                2,
                [
                    dataclasses.replace(
                        packet,
                        commitment=dataclasses.replace(
                            commitment, values=list(commitment.values)
                        ),
                    )
                ],
            )
        with self.assertRaises(TypeError):
            aggregate_local_dkg(
                2,
                [
                    dataclasses.replace(
                        packet,
                        commitment=dataclasses.replace(
                            commitment, values=(True,) + commitment.values[1:]
                        ),
                    )
                ],
            )

    def test_feldman_field_types(self):
        packet = self.packets[0]
        feldman = packet.feldman_commitment
        for field in ("field_prime", "group_prime", "generator"):
            broken = dataclasses.replace(feldman, **{field: True})
            with self.assertRaises(TypeError, msg=field):
                aggregate_local_dkg(
                    2, [dataclasses.replace(packet, feldman_commitment=broken)]
                )
        with self.assertRaises(TypeError):
            aggregate_local_dkg(
                2,
                [
                    dataclasses.replace(
                        packet,
                        feldman_commitment=dataclasses.replace(
                            feldman, values=list(feldman.values)
                        ),
                    )
                ],
            )


class AggregateLocalDKGValueErrorTest(unittest.TestCase):
    def setUp(self):
        self.packets = make_packets(2)

    def test_empty_batch(self):
        with self.assertRaises(ValueError):
            aggregate_local_dkg(2, [])

    def test_empty_participant_ids(self):
        packet = dataclasses.replace(self.packets[0], participant_ids=())
        with self.assertRaises(ValueError):
            aggregate_local_dkg(2, [packet])

    def test_non_increasing_participant_ids(self):
        for ids in ((2, 1, 3), (1, 1, 2), (3, 2, 1)):
            packet = dataclasses.replace(self.packets[0], participant_ids=ids)
            with self.assertRaises(ValueError, msg=repr(ids)):
                aggregate_local_dkg(2, [packet])

    def test_participant_id_out_of_range(self):
        for ids in ((0, 1, 2), (1, 2, FIELD_PRIME), (1, 2, FIELD_PRIME + 1)):
            packet = dataclasses.replace(self.packets[0], participant_ids=ids)
            with self.assertRaises(ValueError, msg=repr(ids)):
                aggregate_local_dkg(2, [packet])

    def test_receiver_not_a_participant(self):
        for bad in (4, 0, FIELD_PRIME):
            with self.assertRaises(ValueError, msg=repr(bad)):
                aggregate_local_dkg(bad, self.packets)

    def test_sender_not_a_participant(self):
        packet = self.packets[0]
        broken = dataclasses.replace(
            packet.received, sender_id=4
        )
        with self.assertRaises(ValueError):
            aggregate_local_dkg(
                2, [dataclasses.replace(packet, received=broken)]
            )

    def test_duplicate_sender(self):
        packets = [self.packets[0], self.packets[0], self.packets[2]]
        with self.assertRaises(ValueError):
            aggregate_local_dkg(2, packets)

    def test_missing_sender(self):
        with self.assertRaises(ValueError):
            aggregate_local_dkg(2, self.packets[:2])

    def test_receiver_id_mismatch(self):
        packet = self.packets[0]
        broken = dataclasses.replace(packet.received, receiver_id=1)
        with self.assertRaises(ValueError):
            aggregate_local_dkg(
                2, [dataclasses.replace(packet, received=broken)]
            )

    def test_share_coordinate_mismatch(self):
        packet = self.packets[0]
        received = packet.received
        for field in ("share", "blinding_share"):
            original = getattr(received, field)
            broken = dataclasses.replace(
                received, **{field: Share(x=1, y=original.y)}
            )
            with self.assertRaises(ValueError, msg=field):
                aggregate_local_dkg(
                    2, [dataclasses.replace(packet, received=broken)]
                )

    def test_share_value_out_of_range(self):
        packet = self.packets[0]
        received = packet.received
        for bad_y in (-1, FIELD_PRIME, FIELD_PRIME + 1):
            broken = dataclasses.replace(
                received, share=Share(x=received.share.x, y=bad_y)
            )
            with self.assertRaises(ValueError, msg=repr(bad_y)):
                aggregate_local_dkg(
                    2, [dataclasses.replace(packet, received=broken)]
                )
        broken = dataclasses.replace(
            received,
            blinding_share=Share(x=received.blinding_share.x, y=FIELD_PRIME),
        )
        with self.assertRaises(ValueError):
            aggregate_local_dkg(2, [dataclasses.replace(packet, received=broken)])

    def test_threshold_out_of_range(self):
        packet = self.packets[0]
        commitment = packet.commitment
        feldman = packet.feldman_commitment
        empty = dataclasses.replace(
            packet,
            commitment=dataclasses.replace(commitment, values=()),
            feldman_commitment=dataclasses.replace(feldman, values=()),
        )
        with self.assertRaises(ValueError):
            aggregate_local_dkg(2, [empty])
        too_long = (1,) * 4
        over = dataclasses.replace(
            packet,
            commitment=dataclasses.replace(commitment, values=too_long),
            feldman_commitment=dataclasses.replace(feldman, values=too_long),
        )
        with self.assertRaises(ValueError):
            aggregate_local_dkg(2, [over])

    def test_commitment_threshold_mismatch(self):
        packet = self.packets[0]
        broken = dataclasses.replace(
            packet,
            feldman_commitment=dataclasses.replace(
                packet.feldman_commitment,
                values=packet.feldman_commitment.values + (1,),
            ),
        )
        with self.assertRaises(ValueError):
            aggregate_local_dkg(2, [broken])

    def test_commitment_group_mismatch(self):
        packet = self.packets[0]
        broken = dataclasses.replace(
            packet,
            feldman_commitment=dataclasses.replace(
                packet.feldman_commitment, generator=BLINDING_GENERATOR
            ),
        )
        with self.assertRaises(ValueError):
            aggregate_local_dkg(2, [broken])

    def test_illegal_group_parameters(self):
        packet = self.packets[0]
        commitment = packet.commitment
        feldman = packet.feldman_commitment
        cases = [
            dataclasses.replace(commitment, field_prime=4),
            dataclasses.replace(commitment, group_prime=8),
            dataclasses.replace(commitment, generator=1),
            dataclasses.replace(commitment, generator=GROUP_PRIME),
            dataclasses.replace(commitment, blinding_generator=GENERATOR),
            dataclasses.replace(commitment, blinding_generator=1),
        ]
        for broken_commitment in cases:
            broken = dataclasses.replace(
                packet,
                commitment=broken_commitment,
                feldman_commitment=dataclasses.replace(
                    feldman,
                    field_prime=broken_commitment.field_prime,
                    group_prime=broken_commitment.group_prime,
                    generator=broken_commitment.generator,
                ),
            )
            with self.assertRaises(ValueError, msg=repr(broken_commitment)):
                aggregate_local_dkg(2, [broken])

    def test_commitment_value_out_of_range_or_subgroup(self):
        packet = self.packets[0]
        commitment = packet.commitment
        for bad_value in (0, GROUP_PRIME, 2):
            broken = dataclasses.replace(
                packet,
                commitment=dataclasses.replace(
                    commitment, values=(bad_value,) + commitment.values[1:]
                ),
            )
            with self.assertRaises(ValueError, msg=repr(bad_value)):
                aggregate_local_dkg(2, [broken])
        broken_feldman = dataclasses.replace(
            packet,
            feldman_commitment=dataclasses.replace(
                packet.feldman_commitment,
                values=(2,) + packet.feldman_commitment.values[1:],
            ),
        )
        with self.assertRaises(ValueError):
            aggregate_local_dkg(2, [broken_feldman])

    def test_packets_disagree_on_participant_ids(self):
        other = make_packets(2, participant_ids=(1, 2, 4))
        with self.assertRaises(ValueError):
            aggregate_local_dkg(2, [self.packets[0], other[1], self.packets[2]])

    def test_packets_disagree_on_group_parameters(self):
        packet = self.packets[1]
        commitment = packet.commitment
        # 4096 = 16 ** 3 mod 8069 is another legal subgroup generator.
        moved = dataclasses.replace(
            packet,
            commitment=dataclasses.replace(
                commitment, blinding_generator=4096
            ),
        )
        with self.assertRaises(ValueError):
            aggregate_local_dkg(2, [self.packets[0], moved, self.packets[2]])

    def test_packets_disagree_on_threshold(self):
        other = make_packets(2, threshold=3)
        with self.assertRaises(ValueError):
            aggregate_local_dkg(2, [self.packets[0], other[1], self.packets[2]])


if __name__ == "__main__":
    unittest.main()
