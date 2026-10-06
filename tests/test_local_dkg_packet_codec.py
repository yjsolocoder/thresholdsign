"""Tests for the canonical local DKG packet transport encoding:
encode_local_dkg_packet / decode_local_dkg_packet, including its reuse
for refresh and reshare packets."""

import dataclasses
import unittest

from thresholdsign import (
    DKGReceivedShare,
    DKGRejection,
    FeldmanCommitment,
    LocalDKGPacket,
    PedersenCommitment,
    Share,
    SigningDKGResult,
    aggregate_local_dkg,
    aggregate_signing_dkg,
    create_refresh,
    create_reshare,
    create_signing_contribution,
    decode_local_dkg_packet,
    encode_local_dkg_packet,
    export_signing_public_context,
    refresh_local,
    reshare_local,
)

# Same toy Pedersen group as the local DKG tests: 8069 = 4 * 2017 + 1 and
# 16, 256 = 16 ** 2 generate the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

WIRE_TAG = b"thresholdsign/local-dkg-packet/v1"


def fixed_random(seed=1):
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


def make_contributions(participant_ids=(1, 2, 3), threshold=2, randbelow=None):
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
    outcome = aggregate_signing_dkg(
        make_contributions(participant_ids, threshold, randbelow)
    )
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


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def encode_pedersen(commitment: PedersenCommitment) -> bytes:
    out = bytearray(u32(len(commitment.values)))
    for value in commitment.values:
        out += varint(value)
    out += varint(commitment.field_prime)
    out += varint(commitment.group_prime)
    out += varint(commitment.generator)
    out += varint(commitment.blinding_generator)
    return bytes(out)


def encode_feldman(commitment: FeldmanCommitment) -> bytes:
    out = bytearray(u32(len(commitment.values)))
    for value in commitment.values:
        out += varint(value)
    out += varint(commitment.field_prime)
    out += varint(commitment.group_prime)
    out += varint(commitment.generator)
    return bytes(out)


def build_wire(packet: LocalDKGPacket) -> bytes:
    out = bytearray(WIRE_TAG)
    out += u32(len(packet.participant_ids))
    for member_id in packet.participant_ids:
        out += varint(member_id)
    out += varint(packet.received.sender_id)
    out += varint(packet.received.receiver_id)
    for share in (packet.received.share, packet.received.blinding_share):
        out += varint(share.x)
        out += varint(share.y)
    out += encode_pedersen(packet.commitment)
    out += encode_feldman(packet.feldman_commitment)
    return bytes(out)


class RoundTripTest(unittest.TestCase):
    def test_round_trip_real_packet(self):
        for packet in make_packets(2):
            wire = encode_local_dkg_packet(packet)
            decoded = decode_local_dkg_packet(wire)
            self.assertEqual(decoded, packet)
            self.assertIsInstance(decoded, LocalDKGPacket)
            self.assertIsInstance(decoded.received, DKGReceivedShare)
            self.assertIsInstance(decoded.commitment, PedersenCommitment)
            self.assertIsInstance(decoded.feldman_commitment, FeldmanCommitment)
            self.assertEqual(encode_local_dkg_packet(decoded), wire)

    def test_encoding_matches_independent_builder(self):
        for args in (
            (1, (1, 2, 3), 2),
            (5, (2, 5, 7), 2),
            (1, (1, 2), 1),
            (4, (1, 2, 3, 4, 5), 3),
        ):
            receiver_id, participant_ids, threshold = args
            for packet in make_packets(receiver_id, participant_ids, threshold):
                self.assertEqual(encode_local_dkg_packet(packet), build_wire(packet))

    def test_layout_starts_with_tag_then_fields_in_order(self):
        packet = make_packets(2)[0]
        wire = encode_local_dkg_packet(packet)
        self.assertTrue(wire.startswith(WIRE_TAG))
        offset = len(WIRE_TAG)
        self.assertEqual(wire[offset:offset + 4], u32(3))
        offset += 4
        for member_id in (1, 2, 3):
            self.assertEqual(wire[offset:offset + 5], varint(member_id))
            offset += 5
        self.assertEqual(wire[offset:offset + 5], varint(packet.received.sender_id))
        offset += 5
        self.assertEqual(wire[offset:offset + 5], varint(2))
        offset += 5
        self.assertEqual(wire[offset:offset + 5], varint(2))  # share.x
        offset += 5
        share_y = packet.received.share.y
        size = 4 + (share_y.bit_length() + 7) // 8 or 5
        self.assertEqual(wire[offset:offset + size], varint(share_y))
        offset += size
        self.assertEqual(wire[offset:offset + 5], varint(2))  # blinding_share.x
        offset += 5
        blinding_y = packet.received.blinding_share.y
        size = 4 + (blinding_y.bit_length() + 7) // 8 or 5
        self.assertEqual(wire[offset:offset + size], varint(blinding_y))
        offset += size
        self.assertEqual(
            wire[offset:offset + len(encode_pedersen(packet.commitment))],
            encode_pedersen(packet.commitment),
        )
        offset += len(encode_pedersen(packet.commitment))
        self.assertEqual(wire[offset:], encode_feldman(packet.feldman_commitment))

    def test_threshold_one_and_zero_shares_stay_legal(self):
        contributions = make_contributions((1, 2), 1, randbelow=zero_random())
        packet = packet_for(contributions[0], 1)
        self.assertEqual(packet.received.share.y, 0)
        self.assertEqual(packet.received.blinding_share.y, 0)
        # All-zero polynomials commit to the identity element.
        self.assertEqual(packet.commitment.values, (1,))
        self.assertEqual(packet.feldman_commitment.values, (1,))
        wire = encode_local_dkg_packet(packet)
        decoded = decode_local_dkg_packet(wire)
        self.assertEqual(decoded, packet)
        self.assertEqual(encode_local_dkg_packet(decoded), wire)

    def test_encoding_is_unique_and_deterministic(self):
        packet = make_packets(1)[0]
        self.assertEqual(
            encode_local_dkg_packet(packet), encode_local_dkg_packet(packet)
        )
        clone = LocalDKGPacket(
            packet.participant_ids,
            packet.received,
            packet.commitment,
            packet.feldman_commitment,
        )
        self.assertEqual(encode_local_dkg_packet(clone), encode_local_dkg_packet(packet))

    def test_encode_does_not_mutate_input(self):
        packet = make_packets(1)[0]
        snapshot = (
            packet.participant_ids,
            packet.received,
            packet.commitment,
            packet.feldman_commitment,
        )
        encode_local_dkg_packet(packet)
        self.assertEqual(
            snapshot,
            (
                packet.participant_ids,
                packet.received,
                packet.commitment,
                packet.feldman_commitment,
            ),
        )


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.packet = make_packets(2)[0]
        self.wire = encode_local_dkg_packet(self.packet)

    def test_non_bytes_raises_type_error(self):
        for bad in (None, 42, "bytes", bytearray(self.wire), [self.wire]):
            with self.assertRaises(TypeError):
                decode_local_dkg_packet(bad)  # type: ignore[arg-type]

    def test_bad_tag(self):
        bad = WIRE_TAG.replace(b"local", b"locale") + self.wire[len(WIRE_TAG):]
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(bad)
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(b"")

    def test_truncation_at_every_offset(self):
        for length in range(len(self.wire)):
            with self.assertRaises(ValueError):
                decode_local_dkg_packet(self.wire[:length])

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(self.wire + b"\x00")

    def test_zero_member_count(self):
        rest = self.wire[len(WIRE_TAG) + 4:]
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(WIRE_TAG + u32(0) + rest)

    def test_non_minimal_integer_rejected(self):
        # sender id 1 as a two-byte body with a leading zero.
        packet = self.packet
        prefix = bytearray(WIRE_TAG)
        prefix += u32(len(packet.participant_ids))
        for member_id in packet.participant_ids:
            prefix += varint(member_id)
        bad = bytes(prefix) + u32(2) + b"\x00\x01"
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(bad)
        # Zero-length body.
        bad = bytes(prefix) + u32(0)
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(bad)

    def _wire_with(self, **changes) -> bytes:
        packet = dataclasses.replace(self.packet, **changes)
        return build_wire(packet)

    def test_unsorted_or_duplicate_members_rejected(self):
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(self._wire_with(participant_ids=(1, 3, 2)))
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(self._wire_with(participant_ids=(1, 2, 2)))

    def test_member_id_out_of_range_rejected(self):
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(self._wire_with(participant_ids=(1, 2, FIELD_PRIME)))

    def test_sender_or_receiver_not_a_member_rejected(self):
        received = self.packet.received
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(
                self._wire_with(received=dataclasses.replace(received, sender_id=4))
            )
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(
                self._wire_with(received=dataclasses.replace(received, receiver_id=3))
            )

    def test_share_coordinate_mismatch_rejected(self):
        received = self.packet.received
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(
                self._wire_with(
                    received=dataclasses.replace(
                        received, share=Share(1, received.share.y)
                    )
                )
            )
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(
                self._wire_with(
                    received=dataclasses.replace(
                        received, blinding_share=Share(3, received.blinding_share.y)
                    )
                )
            )

    def test_share_value_out_of_range_rejected(self):
        received = self.packet.received
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(
                self._wire_with(
                    received=dataclasses.replace(
                        received, share=Share(2, FIELD_PRIME)
                    )
                )
            )

    def test_threshold_mismatch_rejected(self):
        feldman = self.packet.feldman_commitment
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(
                self._wire_with(
                    feldman_commitment=dataclasses.replace(
                        feldman, values=feldman.values[:1]
                    )
                )
            )

    def test_threshold_out_of_range_rejected(self):
        commitment = self.packet.commitment
        feldman = self.packet.feldman_commitment
        # Four values over three members: threshold 4 > member count 3.
        extra = commitment.values + (1, 1)
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(
                self._wire_with(
                    commitment=dataclasses.replace(commitment, values=extra),
                    feldman_commitment=dataclasses.replace(feldman, values=extra),
                )
            )

    def test_group_parameter_mismatch_rejected(self):
        feldman = self.packet.feldman_commitment
        for changes in (
            {"field_prime": 2011},
            {"group_prime": 8081},
            {"generator": BLINDING_GENERATOR},
        ):
            with self.assertRaises(ValueError):
                decode_local_dkg_packet(
                    self._wire_with(
                        feldman_commitment=dataclasses.replace(feldman, **changes)
                    )
                )

    def test_illegal_group_parameters_rejected(self):
        commitment = self.packet.commitment
        feldman = self.packet.feldman_commitment
        # 2018 is not prime.
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(
                self._wire_with(
                    commitment=dataclasses.replace(commitment, field_prime=2018),
                    feldman_commitment=dataclasses.replace(feldman, field_prime=2018),
                )
            )
        # generator 1 is the identity, not a subgroup generator.
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(
                self._wire_with(
                    commitment=dataclasses.replace(commitment, generator=1),
                    feldman_commitment=dataclasses.replace(feldman, generator=1),
                )
            )

    def test_illegal_commitment_value_rejected(self):
        commitment = self.packet.commitment
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(
                self._wire_with(
                    commitment=dataclasses.replace(
                        commitment, values=(0, commitment.values[1])
                    )
                )
            )
        # 2 is not in the order-2017 subgroup.
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(
                self._wire_with(
                    commitment=dataclasses.replace(
                        commitment, values=(2, commitment.values[1])
                    )
                )
            )


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.packet = make_packets(2)[0]

    def test_non_packet_raises_type_error(self):
        for bad in (
            None,
            42,
            "packet",
            (1, 2),
            Share(1, 2),
            self.packet.received,
            self.packet.commitment,
        ):
            with self.assertRaises(TypeError):
                encode_local_dkg_packet(bad)  # type: ignore[arg-type]

    def test_bad_field_types_raise_type_error(self):
        packet = self.packet
        received = packet.received
        variants = (
            dataclasses.replace(packet, participant_ids=[1, 2, 3]),
            dataclasses.replace(packet, participant_ids=(1, 2, "3")),
            dataclasses.replace(packet, participant_ids=(1, 2, True)),
            dataclasses.replace(packet, received="received"),
            dataclasses.replace(
                packet, received=dataclasses.replace(received, sender_id="1")
            ),
            dataclasses.replace(
                packet, received=dataclasses.replace(received, receiver_id=False)
            ),
            dataclasses.replace(
                packet,
                received=dataclasses.replace(received, share=Share(2, "y")),
            ),
            dataclasses.replace(
                packet,
                received=dataclasses.replace(received, blinding_share=(2, 3)),
            ),
            dataclasses.replace(packet, commitment=packet.feldman_commitment),
            dataclasses.replace(packet, feldman_commitment=packet.commitment),
            dataclasses.replace(
                packet,
                commitment=dataclasses.replace(packet.commitment, values=[1, 2]),
            ),
            dataclasses.replace(
                packet,
                commitment=dataclasses.replace(
                    packet.commitment, blinding_generator=True
                ),
            ),
            dataclasses.replace(
                packet,
                feldman_commitment=dataclasses.replace(
                    packet.feldman_commitment, group_prime=8069.0
                ),
            ),
        )
        for bad in variants:
            with self.assertRaises(TypeError):
                encode_local_dkg_packet(bad)

    def test_illegal_structure_raises_value_error(self):
        packet = self.packet
        received = packet.received
        commitment = packet.commitment
        feldman = packet.feldman_commitment
        variants = (
            dataclasses.replace(packet, participant_ids=()),
            dataclasses.replace(packet, participant_ids=(2, 1, 3)),
            dataclasses.replace(packet, participant_ids=(0, 1, 2)),
            dataclasses.replace(packet, participant_ids=(1, 2, FIELD_PRIME)),
            dataclasses.replace(
                packet, received=dataclasses.replace(received, sender_id=9)
            ),
            dataclasses.replace(
                packet, received=dataclasses.replace(received, receiver_id=3)
            ),
            dataclasses.replace(
                packet,
                received=dataclasses.replace(received, share=Share(1, received.share.y)),
            ),
            dataclasses.replace(
                packet,
                received=dataclasses.replace(
                    received, share=Share(2, FIELD_PRIME)
                ),
            ),
            dataclasses.replace(
                packet,
                feldman_commitment=dataclasses.replace(
                    feldman, values=feldman.values[:1]
                ),
            ),
            dataclasses.replace(
                packet,
                commitment=dataclasses.replace(
                    commitment, values=commitment.values + (1, 1)
                ),
                feldman_commitment=dataclasses.replace(
                    feldman, values=feldman.values + (1, 1)
                ),
            ),
            dataclasses.replace(
                packet,
                feldman_commitment=dataclasses.replace(feldman, generator=BLINDING_GENERATOR),
            ),
            dataclasses.replace(
                packet,
                commitment=dataclasses.replace(commitment, values=(0, 1)),
            ),
        )
        for bad in variants:
            with self.assertRaises(ValueError):
                encode_local_dkg_packet(bad)


class AggregationEquivalenceTest(unittest.TestCase):
    def test_decoded_packets_aggregate_identically(self):
        contributions = make_contributions()
        packets = packets_for(contributions, 2)
        decoded = [
            decode_local_dkg_packet(encode_local_dkg_packet(packet))
            for packet in packets
        ]
        original = aggregate_local_dkg(2, packets)
        round_trip = aggregate_local_dkg(2, decoded)
        self.assertNotIsInstance(original, list)
        self.assertEqual(round_trip, original)

    def test_rejection_list_is_preserved(self):
        contributions = make_contributions()
        packets = packets_for(contributions, 3)
        bad = dataclasses.replace(
            packets[1],
            received=dataclasses.replace(
                packets[1].received,
                share=Share(3, (packets[1].received.share.y + 1) % FIELD_PRIME),
            ),
        )
        direct = aggregate_local_dkg(3, [packets[0], bad, packets[2]])
        round_trip_bad = decode_local_dkg_packet(encode_local_dkg_packet(bad))
        through_codec = aggregate_local_dkg(
            3, [packets[0], round_trip_bad, packets[2]]
        )
        self.assertEqual(direct, [DKGRejection(sender_id=2)])
        self.assertEqual(through_codec, direct)

    def test_unbound_commitments_still_round_trip(self):
        packet = make_packets(1)[0]
        # Other legal subgroup elements, same parameters and count:
        # structurally fine, but they commit to a different polynomial.
        other_values = tuple(pow(GENERATOR, j + 2, GROUP_PRIME) for j in range(2))
        unbound = dataclasses.replace(
            packet,
            feldman_commitment=dataclasses.replace(
                packet.feldman_commitment, values=other_values
            ),
        )
        wire = encode_local_dkg_packet(unbound)
        decoded = decode_local_dkg_packet(wire)
        self.assertEqual(decoded, unbound)
        self.assertEqual(encode_local_dkg_packet(decoded), wire)
        others = make_packets(1)[1:]
        direct = aggregate_local_dkg(1, [unbound] + others)
        through_codec = aggregate_local_dkg(1, [decoded] + others)
        self.assertEqual(direct, [DKGRejection(sender_id=1)])
        self.assertEqual(through_codec, direct)


class RefreshReshareEquivalenceTest(unittest.TestCase):
    def test_refresh_packets_round_trip_and_act_identically(self):
        key = make_key()
        contributions = [
            create_refresh(pid, key, randbelow=fixed_random(pid + 100))
            for pid in (1, 2, 3)
        ]
        receiver_id = 2
        index = key.result.participant_ids.index(receiver_id)
        packets = packets_for(contributions, receiver_id)
        decoded = [
            decode_local_dkg_packet(encode_local_dkg_packet(packet))
            for packet in packets
        ]
        context = export_signing_public_context(key)
        direct = refresh_local(
            receiver_id,
            key.result.shares[index],
            key.result.blinding_shares[index],
            key.result.commitment,
            context,
            packets,
        )
        through_codec = refresh_local(
            receiver_id,
            key.result.shares[index],
            key.result.blinding_shares[index],
            key.result.commitment,
            context,
            decoded,
        )
        self.assertNotIsInstance(direct, list)
        self.assertEqual(through_codec, direct)

    def test_refresh_rejection_is_preserved(self):
        key = make_key()
        contributions = [
            create_refresh(pid, key, randbelow=fixed_random(pid + 100))
            for pid in (1, 2, 3)
        ]
        receiver_id = 1
        index = key.result.participant_ids.index(receiver_id)
        packets = packets_for(contributions, receiver_id)
        bad = dataclasses.replace(
            packets[1],
            received=dataclasses.replace(
                packets[1].received,
                share=Share(1, (packets[1].received.share.y + 1) % FIELD_PRIME),
            ),
        )
        batch = [packets[0], bad, packets[2]]
        decoded_batch = [
            packets[0],
            decode_local_dkg_packet(encode_local_dkg_packet(bad)),
            packets[2],
        ]
        context = export_signing_public_context(key)
        args = (
            receiver_id,
            key.result.shares[index],
            key.result.blinding_shares[index],
            key.result.commitment,
            context,
        )
        direct = refresh_local(*args, batch)
        through_codec = refresh_local(*args, decoded_batch)
        self.assertEqual(direct, [DKGRejection(sender_id=2)])
        self.assertEqual(through_codec, direct)

    def test_reshare_packets_round_trip_and_act_identically(self):
        key = make_key()
        dealers = (1, 2)
        members = (1, 2, 4, 5)
        contributions = [
            create_reshare(
                dealer,
                key.result.shares[key.result.participant_ids.index(dealer)].y,
                dealers,
                members,
                3,
                key,
                rng=fixed_random(dealer + 200),
            )
            for dealer in dealers
        ]
        receiver_id = 4
        packets = packets_for(contributions, receiver_id)
        decoded = [
            decode_local_dkg_packet(encode_local_dkg_packet(packet))
            for packet in packets
        ]
        args = (
            receiver_id,
            dealers,
            export_signing_public_context(key),
            key.result.commitment,
        )
        direct = reshare_local(args[0], packets, *args[1:])
        through_codec = reshare_local(args[0], decoded, *args[1:])
        self.assertNotIsInstance(direct, list)
        self.assertEqual(through_codec, direct)

    def test_reshare_rejection_is_preserved(self):
        key = make_key()
        dealers = (1, 2)
        members = (1, 2, 4, 5)
        contributions = [
            create_reshare(
                dealer,
                key.result.shares[key.result.participant_ids.index(dealer)].y,
                dealers,
                members,
                3,
                key,
                rng=fixed_random(dealer + 200),
            )
            for dealer in dealers
        ]
        receiver_id = 5
        packets = packets_for(contributions, receiver_id)
        bad = dataclasses.replace(
            packets[0],
            received=dataclasses.replace(
                packets[0].received,
                blinding_share=Share(
                    5, (packets[0].received.blinding_share.y + 1) % FIELD_PRIME
                ),
            ),
        )
        batch = [bad, packets[1]]
        decoded_batch = [
            decode_local_dkg_packet(encode_local_dkg_packet(bad)),
            packets[1],
        ]
        args = (
            receiver_id,
            dealers,
            export_signing_public_context(key),
            key.result.commitment,
        )
        direct = reshare_local(args[0], batch, *args[1:])
        through_codec = reshare_local(args[0], decoded_batch, *args[1:])
        self.assertEqual(direct, [DKGRejection(sender_id=1)])
        self.assertEqual(through_codec, direct)


if __name__ == "__main__":
    unittest.main()
