"""Tests for the canonical local DKG packet transport encoding:
encode_local_dkg_packet / decode_local_dkg_packet."""

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

# Same toy Pedersen setup as the local DKG tests: 8069 = 4 * 2017 + 1 is
# prime, 16 and 256 = 16 ** 2 are distinct generators of the order-2017
# subgroup of the multiplicative group modulo 8069.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

WIRE_TAG = b"thresholdsign/local-dkg-packet/v1"


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
    """Deterministic source that draws only zeros (all-zero polynomials)."""
    return lambda upper: 0


def make_contributions(
    participant_ids=(1, 2, 3),
    threshold=2,
    randbelow=None,
    field_prime=FIELD_PRIME,
    group_prime=GROUP_PRIME,
    generator=GENERATOR,
    blinding_generator=BLINDING_GENERATOR,
):
    """One valid SigningContribution per participant."""
    return [
        create_signing_contribution(
            pid,
            participant_ids,
            threshold,
            prime=field_prime,
            group_prime=group_prime,
            generator=generator,
            blinding_generator=blinding_generator,
            randbelow=randbelow if randbelow is not None else fixed_random(pid),
        )
        for pid in participant_ids
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


def make_packets(receiver_id, participant_ids=(1, 2, 3), threshold=2, randbelow=None):
    return [
        packet_for(contribution, receiver_id)
        for contribution in make_contributions(
            participant_ids, threshold, randbelow
        )
    ]


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def encode_pedersen(commitment: PedersenCommitment) -> bytes:
    """Independently encode a Pedersen commitment straight from the spec."""
    out = bytearray(u32(len(commitment.values)))
    for value in commitment.values:
        out += varint(value)
    out += varint(commitment.field_prime)
    out += varint(commitment.group_prime)
    out += varint(commitment.generator)
    out += varint(commitment.blinding_generator)
    return bytes(out)


def encode_feldman(commitment: FeldmanCommitment) -> bytes:
    """Independently encode a Feldman commitment straight from the spec."""
    out = bytearray(u32(len(commitment.values)))
    for value in commitment.values:
        out += varint(value)
    out += varint(commitment.field_prime)
    out += varint(commitment.group_prime)
    out += varint(commitment.generator)
    return bytes(out)


def build_wire(packet: LocalDKGPacket) -> bytes:
    """Independently build the local DKG packet wire format from the spec."""
    out = bytearray(WIRE_TAG)
    out += u32(len(packet.participant_ids))
    for participant_id in packet.participant_ids:
        out += varint(participant_id)
    received = packet.received
    out += varint(received.sender_id)
    out += varint(received.receiver_id)
    out += varint(received.share.x)
    out += varint(received.share.y)
    out += varint(received.blinding_share.x)
    out += varint(received.blinding_share.y)
    out += encode_pedersen(packet.commitment)
    out += encode_feldman(packet.feldman_commitment)
    return bytes(out)


class RoundTripTest(unittest.TestCase):
    def test_round_trip_real_packet(self):
        for receiver_id in (1, 2, 3):
            for packet in make_packets(receiver_id):
                wire = encode_local_dkg_packet(packet)
                decoded = decode_local_dkg_packet(wire)
                self.assertEqual(decoded, packet)
                self.assertIsInstance(decoded, LocalDKGPacket)
                self.assertEqual(encode_local_dkg_packet(decoded), wire)

    def test_encoding_matches_independent_builder(self):
        for receiver_id, participant_ids, threshold in (
            (2, (1, 2, 3), 2),
            (5, (2, 5, 7), 2),
            (1, (1, 2), 1),
            (4, (1, 2, 3, 4, 5), 3),
        ):
            for packet in make_packets(receiver_id, participant_ids, threshold):
                self.assertEqual(encode_local_dkg_packet(packet), build_wire(packet))

    def test_zero_shares_and_identity_commitments_round_trip(self):
        # All-zero polynomials: zero share values and identity commitment
        # values stay legal, exactly as in the full aggregation.
        for packet in make_packets(2, randbelow=zero_random()):
            self.assertEqual(packet.received.share.y, 0)
            self.assertEqual(packet.received.blinding_share.y, 0)
            self.assertEqual(packet.commitment.values, (1, 1))
            wire = encode_local_dkg_packet(packet)
            decoded = decode_local_dkg_packet(wire)
            self.assertEqual(decoded, packet)
            self.assertEqual(encode_local_dkg_packet(decoded), wire)

    def test_threshold_one_round_trip(self):
        for packet in make_packets(1, (1, 2), 1):
            wire = encode_local_dkg_packet(packet)
            self.assertEqual(decode_local_dkg_packet(wire), packet)
            self.assertEqual(encode_local_dkg_packet(decode_local_dkg_packet(wire)), wire)

    def test_encoding_is_unique_and_deterministic(self):
        packet = make_packets(2)[0]
        self.assertEqual(
            encode_local_dkg_packet(packet),
            encode_local_dkg_packet(packet),
        )
        clone = LocalDKGPacket(
            packet.participant_ids,
            packet.received,
            packet.commitment,
            packet.feldman_commitment,
        )
        self.assertEqual(encode_local_dkg_packet(clone), encode_local_dkg_packet(packet))

    def test_starts_with_tag_and_layout(self):
        packet = make_packets(2, (1, 2, 3), 1)[1]
        wire = encode_local_dkg_packet(packet)
        self.assertTrue(wire.startswith(WIRE_TAG))
        offset = len(WIRE_TAG)
        # participant count 3, ids 1, 2, 3 as single-byte varints
        self.assertEqual(wire[offset:offset + 4], u32(3))
        offset += 4
        for expected in (1, 2, 3):
            self.assertEqual(wire[offset:offset + 5], u32(1) + bytes([expected]))
            offset += 5
        # sender id 2, receiver id 2
        self.assertEqual(wire[offset:offset + 5], u32(1) + b"\x02")
        offset += 5
        self.assertEqual(wire[offset:offset + 5], u32(1) + b"\x02")
        offset += 5
        received = packet.received
        for share in (received.share, received.blinding_share):
            frame = varint(share.x) + varint(share.y)
            self.assertEqual(wire[offset:offset + len(frame)], frame)
            offset += len(frame)
        # remainder is exactly the two commitment encodings
        self.assertEqual(
            wire[offset:],
            encode_pedersen(packet.commitment) + encode_feldman(packet.feldman_commitment),
        )

    def test_multi_byte_integer_encoding_is_canonical(self):
        # Larger toy group (same one the refresh tests use): share values,
        # primes and generators are all genuinely multi-byte.
        contributions = make_contributions(
            field_prime=1000151,
            group_prime=2000303,
            generator=9,
            blinding_generator=81,
        )
        packet = packet_for(contributions[2], 3)
        wire = encode_local_dkg_packet(packet)
        decoded = decode_local_dkg_packet(wire)
        self.assertEqual(decoded, packet)
        self.assertEqual(encode_local_dkg_packet(decoded), wire)
        self.assertEqual(wire, build_wire(packet))
        # At least one commitment value spans more than one body byte.
        wide = [v for v in packet.commitment.values if v > 255]
        self.assertTrue(wide)
        value = wide[0]
        body = value.to_bytes((value.bit_length() + 7) // 8, "big")
        self.assertIn(u32(len(body)) + body, wire)

    def test_encode_does_not_modify_input(self):
        packet = make_packets(2)[0]
        snapshot = LocalDKGPacket(
            packet.participant_ids,
            packet.received,
            packet.commitment,
            packet.feldman_commitment,
        )
        encode_local_dkg_packet(packet)
        self.assertEqual(packet, snapshot)


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.packet = make_packets(2)[1]
        self.wire = encode_local_dkg_packet(self.packet)

    def test_non_bytes_raises_type_error(self):
        for bad in (None, 42, "bytes", bytearray(self.wire), [self.wire]):
            with self.assertRaises(TypeError):
                decode_local_dkg_packet(bad)  # type: ignore[arg-type]

    def test_bad_tag(self):
        bad = b"thresholdsign/dkg-contribution/v1" + self.wire[len(WIRE_TAG):]
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(bad)
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(b"")

    def test_truncation_at_every_offset(self):
        for length in range(0, len(self.wire)):
            with self.assertRaises(ValueError):
                decode_local_dkg_packet(self.wire[:length])

    def test_trailing_bytes(self):
        for suffix in (b"\x00", b"\x01\x02", b"trailing"):
            with self.assertRaises(ValueError):
                decode_local_dkg_packet(self.wire + suffix)

    def test_zero_participant_count(self):
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(WIRE_TAG + u32(0))

    def test_zero_or_unsorted_or_duplicate_participant_ids(self):
        for encoded_ids in (
            u32(1) + varint(0),
            u32(2) + varint(2) + varint(1),
            u32(2) + varint(2) + varint(2),
        ):
            with self.assertRaises(ValueError):
                decode_local_dkg_packet(WIRE_TAG + encoded_ids)

    def test_non_canonical_integer_frames(self):
        # zero-length body
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(WIRE_TAG + u32(0))
        # leading zero inside a multi-byte body
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(WIRE_TAG + u32(2) + b"\x00\x02")
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(WIRE_TAG + u32(2) + b"\x00\x00")
        # declared body longer than the stream
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(WIRE_TAG + u32(9) + b"\x02")

    def rebuild(self, packet: LocalDKGPacket) -> bytes:
        """Encode a (possibly illegal) packet straight from the spec."""
        return build_wire(packet)

    def test_sender_outside_participant_set(self):
        bad = dataclasses.replace(
            self.packet,
            received=dataclasses.replace(self.packet.received, sender_id=4),
        )
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(self.rebuild(bad))
        bad_zero = dataclasses.replace(
            self.packet,
            received=dataclasses.replace(self.packet.received, sender_id=0),
        )
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(self.rebuild(bad_zero))

    def test_receiver_outside_participant_set(self):
        bad = dataclasses.replace(
            self.packet,
            received=DKGReceivedShare(
                sender_id=self.packet.received.sender_id,
                receiver_id=4,
                share=Share(4, self.packet.received.share.y),
                blinding_share=Share(4, self.packet.received.blinding_share.y),
            ),
        )
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(self.rebuild(bad))

    def test_share_coordinate_not_receiver(self):
        received = self.packet.received
        bad = dataclasses.replace(
            self.packet,
            received=dataclasses.replace(
                received, share=Share(received.receiver_id + 1, received.share.y)
            ),
        )
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(self.rebuild(bad))
        bad_blinding = dataclasses.replace(
            self.packet,
            received=dataclasses.replace(
                received,
                blinding_share=Share(0, received.blinding_share.y),
            ),
        )
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(self.rebuild(bad_blinding))

    def test_share_value_outside_field(self):
        received = self.packet.received
        bad = dataclasses.replace(
            self.packet,
            received=dataclasses.replace(
                received, share=Share(received.receiver_id, FIELD_PRIME)
            ),
        )
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(self.rebuild(bad))

    def test_commitment_threshold_mismatch(self):
        bad = dataclasses.replace(
            self.packet,
            feldman_commitment=dataclasses.replace(
                self.packet.feldman_commitment,
                values=self.packet.feldman_commitment.values + (1,),
            ),
        )
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(self.rebuild(bad))

    def test_threshold_above_participant_count_rejected(self):
        commitment = dataclasses.replace(
            self.packet.commitment, values=(1, 1, 1, 1)
        )
        feldman = dataclasses.replace(
            self.packet.feldman_commitment, values=(1, 1, 1, 1)
        )
        bad = dataclasses.replace(
            self.packet, commitment=commitment, feldman_commitment=feldman
        )
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(self.rebuild(bad))

    def test_commitments_disagreeing_on_group_parameters(self):
        bad = dataclasses.replace(
            self.packet,
            feldman_commitment=dataclasses.replace(
                self.packet.feldman_commitment, generator=BLINDING_GENERATOR
            ),
        )
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(self.rebuild(bad))

    def test_illegal_commitment_rejected(self):
        illegal_values = dataclasses.replace(
            self.packet.commitment, values=(0, 1)
        )
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(
                self.rebuild(dataclasses.replace(self.packet, commitment=illegal_values))
            )
        same_generators = dataclasses.replace(
            self.packet.commitment, blinding_generator=GENERATOR
        )
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(
                self.rebuild(dataclasses.replace(self.packet, commitment=same_generators))
            )
        non_prime = dataclasses.replace(
            self.packet.feldman_commitment, field_prime=2021
        )
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(
                self.rebuild(dataclasses.replace(self.packet, feldman_commitment=non_prime))
            )
        outside_subgroup = dataclasses.replace(
            self.packet.commitment, values=(2, 1)
        )
        with self.assertRaises(ValueError):
            decode_local_dkg_packet(
                self.rebuild(dataclasses.replace(self.packet, commitment=outside_subgroup))
            )


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.packet = make_packets(2)[1]

    def test_non_packet_raises_type_error(self):
        for bad in (
            None,
            42,
            "packet",
            (1, 2),
            Share(1, 2),
            make_contributions()[0],
            make_contributions()[0].contribution,
        ):
            with self.assertRaises(TypeError):
                encode_local_dkg_packet(bad)  # type: ignore[arg-type]

    def test_bad_field_types_raise_type_error(self):
        packet = self.packet
        variants = (
            dataclasses.replace(packet, participant_ids=[1, 2, 3]),
            dataclasses.replace(packet, received="received"),
            dataclasses.replace(
                packet,
                received=dataclasses.replace(packet.received, sender_id="1"),
            ),
            dataclasses.replace(
                packet,
                received=dataclasses.replace(
                    packet.received, share=(packet.received.share.x, 1)
                ),
            ),
            dataclasses.replace(
                packet,
                commitment=dataclasses.replace(
                    packet.commitment, field_prime="2017"
                ),
            ),
            dataclasses.replace(
                packet,
                commitment=dataclasses.replace(packet.commitment, values=[1, 2]),
            ),
            dataclasses.replace(
                packet,
                feldman_commitment=dataclasses.replace(
                    packet.feldman_commitment, generator=None
                ),
            ),
        )
        for bad in variants:
            with self.assertRaises(TypeError):
                encode_local_dkg_packet(bad)

    def test_boolean_fields_raise_type_error(self):
        packet = self.packet
        variants = (
            dataclasses.replace(packet, participant_ids=(True, 2, 3)),
            dataclasses.replace(
                packet,
                received=dataclasses.replace(packet.received, sender_id=True),
            ),
            dataclasses.replace(
                packet,
                received=dataclasses.replace(packet.received, receiver_id=False),
            ),
            dataclasses.replace(
                packet,
                received=dataclasses.replace(
                    packet.received, share=Share(True, 0)
                ),
            ),
            dataclasses.replace(
                packet,
                commitment=dataclasses.replace(
                    packet.commitment, values=(True, True)
                ),
            ),
        )
        for bad in variants:
            with self.assertRaises(TypeError):
                encode_local_dkg_packet(bad)

    def test_illegal_structure_raises_value_error(self):
        packet = self.packet
        received = packet.received
        variants = (
            dataclasses.replace(packet, participant_ids=()),
            dataclasses.replace(packet, participant_ids=(2, 1, 3)),
            dataclasses.replace(packet, participant_ids=(0, 1, 2)),
            dataclasses.replace(
                packet,
                received=dataclasses.replace(received, sender_id=4),
            ),
            dataclasses.replace(
                packet,
                received=dataclasses.replace(received, receiver_id=4),
            ),
            dataclasses.replace(
                packet,
                received=dataclasses.replace(
                    received, share=Share(received.receiver_id, FIELD_PRIME)
                ),
            ),
            dataclasses.replace(
                packet,
                commitment=dataclasses.replace(packet.commitment, values=(0, 1)),
            ),
            dataclasses.replace(
                packet,
                commitment=dataclasses.replace(
                    packet.commitment, values=(1, 1, 1, 1)
                ),
                feldman_commitment=dataclasses.replace(
                    packet.feldman_commitment, values=(1, 1, 1, 1)
                ),
            ),
        )
        for bad in variants:
            with self.assertRaises(ValueError):
                encode_local_dkg_packet(bad)


class AggregationEquivalenceTest(unittest.TestCase):
    def test_decoded_packets_aggregate_identically(self):
        packets = make_packets(2)
        decoded = [
            decode_local_dkg_packet(encode_local_dkg_packet(packet))
            for packet in packets
        ]
        original = aggregate_local_dkg(2, packets)
        round_trip = aggregate_local_dkg(2, decoded)
        self.assertNotIsInstance(original, list)
        self.assertEqual(round_trip, original)

    def test_input_order_independence_preserved(self):
        packets = make_packets(3)
        decoded = [
            decode_local_dkg_packet(encode_local_dkg_packet(packet))
            for packet in packets
        ]
        self.assertEqual(
            aggregate_local_dkg(3, decoded),
            aggregate_local_dkg(3, list(reversed(decoded))),
        )

    def test_cryptographic_rejection_is_preserved(self):
        packets = make_packets(2)
        received = packets[1].received
        tampered = dataclasses.replace(
            packets[1],
            received=dataclasses.replace(
                received,
                share=Share(received.receiver_id, (received.share.y + 1) % FIELD_PRIME),
            ),
        )
        direct = aggregate_local_dkg(2, [packets[0], tampered, packets[2]])
        round_trip_bad = decode_local_dkg_packet(encode_local_dkg_packet(tampered))
        through_codec = aggregate_local_dkg(
            2, [packets[0], round_trip_bad, packets[2]]
        )
        self.assertEqual(direct, [DKGRejection(sender_id=2)])
        self.assertEqual(through_codec, direct)

    def test_decoded_packets_feed_refresh_local(self):
        contributions = make_contributions()
        key = aggregate_signing_dkg(contributions)
        self.assertIsInstance(key, SigningDKGResult)
        receiver_id = 2
        index = key.result.participant_ids.index(receiver_id)
        context = export_signing_public_context(key)
        refresh_contributions = [
            create_refresh(pid, key, randbelow=fixed_random(100 + pid))
            for pid in key.result.participant_ids
        ]
        packets = [packet_for(c, receiver_id) for c in refresh_contributions]
        decoded = [
            decode_local_dkg_packet(encode_local_dkg_packet(packet))
            for packet in packets
        ]
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

    def test_decoded_packets_feed_reshare_local(self):
        key = aggregate_signing_dkg(make_contributions())
        self.assertIsInstance(key, SigningDKGResult)
        dealers = (2, 3)
        members = (2, 3, 4)
        reshare_contributions = [
            create_reshare(
                dealer,
                key.result.shares[
                    key.result.participant_ids.index(dealer)
                ].y,
                dealers,
                members,
                2,
                key,
                rng=fixed_random(100 + dealer),
            )
            for dealer in dealers
        ]
        receiver_id = 4
        packets = [packet_for(c, receiver_id) for c in reshare_contributions]
        decoded = [
            decode_local_dkg_packet(encode_local_dkg_packet(packet))
            for packet in packets
        ]
        old_context = export_signing_public_context(key)
        old_commitment = key.result.commitment
        direct = reshare_local(
            receiver_id, packets, dealers, old_context, old_commitment
        )
        through_codec = reshare_local(
            receiver_id, decoded, dealers, old_context, old_commitment
        )
        self.assertNotIsInstance(direct, list)
        self.assertEqual(through_codec, direct)


if __name__ == "__main__":
    unittest.main()
