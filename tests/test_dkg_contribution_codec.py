"""Tests for the canonical DKG contribution transport encoding:
encode_dkg_contribution / decode_dkg_contribution."""

import dataclasses
import unittest

from thresholdsign import (
    DKGContribution,
    DKGRejection,
    DKGResult,
    FeldmanCommitment,
    PedersenCommitment,
    Share,
    SigningContribution,
    aggregate_dkg,
    create_dkg_contribution,
    decode_dkg_contribution,
    encode_dkg_contribution,
)

# Same toy Pedersen setup as test_dkg: 8069 = 4 * 2017 + 1 is prime and
# 16, 256 = 16 ** 2 are distinct generators of the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

WIRE_TAG = b"thresholdsign/dkg-contribution/v1"


def fixed_random(seed=1):
    state = {"value": seed}

    def randbelow(upper: int) -> int:
        state["value"] = (
            state["value"] * 6364136223846793005 + 1442695040888963407
        ) % upper
        return state["value"]

    return randbelow


def make_contribution(
    sender_id,
    participant_ids=(1, 2, 3),
    threshold=2,
    field_prime=FIELD_PRIME,
    group_prime=GROUP_PRIME,
    generator=GENERATOR,
    blinding_generator=BLINDING_GENERATOR,
    **kwargs,
):
    options = {
        "prime": field_prime,
        "group_prime": group_prime,
        "generator": generator,
        "blinding_generator": blinding_generator,
        "randbelow": fixed_random(sender_id),
    }
    options.update(kwargs)
    return create_dkg_contribution(
        sender_id, participant_ids, threshold, **options
    )


def make_contributions(participant_ids=(1, 2, 3), threshold=2):
    return [
        make_contribution(pid, participant_ids, threshold)
        for pid in participant_ids
    ]


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def encode_commitment(commitment: PedersenCommitment) -> bytes:
    """Independently encode a Pedersen commitment straight from the spec."""
    out = bytearray(u32(len(commitment.values)))
    for value in commitment.values:
        out += varint(value)
    out += varint(commitment.field_prime)
    out += varint(commitment.group_prime)
    out += varint(commitment.generator)
    out += varint(commitment.blinding_generator)
    return bytes(out)


def build_wire(contribution: DKGContribution) -> bytes:
    """Independently build the DKG contribution wire format from the spec."""
    out = bytearray(WIRE_TAG)
    out += varint(contribution.sender_id)
    ids = contribution.participant_ids
    out += u32(len(ids))
    for participant_id in ids:
        out += varint(participant_id)
    for shares in (contribution.shares, contribution.blinding_shares):
        out += u32(len(shares))
        for share in shares:
            out += varint(share.x)
            out += varint(share.y)
    out += encode_commitment(contribution.commitment)
    return bytes(out)


class RoundTripTest(unittest.TestCase):
    def test_round_trip_real_contribution(self):
        contribution = make_contribution(2)
        wire = encode_dkg_contribution(contribution)
        decoded = decode_dkg_contribution(wire)
        self.assertEqual(decoded, contribution)
        self.assertIsInstance(decoded, DKGContribution)
        self.assertEqual(encode_dkg_contribution(decoded), wire)

    def test_encoding_matches_independent_builder(self):
        for args in (
            (1, (1, 2, 3), 2),
            (5, (2, 5, 7), 2),
            (1, (1, 2), 1),
            (4, (1, 2, 3, 4, 5), 3),
        ):
            contribution = make_contribution(*args)
            self.assertEqual(
                encode_dkg_contribution(contribution), build_wire(contribution)
            )

    def test_zero_share_values_round_trip(self):
        contribution = make_contribution(1, randbelow=lambda upper: 0)
        wire = encode_dkg_contribution(contribution)
        decoded = decode_dkg_contribution(wire)
        self.assertEqual(decoded, contribution)
        self.assertEqual(encode_dkg_contribution(decoded), wire)

    def test_encoding_is_unique_and_deterministic(self):
        contribution = make_contribution(1)
        self.assertEqual(
            encode_dkg_contribution(contribution),
            encode_dkg_contribution(contribution),
        )

    def test_starts_with_tag_and_layout(self):
        contribution = make_contribution(2, (1, 2, 3), 1)
        wire = encode_dkg_contribution(contribution)
        self.assertTrue(wire.startswith(WIRE_TAG))
        offset = len(WIRE_TAG)
        # sender id 2: length 1, body 02
        self.assertEqual(wire[offset:offset + 5], u32(1) + b"\x02")
        offset += 5
        # participant count 3
        self.assertEqual(wire[offset:offset + 4], u32(3))
        offset += 4
        # ids 1, 2, 3 as single-byte varints
        for expected in (1, 2, 3):
            self.assertEqual(wire[offset:offset + 5], u32(1) + bytes([expected]))
            offset += 5
        # share count 3, then one share (x, y) each
        self.assertEqual(wire[offset:offset + 4], u32(3))
        offset += 4
        for share in contribution.shares:
            frame = varint(share.x) + varint(share.y)
            self.assertEqual(wire[offset:offset + len(frame)], frame)
            offset += len(frame)
        # blinding share count 3
        self.assertEqual(wire[offset:offset + 4], u32(3))
        offset += 4
        for share in contribution.blinding_shares:
            offset += len(varint(share.x) + varint(share.y))
        # remainder is exactly the commitment encoding
        self.assertEqual(
            wire[offset:], encode_commitment(contribution.commitment)
        )

    def test_multi_byte_integer_encoding_is_canonical(self):
        # Larger toy group (same one the refresh tests use): share values,
        # primes and generators are all genuinely multi-byte.
        big_field = 1000151
        big_group = 2000303
        big_g = 9
        big_h = 81
        contribution = create_dkg_contribution(
            3,
            (1, 2, 3),
            2,
            prime=big_field,
            group_prime=big_group,
            generator=big_g,
            blinding_generator=big_h,
            randbelow=fixed_random(3),
        )
        wire = encode_dkg_contribution(contribution)
        decoded = decode_dkg_contribution(wire)
        self.assertEqual(decoded, contribution)
        self.assertEqual(encode_dkg_contribution(decoded), wire)
        self.assertEqual(wire, build_wire(contribution))
        # At least one commitment value spans more than one body byte.
        wide = [v for v in contribution.commitment.values if v > 255]
        self.assertTrue(wide)
        value = wide[0]
        body = value.to_bytes((value.bit_length() + 7) // 8, "big")
        self.assertIn(u32(len(body)) + body, wire)


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.contribution = make_contribution(2)
        self.wire = encode_dkg_contribution(self.contribution)

    def test_non_bytes_raises_type_error(self):
        for bad in (None, 42, "bytes", bytearray(self.wire), [self.wire]):
            with self.assertRaises(TypeError):
                decode_dkg_contribution(bad)  # type: ignore[arg-type]

    def test_bad_tag(self):
        bad = b"thresholdsign/other-contribution/v1" + self.wire[
            len(WIRE_TAG):
        ]
        with self.assertRaises(ValueError):
            decode_dkg_contribution(bad)
        with self.assertRaises(ValueError):
            decode_dkg_contribution(b"")

    def test_truncation_at_every_offset(self):
        for length in range(0, len(self.wire)):
            with self.assertRaises(ValueError):
                decode_dkg_contribution(self.wire[:length])

    def test_trailing_bytes(self):
        for suffix in (b"\x00", b"\x01\x02", b"trailing"):
            with self.assertRaises(ValueError):
                decode_dkg_contribution(self.wire + suffix)

    def test_zero_participant_count(self):
        bad = WIRE_TAG + varint(2) + u32(0)
        with self.assertRaises(ValueError):
            decode_dkg_contribution(bad)

    def test_zero_share_counts(self):
        ids = u32(3) + b"".join(varint(i) for i in (1, 2, 3))
        bad = WIRE_TAG + varint(2) + ids + u32(0)
        with self.assertRaises(ValueError):
            decode_dkg_contribution(bad)

    def test_share_count_mismatch(self):
        contribution = self.contribution
        ids = u32(3) + b"".join(varint(i) for i in (1, 2, 3))
        only_two = b"".join(
            varint(share.x) + varint(share.y)
            for share in contribution.shares[:2]
        )
        bad = WIRE_TAG + varint(2) + ids + u32(2) + only_two
        with self.assertRaises(ValueError):
            decode_dkg_contribution(bad)

    def test_blinding_share_count_mismatch(self):
        contribution = self.contribution
        ids = u32(3) + b"".join(varint(i) for i in (1, 2, 3))
        shares = u32(3) + b"".join(
            varint(share.x) + varint(share.y) for share in contribution.shares
        )
        bad = WIRE_TAG + varint(2) + ids + shares + u32(2)
        with self.assertRaises(ValueError):
            decode_dkg_contribution(bad)

    def test_zero_or_unsorted_or_duplicate_participant_ids(self):
        prefix = WIRE_TAG + varint(1)
        for encoded_ids in (
            u32(1) + varint(0),
            u32(2) + varint(2) + varint(1),
            u32(2) + varint(2) + varint(2),
        ):
            with self.assertRaises(ValueError):
                decode_dkg_contribution(prefix + encoded_ids)

    def test_sender_outside_participant_set(self):
        contribution = self.contribution
        ids = u32(1) + varint(1)
        shares = u32(1) + varint(1) + varint(contribution.shares[0].y)
        blinding = (
            u32(1) + varint(1) + varint(contribution.blinding_shares[0].y)
        )
        commitment = encode_commitment(contribution.commitment)
        bad = WIRE_TAG + varint(2) + ids + shares + blinding + commitment
        with self.assertRaises(ValueError):
            decode_dkg_contribution(bad)
        bad_zero = WIRE_TAG + varint(0) + ids + shares + blinding + commitment
        with self.assertRaises(ValueError):
            decode_dkg_contribution(bad_zero)

    def test_non_canonical_integer_frames(self):
        # zero-length body
        with self.assertRaises(ValueError):
            decode_dkg_contribution(WIRE_TAG + u32(0))
        # leading zero inside a multi-byte body
        with self.assertRaises(ValueError):
            decode_dkg_contribution(WIRE_TAG + u32(2) + b"\x00\x02")
        with self.assertRaises(ValueError):
            decode_dkg_contribution(WIRE_TAG + u32(2) + b"\x00\x00")
        # declared body longer than the stream
        with self.assertRaises(ValueError):
            decode_dkg_contribution(WIRE_TAG + u32(9) + b"\x02")

    def test_illegal_commitment_rejected(self):
        contribution = self.contribution
        prefix = self.wire[: -len(encode_commitment(contribution.commitment))]

        def wire_with_commitment(commitment: PedersenCommitment) -> bytes:
            return prefix + encode_commitment(commitment)

        illegal_values = dataclasses.replace(contribution.commitment, values=(0, 1))
        with self.assertRaises(ValueError):
            decode_dkg_contribution(wire_with_commitment(illegal_values))
        empty_values = dataclasses.replace(
            contribution.commitment, values=()
        )
        with self.assertRaises(ValueError):
            decode_dkg_contribution(
                wire_with_commitment(empty_values)
            )
        same_generators = dataclasses.replace(
            contribution.commitment, blinding_generator=GENERATOR
        )
        with self.assertRaises(ValueError):
            decode_dkg_contribution(wire_with_commitment(same_generators))
        non_prime = dataclasses.replace(contribution.commitment, field_prime=2021)
        with self.assertRaises(ValueError):
            decode_dkg_contribution(wire_with_commitment(non_prime))

    def test_threshold_above_participant_count_rejected(self):
        contribution = self.contribution
        prefix = self.wire[: -len(encode_commitment(contribution.commitment))]
        four_values = (1, 1, 1, 1)
        commitment = dataclasses.replace(
            contribution.commitment, values=four_values
        )
        with self.assertRaises(ValueError):
            decode_dkg_contribution(prefix + encode_commitment(commitment))

    def test_share_coordinates_outside_field_rejected(self):
        contribution = self.contribution
        bad_share = dataclasses.replace(
            contribution.shares[0], x=0
        )
        bad = dataclasses.replace(
            contribution, shares=(bad_share,) + contribution.shares[1:]
        )
        with self.assertRaises(ValueError):
            decode_dkg_contribution(encode_dkg_contribution(bad))

    def test_share_values_outside_field_rejected(self):
        contribution = self.contribution
        bad_share = dataclasses.replace(
            contribution.blinding_shares[0], y=FIELD_PRIME
        )
        bad = dataclasses.replace(
            contribution,
            blinding_shares=(bad_share,) + contribution.blinding_shares[1:],
        )
        with self.assertRaises(ValueError):
            encode_dkg_contribution(bad)


class EncodeValidationTest(unittest.TestCase):
    def test_non_contribution_raises_type_error(self):
        for bad in (
            None,
            42,
            "contribution",
            (1, 2),
            Share(1, 2),
            SigningContribution(
                make_contribution(1),
                FeldmanCommitment((1,), FIELD_PRIME, GROUP_PRIME, GENERATOR),
            ),
        ):
            with self.assertRaises(TypeError):
                encode_dkg_contribution(bad)  # type: ignore[arg-type]

    def test_bad_field_types_raise_type_error(self):
        contribution = make_contribution(1)
        variants = (
            dataclasses.replace(contribution, sender_id="1"),
            dataclasses.replace(contribution, participant_ids=[1, 2, 3]),
            dataclasses.replace(
                contribution, shares=list(contribution.shares)
            ),
            dataclasses.replace(
                contribution,
                commitment=dataclasses.replace(
                    contribution.commitment, field_prime="2017"
                ),
            ),
        )
        for bad in variants:
            with self.assertRaises(TypeError):
                encode_dkg_contribution(bad)

    def test_illegal_structure_raises_value_error(self):
        contribution = make_contribution(1)
        variants = (
            dataclasses.replace(contribution, participant_ids=()),
            dataclasses.replace(
                contribution, participant_ids=(2, 1, 3)
            ),
            dataclasses.replace(contribution, sender_id=4),
            dataclasses.replace(
                contribution,
                shares=contribution.shares[:2],
            ),
            dataclasses.replace(
                contribution,
                commitment=dataclasses.replace(
                    contribution.commitment, values=(0, 1)
                ),
            ),
        )
        for bad in variants:
            with self.assertRaises(ValueError):
                encode_dkg_contribution(bad)


class AggregationEquivalenceTest(unittest.TestCase):
    def test_decoded_contributions_aggregate_identically(self):
        contributions = make_contributions()
        decoded = [
            decode_dkg_contribution(encode_dkg_contribution(contribution))
            for contribution in contributions
        ]
        original = aggregate_dkg(contributions)
        round_trip = aggregate_dkg(decoded)
        self.assertIsInstance(original, DKGResult)
        self.assertEqual(round_trip, original)

    def test_input_order_independence_preserved(self):
        contributions = make_contributions()
        decoded = [
            decode_dkg_contribution(encode_dkg_contribution(contribution))
            for contribution in contributions
        ]
        self.assertEqual(
            aggregate_dkg(decoded), aggregate_dkg(list(reversed(decoded)))
        )

    def test_cryptographic_rejection_is_preserved(self):
        contributions = make_contributions()
        bad = dataclasses.replace(
            contributions[1],
            shares=(
                Share(
                    contributions[1].shares[0].x,
                    (contributions[1].shares[0].y + 1) % FIELD_PRIME,
                ),
            )
            + contributions[1].shares[1:],
        )
        direct = aggregate_dkg([contributions[0], bad, contributions[2]])
        round_trip_bad = decode_dkg_contribution(encode_dkg_contribution(bad))
        through_codec = aggregate_dkg(
            [contributions[0], round_trip_bad, contributions[2]]
        )
        self.assertEqual(direct, [DKGRejection(sender_id=2)])
        self.assertEqual(through_codec, direct)

    def test_misaddressed_share_round_trips_and_still_rejected(self):
        contribution = make_contribution(1)
        misaddressed = dataclasses.replace(
            contribution,
            shares=(Share(2, contribution.shares[0].y),)
            + contribution.shares[1:],
        )
        wire = encode_dkg_contribution(misaddressed)
        decoded = decode_dkg_contribution(wire)
        self.assertEqual(decoded, misaddressed)
        others = make_contributions()[1:]
        outcome = aggregate_dkg([decoded] + others)
        self.assertEqual(outcome, [DKGRejection(sender_id=1)])


if __name__ == "__main__":
    unittest.main()
