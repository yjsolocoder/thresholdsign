"""Tests for the canonical signing contribution transport encoding:
encode_signing_contribution / decode_signing_contribution, including its
reuse for refresh and reshare contributions."""

import dataclasses
import unittest

from thresholdsign import (
    DKGContribution,
    DKGRejection,
    FeldmanCommitment,
    Share,
    SigningContribution,
    SigningDKGResult,
    aggregate_signing_dkg,
    create_refresh,
    create_reshare,
    create_signing_contribution,
    decode_signing_contribution,
    encode_dkg_contribution,
    encode_signing_contribution,
    refresh,
    reshare,
)

# Same toy Pedersen group as the signing tests: 8069 = 4 * 2017 + 1 and
# 16, 256 = 16 ** 2 generate the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

WIRE_TAG = b"thresholdsign/signing-contribution/v1"
DKG_TAG = b"thresholdsign/dkg-contribution/v1"


def fixed_random(seed=1):
    state = {"value": seed}

    def randbelow(upper: int) -> int:
        state["value"] = (
            state["value"] * 6364136223846793005 + 1442695040888963407
        ) % upper
        return state["value"]

    return randbelow


def make_signing_contribution(
    sender_id,
    participant_ids=(1, 2, 3),
    threshold=2,
    field_prime=FIELD_PRIME,
    group_prime=GROUP_PRIME,
    generator=GENERATOR,
    blinding_generator=BLINDING_GENERATOR,
):
    return create_signing_contribution(
        sender_id,
        participant_ids,
        threshold,
        prime=field_prime,
        group_prime=group_prime,
        generator=generator,
        blinding_generator=blinding_generator,
        randbelow=fixed_random(sender_id),
    )


def make_signing_contributions(participant_ids=(1, 2, 3), threshold=2):
    return [
        make_signing_contribution(pid, participant_ids, threshold)
        for pid in participant_ids
    ]


def make_key(participant_ids=(1, 2, 3), threshold=2, seed_base=0):
    contributions = [
        create_signing_contribution(
            pid,
            participant_ids,
            threshold,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            blinding_generator=BLINDING_GENERATOR,
            randbelow=fixed_random(pid + seed_base),
        )
        for pid in participant_ids
    ]
    outcome = aggregate_signing_dkg(contributions)
    assert isinstance(outcome, SigningDKGResult), outcome
    return outcome


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def encode_feldman(commitment: FeldmanCommitment) -> bytes:
    out = bytearray(u32(len(commitment.values)))
    for value in commitment.values:
        out += varint(value)
    out += varint(commitment.field_prime)
    out += varint(commitment.group_prime)
    out += varint(commitment.generator)
    return bytes(out)


def build_wire(contribution: SigningContribution) -> bytes:
    nested = encode_dkg_contribution(contribution.contribution)
    return (
        WIRE_TAG
        + u32(len(nested))
        + nested
        + encode_feldman(contribution.feldman_commitment)
    )


class RoundTripTest(unittest.TestCase):
    def test_round_trip_real_contribution(self):
        contribution = make_signing_contribution(2)
        wire = encode_signing_contribution(contribution)
        decoded = decode_signing_contribution(wire)
        self.assertEqual(decoded, contribution)
        self.assertIsInstance(decoded, SigningContribution)
        self.assertIsInstance(decoded.contribution, DKGContribution)
        self.assertIsInstance(decoded.feldman_commitment, FeldmanCommitment)
        self.assertEqual(encode_signing_contribution(decoded), wire)

    def test_encoding_matches_independent_builder(self):
        for args in (
            (1, (1, 2, 3), 2),
            (5, (2, 5, 7), 2),
            (1, (1, 2), 1),
            (4, (1, 2, 3, 4, 5), 3),
        ):
            contribution = make_signing_contribution(*args)
            self.assertEqual(
                encode_signing_contribution(contribution),
                build_wire(contribution),
            )

    def test_layout_starts_with_tag_then_nested_frame(self):
        contribution = make_signing_contribution(1, (1, 2), 1)
        wire = encode_signing_contribution(contribution)
        self.assertTrue(wire.startswith(WIRE_TAG))
        offset = len(WIRE_TAG)
        nested = encode_dkg_contribution(contribution.contribution)
        self.assertEqual(wire[offset:offset + 4], u32(len(nested)))
        offset += 4
        self.assertEqual(wire[offset:offset + len(nested)], nested)
        self.assertTrue(nested.startswith(DKG_TAG))
        offset += len(nested)
        self.assertEqual(
            wire[offset:], encode_feldman(contribution.feldman_commitment)
        )

    def test_refresh_contributions_use_the_same_format(self):
        key = make_key()
        contribution = create_refresh(2, key, randbelow=fixed_random(102))
        wire = encode_signing_contribution(contribution)
        self.assertTrue(wire.startswith(WIRE_TAG))
        decoded = decode_signing_contribution(wire)
        self.assertEqual(decoded, contribution)
        self.assertEqual(encode_signing_contribution(decoded), wire)
        self.assertEqual(build_wire(contribution), wire)
        # The refresh constant-term commitment g**0 == 1 is just a value.
        self.assertEqual(contribution.feldman_commitment.values[0], 1)

    def test_reshare_contributions_use_the_same_format(self):
        key = make_key()
        dealers = (1, 2)
        members = (1, 2, 4, 5)
        sender = 2
        index = key.result.participant_ids.index(sender)
        contribution = create_reshare(
            sender,
            key.result.shares[index].y,
            dealers,
            members,
            3,
            key,
            rng=fixed_random(202),
        )
        wire = encode_signing_contribution(contribution)
        decoded = decode_signing_contribution(wire)
        self.assertEqual(decoded, contribution)
        self.assertEqual(encode_signing_contribution(decoded), wire)
        self.assertEqual(build_wire(contribution), wire)

    def test_encoding_is_unique_and_deterministic(self):
        contribution = make_signing_contribution(1)
        self.assertEqual(
            encode_signing_contribution(contribution),
            encode_signing_contribution(contribution),
        )


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.contribution = make_signing_contribution(2)
        self.wire = encode_signing_contribution(self.contribution)

    def test_non_bytes_raises_type_error(self):
        for bad in (None, 42, "bytes", bytearray(self.wire), [self.wire]):
            with self.assertRaises(TypeError):
                decode_signing_contribution(bad)  # type: ignore[arg-type]

    def test_bad_tag(self):
        bad = WIRE_TAG.replace(b"signing", b"singing") + self.wire[len(WIRE_TAG):]
        with self.assertRaises(ValueError):
            decode_signing_contribution(bad)

    def test_zero_or_oversized_nested_frame_length(self):
        offset = len(WIRE_TAG)
        with self.assertRaises(ValueError):
            decode_signing_contribution(self.wire[:offset] + u32(0))
        nested = encode_dkg_contribution(self.contribution.contribution)
        with self.assertRaises(ValueError):
            decode_signing_contribution(
                self.wire[:offset] + u32(len(nested) + 1) + nested
            )
        with self.assertRaises(ValueError):
            decode_signing_contribution(self.wire[:offset] + u32(1))

    def test_nested_frame_with_bad_tag(self):
        nested = encode_dkg_contribution(self.contribution.contribution)
        bad_nested = b"Z" + nested[1:]
        feldman = encode_feldman(self.contribution.feldman_commitment)
        bad = WIRE_TAG + u32(len(bad_nested)) + bad_nested + feldman
        with self.assertRaises(ValueError):
            decode_signing_contribution(bad)

    def test_truncation_at_every_offset(self):
        for length in range(len(WIRE_TAG), len(self.wire)):
            with self.assertRaises(ValueError):
                decode_signing_contribution(self.wire[:length])

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_signing_contribution(self.wire + b"\x00")

    def _wire_with_feldman(self, commitment: FeldmanCommitment) -> bytes:
        nested = encode_dkg_contribution(self.contribution.contribution)
        return WIRE_TAG + u32(len(nested)) + nested + encode_feldman(commitment)

    def test_feldman_parameter_mismatch_rejected(self):
        feldman = self.contribution.feldman_commitment
        variants = (
            dataclasses.replace(feldman, field_prime=2011),
            dataclasses.replace(feldman, group_prime=8081),
            dataclasses.replace(feldman, generator=BLINDING_GENERATOR),
        )
        for bad_commitment in variants:
            with self.assertRaises(ValueError):
                decode_signing_contribution(self._wire_with_feldman(bad_commitment))

    def test_feldman_threshold_mismatch_rejected(self):
        feldman = self.contribution.feldman_commitment
        fewer = dataclasses.replace(feldman, values=feldman.values[:1])
        with self.assertRaises(ValueError):
            decode_signing_contribution(self._wire_with_feldman(fewer))
        more_values = feldman.values + (1,)
        more = dataclasses.replace(feldman, values=more_values)
        with self.assertRaises(ValueError):
            decode_signing_contribution(self._wire_with_feldman(more))

    def test_illegal_feldman_commitment_rejected(self):
        feldman = self.contribution.feldman_commitment
        bad_value = dataclasses.replace(feldman, values=(0, feldman.values[1]))
        with self.assertRaises(ValueError):
            decode_signing_contribution(self._wire_with_feldman(bad_value))
        identity_generator = dataclasses.replace(feldman, generator=1)
        with self.assertRaises(ValueError):
            decode_signing_contribution(
                self._wire_with_feldman(identity_generator)
            )

    def test_nested_structure_errors_propagate(self):
        # Flip the nested participant count to zero by rebuilding the frame.
        nested = bytearray(
            encode_dkg_contribution(self.contribution.contribution)
        )
        nested_tag_end = len(DKG_TAG)
        # sender id is one single-byte varint (5 bytes) for sender 2
        nested[nested_tag_end + 5: nested_tag_end + 9] = u32(0)
        feldman = encode_feldman(self.contribution.feldman_commitment)
        bad = WIRE_TAG + u32(len(nested)) + bytes(nested) + feldman
        with self.assertRaises(ValueError):
            decode_signing_contribution(bad)


class EncodeValidationTest(unittest.TestCase):
    def test_non_contribution_raises_type_error(self):
        for bad in (
            None,
            42,
            "contribution",
            (1, 2),
            Share(1, 2),
            make_signing_contribution(1).contribution,
        ):
            with self.assertRaises(TypeError):
                encode_signing_contribution(bad)  # type: ignore[arg-type]

    def test_bad_field_types_raise_type_error(self):
        contribution = make_signing_contribution(1)
        variants = (
            SigningContribution(
                contribution.contribution,
                dataclasses.replace(
                    contribution.feldman_commitment, field_prime="2017"
                ),
            ),
            SigningContribution("nested", contribution.feldman_commitment),
        )
        for bad in variants:
            with self.assertRaises(TypeError):
                encode_signing_contribution(bad)

    def test_inconsistent_commitments_raise_value_error(self):
        contribution = make_signing_contribution(1)
        feldman = contribution.feldman_commitment
        variants = (
            SigningContribution(
                contribution.contribution,
                dataclasses.replace(feldman, field_prime=2011),
            ),
            SigningContribution(
                contribution.contribution,
                dataclasses.replace(feldman, values=feldman.values[:1]),
            ),
            SigningContribution(
                contribution.contribution,
                dataclasses.replace(feldman, generator=BLINDING_GENERATOR),
            ),
        )
        for bad in variants:
            with self.assertRaises(ValueError):
                encode_signing_contribution(bad)


class AggregationEquivalenceTest(unittest.TestCase):
    def test_decoded_contributions_aggregate_identically(self):
        contributions = make_signing_contributions()
        decoded = [
            decode_signing_contribution(encode_signing_contribution(contribution))
            for contribution in contributions
        ]
        original = aggregate_signing_dkg(contributions)
        round_trip = aggregate_signing_dkg(decoded)
        self.assertIsInstance(original, SigningDKGResult)
        self.assertEqual(round_trip, original)

    def test_input_order_independence_preserved(self):
        contributions = make_signing_contributions()
        decoded = [
            decode_signing_contribution(encode_signing_contribution(contribution))
            for contribution in contributions
        ]
        self.assertEqual(
            aggregate_signing_dkg(decoded),
            aggregate_signing_dkg(list(reversed(decoded))),
        )

    def test_pedersen_failure_still_rejected_through_codec(self):
        contributions = make_signing_contributions()
        bad = dataclasses.replace(
            contributions[1],
            contribution=dataclasses.replace(
                contributions[1].contribution,
                shares=(
                    Share(
                        1,
                        (contributions[1].contribution.shares[0].y + 1)
                        % FIELD_PRIME,
                    ),
                )
                + contributions[1].contribution.shares[1:],
            ),
        )
        direct = aggregate_signing_dkg(
            [contributions[0], bad, contributions[2]]
        )
        round_trip_bad = decode_signing_contribution(
            encode_signing_contribution(bad)
        )
        through_codec = aggregate_signing_dkg(
            [contributions[0], round_trip_bad, contributions[2]]
        )
        self.assertEqual(direct, [DKGRejection(sender_id=2)])
        self.assertEqual(through_codec, direct)

    def test_unbound_feldman_decodes_but_aggregation_still_raises(self):
        contribution = make_signing_contribution(1)
        # Other legal subgroup elements, same parameters and count:
        # structurally fine, but they commit to a different polynomial.
        other_values = tuple(pow(GENERATOR, j + 1, GROUP_PRIME) for j in range(2))
        unbound = SigningContribution(
            contribution.contribution,
            dataclasses.replace(contribution.feldman_commitment, values=other_values),
        )
        wire = encode_signing_contribution(unbound)
        decoded = decode_signing_contribution(wire)
        self.assertEqual(decoded, unbound)
        others = make_signing_contributions()[1:]
        with self.assertRaises(ValueError):
            aggregate_signing_dkg([unbound] + others)
        with self.assertRaises(ValueError):
            aggregate_signing_dkg([decoded] + others)


class RefreshReshareEquivalenceTest(unittest.TestCase):
    def test_refresh_round_trip_contributions_act_identically(self):
        key = make_key()
        contributions = [
            create_refresh(pid, key, randbelow=fixed_random(pid + 100))
            for pid in (1, 2, 3)
        ]
        decoded = [
            decode_signing_contribution(encode_signing_contribution(contribution))
            for contribution in contributions
        ]
        direct = refresh(contributions, key)
        through_codec = refresh(decoded, key)
        self.assertIsInstance(direct, SigningDKGResult)
        self.assertEqual(through_codec, direct)
        self.assertEqual(direct.public_key, key.public_key)

    def test_refresh_rejection_is_preserved(self):
        key = make_key()
        good = create_refresh(1, key, randbelow=fixed_random(101))
        bad_sender = dataclasses.replace(
            good,
            contribution=dataclasses.replace(
                good.contribution,
                shares=(
                    Share(1, (good.contribution.shares[0].y + 1) % FIELD_PRIME),
                )
                + good.contribution.shares[1:],
            ),
        )
        rest = [
            create_refresh(pid, key, randbelow=fixed_random(pid + 100))
            for pid in (2, 3)
        ]
        direct = refresh([bad_sender] + rest, key)
        round_trip = refresh(
            [
                decode_signing_contribution(encode_signing_contribution(bad_sender))
            ]
            + rest,
            key,
        )
        self.assertEqual(direct, [DKGRejection(sender_id=1)])
        self.assertEqual(round_trip, direct)

    def test_reshare_round_trip_contributions_act_identically(self):
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
        decoded = [
            decode_signing_contribution(encode_signing_contribution(contribution))
            for contribution in contributions
        ]
        direct = reshare(contributions, dealers, key)
        through_codec = reshare(decoded, dealers, key)
        self.assertIsInstance(direct, SigningDKGResult)
        self.assertEqual(through_codec, direct)
        self.assertEqual(direct.public_key, key.public_key)
        self.assertEqual(direct.result.participant_ids, members)

    def test_reshare_rejection_is_preserved(self):
        key = make_key()
        dealers = (1, 2)
        members = (1, 2, 4, 5)
        good = create_reshare(
            1,
            key.result.shares[0].y,
            dealers,
            members,
            3,
            key,
            rng=fixed_random(201),
        )
        bad = dataclasses.replace(
            good,
            contribution=dataclasses.replace(
                good.contribution,
                shares=(
                    Share(1, (good.contribution.shares[0].y + 1) % FIELD_PRIME),
                )
                + good.contribution.shares[1:],
            ),
        )
        other = create_reshare(
            2,
            key.result.shares[1].y,
            dealers,
            members,
            3,
            key,
            rng=fixed_random(202),
        )
        direct = reshare([bad, other], dealers, key)
        round_trip = reshare(
            [
                decode_signing_contribution(encode_signing_contribution(bad)),
                other,
            ],
            dealers,
            key,
        )
        self.assertEqual(direct, [DKGRejection(sender_id=1)])
        self.assertEqual(round_trip, direct)


if __name__ == "__main__":
    unittest.main()
