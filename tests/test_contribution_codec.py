"""Tests for the canonical contribution transport encodings:
encode_dkg_contribution / decode_dkg_contribution and
encode_signing_contribution / decode_signing_contribution.

The signing format is shared verbatim by refresh and reshare contributions;
the aggregation-equivalence tests below cover all four public entry points.
"""

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
    SigningDKGResult,
    aggregate_dkg,
    aggregate_signing_dkg,
    create_dkg_contribution,
    create_refresh,
    create_reshare,
    create_signing_contribution,
    decode_dkg_contribution,
    decode_signing_contribution,
    encode_dkg_contribution,
    encode_signing_contribution,
    refresh,
    reshare,
)

# Same toy group as the DKG tests: 8069 = 4 * 2017 + 1 is prime, 16 and
# 256 = 16 ** 2 are distinct generators of the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

DKG_TAG = b"thresholdsign/dkg-contribution/v1"
SIGNING_TAG = b"thresholdsign/signing-contribution/v1"


def fixed_random(seed=1):
    """Deterministic stand-in for secrets.randbelow (same LCG as DKG tests)."""
    state = {"value": seed}

    def randbelow(upper: int) -> int:
        state["value"] = (
            state["value"] * 6364136223846793005 + 1442695040888963407
        ) % upper
        return state["value"]

    return randbelow


def make_dkg_contribution(sender_id, participant_ids=(1, 2, 3), threshold=2):
    return create_dkg_contribution(
        sender_id,
        participant_ids,
        threshold,
        prime=FIELD_PRIME,
        group_prime=GROUP_PRIME,
        generator=GENERATOR,
        blinding_generator=BLINDING_GENERATOR,
        randbelow=fixed_random(sender_id),
    )


def make_signing_contribution(sender_id, participant_ids=(1, 2, 3), threshold=2):
    return create_signing_contribution(
        sender_id,
        participant_ids,
        threshold,
        prime=FIELD_PRIME,
        group_prime=GROUP_PRIME,
        generator=GENERATOR,
        blinding_generator=BLINDING_GENERATOR,
        randbelow=fixed_random(sender_id),
    )


def make_key(participant_ids=(1, 2, 3), threshold=2):
    contributions = [
        make_signing_contribution(pid, participant_ids, threshold)
        for pid in participant_ids
    ]
    outcome = aggregate_signing_dkg(contributions)
    assert isinstance(outcome, SigningDKGResult), outcome
    return outcome


# --------------------------------------------------------------------------
# Independent wire builder straight from the format specification.
# --------------------------------------------------------------------------


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big", signed=False)


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return u32(len(body)) + body


def feldman_body(commitment: FeldmanCommitment) -> bytes:
    out = bytearray(u32(len(commitment.values)))
    for value in commitment.values:
        out += varint(value)
    out += varint(commitment.field_prime)
    out += varint(commitment.group_prime)
    out += varint(commitment.generator)
    return bytes(out)


def pedersen_body(commitment: PedersenCommitment) -> bytes:
    as_feldman = FeldmanCommitment(
        values=commitment.values,
        field_prime=commitment.field_prime,
        group_prime=commitment.group_prime,
        generator=commitment.generator,
    )
    return feldman_body(as_feldman) + varint(commitment.blinding_generator)


def dkg_body(contribution: DKGContribution) -> bytes:
    out = bytearray()
    out += varint(contribution.sender_id)
    out += u32(len(contribution.participant_ids))
    for participant_id in contribution.participant_ids:
        out += varint(participant_id)
    for shares in (contribution.shares, contribution.blinding_shares):
        out += u32(len(shares))
        for share in shares:
            out += varint(share.x)
            out += varint(share.y)
    out += pedersen_body(contribution.commitment)
    return bytes(out)


def build_dkg(contribution: DKGContribution, tag: bytes = DKG_TAG) -> bytes:
    return tag + dkg_body(contribution)


def build_signing(item: SigningContribution, tag: bytes = SIGNING_TAG) -> bytes:
    return tag + dkg_body(item.contribution) + feldman_body(item.feldman_commitment)


def build_raw_dkg(
    sender_id,
    participant_ids,
    shares,
    blinding_shares,
    commitment,
    *,
    tag=DKG_TAG,
    share_count=None,
    blinding_share_count=None,
    participant_count=None,
):
    """Assemble a plain contribution wire from raw pieces for malformed-input tests."""
    out = bytearray(tag)
    out += varint(sender_id)
    out += u32(len(participant_ids) if participant_count is None else participant_count)
    for participant_id in participant_ids:
        out += varint(participant_id)
    written_shares = shares[:share_count] if share_count is not None else shares
    out += u32(
        len(written_shares) if share_count is None else share_count
    )
    for x, y in written_shares:
        out += varint(x)
        out += varint(y)
    written_blinding = (
        blinding_shares[:blinding_share_count]
        if blinding_share_count is not None
        else blinding_shares
    )
    out += u32(
        len(written_blinding)
        if blinding_share_count is None
        else blinding_share_count
    )
    for x, y in written_blinding:
        out += varint(x)
        out += varint(y)
    out += commitment
    return bytes(out)


class RoundTripTest(unittest.TestCase):
    def test_dkg_round_trip_real_contribution(self):
        contribution = make_dkg_contribution(2)
        wire = encode_dkg_contribution(contribution)
        decoded = decode_dkg_contribution(wire)
        self.assertIsInstance(decoded, DKGContribution)
        self.assertEqual(decoded, contribution)
        self.assertEqual(encode_dkg_contribution(decoded), wire)

    def test_signing_round_trip_real_contribution(self):
        contribution = make_signing_contribution(3)
        wire = encode_signing_contribution(contribution)
        decoded = decode_signing_contribution(wire)
        self.assertIsInstance(decoded, SigningContribution)
        self.assertEqual(decoded, contribution)
        self.assertEqual(encode_signing_contribution(decoded), wire)

    def test_encodings_match_independent_builders(self):
        plain = make_dkg_contribution(1)
        self.assertEqual(encode_dkg_contribution(plain), build_dkg(plain))
        signing = make_signing_contribution(1)
        self.assertEqual(encode_signing_contribution(signing), build_signing(signing))

    def test_threshold_one_round_trips(self):
        plain = make_dkg_contribution(1, (1, 2), 1)
        self.assertEqual(decode_dkg_contribution(encode_dkg_contribution(plain)), plain)
        signing = make_signing_contribution(2, (1, 2), 1)
        self.assertEqual(
            decode_signing_contribution(encode_signing_contribution(signing)), signing
        )

    def test_share_value_zero_round_trips(self):
        # Zero is a legal (canonical) field value; replacing a share value
        # only breaks the cryptographic relation, which the codec ignores.
        plain = make_dkg_contribution(1)
        shares = tuple(
            dataclasses.replace(share, y=0) if index == 0 else share
            for index, share in enumerate(plain.shares)
        )
        altered = dataclasses.replace(plain, shares=shares)
        wire = encode_dkg_contribution(altered)
        decoded = decode_dkg_contribution(wire)
        self.assertEqual(decoded, altered)
        self.assertEqual(encode_dkg_contribution(decoded), wire)
        # The single body byte 00 follows the 4-byte length 01; it is the
        # first share's y frame, right after its x frame VARINT(1).
        offset = len(DKG_TAG) + 5 + 4 + 5 * 3 + 4
        self.assertEqual(wire[offset:offset + 10], b"\x00\x00\x00\x01\x01"
                         b"\x00\x00\x00\x01\x00")

    def test_encoding_is_unique_and_stateless(self):
        plain = make_dkg_contribution(1)
        self.assertEqual(encode_dkg_contribution(plain), encode_dkg_contribution(plain))
        signing = make_signing_contribution(1)
        self.assertEqual(
            encode_signing_contribution(signing), encode_signing_contribution(signing)
        )

    def test_wire_starts_with_tag_and_layout(self):
        plain = make_dkg_contribution(1)
        wire = encode_dkg_contribution(plain)
        self.assertTrue(wire.startswith(DKG_TAG))
        offset = len(DKG_TAG)
        # sender_id 1 -> U32(1) 01
        self.assertEqual(wire[offset:offset + 5], b"\x00\x00\x00\x01\x01")
        # then participant count 3
        self.assertEqual(wire[offset + 5:offset + 9], u32(3))

        signing = make_signing_contribution(1)
        swire = encode_signing_contribution(signing)
        self.assertTrue(swire.startswith(SIGNING_TAG))
        # The signing body embeds the plain body verbatim (no inner tag).
        self.assertEqual(
            swire[len(SIGNING_TAG):len(SIGNING_TAG) + len(dkg_body(plain))],
            dkg_body(signing.contribution),
        )


class AggregationEquivalenceTest(unittest.TestCase):
    def test_decoded_dkg_contributions_aggregate_identically(self):
        contributions = [make_dkg_contribution(pid) for pid in (1, 2, 3)]
        direct = aggregate_dkg(contributions)
        restored = [
            decode_dkg_contribution(encode_dkg_contribution(c)) for c in contributions
        ]
        via_wire = aggregate_dkg(restored)
        self.assertIsInstance(direct, DKGResult)
        self.assertEqual(via_wire, direct)

    def test_decoded_signing_contributions_aggregate_identically(self):
        contributions = [make_signing_contribution(pid) for pid in (1, 2, 3)]
        direct = aggregate_signing_dkg(contributions)
        restored = [
            decode_signing_contribution(encode_signing_contribution(c))
            for c in contributions
        ]
        via_wire = aggregate_signing_dkg(restored)
        self.assertIsInstance(direct, SigningDKGResult)
        self.assertEqual(via_wire, direct)

    def test_decoded_refresh_contributions_refresh_identically(self):
        key = make_key()
        contributions = [
            create_refresh(pid, key, randbelow=fixed_random(100 + pid))
            for pid in (1, 2, 3)
        ]
        direct = refresh(contributions, key)
        restored = [
            decode_signing_contribution(encode_signing_contribution(c))
            for c in contributions
        ]
        via_wire = refresh(restored, key)
        self.assertIsInstance(direct, SigningDKGResult)
        self.assertEqual(via_wire, direct)
        self.assertEqual(via_wire.public_key, key.public_key)

    def test_decoded_reshare_contributions_reshare_identically(self):
        key = make_key()
        dealers = (1, 2, 3)
        members = (1, 2, 3, 4)
        contributions = [
            create_reshare(
                dealer,
                key.result.shares[dealer - 1].y,
                dealers,
                members,
                3,
                key,
                rng=fixed_random(500 + dealer),
            )
            for dealer in dealers
        ]
        direct = reshare(contributions, dealers, key)
        restored = [
            decode_signing_contribution(encode_signing_contribution(c))
            for c in contributions
        ]
        via_wire = reshare(restored, dealers, key)
        self.assertIsInstance(direct, SigningDKGResult)
        self.assertEqual(via_wire, direct)
        self.assertEqual(via_wire.public_key, key.public_key)
        self.assertEqual(via_wire.result.participant_ids, members)


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.plain = make_dkg_contribution(1)
        self.signing = make_signing_contribution(1)

    def test_wrong_class_type_error(self):
        with self.assertRaises(TypeError):
            encode_dkg_contribution(self.signing)
        with self.assertRaises(TypeError):
            encode_dkg_contribution(("not", "a", "contribution"))
        with self.assertRaises(TypeError):
            encode_signing_contribution(self.plain)
        with self.assertRaises(TypeError):
            encode_signing_contribution(dkg_body)

    def test_plain_field_type_errors(self):
        plain = self.plain
        ped = plain.commitment
        for bad in (
            dataclasses.replace(plain, sender_id=True),
            dataclasses.replace(plain, sender_id="1"),
            dataclasses.replace(plain, participant_ids=list(plain.participant_ids)),
            dataclasses.replace(plain, participant_ids=(1, 2, True)),
            dataclasses.replace(plain, shares=list(plain.shares)),
            dataclasses.replace(
                plain, shares=tuple([object()] + list(plain.shares[1:]))
            ),
            dataclasses.replace(
                plain,
                shares=tuple(
                    [dataclasses.replace(plain.shares[0], x=True)]
                    + list(plain.shares[1:])
                ),
            ),
            dataclasses.replace(
                plain,
                blinding_shares=tuple(
                    [dataclasses.replace(plain.shares[0], y="0")]
                    + list(plain.blinding_shares[1:])
                ),
            ),
            dataclasses.replace(
                plain,
                commitment=dataclasses.replace(ped, values=list(ped.values)),
            ),
            dataclasses.replace(
                plain,
                commitment=dataclasses.replace(ped, values=(1, True)),
            ),
            dataclasses.replace(
                plain,
                commitment=FeldmanCommitment(
                    values=ped.values,
                    field_prime=ped.field_prime,
                    group_prime=ped.group_prime,
                    generator=ped.generator,
                ),
            ),
            dataclasses.replace(
                plain, commitment=dataclasses.replace(ped, field_prime=True)
            ),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_dkg_contribution(bad)

    def test_signing_field_type_errors(self):
        signing = self.signing
        for bad in (
            dataclasses.replace(signing, contribution=object()),
            dataclasses.replace(signing, contribution=signing),
            dataclasses.replace(signing, feldman_commitment=object()),
            dataclasses.replace(
                signing,
                feldman_commitment=signing.contribution.commitment,
            ),
            dataclasses.replace(
                signing,
                feldman_commitment=dataclasses.replace(
                    signing.feldman_commitment, values=list(
                        signing.feldman_commitment.values
                    )
                ),
            ),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_signing_contribution(bad)

    def test_plain_value_errors(self):
        plain = self.plain
        ids = plain.participant_ids
        shares = plain.shares
        blinding = plain.blinding_shares
        ped = plain.commitment
        for bad in (
            dataclasses.replace(plain, sender_id=0),
            dataclasses.replace(plain, sender_id=4),
            dataclasses.replace(plain, participant_ids=()),
            dataclasses.replace(plain, participant_ids=(1, 1, 3)),
            dataclasses.replace(plain, participant_ids=(2, 1, 3)),
            dataclasses.replace(plain, shares=shares[:2]),
            dataclasses.replace(plain, blinding_shares=blinding[:2]),
            dataclasses.replace(
                plain,
                shares=tuple(
                    [Share(x=2, y=shares[0].y)] + list(shares[1:])
                ),
            ),
            dataclasses.replace(
                plain,
                shares=tuple(
                    [Share(x=shares[0].x, y=FIELD_PRIME)] + list(shares[1:])
                ),
            ),
            dataclasses.replace(
                plain,
                commitment=dataclasses.replace(ped, values=()),
            ),
            dataclasses.replace(
                plain,
                commitment=dataclasses.replace(ped, values=ped.values + (1, 1)),
            ),
            dataclasses.replace(
                plain,
                commitment=dataclasses.replace(ped, generator=1),
            ),
            dataclasses.replace(
                plain,
                commitment=dataclasses.replace(
                    ped, blinding_generator=ped.generator
                ),
            ),
            dataclasses.replace(
                plain,
                commitment=dataclasses.replace(ped, field_prime=2011),
            ),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                encode_dkg_contribution(bad)

    def test_signing_value_errors(self):
        signing = self.signing
        feldman = signing.feldman_commitment
        for bad in (
            dataclasses.replace(
                signing, feldman_commitment=dataclasses.replace(feldman, values=(1,))
            ),
            dataclasses.replace(
                signing,
                feldman_commitment=dataclasses.replace(
                    feldman, values=feldman.values + (1,)
                ),
            ),
            dataclasses.replace(
                signing,
                feldman_commitment=dataclasses.replace(
                    feldman, field_prime=1009
                ),
            ),
            dataclasses.replace(
                signing,
                feldman_commitment=dataclasses.replace(
                    feldman, group_prime=GROUP_PRIME + 4
                ),
            ),
            dataclasses.replace(
                signing,
                feldman_commitment=dataclasses.replace(
                    feldman, generator=BLINDING_GENERATOR
                ),
            ),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                encode_signing_contribution(bad)


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.plain = make_dkg_contribution(1)
        self.wire = encode_dkg_contribution(self.plain)
        self.signing = make_signing_contribution(1)
        self.swire = encode_signing_contribution(self.signing)

    def test_non_bytes_type_error(self):
        for decode, wire in (
            (decode_dkg_contribution, self.wire),
            (decode_signing_contribution, self.swire),
        ):
            with self.assertRaises(TypeError):
                decode(wire.decode("ascii", "ignore"))
            with self.assertRaises(TypeError):
                decode(bytearray(wire))
            with self.assertRaises(TypeError):
                decode(None)

    def test_bad_tag(self):
        with self.assertRaises(ValueError):
            decode_dkg_contribution(b"")
        with self.assertRaises(ValueError):
            decode_dkg_contribution(
                b"thresholdsign/dkg-contribution/v2" + self.wire[len(DKG_TAG):]
            )
        with self.assertRaises(ValueError):
            decode_dkg_contribution(b"x" + self.wire[1:])
        with self.assertRaises(ValueError):
            decode_signing_contribution(
                b"thresholdsign/signing-contribution/v2"
                + self.swire[len(SIGNING_TAG):]
            )
        # Each tag is rejected by the other decoder.
        with self.assertRaises(ValueError):
            decode_dkg_contribution(self.swire)
        with self.assertRaises(ValueError):
            decode_signing_contribution(self.wire)

    def test_dkg_truncation_at_every_byte(self):
        for cut in range(len(DKG_TAG), len(self.wire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_dkg_contribution(self.wire[:cut])

    def test_signing_truncation_at_every_byte(self):
        for cut in range(len(SIGNING_TAG), len(self.swire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_signing_contribution(self.swire[:cut])

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_dkg_contribution(self.wire + b"\x00")
        with self.assertRaises(ValueError):
            decode_signing_contribution(self.swire + b"\x00")

    def test_non_canonical_integer(self):
        # sender_id frame with a two-byte body carrying a leading zero.
        body = self.wire[len(DKG_TAG):]
        bad = DKG_TAG + u32(2) + b"\x00\x01" + body[5:]
        with self.assertRaises(ValueError):
            decode_dkg_contribution(bad)
        sbody = self.swire[len(SIGNING_TAG):]
        bad = SIGNING_TAG + u32(2) + b"\x00\x01" + sbody[5:]
        with self.assertRaises(ValueError):
            decode_signing_contribution(bad)

    def test_integer_frame_length_mismatch(self):
        # Zero-length integer body.
        body = self.wire[len(DKG_TAG):]
        with self.assertRaises(ValueError):
            decode_dkg_contribution(DKG_TAG + u32(0) + body[4:])
        # Frame length running past the end.
        with self.assertRaises(ValueError):
            decode_dkg_contribution(DKG_TAG + u32(0xFFFFFFFF) + b"\x01")

    def test_participant_count_mismatch(self):
        plain = self.plain
        raw_ids = b"".join(varint(pid) for pid in plain.participant_ids)
        share_pairs = [(s.x, s.y) for s in plain.shares]
        blind_pairs = [(s.x, s.y) for s in plain.blinding_shares]
        prefix = build_raw_dkg(
            plain.sender_id,
            plain.participant_ids,
            share_pairs,
            blind_pairs,
            pedersen_body(plain.commitment),
            participant_count=0,
        )
        with self.assertRaises(ValueError):
            decode_dkg_contribution(prefix)
        # Declared count 2 while three id frames follow: the reader consumes
        # the third id as the first share count and necessarily derails.
        bad = build_raw_dkg(
            plain.sender_id,
            plain.participant_ids,
            share_pairs,
            blind_pairs,
            pedersen_body(plain.commitment),
            participant_count=2,
        )
        with self.assertRaises(ValueError):
            decode_dkg_contribution(bad)

    def test_share_count_mismatch(self):
        plain = self.plain
        share_pairs = [(s.x, s.y) for s in plain.shares]
        blind_pairs = [(s.x, s.y) for s in plain.blinding_shares]
        for declared in (0, 2, 4):
            bad = build_raw_dkg(
                plain.sender_id,
                plain.participant_ids,
                share_pairs,
                blind_pairs,
                pedersen_body(plain.commitment),
                share_count=declared,
            )
            with self.assertRaises(ValueError, msg=f"shares={declared}"):
                decode_dkg_contribution(bad)
        bad = build_raw_dkg(
            plain.sender_id,
            plain.participant_ids,
            share_pairs,
            blind_pairs,
            pedersen_body(plain.commitment),
            blinding_share_count=2,
        )
        with self.assertRaises(ValueError):
            decode_dkg_contribution(bad)

    def test_zero_unordered_or_duplicate_participant_ids(self):
        plain = self.plain
        share_pairs = [(s.x, s.y) for s in plain.shares]
        blind_pairs = [(s.x, s.y) for s in plain.blinding_shares]
        for ids in ((0, 2, 3), (3, 2, 1), (1, 1, 3)):
            bad = build_raw_dkg(
                plain.sender_id, ids, share_pairs, blind_pairs,
                pedersen_body(plain.commitment),
            )
            with self.assertRaises(ValueError, msg=f"ids={ids}"):
                decode_dkg_contribution(bad)

    def test_share_coordinate_mismatch(self):
        plain = self.plain
        share_pairs = [(s.x, s.y) for s in plain.shares]
        blind_pairs = [(s.x, s.y) for s in plain.blinding_shares]
        # The first share names a different x than the addressed participant.
        bad_pairs = [(2, share_pairs[0][1])] + share_pairs[1:]
        bad = build_raw_dkg(
            plain.sender_id, plain.participant_ids, bad_pairs, blind_pairs,
            pedersen_body(plain.commitment),
        )
        with self.assertRaises(ValueError):
            decode_dkg_contribution(bad)

    def test_sender_outside_member_set(self):
        plain = self.plain
        share_pairs = [(s.x, s.y) for s in plain.shares]
        blind_pairs = [(s.x, s.y) for s in plain.blinding_shares]
        bad = build_raw_dkg(
            4, plain.participant_ids, share_pairs, blind_pairs,
            pedersen_body(plain.commitment),
        )
        with self.assertRaises(ValueError):
            decode_dkg_contribution(bad)

    def test_illegal_commitment_rejected(self):
        plain = self.plain
        share_pairs = [(s.x, s.y) for s in plain.shares]
        blind_pairs = [(s.x, s.y) for s in plain.blinding_shares]
        ped = plain.commitment
        illegal_commitments = (
            dataclasses.replace(ped, generator=1),
            dataclasses.replace(ped, generator=GROUP_PRIME),
            dataclasses.replace(ped, blinding_generator=ped.generator),
            dataclasses.replace(ped, values=(2,) + ped.values[1:]),
            dataclasses.replace(ped, field_prime=1009),
            dataclasses.replace(ped, group_prime=8081),
        )
        for illegal in illegal_commitments:
            bad = build_raw_dkg(
                plain.sender_id, plain.participant_ids, share_pairs,
                blind_pairs, pedersen_body(illegal),
            )
            with self.assertRaises(ValueError, msg=repr(illegal)):
                decode_dkg_contribution(bad)
        # Empty commitment value count (truncated-style explicit frame).
        empty = (
            u32(0)
            + varint(ped.field_prime)
            + varint(ped.group_prime)
            + varint(ped.generator)
            + varint(ped.blinding_generator)
        )
        bad = build_raw_dkg(
            plain.sender_id, plain.participant_ids, share_pairs,
            blind_pairs, empty,
        )
        with self.assertRaises(ValueError):
            decode_dkg_contribution(bad)

    def test_signing_threshold_mismatch_rejected(self):
        signing = self.signing
        feldman = signing.feldman_commitment
        short = dataclasses.replace(feldman, values=feldman.values[:1])
        bad = SIGNING_TAG + dkg_body(signing.contribution) + feldman_body(short)
        with self.assertRaises(ValueError):
            decode_signing_contribution(bad)
        long = dataclasses.replace(feldman, values=feldman.values + (1,))
        # One extra trailing Feldman value is consumed as a bogus trailing
        # integer unless the parameter frames absorb it; either way the
        # structural threshold check or the trailing-bytes check rejects it.
        bad = SIGNING_TAG + dkg_body(signing.contribution) + feldman_body(long)
        with self.assertRaises(ValueError):
            decode_signing_contribution(bad)

    def test_signing_parameter_mismatch_rejected(self):
        signing = self.signing
        body = dkg_body(signing.contribution)
        for altered in (
            dataclasses.replace(signing.feldman_commitment, field_prime=1009),
            dataclasses.replace(
                signing.feldman_commitment, group_prime=GROUP_PRIME + 4
            ),
            dataclasses.replace(
                signing.feldman_commitment, generator=BLINDING_GENERATOR
            ),
        ):
            bad = SIGNING_TAG + body + feldman_body(altered)
            with self.assertRaises(ValueError, msg=repr(altered)):
                decode_signing_contribution(bad)


class CryptographicMismatchDecodedTest(unittest.TestCase):
    def test_tampered_dkg_share_decodes_and_is_rejected_by_aggregation(self):
        contributions = [make_dkg_contribution(pid) for pid in (1, 2, 3)]
        target = contributions[0]
        tampered = dataclasses.replace(
            target,
            shares=tuple(
                dataclasses.replace(share, y=(share.y + 1) % FIELD_PRIME)
                if index == 0
                else share
                for index, share in enumerate(target.shares)
            ),
        )
        decoded = decode_dkg_contribution(encode_dkg_contribution(tampered))
        self.assertEqual(decoded, tampered)
        outcome = aggregate_dkg([decoded] + contributions[1:])
        self.assertEqual(outcome, [DKGRejection(1)])

    def test_tampered_signing_share_decodes_and_is_rejected(self):
        contributions = [make_signing_contribution(pid) for pid in (1, 2, 3)]
        target = contributions[0]
        tampered_dealing = dataclasses.replace(
            target.contribution,
            shares=tuple(
                dataclasses.replace(share, y=(share.y + 1) % FIELD_PRIME)
                if index == 0
                else share
                for index, share in enumerate(target.contribution.shares)
            ),
        )
        tampered = SigningContribution(
            contribution=tampered_dealing,
            feldman_commitment=target.feldman_commitment,
        )
        decoded = decode_signing_contribution(encode_signing_contribution(tampered))
        self.assertEqual(decoded, tampered)
        outcome = aggregate_signing_dkg([decoded] + contributions[1:])
        self.assertEqual(outcome, [DKGRejection(1)])

    def test_non_one_refresh_constant_decodes_and_refresh_rejects_it(self):
        key = make_key()
        good = create_refresh(1, key, randbelow=fixed_random(101))
        # Replace the Feldman constant commitment with another non-identity
        # subgroup element (g itself): structurally legal, but not 1, so it
        # fails the zero-constant refresh check.
        values = good.feldman_commitment.values
        flipped = dataclasses.replace(
            good.feldman_commitment,
            values=(GENERATOR,) + values[1:],
        )
        tampered = SigningContribution(
            contribution=good.contribution, feldman_commitment=flipped
        )
        decoded = decode_signing_contribution(encode_signing_contribution(tampered))
        self.assertEqual(decoded, tampered)
        others = [create_refresh(pid, key, randbelow=fixed_random(200 + pid))
                  for pid in (2, 3)]
        outcome = refresh([decoded] + others, key)
        self.assertEqual(outcome, [DKGRejection(1)])

    def test_wrong_reshare_constant_decodes_and_reshare_rejects_it(self):
        key = make_key()
        dealers = (1, 2, 3)
        members = (1, 2, 3, 4)
        good = create_reshare(
            1, key.result.shares[0].y, dealers, members, 3, key,
            rng=fixed_random(501),
        )
        values = good.feldman_commitment.values
        # Another non-identity subgroup element (g): neither the expected
        # Y_i ** lambda_i constant nor a polynomial the shares evaluate on.
        flipped = dataclasses.replace(
            good.feldman_commitment,
            values=(GENERATOR,) + values[1:],
        )
        tampered = SigningContribution(
            contribution=good.contribution, feldman_commitment=flipped
        )
        decoded = decode_signing_contribution(encode_signing_contribution(tampered))
        self.assertEqual(decoded, tampered)
        others = [
            create_reshare(
                dealer,
                key.result.shares[dealer - 1].y,
                dealers,
                members,
                3,
                key,
                rng=fixed_random(600 + dealer),
            )
            for dealer in (2, 3)
        ]
        outcome = reshare([decoded] + others, dealers, key)
        self.assertEqual(outcome, [DKGRejection(1)])


if __name__ == "__main__":
    unittest.main()
