"""Tests for the standalone SigningPublicContext codec."""

import dataclasses
import unittest

from thresholdsign import (
    ROUND_PACKET_TAG,
    SIGNING_PUBLIC_CONTEXT_TAG,
    AggregateSignature,
    DKGReceivedShare,
    LocalDKGPacket,
    SigningDKGResult,
    SigningPublicContext,
    SigningRoundPacket,
    aggregate_local_dkg,
    aggregate_signature,
    aggregate_signing_dkg,
    create_refresh,
    create_reshare,
    create_signing_round,
    decode_signing_public_context,
    encode_round_packet,
    encode_signing_public_context,
    export_signing_public_context,
    refresh,
    refresh_local,
    reshare,
    reshare_local,
    verify_round_packet,
    verify_signature,
    verify_signature_share,
    verify_signing_public_context,
)
from tests.test_signing import (
    BLINDING_GENERATOR,
    FIELD_PRIME,
    GENERATOR,
    GROUP_PRIME,
    LARGE_FIELD,
    LARGE_G,
    LARGE_GROUP,
    LARGE_H,
    MESSAGE,
    fixed_random,
    make_round,
    make_shares,
    make_signing_contributions,
    make_signing_dkg,
)


def varint(value):
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def expected_encoding(context):
    """The canonical encoding rebuilt by hand from the public fields."""
    blob = bytearray(SIGNING_PUBLIC_CONTEXT_TAG)
    blob += len(context.participant_ids).to_bytes(4, "big")
    for participant_id in context.participant_ids:
        blob += varint(participant_id)
    for value in (
        context.threshold,
        context.field_prime,
        context.group_prime,
        context.generator,
        context.public_key,
    ):
        blob += varint(value)
    blob += len(context.verification_shares).to_bytes(4, "big")
    for share in context.verification_shares:
        blob += varint(share)
    return bytes(blob)


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


def packets_for(contributions, receiver_id):
    return [packet_for(contribution, receiver_id) for contribution in contributions]


def make_refreshed(key, seed_base=100):
    contributions = [
        create_refresh(pid, key, randbelow=fixed_random(pid + seed_base))
        for pid in key.result.participant_ids
    ]
    refreshed = refresh(contributions, key)
    assert isinstance(refreshed, SigningDKGResult)
    return contributions, refreshed


def make_reshared(key, dealers=(2, 3), members=(2, 3, 4), threshold=2, seed_base=100):
    contributions = [
        create_reshare(
            dealer,
            secret_share_of(key, dealer),
            dealers,
            members,
            threshold,
            key,
            rng=fixed_random(dealer + seed_base),
        )
        for dealer in dealers
    ]
    reshared = reshare(contributions, dealers, key)
    assert isinstance(reshared, SigningDKGResult)
    return contributions, reshared


class PublicContextCodecTest(unittest.TestCase):
    def setUp(self):
        self.dkg = make_signing_dkg()
        self.context = export_signing_public_context(self.dkg)

    def test_round_trip_is_byte_exact(self):
        blob = encode_signing_public_context(self.context)
        self.assertIsInstance(blob, bytes)
        decoded = decode_signing_public_context(blob)
        self.assertEqual(decoded, self.context)
        self.assertIsInstance(decoded, SigningPublicContext)
        self.assertEqual(encode_signing_public_context(decoded), blob)
        self.assertEqual(encode_signing_public_context(self.context), blob)

    def test_starts_with_tag(self):
        blob = encode_signing_public_context(self.context)
        self.assertTrue(blob.startswith(b"thresholdsign/signing-public-context/v1"))
        self.assertTrue(blob.startswith(SIGNING_PUBLIC_CONTEXT_TAG))

    def test_encoding_is_deterministic(self):
        self.assertEqual(
            encode_signing_public_context(self.context),
            encode_signing_public_context(self.context),
        )

    def test_encoding_matches_manual_layout(self):
        self.assertEqual(
            encode_signing_public_context(self.context), expected_encoding(self.context)
        )

    def test_encoding_is_the_round_packet_context_section(self):
        # The bytes after the tag are exactly the context section of the
        # public round packet format: a round packet built on the same
        # context starts with the same section and only appends the round.
        _round_info, commitments, _nonces = make_round(self.dkg)
        packet = SigningRoundPacket(context=self.context, round_info=_round_info)
        packet_blob = encode_round_packet(packet)
        context_blob = encode_signing_public_context(self.context)
        self.assertEqual(
            packet_blob[: len(ROUND_PACKET_TAG) + len(context_blob) - len(SIGNING_PUBLIC_CONTEXT_TAG)],
            ROUND_PACKET_TAG + context_blob[len(SIGNING_PUBLIC_CONTEXT_TAG):],
        )
        self.assertGreater(len(packet_blob), len(context_blob))

    def test_round_trip_large_group(self):
        dkg = make_signing_dkg(
            (1, 2, 3), 2,
            field_prime=LARGE_FIELD, group_prime=LARGE_GROUP,
            generator=LARGE_G, blinding_generator=LARGE_H,
        )
        context = export_signing_public_context(dkg)
        blob = encode_signing_public_context(context)
        self.assertEqual(decode_signing_public_context(blob), context)
        self.assertEqual(encode_signing_public_context(decode_signing_public_context(blob)), blob)

    def test_round_trip_single_member_and_threshold_one(self):
        dkg = make_signing_dkg((1,), 1)
        context = export_signing_public_context(dkg)
        self.assertEqual(context.participant_ids, (1,))
        self.assertEqual(context.threshold, 1)
        blob = encode_signing_public_context(context)
        self.assertEqual(decode_signing_public_context(blob), context)
        self.assertEqual(encode_signing_public_context(decode_signing_public_context(blob)), blob)

        dkg3 = make_signing_dkg((1, 2, 3), 1)
        context3 = export_signing_public_context(dkg3)
        self.assertEqual(
            decode_signing_public_context(encode_signing_public_context(context3)), context3
        )

    def test_round_trip_identity_public_key_and_shares(self):
        # The group identity stays a legal public key / verification share.
        context = SigningPublicContext(
            participant_ids=(1, 2),
            threshold=1,
            field_prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            public_key=1,
            verification_shares=(1, 1),
        )
        blob = encode_signing_public_context(context)
        self.assertEqual(decode_signing_public_context(blob), context)
        self.assertEqual(encode_signing_public_context(decode_signing_public_context(blob)), blob)
        self.assertTrue(verify_signing_public_context(decode_signing_public_context(blob)))

    def test_same_encoding_from_every_source(self):
        # Full DKG export, receiver-local aggregation, receiver-local
        # refresh and resharing, full refresh/reshare export and a directly
        # constructed equal object all encode to the same bytes.
        contributions = make_signing_contributions()
        dkg = aggregate_signing_dkg(contributions)
        self.assertIsInstance(dkg, SigningDKGResult)
        from_dkg = export_signing_public_context(dkg)

        _share, _blinding, from_local = aggregate_local_dkg(
            2, packets_for(contributions, 2)
        )
        self.assertEqual(from_local, from_dkg)

        direct = SigningPublicContext(
            participant_ids=from_dkg.participant_ids,
            threshold=from_dkg.threshold,
            field_prime=from_dkg.field_prime,
            group_prime=from_dkg.group_prime,
            generator=from_dkg.generator,
            public_key=from_dkg.public_key,
            verification_shares=from_dkg.verification_shares,
        )
        self.assertEqual(direct, from_dkg)

        expected = encode_signing_public_context(from_dkg)
        self.assertEqual(encode_signing_public_context(from_local), expected)
        self.assertEqual(encode_signing_public_context(direct), expected)

        refresh_contributions, refreshed = make_refreshed(dkg)
        from_refresh = export_signing_public_context(refreshed)
        index = dkg.result.participant_ids.index(2)
        _s, _b, _c, from_refresh_local = refresh_local(
            2,
            dkg.result.shares[index],
            dkg.result.blinding_shares[index],
            dkg.result.commitment,
            from_dkg,
            packets_for(refresh_contributions, 2),
        )
        self.assertEqual(from_refresh_local, from_refresh)
        self.assertEqual(
            encode_signing_public_context(from_refresh_local),
            encode_signing_public_context(from_refresh),
        )

        reshare_contributions, reshared = make_reshared(dkg)
        from_reshare = export_signing_public_context(reshared)
        _s, _b, _c, from_reshare_local = reshare_local(
            3,
            packets_for(reshare_contributions, 3),
            (2, 3),
            from_dkg,
            dkg.result.commitment,
        )
        self.assertEqual(from_reshare_local, from_reshare)
        self.assertEqual(
            encode_signing_public_context(from_reshare_local),
            encode_signing_public_context(from_reshare),
        )

    def test_decode_non_bytes_raises_type_error(self):
        with self.assertRaises(TypeError):
            decode_signing_public_context("bytes only")
        with self.assertRaises(TypeError):
            decode_signing_public_context(bytearray(b"x"))
        with self.assertRaises(TypeError):
            decode_signing_public_context(None)

    def test_bad_tag_raises_value_error(self):
        blob = encode_signing_public_context(self.context)
        with self.assertRaises(ValueError):
            decode_signing_public_context(b"x" + blob)
        with self.assertRaises(ValueError):
            decode_signing_public_context(b"")
        with self.assertRaises(ValueError):
            decode_signing_public_context(blob[:10])
        with self.assertRaises(ValueError):
            decode_signing_public_context(
                ROUND_PACKET_TAG + blob[len(SIGNING_PUBLIC_CONTEXT_TAG):]
            )

    def test_truncation_raises_value_error(self):
        blob = encode_signing_public_context(self.context)
        for cut in range(len(blob)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_signing_public_context(blob[:cut])

    def test_trailing_bytes_raise_value_error(self):
        blob = encode_signing_public_context(self.context)
        with self.assertRaises(ValueError):
            decode_signing_public_context(blob + b"\x00")
        with self.assertRaises(ValueError):
            decode_signing_public_context(blob + b"tail")

    def test_non_canonical_integer_raises_value_error(self):
        blob = bytearray(encode_signing_public_context(self.context))
        first_int = len(SIGNING_PUBLIC_CONTEXT_TAG) + 4  # first participant id body
        length = int.from_bytes(blob[first_int:first_int + 4], "big")
        self.assertGreaterEqual(length, 1)
        blob[first_int:first_int + 4] = (length + 1).to_bytes(4, "big")
        blob[first_int + 4:first_int + 4] = b"\x00"
        with self.assertRaises(ValueError):
            decode_signing_public_context(bytes(blob))

    def test_zero_length_integer_body_rejected(self):
        blob = bytearray(encode_signing_public_context(self.context))
        first_int = len(SIGNING_PUBLIC_CONTEXT_TAG) + 4
        blob[first_int:first_int + 4] = (0).to_bytes(4, "big")
        with self.assertRaises(ValueError):
            decode_signing_public_context(bytes(blob))

    def test_count_mismatch_raises_value_error(self):
        # Participant count 3 -> 4 desynchronises the stream.
        blob = bytearray(encode_signing_public_context(self.context))
        count_at = len(SIGNING_PUBLIC_CONTEXT_TAG)
        blob[count_at:count_at + 4] = (4).to_bytes(4, "big")
        with self.assertRaises(ValueError):
            decode_signing_public_context(bytes(blob))

        # Verification-share count 3 -> 2 leaves trailing bytes.
        blob = bytearray(encode_signing_public_context(self.context))
        offset = len(SIGNING_PUBLIC_CONTEXT_TAG) + 4
        for participant_id in self.context.participant_ids:
            offset += len(varint(participant_id))
        for value in (
            self.context.threshold,
            self.context.field_prime,
            self.context.group_prime,
            self.context.generator,
            self.context.public_key,
        ):
            offset += len(varint(value))
        self.assertEqual(
            int.from_bytes(blob[offset:offset + 4], "big"),
            len(self.context.verification_shares),
        )
        blob[offset:offset + 4] = (2).to_bytes(4, "big")
        with self.assertRaises(ValueError):
            decode_signing_public_context(bytes(blob))

    def test_oversized_count_raises_value_error(self):
        blob = bytearray(encode_signing_public_context(self.context))
        count_at = len(SIGNING_PUBLIC_CONTEXT_TAG)
        blob[count_at:count_at + 4] = (0xFFFFFFFF).to_bytes(4, "big")
        with self.assertRaises(ValueError):
            decode_signing_public_context(bytes(blob))

    def test_encode_wrong_type_raises_type_error(self):
        with self.assertRaises(TypeError):
            encode_signing_public_context("not a context")
        with self.assertRaises(TypeError):
            encode_signing_public_context(None)
        with self.assertRaises(TypeError):
            encode_signing_public_context(self.dkg)
        round_info, _c, _n = make_round(self.dkg)
        with self.assertRaises(TypeError):
            encode_signing_public_context(
                SigningRoundPacket(context=self.context, round_info=round_info)
            )

    def test_encode_field_type_errors(self):
        type_errors = [
            dataclasses.replace(self.context, participant_ids=[1, 2, 3]),
            dataclasses.replace(self.context, participant_ids=(1, "2", 3)),
            dataclasses.replace(self.context, participant_ids=(1, True, 3)),
            dataclasses.replace(self.context, threshold=True),
            dataclasses.replace(self.context, threshold="2"),
            dataclasses.replace(self.context, field_prime=False),
            dataclasses.replace(self.context, field_prime=2017.0),
            dataclasses.replace(self.context, group_prime=True),
            dataclasses.replace(self.context, generator="16"),
            dataclasses.replace(self.context, public_key=True),
            dataclasses.replace(self.context, verification_shares=[1, 2, 3]),
            dataclasses.replace(self.context, verification_shares=(1, True, 3)),
        ]
        for context in type_errors:
            with self.assertRaises(TypeError, msg=repr(context)):
                encode_signing_public_context(context)

    def test_encode_value_errors(self):
        shares = self.context.verification_shares
        cases = [
            dataclasses.replace(self.context, participant_ids=()),
            dataclasses.replace(self.context, participant_ids=(2, 1, 3)),
            dataclasses.replace(self.context, participant_ids=(1, 1, 3)),
            dataclasses.replace(self.context, participant_ids=(0, 1, 2)),
            dataclasses.replace(self.context, participant_ids=(1, 2, FIELD_PRIME)),
            dataclasses.replace(self.context, threshold=0),
            dataclasses.replace(self.context, threshold=-1),
            dataclasses.replace(self.context, threshold=4),
            dataclasses.replace(self.context, field_prime=2018),
            dataclasses.replace(self.context, group_prime=8070),
            dataclasses.replace(self.context, generator=1),
            dataclasses.replace(self.context, generator=GROUP_PRIME - 1),
            dataclasses.replace(self.context, public_key=0),
            dataclasses.replace(self.context, public_key=GROUP_PRIME),
            dataclasses.replace(self.context, public_key=GROUP_PRIME - 1),
            dataclasses.replace(self.context, verification_shares=shares[:2]),
            dataclasses.replace(self.context, verification_shares=shares + (1,)),
            dataclasses.replace(self.context, verification_shares=(0,) + shares[1:]),
            dataclasses.replace(
                self.context, verification_shares=(GROUP_PRIME,) + shares[1:]
            ),
            dataclasses.replace(
                self.context, verification_shares=(GROUP_PRIME - 1,) + shares[1:]
            ),
        ]
        for context in cases:
            with self.assertRaises(ValueError, msg=repr(context)):
                encode_signing_public_context(context)

    def test_decode_value_errors_surface_as_value_error(self):
        # A structurally illegal context never decodes: zero the public key
        # in the stream and the decode boundary raises ValueError.
        blob = bytearray(encode_signing_public_context(self.context))
        offset = len(SIGNING_PUBLIC_CONTEXT_TAG) + 4
        for participant_id in self.context.participant_ids:
            offset += len(varint(participant_id))
        for value in (
            self.context.threshold,
            self.context.field_prime,
            self.context.group_prime,
            self.context.generator,
        ):
            offset += len(varint(value))
        key_length = int.from_bytes(blob[offset:offset + 4], "big")
        blob[offset:offset + 4 + key_length] = varint(0)
        with self.assertRaises(ValueError):
            decode_signing_public_context(bytes(blob))

    def test_decode_does_not_check_threshold_consistency(self):
        # A structurally legal context whose verification shares do not fit
        # the joint key on one degree-below-threshold polynomial still
        # round-trips; verify_signing_public_context reports False.
        forged = dataclasses.replace(
            self.context,
            verification_shares=(
                pow(self.context.verification_shares[0], 2, GROUP_PRIME),
            ) + self.context.verification_shares[1:],
        )
        self.assertFalse(verify_signing_public_context(forged))
        blob = encode_signing_public_context(forged)
        decoded = decode_signing_public_context(blob)
        self.assertEqual(decoded, forged)
        self.assertEqual(encode_signing_public_context(decoded), blob)
        self.assertFalse(verify_signing_public_context(decoded))

    def test_decoded_context_drops_into_existing_entry_points(self):
        decoded = decode_signing_public_context(encode_signing_public_context(self.context))
        self.assertTrue(verify_signing_public_context(decoded))

        round_info, commitments, nonces = make_round(self.dkg)
        from_original = create_signing_round(
            MESSAGE, (1, 2), commitments, self.context
        )
        from_decoded = create_signing_round(MESSAGE, (1, 2), commitments, decoded)
        self.assertEqual(from_decoded, from_original)

        shares = make_shares(self.dkg, round_info, nonces)
        for share in shares:
            self.assertIs(
                verify_signature_share(share, round_info, decoded),
                verify_signature_share(share, round_info, self.context),
            )
        signature = aggregate_signature(shares, round_info, decoded)
        self.assertIsInstance(signature, AggregateSignature)
        self.assertEqual(signature, aggregate_signature(shares, round_info, self.context))
        self.assertTrue(
            verify_signature(
                MESSAGE, signature, decoded.public_key,
                prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
            )
        )

    def test_refreshed_context_round_trip_keeps_packet_verdict(self):
        _contributions, refreshed = make_refreshed(self.dkg)
        refreshed_context = export_signing_public_context(refreshed)
        decoded = decode_signing_public_context(
            encode_signing_public_context(refreshed_context)
        )
        self.assertEqual(decoded, refreshed_context)
        self.assertEqual(
            dataclasses.astuple(decoded), dataclasses.astuple(refreshed_context)
        )

        # A packet exported under the pre-refresh context fails verification
        # against the refreshed context, identically before and after the
        # context's codec round-trip.
        round_info, _c, _n = make_round(self.dkg)
        stale_packet = SigningRoundPacket(context=self.context, round_info=round_info)
        self.assertFalse(verify_round_packet(stale_packet, refreshed_context))
        self.assertFalse(verify_round_packet(stale_packet, decoded))

        # A packet under the refreshed context verifies against both.
        new_round, _c2, _n2 = make_round(refreshed)
        fresh_packet = SigningRoundPacket(context=refreshed_context, round_info=new_round)
        self.assertTrue(verify_round_packet(fresh_packet, refreshed_context))
        self.assertTrue(verify_round_packet(fresh_packet, decoded))

    def test_reshared_context_round_trip_keeps_packet_verdict(self):
        _contributions, reshared = make_reshared(self.dkg)
        reshared_context = export_signing_public_context(reshared)
        decoded = decode_signing_public_context(
            encode_signing_public_context(reshared_context)
        )
        self.assertEqual(decoded, reshared_context)

        round_info, _c, _n = make_round(self.dkg)
        stale_packet = SigningRoundPacket(context=self.context, round_info=round_info)
        self.assertFalse(verify_round_packet(stale_packet, reshared_context))
        self.assertFalse(verify_round_packet(stale_packet, decoded))

        new_round, _c2, _n2 = make_round(reshared, signer_ids=(2, 4))
        fresh_packet = SigningRoundPacket(context=reshared_context, round_info=new_round)
        self.assertTrue(verify_round_packet(fresh_packet, reshared_context))
        self.assertTrue(verify_round_packet(fresh_packet, decoded))


if __name__ == "__main__":
    unittest.main()
