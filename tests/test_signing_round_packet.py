"""Tests for the SigningRoundPacket and its codec/verifier."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    ROUND_PACKET_TAG,
    AggregateSignature,
    SigningNonceCommitment,
    SigningPublicContext,
    SigningRound,
    SigningRoundPacket,
    aggregate_signature,
    create_refresh,
    create_reshare,
    decode_round_packet,
    encode_round_packet,
    export_signing_public_context,
    refresh,
    reshare,
    schnorr_challenge,
    verify_round_packet,
    verify_signature,
    verify_signature_share,
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
    make_signing_dkg,
)


def varint(value):
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def make_packet(dkg=None, signer_ids=(1, 2), message=MESSAGE, seed=10):
    dkg = dkg or make_signing_dkg()
    context = export_signing_public_context(dkg)
    round_info, commitments, nonces = make_round(dkg, signer_ids, message, seed=seed)
    packet = SigningRoundPacket(context=context, round_info=round_info)
    return dkg, context, round_info, commitments, nonces, packet


def secret_share_of(key, participant_id):
    index = key.result.participant_ids.index(participant_id)
    return key.result.shares[index].y


class SigningRoundPacketTest(unittest.TestCase):
    def test_fields_are_the_context_and_round(self):
        _dkg, context, round_info, _c, _n, packet = make_packet()
        self.assertIsInstance(packet, SigningRoundPacket)
        self.assertEqual(packet.context, context)
        self.assertEqual(packet.round_info, round_info)
        self.assertIsInstance(packet.context, SigningPublicContext)
        self.assertIsInstance(packet.round_info, SigningRound)

    def test_positional_construction_and_value_equality(self):
        _dkg, context, round_info, _c, _n, packet = make_packet()
        self.assertEqual(
            packet, SigningRoundPacket(context, round_info)
        )
        self.assertEqual(
            packet,
            SigningRoundPacket(context=context, round_info=round_info),
        )
        _dkg2, _c2, _r2, _co2, _n2, same = make_packet()
        self.assertEqual(packet, same)
        self.assertNotEqual(packet, make_packet(message=b"other message")[-1])

    def test_frozen_and_no_secret_fields(self):
        _dkg, _c, _r, _co, _n, packet = make_packet()
        with self.assertRaises(FrozenInstanceError):
            packet.context = None  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            packet.round_info = None  # type: ignore[misc]
        self.assertEqual(
            {f.name for f in dataclasses.fields(packet)},
            {"context", "round_info"},
        )
        for name in ("dkg_result", "nonce", "secret_share", "blinding_share"):
            self.assertFalse(hasattr(packet, name))

    def test_empty_message_threshold_one_and_identity_elements(self):
        dkg = make_signing_dkg((1, 2, 3), 1)
        context = export_signing_public_context(dkg)
        round_info, _c, _n = make_round(dkg, (2,), b"")
        packet = SigningRoundPacket(context=context, round_info=round_info)
        self.assertTrue(verify_round_packet(packet, context))

        # A hand-built packet with identity public key, identity
        # verification shares and commitments multiplying to R = 1 stays
        # legal, exactly as the signing entry points allow.
        commitments = (
            SigningNonceCommitment(1, pow(GENERATOR, 5, GROUP_PRIME)),
            SigningNonceCommitment(2, pow(GENERATOR, FIELD_PRIME - 5, GROUP_PRIME)),
        )
        self.assertEqual(
            commitments[0].commitment * commitments[1].commitment % GROUP_PRIME, 1
        )
        synthetic_context = SigningPublicContext(
            participant_ids=(1, 2),
            threshold=1,
            field_prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            public_key=1,
            verification_shares=(1, 1),
        )
        synthetic_round = SigningRound(
            message=b"",
            signer_ids=(1, 2),
            nonce_commitments=commitments,
            R=1,
            challenge=schnorr_challenge(
                b"", 1, 1, (1, 2),
                field_prime=FIELD_PRIME, group_prime=GROUP_PRIME,
            ),
        )
        synthetic = SigningRoundPacket(synthetic_context, synthetic_round)
        self.assertTrue(verify_round_packet(synthetic, synthetic_context))
        blob = encode_round_packet(synthetic)
        self.assertEqual(decode_round_packet(blob), synthetic)


class RoundPacketCodecTest(unittest.TestCase):
    def setUp(self):
        (self.dkg, self.context, self.round_info, self.commitments,
         self.nonces, self.packet) = make_packet()

    def test_round_trip_is_byte_exact(self):
        blob = encode_round_packet(self.packet)
        self.assertIsInstance(blob, bytes)
        decoded = decode_round_packet(blob)
        self.assertEqual(decoded, self.packet)
        self.assertEqual(encode_round_packet(decoded), blob)
        self.assertEqual(encode_round_packet(self.packet), blob)

    def test_starts_with_tag(self):
        blob = encode_round_packet(self.packet)
        self.assertTrue(blob.startswith(b"thresholdsign/round-packet/v1"))
        self.assertTrue(blob.startswith(ROUND_PACKET_TAG))

    def test_encoding_is_deterministic(self):
        self.assertEqual(
            encode_round_packet(self.packet), encode_round_packet(self.packet)
        )

    def test_round_trip_empty_and_binary_message(self):
        for message in (b"", bytes(range(256)), b"\x00" * 1000):
            _d, _c, _r, _co, _n, packet = make_packet(message=message)
            blob = encode_round_packet(packet)
            decoded = decode_round_packet(blob)
            self.assertEqual(decoded, packet)
            self.assertEqual(encode_round_packet(decoded), blob)

    def test_round_trip_large_group(self):
        dkg = make_signing_dkg(
            (1, 2, 3), 2,
            field_prime=LARGE_FIELD, group_prime=LARGE_GROUP,
            generator=LARGE_G, blinding_generator=LARGE_H,
        )
        _d, _c, _r, _co, _n, packet = make_packet(dkg)
        blob = encode_round_packet(packet)
        self.assertEqual(decode_round_packet(blob), packet)
        self.assertEqual(encode_round_packet(decode_round_packet(blob)), blob)

    def test_round_trip_threshold_one_and_nonconsecutive_signers(self):
        dkg = make_signing_dkg((1, 2, 3, 4), 2)
        _d, _c, _r, _co, _n, packet = make_packet(dkg, signer_ids=(2, 4))
        blob = encode_round_packet(packet)
        self.assertEqual(decode_round_packet(blob), packet)

        dkg1 = make_signing_dkg((1, 2), 1)
        _d, _c, _r, _co, _n, packet1 = make_packet(dkg1, signer_ids=(2,))
        self.assertEqual(decode_round_packet(encode_round_packet(packet1)), packet1)

    def test_encoding_carries_no_secret_material(self):
        # Rebuild the encoding solely from the packet's public fields.
        context = self.packet.context
        round_info = self.packet.round_info
        expected = bytearray(ROUND_PACKET_TAG)
        expected += len(context.participant_ids).to_bytes(4, "big")
        for participant_id in context.participant_ids:
            expected += varint(participant_id)
        for value in (
            context.threshold,
            context.field_prime,
            context.group_prime,
            context.generator,
            context.public_key,
        ):
            expected += varint(value)
        expected += len(context.verification_shares).to_bytes(4, "big")
        for share in context.verification_shares:
            expected += varint(share)
        expected += len(round_info.message).to_bytes(4, "big")
        expected += round_info.message
        expected += len(round_info.signer_ids).to_bytes(4, "big")
        for signer_id in round_info.signer_ids:
            expected += varint(signer_id)
        expected += len(round_info.nonce_commitments).to_bytes(4, "big")
        for commitment in round_info.nonce_commitments:
            expected += varint(commitment.signer_id)
            expected += varint(commitment.commitment)
        expected += varint(round_info.R)
        expected += varint(round_info.challenge)
        self.assertEqual(encode_round_packet(self.packet), bytes(expected))

    def test_decode_non_bytes_raises_type_error(self):
        with self.assertRaises(TypeError):
            decode_round_packet("bytes only")
        with self.assertRaises(TypeError):
            decode_round_packet(bytearray(b"x"))
        with self.assertRaises(TypeError):
            decode_round_packet(None)

    def test_bad_tag_raises_value_error(self):
        blob = encode_round_packet(self.packet)
        with self.assertRaises(ValueError):
            decode_round_packet(b"x" + blob)
        with self.assertRaises(ValueError):
            decode_round_packet(b"")
        with self.assertRaises(ValueError):
            decode_round_packet(blob[:10])

    def test_truncation_raises_value_error(self):
        blob = encode_round_packet(self.packet)
        for cut in range(len(blob)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_round_packet(blob[:cut])

    def test_trailing_bytes_raise_value_error(self):
        blob = encode_round_packet(self.packet)
        with self.assertRaises(ValueError):
            decode_round_packet(blob + b"\x00")
        with self.assertRaises(ValueError):
            decode_round_packet(blob + b"tail")

    def test_declared_message_length_too_large(self):
        blob = bytearray(encode_round_packet(self.packet))
        # The message length frame follows the context block; locate it by
        # walking the same structure the encoder writes.
        offset = len(ROUND_PACKET_TAG)
        offset += 4  # participant count
        for participant_id in self.context.participant_ids:
            offset += 4 + len(varint(participant_id)) - 4
        for value in (
            self.context.threshold,
            self.context.field_prime,
            self.context.group_prime,
            self.context.generator,
            self.context.public_key,
        ):
            offset += len(varint(value))
        offset += 4  # verification share count
        for share in self.context.verification_shares:
            offset += len(varint(share))
        declared = int.from_bytes(blob[offset:offset + 4], "big")
        self.assertEqual(declared, len(self.round_info.message))
        blob[offset + 3] = (declared + 1) & 0xFF
        with self.assertRaises(ValueError):
            decode_round_packet(bytes(blob))

    def test_non_canonical_integer_raises_value_error(self):
        blob = bytearray(encode_round_packet(self.packet))
        first_int = len(ROUND_PACKET_TAG) + 4  # first participant id body
        length = int.from_bytes(blob[first_int:first_int + 4], "big")
        self.assertGreaterEqual(length, 1)
        blob[first_int:first_int + 4] = (length + 1).to_bytes(4, "big")
        blob[first_int + 4:first_int + 4] = b"\x00"
        with self.assertRaises(ValueError):
            decode_round_packet(bytes(blob))

    def test_zero_length_integer_body_rejected(self):
        blob = bytearray(encode_round_packet(self.packet))
        first_int = len(ROUND_PACKET_TAG) + 4
        blob[first_int:first_int + 4] = (0).to_bytes(4, "big")
        with self.assertRaises(ValueError):
            decode_round_packet(bytes(blob))

    def test_encode_wrong_type_raises_type_error(self):
        with self.assertRaises(TypeError):
            encode_round_packet("not a packet")
        with self.assertRaises(TypeError):
            encode_round_packet(None)
        with self.assertRaises(TypeError):
            encode_round_packet(self.round_info)
        bad = SigningRoundPacket(context=self.context, round_info=self.context)
        with self.assertRaises(TypeError):
            encode_round_packet(bad)
        bad = SigningRoundPacket(context=self.round_info, round_info=self.round_info)
        with self.assertRaises(TypeError):
            encode_round_packet(bad)

    def test_encode_field_type_errors(self):
        bad = dataclasses.replace(
            self.packet, context=dataclasses.replace(self.context, threshold=True)
        )
        with self.assertRaises(TypeError):
            encode_round_packet(bad)
        bad = dataclasses.replace(
            self.packet,
            context=dataclasses.replace(self.context, participant_ids=[1, 2, 3]),
        )
        with self.assertRaises(TypeError):
            encode_round_packet(bad)
        bad = dataclasses.replace(
            self.packet,
            context=dataclasses.replace(self.context, participant_ids=(1, True, 3)),
        )
        with self.assertRaises(TypeError):
            encode_round_packet(bad)
        bad = dataclasses.replace(
            self.packet,
            round_info=dataclasses.replace(self.round_info, message="not bytes"),
        )
        with self.assertRaises(TypeError):
            encode_round_packet(bad)
        bad = dataclasses.replace(
            self.packet,
            round_info=dataclasses.replace(self.round_info, signer_ids=[1, 2]),
        )
        with self.assertRaises(TypeError):
            encode_round_packet(bad)
        bad = dataclasses.replace(
            self.packet,
            round_info=dataclasses.replace(self.round_info, R=True),
        )
        with self.assertRaises(TypeError):
            encode_round_packet(bad)
        bad = dataclasses.replace(
            self.packet,
            round_info=dataclasses.replace(self.round_info, challenge="1"),
        )
        with self.assertRaises(TypeError):
            encode_round_packet(bad)

    def test_encode_context_value_errors(self):
        cases = [
            dataclasses.replace(self.context, participant_ids=(2, 1, 3)),
            dataclasses.replace(self.context, participant_ids=(1, 1, 3)),
            dataclasses.replace(self.context, participant_ids=(0, 1, 2)),
            dataclasses.replace(self.context, participant_ids=()),
            dataclasses.replace(self.context, threshold=0),
            dataclasses.replace(self.context, threshold=4),
            dataclasses.replace(self.context, field_prime=2018),
            dataclasses.replace(self.context, group_prime=8070),
            dataclasses.replace(self.context, generator=1),
            dataclasses.replace(self.context, public_key=0),
            dataclasses.replace(self.context, public_key=GROUP_PRIME),
            dataclasses.replace(self.context, verification_shares=(1, 1)),
            dataclasses.replace(self.context, verification_shares=(1, 1, 1, 1)),
            dataclasses.replace(self.context, verification_shares=(0, 1, 1)),
        ]
        for context in cases:
            packet = dataclasses.replace(self.packet, context=context)
            with self.assertRaises(ValueError, msg=repr(context)):
                encode_round_packet(packet)

    def test_encode_round_value_errors(self):
        round_cases = [
            dataclasses.replace(self.round_info, signer_ids=(2, 1)),
            dataclasses.replace(self.round_info, signer_ids=(1, 1)),
            dataclasses.replace(self.round_info, signer_ids=(1,)),
            dataclasses.replace(self.round_info, signer_ids=(1, 4)),
            dataclasses.replace(self.round_info, signer_ids=()),
            dataclasses.replace(self.round_info, R=0),
            dataclasses.replace(self.round_info, R=GROUP_PRIME),
            dataclasses.replace(self.round_info, challenge=-1),
            dataclasses.replace(self.round_info, challenge=FIELD_PRIME),
            # Missing, duplicated and misaligned commitments.
            dataclasses.replace(
                self.round_info,
                nonce_commitments=self.round_info.nonce_commitments[:1],
            ),
            dataclasses.replace(
                self.round_info,
                nonce_commitments=self.round_info.nonce_commitments
                + self.round_info.nonce_commitments[:1],
            ),
            dataclasses.replace(
                self.round_info,
                nonce_commitments=tuple(
                    reversed(self.round_info.nonce_commitments)
                ),
            ),
            dataclasses.replace(
                self.round_info,
                nonce_commitments=(
                    self.round_info.nonce_commitments[0],
                    SigningNonceCommitment(2, 1),
                ),
            ),
            dataclasses.replace(
                self.round_info,
                nonce_commitments=(
                    self.round_info.nonce_commitments[0],
                    SigningNonceCommitment(2, GROUP_PRIME),
                ),
            ),
        ]
        for round_info in round_cases:
            packet = dataclasses.replace(self.packet, round_info=round_info)
            with self.assertRaises(ValueError, msg=repr(round_info)):
                encode_round_packet(packet)

    def test_decode_rejects_structural_violations(self):
        # A decode-time structural failure surfaces as ValueError too: build
        # the blob from a legal packet, then corrupt one length prefix so a
        # count no longer matches the stream.
        blob = bytearray(encode_round_packet(self.packet))
        # Participant count 3 -> 4 makes the following threshold varint be
        # read as a participant id and desynchronises the stream.
        count_at = len(ROUND_PACKET_TAG)
        blob[count_at:count_at + 4] = (4).to_bytes(4, "big")
        with self.assertRaises(ValueError):
            decode_round_packet(bytes(blob))

    def test_decode_does_not_check_R_or_challenge(self):
        forged = dataclasses.replace(
            self.packet,
            round_info=dataclasses.replace(
                self.round_info,
                R=(self.round_info.R + 1) % GROUP_PRIME,
                challenge=(self.round_info.challenge + 1) % FIELD_PRIME,
            ),
        )
        blob = encode_round_packet(forged)
        decoded = decode_round_packet(blob)
        self.assertEqual(decoded, forged)
        self.assertEqual(encode_round_packet(decoded), blob)
        self.assertFalse(verify_round_packet(decoded, self.context))


class VerifyRoundPacketTest(unittest.TestCase):
    def setUp(self):
        (self.dkg, self.context, self.round_info, self.commitments,
         self.nonces, self.packet) = make_packet()

    def test_valid_packet_is_true(self):
        self.assertTrue(verify_round_packet(self.packet, self.context))

    def test_decoded_packet_verifies(self):
        decoded = decode_round_packet(encode_round_packet(self.packet))
        self.assertTrue(verify_round_packet(decoded, self.context))

    def test_verified_packet_drops_into_existing_entry_points(self):
        blob = encode_round_packet(self.packet)
        decoded = decode_round_packet(blob)
        self.assertTrue(verify_round_packet(decoded, self.context))
        shares = make_shares(self.dkg, decoded.round_info, self.nonces)
        for share in shares:
            self.assertTrue(
                verify_signature_share(share, decoded.round_info, self.context)
            )
        signature = aggregate_signature(shares, decoded.round_info, self.context)
        self.assertIsInstance(signature, AggregateSignature)
        original = aggregate_signature(shares, self.round_info, self.context)
        self.assertEqual(signature, original)
        self.assertTrue(
            verify_signature(
                decoded.round_info.message,
                signature,
                self.context.public_key,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            )
        )

    def test_tampered_round_fields_are_false(self):
        cases = [
            dataclasses.replace(self.round_info, message=b"another message"),
            dataclasses.replace(
                self.round_info, R=(self.round_info.R + 1) % GROUP_PRIME
            ),
            dataclasses.replace(
                self.round_info,
                challenge=(self.round_info.challenge + 1) % FIELD_PRIME,
            ),
            dataclasses.replace(
                self.round_info,
                nonce_commitments=(
                    self.round_info.nonce_commitments[0],
                    SigningNonceCommitment(
                        2,
                        self.round_info.nonce_commitments[1].commitment ** 2
                        % GROUP_PRIME,
                    ),
                ),
            ),
        ]
        for round_info in cases:
            packet = dataclasses.replace(self.packet, round_info=round_info)
            with self.subTest(round_info=round_info):
                self.assertFalse(verify_round_packet(packet, self.context))

    def test_tampered_context_fields_are_false(self):
        other = make_signing_dkg(seed_base=500)
        other_context = export_signing_public_context(other)
        cases = [
            dataclasses.replace(self.context, participant_ids=(1, 2, 4)),
            dataclasses.replace(self.context, threshold=1),
            # The other generator of the same subgroup is structurally legal.
            dataclasses.replace(self.context, generator=BLINDING_GENERATOR),
            dataclasses.replace(self.context, public_key=other_context.public_key),
            dataclasses.replace(
                self.context,
                verification_shares=(
                    self.context.verification_shares[1],
                    self.context.verification_shares[0],
                    self.context.verification_shares[2],
                ),
            ),
        ]
        for context in cases:
            packet = dataclasses.replace(self.packet, context=context)
            with self.subTest(context=context):
                self.assertFalse(verify_round_packet(packet, self.context))

    def test_packet_under_another_context_is_false(self):
        other = make_signing_dkg(seed_base=500)
        other_context = export_signing_public_context(other)
        self.assertFalse(verify_round_packet(self.packet, other_context))

    def test_refresh_invalidates_old_packet(self):
        contributions = [
            create_refresh(pid, self.dkg, randbelow=fixed_random(pid + 100))
            for pid in self.dkg.result.participant_ids
        ]
        refreshed = refresh(contributions, self.dkg)
        refreshed_context = export_signing_public_context(refreshed)
        # The joint public key is unchanged by a refresh, but the public
        # context changed, so the old packet no longer verifies.
        self.assertEqual(refreshed_context.public_key, self.context.public_key)
        self.assertNotEqual(
            refreshed_context.verification_shares, self.context.verification_shares
        )
        self.assertFalse(verify_round_packet(self.packet, refreshed_context))

    def test_reshare_invalidates_old_packet(self):
        dealers = (2, 3)
        members = (2, 3, 4)
        contributions = [
            create_reshare(
                dealer,
                secret_share_of(self.dkg, dealer),
                dealers,
                members,
                2,
                self.dkg,
                rng=fixed_random(dealer + 100),
            )
            for dealer in dealers
        ]
        reshared = reshare(contributions, dealers, self.dkg)
        reshared_context = export_signing_public_context(reshared)
        self.assertEqual(reshared_context.public_key, self.context.public_key)
        self.assertFalse(verify_round_packet(self.packet, reshared_context))

    def test_wrong_argument_types_raise_type_error(self):
        with self.assertRaises(TypeError):
            verify_round_packet("not a packet", self.context)
        with self.assertRaises(TypeError):
            verify_round_packet(self.packet, "not a context")
        with self.assertRaises(TypeError):
            verify_round_packet(self.packet, self.dkg)
        with self.assertRaises(TypeError):
            verify_round_packet(self.round_info, self.context)

    def test_structural_errors_raise_not_false(self):
        bad = dataclasses.replace(
            self.packet, context=dataclasses.replace(self.context, threshold=True)
        )
        with self.assertRaises(TypeError):
            verify_round_packet(bad, self.context)
        bad = dataclasses.replace(
            self.packet, context=dataclasses.replace(self.context, threshold=0)
        )
        with self.assertRaises(ValueError):
            verify_round_packet(bad, self.context)
        bad = dataclasses.replace(
            self.packet, context=dataclasses.replace(self.context, field_prime=2018)
        )
        with self.assertRaises(ValueError):
            verify_round_packet(bad, self.context)
        misaligned = dataclasses.replace(
            self.packet,
            round_info=dataclasses.replace(
                self.round_info,
                nonce_commitments=tuple(
                    reversed(self.round_info.nonce_commitments)
                ),
            ),
        )
        with self.assertRaises(ValueError):
            verify_round_packet(misaligned, self.context)
        bad_trusted = dataclasses.replace(self.context, public_key=0)
        with self.assertRaises(ValueError):
            verify_round_packet(self.packet, bad_trusted)
        bad_trusted = dataclasses.replace(self.context, threshold=False)
        with self.assertRaises(TypeError):
            verify_round_packet(self.packet, bad_trusted)

    def test_empty_message_and_threshold_one_verify(self):
        dkg = make_signing_dkg((1, 2, 3), 1)
        _d, context, _r, _c, _n, packet = make_packet(dkg, (2,), b"")
        self.assertTrue(verify_round_packet(packet, context))


if __name__ == "__main__":
    unittest.main()
