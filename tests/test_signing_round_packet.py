"""Tests for SigningRoundPacket and its encode/decode/verify entry points."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    SigningDKGResult,
    SigningNonceCommitment,
    SigningPublicContext,
    SigningRound,
    SigningRoundPacket,
    aggregate_signature,
    aggregate_signing_dkg,
    create_refresh,
    create_reshare,
    create_signature_share,
    create_signing_contribution,
    create_signing_nonce_commitment,
    create_signing_round,
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

# Same toy group as the signing tests: 8069 = 4 * 2017 + 1 is prime, 16 and
# 256 = 16 ** 2 are distinct generators of the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

MESSAGE = b"round packet test message"
ROUND_PACKET_TAG = b"thresholdsign/signing-round-packet/v1"


def fixed_random(seed=1):
    """Deterministic stand-in for secrets.randbelow (same LCG as signing tests)."""
    state = {"value": seed}

    def randbelow(upper: int) -> int:
        state["value"] = (
            state["value"] * 6364136223846793005 + 1442695040888963407
        ) % upper
        return state["value"]

    return randbelow


def make_key(
    participant_ids=(1, 2, 3),
    threshold=2,
    field_prime=FIELD_PRIME,
    group_prime=GROUP_PRIME,
    generator=GENERATOR,
    blinding_generator=BLINDING_GENERATOR,
    seed_base=0,
):
    contributions = [
        create_signing_contribution(
            pid,
            participant_ids,
            threshold,
            prime=field_prime,
            group_prime=group_prime,
            generator=generator,
            blinding_generator=blinding_generator,
            randbelow=fixed_random(pid + seed_base),
        )
        for pid in participant_ids
    ]
    outcome = aggregate_signing_dkg(contributions)
    assert isinstance(outcome, SigningDKGResult), outcome
    return outcome


def secret_share_of(key, participant_id):
    index = key.result.participant_ids.index(participant_id)
    return key.result.shares[index].y


def make_round(key_or_context, signer_ids=(1, 2), message=MESSAGE, seed=10):
    commitments = []
    nonces = {}
    for offset, signer_id in enumerate(signer_ids):
        commitment, nonce = create_signing_nonce_commitment(
            signer_id,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            randbelow=fixed_random(seed + 100 * offset + signer_id),
        )
        commitments.append(commitment)
        nonces[signer_id] = nonce
    round_info = create_signing_round(
        message, tuple(signer_ids), commitments, key_or_context
    )
    return round_info, commitments, nonces


def make_shares(key, round_info, nonces):
    return [
        create_signature_share(
            signer_id, secret_share_of(key, signer_id), nonces[signer_id], round_info, key
        )
        for signer_id in round_info.signer_ids
    ]


def make_packet(key_or_context=None, signer_ids=(1, 2), message=MESSAGE):
    if key_or_context is None:
        key_or_context = make_key()
    round_info, _commitments, _nonces = make_round(
        key_or_context, signer_ids=signer_ids, message=message
    )
    if isinstance(key_or_context, SigningPublicContext):
        context = key_or_context
    else:
        context = export_signing_public_context(key_or_context)
    return SigningRoundPacket(context=context, round_info=round_info)


def subgroup_element(exponent):
    return pow(GENERATOR, exponent, GROUP_PRIME)


class PacketShapeTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.context = export_signing_public_context(self.key)
        self.round_info, _c, _n = make_round(self.key)
        self.packet = SigningRoundPacket(self.context, self.round_info)

    def test_frozen_positionally_constructible_and_compared_by_value(self):
        again = SigningRoundPacket(
            context=SigningPublicContext(
                participant_ids=self.context.participant_ids,
                threshold=self.context.threshold,
                field_prime=self.context.field_prime,
                group_prime=self.context.group_prime,
                generator=self.context.generator,
                public_key=self.context.public_key,
                verification_shares=self.context.verification_shares,
            ),
            round_info=SigningRound(
                message=self.round_info.message,
                signer_ids=self.round_info.signer_ids,
                nonce_commitments=self.round_info.nonce_commitments,
                R=self.round_info.R,
                challenge=self.round_info.challenge,
            ),
        )
        self.assertEqual(self.packet, again)
        self.assertEqual(hash(self.packet), hash(again))
        self.assertNotEqual(self.packet, (self.context, self.round_info))
        with self.assertRaises(FrozenInstanceError):
            self.packet.context = self.context  # type: ignore[misc]

    def test_exactly_context_and_round_fields(self):
        self.assertEqual(
            {field.name for field in dataclasses.fields(self.packet)},
            {"context", "round_info"},
        )

    def test_packet_round_has_no_nonce_field(self):
        self.assertEqual(
            {field.name for field in dataclasses.fields(self.round_info)},
            {"message", "signer_ids", "nonce_commitments", "R", "challenge"},
        )
        self.assertEqual(
            {field.name for field in dataclasses.fields(self.context)},
            {
                "participant_ids",
                "threshold",
                "field_prime",
                "group_prime",
                "generator",
                "public_key",
                "verification_shares",
            },
        )


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.context = export_signing_public_context(self.key)
        self.round_info, _c, _n = make_round(self.key)
        self.packet = SigningRoundPacket(self.context, self.round_info)

    def test_encoding_is_deterministic_tagged_bytes(self):
        blob = encode_round_packet(self.packet)
        self.assertIsInstance(blob, bytes)
        self.assertTrue(blob.startswith(ROUND_PACKET_TAG))
        self.assertEqual(blob, encode_round_packet(self.packet))

    def test_decode_restores_equal_packet(self):
        blob = encode_round_packet(self.packet)
        restored = decode_round_packet(blob)
        self.assertIsInstance(restored, SigningRoundPacket)
        self.assertEqual(restored, self.packet)
        self.assertIsInstance(restored.context, SigningPublicContext)
        self.assertIsInstance(restored.round_info, SigningRound)
        self.assertIsInstance(restored.round_info.message, bytes)
        self.assertIsInstance(restored.round_info.signer_ids, tuple)
        self.assertIsInstance(restored.round_info.nonce_commitments, tuple)
        for commitment in restored.round_info.nonce_commitments:
            self.assertIsInstance(commitment, SigningNonceCommitment)

    def test_reencoding_is_byte_identical(self):
        blob = encode_round_packet(self.packet)
        self.assertEqual(encode_round_packet(decode_round_packet(blob)), blob)

    def test_empty_message_round_trips(self):
        packet = make_packet(self.context, message=b"")
        blob = encode_round_packet(packet)
        self.assertEqual(decode_round_packet(blob), packet)
        self.assertIs(verify_round_packet(decode_round_packet(blob), self.context), True)

    def test_threshold_one_round_trips(self):
        key = make_key((2, 5, 9), 1)
        context = export_signing_public_context(key)
        packet = make_packet(context, signer_ids=(5,))
        blob = encode_round_packet(packet)
        self.assertEqual(decode_round_packet(blob), packet)
        self.assertIs(verify_round_packet(decode_round_packet(blob), context), True)

    def test_identity_public_key_and_verification_shares_supported(self):
        identity = dataclasses.replace(
            self.context, public_key=1, verification_shares=(1, 1, 1)
        )
        packet = make_packet(identity)
        blob = encode_round_packet(packet)
        restored = decode_round_packet(blob)
        self.assertEqual(restored, packet)
        self.assertIs(verify_round_packet(restored, identity), True)

    def test_aggregate_R_equal_to_one_supported_when_commitments_multiply_to_it(self):
        inverse = pow(GENERATOR, -1, GROUP_PRIME)
        self.assertNotEqual(inverse, GENERATOR)
        commitments = (
            SigningNonceCommitment(signer_id=1, commitment=GENERATOR),
            SigningNonceCommitment(signer_id=2, commitment=inverse),
        )
        challenge = schnorr_challenge(
            MESSAGE,
            self.context.public_key,
            1,
            (1, 2),
            field_prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
        )
        round_info = SigningRound(
            message=MESSAGE,
            signer_ids=(1, 2),
            nonce_commitments=commitments,
            R=1,
            challenge=challenge,
        )
        packet = SigningRoundPacket(self.context, round_info)
        restored = decode_round_packet(encode_round_packet(packet))
        self.assertEqual(restored, packet)
        self.assertIs(verify_round_packet(restored, self.context), True)

    def test_structural_packet_with_mismatched_R_and_challenge_decodes(self):
        round_info = SigningRound(
            message=MESSAGE,
            signer_ids=self.round_info.signer_ids,
            nonce_commitments=self.round_info.nonce_commitments,
            R=1,
            challenge=0,
        )
        packet = SigningRoundPacket(self.context, round_info)
        restored = decode_round_packet(encode_round_packet(packet))
        self.assertEqual(restored, packet)
        self.assertIs(verify_round_packet(restored, self.context), False)


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.context = export_signing_public_context(self.key)
        self.round_info, _c, _n = make_round(self.key)
        self.packet = SigningRoundPacket(self.context, self.round_info)

    def _assert_type_error(self, packet):
        with self.assertRaises(TypeError):
            encode_round_packet(packet)

    def _assert_value_error(self, packet):
        with self.assertRaises(ValueError):
            encode_round_packet(packet)

    def test_wrong_top_level_types(self):
        self._assert_type_error("packet")
        self._assert_type_error(None)
        self._assert_type_error(SigningRoundPacket("context", self.round_info))
        self._assert_type_error(SigningRoundPacket(("context",), self.round_info))
        self._assert_type_error(SigningRoundPacket(object(), self.round_info))
        self._assert_type_error(SigningRoundPacket(self.context, "round"))
        self._assert_type_error(SigningRoundPacket(self.context, ("round",)))

    def test_bool_is_not_an_integer(self):
        self._assert_type_error(
            SigningRoundPacket(
                dataclasses.replace(self.context, threshold=True), self.round_info
            )
        )
        self._assert_type_error(
            SigningRoundPacket(
                dataclasses.replace(self.context, public_key=True), self.round_info
            )
        )
        self._assert_type_error(
            SigningRoundPacket(
                self.context, dataclasses.replace(self.round_info, R=True)
            )
        )

    def test_wrong_container_and_element_types(self):
        self._assert_type_error(
            SigningRoundPacket(
                dataclasses.replace(self.context, participant_ids=[1, 2, 3]),
                self.round_info,
            )
        )
        self._assert_type_error(
            SigningRoundPacket(
                self.context,
                dataclasses.replace(self.round_info, message="not bytes"),
            )
        )
        self._assert_type_error(
            SigningRoundPacket(
                self.context,
                dataclasses.replace(self.round_info, signer_ids=[1, 2]),
            )
        )
        self._assert_type_error(
            SigningRoundPacket(
                self.context,
                dataclasses.replace(self.round_info, nonce_commitments=("R_i", "R_i")),
            )
        )

    def test_context_value_errors(self):
        self._assert_value_error(
            SigningRoundPacket(
                dataclasses.replace(self.context, field_prime=2018), self.round_info
            )
        )
        self._assert_value_error(
            SigningRoundPacket(
                dataclasses.replace(self.context, generator=1), self.round_info
            )
        )
        self._assert_value_error(
            SigningRoundPacket(
                dataclasses.replace(self.context, generator=GROUP_PRIME - 1),
                self.round_info,
            )
        )
        self._assert_value_error(
            SigningRoundPacket(
                dataclasses.replace(
                    self.context,
                    participant_ids=(),
                    verification_shares=(),
                    threshold=1,
                ),
                self.round_info,
            )
        )
        self._assert_value_error(
            SigningRoundPacket(
                dataclasses.replace(self.context, threshold=0), self.round_info
            )
        )
        self._assert_value_error(
            SigningRoundPacket(
                dataclasses.replace(self.context, threshold=4), self.round_info
            )
        )
        self._assert_value_error(
            SigningRoundPacket(
                dataclasses.replace(
                    self.context, verification_shares=self.context.verification_shares[:2]
                ),
                self.round_info,
            )
        )
        self._assert_value_error(
            SigningRoundPacket(
                dataclasses.replace(self.context, public_key=0), self.round_info
            )
        )
        self._assert_value_error(
            SigningRoundPacket(
                dataclasses.replace(self.context, public_key=GROUP_PRIME),
                self.round_info,
            )
        )
        self._assert_value_error(
            SigningRoundPacket(
                dataclasses.replace(
                    self.context,
                    verification_shares=(GROUP_PRIME - 1,)
                    + self.context.verification_shares[1:],
                ),
                self.round_info,
            )
        )

    def _bare_round(self, signer_ids, commitments, R=2, challenge=0):
        return SigningRound(
            message=MESSAGE,
            signer_ids=signer_ids,
            nonce_commitments=tuple(commitments),
            R=R,
            challenge=challenge,
        )

    def test_round_value_errors(self):
        R_value = subgroup_element(11)
        # Signer outside the membership.
        self._assert_value_error(
            SigningRoundPacket(
                self.context,
                self._bare_round(
                    (1, 4),
                    (
                        SigningNonceCommitment(1, subgroup_element(11)),
                        SigningNonceCommitment(4, subgroup_element(12)),
                    ),
                ),
            )
        )
        # Fewer than threshold signers.
        self._assert_value_error(
            SigningRoundPacket(
                self.context,
                self._bare_round(
                    (1,), (SigningNonceCommitment(1, subgroup_element(11)),)
                ),
            )
        )
        # Duplicated and out-of-order ids.
        self._assert_value_error(
            SigningRoundPacket(
                self.context,
                self._bare_round(
                    (1, 1),
                    (
                        SigningNonceCommitment(1, subgroup_element(11)),
                        SigningNonceCommitment(1, subgroup_element(12)),
                    ),
                ),
            )
        )
        self._assert_value_error(
            SigningRoundPacket(
                self.context,
                self._bare_round(
                    (2, 1),
                    (
                        SigningNonceCommitment(2, subgroup_element(11)),
                        SigningNonceCommitment(1, subgroup_element(12)),
                    ),
                ),
            )
        )
        # Missing commitment.
        self._assert_value_error(
            SigningRoundPacket(
                self.context,
                self._bare_round(
                    (1, 2), (SigningNonceCommitment(1, subgroup_element(11)),)
                ),
            )
        )
        # Identity, out-of-range and subgroup-invalid commitments.
        for bad_value in (0, 1, GROUP_PRIME, GROUP_PRIME - 1):
            self._assert_value_error(
                SigningRoundPacket(
                    self.context,
                    self._bare_round(
                        (1, 2),
                        (
                            SigningNonceCommitment(1, bad_value),
                            SigningNonceCommitment(2, subgroup_element(12)),
                        ),
                    ),
                )
            )
        # Duplicate commitment values.
        self._assert_value_error(
            SigningRoundPacket(
                self.context,
                self._bare_round(
                    (1, 2),
                    (
                        SigningNonceCommitment(1, R_value),
                        SigningNonceCommitment(2, R_value),
                    ),
                ),
            )
        )
        # Misaligned commitment tuple (swapped signer ids).
        self._assert_value_error(
            SigningRoundPacket(
                self.context,
                self._bare_round(
                    (1, 2),
                    (
                        SigningNonceCommitment(2, subgroup_element(11)),
                        SigningNonceCommitment(1, subgroup_element(12)),
                    ),
                ),
            )
        )
        # Out-of-range aggregate R and challenge.
        self._assert_value_error(
            SigningRoundPacket(
                self.context, dataclasses.replace(self.round_info, R=0)
            )
        )
        self._assert_value_error(
            SigningRoundPacket(
                self.context, dataclasses.replace(self.round_info, R=GROUP_PRIME)
            )
        )
        self._assert_value_error(
            SigningRoundPacket(
                self.context, dataclasses.replace(self.round_info, challenge=FIELD_PRIME)
            )
        )
        self._assert_value_error(
            SigningRoundPacket(
                self.context, dataclasses.replace(self.round_info, challenge=-1)
            )
        )


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.context = export_signing_public_context(self.key)
        self.blob = encode_round_packet(make_packet(self.context))

    def test_non_bytes_inputs_raise_type_error(self):
        for bad in ("bytes", bytearray(b"1234"), None, 42, [1, 2]):
            with self.assertRaises(TypeError, msg=bad):
                decode_round_packet(bad)

    def test_bad_tag(self):
        with self.assertRaises(ValueError):
            decode_round_packet(b"thresholdsign/signing-round-packet/v0" + self.blob[len(ROUND_PACKET_TAG):])
        with self.assertRaises(ValueError):
            decode_round_packet(b"")
        with self.assertRaises(ValueError):
            decode_round_packet(ROUND_PACKET_TAG[:-1])
        with self.assertRaises(ValueError):
            decode_round_packet(self.blob[: len(ROUND_PACKET_TAG)])

    def test_truncation_at_every_region(self):
        for cut in (
            len(ROUND_PACKET_TAG) + 1,
            len(ROUND_PACKET_TAG) + 5,
            self.blob.index(MESSAGE) - 1,
            self.blob.index(MESSAGE),
            self.blob.index(MESSAGE) + len(MESSAGE) + 1,
            len(self.blob) - 1,
            len(self.blob) // 2,
        ):
            with self.assertRaises(ValueError, msg=cut):
                decode_round_packet(self.blob[:cut])

    def test_trailing_bytes_rejected(self):
        with self.assertRaises(ValueError):
            decode_round_packet(self.blob + b"\x00")

    def test_noncanonical_integer_rejected(self):
        # The threshold varint (length 1, body 0x02) sits right after the tag;
        # rewrite it as length 2 with a forbidden leading zero.
        offset = len(ROUND_PACKET_TAG)
        self.assertEqual(self.blob[offset:offset + 5], b"\x00\x00\x00\x01\x02")
        mutated = (
            self.blob[:offset] + b"\x00\x00\x00\x02\x00\x02" + self.blob[offset + 5:]
        )
        with self.assertRaises(ValueError):
            decode_round_packet(mutated)

    def test_zero_participant_and_signer_counts_rejected(self):
        offset = self.blob.index(b"\x00\x00\x00\x03")
        mutated = self.blob[:offset] + b"\x00\x00\x00\x00" + self.blob[offset + 4:]
        with self.assertRaises(ValueError):
            decode_round_packet(mutated)

        signer_count_offset = self.blob.index(MESSAGE) + len(MESSAGE)
        self.assertEqual(
            self.blob[signer_count_offset:signer_count_offset + 4],
            b"\x00\x00\x00\x02",
        )
        mutated = (
            self.blob[:signer_count_offset]
            + b"\x00\x00\x00\x00"
            + self.blob[signer_count_offset + 4:]
        )
        with self.assertRaises(ValueError):
            decode_round_packet(mutated)

    def test_message_length_mismatch_rejected(self):
        length_offset = self.blob.index(MESSAGE) - 4
        declared = int.from_bytes(
            self.blob[length_offset:length_offset + 4], "big"
        )
        self.assertEqual(declared, len(MESSAGE))
        mutated = (
            self.blob[:length_offset]
            + (declared + 1).to_bytes(4, "big")
            + self.blob[length_offset + 4:]
        )
        with self.assertRaises(ValueError):
            decode_round_packet(mutated)

    def test_flipped_bytes_never_decode_to_the_same_packet(self):
        for position in (
            len(ROUND_PACKET_TAG) + 4,  # threshold body
            self.blob.index(MESSAGE),
            len(self.blob) - 1,  # challenge body
            len(self.blob) - 6,  # R region
        ):
            mutated = (
                self.blob[:position]
                + bytes([self.blob[position] ^ 0x01])
                + self.blob[position + 1:]
            )
            try:
                decoded = decode_round_packet(mutated)
            except ValueError:
                continue
            # If the flip still parses, the result must be a different,
            # still-canonical packet.
            self.assertEqual(encode_round_packet(decoded), mutated)
            self.assertNotEqual(decoded, decode_round_packet(self.blob))


class VerifyRoundPacketTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.context = export_signing_public_context(self.key)
        self.packet = make_packet(self.context)

    def test_valid_packet_verifies(self):
        self.assertIs(verify_round_packet(self.packet, self.context), True)
        self.assertIs(
            verify_round_packet(decode_round_packet(
                encode_round_packet(self.packet)
            ), self.context),
            True,
        )

    def test_structure_is_checked_before_trusted_context(self):
        with self.assertRaises(TypeError):
            verify_round_packet("packet", self.context)
        with self.assertRaises(TypeError):
            verify_round_packet(self.packet, "context")
        with self.assertRaises(TypeError):
            verify_round_packet(self.packet, None)
        bad_context = dataclasses.replace(self.context, threshold=True)
        with self.assertRaises(TypeError):
            verify_round_packet(self.packet, bad_context)
        bad_context = dataclasses.replace(self.context, field_prime=2018)
        with self.assertRaises(ValueError):
            verify_round_packet(self.packet, bad_context)
        bad_packet = SigningRoundPacket(
            self.context, dataclasses.replace(self.packet.round_info, R=GROUP_PRIME)
        )
        with self.assertRaises(ValueError):
            verify_round_packet(bad_packet, self.context)
        misaligned = SigningRound(
            message=MESSAGE,
            signer_ids=(1, 2),
            nonce_commitments=tuple(
                reversed(self.packet.round_info.nonce_commitments)
            ),
            R=self.packet.round_info.R,
            challenge=self.packet.round_info.challenge,
        )
        with self.assertRaises(ValueError):
            verify_round_packet(
                SigningRoundPacket(self.context, misaligned), self.context
            )

    def _tampered_packet(self, **context_changes):
        return SigningRoundPacket(
            dataclasses.replace(self.context, **context_changes),
            self.packet.round_info,
        )

    def test_context_field_mismatches_return_false(self):
        # Different but still structurally legal public key.
        other_key = subgroup_element(7)
        self.assertNotEqual(other_key, self.context.public_key)
        self.assertIs(
            verify_round_packet(
                self._tampered_packet(public_key=other_key), self.context
            ),
            False,
        )
        # Swapped verification shares stay legal subgroup elements.
        shares = self.context.verification_shares
        self.assertIs(
            verify_round_packet(
                self._tampered_packet(
                    verification_shares=(shares[1], shares[0], shares[2])
                ),
                self.context,
            ),
            False,
        )
        # Participant (3) -> (4): signers (1, 2) stay members, share list
        # merely re-labelled.
        self.assertIs(
            verify_round_packet(
                self._tampered_packet(
                    participant_ids=(1, 2, 4),
                    verification_shares=(shares[0], shares[1], shares[2]),
                ),
                self.context,
            ),
            False,
        )
        # threshold 2 -> 1 with two signers stays legal.
        self.assertIs(
            verify_round_packet(
                self._tampered_packet(threshold=1), self.context
            ),
            False,
        )
        # 256 is another valid order-2017 generator in the same group.
        self.assertIs(
            verify_round_packet(
                self._tampered_packet(generator=BLINDING_GENERATOR), self.context
            ),
            False,
        )

    def test_round_tampering_returns_false(self):
        round_info = self.packet.round_info
        tamperings = []
        tamperings.append(dataclasses.replace(round_info, message=b"tampered message"))
        other_R = round_info.R + 2
        if other_R >= GROUP_PRIME:
            other_R = 2
        tamperings.append(dataclasses.replace(round_info, R=other_R))
        other_c = 0 if round_info.challenge != 0 else 1
        tamperings.append(dataclasses.replace(round_info, challenge=other_c))
        used = {c.commitment for c in round_info.nonce_commitments}
        exponent = 41
        replacement = subgroup_element(exponent)
        while replacement in used:
            exponent += 1
            replacement = subgroup_element(exponent)
        commitments = (
            SigningNonceCommitment(1, replacement),
            round_info.nonce_commitments[1],
        )
        tamperings.append(
            dataclasses.replace(round_info, nonce_commitments=commitments)
        )
        for tampered in tamperings:
            packet = SigningRoundPacket(self.context, tampered)
            # Every tampered packet is itself structurally legal and decodes.
            self.assertEqual(
                decode_round_packet(encode_round_packet(packet)), packet
            )
            self.assertIs(
                verify_round_packet(packet, self.context), False
            )

    def test_packet_context_is_not_identity_authentication(self):
        # The receiver trusts a different but self-consistent context; the
        # packet's embedded context must not vouch for itself.
        other = make_key(seed_base=100)
        other_context = export_signing_public_context(other)
        self.assertNotEqual(other_context.public_key, self.context.public_key)
        self.assertIs(verify_round_packet(self.packet, other_context), False)


class RefreshReshareStalenessTest(unittest.TestCase):
    def _refresh(self, key):
        contributions = [
            create_refresh(pid, key, randbelow=fixed_random(pid + 100))
            for pid in key.result.participant_ids
        ]
        outcome = refresh(contributions, key)
        self.assertIsInstance(outcome, type(key))
        return outcome

    def test_old_packet_fails_against_refreshed_context_even_with_same_public_key(self):
        key = make_key()
        context = export_signing_public_context(key)
        old_packet = make_packet(context)
        self.assertIs(verify_round_packet(old_packet, context), True)

        refreshed = self._refresh(key)
        new_context = export_signing_public_context(refreshed)
        self.assertEqual(new_context.public_key, context.public_key)
        self.assertNotEqual(
            new_context.verification_shares, context.verification_shares
        )
        self.assertIs(verify_round_packet(old_packet, new_context), False)

        # A packet minted under the refreshed context verifies and works.
        new_round, _c, new_nonces = make_round(refreshed)
        new_packet = SigningRoundPacket(new_context, new_round)
        restored = decode_round_packet(encode_round_packet(new_packet))
        self.assertIs(verify_round_packet(restored, new_context), True)
        shares = make_shares(refreshed, restored.round_info, new_nonces)
        signature = aggregate_signature(shares, restored.round_info, new_context)
        self.assertTrue(
            verify_signature(
                MESSAGE,
                signature,
                new_context.public_key,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            )
        )

    def test_old_packet_fails_against_reshared_context_with_same_public_key(self):
        key = make_key()
        context = export_signing_public_context(key)
        old_packet = make_packet(context)

        dealers = (2, 3)
        members = (2, 3, 4)
        contributions = [
            create_reshare(
                dealer,
                secret_share_of(key, dealer),
                dealers,
                members,
                2,
                key,
                rng=fixed_random(dealer + 100),
            )
            for dealer in dealers
        ]
        reshared = reshare(contributions, dealers, key)
        self.assertIsInstance(reshared, type(key))
        new_context = export_signing_public_context(reshared)
        self.assertEqual(new_context.participant_ids, members)
        self.assertEqual(new_context.public_key, context.public_key)
        self.assertIs(verify_round_packet(old_packet, new_context), False)

        new_round, _c, new_nonces = make_round(reshared, signer_ids=(2, 4))
        new_packet = SigningRoundPacket(new_context, new_round)
        self.assertIs(
            verify_round_packet(
                decode_round_packet(encode_round_packet(new_packet)), new_context
            ),
            True,
        )
        shares = make_shares(reshared, new_round, new_nonces)
        signature = aggregate_signature(shares, new_packet.round_info, new_context)
        self.assertTrue(
            verify_signature(
                MESSAGE,
                signature,
                new_context.public_key,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            )
        )


class EndToEndTest(unittest.TestCase):
    def test_decoded_packet_feeds_existing_share_verification_and_aggregation(self):
        key = make_key()
        context = export_signing_public_context(key)
        round_info, _commitments, nonces = make_round(key)
        packet = SigningRoundPacket(context, round_info)
        restored = decode_round_packet(encode_round_packet(packet))
        self.assertIs(verify_round_packet(restored, context), True)

        shares = make_shares(key, round_info, nonces)
        for share in shares:
            self.assertIs(
                verify_signature_share(share, restored.round_info, context), True
            )
            self.assertIs(
                verify_signature_share(share, restored.round_info, restored.context),
                True,
            )

        signature_from_packet = aggregate_signature(
            list(reversed(shares)), restored.round_info, context
        )
        signature_from_original = aggregate_signature(shares, round_info, key)
        self.assertEqual(signature_from_packet, signature_from_original)
        self.assertTrue(
            verify_signature(
                MESSAGE,
                signature_from_packet,
                context.public_key,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            )
        )

    def test_tampered_share_still_rejected_through_decoded_packet(self):
        key = make_key()
        context = export_signing_public_context(key)
        round_info, _commitments, nonces = make_round(key)
        restored = decode_round_packet(
            encode_round_packet(SigningRoundPacket(context, round_info))
        )
        shares = make_shares(key, round_info, nonces)
        bad = dataclasses.replace(shares[0], z=(shares[0].z + 1) % FIELD_PRIME)
        self.assertIs(
            verify_signature_share(bad, restored.round_info, context), False
        )


if __name__ == "__main__":
    unittest.main()
