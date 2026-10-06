"""Tests for the canonical signing public context transport encoding:
encode_signing_public_context / decode_signing_public_context."""

import dataclasses
import unittest

from thresholdsign import (
    AggregateSignature,
    LocalDKGPacket,
    DKGReceivedShare,
    SigningDKGResult,
    SigningPublicContext,
    SigningRoundPacket,
    aggregate_local_dkg,
    aggregate_signature,
    aggregate_signing_dkg,
    create_refresh,
    create_reshare,
    create_signature_share,
    create_signing_contribution,
    create_signing_nonce_commitment,
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
    verify_signature_share,
    verify_signing_public_context,
)

# Same toy group as the signing tests: 8069 = 4 * 2017 + 1 is prime, 16 and
# 256 = 16 ** 2 are distinct generators of the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

MESSAGE = b"public context codec test message"

WIRE_TAG = b"thresholdsign/signing-public-context/v1"
ROUND_PACKET_TAG = b"thresholdsign/round-packet/v1"


def fixed_random(seed=1):
    """Deterministic stand-in for secrets.randbelow (same LCG as signing tests)."""
    state = {"value": seed}

    def randbelow(upper: int) -> int:
        state["value"] = (
            state["value"] * 6364136223846793005 + 1442695040888963407
        ) % upper
        return state["value"]

    return randbelow


def make_contributions(participant_ids=(1, 2, 3), threshold=2, seed_base=0):
    return [
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


def make_key(participant_ids=(1, 2, 3), threshold=2, seed_base=0):
    outcome = aggregate_signing_dkg(
        make_contributions(participant_ids, threshold, seed_base)
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
            signer_id, secret_share_of(key, signer_id), nonces[signer_id],
            round_info, key,
        )
        for signer_id in round_info.signer_ids
    ]


class EncodeTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.context = export_signing_public_context(self.key)

    def test_starts_with_tag(self):
        self.assertTrue(
            encode_signing_public_context(self.context).startswith(WIRE_TAG)
        )

    def test_returns_bytes(self):
        self.assertIsInstance(encode_signing_public_context(self.context), bytes)

    def test_deterministic(self):
        self.assertEqual(
            encode_signing_public_context(self.context),
            encode_signing_public_context(self.context),
        )

    def test_matches_round_packet_context_section(self):
        round_info, _commitments, _nonces = make_round(self.context)
        packet = SigningRoundPacket(context=self.context, round_info=round_info)
        packet_bytes = encode_round_packet(packet)
        context_bytes = encode_signing_public_context(self.context)
        section = context_bytes[len(WIRE_TAG):]
        self.assertEqual(
            packet_bytes[len(ROUND_PACKET_TAG):len(ROUND_PACKET_TAG) + len(section)],
            section,
        )

    def test_directly_constructed_equal_context_encodes_identically(self):
        direct = SigningPublicContext(
            participant_ids=self.context.participant_ids,
            threshold=self.context.threshold,
            field_prime=self.context.field_prime,
            group_prime=self.context.group_prime,
            generator=self.context.generator,
            public_key=self.context.public_key,
            verification_shares=self.context.verification_shares,
        )
        self.assertEqual(
            encode_signing_public_context(direct),
            encode_signing_public_context(self.context),
        )

    def test_single_member_threshold_one_identity_values(self):
        context = SigningPublicContext(
            participant_ids=(1,),
            threshold=1,
            field_prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            public_key=1,
            verification_shares=(1,),
        )
        encoded = encode_signing_public_context(context)
        self.assertEqual(decode_signing_public_context(encoded), context)

    def test_inconsistent_but_structural_context_encodes(self):
        context = dataclasses.replace(
            self.context, public_key=self.context.verification_shares[0]
        )
        self.assertFalse(verify_signing_public_context(context))
        self.assertEqual(
            decode_signing_public_context(encode_signing_public_context(context)),
            context,
        )


class EncodeTypeErrorTest(unittest.TestCase):
    def setUp(self):
        self.context = export_signing_public_context(make_key())

    def test_non_context_argument(self):
        for bad in (None, "context", b"bytes", 42, make_key()):
            with self.assertRaises(TypeError):
                encode_signing_public_context(bad)

    def test_field_type_errors(self):
        for field, value in (
            ("participant_ids", [1, 2, 3]),
            ("participant_ids", (1, 2, True)),
            ("threshold", True),
            ("field_prime", 1.5),
            ("group_prime", "8069"),
            ("generator", None),
            ("public_key", False),
            ("verification_shares", [1, 2, 3]),
            ("verification_shares", (1, 2, True)),
        ):
            with self.assertRaises(TypeError, msg=(field, value)):
                encode_signing_public_context(
                    dataclasses.replace(self.context, **{field: value})
                )


class EncodeValueErrorTest(unittest.TestCase):
    def setUp(self):
        self.context = export_signing_public_context(make_key())

    def test_field_value_errors(self):
        for field, value in (
            ("participant_ids", ()),
            ("participant_ids", (1, 1, 2)),
            ("participant_ids", (2, 1, 3)),
            ("participant_ids", (0, 1, 2)),
            ("participant_ids", (1, 2, FIELD_PRIME)),
            ("threshold", 0),
            ("threshold", 4),
            ("verification_shares", (1, 2)),
            ("verification_shares", (1, 2, 3, 4)),
            ("field_prime", 15),
            ("group_prime", 15),
            ("generator", 0),
            ("generator", 1),
            ("public_key", 0),
            ("public_key", GROUP_PRIME),
            ("public_key", 5),
            ("verification_shares", (1, 2, 3)),
        ):
            with self.assertRaises(ValueError, msg=(field, value)):
                encode_signing_public_context(
                    dataclasses.replace(self.context, **{field: value})
                )


class DecodeTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.context = export_signing_public_context(self.key)
        self.encoded = encode_signing_public_context(self.context)

    def test_round_trip(self):
        decoded = decode_signing_public_context(self.encoded)
        self.assertEqual(decoded, self.context)
        self.assertIsInstance(decoded, SigningPublicContext)

    def test_decoded_reencodes_byte_identically(self):
        decoded = decode_signing_public_context(self.encoded)
        self.assertEqual(encode_signing_public_context(decoded), self.encoded)

    def test_non_bytes_argument(self):
        for bad in ("str", bytearray(self.encoded), memoryview(self.encoded), None, 42):
            with self.assertRaises(TypeError):
                decode_signing_public_context(bad)

    def test_bad_tag(self):
        with self.assertRaises(ValueError):
            decode_signing_public_context(b"thresholdsign/other/v1" + self.encoded)
        with self.assertRaises(ValueError):
            decode_signing_public_context(self.encoded[1:])

    def test_truncation(self):
        for cut in (len(WIRE_TAG), len(self.encoded) // 2, len(self.encoded) - 1):
            with self.assertRaises(ValueError, msg=cut):
                decode_signing_public_context(self.encoded[:cut])

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_signing_public_context(self.encoded + b"\x00")

    def test_non_minimal_integer(self):
        # Participant id 1 is encoded as 00 00 00 01 01; a two-byte body
        # 00 01 carries a forbidden leading zero.
        marker = b"\x00\x00\x00\x01\x01"
        index = self.encoded.index(marker)
        mutated = (
            self.encoded[:index]
            + b"\x00\x00\x00\x02\x00\x01"
            + self.encoded[index + len(marker):]
        )
        with self.assertRaises(ValueError):
            decode_signing_public_context(mutated)

    def test_count_content_mismatch(self):
        # Bump the participant count from 3 to 4 without adding an entry.
        bumped = (
            self.encoded[:len(WIRE_TAG)]
            + (4).to_bytes(4, "big")
            + self.encoded[len(WIRE_TAG) + 4:]
        )
        with self.assertRaises(ValueError):
            decode_signing_public_context(bumped)

    def test_structurally_invalid_values_rejected(self):
        # Threshold 0 is structurally illegal: hand-encode it by rewriting
        # the threshold varint 00 00 00 01 02 to 00 00 00 01 00.
        marker = b"\x00\x00\x00\x01\x02"
        index = self.encoded.index(marker)
        mutated = (
            self.encoded[:index]
            + b"\x00\x00\x00\x01\x00"
            + self.encoded[index + len(marker):]
        )
        with self.assertRaises(ValueError):
            decode_signing_public_context(mutated)

    def test_decoded_context_verifies_consistency(self):
        decoded = decode_signing_public_context(self.encoded)
        self.assertTrue(verify_signing_public_context(decoded))

    def test_decoded_context_matches_original_everywhere(self):
        decoded = decode_signing_public_context(self.encoded)
        round_original, commitments, nonces = make_round(self.context, seed=50)
        round_decoded = create_signing_round(
            MESSAGE, (1, 2), commitments, decoded
        )
        self.assertEqual(round_original, round_decoded)
        shares = make_shares(self.key, round_original, nonces)
        for share in shares:
            self.assertEqual(
                verify_signature_share(share, round_original, self.context),
                verify_signature_share(share, round_original, decoded),
            )
        signature_original = aggregate_signature(shares, round_original, self.context)
        signature_decoded = aggregate_signature(shares, round_original, decoded)
        self.assertIsInstance(signature_decoded, AggregateSignature)
        self.assertEqual(signature_original, signature_decoded)


class ContextSourceTest(unittest.TestCase):
    """Contexts from every source round-trip with all public fields intact."""

    def round_trip(self, context):
        decoded = decode_signing_public_context(encode_signing_public_context(context))
        self.assertEqual(decoded, context)
        return decoded

    def test_local_dkg_context(self):
        packets = [packet_for(c, 1) for c in make_contributions()]
        _share, _blinding, context = aggregate_local_dkg(1, packets)
        self.assertIsInstance(context, SigningPublicContext)
        self.round_trip(context)

    def test_refresh_context(self):
        key = make_key()
        contributions = [
            create_refresh(pid, key, randbelow=fixed_random(300 + pid))
            for pid in (1, 2, 3)
        ]
        refreshed = refresh(contributions, key)
        self.assertIsInstance(refreshed, SigningDKGResult)
        context = export_signing_public_context(refreshed)
        decoded = self.round_trip(context)
        self.assertEqual(decoded.public_key, key.public_key)
        self.assertTrue(verify_signing_public_context(decoded))

    def test_refresh_local_context(self):
        key = make_key()
        context = export_signing_public_context(key)
        share, blinding, _ = aggregate_local_dkg(
            1, [packet_for(c, 1) for c in make_contributions()]
        )
        contributions = [
            create_refresh(pid, key, randbelow=fixed_random(300 + pid))
            for pid in (1, 2, 3)
        ]
        outcome = refresh_local(
            1, share, blinding, key.result.commitment, context,
            [packet_for(c, 1) for c in contributions],
        )
        self.round_trip(outcome[3])

    def test_reshare_context(self):
        key = make_key()
        dealers, members = (2, 3), (2, 3, 4)
        contributions = [
            create_reshare(
                dealer, secret_share_of(key, dealer), dealers, members, 2, key,
                rng=fixed_random(dealer + 100),
            )
            for dealer in dealers
        ]
        reshared = reshare(contributions, dealers, key)
        self.assertIsInstance(reshared, SigningDKGResult)
        context = export_signing_public_context(reshared)
        decoded = self.round_trip(context)
        self.assertEqual(decoded.participant_ids, members)
        self.assertEqual(decoded.public_key, key.public_key)
        self.assertTrue(verify_signing_public_context(decoded))

    def test_reshare_local_context(self):
        key = make_key()
        context = export_signing_public_context(key)
        dealers, members = (2, 3), (2, 3, 4)
        contributions = [
            create_reshare(
                dealer, secret_share_of(key, dealer), dealers, members, 2, key,
                rng=fixed_random(dealer + 100),
            )
            for dealer in dealers
        ]
        outcome = reshare_local(
            2, [packet_for(c, 2) for c in contributions], dealers, context,
            key.result.commitment,
        )
        decoded = self.round_trip(outcome[3])
        self.assertEqual(decoded.participant_ids, members)

    def test_old_round_packet_verdict_preserved_after_round_trip(self):
        key = make_key()
        context = export_signing_public_context(key)
        contributions = [
            create_refresh(pid, key, randbelow=fixed_random(300 + pid))
            for pid in (1, 2, 3)
        ]
        refreshed = refresh(contributions, key)
        refreshed_context = export_signing_public_context(refreshed)
        decoded = self.round_trip(refreshed_context)
        round_info, _commitments, _nonces = make_round(context, seed=10)
        packet = SigningRoundPacket(context=refreshed_context, round_info=round_info)
        self.assertEqual(
            verify_round_packet(packet, refreshed_context),
            verify_round_packet(packet, decoded),
        )


if __name__ == "__main__":
    unittest.main()
