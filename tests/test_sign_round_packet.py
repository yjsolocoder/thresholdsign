"""Tests for sign_round_packet, the packet-based signature-share entry point."""

import dataclasses
import unittest

from thresholdsign import (
    SigningNonceCommitment,
    SigningPublicContext,
    SigningRound,
    SigningRoundPacket,
    SignatureShare,
    aggregate_signature,
    create_refresh,
    create_signature_share,
    decode_round_packet,
    encode_round_packet,
    export_signing_public_context,
    refresh,
    sign_round_packet,
    schnorr_challenge,
    verify_round_packet,
    verify_signature,
    verify_signature_share,
)
from tests.test_signing import (
    FIELD_PRIME,
    GENERATOR,
    GROUP_PRIME,
    MESSAGE,
    fixed_random,
    make_round,
    make_signing_dkg,
)
from tests.test_signing_round_packet import make_packet, secret_share_of


def make_inputs(signer_id=1, message=MESSAGE):
    dkg, context, round_info, _commitments, nonces, packet = make_packet(
        message=message
    )
    secret_share = secret_share_of(dkg, signer_id)
    return dkg, context, round_info, nonces, packet, secret_share


class SignRoundPacketTest(unittest.TestCase):
    def test_matches_create_signature_share_by_value(self):
        dkg, context, round_info, nonces, packet, secret_share = make_inputs()
        for signer_id in round_info.signer_ids:
            share = sign_round_packet(
                signer_id,
                secret_share_of(dkg, signer_id),
                nonces[signer_id],
                packet,
                context,
                MESSAGE,
            )
            reference = create_signature_share(
                signer_id,
                secret_share_of(dkg, signer_id),
                nonces[signer_id],
                round_info,
                dkg,
            )
            self.assertEqual(share, reference)
            self.assertIsInstance(share, SignatureShare)

    def test_share_verifies_and_aggregates_into_a_valid_signature(self):
        dkg, context, round_info, nonces, packet, _s = make_inputs()
        shares = [
            sign_round_packet(
                signer_id,
                secret_share_of(dkg, signer_id),
                nonces[signer_id],
                packet,
                context,
                MESSAGE,
            )
            for signer_id in round_info.signer_ids
        ]
        for share in shares:
            self.assertTrue(verify_signature_share(share, round_info, context))
        signature = aggregate_signature(shares, round_info, context)
        self.assertTrue(
            verify_signature(
                MESSAGE,
                signature,
                context.public_key,
                group_prime=context.group_prime,
                generator=context.generator,
                prime=context.field_prime,
            )
        )

    def test_decoded_and_directly_built_packets_behave_identically(self):
        dkg, context, _r, nonces, packet, secret_share = make_inputs()
        decoded = decode_round_packet(encode_round_packet(packet))
        self.assertEqual(packet, decoded)
        direct = SigningRoundPacket(
            context=SigningPublicContext(
                participant_ids=context.participant_ids,
                threshold=context.threshold,
                field_prime=context.field_prime,
                group_prime=context.group_prime,
                generator=context.generator,
                public_key=context.public_key,
                verification_shares=context.verification_shares,
            ),
            round_info=packet.round_info,
        )
        expected = sign_round_packet(1, secret_share, nonces[1], packet, context, MESSAGE)
        self.assertEqual(
            sign_round_packet(1, secret_share, nonces[1], decoded, context, MESSAGE),
            expected,
        )
        self.assertEqual(
            sign_round_packet(1, secret_share, nonces[1], direct, context, MESSAGE),
            expected,
        )

    def test_deterministic_and_inputs_untouched(self):
        _dkg, context, _r, nonces, packet, secret_share = make_inputs()
        snapshot = encode_round_packet(packet)
        first = sign_round_packet(1, secret_share, nonces[1], packet, context, MESSAGE)
        second = sign_round_packet(1, secret_share, nonces[1], packet, context, MESSAGE)
        self.assertEqual(first, second)
        self.assertEqual(encode_round_packet(packet), snapshot)

    def test_empty_message_and_threshold_one(self):
        dkg = make_signing_dkg((1, 2, 3), 1)
        context = export_signing_public_context(dkg)
        round_info, _c, nonces = make_round(dkg, (2,), b"")
        packet = SigningRoundPacket(context=context, round_info=round_info)
        share = sign_round_packet(
            2, secret_share_of(dkg, 2), nonces[2], packet, context, b""
        )
        self.assertEqual(
            share,
            create_signature_share(
                2, secret_share_of(dkg, 2), nonces[2], round_info, dkg
            ),
        )
        self.assertTrue(verify_signature_share(share, round_info, context))

    def test_zero_secret_share_and_identity_elements(self):
        # Identity public key / verification shares and an aggregate
        # commitment of R = 1 stay legal, exactly as at the other entries.
        commitments = (
            SigningNonceCommitment(1, pow(GENERATOR, 5, GROUP_PRIME)),
            SigningNonceCommitment(2, pow(GENERATOR, FIELD_PRIME - 5, GROUP_PRIME)),
        )
        self.assertEqual(
            commitments[0].commitment * commitments[1].commitment % GROUP_PRIME, 1
        )
        context = SigningPublicContext(
            participant_ids=(1, 2),
            threshold=1,
            field_prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            public_key=1,
            verification_shares=(1, 1),
        )
        message = b"identity elements"
        challenge = schnorr_challenge(
            message, 1, 1, (1, 2), field_prime=FIELD_PRIME, group_prime=GROUP_PRIME
        )
        round_info = SigningRound(
            message=message,
            signer_ids=(1, 2),
            nonce_commitments=commitments,
            R=1,
            challenge=challenge,
        )
        packet = SigningRoundPacket(context=context, round_info=round_info)
        self.assertTrue(verify_round_packet(packet, context))
        share = sign_round_packet(1, 0, 5, packet, context, message)
        self.assertTrue(verify_signature_share(share, round_info, context))
        other = sign_round_packet(
            2, 0, FIELD_PRIME - 5, packet, context, message
        )
        signature = aggregate_signature((share, other), round_info, context)
        self.assertTrue(
            verify_signature(
                message,
                signature,
                1,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
                prime=FIELD_PRIME,
            )
        )

    def test_context_field_mismatch_raises_value_error(self):
        _dkg, context, _r, nonces, packet, secret_share = make_inputs()
        for field, value in (
            ("participant_ids", (1, 2, 3, 4)),
            ("threshold", 1),
            ("field_prime", FIELD_PRIME + 2),
            ("group_prime", GROUP_PRIME + 2),
            ("generator", 256),
            ("public_key", pow(GENERATOR, 3, GROUP_PRIME)),
            ("verification_shares", tuple(reversed(context.verification_shares))),
        ):
            tampered_context = dataclasses.replace(context, **{field: value})
            packet = SigningRoundPacket(
                context=tampered_context, round_info=packet.round_info
            )
            with self.assertRaises(ValueError, msg=field):
                sign_round_packet(
                    1, secret_share, nonces[1], packet, context, MESSAGE
                )

    def test_refreshed_context_rejects_old_packet_even_with_same_key(self):
        dkg = make_signing_dkg()
        old_context = export_signing_public_context(dkg)
        round_info, _c, nonces = make_round(dkg, (1, 2), MESSAGE)
        old_packet = SigningRoundPacket(context=old_context, round_info=round_info)

        contributions = [
            create_refresh(pid, dkg, randbelow=fixed_random(pid + 100))
            for pid in dkg.result.participant_ids
        ]
        refreshed = refresh(contributions, dkg)
        new_context = export_signing_public_context(refreshed)
        self.assertEqual(new_context.public_key, old_context.public_key)
        self.assertNotEqual(new_context, old_context)
        with self.assertRaises(ValueError):
            sign_round_packet(
                1,
                secret_share_of(refreshed, 1),
                nonces[1],
                old_packet,
                new_context,
                MESSAGE,
            )

    def test_message_mismatch_raises_even_with_recomputed_challenge(self):
        _dkg, context, round_info, nonces, packet, secret_share = make_inputs()
        # Different expected message than the packet carries.
        with self.assertRaises(ValueError):
            sign_round_packet(
                1, secret_share, nonces[1], packet, context, b"forged message"
            )
        # Rebuild the packet over a modified message with a fully legal
        # recomputed R and challenge: the expected-message check still
        # rejects it when the signer did not agree to that message.
        forged_message = b"forged message"
        challenge = schnorr_challenge(
            forged_message,
            context.public_key,
            round_info.R,
            round_info.signer_ids,
            field_prime=context.field_prime,
            group_prime=context.group_prime,
        )
        forged_round = SigningRound(
            message=forged_message,
            signer_ids=round_info.signer_ids,
            nonce_commitments=round_info.nonce_commitments,
            R=round_info.R,
            challenge=challenge,
        )
        forged_packet = SigningRoundPacket(context=context, round_info=forged_round)
        self.assertTrue(verify_round_packet(forged_packet, context))
        with self.assertRaises(ValueError):
            sign_round_packet(
                1, secret_share, nonces[1], forged_packet, context, MESSAGE
            )

    def test_tampered_product_or_challenge_raises(self):
        _dkg, context, round_info, nonces, packet, secret_share = make_inputs()
        bad_r = SigningRoundPacket(
            context=context,
            round_info=SigningRound(
                message=round_info.message,
                signer_ids=round_info.signer_ids,
                nonce_commitments=round_info.nonce_commitments,
                R=(round_info.R % (GROUP_PRIME - 1)) + 1,
                challenge=round_info.challenge,
            ),
        )
        with self.assertRaises(ValueError):
            sign_round_packet(1, secret_share, nonces[1], bad_r, context, MESSAGE)
        bad_challenge = SigningRoundPacket(
            context=context,
            round_info=SigningRound(
                message=round_info.message,
                signer_ids=round_info.signer_ids,
                nonce_commitments=round_info.nonce_commitments,
                R=round_info.R,
                challenge=(round_info.challenge + 1) % FIELD_PRIME,
            ),
        )
        with self.assertRaises(ValueError):
            sign_round_packet(
                1, secret_share, nonces[1], bad_challenge, context, MESSAGE
            )

    def test_signer_membership_checks(self):
        _dkg, context, _r, nonces, packet, secret_share = make_inputs()
        # Signer 3 is a context participant but not in this round.
        with self.assertRaises(ValueError):
            sign_round_packet(
                3, secret_share_of(_dkg, 3), 7, packet, context, MESSAGE
            )
        # Signer 4 is in neither the context nor the round.
        with self.assertRaises(ValueError):
            sign_round_packet(4, secret_share, nonces[1], packet, context, MESSAGE)

    def test_secret_share_range_and_match(self):
        _dkg, context, _r, nonces, packet, secret_share = make_inputs()
        for bad in (-1, FIELD_PRIME, FIELD_PRIME + 5):
            with self.assertRaises(ValueError):
                sign_round_packet(1, bad, nonces[1], packet, context, MESSAGE)
        # In range but not the signer's share.
        wrong = (secret_share + 1) % FIELD_PRIME
        with self.assertRaises(ValueError):
            sign_round_packet(1, wrong, nonces[1], packet, context, MESSAGE)

    def test_secret_share_checked_even_when_challenge_is_zero(self):
        # Craft a legal packet whose challenge is zero by searching a
        # message; the secret-share match must still be enforced.
        dkg = make_signing_dkg()
        context = export_signing_public_context(dkg)
        round_info, _c, nonces = make_round(dkg, (1, 2), MESSAGE)
        message = MESSAGE
        counter = 0
        while round_info.challenge != 0:
            counter += 1
            message = b"zero challenge hunt " + str(counter).encode()
            round_info, _c, nonces = make_round(dkg, (1, 2), message)
        packet = SigningRoundPacket(context=context, round_info=round_info)
        wrong = (secret_share_of(dkg, 1) + 1) % FIELD_PRIME
        with self.assertRaises(ValueError):
            sign_round_packet(1, wrong, nonces[1], packet, context, message)
        share = sign_round_packet(
            1, secret_share_of(dkg, 1), nonces[1], packet, context, message
        )
        self.assertTrue(verify_signature_share(share, round_info, context))

    def test_nonce_range_and_commitment_match(self):
        _dkg, context, _r, nonces, packet, _s = make_inputs()
        secret_share = secret_share_of(_dkg, 1)
        for bad in (0, -3, FIELD_PRIME, FIELD_PRIME + 1):
            with self.assertRaises(ValueError):
                sign_round_packet(1, secret_share, bad, packet, context, MESSAGE)
        # In range but behind a different commitment.
        with self.assertRaises(ValueError):
            sign_round_packet(
                1, secret_share, nonces[1] % (FIELD_PRIME - 1) + 1, packet, context, MESSAGE
            )

    def test_type_errors(self):
        _dkg, context, _r, nonces, packet, secret_share = make_inputs()
        good = (1, secret_share, nonces[1], packet, context, MESSAGE)
        for index, bad in (
            (0, "1"),
            (0, True),
            (1, 1.5),
            (1, False),
            (2, None),
            (2, True),
            (3, "packet"),
            (3, None),
            (4, packet),
            (4, None),
            (5, "message"),
            (5, None),
        ):
            args = list(good)
            args[index] = bad
            with self.assertRaises(TypeError, msg=f"arg {index}"):
                sign_round_packet(*args)

    def test_structural_packet_errors_raise_value_error(self):
        _dkg, context, round_info, nonces, packet, secret_share = make_inputs()
        # Misaligned nonce commitments: ids not aligned with signer ids.
        misaligned = SigningRoundPacket(
            context=context,
            round_info=SigningRound(
                message=round_info.message,
                signer_ids=round_info.signer_ids,
                nonce_commitments=tuple(reversed(round_info.nonce_commitments)),
                R=round_info.R,
                challenge=round_info.challenge,
            ),
        )
        with self.assertRaises(ValueError):
            sign_round_packet(1, secret_share, nonces[1], misaligned, context, MESSAGE)
        # Out-of-range R.
        bad_range = SigningRoundPacket(
            context=context,
            round_info=SigningRound(
                message=round_info.message,
                signer_ids=round_info.signer_ids,
                nonce_commitments=round_info.nonce_commitments,
                R=GROUP_PRIME,
                challenge=round_info.challenge,
            ),
        )
        with self.assertRaises(ValueError):
            sign_round_packet(1, secret_share, nonces[1], bad_range, context, MESSAGE)

    def test_failure_returns_no_share(self):
        _dkg, context, _r, nonces, packet, _s = make_inputs()
        try:
            sign_round_packet(1, 0, nonces[1], packet, context, MESSAGE)
        except ValueError:
            pass
        else:
            self.fail("expected ValueError")


if __name__ == "__main__":
    unittest.main()
