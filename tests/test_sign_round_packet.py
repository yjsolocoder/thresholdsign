"""Tests for sign_round_packet: signer-side share creation from a round packet."""

import dataclasses
import unittest

from thresholdsign import (
    AggregateSignature,
    SignatureShare,
    SigningNonceCommitment,
    SigningPublicContext,
    SigningRound,
    SigningRoundPacket,
    aggregate_signature,
    create_refresh,
    create_reshare,
    create_signature_share,
    decode_round_packet,
    encode_round_packet,
    export_signing_public_context,
    refresh,
    reshare,
    schnorr_challenge,
    sign_round_packet,
    verify_round_packet,
    verify_signature,
    verify_signature_share,
)
from tests.test_signing import (
    BLINDING_GENERATOR,
    FIELD_PRIME,
    GENERATOR,
    GROUP_PRIME,
    MESSAGE,
    fixed_random,
    make_signing_dkg,
)
from tests.test_signing_round_packet import make_packet, secret_share_of


def packet_shares(dkg, packet, nonces, context=None, expected_message=None):
    """Sign every round signer through sign_round_packet."""
    context = context or packet.context
    expected_message = (
        packet.round_info.message if expected_message is None else expected_message
    )
    return [
        sign_round_packet(
            signer_id,
            secret_share_of(dkg, signer_id),
            nonces[signer_id],
            packet,
            context,
            expected_message,
        )
        for signer_id in packet.round_info.signer_ids
    ]


class SignRoundPacketValidTest(unittest.TestCase):
    def setUp(self):
        (self.dkg, self.context, self.round_info, self.commitments,
         self.nonces, self.packet) = make_packet()

    def sign(self, signer_id, **overrides):
        args = dict(
            secret_share=secret_share_of(self.dkg, signer_id),
            nonce=self.nonces.get(signer_id, 7),
            packet=self.packet,
            context=self.context,
            expected_message=self.round_info.message,
        )
        args.update(overrides)
        return sign_round_packet(signer_id, **args)

    def test_share_matches_create_signature_share(self):
        for signer_id in self.round_info.signer_ids:
            expected = create_signature_share(
                signer_id,
                secret_share_of(self.dkg, signer_id),
                self.nonces[signer_id],
                self.round_info,
                self.dkg,
            )
            self.assertEqual(self.sign(signer_id), expected)
            self.assertIsInstance(self.sign(signer_id), SignatureShare)

    def test_share_carries_no_secret_material(self):
        share = self.sign(1)
        self.assertEqual(
            {f.name for f in dataclasses.fields(share)},
            {"signer_id", "nonce_commitment", "z"},
        )
        self.assertEqual(share.signer_id, 1)
        self.assertEqual(
            share.nonce_commitment,
            self.round_info.nonce_commitments[0].commitment,
        )

    def test_shares_drop_into_verification_and_aggregation(self):
        shares = packet_shares(self.dkg, self.packet, self.nonces)
        for share in shares:
            self.assertTrue(
                verify_signature_share(share, self.round_info, self.context)
            )
        signature = aggregate_signature(shares, self.round_info, self.context)
        self.assertIsInstance(signature, AggregateSignature)
        self.assertTrue(
            verify_signature(
                self.round_info.message,
                signature,
                self.context.public_key,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            )
        )

    def test_decoded_packet_behaves_identically(self):
        decoded = decode_round_packet(encode_round_packet(self.packet))
        for signer_id in self.round_info.signer_ids:
            self.assertEqual(
                self.sign(signer_id, packet=decoded), self.sign(signer_id)
            )

    def test_directly_constructed_equal_packet_behaves_identically(self):
        clone = SigningRoundPacket(
            SigningPublicContext(
                participant_ids=self.context.participant_ids,
                threshold=self.context.threshold,
                field_prime=self.context.field_prime,
                group_prime=self.context.group_prime,
                generator=self.context.generator,
                public_key=self.context.public_key,
                verification_shares=self.context.verification_shares,
            ),
            SigningRound(
                message=bytes(self.round_info.message),
                signer_ids=tuple(self.round_info.signer_ids),
                nonce_commitments=tuple(self.round_info.nonce_commitments),
                R=self.round_info.R,
                challenge=self.round_info.challenge,
            ),
        )
        self.assertEqual(clone, self.packet)
        for signer_id in self.round_info.signer_ids:
            self.assertEqual(self.sign(signer_id, packet=clone), self.sign(signer_id))

    def test_deterministic_and_inputs_unchanged(self):
        first = self.sign(1)
        second = self.sign(1)
        self.assertEqual(first, second)
        self.assertEqual(
            self.packet,
            SigningRoundPacket(context=self.context, round_info=self.round_info),
        )
        self.assertEqual(self.context, export_signing_public_context(self.dkg))

    def test_empty_message_and_threshold_one(self):
        dkg = make_signing_dkg((1, 2, 3), 1)
        _d, context, round_info, _c, nonces, packet = make_packet(dkg, (2,), b"")
        share = sign_round_packet(
            2, secret_share_of(dkg, 2), nonces[2], packet, context, b""
        )
        self.assertTrue(verify_signature_share(share, round_info, context))
        signature = aggregate_signature([share], round_info, context)
        self.assertIsInstance(signature, AggregateSignature)
        self.assertTrue(
            verify_signature(
                b"", signature, context.public_key,
                prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
            )
        )

    def test_zero_secret_share_identity_key_and_identity_aggregate(self):
        # Synthetic legal context: identity public key and identity
        # verification shares, so the secret share of both signers is 0;
        # the commitments multiply to R = 1.
        commitments = (
            SigningNonceCommitment(1, pow(GENERATOR, 5, GROUP_PRIME)),
            SigningNonceCommitment(2, pow(GENERATOR, FIELD_PRIME - 5, GROUP_PRIME)),
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
        round_info = SigningRound(
            message=b"",
            signer_ids=(1, 2),
            nonce_commitments=commitments,
            R=1,
            challenge=schnorr_challenge(
                b"", 1, 1, (1, 2),
                field_prime=FIELD_PRIME, group_prime=GROUP_PRIME,
            ),
        )
        packet = SigningRoundPacket(context, round_info)
        self.assertTrue(verify_round_packet(packet, context))
        shares = [
            sign_round_packet(1, 0, 5, packet, context, b""),
            sign_round_packet(2, 0, FIELD_PRIME - 5, packet, context, b""),
        ]
        for share in shares:
            self.assertTrue(verify_signature_share(share, round_info, context))
        signature = aggregate_signature(shares, round_info, context)
        self.assertIsInstance(signature, AggregateSignature)
        self.assertTrue(
            verify_signature(
                b"", signature, 1,
                prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
            )
        )

    def test_zero_challenge_still_checks_secret_share(self):
        # Find a message whose honest challenge is zero, then confirm the
        # secret-share match is not skipped.
        dkg = self.dkg
        R = 1
        for commitment in self.round_info.nonce_commitments:
            R = R * commitment.commitment % GROUP_PRIME
        message = None
        for length in range(1, 10000):
            candidate = b"\x00" * length
            if schnorr_challenge(
                candidate, self.context.public_key, R, self.round_info.signer_ids,
                field_prime=FIELD_PRIME, group_prime=GROUP_PRIME,
            ) == 0:
                message = candidate
                break
        self.assertIsNotNone(message, "no zero-challenge message found")
        round_info = SigningRound(
            message=message,
            signer_ids=self.round_info.signer_ids,
            nonce_commitments=self.round_info.nonce_commitments,
            R=R,
            challenge=0,
        )
        packet = SigningRoundPacket(self.context, round_info)
        self.assertTrue(verify_round_packet(packet, self.context))
        wrong_share = (secret_share_of(dkg, 1) + 1) % FIELD_PRIME
        with self.assertRaises(ValueError):
            sign_round_packet(
                1, wrong_share, self.nonces[1], packet, self.context, message
            )
        share = sign_round_packet(
            1, secret_share_of(dkg, 1), self.nonces[1], packet, self.context, message
        )
        self.assertEqual(share.z, self.nonces[1])
        self.assertTrue(verify_signature_share(share, round_info, self.context))


class SignRoundPacketRejectionTest(unittest.TestCase):
    def setUp(self):
        (self.dkg, self.context, self.round_info, self.commitments,
         self.nonces, self.packet) = make_packet()

    def sign(self, signer_id=1, **overrides):
        args = dict(
            secret_share=secret_share_of(self.dkg, signer_id),
            nonce=self.nonces.get(signer_id, 7),
            packet=self.packet,
            context=self.context,
            expected_message=self.round_info.message,
        )
        args.update(overrides)
        return sign_round_packet(signer_id, **args)

    def test_context_field_mismatch_raises_value_error(self):
        cases = [
            dataclasses.replace(self.context, participant_ids=(1, 2, 4)),
            dataclasses.replace(self.context, threshold=1),
            dataclasses.replace(self.context, generator=BLINDING_GENERATOR),
            dataclasses.replace(
                self.context, public_key=pow(GENERATOR, 7, GROUP_PRIME)
            ),
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
                # The trusted context is the anchor: a packet whose bundled
                # context was altered is rejected against the real one.
                with self.assertRaises(ValueError):
                    self.sign(packet=packet)

    def test_refresh_and_reshare_invalidate_old_packet(self):
        contributions = [
            create_refresh(pid, self.dkg, randbelow=fixed_random(pid + 100))
            for pid in self.dkg.result.participant_ids
        ]
        refreshed_context = export_signing_public_context(
            refresh(contributions, self.dkg)
        )
        self.assertEqual(refreshed_context.public_key, self.context.public_key)
        with self.assertRaises(ValueError):
            self.sign(context=refreshed_context)

        dealers = (2, 3)
        contributions = [
            create_reshare(
                dealer,
                secret_share_of(self.dkg, dealer),
                dealers,
                (2, 3, 4),
                2,
                self.dkg,
                rng=fixed_random(dealer + 100),
            )
            for dealer in dealers
        ]
        reshared_context = export_signing_public_context(
            reshare(contributions, dealers, self.dkg)
        )
        self.assertEqual(reshared_context.public_key, self.context.public_key)
        with self.assertRaises(ValueError):
            self.sign(context=reshared_context)

    def test_message_mismatch_raises_value_error(self):
        with self.assertRaises(ValueError):
            self.sign(expected_message=b"another message")
        with self.assertRaises(ValueError):
            self.sign(expected_message=self.round_info.message + b"\x00")
        with self.assertRaises(ValueError):
            self.sign(expected_message=b"")

    def test_recomputed_challenge_forgery_does_not_bypass_message_check(self):
        # A forger swaps the message and recomputes a fully legal challenge
        # for it; the packet then passes verify_round_packet, yet the
        # expected-message check must still reject it.
        forged_message = b"forged message"
        challenge = schnorr_challenge(
            forged_message,
            self.context.public_key,
            self.round_info.R,
            self.round_info.signer_ids,
            field_prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
        )
        forged = dataclasses.replace(
            self.packet,
            round_info=dataclasses.replace(
                self.round_info, message=forged_message, challenge=challenge
            ),
        )
        self.assertTrue(verify_round_packet(forged, self.context))
        with self.assertRaises(ValueError):
            self.sign(packet=forged, expected_message=self.round_info.message)
        # Signing the forged message is only possible by consenting to it.
        share = self.sign(packet=forged, expected_message=forged_message)
        self.assertTrue(
            verify_signature_share(share, forged.round_info, self.context)
        )

    def test_tampered_R_or_challenge_raises_value_error(self):
        bad_R = dataclasses.replace(
            self.packet,
            round_info=dataclasses.replace(
                self.round_info, R=(self.round_info.R + 1) % GROUP_PRIME
            ),
        )
        with self.assertRaises(ValueError):
            self.sign(packet=bad_R)
        bad_challenge = dataclasses.replace(
            self.packet,
            round_info=dataclasses.replace(
                self.round_info,
                challenge=(self.round_info.challenge + 1) % FIELD_PRIME,
            ),
        )
        with self.assertRaises(ValueError):
            self.sign(packet=bad_challenge)

    def test_signer_membership_raises_value_error(self):
        # Participant 3 is a context member but not a round signer.
        with self.assertRaises(ValueError):
            self.sign(3, nonce=7)
        # Signer 4 is neither a participant nor a round signer.
        with self.assertRaises(ValueError):
            self.sign(4, secret_share=3, nonce=7)
        with self.assertRaises(ValueError):
            self.sign(0, secret_share=3, nonce=7)

    def test_secret_share_range_and_match_raise_value_error(self):
        for bad in (-1, FIELD_PRIME, FIELD_PRIME + 1):
            with self.assertRaises(ValueError, msg=f"secret_share={bad}"):
                self.sign(secret_share=bad)
        wrong = (secret_share_of(self.dkg, 1) + 1) % FIELD_PRIME
        with self.assertRaises(ValueError):
            self.sign(secret_share=wrong)
        # Another participant's secret share is equally rejected.
        with self.assertRaises(ValueError):
            self.sign(secret_share=secret_share_of(self.dkg, 2))

    def test_nonce_range_and_match_raise_value_error(self):
        for bad in (0, FIELD_PRIME, FIELD_PRIME + 1, -1):
            with self.assertRaises(ValueError, msg=f"nonce={bad}"):
                self.sign(nonce=bad)
        wrong = self.nonces[1] % (FIELD_PRIME - 1) + 1
        if wrong == self.nonces[1]:
            wrong = wrong % (FIELD_PRIME - 1) + 1
        with self.assertRaises(ValueError):
            self.sign(nonce=wrong)
        # The other signer's nonce does not match this signer's commitment.
        with self.assertRaises(ValueError):
            self.sign(nonce=self.nonces[2])

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            sign_round_packet(True, 1, 1, self.packet, self.context, b"")
        with self.assertRaises(TypeError):
            sign_round_packet(1, True, 1, self.packet, self.context, b"")
        with self.assertRaises(TypeError):
            sign_round_packet(1, 1, True, self.packet, self.context, b"")
        with self.assertRaises(TypeError):
            sign_round_packet("1", 1, 1, self.packet, self.context, b"")
        with self.assertRaises(TypeError):
            sign_round_packet(1, 1.0, 1, self.packet, self.context, b"")
        with self.assertRaises(TypeError):
            sign_round_packet(1, 1, "1", self.packet, self.context, b"")
        with self.assertRaises(TypeError):
            sign_round_packet(1, 1, 1, "not a packet", self.context, b"")
        with self.assertRaises(TypeError):
            sign_round_packet(1, 1, 1, self.round_info, self.context, b"")
        with self.assertRaises(TypeError):
            sign_round_packet(1, 1, 1, self.packet, self.dkg, b"")
        with self.assertRaises(TypeError):
            sign_round_packet(1, 1, 1, self.packet, "not a context", b"")
        with self.assertRaises(TypeError):
            sign_round_packet(1, 1, 1, self.packet, self.context, "not bytes")
        with self.assertRaises(TypeError):
            sign_round_packet(1, 1, 1, self.packet, self.context, None)

    def test_structural_packet_errors_raise_not_sign(self):
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
            self.sign(packet=misaligned)
        bad = dataclasses.replace(
            self.packet,
            round_info=dataclasses.replace(self.round_info, signer_ids=(1,)),
        )
        with self.assertRaises(ValueError):
            self.sign(packet=bad)
        bad = dataclasses.replace(
            self.packet,
            context=dataclasses.replace(self.context, threshold=0),
        )
        with self.assertRaises(ValueError):
            self.sign(packet=bad)
        bad = dataclasses.replace(
            self.packet,
            context=dataclasses.replace(self.context, threshold=True),
        )
        with self.assertRaises(TypeError):
            self.sign(packet=bad)
        bad_trusted = dataclasses.replace(self.context, public_key=0)
        with self.assertRaises(ValueError):
            self.sign(context=bad_trusted)
        bad_trusted = dataclasses.replace(self.context, threshold=False)
        with self.assertRaises(TypeError):
            self.sign(context=bad_trusted)


if __name__ == "__main__":
    unittest.main()
