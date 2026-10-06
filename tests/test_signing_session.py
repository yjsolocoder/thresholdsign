"""Tests for SigningSession: the single-use signer-side signing session."""

import copy
import dataclasses
import pickle
import threading
import unittest

from thresholdsign import (
    AggregateSignature,
    SignatureShare,
    SigningNonceCommitment,
    SigningPublicContext,
    SigningRound,
    SigningRoundPacket,
    SigningSession,
    aggregate_signature,
    create_refresh,
    create_signing_round,
    export_signing_public_context,
    refresh,
    schnorr_challenge,
    sign_round_packet,
    verify_signature,
    verify_signature_share,
)
from tests.test_signing import (
    FIELD_PRIME,
    GENERATOR,
    GROUP_PRIME,
    MESSAGE,
    fixed_random,
    make_signing_dkg,
)
from tests.test_signing_round_packet import make_packet, secret_share_of


def make_session(signer_id=1, dkg=None, message=MESSAGE, seed=10, **kwargs):
    """Build a session for signer_id plus a packet whose round includes it."""
    dkg, context, round_info, commitments, nonces, packet = make_packet(
        dkg=dkg, message=message, seed=seed
    )
    kwargs.setdefault("randbelow", fixed_random(signer_id + 40))
    session = SigningSession(signer_id, context, message, **kwargs)
    # Rebuild the round so the session's own commitment takes part.
    others = [
        commitment
        for commitment in commitments
        if commitment.signer_id != signer_id
    ]
    round_commitments = tuple(
        sorted(
            [session.commitment, *others],
            key=lambda commitment: commitment.signer_id,
        )
    )
    round_info = create_signing_round(
        message, round_info.signer_ids, round_commitments, context
    )
    packet = SigningRoundPacket(context=context, round_info=round_info)
    return dkg, context, round_info, session, packet


class SigningSessionCreationTest(unittest.TestCase):
    def setUp(self):
        self.dkg = make_signing_dkg()
        self.context = export_signing_public_context(self.dkg)

    def session(self, signer_id=1, **kwargs):
        kwargs.setdefault("randbelow", fixed_random(signer_id + 40))
        return SigningSession(signer_id, self.context, MESSAGE, **kwargs)

    def test_commitment_matches_existing_nonce_semantics(self):
        session = self.session(1)
        self.assertIsInstance(session.commitment, SigningNonceCommitment)
        self.assertEqual(session.commitment.signer_id, 1)
        # fixed_random(41) draws over field_prime - 1; the nonce is draw + 1.
        expected_nonce = fixed_random(41)(FIELD_PRIME - 1) + 1
        self.assertEqual(
            session.commitment.commitment,
            pow(GENERATOR, expected_nonce, GROUP_PRIME),
        )
        self.assertEqual(session.state, "ready")

    def test_default_randbelow_draws_a_valid_commitment(self):
        session = SigningSession(2, self.context, MESSAGE)
        self.assertEqual(session.commitment.signer_id, 2)
        self.assertTrue(1 < session.commitment.commitment < GROUP_PRIME)
        self.assertEqual(
            pow(session.commitment.commitment, FIELD_PRIME, GROUP_PRIME), 1
        )

    def test_nonce_is_not_exposed(self):
        session = self.session(1)
        self.assertFalse(hasattr(session, "nonce"))
        self.assertNotIn("nonce", vars(session))

    def test_commitment_drops_into_create_signing_round(self):
        sessions = [self.session(1), self.session(2)]
        commitments = tuple(session.commitment for session in sessions)
        round_info = create_signing_round(MESSAGE, (1, 2), commitments, self.context)
        self.assertEqual(round_info.nonce_commitments, commitments)

    def test_type_errors(self):
        for bad_signer in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=f"signer_id={bad_signer!r}"):
                self.session(bad_signer)
        with self.assertRaises(TypeError):
            SigningSession(1, self.dkg, MESSAGE)
        with self.assertRaises(TypeError):
            SigningSession(1, "not a context", MESSAGE)
        with self.assertRaises(TypeError):
            SigningSession(1, self.context, "not bytes")
        with self.assertRaises(TypeError):
            SigningSession(1, self.context, None)
        bad_context = dataclasses.replace(self.context, threshold=True)
        with self.assertRaises(TypeError):
            SigningSession(1, bad_context, MESSAGE)

    def test_value_errors(self):
        # Signer 4 is not a context participant.
        with self.assertRaises(ValueError):
            self.session(4)
        with self.assertRaises(ValueError):
            self.session(0)
        bad_context = dataclasses.replace(self.context, threshold=0)
        with self.assertRaises(ValueError):
            SigningSession(1, bad_context, MESSAGE)
        bad_context = dataclasses.replace(self.context, public_key=0)
        with self.assertRaises(ValueError):
            SigningSession(1, bad_context, MESSAGE)

    def test_inconsistent_context_raises_value_error(self):
        swapped = dataclasses.replace(
            self.context,
            verification_shares=(
                self.context.verification_shares[1],
                self.context.verification_shares[0],
                self.context.verification_shares[2],
            ),
        )
        self.assertTrue(
            # Structurally legal but not on one polynomial with the key.
            all(0 < share < GROUP_PRIME for share in swapped.verification_shares)
        )
        with self.assertRaises(ValueError):
            SigningSession(1, swapped, MESSAGE)

    def test_bad_randbelow_propagates(self):
        with self.assertRaises(ValueError):
            self.session(1, randbelow=lambda upper: upper)
        with self.assertRaises(TypeError):
            self.session(1, randbelow=lambda upper: True)

    def test_threshold_one_and_empty_message(self):
        dkg = make_signing_dkg((1, 2, 3), 1)
        context = export_signing_public_context(dkg)
        session = SigningSession(2, context, b"", randbelow=fixed_random(7))
        self.assertEqual(session.state, "ready")
        round_info = create_signing_round(b"", (2,), (session.commitment,), context)
        packet = SigningRoundPacket(context=context, round_info=round_info)
        share = session.sign(secret_share_of(dkg, 2), packet)
        self.assertTrue(verify_signature_share(share, round_info, context))


class SigningSessionSignTest(unittest.TestCase):
    def setUp(self):
        (self.dkg, self.context, self.round_info,
         self.session, self.packet) = make_session()

    def sign(self, **overrides):
        args = dict(
            secret_share=secret_share_of(self.dkg, 1),
            packet=self.packet,
        )
        args.update(overrides)
        return self.session.sign(**args)

    def test_share_matches_sign_round_packet(self):
        share = self.sign()
        self.assertIsInstance(share, SignatureShare)
        self.assertEqual(share.signer_id, 1)
        self.assertEqual(share.nonce_commitment, self.session.commitment.commitment)
        # The same share the stateless entry point produces for the nonce.
        nonce = None
        for candidate in range(1, FIELD_PRIME):
            if pow(GENERATOR, candidate, GROUP_PRIME) == share.nonce_commitment:
                nonce = candidate
                break
        self.assertIsNotNone(nonce)
        expected = sign_round_packet(
            1,
            secret_share_of(self.dkg, 1),
            nonce,
            self.packet,
            self.context,
            MESSAGE,
        )
        self.assertEqual(share, expected)

    def test_share_drops_into_verification_aggregation_and_receipts(self):
        sessions = {}
        commitments = []
        for signer_id in self.round_info.signer_ids:
            session = SigningSession(
                signer_id, self.context, MESSAGE,
                randbelow=fixed_random(signer_id + 40),
            )
            sessions[signer_id] = session
            commitments.append(session.commitment)
        round_info = create_signing_round(
            MESSAGE, self.round_info.signer_ids, commitments, self.context
        )
        packet = SigningRoundPacket(context=self.context, round_info=round_info)
        shares = [
            sessions[signer_id].sign(secret_share_of(self.dkg, signer_id), packet)
            for signer_id in self.round_info.signer_ids
        ]
        for share in shares:
            self.assertTrue(verify_signature_share(share, round_info, self.context))
        signature = aggregate_signature(shares, round_info, self.context)
        self.assertIsInstance(signature, AggregateSignature)
        self.assertTrue(
            verify_signature(
                MESSAGE,
                signature,
                self.context.public_key,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            )
        )

    def test_success_flips_state_to_used_and_blocks_everything(self):
        self.sign()
        self.assertEqual(self.session.state, "used")
        with self.assertRaises(RuntimeError):
            self.sign()
        # Even invalid input meets the RuntimeError first.
        with self.assertRaises(RuntimeError):
            self.session.sign("not an int", "not a packet")
        # The commitment stays readable.
        self.assertIsInstance(self.session.commitment, SigningNonceCommitment)

    def test_failure_keeps_ready_and_allows_retry(self):
        with self.assertRaises(ValueError):
            self.sign(secret_share=(secret_share_of(self.dkg, 1) + 1) % FIELD_PRIME)
        self.assertEqual(self.session.state, "ready")
        with self.assertRaises(TypeError):
            self.sign(secret_share=True)
        self.assertEqual(self.session.state, "ready")
        share = self.sign()
        self.assertEqual(self.session.state, "used")
        self.assertIsInstance(share, SignatureShare)

    def test_round_commitment_must_equal_session_commitment(self):
        # A legal round for the same message and signer set whose own
        # commitment for signer 1 is not the session's commitment.
        _dkg, context, round_info, commitments, _n, packet = make_packet(
            dkg=self.dkg
        )
        self.assertNotEqual(
            round_info.nonce_commitments[0].commitment,
            self.session.commitment.commitment,
        )
        with self.assertRaises(ValueError):
            self.sign(packet=packet)
        self.assertEqual(self.session.state, "ready")

    def test_message_and_context_mismatch_raise_value_error(self):
        _d, _c, _r, other_session, other_packet = make_session(
            1, dkg=self.dkg, message=b"another message"
        )
        with self.assertRaises(ValueError):
            self.sign(packet=other_packet)
        self.assertEqual(self.session.state, "ready")

    def test_refreshed_context_packet_is_rejected(self):
        contributions = [
            create_refresh(pid, self.dkg, randbelow=fixed_random(pid + 100))
            for pid in self.dkg.result.participant_ids
        ]
        refreshed = refresh(contributions, self.dkg)
        refreshed_context = export_signing_public_context(refreshed)
        self.assertEqual(refreshed_context.public_key, self.context.public_key)
        packet = dataclasses.replace(self.packet, context=refreshed_context)
        with self.assertRaises(ValueError):
            self.sign(packet=packet)
        self.assertEqual(self.session.state, "ready")

    def test_tampered_round_raises_value_error(self):
        bad = dataclasses.replace(
            self.packet,
            round_info=dataclasses.replace(
                self.round_info, challenge=(self.round_info.challenge + 1) % FIELD_PRIME
            ),
        )
        with self.assertRaises(ValueError):
            self.sign(packet=bad)
        bad = dataclasses.replace(
            self.packet,
            round_info=dataclasses.replace(
                self.round_info, R=(self.round_info.R + 1) % GROUP_PRIME
            ),
        )
        with self.assertRaises(ValueError):
            self.sign(packet=bad)

    def test_zero_secret_share_and_zero_challenge(self):
        # Identity-key synthetic context: both secret shares are 0.
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
        message = b""
        R = 1
        challenge = schnorr_challenge(
            message, 1, 1, (1, 2), field_prime=FIELD_PRIME, group_prime=GROUP_PRIME
        )
        sessions = {}
        for signer_id, nonce in ((1, 5), (2, FIELD_PRIME - 5)):
            session = SigningSession(
                signer_id, context, message,
                randbelow=lambda upper, value=nonce: (value - 1) % upper,
            )
            self.assertEqual(
                session.commitment.commitment, commitments[signer_id - 1].commitment
            )
            sessions[signer_id] = session
        round_info = SigningRound(
            message=message,
            signer_ids=(1, 2),
            nonce_commitments=commitments,
            R=R,
            challenge=challenge,
        )
        packet = SigningRoundPacket(context, round_info)
        shares = [sessions[signer_id].sign(0, packet) for signer_id in (1, 2)]
        for share in shares:
            self.assertTrue(verify_signature_share(share, round_info, context))
        signature = aggregate_signature(shares, round_info, context)
        self.assertIsInstance(signature, AggregateSignature)
        self.assertTrue(
            verify_signature(
                message, signature, 1,
                prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
            )
        )


class SigningSessionCancelTest(unittest.TestCase):
    def setUp(self):
        (self.dkg, self.context, self.round_info,
         self.session, self.packet) = make_session()

    def test_cancel_blocks_signing(self):
        self.session.cancel()
        self.assertEqual(self.session.state, "cancelled")
        with self.assertRaises(RuntimeError):
            self.session.sign(secret_share_of(self.dkg, 1), self.packet)
        with self.assertRaises(RuntimeError):
            self.session.sign("junk", None)
        self.assertIsInstance(self.session.commitment, SigningNonceCommitment)

    def test_repeated_cancel_is_idempotent(self):
        self.session.cancel()
        self.session.cancel()
        self.assertEqual(self.session.state, "cancelled")

    def test_cancel_after_use_keeps_used(self):
        self.session.sign(secret_share_of(self.dkg, 1), self.packet)
        self.session.cancel()
        self.assertEqual(self.session.state, "used")

    def test_concurrent_sign_returns_at_most_one_share(self):
        results = []
        errors = []

        def attempt():
            try:
                results.append(
                    self.session.sign(secret_share_of(self.dkg, 1), self.packet)
                )
            except RuntimeError:
                errors.append("runtime")

        threads = [threading.Thread(target=attempt) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(results), 1)
        self.assertEqual(len(errors), 7)
        self.assertEqual(self.session.state, "used")

    def test_concurrent_cancel_and_sign_single_winner(self):
        outcomes = []

        def attempt_sign():
            try:
                self.session.sign(secret_share_of(self.dkg, 1), self.packet)
                outcomes.append("signed")
            except RuntimeError:
                outcomes.append("blocked")

        def attempt_cancel():
            self.session.cancel()
            outcomes.append("cancelled")

        threads = [
            threading.Thread(target=attempt_sign if index % 2 == 0 else attempt_cancel)
            for index in range(8)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertLessEqual(outcomes.count("signed"), 1)
        self.assertIn(self.session.state, ("used", "cancelled"))
        if self.session.state == "used":
            self.assertEqual(outcomes.count("signed"), 1)
        with self.assertRaises(RuntimeError):
            self.session.sign(secret_share_of(self.dkg, 1), self.packet)


class SigningSessionImmutabilityTest(unittest.TestCase):
    def setUp(self):
        _d, _c, _r, self.session, _p = make_session()

    def test_state_and_commitment_are_not_assignable(self):
        with self.assertRaises(AttributeError):
            self.session.state = "ready"
        with self.assertRaises(AttributeError):
            self.session.commitment = None
        with self.assertRaises(AttributeError):
            self.session.state = "cancelled"

    def test_copy_deepcopy_and_pickle_raise_type_error(self):
        with self.assertRaises(TypeError):
            copy.copy(self.session)
        with self.assertRaises(TypeError):
            copy.deepcopy(self.session)
        with self.assertRaises(TypeError):
            pickle.dumps(self.session)
        # The failed copies left the session itself untouched.
        self.assertEqual(self.session.state, "ready")

    def test_used_session_still_rejects_copy_and_pickle(self):
        dkg, context, round_info, session, packet = make_session()
        session.sign(secret_share_of(dkg, 1), packet)
        self.assertEqual(session.state, "used")
        with self.assertRaises(TypeError):
            copy.copy(session)
        with self.assertRaises(TypeError):
            copy.deepcopy(session)
        with self.assertRaises(TypeError):
            pickle.dumps(session)


if __name__ == "__main__":
    unittest.main()
