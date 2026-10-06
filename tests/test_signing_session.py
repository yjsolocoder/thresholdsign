"""Tests for SigningSession: the stateful single-use signer handle."""

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
    SigningRoundPacket,
    SigningSession,
    aggregate_signature,
    create_refresh,
    create_reshare,
    create_signature_receipt,
    create_signing_nonce_commitment,
    create_signing_round,
    export_signing_public_context,
    refresh,
    reshare,
    schnorr_challenge,
    sign_round_packet,
    verify_signature,
    verify_signature_receipt,
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
    nonce_standin,
)
from tests.test_signing_round_packet import make_packet, secret_share_of


def make_sessions(context, signer_ids, message=MESSAGE, seed=200):
    """One session per signer with deterministic nonce draws."""
    return {
        signer_id: SigningSession(
            signer_id, context, message, randbelow=fixed_random(seed + signer_id)
        )
        for signer_id in signer_ids
    }


def session_packet(context, sessions, signer_ids, message=MESSAGE):
    """Run the existing round-creation flow over the sessions' commitments."""
    round_info = create_signing_round(
        message, signer_ids, [sessions[sid].commitment for sid in signer_ids], context
    )
    return SigningRoundPacket(context=context, round_info=round_info)


class SigningSessionCreationTest(unittest.TestCase):
    def setUp(self):
        self.dkg = make_signing_dkg()
        self.context = export_signing_public_context(self.dkg)

    def session(self, signer_id=1, **overrides):
        args = dict(context=self.context, message=MESSAGE, randbelow=fixed_random(101))
        args.update(overrides)
        return SigningSession(signer_id, **args)

    def test_commitment_matches_stateless_nonce_draw(self):
        for seed in (1, 7, 12345):
            expected, nonce = create_signing_nonce_commitment(
                1,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
                prime=FIELD_PRIME,
                randbelow=fixed_random(seed),
            )
            session = self.session(randbelow=fixed_random(seed))
            self.assertEqual(session.commitment, expected)
            self.assertEqual(
                session.commitment.commitment,
                pow(GENERATOR, nonce, GROUP_PRIME),
            )

    def test_initial_state_and_bound_inputs(self):
        session = self.session()
        self.assertEqual(session.state, "ready")
        self.assertIsInstance(session.commitment, SigningNonceCommitment)
        self.assertEqual(session.commitment.signer_id, 1)
        self.assertTrue(1 < session.commitment.commitment < GROUP_PRIME)
        self.assertEqual(
            pow(session.commitment.commitment, FIELD_PRIME, GROUP_PRIME), 1
        )

    def test_nonce_is_not_exposed(self):
        session = self.session()
        for name in ("nonce", "secret_share", "message", "context", "signer_id"):
            self.assertFalse(hasattr(session, name), name)

    def test_commitment_drops_into_create_signing_round(self):
        sessions = make_sessions(self.context, (1, 2))
        packet = session_packet(self.context, sessions, (1, 2))
        self.assertEqual(
            packet.round_info.nonce_commitments,
            (sessions[1].commitment, sessions[2].commitment),
        )

    def test_empty_message_and_threshold_one(self):
        dkg = make_signing_dkg((1, 2, 3), 1)
        context = export_signing_public_context(dkg)
        session = SigningSession(2, context, b"", randbelow=fixed_random(3))
        packet = session_packet(context, {2: session}, (2,), message=b"")
        share = session.sign(secret_share_of(dkg, 2), packet)
        self.assertTrue(verify_signature_share(share, packet.round_info, context))
        signature = aggregate_signature([share], packet.round_info, context)
        self.assertIsInstance(signature, AggregateSignature)
        self.assertTrue(
            verify_signature(
                b"", signature, context.public_key,
                prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
            )
        )

    def test_type_errors(self):
        for bad_id in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=f"signer_id={bad_id!r}"):
                self.session(bad_id)
        for bad_context in ("not a context", None, self.dkg, 7):
            with self.assertRaises(TypeError, msg=f"context={bad_context!r}"):
                self.session(context=bad_context)
        for bad_message in ("not bytes", None, 5, bytearray(b"x")):
            with self.assertRaises(TypeError, msg=f"message={bad_message!r}"):
                self.session(message=bad_message)
        with self.assertRaises(TypeError):
            self.session(context=dataclasses.replace(self.context, threshold=True))
        with self.assertRaises(TypeError):
            self.session(
                context=dataclasses.replace(self.context, participant_ids=[1, 2, 3])
            )
        # randbelow must behave like secrets.randbelow.
        with self.assertRaises(TypeError):
            self.session(randbelow=lambda upper: True)
        with self.assertRaises(TypeError):
            self.session(randbelow=lambda upper: "1")

    def test_value_errors(self):
        # Non-members, whatever their value.
        for bad_id in (0, 4, -1, FIELD_PRIME):
            with self.assertRaises(ValueError, msg=f"signer_id={bad_id}"):
                self.session(bad_id)
        # Structurally illegal contexts.
        with self.assertRaises(ValueError):
            self.session(context=dataclasses.replace(self.context, threshold=0))
        with self.assertRaises(ValueError):
            self.session(context=dataclasses.replace(self.context, public_key=0))
        with self.assertRaises(ValueError):
            self.session(
                context=dataclasses.replace(self.context, participant_ids=(1, 1, 2))
            )
        # Inconsistent public shares: every value is a legal subgroup
        # element, but they no longer interpolate with the joint key.
        swapped = dataclasses.replace(
            self.context,
            verification_shares=(
                self.context.verification_shares[1],
                self.context.verification_shares[0],
                self.context.verification_shares[2],
            ),
        )
        with self.assertRaises(ValueError):
            self.session(context=swapped)
        wrong_key = dataclasses.replace(
            self.context, public_key=pow(GENERATOR, 7, GROUP_PRIME)
        )
        with self.assertRaises(ValueError):
            self.session(context=wrong_key)
        # randbelow draws outside range(prime - 1) are rejected.
        with self.assertRaises(ValueError):
            self.session(randbelow=lambda upper: upper)
        with self.assertRaises(ValueError):
            self.session(randbelow=lambda upper: -1)

    def test_refreshed_or_reshared_context_is_a_different_binding(self):
        contributions = [
            create_refresh(pid, self.dkg, randbelow=fixed_random(pid + 100))
            for pid in self.dkg.result.participant_ids
        ]
        refreshed = refresh(contributions, self.dkg)
        refreshed_context = export_signing_public_context(refreshed)
        self.assertEqual(refreshed_context.public_key, self.context.public_key)
        # A session binds its own context: a packet exported under the
        # pre-refresh context is rejected even though the key is unchanged.
        session = SigningSession(1, refreshed_context, MESSAGE, randbelow=fixed_random(1))
        _d, _c, _r, _co, _n, old_packet = make_packet(self.dkg)
        with self.assertRaises(ValueError):
            session.sign(secret_share_of(refreshed, 1), old_packet)
        self.assertEqual(session.state, "ready")

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
        # The old session's bound context is equally not replaced by the
        # reshared one: a packet exported under the reshared context fails
        # against the session bound to the original context.
        session = SigningSession(2, self.context, MESSAGE, randbelow=fixed_random(2))
        reshared_dkg = reshare(contributions, dealers, self.dkg)
        new_round = create_signing_round(
            MESSAGE,
            (2, 3),
            (
                session.commitment,
                SigningNonceCommitment(3, pow(GENERATOR, 5, GROUP_PRIME)),
            ),
            reshared_context,
        )
        packet = SigningRoundPacket(context=reshared_context, round_info=new_round)
        with self.assertRaises(ValueError):
            session.sign(secret_share_of(reshared_dkg, 2), packet)
        self.assertEqual(session.state, "ready")


class SigningSessionSignTest(unittest.TestCase):
    def setUp(self):
        (self.dkg, self.context, self.round_info, self.commitments,
         self.nonces, self.packet) = make_packet()

    def session(self, signer_id=1, seed=None, context=None, message=MESSAGE):
        # Reproduce the nonce the packet was created with: make_round used
        # fixed_random(10 + 100 * offset + signer_id) per signer.
        if seed is None:
            seed = 10 + 100 * self.round_info.signer_ids.index(signer_id) + signer_id
        return SigningSession(
            signer_id,
            context or self.context,
            message,
            randbelow=fixed_random(seed),
        )

    def test_share_matches_sign_round_packet(self):
        for offset, signer_id in enumerate(self.round_info.signer_ids):
            session = self.session(signer_id)
            self.assertEqual(session.commitment, self.commitments[offset])
            expected = sign_round_packet(
                signer_id,
                secret_share_of(self.dkg, signer_id),
                self.nonces[signer_id],
                self.packet,
                self.context,
                MESSAGE,
            )
            share = session.sign(secret_share_of(self.dkg, signer_id), self.packet)
            self.assertEqual(share, expected)
            self.assertIsInstance(share, SignatureShare)
            self.assertEqual(session.state, "used")

    def test_shares_drop_into_verification_aggregation_and_receipt(self):
        sessions = make_sessions(self.context, self.round_info.signer_ids)
        packet = session_packet(self.context, sessions, self.round_info.signer_ids)
        shares = [
            sessions[sid].sign(secret_share_of(self.dkg, sid), packet)
            for sid in self.round_info.signer_ids
        ]
        for share in shares:
            self.assertTrue(
                verify_signature_share(share, packet.round_info, self.context)
            )
        signature = aggregate_signature(shares, packet.round_info, self.context)
        self.assertIsInstance(signature, AggregateSignature)
        self.assertTrue(
            verify_signature(
                MESSAGE, signature, self.context.public_key,
                prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
            )
        )
        receipt = create_signature_receipt(MESSAGE, signature, self.dkg)
        self.assertTrue(verify_signature_receipt(receipt))

    def test_failed_sign_keeps_ready_and_allows_retry(self):
        session = self.session(1)
        secret = secret_share_of(self.dkg, 1)
        wrong = (secret + 1) % FIELD_PRIME
        with self.assertRaises(ValueError):
            session.sign(wrong, self.packet)
        self.assertEqual(session.state, "ready")
        share = session.sign(secret, self.packet)
        self.assertTrue(
            verify_signature_share(share, self.round_info, self.context)
        )
        self.assertEqual(session.state, "used")

    def test_message_mismatch_raises_value_error(self):
        session = self.session(1, message=b"a different message")
        with self.assertRaises(ValueError):
            session.sign(secret_share_of(self.dkg, 1), self.packet)
        self.assertEqual(session.state, "ready")

    def test_context_mismatch_raises_value_error(self):
        other = dataclasses.replace(self.context, threshold=1)
        packet = dataclasses.replace(self.packet, context=other)
        session = self.session(1)
        with self.assertRaises(ValueError):
            session.sign(secret_share_of(self.dkg, 1), packet)
        # A trusted context differing from the packet's bundled context is
        # equally rejected: build the session on a refreshed context.
        contributions = [
            create_refresh(pid, self.dkg, randbelow=fixed_random(pid + 100))
            for pid in self.dkg.result.participant_ids
        ]
        refreshed_context = export_signing_public_context(
            refresh(contributions, self.dkg)
        )
        self.assertEqual(refreshed_context.public_key, self.context.public_key)
        session = self.session(1, context=refreshed_context)
        with self.assertRaises(ValueError):
            session.sign(secret_share_of(self.dkg, 1), self.packet)

    def test_tampered_round_fields_raise_value_error(self):
        session = self.session(1)
        secret = secret_share_of(self.dkg, 1)
        bad_R = dataclasses.replace(
            self.packet,
            round_info=dataclasses.replace(
                self.round_info, R=(self.round_info.R + 1) % GROUP_PRIME
            ),
        )
        with self.assertRaises(ValueError):
            session.sign(secret, bad_R)
        bad_challenge = dataclasses.replace(
            self.packet,
            round_info=dataclasses.replace(
                self.round_info,
                challenge=(self.round_info.challenge + 1) % FIELD_PRIME,
            ),
        )
        with self.assertRaises(ValueError):
            session.sign(secret, bad_challenge)
        misaligned = dataclasses.replace(
            self.packet,
            round_info=dataclasses.replace(
                self.round_info,
                nonce_commitments=tuple(reversed(self.round_info.nonce_commitments)),
            ),
        )
        with self.assertRaises(ValueError):
            session.sign(secret, misaligned)
        self.assertEqual(session.state, "ready")

    def test_foreign_round_commitment_raises_value_error(self):
        # The packet names this signer but with a commitment that is not the
        # session's: rejected, and the session stays ready.
        session = self.session(1)
        foreign, _nonce = create_signing_nonce_commitment(
            1,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            prime=FIELD_PRIME,
            randbelow=fixed_random(999),
        )
        self.assertNotEqual(foreign, session.commitment)
        round_info = create_signing_round(
            MESSAGE, (1, 2), (foreign, self.commitments[1]), self.context
        )
        packet = SigningRoundPacket(context=self.context, round_info=round_info)
        with self.assertRaises(ValueError):
            session.sign(secret_share_of(self.dkg, 1), packet)
        self.assertEqual(session.state, "ready")

    def test_signer_set_and_secret_share_checks(self):
        session = self.session(1)
        secret = secret_share_of(self.dkg, 1)
        # A round this signer does not take part in.
        other_round = create_signing_round(
            MESSAGE, (2, 3),
            (
                SigningNonceCommitment(2, pow(GENERATOR, 3, GROUP_PRIME)),
                SigningNonceCommitment(3, pow(GENERATOR, 5, GROUP_PRIME)),
            ),
            self.context,
        )
        packet = SigningRoundPacket(context=self.context, round_info=other_round)
        with self.assertRaises(ValueError):
            session.sign(secret, packet)
        # Out-of-range and foreign secret shares.
        for bad in (-1, FIELD_PRIME, secret_share_of(self.dkg, 2)):
            with self.assertRaises(ValueError, msg=f"secret_share={bad}"):
                session.sign(bad, self.packet)
        self.assertEqual(session.state, "ready")

    def test_type_errors(self):
        session = self.session(1)
        with self.assertRaises(TypeError):
            session.sign(True, self.packet)
        with self.assertRaises(TypeError):
            session.sign("1", self.packet)
        with self.assertRaises(TypeError):
            session.sign(secret_share_of(self.dkg, 1), "not a packet")
        with self.assertRaises(TypeError):
            session.sign(secret_share_of(self.dkg, 1), self.round_info)
        self.assertEqual(session.state, "ready")

    def test_zero_secret_share_and_identity_aggregate(self):
        context = SigningPublicContext(
            participant_ids=(1, 2),
            threshold=1,
            field_prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            public_key=1,
            verification_shares=(1, 1),
        )
        session1 = SigningSession(1, context, b"", randbelow=nonce_standin(4))
        session2 = SigningSession(
            2, context, b"", randbelow=nonce_standin(FIELD_PRIME - 6)
        )
        self.assertEqual(session1.commitment.commitment, pow(GENERATOR, 5, GROUP_PRIME))
        self.assertEqual(
            session2.commitment.commitment,
            pow(GENERATOR, FIELD_PRIME - 5, GROUP_PRIME),
        )
        packet = session_packet(context, {1: session1, 2: session2}, (1, 2), message=b"")
        self.assertEqual(packet.round_info.R, 1)
        shares = [session1.sign(0, packet), session2.sign(0, packet)]
        for share in shares:
            self.assertTrue(
                verify_signature_share(share, packet.round_info, context)
            )
        signature = aggregate_signature(shares, packet.round_info, context)
        self.assertIsInstance(signature, AggregateSignature)
        self.assertTrue(
            verify_signature(
                b"", signature, 1,
                prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
            )
        )

    def test_zero_challenge_still_checks_secret_share(self):
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
        # Reuse the packet's commitments so R (and the zero challenge) hold.
        round_info = create_signing_round(
            message, self.round_info.signer_ids,
            self.round_info.nonce_commitments, self.context,
        )
        self.assertEqual(round_info.challenge, 0)
        packet = SigningRoundPacket(context=self.context, round_info=round_info)
        sessions = {
            signer_id: self.session(signer_id, message=message)
            for signer_id in self.round_info.signer_ids
        }
        session = sessions[1]
        wrong = (secret_share_of(self.dkg, 1) + 1) % FIELD_PRIME
        with self.assertRaises(ValueError):
            session.sign(wrong, packet)
        share = session.sign(secret_share_of(self.dkg, 1), packet)
        self.assertEqual(share.z, self.nonces[1])
        self.assertTrue(verify_signature_share(share, round_info, self.context))


class SigningSessionStateTest(unittest.TestCase):
    def setUp(self):
        (self.dkg, self.context, self.round_info, self.commitments,
         self.nonces, self.packet) = make_packet()

    def session(self, signer_id=1):
        seed = 10 + 100 * self.round_info.signer_ids.index(signer_id) + signer_id
        return SigningSession(
            signer_id, self.context, MESSAGE, randbelow=fixed_random(seed)
        )

    def test_used_state_is_terminal(self):
        session = self.session(1)
        secret = secret_share_of(self.dkg, 1)
        session.sign(secret, self.packet)
        self.assertEqual(session.state, "used")
        # RuntimeError comes first, whatever the arguments.
        with self.assertRaises(RuntimeError):
            session.sign(secret, self.packet)
        with self.assertRaises(RuntimeError):
            session.sign(secret, self.packet)
        with self.assertRaises(RuntimeError):
            session.sign(None, None)
        with self.assertRaises(RuntimeError):
            session.sign(True, "garbage")
        self.assertEqual(session.state, "used")

    def test_cancel_closes_ready_session(self):
        session = self.session(1)
        session.cancel()
        self.assertEqual(session.state, "cancelled")
        with self.assertRaises(RuntimeError):
            session.sign(secret_share_of(self.dkg, 1), self.packet)
        with self.assertRaises(RuntimeError):
            session.sign(None, None)
        # Cancelling a terminal session changes nothing and does not raise.
        session.cancel()
        self.assertEqual(session.state, "cancelled")

    def test_cancel_after_use_is_a_no_op(self):
        session = self.session(1)
        session.sign(secret_share_of(self.dkg, 1), self.packet)
        session.cancel()
        self.assertEqual(session.state, "used")

    def test_commitment_and_state_are_read_only(self):
        session = self.session(1)
        commitment = session.commitment
        with self.assertRaises(AttributeError):
            session.state = "cancelled"  # type: ignore[misc]
        with self.assertRaises(AttributeError):
            session.commitment = None  # type: ignore[misc]
        with self.assertRaises(AttributeError):
            session.nonce = 1  # type: ignore[attr-defined]
        session.cancel()
        self.assertEqual(session.commitment, commitment)
        self.assertEqual(session.state, "cancelled")

    def test_commitment_readable_after_termination(self):
        session = self.session(1)
        commitment = session.commitment
        session.sign(secret_share_of(self.dkg, 1), self.packet)
        self.assertEqual(session.commitment, commitment)
        other = self.session(2)
        other_commitment = other.commitment
        other.cancel()
        self.assertEqual(other.commitment, other_commitment)

    def test_no_copy_deepcopy_or_pickle(self):
        session = self.session(1)
        with self.assertRaises(TypeError):
            copy.copy(session)
        with self.assertRaises(TypeError):
            copy.deepcopy(session)
        with self.assertRaises(TypeError):
            pickle.dumps(session)
        # The failed copies leave the session usable.
        self.assertEqual(session.state, "ready")
        share = session.sign(secret_share_of(self.dkg, 1), self.packet)
        self.assertTrue(
            verify_signature_share(share, self.round_info, self.context)
        )

    def test_state_is_per_session(self):
        first = self.session(1)
        second = self.session(1)
        self.assertEqual(first.commitment, second.commitment)
        first.sign(secret_share_of(self.dkg, 1), self.packet)
        # A distinct session object is independent state, even when it
        # carries the same commitment.
        self.assertEqual(second.state, "ready")
        second.cancel()
        self.assertEqual(first.state, "used")
        self.assertEqual(second.state, "cancelled")

    def test_concurrent_sign_returns_at_most_one_share(self):
        session = self.session(1)
        secret = secret_share_of(self.dkg, 1)
        barrier = threading.Barrier(8)
        shares = []
        errors = []
        lock = threading.Lock()

        def worker():
            barrier.wait()
            try:
                share = session.sign(secret, self.packet)
            except RuntimeError:
                with lock:
                    errors.append("runtime")
            else:
                with lock:
                    shares.append(share)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(shares), 1)
        self.assertEqual(len(errors), 7)
        self.assertEqual(session.state, "used")
        self.assertTrue(
            verify_signature_share(shares[0], self.round_info, self.context)
        )

    def test_cancel_first_prevents_any_signature(self):
        session = self.session(1)
        session.cancel()
        shares = []

        def worker():
            try:
                shares.append(
                    session.sign(secret_share_of(self.dkg, 1), self.packet)
                )
            except RuntimeError:
                pass

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(shares, [])
        self.assertEqual(session.state, "cancelled")

    def test_sign_cancel_race_has_a_single_outcome(self):
        for _ in range(20):
            session = self.session(1)
            secret = secret_share_of(self.dkg, 1)
            barrier = threading.Barrier(2)
            shares = []

            def signer():
                barrier.wait()
                try:
                    shares.append(session.sign(secret, self.packet))
                except RuntimeError:
                    pass

            def canceller():
                barrier.wait()
                session.cancel()

            threads = [
                threading.Thread(target=signer),
                threading.Thread(target=canceller),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            if shares:
                self.assertEqual(len(shares), 1)
                self.assertEqual(session.state, "used")
            else:
                self.assertEqual(session.state, "cancelled")


if __name__ == "__main__":
    unittest.main()
