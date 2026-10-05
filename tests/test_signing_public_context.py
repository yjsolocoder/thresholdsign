"""Tests for SigningPublicContext and export_signing_public_context."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    SigningDKGResult,
    SigningPublicContext,
    SigningRound,
    SignatureShare,
    SignatureShareRejection,
    aggregate_signature,
    aggregate_signing_dkg,
    create_refresh,
    create_reshare,
    create_signature_share,
    create_signing_contribution,
    create_signing_nonce_commitment,
    create_signing_round,
    export_signing_public_context,
    refresh,
    reshare,
    verify_signature,
    verify_signature_share,
)

# Same toy group as the signing tests: 8069 = 4 * 2017 + 1 is prime, 16 and
# 256 = 16 ** 2 are distinct generators of the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

MESSAGE = b"public context test message"


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


class ExportTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.context = export_signing_public_context(self.key)

    def test_fields_match_key_public_material(self):
        self.assertIsInstance(self.context, SigningPublicContext)
        self.assertEqual(self.context.participant_ids, (1, 2, 3))
        self.assertEqual(self.context.threshold, 2)
        self.assertEqual(self.context.field_prime, FIELD_PRIME)
        self.assertEqual(self.context.group_prime, GROUP_PRIME)
        self.assertEqual(self.context.generator, GENERATOR)
        self.assertEqual(self.context.public_key, self.key.public_key)
        self.assertEqual(self.context.verification_shares, self.key.verification_shares)
        self.assertIsInstance(self.context.participant_ids, tuple)
        self.assertIsInstance(self.context.verification_shares, tuple)

    def test_equals_directly_constructed_context(self):
        direct = SigningPublicContext(
            participant_ids=(1, 2, 3),
            threshold=2,
            field_prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            public_key=self.key.public_key,
            verification_shares=self.key.verification_shares,
        )
        self.assertEqual(self.context, direct)

    def test_carries_no_secret_material(self):
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
        for value in dataclasses.astuple(self.context):
            self.assertIsInstance(value, (int, tuple))
            if isinstance(value, tuple):
                for element in value:
                    self.assertIsInstance(element, int)

    def test_context_is_frozen(self):
        with self.assertRaises(FrozenInstanceError):
            self.context.public_key = 1  # type: ignore[misc]

    def test_export_from_refresh_result(self):
        key = make_key()
        contributions = [
            create_refresh(pid, key, randbelow=fixed_random(pid + 100))
            for pid in key.result.participant_ids
        ]
        refreshed = refresh(contributions, key)
        self.assertIsInstance(refreshed, SigningDKGResult)
        context = export_signing_public_context(refreshed)
        self.assertEqual(context.public_key, refreshed.public_key)
        self.assertEqual(context.verification_shares, refreshed.verification_shares)
        # The refreshed key still signs through its context.
        round_info, _commitments, nonces = make_round(context)
        shares = make_shares(refreshed, round_info, nonces)
        signature = aggregate_signature(shares, round_info, context)
        self.assertIsInstance(signature, AggregateSignature)
        self.assertTrue(
            verify_signature(
                MESSAGE, signature, context.public_key,
                prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
            )
        )

    def test_export_from_reshare_result(self):
        key = make_key()
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
        self.assertIsInstance(reshared, SigningDKGResult)
        context = export_signing_public_context(reshared)
        self.assertEqual(context.participant_ids, members)
        self.assertEqual(context.public_key, key.public_key)
        round_info, _commitments, nonces = make_round(context, signer_ids=(2, 4))
        shares = make_shares(reshared, round_info, nonces)
        signature = aggregate_signature(shares, round_info, context)
        self.assertIsInstance(signature, AggregateSignature)
        self.assertTrue(
            verify_signature(
                MESSAGE, signature, context.public_key,
                prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
            )
        )

    def test_export_threshold_one_and_nonconsecutive_ids(self):
        key = make_key((2, 5, 9), 1)
        context = export_signing_public_context(key)
        self.assertEqual(context.participant_ids, (2, 5, 9))
        self.assertEqual(context.threshold, 1)
        round_info, _commitments, nonces = make_round(context, signer_ids=(5,))
        shares = make_shares(key, round_info, nonces)
        signature = aggregate_signature(shares, round_info, context)
        self.assertIsInstance(signature, AggregateSignature)
        self.assertTrue(
            verify_signature(
                MESSAGE, signature, context.public_key,
                prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
            )
        )

    def test_export_rejects_wrong_type(self):
        with self.assertRaises(TypeError):
            export_signing_public_context(self.context)
        with self.assertRaises(TypeError):
            export_signing_public_context("key")
        with self.assertRaises(TypeError):
            export_signing_public_context(None)

    def test_export_rejects_invalid_key(self):
        bad = dataclasses.replace(self.key, verification_shares=self.key.verification_shares[:2])
        with self.assertRaises(ValueError):
            export_signing_public_context(bad)
        bad = dataclasses.replace(self.key, public_key=0)
        with self.assertRaises(ValueError):
            export_signing_public_context(bad)


class RoundWithContextTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.context = export_signing_public_context(self.key)

    def test_round_matches_key_round(self):
        round_key, commitments, _ = make_round(self.key)
        round_context = create_signing_round(
            MESSAGE, (1, 2), list(reversed(commitments)), self.context
        )
        self.assertEqual(round_key, round_context)
        self.assertIsInstance(round_context, SigningRound)

    def test_directly_constructed_context_gives_same_round(self):
        direct = SigningPublicContext(
            participant_ids=(1, 2, 3),
            threshold=2,
            field_prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            public_key=self.key.public_key,
            verification_shares=self.key.verification_shares,
        )
        round_key, commitments, _ = make_round(self.key)
        self.assertEqual(
            round_key, create_signing_round(MESSAGE, (1, 2), commitments, direct)
        )

    def test_round_input_constraints_still_enforced(self):
        _round_info, commitments, _ = make_round(self.context)
        with self.assertRaises(ValueError):
            create_signing_round(MESSAGE, (1,), commitments[:1], self.context)
        with self.assertRaises(ValueError):
            create_signing_round(MESSAGE, (2, 1), commitments, self.context)
        with self.assertRaises(ValueError):
            create_signing_round(MESSAGE, (1, 9), commitments, self.context)
        with self.assertRaises(ValueError):
            create_signing_round(MESSAGE, (1, 2), commitments[:1], self.context)
        with self.assertRaises(TypeError):
            create_signing_round("not bytes", (1, 2), commitments, self.context)


class VerifyShareWithContextTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.context = export_signing_public_context(self.key)
        self.round_info, self.commitments, self.nonces = make_round(self.key)
        self.shares = make_shares(self.key, self.round_info, self.nonces)

    def test_valid_shares_verify(self):
        for share in self.shares:
            self.assertIs(verify_signature_share(share, self.round_info, self.context), True)

    def test_verdicts_match_key_for_tampered_shares(self):
        tampered = [
            dataclasses.replace(self.shares[0], z=(self.shares[0].z + 1) % FIELD_PRIME),
            dataclasses.replace(
                self.shares[1], nonce_commitment=self.commitments[0].commitment
            ),
        ]
        for share in tampered:
            self.assertIs(
                verify_signature_share(share, self.round_info, self.context),
                verify_signature_share(share, self.round_info, self.key),
            )
            self.assertIs(verify_signature_share(share, self.round_info, self.context), False)

    def test_edited_round_commitment_sum_returns_false(self):
        bad_round = dataclasses.replace(
            self.round_info, R=(self.round_info.R + 1) % GROUP_PRIME or 2
        )
        self.assertIs(
            verify_signature_share(self.shares[0], bad_round, self.context), False
        )

    def test_edited_round_challenge_returns_false(self):
        bad_round = dataclasses.replace(
            self.round_info, challenge=(self.round_info.challenge + 1) % FIELD_PRIME
        )
        self.assertIs(
            verify_signature_share(self.shares[0], bad_round, self.context), False
        )

    def test_share_from_other_message_returns_false(self):
        other_round, _, _ = make_round(self.context, message=b"another message")
        self.assertIs(
            verify_signature_share(self.shares[0], other_round, self.context), False
        )

    def test_share_field_constraints_still_enforced(self):
        bad = dataclasses.replace(self.shares[0], z=FIELD_PRIME)
        with self.assertRaises(ValueError):
            verify_signature_share(bad, self.round_info, self.context)
        with self.assertRaises(TypeError):
            verify_signature_share("share", self.round_info, self.context)


class AggregateWithContextTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.context = export_signing_public_context(self.key)
        self.round_info, _commitments, self.nonces = make_round(self.key)
        self.shares = make_shares(self.key, self.round_info, self.nonces)

    def test_signature_matches_key_signature(self):
        from_key = aggregate_signature(self.shares, self.round_info, self.key)
        from_context = aggregate_signature(
            list(reversed(self.shares)), self.round_info, self.context
        )
        self.assertEqual(from_key, from_context)
        self.assertIsInstance(from_context, AggregateSignature)

    def test_final_signature_verifies(self):
        signature = aggregate_signature(self.shares, self.round_info, self.context)
        self.assertTrue(
            verify_signature(
                MESSAGE, signature, self.context.public_key,
                prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
            )
        )

    def test_rejection_list_matches_key_and_names_every_failure(self):
        bad = [
            dataclasses.replace(share, z=(share.z + 1) % FIELD_PRIME)
            for share in self.shares
        ]
        batch = [bad[1], bad[0]]
        expected = [
            SignatureShareRejection(signer_id=1),
            SignatureShareRejection(signer_id=2),
        ]
        self.assertEqual(aggregate_signature(batch, self.round_info, self.key), expected)
        self.assertEqual(
            aggregate_signature(list(reversed(batch)), self.round_info, self.context),
            expected,
        )

    def test_missing_duplicate_extra_shares_rejected(self):
        with self.assertRaises(ValueError):
            aggregate_signature(self.shares[:1], self.round_info, self.context)
        with self.assertRaises(ValueError):
            aggregate_signature(
                [self.shares[0], self.shares[0], self.shares[1]],
                self.round_info,
                self.context,
            )
        extra = SignatureShare(
            signer_id=3,
            nonce_commitment=self.shares[0].nonce_commitment,
            z=self.shares[0].z,
        )
        with self.assertRaises(ValueError):
            aggregate_signature(self.shares + [extra], self.round_info, self.context)
        with self.assertRaises(ValueError):
            aggregate_signature([], self.round_info, self.context)
        with self.assertRaises(TypeError):
            aggregate_signature(["nope"], self.round_info, self.context)


class ContextValidationTest(unittest.TestCase):
    """Every public field is checked at export and at all three entry points."""

    def setUp(self):
        self.key = make_key()
        self.context = export_signing_public_context(self.key)
        self.round_info, _commitments, self.nonces = make_round(self.key)
        self.shares = make_shares(self.key, self.round_info, self.nonces)

    def _use_context(self, context):
        """Exercise the context at all three entry points."""
        create_signing_round(
            MESSAGE, (1, 2),
            [c for c, _ in [create_signing_nonce_commitment(
                signer_id, prime=FIELD_PRIME, group_prime=GROUP_PRIME,
                generator=GENERATOR, randbelow=fixed_random(signer_id),
            ) for signer_id in (1, 2)]],
            context,
        )
        verify_signature_share(self.shares[0], self.round_info, context)
        aggregate_signature(self.shares, self.round_info, context)

    def _assert_type_error(self, **field):
        context = dataclasses.replace(self.context, **field)
        with self.assertRaises(TypeError, msg=field):
            self._use_context(context)

    def _assert_value_error(self, **field):
        context = dataclasses.replace(self.context, **field)
        with self.assertRaises(ValueError, msg=field):
            self._use_context(context)

    def test_valid_context_accepted(self):
        self._use_context(self.context)

    def test_field_type_errors(self):
        self._assert_type_error(participant_ids=[1, 2, 3])
        self._assert_type_error(participant_ids=(1, "2", 3))
        self._assert_type_error(participant_ids=(1, True, 3))
        self._assert_type_error(threshold=True)
        self._assert_type_error(threshold="2")
        self._assert_type_error(field_prime=True)
        self._assert_type_error(field_prime=2017.0)
        self._assert_type_error(group_prime=False)
        self._assert_type_error(generator="16")
        self._assert_type_error(public_key=True)
        self._assert_type_error(verification_shares=[1, 2, 3])
        self._assert_type_error(verification_shares=(1, True, 3))
        self._assert_type_error(verification_shares=(1, 2, "3"))

    def test_participant_id_value_errors(self):
        self._assert_value_error(participant_ids=())
        self._assert_value_error(participant_ids=(2, 1, 3))
        self._assert_value_error(participant_ids=(1, 1, 3))
        self._assert_value_error(participant_ids=(0, 1, 2))
        self._assert_value_error(participant_ids=(1, 2, FIELD_PRIME))

    def test_threshold_value_errors(self):
        self._assert_value_error(threshold=0)
        self._assert_value_error(threshold=-1)
        self._assert_value_error(threshold=4)

    def test_verification_share_count_mismatch(self):
        self._assert_value_error(
            verification_shares=self.context.verification_shares[:2]
        )
        self._assert_value_error(
            verification_shares=self.context.verification_shares + (1,)
        )

    def test_group_parameter_value_errors(self):
        self._assert_value_error(field_prime=2018)  # not prime
        self._assert_value_error(group_prime=8070)  # not prime
        self._assert_value_error(field_prime=2017, group_prime=2 * 2017 + 2)
        self._assert_value_error(generator=1)
        self._assert_value_error(generator=GROUP_PRIME)
        # GROUP_PRIME - 1 has order 2, not 2017.
        self._assert_value_error(generator=GROUP_PRIME - 1)

    def test_public_key_value_errors(self):
        self._assert_value_error(public_key=0)
        self._assert_value_error(public_key=GROUP_PRIME)
        self._assert_value_error(public_key=GROUP_PRIME - 1)  # order 2, not in subgroup

    def test_verification_share_value_errors(self):
        shares = self.context.verification_shares
        self._assert_value_error(verification_shares=(0,) + shares[1:])
        self._assert_value_error(verification_shares=(GROUP_PRIME,) + shares[1:])
        self._assert_value_error(
            verification_shares=(GROUP_PRIME - 1,) + shares[1:]
        )

    def test_group_identity_allowed_as_public_key_and_shares(self):
        identity = dataclasses.replace(
            self.context,
            public_key=1,
            verification_shares=(1, 1, 1),
        )
        # Structurally legal: round creation works; an honest share simply
        # fails the public equation and aggregation reports the rejections.
        round_info = create_signing_round(
            MESSAGE, (1, 2),
            [create_signing_nonce_commitment(
                signer_id, prime=FIELD_PRIME, group_prime=GROUP_PRIME,
                generator=GENERATOR, randbelow=fixed_random(signer_id),
            )[0] for signer_id in (1, 2)],
            identity,
        )
        self.assertIsInstance(round_info, SigningRound)
        self.assertIs(
            verify_signature_share(self.shares[0], self.round_info, identity), False
        )
        outcome = aggregate_signature(self.shares, self.round_info, identity)
        self.assertEqual(
            outcome,
            [
                SignatureShareRejection(signer_id=1),
                SignatureShareRejection(signer_id=2),
            ],
        )

    def test_wrong_key_type_still_type_error(self):
        with self.assertRaises(TypeError):
            create_signing_round(MESSAGE, (1, 2), [], "key")
        with self.assertRaises(TypeError):
            verify_signature_share(self.shares[0], self.round_info, 42)
        with self.assertRaises(TypeError):
            aggregate_signature(self.shares, self.round_info, None)


if __name__ == "__main__":
    unittest.main()
