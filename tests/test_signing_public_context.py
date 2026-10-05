"""Tests for SigningPublicContext and its use at the signing entry points."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    SigningDKGResult,
    SigningPublicContext,
    SignatureShareRejection,
    aggregate_signature,
    create_refresh,
    create_reshare,
    create_signing_nonce_commitment,
    create_signing_round,
    export_signing_public_context,
    refresh,
    reshare,
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
    make_shares,
    make_signing_dkg,
)


def nonce_commitments(signer_ids, seed=7):
    return [
        create_signing_nonce_commitment(
            signer_id,
            prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
            randbelow=fixed_random(signer_id * 31 + seed),
        )[0]
        for signer_id in signer_ids
    ]


class ExportTest(unittest.TestCase):
    def setUp(self):
        self.dkg = make_signing_dkg()
        self.context = export_signing_public_context(self.dkg)

    def test_fields_match_source_key(self):
        pedersen = self.dkg.result.commitment
        self.assertEqual(self.context.participant_ids, (1, 2, 3))
        self.assertEqual(self.context.threshold, len(pedersen.values))
        self.assertEqual(self.context.field_prime, FIELD_PRIME)
        self.assertEqual(self.context.group_prime, GROUP_PRIME)
        self.assertEqual(self.context.generator, GENERATOR)
        self.assertEqual(self.context.public_key, self.dkg.public_key)
        self.assertEqual(
            self.context.verification_shares, self.dkg.verification_shares
        )

    def test_members_and_shares_are_aligned_tuples(self):
        self.assertIsInstance(self.context.participant_ids, tuple)
        self.assertIsInstance(self.context.verification_shares, tuple)
        self.assertEqual(
            len(self.context.participant_ids), len(self.context.verification_shares)
        )
        for share, Y_i in zip(self.dkg.result.shares, self.context.verification_shares):
            self.assertEqual(pow(GENERATOR, share.y, GROUP_PRIME), Y_i)

    def test_carries_no_secret_material(self):
        self.assertEqual(
            {f.name for f in dataclasses.fields(self.context)},
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
        for name in (
            "result",
            "shares",
            "blinding_shares",
            "secret",
            "nonce",
            "dkg_result",
        ):
            self.assertFalse(hasattr(self.context, name))

    def test_context_is_frozen(self):
        with self.assertRaises(FrozenInstanceError):
            self.context.public_key = 1  # type: ignore[misc]

    def test_direct_construction_of_equal_object(self):
        direct = SigningPublicContext(
            participant_ids=self.dkg.result.participant_ids,
            threshold=len(self.dkg.result.commitment.values),
            field_prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            public_key=self.dkg.public_key,
            verification_shares=self.dkg.verification_shares,
        )
        self.assertEqual(direct, self.context)

    def test_export_from_refresh_result(self):
        contributions = [
            create_refresh(pid, self.dkg, randbelow=fixed_random(pid + 900))
            for pid in self.dkg.result.participant_ids
        ]
        refreshed = refresh(contributions, self.dkg)
        self.assertIsInstance(refreshed, SigningDKGResult)
        context = export_signing_public_context(refreshed)
        self.assertEqual(context.public_key, self.dkg.public_key)
        self.assertEqual(context.participant_ids, self.context.participant_ids)
        # The refreshed verification shares match the refreshed secret shares.
        for share, Y_i in zip(refreshed.result.shares, context.verification_shares):
            self.assertEqual(pow(GENERATOR, share.y, GROUP_PRIME), Y_i)

    def test_export_from_reshare_result(self):
        dealers = (1, 2)
        contributions = [
            create_reshare(
                dealer,
                self.dkg.result.shares[dealer - 1].y,
                dealers,
                (1, 2, 3),
                2,
                self.dkg,
                rng=fixed_random(dealer + 700),
            )
            for dealer in dealers
        ]
        reshared = reshare(contributions, dealers, self.dkg)
        self.assertIsInstance(reshared, SigningDKGResult)
        context = export_signing_public_context(reshared)
        self.assertEqual(context.public_key, self.dkg.public_key)
        round_info, _commitments, nonces = make_round(reshared, (1, 3))
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
        dkg = make_signing_dkg((2, 5, 9), 1)
        context = export_signing_public_context(dkg)
        self.assertEqual(context.participant_ids, (2, 5, 9))
        self.assertEqual(context.threshold, 1)

    def test_export_rejects_non_key(self):
        with self.assertRaises(TypeError):
            export_signing_public_context(self.context)
        with self.assertRaises(TypeError):
            export_signing_public_context("key")

    def test_export_rejects_illegal_key(self):
        bad = dataclasses.replace(self.dkg, public_key=0)
        with self.assertRaises(ValueError):
            export_signing_public_context(bad)
        bad = dataclasses.replace(self.dkg, public_key="1")
        with self.assertRaises(TypeError):
            export_signing_public_context(bad)


class EquivalenceTest(unittest.TestCase):
    """Key and context of the same key must behave identically."""

    def setUp(self):
        self.dkg = make_signing_dkg()
        self.context = export_signing_public_context(self.dkg)
        self.round_info, self.commitments, self.nonces = make_round(self.dkg, (1, 2))
        self.shares = make_shares(self.dkg, self.round_info, self.nonces)

    def test_round_creation_matches(self):
        commitments = nonce_commitments((1, 2))
        from_key = create_signing_round(MESSAGE, (1, 2), commitments, self.dkg)
        from_context = create_signing_round(MESSAGE, (1, 2), commitments, self.context)
        self.assertEqual(from_key, from_context)

    def test_round_creation_commitment_order_irrelevant(self):
        commitments = nonce_commitments((1, 2))
        forward = create_signing_round(MESSAGE, (1, 2), commitments, self.context)
        backward = create_signing_round(
            MESSAGE, (1, 2), list(reversed(commitments)), self.context
        )
        self.assertEqual(forward, backward)

    def test_share_verdicts_match(self):
        for share in self.shares:
            self.assertIs(
                verify_signature_share(share, self.round_info, self.context), True
            )
        bad = dataclasses.replace(self.shares[0], z=(self.shares[0].z + 1) % FIELD_PRIME)
        self.assertEqual(
            verify_signature_share(bad, self.round_info, self.dkg),
            verify_signature_share(bad, self.round_info, self.context),
        )
        self.assertFalse(verify_signature_share(bad, self.round_info, self.context))

    def test_edited_round_verdicts_match(self):
        bad_round = dataclasses.replace(
            self.round_info, challenge=(self.round_info.challenge + 1) % FIELD_PRIME
        )
        self.assertFalse(verify_signature_share(self.shares[0], bad_round, self.context))
        bad_round = dataclasses.replace(
            self.round_info, R=(self.round_info.R + 1) % GROUP_PRIME
        )
        self.assertFalse(verify_signature_share(self.shares[0], bad_round, self.context))

    def test_aggregation_matches_and_verifies(self):
        from_key = aggregate_signature(self.shares, self.round_info, self.dkg)
        from_context = aggregate_signature(self.shares, self.round_info, self.context)
        self.assertEqual(from_key, from_context)
        self.assertIsInstance(from_context, AggregateSignature)
        self.assertTrue(
            verify_signature(
                MESSAGE, from_context, self.context.public_key,
                prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
            )
        )

    def test_aggregation_share_order_irrelevant(self):
        forward = aggregate_signature(self.shares, self.round_info, self.context)
        backward = aggregate_signature(
            list(reversed(self.shares)), self.round_info, self.context
        )
        self.assertEqual(forward, backward)

    def test_rejection_lists_match(self):
        bad = [
            dataclasses.replace(share, z=(share.z + 1) % FIELD_PRIME)
            for share in self.shares
        ]
        expected = [
            SignatureShareRejection(signer_id=1),
            SignatureShareRejection(signer_id=2),
        ]
        self.assertEqual(
            aggregate_signature(list(reversed(bad)), self.round_info, self.context),
            expected,
        )
        self.assertEqual(
            aggregate_signature(bad, self.round_info, self.dkg),
            aggregate_signature(bad, self.round_info, self.context),
        )

    def test_missing_duplicate_extra_shares_still_value_error(self):
        with self.assertRaises(ValueError):
            aggregate_signature(self.shares[:1], self.round_info, self.context)
        with self.assertRaises(ValueError):
            aggregate_signature(
                [self.shares[0], self.shares[0], self.shares[1]],
                self.round_info,
                self.context,
            )
        with self.assertRaises(ValueError):
            aggregate_signature([], self.round_info, self.context)

    def test_threshold_one_end_to_end(self):
        dkg = make_signing_dkg((1, 2), 1)
        context = export_signing_public_context(dkg)
        round_info, _commitments, nonces = make_round(dkg, (1,))
        shares = make_shares(dkg, round_info, nonces)
        signature = aggregate_signature(shares, round_info, context)
        self.assertTrue(
            verify_signature(
                MESSAGE, signature, context.public_key,
                prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
            )
        )

    def test_nonconsecutive_ids_end_to_end(self):
        dkg = make_signing_dkg((2, 5, 9), 2)
        context = export_signing_public_context(dkg)
        round_info, _commitments, nonces = make_round(dkg, (5, 9))
        shares = make_shares(dkg, round_info, nonces)
        for share in shares:
            self.assertTrue(verify_signature_share(share, round_info, context))
        signature = aggregate_signature(shares, round_info, context)
        self.assertTrue(
            verify_signature(
                MESSAGE, signature, context.public_key,
                prime=FIELD_PRIME, group_prime=GROUP_PRIME, generator=GENERATOR,
            )
        )


class ContextValidationTest(unittest.TestCase):
    """Directly constructed contexts are checked at every use."""

    def _context(self, **overrides):
        fields = {
            "participant_ids": (1, 2, 3),
            "threshold": 2,
            "field_prime": FIELD_PRIME,
            "group_prime": GROUP_PRIME,
            "generator": GENERATOR,
            "public_key": 1,
            "verification_shares": (1, 1, 1),
        }
        fields.update(overrides)
        return SigningPublicContext(**fields)

    def test_identity_public_key_and_shares_allowed(self):
        # The group identity passes the range and subgroup checks, matching
        # the DKG-side validation boundary: a full valid round is created.
        context = self._context()
        commitments = nonce_commitments((1, 2))
        round_info = create_signing_round(MESSAGE, (1, 2), commitments, context)
        self.assertEqual(round_info.signer_ids, (1, 2))

    def test_type_errors(self):
        commitments = nonce_commitments((1, 2))
        for overrides in (
            {"participant_ids": [1, 2, 3]},
            {"participant_ids": (1, "2", 3)},
            {"participant_ids": (1, True, 3)},
            {"threshold": True},
            {"threshold": "2"},
            {"field_prime": True},
            {"group_prime": "8069"},
            {"generator": 16.0},
            {"public_key": False},
            {"verification_shares": [1, 1, 1]},
            {"verification_shares": (1, "1", 1)},
            {"verification_shares": (1, False, 1)},
        ):
            context = self._context(**overrides)
            with self.assertRaises(TypeError, msg=overrides):
                create_signing_round(MESSAGE, (1, 2), commitments, context)
            with self.assertRaises(TypeError, msg=overrides):
                aggregate_signature([], None, context)

    def test_value_errors(self):
        commitments = nonce_commitments((1, 2))
        for overrides in (
            {"participant_ids": ()},
            {"participant_ids": (1, 1, 2)},
            {"participant_ids": (2, 1, 3)},
            {"participant_ids": (0, 1, 2)},
            {"participant_ids": (1, 2, FIELD_PRIME)},
            {"threshold": 0},
            {"threshold": 4},
            {"field_prime": 2018},
            {"group_prime": 8070},
            {"generator": 1},
            {"generator": GROUP_PRIME},
            {"generator": 2},  # not in the order-field_prime subgroup
            {"verification_shares": (1, 1)},
            {"verification_shares": (1, 1, 1, 1)},
            {"verification_shares": (1, 0, 1)},
            {"verification_shares": (1, GROUP_PRIME, 1)},
            {"verification_shares": (1, 2, 1)},  # 2 not in subgroup
            {"public_key": 0},
            {"public_key": GROUP_PRIME},
            {"public_key": 2},
        ):
            context = self._context(**overrides)
            with self.assertRaises(ValueError, msg=overrides):
                create_signing_round(MESSAGE, (1, 2), commitments, context)

    def test_field_prime_must_divide_group_minus_one(self):
        import thresholdsign

        # 4057 is prime but 4056 % 2017 != 0.
        self.assertTrue(thresholdsign._is_prime(4057))
        self.assertNotEqual(4056 % FIELD_PRIME, 0)
        context = self._context(group_prime=4057)
        with self.assertRaises(ValueError):
            create_signing_round(MESSAGE, (1, 2), nonce_commitments((1, 2)), context)

    def test_non_key_non_context_rejected(self):
        commitments = nonce_commitments((1, 2))
        with self.assertRaises(TypeError):
            create_signing_round(MESSAGE, (1, 2), commitments, "key")
        dkg = make_signing_dkg()
        round_info, _commitments, nonces = make_round(dkg, (1, 2))
        share = make_shares(dkg, round_info, nonces)[0]
        with self.assertRaises(TypeError):
            verify_signature_share(share, round_info, object())
        with self.assertRaises(TypeError):
            aggregate_signature([], round_info, 42)


if __name__ == "__main__":
    unittest.main()
