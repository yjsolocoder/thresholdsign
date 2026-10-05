"""Tests for aggregate_share_receipts: share receipts -> SignatureReceipt."""

import dataclasses
import unittest

from thresholdsign import (
    AggregateSignature,
    SignatureReceipt,
    SigningPublicContext,
    aggregate_share_receipts,
    aggregate_signature,
    create_refresh,
    create_signature_receipt,
    create_signature_share_receipt,
    decode_signature_receipt,
    encode_signature_receipt,
    export_signing_public_context,
    refresh,
    verify_signature_receipt,
)
from tests.test_signing import (
    FIELD_PRIME,
    GROUP_PRIME,
    GENERATOR,
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


def make_receipt_batch(dkg=None, signer_ids=(1, 2), message=MESSAGE, seed=10):
    """Run a full round and package every share as a receipt plus context."""
    dkg = dkg if dkg is not None else make_signing_dkg()
    round_info, _commitments, nonces = make_round(dkg, signer_ids, message, seed=seed)
    shares = make_shares(dkg, round_info, nonces)
    receipts = [
        create_signature_share_receipt(message, share, round_info, dkg)
        for share in shares
    ]
    context = export_signing_public_context(dkg)
    return dkg, round_info, shares, receipts, context


class AggregateShareReceiptsTest(unittest.TestCase):
    def test_matches_existing_aggregation_and_receipt_pipeline(self):
        dkg, round_info, shares, receipts, context = make_receipt_batch()
        expected = create_signature_receipt(
            MESSAGE, aggregate_signature(shares, round_info, dkg), dkg
        )
        result = aggregate_share_receipts(receipts, context)
        self.assertIsInstance(result, SignatureReceipt)
        self.assertEqual(result, expected)
        self.assertEqual(result.message, MESSAGE)
        self.assertEqual(result.signature.signer_ids, (1, 2))
        self.assertEqual(result.signature.R, round_info.R)
        self.assertEqual(
            result.signature.z,
            sum(share.z for share in shares) % FIELD_PRIME,
        )
        self.assertEqual(result.public_key, context.public_key)
        self.assertEqual(
            (result.field_prime, result.group_prime, result.generator),
            (FIELD_PRIME, GROUP_PRIME, GENERATOR),
        )

    def test_result_uses_existing_codec_and_verify_entries(self):
        _dkg, _r, _s, receipts, context = make_receipt_batch()
        result = aggregate_share_receipts(receipts, context)
        self.assertTrue(verify_signature_receipt(result))
        blob = encode_signature_receipt(result)
        decoded = decode_signature_receipt(blob)
        self.assertEqual(decoded, result)
        self.assertTrue(verify_signature_receipt(decoded))
        self.assertEqual(encode_signature_receipt(decoded), blob)

    def test_accepts_one_shot_generator(self):
        _dkg, _r, _s, receipts, context = make_receipt_batch()
        expected = aggregate_share_receipts(receipts, context)
        self.assertEqual(
            aggregate_share_receipts(
                (receipt for receipt in receipts), context
            ),
            expected,
        )
        self.assertEqual(
            aggregate_share_receipts(iter(receipts), context), expected
        )

    def test_input_order_does_not_matter(self):
        _dkg, _r, _s, receipts, context = make_receipt_batch(
            signer_ids=(1, 2, 3)
        )
        baseline = aggregate_share_receipts(receipts, context)
        self.assertEqual(aggregate_share_receipts(receipts[::-1], context), baseline)
        rotated = receipts[1:] + receipts[:1]
        self.assertEqual(aggregate_share_receipts(rotated, context), baseline)

    def test_inputs_are_not_mutated(self):
        _dkg, _r, _s, receipts, context = make_receipt_batch()
        snapshot = list(receipts)
        aggregate_share_receipts(receipts, context)
        self.assertEqual(receipts, snapshot)

    def test_empty_message(self):
        _dkg, _r, _s, receipts, context = make_receipt_batch(message=b"")
        result = aggregate_share_receipts(receipts, context)
        self.assertEqual(result.message, b"")
        self.assertTrue(verify_signature_receipt(result))

    def test_threshold_one(self):
        dkg = make_signing_dkg((1, 2), 1)
        _dkg, _r, _s, receipts, context = make_receipt_batch(dkg, signer_ids=(2,))
        result = aggregate_share_receipts(receipts, context)
        self.assertEqual(result.signature.signer_ids, (2,))
        self.assertTrue(verify_signature_receipt(result))

    def test_over_threshold_full_signing_set(self):
        dkg = make_signing_dkg((1, 2, 3, 4), 2)
        _dkg, _r, shares, receipts, context = make_receipt_batch(
            dkg, signer_ids=(1, 2, 3, 4)
        )
        result = aggregate_share_receipts(receipts, context)
        self.assertEqual(result.signature.signer_ids, (1, 2, 3, 4))
        self.assertEqual(
            result.signature.z,
            sum(share.z for share in shares) % FIELD_PRIME,
        )
        self.assertTrue(verify_signature_receipt(result))

    def test_large_group(self):
        dkg = make_signing_dkg(
            (1, 2, 3), 2,
            field_prime=LARGE_FIELD, group_prime=LARGE_GROUP,
            generator=LARGE_G, blinding_generator=LARGE_H,
        )
        _dkg, _r, _s, receipts, context = make_receipt_batch(dkg)
        result = aggregate_share_receipts(receipts, context)
        self.assertEqual(
            (result.field_prime, result.group_prime, result.generator),
            (LARGE_FIELD, LARGE_GROUP, LARGE_G),
        )
        self.assertTrue(verify_signature_receipt(result))

    def test_directly_constructed_context_behaves_identically(self):
        _dkg, _r, _s, receipts, context = make_receipt_batch()
        direct = SigningPublicContext(
            participant_ids=context.participant_ids,
            threshold=context.threshold,
            field_prime=context.field_prime,
            group_prime=context.group_prime,
            generator=context.generator,
            public_key=context.public_key,
            verification_shares=context.verification_shares,
        )
        self.assertEqual(
            aggregate_share_receipts(receipts, direct),
            aggregate_share_receipts(receipts, context),
        )


class AggregateShareReceiptsTypeTest(unittest.TestCase):
    def setUp(self):
        (_dkg, _r, _s, self.receipts, self.context) = make_receipt_batch()

    def test_non_iterable_receipts_raise_type_error(self):
        with self.assertRaises(TypeError):
            aggregate_share_receipts(None, self.context)
        with self.assertRaises(TypeError):
            aggregate_share_receipts(42, self.context)
        with self.assertRaises(TypeError):
            aggregate_share_receipts(self.receipts[0], self.context)

    def test_wrong_context_type_raises_type_error(self):
        dkg, _r, _s, receipts, context = make_receipt_batch()
        with self.assertRaises(TypeError):
            aggregate_share_receipts(receipts, dkg)
        with self.assertRaises(TypeError):
            aggregate_share_receipts(receipts, "context")
        with self.assertRaises(TypeError):
            aggregate_share_receipts(receipts, None)

    def test_wrong_element_type_raises_type_error(self):
        with self.assertRaises(TypeError):
            aggregate_share_receipts([self.receipts[0], "receipt"], self.context)
        with self.assertRaises(TypeError):
            aggregate_share_receipts([None, None], self.context)

    def test_receipt_field_type_errors_raise_type_error(self):
        bad = dataclasses.replace(self.receipts[0], message="not bytes")
        with self.assertRaises(TypeError):
            aggregate_share_receipts([bad, self.receipts[1]], self.context)
        bad = dataclasses.replace(self.receipts[0], signer_ids=[1, 2])
        with self.assertRaises(TypeError):
            aggregate_share_receipts([bad, self.receipts[1]], self.context)

    def test_bool_is_not_an_integer(self):
        bad = dataclasses.replace(self.receipts[0], z_i=True)
        with self.assertRaises(TypeError):
            aggregate_share_receipts([bad, self.receipts[1]], self.context)
        bad_context = dataclasses.replace(self.context, threshold=True)
        with self.assertRaises(TypeError):
            aggregate_share_receipts(self.receipts, bad_context)


class AggregateShareReceiptsValueTest(unittest.TestCase):
    def setUp(self):
        (self.dkg, self.round_info, self.shares,
         self.receipts, self.context) = make_receipt_batch()

    def test_empty_batch_raises_value_error(self):
        with self.assertRaises(ValueError):
            aggregate_share_receipts([], self.context)
        with self.assertRaises(ValueError):
            aggregate_share_receipts(iter(()), self.context)

    def test_duplicate_receipt_raises_value_error(self):
        batch = [self.receipts[0], self.receipts[0]]
        with self.assertRaises(ValueError):
            aggregate_share_receipts(batch, self.context)

    def test_missing_receipt_raises_value_error(self):
        with self.assertRaises(ValueError):
            aggregate_share_receipts(self.receipts[:1], self.context)

    def test_threshold_subset_is_not_accepted(self):
        # Three signers, threshold two: dropping any one receipt must fail
        # even though two receipts would meet the threshold.
        _dkg, _r, _s, receipts, context = make_receipt_batch(
            signer_ids=(1, 2, 3)
        )
        self.assertEqual(context.threshold, 2)
        with self.assertRaises(ValueError):
            aggregate_share_receipts(receipts[:2], context)

    def test_unknown_member_raises_value_error(self):
        # A context whose participant set does not contain signer 2.
        context = dataclasses.replace(
            self.context,
            participant_ids=(1, 3),
            verification_shares=(
                self.context.verification_shares[0],
                self.context.verification_shares[2],
            ),
        )
        with self.assertRaises(ValueError):
            aggregate_share_receipts(self.receipts, context)

    def test_below_threshold_raises_value_error(self):
        context = dataclasses.replace(self.context, threshold=3)
        with self.assertRaises(ValueError):
            aggregate_share_receipts(self.receipts, context)

    def test_out_of_range_field_raises_value_error(self):
        bad = dataclasses.replace(self.receipts[0], z_i=FIELD_PRIME)
        with self.assertRaises(ValueError):
            aggregate_share_receipts([bad, self.receipts[1]], self.context)

    def test_illegal_group_parameters_raise_value_error(self):
        bad = dataclasses.replace(self.receipts[0], q=2018)
        with self.assertRaises(ValueError):
            aggregate_share_receipts([bad, self.receipts[1]], self.context)

    def test_context_key_mismatch_raises_value_error(self):
        other_dkg = make_signing_dkg(seed_base=5000)
        other_context = export_signing_public_context(other_dkg)
        self.assertNotEqual(other_context.public_key, self.context.public_key)
        with self.assertRaises(ValueError):
            aggregate_share_receipts(self.receipts, other_context)

    def test_context_generator_mismatch_raises_value_error(self):
        # 256 = 16 ** 2 is another generator of the same subgroup.
        context = dataclasses.replace(self.context, generator=256)
        with self.assertRaises(ValueError):
            aggregate_share_receipts(self.receipts, context)

    def test_context_verification_share_mismatch_raises_value_error(self):
        shares = list(self.context.verification_shares)
        shares[0] = self.context.verification_shares[1]
        shares[1] = self.context.verification_shares[0]
        context = dataclasses.replace(
            self.context, verification_shares=tuple(shares)
        )
        with self.assertRaises(ValueError):
            aggregate_share_receipts(self.receipts, context)

    def test_inconsistent_receipts_raise_value_error(self):
        other = make_receipt_batch(seed=77)
        for index in (0, 1):
            mixed = [self.receipts[index], other[3][index]]
            with self.assertRaises(ValueError):
                aggregate_share_receipts(mixed, self.context)
        # Same signers, another message: the message fields differ.
        other_message = make_receipt_batch(message=b"another message")
        mixed = [self.receipts[0], other_message[3][1]]
        with self.assertRaises(ValueError):
            aggregate_share_receipts(mixed, self.context)

    def test_tampered_signer_set_raises_value_error(self):
        bad = dataclasses.replace(self.receipts[0], signer_ids=(1, 3))
        with self.assertRaises(ValueError):
            aggregate_share_receipts([bad, self.receipts[1]], self.context)

    def test_duplicate_commitment_raises_value_error(self):
        bad = dataclasses.replace(self.receipts[1], R_i=self.receipts[0].R_i)
        with self.assertRaises(ValueError):
            aggregate_share_receipts([self.receipts[0], bad], self.context)

    def test_commitment_product_mismatch_raises_value_error(self):
        altered = pow(self.receipts[0].R_i, 2, GROUP_PRIME)
        self.assertNotEqual(altered, self.receipts[0].R_i)
        self.assertNotEqual(altered, self.receipts[1].R_i)
        bad = dataclasses.replace(self.receipts[0], R_i=altered)
        with self.assertRaises(ValueError):
            aggregate_share_receipts([bad, self.receipts[1]], self.context)

    def test_non_subgroup_commitment_raises_value_error(self):
        bad = dataclasses.replace(self.receipts[0], R_i=2)
        with self.assertRaises(ValueError):
            aggregate_share_receipts([bad, self.receipts[1]], self.context)
        identity = dataclasses.replace(self.receipts[0], R_i=1)
        with self.assertRaises(ValueError):
            aggregate_share_receipts([identity, self.receipts[1]], self.context)

    def test_share_equation_failure_raises_value_error(self):
        bad = dataclasses.replace(
            self.receipts[0], z_i=(self.receipts[0].z_i + 1) % FIELD_PRIME
        )
        with self.assertRaises(ValueError):
            aggregate_share_receipts([bad, self.receipts[1]], self.context)

    def test_tampered_aggregate_R_raises_value_error(self):
        other = make_receipt_batch(seed=77)[3]
        bad = dataclasses.replace(self.receipts[0], R=other[0].R)
        with self.assertRaises(ValueError):
            aggregate_share_receipts([bad, self.receipts[1]], self.context)

    def test_failure_returns_no_partial_signature(self):
        bad = dataclasses.replace(
            self.receipts[0], z_i=(self.receipts[0].z_i + 1) % FIELD_PRIME
        )
        with self.assertRaises(ValueError) as caught:
            aggregate_share_receipts([bad, self.receipts[1]], self.context)
        self.assertNotIsInstance(caught.exception, SignatureReceipt)
        self.assertNotIsInstance(caught.exception, AggregateSignature)


class AggregateShareReceiptsRefreshTest(unittest.TestCase):
    """Receipts are checked against the context's current verification shares."""

    def test_receipts_from_before_refresh_are_rejected(self):
        dkg, _r, _s, receipts, context = make_receipt_batch()
        contributions = [
            create_refresh(pid, dkg, randbelow=fixed_random(pid + 100))
            for pid in dkg.result.participant_ids
        ]
        refreshed = refresh(contributions, dkg)
        refreshed_context = export_signing_public_context(refreshed)
        # The joint key is unchanged but the verification shares moved.
        self.assertEqual(refreshed_context.public_key, context.public_key)
        self.assertNotEqual(
            refreshed_context.verification_shares, context.verification_shares
        )
        with self.assertRaises(ValueError):
            aggregate_share_receipts(receipts, refreshed_context)

    def test_receipts_created_after_refresh_aggregate(self):
        dkg = make_signing_dkg()
        contributions = [
            create_refresh(pid, dkg, randbelow=fixed_random(pid + 100))
            for pid in dkg.result.participant_ids
        ]
        refreshed = refresh(contributions, dkg)
        _dkg, _r, _s, receipts, context = make_receipt_batch(refreshed)
        result = aggregate_share_receipts(receipts, context)
        self.assertTrue(verify_signature_receipt(result))
        self.assertEqual(result.public_key, dkg.public_key)


if __name__ == "__main__":
    unittest.main()
