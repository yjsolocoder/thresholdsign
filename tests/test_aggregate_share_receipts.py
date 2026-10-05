"""Tests for aggregate_share_receipts: share receipts -> SignatureReceipt."""

import dataclasses
import unittest

from thresholdsign import (
    AggregateSignature,
    SignatureReceipt,
    SignatureShareReceipt,
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
    GENERATOR,
    GROUP_PRIME,
    MESSAGE,
    fixed_random,
    make_round,
    make_shares,
    make_signing_dkg,
)


def make_receipts(dkg=None, signer_ids=(1, 2), message=MESSAGE, seed=10):
    """Run a full round and return (dkg, round, shares, receipts, context)."""
    dkg = dkg or make_signing_dkg()
    round_info, _commitments, nonces = make_round(
        dkg, signer_ids, message, seed=seed
    )
    shares = make_shares(dkg, round_info, nonces)
    receipts = [
        create_signature_share_receipt(message, share, round_info, dkg)
        for share in shares
    ]
    context = export_signing_public_context(dkg)
    return dkg, round_info, shares, receipts, context


class AggregateShareReceiptsTest(unittest.TestCase):
    def test_matches_aggregate_signature_and_create_signature_receipt(self):
        dkg, round_info, shares, receipts, context = make_receipts()
        result = aggregate_share_receipts(receipts, context)
        expected = create_signature_receipt(
            MESSAGE, aggregate_signature(shares, round_info, dkg), dkg
        )
        self.assertIsInstance(result, SignatureReceipt)
        self.assertEqual(result, expected)
        self.assertEqual(result.message, MESSAGE)
        self.assertEqual(result.signature.signer_ids, (1, 2))
        self.assertEqual(result.signature.R, round_info.R)
        self.assertEqual(
            result.signature.z, sum(share.z for share in shares) % FIELD_PRIME
        )
        self.assertEqual(result.public_key, context.public_key)
        self.assertEqual(
            (result.field_prime, result.group_prime, result.generator),
            (FIELD_PRIME, GROUP_PRIME, GENERATOR),
        )

    def test_result_verifies_encodes_and_decodes(self):
        _dkg, _r, _s, receipts, context = make_receipts()
        result = aggregate_share_receipts(receipts, context)
        self.assertTrue(verify_signature_receipt(result))
        self.assertEqual(
            decode_signature_receipt(encode_signature_receipt(result)), result
        )

    def test_one_shot_generator_input(self):
        _dkg, _r, _s, receipts, context = make_receipts()
        result = aggregate_share_receipts(
            (receipt for receipt in receipts), context
        )
        self.assertEqual(result, aggregate_share_receipts(receipts, context))

    def test_input_order_irrelevant_and_inputs_untouched(self):
        _dkg, _r, _s, receipts, context = make_receipts(
            signer_ids=(1, 2, 3)
        )
        snapshot = list(receipts)
        forward = aggregate_share_receipts(receipts, context)
        backward = aggregate_share_receipts(list(reversed(receipts)), context)
        rotated = aggregate_share_receipts(receipts[1:] + receipts[:1], context)
        self.assertEqual(forward, backward)
        self.assertEqual(forward, rotated)
        self.assertEqual(receipts, snapshot)

    def test_full_set_above_threshold(self):
        dkg, round_info, shares, receipts, context = make_receipts(
            signer_ids=(1, 2, 3)
        )
        result = aggregate_share_receipts(receipts, context)
        self.assertEqual(result.signature.signer_ids, (1, 2, 3))
        expected = create_signature_receipt(
            MESSAGE, aggregate_signature(shares, round_info, dkg), dkg
        )
        self.assertEqual(result, expected)
        self.assertTrue(verify_signature_receipt(result))

    def test_threshold_one_and_empty_message(self):
        dkg = make_signing_dkg((1, 2), 1)
        _dkg, _r, _s, receipts, context = make_receipts(
            dkg, signer_ids=(2,), message=b""
        )
        result = aggregate_share_receipts(receipts, context)
        self.assertEqual(result.message, b"")
        self.assertEqual(result.signature.signer_ids, (2,))
        self.assertTrue(verify_signature_receipt(result))

    def test_refreshed_context_current_verification_shares(self):
        dkg, _r, _s, stale_receipts, _context = make_receipts()
        contributions = [
            create_refresh(pid, dkg, randbelow=fixed_random(pid + 100))
            for pid in dkg.result.participant_ids
        ]
        refreshed = refresh(contributions, dkg)
        refreshed_context = export_signing_public_context(refreshed)
        self.assertEqual(refreshed_context.public_key, dkg.public_key)
        # The joint key is unchanged but the verification shares rotated:
        # receipts carrying the stale Y_i are rejected.
        with self.assertRaises(ValueError):
            aggregate_share_receipts(stale_receipts, refreshed_context)
        # Receipts minted under the refreshed key pass against its context.
        _d, _r, _s, fresh_receipts, fresh_context = make_receipts(refreshed)
        self.assertEqual(fresh_context, refreshed_context)
        result = aggregate_share_receipts(fresh_receipts, refreshed_context)
        self.assertTrue(verify_signature_receipt(result))

    def test_non_iterable_receipts_raises_type_error(self):
        _dkg, _r, _s, receipts, context = make_receipts()
        for bad in (42, 3.5, None, b"bytes", "text"):
            with self.assertRaises(TypeError):
                aggregate_share_receipts(bad, context)

    def test_wrong_context_type_raises_type_error(self):
        dkg, _r, _s, receipts, context = make_receipts()
        for bad in (dkg, None, 42, "context"):
            with self.assertRaises(TypeError):
                aggregate_share_receipts(receipts, bad)
        broken = dataclasses.replace(context, threshold=True)
        with self.assertRaises(TypeError):
            aggregate_share_receipts(receipts, broken)

    def test_wrong_element_type_raises_type_error(self):
        _dkg, _r, shares, receipts, context = make_receipts()
        for bad_element in (shares[0], 42, "receipt", None):
            with self.assertRaises(TypeError):
                aggregate_share_receipts([bad_element], context)
        with self.assertRaises(TypeError):
            aggregate_share_receipts([receipts[0], shares[1]], context)

    def test_wrong_field_type_raises_type_error(self):
        _dkg, _r, _s, receipts, context = make_receipts()
        for field, value in (
            ("message", "not bytes"),
            ("R", "1"),
            ("signer_ids", [1, 2]),
            ("signer_id", True),
            ("Y_i", 1.5),
            ("Y", False),
            ("q", None),
            ("p", "8069"),
            ("g", True),
            ("R_i", 2.0),
            ("z_i", True),
        ):
            broken = dataclasses.replace(receipts[0], **{field: value})
            with self.assertRaises(TypeError, msg=field):
                aggregate_share_receipts([broken, receipts[1]], context)
        broken = dataclasses.replace(receipts[0], signer_ids=(1, True))
        with self.assertRaises(TypeError):
            aggregate_share_receipts([broken, receipts[1]], context)

    def test_out_of_range_and_bad_group_values_raise_value_error(self):
        _dkg, _r, _s, receipts, context = make_receipts()
        for field, value in (
            ("z_i", FIELD_PRIME),
            ("z_i", -1),
            ("R_i", 1),
            ("R_i", GROUP_PRIME),
            ("Y_i", 0),
            ("q", 4),
            ("p", 8),
            ("g", 1),
            ("signer_id", 3),
        ):
            broken = dataclasses.replace(receipts[0], **{field: value})
            with self.assertRaises(ValueError, msg=field):
                aggregate_share_receipts([broken, receipts[1]], context)

    def test_empty_collection_raises_value_error(self):
        _dkg, _r, _s, _receipts, context = make_receipts()
        with self.assertRaises(ValueError):
            aggregate_share_receipts([], context)

    def test_duplicate_and_missing_receipt_raise_value_error(self):
        _dkg, _r, _s, receipts, context = make_receipts()
        with self.assertRaises(ValueError):
            aggregate_share_receipts([receipts[0], receipts[0]], context)
        with self.assertRaises(ValueError):
            aggregate_share_receipts(receipts[:1], context)

    def test_threshold_sized_subset_of_larger_set_raises_value_error(self):
        _dkg, _r, _s, receipts, context = make_receipts(signer_ids=(1, 2, 3))
        # Two of three receipts meet the threshold but not the declared set.
        with self.assertRaises(ValueError):
            aggregate_share_receipts(receipts[:2], context)

    def test_unknown_member_raises_value_error(self):
        _dkg, _r, _s, receipts, context = make_receipts()
        moved = [
            dataclasses.replace(receipt, signer_ids=(1, 2, 4))
            for receipt in receipts
        ]
        with self.assertRaises(ValueError):
            aggregate_share_receipts(moved, context)

    def test_below_threshold_set_raises_value_error(self):
        dkg = make_signing_dkg((1, 2, 3), 3)
        _dkg, _r, _s, receipts, context = make_receipts(
            dkg, signer_ids=(1, 2, 3)
        )
        shrunk = [
            dataclasses.replace(receipt, signer_ids=(1, 2))
            for receipt in receipts
            if receipt.signer_id in (1, 2)
        ]
        with self.assertRaises(ValueError):
            aggregate_share_receipts(shrunk, context)

    def test_context_mismatch_raises_value_error(self):
        _dkg, _r, _s, receipts, _context = make_receipts()
        other = export_signing_public_context(
            make_signing_dkg(seed_base=500)
        )
        self.assertNotEqual(other.public_key, _context.public_key)
        with self.assertRaises(ValueError):
            aggregate_share_receipts(receipts, other)

    def test_verification_share_mismatch_raises_value_error(self):
        _dkg, _r, _s, receipts, context = make_receipts()
        other_position = context.participant_ids.index(receipts[0].signer_id) - 1
        stale_y_i = context.verification_shares[other_position]
        broken = dataclasses.replace(receipts[0], Y_i=stale_y_i)
        with self.assertRaises(ValueError):
            aggregate_share_receipts([broken, receipts[1]], context)

    def test_inconsistent_receipts_raise_value_error(self):
        _dkg, _r, _s, receipts, context = make_receipts()
        _d2, _r2, _s2, other_receipts, _c2 = make_receipts(
            message=b"a different message"
        )
        with self.assertRaises(ValueError):
            aggregate_share_receipts(
                [receipts[0], other_receipts[1]], context
            )
        # Same message, different round: the aggregate R differs.
        _d3, _r3, _s3, later_receipts, _c3 = make_receipts(seed=77)
        self.assertNotEqual(later_receipts[0].R, receipts[0].R)
        with self.assertRaises(ValueError):
            aggregate_share_receipts([receipts[0], later_receipts[1]], context)

    def test_commitment_product_mismatch_raises_value_error(self):
        _dkg, _r, _s, receipts, context = make_receipts()
        _d2, _r2, _s2, other_receipts, _c2 = make_receipts(seed=77)
        self.assertNotEqual(other_receipts[0].R, receipts[0].R)
        moved_r = [
            dataclasses.replace(receipt, R=other_receipts[0].R)
            for receipt in receipts
        ]
        with self.assertRaises(ValueError):
            aggregate_share_receipts(moved_r, context)

    def test_duplicate_commitment_value_raises_value_error(self):
        _dkg, _r, _s, receipts, context = make_receipts()
        copied = dataclasses.replace(receipts[1], R_i=receipts[0].R_i)
        with self.assertRaises(ValueError):
            aggregate_share_receipts([receipts[0], copied], context)

    def test_failing_share_equation_raises_value_error(self):
        _dkg, _r, _s, receipts, context = make_receipts()
        tampered = dataclasses.replace(
            receipts[0], z_i=(receipts[0].z_i + 1) % FIELD_PRIME
        )
        with self.assertRaises(ValueError):
            aggregate_share_receipts([tampered, receipts[1]], context)

    def test_failure_is_order_independent(self):
        _dkg, _r, _s, receipts, context = make_receipts()
        tampered = dataclasses.replace(
            receipts[0], z_i=(receipts[0].z_i + 1) % FIELD_PRIME
        )
        for ordering in (
            [tampered, receipts[1]],
            [receipts[1], tampered],
        ):
            with self.assertRaises(ValueError):
                aggregate_share_receipts(ordering, context)

    def test_no_partial_signature_on_failure(self):
        _dkg, _r, _s, receipts, context = make_receipts()
        tampered = dataclasses.replace(
            receipts[1], z_i=(receipts[1].z_i + 1) % FIELD_PRIME
        )
        try:
            aggregate_share_receipts([receipts[0], tampered], context)
        except ValueError:
            pass
        else:
            self.fail("expected ValueError")
        # The untampered batch still aggregates afterwards: no hidden state.
        result = aggregate_share_receipts(receipts, context)
        self.assertTrue(verify_signature_receipt(result))


if __name__ == "__main__":
    unittest.main()
