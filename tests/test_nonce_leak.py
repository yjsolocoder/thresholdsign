"""Tests for leaked-share recovery: NonceLeak / recover_leaks."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    NonceLeak,
    SignatureShare,
    SigningAudit,
    create_audit,
    find_nonce_reuse,
    recover_leaks,
)

from test_nonce_reuse import (
    FIELD_PRIME,
    GROUP_PRIME,
    GENERATOR,
    MESSAGE_A,
    MESSAGE_B,
    MESSAGE_C,
    MESSAGE_D,
    make_key,
    make_record,
    make_round,
)


def expected_share(key, signer_id):
    return key.result.shares[key.result.participant_ids.index(signer_id)].y


class NonceLeakTest(unittest.TestCase):
    def test_frozen_fields_value_equality(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(NonceLeak)],
            ["signer_id", "commitment", "share", "receipts"],
        )
        receipts = (SigningAudit(b"a"), SigningAudit(b"b"))
        leak = NonceLeak(1, 42, 7, receipts)  # positional construction
        self.assertEqual(leak, NonceLeak(1, 42, 7, receipts))
        self.assertEqual(
            leak,
            NonceLeak(signer_id=1, commitment=42, share=7, receipts=receipts),
        )
        self.assertNotEqual(leak, NonceLeak(2, 42, 7, receipts))
        self.assertNotEqual(leak, NonceLeak(1, 43, 7, receipts))
        self.assertNotEqual(leak, NonceLeak(1, 42, 8, receipts))
        self.assertNotEqual(leak, NonceLeak(1, 42, 7, (SigningAudit(b"a"),)))
        self.assertEqual(hash(leak), hash(NonceLeak(1, 42, 7, receipts)))
        with self.assertRaises(FrozenInstanceError):
            leak.share = 8


class RecoverLeaksTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()

    def test_no_reuse_recovers_nothing(self):
        records = [
            make_record(self.key, MESSAGE_A, seed=100),
            make_record(self.key, MESSAGE_B, seed=200),
        ]
        self.assertEqual(recover_leaks(records, self.key), ())
        self.assertEqual(recover_leaks([], self.key), ())

    def test_reused_nonce_recovers_secret_share(self):
        record_a = make_record(self.key, MESSAGE_A, seed=100, nonces={1: 777})
        record_b = make_record(self.key, MESSAGE_B, seed=200, nonces={1: 777})
        leaks = recover_leaks([record_a, record_b], self.key)
        self.assertEqual(len(leaks), 1)
        leak = leaks[0]
        self.assertIsInstance(leak, NonceLeak)
        self.assertEqual(leak.signer_id, 1)
        self.assertEqual(leak.commitment, pow(GENERATOR, 777, GROUP_PRIME))
        self.assertEqual(leak.share, expected_share(self.key, 1))
        self.assertEqual(
            leak.receipts,
            tuple(sorted((record_a[1], record_b[1]), key=lambda a: a.payload)),
        )

    def test_recovery_matches_verification_share(self):
        record_a = make_record(self.key, MESSAGE_A, seed=100, nonces={3: 555})
        record_b = make_record(self.key, MESSAGE_B, seed=200, nonces={3: 555})
        leak = recover_leaks([record_a, record_b], self.key)[0]
        self.assertEqual(leak.signer_id, 3)
        self.assertEqual(
            pow(GENERATOR, leak.share, GROUP_PRIME),
            self.key.verification_shares[2],
        )

    def test_same_receipt_twice_recovers_nothing(self):
        record = make_record(self.key, MESSAGE_A, nonces={1: 777})
        self.assertEqual(recover_leaks([record, record], self.key), ())

    def test_failed_status_receipts_do_not_participate(self):
        round_info, shares = make_round(
            self.key, MESSAGE_B, seed=200, nonces={1: 777}
        )
        bad = SignatureShare(
            signer_id=shares[0].signer_id,
            nonce_commitment=shares[0].nonce_commitment,
            z=(shares[0].z + 1) % FIELD_PRIME,
        )
        failing = (
            MESSAGE_B,
            create_audit(MESSAGE_B, [bad, shares[1]], round_info, self.key),
        )
        passing = make_record(self.key, MESSAGE_A, seed=100, nonces={1: 777})
        self.assertEqual(recover_leaks([passing, failing], self.key), ())

    def test_three_receipts_pick_smallest_payload_pair(self):
        record_a = make_record(self.key, MESSAGE_A, seed=100, nonces={1: 777})
        record_b = make_record(self.key, MESSAGE_B, seed=200, nonces={1: 777})
        record_c = make_record(self.key, MESSAGE_C, seed=300, nonces={1: 777})
        leaks = recover_leaks([record_c, record_a, record_b], self.key)
        self.assertEqual(len(leaks), 1)
        ordered = sorted(
            (record_a[1], record_b[1], record_c[1]), key=lambda a: a.payload
        )
        # Distinct messages give distinct challenges, so the pair is the two
        # smallest payloads.
        self.assertEqual(leaks[0].receipts, (ordered[0], ordered[1]))
        self.assertEqual(leaks[0].share, expected_share(self.key, 1))

    def test_multiple_leaks_sorted_by_signer_id_then_commitment(self):
        nonce_1, nonce_3a, nonce_3b = 41, 42, 43
        r_1 = pow(GENERATOR, nonce_1, GROUP_PRIME)
        r_3a = pow(GENERATOR, nonce_3a, GROUP_PRIME)
        r_3b = pow(GENERATOR, nonce_3b, GROUP_PRIME)
        records = [
            make_record(
                self.key, MESSAGE_A, seed=100, nonces={1: nonce_1, 3: nonce_3a}
            ),
            make_record(
                self.key, MESSAGE_B, seed=200, nonces={1: nonce_1, 3: nonce_3b}
            ),
            make_record(
                self.key, MESSAGE_C, seed=300, nonces={1: 901, 3: nonce_3a}
            ),
            make_record(
                self.key, MESSAGE_D, seed=400, nonces={1: 902, 3: nonce_3b}
            ),
        ]
        leaks = recover_leaks(records, self.key)
        self.assertEqual(
            [(leak.signer_id, leak.commitment) for leak in leaks],
            [(1, r_1), (3, min(r_3a, r_3b)), (3, max(r_3a, r_3b))],
        )
        self.assertEqual(
            [leak.share for leak in leaks],
            [expected_share(self.key, 1)] + [expected_share(self.key, 3)] * 2,
        )

    def test_input_order_does_not_matter(self):
        record_a = make_record(self.key, MESSAGE_A, seed=100, nonces={1: 111})
        record_b = make_record(
            self.key, MESSAGE_B, seed=200, nonces={1: 111, 3: 222}
        )
        record_c = make_record(self.key, MESSAGE_C, seed=300, nonces={3: 222})
        forward = recover_leaks([record_a, record_b, record_c], self.key)
        backward = recover_leaks([record_c, record_b, record_a], self.key)
        self.assertEqual(forward, backward)
        self.assertEqual(len(forward), 2)

    def test_grouping_matches_find_nonce_reuse(self):
        record_a = make_record(self.key, MESSAGE_A, seed=100, nonces={1: 777})
        record_b = make_record(self.key, MESSAGE_B, seed=200, nonces={1: 777})
        records = [record_a, record_b]
        reuses = find_nonce_reuse(records, self.key)
        leaks = recover_leaks(records, self.key)
        self.assertEqual(
            [(r.signer_id, r.nonce_commitment) for r in reuses],
            [(leak.signer_id, leak.commitment) for leak in leaks],
        )

    def test_type_errors(self):
        record = make_record(self.key, MESSAGE_A)
        with self.assertRaises(TypeError):
            recover_leaks("records", self.key)
        with self.assertRaises(TypeError):
            recover_leaks(b"records", self.key)
        with self.assertRaises(TypeError):
            recover_leaks([MESSAGE_A], self.key)
        with self.assertRaises(TypeError):
            recover_leaks([("message", record[1])], self.key)
        with self.assertRaises(TypeError):
            recover_leaks([(MESSAGE_A, "receipt")], self.key)
        with self.assertRaises(TypeError):
            recover_leaks([record], "key")
        with self.assertRaises(TypeError):
            recover_leaks([record], None)

    def test_mismatched_message_raises_value_error(self):
        record = make_record(self.key, MESSAGE_A)
        with self.assertRaises(ValueError):
            recover_leaks([(MESSAGE_B, record[1])], self.key)

    def test_mismatched_key_raises_value_error(self):
        other_key = make_key(participant_ids=(1, 2, 4))
        record = make_record(self.key, MESSAGE_A)
        with self.assertRaises(ValueError):
            recover_leaks([record], other_key)

    def test_structurally_illegal_receipt_raises_value_error(self):
        record = make_record(self.key, MESSAGE_A)
        with self.assertRaises(ValueError):
            recover_leaks(
                [(MESSAGE_A, SigningAudit(record[1].payload[:-1]))], self.key
            )


if __name__ == "__main__":
    unittest.main()
