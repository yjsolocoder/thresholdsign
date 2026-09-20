"""Tests for the signing audit receipts (SigningAudit / create_audit / check_audit)."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    SigningAudit,
    SigningDKGResult,
    aggregate_signature,
    aggregate_signing_dkg,
    check_audit,
    create_audit,
    create_signature_share,
    create_signing_contribution,
    create_signing_nonce_commitment,
    create_signing_round,
)

# Same toy group as the signing tests: 8069 = 4 * 2017 + 1 is prime, 16 and
# 256 = 16 ** 2 are distinct generators of the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

# A 3-byte group prime (L = 3) for encoding tests: 2000303 = 2 * 1000151 + 1
# is a safe prime, 9 = 3 ** 2 and 81 = 9 ** 2 generate the order-1000151
# subgroup.
LARGE_FIELD = 1000151
LARGE_GROUP = 2000303
LARGE_G = 9
LARGE_H = 81

AUDIT_TAG = b"thresholdsign/audit/v1"
MESSAGE = b"threshold schnorr audit test message"


def fixed_random(seed=1):
    """Deterministic stand-in for secrets.randbelow (same LCG as signing tests)."""
    state = {"value": seed}

    def randbelow(upper: int) -> int:
        state["value"] = (
            state["value"] * 6364136223846793005 + 1442695040888963407
        ) % upper
        return state["value"]

    return randbelow


def make_dkg(
    participant_ids=(1, 2, 3),
    threshold=2,
    field_prime=FIELD_PRIME,
    group_prime=GROUP_PRIME,
    generator=GENERATOR,
    blinding_generator=BLINDING_GENERATOR,
    seed_base=0,
):
    outcome = aggregate_signing_dkg(
        [
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
    )
    assert isinstance(outcome, SigningDKGResult), outcome
    return outcome


def make_round_and_shares(
    dkg_result,
    signer_ids=(1, 2),
    message=MESSAGE,
    seed=10,
):
    """Run both rounds for the given signers with deterministic nonces."""
    commitments = []
    nonces = {}
    for offset, signer_id in enumerate(signer_ids):
        commitment, nonce = create_signing_nonce_commitment(
            signer_id,
            prime=dkg_result.result.commitment.field_prime,
            group_prime=dkg_result.result.commitment.group_prime,
            generator=dkg_result.result.commitment.generator,
            randbelow=fixed_random(seed + 100 * offset + signer_id),
        )
        commitments.append(commitment)
        nonces[signer_id] = nonce
    round_info = create_signing_round(
        message, tuple(signer_ids), commitments, dkg_result
    )
    shares = [
        create_signature_share(
            signer_id,
            dkg_result.result.shares[
                dkg_result.result.participant_ids.index(signer_id)
            ].y,
            nonces[signer_id],
            round_info,
            dkg_result,
        )
        for signer_id in signer_ids
    ]
    return round_info, shares


def audit_width(group_prime):
    return (group_prime.bit_length() + 7) // 8


class SigningAuditDataclassTest(unittest.TestCase):
    def test_payload_is_the_only_field(self):
        fields = dataclasses.fields(SigningAudit)
        self.assertEqual([field.name for field in fields], ["payload"])

    def test_positional_construction_and_value_equality(self):
        payload = b"anything"
        self.assertEqual(SigningAudit(payload), SigningAudit(b"anything"))
        self.assertEqual(SigningAudit(payload), SigningAudit(payload=payload))
        self.assertNotEqual(SigningAudit(payload), SigningAudit(b"other"))

    def test_frozen(self):
        receipt = SigningAudit(b"anything")
        with self.assertRaises(FrozenInstanceError):
            receipt.payload = b"changed"


class CreateAuditSuccessTest(unittest.TestCase):
    def setUp(self):
        self.key = make_dkg()
        self.round_info, self.shares = make_round_and_shares(self.key)

    def test_success_receipt_round_trips(self):
        receipt = create_audit(MESSAGE, self.shares, self.round_info, self.key)
        self.assertIsInstance(receipt, SigningAudit)
        self.assertTrue(check_audit(MESSAGE, receipt, self.key))

    def test_payload_exact_layout(self):
        receipt = create_audit(MESSAGE, self.shares, self.round_info, self.key)
        payload = receipt.payload
        width = audit_width(GROUP_PRIME)  # L = 2
        offset = 0
        self.assertTrue(payload.startswith(AUDIT_TAG))
        offset += len(AUDIT_TAG)
        self.assertEqual(
            payload[offset : offset + 32], hashlib.sha256(MESSAGE).digest()
        )
        offset += 32
        self.assertEqual(
            int.from_bytes(payload[offset : offset + width], "big"),
            self.key.public_key,
        )
        offset += width
        self.assertEqual(
            int.from_bytes(payload[offset : offset + width], "big"), self.round_info.R
        )
        offset += width
        self.assertEqual(
            int.from_bytes(payload[offset : offset + width], "big"),
            self.round_info.challenge,
        )
        offset += width
        self.assertEqual(
            int.from_bytes(payload[offset : offset + 4], "big"),
            len(self.round_info.signer_ids),
        )
        offset += 4
        for signer_id in self.round_info.signer_ids:
            share = self.shares[
                [share.signer_id for share in self.shares].index(signer_id)
            ]
            self.assertEqual(
                int.from_bytes(payload[offset : offset + width], "big"), signer_id
            )
            offset += width
            self.assertEqual(
                int.from_bytes(payload[offset : offset + width], "big"),
                share.nonce_commitment,
            )
            offset += width
            self.assertEqual(
                int.from_bytes(payload[offset : offset + width], "big"), share.z
            )
            offset += width
        self.assertEqual(payload[offset], 1)  # status
        self.assertEqual(payload[offset + 1], 1)  # present
        offset += 2
        aggregate_z = sum(share.z for share in self.shares) % FIELD_PRIME
        self.assertEqual(
            int.from_bytes(payload[offset : offset + width], "big"), aggregate_z
        )
        offset += width
        self.assertEqual(offset, len(payload))

    def test_three_byte_width_encoding(self):
        key = make_dkg(
            field_prime=LARGE_FIELD,
            group_prime=LARGE_GROUP,
            generator=LARGE_G,
            blinding_generator=LARGE_H,
        )
        round_info, shares = make_round_and_shares(key)
        receipt = create_audit(MESSAGE, shares, round_info, key)
        width = audit_width(LARGE_GROUP)  # L = 3
        self.assertEqual(width, 3)
        expected_length = (
            len(AUDIT_TAG) + 32 + 3 * width + 4 + len(shares) * 3 * width + 2 + width
        )
        self.assertEqual(len(receipt.payload), expected_length)
        self.assertTrue(check_audit(MESSAGE, receipt, key))

    def test_share_input_order_does_not_matter(self):
        first = create_audit(MESSAGE, reversed(self.shares), self.round_info, self.key)
        second = create_audit(MESSAGE, self.shares, self.round_info, self.key)
        self.assertEqual(first.payload, second.payload)
        # Rows are ascending by signer id regardless of the input order.
        width = audit_width(GROUP_PRIME)
        rows_start = len(AUDIT_TAG) + 32 + 3 * width + 4
        ids = [
            int.from_bytes(
                first.payload[rows_start + 3 * width * i : rows_start + 3 * width * i + width],
                "big",
            )
            for i in range(2)
        ]
        self.assertEqual(ids, list(self.round_info.signer_ids))

    def test_aggregate_z_matches_aggregate_signature(self):
        receipt = create_audit(MESSAGE, self.shares, self.round_info, self.key)
        signature = aggregate_signature(self.shares, self.round_info, self.key)
        width = audit_width(GROUP_PRIME)
        self.assertEqual(
            int.from_bytes(receipt.payload[-width:], "big"), signature.z
        )
        self.assertEqual(signature.R, self.round_info.R)

    def test_more_than_threshold_signers(self):
        round_info, shares = make_round_and_shares(self.key, signer_ids=(1, 2, 3))
        receipt = create_audit(MESSAGE, shares, round_info, self.key)
        self.assertTrue(check_audit(MESSAGE, receipt, self.key))
        width = audit_width(GROUP_PRIME)
        n_offset = len(AUDIT_TAG) + 32 + 3 * width
        self.assertEqual(
            int.from_bytes(receipt.payload[n_offset : n_offset + 4], "big"), 3
        )

    def test_threshold_one(self):
        key = make_dkg(participant_ids=(1, 2), threshold=1)
        round_info, shares = make_round_and_shares(key, signer_ids=(2,))
        receipt = create_audit(MESSAGE, shares, round_info, key)
        self.assertTrue(check_audit(MESSAGE, receipt, key))


class CreateAuditFailureTest(unittest.TestCase):
    def setUp(self):
        self.key = make_dkg()
        self.round_info, self.shares = make_round_and_shares(self.key)

    def test_failed_share_gives_status_zero_without_z(self):
        tampered = dataclasses.replace(
            self.shares[0], z=(self.shares[0].z + 1) % FIELD_PRIME
        )
        good = create_audit(MESSAGE, self.shares, self.round_info, self.key)
        receipt = create_audit(MESSAGE, [tampered, self.shares[1]], self.round_info, self.key)
        self.assertEqual(receipt.payload[-2], 0)  # status
        self.assertEqual(receipt.payload[-1], 0)  # present
        self.assertEqual(len(receipt.payload), len(good.payload) - audit_width(GROUP_PRIME))
        self.assertTrue(check_audit(MESSAGE, receipt, self.key))

    def test_one_failure_among_three_rows(self):
        round_info, shares = make_round_and_shares(self.key, signer_ids=(1, 2, 3))
        tampered = dataclasses.replace(shares[1], z=(shares[1].z + 1) % FIELD_PRIME)
        receipt = create_audit(
            MESSAGE, [shares[0], tampered, shares[2]], round_info, self.key
        )
        self.assertEqual(receipt.payload[-2], 0)
        self.assertEqual(receipt.payload[-1], 0)
        self.assertTrue(check_audit(MESSAGE, receipt, self.key))

    def test_share_from_other_round_fails_cryptographically(self):
        # Same signer id, a different R_i: structurally one share per signer,
        # but it cannot verify against this round, so status must be 0.
        other_round, other_shares = make_round_and_shares(
            self.key, signer_ids=(1, 2), message=b"a different message"
        )
        receipt = create_audit(
            MESSAGE, [other_shares[0], self.shares[1]], self.round_info, self.key
        )
        self.assertEqual(receipt.payload[-2], 0)
        self.assertTrue(check_audit(MESSAGE, receipt, self.key))


class CheckAuditTamperTest(unittest.TestCase):
    def setUp(self):
        self.key = make_dkg()
        self.round_info, self.shares = make_round_and_shares(self.key)
        self.receipt = create_audit(MESSAGE, self.shares, self.round_info, self.key)

    def _replace_region(self, start, end, value):
        data = bytearray(self.receipt.payload)
        data[start:end] = value
        return SigningAudit(bytes(data))

    def test_different_message_returns_false(self):
        self.assertFalse(check_audit(b"another message", self.receipt, self.key))

    def test_digest_tamper_returns_false(self):
        data = bytearray(self.receipt.payload)
        data[len(AUDIT_TAG)] ^= 1
        self.assertFalse(check_audit(MESSAGE, SigningAudit(bytes(data)), self.key))

    def test_public_key_tamper_returns_false(self):
        width = audit_width(GROUP_PRIME)
        start = len(AUDIT_TAG) + 32
        # Another valid subgroup element keeps the structure legal.
        other_y = self.key.public_key * GENERATOR % GROUP_PRIME
        receipt = self._replace_region(start, start + width, other_y.to_bytes(width, "big"))
        self.assertFalse(check_audit(MESSAGE, receipt, self.key))

    def test_R_tamper_returns_false(self):
        width = audit_width(GROUP_PRIME)
        start = len(AUDIT_TAG) + 32 + width
        receipt = self._replace_region(
            start, start + width, pow(GENERATOR, 424, GROUP_PRIME).to_bytes(width, "big")
        )
        self.assertFalse(check_audit(MESSAGE, receipt, self.key))

    def test_challenge_tamper_returns_false(self):
        width = audit_width(GROUP_PRIME)
        start = len(AUDIT_TAG) + 32 + 2 * width
        other_c = (self.round_info.challenge + 1) % FIELD_PRIME
        receipt = self._replace_region(start, start + width, other_c.to_bytes(width, "big"))
        self.assertFalse(check_audit(MESSAGE, receipt, self.key))

    def test_row_z_tamper_returns_false(self):
        width = audit_width(GROUP_PRIME)
        rows_start = len(AUDIT_TAG) + 32 + 3 * width + 4
        # Last L bytes of the first row's (id, R_i, z_i) triple are its z_i.
        z_start = rows_start + 2 * width
        current = int.from_bytes(
            self.receipt.payload[z_start : z_start + width], "big"
        )
        receipt = self._replace_region(
            z_start, z_start + width, ((current + 1) % FIELD_PRIME).to_bytes(width, "big")
        )
        self.assertFalse(check_audit(MESSAGE, receipt, self.key))

    def test_row_commitment_legal_tamper_returns_false(self):
        width = audit_width(GROUP_PRIME)
        rows_start = len(AUDIT_TAG) + 32 + 3 * width + 4
        r_start = rows_start + width
        receipt = self._replace_region(
            r_start,
            r_start + width,
            pow(GENERATOR, 777, GROUP_PRIME).to_bytes(width, "big"),
        )
        self.assertFalse(check_audit(MESSAGE, receipt, self.key))

    def test_row_id_legal_tamper_returns_false(self):
        # Use the signing set (2, 3) so rewriting the first id 2 -> 1 keeps
        # the rows ascending and in range (1 is still a DKG participant);
        # every recomputation must then disagree.
        round_info, shares = make_round_and_shares(self.key, signer_ids=(2, 3))
        receipt = create_audit(MESSAGE, shares, round_info, self.key)
        width = audit_width(GROUP_PRIME)
        rows_start = len(AUDIT_TAG) + 32 + 3 * width + 4
        data = bytearray(receipt.payload)
        data[rows_start : rows_start + width] = (1).to_bytes(width, "big")
        self.assertFalse(check_audit(MESSAGE, SigningAudit(bytes(data)), self.key))

    def test_aggregate_z_tamper_returns_false(self):
        width = audit_width(GROUP_PRIME)
        current = int.from_bytes(self.receipt.payload[-width:], "big")
        receipt = self._replace_region(
            len(self.receipt.payload) - width,
            len(self.receipt.payload),
            ((current + 1) % FIELD_PRIME).to_bytes(width, "big"),
        )
        self.assertFalse(check_audit(MESSAGE, receipt, self.key))

    def test_wrong_key_returns_false(self):
        other_key = make_dkg(seed_base=100)
        self.assertFalse(check_audit(MESSAGE, self.receipt, other_key))

    def test_failure_receipt_message_mismatch_returns_false(self):
        tampered = dataclasses.replace(
            self.shares[0], z=(self.shares[0].z + 1) % FIELD_PRIME
        )
        receipt = create_audit(
            MESSAGE, [tampered, self.shares[1]], self.round_info, self.key
        )
        self.assertFalse(check_audit(b"another message", receipt, self.key))


class AuditStructuralValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_dkg()
        self.round_info, self.shares = make_round_and_shares(self.key)
        self.receipt = create_audit(MESSAGE, self.shares, self.round_info, self.key)

    def test_truncated_payload_raises_value_error(self):
        with self.assertRaises(ValueError):
            check_audit(MESSAGE, SigningAudit(self.receipt.payload[:-1]), self.key)
        with self.assertRaises(ValueError):
            check_audit(MESSAGE, SigningAudit(b""), self.key)

    def test_trailing_bytes_raise_value_error(self):
        with self.assertRaises(ValueError):
            check_audit(
                MESSAGE, SigningAudit(self.receipt.payload + b"\x00"), self.key
            )

    def test_bad_tag_raises_value_error(self):
        data = b"x" * len(AUDIT_TAG) + self.receipt.payload[len(AUDIT_TAG) :]
        with self.assertRaises(ValueError):
            check_audit(MESSAGE, SigningAudit(data), self.key)

    def test_status_present_disagreement_raises_value_error(self):
        # A success receipt ends with status, present and the L-byte z.
        data = bytearray(self.receipt.payload)
        data[-4] = 0  # status 0 while present stays 1, plus trailing z
        with self.assertRaises(ValueError):
            check_audit(MESSAGE, SigningAudit(bytes(data)), self.key)

    def test_illegal_status_byte_raises_value_error(self):
        data = bytearray(self.receipt.payload)
        data[-4] = 2
        data[-3] = 2
        with self.assertRaises(ValueError):
            check_audit(MESSAGE, SigningAudit(bytes(data)), self.key)

    def test_non_subgroup_commitment_raises_value_error(self):
        width = audit_width(GROUP_PRIME)
        rows_start = len(AUDIT_TAG) + 32 + 3 * width + 4
        r_start = rows_start + width
        data = bytearray(self.receipt.payload)
        data[r_start : r_start + width] = (2).to_bytes(width, "big")
        with self.assertRaises(ValueError):
            check_audit(MESSAGE, SigningAudit(bytes(data)), self.key)

    def test_zero_row_count_raises_value_error(self):
        data = bytearray(self.receipt.payload)
        n_offset = len(AUDIT_TAG) + 32 + 3 * audit_width(GROUP_PRIME)
        data[n_offset : n_offset + 4] = (0).to_bytes(4, "big")
        with self.assertRaises(ValueError):
            check_audit(MESSAGE, SigningAudit(bytes(data)), self.key)

    def test_non_ascending_rows_raise_value_error(self):
        width = audit_width(GROUP_PRIME)
        rows_start = len(AUDIT_TAG) + 32 + 3 * width + 4
        data = bytearray(self.receipt.payload)
        # First row id 1 -> 2 duplicates the second row id 2.
        data[rows_start : rows_start + width] = (2).to_bytes(width, "big")
        with self.assertRaises(ValueError):
            check_audit(MESSAGE, SigningAudit(bytes(data)), self.key)

    def test_duplicate_row_commitments_raise_value_error(self):
        width = audit_width(GROUP_PRIME)
        rows_start = len(AUDIT_TAG) + 32 + 3 * width + 4
        data = bytearray(self.receipt.payload)
        first_commitment = data[rows_start + width : rows_start + 2 * width]
        data[rows_start + 4 * width : rows_start + 5 * width] = first_commitment
        with self.assertRaises(ValueError):
            check_audit(MESSAGE, SigningAudit(bytes(data)), self.key)

    def test_fewer_than_threshold_rows_raises_value_error(self):
        # Drop one of the two rows and set n to 1; the parser succeeds but the
        # receipt covers fewer than threshold (= 2) signers.
        width = audit_width(GROUP_PRIME)
        payload = self.receipt.payload
        head_end = len(AUDIT_TAG) + 32 + 3 * width
        rows_start = head_end + 4
        second_row = payload[rows_start + 3 * width : rows_start + 2 * 3 * width]
        tail = payload[rows_start + 2 * 3 * width :]
        rebuilt = (
            payload[:head_end]
            + (1).to_bytes(4, "big")
            + second_row
            + tail
        )
        with self.assertRaises(ValueError):
            check_audit(MESSAGE, SigningAudit(rebuilt), self.key)

    def test_non_participant_row_raises_value_error(self):
        width = audit_width(GROUP_PRIME)
        rows_start = len(AUDIT_TAG) + 32 + 3 * width + 4
        data = bytearray(self.receipt.payload)
        # Rewrite both rows to ids (2, 9) keeping ascending order; 9 is not a
        # DKG participant.
        data[rows_start : rows_start + width] = (2).to_bytes(width, "big")
        data[rows_start + 3 * width : rows_start + 4 * width] = (9).to_bytes(
            width, "big"
        )
        with self.assertRaises(ValueError):
            check_audit(MESSAGE, SigningAudit(bytes(data)), self.key)

    def test_missing_share_raises_value_error(self):
        with self.assertRaises(ValueError):
            create_audit(MESSAGE, [self.shares[0]], self.round_info, self.key)

    def test_duplicate_share_raises_value_error(self):
        with self.assertRaises(ValueError):
            create_audit(
                MESSAGE,
                [self.shares[0], self.shares[0]],
                self.round_info,
                self.key,
            )

    def test_extra_share_raises_value_error(self):
        _, all_shares = make_round_and_shares(self.key, signer_ids=(1, 2, 3))
        with self.assertRaises(ValueError):
            create_audit(MESSAGE, all_shares, self.round_info, self.key)

    def test_empty_shares_raise_value_error(self):
        with self.assertRaises(ValueError):
            create_audit(MESSAGE, [], self.round_info, self.key)

    def test_internally_tampered_round_raises_value_error(self):
        evil_round = dataclasses.replace(
            self.round_info, R=(self.round_info.R + 1) % GROUP_PRIME
        )
        with self.assertRaises(ValueError):
            create_audit(MESSAGE, self.shares, evil_round, self.key)
        evil_challenge = dataclasses.replace(
            self.round_info, challenge=(self.round_info.challenge + 1) % FIELD_PRIME
        )
        with self.assertRaises(ValueError):
            create_audit(MESSAGE, self.shares, evil_challenge, self.key)

    def test_message_mismatching_round_raises_value_error(self):
        with self.assertRaises(ValueError):
            create_audit(b"another message", self.shares, self.round_info, self.key)

    def test_status_zero_payload_must_not_carry_z(self):
        # A genuine status-0 receipt ends with the two flag bytes; an
        # unexpected z-shaped tail is a structural error, not a False.
        tampered = dataclasses.replace(
            self.shares[0], z=(self.shares[0].z + 1) % FIELD_PRIME
        )
        failure_receipt = create_audit(
            MESSAGE, [tampered, self.shares[1]], self.round_info, self.key
        )
        self.assertEqual(failure_receipt.payload[-2:], b"\x00\x00")
        with self.assertRaises(ValueError):
            check_audit(
                MESSAGE,
                SigningAudit(
                    failure_receipt.payload + b"\x00" * audit_width(GROUP_PRIME)
                ),
                self.key,
            )


class AuditTypeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_dkg()
        self.round_info, self.shares = make_round_and_shares(self.key)

    def test_create_audit_type_errors(self):
        with self.assertRaises(TypeError):
            create_audit("not bytes", self.shares, self.round_info, self.key)
        with self.assertRaises(TypeError):
            create_audit(MESSAGE, self.shares, "not a round", self.key)
        with self.assertRaises(TypeError):
            create_audit(MESSAGE, self.shares, self.round_info, "not a key")
        with self.assertRaises(TypeError):
            create_audit(MESSAGE, [1], self.round_info, self.key)
        with self.assertRaises(TypeError):
            create_audit(MESSAGE, 123, self.round_info, self.key)

    def test_check_audit_type_errors(self):
        receipt = create_audit(MESSAGE, self.shares, self.round_info, self.key)
        with self.assertRaises(TypeError):
            check_audit("not bytes", receipt, self.key)
        with self.assertRaises(TypeError):
            check_audit(MESSAGE, b"not a receipt", self.key)
        with self.assertRaises(TypeError):
            check_audit(MESSAGE, receipt, "not a key")

    def test_bool_is_not_an_integer_share(self):
        with self.assertRaises(TypeError):
            create_audit(
                MESSAGE,
                [self.shares[0], True],
                self.round_info,
                self.key,
            )


if __name__ == "__main__":
    unittest.main()
