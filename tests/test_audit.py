"""Tests for the signing audit receipts: SigningAudit / create_audit / check_audit."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    SignatureShare,
    SigningAudit,
    aggregate_signature,
    aggregate_signing_dkg,
    check_audit,
    create_audit,
    create_signature_share,
    create_signing_contribution,
    create_signing_nonce_commitment,
    create_signing_round,
    schnorr_challenge,
    verify_signature,
)

# Same toy group as the signing tests: 8069 = 4 * 2017 + 1 is prime, 16 and
# 256 = 16 ** 2 are distinct generators of the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

# A 3-byte group prime (L = 3) for encoding tests, same as the signing tests.
LARGE_FIELD = 1000151
LARGE_GROUP = 2000303
LARGE_G = 9
LARGE_H = 81

MESSAGE = b"threshold schnorr audit message"
AUDIT_TAG = b"thresholdsign/audit/v1"
L = (GROUP_PRIME.bit_length() + 7) // 8


def fixed_random(seed=1):
    """Deterministic stand-in for secrets.randbelow (same LCG as DKG tests)."""
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
            randbelow=fixed_random(pid),
        )
        for pid in participant_ids
    ]
    return aggregate_signing_dkg(contributions)


def make_round(key, message=MESSAGE, signer_ids=(1, 3), seed=100):
    commitments = []
    nonces = {}
    for index, pid in enumerate(signer_ids):
        commitment, nonce = create_signing_nonce_commitment(
            pid,
            prime=key.result.commitment.field_prime,
            group_prime=key.result.commitment.group_prime,
            generator=key.result.commitment.generator,
            randbelow=fixed_random(seed + index),
        )
        commitments.append(commitment)
        nonces[pid] = nonce
    round_info = create_signing_round(message, signer_ids, commitments, key)
    shares = [
        create_signature_share(
            pid,
            key.result.shares[key.result.participant_ids.index(pid)].y,
            nonces[pid],
            round_info,
            key,
        )
        for pid in signer_ids
    ]
    return round_info, shares


def encode(value, length=L):
    return value.to_bytes(length, "big", signed=False)


class SigningAuditTest(unittest.TestCase):
    def test_frozen_single_field_value_equality(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(SigningAudit)], ["payload"]
        )
        audit = SigningAudit(b"payload")
        self.assertEqual(audit, SigningAudit(b"payload"))  # positional construction
        self.assertEqual(audit, SigningAudit(payload=b"payload"))
        self.assertNotEqual(audit, SigningAudit(b"other"))
        self.assertEqual(hash(audit), hash(SigningAudit(b"payload")))
        with self.assertRaises(FrozenInstanceError):
            audit.payload = b"other"


class CreateAuditTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.round_info, self.shares = make_round(self.key)

    def test_payload_layout_passing(self):
        audit = create_audit(MESSAGE, self.shares, self.round_info, self.key)
        z_total = sum(share.z for share in self.shares) % FIELD_PRIME
        expected = bytearray(AUDIT_TAG)
        expected += hashlib.sha256(MESSAGE).digest()
        expected += encode(self.key.public_key)
        expected += encode(self.round_info.R)
        expected += encode(self.round_info.challenge)
        expected += (2).to_bytes(4, "big")
        for share in sorted(self.shares, key=lambda share: share.signer_id):
            expected += encode(share.signer_id)
            expected += encode(share.nonce_commitment)
            expected += encode(share.z)
        expected += b"\x01\x01"
        expected += encode(z_total)
        self.assertEqual(audit.payload, bytes(expected))

    def test_payload_layout_failing_share(self):
        bad = SignatureShare(
            signer_id=self.shares[1].signer_id,
            nonce_commitment=self.shares[1].nonce_commitment,
            z=(self.shares[1].z + 1) % FIELD_PRIME,
        )
        audit = create_audit(MESSAGE, [self.shares[0], bad], self.round_info, self.key)
        # status 0, present 0, no trailing z
        self.assertEqual(audit.payload[-2:], b"\x00\x00")
        expected_length = len(AUDIT_TAG) + 32 + 3 * L + 4 + 2 * 3 * L + 2
        self.assertEqual(len(audit.payload), expected_length)

    def test_input_order_does_not_matter(self):
        audit = create_audit(MESSAGE, self.shares, self.round_info, self.key)
        reversed_audit = create_audit(
            MESSAGE, list(reversed(self.shares)), self.round_info, self.key
        )
        self.assertEqual(audit, reversed_audit)

    def test_aggregate_z_matches_aggregate_signature(self):
        audit = create_audit(MESSAGE, self.shares, self.round_info, self.key)
        signature = aggregate_signature(self.shares, self.round_info, self.key)
        self.assertIsInstance(signature, AggregateSignature)
        self.assertEqual(audit.payload[-L:], encode(signature.z))
        self.assertTrue(
            verify_signature(
                MESSAGE,
                signature,
                self.key.public_key,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            )
        )

    def test_threshold_one(self):
        key = make_key(participant_ids=(1, 2), threshold=1)
        round_info, shares = make_round(key, signer_ids=(2,), seed=7)
        audit = create_audit(MESSAGE, shares, round_info, key)
        self.assertTrue(check_audit(MESSAGE, audit, key))

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            create_audit("message", self.shares, self.round_info, self.key)
        with self.assertRaises(TypeError):
            create_audit(MESSAGE, ["share"], self.round_info, self.key)
        with self.assertRaises(TypeError):
            create_audit(
                MESSAGE,
                [SignatureShare(signer_id="1", nonce_commitment=2, z=3)],
                self.round_info,
                self.key,
            )
        with self.assertRaises(TypeError):
            create_audit(MESSAGE, self.shares, "round", self.key)
        with self.assertRaises(TypeError):
            create_audit(MESSAGE, self.shares, self.round_info, "key")

    def test_share_set_errors(self):
        with self.assertRaises(ValueError):
            create_audit(MESSAGE, [], self.round_info, self.key)
        with self.assertRaises(ValueError):
            create_audit(MESSAGE, [self.shares[0]], self.round_info, self.key)
        with self.assertRaises(ValueError):
            create_audit(
                MESSAGE, [self.shares[0], self.shares[0]], self.round_info, self.key
            )
        with self.assertRaises(ValueError):
            create_audit(
                MESSAGE, self.shares + [self.shares[0]], self.round_info, self.key
            )
        # a share from a signer outside the round
        outsider = SignatureShare(
            signer_id=2,
            nonce_commitment=self.shares[0].nonce_commitment,
            z=self.shares[0].z,
        )
        with self.assertRaises(ValueError):
            create_audit(
                MESSAGE, [self.shares[0], outsider], self.round_info, self.key
            )

    def test_out_of_range_share_values(self):
        with self.assertRaises(ValueError):
            create_audit(
                MESSAGE,
                [self.shares[0], SignatureShare(3, self.shares[1].nonce_commitment, FIELD_PRIME)],
                self.round_info,
                self.key,
            )
        with self.assertRaises(ValueError):
            create_audit(
                MESSAGE,
                [self.shares[0], SignatureShare(3, 1, self.shares[1].z)],
                self.round_info,
                self.key,
            )


class CheckAuditTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.round_info, self.shares = make_round(self.key)
        self.audit = create_audit(MESSAGE, self.shares, self.round_info, self.key)

    def test_passing_audit_checks(self):
        self.assertTrue(check_audit(MESSAGE, self.audit, self.key))

    def test_failing_audit_checks(self):
        bad = SignatureShare(
            signer_id=self.shares[1].signer_id,
            nonce_commitment=self.shares[1].nonce_commitment,
            z=(self.shares[1].z + 1) % FIELD_PRIME,
        )
        audit = create_audit(MESSAGE, [self.shares[0], bad], self.round_info, self.key)
        self.assertTrue(check_audit(MESSAGE, audit, self.key))

    def test_other_message_returns_false(self):
        self.assertFalse(check_audit(b"another message", self.audit, self.key))

    def test_tampered_public_key_returns_false(self):
        # Tamper Y to a different legal subgroup element: must return False.
        offset = len(AUDIT_TAG) + 32
        other_Y = self.key.verification_shares[0]
        if other_Y == self.key.public_key:
            other_Y = self.key.verification_shares[1]
        tampered = SigningAudit(
            self.audit.payload[:offset] + encode(other_Y) + self.audit.payload[offset + L:]
        )
        self.assertFalse(check_audit(MESSAGE, tampered, self.key))

    def test_tampered_values_return_false(self):
        # Tamper the aggregate z.
        z = int.from_bytes(self.audit.payload[-L:], "big")
        bad_z = (z + 1) % FIELD_PRIME
        tampered = SigningAudit(self.audit.payload[:-L] + encode(bad_z))
        self.assertFalse(check_audit(MESSAGE, tampered, self.key))

        # Tamper the challenge.
        offset = len(AUDIT_TAG) + 32 + 2 * L
        c = int.from_bytes(self.audit.payload[offset:offset + L], "big")
        bad_c = (c + 1) % FIELD_PRIME
        tampered = SigningAudit(
            self.audit.payload[:offset] + encode(bad_c) + self.audit.payload[offset + L:]
        )
        self.assertFalse(check_audit(MESSAGE, tampered, self.key))

        # Tamper R.
        offset = len(AUDIT_TAG) + 32 + L
        R = int.from_bytes(self.audit.payload[offset:offset + L], "big")
        bad_R = R * GENERATOR % GROUP_PRIME
        tampered = SigningAudit(
            self.audit.payload[:offset] + encode(bad_R) + self.audit.payload[offset + L:]
        )
        self.assertFalse(check_audit(MESSAGE, tampered, self.key))

        # Tamper a row's z_i.
        row_offset = len(AUDIT_TAG) + 32 + 3 * L + 4
        z_i = int.from_bytes(
            self.audit.payload[row_offset + 2 * L:row_offset + 3 * L], "big"
        )
        bad_zi = (z_i + 1) % FIELD_PRIME
        tampered = SigningAudit(
            self.audit.payload[:row_offset + 2 * L]
            + encode(bad_zi)
            + self.audit.payload[row_offset + 3 * L:]
        )
        self.assertFalse(check_audit(MESSAGE, tampered, self.key))

        # Flip status 1 -> 0 (dropping z would change length; keep z: present
        # mismatch is structural, so instead craft a full status-0 payload).
        bad = bytearray(self.audit.payload[:-L])
        bad[-2] = 0
        bad[-1] = 0
        self.assertFalse(check_audit(MESSAGE, SigningAudit(bytes(bad)), self.key))

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            check_audit("message", self.audit, self.key)
        with self.assertRaises(TypeError):
            check_audit(MESSAGE, "audit", self.key)
        with self.assertRaises(TypeError):
            check_audit(MESSAGE, SigningAudit(123), self.key)
        with self.assertRaises(TypeError):
            check_audit(MESSAGE, self.audit, "key")

    def test_decode_errors(self):
        # Wrong tag.
        with self.assertRaises(ValueError):
            check_audit(
                MESSAGE, SigningAudit(b"wrong" + self.audit.payload[5:]), self.key
            )
        # Truncated.
        with self.assertRaises(ValueError):
            check_audit(MESSAGE, SigningAudit(self.audit.payload[:-1]), self.key)
        with self.assertRaises(ValueError):
            check_audit(MESSAGE, SigningAudit(AUDIT_TAG), self.key)
        # Trailing garbage.
        with self.assertRaises(ValueError):
            check_audit(MESSAGE, SigningAudit(self.audit.payload + b"\x00"), self.key)
        # status = 0 with present = 1.
        bad = bytearray(self.audit.payload)
        bad[-L - 2] = 0
        with self.assertRaises(ValueError):
            check_audit(MESSAGE, SigningAudit(bytes(bad)), self.key)
        # status = 1 with present = 0.
        bad = bytearray(self.audit.payload)
        bad[-L - 1] = 0
        with self.assertRaises(ValueError):
            check_audit(MESSAGE, SigningAudit(bytes(bad)), self.key)
        # status / present bytes out of range.
        bad = bytearray(self.audit.payload)
        bad[-L - 2] = 2
        with self.assertRaises(ValueError):
            check_audit(MESSAGE, SigningAudit(bytes(bad)), self.key)
        bad = bytearray(self.audit.payload)
        bad[-L - 1] = 2
        with self.assertRaises(ValueError):
            check_audit(MESSAGE, SigningAudit(bytes(bad)), self.key)
        # status = 0 payload carrying a trailing z.
        bad = bytearray(self.audit.payload)
        bad[-L - 2] = 0
        bad[-L - 1] = 0
        with self.assertRaises(ValueError):
            check_audit(MESSAGE, SigningAudit(bytes(bad)), self.key)
        # Out-of-range encoded values.
        offset = len(AUDIT_TAG) + 32 + 2 * L
        bad = (
            self.audit.payload[:offset]
            + encode(FIELD_PRIME)
            + self.audit.payload[offset + L:]
        )
        with self.assertRaises(ValueError):
            check_audit(MESSAGE, SigningAudit(bad), self.key)
        # Rows not strictly increasing: swap the two rows.
        row_offset = len(AUDIT_TAG) + 32 + 3 * L + 4
        row1 = self.audit.payload[row_offset:row_offset + 3 * L]
        row2 = self.audit.payload[row_offset + 3 * L:row_offset + 6 * L]
        bad = (
            self.audit.payload[:row_offset]
            + row2
            + row1
            + self.audit.payload[row_offset + 6 * L:]
        )
        with self.assertRaises(ValueError):
            check_audit(MESSAGE, SigningAudit(bad), self.key)

    def test_large_group_width(self):
        key = make_key(
            field_prime=LARGE_FIELD,
            group_prime=LARGE_GROUP,
            generator=LARGE_G,
            blinding_generator=LARGE_H,
        )
        round_info, shares = make_round(key, signer_ids=(2, 3), seed=11)
        audit = create_audit(MESSAGE, shares, round_info, key)
        large_L = (LARGE_GROUP.bit_length() + 7) // 8
        self.assertEqual(large_L, 3)
        expected_length = len(AUDIT_TAG) + 32 + 3 * large_L + 4 + 2 * 3 * large_L + 2 + large_L
        self.assertEqual(len(audit.payload), expected_length)
        self.assertTrue(check_audit(MESSAGE, audit, key))
        # The challenge inside the payload matches the public recomputation.
        offset = len(AUDIT_TAG) + 32 + 2 * large_L
        c = int.from_bytes(audit.payload[offset:offset + large_L], "big")
        self.assertEqual(
            c,
            schnorr_challenge(
                MESSAGE,
                key.public_key,
                round_info.R,
                (2, 3),
                field_prime=LARGE_FIELD,
                group_prime=LARGE_GROUP,
            ),
        )


if __name__ == "__main__":
    unittest.main()
