"""Tests for the self-contained AuditReceipt and its codec."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AuditReceipt,
    SignatureShare,
    SigningAudit,
    check_audit,
    create_audit,
    create_audit_receipt,
    create_signature_share,
    create_signing_contribution,
    create_signing_nonce_commitment,
    create_signing_round,
    decode_audit_receipt,
    encode_audit_receipt,
    verify_audit_receipt,
    aggregate_signing_dkg,
)

# Same toy group as the audit/signing tests: 8069 = 4 * 2017 + 1 is prime,
# 16 and 256 = 16 ** 2 are distinct generators of the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

# A 3-byte group prime (L = 3) for encoding tests.
LARGE_FIELD = 1000151
LARGE_GROUP = 2000303
LARGE_G = 9
LARGE_H = 81

MESSAGE = b"threshold schnorr audit receipt message"
AUDIT_TAG = b"thresholdsign/audit/v1"
RECEIPT_TAG = b"thresholdsign/audit-receipt/v1"
L = (GROUP_PRIME.bit_length() + 7) // 8


def fixed_random(seed=1):
    """Deterministic stand-in for secrets.randbelow (same LCG as audit tests)."""
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


def make_audit(key=None, message=MESSAGE, signer_ids=(1, 3), failing=False, seed=100):
    key = key or make_key()
    round_info, shares = make_round(key, message, signer_ids, seed)
    if failing:
        shares[1] = SignatureShare(
            signer_id=shares[1].signer_id,
            nonce_commitment=shares[1].nonce_commitment,
            z=(shares[1].z + 1) % FIELD_PRIME,
        )
    audit = create_audit(message, shares, round_info, key)
    return key, round_info, shares, audit


def varint(value):
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def make_receipt(key=None, message=MESSAGE, signer_ids=(1, 3), failing=False, seed=100):
    key, round_info, shares, audit = make_audit(
        key, message, signer_ids, failing, seed
    )
    receipt = create_audit_receipt(message, audit, key)
    return key, round_info, shares, audit, receipt


class AuditReceiptDataclassTest(unittest.TestCase):
    def test_frozen_fields_and_equality(self):
        audit = SigningAudit(b"payload")
        receipt = AuditReceipt(
            MESSAGE,
            audit,
            (1, 2, 3),
            2,
            FIELD_PRIME,
            GROUP_PRIME,
            GENERATOR,
            1234,
            (5, 6, 7),
        )
        self.assertEqual(
            [field.name for field in dataclasses.fields(receipt)],
            [
                "message",
                "audit",
                "participant_ids",
                "threshold",
                "field_prime",
                "group_prime",
                "generator",
                "public_key",
                "verification_shares",
            ],
        )
        same = AuditReceipt(
            message=MESSAGE,
            audit=audit,
            participant_ids=(1, 2, 3),
            threshold=2,
            field_prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            public_key=1234,
            verification_shares=(5, 6, 7),
        )
        self.assertEqual(receipt, same)
        self.assertEqual(hash(receipt), hash(same))
        other = dataclasses.replace(receipt, threshold=1)
        self.assertNotEqual(receipt, other)
        with self.assertRaises(FrozenInstanceError):
            receipt.threshold = 3

    def test_carries_no_secret_or_state(self):
        _key, _round, _shares, _audit, receipt = make_receipt()
        for name in (
            "result",
            "shares",
            "blinding_shares",
            "dkg_result",
            "nonce",
            "secret",
        ):
            self.assertFalse(hasattr(receipt, name))


class CreateAuditReceiptTest(unittest.TestCase):
    def test_fields_come_from_dkg_and_audit(self):
        key, round_info, shares, audit, receipt = make_receipt()
        self.assertIsInstance(receipt, AuditReceipt)
        self.assertEqual(receipt.message, MESSAGE)
        self.assertIs(receipt.audit, audit)
        self.assertEqual(receipt.participant_ids, key.result.participant_ids)
        self.assertEqual(receipt.threshold, len(key.result.commitment.values))
        self.assertEqual(receipt.field_prime, key.result.commitment.field_prime)
        self.assertEqual(receipt.group_prime, key.result.commitment.group_prime)
        self.assertEqual(receipt.generator, key.result.commitment.generator)
        self.assertEqual(receipt.public_key, key.public_key)
        self.assertEqual(receipt.verification_shares, key.verification_shares)
        # Participant numbers strictly increase; shares align positionally.
        ids = receipt.participant_ids
        self.assertTrue(all(ids[i] < ids[i + 1] for i in range(len(ids) - 1)))
        self.assertEqual(len(receipt.verification_shares), len(ids))

    def test_passing_and_failing_audits_are_packaged(self):
        _key, _r, _s, audit, receipt = make_receipt()
        self.assertTrue(check_audit(MESSAGE, audit, _key))
        self.assertTrue(verify_audit_receipt(receipt))

        key, _r, _s, bad_audit, bad_receipt = make_receipt(failing=True)
        self.assertEqual(bad_audit.payload[-2:], b"\x00\x00")
        self.assertTrue(check_audit(MESSAGE, bad_audit, key))
        self.assertTrue(verify_audit_receipt(bad_receipt))

    def test_large_group_and_threshold_one(self):
        key = make_key(
            participant_ids=(1, 2, 3),
            threshold=2,
            field_prime=LARGE_FIELD,
            group_prime=LARGE_GROUP,
            generator=LARGE_G,
            blinding_generator=LARGE_H,
        )
        _k, _r, _s, _a, receipt = make_receipt(key, signer_ids=(2, 3), seed=11)
        self.assertTrue(verify_audit_receipt(receipt))

        key1 = make_key(participant_ids=(1, 2), threshold=1)
        _k, _r, _s, _a, receipt1 = make_receipt(key1, signer_ids=(2,), seed=7)
        self.assertTrue(verify_audit_receipt(receipt1))

    def test_wrong_message_raises_value_error(self):
        key, _r, _s, audit, _receipt = make_receipt()
        with self.assertRaises(ValueError):
            create_audit_receipt(b"another message", audit, key)

    def test_audit_bound_to_other_key_raises_value_error(self):
        key1 = make_key(seed_base=0)
        key2 = make_key(seed_base=100)
        _k, _r, _s, audit2, _receipt = make_receipt(key2)
        self.assertTrue(check_audit(MESSAGE, audit2, key2))
        with self.assertRaises(ValueError):
            create_audit_receipt(MESSAGE, audit2, key1)

    def test_malformed_audit_payload_raises_value_error(self):
        key = make_key()
        with self.assertRaises(ValueError):
            create_audit_receipt(MESSAGE, SigningAudit(b"junk"), key)

    def test_type_errors(self):
        key, _r, _s, audit, _receipt = make_receipt()
        with self.assertRaises(TypeError):
            create_audit_receipt("message", audit, key)
        with self.assertRaises(TypeError):
            create_audit_receipt(MESSAGE, "audit", key)
        with self.assertRaises(TypeError):
            create_audit_receipt(MESSAGE, SigningAudit(123), key)
        with self.assertRaises(TypeError):
            create_audit_receipt(MESSAGE, audit, "key")


class VerifyAuditReceiptTest(unittest.TestCase):
    def setUp(self):
        self.key, self.round_info, self.shares, self.audit, self.receipt = (
            make_receipt()
        )

    def test_passing_receipt_verifies(self):
        self.assertTrue(verify_audit_receipt(self.receipt))

    def test_failing_receipt_verifies(self):
        key, _r, _s, _a, receipt = make_receipt(failing=True)
        self.assertTrue(verify_audit_receipt(receipt))

    def test_rebound_message_returns_false(self):
        self.assertFalse(
            verify_audit_receipt(dataclasses.replace(self.receipt, message=b"other"))
        )

    def test_tampered_public_key_returns_false(self):
        other_y = self.key.verification_shares[0]
        if other_y == self.key.public_key:
            other_y = self.key.verification_shares[1]
        self.assertFalse(
            verify_audit_receipt(
                dataclasses.replace(self.receipt, public_key=other_y)
            )
        )

    def test_tampered_generator_returns_false(self):
        # 256 is another generator of the same order-field_prime subgroup, so
        # the receipt stays structurally legal and only the equations fail.
        tampered = dataclasses.replace(self.receipt, generator=BLINDING_GENERATOR)
        self.assertFalse(verify_audit_receipt(tampered))

    def test_tampered_verification_share_returns_false(self):
        shares = list(self.receipt.verification_shares)
        shares[0] = shares[0] * GENERATOR % GROUP_PRIME
        tampered = dataclasses.replace(
            self.receipt, verification_shares=tuple(shares)
        )
        self.assertFalse(verify_audit_receipt(tampered))

    def test_realigned_participant_ids_returns_false(self):
        # Rebind participant number 2's slot to id 4: the share list no
        # longer aligns with the audit's signer numbers.
        self.assertEqual(self.receipt.participant_ids, (1, 2, 3))
        tampered = dataclasses.replace(
            self.receipt, participant_ids=(1, 3, 4)
        )
        self.assertFalse(verify_audit_receipt(tampered))

    def test_tampered_audit_challenge_returns_false(self):
        offset = len(AUDIT_TAG) + 32 + 2 * L
        challenge = int.from_bytes(
            self.audit.payload[offset:offset + L], "big"
        )
        bad_challenge = (challenge + 1) % FIELD_PRIME
        payload = (
            self.audit.payload[:offset]
            + bad_challenge.to_bytes(L, "big")
            + self.audit.payload[offset + L:]
        )
        tampered = dataclasses.replace(
            self.receipt, audit=SigningAudit(payload)
        )
        self.assertFalse(verify_audit_receipt(tampered))

    def test_tampered_audit_row_z_i_returns_false(self):
        row_offset = len(AUDIT_TAG) + 32 + 3 * L + 4
        z_i = int.from_bytes(
            self.audit.payload[row_offset + 2 * L:row_offset + 3 * L], "big"
        )
        bad_z_i = (z_i + 1) % FIELD_PRIME
        payload = (
            self.audit.payload[:row_offset + 2 * L]
            + bad_z_i.to_bytes(L, "big")
            + self.audit.payload[row_offset + 3 * L:]
        )
        tampered = dataclasses.replace(
            self.receipt, audit=SigningAudit(payload)
        )
        # The share equation now fails, so the recorded success status no
        # longer matches the recomputed one.
        self.assertFalse(verify_audit_receipt(tampered))

    def test_tampered_aggregate_z_returns_false(self):
        z = int.from_bytes(self.audit.payload[-L:], "big")
        bad_z = (z + 1) % FIELD_PRIME
        payload = self.audit.payload[:-L] + bad_z.to_bytes(L, "big")
        tampered = dataclasses.replace(
            self.receipt, audit=SigningAudit(payload)
        )
        self.assertFalse(verify_audit_receipt(tampered))

    def test_rebound_to_other_key_material_returns_false(self):
        key2 = make_key(seed_base=100)
        _k, _r, _s, audit2, receipt2 = make_receipt(key2)
        # Same message, audit of key 2, but public material of key 1.
        mixed = AuditReceipt(
            message=MESSAGE,
            audit=audit2,
            participant_ids=self.receipt.participant_ids,
            threshold=self.receipt.threshold,
            field_prime=self.receipt.field_prime,
            group_prime=self.receipt.group_prime,
            generator=self.receipt.generator,
            public_key=self.receipt.public_key,
            verification_shares=self.receipt.verification_shares,
        )
        self.assertFalse(verify_audit_receipt(mixed))

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            verify_audit_receipt("receipt")
        with self.assertRaises(TypeError):
            verify_audit_receipt(None)

        cases = {
            "message": "x",
            "audit": "x",
            "participant_ids": [1, 2, 3],
            "threshold": True,
            "field_prime": 1.5,
            "group_prime": "p",
            "generator": None,
            "public_key": [1],
            "verification_shares": [1, 2, 3],
        }
        for name, bad_value in cases.items():
            with self.assertRaises(TypeError, msg=name):
                verify_audit_receipt(
                    dataclasses.replace(self.receipt, **{name: bad_value})
                )
        with self.assertRaises(TypeError):
            verify_audit_receipt(
                dataclasses.replace(
                    self.receipt, audit=SigningAudit(payload=123)
                )
            )
        with self.assertRaises(TypeError):
            verify_audit_receipt(
                dataclasses.replace(
                    self.receipt, participant_ids=(1, True, 3)
                )
            )

    def test_structural_errors_raise_value_error(self):
        # Fewer audit rows than the claimed threshold.
        with self.assertRaises(ValueError):
            verify_audit_receipt(
                dataclasses.replace(self.receipt, threshold=3)
            )
        with self.assertRaises(ValueError):
            verify_audit_receipt(
                dataclasses.replace(self.receipt, threshold=0)
            )
        # Mismatched verification share count.
        with self.assertRaises(ValueError):
            verify_audit_receipt(
                dataclasses.replace(
                    self.receipt, verification_shares=(1, 2)
                )
            )
        # A signer id outside the participant set.
        with self.assertRaises(ValueError):
            verify_audit_receipt(
                dataclasses.replace(self.receipt, participant_ids=(1, 2, 4))
            )
        # Malformed audit payload.
        with self.assertRaises(ValueError):
            verify_audit_receipt(
                dataclasses.replace(
                    self.receipt, audit=SigningAudit(b"junk")
                )
            )
        # Out-of-range field prime.
        with self.assertRaises(ValueError):
            verify_audit_receipt(
                dataclasses.replace(self.receipt, field_prime=2011)
            )


class AuditReceiptCodecTest(unittest.TestCase):
    def setUp(self):
        self.key, self.round_info, self.shares, self.audit, self.receipt = (
            make_receipt()
        )
        self.blob = encode_audit_receipt(self.receipt)

    def test_round_trip_is_byte_exact(self):
        self.assertIsInstance(self.blob, bytes)
        decoded = decode_audit_receipt(self.blob)
        self.assertEqual(decoded, self.receipt)
        self.assertTrue(verify_audit_receipt(decoded))
        self.assertEqual(encode_audit_receipt(decoded), self.blob)
        self.assertEqual(encode_audit_receipt(self.receipt), self.blob)

    def test_starts_with_tag(self):
        self.assertTrue(self.blob.startswith(RECEIPT_TAG))

    def test_layout_matches_specification_order(self):
        r = self.receipt
        expected = bytearray(RECEIPT_TAG)
        expected += len(r.message).to_bytes(4, "big") + r.message
        for value in (r.field_prime, r.group_prime, r.generator, r.public_key):
            expected += varint(value)
        expected += varint(r.threshold)
        expected += len(r.participant_ids).to_bytes(4, "big")
        for participant_id in r.participant_ids:
            expected += varint(participant_id)
        expected += len(r.verification_shares).to_bytes(4, "big")
        for share in r.verification_shares:
            expected += varint(share)
        expected += len(r.audit.payload).to_bytes(4, "big")
        expected += r.audit.payload
        self.assertEqual(self.blob, bytes(expected))

    def test_round_trip_failing_empty_and_binary_messages(self):
        for message in (b"", bytes(range(256)), b"\x00" * 500):
            _k, _r, _s, _a, receipt = make_receipt(message=message)
            blob = encode_audit_receipt(receipt)
            decoded = decode_audit_receipt(blob)
            self.assertEqual(decoded, receipt)
            self.assertEqual(encode_audit_receipt(decoded), blob)
            self.assertTrue(verify_audit_receipt(decoded))

        _k, _r, _s, _a, failing = make_receipt(failing=True)
        blob = encode_audit_receipt(failing)
        decoded = decode_audit_receipt(blob)
        self.assertEqual(decoded, failing)
        self.assertTrue(verify_audit_receipt(decoded))

    def test_large_group_round_trip(self):
        key = make_key(
            participant_ids=(1, 2, 3),
            threshold=2,
            field_prime=LARGE_FIELD,
            group_prime=LARGE_GROUP,
            generator=LARGE_G,
            blinding_generator=LARGE_H,
        )
        _k, _r, _s, _a, receipt = make_receipt(key, signer_ids=(2, 3), seed=11)
        blob = encode_audit_receipt(receipt)
        decoded = decode_audit_receipt(blob)
        self.assertEqual(decoded, receipt)
        self.assertEqual(encode_audit_receipt(decoded), blob)

    def test_encoding_carries_no_secret_material(self):
        # The encoding is fully rebuilt from public values; the DKG result and
        # its secret shares are not involved anywhere.
        r = self.receipt
        self.assertEqual(
            self.blob,
            encode_audit_receipt(
                AuditReceipt(
                    message=r.message,
                    audit=r.audit,
                    participant_ids=r.participant_ids,
                    threshold=r.threshold,
                    field_prime=r.field_prime,
                    group_prime=r.group_prime,
                    generator=r.generator,
                    public_key=r.public_key,
                    verification_shares=r.verification_shares,
                )
            ),
        )

    def test_decode_non_bytes_raises_type_error(self):
        for bad in ("bytes only", bytearray(b"x"), None, 42):
            with self.assertRaises(TypeError):
                decode_audit_receipt(bad)

    def test_encode_wrong_type_raises_type_error(self):
        with self.assertRaises(TypeError):
            encode_audit_receipt("receipt")
        with self.assertRaises(TypeError):
            encode_audit_receipt(None)

    def test_bad_tag_raises_value_error(self):
        with self.assertRaises(ValueError):
            decode_audit_receipt(b"x" + self.blob)
        with self.assertRaises(ValueError):
            decode_audit_receipt(b"")
        with self.assertRaises(ValueError):
            decode_audit_receipt(self.blob[:10])
        # Tag prefix only.
        with self.assertRaises(ValueError):
            decode_audit_receipt(RECEIPT_TAG)

    def test_truncation_raises_value_error(self):
        for cut in range(len(self.blob) - 1):
            with self.assertRaises(ValueError):
                decode_audit_receipt(self.blob[:cut])

    def test_trailing_bytes_raise_value_error(self):
        with self.assertRaises(ValueError):
            decode_audit_receipt(self.blob + b"\x00")
        with self.assertRaises(ValueError):
            decode_audit_receipt(self.blob + b"tail")

    def test_declared_lengths_too_large(self):
        tag_len = len(RECEIPT_TAG)
        # Message length.
        blob = bytearray(self.blob)
        declared = int.from_bytes(blob[tag_len:tag_len + 4], "big")
        blob[tag_len + 3] = (declared + 1) & 0xFF
        with self.assertRaises(ValueError):
            decode_audit_receipt(bytes(blob))

        # Audit payload length (last 4-byte prefix before the payload).
        payload = self.audit.payload
        frame_pos = len(self.blob) - len(payload) - 4
        blob = bytearray(self.blob)
        declared = int.from_bytes(blob[frame_pos:frame_pos + 4], "big")
        blob[frame_pos + 3] = (declared + 1) & 0xFF
        with self.assertRaises(ValueError):
            decode_audit_receipt(bytes(blob))

    def test_non_canonical_integer_raises_value_error(self):
        tag_len = len(RECEIPT_TAG)
        message_length = int.from_bytes(
            self.blob[tag_len:tag_len + 4], "big"
        )
        first_int = tag_len + 4 + message_length
        length = int.from_bytes(self.blob[first_int:first_int + 4], "big")
        self.assertGreaterEqual(length, 1)
        blob = bytearray(self.blob)
        blob[first_int:first_int + 4] = (length + 1).to_bytes(4, "big")
        blob[first_int + 4:first_int + 4] = b"\x00"
        with self.assertRaises(ValueError):
            decode_audit_receipt(bytes(blob))

    def test_zero_length_integer_body_rejected(self):
        tag_len = len(RECEIPT_TAG)
        message_length = int.from_bytes(
            self.blob[tag_len:tag_len + 4], "big"
        )
        first_int = tag_len + 4 + message_length
        blob = bytearray(self.blob)
        blob[first_int:first_int + 4] = (0).to_bytes(4, "big")
        with self.assertRaises(ValueError):
            decode_audit_receipt(bytes(blob))

    def test_bad_counts_raise_value_error(self):
        r = self.receipt

        def assemble(participant_ids, share_count, threshold=r.threshold):
            out = bytearray(RECEIPT_TAG)
            out += len(r.message).to_bytes(4, "big") + r.message
            for value in (r.field_prime, r.group_prime, r.generator, r.public_key):
                out += varint(value)
            out += varint(threshold)
            out += len(participant_ids).to_bytes(4, "big")
            for participant_id in participant_ids:
                out += varint(participant_id)
            out += share_count.to_bytes(4, "big")
            for share in r.verification_shares[:share_count]:
                out += varint(share)
            out += len(r.audit.payload).to_bytes(4, "big")
            out += r.audit.payload
            return bytes(out)

        # Zero participants.
        with self.assertRaises(ValueError):
            decode_audit_receipt(assemble((), 0))
        # Share count disagreeing with the participant count.
        with self.assertRaises(ValueError):
            decode_audit_receipt(assemble((1, 2, 3), 2))
        with self.assertRaises(ValueError):
            decode_audit_receipt(assemble((1, 2, 3), 4))
        # Threshold above the participant count.
        with self.assertRaises(ValueError):
            decode_audit_receipt(assemble((1, 2, 3), 3, threshold=4))
        # Unordered participant ids.
        with self.assertRaises(ValueError):
            decode_audit_receipt(assemble((1, 3, 2), 3))

    def test_empty_audit_payload_frame_rejected(self):
        r = self.receipt
        out = bytearray(RECEIPT_TAG)
        out += len(r.message).to_bytes(4, "big") + r.message
        for value in (r.field_prime, r.group_prime, r.generator, r.public_key):
            out += varint(value)
        out += varint(r.threshold)
        out += len(r.participant_ids).to_bytes(4, "big")
        for participant_id in r.participant_ids:
            out += varint(participant_id)
        out += len(r.verification_shares).to_bytes(4, "big")
        for share in r.verification_shares:
            out += varint(share)
        out += (0).to_bytes(4, "big")
        with self.assertRaises(ValueError):
            decode_audit_receipt(bytes(out))

    def test_structural_decode_allows_cryptographically_bad_audit(self):
        # An in-range tampered challenge keeps the receipt structurally legal:
        # decode succeeds, verify returns False.
        offset = len(AUDIT_TAG) + 32 + 2 * L
        challenge = int.from_bytes(
            self.audit.payload[offset:offset + L], "big"
        )
        bad = (challenge + 1) % FIELD_PRIME
        payload = (
            self.audit.payload[:offset]
            + bad.to_bytes(L, "big")
            + self.audit.payload[offset + L:]
        )
        tampered = dataclasses.replace(
            self.receipt, audit=SigningAudit(payload)
        )
        blob = encode_audit_receipt(tampered)
        decoded = decode_audit_receipt(blob)
        self.assertEqual(decoded, tampered)
        self.assertFalse(verify_audit_receipt(decoded))


if __name__ == "__main__":
    unittest.main()
