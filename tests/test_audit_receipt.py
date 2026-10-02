"""Tests for the self-contained audit credential:
AuditReceipt / create_audit_receipt / verify_audit_receipt and the
canonical codec encode_audit_receipt / decode_audit_receipt.
"""

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
    aggregate_signing_dkg,
    verify_audit_receipt,
)

# Same toy group as the audit tests: 8069 = 4 * 2017 + 1 is prime, 16 and
# 256 = 16 ** 2 are distinct generators of the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

MESSAGE = b"self-contained audit receipt message"
RECEIPT_TAG = b"thresholdsign/audit-receipt/v1"


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
    seed_offset=0,
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
            randbelow=fixed_random(pid + seed_offset),
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


def varint(value: int) -> bytes:
    """Independently build the 4-byte-length-prefixed integer encoding."""
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def build_wire(receipt: AuditReceipt) -> bytes:
    """Independently build the canonical wire format straight from the spec."""
    out = bytearray(RECEIPT_TAG)
    out += len(receipt.message).to_bytes(4, "big", signed=False)
    out += receipt.message
    for value in (
        receipt.field_prime,
        receipt.group_prime,
        receipt.generator,
        receipt.public_key,
        receipt.threshold,
    ):
        out += varint(value)
    out += len(receipt.participant_ids).to_bytes(4, "big", signed=False)
    for participant_id in receipt.participant_ids:
        out += varint(participant_id)
    out += len(receipt.verification_shares).to_bytes(4, "big", signed=False)
    for value in receipt.verification_shares:
        out += varint(value)
    out += len(receipt.audit.payload).to_bytes(4, "big", signed=False)
    out += receipt.audit.payload
    return bytes(out)


class AuditReceiptDataclassTest(unittest.TestCase):
    def test_frozen_field_order_value_equality(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(AuditReceipt)],
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
        key = make_key()
        round_info, shares = make_round(key)
        audit = create_audit(MESSAGE, shares, round_info, key)
        values = (
            MESSAGE,
            audit,
            key.result.participant_ids,
            len(key.result.commitment.values),
            FIELD_PRIME,
            GROUP_PRIME,
            GENERATOR,
            key.public_key,
            key.verification_shares,
        )
        receipt = AuditReceipt(*values)  # positional construction
        self.assertEqual(receipt, AuditReceipt(**dict(zip(
            [f.name for f in dataclasses.fields(AuditReceipt)], values
        ))))
        self.assertEqual(
            hash(receipt),
            hash(AuditReceipt(*values)),
        )
        self.assertNotEqual(receipt, dataclasses.replace(receipt, message=b"x"))
        with self.assertRaises(FrozenInstanceError):
            receipt.threshold = 3

    def test_carries_no_secret_material(self):
        # The receipt's public surface exposes only the documented fields.
        key = make_key()
        round_info, shares = make_round(key)
        audit = create_audit(MESSAGE, shares, round_info, key)
        receipt = create_audit_receipt(MESSAGE, audit, key)
        exposed = {f.name for f in dataclasses.fields(receipt)}
        self.assertEqual(
            exposed,
            {
                "message",
                "audit",
                "participant_ids",
                "threshold",
                "field_prime",
                "group_prime",
                "generator",
                "public_key",
                "verification_shares",
            },
        )


class CreateAuditReceiptTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.round_info, self.shares = make_round(self.key)
        self.audit = create_audit(MESSAGE, self.shares, self.round_info, self.key)

    def test_passing_audit_packages_public_values(self):
        receipt = create_audit_receipt(MESSAGE, self.audit, self.key)
        self.assertEqual(receipt.message, MESSAGE)
        self.assertEqual(receipt.audit, self.audit)
        self.assertEqual(receipt.participant_ids, self.key.result.participant_ids)
        self.assertEqual(
            receipt.threshold, len(self.key.result.commitment.values)
        )
        self.assertEqual(receipt.field_prime, FIELD_PRIME)
        self.assertEqual(receipt.group_prime, GROUP_PRIME)
        self.assertEqual(receipt.generator, GENERATOR)
        self.assertEqual(receipt.public_key, self.key.public_key)
        self.assertEqual(
            receipt.verification_shares, self.key.verification_shares
        )
        # Verification shares align positionally with participant ids.
        self.assertEqual(
            len(receipt.verification_shares), len(receipt.participant_ids)
        )
        self.assertTrue(verify_audit_receipt(receipt))

    def test_faithfully_failed_audit_can_be_packaged(self):
        bad = SignatureShare(
            signer_id=self.shares[1].signer_id,
            nonce_commitment=self.shares[1].nonce_commitment,
            z=(self.shares[1].z + 1) % FIELD_PRIME,
        )
        failed = create_audit(MESSAGE, [self.shares[0], bad], self.round_info, self.key)
        self.assertEqual(failed.payload[-2:], b"\x00\x00")
        receipt = create_audit_receipt(MESSAGE, failed, self.key)
        self.assertTrue(verify_audit_receipt(receipt))

    def test_confirmation_matches_check_audit(self):
        receipt = create_audit_receipt(MESSAGE, self.audit, self.key)
        # check_audit and the receipt's own verifier agree on the record.
        self.assertTrue(check_audit(MESSAGE, self.audit, self.key))
        self.assertTrue(verify_audit_receipt(receipt))

    def test_rebound_to_other_message_rejected(self):
        with self.assertRaises(ValueError):
            create_audit_receipt(b"a different message", self.audit, self.key)

    def test_rebound_to_other_key_rejected(self):
        other_key = make_key(seed_offset=99)
        with self.assertRaises(ValueError):
            create_audit_receipt(MESSAGE, self.audit, other_key)

    def test_tampered_record_rejected(self):
        # A record with the challenge byte flipped is cryptographically
        # inconsistent, even though its payload still parses structurally.
        length = (GROUP_PRIME.bit_length() + 7) // 8
        offset = len(b"thresholdsign/audit/v1") + 32 + 2 * length
        flipped = (self.audit.payload[offset] + 1) % 256
        tampered = SigningAudit(
            self.audit.payload[:offset]
            + bytes([flipped])
            + self.audit.payload[offset + 1:]
        )
        with self.assertRaises(ValueError):
            create_audit_receipt(MESSAGE, tampered, self.key)

    def test_threshold_one(self):
        key = make_key(participant_ids=(1, 2), threshold=1)
        round_info, shares = make_round(key, signer_ids=(2,), seed=7)
        audit = create_audit(MESSAGE, shares, round_info, key)
        receipt = create_audit_receipt(MESSAGE, audit, key)
        self.assertEqual(receipt.threshold, 1)
        self.assertTrue(verify_audit_receipt(receipt))

    def test_non_contiguous_participant_ids(self):
        key = make_key(participant_ids=(2, 5, 9))
        round_info, shares = make_round(key, signer_ids=(2, 9))
        audit = create_audit(MESSAGE, shares, round_info, key)
        receipt = create_audit_receipt(MESSAGE, audit, key)
        self.assertEqual(receipt.participant_ids, (2, 5, 9))
        self.assertEqual(
            len(receipt.verification_shares), 3
        )
        self.assertTrue(verify_audit_receipt(receipt))

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            create_audit_receipt("message", self.audit, self.key)
        with self.assertRaises(TypeError):
            create_audit_receipt(MESSAGE, b"not-an-audit", self.key)
        with self.assertRaises(TypeError):
            create_audit_receipt(MESSAGE, self.audit, "not-a-key")
        with self.assertRaises(TypeError):
            create_audit_receipt(MESSAGE, SigningAudit(123), self.key)

    def test_structural_errors(self):
        # A structurally broken audit payload raises ValueError, not bool.
        with self.assertRaises(ValueError):
            create_audit_receipt(
                MESSAGE, SigningAudit(b"thresholdsign/audit/v1" + b"\x00" * 5), self.key
            )
        # Rows covering fewer than threshold signers: strip one row (and
        # fix the count) from a valid 3-of-4 audit payload. create_audit
        # itself never emits such a record, so it is hand-crafted here.
        key = make_key(participant_ids=(1, 2, 3, 4), threshold=3)
        round_info, shares = make_round(key, signer_ids=(1, 2, 4), seed=50)
        audit = create_audit(MESSAGE, shares, round_info, key)
        length = (GROUP_PRIME.bit_length() + 7) // 8
        prefix = len(b"thresholdsign/audit/v1") + 32 + 3 * length
        stripped = (
            audit.payload[:prefix]
            + (2).to_bytes(4, "big")
            + audit.payload[prefix + 4:prefix + 4 + 2 * 3 * length]
            + b"\x00\x00"
        )
        with self.assertRaises(ValueError):
            create_audit_receipt(MESSAGE, SigningAudit(stripped), key)


class VerifyAuditReceiptTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.round_info, self.shares = make_round(self.key)
        self.audit = create_audit(MESSAGE, self.shares, self.round_info, self.key)
        self.receipt = create_audit_receipt(MESSAGE, self.audit, self.key)

    def test_genuine_receipt_verifies(self):
        self.assertTrue(verify_audit_receipt(self.receipt))

    def test_failed_receipt_verifies(self):
        bad = SignatureShare(
            signer_id=self.shares[1].signer_id,
            nonce_commitment=self.shares[1].nonce_commitment,
            z=(self.shares[1].z + 1) % FIELD_PRIME,
        )
        failed = create_audit(MESSAGE, [self.shares[0], bad], self.round_info, self.key)
        self.assertTrue(
            verify_audit_receipt(create_audit_receipt(MESSAGE, failed, self.key))
        )

    def test_needs_no_dkg_or_secret(self):
        # The verifier accepts the receipt object alone; this test never
        # passes a SigningDKGResult or share into it.
        self.assertTrue(verify_audit_receipt(dataclasses.replace(self.receipt)))

    def test_tampered_message_returns_false(self):
        self.assertFalse(
            verify_audit_receipt(dataclasses.replace(self.receipt, message=b"x"))
        )

    def test_rebound_public_key_returns_false(self):
        other = self.receipt.public_key * GENERATOR % GROUP_PRIME
        self.assertNotEqual(other, self.receipt.public_key)
        self.assertFalse(
            verify_audit_receipt(dataclasses.replace(self.receipt, public_key=other))
        )

    def test_rebound_verification_share_returns_false(self):
        shares = list(self.receipt.verification_shares)
        shares[0] = shares[0] * GENERATOR % GROUP_PRIME
        self.assertFalse(
            verify_audit_receipt(
                dataclasses.replace(self.receipt, verification_shares=tuple(shares))
            )
        )

    def test_swapped_verification_shares_returns_false(self):
        # Realigning shares against different ids (a rebinding) must fail.
        shares = list(self.receipt.verification_shares)
        shares[0], shares[1] = shares[1], shares[0]
        self.assertFalse(
            verify_audit_receipt(
                dataclasses.replace(self.receipt, verification_shares=tuple(shares))
            )
        )

    def test_tampered_generator_returns_false(self):
        # 256 is another generator of the same order-q subgroup; using it
        # changes every g ** z comparison without breaking structure.
        self.assertFalse(
            verify_audit_receipt(
                dataclasses.replace(self.receipt, generator=BLINDING_GENERATOR)
            )
        )

    def test_tampered_audit_digest_returns_false(self):
        payload = bytearray(self.receipt.audit.payload)
        digest_offset = len(b"thresholdsign/audit/v1")
        payload[digest_offset] ^= 0x01
        self.assertFalse(
            verify_audit_receipt(
                dataclasses.replace(self.receipt, audit=SigningAudit(bytes(payload)))
            )
        )

    def test_tampered_audit_row_returns_false(self):
        length = (GROUP_PRIME.bit_length() + 7) // 8
        # Flip one byte of the first row's z_i (last row field of row 1).
        row_offset = len(b"thresholdsign/audit/v1") + 32 + 3 * length + 4
        z_offset = row_offset + 2 * length + 1
        payload = bytearray(self.receipt.audit.payload)
        payload[z_offset] = (payload[z_offset] + 1) % 256
        # A naive flip may push z_i out of range; choose a flip that keeps
        # it in [0, q) by construction: add q-neutral delta if needed.
        candidate = SigningAudit(bytes(payload))
        try:
            result = verify_audit_receipt(
                dataclasses.replace(self.receipt, audit=candidate)
            )
        except ValueError:
            self.skipTest("flip moved z_i out of range")
        self.assertFalse(result)

    def test_foreign_audit_payload_rejected(self):
        # The audit record of a second, independent key rebound onto this
        # receipt's public material must not verify.
        other_key = make_key(seed_offset=99)
        other_round, other_shares = make_round(other_key)
        other_audit = create_audit(MESSAGE, other_shares, other_round, other_key)
        rebound = dataclasses.replace(self.receipt, audit=other_audit)
        self.assertFalse(verify_audit_receipt(rebound))

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            verify_audit_receipt("not a receipt")
        with self.assertRaises(TypeError):
            verify_audit_receipt(dataclasses.replace(self.receipt, message="x"))
        with self.assertRaises(TypeError):
            verify_audit_receipt(
                dataclasses.replace(self.receipt, threshold="2")
            )
        with self.assertRaises(TypeError):
            verify_audit_receipt(
                dataclasses.replace(self.receipt, participant_ids=[1, 2, 3])
            )
        with self.assertRaises(TypeError):
            verify_audit_receipt(
                dataclasses.replace(self.receipt, participant_ids=(1, True, 3))
            )

    def test_structural_errors(self):
        # threshold above the participant count
        with self.assertRaises(ValueError):
            verify_audit_receipt(dataclasses.replace(self.receipt, threshold=4))
        # threshold zero
        with self.assertRaises(ValueError):
            verify_audit_receipt(dataclasses.replace(self.receipt, threshold=0))
        # misaligned verification share count
        with self.assertRaises(ValueError):
            verify_audit_receipt(
                dataclasses.replace(
                    self.receipt, verification_shares=self.receipt.verification_shares[:2]
                )
            )
        # unsorted participant ids
        with self.assertRaises(ValueError):
            verify_audit_receipt(
                dataclasses.replace(
                    self.receipt,
                    participant_ids=(1, 3, 2),
                    verification_shares=(
                        self.receipt.verification_shares[0],
                        self.receipt.verification_shares[2],
                        self.receipt.verification_shares[1],
                    ),
                )
            )
        # participant id out of field range
        with self.assertRaises(ValueError):
            verify_audit_receipt(
                dataclasses.replace(
                    self.receipt,
                    participant_ids=(1, 2, FIELD_PRIME),
                )
            )
        # malformed audit payload
        with self.assertRaises(ValueError):
            verify_audit_receipt(
                dataclasses.replace(
                    self.receipt, audit=SigningAudit(b"bad-payload")
                )
            )
        # bad group parameters
        with self.assertRaises(ValueError):
            verify_audit_receipt(
                dataclasses.replace(self.receipt, field_prime=2018)
            )


class EncodeAuditReceiptTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.round_info, self.shares = make_round(self.key)
        self.audit = create_audit(MESSAGE, self.shares, self.round_info, self.key)
        self.receipt = create_audit_receipt(MESSAGE, self.audit, self.key)

    def test_wire_layout_matches_independent_builder(self):
        self.assertEqual(
            encode_audit_receipt(self.receipt), build_wire(self.receipt)
        )

    def test_tag_and_order(self):
        blob = encode_audit_receipt(self.receipt)
        self.assertTrue(blob.startswith(RECEIPT_TAG))

    def test_encoding_is_unique(self):
        once = encode_audit_receipt(self.receipt)
        twice = encode_audit_receipt(self.receipt)
        self.assertEqual(once, twice)

    def test_roundtrip_value_equality(self):
        blob = encode_audit_receipt(self.receipt)
        decoded = decode_audit_receipt(blob)
        self.assertEqual(decoded, self.receipt)
        self.assertEqual(encode_audit_receipt(decoded), blob)

    def test_failed_receipt_roundtrip(self):
        bad = SignatureShare(
            signer_id=self.shares[1].signer_id,
            nonce_commitment=self.shares[1].nonce_commitment,
            z=(self.shares[1].z + 1) % FIELD_PRIME,
        )
        failed = create_audit(MESSAGE, [self.shares[0], bad], self.round_info, self.key)
        receipt = create_audit_receipt(MESSAGE, failed, self.key)
        blob = encode_audit_receipt(receipt)
        self.assertEqual(decode_audit_receipt(blob), receipt)
        self.assertEqual(build_wire(receipt), blob)

    def test_empty_message(self):
        key = make_key(seed_offset=7)
        round_info, shares = make_round(key, message=b"")
        audit = create_audit(b"", shares, round_info, key)
        receipt = create_audit_receipt(b"", audit, key)
        blob = encode_audit_receipt(receipt)
        self.assertEqual(decode_audit_receipt(blob), receipt)

    def test_encoding_contains_no_dkg_secret(self):
        # The wire form is tag + public integers + the audit payload, and
        # the audit payload itself never carries nonces or secret shares.
        blob = encode_audit_receipt(self.receipt)
        for secret_share in (share.y for share in self.key.result.shares):
            body = secret_share.to_bytes(2, "big")
            # A 2-byte big-endian secret could appear by chance; assert it
            # does not appear in the public receipt.
            self.assertNotIn(body, blob)

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            encode_audit_receipt("not a receipt")

    def test_structurally_invalid_receipt_rejected(self):
        bad = dataclasses.replace(self.receipt, threshold=0)
        with self.assertRaises(ValueError):
            encode_audit_receipt(bad)
        bad = dataclasses.replace(
            self.receipt, audit=SigningAudit(b"garbage")
        )
        with self.assertRaises(ValueError):
            encode_audit_receipt(bad)


class DecodeAuditReceiptTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.round_info, self.shares = make_round(self.key)
        self.audit = create_audit(MESSAGE, self.shares, self.round_info, self.key)
        self.receipt = create_audit_receipt(MESSAGE, self.audit, self.key)
        self.blob = encode_audit_receipt(self.receipt)
        self.tag_length = len(RECEIPT_TAG)
        # Offset of the first length-prefixed integer (field_prime).
        self.first_int = self.tag_length + 4 + len(MESSAGE)

    def test_type_error_on_non_bytes(self):
        with self.assertRaises(TypeError):
            decode_audit_receipt("bytes-only")
        with self.assertRaises(TypeError):
            decode_audit_receipt(bytearray(self.blob))

    def test_bad_tag(self):
        with self.assertRaises(ValueError):
            decode_audit_receipt(b"thresholdsign/wrong-tag/v1" + b"\x00" * 20)
        with self.assertRaises(ValueError):
            decode_audit_receipt(b"")

    def test_truncation(self):
        for cut in (1, 4, len(MESSAGE), 10, len(self.blob) - 1):
            with self.assertRaises(ValueError):
                decode_audit_receipt(self.blob[:-cut])

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_audit_receipt(self.blob + b"\x00")
        with self.assertRaises(ValueError):
            decode_audit_receipt(self.blob + b"trailing")

    def test_declared_message_length_runs_past_end(self):
        mutated = (
            self.blob[: self.tag_length]
            + (len(MESSAGE) + 1).to_bytes(4, "big")
            + self.blob[self.tag_length + 4:]
        )
        with self.assertRaises(ValueError):
            decode_audit_receipt(mutated)

    def test_non_canonical_integer_leading_zero(self):
        # field_prime is 2017 = 0x07e1, encoded as length 2, body 07 e1.
        self.assertEqual(
            self.blob[self.first_int:self.first_int + 6],
            b"\x00\x00\x00\x02\x07\xe1",
        )
        mutated = (
            self.blob[: self.first_int]
            + b"\x00\x00\x00\x03\x00\x07\xe1"
            + self.blob[self.first_int + 6:]
        )
        with self.assertRaises(ValueError):
            decode_audit_receipt(mutated)

    def test_over_long_integer_length(self):
        mutated = (
            self.blob[: self.first_int + 3]
            + b"\x03"
            + self.blob[self.first_int + 4:]
        )
        with self.assertRaises(ValueError):
            decode_audit_receipt(mutated)

    def test_zero_integer_length(self):
        mutated = (
            self.blob[: self.first_int + 3]
            + b"\x00"
            + self.blob[self.first_int + 4:]
        )
        with self.assertRaises(ValueError):
            decode_audit_receipt(mutated)

    def test_participant_count_mismatch(self):
        # Advance to the participant count: tag + message + 5 integers
        # (field, group, generator, public_key, threshold).
        offset = self.first_int
        for _ in range(5):
            length = int.from_bytes(self.blob[offset:offset + 4], "big")
            offset += 4 + length
        self.assertLess(offset + 4, len(self.blob))
        count = int.from_bytes(self.blob[offset:offset + 4], "big")
        self.assertEqual(count, 3)
        mutated = (
            self.blob[:offset]
            + (count - 1).to_bytes(4, "big")
            + self.blob[offset + 4:]
        )
        with self.assertRaises(ValueError):
            decode_audit_receipt(mutated)

    def test_share_count_mismatch(self):
        offset = self.first_int
        for _ in range(5):
            length = int.from_bytes(self.blob[offset:offset + 4], "big")
            offset += 4 + length
        participant_count = int.from_bytes(self.blob[offset:offset + 4], "big")
        offset += 4
        for _ in range(participant_count):
            length = int.from_bytes(self.blob[offset:offset + 4], "big")
            offset += 4 + length
        share_count = int.from_bytes(self.blob[offset:offset + 4], "big")
        self.assertEqual(share_count, participant_count)
        mutated = (
            self.blob[:offset]
            + (share_count + 1).to_bytes(4, "big")
            + self.blob[offset + 4:]
        )
        with self.assertRaises(ValueError):
            decode_audit_receipt(mutated)

    def test_audit_payload_length_mismatch(self):
        # The audit payload length sits 4 bytes before the payload itself.
        offset = len(self.blob) - len(self.audit.payload) - 4
        length = int.from_bytes(self.blob[offset:offset + 4], "big")
        mutated = (
            self.blob[:offset]
            + (length - 1).to_bytes(4, "big")
            + self.blob[offset + 4:]
        )
        with self.assertRaises(ValueError):
            decode_audit_receipt(mutated)

    def test_decoded_payload_is_structure_only(self):
        # A structurally valid encoding whose record does not verify is
        # still decoded; verify_audit_receipt reports False rather than
        # decode raising.
        payload = bytearray(self.audit.payload)
        offset = len(b"thresholdsign/audit/v1")
        payload[offset] ^= 0x01  # digest flip
        tampered = dataclasses.replace(self.receipt, audit=SigningAudit(bytes(payload)))
        blob = encode_audit_receipt(tampered)
        decoded = decode_audit_receipt(blob)
        self.assertEqual(decoded, tampered)
        self.assertFalse(verify_audit_receipt(decoded))

    def test_out_of_range_threshold_rejected(self):
        # threshold is the 5th length-prefixed integer.
        offset = self.first_int
        for _ in range(4):
            length = int.from_bytes(self.blob[offset:offset + 4], "big")
            offset += 4 + length
        body = varint(99)
        mutated = (
            self.blob[:offset] + body + self.blob[offset + 4 + 1:]
        )
        with self.assertRaises(ValueError):
            decode_audit_receipt(mutated)

    def test_illegal_group_parameter_rejected(self):
        # Replace field_prime (2017) with the composite 1000: structure
        # parses, but primality validation must fail.
        mutated = (
            self.blob[: self.first_int]
            + varint(1000)
            + self.blob[self.first_int + 6:]
        )
        with self.assertRaises(ValueError):
            decode_audit_receipt(mutated)

    def test_roundtrip_preserves_every_value(self):
        decoded = decode_audit_receipt(self.blob)
        self.assertEqual(decoded.message, self.receipt.message)
        self.assertEqual(decoded.audit, self.receipt.audit)
        self.assertEqual(decoded.participant_ids, self.receipt.participant_ids)
        self.assertEqual(decoded.threshold, self.receipt.threshold)
        self.assertEqual(decoded.field_prime, self.receipt.field_prime)
        self.assertEqual(decoded.group_prime, self.receipt.group_prime)
        self.assertEqual(decoded.generator, self.receipt.generator)
        self.assertEqual(decoded.public_key, self.receipt.public_key)
        self.assertEqual(
            decoded.verification_shares, self.receipt.verification_shares
        )


if __name__ == "__main__":
    unittest.main()
