"""Tests for the stateless threshold-Schnorr audit chain: AuditChain /
audit_chain_payload / verify_audit_chain."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    AuditChain,
    SignatureShare,
    SigningAudit,
    aggregate_signature,
    aggregate_signing_dkg,
    audit_chain_payload,
    check_audit,
    create_audit,
    create_signature_share,
    create_signing_contribution,
    create_signing_nonce_commitment,
    create_signing_round,
    verify_audit_chain,
    verify_signature,
)

# Same toy group as the audit tests: 8069 = 4 * 2017 + 1 is prime, 16 and
# 256 = 16 ** 2 are distinct generators of the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

CHAIN_TAG = b"ts/ac/v1"


def fixed_random(seed=1):
    """Deterministic stand-in for secrets.randbelow (same LCG as DKG tests)."""
    state = {"value": seed}

    def randbelow(upper: int) -> int:
        state["value"] = (
            state["value"] * 6364136223846793005 + 1442695040888963407
        ) % upper
        return state["value"]

    return randbelow


def make_key(participant_ids=(1, 2, 3), threshold=2, seed_offset=0):
    contributions = [
        create_signing_contribution(
            pid,
            participant_ids,
            threshold,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            blinding_generator=BLINDING_GENERATOR,
            randbelow=fixed_random(pid + seed_offset),
        )
        for pid in participant_ids
    ]
    return aggregate_signing_dkg(contributions)


def make_round(key, message, signer_ids=(1, 3), seed=100):
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


def make_record(key, message, *, failing=False, seed=0):
    round_info, shares = make_round(key, message, seed=seed)
    if failing:
        shares = [
            shares[0],
            SignatureShare(
                signer_id=shares[1].signer_id,
                nonce_commitment=shares[1].nonce_commitment,
                z=(shares[1].z + 1) % FIELD_PRIME,
            ),
        ]
    audit = create_audit(message, shares, round_info, key)
    return (message, audit)


def sign_records(key, records, *, signer_ids=(1, 3), seed=900):
    message = audit_chain_payload(records, key.public_key)
    round_info, shares = make_round(key, message, signer_ids, seed)
    signature = aggregate_signature(shares, round_info, key)
    assert isinstance(signature, AggregateSignature)
    return AuditChain(records=tuple(records), signature=signature)


class AuditChainDataclassTest(unittest.TestCase):
    def test_frozen_two_fields_positional_and_value_equality(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(AuditChain)],
            ["records", "signature"],
        )
        key = make_key()
        chain = sign_records(key, (make_record(key, b"m", seed=1),))
        self.assertEqual(chain, AuditChain(chain.records, chain.signature))
        self.assertEqual(
            chain, AuditChain(records=chain.records, signature=chain.signature)
        )
        self.assertEqual(hash(chain), hash(AuditChain(chain.records, chain.signature)))
        with self.assertRaises(FrozenInstanceError):
            chain.records = ()
        with self.assertRaises(FrozenInstanceError):
            chain.signature = chain.signature


class AuditChainPayloadTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = (
            make_record(self.key, b"message-one", seed=10),
            make_record(self.key, b"message-two", seed=20),
            make_record(self.key, b"message-three", seed=30),
        )

    def test_payload_layout(self):
        key_bytes = self.key.public_key.to_bytes(
            (self.key.public_key.bit_length() + 7) // 8, "big"
        )
        expected = bytearray(CHAIN_TAG)
        expected += hashlib.sha256(key_bytes).digest()
        expected += (3).to_bytes(8, "big")
        for message, audit in self.records:
            expected += hashlib.sha256(message).digest()
            expected += hashlib.sha256(audit.payload).digest()
        payload = audit_chain_payload(self.records, self.key.public_key)
        self.assertEqual(payload, bytes(expected))
        self.assertEqual(len(payload), 8 + 32 + 8 + 3 * 64)

    def test_order_sensitive_and_position_bound(self):
        payload = audit_chain_payload(self.records, self.key.public_key)
        reordered = audit_chain_payload(
            (self.records[1], self.records[0], self.records[2]),
            self.key.public_key,
        )
        self.assertNotEqual(payload, reordered)
        swapped = audit_chain_payload(
            ((self.records[0][0], self.records[1][1]),) + self.records[1:],
            self.key.public_key,
        )
        self.assertNotEqual(payload, swapped)
        # Swapping just the message of one record changes the digest pair.
        re_message = audit_chain_payload(
            ((b"other", self.records[0][1]),) + self.records[1:],
            self.key.public_key,
        )
        self.assertNotEqual(payload, re_message)

    def test_key_binding(self):
        payload = audit_chain_payload(self.records, self.key.public_key)
        other = make_key(seed_offset=100)
        self.assertNotEqual(other.public_key, self.key.public_key)
        self.assertNotEqual(
            payload, audit_chain_payload(self.records, other.public_key)
        )

    def test_accepts_any_iterable(self):
        payload = audit_chain_payload(self.records, self.key.public_key)
        self.assertEqual(
            audit_chain_payload(iter(self.records), self.key.public_key), payload
        )
        self.assertEqual(
            audit_chain_payload(list(self.records), self.key.public_key), payload
        )

    def test_minimal_key_encoding_is_canonical(self):
        # The digested key bytes are the shortest unsigned big-endian form:
        # the integer 1 is the single byte 01 with no leading zero.
        self.assertEqual(
            audit_chain_payload(self.records[:1], 1)[:8 + 32],
            CHAIN_TAG + hashlib.sha256(b"\x01").digest(),
        )

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            audit_chain_payload(self.records, "1")
        with self.assertRaises(TypeError):
            audit_chain_payload(self.records, True)
        with self.assertRaises(TypeError):
            audit_chain_payload(b"raw", self.key.public_key)
        with self.assertRaises(TypeError):
            audit_chain_payload(["record"], self.key.public_key)
        with self.assertRaises(TypeError):
            audit_chain_payload(
                [("message-one", self.records[0][1])], self.key.public_key
            )
        with self.assertRaises(TypeError):
            audit_chain_payload(
                [(b"message-one", "audit")], self.key.public_key
            )
        with self.assertRaises(TypeError):
            audit_chain_payload([(b"message-one",)], self.key.public_key)
        with self.assertRaises(TypeError):
            audit_chain_payload([(b"message-one", 1, 2)], self.key.public_key)
        bogus = object.__new__(SigningAudit)
        object.__setattr__(bogus, "payload", 123)
        with self.assertRaises(TypeError):
            audit_chain_payload([(b"message-one", bogus)], self.key.public_key)

    def test_value_errors(self):
        with self.assertRaises(ValueError):
            audit_chain_payload((), self.key.public_key)
        with self.assertRaises(ValueError):
            audit_chain_payload(iter(()), self.key.public_key)
        with self.assertRaises(ValueError):
            audit_chain_payload(self.records, 0)
        with self.assertRaises(ValueError):
            audit_chain_payload(self.records, -1)


class VerifyAuditChainTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = (
            make_record(self.key, b"message-one", seed=10),
            make_record(self.key, b"message-two", failing=True, seed=20),
            make_record(self.key, b"message-three", seed=30),
        )
        self.chain = sign_records(self.key, self.records)

    def test_verifies_with_passing_and_failing_receipts(self):
        self.assertTrue(verify_audit_chain(self.chain, self.key))

    def test_signature_is_on_the_chain_message(self):
        payload = audit_chain_payload(self.records, self.key.public_key)
        self.assertTrue(
            verify_signature(
                payload,
                self.chain.signature,
                self.key.public_key,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            )
        )

    def test_deletion_detected(self):
        self.assertFalse(
            verify_audit_chain(
                AuditChain(self.records[:2], self.chain.signature), self.key
            )
        )
        self.assertFalse(
            verify_audit_chain(
                AuditChain(self.records[1:], self.chain.signature), self.key
            )
        )

    def test_insertion_detected(self):
        extra = make_record(self.key, b"message-four", seed=40)
        self.assertFalse(
            verify_audit_chain(
                AuditChain((extra,) + self.records, self.chain.signature), self.key
            )
        )
        self.assertFalse(
            verify_audit_chain(
                AuditChain(self.records[:2] + (extra,), self.chain.signature),
                self.key,
            )
        )

    def test_reordering_detected(self):
        reordered = AuditChain(
            (self.records[1], self.records[0], self.records[2]),
            self.chain.signature,
        )
        self.assertFalse(verify_audit_chain(reordered, self.key))

    def test_value_substitution_detected(self):
        # Same message bound to a different receipt and vice versa.
        swapped = AuditChain(
            ((self.records[0][0], self.records[1][1]),) + self.records[1:],
            self.chain.signature,
        )
        self.assertFalse(verify_audit_chain(swapped, self.key))
        re_messaged = AuditChain(
            ((b"other-message", self.records[0][1]),) + self.records[1:],
            self.chain.signature,
        )
        self.assertFalse(verify_audit_chain(re_messaged, self.key))

    def test_cross_key_substitution_detected(self):
        other = make_key(seed_offset=100)
        # The other key shares the same group and participant ids, so the
        # receipts decode structurally but fail check_audit against it.
        self.assertFalse(verify_audit_chain(self.chain, other))

    def test_tampered_signature_returns_false(self):
        sig = self.chain.signature
        bad = AggregateSignature(
            R=sig.R, z=(sig.z + 1) % FIELD_PRIME, signer_ids=sig.signer_ids
        )
        self.assertFalse(
            verify_audit_chain(AuditChain(self.records, bad), self.key)
        )

    def test_signed_under_another_key_returns_false(self):
        other = make_key(seed_offset=100)
        # Build receipts that genuinely belong to other, signed by other, and
        # present them to self.key: the per-record check_audit fails.
        foreign_records = (make_record(other, b"message-one", seed=10),)
        foreign_chain = sign_records(other, foreign_records)
        self.assertFalse(verify_audit_chain(foreign_chain, self.key))

    def test_single_record_chain(self):
        key = make_key(participant_ids=(1, 2, 3), threshold=1)
        records = (make_record(key, b"alone", seed=7),)
        chain = sign_records(key, records, signer_ids=(2,), seed=5)
        self.assertTrue(verify_audit_chain(chain, key))

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            verify_audit_chain("chain", self.key)
        with self.assertRaises(TypeError):
            verify_audit_chain(self.chain, "key")
        with self.assertRaises(TypeError):
            verify_audit_chain(AuditChain([], self.chain.signature), self.key)
        with self.assertRaises(TypeError):
            verify_audit_chain(
                AuditChain((1,), self.chain.signature), self.key
            )
        with self.assertRaises(TypeError):
            verify_audit_chain(
                AuditChain(((b"m", "audit"),), self.chain.signature), self.key
            )
        with self.assertRaises(TypeError):
            verify_audit_chain(
                AuditChain(self.records, "signature"), self.key
            )
        bogus = object.__new__(SigningAudit)
        object.__setattr__(bogus, "payload", 123)
        with self.assertRaises(TypeError):
            verify_audit_chain(
                AuditChain(((b"m", bogus),), self.chain.signature), self.key
            )

    def test_value_errors(self):
        with self.assertRaises(ValueError):
            verify_audit_chain(AuditChain((), self.chain.signature), self.key)
        sig = self.chain.signature
        no_signers = AggregateSignature(R=sig.R, z=sig.z, signer_ids=())
        with self.assertRaises(ValueError):
            verify_audit_chain(AuditChain(self.records, no_signers), self.key)
        unsorted_ids = AggregateSignature(
            R=sig.R, z=sig.z, signer_ids=tuple(reversed(sig.signer_ids))
        )
        with self.assertRaises(ValueError):
            verify_audit_chain(
                AuditChain(self.records, unsorted_ids), self.key
            )

    def test_structurally_illegal_receipt_raises_value_error(self):
        message, audit = self.records[0]
        broken = SigningAudit(audit.payload[:-1])
        chain = AuditChain(((message, broken),), self.chain.signature)
        with self.assertRaises(ValueError):
            verify_audit_chain(chain, self.key)

    def test_wrong_key_context_raises_on_structural_mismatch(self):
        # A key with different participant ids makes the receipt structurally
        # illegal (rows must be DKG participants) -> ValueError, not False.
        other = make_key(participant_ids=(4, 5, 6), seed_offset=200)
        with self.assertRaises(ValueError):
            verify_audit_chain(self.chain, other)


if __name__ == "__main__":
    unittest.main()
