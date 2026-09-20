"""Tests for the stateless audit chain: AuditChain / audit_chain_payload /
verify_audit_chain."""

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
    decode_audit_chain,
    encode_audit_chain,
    verify_audit_chain,
)

# Same toy group as the audit tests: 8069 = 4 * 2017 + 1 is prime, 16 and
# 256 = 16 ** 2 are distinct generators of the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

CHAIN_TAG = b"ts/ac/v1"
WIRE_TAG = b"thresholdsign/audit-chain/v1"


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def build_wire(records, signature):
    """Independently build the audit-chain wire format straight from the spec."""
    out = bytearray(WIRE_TAG)
    out += len(records).to_bytes(4, "big", signed=False)
    for message, audit in records:
        out += len(message).to_bytes(4, "big", signed=False)
        out += message
        out += len(audit.payload).to_bytes(4, "big", signed=False)
        out += audit.payload
    out += varint(signature.R)
    out += varint(signature.z)
    out += len(signature.signer_ids).to_bytes(4, "big", signed=False)
    for signer_id in signature.signer_ids:
        out += varint(signer_id)
    return bytes(out)


def _wire_varint(stream, offset):
    """Read one length-prefixed integer from a wire encoding in tests."""
    length = int.from_bytes(stream[offset:offset + 4], "big")
    offset += 4
    value = int.from_bytes(stream[offset:offset + length], "big")
    return value, offset + length


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


def sign_message(key, message, signer_ids=(1, 3), seed=100):
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
    signature = aggregate_signature(shares, round_info, key)
    assert isinstance(signature, AggregateSignature)
    return signature


def make_record(key, message, *, signer_ids=(1, 3), seed=100, bad_share=False):
    """Create one (message, SigningAudit) pair; bad_share records a status-0 receipt."""
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
    if bad_share:
        shares[1] = SignatureShare(
            signer_id=shares[1].signer_id,
            nonce_commitment=shares[1].nonce_commitment,
            z=(shares[1].z + 1) % FIELD_PRIME,
        )
    audit = create_audit(message, shares, round_info, key)
    return message, audit


def seal_chain(key, records, *, seed=900):
    """Seal records into an AuditChain with a threshold signature of the key."""
    payload = audit_chain_payload(records, key.public_key)
    signature = sign_message(key, payload, seed=seed)
    return AuditChain(records=records, signature=signature)


def minimal_be(value: int) -> bytes:
    return value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")


def expected_payload(records, public_key):
    """Independently build the chain message straight from the spec."""
    out = bytearray(CHAIN_TAG)
    out += hashlib.sha256(minimal_be(public_key)).digest()
    out += len(records).to_bytes(8, "big", signed=False)
    for message, audit in records:
        out += hashlib.sha256(message).digest()
        out += hashlib.sha256(audit.payload).digest()
    return bytes(out)


class AuditChainDataTest(unittest.TestCase):
    def test_frozen_positional_value_equality(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(AuditChain)],
            ["records", "signature"],
        )
        sig = AggregateSignature(R=2, z=3, signer_ids=(1, 3))
        record = (b"m", SigningAudit(b"a"))
        chain = AuditChain((record,), sig)
        same = AuditChain(records=(record,), signature=sig)
        self.assertEqual(chain, same)
        self.assertEqual(hash(chain), hash(same))
        self.assertNotEqual(chain, AuditChain((record,), dataclasses.replace(sig, z=4)))
        with self.assertRaises(FrozenInstanceError):
            chain.records = ()

    def test_non_empty_and_order_preserved(self):
        sig = AggregateSignature(R=2, z=3, signer_ids=(1, 3))
        r0 = (b"m0", SigningAudit(b"a0"))
        r1 = (b"m1", SigningAudit(b"a1"))
        chain = AuditChain((r0, r1), sig)
        self.assertEqual(len(chain.records), 2)
        self.assertIs(chain.records[0], r0)
        self.assertIs(chain.records[1], r1)
        self.assertNotEqual(chain, AuditChain((r1, r0), sig))


class AuditChainPayloadTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = tuple(
            make_record(self.key, f"message-{i}".encode(), seed=100 + 10 * i)
            for i in range(3)
        )

    def test_layout_matches_independent_builder(self):
        payload = audit_chain_payload(self.records, self.key.public_key)
        self.assertEqual(payload, expected_payload(self.records, self.key.public_key))
        self.assertTrue(payload.startswith(CHAIN_TAG))
        offset = len(CHAIN_TAG)
        self.assertEqual(
            payload[offset:offset + 32],
            hashlib.sha256(minimal_be(self.key.public_key)).digest(),
        )
        offset += 32
        self.assertEqual(int.from_bytes(payload[offset:offset + 8], "big"), 3)

    def test_single_record_layout(self):
        record = self.records[:1]
        payload = audit_chain_payload(record, self.key.public_key)
        self.assertEqual(payload, expected_payload(record, self.key.public_key))
        self.assertEqual(
            len(payload), len(CHAIN_TAG) + 32 + 8 + 32 + 32
        )

    def test_deterministic(self):
        payload = audit_chain_payload(self.records, self.key.public_key)
        self.assertEqual(payload, audit_chain_payload(self.records, self.key.public_key))

    def test_order_matters(self):
        payload = audit_chain_payload(self.records, self.key.public_key)
        reordered = (self.records[1], self.records[0], self.records[2])
        self.assertNotEqual(payload, audit_chain_payload(reordered, self.key.public_key))

    def test_key_is_bound(self):
        other_key = make_key(seed_offset=10)
        self.assertNotEqual(other_key.public_key, self.key.public_key)
        payload = audit_chain_payload(self.records, self.key.public_key)
        self.assertNotEqual(
            payload, audit_chain_payload(self.records, other_key.public_key)
        )

    def test_type_errors(self):
        record = self.records[0]
        with self.assertRaises(TypeError):
            audit_chain_payload([record], self.key.public_key)
        with self.assertRaises(TypeError):
            audit_chain_payload((b"only-message",), self.key.public_key)
        with self.assertRaises(TypeError):
            audit_chain_payload(((b"m", b"not-an-audit"),), self.key.public_key)
        with self.assertRaises(TypeError):
            audit_chain_payload(((bytearray(b"m"), record[1]),), self.key.public_key)
        with self.assertRaises(TypeError):
            audit_chain_payload(((record[0], record[1], None),), self.key.public_key)
        with self.assertRaises(TypeError):
            audit_chain_payload(self.records, str(self.key.public_key))
        with self.assertRaises(TypeError):
            audit_chain_payload(self.records, True)

    def test_empty_and_non_positive_key_raise_value_error(self):
        with self.assertRaises(ValueError):
            audit_chain_payload((), self.key.public_key)
        with self.assertRaises(ValueError):
            audit_chain_payload(self.records, 0)
        with self.assertRaises(ValueError):
            audit_chain_payload(self.records, -1)

    def test_count_overflow_raises_value_error(self):
        class HugeTuple(tuple):
            def __len__(self):
                return 2 ** 64

        records = HugeTuple((self.records[0],))
        with self.assertRaises(ValueError):
            audit_chain_payload(records, self.key.public_key)


class VerifyAuditChainTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = tuple(
            make_record(self.key, f"message-{i}".encode(), seed=100 + 10 * i)
            for i in range(3)
        )
        self.chain = seal_chain(self.key, self.records, seed=900)

    def test_honest_chain_verifies(self):
        self.assertTrue(verify_audit_chain(self.chain, self.key))

    def test_single_record_chain_verifies(self):
        chain = seal_chain(self.key, self.records[:1], seed=910)
        self.assertTrue(verify_audit_chain(chain, self.key))

    def test_failure_receipt_verifies(self):
        # A faithfully recorded failure receipt (status 0) belongs in a chain.
        failing = make_record(
            self.key, b"failing-message", seed=150, bad_share=True
        )
        self.assertTrue(check_audit(failing[0], failing[1], self.key))
        records = (self.records[0], failing, self.records[2])
        chain = seal_chain(self.key, records, seed=920)
        self.assertTrue(verify_audit_chain(chain, self.key))

    def test_payload_was_signed_under_the_key(self):
        # The signature is an ordinary threshold Schnorr signature on the
        # canonical payload, independently verifiable with verify_signature.
        from thresholdsign import verify_signature

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

    def test_deleting_a_record_is_detected(self):
        chain = AuditChain(self.records[:2], self.chain.signature)
        self.assertFalse(verify_audit_chain(chain, self.key))

    def test_inserting_a_record_is_detected(self):
        extra = make_record(self.key, b"inserted-message", seed=200)
        chain = AuditChain(
            (self.records[0], extra) + self.records[1:], self.chain.signature
        )
        self.assertFalse(verify_audit_chain(chain, self.key))

    def test_reordering_records_is_detected(self):
        reordered = (self.records[1], self.records[0], self.records[2])
        chain = AuditChain(reordered, self.chain.signature)
        self.assertFalse(verify_audit_chain(chain, self.key))

    def test_cross_key_replacement_is_detected(self):
        # A second key over the same participant ids (so the foreign receipt's
        # rows remain well-formed for check_audit) produces a genuine receipt
        # that must not be substitutable into the first key's chain.
        other_key = make_key(seed_offset=10)
        self.assertNotEqual(other_key.public_key, self.key.public_key)
        foreign = make_record(other_key, b"foreign-message", seed=300)
        self.assertTrue(check_audit(foreign[0], foreign[1], other_key))
        replaced = (self.records[0], foreign, self.records[2])
        chain = AuditChain(replaced, self.chain.signature)
        self.assertFalse(verify_audit_chain(chain, self.key))

    def test_message_swap_is_detected(self):
        swapped = (
            (b"wrong-message", self.records[0][1]),
        ) + self.records[1:]
        chain = AuditChain(swapped, self.chain.signature)
        self.assertFalse(verify_audit_chain(chain, self.key))

    def test_tampered_receipt_is_detected(self):
        message, audit = self.records[0]
        L = (GROUP_PRIME.bit_length() + 7) // 8
        bad_z = (int.from_bytes(audit.payload[-L:], "big") + 1) % FIELD_PRIME
        tampered = SigningAudit(
            audit.payload[:-L] + bad_z.to_bytes(L, "big")
        )
        self.assertFalse(check_audit(message, tampered, self.key))
        chain = AuditChain(
            ((message, tampered),) + self.records[1:], self.chain.signature
        )
        self.assertFalse(verify_audit_chain(chain, self.key))

    def test_bad_signature_returns_false(self):
        bad_sig = AggregateSignature(
            R=self.chain.signature.R,
            z=(self.chain.signature.z + 1) % FIELD_PRIME,
            signer_ids=self.chain.signature.signer_ids,
        )
        chain = AuditChain(self.records, bad_sig)
        self.assertFalse(verify_audit_chain(chain, self.key))

    def test_signature_from_another_payload_returns_false(self):
        other_chain = seal_chain(self.key, self.records[:2], seed=930)
        chain = AuditChain(self.records, other_chain.signature)
        self.assertFalse(verify_audit_chain(chain, self.key))

    def test_verification_under_another_key_returns_false(self):
        other_key = make_key(seed_offset=10)
        self.assertFalse(verify_audit_chain(self.chain, other_key))

    def test_type_errors(self):
        record = self.records[0]
        with self.assertRaises(TypeError):
            verify_audit_chain("chain", self.key)
        with self.assertRaises(TypeError):
            verify_audit_chain(AuditChain(self.records, "sig"), self.key)
        with self.assertRaises(TypeError):
            verify_audit_chain(AuditChain([record], self.chain.signature), self.key)
        with self.assertRaises(TypeError):
            verify_audit_chain(
                AuditChain(((b"m", b"x"),), self.chain.signature), self.key
            )
        with self.assertRaises(TypeError):
            verify_audit_chain(
                AuditChain(((bytearray(b"m"), record[1]),), self.chain.signature),
                self.key,
            )
        with self.assertRaises(TypeError):
            verify_audit_chain(self.chain, "key")

    def test_empty_chain_raises_value_error(self):
        with self.assertRaises(ValueError):
            verify_audit_chain(AuditChain((), self.chain.signature), self.key)

    def test_structurally_illegal_receipt_raises_value_error(self):
        message, _audit = self.records[0]
        broken = SigningAudit(b"not-an-audit-payload")
        chain = AuditChain(
            ((message, broken),) + self.records[1:], self.chain.signature
        )
        with self.assertRaises(ValueError):
            verify_audit_chain(chain, self.key)

    def test_structurally_illegal_signature_raises_value_error(self):
        bad_sig = AggregateSignature(
            R=GROUP_PRIME,  # out of range
            z=0,
            signer_ids=(1, 3),
        )
        chain = AuditChain(self.records, bad_sig)
        with self.assertRaises(ValueError):
            verify_audit_chain(chain, self.key)


class EncodeAuditChainTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = tuple(
            make_record(self.key, f"message-{i}".encode(), seed=100 + 10 * i)
            for i in range(3)
        )
        self.chain = seal_chain(self.key, self.records, seed=900)

    def test_layout_matches_independent_builder(self):
        wire = encode_audit_chain(self.chain)
        self.assertEqual(wire, build_wire(self.records, self.chain.signature))

    def test_tag_count_and_frames_in_order(self):
        wire = encode_audit_chain(self.chain)
        self.assertTrue(wire.startswith(WIRE_TAG))
        offset = len(WIRE_TAG)
        self.assertEqual(int.from_bytes(wire[offset:offset + 4], "big"), 3)
        offset += 4
        for message, audit in self.records:
            message_len = int.from_bytes(wire[offset:offset + 4], "big")
            offset += 4
            self.assertEqual(wire[offset:offset + message_len], message)
            offset += message_len
            receipt_len = int.from_bytes(wire[offset:offset + 4], "big")
            offset += 4
            self.assertEqual(wire[offset:offset + receipt_len], audit.payload)
            offset += receipt_len
        # Walk the signature frame explicitly.
        R, offset = _wire_varint(wire, offset)
        z, offset = _wire_varint(wire, offset)
        self.assertEqual(R, self.chain.signature.R)
        self.assertEqual(z, self.chain.signature.z)
        signer_count = int.from_bytes(wire[offset:offset + 4], "big")
        offset += 4
        self.assertEqual(signer_count, len(self.chain.signature.signer_ids))
        signer_ids = []
        for _ in range(signer_count):
            signer_id, offset = _wire_varint(wire, offset)
            signer_ids.append(signer_id)
        self.assertEqual(tuple(signer_ids), self.chain.signature.signer_ids)
        self.assertEqual(offset, len(wire))

    def test_empty_message_frame(self):
        empty_record = make_record(self.key, b"", seed=940)
        chain = seal_chain(self.key, (empty_record,), seed=941)
        wire = encode_audit_chain(chain)
        offset = len(WIRE_TAG) + 4
        self.assertEqual(wire[offset:offset + 4], (0).to_bytes(4, "big"))
        self.assertEqual(decode_audit_chain(wire), chain)

    def test_zero_integer_encodes_as_single_00(self):
        sig = AggregateSignature(R=2, z=0, signer_ids=(1,))
        chain = AuditChain(((b"m", SigningAudit(b"a")),), sig)
        wire = encode_audit_chain(chain)
        self.assertIn(b"\x00\x00\x00\x01\x00", wire)

    def test_deterministic_and_order_bound(self):
        wire = encode_audit_chain(self.chain)
        self.assertEqual(wire, encode_audit_chain(self.chain))
        reordered = AuditChain(
            (self.records[1], self.records[0], self.records[2]),
            self.chain.signature,
        )
        self.assertNotEqual(wire, encode_audit_chain(reordered))

    def test_roundtrip(self):
        decoded = decode_audit_chain(encode_audit_chain(self.chain))
        self.assertEqual(decoded, self.chain)
        self.assertEqual(
            encode_audit_chain(decoded), encode_audit_chain(self.chain)
        )

    def test_encode_does_not_require_matching_receipts_or_signature(self):
        # An opaque payload that is not a real audit receipt still encodes and
        # round-trips; verify_audit_chain is the first thing to inspect it and
        # raises ValueError on the structurally illegal receipt.
        broken = AuditChain(
            ((b"m", SigningAudit(b"totally-not-an-audit")),),
            self.chain.signature,
        )
        decoded = decode_audit_chain(encode_audit_chain(broken))
        self.assertEqual(decoded, broken)
        self.assertRaises(ValueError, verify_audit_chain, decoded, self.key)

    def test_type_errors(self):
        sig = self.chain.signature
        for bad in ("chain", None, 42, object()):
            self.assertRaises(TypeError, encode_audit_chain, bad)
        self.assertRaises(
            TypeError, encode_audit_chain, AuditChain([self.records[0]], sig)
        )
        self.assertRaises(
            TypeError, encode_audit_chain, AuditChain((b"m",), sig)
        )
        self.assertRaises(
            TypeError,
            encode_audit_chain,
            AuditChain(((b"m", b"receipt"),), sig),
        )
        self.assertRaises(
            TypeError,
            encode_audit_chain,
            AuditChain(((bytearray(b"m"), self.records[0][1]),), sig),
        )
        self.assertRaises(
            TypeError, encode_audit_chain, AuditChain(self.records, "sig")
        )
        self.assertRaises(
            TypeError,
            encode_audit_chain,
            AuditChain(self.records, dataclasses.replace(sig, R="1")),
        )
        self.assertRaises(
            TypeError,
            encode_audit_chain,
            AuditChain(self.records, dataclasses.replace(sig, R=True)),
        )
        self.assertRaises(
            TypeError,
            encode_audit_chain,
            AuditChain(self.records, dataclasses.replace(sig, signer_ids=[1, 3])),
        )
        self.assertRaises(
            TypeError,
            encode_audit_chain,
            AuditChain(
                self.records, dataclasses.replace(sig, signer_ids=(1, "3"))
            ),
        )

    def test_value_errors(self):
        sig = self.chain.signature
        self.assertRaises(ValueError, encode_audit_chain, AuditChain((), sig))
        self.assertRaises(
            ValueError,
            encode_audit_chain,
            AuditChain(((b"m", SigningAudit(b"")),), sig),
        )
        self.assertRaises(
            ValueError,
            encode_audit_chain,
            AuditChain(self.records, dataclasses.replace(sig, R=-1)),
        )
        self.assertRaises(
            ValueError,
            encode_audit_chain,
            AuditChain(self.records, dataclasses.replace(sig, z=-1)),
        )
        self.assertRaises(
            ValueError,
            encode_audit_chain,
            AuditChain(self.records, dataclasses.replace(sig, signer_ids=())),
        )
        self.assertRaises(
            ValueError,
            encode_audit_chain,
            AuditChain(
                self.records, dataclasses.replace(sig, signer_ids=(0, 1))
            ),
        )
        self.assertRaises(
            ValueError,
            encode_audit_chain,
            AuditChain(
                self.records, dataclasses.replace(sig, signer_ids=(3, 1))
            ),
        )
        self.assertRaises(
            ValueError,
            encode_audit_chain,
            AuditChain(
                self.records, dataclasses.replace(sig, signer_ids=(1, 1))
            ),
        )


class DecodeAuditChainTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = tuple(
            make_record(self.key, f"message-{i}".encode(), seed=100 + 10 * i)
            for i in range(3)
        )
        self.chain = seal_chain(self.key, self.records, seed=900)

    def test_roundtrip_value_equality(self):
        decoded = decode_audit_chain(encode_audit_chain(self.chain))
        self.assertEqual(decoded, self.chain)
        self.assertEqual(
            encode_audit_chain(decoded), encode_audit_chain(self.chain)
        )

    def test_decoded_chain_still_verifies(self):
        decoded = decode_audit_chain(encode_audit_chain(self.chain))
        self.assertTrue(verify_audit_chain(decoded, self.key))

    def test_bad_signature_decodes_without_verification(self):
        bad_sig = AggregateSignature(
            R=self.chain.signature.R,
            z=(self.chain.signature.z + 1) % FIELD_PRIME,
            signer_ids=self.chain.signature.signer_ids,
        )
        chain = AuditChain(self.records, bad_sig)
        decoded = decode_audit_chain(encode_audit_chain(chain))
        self.assertEqual(decoded, chain)
        self.assertFalse(verify_audit_chain(decoded, self.key))

    def test_rejects_bad_argument_types(self):
        wire = encode_audit_chain(self.chain)
        for bad in ("wire", bytearray(wire), None, 42):
            self.assertRaises(TypeError, decode_audit_chain, bad)

    def test_rejects_bad_tag(self):
        wire = encode_audit_chain(self.chain)
        self.assertRaises(ValueError, decode_audit_chain, b"x" + wire[1:])
        self.assertRaises(ValueError, decode_audit_chain, WIRE_TAG)
        self.assertRaises(ValueError, decode_audit_chain, b"")
        # The signed chain-message tag must not be accepted as the wire tag.
        self.assertRaises(ValueError, decode_audit_chain, CHAIN_TAG + wire[8:])

    def test_rejects_zero_count(self):
        self.assertRaises(
            ValueError, decode_audit_chain, WIRE_TAG + (0).to_bytes(4, "big")
        )

    def test_rejects_truncation_at_every_cut(self):
        wire = encode_audit_chain(self.chain)
        for cut in range(len(wire)):
            with self.assertRaises(ValueError, msg=f"cut {cut}"):
                decode_audit_chain(wire[:cut])

    def test_rejects_trailing_bytes(self):
        wire = encode_audit_chain(self.chain)
        self.assertRaises(ValueError, decode_audit_chain, wire + b"\x00")
        self.assertRaises(ValueError, decode_audit_chain, wire + b"extra")

    def test_rejects_count_mismatch(self):
        wire = bytearray(encode_audit_chain(self.chain))
        count_offset = len(WIRE_TAG)
        # Declared four records but frames for three follow -> truncation.
        wire[count_offset:count_offset + 4] = (4).to_bytes(4, "big")
        self.assertRaises(ValueError, decode_audit_chain, bytes(wire))
        # Declared two records but three frames follow -> trailing bytes.
        wire[count_offset:count_offset + 4] = (2).to_bytes(4, "big")
        self.assertRaises(ValueError, decode_audit_chain, bytes(wire))

    def test_rejects_zero_length_receipt(self):
        # One record: empty (allowed) message then a zero-length receipt.
        wire = (
            WIRE_TAG
            + (1).to_bytes(4, "big")
            + (0).to_bytes(4, "big")
            + (0).to_bytes(4, "big")
        )
        self.assertRaises(ValueError, decode_audit_chain, wire)

    def test_rejects_zero_length_integer_body(self):
        wire = (
            WIRE_TAG
            + (1).to_bytes(4, "big")
            + (1).to_bytes(4, "big") + b"m"
            + (1).to_bytes(4, "big") + b"a"
            + (0).to_bytes(4, "big")
        )
        self.assertRaises(ValueError, decode_audit_chain, wire)

    def test_rejects_non_canonical_integer(self):
        sig = AggregateSignature(R=256, z=3, signer_ids=(1, 3))
        chain = AuditChain(((b"m", SigningAudit(b"a")),), sig)
        wire = bytearray(encode_audit_chain(chain))
        # Offset of R's length prefix: tag, count, message frame, receipt frame.
        pos = len(WIRE_TAG) + 4 + 4 + 1 + 4 + 1
        self.assertEqual(bytes(wire[pos:pos + 4]), (2).to_bytes(4, "big"))
        # Pad R's body with a forbidden leading zero and stretch its length.
        wire[pos:pos + 6] = (3).to_bytes(4, "big") + b"\x00\x01\x00"
        self.assertRaises(ValueError, decode_audit_chain, bytes(wire))

    def test_rejects_bad_signer_sets(self):
        base = (
            WIRE_TAG
            + (1).to_bytes(4, "big")
            + (1).to_bytes(4, "big") + b"m"
            + (1).to_bytes(4, "big") + b"a"
            + varint(5) + varint(7)
        )
        self.assertRaises(
            ValueError, decode_audit_chain, base + (0).to_bytes(4, "big")
        )
        self.assertRaises(
            ValueError,
            decode_audit_chain,
            base + (1).to_bytes(4, "big") + varint(0),
        )
        self.assertRaises(
            ValueError,
            decode_audit_chain,
            base + (2).to_bytes(4, "big") + varint(3) + varint(2),
        )
        self.assertRaises(
            ValueError,
            decode_audit_chain,
            base + (2).to_bytes(4, "big") + varint(2) + varint(2),
        )
        # Two signers declared but only one id follows -> truncation.
        self.assertRaises(
            ValueError,
            decode_audit_chain,
            base + (2).to_bytes(4, "big") + varint(2),
        )


if __name__ == "__main__":
    unittest.main()
