"""Tests for the stateless audit chain: AuditChain / audit_chain_payload /
verify_audit_chain / encode_audit_chain / decode_audit_chain."""

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


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big", signed=False) + body


def varint(value: int) -> bytes:
    return frame(minimal_be(value))


def build_wire(chain: AuditChain) -> bytes:
    """Hand-build the chain wire format independently of the encoder."""
    out = bytearray(WIRE_TAG)
    out += len(chain.records).to_bytes(4, "big", signed=False)
    for message, audit in chain.records:
        out += frame(message)
        out += frame(audit.payload)
    sig = chain.signature
    out += varint(sig.R)
    out += varint(sig.z)
    out += len(sig.signer_ids).to_bytes(4, "big", signed=False)
    for signer_id in sig.signer_ids:
        out += varint(signer_id)
    return bytes(out)


def synthetic_chain():
    """A structurally legal chain whose receipts/signature need not match."""
    sig = AggregateSignature(R=2, z=3, signer_ids=(1, 3))
    records = (
        (b"", SigningAudit(b"r0")),
        (b"m1", SigningAudit(b"\x00r1")),
    )
    return AuditChain(records, sig)


class EncodeAuditChainTest(unittest.TestCase):
    def test_layout_matches_independent_builder(self):
        chain = synthetic_chain()
        self.assertEqual(encode_audit_chain(chain), build_wire(chain))

    def test_tag_count_and_frames_in_order(self):
        chain = synthetic_chain()
        wire = encode_audit_chain(chain)
        self.assertTrue(wire.startswith(WIRE_TAG))
        offset = len(WIRE_TAG)
        self.assertEqual(int.from_bytes(wire[offset:offset + 4], "big"), 2)
        offset += 4
        for message, audit in chain.records:
            message_len = int.from_bytes(wire[offset:offset + 4], "big")
            offset += 4
            self.assertEqual(wire[offset:offset + message_len], message)
            offset += message_len
            receipt_len = int.from_bytes(wire[offset:offset + 4], "big")
            offset += 4
            self.assertEqual(wire[offset:offset + receipt_len], audit.payload)
            offset += receipt_len
        R_len = int.from_bytes(wire[offset:offset + 4], "big")
        offset += 4
        self.assertEqual(int.from_bytes(wire[offset:offset + R_len], "big"), 2)
        offset += R_len
        z_len = int.from_bytes(wire[offset:offset + 4], "big")
        offset += 4
        self.assertEqual(int.from_bytes(wire[offset:offset + z_len], "big"), 3)
        offset += z_len
        self.assertEqual(int.from_bytes(wire[offset:offset + 4], "big"), 2)
        offset += 4
        ids = []
        for _ in range(2):
            id_len = int.from_bytes(wire[offset:offset + 4], "big")
            offset += 4
            ids.append(int.from_bytes(wire[offset:offset + id_len], "big"))
            offset += id_len
        self.assertEqual(tuple(ids), (1, 3))
        self.assertEqual(offset, len(wire))

    def test_empty_message_allowed_empty_receipt_is_not(self):
        sig = AggregateSignature(R=2, z=3, signer_ids=(1,))
        chain = AuditChain(((b"", SigningAudit(b"receipt")),), sig)
        wire = encode_audit_chain(chain)
        offset = len(WIRE_TAG) + 4
        # Empty message frame: length 0 and no body.
        self.assertEqual(wire[offset:offset + 4], b"\x00\x00\x00\x00")

    def test_zero_integers_encode_as_single_00(self):
        sig = AggregateSignature(R=0, z=0, signer_ids=(1,))
        chain = AuditChain(((b"m", SigningAudit(b"r")),), sig)
        wire = encode_audit_chain(chain)
        # Each zero integer: length 1 then body 00.
        self.assertIn(b"\x00\x00\x00\x01\x00", wire)
        decoded = decode_audit_chain(wire)
        self.assertEqual(decoded.signature.R, 0)
        self.assertEqual(decoded.signature.z, 0)

    def test_receipt_leading_zero_is_opaque_content(self):
        # A receipt starting with 0x00 is raw content, not a non-canonical int.
        chain = AuditChain(
            ((b"m", SigningAudit(b"\x00\x00receipt")),),
            AggregateSignature(R=2, z=3, signer_ids=(1,)),
        )
        decoded = decode_audit_chain(encode_audit_chain(chain))
        self.assertEqual(decoded, chain)

    def test_deterministic_unique_output(self):
        chain = synthetic_chain()
        wire = encode_audit_chain(chain)
        self.assertEqual(wire, encode_audit_chain(chain))
        reordered = AuditChain(
            (chain.records[1], chain.records[0]), chain.signature
        )
        self.assertNotEqual(wire, encode_audit_chain(reordered))

    def test_roundtrip_synthetic(self):
        chain = synthetic_chain()
        decoded = decode_audit_chain(encode_audit_chain(chain))
        self.assertEqual(decoded, chain)
        self.assertEqual(encode_audit_chain(decoded), encode_audit_chain(chain))
        # Records keep their exact order, message bytes and receipt payloads.
        self.assertEqual(
            [message for message, _ in decoded.records],
            [b"", b"m1"],
        )
        self.assertEqual(
            [audit.payload for _, audit in decoded.records],
            [b"r0", b"\x00r1"],
        )

    # --- rejection: encode ----------------------------------------------

    def test_encode_rejects_bad_types(self):
        chain = synthetic_chain()
        self.assertRaises(TypeError, encode_audit_chain, "chain")
        self.assertRaises(
            TypeError, encode_audit_chain, AuditChain(chain.records, "sig")
        )
        self.assertRaises(
            TypeError, encode_audit_chain, AuditChain(list(chain.records), chain.signature)
        )
        self.assertRaises(
            TypeError,
            encode_audit_chain,
            AuditChain(((b"m", b"not-an-audit"),), chain.signature),
        )
        self.assertRaises(
            TypeError,
            encode_audit_chain,
            AuditChain(
                ((bytearray(b"m"), chain.records[0][1]),), chain.signature
            ),
        )
        self.assertRaises(
            TypeError,
            encode_audit_chain,
            AuditChain(
                ((b"m", SigningAudit(payload=1)),), chain.signature
            ),
        )
        self.assertRaises(
            TypeError,
            encode_audit_chain,
            AuditChain(
                chain.records,
                AggregateSignature(R="2", z=3, signer_ids=(1,)),
            ),
        )
        self.assertRaises(
            TypeError,
            encode_audit_chain,
            AuditChain(
                chain.records,
                AggregateSignature(R=True, z=3, signer_ids=(1,)),
            ),
        )
        self.assertRaises(
            TypeError,
            encode_audit_chain,
            AuditChain(
                chain.records,
                AggregateSignature(R=2, z=3, signer_ids=[1, 3]),
            ),
        )
        self.assertRaises(
            TypeError,
            encode_audit_chain,
            AuditChain(
                chain.records,
                AggregateSignature(R=2, z=3, signer_ids=(1, "3")),
            ),
        )
        self.assertRaises(
            TypeError,
            encode_audit_chain,
            AuditChain(
                chain.records,
                AggregateSignature(R=2, z=3, signer_ids=(1, True)),
            ),
        )

    def test_encode_rejects_empty_chain_and_empty_receipt(self):
        sig = AggregateSignature(R=2, z=3, signer_ids=(1,))
        self.assertRaises(ValueError, encode_audit_chain, AuditChain((), sig))
        self.assertRaises(
            ValueError,
            encode_audit_chain,
            AuditChain(((b"m", SigningAudit(b"")),), sig),
        )

    def test_encode_rejects_negative_signature_integers(self):
        self.assertRaises(
            ValueError,
            encode_audit_chain,
            AuditChain(
                synthetic_chain().records,
                AggregateSignature(R=-1, z=3, signer_ids=(1,)),
            ),
        )
        self.assertRaises(
            ValueError,
            encode_audit_chain,
            AuditChain(
                synthetic_chain().records,
                AggregateSignature(R=2, z=-3, signer_ids=(1,)),
            ),
        )

    def test_encode_rejects_bad_signer_ids(self):
        records = synthetic_chain().records
        for bad_ids in ((), (0,), (3, 1), (1, 1), (-1,)):
            with self.assertRaises(ValueError, msg=f"ids={bad_ids}"):
                encode_audit_chain(
                    AuditChain(
                        records, AggregateSignature(R=2, z=3, signer_ids=bad_ids)
                    )
                )

    def test_count_overflow_raises_value_error(self):
        class HugeTuple(tuple):
            def __len__(self):
                return 2 ** 32

        sig = AggregateSignature(R=2, z=3, signer_ids=(1,))
        chain = AuditChain(HugeTuple(((b"m", SigningAudit(b"r")),)), sig)
        with self.assertRaises(ValueError):
            encode_audit_chain(chain)


class DecodeAuditChainTest(unittest.TestCase):
    def test_roundtrip_sealed_chain_still_verifies(self):
        key = make_key()
        records = tuple(
            make_record(key, f"message-{i}".encode(), seed=100 + 10 * i)
            for i in range(3)
        )
        chain = seal_chain(key, records, seed=900)
        decoded = decode_audit_chain(encode_audit_chain(chain))
        self.assertEqual(decoded, chain)
        self.assertTrue(verify_audit_chain(decoded, key))

    def test_roundtrip_status_zero_receipt(self):
        key = make_key()
        failing = make_record(key, b"failing", seed=150, bad_share=True)
        chain = seal_chain(key, (failing,), seed=940)
        decoded = decode_audit_chain(encode_audit_chain(chain))
        self.assertEqual(decoded, chain)
        self.assertTrue(verify_audit_chain(decoded, key))

    def test_decode_does_not_verify(self):
        # A bad signature decodes normally; verification reports False.
        chain = synthetic_chain()
        bad = AuditChain(
            chain.records,
            dataclasses.replace(chain.signature, z=999),
        )
        decoded = decode_audit_chain(encode_audit_chain(bad))
        self.assertEqual(decoded, bad)

    def test_decode_does_not_check_receipts(self):
        # Opaque, structurally arbitrary receipt bytes are restored verbatim.
        key = make_key()
        records = tuple(
            make_record(key, f"message-{i}".encode(), seed=100 + 10 * i)
            for i in range(3)
        )
        chain = seal_chain(key, records, seed=900)
        broken = SigningAudit(b"not-an-audit-payload")
        tampered = AuditChain(
            ((records[0][0], broken),) + records[1:], chain.signature
        )
        decoded = decode_audit_chain(encode_audit_chain(tampered))
        self.assertEqual(decoded, tampered)
        # Decoding restored it untouched; verification is what rejects it.
        with self.assertRaises(ValueError):
            verify_audit_chain(decoded, key)

    # --- rejection: decode ----------------------------------------------

    def test_decode_rejects_bad_types(self):
        wire = encode_audit_chain(synthetic_chain())
        for bad in ("wire", bytearray(wire), None, 42):
            self.assertRaises(TypeError, decode_audit_chain, bad)

    def test_decode_rejects_bad_tag(self):
        wire = encode_audit_chain(synthetic_chain())
        self.assertRaises(ValueError, decode_audit_chain, b"x" + wire[1:])
        self.assertRaises(ValueError, decode_audit_chain, WIRE_TAG)
        self.assertRaises(ValueError, decode_audit_chain, b"")

    def test_decode_rejects_zero_count(self):
        self.assertRaises(
            ValueError,
            decode_audit_chain,
            WIRE_TAG + (0).to_bytes(4, "big"),
        )

    def test_decode_rejects_zero_length_receipt(self):
        # One record: a valid empty message frame then a zero-length receipt.
        wire = (
            WIRE_TAG
            + (1).to_bytes(4, "big")
            + (0).to_bytes(4, "big")  # empty message
            + (0).to_bytes(4, "big")  # empty receipt
        )
        self.assertRaises(ValueError, decode_audit_chain, wire)

    def test_decode_rejects_truncation_at_every_cut(self):
        wire = encode_audit_chain(synthetic_chain())
        for cut in range(len(wire)):
            with self.assertRaises(ValueError, msg=f"cut {cut}"):
                decode_audit_chain(wire[:cut])

    def test_decode_rejects_trailing_bytes(self):
        wire = encode_audit_chain(synthetic_chain())
        self.assertRaises(ValueError, decode_audit_chain, wire + b"\x00")
        self.assertRaises(ValueError, decode_audit_chain, wire + b"extra")

    def test_decode_rejects_count_mismatch(self):
        chain = synthetic_chain()
        wire = bytearray(encode_audit_chain(chain))
        count_offset = len(WIRE_TAG)
        # Declare three records but only two follow -> truncated.
        wire[count_offset:count_offset + 4] = (3).to_bytes(4, "big")
        self.assertRaises(ValueError, decode_audit_chain, bytes(wire))
        # Declare one record but the second becomes trailing content.
        wire[count_offset:count_offset + 4] = (1).to_bytes(4, "big")
        self.assertRaises(ValueError, decode_audit_chain, bytes(wire))

    def test_decode_rejects_huge_frame_length(self):
        wire = (
            WIRE_TAG
            + (1).to_bytes(4, "big")
            + (0xFFFFFFFF).to_bytes(4, "big")
            + b"message"
        )
        self.assertRaises(ValueError, decode_audit_chain, wire)

    def test_decode_rejects_non_canonical_signature_integer(self):
        wire = bytearray(encode_audit_chain(synthetic_chain()))
        # The first signature integer R=2 sits at the end of the records;
        # rewrite its frame from (len 1, 02) to (len 2, 00 02).
        needle = (1).to_bytes(4, "big") + b"\x02"
        position = bytes(wire).rfind(needle)
        self.assertNotEqual(position, -1)
        wire[position:position + 5] = (2).to_bytes(4, "big") + b"\x00\x02"
        self.assertRaises(ValueError, decode_audit_chain, bytes(wire))

    def test_decode_rejects_empty_signer_set(self):
        chain = synthetic_chain()
        wire = bytearray(build_wire(chain))
        # The signer-id count is the last four bytes (two varint ids follow R,z).
        # Rebuild directly: tag, count, records, R, z, id-count=0.
        body = bytearray(WIRE_TAG)
        body += len(chain.records).to_bytes(4, "big")
        for message, audit in chain.records:
            body += frame(message)
            body += frame(audit.payload)
        body += varint(chain.signature.R)
        body += varint(chain.signature.z)
        body += (0).to_bytes(4, "big")
        self.assertRaises(ValueError, decode_audit_chain, bytes(body))

    def test_decode_rejects_non_increasing_signer_ids(self):
        chain = synthetic_chain()
        body = bytearray(WIRE_TAG)
        body += len(chain.records).to_bytes(4, "big")
        for message, audit in chain.records:
            body += frame(message)
            body += frame(audit.payload)
        body += varint(chain.signature.R)
        body += varint(chain.signature.z)
        body += (2).to_bytes(4, "big")
        body += varint(3)
        body += varint(1)
        self.assertRaises(ValueError, decode_audit_chain, bytes(body))


if __name__ == "__main__":
    unittest.main()
