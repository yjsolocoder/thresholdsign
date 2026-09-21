"""Tests for the canonical AuditMultiProof transport encoding:
encode_audit_multi_proof / decode_audit_multi_proof."""

import dataclasses
import unittest

from thresholdsign import (
    AuditMultiProof,
    SigningAudit,
    check_multi_proof,
    decode_audit_multi_proof,
    encode_audit_multi_proof,
    make_multi_proof,
)

from test_audit_chain import make_key, make_record, sign_message

WIRE_TAG = b"thresholdsign/audit-multi-proof/v1"


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big", signed=False)


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def build_wire(proof: AuditMultiProof) -> bytes:
    """Independently build the multi-proof wire format straight from the spec."""
    out = bytearray(WIRE_TAG)
    out += varint(proof.n)
    out += u32(len(proof.indices))
    for index in proof.indices:
        out += varint(index)
    out += u32(len(proof.records))
    for message, audit in proof.records:
        out += frame(message)
        out += frame(audit.payload)
    out += u32(len(proof.siblings))
    for sibling in proof.siblings:
        out += sibling
    return bytes(out)


def seal_multi(key, records, indices, *, seed=900):
    message, proof = make_multi_proof(records, indices)
    signature = sign_message(key, message, seed=seed + sum(indices))
    return proof, signature


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = tuple(
            make_record(self.key, f"message-{i}".encode(), seed=100 + 10 * i)
            for i in range(9)
        )

    def _records_of_size(self, n):
        return tuple(self.records[:n])

    def test_round_trip_for_every_size_and_subset(self):
        for n in range(1, 10):
            records = self._records_of_size(n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                _message, proof = make_multi_proof(records, indices)
                wire = encode_audit_multi_proof(proof)
                decoded = decode_audit_multi_proof(wire)
                self.assertEqual(decoded, proof, msg=f"n={n} indices={indices}")
                # Re-encoding the decoded proof is byte-for-byte the input.
                self.assertEqual(encode_audit_multi_proof(decoded), wire)

    def test_encoding_matches_independent_builder(self):
        for n in range(1, 10):
            records = self._records_of_size(n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                _message, proof = make_multi_proof(records, indices)
                self.assertEqual(
                    encode_audit_multi_proof(proof),
                    build_wire(proof),
                    msg=f"n={n} indices={indices}",
                )

    def test_starts_with_tag_and_counter_heads(self):
        _message, proof = make_multi_proof(self.records, (2, 4))
        wire = encode_audit_multi_proof(proof)
        self.assertTrue(wire.startswith(WIRE_TAG))
        offset = len(WIRE_TAG)
        # VARINT(n = 9) -> 00 00 00 01 09
        self.assertEqual(wire[offset:offset + 5], b"\x00\x00\x00\x01\x09")
        offset += 5
        # U32 index count = 2
        self.assertEqual(wire[offset:offset + 4], u32(2))
        offset += 4
        # VARINT(index 2) -> 00 00 00 01 02
        self.assertEqual(wire[offset:offset + 5], b"\x00\x00\x00\x01\x02")
        offset += 5
        # VARINT(index 4) -> 00 00 00 01 04
        self.assertEqual(wire[offset:offset + 5], b"\x00\x00\x00\x01\x04")

    def test_zero_index_encodes_as_single_body_byte(self):
        _message, proof = make_multi_proof(self.records, (0,))
        wire = encode_audit_multi_proof(proof)
        offset = len(WIRE_TAG) + len(varint(proof.n)) + 4
        self.assertEqual(wire[offset:offset + 5], b"\x00\x00\x00\x01\x00")

    def test_empty_message_is_allowed(self):
        records = ((b"", self.records[0][1]),) + self.records[1:]
        _message, proof = make_multi_proof(records, (0, 2))
        wire = encode_audit_multi_proof(proof)
        decoded = decode_audit_multi_proof(wire)
        self.assertEqual(decoded, proof)
        self.assertEqual(decoded.records[0][0], b"")

    def test_proving_every_record_round_trips_with_zero_siblings(self):
        _message, proof = make_multi_proof(self.records, tuple(range(9)))
        self.assertEqual(proof.siblings, ())
        decoded = decode_audit_multi_proof(encode_audit_multi_proof(proof))
        self.assertEqual(decoded, proof)

    def test_decoded_proof_still_checks(self):
        for n in range(1, 10):
            records = self._records_of_size(n)
            message, _any = make_multi_proof(records, (0,))
            signature = sign_message(self.key, message, seed=1000 + n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                _msg, proof = make_multi_proof(records, indices)
                decoded = decode_audit_multi_proof(encode_audit_multi_proof(proof))
                self.assertTrue(
                    check_multi_proof(decoded, signature, self.key),
                    msg=f"n={n} indices={indices}",
                )

    def test_encoding_is_unique_and_stateless(self):
        _message, proof = make_multi_proof(self.records, (0, 2, 4))
        self.assertEqual(
            encode_audit_multi_proof(proof), encode_audit_multi_proof(proof)
        )


class StructureOnlyTest(unittest.TestCase):
    def test_decode_does_not_parse_receipts_or_verify(self):
        # An opaque, structurally framed but cryptographically meaningless
        # receipt decodes fine; check_multi_proof rejects it later.
        receipt = b"not-an-audit-receipt"
        proof = AuditMultiProof(
            indices=(0,),
            n=1,
            records=((b"m", SigningAudit(receipt)),),
            siblings=(),
        )
        decoded = decode_audit_multi_proof(encode_audit_multi_proof(proof))
        self.assertEqual(decoded, proof)
        self.assertEqual(decoded.records[0][1].payload, receipt)

    def test_encoding_does_not_check_a_signature(self):
        # No signature is part of the proof at all; the codec needs none.
        _message, proof = make_multi_proof(
            (make_record(make_key(), b"m", seed=1),), (0,)
        )
        self.assertTrue(encode_audit_multi_proof(proof))


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = tuple(
            make_record(self.key, f"message-{i}".encode(), seed=100 + 10 * i)
            for i in range(5)
        )
        _msg, self.proof = make_multi_proof(self.records, (0, 2, 4))

    def test_non_proof_type_error(self):
        with self.assertRaises(TypeError):
            encode_audit_multi_proof(("not", "a", "proof"))

    def test_field_type_errors(self):
        proof = self.proof
        for bad in (
            dataclasses.replace(proof, indices=[0, 2, 4]),
            dataclasses.replace(proof, indices=(True, 2, 4)),
            dataclasses.replace(proof, indices=("0", 2, 4)),
            dataclasses.replace(proof, n=True),
            dataclasses.replace(proof, n="5"),
            dataclasses.replace(proof, records=list(proof.records)),
            dataclasses.replace(
                proof, records=((b"m", b"not-an-audit"),) * 3
            ),
            dataclasses.replace(
                proof,
                records=tuple((bytearray(b"m"), audit) for _m, audit in proof.records),
            ),
            dataclasses.replace(proof, siblings=[b"s" * 32]),
            dataclasses.replace(proof, siblings=(b"s" * 32, 33)),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_audit_multi_proof(bad)

    def test_value_errors(self):
        proof = self.proof
        (msg0, audit0) = proof.records[0]
        for bad in (
            dataclasses.replace(proof, n=0),
            dataclasses.replace(proof, n=-1),
            dataclasses.replace(proof, n=2 ** 64),
            AuditMultiProof((), 5, (), proof.siblings),
            AuditMultiProof((0, 0), 5, ((msg0, audit0),) * 2, ()),
            AuditMultiProof((5,), 5, ((msg0, audit0),), ()),
            AuditMultiProof((0, 2, 4), 5, proof.records[:2], ()),
            AuditMultiProof((0,), 5, ((b"m", SigningAudit(b"")),), ()),
            dataclasses.replace(proof, siblings=(b"s" * 31,) * len(proof.siblings)),
            dataclasses.replace(proof, siblings=(b"s" * 33,) * len(proof.siblings)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                encode_audit_multi_proof(bad)


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = tuple(
            make_record(self.key, f"message-{i}".encode(), seed=100 + 10 * i)
            for i in range(5)
        )
        _msg, self.proof = make_multi_proof(self.records, (0, 2, 4))
        self.wire = encode_audit_multi_proof(self.proof)

    def test_non_bytes_type_error(self):
        with self.assertRaises(TypeError):
            decode_audit_multi_proof("not bytes")
        with self.assertRaises(TypeError):
            decode_audit_multi_proof(bytearray(self.wire))

    def test_bad_tag(self):
        bad = b"thresholdsign/audit-multi-proof/v2" + self.wire[len(WIRE_TAG):]
        with self.assertRaises(ValueError):
            decode_audit_multi_proof(bad)
        with self.assertRaises(ValueError):
            decode_audit_multi_proof(b"x" + self.wire[1:])

    def test_truncation(self):
        for cut in range(len(WIRE_TAG), len(self.wire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_audit_multi_proof(self.wire[:cut])

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_audit_multi_proof(self.wire + b"\x00")

    def test_empty_indices_rejected(self):
        out = WIRE_TAG + varint(1) + u32(0)
        with self.assertRaises(ValueError):
            decode_audit_multi_proof(out)

    def test_empty_receipt_rejected(self):
        out = bytearray(WIRE_TAG)
        out += varint(1) + u32(1) + varint(0)
        out += u32(1)
        out += frame(b"m") + frame(b"")
        with self.assertRaises(ValueError):
            decode_audit_multi_proof(bytes(out))

    def test_non_canonical_varint_leading_zero(self):
        # n = 5 encoded with a forbidden leading-zero body (00 05).
        out = bytearray(WIRE_TAG)
        out += (2).to_bytes(4, "big") + b"\x00\x05"
        out += self.wire[len(WIRE_TAG) + len(varint(5)):]
        with self.assertRaises(ValueError):
            decode_audit_multi_proof(bytes(out))

    def test_non_canonical_zero_two_bytes(self):
        out = bytearray(WIRE_TAG)
        out += (2).to_bytes(4, "big") + b"\x00\x00"
        out += self.wire[len(WIRE_TAG) + len(varint(5)):]
        with self.assertRaises(ValueError):
            decode_audit_multi_proof(bytes(out))

    def test_over_long_varint_length_truncated(self):
        head = WIRE_TAG + (0xFFFFFFFF).to_bytes(4, "big")
        with self.assertRaises(ValueError):
            decode_audit_multi_proof(head)

    def test_n_zero_rejected(self):
        out = WIRE_TAG + varint(0) + u32(1) + varint(0)
        with self.assertRaises(ValueError):
            decode_audit_multi_proof(out)

    def test_n_too_large(self):
        message, audit = self.proof.records[0]
        out = bytearray(WIRE_TAG)
        out += varint(2 ** 64)
        out += u32(1) + varint(0)
        out += u32(1)
        out += frame(message) + frame(audit.payload)
        out += u32(0)
        with self.assertRaises(ValueError):
            decode_audit_multi_proof(bytes(out))

    def test_index_out_of_range(self):
        # Single-index proof for (0,): rewrite the index VARINT from 0 to 5
        # so that i == n.
        out = bytearray()
        _msg, single = make_multi_proof(self.records, (0,))
        good = encode_audit_multi_proof(single)
        marker = len(WIRE_TAG) + len(varint(single.n)) + 4
        out += good[:marker] + varint(5) + good[marker + len(varint(0)):]
        with self.assertRaises(ValueError):
            decode_audit_multi_proof(bytes(out))

    def test_indices_not_strictly_increasing(self):
        out = WIRE_TAG + varint(5) + u32(2) + varint(2) + varint(1)
        with self.assertRaises(ValueError):
            decode_audit_multi_proof(out)

    def test_record_count_mismatch(self):
        out = WIRE_TAG + varint(5) + u32(1) + varint(0) + u32(2)
        with self.assertRaises(ValueError):
            decode_audit_multi_proof(out)

    def test_sibling_wrong_width(self):
        # Declare one sibling but supply only 31 bytes.
        out = bytearray()
        out += self.wire[:-len(self.proof.siblings) * 32 - 4]
        out += u32(1) + b"s" * 31
        with self.assertRaises(ValueError):
            decode_audit_multi_proof(bytes(out))


if __name__ == "__main__":
    unittest.main()
