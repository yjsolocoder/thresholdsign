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


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


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

    def test_starts_with_tag_and_varint_n(self):
        _message, proof = make_multi_proof(self.records, (2, 4))
        wire = encode_audit_multi_proof(proof)
        self.assertTrue(wire.startswith(WIRE_TAG))
        offset = len(WIRE_TAG)
        # n = 9 -> VARINT is 00 00 00 01 09
        self.assertEqual(wire[offset:offset + 5], b"\x00\x00\x00\x01\x09")
        # index count = 2 -> 00 00 00 02
        self.assertEqual(wire[offset + 5:offset + 9], u32(2))

    def test_zero_index_encodes_as_single_body_byte(self):
        _message, proof = make_multi_proof(self.records, (0,))
        wire = encode_audit_multi_proof(proof)
        offset = len(WIRE_TAG) + len(varint(proof.n)) + 4
        # index 0 -> VARINT 00 00 00 01 00
        self.assertEqual(wire[offset:offset + 5], b"\x00\x00\x00\x01\x00")

    def test_empty_message_is_allowed(self):
        records = ((b"", self.records[0][1]),) + self.records[1:]
        _message, proof = make_multi_proof(records, (0, 2))
        wire = encode_audit_multi_proof(proof)
        decoded = decode_audit_multi_proof(wire)
        self.assertEqual(decoded, proof)
        self.assertEqual(decoded.records[0][0], b"")

    def test_decoded_proof_still_checks(self):
        for n in range(1, 10):
            records = self._records_of_size(n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                proof, signature = seal_multi(self.key, records, indices)
                decoded = decode_audit_multi_proof(encode_audit_multi_proof(proof))
                self.assertTrue(
                    check_multi_proof(decoded, signature, self.key),
                    msg=f"n={n} indices={indices}",
                )

    def test_encoding_is_unique_and_stateless(self):
        _message, proof = make_multi_proof(self.records, (1, 3, 5))
        self.assertEqual(
            encode_audit_multi_proof(proof), encode_audit_multi_proof(proof)
        )


class StructureOnlyTest(unittest.TestCase):
    def test_decode_does_not_parse_receipts_or_verify(self):
        receipt = b"not-an-audit-receipt"
        # n=3 with indices (0, 2) determines exactly one sibling digest.
        proof = AuditMultiProof(
            indices=(0, 2),
            n=3,
            records=((b"m", SigningAudit(receipt)), (b"m2", SigningAudit(b"x"))),
            siblings=(b"s" * 32,),
        )
        decoded = decode_audit_multi_proof(encode_audit_multi_proof(proof))
        self.assertEqual(decoded.records[0][1].payload, receipt)

    def test_encoding_does_not_check_a_signature(self):
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
        _msg, self.proof = make_multi_proof(self.records, (1, 2))

    def test_non_proof_type_error(self):
        with self.assertRaises(TypeError):
            encode_audit_multi_proof(("not", "a", "proof"))

    def test_field_type_errors(self):
        proof = self.proof
        for bad in (
            dataclasses.replace(proof, n=True),
            dataclasses.replace(proof, n="5"),
            dataclasses.replace(proof, indices=[1, 2]),
            dataclasses.replace(proof, indices=(True, 2)),
            dataclasses.replace(proof, indices=("1", 2)),
            dataclasses.replace(proof, records=[proof.records[0]] * 2),
            dataclasses.replace(
                proof, records=((b"m", b"not-an-audit"),) * 2
            ),
            dataclasses.replace(
                proof,
                records=((bytearray(b"m"), proof.records[0][1]),) * 2,
            ),
            dataclasses.replace(proof, siblings=[b"s" * 32]),
            dataclasses.replace(proof, siblings=(b"s" * 32, 33)),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_audit_multi_proof(bad)

    def test_value_errors(self):
        proof = self.proof
        (msg0, audit0), (_msg1, _audit1) = proof.records
        thirty_two = b"s" * 32
        for bad in (
            AuditMultiProof((1, 2), 0, proof.records, ()),
            AuditMultiProof((1, 2), -1, proof.records, ()),
            AuditMultiProof((1, 2), 2 ** 64, proof.records, ()),
            AuditMultiProof((), 5, (), ()),
            AuditMultiProof((-1, 2), 5, proof.records, ()),
            AuditMultiProof((1, 5), 5, proof.records, ()),
            AuditMultiProof((2, 1), 5, proof.records, ()),
            AuditMultiProof((1, 1), 5, ((msg0, audit0),), ()),
            AuditMultiProof((1,), 5, (), ()),
            AuditMultiProof((1, 2, 3), 5, proof.records, ()),
            AuditMultiProof(
                (1, 2), 5, ((msg0, SigningAudit(b"")),) + proof.records[1:], ()
            ),
            dataclasses.replace(proof, siblings=(thirty_two[:-1],)),
            dataclasses.replace(proof, siblings=(thirty_two + b"x",)),
            # n and the indices determine a unique sibling count: both a
            # missing and an extra 32-byte digest are rejected.
            dataclasses.replace(proof, siblings=proof.siblings[:-1]),
            dataclasses.replace(proof, siblings=proof.siblings + (thirty_two,)),
            dataclasses.replace(proof, siblings=()),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                encode_audit_multi_proof(bad)

    def test_sibling_count_matches_make_multi_proof_for_every_subset(self):
        thirty_two = b"s" * 32
        for n in range(1, 10):
            records = tuple(
                make_record(self.key, f"sized-{i}".encode(), seed=300 + i)
                for i in range(n)
            )
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                _msg, proof = make_multi_proof(records, indices)
                # The encoder accepts exactly the count make_multi_proof emits.
                encode_audit_multi_proof(proof)
                if proof.siblings:
                    with self.assertRaises(
                        ValueError, msg=f"n={n} indices={indices}"
                    ):
                        encode_audit_multi_proof(
                            dataclasses.replace(
                                proof, siblings=proof.siblings[:-1]
                            )
                        )
                with self.assertRaises(ValueError, msg=f"n={n} indices={indices}"):
                    encode_audit_multi_proof(
                        dataclasses.replace(
                            proof, siblings=proof.siblings + (thirty_two,)
                        )
                    )


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = tuple(
            make_record(self.key, f"message-{i}".encode(), seed=100 + 10 * i)
            for i in range(5)
        )
        _msg, self.proof = make_multi_proof(self.records, (1, 2))
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
        out = bytearray(WIRE_TAG)
        out += varint(self.proof.n)
        out += u32(0)  # no indices
        with self.assertRaises(ValueError):
            decode_audit_multi_proof(bytes(out))

    def test_empty_receipt_rejected(self):
        out = bytearray(WIRE_TAG)
        out += varint(1)
        out += u32(1) + varint(0)
        out += u32(1)
        out += frame(b"m") + frame(b"")
        out += u32(0)
        with self.assertRaises(ValueError):
            decode_audit_multi_proof(bytes(out))

    def test_record_count_mismatch(self):
        out = bytearray(WIRE_TAG)
        out += varint(self.proof.n)
        out += u32(len(self.proof.indices))
        for index in self.proof.indices:
            out += varint(index)
        out += u32(1)  # records claim one, indices are two
        message, audit = self.proof.records[0]
        out += frame(message) + frame(audit.payload)
        with self.assertRaises(ValueError):
            decode_audit_multi_proof(bytes(out))

    def test_non_canonical_varint_leading_zero(self):
        out = bytearray(WIRE_TAG)
        out += varint(self.proof.n)
        out += u32(len(self.proof.indices))
        out += (2).to_bytes(4, "big") + b"\x00\x01"  # index 1 with leading zero
        for index in self.proof.indices[1:]:
            out += varint(index)
        out += u32(len(self.proof.records))
        for message, audit in self.proof.records:
            out += frame(message) + frame(audit.payload)
        out += u32(len(self.proof.siblings))
        for sibling in self.proof.siblings:
            out += sibling
        with self.assertRaises(ValueError):
            decode_audit_multi_proof(bytes(out))

    def test_non_canonical_n_leading_zero(self):
        out = bytearray(WIRE_TAG)
        out += (1).to_bytes(4, "big") + b"\x00\x05"  # n = 5 with leading zero
        out += u32(len(self.proof.indices))
        for index in self.proof.indices:
            out += varint(index)
        out += u32(len(self.proof.records))
        for message, audit in self.proof.records:
            out += frame(message) + frame(audit.payload)
        out += u32(len(self.proof.siblings))
        for sibling in self.proof.siblings:
            out += sibling
        with self.assertRaises(ValueError):
            decode_audit_multi_proof(bytes(out))

    def test_n_too_large(self):
        out = bytearray(WIRE_TAG)
        out += varint(2 ** 64)
        out += u32(1) + varint(0)
        out += u32(1)
        message, audit = self.proof.records[0]
        out += frame(message) + frame(audit.payload)
        out += u32(0)
        with self.assertRaises(ValueError):
            decode_audit_multi_proof(bytes(out))

    def test_index_out_of_range(self):
        out = bytearray(WIRE_TAG)
        out += varint(self.proof.n)
        out += u32(2)
        out += varint(1) + varint(5)  # second index == n
        out += u32(2)
        for message, audit in self.proof.records:
            out += frame(message) + frame(audit.payload)
        out += u32(0)
        with self.assertRaises(ValueError):
            decode_audit_multi_proof(bytes(out))

    def test_indices_not_strictly_increasing(self):
        out = bytearray(WIRE_TAG)
        out += varint(self.proof.n)
        out += u32(2)
        out += varint(2) + varint(1)
        out += u32(2)
        for message, audit in self.proof.records:
            out += frame(message) + frame(audit.payload)
        out += u32(0)
        with self.assertRaises(ValueError):
            decode_audit_multi_proof(bytes(out))

    def test_sibling_wrong_width(self):
        out = bytearray(WIRE_TAG)
        out += varint(self.proof.n)
        out += u32(len(self.proof.indices))
        for index in self.proof.indices:
            out += varint(index)
        out += u32(len(self.proof.records))
        for message, audit in self.proof.records:
            out += frame(message) + frame(audit.payload)
        out += u32(1)
        out += b"s" * 31
        with self.assertRaises(ValueError):
            decode_audit_multi_proof(bytes(out))

    def test_sibling_count_mismatch(self):
        # n=5 with indices (1, 2) determines exactly three sibling digests;
        # both fewer and more well-formed 32-byte entries are rejected.
        for count in (0, 2, 4):
            out = bytearray(WIRE_TAG)
            out += varint(self.proof.n)
            out += u32(len(self.proof.indices))
            for index in self.proof.indices:
                out += varint(index)
            out += u32(len(self.proof.records))
            for message, audit in self.proof.records:
                out += frame(message) + frame(audit.payload)
            out += u32(count)
            out += b"s" * 32 * count
            with self.assertRaises(ValueError, msg=f"count={count}"):
                decode_audit_multi_proof(bytes(out))


if __name__ == "__main__":
    unittest.main()
