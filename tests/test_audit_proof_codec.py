"""Tests for the canonical AuditProof transport encoding:
encode_audit_proof / decode_audit_proof."""

import dataclasses
import unittest

from thresholdsign import (
    AuditProof,
    SigningAudit,
    check_proof,
    decode_audit_proof,
    encode_audit_proof,
    make_proof,
)

from test_audit_chain import make_key, make_record

WIRE_TAG = b"thresholdsign/audit-proof/v1"


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def build_wire(proof: AuditProof) -> bytes:
    """Independently build the audit-proof wire format straight from the spec."""
    out = bytearray(WIRE_TAG)
    out += varint(proof.i)
    out += varint(proof.n)
    out += frame(proof.m)
    out += frame(proof.a.payload)
    out += len(proof.p).to_bytes(4, "big")
    for sibling in proof.p:
        out += sibling
    return bytes(out)


def seal_proof(key, records, index, *, seed=700):
    message, proof = make_proof(records, index)
    from test_audit_chain import sign_message
    signature = sign_message(key, message, seed=seed + index)
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

    def test_round_trip_for_every_leaf_and_size(self):
        for n in range(1, 10):
            records = self._records_of_size(n)
            for index in range(n):
                _message, proof = make_proof(records, index)
                wire = encode_audit_proof(proof)
                decoded = decode_audit_proof(wire)
                self.assertEqual(decoded, proof, msg=f"n={n} i={index}")
                # Re-encoding the decoded proof is byte-for-byte the input.
                self.assertEqual(encode_audit_proof(decoded), wire)

    def test_encoding_matches_independent_builder(self):
        for n in range(1, 10):
            records = self._records_of_size(n)
            for index in range(n):
                _message, proof = make_proof(records, index)
                self.assertEqual(
                    encode_audit_proof(proof), build_wire(proof),
                    msg=f"n={n} i={index}",
                )

    def test_starts_with_tag_and_varint_heads(self):
        _message, proof = make_proof(self.records, 2)
        wire = encode_audit_proof(proof)
        self.assertTrue(wire.startswith(WIRE_TAG))
        offset = len(WIRE_TAG)
        # i = 2 -> VARINT is 00 00 00 01 02
        self.assertEqual(wire[offset:offset + 5], b"\x00\x00\x00\x01\x02")
        # n = 9 -> VARINT is 00 00 00 01 09
        self.assertEqual(wire[offset + 5:offset + 10], b"\x00\x00\x00\x01\x09")

    def test_zero_i_encodes_as_single_body_byte(self):
        _message, proof = make_proof(self.records, 0)
        wire = encode_audit_proof(proof)
        offset = len(WIRE_TAG)
        self.assertEqual(wire[offset:offset + 5], b"\x00\x00\x00\x01\x00")

    def test_empty_message_is_allowed(self):
        records = ((b"", self.records[0][1]),) + self.records[1:]
        _message, proof = make_proof(records, 0)
        self.assertEqual(proof.m, b"")
        wire = encode_audit_proof(proof)
        decoded = decode_audit_proof(wire)
        self.assertEqual(decoded, proof)
        self.assertEqual(decoded.m, b"")

    def test_decoded_proof_still_checks(self):
        for n in range(1, 10):
            records = self._records_of_size(n)
            for index in range(n):
                proof, signature = seal_proof(self.key, records, index)
                decoded = decode_audit_proof(encode_audit_proof(proof))
                self.assertTrue(
                    check_proof(decoded, signature, self.key),
                    msg=f"n={n} i={index}",
                )

    def test_encoding_is_unique_and_stateless(self):
        _message, proof = make_proof(self.records, 2)
        self.assertEqual(encode_audit_proof(proof), encode_audit_proof(proof))


class StructureOnlyTest(unittest.TestCase):
    def test_decode_does_not_parse_receipt_or_verify(self):
        # An opaque, structurally framed but cryptographically meaningless
        # receipt decodes fine; check_proof is left to reject it later.
        receipt = b"not-an-audit-receipt"
        path = (b"s" * 32,)
        proof = AuditProof(0, 2, b"m", SigningAudit(receipt), path)
        decoded = decode_audit_proof(encode_audit_proof(proof))
        self.assertEqual(decoded.a.payload, receipt)

    def test_encoding_does_not_check_a_signature(self):
        # No signature is part of the proof at all; the codec needs none.
        _message, proof = make_proof(
            (make_record(make_key(), b"m", seed=1),), 0
        )
        self.assertTrue(encode_audit_proof(proof))


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = tuple(
            make_record(self.key, f"message-{i}".encode(), seed=100 + 10 * i)
            for i in range(5)
        )
        _msg, self.proof = make_proof(self.records, 2)

    def test_non_proof_type_error(self):
        with self.assertRaises(TypeError):
            encode_audit_proof(("not", "a", "proof"))

    def test_field_type_errors(self):
        proof = self.proof
        for bad in (
            dataclasses.replace(proof, i=True),
            dataclasses.replace(proof, i="2"),
            dataclasses.replace(proof, n=True),
            dataclasses.replace(proof, m=bytearray(b"m")),
            dataclasses.replace(proof, a=b"receipt"),
            dataclasses.replace(proof, p=[b"s" * 32, b"t" * 32]),
            dataclasses.replace(proof, p=(b"s" * 32, 33)),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_audit_proof(bad)

    def test_value_errors(self):
        proof = self.proof
        thirty_two = b"s" * 32
        for bad in (
            dataclasses.replace(proof, n=0),
            dataclasses.replace(proof, n=-1),
            dataclasses.replace(proof, n=2 ** 64),
            dataclasses.replace(proof, i=-1),
            dataclasses.replace(proof, i=5),
            dataclasses.replace(proof, a=SigningAudit(b"")),
            dataclasses.replace(proof, p=()),
            dataclasses.replace(proof, p=(thirty_two,)),
            dataclasses.replace(proof, p=(thirty_two,) * 2),
            dataclasses.replace(proof, p=(b"s" * 31,) * 3),
            dataclasses.replace(proof, p=(b"s" * 33,) * 3),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                encode_audit_proof(bad)


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = tuple(
            make_record(self.key, f"message-{i}".encode(), seed=100 + 10 * i)
            for i in range(5)
        )
        _msg, self.proof = make_proof(self.records, 2)
        self.wire = encode_audit_proof(self.proof)

    def test_non_bytes_type_error(self):
        with self.assertRaises(TypeError):
            decode_audit_proof("not bytes")
        with self.assertRaises(TypeError):
            decode_audit_proof(bytearray(self.wire))

    def test_bad_tag(self):
        bad = b"thresholdsign/audit-proof/v2" + self.wire[len(WIRE_TAG):]
        with self.assertRaises(ValueError):
            decode_audit_proof(bad)
        with self.assertRaises(ValueError):
            decode_audit_proof(b"x" + self.wire[1:])

    def test_truncation(self):
        for cut in range(len(WIRE_TAG), len(self.wire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_audit_proof(self.wire[:cut])

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_audit_proof(self.wire + b"\x00")

    def test_empty_receipt_rejected(self):
        proof = AuditProof(0, 1, b"m", SigningAudit(b""), ())
        # Build a wire frame with a zero receipt length by hand.
        out = bytearray(WIRE_TAG)
        out += varint(0) + varint(1)
        out += frame(b"m") + frame(b"")
        out += (0).to_bytes(4, "big")
        with self.assertRaises(ValueError):
            decode_audit_proof(bytes(out))

    def test_non_canonical_varint_leading_zero(self):
        # i = 2 encoded with a forbidden leading zero body (00 02).
        out = bytearray(WIRE_TAG)
        out += (2).to_bytes(4, "big") + b"\x00\x02"
        out += varint(self.proof.n)
        out += frame(self.proof.m) + frame(self.proof.a.payload)
        out += len(self.proof.p).to_bytes(4, "big")
        for sibling in self.proof.p:
            out += sibling
        with self.assertRaises(ValueError):
            decode_audit_proof(bytes(out))

    def test_non_canonical_zero_two_bytes(self):
        out = bytearray(WIRE_TAG)
        out += (2).to_bytes(4, "big") + b"\x00\x00"
        out += varint(self.proof.n)
        out += frame(self.proof.m) + frame(self.proof.a.payload)
        out += len(self.proof.p).to_bytes(4, "big")
        for sibling in self.proof.p:
            out += sibling
        with self.assertRaises(ValueError):
            decode_audit_proof(bytes(out))

    def test_over_long_varint_length_truncated(self):
        # Declare a 1-byte body then run out of bytes.
        head = WIRE_TAG + (1).to_bytes(4, "big")
        with self.assertRaises(ValueError):
            decode_audit_proof(head)

    def test_i_out_of_range(self):
        out = bytearray(WIRE_TAG)
        out += varint(5) + varint(5)  # i == n
        out += frame(self.proof.m) + frame(self.proof.a.payload)
        out += len(self.proof.p).to_bytes(4, "big")
        for sibling in self.proof.p:
            out += sibling
        with self.assertRaises(ValueError):
            decode_audit_proof(bytes(out))

    def test_n_too_large(self):
        out = bytearray(WIRE_TAG)
        out += varint(0) + varint(2 ** 64)
        out += frame(self.proof.m) + frame(self.proof.a.payload)
        out += len(self.proof.p).to_bytes(4, "big")
        for sibling in self.proof.p:
            out += sibling
        with self.assertRaises(ValueError):
            decode_audit_proof(bytes(out))

    def test_path_count_mismatch(self):
        # Declare one fewer path entry than n = 5 requires (needs 3).
        out = bytearray(WIRE_TAG)
        out += varint(self.proof.i) + varint(self.proof.n)
        out += frame(self.proof.m) + frame(self.proof.a.payload)
        out += (2).to_bytes(4, "big")
        for sibling in self.proof.p[:2]:
            out += sibling
        with self.assertRaises(ValueError):
            decode_audit_proof(bytes(out))

    def test_path_entries_are_raw_32_bytes(self):
        # A path item shorter than 32 bytes leaves the stream misaligned.
        out = bytearray(WIRE_TAG)
        out += varint(self.proof.i) + varint(self.proof.n)
        out += frame(self.proof.m) + frame(self.proof.a.payload)
        out += (3).to_bytes(4, "big")
        out += b"s" * 31
        out += b"t" * 32
        out += b"u" * 32
        with self.assertRaises(ValueError):
            decode_audit_proof(bytes(out))


class OddTailSiblingTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        # 3 leaves: the last (index 2) is the odd tail at the leaf level and
        # rebuilds via H(node, node), so the recorded sibling there is unused.
        self.records = tuple(
            make_record(self.key, f"message-{i}".encode(), seed=100 + 10 * i)
            for i in range(3)
        )

    def test_honest_odd_tail_verifies(self):
        proof, signature = seal_proof(self.key, self.records, 2)
        self.assertTrue(check_proof(proof, signature, self.key))

    def test_tampered_odd_tail_sibling_is_ignored(self):
        proof, signature = seal_proof(self.key, self.records, 2)
        flipped = bytearray(proof.p[0])
        flipped[0] ^= 1
        bad = dataclasses.replace(proof, p=(bytes(flipped),) + proof.p[1:])
        self.assertTrue(check_proof(bad, signature, self.key))

    def test_even_leaf_sibling_still_matters(self):
        proof, signature = seal_proof(self.key, self.records, 0)
        flipped = bytearray(proof.p[0])
        flipped[0] ^= 1
        bad = dataclasses.replace(proof, p=(bytes(flipped),) + proof.p[1:])
        self.assertFalse(check_proof(bad, signature, self.key))


if __name__ == "__main__":
    unittest.main()
