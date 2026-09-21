"""Tests for the canonical AuditExtensionProof transport encoding:
encode_extension / decode_extension."""

import dataclasses
import unittest

from thresholdsign import (
    AuditExtensionProof,
    check_extension,
    decode_extension,
    encode_extension,
    make_extension,
)

from test_audit_chain import make_key, make_record
from test_audit_extension import seal_extension

WIRE_TAG = b"thresholdsign/audit-extension/v1"


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big", signed=False)


def build_wire(proof: AuditExtensionProof) -> bytes:
    """Independently build the extension wire format straight from the spec."""
    out = bytearray(WIRE_TAG)
    out += u64(proof.old_n)
    out += u64(len(proof.leaves))
    for leaf in proof.leaves:
        out += leaf
    return bytes(out)


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = tuple(
            make_record(self.key, f"message-{i}".encode(), seed=100 + 10 * i)
            for i in range(8)
        )

    def test_round_trip_for_every_split_and_size(self):
        for n in range(2, 9):
            records = self.records[:n]
            for old_n in range(1, n):
                _old, _new, proof = make_extension(records, old_n)
                wire = encode_extension(proof)
                decoded = decode_extension(wire)
                self.assertEqual(decoded, proof, msg=f"n={n} old_n={old_n}")
                # Re-encoding the decoded proof is byte-for-byte the input.
                self.assertEqual(encode_extension(decoded), wire)

    def test_encoding_matches_independent_builder(self):
        for n in range(2, 9):
            records = self.records[:n]
            for old_n in range(1, n):
                _old, _new, proof = make_extension(records, old_n)
                self.assertEqual(
                    encode_extension(proof), build_wire(proof),
                    msg=f"n={n} old_n={old_n}",
                )

    def test_starts_with_tag_and_fixed_width_header(self):
        _old, _new, proof = make_extension(self.records[:5], 2)
        wire = encode_extension(proof)
        self.assertTrue(wire.startswith(WIRE_TAG))
        offset = len(WIRE_TAG)
        self.assertEqual(wire[offset:offset + 8], u64(2))
        self.assertEqual(wire[offset + 8:offset + 16], u64(5))
        # No separators: the leaves follow the header immediately.
        self.assertEqual(wire[offset + 16:], b"".join(proof.leaves))
        self.assertEqual(len(wire), len(WIRE_TAG) + 16 + 5 * 32)

    def test_decoded_proof_still_checks(self):
        seed = 700
        for n in range(2, 9):
            records = self.records[:n]
            for old_n in range(1, n):
                proof, old_sig, new_sig = seal_extension(
                    self.key, records, old_n, seed=seed
                )
                seed += 10
                decoded = decode_extension(encode_extension(proof))
                self.assertTrue(
                    check_extension(decoded, old_sig, new_sig, self.key),
                    msg=f"n={n} old_n={old_n}",
                )

    def test_encoding_is_unique_and_stateless(self):
        _old, _new, proof = make_extension(self.records[:4], 2)
        self.assertEqual(encode_extension(proof), encode_extension(proof))


class StructureOnlyTest(unittest.TestCase):
    def test_decode_does_not_parse_leaves_or_verify(self):
        # Opaque, structurally framed but cryptographically meaningless
        # leaves decode fine; check_extension is left to reject them later.
        leaves = (b"x" * 32, b"y" * 32, b"z" * 32)
        proof = AuditExtensionProof(1, leaves)
        decoded = decode_extension(encode_extension(proof))
        self.assertEqual(decoded.leaves, leaves)

    def test_encoding_does_not_check_a_signature(self):
        # No signature is part of the proof at all; the codec needs none.
        proof = AuditExtensionProof(1, (b"a" * 32, b"b" * 32))
        self.assertTrue(encode_extension(proof))


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = tuple(
            make_record(self.key, f"message-{i}".encode(), seed=100 + 10 * i)
            for i in range(5)
        )
        _old, _new, self.proof = make_extension(self.records, 3)

    def test_non_proof_type_error(self):
        with self.assertRaises(TypeError):
            encode_extension(("not", "a", "proof"))

    def test_field_type_errors(self):
        proof = self.proof
        for bad in (
            dataclasses.replace(proof, old_n=True),
            dataclasses.replace(proof, old_n="3"),
            dataclasses.replace(proof, leaves=list(proof.leaves)),
            dataclasses.replace(proof, leaves=(b"a" * 32, 33)),
            dataclasses.replace(proof, leaves=(bytearray(b"a" * 32),) * 5),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_extension(bad)

    def test_value_errors(self):
        proof = self.proof
        for bad in (
            dataclasses.replace(proof, old_n=0),
            dataclasses.replace(proof, old_n=-1),
            dataclasses.replace(proof, old_n=5),
            dataclasses.replace(proof, old_n=6),
            dataclasses.replace(proof, leaves=()),
            dataclasses.replace(proof, leaves=(b"a" * 31,) * 5),
            dataclasses.replace(proof, leaves=(b"a" * 33,) * 5),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                encode_extension(bad)


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = tuple(
            make_record(self.key, f"message-{i}".encode(), seed=100 + 10 * i)
            for i in range(5)
        )
        _old, _new, self.proof = make_extension(self.records, 3)
        self.wire = encode_extension(self.proof)

    def test_non_bytes_type_error(self):
        with self.assertRaises(TypeError):
            decode_extension("not bytes")
        with self.assertRaises(TypeError):
            decode_extension(bytearray(self.wire))

    def test_bad_tag(self):
        bad = b"thresholdsign/audit-extension/v2" + self.wire[len(WIRE_TAG):]
        with self.assertRaises(ValueError):
            decode_extension(bad)
        with self.assertRaises(ValueError):
            decode_extension(b"x" + self.wire[1:])

    def test_truncation(self):
        for cut in range(len(WIRE_TAG), len(self.wire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_extension(self.wire[:cut])

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_extension(self.wire + b"\x00")

    def test_empty_leaf_sequence_rejected(self):
        out = bytearray(WIRE_TAG)
        out += u64(0) + u64(0)
        with self.assertRaises(ValueError):
            decode_extension(bytes(out))

    def test_old_n_out_of_range(self):
        for old_n in (0, 5, 6, 2 ** 64 - 1):
            out = bytearray(WIRE_TAG)
            out += u64(old_n) + u64(5)
            for leaf in self.proof.leaves:
                out += leaf
            with self.assertRaises(ValueError, msg=f"old_n={old_n}"):
                decode_extension(bytes(out))

    def test_leaf_count_mismatch(self):
        # Declare one fewer leaf than the payload carries.
        out = bytearray(WIRE_TAG)
        out += u64(3) + u64(4)
        for leaf in self.proof.leaves:
            out += leaf
        with self.assertRaises(ValueError):
            decode_extension(bytes(out))
        # Declare one more leaf than the payload carries.
        out = bytearray(WIRE_TAG)
        out += u64(3) + u64(6)
        for leaf in self.proof.leaves:
            out += leaf
        with self.assertRaises(ValueError):
            decode_extension(bytes(out))

    def test_oversized_count_rejected(self):
        # n = 2**64 cannot match any real payload and is out of range.
        out = bytearray(WIRE_TAG)
        out += u64(1) + (2 ** 64 - 1).to_bytes(8, "big")
        with self.assertRaises(ValueError):
            decode_extension(bytes(out))

    def test_leaf_entries_are_raw_32_bytes(self):
        # A 31-byte tail leaf leaves the stream misaligned with n = 5.
        out = bytearray(WIRE_TAG)
        out += u64(3) + u64(5)
        for leaf in self.proof.leaves[:4]:
            out += leaf
        out += b"a" * 31
        with self.assertRaises(ValueError):
            decode_extension(bytes(out))


if __name__ == "__main__":
    unittest.main()
