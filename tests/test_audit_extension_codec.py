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


def seal_extension(key, records, old_n, *, seed=700):
    from test_audit_chain import sign_message

    old_message, new_message, proof = make_extension(records, old_n)
    old_sig = sign_message(key, old_message, seed=seed)
    new_sig = sign_message(key, new_message, seed=seed + 1)
    return proof, old_sig, new_sig


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = tuple(
            make_record(self.key, f"message-{i}".encode(), seed=100 + 10 * i)
            for i in range(9)
        )

    def test_round_trip_for_every_size_and_split(self):
        for n in range(2, 10):
            records = tuple(self.records[:n])
            for old_n in range(1, n):
                _old_message, _new_message, proof = make_extension(
                    records, old_n
                )
                wire = encode_extension(proof)
                decoded = decode_extension(wire)
                self.assertEqual(decoded, proof, msg=f"n={n} old_n={old_n}")
                # Re-encoding the decoded proof is byte-for-byte the input.
                self.assertEqual(encode_extension(decoded), wire)

    def test_encoding_matches_independent_builder(self):
        for n in range(2, 10):
            records = tuple(self.records[:n])
            for old_n in range(1, n):
                _old_message, _new_message, proof = make_extension(
                    records, old_n
                )
                self.assertEqual(
                    encode_extension(proof),
                    build_wire(proof),
                    msg=f"n={n} old_n={old_n}",
                )

    def test_starts_with_tag_and_u64_counters(self):
        _old_message, _new_message, proof = make_extension(self.records, 3)
        wire = encode_extension(proof)
        self.assertTrue(wire.startswith(WIRE_TAG))
        offset = len(WIRE_TAG)
        self.assertEqual(wire[offset:offset + 8], u64(3))
        self.assertEqual(wire[offset + 8:offset + 16], u64(9))
        # The first leaf follows immediately, with no extra delimiter.
        self.assertEqual(
            wire[offset + 16:offset + 48], proof.leaves[0]
        )

    def test_total_length_is_tag_counters_and_32_bytes_per_leaf(self):
        _old_message, _new_message, proof = make_extension(self.records, 3)
        wire = encode_extension(proof)
        self.assertEqual(
            len(wire), len(WIRE_TAG) + 8 + 8 + 32 * len(proof.leaves)
        )

    def test_large_counters_use_full_8_bytes(self):
        # old_n=255, n=256: both counters need their high bytes.
        leaves = tuple(bytes((index % 256,)) * 32 for index in range(256))
        proof = AuditExtensionProof(255, leaves)
        wire = encode_extension(proof)
        offset = len(WIRE_TAG)
        self.assertEqual(wire[offset:offset + 8], u64(255))
        self.assertEqual(wire[offset + 8:offset + 16], u64(256))
        self.assertEqual(decode_extension(wire), proof)

    def test_decoded_proof_still_checks(self):
        for n in range(2, 8):
            records = tuple(self.records[:n])
            proof, old_sig, new_sig = seal_extension(
                self.key, records, n - 1
            )
            decoded = decode_extension(encode_extension(proof))
            self.assertTrue(
                check_extension(decoded, old_sig, new_sig, self.key),
                msg=f"n={n}",
            )

    def test_encoding_is_unique_and_stateless(self):
        _old_message, _new_message, proof = make_extension(self.records, 3)
        self.assertEqual(encode_extension(proof), encode_extension(proof))


class StructureOnlyTest(unittest.TestCase):
    def test_decode_does_not_parse_leaves_or_verify(self):
        # Opaque, cryptographically meaningless 32-byte digests decode fine;
        # check_extension is left to reject them against signatures later.
        leaves = tuple(bytes((index,)) * 32 for index in range(1, 4))
        proof = AuditExtensionProof(1, leaves)
        decoded = decode_extension(encode_extension(proof))
        self.assertEqual(decoded, proof)

    def test_encoding_does_not_require_a_signature(self):
        # No signature is part of the proof at all; the codec needs none.
        _old_message, _new_message, proof = make_extension(
            tuple(
                make_record(make_key(), f"m{i}".encode(), seed=i + 1)
                for i in range(2)
            ),
            1,
        )
        self.assertTrue(encode_extension(proof))


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = tuple(
            make_record(self.key, f"message-{i}".encode(), seed=100 + 10 * i)
            for i in range(5)
        )
        _old_message, _new_message, self.proof = make_extension(
            self.records, 2
        )

    def test_non_proof_type_error(self):
        with self.assertRaises(TypeError):
            encode_extension(("not", "a", "proof"))

    def test_field_type_errors(self):
        proof = self.proof
        for bad in (
            dataclasses.replace(proof, old_n=True),
            dataclasses.replace(proof, old_n="2"),
            dataclasses.replace(proof, leaves=[b"s" * 32, b"t" * 32]),
            dataclasses.replace(proof, leaves=(b"s" * 32, 33)),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_extension(bad)

    def test_value_errors(self):
        proof = self.proof
        thirty_two = b"s" * 32
        for bad in (
            AuditExtensionProof(0, (thirty_two, thirty_two)),
            AuditExtensionProof(-1, (thirty_two, thirty_two)),
            AuditExtensionProof(2, (thirty_two, thirty_two)),
            AuditExtensionProof(5, proof.leaves),
            AuditExtensionProof(2 ** 64 - 1, (thirty_two, thirty_two)),
            AuditExtensionProof(1, ()),
            AuditExtensionProof(1, (thirty_two,)),
            AuditExtensionProof(1, (b"s" * 31, thirty_two)),
            AuditExtensionProof(1, (b"s" * 33, thirty_two)),
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
        _old_message, _new_message, self.proof = make_extension(
            self.records, 2
        )
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

    def test_too_short_for_counters(self):
        with self.assertRaises(ValueError):
            decode_extension(WIRE_TAG + u64(1))

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_extension(self.wire + b"\x00")

    def test_zero_old_n_rejected(self):
        out = bytearray(WIRE_TAG)
        out += u64(0) + u64(5)
        out += b"".join(self.proof.leaves)
        with self.assertRaises(ValueError):
            decode_extension(bytes(out))

    def test_zero_n_rejected(self):
        out = bytearray(WIRE_TAG)
        out += u64(0) + u64(0)
        with self.assertRaises(ValueError):
            decode_extension(bytes(out))

    def test_old_n_equals_n_rejected(self):
        out = bytearray(WIRE_TAG)
        out += u64(5) + u64(5)
        out += b"".join(self.proof.leaves)
        with self.assertRaises(ValueError):
            decode_extension(bytes(out))

    def test_old_n_above_n_rejected(self):
        out = bytearray(WIRE_TAG)
        out += u64(6) + u64(5)
        out += b"".join(self.proof.leaves)
        with self.assertRaises(ValueError):
            decode_extension(bytes(out))

    def test_declared_count_does_not_match_body(self):
        # Declare one more leaf than the body actually carries.
        out = bytearray(WIRE_TAG)
        out += u64(2) + u64(6)
        out += b"".join(self.proof.leaves)
        with self.assertRaises(ValueError):
            decode_extension(bytes(out))

    def test_declared_count_zero_with_leaf_body(self):
        # Counters illegal regardless of trailing body.
        out = bytearray(WIRE_TAG)
        out += u64(1) + u64(0)
        out += b"s" * 32
        with self.assertRaises(ValueError):
            decode_extension(bytes(out))

    def test_one_byte_short_of_a_leaf(self):
        with self.assertRaises(ValueError):
            decode_extension(self.wire[:-1])


if __name__ == "__main__":
    unittest.main()
