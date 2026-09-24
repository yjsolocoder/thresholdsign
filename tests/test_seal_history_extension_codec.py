"""Tests for the canonical SealHistoryExtension transport encoding:
encode_history_extension / decode_history_extension."""

import dataclasses
import unittest

from thresholdsign import (
    SealHistoryExtension,
    check_history_extension,
    decode_history_extension,
    encode_history_extension,
    make_history_extension,
)

from test_seal_history_extension import (
    history_of_size,
    seal_extension,
)
from test_nonce_reuse import make_key

WIRE_TAG = b"thresholdsign/seal-history-extension/v1"


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big", signed=False)


def build_wire(proof: SealHistoryExtension) -> bytes:
    """Independently build the extension wire format straight from the spec."""
    out = bytearray(WIRE_TAG)
    out += u64(proof.old_total)
    out += u64(len(proof.leaves))
    for leaf in proof.leaves:
        out += leaf
    return bytes(out)


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = history_of_size(self.key, 6)

    def test_round_trip_for_every_split_and_size(self):
        for n in range(2, 9):
            history = history_of_size(self.key, n)
            for old_total in range(1, n):
                _old, _new, proof = make_history_extension(history, old_total)
                wire = encode_history_extension(proof)
                decoded = decode_history_extension(wire)
                self.assertEqual(
                    decoded, proof, msg=f"n={n} old_total={old_total}"
                )
                # Re-encoding the decoded proof is byte-for-byte the input.
                self.assertEqual(encode_history_extension(decoded), wire)

    def test_encoding_matches_independent_builder(self):
        for n in range(2, 9):
            history = history_of_size(self.key, n)
            for old_total in range(1, n):
                _old, _new, proof = make_history_extension(history, old_total)
                self.assertEqual(
                    encode_history_extension(proof),
                    build_wire(proof),
                    msg=f"n={n} old_total={old_total}",
                )

    def test_starts_with_tag_and_fixed_width_header(self):
        _old, _new, proof = make_history_extension(self.history, 2)
        n = len(proof.leaves)
        wire = encode_history_extension(proof)
        self.assertTrue(wire.startswith(WIRE_TAG))
        offset = len(WIRE_TAG)
        self.assertEqual(wire[offset:offset + 8], u64(2))
        self.assertEqual(wire[offset + 8:offset + 16], u64(n))
        # No separators or padding: the leaves follow the header immediately.
        self.assertEqual(wire[offset + 16:], b"".join(proof.leaves))
        self.assertEqual(len(wire), len(WIRE_TAG) + 16 + n * 32)

    def test_decoded_proof_still_checks(self):
        seed = 700
        for n in range(2, 9):
            history = history_of_size(self.key, n)
            for old_total in range(1, n):
                proof, old_sig, new_sig = seal_extension(
                    self.key, history, old_total, seed=seed
                )
                seed += 10
                decoded = decode_history_extension(encode_history_extension(proof))
                self.assertTrue(
                    check_history_extension(
                        decoded, old_sig, new_sig, self.key
                    ),
                    msg=f"n={n} old_total={old_total}",
                )

    def test_encoding_is_unique_and_stateless(self):
        _old, _new, proof = make_history_extension(self.history, 2)
        self.assertEqual(
            encode_history_extension(proof),
            encode_history_extension(proof),
        )

    def test_encoding_carries_only_tag_counts_and_leaves(self):
        _old, _new, proof = make_history_extension(self.history, 2)
        wire = encode_history_extension(proof)
        self.assertEqual(
            wire,
            WIRE_TAG
            + u64(proof.old_total)
            + u64(len(proof.leaves))
            + b"".join(proof.leaves),
        )


class StructureOnlyTest(unittest.TestCase):
    def test_decode_does_not_parse_leaves_or_verify(self):
        # Opaque, structurally framed but cryptographically meaningless
        # leaves decode fine; check_history_extension is left to reject later.
        leaves = (b"x" * 32, b"y" * 32, b"z" * 32)
        proof = SealHistoryExtension(1, leaves)
        decoded = decode_history_extension(encode_history_extension(proof))
        self.assertEqual(decoded.leaves, leaves)

    def test_decoded_proof_is_frozen_container_only(self):
        proof = SealHistoryExtension(1, (b"a" * 32, b"b" * 32))
        decoded = decode_history_extension(encode_history_extension(proof))
        self.assertEqual(decoded, proof)
        self.assertIsInstance(decoded, SealHistoryExtension)


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = history_of_size(self.key, 6)
        _old, _new, self.proof = make_history_extension(self.history, 3)

    def test_non_proof_type_error(self):
        for bad in (("not", "a", "proof"), object(), None, 42):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_history_extension(bad)

    def test_field_type_errors(self):
        proof = self.proof
        for bad in (
            dataclasses.replace(proof, old_total=True),
            dataclasses.replace(proof, old_total=False),
            dataclasses.replace(proof, old_total="3"),
            dataclasses.replace(proof, old_total=3.0),
            dataclasses.replace(proof, leaves=list(proof.leaves)),
            dataclasses.replace(proof, leaves=(b"a" * 32, 33)),
            dataclasses.replace(proof, leaves=(bytearray(b"a" * 32),) * 6),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_history_extension(bad)

    def test_value_errors(self):
        proof = self.proof
        for bad in (
            dataclasses.replace(proof, old_total=0),
            dataclasses.replace(proof, old_total=-1),
            dataclasses.replace(proof, old_total=6),
            dataclasses.replace(proof, old_total=7),
            dataclasses.replace(proof, leaves=()),
            dataclasses.replace(proof, leaves=(b"a" * 31,) * 6),
            dataclasses.replace(proof, leaves=(b"a" * 33,) * 6),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                encode_history_extension(bad)


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = history_of_size(self.key, 6)
        _old, _new, self.proof = make_history_extension(self.history, 3)
        self.wire = encode_history_extension(self.proof)

    def test_non_bytes_type_error(self):
        with self.assertRaises(TypeError):
            decode_history_extension("not bytes")
        with self.assertRaises(TypeError):
            decode_history_extension(bytearray(self.wire))
        with self.assertRaises(TypeError):
            decode_history_extension(memoryview(self.wire))

    def test_bad_tag(self):
        bad = (
            b"thresholdsign/seal-history-extension/v2"
            + self.wire[len(WIRE_TAG):]
        )
        with self.assertRaises(ValueError):
            decode_history_extension(bad)
        with self.assertRaises(ValueError):
            decode_history_extension(b"x" + self.wire[1:])
        with self.assertRaises(ValueError):
            decode_history_extension(self.wire[len(WIRE_TAG):])

    def test_truncation(self):
        for cut in range(len(WIRE_TAG), len(self.wire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_history_extension(self.wire[:cut])

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_history_extension(self.wire + b"\x00")
        with self.assertRaises(ValueError):
            decode_history_extension(self.wire + b"a" * 32)

    def test_empty_leaf_sequence_rejected(self):
        out = bytearray(WIRE_TAG)
        out += u64(0) + u64(0)
        with self.assertRaises(ValueError):
            decode_history_extension(bytes(out))

    def test_old_total_out_of_range(self):
        for old_total in (0, 5, 6, 2 ** 64 - 1):
            out = bytearray(WIRE_TAG)
            out += u64(old_total) + u64(5)
            for leaf in self.proof.leaves[:5]:
                out += leaf
            with self.assertRaises(ValueError, msg=f"old_total={old_total}"):
                decode_history_extension(bytes(out))

    def test_leaf_count_mismatch(self):
        # Declare one fewer leaf than the payload carries.
        out = bytearray(WIRE_TAG)
        out += u64(3) + u64(5)
        for leaf in self.proof.leaves:
            out += leaf
        with self.assertRaises(ValueError):
            decode_history_extension(bytes(out))
        # Declare one more leaf than the payload carries.
        out = bytearray(WIRE_TAG)
        out += u64(3) + u64(7)
        for leaf in self.proof.leaves:
            out += leaf
        with self.assertRaises(ValueError):
            decode_history_extension(bytes(out))

    def test_oversized_count_rejected(self):
        # n = 2**64 - 1 cannot match any real payload and is out of range;
        # a header claiming it with no leaf bytes must fail.
        out = bytearray(WIRE_TAG)
        out += u64(1) + (2 ** 64 - 1).to_bytes(8, "big")
        with self.assertRaises(ValueError):
            decode_history_extension(bytes(out))

    def test_leaf_entries_are_raw_32_bytes(self):
        # A 31-byte tail leaf leaves the stream misaligned with n = 6.
        out = bytearray(WIRE_TAG)
        out += u64(3) + u64(6)
        for leaf in self.proof.leaves[:5]:
            out += leaf
        out += b"a" * 31
        with self.assertRaises(ValueError):
            decode_history_extension(bytes(out))


if __name__ == "__main__":
    unittest.main()
