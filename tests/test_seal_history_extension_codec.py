"""Tests for the canonical SealHistoryExtension transport encoding:
encode_history_extension / decode_history_extension."""

import dataclasses
import unittest

from thresholdsign import (
    SealHistory,
    SealHistoryExtension,
    check_history_extension,
    decode_history_extension,
    encode_history_extension,
    make_history_extension,
)

from test_nonce_reuse import make_key
from test_seal_history import make_history
from test_seal_history_extension import history_of_size, seal_extension

WIRE_TAG = b"thresholdsign/seal-history-extension/v1"


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big", signed=False)


def build_wire(proof: SealHistoryExtension) -> bytes:
    """Independently build the extension wire format from the spec."""
    out = bytearray(WIRE_TAG)
    out += u64(proof.old_total)
    out += u64(len(proof.leaves))
    for leaf in proof.leaves:
        out += leaf
    return bytes(out)


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()

    def test_round_trip_for_every_split_and_size(self):
        for n in range(2, 10):
            history = history_of_size(self.key, n)
            for old_total in range(1, n):
                _old_message, _new_message, proof = make_history_extension(
                    history, old_total
                )
                wire = encode_history_extension(proof)
                decoded = decode_history_extension(wire)
                self.assertEqual(decoded, proof, msg=f"n={n} old={old_total}")
                # Re-encoding the decoded proof is byte-for-byte the input.
                self.assertEqual(encode_history_extension(decoded), wire)
                self.assertEqual((decoded.old_total, decoded.leaves),
                                 (proof.old_total, proof.leaves))
                self.assertIsInstance(decoded.leaves, tuple)
                self.assertTrue(
                    all(isinstance(leaf, bytes) for leaf in decoded.leaves)
                )

    def test_encoding_matches_independent_builder(self):
        for n in range(2, 10):
            history = history_of_size(self.key, n)
            for old_total in range(1, n):
                _message, _new_message, proof = make_history_extension(
                    history, old_total
                )
                self.assertEqual(
                    encode_history_extension(proof),
                    build_wire(proof),
                    msg=f"n={n} old={old_total}",
                )

    def test_layout_is_tag_two_u64_then_raw_leaves(self):
        history = history_of_size(self.key, 6)
        _old_message, _new_message, proof = make_history_extension(history, 2)
        wire = encode_history_extension(proof)
        self.assertTrue(wire.startswith(WIRE_TAG))
        offset = len(WIRE_TAG)
        self.assertEqual(wire[offset:offset + 8], u64(2))
        self.assertEqual(wire[offset + 8:offset + 16], u64(6))
        body = wire[offset + 16:]
        self.assertEqual(b"".join(proof.leaves), body)
        # Total length is fixed by the tag and the leaf count alone.
        self.assertEqual(len(wire), len(WIRE_TAG) + 16 + 32 * 6)

    def test_single_leaf_prefix_boundary(self):
        history = history_of_size(self.key, 2)
        _old_message, _new_message, proof = make_history_extension(history, 1)
        wire = encode_history_extension(proof)
        decoded = decode_history_extension(wire)
        self.assertEqual(decoded, proof)
        self.assertEqual(len(wire), len(WIRE_TAG) + 16 + 64)

    def test_decoded_proof_still_checks(self):
        for n in range(2, 9):
            history = history_of_size(self.key, n)
            for old_total in range(1, n):
                proof, old_sig, new_sig = seal_extension(
                    self.key, history, old_total, seed=800 + 17 * n
                )
                decoded = decode_history_extension(
                    encode_history_extension(proof)
                )
                self.assertTrue(
                    check_history_extension(
                        decoded, old_sig, new_sig, self.key
                    ),
                    msg=f"n={n} old={old_total}",
                )

    def test_encoding_is_unique_and_stateless(self):
        history = history_of_size(self.key, 6)
        _old_message, _new_message, proof = make_history_extension(history, 2)
        self.assertEqual(
            encode_history_extension(proof),
            encode_history_extension(proof),
        )

    def test_arbitrary_thirty_two_byte_leaves_need_not_be_digests(self):
        # The codec handles container structure only: leaf bytes are never
        # interpreted as cryptographic digests.
        leaves = tuple(bytes((i,)) * 32 for i in range(1, 4))
        proof = SealHistoryExtension(2, leaves)
        decoded = decode_history_extension(encode_history_extension(proof))
        self.assertEqual(decoded, proof)


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = make_history(self.key, nonces=(401, 402, 403))
        _old_message, _new_message, self.proof = make_history_extension(
            self.history, 2
        )

    def test_non_proof_type_error(self):
        for bad in (("not", "a", "proof"), None, object(), 7):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_history_extension(bad)

    def test_field_type_errors(self):
        proof = self.proof
        for bad in (
            dataclasses.replace(proof, old_total=True),
            dataclasses.replace(proof, old_total=False),
            dataclasses.replace(proof, old_total="2"),
            dataclasses.replace(proof, old_total=2.0),
            dataclasses.replace(proof, old_total=None),
            dataclasses.replace(proof, leaves=list(proof.leaves)),
            dataclasses.replace(
                proof, leaves=(b"a" * 32, 33, b"c" * 32)
            ),
            dataclasses.replace(
                proof, leaves=(bytearray(b"a" * 32),) * 3
            ),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_history_extension(bad)

    def test_value_errors(self):
        proof = self.proof
        leaves = proof.leaves
        for bad in (
            SealHistoryExtension(0, ()),
            SealHistoryExtension(1, ()),
            SealHistoryExtension(0, leaves),
            SealHistoryExtension(-1, leaves),
            SealHistoryExtension(len(leaves), leaves),
            SealHistoryExtension(len(leaves) + 1, leaves),
            SealHistoryExtension(2, (b"a" * 31,) * 3),
            SealHistoryExtension(2, (b"a" * 33,) * 3),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                encode_history_extension(bad)

    def test_leaf_total_at_u64_max_rejected(self):
        class HugeTuple(tuple):
            def __len__(self):
                return 2 ** 64 - 1

        proof = SealHistoryExtension(1, HugeTuple((b"a" * 32,)))
        with self.assertRaises(ValueError):
            encode_history_extension(proof)


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = make_history(self.key, nonces=(401, 402, 403))
        _old_message, _new_message, self.proof = make_history_extension(
            self.history, 2
        )
        self.wire = encode_history_extension(self.proof)

    def _rebuild(
        self,
        *,
        old_total=None,
        leaf_count=None,
        leaves=None,
        tag=WIRE_TAG,
    ):
        old_total = self.proof.old_total if old_total is None else old_total
        leaves = self.proof.leaves if leaves is None else leaves
        leaf_count = len(leaves) if leaf_count is None else leaf_count
        out = bytearray(tag)
        out += u64(old_total)
        out += u64(leaf_count)
        for leaf in leaves:
            out += leaf
        return bytes(out)

    def test_non_bytes_type_error(self):
        for bad in ("not bytes", bytearray(self.wire), None, 7):
            with self.assertRaises(TypeError, msg=repr(bad)):
                decode_history_extension(bad)

    def test_bad_tag(self):
        with self.assertRaises(ValueError):
            decode_history_extension(
                self._rebuild(
                    tag=b"thresholdsign/seal-history-extension/v2"
                )
            )
        with self.assertRaises(ValueError):
            decode_history_extension(b"x" + self.wire[1:])
        with self.assertRaises(ValueError):
            decode_history_extension(self.wire[1:])

    def test_truncation(self):
        for cut in range(len(WIRE_TAG), len(self.wire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_history_extension(self.wire[:cut])

    def test_tag_only_and_partial_counts(self):
        for length in (
            0,
            1,
            7,
            8,
            15,
        ):
            with self.assertRaises(ValueError, msg=f"length={length}"):
                decode_history_extension(
                    WIRE_TAG + b"\x00" * length
                )

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_history_extension(self.wire + b"\x00")
        with self.assertRaises(ValueError):
            decode_history_extension(self.wire + b"ab")

    def test_zero_leaf_total(self):
        with self.assertRaises(ValueError):
            decode_history_extension(self._rebuild(leaves=(), leaf_count=0))

    def test_leaf_total_at_u64_max_rejected(self):
        out = WIRE_TAG + u64(1) + u64(2 ** 64 - 1)
        with self.assertRaises(ValueError):
            decode_history_extension(out)
        # Even with leaf bytes present the bound still rejects.
        with self.assertRaises(ValueError):
            decode_history_extension(out + b"a" * 32)

    def test_old_total_out_of_range(self):
        leaves = self.proof.leaves
        for bad in (0, len(leaves), len(leaves) + 1, 2 ** 64 - 1):
            with self.assertRaises(ValueError, msg=f"old_total={bad}"):
                decode_history_extension(self._rebuild(old_total=bad))

    def test_leaf_data_short_of_count(self):
        # Declare more leaves than the bytes carry.
        out = bytearray(WIRE_TAG)
        out += u64(1)
        out += u64(4)
        for leaf in self.proof.leaves:
            out += leaf
        with self.assertRaises(ValueError):
            decode_history_extension(bytes(out))

    def test_leaf_data_exceeds_count(self):
        # Declare fewer leaves than the bytes carry.
        out = bytearray(WIRE_TAG)
        out += u64(1)
        out += u64(2)
        for leaf in self.proof.leaves:
            out += leaf
        with self.assertRaises(ValueError):
            decode_history_extension(bytes(out))

    def test_partial_final_leaf_rejected(self):
        # One extra byte past a whole number of leaves is truncation of a
        # claimed extra leaf.
        out = bytearray(WIRE_TAG)
        out += u64(1)
        out += u64(4)
        for leaf in self.proof.leaves:
            out += leaf
        out += b"\x00"  # 31 bytes short of a fourth leaf
        with self.assertRaises(ValueError):
            decode_history_extension(bytes(out))



if __name__ == "__main__":
    unittest.main()
