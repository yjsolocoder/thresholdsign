"""Tests for the canonical SealHistoryProof transport encoding:
encode_history_proof / decode_history_proof."""

import dataclasses
import unittest

from thresholdsign import (
    AggregateSignature,
    NonceLeakReport,
    ReportSeal,
    SealHistory,
    SealHistoryProof,
    check_history_proof,
    decode_history_proof,
    encode_history_proof,
    encode_seal,
    make_history_proof,
)

from test_nonce_reuse import make_key
from test_report_seal import synthetic
from test_seal_history import make_history, sign_message

WIRE_TAG = b"thresholdsign/seal-history-proof/v1"


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def build_wire(proof: SealHistoryProof) -> bytes:
    """Independently build the history-proof wire format from the spec."""
    out = bytearray(WIRE_TAG)
    out += varint(proof.index)
    out += varint(proof.total)
    out += frame(encode_seal(proof.seal))
    out += len(proof.siblings).to_bytes(4, "big")
    for sibling in proof.siblings:
        out += sibling
    return bytes(out)


def signed_proof(history, index, key, *, seed=700):
    message, proof = make_history_proof(history, index)
    signature = sign_message(message, key, seed=seed + index)
    return proof, signature


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = make_history(
            self.key, nonces=tuple(100 + i for i in range(9))
        )

    def _history_of_size(self, n):
        return SealHistory(self.history.items[:n])

    def test_round_trip_for_every_leaf_and_size(self):
        for n in range(1, 10):
            history = self._history_of_size(n)
            for index in range(n):
                _message, proof = make_history_proof(history, index)
                wire = encode_history_proof(proof)
                decoded = decode_history_proof(wire)
                self.assertEqual(decoded, proof, msg=f"n={n} i={index}")
                # Re-encoding the decoded proof is byte-for-byte the input.
                self.assertEqual(encode_history_proof(decoded), wire)
                # Path entries come back as bytes inside a tuple.
                self.assertIsInstance(decoded.siblings, tuple)
                self.assertTrue(
                    all(isinstance(sibling, bytes) for sibling in decoded.siblings)
                )

    def test_encoding_matches_independent_builder(self):
        for n in range(1, 10):
            history = self._history_of_size(n)
            for index in range(n):
                _message, proof = make_history_proof(history, index)
                self.assertEqual(
                    encode_history_proof(proof),
                    build_wire(proof),
                    msg=f"n={n} i={index}",
                )

    def test_starts_with_tag_and_varint_heads(self):
        _message, proof = make_history_proof(self._history_of_size(9), 2)
        wire = encode_history_proof(proof)
        self.assertTrue(wire.startswith(WIRE_TAG))
        offset = len(WIRE_TAG)
        # index = 2 -> VARINT is 00 00 00 01 02
        self.assertEqual(wire[offset:offset + 5], b"\x00\x00\x00\x01\x02")
        # total = 9 -> VARINT is 00 00 00 01 09
        self.assertEqual(wire[offset + 5:offset + 10], b"\x00\x00\x00\x01\x09")

    def test_zero_index_encodes_as_single_body_byte(self):
        _message, proof = make_history_proof(self._history_of_size(9), 0)
        wire = encode_history_proof(proof)
        offset = len(WIRE_TAG)
        self.assertEqual(wire[offset:offset + 5], b"\x00\x00\x00\x01\x00")

    def test_single_item_history_uses_empty_path(self):
        _message, proof = make_history_proof(self._history_of_size(1), 0)
        self.assertEqual(proof.siblings, ())
        wire = encode_history_proof(proof)
        decoded = decode_history_proof(wire)
        self.assertEqual(decoded, proof)
        self.assertEqual(decoded.siblings, ())
        # After the seal frame the U32 path count is zero with nothing after.
        self.assertTrue(wire.endswith((0).to_bytes(4, "big")))

    def test_decoded_proof_still_checks(self):
        for n in range(1, 10):
            history = self._history_of_size(n)
            for index in range(n):
                proof, signature = signed_proof(
                    history, index, self.key, seed=900 + 17 * n
                )
                decoded = decode_history_proof(encode_history_proof(proof))
                self.assertTrue(
                    check_history_proof(decoded, signature, self.key),
                    msg=f"n={n} i={index}",
                )

    def test_encoding_is_unique_and_stateless(self):
        _message, proof = make_history_proof(self._history_of_size(9), 2)
        self.assertEqual(
            encode_history_proof(proof), encode_history_proof(proof)
        )


class StructureOnlyTest(unittest.TestCase):
    def test_decode_does_not_verify_seal_or_signature(self):
        # A structurally legal seal carrying a meaningless signature
        # encodes and decodes fine; check_history_proof rejects it later.
        seal = ReportSeal(
            NonceLeakReport((synthetic(1, 10),)),
            AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
        )
        proof = SealHistoryProof(1, 3, seal, (b"s" * 32, b"t" * 32))
        decoded = decode_history_proof(encode_history_proof(proof))
        self.assertEqual(decoded, proof)

    def test_encoding_checks_no_signature(self):
        key = make_key()
        history = make_history(key, nonces=(101, 102))
        _message, proof = make_history_proof(history, 0)
        self.assertTrue(encode_history_proof(proof))


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = make_history(self.key, nonces=(401, 402, 403))
        _message, self.proof = make_history_proof(self.history, 1)

    def test_non_proof_type_error(self):
        with self.assertRaises(TypeError):
            encode_history_proof(("not", "a", "proof"))
        with self.assertRaises(TypeError):
            encode_history_proof(None)

    def test_field_type_errors(self):
        proof = self.proof
        for bad in (
            dataclasses.replace(proof, index="1"),
            dataclasses.replace(proof, index=True),
            dataclasses.replace(proof, total="3"),
            dataclasses.replace(proof, total=False),
            dataclasses.replace(proof, seal="seal"),
            dataclasses.replace(proof, seal=proof.seal.signature),
            SealHistoryProof(1, 3, proof.seal, list(proof.siblings)),
            SealHistoryProof(
                1, 3, proof.seal, (b"s" * 32, 33)
            ),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_history_proof(bad)

    def test_value_errors(self):
        proof = self.proof
        seal = proof.seal
        thirty_two = b"s" * 32
        for bad in (
            SealHistoryProof(0, 0, seal, ()),
            SealHistoryProof(0, -1, seal, ()),
            SealHistoryProof(0, 2 ** 64, seal, ()),
            SealHistoryProof(-1, 3, seal, proof.siblings),
            SealHistoryProof(3, 3, seal, proof.siblings),
            SealHistoryProof(1, 3, seal, ()),
            SealHistoryProof(1, 3, seal, proof.siblings + (thirty_two,)),
            SealHistoryProof(1, 3, seal, (b"x" * 31,) + proof.siblings[1:]),
            SealHistoryProof(1, 3, seal, (b"x" * 33,) + proof.siblings[1:]),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                encode_history_proof(bad)

    def test_illegal_nested_seal_value_error(self):
        bad = ReportSeal(
            NonceLeakReport((synthetic(1, 10),)),
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
        )
        with self.assertRaises(ValueError):
            encode_history_proof(
                SealHistoryProof(
                    self.proof.index,
                    self.proof.total,
                    bad,
                    self.proof.siblings,
                )
            )


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = make_history(self.key, nonces=(401, 402, 403))
        _message, self.proof = make_history_proof(self.history, 1)
        self.wire = encode_history_proof(self.proof)

    def _rebuild(
        self,
        *,
        index=None,
        total=None,
        seal_bytes=None,
        siblings=None,
        tag=WIRE_TAG,
        path_count=None,
    ):
        index = self.proof.index if index is None else index
        total = self.proof.total if total is None else total
        seal_bytes = (
            encode_seal(self.proof.seal) if seal_bytes is None else seal_bytes
        )
        siblings = self.proof.siblings if siblings is None else siblings
        out = bytearray(tag)
        out += varint(index)
        out += varint(total)
        out += frame(seal_bytes)
        count = len(siblings) if path_count is None else path_count
        out += count.to_bytes(4, "big")
        for sibling in siblings:
            out += sibling
        return bytes(out)

    def test_non_bytes_type_error(self):
        with self.assertRaises(TypeError):
            decode_history_proof("not bytes")
        with self.assertRaises(TypeError):
            decode_history_proof(bytearray(self.wire))
        with self.assertRaises(TypeError):
            decode_history_proof(None)

    def test_bad_tag(self):
        with self.assertRaises(ValueError):
            decode_history_proof(self._rebuild(tag=b"thresholdsign/seal-history-proof/v2"))
        with self.assertRaises(ValueError):
            decode_history_proof(b"x" + self.wire[1:])

    def test_truncation(self):
        for cut in range(len(WIRE_TAG), len(self.wire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_history_proof(self.wire[:cut])

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_history_proof(self.wire + b"\x00")

    def test_empty_seal_frame_rejected(self):
        with self.assertRaises(ValueError):
            decode_history_proof(self._rebuild(seal_bytes=b""))

    def test_over_long_seal_frame(self):
        body = encode_seal(self.proof.seal)
        out = bytearray(WIRE_TAG)
        out += varint(self.proof.index)
        out += varint(self.proof.total)
        out += (len(body) + 5).to_bytes(4, "big")
        out += body
        out += len(self.proof.siblings).to_bytes(4, "big")
        for sibling in self.proof.siblings:
            out += sibling
        with self.assertRaises(ValueError):
            decode_history_proof(bytes(out))

    def test_illegal_nested_seal_rejected(self):
        bad = ReportSeal(
            NonceLeakReport((synthetic(1, 10),)),
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
        )
        with self.assertRaises(ValueError):
            decode_history_proof(self._rebuild(seal_bytes=encode_seal(bad)))

    def test_index_out_of_range(self):
        with self.assertRaises(ValueError):
            decode_history_proof(self._rebuild(index=3))
        with self.assertRaises(ValueError):
            decode_history_proof(self._rebuild(index=2 ** 64 - 1))

    def test_total_out_of_range(self):
        body = encode_seal(self.proof.seal)
        with self.assertRaises(ValueError):
            decode_history_proof(self._rebuild(index=0, total=0))
        # total = 2**64: structurally framed, rejected on the bound.
        out = bytearray(WIRE_TAG)
        out += varint(0)
        out += varint(2 ** 64)
        out += frame(body)
        out += (0).to_bytes(4, "big")
        with self.assertRaises(ValueError):
            decode_history_proof(bytes(out))

    def test_path_count_mismatch(self):
        # n = 3 needs 2 path entries.
        with self.assertRaises(ValueError):
            decode_history_proof(
                self._rebuild(
                    path_count=1, siblings=self.proof.siblings[:1]
                )
            )
        with self.assertRaises(ValueError):
            decode_history_proof(
                self._rebuild(
                    path_count=3,
                    siblings=self.proof.siblings + (b"z" * 32,),
                )
            )

    def test_path_entries_are_raw_32_bytes(self):
        with self.assertRaises(ValueError):
            decode_history_proof(
                self._rebuild(siblings=(b"x" * 31, b"y" * 32))
            )
        with self.assertRaises(ValueError):
            decode_history_proof(
                self._rebuild(siblings=(b"x" * 33, b"y" * 32))
            )

    def test_non_canonical_varint_leading_zero(self):
        body = encode_seal(self.proof.seal)
        out = bytearray(WIRE_TAG)
        # index = 1 with a forbidden leading-zero body (00 01).
        out += (2).to_bytes(4, "big") + b"\x00\x01"
        out += varint(self.proof.total)
        out += frame(body)
        out += len(self.proof.siblings).to_bytes(4, "big")
        for sibling in self.proof.siblings:
            out += sibling
        with self.assertRaises(ValueError):
            decode_history_proof(bytes(out))

    def test_non_canonical_zero_two_bytes(self):
        body = encode_seal(self.proof.seal)
        out = bytearray(WIRE_TAG)
        out += (2).to_bytes(4, "big") + b"\x00\x00"
        out += varint(self.proof.total)
        out += frame(body)
        out += len(self.proof.siblings).to_bytes(4, "big")
        for sibling in self.proof.siblings:
            out += sibling
        with self.assertRaises(ValueError):
            decode_history_proof(bytes(out))

    def test_zero_length_varint_body_rejected(self):
        body = encode_seal(self.proof.seal)
        out = bytearray(WIRE_TAG)
        out += (0).to_bytes(4, "big")  # canonical zero is length 1
        out += varint(self.proof.total)
        out += frame(body)
        out += len(self.proof.siblings).to_bytes(4, "big")
        for sibling in self.proof.siblings:
            out += sibling
        with self.assertRaises(ValueError):
            decode_history_proof(bytes(out))


if __name__ == "__main__":
    unittest.main()
