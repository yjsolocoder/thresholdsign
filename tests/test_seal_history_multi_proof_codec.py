"""Tests for the canonical SealHistoryMultiProof transport encoding:
encode_history_multi_proof / decode_history_multi_proof."""

import dataclasses
import unittest

from thresholdsign import (
    AggregateSignature,
    NonceLeakReport,
    ReportSeal,
    SealHistoryMultiProof,
    check_history_multi_proof,
    decode_history_multi_proof,
    encode_history_multi_proof,
    encode_seal,
    make_history_multi_proof,
)

from test_nonce_reuse import make_key
from test_report_seal import synthetic
from test_seal_history import make_history, sign_message

WIRE_TAG = b"thresholdsign/seal-history-multi-proof/v1"


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def build_wire(proof: SealHistoryMultiProof) -> bytes:
    """Independently build the multi-proof wire format straight from the spec."""
    out = bytearray(WIRE_TAG)
    out += varint(proof.total)
    out += u32(len(proof.indices))
    for index in proof.indices:
        out += varint(index)
    out += u32(len(proof.seals))
    for seal in proof.seals:
        out += frame(encode_seal(seal))
    out += u32(len(proof.siblings))
    for sibling in proof.siblings:
        out += sibling
    return bytes(out)


def sealed_multi(history, indices, key, *, seed=900):
    message, proof = make_history_multi_proof(history, indices)
    signature = sign_message(message, key, seed=seed + sum(indices))
    return proof, signature


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = make_history(
            self.key, nonces=tuple(100 + i for i in range(9))
        )

    def _history_of_size(self, n):
        return self.history.__class__(self.history.items[:n])

    def test_round_trip_for_every_size_and_subset(self):
        for n in range(1, 10):
            history = self._history_of_size(n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                _message, proof = make_history_multi_proof(history, indices)
                wire = encode_history_multi_proof(proof)
                decoded = decode_history_multi_proof(wire)
                self.assertEqual(decoded, proof, msg=f"n={n} indices={indices}")
                self.assertEqual(encode_history_multi_proof(decoded), wire)
                self.assertIsInstance(decoded.indices, tuple)
                self.assertIsInstance(decoded.seals, tuple)
                self.assertIsInstance(decoded.siblings, tuple)
                self.assertTrue(
                    all(isinstance(s, bytes) for s in decoded.siblings)
                )

    def test_encoding_matches_independent_builder(self):
        for n in range(1, 10):
            history = self._history_of_size(n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                _message, proof = make_history_multi_proof(history, indices)
                self.assertEqual(
                    encode_history_multi_proof(proof),
                    build_wire(proof),
                    msg=f"n={n} indices={indices}",
                )

    def test_starts_with_tag_and_varint_total(self):
        _message, proof = make_history_multi_proof(self.history, (2, 4))
        wire = encode_history_multi_proof(proof)
        self.assertTrue(wire.startswith(WIRE_TAG))
        offset = len(WIRE_TAG)
        # total = 9 -> VARINT is 00 00 00 01 09
        self.assertEqual(wire[offset:offset + 5], b"\x00\x00\x00\x01\x09")
        # index count = 2 -> 00 00 00 02
        self.assertEqual(wire[offset + 5:offset + 9], u32(2))

    def test_zero_index_encodes_as_single_body_byte(self):
        _message, proof = make_history_multi_proof(self.history, (0,))
        wire = encode_history_multi_proof(proof)
        offset = len(WIRE_TAG) + len(varint(proof.total)) + 4
        # index 0 -> VARINT 00 00 00 01 00
        self.assertEqual(wire[offset:offset + 5], b"\x00\x00\x00\x01\x00")

    def test_single_item_history_round_trips_with_empty_siblings(self):
        history = self._history_of_size(1)
        _message, proof = make_history_multi_proof(history, (0,))
        self.assertEqual(proof.siblings, ())
        wire = encode_history_multi_proof(proof)
        decoded = decode_history_multi_proof(wire)
        self.assertEqual(decoded, proof)
        # After the last seal frame the U32 sibling count is zero, then end.
        self.assertTrue(wire.endswith((0).to_bytes(4, "big")))

    def test_decoded_proof_still_checks(self):
        for n in range(1, 10):
            history = self._history_of_size(n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                proof, signature = sealed_multi(
                    history, indices, self.key, seed=1000 + 17 * n
                )
                decoded = decode_history_multi_proof(
                    encode_history_multi_proof(proof)
                )
                self.assertTrue(
                    check_history_multi_proof(decoded, signature, self.key),
                    msg=f"n={n} indices={indices}",
                )

    def test_encoding_is_unique_and_stateless(self):
        _message, proof = make_history_multi_proof(self.history, (1, 3, 5))
        self.assertEqual(
            encode_history_multi_proof(proof),
            encode_history_multi_proof(proof),
        )


class StructureOnlyTest(unittest.TestCase):
    def test_decode_does_not_verify_seal_or_signature(self):
        # A structurally legal seal carrying a meaningless signature
        # encodes and decodes fine; check_history_multi_proof rejects it.
        seal = ReportSeal(
            NonceLeakReport((synthetic(1, 10),)),
            AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
        )
        proof = SealHistoryMultiProof((1,), 3, (seal,), (b"s" * 32,) * 2)
        decoded = decode_history_multi_proof(encode_history_multi_proof(proof))
        self.assertEqual(decoded, proof)

    def test_encoding_checks_no_signature(self):
        key = make_key()
        history = make_history(key, nonces=(101, 102))
        _message, proof = make_history_multi_proof(history, (0,))
        self.assertTrue(encode_history_multi_proof(proof))


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = make_history(
            self.key, nonces=tuple(401 + i for i in range(5))
        )
        _msg, self.proof = make_history_multi_proof(self.history, (1, 2))

    def test_non_proof_type_error(self):
        with self.assertRaises(TypeError):
            encode_history_multi_proof(("not", "a", "proof"))
        with self.assertRaises(TypeError):
            encode_history_multi_proof(None)

    def test_field_type_errors(self):
        proof = self.proof
        for bad in (
            dataclasses.replace(proof, total=True),
            dataclasses.replace(proof, total="5"),
            dataclasses.replace(proof, indices=[1, 2]),
            dataclasses.replace(proof, indices=(True, 2)),
            dataclasses.replace(proof, indices=("1", 2)),
            dataclasses.replace(proof, seals=[proof.seals[0]] * 2),
            dataclasses.replace(proof, seals=("not-a-seal",) * 2),
            dataclasses.replace(proof, siblings=[b"s" * 32]),
            dataclasses.replace(proof, siblings=(b"s" * 32, 33)),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_history_multi_proof(bad)

    def test_value_errors(self):
        proof = self.proof
        seal1, seal2 = proof.seals
        thirty_two = b"s" * 32
        for bad in (
            SealHistoryMultiProof((1, 2), 0, proof.seals, ()),
            SealHistoryMultiProof((1, 2), -1, proof.seals, ()),
            SealHistoryMultiProof((1, 2), 2 ** 64, proof.seals, ()),
            SealHistoryMultiProof((), 5, (), ()),
            SealHistoryMultiProof((-1, 2), 5, proof.seals, ()),
            SealHistoryMultiProof((1, 5), 5, proof.seals, ()),
            SealHistoryMultiProof((2, 1), 5, proof.seals, ()),
            SealHistoryMultiProof((1, 1), 5, (seal1,), ()),
            SealHistoryMultiProof((1,), 5, (), ()),
            SealHistoryMultiProof(
                (1, 2, 3), 5, proof.seals + proof.seals[0:1], ()
            ),
            dataclasses.replace(proof, siblings=(thirty_two[:-1],) * 3),
            dataclasses.replace(proof, siblings=(thirty_two + b"x",) * 3),
            dataclasses.replace(proof, siblings=proof.siblings[:-1]),
            dataclasses.replace(proof, siblings=proof.siblings + (thirty_two,)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                encode_history_multi_proof(bad)

    def test_illegal_nested_seal_value_error(self):
        bad_seal = ReportSeal(
            NonceLeakReport((synthetic(1, 10),)),
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
        )
        bad = dataclasses.replace(
            self.proof, seals=(bad_seal,) + self.proof.seals[1:]
        )
        with self.assertRaises(ValueError):
            encode_history_multi_proof(bad)


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = make_history(
            self.key, nonces=tuple(401 + i for i in range(5))
        )
        _msg, self.proof = make_history_multi_proof(self.history, (1, 2))
        self.wire = encode_history_multi_proof(self.proof)

    def test_non_bytes_type_error(self):
        with self.assertRaises(TypeError):
            decode_history_multi_proof("not bytes")
        with self.assertRaises(TypeError):
            decode_history_multi_proof(bytearray(self.wire))
        with self.assertRaises(TypeError):
            decode_history_multi_proof(None)

    def test_bad_tag(self):
        bad = b"thresholdsign/seal-history-multi-proof/v2" + self.wire[len(WIRE_TAG):]
        with self.assertRaises(ValueError):
            decode_history_multi_proof(bad)
        with self.assertRaises(ValueError):
            decode_history_multi_proof(b"x" + self.wire[1:])

    def test_truncation(self):
        for cut in range(len(WIRE_TAG), len(self.wire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_history_multi_proof(self.wire[:cut])

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_history_multi_proof(self.wire + b"\x00")

    def test_empty_indices_rejected(self):
        out = bytearray(WIRE_TAG)
        out += varint(self.proof.total)
        out += u32(0)  # no indices
        with self.assertRaises(ValueError):
            decode_history_multi_proof(bytes(out))

    def test_seal_count_mismatch(self):
        out = bytearray(WIRE_TAG)
        out += varint(self.proof.total)
        out += u32(len(self.proof.indices))
        for index in self.proof.indices:
            out += varint(index)
        out += u32(1)  # seals claim one, indices are two
        out += frame(encode_seal(self.proof.seals[0]))
        with self.assertRaises(ValueError):
            decode_history_multi_proof(bytes(out))

    def test_empty_seal_frame_rejected(self):
        out = bytearray(WIRE_TAG)
        out += varint(1)
        out += u32(1) + varint(0)
        out += u32(1)
        out += u32(0)  # empty seal frame
        out += u32(0)
        with self.assertRaises(ValueError):
            decode_history_multi_proof(bytes(out))

    def test_illegal_nested_seal_rejected(self):
        out = bytearray(WIRE_TAG)
        out += varint(self.proof.total)
        out += u32(len(self.proof.indices))
        for index in self.proof.indices:
            out += varint(index)
        out += u32(len(self.proof.seals))
        out += frame(b"not-a-seal")
        out += frame(encode_seal(self.proof.seals[1]))
        out += u32(len(self.proof.siblings))
        for sibling in self.proof.siblings:
            out += sibling
        with self.assertRaises(ValueError):
            decode_history_multi_proof(bytes(out))

    def test_non_canonical_varint_leading_zero(self):
        out = bytearray(WIRE_TAG)
        out += varint(self.proof.total)
        out += u32(len(self.proof.indices))
        out += (2).to_bytes(4, "big") + b"\x00\x01"  # index 1, leading zero
        for index in self.proof.indices[1:]:
            out += varint(index)
        out += u32(len(self.proof.seals))
        for seal in self.proof.seals:
            out += frame(encode_seal(seal))
        out += u32(len(self.proof.siblings))
        for sibling in self.proof.siblings:
            out += sibling
        with self.assertRaises(ValueError):
            decode_history_multi_proof(bytes(out))

    def test_non_canonical_total_leading_zero(self):
        out = bytearray(WIRE_TAG)
        out += (1).to_bytes(4, "big") + b"\x00\x05"  # total 5, leading zero
        out += u32(len(self.proof.indices))
        for index in self.proof.indices:
            out += varint(index)
        out += u32(len(self.proof.seals))
        for seal in self.proof.seals:
            out += frame(encode_seal(seal))
        out += u32(len(self.proof.siblings))
        for sibling in self.proof.siblings:
            out += sibling
        with self.assertRaises(ValueError):
            decode_history_multi_proof(bytes(out))

    def test_total_too_large(self):
        out = bytearray(WIRE_TAG)
        out += varint(2 ** 64)
        out += u32(1) + varint(0)
        out += u32(1)
        out += frame(encode_seal(self.proof.seals[0]))
        out += u32(0)
        with self.assertRaises(ValueError):
            decode_history_multi_proof(bytes(out))

    def test_zero_total_rejected(self):
        out = bytearray(WIRE_TAG)
        out += varint(0)
        out += u32(1) + varint(0)
        out += u32(1)
        out += frame(encode_seal(self.proof.seals[0]))
        out += u32(0)
        with self.assertRaises(ValueError):
            decode_history_multi_proof(bytes(out))

    def test_index_out_of_range(self):
        out = bytearray(WIRE_TAG)
        out += varint(self.proof.total)
        out += u32(2)
        out += varint(1) + varint(5)  # second index == total
        out += u32(2)
        for seal in self.proof.seals:
            out += frame(encode_seal(seal))
        out += u32(0)
        with self.assertRaises(ValueError):
            decode_history_multi_proof(bytes(out))

    def test_indices_not_strictly_increasing(self):
        out = bytearray(WIRE_TAG)
        out += varint(self.proof.total)
        out += u32(2)
        out += varint(2) + varint(1)
        out += u32(2)
        for seal in self.proof.seals:
            out += frame(encode_seal(seal))
        out += u32(0)
        with self.assertRaises(ValueError):
            decode_history_multi_proof(bytes(out))

    def test_duplicate_indices_rejected(self):
        out = bytearray(WIRE_TAG)
        out += varint(self.proof.total)
        out += u32(2)
        out += varint(1) + varint(1)
        out += u32(2)
        for seal in self.proof.seals:
            out += frame(encode_seal(seal))
        out += u32(0)
        with self.assertRaises(ValueError):
            decode_history_multi_proof(bytes(out))

    def test_sibling_wrong_width(self):
        out = bytearray(WIRE_TAG)
        out += varint(self.proof.total)
        out += u32(len(self.proof.indices))
        for index in self.proof.indices:
            out += varint(index)
        out += u32(len(self.proof.seals))
        for seal in self.proof.seals:
            out += frame(encode_seal(seal))
        out += u32(1)
        out += b"s" * 31
        with self.assertRaises(ValueError):
            decode_history_multi_proof(bytes(out))

    def _wire_with_sibling_count(self, sibling_digests):
        out = bytearray(WIRE_TAG)
        out += varint(self.proof.total)
        out += u32(len(self.proof.indices))
        for index in self.proof.indices:
            out += varint(index)
        out += u32(len(self.proof.seals))
        for seal in self.proof.seals:
            out += frame(encode_seal(seal))
        out += u32(len(sibling_digests))
        for digest in sibling_digests:
            out += digest
        return bytes(out)

    def test_missing_sibling_rejected(self):
        # n=5 with indices (1, 2) derives three companions; two is short.
        wire = self._wire_with_sibling_count(self.proof.siblings[:-1])
        with self.assertRaises(ValueError):
            decode_history_multi_proof(wire)

    def test_extra_sibling_rejected(self):
        wire = self._wire_with_sibling_count(
            self.proof.siblings + (b"u" * 32,)
        )
        with self.assertRaises(ValueError):
            decode_history_multi_proof(wire)

    def test_zero_siblings_when_tree_is_fully_disclosed(self):
        history = self.history.__class__(self.history.items[:4])
        _message, proof = make_history_multi_proof(
            history, (0, 1, 2, 3)
        )
        self.assertEqual(proof.siblings, ())
        decoded = decode_history_multi_proof(encode_history_multi_proof(proof))
        self.assertEqual(decoded, proof)
        out = bytearray(encode_history_multi_proof(proof))
        # Flip the trailing zero sibling count into a one and append a
        # well-formed digest: the derived count is still zero.
        bad = bytes(out[:-4]) + u32(1) + b"u" * 32
        with self.assertRaises(ValueError):
            decode_history_multi_proof(bad)

    def test_derived_sibling_count_matches_maker_for_every_shape(self):
        for n in range(1, 6):
            history = self.history.__class__(self.history.items[:n])
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                _message, proof = make_history_multi_proof(history, indices)
                required = len(proof.siblings)
                with self.assertRaises(
                    ValueError, msg=f"n={n} indices={indices} long"
                ):
                    encode_history_multi_proof(
                        dataclasses.replace(
                            proof, siblings=proof.siblings + (b"u" * 32,)
                        )
                    )
                if required:
                    with self.assertRaises(
                        ValueError, msg=f"n={n} indices={indices} short"
                    ):
                        encode_history_multi_proof(
                            dataclasses.replace(
                                proof, siblings=proof.siblings[:-1]
                            )
                        )
                self.assertEqual(
                    decode_history_multi_proof(
                        encode_history_multi_proof(proof)
                    ),
                    proof,
                )


if __name__ == "__main__":
    unittest.main()
