"""Tests for the canonical SealHistoryMultiProof transport encoding:
encode_history_multi_proof / decode_history_multi_proof."""

import dataclasses
import unittest

from thresholdsign import (
    AggregateSignature,
    NonceLeakReport,
    ReportSeal,
    SealHistory,
    SealHistoryMultiProof,
    check_history_multi_proof,
    decode_history_multi_proof,
    encode_history_multi_proof,
    encode_seal,
    make_history_multi_proof,
)

from test_report_seal import synthetic
from test_seal_history import make_history, make_key, sign_message

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


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = make_history(
            self.key, nonces=tuple(700 + i for i in range(9))
        )

    def _history_of_size(self, n):
        return SealHistory(self.history.items[:n])

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

    def test_seal_frames_are_non_empty(self):
        _message, proof = make_history_multi_proof(self.history, (0, 2))
        wire = encode_history_multi_proof(proof)
        self.assertIn(encode_seal(proof.seals[0]), wire)
        self.assertIn(encode_seal(proof.seals[1]), wire)

    def test_decoded_proof_still_checks(self):
        for n in range(1, 10):
            history = self._history_of_size(n)
            root_message, _ = make_history_multi_proof(history, (0,))
            signature = sign_message(root_message, self.key, seed=1000 + n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                _message, proof = make_history_multi_proof(history, indices)
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
    def test_decode_does_not_verify_seals_or_signature(self):
        # Structurally legal synthetic seals that never went through a real
        # key round-trip untouched; n=3 with disclosed leaves 0 and 2
        # derives exactly one sibling.
        seals = (
            ReportSeal(
                NonceLeakReport((synthetic(1, 10),)),
                AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
            ),
            ReportSeal(
                NonceLeakReport((synthetic(2, 20),)),
                AggregateSignature(R=6, z=8, signer_ids=(1, 3)),
            ),
        )
        proof = SealHistoryMultiProof(
            indices=(0, 2), total=3, seals=seals, siblings=(b"s" * 32,)
        )
        decoded = decode_history_multi_proof(encode_history_multi_proof(proof))
        self.assertEqual(decoded, proof)

    def test_encoding_does_not_check_a_signature(self):
        history = SealHistory(
            (
                ReportSeal(
                    NonceLeakReport((synthetic(1, 10),)),
                    AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
                ),
            )
        )
        _message, proof = make_history_multi_proof(history, (0,))
        self.assertTrue(encode_history_multi_proof(proof))


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = make_history(
            self.key, nonces=tuple(800 + i for i in range(5))
        )
        _msg, self.proof = make_history_multi_proof(self.history, (1, 2))

    def test_non_proof_type_error(self):
        with self.assertRaises(TypeError):
            encode_history_multi_proof(("not", "a", "proof"))

    def test_field_type_errors(self):
        proof = self.proof
        for bad in (
            SealHistoryMultiProof(
                proof.indices, True, proof.seals, proof.siblings
            ),
            SealHistoryMultiProof(
                proof.indices, "5", proof.seals, proof.siblings
            ),
            SealHistoryMultiProof(
                [1, 2], proof.total, proof.seals, proof.siblings
            ),
            SealHistoryMultiProof(
                (True, 2), proof.total, proof.seals, proof.siblings
            ),
            SealHistoryMultiProof(
                ("1", 2), proof.total, proof.seals, proof.siblings
            ),
            SealHistoryMultiProof(
                proof.indices, proof.total, [proof.seals[0]] * 2, proof.siblings
            ),
            SealHistoryMultiProof(
                proof.indices, proof.total, ("not-a-seal",) * 2, proof.siblings
            ),
            SealHistoryMultiProof(
                proof.indices, proof.total, proof.seals, [b"s" * 32]
            ),
            SealHistoryMultiProof(
                proof.indices, proof.total, proof.seals, (b"s" * 32, 33)
            ),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_history_multi_proof(bad)

    def test_value_errors(self):
        proof = self.proof
        seal1, seal2 = proof.seals
        thirty_two = b"s" * 32
        bad_seal = ReportSeal(
            NonceLeakReport((synthetic(1, 10),)),
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
        )
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
            SealHistoryMultiProof((1, 2, 3), 5, proof.seals, ()),
            SealHistoryMultiProof(
                (1, 2), 5, (seal1, bad_seal), proof.siblings
            ),
            dataclasses.replace(proof, siblings=(thirty_two[:-1],)),
            dataclasses.replace(proof, siblings=(thirty_two + b"x",)),
            # Every entry is exactly 32 bytes, but the count is not the one
            # n=5 with indices (1, 2) derives.
            dataclasses.replace(proof, siblings=proof.siblings[:-1]),
            dataclasses.replace(proof, siblings=proof.siblings + (thirty_two,)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                encode_history_multi_proof(bad)


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = make_history(
            self.key, nonces=tuple(900 + i for i in range(5))
        )
        _msg, self.proof = make_history_multi_proof(self.history, (1, 2))
        self.wire = encode_history_multi_proof(self.proof)

    def test_non_bytes_type_error(self):
        with self.assertRaises(TypeError):
            decode_history_multi_proof("not bytes")
        with self.assertRaises(TypeError):
            decode_history_multi_proof(bytearray(self.wire))

    def test_bad_tag(self):
        bad = (
            b"thresholdsign/seal-history-multi-proof/v2"
            + self.wire[len(WIRE_TAG):]
        )
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

    def test_zero_total_rejected(self):
        out = bytearray(WIRE_TAG)
        out += varint(0)
        out += u32(1)
        out += varint(0)
        with self.assertRaises(ValueError):
            decode_history_multi_proof(bytes(out))

    def test_total_too_large(self):
        out = bytearray(WIRE_TAG)
        out += varint(2 ** 64)
        with self.assertRaises(ValueError):
            decode_history_multi_proof(bytes(out))

    def test_empty_seal_frame_rejected(self):
        out = bytearray(WIRE_TAG)
        out += varint(1)
        out += u32(1) + varint(0)
        out += u32(1)
        out += frame(b"")
        out += u32(0)
        with self.assertRaises(ValueError):
            decode_history_multi_proof(bytes(out))

    def test_junk_seal_frame_rejected(self):
        out = bytearray(WIRE_TAG)
        out += varint(1)
        out += u32(1) + varint(0)
        out += u32(1)
        out += frame(b"not-a-seal")
        out += u32(0)
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

    def test_non_canonical_varint_leading_zero(self):
        out = bytearray(WIRE_TAG)
        out += varint(self.proof.total)
        out += u32(len(self.proof.indices))
        out += (2).to_bytes(4, "big") + b"\x00\x01"  # index 1 with leading zero
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
        out += (1).to_bytes(4, "big") + b"\x00\x05"  # total = 5 with leading zero
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
        # n=5 with indices (1, 2) derives the companions the maker emits;
        # dropping the last one makes the declared count short.
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
        # Disclosing every leaf of a 4-item tree derives no siblings.
        history = SealHistory(self.history.items[:4])
        _message, proof = make_history_multi_proof(history, (0, 1, 2, 3))
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
            history = SealHistory(self.history.items[:n])
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                _message, proof = make_history_multi_proof(history, indices)
                required = len(proof.siblings)
                # An extra companion is always rejected.
                with self.assertRaises(
                    ValueError, msg=f"n={n} indices={indices} long"
                ):
                    encode_history_multi_proof(
                        dataclasses.replace(
                            proof, siblings=proof.siblings + (b"u" * 32,)
                        )
                    )
                # A missing companion is rejected unless the derived count
                # is already zero.
                if required:
                    with self.assertRaises(
                        ValueError, msg=f"n={n} indices={indices} short"
                    ):
                        encode_history_multi_proof(
                            dataclasses.replace(
                                proof, siblings=proof.siblings[:-1]
                            )
                        )
                # The correct count is the only accepted one.
                self.assertEqual(
                    decode_history_multi_proof(
                        encode_history_multi_proof(proof)
                    ),
                    proof,
                )


if __name__ == "__main__":
    unittest.main()
