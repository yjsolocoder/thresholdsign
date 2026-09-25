"""Tests for the canonical HDSCProof transport encoding:
encode_hdsc_proof / decode_hdsc_proof."""

import dataclasses
import unittest

from thresholdsign import (
    AggregateSignature,
    HDSCProof,
    HistoryDeltaSegmentsSeal,
    HistoryDeltaSegmentsSealChain,
    check_hdsc_proof,
    decode_hdsc_proof,
    encode_hds,
    encode_hdsc_proof,
    make_hdsc_proof,
)

from test_audit_chain import sign_message
from test_history_delta_segments_codec import build_segments
from test_history_delta_segments_seal import make_seal
from test_history_delta_segments_seal_chain import make_chain
from test_hdsc_proof import chain_of_size
from test_nonce_reuse import make_key

WIRE_TAG = b"ts/hdscp/w1"


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def build_wire(proof: HDSCProof) -> bytes:
    """Independently build the proof wire format straight from the spec."""
    out = bytearray(WIRE_TAG)
    out += varint(proof.total)
    out += u32(len(proof.indices))
    for index in proof.indices:
        out += varint(index)
    out += u32(len(proof.seals))
    for seal in proof.seals:
        out += frame(encode_hds(seal))
    out += u32(len(proof.siblings))
    for sibling in proof.siblings:
        out += sibling
    return bytes(out)


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.chain = chain_of_size(8, self.key, seed_base=6200)

    def _chain_of_size(self, n):
        return HistoryDeltaSegmentsSealChain(
            self.chain.seals[:n], self.chain.signature
        )

    def test_round_trip_for_every_size_and_subset(self):
        for n in range(1, 9):
            chain = self._chain_of_size(n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                _message, proof = make_hdsc_proof(chain, indices)
                wire = encode_hdsc_proof(proof)
                decoded = decode_hdsc_proof(wire)
                self.assertEqual(decoded, proof, msg=f"n={n} indices={indices}")
                self.assertEqual(encode_hdsc_proof(decoded), wire)

    def test_encoding_matches_independent_builder(self):
        for n in range(1, 9):
            chain = self._chain_of_size(n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                _message, proof = make_hdsc_proof(chain, indices)
                self.assertEqual(
                    encode_hdsc_proof(proof),
                    build_wire(proof),
                    msg=f"n={n} indices={indices}",
                )

    def test_starts_with_tag_and_varint_total(self):
        _message, proof = make_hdsc_proof(self.chain, (2, 4))
        wire = encode_hdsc_proof(proof)
        self.assertTrue(wire.startswith(WIRE_TAG))
        offset = len(WIRE_TAG)
        # total = 8 -> VARINT is 00 00 00 01 08
        self.assertEqual(wire[offset:offset + 5], b"\x00\x00\x00\x01\x08")
        # index count = 2 -> 00 00 00 02
        self.assertEqual(wire[offset + 5:offset + 9], u32(2))

    def test_zero_index_encodes_as_single_body_byte(self):
        _message, proof = make_hdsc_proof(self.chain, (0,))
        wire = encode_hdsc_proof(proof)
        offset = len(WIRE_TAG) + len(varint(proof.total)) + 4
        # index 0 -> VARINT 00 00 00 01 00
        self.assertEqual(wire[offset:offset + 5], b"\x00\x00\x00\x01\x00")

    def test_seal_frames_are_non_empty(self):
        _message, proof = make_hdsc_proof(self.chain, (0, 2))
        wire = encode_hdsc_proof(proof)
        self.assertIn(encode_hds(proof.seals[0]), wire)
        self.assertIn(encode_hds(proof.seals[1]), wire)

    def test_decoded_proof_still_checks(self):
        for n in range(1, 9):
            chain = self._chain_of_size(n)
            root_message, _ = make_hdsc_proof(chain, (0,))
            signature = sign_message(self.key, root_message, seed=7000 + n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                _message, proof = make_hdsc_proof(chain, indices)
                decoded = decode_hdsc_proof(encode_hdsc_proof(proof))
                self.assertTrue(
                    check_hdsc_proof(decoded, signature, self.key),
                    msg=f"n={n} indices={indices}",
                )

    def test_encoding_is_unique_and_stateless(self):
        _message, proof = make_hdsc_proof(self.chain, (1, 3, 5))
        self.assertEqual(
            encode_hdsc_proof(proof),
            encode_hdsc_proof(proof),
        )


class StructureOnlyTest(unittest.TestCase):
    def test_decode_does_not_verify_seals_or_signature(self):
        # Structurally legal synthetic seals that never went through a real
        # key round-trip untouched; n=3 with disclosed leaves 0 and 2
        # derives exactly one sibling.
        key, _delta, segments = build_segments()
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        seals = (
            HistoryDeltaSegmentsSeal((segments[0],), signature),
            HistoryDeltaSegmentsSeal((segments[1], segments[2]), signature),
        )
        proof = HDSCProof(
            indices=(0, 2), total=3, seals=seals, siblings=(b"s" * 32,)
        )
        decoded = decode_hdsc_proof(encode_hdsc_proof(proof))
        self.assertEqual(decoded, proof)

    def test_encoding_does_not_check_a_signature(self):
        key, _delta, segments = build_segments()
        chain = HistoryDeltaSegmentsSealChain(
            (
                HistoryDeltaSegmentsSeal(
                    (segments[0],),
                    AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
                ),
            ),
            "not-a-signature",
        )
        _message, proof = make_hdsc_proof(chain, (0,))
        self.assertTrue(encode_hdsc_proof(proof))


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.chain = chain_of_size(5, self.key, seed_base=6400)
        _msg, self.proof = make_hdsc_proof(self.chain, (1, 2))

    def test_non_proof_type_error(self):
        with self.assertRaises(TypeError):
            encode_hdsc_proof(("not", "a", "proof"))

    def test_field_type_errors(self):
        proof = self.proof
        for bad in (
            HDSCProof(proof.indices, True, proof.seals, proof.siblings),
            HDSCProof(proof.indices, "5", proof.seals, proof.siblings),
            HDSCProof([1, 2], proof.total, proof.seals, proof.siblings),
            HDSCProof((True, 2), proof.total, proof.seals, proof.siblings),
            HDSCProof(("1", 2), proof.total, proof.seals, proof.siblings),
            HDSCProof(
                proof.indices, proof.total, [proof.seals[0]] * 2, proof.siblings
            ),
            HDSCProof(
                proof.indices, proof.total, ("not-a-seal",) * 2, proof.siblings
            ),
            HDSCProof(proof.indices, proof.total, proof.seals, [b"s" * 32]),
            HDSCProof(proof.indices, proof.total, proof.seals, (b"s" * 32, 33)),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_hdsc_proof(bad)

    def test_value_errors(self):
        proof = self.proof
        seal1, seal2 = proof.seals
        thirty_two = b"s" * 32
        bad_seal = HistoryDeltaSegmentsSeal(
            (), AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        )
        for bad in (
            HDSCProof((1, 2), 0, proof.seals, ()),
            HDSCProof((1, 2), -1, proof.seals, ()),
            HDSCProof((1, 2), 2 ** 64, proof.seals, ()),
            HDSCProof((), 5, (), ()),
            HDSCProof((-1, 2), 5, proof.seals, ()),
            HDSCProof((1, 5), 5, proof.seals, ()),
            HDSCProof((2, 1), 5, proof.seals, ()),
            HDSCProof((1, 1), 5, (seal1,), ()),
            HDSCProof((1,), 5, (), ()),
            HDSCProof((1, 2, 3), 5, proof.seals, ()),
            HDSCProof((1, 2), 5, (seal1, bad_seal), proof.siblings),
            dataclasses.replace(proof, siblings=(thirty_two[:-1],)),
            dataclasses.replace(proof, siblings=(thirty_two + b"x",)),
            # Every entry is exactly 32 bytes, but the count is not the one
            # n=5 with indices (1, 2) derives.
            dataclasses.replace(proof, siblings=proof.siblings[:-1]),
            dataclasses.replace(proof, siblings=proof.siblings + (thirty_two,)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                encode_hdsc_proof(bad)


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.chain = chain_of_size(5, self.key, seed_base=6600)
        _msg, self.proof = make_hdsc_proof(self.chain, (1, 2))
        self.wire = encode_hdsc_proof(self.proof)

    def test_non_bytes_type_error(self):
        with self.assertRaises(TypeError):
            decode_hdsc_proof("not bytes")
        with self.assertRaises(TypeError):
            decode_hdsc_proof(bytearray(self.wire))

    def test_bad_tag(self):
        bad = b"ts/hdscp/w2" + self.wire[len(WIRE_TAG):]
        with self.assertRaises(ValueError):
            decode_hdsc_proof(bad)
        with self.assertRaises(ValueError):
            decode_hdsc_proof(b"x" + self.wire[1:])

    def test_truncation(self):
        for cut in range(len(WIRE_TAG), len(self.wire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_hdsc_proof(self.wire[:cut])

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_hdsc_proof(self.wire + b"\x00")

    def test_empty_indices_rejected(self):
        out = bytearray(WIRE_TAG)
        out += varint(self.proof.total)
        out += u32(0)  # no indices
        with self.assertRaises(ValueError):
            decode_hdsc_proof(bytes(out))

    def test_zero_total_rejected(self):
        out = bytearray(WIRE_TAG)
        out += varint(0)
        out += u32(1)
        out += varint(0)
        with self.assertRaises(ValueError):
            decode_hdsc_proof(bytes(out))

    def test_total_too_large(self):
        out = bytearray(WIRE_TAG)
        out += varint(2 ** 64)
        with self.assertRaises(ValueError):
            decode_hdsc_proof(bytes(out))

    def test_empty_seal_frame_rejected(self):
        out = bytearray(WIRE_TAG)
        out += varint(1)
        out += u32(1) + varint(0)
        out += u32(1)
        out += frame(b"")
        out += u32(0)
        with self.assertRaises(ValueError):
            decode_hdsc_proof(bytes(out))

    def test_junk_seal_frame_rejected(self):
        out = bytearray(WIRE_TAG)
        out += varint(1)
        out += u32(1) + varint(0)
        out += u32(1)
        out += frame(b"not-a-seal")
        out += u32(0)
        with self.assertRaises(ValueError):
            decode_hdsc_proof(bytes(out))

    def test_seal_count_mismatch(self):
        out = bytearray(WIRE_TAG)
        out += varint(self.proof.total)
        out += u32(len(self.proof.indices))
        for index in self.proof.indices:
            out += varint(index)
        out += u32(1)  # seals claim one, indices are two
        out += frame(encode_hds(self.proof.seals[0]))
        with self.assertRaises(ValueError):
            decode_hdsc_proof(bytes(out))

    def test_non_canonical_varint_leading_zero(self):
        out = bytearray(WIRE_TAG)
        out += varint(self.proof.total)
        out += u32(len(self.proof.indices))
        out += (2).to_bytes(4, "big") + b"\x00\x01"  # index 1 with leading zero
        for index in self.proof.indices[1:]:
            out += varint(index)
        out += u32(len(self.proof.seals))
        for seal in self.proof.seals:
            out += frame(encode_hds(seal))
        out += u32(len(self.proof.siblings))
        for sibling in self.proof.siblings:
            out += sibling
        with self.assertRaises(ValueError):
            decode_hdsc_proof(bytes(out))

    def test_non_canonical_total_leading_zero(self):
        out = bytearray(WIRE_TAG)
        out += (1).to_bytes(4, "big") + b"\x00\x05"  # total = 5 with leading zero
        out += u32(len(self.proof.indices))
        for index in self.proof.indices:
            out += varint(index)
        out += u32(len(self.proof.seals))
        for seal in self.proof.seals:
            out += frame(encode_hds(seal))
        out += u32(len(self.proof.siblings))
        for sibling in self.proof.siblings:
            out += sibling
        with self.assertRaises(ValueError):
            decode_hdsc_proof(bytes(out))

    def test_index_out_of_range(self):
        out = bytearray(WIRE_TAG)
        out += varint(self.proof.total)
        out += u32(2)
        out += varint(1) + varint(5)  # second index == total
        out += u32(2)
        for seal in self.proof.seals:
            out += frame(encode_hds(seal))
        out += u32(0)
        with self.assertRaises(ValueError):
            decode_hdsc_proof(bytes(out))

    def test_indices_not_strictly_increasing(self):
        out = bytearray(WIRE_TAG)
        out += varint(self.proof.total)
        out += u32(2)
        out += varint(2) + varint(1)
        out += u32(2)
        for seal in self.proof.seals:
            out += frame(encode_hds(seal))
        out += u32(0)
        with self.assertRaises(ValueError):
            decode_hdsc_proof(bytes(out))

    def test_sibling_wrong_width(self):
        out = bytearray(WIRE_TAG)
        out += varint(self.proof.total)
        out += u32(len(self.proof.indices))
        for index in self.proof.indices:
            out += varint(index)
        out += u32(len(self.proof.seals))
        for seal in self.proof.seals:
            out += frame(encode_hds(seal))
        out += u32(1)
        out += b"s" * 31
        with self.assertRaises(ValueError):
            decode_hdsc_proof(bytes(out))

    def test_sibling_count_mismatch(self):
        # n=5 with indices (1, 2) derives exactly three siblings; claiming
        # one or four must be rejected even with well-sized entries.
        for claimed, entries in (
            (1, (b"s" * 32,)),
            (4, (b"s" * 32,) * 4),
        ):
            out = bytearray(WIRE_TAG)
            out += varint(self.proof.total)
            out += u32(len(self.proof.indices))
            for index in self.proof.indices:
                out += varint(index)
            out += u32(len(self.proof.seals))
            for seal in self.proof.seals:
                out += frame(encode_hds(seal))
            out += u32(claimed)
            for entry in entries:
                out += entry
            with self.assertRaises(ValueError, msg=f"claimed={claimed}"):
                decode_hdsc_proof(bytes(out))


if __name__ == "__main__":
    unittest.main()
