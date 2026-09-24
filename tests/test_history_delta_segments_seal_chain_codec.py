"""Tests for the canonical transport encoding of the non-empty
order-preserving chain of whole history delta segments seals:
encode_hdsc / decode_hdsc."""

import unittest

from thresholdsign import (
    AggregateSignature,
    AuditProofBundle,
    HistoryDeltaSegmentsSeal,
    HistoryDeltaSegmentsSealChain,
    decode_hdsc,
    decode_hds,
    encode_audit_proof,
    encode_audit_proof_bundle,
    encode_hdsc,
    encode_hds,
    encode_history_delta_segments,
    make_proof,
    verify_hdsc,
)

from test_audit_extension_proof_bundle_codec import make_records
from test_history_delta_segments_codec import build_segments
from test_history_delta_segments_seal import make_seal
from test_history_delta_segments_seal_chain import make_chain, make_items

WIRE_TAG = b"ts/hdsc/w1"
SEAL_WIRE_TAG = b"ts/hds/w1"
APB_TAG = b"ts/apb/v1"
SEGMENTS_TAG = b"thresholdsign/history-delta-segments/v1"


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def signature_frame(signature: AggregateSignature) -> bytes:
    """Independently build the AuditProofBundle signature frame."""
    out = bytearray(varint(signature.R))
    out += varint(signature.z)
    out += u32(len(signature.signer_ids))
    for signer_id in signature.signer_ids:
        out += varint(signer_id)
    return bytes(out)


def build_wire(chain: HistoryDeltaSegmentsSealChain) -> bytes:
    """Independently build the chain wire format straight from the spec."""
    out = bytearray(WIRE_TAG)
    out += u32(len(chain.items))
    for item in chain.items:
        encoded = encode_hds(item)
        out += u32(len(encoded))
        out += encoded
    out += signature_frame(chain.signature)
    return bytes(out)


class EncodeDecodeSealChainTest(unittest.TestCase):
    def setUp(self):
        self.key, _delta, self.segments = build_segments()
        self.items_single = make_items(self.key, self.segments, seed=1600)[:1]
        self.items_many = make_items(self.key, self.segments, seed=1610)
        self.chains = (
            make_chain(self.items_single, self.key, seed=1620),
            make_chain(self.items_many, self.key, seed=1621),
        )

    def test_wire_matches_independent_spec_build(self):
        for chain in self.chains:
            with self.subTest(n=len(chain.items)):
                blob = encode_hdsc(chain)
                self.assertEqual(blob, build_wire(chain))
                self.assertTrue(blob.startswith(WIRE_TAG))

    def test_wire_layout_is_tag_count_frames_then_signature(self):
        chain = self.chains[1]
        blob = encode_hdsc(chain)
        offset = 0
        self.assertEqual(blob[offset:len(WIRE_TAG)], WIRE_TAG)
        offset += len(WIRE_TAG)
        self.assertEqual(blob[offset:offset + 4], u32(len(chain.items)))
        offset += 4
        for item in chain.items:
            encoded = encode_hds(item)
            self.assertEqual(blob[offset:offset + 4], u32(len(encoded)))
            offset += 4
            self.assertEqual(blob[offset:offset + len(encoded)], encoded)
            offset += len(encoded)
        self.assertEqual(
            blob[offset:], signature_frame(chain.signature)
        )

    def test_outer_signature_frame_matches_audit_proof_bundle_frame(self):
        # The trailing outer signature frame is exactly the frame
        # encode_audit_proof_bundle writes for the same signature.
        chain = self.chains[0]
        records = make_records(self.key, 1)
        _message, proof = make_proof(records, 0)
        bundle = AuditProofBundle(proof, chain.signature)
        bundle_blob = encode_audit_proof_bundle(bundle)
        proof_body = encode_audit_proof(proof)
        bundle_tail = bundle_blob[len(APB_TAG) + 4 + len(proof_body):]

        chain_blob = encode_hdsc(chain)
        self.assertEqual(chain_blob[-len(bundle_tail):], bundle_tail)

    def test_round_trip_byte_for_byte(self):
        for chain in self.chains:
            with self.subTest(n=len(chain.items)):
                blob = encode_hdsc(chain)
                restored = decode_hdsc(blob)
                self.assertIsInstance(restored, HistoryDeltaSegmentsSealChain)
                self.assertEqual(restored, chain)
                self.assertEqual(encode_hdsc(restored), blob)

    def test_nested_seal_frames_decode_standalone(self):
        chain = self.chains[1]
        blob = encode_hdsc(chain)
        offset = len(WIRE_TAG) + 4
        for item in chain.items:
            length = int.from_bytes(blob[offset:offset + 4], "big")
            frame = blob[offset + 4:offset + 4 + length]
            self.assertEqual(decode_hds(bytes(frame)), item)
            offset += 4 + length

    def test_order_is_preserved(self):
        forward = make_chain(self.items_many, self.key, seed=1630)
        reverse_items = tuple(reversed(self.items_many))
        reverse = make_chain(reverse_items, self.key, seed=1631)
        restored = decode_hdsc(encode_hdsc(forward))
        self.assertEqual(restored.items, self.items_many)
        self.assertNotEqual(restored, reverse)
        self.assertEqual(
            decode_hdsc(encode_hdsc(reverse)).items,
            reverse_items,
        )

    def test_encoding_is_deterministic_and_unique(self):
        chain_a = make_chain(self.items_many, self.key, seed=1640)
        chain_b = make_chain(self.items_many[:2], self.key, seed=1641)
        chain_c = make_chain(
            tuple(reversed(self.items_many)), self.key, seed=1642
        )
        self.assertEqual(encode_hdsc(chain_a), encode_hdsc(chain_a))
        self.assertNotEqual(encode_hdsc(chain_a), encode_hdsc(chain_b))
        self.assertNotEqual(encode_hdsc(chain_a), encode_hdsc(chain_c))

    def test_z_zero_is_structurally_legal_and_round_trips(self):
        # z may be zero and encodes as the single body byte 00; a chain
        # with a structural dummy outer signature carries no verdict but
        # is still a legal structure for the codec.
        chain = HistoryDeltaSegmentsSealChain(
            self.items_single,
            AggregateSignature(R=5, z=0, signer_ids=(1,)),
        )
        blob = encode_hdsc(chain)
        restored = decode_hdsc(blob)
        self.assertEqual(restored, chain)
        self.assertEqual(encode_hdsc(restored), blob)

    def test_structurally_legal_but_wrong_outer_signature_decodes(self):
        chain = make_chain(self.items_many, self.key, seed=1650)
        blob = bytearray(encode_hdsc(chain))
        # Flip the last signer-id body byte: still a canonical legal
        # structure, but no longer the signing outer signature.
        blob[-1] ^= 0xFF
        restored = decode_hdsc(bytes(blob))
        self.assertNotEqual(restored, chain)
        self.assertFalse(verify_hdsc(restored, self.key))

    def test_mismatched_chain_decodes_and_fails_verification(self):
        # A structurally legal chain whose nested seal does not verify is
        # returned normally by the codec; verify_hdsc reports False.
        bad_seal = HistoryDeltaSegmentsSeal(
            self.segments[:1], self.items_many[1].signature
        )
        chain = make_chain(
            (self.items_many[0], bad_seal), self.key, seed=1655
        )
        restored = decode_hdsc(encode_hdsc(chain))
        self.assertEqual(restored, chain)
        self.assertFalse(verify_hdsc(restored, self.key))

    def test_decoded_verifying_chain_still_verifies(self):
        chain = make_chain(self.items_many, self.key, seed=1660)
        restored = decode_hdsc(encode_hdsc(chain))
        self.assertTrue(verify_hdsc(restored, self.key))


class EncodeSealChainErrorTest(unittest.TestCase):
    def setUp(self):
        self.key, _delta, self.segments = build_segments()
        self.items = (
            make_seal(self.segments[:2], self.key, seed=1700),
        )
        self.signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))

    def test_non_chain_type_error(self):
        for bad in ("x", None, 42, b"x", object(), self.items):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_hdsc(bad)

    def test_non_tuple_items_type_error(self):
        for bad in (list(self.items), iter(self.items), None, "items"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_hdsc(HistoryDeltaSegmentsSealChain(bad, self.signature))

    def test_non_seal_element_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_hdsc(
                    HistoryDeltaSegmentsSealChain((bad,), self.signature)
                )
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_hdsc(
                    HistoryDeltaSegmentsSealChain(
                        (self.items[0], bad), self.signature
                    )
                )

    def test_empty_chain_value_error(self):
        with self.assertRaises(ValueError):
            encode_hdsc(HistoryDeltaSegmentsSealChain((), self.signature))

    def test_illegal_nested_seal_value_error(self):
        bad_seal = HistoryDeltaSegmentsSeal((), self.signature)
        with self.assertRaises(ValueError):
            encode_hdsc(
                HistoryDeltaSegmentsSealChain((bad_seal,), self.signature)
            )
        with self.assertRaises(ValueError):
            encode_hdsc(
                HistoryDeltaSegmentsSealChain(
                    (self.items[0], bad_seal), self.signature
                )
            )

    def test_nested_seal_field_type_error(self):
        bad_seal = HistoryDeltaSegmentsSeal("not-segments", self.signature)
        with self.assertRaises(TypeError):
            encode_hdsc(
                HistoryDeltaSegmentsSealChain((bad_seal,), self.signature)
            )

    def test_illegal_outer_signature_value_error(self):
        bad_signatures = (
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=-1, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=-1, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=7, signer_ids=()),
            AggregateSignature(R=5, z=7, signer_ids=(0, 1)),
            AggregateSignature(R=5, z=7, signer_ids=(3, 1)),
            AggregateSignature(R=5, z=7, signer_ids=(1, 1)),
        )
        for bad in bad_signatures:
            with self.assertRaises(ValueError, msg=repr(bad)):
                encode_hdsc(HistoryDeltaSegmentsSealChain(self.items, bad))

    def test_bad_outer_signature_field_type_error(self):
        for bad in ("x", None, 5.0, True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_hdsc(HistoryDeltaSegmentsSealChain(self.items, bad))


class DecodeSealChainErrorTest(unittest.TestCase):
    def setUp(self):
        self.key, _delta, self.segments = build_segments()
        self.items = (
            make_seal(self.segments[:2], self.key, seed=1800),
            make_seal(self.segments[2:], self.key, seed=1801),
        )
        self.chain = make_chain(self.items, self.key, seed=1802)
        self.blob = encode_hdsc(self.chain)
        self.frames = [encode_hds(item) for item in self.items]

    def test_non_bytes_type_error(self):
        for bad in (
            self.blob.decode("latin1"),
            bytearray(self.blob),
            None,
            42,
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                decode_hdsc(bad)

    def test_bad_tag(self):
        swap = b"ts/hdsc/w0"
        with self.assertRaises(ValueError):
            decode_hdsc(swap + self.blob[len(WIRE_TAG):])
        with self.assertRaises(ValueError):
            decode_hdsc(b"")
        with self.assertRaises(ValueError):
            decode_hdsc(self.blob[3:])

    def test_zero_item_count_is_illegal(self):
        with self.assertRaises(ValueError):
            decode_hdsc(
                WIRE_TAG
                + u32(0)
                + signature_frame(self.chain.signature)
            )

    def test_truncated_item_count(self):
        with self.assertRaises(ValueError):
            decode_hdsc(WIRE_TAG)
        with self.assertRaises(ValueError):
            decode_hdsc(
                WIRE_TAG + self.blob[len(WIRE_TAG):len(WIRE_TAG) + 2]
            )

    def test_zero_or_overlong_seal_frame(self):
        # A zero-length first frame.
        with self.assertRaises(ValueError):
            decode_hdsc(
                WIRE_TAG
                + u32(1)
                + u32(0)
                + signature_frame(self.chain.signature)
            )
        # A declared frame longer than the bytes that follow.
        with self.assertRaises(ValueError):
            decode_hdsc(
                WIRE_TAG
                + u32(1)
                + u32(len(self.frames[0]) + 1)
                + self.frames[0]
                + signature_frame(self.chain.signature)
            )

    def test_item_count_mismatch(self):
        # Count says two items but only one seal frame precedes the
        # outer signature frame, so parsing runs off the end.
        with self.assertRaises(ValueError):
            decode_hdsc(
                WIRE_TAG
                + u32(2)
                + u32(len(self.frames[0]))
                + self.frames[0]
                + signature_frame(self.chain.signature)
            )

    def test_truncation(self):
        for cut in range(len(WIRE_TAG), len(self.blob)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_hdsc(self.blob[:cut])

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_hdsc(self.blob + b"\x00")

    def test_illegal_nested_seal_frame(self):
        # A nested seal frame that wraps an empty segment set is
        # rejected by the nested seal decoder even though the outer
        # framing lines up.
        empty_segments = SEGMENTS_TAG + u32(0)
        signature = self.chain.signature
        bad_seal_blob = (
            SEAL_WIRE_TAG
            + u32(len(empty_segments))
            + empty_segments
            + signature_frame(signature)
        )
        bad = (
            WIRE_TAG
            + u32(1)
            + u32(len(bad_seal_blob))
            + bad_seal_blob
            + signature_frame(signature)
        )
        with self.assertRaises(ValueError):
            decode_hdsc(bad)

    def test_non_canonical_nested_seal_frame(self):
        # A nested seal whose inner segment-set count is flipped no
        # longer re-encodes canonically.
        encoded_segments = encode_history_delta_segments(self.segments[:1])
        count_offset = len(SEGMENTS_TAG)
        bad_inner = (
            encoded_segments[:count_offset]
            + u32(99)
            + encoded_segments[count_offset + 4:]
        )
        signature = self.chain.signature
        bad_seal_blob = (
            SEAL_WIRE_TAG
            + u32(len(bad_inner))
            + bad_inner
            + signature_frame(signature)
        )
        bad = (
            WIRE_TAG
            + u32(1)
            + u32(len(bad_seal_blob))
            + bad_seal_blob
            + signature_frame(signature)
        )
        with self.assertRaises(ValueError):
            decode_hdsc(bad)

    def test_tampered_nested_seal_frame(self):
        tampered = bytearray(self.blob)
        # First seal frame body starts after tag, count and its length.
        tampered[len(WIRE_TAG) + 4 + 4 + 5] ^= 0x01
        with self.assertRaises(ValueError):
            decode_hdsc(bytes(tampered))

    def test_zero_R_is_illegal(self):
        bad = (
            WIRE_TAG
            + u32(len(self.frames))
            + b"".join(u32(len(frame)) + frame for frame in self.frames)
            + varint(0)
            + varint(self.chain.signature.z)
            + u32(len(self.chain.signature.signer_ids))
            + b"".join(
                varint(sid) for sid in self.chain.signature.signer_ids
            )
        )
        with self.assertRaises(ValueError):
            decode_hdsc(bad)

    def test_non_canonical_leading_zero_integer(self):
        # Lengthen the outer R body to two bytes with a leading 00.
        prefix = (
            WIRE_TAG
            + u32(len(self.frames))
            + b"".join(u32(len(frame)) + frame for frame in self.frames)
        )
        bad = bytearray(
            prefix
            + varint(self.chain.signature.R)
            + varint(self.chain.signature.z)
            + u32(len(self.chain.signature.signer_ids))
            + b"".join(
                varint(sid) for sid in self.chain.signature.signer_ids
            )
        )
        offset = len(prefix)
        r_body = self.chain.signature.R.to_bytes(
            (self.chain.signature.R.bit_length() + 7) // 8, "big"
        )
        bad[offset:offset + 4 + len(r_body)] = (
            u32(len(r_body) + 1) + b"\x00" + r_body
        )
        with self.assertRaises(ValueError):
            decode_hdsc(bytes(bad))

    def test_zero_signer_count_is_illegal(self):
        bad = (
            WIRE_TAG
            + u32(len(self.frames))
            + b"".join(u32(len(frame)) + frame for frame in self.frames)
            + varint(self.chain.signature.R)
            + varint(self.chain.signature.z)
            + u32(0)
        )
        with self.assertRaises(ValueError):
            decode_hdsc(bad)

    def test_signer_count_mismatch(self):
        bad = (
            WIRE_TAG
            + u32(len(self.frames))
            + b"".join(u32(len(frame)) + frame for frame in self.frames)
            + varint(self.chain.signature.R)
            + varint(self.chain.signature.z)
            + u32(3)
            + b"".join(
                varint(sid) for sid in self.chain.signature.signer_ids
            )
        )
        with self.assertRaises(ValueError):
            decode_hdsc(bad)

    def test_non_increasing_signer_ids(self):
        bad = (
            WIRE_TAG
            + u32(len(self.frames))
            + b"".join(u32(len(frame)) + frame for frame in self.frames)
            + varint(self.chain.signature.R)
            + varint(self.chain.signature.z)
            + u32(2)
            + varint(3)
            + varint(1)
        )
        with self.assertRaises(ValueError):
            decode_hdsc(bad)

    def test_short_garbage(self):
        with self.assertRaises(ValueError):
            decode_hdsc(WIRE_TAG + u32(1) + b"x")


if __name__ == "__main__":
    unittest.main()
