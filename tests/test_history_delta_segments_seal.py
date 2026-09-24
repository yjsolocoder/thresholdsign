"""Tests for the threshold-Schnorr-authenticated whole segment-set archive
seal: HistoryDeltaSegmentsSeal / hds_message / encode_hds / decode_hds /
verify_hds."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    HistoryDeltaSegmentsSeal,
    SealHistoryExtensionDeltaChain,
    aggregate_signature,
    create_signature_share,
    create_signing_nonce_commitment,
    create_signing_round,
    decode_hds,
    decode_history_delta_segments,
    encode_hds,
    encode_history_delta,
    encode_history_delta_segments,
    hds_message,
    verify_hds,
    verify_signature,
)

from test_nonce_reuse import (
    FIELD_PRIME,
    GENERATOR,
    GROUP_PRIME,
    fixed_random,
    make_key,
)
from test_nonce_leak_codec import make_other_key
from test_seal_history_extension import history_of_size
from test_seal_history_extension_delta_chain import linked_delta
from test_history_delta_segments_codec import build_segments

MESSAGE_TAG = b"ts/hds/m1"
WIRE_TAG = b"ts/hds/w1"
SEGMENTS_TAG = b"thresholdsign/history-delta-segments/v1"


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def build_message(segments, public_key: int) -> bytes:
    """Independently build the sealed message straight from the spec."""
    encoded = encode_history_delta_segments(segments)
    return MESSAGE_TAG + hashlib.sha256(encoded).digest() + varint(public_key)


def build_wire(seal: HistoryDeltaSegmentsSeal) -> bytes:
    """Independently build the hds wire format straight from the spec."""
    encoded_segments = encode_history_delta_segments(seal.segments)
    signature = seal.signature
    out = bytearray(WIRE_TAG)
    out += u32(len(encoded_segments))
    out += encoded_segments
    out += varint(signature.R)
    out += varint(signature.z)
    out += u32(len(signature.signer_ids))
    for signer_id in signature.signer_ids:
        out += varint(signer_id)
    return bytes(out)


def make_seal(segments, key, signer_ids=(1, 3), seed=700) -> HistoryDeltaSegmentsSeal:
    """Seal ``segments`` with a real threshold signature of ``key``."""
    message = hds_message(segments, key.public_key)
    commitments = []
    nonce_map = {}
    for index, signer_id in enumerate(signer_ids):
        commitment, nonce = create_signing_nonce_commitment(
            signer_id,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            randbelow=fixed_random(seed + index),
        )
        commitments.append(commitment)
        nonce_map[signer_id] = nonce
    round_info = create_signing_round(message, signer_ids, commitments, key)
    shares = [
        create_signature_share(
            signer_id,
            key.result.shares[key.result.participant_ids.index(signer_id)].y,
            nonce_map[signer_id],
            round_info,
            key,
        )
        for signer_id in signer_ids
    ]
    signature = aggregate_signature(shares, round_info, key)
    assert isinstance(signature, AggregateSignature)
    return HistoryDeltaSegmentsSeal(segments, signature)


class HistoryDeltaSegmentsSealValueTest(unittest.TestCase):
    def test_frozen_fields_value_equality(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(HistoryDeltaSegmentsSeal)],
            ["segments", "signature"],
        )
        key, delta, segments = build_segments()
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        seal = HistoryDeltaSegmentsSeal(segments, signature)  # positional
        self.assertEqual(seal, HistoryDeltaSegmentsSeal(segments, signature))
        self.assertEqual(
            seal,
            HistoryDeltaSegmentsSeal(segments=segments, signature=signature),
        )
        self.assertEqual(seal.segments, segments)
        self.assertEqual(seal.signature, signature)
        self.assertEqual(hash(seal), hash(HistoryDeltaSegmentsSeal(segments, signature)))
        # Order matters.
        self.assertNotEqual(
            seal, HistoryDeltaSegmentsSeal(tuple(reversed(segments)), signature)
        )
        with self.assertRaises(FrozenInstanceError):
            seal.segments = segments

    def test_construction_does_not_validate(self):
        # The container is a plain value: illegal segments and a bad
        # signature both construct; the codec and verifier reject them.
        HistoryDeltaSegmentsSeal((), AggregateSignature(0, -1, ()))
        HistoryDeltaSegmentsSeal("not-segments", "not-a-signature")


class HdsMessageTest(unittest.TestCase):
    def setUp(self):
        self.key, self.delta, self.segments = build_segments()

    def test_matches_independent_builder(self):
        self.assertEqual(
            hds_message(self.segments, self.key.public_key),
            build_message(self.segments, self.key.public_key),
        )

    def test_layout(self):
        message = hds_message(self.segments, self.key.public_key)
        self.assertTrue(message.startswith(MESSAGE_TAG))
        offset = len(MESSAGE_TAG)
        encoded = encode_history_delta_segments(self.segments)
        self.assertEqual(message[offset:offset + 32], hashlib.sha256(encoded).digest())
        offset += 32
        length = int.from_bytes(message[offset:offset + 4], "big")
        self.assertEqual(
            message[offset + 4:],
            self.key.public_key.to_bytes(length, "big"),
        )
        self.assertEqual(len(message), offset + 4 + length)

    def test_zero_public_key_encodes_as_single_zero_byte(self):
        message = hds_message(self.segments, 0)
        self.assertEqual(message[len(MESSAGE_TAG) + 32:], u32(1) + b"\x00")

    def test_message_is_unique_and_stateless(self):
        first = hds_message(self.segments, self.key.public_key)
        second = hds_message(self.segments, self.key.public_key)
        self.assertEqual(first, second)
        self.assertNotEqual(
            first, hds_message(self.segments, self.key.public_key + 1)
        )

    def test_binds_the_segment_encoding(self):
        other = (self.segments[0],)
        self.assertNotEqual(
            hds_message(self.segments, self.key.public_key),
            hds_message(other, self.key.public_key),
        )
        self.assertNotEqual(
            hds_message(self.segments, self.key.public_key),
            hds_message(tuple(reversed(self.segments)), self.key.public_key),
        )

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            hds_message(list(self.segments), self.key.public_key)
        with self.assertRaises(TypeError):
            hds_message("segments", self.key.public_key)
        with self.assertRaises(TypeError):
            hds_message(("not-a-chain",), self.key.public_key)
        with self.assertRaises(TypeError):
            hds_message(self.segments, "key")
        with self.assertRaises(TypeError):
            hds_message(self.segments, True)

    def test_structure_errors(self):
        with self.assertRaises(ValueError):
            hds_message((), self.key.public_key)
        bad_segment = SealHistoryExtensionDeltaChain(
            self.segments[0].first,
            self.segments[0].additions,
            self.segments[0].signatures[:-1],
        )
        with self.assertRaises(ValueError):
            hds_message((bad_segment,), self.key.public_key)
        with self.assertRaises(ValueError):
            hds_message(self.segments, -1)


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key, self.delta, self.segments = build_segments()
        self.seal = make_seal(self.segments, self.key)

    def test_round_trip_real_seal(self):
        wire = encode_hds(self.seal)
        decoded = decode_hds(wire)
        self.assertEqual(decoded, self.seal)
        self.assertEqual(encode_hds(decoded), wire)
        self.assertIsInstance(decoded, HistoryDeltaSegmentsSeal)
        self.assertIsInstance(decoded.segments, tuple)
        self.assertIsInstance(decoded.signature, AggregateSignature)

    def test_encoding_matches_independent_builder(self):
        self.assertEqual(encode_hds(self.seal), build_wire(self.seal))

    def test_starts_with_tag_and_layout(self):
        wire = encode_hds(self.seal)
        self.assertTrue(wire.startswith(WIRE_TAG))
        offset = len(WIRE_TAG)
        encoded = encode_history_delta_segments(self.segments)
        self.assertEqual(wire[offset:offset + 4], u32(len(encoded)))
        offset += 4
        self.assertEqual(wire[offset:offset + len(encoded)], encoded)
        offset += len(encoded)
        signature = self.seal.signature
        suffix = (
            varint(signature.R)
            + varint(signature.z)
            + u32(len(signature.signer_ids))
            + b"".join(varint(i) for i in signature.signer_ids)
        )
        self.assertEqual(wire[offset:], suffix)
        self.assertEqual(len(wire), offset + len(suffix))

    def test_inner_bytes_are_the_existing_segment_set_encoding(self):
        wire = encode_hds(self.seal)
        offset = len(WIRE_TAG)
        length = int.from_bytes(wire[offset:offset + 4], "big")
        offset += 4
        inner = wire[offset:offset + length]
        self.assertEqual(
            decode_history_delta_segments(bytes(inner)), self.segments
        )

    def test_single_segment_round_trip(self):
        single = (self.segments[0],)
        seal = make_seal(single, self.key, seed=800)
        wire = encode_hds(seal)
        decoded = decode_hds(wire)
        self.assertEqual(decoded, seal)
        self.assertEqual(encode_hds(decoded), wire)

    def test_large_signature_integers_round_trip(self):
        signature = AggregateSignature(
            R=(1 << 256) - 77,
            z=(1 << 200) + 9,
            signer_ids=(1, 3, (1 << 64) + 5),
        )
        seal = HistoryDeltaSegmentsSeal(self.segments, signature)
        decoded = decode_hds(encode_hds(seal))
        self.assertEqual(decoded, seal)

    def test_zero_z_round_trips(self):
        seal = HistoryDeltaSegmentsSeal(
            self.segments, AggregateSignature(R=486, z=0, signer_ids=(1, 3))
        )
        wire = encode_hds(seal)
        self.assertEqual(decode_hds(wire), seal)

    def test_seams_are_not_checked_on_decode(self):
        # Two individually legal segments that do not sit in chain order
        # still decode; join_history_delta_segments rejects them, but the
        # seal codec does not care.
        shuffled = (self.segments[2], self.segments[0])
        seal = HistoryDeltaSegmentsSeal(
            shuffled, AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        )
        decoded = decode_hds(encode_hds(seal))
        self.assertEqual(decoded, seal)


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key, self.delta, self.segments = build_segments()
        self.signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))

    def test_non_seal_type_error(self):
        with self.assertRaises(TypeError):
            encode_hds((self.segments, self.signature))
        with self.assertRaises(TypeError):
            encode_hds(self.segments)

    def test_field_type_errors(self):
        for bad_seal in (
            HistoryDeltaSegmentsSeal("segments", self.signature),
            HistoryDeltaSegmentsSeal(list(self.segments), self.signature),
            HistoryDeltaSegmentsSeal(("x",), self.signature),
            HistoryDeltaSegmentsSeal(self.segments, "signature"),
            HistoryDeltaSegmentsSeal(
                self.segments, AggregateSignature(True, 7, (1, 3))
            ),
            HistoryDeltaSegmentsSeal(
                self.segments, AggregateSignature(5, True, (1, 3))
            ),
            HistoryDeltaSegmentsSeal(
                self.segments, AggregateSignature(5, 7, [1, 3])
            ),
            HistoryDeltaSegmentsSeal(
                self.segments, AggregateSignature(5, 7, (1, True))
            ),
        ):
            with self.assertRaises(TypeError, msg=repr(bad_seal)):
                encode_hds(bad_seal)

    def test_empty_segments_value_error(self):
        with self.assertRaises(ValueError):
            encode_hds(HistoryDeltaSegmentsSeal((), self.signature))

    def test_nested_segment_value_error(self):
        bad_segment = SealHistoryExtensionDeltaChain(
            self.segments[0].first,
            self.segments[0].additions,
            self.segments[0].signatures[:-1],
        )
        with self.assertRaises(ValueError):
            encode_hds(HistoryDeltaSegmentsSeal((bad_segment,), self.signature))

    def test_signature_structure_value_error(self):
        for bad_signature in (
            AggregateSignature(0, 7, (1, 3)),      # R must be positive
            AggregateSignature(-1, 7, (1, 3)),
            AggregateSignature(5, -1, (1, 3)),     # z non-negative
            AggregateSignature(5, 7, ()),          # at least one signer
            AggregateSignature(5, 7, (0, 3)),      # positive ids
            AggregateSignature(5, 7, (3, 1)),      # ascending
            AggregateSignature(5, 7, (1, 1)),      # unique
        ):
            with self.assertRaises(ValueError, msg=repr(bad_signature)):
                encode_hds(
                    HistoryDeltaSegmentsSeal(self.segments, bad_signature)
                )


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key, self.delta, self.segments = build_segments()
        self.seal = make_seal(self.segments, self.key)
        self.wire = encode_hds(self.seal)

    def test_non_bytes_type_error(self):
        for bad in (self.wire.decode("latin1"), bytearray(self.wire), None, 42):
            with self.assertRaises(TypeError, msg=repr(bad)):
                decode_hds(bad)

    def test_bad_tag(self):
        with self.assertRaises(ValueError):
            decode_hds(b"ts/hds/w2" + self.wire[len(WIRE_TAG):])
        with self.assertRaises(ValueError):
            decode_hds(b"x" + self.wire[1:])
        with self.assertRaises(ValueError):
            decode_hds(b"")

    def test_truncation(self):
        for cut in range(len(WIRE_TAG), len(self.wire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_hds(self.wire[:cut])

    def test_header_truncation(self):
        with self.assertRaises(ValueError):
            decode_hds(WIRE_TAG)
        with self.assertRaises(ValueError):
            decode_hds(WIRE_TAG + b"\x00\x00")

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_hds(self.wire + b"\x00")

    def test_zero_or_oversized_segment_frame(self):
        offset = len(WIRE_TAG)
        with self.assertRaises(ValueError):
            decode_hds(self.wire[:offset] + u32(0))
        with self.assertRaises(ValueError):
            decode_hds(
                self.wire[:offset] + u32(0xFFFFFFFF) + b"a"
            )

    def test_segment_frame_truncated(self):
        encoded = encode_history_delta_segments(self.segments)
        with self.assertRaises(ValueError):
            decode_hds(
                self.wire[:len(WIRE_TAG)]
                + u32(len(encoded))
                + encoded[:-1]
                + self._signature_suffix()
            )

    def _signature_suffix(self) -> bytes:
        signature = self.seal.signature
        out = varint(signature.R) + varint(signature.z)
        out += u32(len(signature.signer_ids))
        for signer_id in signature.signer_ids:
            out += varint(signer_id)
        return out

    def test_nested_segments_bad_tag_rejected(self):
        with self.assertRaises(ValueError):
            decode_hds(WIRE_TAG + frame(b"thresholdsign/history-delta-segments/v2"))

    def test_nested_segments_non_canonical_rejected(self):
        encoded = encode_history_delta_segments(self.segments)
        # Flip the declared segment count so the inner framing no longer
        # lines up / re-encodes canonically.
        count_offset = len(SEGMENTS_TAG)
        bad = (
            encoded[:count_offset]
            + u32(99)
            + encoded[count_offset + 4:]
        )
        with self.assertRaises(ValueError):
            decode_hds(WIRE_TAG + frame(bad) + self._signature_suffix())

    def test_declared_count_does_not_match_frames(self):
        # Inner segment set declares two segments but contains one frame.
        one = encode_history_delta_segments((self.segments[0],))
        frame0 = encode_history_delta(self.segments[0])
        bad_inner = SEGMENTS_TAG + u32(2) + u32(len(frame0)) + frame0
        self.assertNotEqual(bad_inner, one)
        with self.assertRaises(ValueError):
            decode_hds(WIRE_TAG + frame(bad_inner) + self._signature_suffix())

    def test_zero_R_rejected(self):
        encoded = encode_history_delta_segments(self.segments)
        bad = (
            WIRE_TAG
            + frame(encoded)
            + varint(0)
            + varint(7)
            + u32(2)
            + varint(1)
            + varint(3)
        )
        with self.assertRaises(ValueError):
            decode_hds(bad)

    def test_non_canonical_varint_rejected(self):
        encoded = encode_history_delta_segments(self.segments)
        bad = (
            WIRE_TAG
            + frame(encoded)
            + u32(2) + b"\x00\x05"
            + varint(7)
            + u32(1)
            + varint(1)
        )
        with self.assertRaises(ValueError):
            decode_hds(bad)

    def test_zero_signer_count_rejected(self):
        encoded = encode_history_delta_segments(self.segments)
        bad = WIRE_TAG + frame(encoded) + varint(5) + varint(7) + u32(0)
        with self.assertRaises(ValueError):
            decode_hds(bad)

    def test_signer_count_mismatch_rejected(self):
        encoded = encode_history_delta_segments(self.segments)
        head = WIRE_TAG + frame(encoded) + varint(5) + varint(7)
        # Declares two ids, one follows.
        with self.assertRaises(ValueError):
            decode_hds(head + u32(2) + varint(1))
        # Declares one id, two follow (the second varint becomes trailing).
        with self.assertRaises(ValueError):
            decode_hds(head + u32(1) + varint(1) + varint(3))

    def test_unordered_duplicate_or_zero_ids_rejected(self):
        encoded = encode_history_delta_segments(self.segments)
        head = WIRE_TAG + frame(encoded) + varint(5) + varint(7)
        for ids in ((3, 1), (1, 1), (0, 3)):
            body = head + u32(len(ids)) + b"".join(varint(i) for i in ids)
            with self.assertRaises(ValueError, msg=repr(ids)):
                decode_hds(body)


class VerifyHdsTest(unittest.TestCase):
    def setUp(self):
        self.key, self.delta, self.segments = build_segments()
        self.seal = make_seal(self.segments, self.key)

    def test_real_seal_verifies(self):
        self.assertTrue(verify_hds(self.seal, self.key))

    def test_decoded_seal_verifies(self):
        decoded = decode_hds(encode_hds(self.seal))
        self.assertTrue(verify_hds(decoded, self.key))

    def test_hds_message_is_what_the_signature_covers(self):
        self.assertTrue(
            verify_signature(
                hds_message(self.segments, self.key.public_key),
                self.seal.signature,
                self.key.public_key,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            )
        )

    def test_dropped_segment_returns_false(self):
        self.assertFalse(
            verify_hds(
                HistoryDeltaSegmentsSeal(
                    self.segments[:-1], self.seal.signature
                ),
                self.key,
            )
        )

    def test_inserted_segment_returns_false(self):
        extra = self.segments + (self.segments[0],)
        self.assertFalse(
            verify_hds(
                HistoryDeltaSegmentsSeal(extra, self.seal.signature),
                self.key,
            )
        )

    def test_reordered_segments_returns_false(self):
        self.assertFalse(
            verify_hds(
                HistoryDeltaSegmentsSeal(
                    tuple(reversed(self.segments)), self.seal.signature
                ),
                self.key,
            )
        )

    def test_tampered_signature_returns_false(self):
        tampered = dataclasses.replace(
            self.seal.signature, z=(self.seal.signature.z + 1) % FIELD_PRIME
        )
        self.assertFalse(
            verify_hds(
                HistoryDeltaSegmentsSeal(self.segments, tampered), self.key
            )
        )

    def test_signature_over_another_segment_set_returns_false(self):
        other_key = make_other_key()
        other_history = history_of_size(other_key, 5)
        splits = [(2, 3), (3, 5)]
        other_delta = linked_delta(other_key, other_history, splits)
        from thresholdsign import partition_history_delta

        other_segments = partition_history_delta(other_delta, (1,))
        other_seal = make_seal(other_segments, other_key, seed=1100)
        self.assertTrue(verify_hds(other_seal, other_key))
        # A genuine signature over a different set does not seal this one.
        self.assertFalse(
            verify_hds(
                HistoryDeltaSegmentsSeal(
                    self.segments, other_seal.signature
                ),
                self.key,
            )
        )

    def test_foreign_key_returns_false(self):
        other_key = make_other_key()
        self.assertNotEqual(other_key.public_key, self.key.public_key)
        self.assertFalse(verify_hds(self.seal, other_key))

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            verify_hds((self.segments, self.seal.signature), self.key)
        with self.assertRaises(TypeError):
            verify_hds("seal", self.key)
        with self.assertRaises(TypeError):
            verify_hds(
                HistoryDeltaSegmentsSeal(self.segments, "signature"), self.key
            )
        with self.assertRaises(TypeError):
            verify_hds(self.seal, "key")
        with self.assertRaises(TypeError):
            verify_hds(self.seal, None)

    def test_structure_errors(self):
        with self.assertRaises(ValueError):
            verify_hds(
                HistoryDeltaSegmentsSeal((), self.seal.signature),
                self.key,
            )
        with self.assertRaises(ValueError):
            verify_hds(
                HistoryDeltaSegmentsSeal(
                    self.segments, AggregateSignature(0, 7, (1, 3))
                ),
                self.key,
            )
        with self.assertRaises(ValueError):
            verify_hds(
                HistoryDeltaSegmentsSeal(
                    self.segments, AggregateSignature(5, 7, ())
                ),
                self.key,
            )


if __name__ == "__main__":
    unittest.main()
