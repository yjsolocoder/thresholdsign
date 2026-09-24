"""Tests for the canonical SealHistoryExtensionDeltaChain transport
encoding: encode_history_delta / decode_history_delta and the
expand-then-verify verify_history_delta entry point."""

import unittest

from thresholdsign import (
    AggregateSignature,
    SealHistoryExtension,
    SealHistoryExtensionDeltaChain,
    decode_history_delta,
    encode_history_delta,
    encode_history_extension,
    verify_history_delta,
)

from test_nonce_reuse import make_key
from test_nonce_leak_codec import make_other_key
from test_seal_history import sign_message
from test_seal_history_extension import history_of_size
from test_seal_history_extension_delta_chain import linked_chain, linked_delta
from test_seal_history_extension_bundle_codec import (
    EXTENSION_TAG,
    frame,
    signature_frame,
    u32,
    varint,
)

DELTA_TAG = b"ts/shed/v1"


def build_wire(delta: SealHistoryExtensionDeltaChain) -> bytes:
    """Independently build the delta chain wire format straight from the
    spec."""
    b = len(delta.additions)
    out = bytearray(DELTA_TAG)
    encoded_first = encode_history_extension(delta.first)
    out += frame(encoded_first)
    out += u32(b)
    for batch in delta.additions:
        out += u32(len(batch))
        for digest in batch:
            out += digest
    assert len(delta.signatures) == b + 2
    for signature in delta.signatures:
        out += signature_frame(signature)
    return bytes(out)


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = history_of_size(self.key, 8)

    def test_honest_chains_round_trip_at_every_length(self):
        seed = 30000
        for m in range(2, 9):
            splits = tuple((i, i + 1) for i in range(1, m))
            delta = linked_delta(self.key, self.history, splits, seed=seed)
            seed += 100
            wire = encode_history_delta(delta)
            decoded = decode_history_delta(wire)
            self.assertEqual(decoded, delta, msg=f"m={m}")
            self.assertEqual(encode_history_delta(decoded), wire)
            self.assertTrue(
                verify_history_delta(decoded, self.key), msg=f"m={m}"
            )

    def test_wider_splits_round_trip_and_verify(self):
        splits = ((2, 4), (4, 5), (5, 8))
        delta = linked_delta(self.key, self.history, splits, seed=31000)
        wire = encode_history_delta(delta)
        self.assertEqual(decode_history_delta(wire), delta)
        self.assertTrue(verify_history_delta(delta, self.key))

    def test_zero_batches_single_hop_round_trips(self):
        delta = linked_delta(self.key, self.history, ((2, 4),), seed=31100)
        self.assertEqual(delta.additions, ())
        self.assertEqual(len(delta.signatures), 2)
        wire = encode_history_delta(delta)
        decoded = decode_history_delta(wire)
        self.assertEqual(decoded, delta)
        self.assertTrue(verify_history_delta(decoded, self.key))

    def test_encoding_matches_independent_builder(self):
        splits = ((2, 4), (4, 5), (5, 7))
        delta = linked_delta(self.key, self.history, splits, seed=32000)
        wire = encode_history_delta(delta)
        self.assertEqual(wire, build_wire(delta))
        self.assertTrue(wire.startswith(DELTA_TAG))
        offset = len(DELTA_TAG)
        encoded_first = encode_history_extension(delta.first)
        self.assertEqual(wire[offset:offset + 4], u32(len(encoded_first)))
        offset += 4
        self.assertEqual(wire[offset:offset + len(encoded_first)], encoded_first)
        offset += len(encoded_first)
        # Three hops compact to the first extension plus two batches.
        self.assertEqual(wire[offset:offset + 4], u32(2))

    def test_layout_is_first_frame_then_batches_then_bare_sig_frames(self):
        splits = ((1, 3), (3, 6))
        delta = linked_delta(self.key, self.history, splits, seed=32100)
        wire = encode_history_delta(delta)
        offset = len(DELTA_TAG)
        encoded_first = encode_history_extension(delta.first)
        self.assertEqual(wire[offset:offset + 4], u32(len(encoded_first)))
        offset += 4
        self.assertEqual(
            wire[offset:offset + len(EXTENSION_TAG)], EXTENSION_TAG
        )
        offset += len(encoded_first)
        # One batch-count u32, then U32(m) and m raw 32-byte digests.
        self.assertEqual(wire[offset:offset + 4], u32(1))
        offset += 4
        (batch,) = delta.additions
        self.assertEqual(wire[offset:offset + 4], u32(len(batch)))
        offset += 4
        self.assertEqual(
            bytes(wire[offset:offset + 32 * len(batch)]),
            b"".join(batch),
        )
        offset += 32 * len(batch)
        # The remaining b+2 signature frames are bare canonical bundle
        # signature frames with no extra wrapping.
        for signature in delta.signatures:
            frame_bytes = signature_frame(signature)
            self.assertEqual(
                wire[offset:offset + len(frame_bytes)], frame_bytes
            )
            offset += len(frame_bytes)
        self.assertEqual(offset, len(wire))

    def test_signature_frame_count_is_batches_plus_two(self):
        delta = linked_delta(
            self.key, self.history, ((1, 3), (3, 5), (5, 7)), seed=32150
        )
        self.assertEqual(len(delta.signatures), len(delta.additions) + 2)
        wire = encode_history_delta(delta)
        self.assertEqual(decode_history_delta(wire), delta)

    def test_encoding_is_unique_and_stateless(self):
        delta = linked_delta(
            self.key, self.history, ((1, 3), (3, 5)), seed=32200
        )
        self.assertEqual(
            encode_history_delta(delta), encode_history_delta(delta)
        )

    def test_delta_wire_is_shorter_than_self_contained_chain_wire(self):
        from thresholdsign import encode_history_extension_bundle_chain

        splits = ((1, 3), (3, 5), (5, 8))
        plain = linked_chain(self.key, self.history, splits, seed=32300)
        delta = linked_delta(self.key, self.history, splits, seed=32300)
        self.assertLess(
            len(encode_history_delta(delta)),
            len(encode_history_extension_bundle_chain(plain)),
        )


class StructureOnlyTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = history_of_size(self.key, 6)

    def test_decode_does_not_check_signatures_or_linkage(self):
        # Structurally legal delta chain with one foreign signature at the
        # first checkpoint decodes byte-for-byte and verifies False.
        delta = linked_delta(
            self.key, self.history, ((2, 4), (4, 6)), seed=33000
        )
        other = make_other_key()
        bad = sign_message(b"unrelated", other, seed=5)
        tampered = SealHistoryExtensionDeltaChain(
            delta.first, delta.additions, (bad,) + delta.signatures[1:]
        )
        decoded = decode_history_delta(encode_history_delta(tampered))
        self.assertEqual(decoded, tampered)
        self.assertFalse(verify_history_delta(decoded, self.key))

    def test_unlinked_batches_decode_but_verify_false(self):
        # A hand-built delta chain whose second batch does not continue the
        # first hop's leaves: structurally legal on the wire, false on
        # verification via the expanded chain's linkage check.
        delta = linked_delta(
            self.key, self.history, ((2, 4), (4, 6)), seed=33100
        )
        bogus_batch = ((b"z" * 32, b"y" * 32),)
        tampered = SealHistoryExtensionDeltaChain(
            delta.first, bogus_batch, delta.signatures
        )
        decoded = decode_history_delta(encode_history_delta(tampered))
        self.assertEqual(decoded, tampered)
        self.assertFalse(verify_history_delta(decoded, self.key))

    def test_honest_chain_wrong_key_decodes_but_fails_verification(self):
        other = make_other_key()
        delta = linked_delta(
            self.key, self.history, ((1, 3), (3, 5)), seed=33200
        )
        self.assertTrue(encode_history_delta(delta))
        self.assertFalse(verify_history_delta(delta, other))


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = history_of_size(self.key, 6)
        self.delta = linked_delta(
            self.key, self.history, ((2, 4), (4, 6)), seed=34000
        )

    def test_non_chain_type_error(self):
        plain = linked_chain(
            self.key, self.history, ((2, 4), (4, 6)), seed=34000
        )
        for bad in (
            ("x", "y", "z"),
            [self.delta.first],
            None,
            plain,
            "delta",
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_history_delta(bad)

    def test_non_tuple_fields_type_error(self):
        with self.assertRaises(TypeError):
            encode_history_delta(
                SealHistoryExtensionDeltaChain(
                    self.delta.first,
                    list(self.delta.additions),
                    self.delta.signatures,
                )
            )
        with self.assertRaises(TypeError):
            encode_history_delta(
                SealHistoryExtensionDeltaChain(
                    self.delta.first,
                    self.delta.additions,
                    list(self.delta.signatures),
                )
            )

    def test_non_first_extension_type_error(self):
        with self.assertRaises(TypeError):
            encode_history_delta(
                SealHistoryExtensionDeltaChain(
                    "not an extension",
                    self.delta.additions,
                    self.delta.signatures,
                )
            )

    def test_non_tuple_batch_type_error(self):
        with self.assertRaises(TypeError):
            encode_history_delta(
                SealHistoryExtensionDeltaChain(
                    self.delta.first,
                    (list(self.delta.additions[0]),),
                    self.delta.signatures,
                )
            )

    def test_non_bytes_digest_type_error(self):
        with self.assertRaises(TypeError):
            encode_history_delta(
                SealHistoryExtensionDeltaChain(
                    self.delta.first,
                    ((1, 2),),
                    self.delta.signatures,
                )
            )

    def test_non_signature_element_type_error(self):
        with self.assertRaises(TypeError):
            encode_history_delta(
                SealHistoryExtensionDeltaChain(
                    self.delta.first,
                    self.delta.additions,
                    self.delta.signatures[:-1] + ("x",),
                )
            )

    def test_empty_batch_value_error(self):
        with self.assertRaises(ValueError):
            encode_history_delta(
                SealHistoryExtensionDeltaChain(
                    self.delta.first, ((),), self.delta.signatures
                )
            )

    def test_digest_wrong_width_value_error(self):
        with self.assertRaises(ValueError):
            encode_history_delta(
                SealHistoryExtensionDeltaChain(
                    self.delta.first,
                    (((b"x" * 31),),),
                    self.delta.signatures,
                )
            )

    def test_signature_count_mismatch_value_error(self):
        with self.assertRaises(ValueError):
            encode_history_delta(
                SealHistoryExtensionDeltaChain(
                    self.delta.first,
                    self.delta.additions,
                    self.delta.signatures[:-1],
                )
            )
        with self.assertRaises(ValueError):
            encode_history_delta(
                SealHistoryExtensionDeltaChain(
                    self.delta.first,
                    self.delta.additions,
                    self.delta.signatures + (self.delta.signatures[0],),
                )
            )

    def test_illegal_nested_extension_value_error(self):
        bad_first = SealHistoryExtension(0, self.delta.first.leaves)
        with self.assertRaises(ValueError):
            encode_history_delta(
                SealHistoryExtensionDeltaChain(
                    bad_first, (), self.delta.signatures[:2]
                )
            )

    def test_illegal_nested_signature_value_error(self):
        bad_sig = AggregateSignature(R=0, z=7, signer_ids=(1, 3))
        with self.assertRaises(ValueError):
            encode_history_delta(
                SealHistoryExtensionDeltaChain(
                    self.delta.first,
                    (),
                    (bad_sig, self.delta.signatures[1]),
                )
            )


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = history_of_size(self.key, 6)
        self.delta = linked_delta(
            self.key, self.history, ((2, 4), (4, 6)), seed=35000
        )
        self.wire = encode_history_delta(self.delta)

    def test_non_bytes_type_error(self):
        with self.assertRaises(TypeError):
            decode_history_delta("not bytes")
        with self.assertRaises(TypeError):
            decode_history_delta(bytearray(self.wire))

    def test_bad_tag(self):
        rest = self.wire[len(DELTA_TAG):]
        with self.assertRaises(ValueError):
            decode_history_delta(b"ts/shed/v2" + rest)
        with self.assertRaises(ValueError):
            decode_history_delta(b"x" + self.wire[1:])

    def test_truncation(self):
        for cut in range(len(DELTA_TAG), len(self.wire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_history_delta(self.wire[:cut])

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_history_delta(self.wire + b"\x00")

    def test_zero_first_frame_length_rejected(self):
        rest = self.wire[len(DELTA_TAG) + 4:]
        bad = DELTA_TAG + u32(0) + rest
        with self.assertRaises(ValueError):
            decode_history_delta(bad)

    def test_declared_first_frame_length_mismatch(self):
        encoded_first = encode_history_extension(self.delta.first)
        rest = self.wire[len(DELTA_TAG) + 4 + len(encoded_first):]
        bad = (
            DELTA_TAG
            + u32(len(encoded_first) - 1)
            + encoded_first
            + rest
        )
        with self.assertRaises(ValueError):
            decode_history_delta(bad)

    def test_junk_nested_first_extension_rejected(self):
        bad = DELTA_TAG + frame(b"not-an-extension") + u32(0)
        # The zero-batch chain still needs its two signature frames; the
        # junk nested extension must be rejected regardless.
        with self.assertRaises(ValueError):
            decode_history_delta(bad)

    def test_nested_non_canonical_encoding_rejected(self):
        encoded_first = encode_history_extension(self.delta.first)
        tampered = b"x" + encoded_first[1:]
        bad = b"".join(
            [
                DELTA_TAG,
                frame(tampered),
                u32(0),
                signature_frame(self.delta.signatures[0]),
                signature_frame(self.delta.signatures[1]),
            ]
        )
        with self.assertRaises(ValueError):
            decode_history_delta(bad)

    def test_nested_bad_old_total_rejected(self):
        # Frame the nested extension bytes with an out-of-range old_total.
        encoded_first = encode_history_extension(self.delta.first)
        tag_len = len(EXTENSION_TAG)
        tampered = (
            encoded_first[:tag_len]
            + (0).to_bytes(8, "big")
            + encoded_first[tag_len + 8:]
        )
        bad = b"".join(
            [
                DELTA_TAG,
                frame(tampered),
                u32(0),
                signature_frame(self.delta.signatures[0]),
                signature_frame(self.delta.signatures[1]),
            ]
        )
        with self.assertRaises(ValueError):
            decode_history_delta(bad)

    def test_declared_batch_count_too_large_then_truncated(self):
        # Claim three batches but supply only two.
        prefix = self.wire[
            : len(DELTA_TAG) + 4 + len(
                encode_history_extension(self.delta.first)
            )
        ]
        bad = prefix + u32(3) + self.wire[len(prefix) + 4:]
        with self.assertRaises(ValueError):
            decode_history_delta(bad)

    def test_declared_batch_count_too_small_leaves_trailing_bytes(self):
        delta = linked_delta(
            self.key, self.history, ((2, 4), (4, 5), (5, 6)), seed=35100
        )
        first = delta.first
        batch0, batch1 = delta.additions
        sig_frames = b"".join(
            signature_frame(sig) for sig in delta.signatures
        )
        bad = b"".join(
            [
                DELTA_TAG,
                frame(encode_history_extension(first)),
                u32(1),
                u32(len(batch0)),
                b"".join(batch0),
                u32(len(batch1)),
                b"".join(batch1),
                sig_frames,
            ]
        )
        with self.assertRaises(ValueError):
            decode_history_delta(bad)

    def test_zero_leaf_count_batch_rejected(self):
        first = self.delta.first
        other_batch = self.delta.additions[0]
        # One declared batch with m=0 followed by enough bytes to show the
        # rejection is the zero count itself, not mere truncation.
        bad = b"".join(
            [
                DELTA_TAG,
                frame(encode_history_extension(first)),
                u32(1),
                u32(0),
                u32(len(other_batch)),
                b"".join(other_batch),
                signature_frame(self.delta.signatures[0]),
                signature_frame(self.delta.signatures[1]),
                signature_frame(self.delta.signatures[2]),
            ]
        )
        with self.assertRaises(ValueError):
            decode_history_delta(bad)

    def test_batch_truncated_leaves_rejected(self):
        # Declare a batch of the true width but chop its leaves short.
        first = self.delta.first
        (good_batch,) = self.delta.additions
        bad = b"".join(
            [
                DELTA_TAG,
                frame(encode_history_extension(first)),
                u32(1),
                u32(len(good_batch)),
                b"".join(good_batch)[:-1],
            ]
        )
        with self.assertRaises(ValueError):
            decode_history_delta(bad)

    def test_missing_signature_frame_rejected(self):
        # Claim zero batches (two signature frames) but supply only one.
        first = self.delta.first
        bad = b"".join(
            [
                DELTA_TAG,
                frame(encode_history_extension(first)),
                u32(0),
                signature_frame(self.delta.signatures[0]),
            ]
        )
        with self.assertRaises(ValueError):
            decode_history_delta(bad)

    def test_extra_signature_frame_rejected(self):
        # Claim zero batches but supply three signature frames.
        first = self.delta.first
        bad = b"".join(
            [
                DELTA_TAG,
                frame(encode_history_extension(first)),
                u32(0),
                b"".join(
                    signature_frame(sig) for sig in self.delta.signatures
                ),
            ]
        )
        with self.assertRaises(ValueError):
            decode_history_delta(bad)

    def test_bad_nested_signature_frame_rejected(self):
        first = self.delta.first
        good_sig = self.delta.signatures[0]
        zero_R_frame = (
            varint(0)
            + varint(good_sig.z)
            + u32(len(good_sig.signer_ids))
            + b"".join(varint(sid) for sid in good_sig.signer_ids)
        )
        blob = b"".join(
            [
                DELTA_TAG,
                frame(encode_history_extension(first)),
                u32(0),
                signature_frame(good_sig),
                zero_R_frame,
            ]
        )
        with self.assertRaises(ValueError):
            decode_history_delta(blob)


class VerifyValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = history_of_size(self.key, 6)
        self.delta = linked_delta(
            self.key, self.history, ((2, 4), (4, 6)), seed=36000
        )

    def test_non_chain_type_error(self):
        for bad in (
            (self.delta.first, self.delta.additions, self.delta.signatures),
            None,
            "delta",
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_history_delta(bad, self.key)

    def test_non_tuple_fields_type_error(self):
        with self.assertRaises(TypeError):
            verify_history_delta(
                SealHistoryExtensionDeltaChain(
                    self.delta.first,
                    list(self.delta.additions),
                    self.delta.signatures,
                ),
                self.key,
            )

    def test_non_signature_element_type_error(self):
        with self.assertRaises(TypeError):
            verify_history_delta(
                SealHistoryExtensionDeltaChain(
                    self.delta.first,
                    self.delta.additions,
                    self.delta.signatures[:-1] + ("x",),
                ),
                self.key,
            )

    def test_empty_batch_value_error(self):
        with self.assertRaises(ValueError):
            verify_history_delta(
                SealHistoryExtensionDeltaChain(
                    self.delta.first, ((),), self.delta.signatures
                ),
                self.key,
            )

    def test_signature_count_mismatch_value_error(self):
        with self.assertRaises(ValueError):
            verify_history_delta(
                SealHistoryExtensionDeltaChain(
                    self.delta.first,
                    self.delta.additions,
                    self.delta.signatures[:-1],
                ),
                self.key,
            )

    def test_illegal_nested_extension_value_error(self):
        bad_first = SealHistoryExtension(0, self.delta.first.leaves)
        with self.assertRaises(ValueError):
            verify_history_delta(
                SealHistoryExtensionDeltaChain(
                    bad_first, (), self.delta.signatures[:2]
                ),
                self.key,
            )

    def test_illegal_nested_signature_value_error(self):
        bad_sig = AggregateSignature(R=0, z=7, signer_ids=(1, 3))
        with self.assertRaises(ValueError):
            verify_history_delta(
                SealHistoryExtensionDeltaChain(
                    self.delta.first,
                    (),
                    (bad_sig, self.delta.signatures[1]),
                ),
                self.key,
            )

    def test_bad_key_type_error(self):
        with self.assertRaises(TypeError):
            verify_history_delta(self.delta, "key")


if __name__ == "__main__":
    unittest.main()
