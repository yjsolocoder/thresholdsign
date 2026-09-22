"""Tests for the canonical AuditExtensionDeltaCheckpointChain transport
encoding: encode_audit_extension_delta_checkpoint_chain /
decode_audit_extension_delta_checkpoint_chain /
verify_audit_extension_delta_checkpoint_chain."""

import unittest

from thresholdsign import (
    AggregateSignature,
    AuditExtensionDeltaCheckpointChain,
    AuditExtensionProof,
    decode_audit_extension_delta_checkpoint_chain,
    encode_audit_extension_delta_checkpoint_chain,
    encode_extension,
    verify_audit_extension_delta_checkpoint_chain,
)

from test_audit_chain import make_key, sign_message
from test_audit_extension_checkpoint_chain_codec import (
    EXTENSION_TAG,
    linked_chain,
    signature_frame,
    u32,
    varint,
)
from test_audit_extension_delta_checkpoint_chain import make_delta
from test_audit_extension_proof_bundle_codec import make_other_key, make_records

DELTA_TAG = b"ts/aepdcc/v1"


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def build_wire(delta: AuditExtensionDeltaCheckpointChain) -> bytes:
    """Independently build the delta checkpoint-chain wire format."""
    b = len(delta.additions)
    out = bytearray(DELTA_TAG)
    encoded_first = encode_extension(delta.first)
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
        self.records = make_records(self.key, 8)

    def test_honest_chains_round_trip_at_every_length(self):
        seed = 20000
        for m in range(2, 9):
            splits = tuple((i, i + 1) for i in range(1, m))
            delta = make_delta(self.key, self.records[:m], splits, seed=seed)
            seed += 100
            wire = encode_audit_extension_delta_checkpoint_chain(delta)
            decoded = decode_audit_extension_delta_checkpoint_chain(wire)
            self.assertEqual(decoded, delta, msg=f"m={m}")
            self.assertEqual(
                encode_audit_extension_delta_checkpoint_chain(decoded), wire
            )
            self.assertTrue(
                verify_audit_extension_delta_checkpoint_chain(
                    decoded, self.key
                ),
                msg=f"m={m}",
            )

    def test_wider_splits_round_trip_and_verify(self):
        splits = ((2, 4), (4, 5), (5, 8))
        delta = make_delta(self.key, self.records, splits, seed=21000)
        wire = encode_audit_extension_delta_checkpoint_chain(delta)
        self.assertEqual(
            decode_audit_extension_delta_checkpoint_chain(wire), delta
        )
        self.assertTrue(
            verify_audit_extension_delta_checkpoint_chain(delta, self.key)
        )

    def test_zero_batches_single_hop_round_trips(self):
        delta = make_delta(self.key, self.records, [(2, 4)], seed=21100)
        self.assertEqual(delta.additions, ())
        self.assertEqual(len(delta.signatures), 2)
        wire = encode_audit_extension_delta_checkpoint_chain(delta)
        decoded = decode_audit_extension_delta_checkpoint_chain(wire)
        self.assertEqual(decoded, delta)
        self.assertTrue(
            verify_audit_extension_delta_checkpoint_chain(decoded, self.key)
        )

    def test_encoding_matches_independent_builder(self):
        splits = ((2, 4), (4, 5), (5, 7))
        delta = make_delta(self.key, self.records, splits, seed=22000)
        wire = encode_audit_extension_delta_checkpoint_chain(delta)
        self.assertEqual(wire, build_wire(delta))
        self.assertTrue(wire.startswith(DELTA_TAG))
        offset = len(DELTA_TAG)
        encoded_first = encode_extension(delta.first)
        self.assertEqual(wire[offset:offset + 4], u32(len(encoded_first)))
        offset += 4
        self.assertEqual(wire[offset:offset + len(encoded_first)], encoded_first)
        offset += len(encoded_first)
        # Three proofs compact to the first proof plus two batches.
        self.assertEqual(wire[offset:offset + 4], u32(2))

    def test_layout_is_first_frame_then_batches_then_bare_sig_frames(self):
        splits = ((1, 3), (3, 6))
        delta = make_delta(self.key, self.records, splits, seed=22100)
        wire = encode_audit_extension_delta_checkpoint_chain(delta)
        offset = len(DELTA_TAG)
        encoded_first = encode_extension(delta.first)
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
        self.assertEqual(bytes(wire[offset:offset + 32 * len(batch)]),
                         b"".join(batch))
        offset += 32 * len(batch)
        # The remaining b+2 signature frames are bare AuditProofBundle
        # signature frames with no extra wrapping.
        for signature in delta.signatures:
            frame_bytes = signature_frame(signature)
            self.assertEqual(
                wire[offset:offset + len(frame_bytes)], frame_bytes
            )
            offset += len(frame_bytes)
        self.assertEqual(offset, len(wire))

    def test_signature_frame_count_is_batches_plus_two(self):
        delta = make_delta(
            self.key, self.records, ((1, 3), (3, 5), (5, 7)), seed=22150
        )
        self.assertEqual(len(delta.signatures), len(delta.additions) + 2)
        wire = encode_audit_extension_delta_checkpoint_chain(delta)
        self.assertEqual(
            decode_audit_extension_delta_checkpoint_chain(wire), delta
        )

    def test_encoding_is_unique_and_stateless(self):
        delta = make_delta(
            self.key, self.records, ((1, 3), (3, 5)), seed=22200
        )
        self.assertEqual(
            encode_audit_extension_delta_checkpoint_chain(delta),
            encode_audit_extension_delta_checkpoint_chain(delta),
        )


class StructureOnlyTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = make_records(self.key, 6)

    def test_decode_does_not_check_signatures(self):
        # Structurally legal delta chain with one foreign signature at the
        # first checkpoint decodes byte-for-byte and verifies False.
        delta = make_delta(self.key, self.records, [(2, 4), (4, 6)])
        other = make_other_key()
        bad = sign_message(other, b"unrelated", seed=5)
        tampered = AuditExtensionDeltaCheckpointChain(
            delta.first, delta.additions, (bad,) + delta.signatures[1:]
        )
        decoded = decode_audit_extension_delta_checkpoint_chain(
            encode_audit_extension_delta_checkpoint_chain(tampered)
        )
        self.assertEqual(decoded, tampered)
        self.assertFalse(
            verify_audit_extension_delta_checkpoint_chain(decoded, self.key)
        )

    def test_honest_chain_wrong_key_decodes_but_fails_verification(self):
        other = make_other_key()
        delta = make_delta(
            self.key, self.records, ((1, 3), (3, 5)), seed=23000
        )
        self.assertTrue(encode_audit_extension_delta_checkpoint_chain(delta))
        self.assertFalse(
            verify_audit_extension_delta_checkpoint_chain(delta, other)
        )


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = make_records(self.key, 6)
        self.delta = make_delta(
            self.key, self.records, ((2, 4), (4, 6)), seed=24000
        )

    def test_non_chain_type_error(self):
        plain = linked_chain(
            self.key, self.records, ((2, 4), (4, 6)), seed=24000
        )
        for bad in (
            ("x", "y", "z"),
            [self.delta.first],
            None,
            plain,
            "delta",
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_audit_extension_delta_checkpoint_chain(bad)

    def test_non_tuple_fields_type_error(self):
        with self.assertRaises(TypeError):
            encode_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    self.delta.first,
                    list(self.delta.additions),
                    self.delta.signatures,
                )
            )
        with self.assertRaises(TypeError):
            encode_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    self.delta.first,
                    self.delta.additions,
                    list(self.delta.signatures),
                )
            )

    def test_non_first_proof_element_type_error(self):
        with self.assertRaises(TypeError):
            encode_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    "not a proof",
                    self.delta.additions,
                    self.delta.signatures,
                )
            )

    def test_non_tuple_batch_type_error(self):
        with self.assertRaises(TypeError):
            encode_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    self.delta.first,
                    (list(self.delta.additions[0]),),
                    self.delta.signatures,
                )
            )

    def test_non_bytes_digest_type_error(self):
        with self.assertRaises(TypeError):
            encode_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    self.delta.first,
                    ((1, 2),),
                    self.delta.signatures,
                )
            )

    def test_non_signature_element_type_error(self):
        with self.assertRaises(TypeError):
            encode_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    self.delta.first,
                    self.delta.additions,
                    self.delta.signatures[:-1] + ("x",),
                )
            )

    def test_empty_batch_value_error(self):
        with self.assertRaises(ValueError):
            encode_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    self.delta.first, ((),), self.delta.signatures
                )
            )

    def test_digest_wrong_width_value_error(self):
        bad_batch = ((b"x" * 31,),)
        with self.assertRaises(ValueError):
            encode_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    self.delta.first, bad_batch, self.delta.signatures
                )
            )

    def test_signature_count_mismatch_value_error(self):
        with self.assertRaises(ValueError):
            encode_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    self.delta.first,
                    self.delta.additions,
                    self.delta.signatures[:-1],
                )
            )
        with self.assertRaises(ValueError):
            encode_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    self.delta.first,
                    self.delta.additions,
                    self.delta.signatures + (self.delta.signatures[0],),
                )
            )

    def test_illegal_nested_proof_value_error(self):
        bad_first = AuditExtensionProof(0, self.delta.first.leaves)
        with self.assertRaises(ValueError):
            encode_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    bad_first, (), self.delta.signatures[:2]
                )
            )

    def test_illegal_nested_signature_value_error(self):
        bad_sig = AggregateSignature(R=0, z=7, signer_ids=(1, 3))
        with self.assertRaises(ValueError):
            encode_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    self.delta.first,
                    (),
                    (bad_sig, self.delta.signatures[1]),
                )
            )


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = make_records(self.key, 6)
        self.delta = make_delta(
            self.key, self.records, ((2, 4), (4, 6)), seed=25000
        )
        self.wire = encode_audit_extension_delta_checkpoint_chain(self.delta)

    def test_non_bytes_type_error(self):
        with self.assertRaises(TypeError):
            decode_audit_extension_delta_checkpoint_chain("not bytes")
        with self.assertRaises(TypeError):
            decode_audit_extension_delta_checkpoint_chain(
                bytearray(self.wire)
            )

    def test_bad_tag(self):
        rest = self.wire[len(DELTA_TAG):]
        with self.assertRaises(ValueError):
            decode_audit_extension_delta_checkpoint_chain(
                b"ts/aepdcc/v2" + rest
            )
        with self.assertRaises(ValueError):
            decode_audit_extension_delta_checkpoint_chain(
                b"x" + self.wire[1:]
            )

    def test_truncation(self):
        for cut in range(len(DELTA_TAG), len(self.wire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_audit_extension_delta_checkpoint_chain(self.wire[:cut])

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_audit_extension_delta_checkpoint_chain(
                self.wire + b"\x00"
            )

    def test_zero_first_frame_length_rejected(self):
        rest = self.wire[len(DELTA_TAG) + 4:]
        bad = DELTA_TAG + u32(0) + rest
        with self.assertRaises(ValueError):
            decode_audit_extension_delta_checkpoint_chain(bad)

    def test_declared_first_frame_length_mismatch(self):
        encoded_first = encode_extension(self.delta.first)
        rest = self.wire[len(DELTA_TAG) + 4 + len(encoded_first):]
        bad = DELTA_TAG + u32(len(encoded_first) - 1) + encoded_first + rest
        with self.assertRaises(ValueError):
            decode_audit_extension_delta_checkpoint_chain(bad)

    def test_junk_nested_first_proof_rejected(self):
        bad = DELTA_TAG + frame(b"not-an-extension") + u32(0)
        # The zero-batch chain still needs its two signature frames; the
        # junk nested proof must be rejected regardless.
        with self.assertRaises(ValueError):
            decode_audit_extension_delta_checkpoint_chain(bad)

    def test_nested_non_canonical_encoding_rejected(self):
        encoded_first = encode_extension(self.delta.first)
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
            decode_audit_extension_delta_checkpoint_chain(bad)

    def test_declared_batch_count_too_large_then_truncated(self):
        # Claim three batches but supply only two.
        prefix = self.wire[: len(DELTA_TAG) + 4 + len(
            encode_extension(self.delta.first)
        )]
        bad = prefix + u32(3) + self.wire[len(prefix) + 4:]
        with self.assertRaises(ValueError):
            decode_audit_extension_delta_checkpoint_chain(bad)

    def test_declared_batch_count_too_small_leaves_trailing_bytes(self):
        delta = make_delta(
            self.key, self.records, ((2, 4), (4, 5), (5, 6)), seed=25100
        )
        first = delta.first
        batch0, batch1 = delta.additions
        sig_frames = b"".join(
            signature_frame(sig) for sig in delta.signatures
        )
        bad = b"".join(
            [
                DELTA_TAG,
                frame(encode_extension(first)),
                u32(1),
                u32(len(batch0)),
                b"".join(batch0),
                u32(len(batch1)),
                b"".join(batch1),
                sig_frames,
            ]
        )
        with self.assertRaises(ValueError):
            decode_audit_extension_delta_checkpoint_chain(bad)

    def test_zero_digest_count_batch_rejected(self):
        first = self.delta.first
        other_batch = self.delta.additions[0]
        # One declared batch with m=0 followed by enough bytes to show the
        # rejection is the zero count itself, not mere truncation.
        bad = b"".join(
            [
                DELTA_TAG,
                frame(encode_extension(first)),
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
            decode_audit_extension_delta_checkpoint_chain(bad)

    def test_batch_digest_wrong_width_rejected(self):
        # Hand-built wire with a 31-byte "digest" inside the last batch; the
        # declared m*32 span runs into the signature frames and must fail.
        first = self.delta.first
        good_batch = self.delta.additions[0]
        bad = b"".join(
            [
                DELTA_TAG,
                frame(encode_extension(first)),
                u32(2),
                u32(len(good_batch)),
                b"".join(good_batch),
                u32(1),
                b"x" * 31,
                b"".join(
                    signature_frame(sig) for sig in self.delta.signatures
                ),
            ]
        )
        with self.assertRaises(ValueError):
            decode_audit_extension_delta_checkpoint_chain(bad)

    def test_missing_signature_frame_rejected(self):
        # Claim zero batches (two signature frames) but supply only one.
        first = self.delta.first
        bad = b"".join(
            [
                DELTA_TAG,
                frame(encode_extension(first)),
                u32(0),
                signature_frame(self.delta.signatures[0]),
            ]
        )
        with self.assertRaises(ValueError):
            decode_audit_extension_delta_checkpoint_chain(bad)

    def test_extra_signature_frame_rejected(self):
        # Claim zero batches but supply three signature frames.
        first = self.delta.first
        bad = b"".join(
            [
                DELTA_TAG,
                frame(encode_extension(first)),
                u32(0),
                b"".join(
                    signature_frame(sig)
                    for sig in self.delta.signatures
                ),
            ]
        )
        with self.assertRaises(ValueError):
            decode_audit_extension_delta_checkpoint_chain(bad)

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
                frame(encode_extension(first)),
                u32(0),
                signature_frame(good_sig),
                zero_R_frame,
            ]
        )
        with self.assertRaises(ValueError):
            decode_audit_extension_delta_checkpoint_chain(blob)


class VerifyValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = make_records(self.key, 6)
        self.delta = make_delta(
            self.key, self.records, ((2, 4), (4, 6)), seed=26000
        )

    def test_non_chain_type_error(self):
        for bad in (
            (self.delta.first, self.delta.additions, self.delta.signatures),
            None,
            "delta",
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_audit_extension_delta_checkpoint_chain(bad, self.key)

    def test_non_tuple_fields_type_error(self):
        with self.assertRaises(TypeError):
            verify_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    self.delta.first,
                    list(self.delta.additions),
                    self.delta.signatures,
                ),
                self.key,
            )

    def test_non_signature_element_type_error(self):
        with self.assertRaises(TypeError):
            verify_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    self.delta.first,
                    self.delta.additions,
                    self.delta.signatures[:-1] + ("x",),
                ),
                self.key,
            )

    def test_empty_batch_value_error(self):
        with self.assertRaises(ValueError):
            verify_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    self.delta.first, ((),), self.delta.signatures
                ),
                self.key,
            )

    def test_signature_count_mismatch_value_error(self):
        with self.assertRaises(ValueError):
            verify_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    self.delta.first,
                    self.delta.additions,
                    self.delta.signatures[:-1],
                ),
                self.key,
            )

    def test_illegal_nested_proof_value_error(self):
        bad_first = AuditExtensionProof(0, self.delta.first.leaves)
        with self.assertRaises(ValueError):
            verify_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    bad_first, (), self.delta.signatures[:2]
                ),
                self.key,
            )

    def test_illegal_nested_signature_value_error(self):
        bad_sig = AggregateSignature(R=0, z=7, signer_ids=(1, 3))
        with self.assertRaises(ValueError):
            verify_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    self.delta.first,
                    (),
                    (bad_sig, self.delta.signatures[1]),
                ),
                self.key,
            )


if __name__ == "__main__":
    unittest.main()
