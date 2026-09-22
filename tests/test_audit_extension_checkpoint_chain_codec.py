"""Tests for the canonical AuditExtensionCheckpointChain transport encoding:
encode_audit_extension_checkpoint_chain /
decode_audit_extension_checkpoint_chain /
verify_audit_extension_checkpoint_chain."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    AuditExtensionCheckpointChain,
    AuditExtensionProof,
    AuditExtensionProofBundle,
    decode_audit_extension_checkpoint_chain,
    encode_audit_extension_checkpoint_chain,
    encode_extension,
    make_extension,
    verify_audit_extension_checkpoint_chain,
)

from test_audit_chain import make_key, make_record, sign_message
from test_audit_extension_proof_bundle_codec import (
    make_other_key,
    make_records,
)

CHAIN_TAG = b"ts/aepcc/v1"
EXTENSION_TAG = b"thresholdsign/audit-extension/v1"


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def signature_frame(signature) -> bytes:
    out = bytearray()
    out += varint(signature.R)
    out += varint(signature.z)
    out += u32(len(signature.signer_ids))
    for signer_id in signature.signer_ids:
        out += varint(signer_id)
    return bytes(out)


def build_wire(chain: AuditExtensionCheckpointChain) -> bytes:
    """Independently build the checkpoint-chain wire format from the spec."""
    n = len(chain.proofs)
    out = bytearray(CHAIN_TAG)
    out += u32(n)
    for proof in chain.proofs:
        out += frame(encode_extension(proof))
    assert len(chain.signatures) == n + 1
    for signature in chain.signatures:
        out += signature_frame(signature)
    return bytes(out)


def make_hop(key, records, old_n, *, seed=800):
    """Return (proof, old_sig, new_sig) for one signed consistency hop."""
    old_message, new_message, proof = make_extension(records, old_n)
    old_sig = sign_message(key, old_message, seed=seed)
    new_sig = sign_message(key, new_message, seed=seed + 1)
    return proof, old_sig, new_sig


def linked_chain(key, records, splits, *, seed=9000):
    """Build a checkpoint chain whose proofs link along the growing splits.

    The n+1 checkpoint signatures are the first hop's old-root signature
    followed by every hop's new-root signature; a linking chain signs the
    same root statement at the shared checkpoint.
    """
    proofs = []
    signatures = []
    for index, (old_n, new_n) in enumerate(splits):
        proof, old_sig, new_sig = make_hop(
            key, records[:new_n], old_n, seed=seed
        )
        proofs.append(proof)
        if index == 0:
            signatures.append(old_sig)
        signatures.append(new_sig)
        seed += 10
    return AuditExtensionCheckpointChain(tuple(proofs), tuple(signatures))


class ChainDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [
                field.name
                for field in dataclasses.fields(AuditExtensionCheckpointChain)
            ],
            ["proofs", "signatures"],
        )
        proof = AuditExtensionProof(1, (b"a" * 32, b"b" * 32))
        old_sig = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        new_sig = AggregateSignature(R=9, z=11, signer_ids=(2, 4))
        chain = AuditExtensionCheckpointChain((proof,), (old_sig, new_sig))
        self.assertEqual(chain.proofs, (proof,))
        self.assertEqual(chain.signatures, (old_sig, new_sig))
        self.assertEqual(
            AuditExtensionCheckpointChain(
                proofs=(proof,), signatures=(old_sig, new_sig)
            ),
            chain,
        )

    def test_frozen_value_equality_and_hash(self):
        first = AuditExtensionProof(1, (b"a" * 32, b"b" * 32))
        second = AuditExtensionProof(
            2, (b"a" * 32, b"b" * 32, b"c" * 32)
        )
        sig0 = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        sig1 = AggregateSignature(R=6, z=8, signer_ids=(1, 3))
        sig2 = AggregateSignature(R=9, z=11, signer_ids=(2, 4))
        chain = AuditExtensionCheckpointChain(
            (first, second), (sig0, sig1, sig2)
        )
        same = AuditExtensionCheckpointChain(
            (first, second), (sig0, sig1, sig2)
        )
        self.assertEqual(chain, same)
        self.assertEqual(hash(chain), hash(same))
        self.assertNotEqual(
            chain,
            AuditExtensionCheckpointChain((first,), (sig0, sig1)),
        )
        self.assertNotEqual(
            chain,
            AuditExtensionCheckpointChain(
                (first, second), (sig0, sig2, sig1)
            ),
        )
        with self.assertRaises(FrozenInstanceError):
            chain.proofs = (first,)

    def test_construction_does_not_validate(self):
        # A plain frozen value: codec and verifier do the checking.
        proof = AuditExtensionProof(1, (b"a" * 32, b"b" * 32))
        sig = AggregateSignature(R=5, z=7, signer_ids=(1,))
        AuditExtensionCheckpointChain((), ())
        AuditExtensionCheckpointChain(("not-a-proof",), (sig, sig))
        AuditExtensionCheckpointChain((proof,), (sig,))  # wrong sig count
        AuditExtensionCheckpointChain(None, None)


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = make_records(self.key, 8)

    def test_honest_chains_round_trip_at_every_length(self):
        seed = 10000
        # Every prefix chain 1 -> 2 -> ... -> m for m in 2..8.
        for m in range(2, 9):
            splits = tuple((i, i + 1) for i in range(1, m))
            chain = linked_chain(self.key, self.records[:m], splits, seed=seed)
            seed += 100
            wire = encode_audit_extension_checkpoint_chain(chain)
            decoded = decode_audit_extension_checkpoint_chain(wire)
            self.assertEqual(decoded, chain, msg=f"m={m}")
            self.assertEqual(
                encode_audit_extension_checkpoint_chain(decoded), wire
            )
            self.assertTrue(
                verify_audit_extension_checkpoint_chain(decoded, self.key),
                msg=f"m={m}",
            )

    def test_wider_splits_round_trip_and_verify(self):
        splits = ((1, 3), (3, 5), (5, 8))
        chain = linked_chain(self.key, self.records, splits, seed=11000)
        wire = encode_audit_extension_checkpoint_chain(chain)
        self.assertEqual(decode_audit_extension_checkpoint_chain(wire), chain)
        self.assertTrue(
            verify_audit_extension_checkpoint_chain(chain, self.key)
        )

    def test_single_proof_chain_round_trips(self):
        proof, old_sig, new_sig = make_hop(
            self.key, self.records[:4], 2, seed=11100
        )
        chain = AuditExtensionCheckpointChain((proof,), (old_sig, new_sig))
        wire = encode_audit_extension_checkpoint_chain(chain)
        decoded = decode_audit_extension_checkpoint_chain(wire)
        self.assertEqual(decoded, chain)
        self.assertTrue(
            verify_audit_extension_checkpoint_chain(decoded, self.key)
        )

    def test_encoding_matches_independent_builder(self):
        splits = ((1, 2), (2, 4), (4, 7))
        chain = linked_chain(self.key, self.records, splits, seed=12000)
        wire = encode_audit_extension_checkpoint_chain(chain)
        self.assertEqual(wire, build_wire(chain))
        self.assertTrue(wire.startswith(CHAIN_TAG))
        self.assertEqual(wire[len(CHAIN_TAG):len(CHAIN_TAG) + 4], u32(3))

    def test_frames_are_existing_extension_encodings_then_bare_sig_frames(self):
        splits = ((1, 3), (3, 6))
        chain = linked_chain(self.key, self.records, splits, seed=12100)
        wire = encode_audit_extension_checkpoint_chain(chain)
        offset = len(CHAIN_TAG) + 4
        for proof in chain.proofs:
            encoded = encode_extension(proof)
            self.assertEqual(wire[offset:offset + 4], u32(len(encoded)))
            offset += 4
            self.assertTrue(
                wire[offset:offset + len(EXTENSION_TAG)] == EXTENSION_TAG
            )
            self.assertEqual(wire[offset:offset + len(encoded)], encoded)
            offset += len(encoded)
        # The remaining n+1 signature frames are bare AuditProofBundle
        # signature frames with no extra wrapping.
        for signature in chain.signatures:
            frame_bytes = signature_frame(signature)
            self.assertEqual(
                wire[offset:offset + len(frame_bytes)], frame_bytes
            )
            offset += len(frame_bytes)
        self.assertEqual(offset, len(wire))

    def test_signature_frame_count_is_proofs_plus_one(self):
        chain = linked_chain(
            self.key, self.records, ((1, 3), (3, 5), (5, 7)), seed=12150
        )
        self.assertEqual(len(chain.signatures), len(chain.proofs) + 1)
        wire = encode_audit_extension_checkpoint_chain(chain)
        self.assertEqual(decode_audit_extension_checkpoint_chain(wire), chain)

    def test_encoding_is_unique_and_stateless(self):
        chain = linked_chain(
            self.key, self.records, ((1, 3), (3, 5)), seed=12200
        )
        self.assertEqual(
            encode_audit_extension_checkpoint_chain(chain),
            encode_audit_extension_checkpoint_chain(chain),
        )


class StructureOnlyTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = make_records(self.key, 6)

    def test_decode_does_not_check_signatures_or_linkage(self):
        # Two individually honest hops over unrelated record sequences;
        # the shared checkpoint signature is taken from the first hop's
        # new root, so the second hop does not verify under it and the
        # leaves do not link either. Decode restores the chain unchanged
        # and the verifier reports False.
        first, _old0, new0 = make_hop(
            self.key, self.records[:4], 2, seed=13100
        )
        other_records = tuple(
            make_record(self.key, b"other-%d" % i, seed=300 + i)
            for i in range(5)
        )
        second, _old1, new1 = make_hop(
            self.key, other_records, 2, seed=13110
        )
        chain = AuditExtensionCheckpointChain(
            (first, second), (new0, new0, new1)
        )
        decoded = decode_audit_extension_checkpoint_chain(
            encode_audit_extension_checkpoint_chain(chain)
        )
        self.assertEqual(decoded, chain)
        self.assertFalse(
            verify_audit_extension_checkpoint_chain(decoded, self.key)
        )

    def test_honest_chain_wrong_key_decodes_but_fails_verification(self):
        other = make_other_key()
        chain = linked_chain(
            self.key, self.records, ((1, 3), (3, 5)), seed=13000
        )
        self.assertTrue(encode_audit_extension_checkpoint_chain(chain))
        self.assertFalse(
            verify_audit_extension_checkpoint_chain(chain, other)
        )


class LinkageTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = make_records(self.key, 8)

    def test_matching_prefixes_link(self):
        chain = linked_chain(
            self.key, self.records, ((2, 4), (4, 6), (6, 8)), seed=14000
        )
        self.assertTrue(
            verify_audit_extension_checkpoint_chain(chain, self.key)
        )

    def test_gap_between_neighbours_returns_false(self):
        # 2 -> 4 then 5 -> 8: the shared checkpoint cannot be both the
        # count-4 new root and the count-5 old root.
        first, old0, new0 = make_hop(
            self.key, self.records[:4], 2, seed=14010
        )
        second, _old1, new1 = make_hop(
            self.key, self.records[:8], 5, seed=14020
        )
        chain = AuditExtensionCheckpointChain(
            (first, second), (old0, new0, new1)
        )
        self.assertFalse(
            verify_audit_extension_checkpoint_chain(chain, self.key)
        )

    def test_overlap_between_neighbours_returns_false(self):
        chain_proofs = linked_chain(
            self.key, self.records, ((2, 5), (3, 8)), seed=14030
        )
        # The proofs' counts do not line up (5 leaves vs old_n 3); the
        # honest signatures cannot repair that.
        self.assertFalse(
            verify_audit_extension_checkpoint_chain(chain_proofs, self.key)
        )

    def test_same_count_but_different_leaves_returns_false(self):
        first, old0, new0 = make_hop(
            self.key, self.records[:4], 2, seed=14100
        )
        other_records = tuple(
            make_record(self.key, b"other-%d" % i, seed=900 + i)
            for i in range(6)
        )
        second, _old1, new1 = make_hop(
            self.key, other_records, 4, seed=14110
        )
        chain = AuditExtensionCheckpointChain(
            (first, second), (old0, new0, new1)
        )
        # Counts line up; the roots (and hence checkpoint statements)
        # differ, so the second hop fails and the leaves do not link.
        self.assertEqual(len(first.leaves), second.old_n)
        self.assertNotEqual(first.leaves, second.leaves[:4])
        self.assertFalse(
            verify_audit_extension_checkpoint_chain(chain, self.key)
        )

    def test_one_foreign_checkpoint_signature_returns_false(self):
        other = make_other_key()
        first, old0, new0 = make_hop(
            self.key, self.records[:4], 2, seed=14200
        )
        second, _old1, new1 = make_hop(
            self.key, self.records[:6], 4, seed=14210
        )
        _, foreign_shared, _foreign_new = make_hop(
            other, self.records[:4], 2, seed=14220
        )
        chain = AuditExtensionCheckpointChain(
            (first, second), (old0, foreign_shared, new1)
        )
        self.assertFalse(
            verify_audit_extension_checkpoint_chain(chain, self.key)
        )
        # Sanity: the all-ours variant verifies.
        self.assertTrue(
            verify_audit_extension_checkpoint_chain(
                AuditExtensionCheckpointChain(
                    (first, second), (old0, new0, new1)
                ),
                self.key,
            )
        )


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = make_records(self.key, 5)
        proof, old_sig, new_sig = make_hop(
            self.key, self.records, 2, seed=15000
        )
        self.proof = proof
        self.old_sig = old_sig
        self.new_sig = new_sig
        self.chain = AuditExtensionCheckpointChain(
            (proof,), (old_sig, new_sig)
        )

    def test_non_chain_type_error(self):
        for bad in (
            ("x", "y"),
            [self.proof],
            None,
            AuditExtensionProofBundle(self.proof, self.old_sig, self.new_sig),
            "chain",
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_audit_extension_checkpoint_chain(bad)

    def test_non_tuple_fields_type_error(self):
        with self.assertRaises(TypeError):
            encode_audit_extension_checkpoint_chain(
                AuditExtensionCheckpointChain(
                    [self.proof], [self.old_sig, self.new_sig]
                )
            )
        with self.assertRaises(TypeError):
            encode_audit_extension_checkpoint_chain(
                AuditExtensionCheckpointChain(
                    (self.proof,), [self.old_sig, self.new_sig]
                )
            )

    def test_non_proof_element_type_error(self):
        for bad in (("x",), (None,), (self.old_sig,)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_audit_extension_checkpoint_chain(
                    AuditExtensionCheckpointChain(
                        bad, (self.old_sig, self.old_sig, self.new_sig)
                    )
                )

    def test_non_signature_element_type_error(self):
        for bad in (
            ("x", self.new_sig),
            (None, self.new_sig),
            (self.proof, self.new_sig),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_audit_extension_checkpoint_chain(
                    AuditExtensionCheckpointChain(
                        (self.proof, self.proof), bad
                    )
                )

    def test_empty_proofs_value_error(self):
        with self.assertRaises(ValueError):
            encode_audit_extension_checkpoint_chain(
                AuditExtensionCheckpointChain((), ())
            )

    def test_signature_count_mismatch_value_error(self):
        # Too few signatures.
        with self.assertRaises(ValueError):
            encode_audit_extension_checkpoint_chain(
                AuditExtensionCheckpointChain(
                    (self.proof,), (self.old_sig,)
                )
            )
        # Too many signatures.
        with self.assertRaises(ValueError):
            encode_audit_extension_checkpoint_chain(
                AuditExtensionCheckpointChain(
                    (self.proof,), (self.old_sig, self.new_sig, self.new_sig)
                )
            )
        # Two proofs still require exactly three signatures.
        with self.assertRaises(ValueError):
            encode_audit_extension_checkpoint_chain(
                AuditExtensionCheckpointChain(
                    (self.proof, self.proof),
                    (self.old_sig, self.new_sig, self.new_sig, self.new_sig),
                )
            )

    def test_illegal_nested_proof_value_error(self):
        bad_proof = AuditExtensionProof(0, (b"a" * 32, b"b" * 32))
        with self.assertRaises(ValueError):
            encode_audit_extension_checkpoint_chain(
                AuditExtensionCheckpointChain(
                    (bad_proof,), (self.old_sig, self.new_sig)
                )
            )

    def test_illegal_nested_signature_value_error(self):
        bad_sig = AggregateSignature(R=0, z=7, signer_ids=(1, 3))
        with self.assertRaises(ValueError):
            encode_audit_extension_checkpoint_chain(
                AuditExtensionCheckpointChain(
                    (self.proof,), (bad_sig, self.new_sig)
                )
            )


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = make_records(self.key, 6)
        self.chain = linked_chain(
            self.key, self.records, ((1, 3), (3, 5)), seed=16000
        )
        self.wire = encode_audit_extension_checkpoint_chain(self.chain)

    def test_non_bytes_type_error(self):
        with self.assertRaises(TypeError):
            decode_audit_extension_checkpoint_chain("not bytes")
        with self.assertRaises(TypeError):
            decode_audit_extension_checkpoint_chain(bytearray(self.wire))

    def test_bad_tag(self):
        rest = self.wire[len(CHAIN_TAG):]
        with self.assertRaises(ValueError):
            decode_audit_extension_checkpoint_chain(b"ts/aepcc/v2" + rest)
        with self.assertRaises(ValueError):
            decode_audit_extension_checkpoint_chain(b"x" + self.wire[1:])

    def test_truncation(self):
        for cut in range(len(CHAIN_TAG), len(self.wire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_audit_extension_checkpoint_chain(self.wire[:cut])

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_audit_extension_checkpoint_chain(self.wire + b"\x00")

    def test_zero_count_rejected(self):
        with self.assertRaises(ValueError):
            decode_audit_extension_checkpoint_chain(CHAIN_TAG + u32(0))

    def test_declared_count_too_large_then_truncated(self):
        body = self.wire[len(CHAIN_TAG) + 4:]
        bad = CHAIN_TAG + u32(3) + body
        with self.assertRaises(ValueError):
            decode_audit_extension_checkpoint_chain(bad)

    def test_declared_count_too_small_leaves_trailing_bytes(self):
        # Declare one proof but keep both proof frames and all three
        # signature frames.
        proof_frames = b"".join(
            frame(encode_extension(proof)) for proof in self.chain.proofs
        )
        sig_frames = b"".join(
            signature_frame(sig) for sig in self.chain.signatures
        )
        bad = CHAIN_TAG + u32(1) + proof_frames + sig_frames
        with self.assertRaises(ValueError):
            decode_audit_extension_checkpoint_chain(bad)

    def test_missing_signature_frame_rejected(self):
        # Declare two proofs but supply only two of the three sig frames.
        proof_frames = b"".join(
            frame(encode_extension(proof)) for proof in self.chain.proofs
        )
        sig_frames = b"".join(
            signature_frame(sig) for sig in self.chain.signatures[:2]
        )
        bad = CHAIN_TAG + u32(2) + proof_frames + sig_frames
        with self.assertRaises(ValueError):
            decode_audit_extension_checkpoint_chain(bad)

    def test_extra_signature_frame_rejected(self):
        proof_frames = b"".join(
            frame(encode_extension(proof)) for proof in self.chain.proofs
        )
        sig_frames = b"".join(
            signature_frame(sig) for sig in self.chain.signatures
        )
        bad = (
            CHAIN_TAG
            + u32(2)
            + proof_frames
            + sig_frames
            + signature_frame(self.chain.signatures[0])
        )
        with self.assertRaises(ValueError):
            decode_audit_extension_checkpoint_chain(bad)

    def test_zero_frame_length_rejected(self):
        first_body = encode_extension(self.chain.proofs[0])
        rest = self.wire[
            len(CHAIN_TAG) + 4 + 4 + len(first_body):
        ]
        bad = CHAIN_TAG + u32(2) + u32(0) + first_body + rest
        with self.assertRaises(ValueError):
            decode_audit_extension_checkpoint_chain(bad)

    def test_junk_nested_frame_rejected(self):
        bad = CHAIN_TAG + u32(1) + frame(b"not-an-extension")
        # The single proof still needs its two signature frames; the junk
        # nested proof must be rejected by decode_extension regardless.
        with self.assertRaises(ValueError):
            decode_audit_extension_checkpoint_chain(bad)

    def test_declared_frame_length_mismatch(self):
        first_body = encode_extension(self.chain.proofs[0])
        rest = self.wire[
            len(CHAIN_TAG) + 4 + 4 + len(first_body):
        ]
        bad = (
            CHAIN_TAG
            + u32(2)
            + u32(len(first_body) - 1)
            + first_body
            + rest
        )
        with self.assertRaises(ValueError):
            decode_audit_extension_checkpoint_chain(bad)

    def test_nested_non_canonical_encoding_rejected(self):
        # Flip a byte inside the nested extension tag: the nested decoder
        # must reject it rather than the chain swallowing the error.
        proof_body = encode_extension(self.chain.proofs[0])
        tampered = b"x" + proof_body[1:]
        bad = (
            CHAIN_TAG
            + u32(1)
            + frame(tampered)
            + signature_frame(self.chain.signatures[0])
            + signature_frame(self.chain.signatures[1])
        )
        with self.assertRaises(ValueError):
            decode_audit_extension_checkpoint_chain(bad)

    def test_bad_nested_signature_frame_rejected(self):
        # A zero R in the second signature frame is a structural error
        # the chain decoder must surface rather than skip.
        proof = self.chain.proofs[0]
        good_sig = self.chain.signatures[0]
        zero_R_frame = (
            varint(0)
            + varint(good_sig.z)
            + u32(len(good_sig.signer_ids))
            + b"".join(varint(sid) for sid in good_sig.signer_ids)
        )
        blob = (
            CHAIN_TAG
            + u32(1)
            + frame(encode_extension(proof))
            + signature_frame(good_sig)
            + zero_R_frame
        )
        with self.assertRaises(ValueError):
            decode_audit_extension_checkpoint_chain(blob)


class VerifyValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = make_records(self.key, 5)
        self.proof, self.old_sig, self.new_sig = make_hop(
            self.key, self.records, 2, seed=17000
        )

    def test_non_chain_type_error(self):
        for bad in (
            ((self.proof,), (self.old_sig, self.new_sig)),
            None,
            "chain",
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_audit_extension_checkpoint_chain(bad, self.key)

    def test_empty_chain_value_error(self):
        with self.assertRaises(ValueError):
            verify_audit_extension_checkpoint_chain(
                AuditExtensionCheckpointChain((), ()), self.key
            )

    def test_non_tuple_fields_type_error(self):
        with self.assertRaises(TypeError):
            verify_audit_extension_checkpoint_chain(
                AuditExtensionCheckpointChain(
                    [self.proof], [self.old_sig, self.new_sig]
                ),
                self.key,
            )

    def test_non_proof_element_type_error(self):
        with self.assertRaises(TypeError):
            verify_audit_extension_checkpoint_chain(
                AuditExtensionCheckpointChain(
                    ("x",), (self.old_sig, self.new_sig)
                ),
                self.key,
            )

    def test_non_signature_element_type_error(self):
        with self.assertRaises(TypeError):
            verify_audit_extension_checkpoint_chain(
                AuditExtensionCheckpointChain(
                    (self.proof,), ("x", self.new_sig)
                ),
                self.key,
            )

    def test_signature_count_mismatch_value_error(self):
        with self.assertRaises(ValueError):
            verify_audit_extension_checkpoint_chain(
                AuditExtensionCheckpointChain((self.proof,), (self.old_sig,)),
                self.key,
            )

    def test_illegal_nested_proof_value_error(self):
        bad_proof = AuditExtensionProof(0, (b"a" * 32, b"b" * 32))
        with self.assertRaises(ValueError):
            verify_audit_extension_checkpoint_chain(
                AuditExtensionCheckpointChain(
                    (bad_proof,), (self.old_sig, self.new_sig)
                ),
                self.key,
            )

    def test_illegal_nested_signature_value_error(self):
        bad_sig = AggregateSignature(R=0, z=7, signer_ids=(1, 3))
        with self.assertRaises(ValueError):
            verify_audit_extension_checkpoint_chain(
                AuditExtensionCheckpointChain(
                    (self.proof,), (bad_sig, self.new_sig)
                ),
                self.key,
            )


if __name__ == "__main__":
    unittest.main()
