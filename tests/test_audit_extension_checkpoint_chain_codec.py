"""Tests for the canonical AuditExtensionCheckpointChain transport encoding:
encode_audit_extension_checkpoint_chain /
decode_audit_extension_checkpoint_chain /
verify_audit_extension_checkpoint_chain."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    AuditExtensionProof,
    AuditExtensionCheckpointChain,
    encode_extension,
    encode_audit_extension_checkpoint_chain,
    decode_audit_extension_checkpoint_chain,
    verify_audit_extension_checkpoint_chain,
    make_extension,
)

from test_audit_chain import make_key, make_record, sign_message
from test_audit_extension_proof_bundle_codec import (
    make_other_key,
    make_records,
    signature_frame,
    u32,
)

CHAIN_TAG = b"ts/aepcc/v1"
EXTENSION_TAG = b"thresholdsign/audit-extension/v1"


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def checkpoint_chain(key, records, splits, *, seed=9000):
    """Build a checkpoint chain along the given growing split points.

    The n+1 signatures are the one old-root signature of the first hop
    and the new-root signature of every hop, so consecutive proofs share
    the signature of their common checkpoint.
    """
    proofs = []
    signatures = []
    for index, (old_n, new_n) in enumerate(splits):
        old_message, new_message, proof = make_extension(records[:new_n], old_n)
        proofs.append(proof)
        if index == 0:
            signatures.append(sign_message(key, old_message, seed=seed))
            seed += 1
        signatures.append(sign_message(key, new_message, seed=seed))
        seed += 1
    return AuditExtensionCheckpointChain(tuple(proofs), tuple(signatures))


def build_wire(chain: AuditExtensionCheckpointChain) -> bytes:
    """Independently build the chain wire format straight from the spec."""
    out = bytearray(CHAIN_TAG)
    out += u32(len(chain.proofs))
    for proof in chain.proofs:
        out += frame(encode_extension(proof))
    for signature in chain.signatures:
        out += signature_frame(signature)
    return bytes(out)


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
        first = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        second = AggregateSignature(R=6, z=8, signer_ids=(1, 3))
        proofs = (proof,)
        signatures = (first, second)
        chain = AuditExtensionCheckpointChain(proofs, signatures)
        self.assertIs(chain.proofs, proofs)
        self.assertIs(chain.signatures, signatures)
        self.assertEqual(
            AuditExtensionCheckpointChain(
                proofs=proofs, signatures=signatures
            ),
            chain,
        )

    def test_frozen_value_equality_and_hash(self):
        proof_a = AuditExtensionProof(1, (b"a" * 32, b"b" * 32))
        proof_b = AuditExtensionProof(2, (b"a" * 32, b"b" * 32, b"c" * 32))
        sig0 = AggregateSignature(R=5, z=7, signer_ids=(1,))
        sig1 = AggregateSignature(R=6, z=8, signer_ids=(1,))
        sig2 = AggregateSignature(R=9, z=11, signer_ids=(1,))
        chain = AuditExtensionCheckpointChain(
            (proof_a, proof_b), (sig0, sig1, sig2)
        )
        same = AuditExtensionCheckpointChain(
            (proof_a, proof_b), (sig0, sig1, sig2)
        )
        self.assertEqual(chain, same)
        self.assertEqual(hash(chain), hash(same))
        self.assertNotEqual(
            chain,
            AuditExtensionCheckpointChain((proof_a,), (sig0, sig1)),
        )
        self.assertNotEqual(
            chain,
            AuditExtensionCheckpointChain(
                (proof_b, proof_a), (sig0, sig1, sig2)
            ),
        )
        self.assertNotEqual(
            chain,
            AuditExtensionCheckpointChain(
                (proof_a, proof_b), (sig0, sig2, sig1)
            ),
        )
        with self.assertRaises(FrozenInstanceError):
            chain.proofs = (proof_a,)

    def test_construction_does_not_validate(self):
        # A plain frozen value: codec and verifier do the checking.
        AuditExtensionCheckpointChain((), ())
        AuditExtensionCheckpointChain(("not-a-proof",), ("not-a-sig",))
        AuditExtensionCheckpointChain(None, None)
        # Even the len(proofs) + 1 signature bound is not enforced here.
        AuditExtensionCheckpointChain((object(),), ())


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = make_records(self.key, 8)

    def test_honest_chains_round_trip_at_every_length(self):
        seed = 10000
        # Every prefix chain 1 -> 2 -> ... -> m for m in 2..8.
        for m in range(2, 9):
            splits = tuple((i, i + 1) for i in range(1, m))
            chain = checkpoint_chain(
                self.key, self.records[:m], splits, seed=seed
            )
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
        chain = checkpoint_chain(self.key, self.records, splits, seed=11000)
        wire = encode_audit_extension_checkpoint_chain(chain)
        self.assertEqual(decode_audit_extension_checkpoint_chain(wire), chain)
        self.assertTrue(
            verify_audit_extension_checkpoint_chain(chain, self.key)
        )

    def test_single_proof_chain_round_trips(self):
        chain = checkpoint_chain(self.key, self.records[:4], ((2, 4),), seed=11100)
        wire = encode_audit_extension_checkpoint_chain(chain)
        decoded = decode_audit_extension_checkpoint_chain(wire)
        self.assertEqual(decoded, chain)
        self.assertEqual(len(chain.signatures), 2)
        self.assertTrue(
            verify_audit_extension_checkpoint_chain(decoded, self.key)
        )

    def test_encoding_matches_independent_builder(self):
        splits = ((1, 2), (2, 4), (4, 7))
        chain = checkpoint_chain(self.key, self.records, splits, seed=12000)
        wire = encode_audit_extension_checkpoint_chain(chain)
        self.assertEqual(wire, build_wire(chain))
        self.assertTrue(wire.startswith(CHAIN_TAG))
        self.assertEqual(wire[len(CHAIN_TAG):len(CHAIN_TAG) + 4], u32(3))

    def test_frames_are_existing_single_proof_encodings(self):
        splits = ((1, 3), (3, 6))
        chain = checkpoint_chain(self.key, self.records, splits, seed=12100)
        wire = encode_audit_extension_checkpoint_chain(chain)
        offset = len(CHAIN_TAG) + 4
        for proof in chain.proofs:
            encoded = encode_extension(proof)
            self.assertEqual(wire[offset:offset + 4], u32(len(encoded)))
            offset += 4
            self.assertEqual(
                wire[offset:offset + len(EXTENSION_TAG)], EXTENSION_TAG
            )
            self.assertEqual(wire[offset:offset + len(encoded)], encoded)
            offset += len(encoded)
        # The tail is exactly the n+1 signature frames, nothing else.
        self.assertEqual(
            wire[offset:],
            b"".join(signature_frame(sig) for sig in chain.signatures),
        )
        self.assertEqual(len(chain.signatures), len(chain.proofs) + 1)

    def test_encoding_is_unique_and_stateless(self):
        chain = checkpoint_chain(
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
        # Two proofs over unrelated record sequences spliced into one
        # checkpoint chain: decode restores it unchanged and the
        # verifier reports the broken shared checkpoint as False.
        first = checkpoint_chain(
            self.key, self.records[:4], ((2, 4),), seed=13100
        )
        other_records = tuple(
            make_record(self.key, b"other-%d" % i, seed=300 + i)
            for i in range(5)
        )
        _, new_message, second_proof = make_extension(other_records, 2)
        second_new = sign_message(self.key, new_message, seed=13110)
        chain = AuditExtensionCheckpointChain(
            (first.proofs[0], second_proof),
            (
                first.signatures[0],
                first.signatures[1],
                second_new,
            ),
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
        chain = checkpoint_chain(
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

    def _chain(self, splits, seed=14000):
        return checkpoint_chain(self.key, self.records, splits, seed=seed)

    def test_matching_prefixes_link(self):
        chain = self._chain(((2, 4), (4, 6), (6, 8)))
        self.assertTrue(
            verify_audit_extension_checkpoint_chain(chain, self.key)
        )

    def test_gap_between_neighbours_returns_false(self):
        # 2 -> 4 then 5 -> 8: the predecessor has 4 leaves but the
        # successor's old_n is 5.
        chain = self._chain(((2, 4), (5, 8)))
        self.assertFalse(
            verify_audit_extension_checkpoint_chain(chain, self.key)
        )

    def test_overlap_between_neighbours_returns_false(self):
        chain = self._chain(((2, 5), (3, 8)))
        self.assertFalse(
            verify_audit_extension_checkpoint_chain(chain, self.key)
        )

    def test_same_count_but_different_leaves_returns_false(self):
        first = checkpoint_chain(
            self.key, self.records[:4], ((2, 4),), seed=14100
        )
        # A successor over different record bytes with matching counts.
        other_records = tuple(
            make_record(self.key, b"other-%d" % i, seed=900 + i)
            for i in range(6)
        )
        old_message, new_message, second_proof = make_extension(
            other_records, 4
        )
        # The shared checkpoint signature is the (valid) new-root
        # signature of the first hop; it does not authenticate this
        # unrelated old root.
        second = AuditExtensionCheckpointChain(
            (second_proof,),
            (
                first.signatures[1],
                sign_message(self.key, new_message, seed=14110),
            ),
        )
        chain = AuditExtensionCheckpointChain(
            (first.proofs[0], second_proof),
            (
                first.signatures[0],
                first.signatures[1],
                second.signatures[1],
            ),
        )
        self.assertEqual(len(first.proofs[0].leaves), second_proof.old_n)
        self.assertFalse(
            verify_audit_extension_checkpoint_chain(chain, self.key)
        )
        # Sanity: the old message really is a different statement.
        self.assertNotEqual(old_message, new_message)

    def test_one_bad_checkpoint_signature_returns_false(self):
        chain = self._chain(((1, 3), (3, 5)), seed=14200)
        forged = sign_message(self.key, b"unrelated", seed=14220)
        tampered = AuditExtensionCheckpointChain(
            chain.proofs,
            chain.signatures[:2] + (forged,),
        )
        # The first hop still verifies (its two signatures are intact);
        # the second hop's new-root signature does not.
        self.assertFalse(
            verify_audit_extension_checkpoint_chain(tampered, self.key)
        )


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = make_records(self.key, 5)
        self.chain = checkpoint_chain(
            self.key, self.records, ((1, 3), (3, 5)), seed=15000
        )

    def test_non_chain_type_error(self):
        proofs, signatures = self.chain.proofs, self.chain.signatures
        for bad in (
            (proofs, signatures),
            [proofs, signatures],
            None,
            self.chain.proofs,
            "chain",
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_audit_extension_checkpoint_chain(bad)

    def test_non_tuple_fields_type_error(self):
        with self.assertRaises(TypeError):
            encode_audit_extension_checkpoint_chain(
                AuditExtensionCheckpointChain(
                    list(self.chain.proofs), self.chain.signatures
                )
            )
        with self.assertRaises(TypeError):
            encode_audit_extension_checkpoint_chain(
                AuditExtensionCheckpointChain(
                    self.chain.proofs, list(self.chain.signatures)
                )
            )

    def test_wrong_element_types_type_error(self):
        sig = self.chain.signatures[0]
        for bad in (
            AuditExtensionCheckpointChain(("x",), (sig, sig)),
            AuditExtensionCheckpointChain((None,), (sig, sig)),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_audit_extension_checkpoint_chain(bad)
        proof = self.chain.proofs[0]
        for bad in (
            AuditExtensionCheckpointChain((proof,), ("x", sig)),
            AuditExtensionCheckpointChain((proof,), (sig, None)),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_audit_extension_checkpoint_chain(bad)

    def test_empty_proofs_value_error(self):
        with self.assertRaises(ValueError):
            encode_audit_extension_checkpoint_chain(
                AuditExtensionCheckpointChain((), ())
            )

    def test_signature_count_must_be_n_plus_one(self):
        proofs = self.chain.proofs
        signatures = self.chain.signatures
        for bad in (
            signatures[:-1],          # n signatures
            signatures[:1],           # too few
            signatures + (signatures[0],),  # n + 2 signatures
        ):
            with self.assertRaises(ValueError, msg=repr(len(bad))):
                encode_audit_extension_checkpoint_chain(
                    AuditExtensionCheckpointChain(proofs, bad)
                )

    def test_illegal_nested_proof_value_error(self):
        bad_proof = AuditExtensionProof(0, (b"a" * 32, b"b" * 32))
        sig = self.chain.signatures[0]
        with self.assertRaises(ValueError):
            encode_audit_extension_checkpoint_chain(
                AuditExtensionCheckpointChain(
                    (bad_proof,), (sig, sig)
                )
            )

    def test_illegal_nested_signature_value_error(self):
        proof = self.chain.proofs[0]
        good = self.chain.signatures[0]
        bad_R = AggregateSignature(R=0, z=7, signer_ids=(1,))
        bad_ids = AggregateSignature(R=5, z=7, signer_ids=(2, 1))
        for bad_signature in (bad_R, bad_ids):
            with self.assertRaises(ValueError):
                encode_audit_extension_checkpoint_chain(
                    AuditExtensionCheckpointChain(
                        (proof,), (good, bad_signature)
                    )
                )


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = make_records(self.key, 6)
        self.chain = checkpoint_chain(
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

    def test_declared_count_too_small_leaves_trailing_frames(self):
        # Rebuild with count 1 but both proofs and all signatures present.
        proof_frames = b"".join(
            frame(encode_extension(proof)) for proof in self.chain.proofs
        )
        signature_frames = b"".join(
            signature_frame(sig) for sig in self.chain.signatures
        )
        bad = CHAIN_TAG + u32(1) + proof_frames + signature_frames
        with self.assertRaises(ValueError):
            decode_audit_extension_checkpoint_chain(bad)

    def test_zero_frame_length_rejected(self):
        first_body = encode_extension(self.chain.proofs[0])
        rest = self.wire[len(CHAIN_TAG) + 4 + 4 + len(first_body):]
        bad = CHAIN_TAG + u32(2) + u32(0) + first_body + rest
        with self.assertRaises(ValueError):
            decode_audit_extension_checkpoint_chain(bad)

    def test_junk_nested_frame_rejected(self):
        bad = CHAIN_TAG + u32(1) + frame(b"not-a-proof")
        with self.assertRaises(ValueError):
            decode_audit_extension_checkpoint_chain(bad)

    def test_declared_frame_length_mismatch(self):
        first_body = encode_extension(self.chain.proofs[0])
        rest = self.wire[len(CHAIN_TAG) + 4 + 4 + len(first_body):]
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
        # Flip a byte inside the nested proof tag: the nested decoder
        # must reject it rather than the chain swallowing the error.
        proof_body = encode_extension(self.chain.proofs[0])
        tampered = b"x" + proof_body[1:]
        bad = CHAIN_TAG + u32(1) + frame(tampered) + signature_frame(
            self.chain.signatures[0]
        ) + signature_frame(self.chain.signatures[1])
        with self.assertRaises(ValueError):
            decode_audit_extension_checkpoint_chain(bad)

    def test_missing_last_signature_rejected(self):
        # n + 1 signatures are required; dropping the last frame is
        # truncation rather than a successful decode with n signatures.
        last = signature_frame(self.chain.signatures[-1])
        truncated = self.wire[:len(self.wire) - len(last)]
        with self.assertRaises(ValueError):
            decode_audit_extension_checkpoint_chain(truncated)

    def test_extra_signature_rejected_as_trailing(self):
        bad = self.wire + signature_frame(self.chain.signatures[0])
        with self.assertRaises(ValueError):
            decode_audit_extension_checkpoint_chain(bad)

    def test_bad_signature_frame_rejected(self):
        # Zero signer count inside the first signature frame.
        proof_frames = b"".join(
            frame(encode_extension(proof)) for proof in self.chain.proofs
        )
        bad_frame = (
            signature_frame(self.chain.signatures[0])[: -4] + u32(0)
        )
        rest = b"".join(
            signature_frame(sig) for sig in self.chain.signatures[1:]
        )
        bad = CHAIN_TAG + u32(2) + proof_frames + bad_frame + rest
        with self.assertRaises(ValueError):
            decode_audit_extension_checkpoint_chain(bad)


class VerifyValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = make_records(self.key, 5)
        self.chain = checkpoint_chain(
            self.key, self.records, ((1, 3), (3, 5)), seed=17000
        )

    def test_non_chain_type_error(self):
        for bad in (
            (self.chain.proofs, self.chain.signatures),
            None,
            self.chain.proofs,
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
                    list(self.chain.proofs), self.chain.signatures
                ),
                self.key,
            )

    def test_wrong_element_types_type_error(self):
        proof = self.chain.proofs[0]
        sig = self.chain.signatures[0]
        with self.assertRaises(TypeError):
            verify_audit_extension_checkpoint_chain(
                AuditExtensionCheckpointChain(("x",), (sig, sig)), self.key
            )
        with self.assertRaises(TypeError):
            verify_audit_extension_checkpoint_chain(
                AuditExtensionCheckpointChain((proof,), (sig, "x")), self.key
            )

    def test_signature_count_mismatch_value_error(self):
        with self.assertRaises(ValueError):
            verify_audit_extension_checkpoint_chain(
                AuditExtensionCheckpointChain(
                    self.chain.proofs, self.chain.signatures[:-1]
                ),
                self.key,
            )

    def test_illegal_nested_proof_value_error(self):
        bad_proof = AuditExtensionProof(0, (b"a" * 32, b"b" * 32))
        sig = self.chain.signatures[0]
        with self.assertRaises(ValueError):
            verify_audit_extension_checkpoint_chain(
                AuditExtensionCheckpointChain((bad_proof,), (sig, sig)),
                self.key,
            )


if __name__ == "__main__":
    unittest.main()
