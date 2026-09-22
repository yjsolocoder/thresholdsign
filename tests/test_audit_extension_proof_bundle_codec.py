"""Tests for the canonical AuditExtensionProofBundle transport encoding:
encode_audit_extension_proof_bundle / decode_audit_extension_proof_bundle /
verify_audit_extension_proof_bundle."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    AuditExtensionProof,
    AuditExtensionProofBundle,
    check_extension,
    decode_audit_extension_proof_bundle,
    encode_audit_extension_proof_bundle,
    encode_extension,
    make_extension,
    verify_audit_extension_proof_bundle,
)

from test_audit_chain import make_key, make_record, sign_message
from test_audit_extension import seal_extension

BUNDLE_TAG = b"ts/aepb/v1"


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def signature_frame(signature: AggregateSignature) -> bytes:
    out = bytearray()
    out += varint(signature.R)
    out += varint(signature.z)
    out += u32(len(signature.signer_ids))
    for signer_id in signature.signer_ids:
        out += varint(signer_id)
    return bytes(out)


def build_wire(bundle: AuditExtensionProofBundle) -> bytes:
    """Independently build the bundle wire format straight from the spec."""
    out = bytearray(BUNDLE_TAG)
    out += frame(encode_extension(bundle.proof))
    out += signature_frame(bundle.old_signature)
    out += signature_frame(bundle.new_signature)
    return bytes(out)


def make_other_key():
    """A different key over the same toy group (different randomness)."""
    return make_key(seed_offset=1000)


def make_records(key, n):
    return tuple(
        make_record(key, f"message-{i}".encode(), seed=100 + 10 * i)
        for i in range(n)
    )


def sealed_bundle(key, records, old_n, *, seed=700):
    """Return a signed AuditExtensionProofBundle for the given split."""
    proof, old_sig, new_sig = seal_extension(key, records, old_n, seed=seed)
    return AuditExtensionProofBundle(proof, old_sig, new_sig)


class BundleDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [
                field.name
                for field in dataclasses.fields(AuditExtensionProofBundle)
            ],
            ["proof", "old_signature", "new_signature"],
        )
        proof = AuditExtensionProof(1, (b"a" * 32, b"b" * 32))
        old_sig = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        new_sig = AggregateSignature(R=9, z=11, signer_ids=(2, 4))
        bundle = AuditExtensionProofBundle(proof, old_sig, new_sig)
        self.assertIs(bundle.proof, proof)
        self.assertIs(bundle.old_signature, old_sig)
        self.assertIs(bundle.new_signature, new_sig)
        self.assertEqual(
            AuditExtensionProofBundle(
                proof=proof, old_signature=old_sig, new_signature=new_sig
            ),
            bundle,
        )

    def test_frozen_value_equality_and_hash(self):
        proof = AuditExtensionProof(1, (b"a" * 32, b"b" * 32))
        old_sig = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        new_sig = AggregateSignature(R=9, z=11, signer_ids=(2, 4))
        bundle = AuditExtensionProofBundle(proof, old_sig, new_sig)
        same = AuditExtensionProofBundle(proof, old_sig, new_sig)
        self.assertEqual(bundle, same)
        self.assertEqual(hash(bundle), hash(same))
        self.assertNotEqual(
            bundle,
            AuditExtensionProofBundle(
                proof,
                AggregateSignature(R=6, z=7, signer_ids=(1, 3)),
                new_sig,
            ),
        )
        self.assertNotEqual(
            bundle,
            AuditExtensionProofBundle(proof, new_sig, old_sig),
        )
        with self.assertRaises(FrozenInstanceError):
            bundle.proof = proof

    def test_construction_does_not_validate(self):
        # A plain frozen value: non-proof and non-signature fields
        # construct; the codec and verifier reject them.
        AuditExtensionProofBundle("not-a-proof", "not-old", "not-new")
        AuditExtensionProofBundle(None, None, None)


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = make_records(self.key, 8)

    def test_round_trip_for_every_split_and_size(self):
        seed = 2000
        for n in range(2, 9):
            records = self.records[:n]
            for old_n in range(1, n):
                bundle = sealed_bundle(self.key, records, old_n, seed=seed)
                seed += 10
                wire = encode_audit_extension_proof_bundle(bundle)
                decoded = decode_audit_extension_proof_bundle(wire)
                self.assertEqual(decoded, bundle, msg=f"n={n} old_n={old_n}")
                self.assertEqual(
                    encode_audit_extension_proof_bundle(decoded), wire
                )

    def test_encoding_matches_independent_builder(self):
        seed = 3000
        for n in range(2, 9):
            records = self.records[:n]
            for old_n in range(1, n):
                bundle = sealed_bundle(self.key, records, old_n, seed=seed)
                seed += 10
                self.assertEqual(
                    encode_audit_extension_proof_bundle(bundle),
                    build_wire(bundle),
                    msg=f"n={n} old_n={old_n}",
                )

    def test_prefix_is_tag_length_and_full_proof_encoding(self):
        bundle = sealed_bundle(self.key, self.records[:5], 2, seed=4000)
        wire = encode_audit_extension_proof_bundle(bundle)
        self.assertTrue(wire.startswith(BUNDLE_TAG))
        offset = len(BUNDLE_TAG)
        proof_bytes = encode_extension(bundle.proof)
        self.assertEqual(wire[offset:offset + 4], u32(len(proof_bytes)))
        offset += 4
        self.assertEqual(wire[offset:offset + len(proof_bytes)], proof_bytes)
        # The nested proof keeps its own distinct wire tag.
        self.assertTrue(
            proof_bytes.startswith(b"thresholdsign/audit-extension/v1")
        )

    def test_suffix_is_the_two_signature_frames(self):
        bundle = sealed_bundle(self.key, self.records[:5], 2, seed=4100)
        wire = encode_audit_extension_proof_bundle(bundle)
        proof_bytes = encode_extension(bundle.proof)
        suffix = wire[len(BUNDLE_TAG) + 4 + len(proof_bytes):]
        expected = signature_frame(bundle.old_signature)
        expected += signature_frame(bundle.new_signature)
        self.assertEqual(suffix, expected)

    def test_zero_z_encodes_as_single_body_byte(self):
        bundle = sealed_bundle(self.key, self.records[:4], 2, seed=4200)
        old_sig = bundle.old_signature
        bundle = AuditExtensionProofBundle(
            bundle.proof,
            AggregateSignature(
                R=old_sig.R, z=0, signer_ids=old_sig.signer_ids
            ),
            bundle.new_signature,
        )
        wire = encode_audit_extension_proof_bundle(bundle)
        proof_bytes = encode_extension(bundle.proof)
        offset = len(BUNDLE_TAG) + 4 + len(proof_bytes)
        # R varint precedes z; z = 0 -> VARINT 00 00 00 01 00.
        offset += len(varint(old_sig.R))
        self.assertEqual(wire[offset:offset + 5], b"\x00\x00\x00\x01\x00")

    def test_decoded_bundle_still_verifies(self):
        seed = 5000
        for n in range(2, 9):
            records = self.records[:n]
            for old_n in range(1, n):
                bundle = sealed_bundle(self.key, records, old_n, seed=seed)
                seed += 10
                decoded = decode_audit_extension_proof_bundle(
                    encode_audit_extension_proof_bundle(bundle)
                )
                self.assertTrue(
                    verify_audit_extension_proof_bundle(decoded, self.key),
                    msg=f"n={n} old_n={old_n}",
                )

    def test_encoding_is_unique_and_stateless(self):
        bundle = sealed_bundle(self.key, self.records[:4], 2, seed=4300)
        self.assertEqual(
            encode_audit_extension_proof_bundle(bundle),
            encode_audit_extension_proof_bundle(bundle),
        )


class StructureOnlyTest(unittest.TestCase):
    def test_decode_does_not_parse_leaves_or_check_signatures(self):
        # Opaque, structurally framed but cryptographically meaningless
        # leaves and arbitrary signature integers decode fine.
        proof = AuditExtensionProof(1, (b"x" * 32, b"y" * 32, b"z" * 32))
        old_sig = AggregateSignature(R=9, z=11, signer_ids=(2, 4))
        new_sig = AggregateSignature(R=13, z=15, signer_ids=(1,))
        bundle = AuditExtensionProofBundle(proof, old_sig, new_sig)
        decoded = decode_audit_extension_proof_bundle(
            encode_audit_extension_proof_bundle(bundle)
        )
        self.assertEqual(decoded, bundle)

    def test_encoding_does_not_check_the_signatures_against_the_roots(self):
        # A bundle signed by one key but presented under another encodes
        # fine — structure alone is checked; verify reports it as False.
        key = make_key()
        records = make_records(key, 4)
        bundle = sealed_bundle(key, records, 2, seed=4400)
        self.assertTrue(encode_audit_extension_proof_bundle(bundle))
        self.assertFalse(
            verify_audit_extension_proof_bundle(bundle, make_other_key())
        )


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = make_records(self.key, 5)
        self.bundle = sealed_bundle(self.key, self.records, 3, seed=4500)

    def test_non_bundle_type_error(self):
        with self.assertRaises(TypeError):
            encode_audit_extension_proof_bundle(
                ("proof", "old_signature", "new_signature")
            )
        with self.assertRaises(TypeError):
            encode_audit_extension_proof_bundle(None)

    def test_non_proof_field_type_error(self):
        with self.assertRaises(TypeError):
            encode_audit_extension_proof_bundle(
                AuditExtensionProofBundle(
                    "not-a-proof",
                    self.bundle.old_signature,
                    self.bundle.new_signature,
                )
            )
        with self.assertRaises(TypeError):
            encode_audit_extension_proof_bundle(
                AuditExtensionProofBundle(
                    None,
                    self.bundle.old_signature,
                    self.bundle.new_signature,
                )
            )

    def test_non_signature_field_type_error(self):
        for position in (1, 2):
            fields = [
                self.bundle.proof,
                self.bundle.old_signature,
                self.bundle.new_signature,
            ]
            fields[position] = "no"
            with self.assertRaises(TypeError, msg=f"position={position}"):
                encode_audit_extension_proof_bundle(
                    AuditExtensionProofBundle(*fields)
                )
            fields[position] = None
            with self.assertRaises(TypeError, msg=f"position={position}"):
                encode_audit_extension_proof_bundle(
                    AuditExtensionProofBundle(*fields)
                )

    def test_signature_field_type_errors(self):
        signature = self.bundle.old_signature
        for bad in (
            AggregateSignature(True, signature.z, signature.signer_ids),
            AggregateSignature("5", signature.z, signature.signer_ids),
            AggregateSignature(signature.R, False, signature.signer_ids),
            AggregateSignature(signature.R, "7", signature.signer_ids),
            AggregateSignature(signature.R, signature.z, [1, 3]),
            AggregateSignature(signature.R, signature.z, (1, "3")),
            AggregateSignature(signature.R, signature.z, (True, 3)),
        ):
            for position in (1, 2):
                fields = [
                    self.bundle.proof,
                    self.bundle.old_signature,
                    self.bundle.new_signature,
                ]
                fields[position] = bad
                with self.assertRaises(
                    TypeError, msg=f"position={position} {bad!r}"
                ):
                    encode_audit_extension_proof_bundle(
                        AuditExtensionProofBundle(*fields)
                    )

    def test_bad_nested_proof_structure_value_error(self):
        bad_proof = AuditExtensionProof(0, (b"a" * 32, b"b" * 32))
        with self.assertRaises(ValueError):
            encode_audit_extension_proof_bundle(
                AuditExtensionProofBundle(
                    bad_proof,
                    self.bundle.old_signature,
                    self.bundle.new_signature,
                )
            )

    def test_signature_value_errors(self):
        signature = self.bundle.old_signature
        for bad in (
            AggregateSignature(0, signature.z, signature.signer_ids),
            AggregateSignature(-1, signature.z, signature.signer_ids),
            AggregateSignature(signature.R, -1, signature.signer_ids),
            AggregateSignature(signature.R, signature.z, ()),
            AggregateSignature(signature.R, signature.z, (0, 3)),
            AggregateSignature(signature.R, signature.z, (-1, 3)),
            AggregateSignature(signature.R, signature.z, (3, 1)),
            AggregateSignature(signature.R, signature.z, (1, 1)),
        ):
            for position in (1, 2):
                fields = [
                    self.bundle.proof,
                    self.bundle.old_signature,
                    self.bundle.new_signature,
                ]
                fields[position] = bad
                with self.assertRaises(
                    ValueError, msg=f"position={position} {bad!r}"
                ):
                    encode_audit_extension_proof_bundle(
                        AuditExtensionProofBundle(*fields)
                    )


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = make_records(self.key, 5)
        self.bundle = sealed_bundle(self.key, self.records, 3, seed=4600)
        self.wire = encode_audit_extension_proof_bundle(self.bundle)
        self.proof_bytes = encode_extension(self.bundle.proof)
        self.old_frame = signature_frame(self.bundle.old_signature)
        self.new_frame = signature_frame(self.bundle.new_signature)
        self.suffix_offset = len(BUNDLE_TAG) + 4 + len(self.proof_bytes)

    def test_non_bytes_type_error(self):
        with self.assertRaises(TypeError):
            decode_audit_extension_proof_bundle("not bytes")
        with self.assertRaises(TypeError):
            decode_audit_extension_proof_bundle(bytearray(self.wire))

    def test_bad_tag(self):
        rest = self.wire[len(BUNDLE_TAG):]
        with self.assertRaises(ValueError):
            decode_audit_extension_proof_bundle(b"ts/aepb/v2" + rest)
        with self.assertRaises(ValueError):
            decode_audit_extension_proof_bundle(b"x" + self.wire[1:])

    def test_truncation(self):
        for cut in range(len(BUNDLE_TAG), len(self.wire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_audit_extension_proof_bundle(self.wire[:cut])

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_audit_extension_proof_bundle(self.wire + b"\x00")

    def test_zero_proof_frame_rejected(self):
        bad = BUNDLE_TAG + u32(0) + self.wire[self.suffix_offset:]
        with self.assertRaises(ValueError):
            decode_audit_extension_proof_bundle(bad)

    def test_junk_proof_frame_rejected(self):
        bad = (
            BUNDLE_TAG
            + frame(b"not-a-proof")
            + self.wire[self.suffix_offset:]
        )
        with self.assertRaises(ValueError):
            decode_audit_extension_proof_bundle(bad)

    def test_declared_proof_frame_length_mismatch(self):
        # Declaring the frame one byte shorter hides a proof byte inside
        # what the parser then reads as the old-R varint length.
        bad = bytearray(self.wire)
        length_offset = len(BUNDLE_TAG)
        declared = len(self.proof_bytes) - 1
        bad[length_offset:length_offset + 4] = u32(declared)
        with self.assertRaises(ValueError):
            decode_audit_extension_proof_bundle(bytes(bad))

    def test_zero_R_rejected_in_either_frame(self):
        for which, signature, frame_offset in (
            ("old", self.bundle.old_signature, self.suffix_offset),
            (
                "new",
                self.bundle.new_signature,
                self.suffix_offset + len(self.old_frame),
            ),
        ):
            bad = (
                self.wire[:frame_offset]
                + varint(0)
                + self.wire[frame_offset + len(varint(signature.R)):]
            )
            with self.assertRaises(ValueError, msg=which):
                decode_audit_extension_proof_bundle(bad)

    def test_non_canonical_R_leading_zero(self):
        # Use a structurally legal small-R signature so the one-byte
        # canonical body 09 can be padded to the non-canonical 00 09.
        bundle = AuditExtensionProofBundle(
            self.bundle.proof,
            AggregateSignature(R=9, z=7, signer_ids=(1, 3)),
            self.bundle.new_signature,
        )
        wire = encode_audit_extension_proof_bundle(bundle)
        non_canonical_R = (2).to_bytes(4, "big") + b"\x00\x09"
        canonical_R = varint(9)
        bad = (
            wire[:self.suffix_offset]
            + non_canonical_R
            + wire[self.suffix_offset + len(canonical_R):]
        )
        with self.assertRaises(ValueError):
            decode_audit_extension_proof_bundle(bad)

    def test_zero_signer_count_rejected(self):
        signature = self.bundle.old_signature
        tail_offset = self.suffix_offset + len(
            varint(signature.R)
        ) + len(varint(signature.z))
        bad = self.wire[:tail_offset] + u32(0)
        with self.assertRaises(ValueError):
            decode_audit_extension_proof_bundle(bad)

    def test_signer_count_too_large_then_truncated(self):
        signature = self.bundle.new_signature
        tail_offset = (
            self.suffix_offset
            + len(self.old_frame)
            + len(varint(signature.R))
            + len(varint(signature.z))
        )
        bad = self.wire[:tail_offset] + u32(len(signature.signer_ids) + 1)
        for signer_id in signature.signer_ids:
            bad += varint(signer_id)
        with self.assertRaises(ValueError):
            decode_audit_extension_proof_bundle(bad)

    def test_non_positive_and_unsorted_signer_ids_rejected(self):
        signature = self.bundle.old_signature
        prefix = (
            BUNDLE_TAG
            + frame(self.proof_bytes)
            + varint(signature.R)
            + varint(signature.z)
        )
        # On the wire every id body is read as an unsigned integer; the raw
        # byte ff stands in for a would-be negative/non-positive id.
        cases = {
            "zero": (b"\x00", b"\x03"),
            "ff_then_small": (b"\xff", b"\x03"),
            "unsorted": (b"\x03", b"\x01"),
            "duplicate": (b"\x01", b"\x01"),
        }
        for label, bodies in cases.items():
            out = bytearray(prefix)
            out += u32(len(bodies))
            for body in bodies:
                out += (1).to_bytes(4, "big")
                out += body
            out += self.new_frame
            with self.assertRaises(ValueError, msg=label):
                decode_audit_extension_proof_bundle(bytes(out))


class VerifyBundleTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.other = make_other_key()
        self.records = make_records(self.key, 8)

    def test_honest_bundles_verify_for_every_split_and_size(self):
        seed = 6000
        for n in range(2, 9):
            records = self.records[:n]
            for old_n in range(1, n):
                bundle = sealed_bundle(self.key, records, old_n, seed=seed)
                seed += 10
                self.assertTrue(
                    verify_audit_extension_proof_bundle(bundle, self.key),
                    msg=f"n={n} old_n={old_n}",
                )

    def test_result_equals_check_extension(self):
        seed = 7000
        for n in range(2, 9):
            records = self.records[:n]
            for old_n in range(1, n):
                bundle = sealed_bundle(self.key, records, old_n, seed=seed)
                seed += 10
                self.assertEqual(
                    verify_audit_extension_proof_bundle(bundle, self.key),
                    check_extension(
                        bundle.proof,
                        bundle.old_signature,
                        bundle.new_signature,
                        self.key,
                    ),
                    msg=f"n={n} old_n={old_n}",
                )

    def test_wrong_key_returns_false(self):
        bundle = sealed_bundle(self.key, self.records[:5], 3, seed=7100)
        self.assertFalse(
            verify_audit_extension_proof_bundle(bundle, self.other)
        )

    def test_swapped_signatures_return_false(self):
        bundle = sealed_bundle(self.key, self.records[:5], 3, seed=7150)
        swapped = AuditExtensionProofBundle(
            bundle.proof, bundle.new_signature, bundle.old_signature
        )
        self.assertFalse(
            verify_audit_extension_proof_bundle(swapped, self.key)
        )

    def test_tampered_signature_returns_false(self):
        bundle = sealed_bundle(self.key, self.records[:5], 3, seed=7200)
        # A valid R of a different real round is still a subgroup element,
        # so the check runs and returns False rather than raising.
        other_message = make_extension(self.records[:4], 2)[1]
        other_signature = sign_message(self.key, other_message, seed=7210)
        tampered = AuditExtensionProofBundle(
            bundle.proof,
            bundle.old_signature,
            AggregateSignature(
                R=other_signature.R,
                z=bundle.new_signature.z,
                signer_ids=bundle.new_signature.signer_ids,
            ),
        )
        self.assertFalse(
            verify_audit_extension_proof_bundle(tampered, self.key)
        )

    def test_signature_over_another_statement_returns_false(self):
        # The root statements bind (n, tree), so signatures of two
        # different extensions are not interchangeable even under one key.
        bundle_a = sealed_bundle(self.key, self.records[:5], 3, seed=7300)
        bundle_b = sealed_bundle(self.key, self.records[:6], 2, seed=7400)
        mixed = AuditExtensionProofBundle(
            bundle_a.proof, bundle_a.old_signature, bundle_b.new_signature
        )
        self.assertFalse(
            verify_audit_extension_proof_bundle(mixed, self.key)
        )

    def test_tampered_leaf_returns_false(self):
        bundle = sealed_bundle(self.key, self.records[:5], 3, seed=7450)
        proof = AuditExtensionProof(
            old_n=bundle.proof.old_n,
            leaves=(b"x" * 32,) + bundle.proof.leaves[1:],
        )
        self.assertFalse(
            verify_audit_extension_proof_bundle(
                AuditExtensionProofBundle(
                    proof, bundle.old_signature, bundle.new_signature
                ),
                self.key,
            )
        )

    def test_decoded_bundle_verifies_identically(self):
        bundle = sealed_bundle(self.key, self.records[:6], 4, seed=7500)
        decoded = decode_audit_extension_proof_bundle(
            encode_audit_extension_proof_bundle(bundle)
        )
        self.assertEqual(
            verify_audit_extension_proof_bundle(decoded, self.key),
            verify_audit_extension_proof_bundle(bundle, self.key),
        )

    def test_non_bundle_type_error(self):
        _old, _new, proof = make_extension(self.records[:4], 2)
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        for bad in (
            (proof, signature, signature),
            "bundle",
            None,
            proof,
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_audit_extension_proof_bundle(bad, self.key)

    def test_bad_nested_structure_value_error(self):
        bad_proof = AuditExtensionProof(0, (b"a" * 32, b"b" * 32))
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        bundle = AuditExtensionProofBundle(bad_proof, signature, signature)
        with self.assertRaises(ValueError):
            verify_audit_extension_proof_bundle(bundle, self.key)


if __name__ == "__main__":
    unittest.main()
