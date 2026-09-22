"""Tests for the canonical SealHistoryProofBundle transport encoding:
encode_history_proof_bundle / decode_history_proof_bundle /
verify_history_proof_bundle."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    NonceLeakReport,
    ReportSeal,
    SealHistory,
    SealHistoryProof,
    SealHistoryProofBundle,
    check_history_proof,
    decode_history_proof_bundle,
    encode_history_proof,
    encode_history_proof_bundle,
    make_history_proof,
    verify_history_proof_bundle,
)

from test_nonce_leak_codec import make_other_key
from test_report_seal import synthetic
from test_seal_history import make_history, make_key, sign_message

BUNDLE_TAG = b"ts/shpb/v1"


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def build_wire(bundle: SealHistoryProofBundle) -> bytes:
    """Independently build the bundle wire format straight from the spec."""
    proof_bytes = encode_history_proof(bundle.proof)
    signature = bundle.signature
    out = bytearray(BUNDLE_TAG)
    out += frame(proof_bytes)
    out += varint(signature.R)
    out += varint(signature.z)
    out += u32(len(signature.signer_ids))
    for signer_id in signature.signer_ids:
        out += varint(signer_id)
    return bytes(out)


def sealed_bundle(history, index, key, *, seed=800):
    """Return a signed SealHistoryProofBundle for the given index."""
    message, proof = make_history_proof(history, index)
    signature = sign_message(message, key, seed=seed + index)
    return SealHistoryProofBundle(proof, signature)


class BundleDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(SealHistoryProofBundle)],
            ["proof", "signature"],
        )
        seal = ReportSeal(
            NonceLeakReport((synthetic(1, 10),)),
            AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
        )
        proof = SealHistoryProof(0, 1, seal, ())
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        bundle = SealHistoryProofBundle(proof, signature)
        self.assertIs(bundle.proof, proof)
        self.assertIs(bundle.signature, signature)
        self.assertEqual(
            SealHistoryProofBundle(proof=proof, signature=signature),
            bundle,
        )

    def test_frozen_value_equality_and_hash(self):
        seal = ReportSeal(
            NonceLeakReport((synthetic(1, 10),)),
            AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
        )
        proof = SealHistoryProof(0, 1, seal, ())
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        bundle = SealHistoryProofBundle(proof, signature)
        same = SealHistoryProofBundle(proof, signature)
        self.assertEqual(bundle, same)
        self.assertEqual(hash(bundle), hash(same))
        self.assertNotEqual(
            bundle,
            SealHistoryProofBundle(
                proof, AggregateSignature(R=6, z=7, signer_ids=(1, 3))
            ),
        )
        with self.assertRaises(FrozenInstanceError):
            bundle.proof = proof

    def test_construction_does_not_validate(self):
        # A plain frozen value: non-proof and non-signature fields
        # construct; the codec and verifier reject them.
        SealHistoryProofBundle("not-a-proof", "not-a-signature")
        SealHistoryProofBundle(None, None)


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = make_history(
            self.key, nonces=tuple(700 + i for i in range(9))
        )

    def _history_of_size(self, n):
        return SealHistory(self.history.items[:n])

    def test_round_trip_for_every_size_and_index(self):
        for n in range(1, 10):
            history = self._history_of_size(n)
            for index in range(n):
                bundle = sealed_bundle(history, index, self.key, seed=2000 + n)
                wire = encode_history_proof_bundle(bundle)
                decoded = decode_history_proof_bundle(wire)
                self.assertEqual(decoded, bundle, msg=f"n={n} index={index}")
                self.assertEqual(
                    encode_history_proof_bundle(decoded), wire
                )

    def test_encoding_matches_independent_builder(self):
        for n in range(1, 10):
            history = self._history_of_size(n)
            for index in range(n):
                bundle = sealed_bundle(history, index, self.key, seed=3000 + n)
                self.assertEqual(
                    encode_history_proof_bundle(bundle),
                    build_wire(bundle),
                    msg=f"n={n} index={index}",
                )

    def test_prefix_is_tag_length_and_full_proof_encoding(self):
        bundle = sealed_bundle(self.history, 4, self.key, seed=4000)
        wire = encode_history_proof_bundle(bundle)
        self.assertTrue(wire.startswith(BUNDLE_TAG))
        offset = len(BUNDLE_TAG)
        proof_bytes = encode_history_proof(bundle.proof)
        self.assertEqual(wire[offset:offset + 4], u32(len(proof_bytes)))
        offset += 4
        self.assertEqual(wire[offset:offset + len(proof_bytes)], proof_bytes)
        # The nested proof keeps its own distinct wire tag.
        self.assertTrue(
            proof_bytes.startswith(b"thresholdsign/seal-history-proof/v1")
        )

    def test_suffix_is_r_z_count_and_ids(self):
        bundle = sealed_bundle(self.history, 4, self.key, seed=4100)
        wire = encode_history_proof_bundle(bundle)
        proof_bytes = encode_history_proof(bundle.proof)
        suffix = wire[len(BUNDLE_TAG) + 4 + len(proof_bytes):]
        signature = bundle.signature
        expected = bytearray()
        expected += varint(signature.R)
        expected += varint(signature.z)
        expected += u32(len(signature.signer_ids))
        for signer_id in signature.signer_ids:
            expected += varint(signer_id)
        self.assertEqual(suffix, bytes(expected))

    def test_zero_z_encodes_as_single_body_byte(self):
        bundle = sealed_bundle(self.history, 0, self.key, seed=4200)
        bundle = SealHistoryProofBundle(
            bundle.proof,
            AggregateSignature(
                R=bundle.signature.R,
                z=0,
                signer_ids=bundle.signature.signer_ids,
            ),
        )
        wire = encode_history_proof_bundle(bundle)
        proof_bytes = encode_history_proof(bundle.proof)
        offset = len(BUNDLE_TAG) + 4 + len(proof_bytes)
        # R varint precedes z; z = 0 -> VARINT 00 00 00 01 00.
        offset += len(varint(bundle.signature.R))
        self.assertEqual(wire[offset:offset + 5], b"\x00\x00\x00\x01\x00")

    def test_decoded_bundle_still_verifies(self):
        for n in range(1, 10):
            history = self._history_of_size(n)
            for index in range(n):
                bundle = sealed_bundle(history, index, self.key, seed=5000 + n)
                decoded = decode_history_proof_bundle(
                    encode_history_proof_bundle(bundle)
                )
                self.assertTrue(
                    verify_history_proof_bundle(decoded, self.key),
                    msg=f"n={n} index={index}",
                )

    def test_encoding_is_unique_and_stateless(self):
        bundle = sealed_bundle(self.history, 5, self.key, seed=4300)
        self.assertEqual(
            encode_history_proof_bundle(bundle),
            encode_history_proof_bundle(bundle),
        )


class StructureOnlyTest(unittest.TestCase):
    def _synthetic_proof(self):
        # A structurally legal synthetic seal that never went through a
        # real key round-trip untouched; n=2 gives exactly one sibling.
        seal = ReportSeal(
            NonceLeakReport((synthetic(1, 10),)),
            AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
        )
        return SealHistoryProof(0, 2, seal, (b"s" * 32,))

    def test_decode_does_not_verify_seal_or_signature(self):
        proof = self._synthetic_proof()
        signature = AggregateSignature(R=9, z=11, signer_ids=(2, 4))
        bundle = SealHistoryProofBundle(proof, signature)
        decoded = decode_history_proof_bundle(
            encode_history_proof_bundle(bundle)
        )
        self.assertEqual(decoded, bundle)

    def test_encoding_does_not_check_the_signature_against_the_root(self):
        # A bundle signed by one key but presented under another encodes
        # fine — structure alone is checked; verify reports it as False.
        history = make_history(make_key(), nonces=(700, 701))
        bundle = sealed_bundle(history, 0, make_key(), seed=4400)
        self.assertTrue(encode_history_proof_bundle(bundle))
        self.assertFalse(
            verify_history_proof_bundle(bundle, make_other_key())
        )


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = make_history(
            self.key, nonces=tuple(800 + i for i in range(5))
        )
        self.bundle = sealed_bundle(self.history, 2, self.key, seed=4500)

    def test_non_bundle_type_error(self):
        with self.assertRaises(TypeError):
            encode_history_proof_bundle(("proof", "signature"))
        with self.assertRaises(TypeError):
            encode_history_proof_bundle(None)

    def test_non_proof_field_type_error(self):
        with self.assertRaises(TypeError):
            encode_history_proof_bundle(
                SealHistoryProofBundle("not-a-proof", self.bundle.signature)
            )
        with self.assertRaises(TypeError):
            encode_history_proof_bundle(
                SealHistoryProofBundle(None, self.bundle.signature)
            )

    def test_non_signature_field_type_error(self):
        with self.assertRaises(TypeError):
            encode_history_proof_bundle(
                SealHistoryProofBundle(self.bundle.proof, "no")
            )
        with self.assertRaises(TypeError):
            encode_history_proof_bundle(
                SealHistoryProofBundle(self.bundle.proof, None)
            )

    def test_signature_field_type_errors(self):
        signature = self.bundle.signature
        for bad in (
            AggregateSignature(True, signature.z, signature.signer_ids),
            AggregateSignature("5", signature.z, signature.signer_ids),
            AggregateSignature(signature.R, False, signature.signer_ids),
            AggregateSignature(signature.R, "7", signature.signer_ids),
            AggregateSignature(signature.R, signature.z, [1, 3]),
            AggregateSignature(signature.R, signature.z, (1, "3")),
            AggregateSignature(signature.R, signature.z, (True, 3)),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_history_proof_bundle(
                    SealHistoryProofBundle(self.bundle.proof, bad)
                )

    def test_bad_nested_proof_structure_value_error(self):
        bad_proof = SealHistoryProof(
            index=0, total=0, seal=self.bundle.proof.seal, siblings=()
        )
        with self.assertRaises(ValueError):
            encode_history_proof_bundle(
                SealHistoryProofBundle(bad_proof, self.bundle.signature)
            )

    def test_signature_value_errors(self):
        signature = self.bundle.signature
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
            with self.assertRaises(ValueError, msg=repr(bad)):
                encode_history_proof_bundle(
                    SealHistoryProofBundle(self.bundle.proof, bad)
                )


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = make_history(
            self.key, nonces=tuple(900 + i for i in range(5))
        )
        self.bundle = sealed_bundle(self.history, 2, self.key, seed=4600)
        self.wire = encode_history_proof_bundle(self.bundle)
        self.proof_bytes = encode_history_proof(self.bundle.proof)

    def test_non_bytes_type_error(self):
        with self.assertRaises(TypeError):
            decode_history_proof_bundle("not bytes")
        with self.assertRaises(TypeError):
            decode_history_proof_bundle(bytearray(self.wire))

    def test_bad_tag(self):
        rest = self.wire[len(BUNDLE_TAG):]
        with self.assertRaises(ValueError):
            decode_history_proof_bundle(b"ts/shpb/v2" + rest)
        with self.assertRaises(ValueError):
            decode_history_proof_bundle(b"x" + self.wire[1:])

    def test_truncation(self):
        for cut in range(len(BUNDLE_TAG), len(self.wire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_history_proof_bundle(self.wire[:cut])

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_history_proof_bundle(self.wire + b"\x00")

    def test_zero_proof_frame_rejected(self):
        bad = (
            BUNDLE_TAG
            + u32(0)
            + self.wire[len(BUNDLE_TAG) + 4 + len(self.proof_bytes):]
        )
        with self.assertRaises(ValueError):
            decode_history_proof_bundle(bad)

    def test_junk_proof_frame_rejected(self):
        suffix = self.wire[
            len(BUNDLE_TAG) + 4 + len(self.proof_bytes):
        ]
        bad = BUNDLE_TAG + frame(b"not-a-proof") + suffix
        with self.assertRaises(ValueError):
            decode_history_proof_bundle(bad)

    def test_declared_proof_frame_length_mismatch(self):
        # Declaring the frame one byte shorter hides a proof byte inside
        # what the parser then reads as the R varint length.
        bad = bytearray(self.wire)
        length_offset = len(BUNDLE_TAG)
        declared = len(self.proof_bytes) - 1
        bad[length_offset:length_offset + 4] = u32(declared)
        with self.assertRaises(ValueError):
            decode_history_proof_bundle(bytes(bad))

    def test_zero_R_rejected(self):
        suffix_offset = len(BUNDLE_TAG) + 4 + len(self.proof_bytes)
        bad = (
            self.wire[:suffix_offset]
            + varint(0)
            + self.wire[suffix_offset + len(varint(self.bundle.signature.R)):]
        )
        with self.assertRaises(ValueError):
            decode_history_proof_bundle(bad)

    def test_non_canonical_R_leading_zero(self):
        # Use a structurally legal small-R signature so the one-byte
        # canonical body 09 can be padded to the non-canonical 00 09.
        bundle = SealHistoryProofBundle(
            self.bundle.proof,
            AggregateSignature(R=9, z=7, signer_ids=(1, 3)),
        )
        wire = encode_history_proof_bundle(bundle)
        proof_bytes = self.proof_bytes
        suffix_offset = len(BUNDLE_TAG) + 4 + len(proof_bytes)
        non_canonical_R = (1).to_bytes(4, "big") + b"\x00\x09"
        canonical_R = varint(9)
        bad = (
            wire[:suffix_offset]
            + non_canonical_R
            + wire[suffix_offset + len(canonical_R):]
        )
        with self.assertRaises(ValueError):
            decode_history_proof_bundle(bad)

    def test_zero_signer_count_rejected(self):
        signature = self.bundle.signature
        tail_offset = (
            len(BUNDLE_TAG)
            + 4
            + len(self.proof_bytes)
            + len(varint(signature.R))
            + len(varint(signature.z))
        )
        bad = self.wire[:tail_offset] + u32(0)
        with self.assertRaises(ValueError):
            decode_history_proof_bundle(bad)

    def test_signer_count_too_large_then_truncated(self):
        signature = self.bundle.signature
        tail_offset = (
            len(BUNDLE_TAG)
            + 4
            + len(self.proof_bytes)
            + len(varint(signature.R))
            + len(varint(signature.z))
        )
        bad = self.wire[:tail_offset] + u32(len(signature.signer_ids) + 1)
        for signer_id in signature.signer_ids:
            bad += varint(signer_id)
        with self.assertRaises(ValueError):
            decode_history_proof_bundle(bad)

    def test_non_positive_and_unsorted_signer_ids_rejected(self):
        signature = self.bundle.signature
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
            with self.assertRaises(ValueError, msg=label):
                decode_history_proof_bundle(bytes(out))


class VerifyBundleTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.other = make_other_key()
        self.history = make_history(
            self.key, nonces=tuple(600 + i for i in range(8))
        )

    def _history_of_size(self, n):
        return SealHistory(self.history.items[:n])

    def test_honest_bundles_verify_for_every_size_and_index(self):
        for n in range(1, 9):
            history = self._history_of_size(n)
            for index in range(n):
                bundle = sealed_bundle(history, index, self.key, seed=6000 + n)
                self.assertTrue(
                    verify_history_proof_bundle(bundle, self.key),
                    msg=f"n={n} index={index}",
                )

    def test_result_equals_check_history_proof(self):
        for n in range(1, 9):
            history = self._history_of_size(n)
            for index in range(n):
                bundle = sealed_bundle(history, index, self.key, seed=7000 + n)
                self.assertEqual(
                    verify_history_proof_bundle(bundle, self.key),
                    check_history_proof(
                        bundle.proof, bundle.signature, self.key
                    ),
                    msg=f"n={n} index={index}",
                )

    def test_wrong_key_returns_false(self):
        bundle = sealed_bundle(self.history, 3, self.key, seed=7100)
        self.assertFalse(
            verify_history_proof_bundle(bundle, self.other)
        )

    def test_tampered_signature_returns_false(self):
        bundle = sealed_bundle(self.history, 3, self.key, seed=7200)
        # A valid R of a different real round is still a subgroup element,
        # so the check runs and returns False rather than raising.
        other_message, _ = make_history_proof(self._history_of_size(3), 1)
        other_signature = sign_message(other_message, self.key, seed=7210)
        tampered = SealHistoryProofBundle(
            bundle.proof,
            AggregateSignature(
                R=other_signature.R,
                z=bundle.signature.z,
                signer_ids=bundle.signature.signer_ids,
            ),
        )
        self.assertFalse(
            verify_history_proof_bundle(tampered, self.key)
        )

    def test_signature_over_another_statement_returns_false(self):
        # The root binds (total, tree), so proofs of two different trees
        # are not interchangeable even under the same key.
        short = SealHistory(self.history.items[:4])
        long_ = SealHistory(self.history.items[:6])
        bundle_a = sealed_bundle(short, 0, self.key, seed=7300)
        bundle_b = sealed_bundle(long_, 1, self.key, seed=7400)
        mixed = SealHistoryProofBundle(bundle_a.proof, bundle_b.signature)
        self.assertFalse(
            verify_history_proof_bundle(mixed, self.key)
        )

    def test_tampered_sibling_returns_false(self):
        bundle = sealed_bundle(self.history, 2, self.key, seed=7450)
        if not bundle.proof.siblings:
            self.skipTest("chosen position needs a non-empty sibling path")
        proof = SealHistoryProof(
            index=bundle.proof.index,
            total=bundle.proof.total,
            seal=bundle.proof.seal,
            siblings=(b"x" * 32,) + bundle.proof.siblings[1:],
        )
        self.assertFalse(
            verify_history_proof_bundle(
                SealHistoryProofBundle(proof, bundle.signature), self.key
            )
        )

    def test_decoded_bundle_verifies_identically(self):
        bundle = sealed_bundle(self.history, 4, self.key, seed=7500)
        decoded = decode_history_proof_bundle(
            encode_history_proof_bundle(bundle)
        )
        self.assertEqual(
            verify_history_proof_bundle(decoded, self.key),
            verify_history_proof_bundle(bundle, self.key),
        )

    def test_non_bundle_type_error(self):
        _message, proof = make_history_proof(self.history, 0)
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        for bad in ((proof, signature), "bundle", None, proof):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_history_proof_bundle(bad, self.key)

    def test_bad_nested_structure_value_error(self):
        bad_proof = SealHistoryProof(
            index=0, total=0, seal=self.history.items[0], siblings=()
        )
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        bundle = SealHistoryProofBundle(bad_proof, signature)
        with self.assertRaises(ValueError):
            verify_history_proof_bundle(bundle, self.key)


if __name__ == "__main__":
    unittest.main()
