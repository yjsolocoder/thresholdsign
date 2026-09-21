"""Tests for the canonical SealHistoryMultiProofBundle transport:
SealHistoryMultiProofBundle / encode_history_multi_proof_bundle /
decode_history_multi_proof_bundle / verify_history_multi_proof_bundle."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    NonceLeakReport,
    ReportSeal,
    SealHistory,
    SealHistoryMultiProof,
    SealHistoryMultiProofBundle,
    check_history_multi_proof,
    decode_history_multi_proof,
    decode_history_multi_proof_bundle,
    encode_history_multi_proof,
    encode_history_multi_proof_bundle,
    make_history_multi_proof,
    verify_history_multi_proof_bundle,
)

from test_nonce_leak_codec import make_other_key
from test_nonce_reuse import FIELD_PRIME, make_key
from test_report_seal import synthetic
from test_seal_history import make_history, sign_message

BUNDLE_TAG = b"ts/shmpb/v1"


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def build_wire(bundle: SealHistoryMultiProofBundle) -> bytes:
    """Independently build the bundle wire format straight from the spec."""
    proof_bytes = encode_history_multi_proof(bundle.proof)
    signature = bundle.signature
    out = bytearray(BUNDLE_TAG)
    out += u32(len(proof_bytes))
    out += proof_bytes
    out += varint(signature.R)
    out += varint(signature.z)
    out += u32(len(signature.signer_ids))
    for signer_id in signature.signer_ids:
        out += varint(signer_id)
    return bytes(out)


def signed_bundle(history, indices, key, *, seed=800):
    """A real threshold-signed multi-proof bundle."""
    message, proof = make_history_multi_proof(history, indices)
    signature = sign_message(message, key, seed=seed + sum(indices))
    return SealHistoryMultiProofBundle(proof, signature)


class SealHistoryMultiProofBundleDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [
                field.name
                for field in dataclasses.fields(SealHistoryMultiProofBundle)
            ],
            ["proof", "signature"],
        )
        proof = SealHistoryMultiProof((0,), 1, (), ())
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        bundle = SealHistoryMultiProofBundle(proof, signature)
        self.assertIs(bundle.proof, proof)
        self.assertIs(bundle.signature, signature)
        self.assertEqual(
            bundle,
            SealHistoryMultiProofBundle(proof=proof, signature=signature),
        )

    def test_frozen_value_equality_and_hash(self):
        proof = SealHistoryMultiProof((0,), 1, (), ())
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        bundle = SealHistoryMultiProofBundle(proof, signature)
        self.assertEqual(
            bundle, SealHistoryMultiProofBundle(proof, signature)
        )
        self.assertEqual(
            hash(bundle), hash(SealHistoryMultiProofBundle(proof, signature))
        )
        self.assertNotEqual(
            bundle,
            SealHistoryMultiProofBundle(
                proof, AggregateSignature(R=6, z=7, signer_ids=(1, 3))
            ),
        )
        with self.assertRaises(FrozenInstanceError):
            bundle.proof = proof


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
            root_message, _ = make_history_multi_proof(history, (0,))
            signature = sign_message(root_message, self.key, seed=1000 + n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                _message, proof = make_history_multi_proof(history, indices)
                bundle = SealHistoryMultiProofBundle(proof, signature)
                wire = encode_history_multi_proof_bundle(bundle)
                decoded = decode_history_multi_proof_bundle(wire)
                self.assertEqual(
                    decoded, bundle, msg=f"n={n} indices={indices}"
                )
                self.assertEqual(
                    encode_history_multi_proof_bundle(decoded), wire
                )
                self.assertEqual(
                    decoded.proof,
                    decode_history_multi_proof(
                        encode_history_multi_proof(proof)
                    ),
                )

    def test_encoding_matches_independent_builder(self):
        for n in range(1, 10):
            history = self._history_of_size(n)
            masks = [1, 0b101, (1 << n) - 1]
            for mask in masks:
                indices = tuple(i for i in range(n) if mask & (1 << i))
                bundle = signed_bundle(history, indices, self.key)
                self.assertEqual(
                    encode_history_multi_proof_bundle(bundle),
                    build_wire(bundle),
                    msg=f"n={n} indices={indices}",
                )

    def test_starts_with_tag_and_length_framed_proof(self):
        bundle = signed_bundle(self.history, (2, 4), self.key)
        wire = encode_history_multi_proof_bundle(bundle)
        self.assertTrue(wire.startswith(BUNDLE_TAG))
        offset = len(BUNDLE_TAG)
        proof_bytes = encode_history_multi_proof(bundle.proof)
        self.assertEqual(wire[offset:offset + 4], u32(len(proof_bytes)))
        offset += 4
        self.assertEqual(wire[offset:offset + len(proof_bytes)], proof_bytes)
        offset += len(proof_bytes)
        encoded_R = varint(bundle.signature.R)
        self.assertEqual(wire[offset:offset + len(encoded_R)], encoded_R)

    def test_signature_suffix_layout(self):
        bundle = signed_bundle(self.history, (0,), self.key)
        wire = encode_history_multi_proof_bundle(bundle)
        proof_bytes = encode_history_multi_proof(bundle.proof)
        offset = len(BUNDLE_TAG) + 4 + len(proof_bytes)
        signature = bundle.signature
        self.assertEqual(wire[offset:offset + len(varint(signature.R))],
                         varint(signature.R))
        offset += len(varint(signature.R))
        self.assertEqual(wire[offset:offset + len(varint(signature.z))],
                         varint(signature.z))
        offset += len(varint(signature.z))
        self.assertEqual(
            wire[offset:offset + 4], u32(len(signature.signer_ids))
        )
        offset += 4
        for signer_id in signature.signer_ids:
            self.assertEqual(wire[offset:offset + len(varint(signer_id))],
                             varint(signer_id))
            offset += len(varint(signer_id))
        self.assertEqual(offset, len(wire))

    def test_zero_z_encodes_as_single_body_byte(self):
        bundle = signed_bundle(self.history, (0,), self.key)
        bundle = SealHistoryMultiProofBundle(
            bundle.proof,
            AggregateSignature(
                R=bundle.signature.R, z=0,
                signer_ids=bundle.signature.signer_ids,
            ),
        )
        wire = encode_history_multi_proof_bundle(bundle)
        proof_bytes = encode_history_multi_proof(bundle.proof)
        offset = len(BUNDLE_TAG) + 4 + len(proof_bytes)
        # VARINT(R) then VARINT(0) = 00 00 00 01 00.
        r_body = max(1, (bundle.signature.R.bit_length() + 7) // 8)
        r_len = 4 + r_body
        self.assertEqual(
            wire[offset + r_len:offset + r_len + 5],
            b"\x00\x00\x00\x01\x00",
        )

    def test_decoded_bundle_verifies(self):
        for n in range(1, 10):
            history = self._history_of_size(n)
            bundle = signed_bundle(
                history, tuple(range(n)), self.key, seed=2000 + n
            )
            decoded = decode_history_multi_proof_bundle(
                encode_history_multi_proof_bundle(bundle)
            )
            self.assertTrue(
                verify_history_multi_proof_bundle(decoded, self.key),
                msg=f"n={n}",
            )

    def test_verify_matches_check_history_multi_proof(self):
        cases = []
        history = self._history_of_size(6)
        good = signed_bundle(history, (0, 2, 4), self.key)
        cases.append(("good", good))
        cases.append((
            "bad z",
            SealHistoryMultiProofBundle(
                good.proof,
                dataclasses.replace(
                    good.signature,
                    z=(good.signature.z + 1) % FIELD_PRIME,
                ),
            ),
        ))
        other_key = make_other_key()
        cases.append(("other key bundle", good))
        # A tampered seal inside the proof.
        tampered = dataclasses.replace(
            good.proof,
            seals=(self.history.items[1],) + good.proof.seals[1:],
        )
        cases.append((
            "tampered seal",
            SealHistoryMultiProofBundle(tampered, good.signature),
        ))
        for name, bundle in cases:
            key = other_key if name == "other key bundle" else self.key
            self.assertEqual(
                verify_history_multi_proof_bundle(bundle, key),
                check_history_multi_proof(
                    bundle.proof, bundle.signature, key
                ),
                msg=name,
            )

    def test_encoding_is_unique_and_stateless(self):
        bundle = signed_bundle(self.history, (1, 3, 5), self.key)
        self.assertEqual(
            encode_history_multi_proof_bundle(bundle),
            encode_history_multi_proof_bundle(bundle),
        )


class StructureOnlyTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()

    def test_decode_does_not_verify_seals_or_signature(self):
        # Structurally legal synthetic proof and signature that never went
        # through a real key round-trip untouched.
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
        signature = AggregateSignature(R=9, z=0, signer_ids=(2, 4, 6))
        bundle = SealHistoryMultiProofBundle(proof, signature)
        decoded = decode_history_multi_proof_bundle(
            encode_history_multi_proof_bundle(bundle)
        )
        self.assertEqual(decoded, bundle)

    def test_encode_does_not_check_the_signature_against_the_proof(self):
        # A signature plainly unrelated to the proof's root is still
        # encoded: verification stays the sole judge.
        history = make_history(self.key, nonces=(801, 802, 803))
        bundle = signed_bundle(history, (0, 2), self.key)
        unrelated = AggregateSignature(
            R=bundle.signature.R + 1,
            z=bundle.signature.z,
            signer_ids=bundle.signature.signer_ids,
        )
        self.assertTrue(
            encode_history_multi_proof_bundle(
                SealHistoryMultiProofBundle(bundle.proof, unrelated)
            )
        )


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = make_history(self.key, nonces=(810, 811, 812))
        self.bundle = signed_bundle(self.history, (1, 2), self.key)

    def test_non_bundle_type_error(self):
        with self.assertRaises(TypeError):
            encode_history_multi_proof_bundle(
                (self.bundle.proof, self.bundle.signature)
            )
        with self.assertRaises(TypeError):
            encode_history_multi_proof_bundle("bundle")

    def test_bad_proof_type_errors(self):
        with self.assertRaises(TypeError):
            encode_history_multi_proof_bundle(
                SealHistoryMultiProofBundle(
                    "proof", self.bundle.signature
                )
            )
        bad_proof = SealHistoryMultiProof(
            [1, 2],
            self.bundle.proof.total,
            self.bundle.proof.seals,
            self.bundle.proof.siblings,
        )
        with self.assertRaises(TypeError):
            encode_history_multi_proof_bundle(
                SealHistoryMultiProofBundle(
                    bad_proof, self.bundle.signature
                )
            )

    def test_bad_proof_structure_value_error(self):
        bad_proof = SealHistoryMultiProof(
            (), 5, (), ()
        )
        with self.assertRaises(ValueError):
            encode_history_multi_proof_bundle(
                SealHistoryMultiProofBundle(
                    bad_proof, self.bundle.signature
                )
            )

    def test_bad_signature_type_errors(self):
        for bad in (
            "signature",
            None,
            AggregateSignature(
                R=True, z=7, signer_ids=(1, 3)
            ),
            AggregateSignature(
                R=5, z="7", signer_ids=(1, 3)
            ),
            AggregateSignature(
                R=5, z=7, signer_ids=[1, 3]
            ),
            AggregateSignature(
                R=5, z=7, signer_ids=(1, True)
            ),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_history_multi_proof_bundle(
                    SealHistoryMultiProofBundle(self.bundle.proof, bad)
                )

    def test_bad_signature_structure_value_errors(self):
        for bad in (
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=-1, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=-1, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=7, signer_ids=()),
            AggregateSignature(R=5, z=7, signer_ids=(0, 3)),
            AggregateSignature(R=5, z=7, signer_ids=(3, 1)),
            AggregateSignature(R=5, z=7, signer_ids=(1, 1)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                encode_history_multi_proof_bundle(
                    SealHistoryMultiProofBundle(self.bundle.proof, bad)
                )

    def test_illegal_nested_seal_value_error(self):
        bad_seal = ReportSeal(
            NonceLeakReport((synthetic(1, 10),)),
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
        )
        bad_proof = dataclasses.replace(
            self.bundle.proof, seals=(bad_seal,) + self.bundle.proof.seals[1:]
        )
        with self.assertRaises(ValueError):
            encode_history_multi_proof_bundle(
                SealHistoryMultiProofBundle(
                    bad_proof, self.bundle.signature
                )
            )


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = make_history(self.key, nonces=(910, 911, 912))
        self.bundle = signed_bundle(self.history, (1, 2), self.key)
        self.wire = encode_history_multi_proof_bundle(self.bundle)

    def test_non_bytes_type_error(self):
        with self.assertRaises(TypeError):
            decode_history_multi_proof_bundle("not bytes")
        with self.assertRaises(TypeError):
            decode_history_multi_proof_bundle(bytearray(self.wire))

    def test_bad_tag(self):
        with self.assertRaises(ValueError):
            decode_history_multi_proof_bundle(
                b"ts/shmpb/v2" + self.wire[len(BUNDLE_TAG):]
            )
        with self.assertRaises(ValueError):
            decode_history_multi_proof_bundle(b"x" + self.wire[1:])

    def test_truncation(self):
        for cut in range(0, len(self.wire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_history_multi_proof_bundle(self.wire[:cut])

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_history_multi_proof_bundle(self.wire + b"\x00")

    def test_header_truncation(self):
        with self.assertRaises(ValueError):
            decode_history_multi_proof_bundle(BUNDLE_TAG)
        with self.assertRaises(ValueError):
            decode_history_multi_proof_bundle(BUNDLE_TAG + b"\x00\x00")

    def test_zero_proof_frame_length_rejected(self):
        offset = len(BUNDLE_TAG)
        bad = self.wire[:offset] + u32(0) + self.wire[offset + 4:]
        with self.assertRaises(ValueError):
            decode_history_multi_proof_bundle(bad)

    def test_declared_frame_longer_than_blob(self):
        offset = len(BUNDLE_TAG)
        proof_len = len(encode_history_multi_proof(self.bundle.proof))
        bad = (
            self.wire[:offset]
            + u32(proof_len + 1)
            + self.wire[offset + 4:]
        )
        with self.assertRaises(ValueError):
            decode_history_multi_proof_bundle(bad)

    def test_junk_nested_proof_rejected(self):
        # Same frame length as P but with the nested tag swapped: the frame
        # parses and the nested decoder rejects it.
        proof_bytes = encode_history_multi_proof(self.bundle.proof)
        offset = len(BUNDLE_TAG) + 4
        junk = (
            b"thresholdsign/seal-history-multi-proof/v2"
            + proof_bytes[len(b"thresholdsign/seal-history-multi-proof/v1"):]
        )
        self.assertEqual(len(junk), len(proof_bytes))
        bad = self.wire[:offset] + junk + self.wire[offset + len(proof_bytes):]
        with self.assertRaises(ValueError):
            decode_history_multi_proof_bundle(bad)

    def test_zero_R_rejected(self):
        proof_bytes = encode_history_multi_proof(self.bundle.proof)
        suffix_offset = len(BUNDLE_TAG) + 4 + len(proof_bytes)
        suffix = self.wire[suffix_offset:]
        bad_suffix = varint(0) + suffix[len(varint(self.bundle.signature.R)):]
        with self.assertRaises(ValueError):
            decode_history_multi_proof_bundle(
                self.wire[:suffix_offset] + bad_suffix
            )

    def test_zero_signer_count_rejected(self):
        proof_bytes = encode_history_multi_proof(self.bundle.proof)
        suffix_offset = len(BUNDLE_TAG) + 4 + len(proof_bytes)
        r = varint(self.bundle.signature.R)
        z = varint(self.bundle.signature.z)
        bad = self.wire[:suffix_offset] + r + z + u32(0)
        with self.assertRaises(ValueError):
            decode_history_multi_proof_bundle(bad)

    def test_non_positive_signer_id_rejected(self):
        proof_bytes = encode_history_multi_proof(self.bundle.proof)
        suffix_offset = len(BUNDLE_TAG) + 4 + len(proof_bytes)
        signature = self.bundle.signature
        suffix = (
            varint(signature.R)
            + varint(signature.z)
            + u32(1)
            + varint(0)
        )
        with self.assertRaises(ValueError):
            decode_history_multi_proof_bundle(
                self.wire[:suffix_offset] + suffix
            )

    def test_non_increasing_signer_ids_rejected(self):
        proof_bytes = encode_history_multi_proof(self.bundle.proof)
        suffix_offset = len(BUNDLE_TAG) + 4 + len(proof_bytes)
        signature = self.bundle.signature
        suffix = (
            varint(signature.R)
            + varint(signature.z)
            + u32(2)
            + varint(3)
            + varint(1)
        )
        with self.assertRaises(ValueError):
            decode_history_multi_proof_bundle(
                self.wire[:suffix_offset] + suffix
            )

    def test_signer_count_mismatch_rejected(self):
        proof_bytes = encode_history_multi_proof(self.bundle.proof)
        suffix_offset = len(BUNDLE_TAG) + 4 + len(proof_bytes)
        signature = self.bundle.signature
        # Declares two signers, only one id follows -> truncation.
        suffix = (
            varint(signature.R)
            + varint(signature.z)
            + u32(2)
            + varint(signature.signer_ids[0])
        )
        with self.assertRaises(ValueError):
            decode_history_multi_proof_bundle(
                self.wire[:suffix_offset] + suffix
            )

    def test_non_canonical_R_leading_zero_rejected(self):
        proof_bytes = encode_history_multi_proof(self.bundle.proof)
        suffix_offset = len(BUNDLE_TAG) + 4 + len(proof_bytes)
        signature = self.bundle.signature
        r_body = signature.R.to_bytes(
            (signature.R.bit_length() + 7) // 8, "big"
        )
        # Length prefix claims one extra byte and the body starts with 00.
        bad_R = (len(r_body) + 1).to_bytes(4, "big") + b"\x00" + r_body
        suffix = (
            bad_R
            + varint(signature.z)
            + u32(len(signature.signer_ids))
            + b"".join(varint(i) for i in signature.signer_ids)
        )
        with self.assertRaises(ValueError):
            decode_history_multi_proof_bundle(
                self.wire[:suffix_offset] + suffix
            )

    def test_non_canonical_frame_length_rejected(self):
        # A longer-but-canonical P cannot exist (the nested proof alone
        # would not decode); a frame length one byte short makes the nested
        # decoder see truncation.
        proof_bytes = encode_history_multi_proof(self.bundle.proof)
        offset = len(BUNDLE_TAG)
        bad = (
            self.wire[:offset]
            + u32(len(proof_bytes) - 1)
            + self.wire[offset + 4:]
        )
        with self.assertRaises(ValueError):
            decode_history_multi_proof_bundle(bad)


class VerifyHistoryMultiProofBundleTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = make_history(self.key, nonces=(820, 821, 822))
        self.bundle = signed_bundle(self.history, (0, 2), self.key)

    def test_honest_bundle_verifies(self):
        self.assertTrue(
            verify_history_multi_proof_bundle(self.bundle, self.key)
        )

    def test_decoded_bundle_verifies(self):
        decoded = decode_history_multi_proof_bundle(
            encode_history_multi_proof_bundle(self.bundle)
        )
        self.assertTrue(
            verify_history_multi_proof_bundle(decoded, self.key)
        )

    def test_bad_signature_returns_false(self):
        bad = SealHistoryMultiProofBundle(
            self.bundle.proof,
            dataclasses.replace(
                self.bundle.signature,
                z=(self.bundle.signature.z + 1) % FIELD_PRIME,
            ),
        )
        self.assertFalse(
            verify_history_multi_proof_bundle(bad, self.key)
        )

    def test_wrong_key_returns_false(self):
        other_key = make_other_key()
        self.assertNotEqual(other_key.public_key, self.key.public_key)
        self.assertFalse(
            verify_history_multi_proof_bundle(self.bundle, other_key)
        )

    def test_non_bundle_type_error(self):
        with self.assertRaises(TypeError):
            verify_history_multi_proof_bundle("bundle", self.key)
        with self.assertRaises(TypeError):
            verify_history_multi_proof_bundle(
                (self.bundle.proof, self.bundle.signature), self.key
            )

    def test_structure_error_propagates_value_error(self):
        bad_proof = SealHistoryMultiProof(
            (), 5, (), ()
        )
        bad_bundle = SealHistoryMultiProofBundle(
            bad_proof, self.bundle.signature
        )
        with self.assertRaises(ValueError):
            verify_history_multi_proof_bundle(bad_bundle, self.key)


if __name__ == "__main__":
    unittest.main()
