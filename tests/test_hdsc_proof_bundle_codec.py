"""Tests for the canonical HDSCProofBundle transport encoding:
encode_hdsc_proof_bundle / decode_hdsc_proof_bundle /
verify_hdsc_proof_bundle."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    HDSCProof,
    HDSCProofBundle,
    HistoryDeltaSegmentsSeal,
    HistoryDeltaSegmentsSealChain,
    check_hdsc_proof,
    decode_hdsc_proof,
    decode_hdsc_proof_bundle,
    encode_hdsc_proof,
    encode_hdsc_proof_bundle,
    make_hdsc_proof,
    verify_hdsc_proof_bundle,
)

from test_nonce_leak_codec import make_other_key
from test_nonce_reuse import make_key
from test_audit_chain import sign_message
from test_history_delta_segments_codec import build_segments
from test_history_delta_segments_seal import make_seal
from test_hdsc_proof import chain_of_size, seals_of_size

BUNDLE_TAG = b"ts/hdscpb/v1"


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def build_wire(bundle: HDSCProofBundle) -> bytes:
    """Independently build the bundle wire format straight from the spec."""
    proof_bytes = encode_hdsc_proof(bundle.proof)
    signature = bundle.signature
    out = bytearray(BUNDLE_TAG)
    out += frame(proof_bytes)
    out += varint(signature.R)
    out += varint(signature.z)
    out += u32(len(signature.signer_ids))
    for signer_id in signature.signer_ids:
        out += varint(signer_id)
    return bytes(out)


def sealed_bundle(chain, indices, key, *, seed=8000):
    """Return a signed HDSCProofBundle for the given indices."""
    message, proof = make_hdsc_proof(chain, indices)
    signature = sign_message(key, message, seed=seed + sum(indices))
    return HDSCProofBundle(proof, signature)


class BundleDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(HDSCProofBundle)],
            ["proof", "signature"],
        )
        key, _delta, segments = build_segments()
        seal = make_seal((segments[0],), key, seed=8010)
        proof = HDSCProof((0,), 1, (seal,), ())
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        bundle = HDSCProofBundle(proof, signature)
        self.assertIs(bundle.proof, proof)
        self.assertIs(bundle.signature, signature)
        self.assertEqual(
            HDSCProofBundle(proof=proof, signature=signature),
            bundle,
        )

    def test_frozen_value_equality_and_hash(self):
        key, _delta, segments = build_segments()
        seal = make_seal((segments[0],), key, seed=8020)
        proof = HDSCProof((0,), 1, (seal,), ())
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        bundle = HDSCProofBundle(proof, signature)
        same = HDSCProofBundle(proof, signature)
        self.assertEqual(bundle, same)
        self.assertEqual(hash(bundle), hash(same))
        self.assertNotEqual(
            bundle,
            HDSCProofBundle(
                proof, AggregateSignature(R=6, z=7, signer_ids=(1, 3))
            ),
        )
        with self.assertRaises(FrozenInstanceError):
            bundle.proof = proof

    def test_construction_does_not_validate(self):
        # A plain frozen value: non-proof and non-signature fields
        # construct; the codec and verifier reject them.
        HDSCProofBundle("not-a-proof", "not-a-signature")
        HDSCProofBundle(None, None)


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.chain = chain_of_size(8, self.key, seed_base=8100)

    def _chain_of_size(self, n):
        return HistoryDeltaSegmentsSealChain(
            self.chain.seals[:n], self.chain.signature
        )

    def test_round_trip_for_every_size_and_subset(self):
        for n in range(1, 9):
            chain = self._chain_of_size(n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                bundle = sealed_bundle(chain, indices, self.key, seed=8200 + n)
                wire = encode_hdsc_proof_bundle(bundle)
                decoded = decode_hdsc_proof_bundle(wire)
                self.assertEqual(decoded, bundle, msg=f"n={n} indices={indices}")
                self.assertEqual(
                    encode_hdsc_proof_bundle(decoded), wire
                )

    def test_encoding_matches_independent_builder(self):
        for n in range(1, 9):
            chain = self._chain_of_size(n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                bundle = sealed_bundle(chain, indices, self.key, seed=8300 + n)
                self.assertEqual(
                    encode_hdsc_proof_bundle(bundle),
                    build_wire(bundle),
                    msg=f"n={n} indices={indices}",
                )

    def test_prefix_is_tag_length_and_full_proof_encoding(self):
        bundle = sealed_bundle(self._chain_of_size(6), (1, 3), self.key, seed=8400)
        wire = encode_hdsc_proof_bundle(bundle)
        self.assertTrue(wire.startswith(BUNDLE_TAG))
        offset = len(BUNDLE_TAG)
        proof_bytes = encode_hdsc_proof(bundle.proof)
        self.assertEqual(wire[offset:offset + 4], u32(len(proof_bytes)))
        offset += 4
        self.assertEqual(wire[offset:offset + len(proof_bytes)], proof_bytes)
        # The nested proof keeps its own distinct wire tag.
        self.assertTrue(proof_bytes.startswith(b"ts/hdscp/w1"))

    def test_suffix_is_r_z_count_and_ids(self):
        bundle = sealed_bundle(self._chain_of_size(6), (1, 3), self.key, seed=8450)
        wire = encode_hdsc_proof_bundle(bundle)
        proof_bytes = encode_hdsc_proof(bundle.proof)
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
        bundle = sealed_bundle(self._chain_of_size(3), (0,), self.key, seed=8460)
        bundle = HDSCProofBundle(
            bundle.proof,
            AggregateSignature(
                R=bundle.signature.R,
                z=0,
                signer_ids=bundle.signature.signer_ids,
            ),
        )
        wire = encode_hdsc_proof_bundle(bundle)
        proof_bytes = encode_hdsc_proof(bundle.proof)
        offset = len(BUNDLE_TAG) + 4 + len(proof_bytes)
        offset += len(varint(bundle.signature.R))
        self.assertEqual(wire[offset:offset + 5], b"\x00\x00\x00\x01\x00")

    def test_decoded_bundle_still_verifies(self):
        for n in range(1, 9):
            chain = self._chain_of_size(n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                bundle = sealed_bundle(chain, indices, self.key, seed=8500 + n)
                decoded = decode_hdsc_proof_bundle(
                    encode_hdsc_proof_bundle(bundle)
                )
                self.assertTrue(
                    verify_hdsc_proof_bundle(decoded, self.key),
                    msg=f"n={n} indices={indices}",
                )

    def test_encoding_is_unique_and_stateless(self):
        bundle = sealed_bundle(self._chain_of_size(6), (0, 2, 4), self.key, seed=8600)
        self.assertEqual(
            encode_hdsc_proof_bundle(bundle),
            encode_hdsc_proof_bundle(bundle),
        )


class StructureOnlyTest(unittest.TestCase):
    def test_decode_does_not_verify_seals_or_signature(self):
        # A structurally legal synthetic seal that never went through a
        # real key round-trip; total=2 needs exactly one sibling.
        _other_key, _delta, segments = build_segments()
        seal = make_seal((segments[0],), make_key(), seed=8700)
        proof = HDSCProof((0,), 2, (seal,), (b"s" * 32,))
        signature = AggregateSignature(R=9, z=11, signer_ids=(2, 4))
        bundle = HDSCProofBundle(proof, signature)
        decoded = decode_hdsc_proof_bundle(
            encode_hdsc_proof_bundle(bundle)
        )
        self.assertEqual(decoded, bundle)

    def test_encoding_does_not_check_the_signature_against_the_root(self):
        # A bundle signed by one key but presented under another encodes
        # fine — structure alone is checked; verify reports it as False.
        key = make_key()
        chain = chain_of_size(2, key, seed_base=8800)
        bundle = sealed_bundle(chain, (0,), key, seed=8810)
        self.assertTrue(encode_hdsc_proof_bundle(bundle))
        self.assertFalse(
            verify_hdsc_proof_bundle(bundle, make_other_key())
        )


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.chain = chain_of_size(5, self.key, seed_base=8900)
        self.bundle = sealed_bundle(self.chain, (1, 2), self.key, seed=8910)

    def test_non_bundle_type_error(self):
        with self.assertRaises(TypeError):
            encode_hdsc_proof_bundle(("proof", "signature"))
        with self.assertRaises(TypeError):
            encode_hdsc_proof_bundle(None)

    def test_non_proof_field_type_error(self):
        with self.assertRaises(TypeError):
            encode_hdsc_proof_bundle(
                HDSCProofBundle("not-a-proof", self.bundle.signature)
            )
        with self.assertRaises(TypeError):
            encode_hdsc_proof_bundle(
                HDSCProofBundle(None, self.bundle.signature)
            )

    def test_non_signature_field_type_error(self):
        with self.assertRaises(TypeError):
            encode_hdsc_proof_bundle(
                HDSCProofBundle(self.bundle.proof, "no")
            )
        with self.assertRaises(TypeError):
            encode_hdsc_proof_bundle(
                HDSCProofBundle(self.bundle.proof, None)
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
                encode_hdsc_proof_bundle(
                    HDSCProofBundle(self.bundle.proof, bad)
                )

    def test_bad_nested_proof_structure_value_error(self):
        bad_proof = HDSCProof(
            indices=(), total=5, seals=(), siblings=()
        )
        with self.assertRaises(ValueError):
            encode_hdsc_proof_bundle(
                HDSCProofBundle(bad_proof, self.bundle.signature)
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
                encode_hdsc_proof_bundle(
                    HDSCProofBundle(self.bundle.proof, bad)
                )


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.chain = chain_of_size(5, self.key, seed_base=9000)
        self.bundle = sealed_bundle(self.chain, (1, 2), self.key, seed=9010)
        self.wire = encode_hdsc_proof_bundle(self.bundle)
        self.proof_bytes = encode_hdsc_proof(self.bundle.proof)

    def test_non_bytes_type_error(self):
        with self.assertRaises(TypeError):
            decode_hdsc_proof_bundle("not bytes")
        with self.assertRaises(TypeError):
            decode_hdsc_proof_bundle(bytearray(self.wire))

    def test_bad_tag(self):
        rest = self.wire[len(BUNDLE_TAG):]
        with self.assertRaises(ValueError):
            decode_hdsc_proof_bundle(b"ts/hdscpb/v2" + rest)
        with self.assertRaises(ValueError):
            decode_hdsc_proof_bundle(b"x" + self.wire[1:])

    def test_truncation(self):
        for cut in range(len(BUNDLE_TAG), len(self.wire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_hdsc_proof_bundle(self.wire[:cut])

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_hdsc_proof_bundle(self.wire + b"\x00")

    def test_zero_proof_frame_rejected(self):
        bad = (
            BUNDLE_TAG
            + u32(0)
            + self.wire[len(BUNDLE_TAG) + 4 + len(self.proof_bytes):]
        )
        with self.assertRaises(ValueError):
            decode_hdsc_proof_bundle(bad)

    def test_junk_proof_frame_rejected(self):
        suffix = self.wire[
            len(BUNDLE_TAG) + 4 + len(self.proof_bytes):
        ]
        bad = BUNDLE_TAG + frame(b"not-a-proof") + suffix
        with self.assertRaises(ValueError):
            decode_hdsc_proof_bundle(bad)

    def test_declared_proof_frame_length_mismatch(self):
        bad = bytearray(self.wire)
        length_offset = len(BUNDLE_TAG)
        declared = len(self.proof_bytes) - 1
        bad[length_offset:length_offset + 4] = u32(declared)
        with self.assertRaises(ValueError):
            decode_hdsc_proof_bundle(bytes(bad))

    def test_zero_R_rejected(self):
        suffix_offset = len(BUNDLE_TAG) + 4 + len(self.proof_bytes)
        bad = (
            self.wire[:suffix_offset]
            + varint(0)
            + self.wire[suffix_offset + len(varint(self.bundle.signature.R)):]
        )
        with self.assertRaises(ValueError):
            decode_hdsc_proof_bundle(bad)

    def test_non_canonical_R_leading_zero(self):
        bundle = HDSCProofBundle(
            self.bundle.proof,
            AggregateSignature(R=9, z=7, signer_ids=(1, 3)),
        )
        wire = encode_hdsc_proof_bundle(bundle)
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
            decode_hdsc_proof_bundle(bad)

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
            decode_hdsc_proof_bundle(bad)

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
            decode_hdsc_proof_bundle(bad)

    def test_non_positive_and_unsorted_signer_ids_rejected(self):
        signature = self.bundle.signature
        prefix = (
            BUNDLE_TAG
            + frame(self.proof_bytes)
            + varint(signature.R)
            + varint(signature.z)
        )
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
                decode_hdsc_proof_bundle(bytes(out))


class VerifyBundleTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.other = make_other_key()
        self.chain = chain_of_size(8, self.key, seed_base=9100)

    def _chain_of_size(self, n):
        return HistoryDeltaSegmentsSealChain(
            self.chain.seals[:n], self.chain.signature
        )

    def test_honest_bundles_verify_for_every_size_and_subset(self):
        for n in range(1, 9):
            chain = self._chain_of_size(n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                bundle = sealed_bundle(chain, indices, self.key, seed=9200 + n)
                self.assertTrue(
                    verify_hdsc_proof_bundle(bundle, self.key),
                    msg=f"n={n} indices={indices}",
                )

    def test_result_equals_check_hdsc_proof(self):
        for n in range(1, 9):
            chain = self._chain_of_size(n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                bundle = sealed_bundle(chain, indices, self.key, seed=9300 + n)
                self.assertEqual(
                    verify_hdsc_proof_bundle(bundle, self.key),
                    check_hdsc_proof(
                        bundle.proof, bundle.signature, self.key
                    ),
                    msg=f"n={n} indices={indices}",
                )

    def test_wrong_key_returns_false(self):
        bundle = sealed_bundle(self.chain, (1, 3), self.key, seed=9310)
        self.assertFalse(
            verify_hdsc_proof_bundle(bundle, self.other)
        )

    def test_tampered_signature_returns_false(self):
        bundle = sealed_bundle(self.chain, (0, 2, 4), self.key, seed=9320)
        other_message, _ = make_hdsc_proof(self._chain_of_size(3), (1,))
        other_signature = sign_message(self.key, other_message, seed=9321)
        tampered = HDSCProofBundle(
            bundle.proof,
            AggregateSignature(
                R=other_signature.R,
                z=bundle.signature.z,
                signer_ids=bundle.signature.signer_ids,
            ),
        )
        self.assertFalse(
            verify_hdsc_proof_bundle(tampered, self.key)
        )

    def test_signature_over_another_statement_returns_false(self):
        short = self._chain_of_size(4)
        long_ = self._chain_of_size(6)
        bundle_a = sealed_bundle(short, (0,), self.key, seed=9330)
        bundle_b = sealed_bundle(long_, (1,), self.key, seed=9340)
        mixed = HDSCProofBundle(bundle_a.proof, bundle_b.signature)
        self.assertFalse(
            verify_hdsc_proof_bundle(mixed, self.key)
        )

    def test_tampered_sibling_returns_false(self):
        bundle = sealed_bundle(self.chain, (0, 2), self.key, seed=9350)
        self.assertTrue(bundle.proof.siblings)
        proof = dataclasses.replace(
            bundle.proof,
            siblings=(b"x" * 32,) + bundle.proof.siblings[1:],
        )
        self.assertFalse(
            verify_hdsc_proof_bundle(
                HDSCProofBundle(proof, bundle.signature), self.key
            )
        )

    def test_tampered_seal_returns_false(self):
        bundle = sealed_bundle(self.chain, (1, 2), self.key, seed=9360)
        bad = dataclasses.replace(
            bundle.proof,
            seals=(self.chain.seals[0],) + bundle.proof.seals[1:],
        )
        self.assertFalse(
            verify_hdsc_proof_bundle(
                HDSCProofBundle(bad, bundle.signature), self.key
            )
        )

    def test_missing_and_extra_sibling_return_false(self):
        bundle = sealed_bundle(self.chain, (0, 2, 4), self.key, seed=9370)
        missing = dataclasses.replace(
            bundle.proof, siblings=bundle.proof.siblings[:-1]
        )
        extra = dataclasses.replace(
            bundle.proof,
            siblings=bundle.proof.siblings + (b"x" * 32,),
        )
        self.assertFalse(
            verify_hdsc_proof_bundle(
                HDSCProofBundle(missing, bundle.signature), self.key
            )
        )
        self.assertFalse(
            verify_hdsc_proof_bundle(
                HDSCProofBundle(extra, bundle.signature), self.key
            )
        )

    def test_decoded_bundle_verifies_identically(self):
        bundle = sealed_bundle(self.chain, (1, 4), self.key, seed=9380)
        decoded = decode_hdsc_proof_bundle(
            encode_hdsc_proof_bundle(bundle)
        )
        self.assertEqual(
            verify_hdsc_proof_bundle(decoded, self.key),
            verify_hdsc_proof_bundle(bundle, self.key),
        )

    def test_non_bundle_type_error(self):
        _message, proof = make_hdsc_proof(self.chain, (0,))
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        for bad in ((proof, signature), "bundle", None, proof):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_hdsc_proof_bundle(bad, self.key)

    def test_bad_nested_structure_value_error(self):
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        bad_proof = HDSCProof((1, 2), 0, (), ())
        bundle = HDSCProofBundle(bad_proof, signature)
        with self.assertRaises(ValueError):
            verify_hdsc_proof_bundle(bundle, self.key)

    def test_structurally_illegal_signature_raises_value_error(self):
        _message, proof = make_hdsc_proof(self.chain, (1, 2))
        for bad_sig in (
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=-1, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=7, signer_ids=()),
            AggregateSignature(R=5, z=7, signer_ids=(3, 1)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad_sig)):
                verify_hdsc_proof_bundle(
                    HDSCProofBundle(proof, bad_sig), self.key
                )


if __name__ == "__main__":
    unittest.main()
