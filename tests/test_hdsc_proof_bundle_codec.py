"""Tests for the canonical HDSCProofBundle transport encoding:
HDSCProofBundle / encode_hdsc_proof_bundle / decode_hdsc_proof_bundle /
verify_hdsc_proof_bundle."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    HDSCProof,
    HDSCProofBundle,
    check_hdsc_proof,
    decode_hdsc_proof_bundle,
    encode_hdsc_proof,
    encode_hdsc_proof_bundle,
    make_hdsc_proof,
    verify_hdsc_proof_bundle,
)

from test_nonce_leak_codec import make_other_key
from test_audit_chain import sign_message
from test_hdsc_proof import chain_of_size, signed_proof
from test_nonce_reuse import FIELD_PRIME, make_key

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


def sealed_bundle(chain, indices, key, *, seed=800):
    """Return a signed HDSCProofBundle for the given indices."""
    proof, signature = signed_proof(chain, indices, key, seed=seed)
    return HDSCProofBundle(proof, signature)


class BundleDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(HDSCProofBundle)],
            ["proof", "signature"],
        )
        proof = HDSCProof((0,), 1, ("not-a-seal",), ())
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        bundle = HDSCProofBundle(proof, signature)
        self.assertIs(bundle.proof, proof)
        self.assertIs(bundle.signature, signature)
        self.assertEqual(
            HDSCProofBundle(proof=proof, signature=signature), bundle
        )

    def test_frozen_value_equality_and_hash(self):
        proof = HDSCProof((0,), 1, ("not-a-seal",), ())
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
        self.assertNotEqual(
            bundle,
            HDSCProofBundle(HDSCProof((0,), 2, ("not-a-seal",), ()), signature),
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
        self.chain = chain_of_size(9, self.key)

    def _chain_of_size(self, n):
        from thresholdsign import HistoryDeltaSegmentsSealChain

        return HistoryDeltaSegmentsSealChain(
            self.chain.seals[:n], self.chain.signature
        )

    def test_round_trip_for_every_size_and_subset(self):
        for n in range(1, 10):
            chain = self._chain_of_size(n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                bundle = sealed_bundle(
                    chain, indices, self.key, seed=2000 + n
                )
                wire = encode_hdsc_proof_bundle(bundle)
                decoded = decode_hdsc_proof_bundle(wire)
                self.assertEqual(
                    decoded, bundle, msg=f"n={n} indices={indices}"
                )
                self.assertEqual(encode_hdsc_proof_bundle(decoded), wire)

    def test_encoding_matches_independent_builder(self):
        for n in range(1, 10):
            chain = self._chain_of_size(n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                bundle = sealed_bundle(
                    chain, indices, self.key, seed=3000 + n
                )
                self.assertEqual(
                    encode_hdsc_proof_bundle(bundle),
                    build_wire(bundle),
                    msg=f"n={n} indices={indices}",
                )

    def test_prefix_is_tag_length_and_full_proof_encoding(self):
        bundle = sealed_bundle(self.chain, (2, 4), self.key, seed=4000)
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
        bundle = sealed_bundle(self.chain, (2, 4), self.key, seed=4100)
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
        bundle = sealed_bundle(self.chain, (0,), self.key, seed=4200)
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
        # R varint precedes z; z = 0 -> VARINT 00 00 00 01 00.
        offset += len(varint(bundle.signature.R))
        self.assertEqual(wire[offset:offset + 5], b"\x00\x00\x00\x01\x00")

    def test_decoded_bundle_still_verifies(self):
        for n in range(1, 10):
            chain = self._chain_of_size(n)
            message, _ = make_hdsc_proof(chain, (0,))
            signature = sign_message(self.key, message, seed=5000 + n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                _message, proof = make_hdsc_proof(chain, indices)
                bundle = HDSCProofBundle(proof, signature)
                decoded = decode_hdsc_proof_bundle(
                    encode_hdsc_proof_bundle(bundle)
                )
                self.assertTrue(
                    verify_hdsc_proof_bundle(decoded, self.key),
                    msg=f"n={n} indices={indices}",
                )

    def test_encoding_is_unique_and_stateless(self):
        bundle = sealed_bundle(self.chain, (1, 3, 5), self.key, seed=4300)
        self.assertEqual(
            encode_hdsc_proof_bundle(bundle),
            encode_hdsc_proof_bundle(bundle),
        )


class StructureOnlyTest(unittest.TestCase):
    def test_decode_does_not_verify_seals_or_signature(self):
        # A structurally legal bundle whose root signature is a synthetic
        # placeholder: it encodes and decodes normally; only the verifier
        # judges it.
        key = make_key()
        chain = chain_of_size(3, key, seed_base=4400)
        _message, proof = make_hdsc_proof(chain, (0, 2))
        signature = AggregateSignature(R=9, z=11, signer_ids=(2, 4))
        bundle = HDSCProofBundle(proof, signature)
        decoded = decode_hdsc_proof_bundle(encode_hdsc_proof_bundle(bundle))
        self.assertEqual(decoded, bundle)
        # A real signature over a different statement is structurally fine
        # and still decodes; only the verifier reports it as False.
        other = chain_of_size(4, key, seed_base=4460)
        other_message, _ = make_hdsc_proof(other, (1,))
        wrong = HDSCProofBundle(
            proof, sign_message(key, other_message, seed=4470)
        )
        self.assertFalse(verify_hdsc_proof_bundle(wrong, key))

    def test_encoding_does_not_check_the_signature_against_the_root(self):
        # A bundle signed by one key but presented under another encodes
        # fine — structure alone is checked; verify reports it as False.
        key = make_key()
        chain = chain_of_size(2, key, seed_base=4500)
        bundle = sealed_bundle(chain, (0,), key, seed=4600)
        self.assertTrue(encode_hdsc_proof_bundle(bundle))
        self.assertFalse(verify_hdsc_proof_bundle(bundle, make_other_key()))


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.chain = chain_of_size(5, self.key, seed_base=4700)
        self.bundle = sealed_bundle(self.chain, (1, 2), self.key, seed=4800)

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
            encode_hdsc_proof_bundle(HDSCProofBundle(self.bundle.proof, "no"))
        with self.assertRaises(TypeError):
            encode_hdsc_proof_bundle(HDSCProofBundle(self.bundle.proof, None))

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
        bad_proof = HDSCProof(indices=(), total=5, seals=(), siblings=())
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
        self.chain = chain_of_size(5, self.key, seed_base=4900)
        self.bundle = sealed_bundle(self.chain, (1, 2), self.key, seed=5000)
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
        suffix = self.wire[len(BUNDLE_TAG) + 4 + len(self.proof_bytes):]
        bad = BUNDLE_TAG + frame(b"not-a-proof") + suffix
        with self.assertRaises(ValueError):
            decode_hdsc_proof_bundle(bad)

    def test_declared_proof_frame_length_mismatch(self):
        # Declaring the frame one byte shorter hides a proof byte inside
        # what the parser then reads as the R varint length.
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
        # Use a structurally legal small-R signature so the one-byte
        # canonical body 09 can be padded to the non-canonical 00 09.
        bundle = HDSCProofBundle(
            self.bundle.proof,
            AggregateSignature(R=9, z=7, signer_ids=(1, 3)),
        )
        wire = encode_hdsc_proof_bundle(bundle)
        suffix_offset = len(BUNDLE_TAG) + 4 + len(self.proof_bytes)
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
                decode_hdsc_proof_bundle(bytes(out))


class VerifyBundleTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.other = make_other_key()
        self.chain = chain_of_size(8, self.key, seed_base=5100)

    def _chain_of_size(self, n):
        from thresholdsign import HistoryDeltaSegmentsSealChain

        return HistoryDeltaSegmentsSealChain(
            self.chain.seals[:n], self.chain.signature
        )

    def test_honest_bundles_verify_for_every_size_and_subset(self):
        for n in range(1, 9):
            chain = self._chain_of_size(n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                bundle = sealed_bundle(
                    chain, indices, self.key, seed=6000 + n
                )
                self.assertTrue(
                    verify_hdsc_proof_bundle(bundle, self.key),
                    msg=f"n={n} indices={indices}",
                )

    def test_result_equals_check_hdsc_proof(self):
        for n in range(1, 9):
            chain = self._chain_of_size(n)
            message, _ = make_hdsc_proof(chain, (0,))
            signature = sign_message(self.key, message, seed=7000 + n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                _msg, proof = make_hdsc_proof(chain, indices)
                bundle = HDSCProofBundle(proof, signature)
                self.assertEqual(
                    verify_hdsc_proof_bundle(bundle, self.key),
                    check_hdsc_proof(proof, signature, self.key),
                    msg=f"n={n} indices={indices}",
                )

    def test_wrong_key_returns_false(self):
        bundle = sealed_bundle(self.chain, (0, 2), self.key, seed=7100)
        self.assertFalse(verify_hdsc_proof_bundle(bundle, self.other))

    def test_tampered_seal_returns_false(self):
        bundle = sealed_bundle(self.chain, (1, 2), self.key, seed=7200)
        bad_proof = dataclasses.replace(
            bundle.proof,
            seals=(self.chain.seals[0],) + bundle.proof.seals[1:],
        )
        tampered = HDSCProofBundle(bad_proof, bundle.signature)
        self.assertFalse(verify_hdsc_proof_bundle(tampered, self.key))

    def test_missing_and_extra_sibling_return_false(self):
        bundle = sealed_bundle(self.chain, (0, 2, 4), self.key, seed=7300)
        for siblings in (
            bundle.proof.siblings[:-1],
            bundle.proof.siblings + (b"x" * 32,),
        ):
            bad_proof = dataclasses.replace(bundle.proof, siblings=siblings)
            tampered = HDSCProofBundle(bad_proof, bundle.signature)
            self.assertFalse(
                verify_hdsc_proof_bundle(tampered, self.key),
                msg=f"siblings={len(siblings)}",
            )

    def test_tampered_signature_returns_false(self):
        bundle = sealed_bundle(self.chain, (0, 2), self.key, seed=7400)
        # A valid R of a different real round is still a subgroup element,
        # so the check runs and returns False rather than raising.
        other_message, _ = make_hdsc_proof(self._chain_of_size(3), (1,))
        other_signature = sign_message(self.key, other_message, seed=7410)
        tampered = HDSCProofBundle(
            bundle.proof,
            AggregateSignature(
                R=other_signature.R,
                z=bundle.signature.z,
                signer_ids=bundle.signature.signer_ids,
            ),
        )
        self.assertFalse(verify_hdsc_proof_bundle(tampered, self.key))
        flipped_z = HDSCProofBundle(
            bundle.proof,
            AggregateSignature(
                R=bundle.signature.R,
                z=(bundle.signature.z + 1) % FIELD_PRIME,
                signer_ids=bundle.signature.signer_ids,
            ),
        )
        self.assertFalse(verify_hdsc_proof_bundle(flipped_z, self.key))

    def test_signature_over_another_statement_returns_false(self):
        # The root binds (total, tree), so proofs of two different trees
        # are not interchangeable even under the same key.
        short = self._chain_of_size(4)
        long_ = self._chain_of_size(6)
        bundle_a = sealed_bundle(short, (0, 2), self.key, seed=7500)
        bundle_b = sealed_bundle(long_, (1, 3), self.key, seed=7600)
        mixed = HDSCProofBundle(bundle_a.proof, bundle_b.signature)
        self.assertFalse(verify_hdsc_proof_bundle(mixed, self.key))

    def test_decoded_bundle_verifies_identically(self):
        bundle = sealed_bundle(self.chain, (0, 2, 4), self.key, seed=7700)
        decoded = decode_hdsc_proof_bundle(encode_hdsc_proof_bundle(bundle))
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
        bad_proof = HDSCProof(indices=(), total=5, seals=(), siblings=())
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
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
            bundle = HDSCProofBundle(proof, bad_sig)
            with self.assertRaises(ValueError, msg=repr(bad_sig)):
                verify_hdsc_proof_bundle(bundle, self.key)


if __name__ == "__main__":
    unittest.main()
