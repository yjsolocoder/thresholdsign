"""Tests for the canonical HDSCArchiveProofBundle transport encoding and
its key-bound verifier: HDSCArchiveProofBundle /
encode_hdsc_archive_proof_bundle / decode_hdsc_archive_proof_bundle /
verify_hdsc_archive_proof_bundle."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    HDSCArchiveProof,
    HDSCArchiveProofBundle,
    HDSCProof,
    HDSCProofBundle,
    HDSCProofBundleArchive,
    check_hdsc_archive_proof,
    decode_hdsc_archive_proof_bundle,
    encode_hdsc_archive_proof_bundle,
    encode_hdsc_proof_bundle,
    make_hdsc_archive_proof,
    verify_hdsc_archive_proof_bundle,
)

from test_audit_chain import sign_message
from test_audit_extension_proof_bundle_codec import make_other_key
from test_nonce_reuse import FIELD_PRIME, make_key
from test_hdsc_archive_proof import archive_of_size, signed_proof
from test_hdsc_proof_bundle_archive import make_signed_bundle

BUNDLE_TAG = b"ts/hdscapb/v1"

DUMMY_SIGNATURE = AggregateSignature(R=5, z=7, signer_ids=(1, 3))


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def build_wire(bundle: HDSCArchiveProofBundle) -> bytes:
    """Independently build the bundle wire format straight from the spec."""
    proof = bundle.proof
    out = bytearray(BUNDLE_TAG)
    out += varint(proof.total)
    out += u32(len(proof.indices))
    for index in proof.indices:
        out += varint(index)
    out += u32(len(proof.bundles))
    for item in proof.bundles:
        out += frame(encode_hdsc_proof_bundle(item))
    out += u32(len(proof.siblings))
    for sibling in proof.siblings:
        out += sibling
    signature = bundle.signature
    out += varint(signature.R)
    out += varint(signature.z)
    out += u32(len(signature.signer_ids))
    for signer_id in signature.signer_ids:
        out += varint(signer_id)
    return bytes(out)


def layout(bundle: HDSCArchiveProofBundle) -> dict:
    """Byte offsets of every section of the bundle's canonical encoding."""
    proof = bundle.proof
    pos = len(BUNDLE_TAG)
    pos += len(varint(proof.total))
    index_count = pos
    pos += 4
    indices = pos
    for index in proof.indices:
        pos += len(varint(index))
    item_count = pos
    pos += 4
    items = []
    for item in proof.bundles:
        items.append(pos)
        pos += 4 + len(encode_hdsc_proof_bundle(item))
    sibling_count = pos
    pos += 4
    siblings = pos
    pos += 32 * len(proof.siblings)
    signature = pos
    signer_count = (
        signature
        + len(varint(bundle.signature.R))
        + len(varint(bundle.signature.z))
    )
    return {
        "index_count": index_count,
        "indices": indices,
        "item_count": item_count,
        "items": items,
        "sibling_count": sibling_count,
        "siblings": siblings,
        "signature": signature,
        "signer_count": signer_count,
    }


def sealed(archive, indices, key, *, seed=10000):
    """A genuinely signed HDSCArchiveProofBundle over ``indices``."""
    proof, signature = signed_proof(archive, indices, key, seed=seed)
    return HDSCArchiveProofBundle(proof, signature)


class BundleDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [
                field.name
                for field in dataclasses.fields(HDSCArchiveProofBundle)
            ],
            ["proof", "signature"],
        )
        key = make_key()
        archive = archive_of_size(4, key, seed_base=10100)
        proof = HDSCArchiveProof((1, 3), 4, archive.items[1:4:2], (b"s" * 32,))
        bundle = HDSCArchiveProofBundle(proof, DUMMY_SIGNATURE)
        self.assertIs(bundle.proof, proof)
        self.assertIs(bundle.signature, DUMMY_SIGNATURE)
        self.assertEqual(
            HDSCArchiveProofBundle(proof=proof, signature=DUMMY_SIGNATURE),
            bundle,
        )

    def test_frozen_value_equality_and_hash(self):
        key = make_key()
        archive = archive_of_size(4, key, seed_base=10200)
        proof = HDSCArchiveProof((0, 2), 4, archive.items[0:3:2], (b"s" * 32,))
        bundle = HDSCArchiveProofBundle(proof, DUMMY_SIGNATURE)
        same = HDSCArchiveProofBundle(proof=proof, signature=DUMMY_SIGNATURE)
        self.assertEqual(bundle, same)
        self.assertEqual(hash(bundle), hash(same))
        other_proof = HDSCArchiveProof(
            (0, 2), 4, archive.items[0:3:2], (b"t" * 32,)
        )
        self.assertNotEqual(
            bundle, HDSCArchiveProofBundle(other_proof, DUMMY_SIGNATURE)
        )
        self.assertNotEqual(
            bundle,
            HDSCArchiveProofBundle(
                proof, AggregateSignature(R=6, z=7, signer_ids=(1, 3))
            ),
        )
        with self.assertRaises(FrozenInstanceError):
            bundle.proof = other_proof

    def test_construction_does_not_validate(self):
        # A plain value: illegal nested proofs and non-signature values
        # all construct; the codec and verifier reject them.
        HDSCArchiveProofBundle("not-a-proof", "not-a-signature")
        HDSCArchiveProofBundle(None, None)
        HDSCArchiveProofBundle(
            HDSCArchiveProof((), 0, (), ()), DUMMY_SIGNATURE
        )


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(8, self.key, seed_base=10300)

    def _archive_of_size(self, n):
        return HDSCProofBundleArchive(
            self.archive.items[:n], self.archive.signature
        )

    def test_round_trip_for_every_size_and_subset(self):
        for n in range(1, 9):
            archive = self._archive_of_size(n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                _message, proof = make_hdsc_archive_proof(archive, indices)
                bundle = HDSCArchiveProofBundle(proof, DUMMY_SIGNATURE)
                wire = encode_hdsc_archive_proof_bundle(bundle)
                decoded = decode_hdsc_archive_proof_bundle(wire)
                self.assertEqual(
                    decoded, bundle, msg=f"n={n} indices={indices}"
                )
                self.assertEqual(
                    encode_hdsc_archive_proof_bundle(decoded), wire
                )

    def test_encoding_matches_independent_builder(self):
        for n in range(1, 9):
            archive = self._archive_of_size(n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                _message, proof = make_hdsc_archive_proof(archive, indices)
                bundle = HDSCArchiveProofBundle(proof, DUMMY_SIGNATURE)
                self.assertEqual(
                    encode_hdsc_archive_proof_bundle(bundle),
                    build_wire(bundle),
                    msg=f"n={n} indices={indices}",
                )

    def test_prefix_is_tag_then_total_and_indices(self):
        bundle = sealed(self._archive_of_size(5), (1, 3), self.key, seed=10400)
        wire = encode_hdsc_archive_proof_bundle(bundle)
        self.assertTrue(wire.startswith(BUNDLE_TAG))
        pos = len(BUNDLE_TAG)
        self.assertEqual(
            wire[pos:pos + len(varint(5))], varint(5)
        )
        pos += len(varint(5))
        self.assertEqual(wire[pos:pos + 4], u32(2))
        pos += 4
        self.assertEqual(wire[pos:pos + 5], varint(1))
        self.assertEqual(wire[pos + 5:pos + 10], varint(3))

    def test_item_frames_are_canonical_bundle_encodings(self):
        bundle = sealed(
            self._archive_of_size(6), (0, 2, 4), self.key, seed=10500
        )
        wire = encode_hdsc_archive_proof_bundle(bundle)
        offsets = layout(bundle)
        self.assertEqual(
            wire[offsets["item_count"]:offsets["item_count"] + 4], u32(3)
        )
        for item, item_offset in zip(bundle.proof.bundles, offsets["items"]):
            encoded = encode_hdsc_proof_bundle(item)
            self.assertEqual(
                wire[item_offset:item_offset + 4], u32(len(encoded))
            )
            self.assertEqual(
                wire[item_offset + 4:item_offset + 4 + len(encoded)],
                encoded,
            )

    def test_suffix_is_siblings_then_signature_frame(self):
        bundle = sealed(self._archive_of_size(5), (1, 3), self.key, seed=10600)
        wire = encode_hdsc_archive_proof_bundle(bundle)
        offsets = layout(bundle)
        siblings = bundle.proof.siblings
        self.assertEqual(
            wire[offsets["sibling_count"]:offsets["sibling_count"] + 4],
            u32(len(siblings)),
        )
        self.assertEqual(
            wire[offsets["siblings"]:offsets["siblings"] + 32 * len(siblings)],
            b"".join(siblings),
        )
        signature = bundle.signature
        expected = bytearray()
        expected += varint(signature.R)
        expected += varint(signature.z)
        expected += u32(len(signature.signer_ids))
        for signer_id in signature.signer_ids:
            expected += varint(signer_id)
        self.assertEqual(wire[offsets["signature"]:], bytes(expected))

    def test_decoded_bundle_still_verifies(self):
        for n in range(1, 9):
            archive = self._archive_of_size(n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                bundle = sealed(archive, indices, self.key, seed=10700 + n)
                decoded = decode_hdsc_archive_proof_bundle(
                    encode_hdsc_archive_proof_bundle(bundle)
                )
                self.assertTrue(
                    verify_hdsc_archive_proof_bundle(decoded, self.key),
                    msg=f"n={n} indices={indices}",
                )

    def test_encoding_is_unique_and_stateless(self):
        bundle = sealed(
            self._archive_of_size(6), (0, 2, 4), self.key, seed=10800
        )
        self.assertEqual(
            encode_hdsc_archive_proof_bundle(bundle),
            encode_hdsc_archive_proof_bundle(bundle),
        )


class StructureOnlyTest(unittest.TestCase):
    def test_decode_does_not_verify_bundles_or_signature(self):
        # A structurally legal bundle whose disclosed bundle belongs to
        # another key and whose root signature is a placeholder decodes
        # and re-encodes; only the verifier reports the mismatch.
        key = make_key()
        foreign = make_signed_bundle(make_other_key(), 8, (0, 2), seed=10900)
        proof = HDSCArchiveProof((0,), 1, (foreign,), ())
        bundle = HDSCArchiveProofBundle(proof, DUMMY_SIGNATURE)
        wire = encode_hdsc_archive_proof_bundle(bundle)
        decoded = decode_hdsc_archive_proof_bundle(wire)
        self.assertEqual(decoded, bundle)
        self.assertFalse(verify_hdsc_archive_proof_bundle(decoded, key))

    def test_structurally_legal_content_mismatch_decodes_normally(self):
        # The root signature signs a different statement than the proof
        # rebuilds: decoding restores the structure and the verifier
        # answers False.
        key = make_key()
        archive = archive_of_size(4, key, seed_base=11000)
        bundle = sealed(archive, (0, 2), key, seed=11100)
        reversed_archive = HDSCProofBundleArchive(
            tuple(reversed(archive.items)), archive.signature
        )
        other_message, _other_proof = make_hdsc_archive_proof(
            reversed_archive, (0, 2)
        )
        mismatched = HDSCArchiveProofBundle(
            bundle.proof,
            sign_message(key, other_message, seed=11300),
        )
        decoded = decode_hdsc_archive_proof_bundle(
            encode_hdsc_archive_proof_bundle(mismatched)
        )
        self.assertEqual(decoded, mismatched)
        self.assertFalse(verify_hdsc_archive_proof_bundle(decoded, key))


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(5, self.key, seed_base=11400)
        self.bundle = sealed(self.archive, (1, 3), self.key, seed=11500)
        self.proof = self.bundle.proof

    def test_non_bundle_type_error(self):
        for bad in (
            (self.proof, DUMMY_SIGNATURE),
            "bundle",
            None,
            42,
            self.proof,
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_hdsc_archive_proof_bundle(bad)

    def test_non_proof_field_type_error(self):
        for bad in ("not-a-proof", None, 42):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_hdsc_archive_proof_bundle(
                    HDSCArchiveProofBundle(bad, DUMMY_SIGNATURE)
                )

    def test_proof_field_type_errors(self):
        for bad_proof in (
            dataclasses.replace(self.proof, indices=[1, 3]),
            dataclasses.replace(self.proof, indices=(True, 3)),
            dataclasses.replace(self.proof, indices=("1", 3)),
            dataclasses.replace(self.proof, total=True),
            dataclasses.replace(self.proof, total="5"),
            dataclasses.replace(self.proof, bundles=[self.proof.bundles[0]] * 2),
            dataclasses.replace(
                self.proof, bundles=("not-a-bundle",) * 2
            ),
            dataclasses.replace(self.proof, siblings=[b"s" * 32]),
            dataclasses.replace(self.proof, siblings=(b"s" * 32, 33)),
        ):
            with self.assertRaises(TypeError, msg=repr(bad_proof)):
                encode_hdsc_archive_proof_bundle(
                    HDSCArchiveProofBundle(bad_proof, DUMMY_SIGNATURE)
                )

    def test_proof_value_errors(self):
        bundles = self.proof.bundles
        for bad_proof in (
            HDSCArchiveProof((1, 3), 0, bundles, ()),
            HDSCArchiveProof((1, 3), -1, bundles, ()),
            HDSCArchiveProof((1, 3), 2 ** 64, bundles, ()),
            HDSCArchiveProof((), 5, (), ()),
            HDSCArchiveProof((-1, 3), 5, bundles, ()),
            HDSCArchiveProof((1, 5), 5, bundles, ()),
            HDSCArchiveProof((3, 1), 5, bundles, ()),
            HDSCArchiveProof((1, 1), 5, bundles, ()),
            dataclasses.replace(self.proof, siblings=(b"s" * 31,) * 3),
            dataclasses.replace(self.proof, siblings=(b"s" * 33,) * 3),
            # A bundle tuple that does not pair one-to-one with indices.
            dataclasses.replace(self.proof, bundles=bundles[:1]),
            dataclasses.replace(self.proof, bundles=bundles + bundles[:1]),
            # A sibling count other than the one total and indices give.
            dataclasses.replace(self.proof, siblings=self.proof.siblings[:-1]),
            dataclasses.replace(
                self.proof, siblings=self.proof.siblings + (b"x" * 32,)
            ),
        ):
            with self.assertRaises(ValueError, msg=repr(bad_proof)):
                encode_hdsc_archive_proof_bundle(
                    HDSCArchiveProofBundle(bad_proof, DUMMY_SIGNATURE)
                )

    def test_illegal_nested_bundle_value_error(self):
        bad_item = HDSCProofBundle(
            HDSCProof(indices=(), total=0, seals=(), siblings=()),
            DUMMY_SIGNATURE,
        )
        bad_proof = dataclasses.replace(
            self.proof, bundles=(bad_item,) + self.proof.bundles[1:]
        )
        with self.assertRaises(ValueError):
            encode_hdsc_archive_proof_bundle(
                HDSCArchiveProofBundle(bad_proof, DUMMY_SIGNATURE)
            )

    def test_non_signature_field_type_error(self):
        for bad in ("not-a-signature", None, 42):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_hdsc_archive_proof_bundle(
                    HDSCArchiveProofBundle(self.proof, bad)
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
                encode_hdsc_archive_proof_bundle(
                    HDSCArchiveProofBundle(self.proof, bad)
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
                encode_hdsc_archive_proof_bundle(
                    HDSCArchiveProofBundle(self.proof, bad)
                )


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(5, self.key, seed_base=11600)
        self.bundle = sealed(self.archive, (1, 3), self.key, seed=11700)
        self.wire = encode_hdsc_archive_proof_bundle(self.bundle)
        self.offsets = layout(self.bundle)

    def test_non_bytes_type_error(self):
        with self.assertRaises(TypeError):
            decode_hdsc_archive_proof_bundle("not bytes")
        with self.assertRaises(TypeError):
            decode_hdsc_archive_proof_bundle(bytearray(self.wire))

    def test_bad_tag(self):
        rest = self.wire[len(BUNDLE_TAG):]
        with self.assertRaises(ValueError):
            decode_hdsc_archive_proof_bundle(b"ts/hdscapb/v2" + rest)
        with self.assertRaises(ValueError):
            decode_hdsc_archive_proof_bundle(b"x" + self.wire[1:])

    def test_truncation(self):
        for cut in range(len(BUNDLE_TAG), len(self.wire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_hdsc_archive_proof_bundle(self.wire[:cut])

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_hdsc_archive_proof_bundle(self.wire + b"\x00")

    def test_zero_total_rejected(self):
        bad = BUNDLE_TAG + varint(0) + self.wire[len(BUNDLE_TAG) + 5:]
        with self.assertRaises(ValueError):
            decode_hdsc_archive_proof_bundle(bad)

    def test_zero_index_count_rejected(self):
        offsets = self.offsets
        bad = (
            self.wire[:offsets["index_count"]]
            + u32(0)
            + self.wire[offsets["item_count"]:]
        )
        with self.assertRaises(ValueError):
            decode_hdsc_archive_proof_bundle(bad)

    def test_non_increasing_and_out_of_range_indices_rejected(self):
        offsets = self.offsets
        suffix = self.wire[offsets["item_count"]:]
        for bad_indices in ((3, 1), (1, 1), (1, 5)):
            out = bytearray(self.wire[:offsets["index_count"]])
            out += u32(len(bad_indices))
            for index in bad_indices:
                out += varint(index)
            out += suffix
            with self.assertRaises(ValueError, msg=f"indices={bad_indices}"):
                decode_hdsc_archive_proof_bundle(bytes(out))

    def test_item_count_mismatch_rejected(self):
        offsets = self.offsets
        bad = (
            self.wire[:offsets["item_count"]]
            + u32(len(self.bundle.proof.bundles) + 1)
            + self.wire[offsets["item_count"] + 4:]
        )
        with self.assertRaises(ValueError):
            decode_hdsc_archive_proof_bundle(bad)

    def test_zero_item_frame_rejected(self):
        offsets = self.offsets
        first = offsets["items"][0]
        encoded = encode_hdsc_proof_bundle(self.bundle.proof.bundles[0])
        bad = (
            self.wire[:first]
            + u32(0)
            + self.wire[first + 4 + len(encoded):]
        )
        with self.assertRaises(ValueError):
            decode_hdsc_archive_proof_bundle(bad)

    def test_junk_item_frame_rejected(self):
        offsets = self.offsets
        first = offsets["items"][0]
        encoded = encode_hdsc_proof_bundle(self.bundle.proof.bundles[0])
        bad = (
            self.wire[:first]
            + frame(b"not-a-bundle")
            + self.wire[first + 4 + len(encoded):]
        )
        with self.assertRaises(ValueError):
            decode_hdsc_archive_proof_bundle(bad)

    def test_declared_item_frame_length_mismatch(self):
        offsets = self.offsets
        first = offsets["items"][0]
        encoded = encode_hdsc_proof_bundle(self.bundle.proof.bundles[0])
        bad = bytearray(self.wire)
        bad[first:first + 4] = u32(len(encoded) - 1)
        with self.assertRaises(ValueError):
            decode_hdsc_archive_proof_bundle(bytes(bad))

    def test_sibling_count_mismatch_rejected(self):
        offsets = self.offsets
        count = len(self.bundle.proof.siblings)
        for bad_count in (count - 1, count + 1):
            bad = (
                self.wire[:offsets["sibling_count"]]
                + u32(bad_count)
                + self.wire[offsets["sibling_count"] + 4:]
            )
            with self.assertRaises(ValueError, msg=f"count={bad_count}"):
                decode_hdsc_archive_proof_bundle(bad)

    def test_zero_R_rejected(self):
        offsets = self.offsets
        signature = self.bundle.signature
        bad = (
            self.wire[:offsets["signature"]]
            + varint(0)
            + self.wire[
                offsets["signature"] + len(varint(signature.R)):
            ]
        )
        with self.assertRaises(ValueError):
            decode_hdsc_archive_proof_bundle(bad)

    def test_non_canonical_R_leading_zero(self):
        bundle = HDSCArchiveProofBundle(
            self.bundle.proof,
            AggregateSignature(R=9, z=7, signer_ids=(1, 3)),
        )
        wire = encode_hdsc_archive_proof_bundle(bundle)
        offsets = layout(bundle)
        non_canonical_R = (1).to_bytes(4, "big") + b"\x00\x09"
        bad = (
            wire[:offsets["signature"]]
            + non_canonical_R
            + wire[offsets["signature"] + len(varint(9)):]
        )
        with self.assertRaises(ValueError):
            decode_hdsc_archive_proof_bundle(bad)

    def test_zero_signer_count_rejected(self):
        offsets = self.offsets
        bad = self.wire[:offsets["signer_count"]] + u32(0)
        with self.assertRaises(ValueError):
            decode_hdsc_archive_proof_bundle(bad)

    def test_signer_count_too_large_then_truncated(self):
        offsets = self.offsets
        signature = self.bundle.signature
        bad = (
            self.wire[:offsets["signer_count"]]
            + u32(len(signature.signer_ids) + 1)
        )
        for signer_id in signature.signer_ids:
            bad += varint(signer_id)
        with self.assertRaises(ValueError):
            decode_hdsc_archive_proof_bundle(bad)

    def test_non_positive_and_unsorted_signer_ids_rejected(self):
        offsets = self.offsets
        prefix = self.wire[:offsets["signer_count"]]
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
                decode_hdsc_archive_proof_bundle(bytes(out))


class VerifyBundleTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.other = make_other_key()
        self.archive = archive_of_size(8, self.key, seed_base=11800)

    def _archive_of_size(self, n):
        return HDSCProofBundleArchive(
            self.archive.items[:n], self.archive.signature
        )

    def test_honest_bundles_verify_for_every_size_and_subset(self):
        for n in range(1, 9):
            archive = self._archive_of_size(n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                bundle = sealed(archive, indices, self.key, seed=11900 + n)
                self.assertTrue(
                    verify_hdsc_archive_proof_bundle(bundle, self.key),
                    msg=f"n={n} indices={indices}",
                )

    def test_result_equals_check_hdsc_archive_proof(self):
        for n in range(1, 9):
            archive = self._archive_of_size(n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                bundle = sealed(archive, indices, self.key, seed=12000 + n)
                self.assertEqual(
                    verify_hdsc_archive_proof_bundle(bundle, self.key),
                    check_hdsc_archive_proof(
                        bundle.proof, bundle.signature, self.key
                    ),
                    msg=f"n={n} indices={indices}",
                )

    def test_wrong_key_returns_false(self):
        bundle = sealed(self.archive, (1, 3), self.key, seed=12100)
        self.assertFalse(
            verify_hdsc_archive_proof_bundle(bundle, self.other)
        )

    def test_tampered_signature_returns_false(self):
        bundle = sealed(self.archive, (0, 2, 4), self.key, seed=12200)
        tampered = HDSCArchiveProofBundle(
            bundle.proof,
            AggregateSignature(
                R=bundle.signature.R,
                z=(bundle.signature.z + 1) % FIELD_PRIME,
                signer_ids=bundle.signature.signer_ids,
            ),
        )
        self.assertFalse(
            verify_hdsc_archive_proof_bundle(tampered, self.key)
        )

    def test_signature_over_another_statement_returns_false(self):
        bundle = sealed(self.archive, (0, 2), self.key, seed=12300)
        other_archive = HDSCProofBundleArchive(
            tuple(reversed(self.archive.items[:5])),
            self.archive.signature,
        )
        other = sealed(other_archive, (0, 2), self.key, seed=12400)
        mixed = HDSCArchiveProofBundle(bundle.proof, other.signature)
        self.assertFalse(
            verify_hdsc_archive_proof_bundle(mixed, self.key)
        )

    def test_swapped_bundles_return_false(self):
        bundle = sealed(self.archive, (1, 2), self.key, seed=12500)
        swapped = (bundle.proof.bundles[1], bundle.proof.bundles[0])
        bad = HDSCArchiveProofBundle(
            dataclasses.replace(bundle.proof, bundles=swapped),
            bundle.signature,
        )
        self.assertFalse(verify_hdsc_archive_proof_bundle(bad, self.key))

    def test_tampered_sibling_returns_false(self):
        bundle = sealed(self.archive, (0, 2), self.key, seed=12600)
        self.assertTrue(bundle.proof.siblings)
        proof = dataclasses.replace(
            bundle.proof,
            siblings=(b"x" * 32,) + bundle.proof.siblings[1:],
        )
        self.assertFalse(
            verify_hdsc_archive_proof_bundle(
                HDSCArchiveProofBundle(proof, bundle.signature), self.key
            )
        )

    def test_missing_and_extra_sibling_return_false(self):
        bundle = sealed(self.archive, (0, 2, 4), self.key, seed=12700)
        missing = dataclasses.replace(
            bundle.proof, siblings=bundle.proof.siblings[:-1]
        )
        extra = dataclasses.replace(
            bundle.proof,
            siblings=bundle.proof.siblings + (b"x" * 32,),
        )
        self.assertFalse(
            verify_hdsc_archive_proof_bundle(
                HDSCArchiveProofBundle(missing, bundle.signature), self.key
            )
        )
        self.assertFalse(
            verify_hdsc_archive_proof_bundle(
                HDSCArchiveProofBundle(extra, bundle.signature), self.key
            )
        )

    def test_tampered_inner_bundle_returns_false(self):
        bundle = sealed(self.archive, (0, 2), self.key, seed=12800)
        foreign = make_signed_bundle(self.other, 8, (0, 2), seed=12900)
        proof = dataclasses.replace(
            bundle.proof, bundles=(foreign,) + bundle.proof.bundles[1:]
        )
        self.assertFalse(
            verify_hdsc_archive_proof_bundle(
                HDSCArchiveProofBundle(proof, bundle.signature), self.key
            )
        )

    def test_decoded_bundle_verifies_identically(self):
        bundle = sealed(self.archive, (1, 4), self.key, seed=13000)
        decoded = decode_hdsc_archive_proof_bundle(
            encode_hdsc_archive_proof_bundle(bundle)
        )
        self.assertEqual(
            verify_hdsc_archive_proof_bundle(decoded, self.key),
            verify_hdsc_archive_proof_bundle(bundle, self.key),
        )

    def test_non_bundle_type_error(self):
        bundle = sealed(self.archive, (0,), self.key, seed=13100)
        for bad in (
            (bundle.proof, bundle.signature),
            "bundle",
            None,
            bundle.proof,
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_hdsc_archive_proof_bundle(bad, self.key)

    def test_bad_nested_structure_value_error(self):
        bad_proof = HDSCArchiveProof((1, 2), 0, (), ())
        bundle = HDSCArchiveProofBundle(bad_proof, DUMMY_SIGNATURE)
        with self.assertRaises(ValueError):
            verify_hdsc_archive_proof_bundle(bundle, self.key)

    def test_structurally_illegal_signature_raises_value_error(self):
        bundle = sealed(self.archive, (1, 2), self.key, seed=13200)
        for bad_sig in (
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=-1, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=7, signer_ids=()),
            AggregateSignature(R=5, z=7, signer_ids=(3, 1)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad_sig)):
                verify_hdsc_archive_proof_bundle(
                    HDSCArchiveProofBundle(bundle.proof, bad_sig), self.key
                )


if __name__ == "__main__":
    unittest.main()
