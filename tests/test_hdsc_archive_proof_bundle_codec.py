"""Tests for the canonical HDSCArchiveProofBundle transport encoding:
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
from test_nonce_reuse import make_key
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
    """Independently build the bundle wire format straight from the spec.

    Serializes the fields verbatim without structural validation, so
    proofs the encoder rejects can still be rendered into bytes to probe
    the decoder.
    """
    proof = bundle.proof
    signature = bundle.signature
    out = bytearray(BUNDLE_TAG)
    out += varint(proof.total)
    out += u32(len(proof.indices))
    for index in proof.indices:
        out += varint(index)
    out += u32(len(proof.bundles))
    for inner in proof.bundles:
        out += frame(encode_hdsc_proof_bundle(inner))
    out += u32(len(proof.siblings))
    for sibling in proof.siblings:
        out += sibling
    out += varint(signature.R)
    out += varint(signature.z)
    out += u32(len(signature.signer_ids))
    for signer_id in signature.signer_ids:
        out += varint(signer_id)
    return bytes(out)


def signed_root_bundle(archive, indices, key, *, seed=10000):
    """Return a signed HDSCArchiveProofBundle for the given indices."""
    proof, signature = signed_proof(archive, indices, key, seed=seed)
    return HDSCArchiveProofBundle(proof, signature)


def prefix_archive(archive, n):
    """A truncated view of a shared archive with its placeholder signature."""
    return HDSCProofBundleArchive(
        archive.items[:n], archive.signature
    )


def signature_offset(wire: bytes, signature: AggregateSignature) -> int:
    """Start of the trailing signature frame in an independently built wire."""
    tail = (
        len(varint(signature.R))
        + len(varint(signature.z))
        + 4
        + sum(len(varint(signer_id)) for signer_id in signature.signer_ids)
    )
    return len(wire) - tail


class ArchiveProofBundleDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [
                field.name
                for field in dataclasses.fields(HDSCArchiveProofBundle)
            ],
            ["proof", "signature"],
        )
        key = make_key()
        archive = archive_of_size(3, key, seed_base=10100)
        _message, proof = make_hdsc_archive_proof(archive, (1,))
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        bundle = HDSCArchiveProofBundle(proof, signature)
        self.assertIs(bundle.proof, proof)
        self.assertIs(bundle.signature, signature)
        self.assertEqual(
            HDSCArchiveProofBundle(proof=proof, signature=signature),
            bundle,
        )

    def test_fields_have_no_defaults(self):
        for field in dataclasses.fields(HDSCArchiveProofBundle):
            self.assertIs(field.default, dataclasses.MISSING, msg=field.name)
            self.assertIs(
                field.default_factory, dataclasses.MISSING, msg=field.name
            )

    def test_frozen_value_equality_and_hash(self):
        key = make_key()
        archive = archive_of_size(4, key, seed_base=10200)
        _message, proof = make_hdsc_archive_proof(archive, (1, 3))
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        bundle = HDSCArchiveProofBundle(proof, signature)
        same = HDSCArchiveProofBundle(proof, signature)
        self.assertEqual(bundle, same)
        self.assertEqual(hash(bundle), hash(same))
        self.assertNotEqual(
            bundle,
            HDSCArchiveProofBundle(
                proof, AggregateSignature(R=6, z=7, signer_ids=(1, 3))
            ),
        )
        with self.assertRaises(FrozenInstanceError):
            bundle.signature = signature

    def test_construction_does_not_validate(self):
        # A plain frozen value: non-proof and non-signature fields
        # construct; the codec and verifier reject them.
        HDSCArchiveProofBundle("not-a-proof", "not-a-signature")
        HDSCArchiveProofBundle(None, None)


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(8, self.key, seed_base=10300)

    def test_round_trip_for_every_size_and_subset(self):
        for n in range(1, 9):
            archive = prefix_archive(self.archive, n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                bundle = signed_root_bundle(
                    archive, indices, self.key, seed=10400 + n
                )
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
            archive = prefix_archive(self.archive, n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                bundle = signed_root_bundle(
                    archive, indices, self.key, seed=10500 + n
                )
                self.assertEqual(
                    encode_hdsc_archive_proof_bundle(bundle),
                    build_wire(bundle),
                    msg=f"n={n} indices={indices}",
                )

    def test_prefix_is_tag_and_varint_total(self):
        bundle = signed_root_bundle(
            prefix_archive(self.archive, 6), (1, 3), self.key, seed=10600
        )
        wire = encode_hdsc_archive_proof_bundle(bundle)
        self.assertTrue(wire.startswith(BUNDLE_TAG))
        self.assertEqual(
            wire[len(BUNDLE_TAG):len(BUNDLE_TAG) + len(varint(6))],
            varint(6),
        )

    def test_nested_frames_keep_their_own_tags(self):
        bundle = signed_root_bundle(
            prefix_archive(self.archive, 6), (1, 3), self.key, seed=10610
        )
        wire = encode_hdsc_archive_proof_bundle(bundle)
        for inner in bundle.proof.bundles:
            encoded_inner = encode_hdsc_proof_bundle(inner)
            self.assertIn(encoded_inner, wire)
            self.assertTrue(encoded_inner.startswith(b"ts/hdscpb/v1"))

    def test_suffix_is_r_z_count_and_ids(self):
        bundle = signed_root_bundle(
            prefix_archive(self.archive, 6), (1, 3), self.key, seed=10620
        )
        wire = encode_hdsc_archive_proof_bundle(bundle)
        start = signature_offset(wire, bundle.signature)
        signature = bundle.signature
        expected = bytearray()
        expected += varint(signature.R)
        expected += varint(signature.z)
        expected += u32(len(signature.signer_ids))
        for signer_id in signature.signer_ids:
            expected += varint(signer_id)
        self.assertEqual(wire[start:], bytes(expected))

    def test_zero_z_encodes_as_single_body_byte(self):
        archive = prefix_archive(self.archive, 3)
        proof, signature = signed_proof(
            archive, (0,), self.key, seed=10630
        )
        bundle = HDSCArchiveProofBundle(
            proof,
            AggregateSignature(
                R=signature.R, z=0, signer_ids=signature.signer_ids
            ),
        )
        wire = encode_hdsc_archive_proof_bundle(bundle)
        start = signature_offset(wire, bundle.signature)
        start += len(varint(bundle.signature.R))
        self.assertEqual(wire[start:start + 5], b"\x00\x00\x00\x01\x00")

    def test_sibling_section_is_a_count_then_raw_thirty_two_byte_digests(self):
        bundle = signed_root_bundle(
            prefix_archive(self.archive, 8),
            (0, 2, 4),
            self.key,
            seed=10640,
        )
        wire = encode_hdsc_archive_proof_bundle(bundle)
        # Locate the sibling section by rebuilding everything before it.
        proof = bundle.proof
        prefix = bytearray(BUNDLE_TAG)
        prefix += varint(proof.total)
        prefix += u32(len(proof.indices))
        for index in proof.indices:
            prefix += varint(index)
        prefix += u32(len(proof.bundles))
        for inner in proof.bundles:
            prefix += frame(encode_hdsc_proof_bundle(inner))
        offset = len(prefix)
        self.assertEqual(wire[offset:offset + 4], u32(len(proof.siblings)))
        offset += 4
        self.assertEqual(
            wire[offset:offset + 32 * len(proof.siblings)],
            b"".join(proof.siblings),
        )

    def test_decoded_bundle_still_verifies(self):
        for n in range(1, 9):
            archive = prefix_archive(self.archive, n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                bundle = signed_root_bundle(
                    archive, indices, self.key, seed=10700 + n
                )
                decoded = decode_hdsc_archive_proof_bundle(
                    encode_hdsc_archive_proof_bundle(bundle)
                )
                self.assertTrue(
                    verify_hdsc_archive_proof_bundle(decoded, self.key),
                    msg=f"n={n} indices={indices}",
                )

    def test_encoding_is_unique_and_stateless(self):
        bundle = signed_root_bundle(
            prefix_archive(self.archive, 6),
            (0, 2, 4),
            self.key,
            seed=10800,
        )
        self.assertEqual(
            encode_hdsc_archive_proof_bundle(bundle),
            encode_hdsc_archive_proof_bundle(bundle),
        )


class StructureOnlyTest(unittest.TestCase):
    def test_decode_does_not_verify_bundles_or_signature(self):
        # Bundles really signed under another key and a placeholder root
        # signature: structure only, so the bytes round-trip.
        other = make_other_key()
        archive = archive_of_size(4, other, seed_base=10900)
        _message, proof = make_hdsc_archive_proof(archive, (0, 2))
        signature = AggregateSignature(R=9, z=11, signer_ids=(2, 4))
        bundle = HDSCArchiveProofBundle(proof, signature)
        decoded = decode_hdsc_archive_proof_bundle(
            encode_hdsc_archive_proof_bundle(bundle)
        )
        self.assertEqual(decoded, bundle)

    def test_encoding_does_not_check_the_signature_against_the_root(self):
        # A bundle whose root signature verifies under another key encodes
        # fine — structure alone is checked; verify reports it as False.
        key = make_key()
        archive = archive_of_size(4, key, seed_base=11000)
        bundle = signed_root_bundle(archive, (0, 2), key, seed=11010)
        self.assertTrue(encode_hdsc_archive_proof_bundle(bundle))
        self.assertFalse(
            verify_hdsc_archive_proof_bundle(bundle, make_other_key())
        )


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(5, self.key, seed_base=11100)
        self.bundle = signed_root_bundle(
            self.archive, (1, 2), self.key, seed=11110
        )

    def test_non_bundle_type_error(self):
        with self.assertRaises(TypeError):
            encode_hdsc_archive_proof_bundle(("proof", "signature"))
        with self.assertRaises(TypeError):
            encode_hdsc_archive_proof_bundle(None)

    def test_non_proof_field_type_error(self):
        with self.assertRaises(TypeError):
            encode_hdsc_archive_proof_bundle(
                HDSCArchiveProofBundle("not-a-proof", self.bundle.signature)
            )
        with self.assertRaises(TypeError):
            encode_hdsc_archive_proof_bundle(
                HDSCArchiveProofBundle(None, self.bundle.signature)
            )

    def test_non_signature_field_type_error(self):
        with self.assertRaises(TypeError):
            encode_hdsc_archive_proof_bundle(
                HDSCArchiveProofBundle(self.bundle.proof, "no")
            )
        with self.assertRaises(TypeError):
            encode_hdsc_archive_proof_bundle(
                HDSCArchiveProofBundle(self.bundle.proof, None)
            )

    def test_nested_proof_field_type_errors(self):
        proof = self.bundle.proof
        signature = self.bundle.signature
        for bad in (
            dataclasses.replace(proof, indices=[1, 2]),
            dataclasses.replace(proof, indices=(True, 2)),
            dataclasses.replace(proof, total="5"),
            dataclasses.replace(proof, total=True),
            dataclasses.replace(proof, bundles=[proof.bundles[0]] * 2),
            dataclasses.replace(proof, bundles=("not-a-bundle",) * 2),
            dataclasses.replace(proof, siblings=33),
            dataclasses.replace(proof, siblings=[b"s" * 32] * 3),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_hdsc_archive_proof_bundle(
                    HDSCArchiveProofBundle(bad, signature)
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
                    HDSCArchiveProofBundle(self.bundle.proof, bad)
                )

    def test_bad_nested_proof_structure_value_error(self):
        signature = self.bundle.signature
        for bad_proof in (
            HDSCArchiveProof(indices=(), total=5, bundles=(), siblings=()),
            HDSCArchiveProof(
                indices=(1, 2), total=0, bundles=(), siblings=()
            ),
            HDSCArchiveProof(
                indices=(2, 1),
                total=5,
                bundles=self.bundle.proof.bundles,
                siblings=self.bundle.proof.siblings,
            ),
            HDSCArchiveProof(
                indices=(5,),
                total=5,
                bundles=self.bundle.proof.bundles[:1],
                siblings=(),
            ),
        ):
            with self.assertRaises(ValueError, msg=repr(bad_proof)):
                encode_hdsc_archive_proof_bundle(
                    HDSCArchiveProofBundle(bad_proof, signature)
                )

    def test_bundle_count_mismatch_value_error(self):
        proof = self.bundle.proof
        bad = dataclasses.replace(proof, bundles=proof.bundles[:1])
        with self.assertRaises(ValueError):
            encode_hdsc_archive_proof_bundle(
                HDSCArchiveProofBundle(bad, self.bundle.signature)
            )

    def test_wrong_sibling_count_value_error(self):
        proof = self.bundle.proof
        self.assertTrue(proof.siblings)
        for siblings in (
            proof.siblings[:-1],
            proof.siblings + (b"x" * 32,),
        ):
            bad = dataclasses.replace(proof, siblings=siblings)
            with self.assertRaises(ValueError, msg=repr(siblings)):
                encode_hdsc_archive_proof_bundle(
                    HDSCArchiveProofBundle(bad, self.bundle.signature)
                )

    def test_sibling_width_value_error(self):
        proof = self.bundle.proof
        bad = dataclasses.replace(
            proof,
            siblings=(b"s" * 31,) + proof.siblings[1:],
        )
        with self.assertRaises(ValueError):
            encode_hdsc_archive_proof_bundle(
                HDSCArchiveProofBundle(bad, self.bundle.signature)
            )

    def test_illegal_nested_bundle_value_error(self):
        bad_inner = HDSCProofBundle(
            HDSCProof(indices=(), total=0, seals=(), siblings=()),
            DUMMY_SIGNATURE,
        )
        proof = self.bundle.proof
        bad = dataclasses.replace(
            proof,
            bundles=(bad_inner,) + proof.bundles[1:],
        )
        with self.assertRaises(ValueError):
            encode_hdsc_archive_proof_bundle(
                HDSCArchiveProofBundle(bad, self.bundle.signature)
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
                    HDSCArchiveProofBundle(self.bundle.proof, bad)
                )


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(5, self.key, seed_base=11200)
        self.bundle = signed_root_bundle(
            self.archive, (1, 2), self.key, seed=11210
        )
        self.wire = encode_hdsc_archive_proof_bundle(self.bundle)

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

    def test_total_zero_rejected(self):
        total_width = len(varint(self.bundle.proof.total))
        bad = BUNDLE_TAG + varint(0) + self.wire[
            len(BUNDLE_TAG) + total_width:
        ]
        with self.assertRaises(ValueError):
            decode_hdsc_archive_proof_bundle(bad)

    def test_non_canonical_total_leading_zero(self):
        total_width = len(varint(self.bundle.proof.total))
        non_canonical_total = u32(2) + b"\x00\x05"
        bad = (
            BUNDLE_TAG
            + non_canonical_total
            + self.wire[len(BUNDLE_TAG) + total_width:]
        )
        with self.assertRaises(ValueError):
            decode_hdsc_archive_proof_bundle(bad)

    def test_empty_index_list_rejected(self):
        total_width = len(varint(self.bundle.proof.total))
        offset = len(BUNDLE_TAG) + total_width
        bad = self.wire[:offset] + u32(0) + self.wire[offset + 4:]
        with self.assertRaises(ValueError):
            decode_hdsc_archive_proof_bundle(bad)

    def test_index_out_of_range_rejected(self):
        proof = self.bundle.proof
        # total=3 with index 5; two siblings keep the counts consistent so
        # the range check itself is what rejects the bytes.
        bad_proof = HDSCArchiveProof(
            indices=(5,),
            total=3,
            bundles=proof.bundles[:1],
            siblings=(b"a" * 32, b"b" * 32),
        )
        wire = build_wire(
            HDSCArchiveProofBundle(bad_proof, self.bundle.signature)
        )
        with self.assertRaises(ValueError):
            decode_hdsc_archive_proof_bundle(wire)

    def test_non_increasing_indices_rejected(self):
        proof = self.bundle.proof
        bad_proof = dataclasses.replace(proof, indices=(2, 1))
        wire = build_wire(
            HDSCArchiveProofBundle(bad_proof, self.bundle.signature)
        )
        with self.assertRaises(ValueError):
            decode_hdsc_archive_proof_bundle(wire)

    def test_bundle_count_mismatch_rejected(self):
        proof = self.bundle.proof
        offset = len(BUNDLE_TAG) + len(varint(proof.total)) + 4
        for index in proof.indices:
            offset += len(varint(index))
        bad = self.wire[:offset] + u32(1) + self.wire[offset + 4:]
        with self.assertRaises(ValueError):
            decode_hdsc_archive_proof_bundle(bad)

    def test_zero_bundle_frame_rejected(self):
        bad = (
            BUNDLE_TAG
            + varint(2)
            + u32(1)
            + varint(0)
            + u32(1)
            + u32(0)
        )
        with self.assertRaises(ValueError):
            decode_hdsc_archive_proof_bundle(bad)

    def test_junk_bundle_frame_rejected(self):
        bad = (
            BUNDLE_TAG
            + varint(2)
            + u32(1)
            + varint(0)
            + u32(1)
            + frame(b"not-a-bundle")
            + u32(1)
            + b"s" * 32
        )
        with self.assertRaises(ValueError):
            decode_hdsc_archive_proof_bundle(bad)

    def test_wrong_sibling_count_rejected(self):
        proof = self.bundle.proof
        self.assertTrue(proof.siblings)
        for siblings in (
            proof.siblings[:-1],
            proof.siblings + (b"x" * 32,),
        ):
            bad_proof = dataclasses.replace(proof, siblings=siblings)
            wire = build_wire(
                HDSCArchiveProofBundle(bad_proof, self.bundle.signature)
            )
            with self.assertRaises(ValueError, msg=repr(siblings)):
                decode_hdsc_archive_proof_bundle(wire)

    def test_truncated_sibling_digests_rejected(self):
        proof = self.bundle.proof
        # Declare the required count but supply one byte less.
        wire = build_wire(self.bundle)
        bad = wire[:-1 - self._signature_frame_len()]
        with self.assertRaises(ValueError):
            decode_hdsc_archive_proof_bundle(bad)

    def _signature_frame_len(self):
        signature = self.bundle.signature
        return (
            len(varint(signature.R))
            + len(varint(signature.z))
            + 4
            + sum(len(varint(s)) for s in signature.signer_ids)
        )

    def test_zero_R_rejected(self):
        signature = self.bundle.signature
        bad_sig = AggregateSignature(
            R=0, z=signature.z, signer_ids=signature.signer_ids
        )
        wire = build_wire(
            HDSCArchiveProofBundle(self.bundle.proof, bad_sig)
        )
        with self.assertRaises(ValueError):
            decode_hdsc_archive_proof_bundle(wire)

    def test_non_canonical_R_leading_zero(self):
        signature = AggregateSignature(R=9, z=7, signer_ids=(1, 3))
        wire = build_wire(
            HDSCArchiveProofBundle(self.bundle.proof, signature)
        )
        start = signature_offset(wire, signature)
        non_canonical_R = u32(2) + b"\x00\x09"
        bad = (
            wire[:start]
            + non_canonical_R
            + wire[start + len(varint(9)):]
        )
        with self.assertRaises(ValueError):
            decode_hdsc_archive_proof_bundle(bad)

    def test_zero_signer_count_rejected(self):
        signature = self.bundle.signature
        start = signature_offset(self.wire, signature)
        tail = len(varint(signature.R)) + len(varint(signature.z))
        bad = self.wire[:start + tail] + u32(0)
        with self.assertRaises(ValueError):
            decode_hdsc_archive_proof_bundle(bad)

    def test_signer_count_too_large_then_truncated(self):
        signature = self.bundle.signature
        start = signature_offset(self.wire, signature)
        tail = len(varint(signature.R)) + len(varint(signature.z))
        bad = self.wire[:start + tail] + u32(
            len(signature.signer_ids) + 1
        )
        for signer_id in signature.signer_ids:
            bad += varint(signer_id)
        with self.assertRaises(ValueError):
            decode_hdsc_archive_proof_bundle(bad)

    def test_non_positive_and_unsorted_signer_ids_rejected(self):
        signature = self.bundle.signature
        start = signature_offset(self.wire, signature)
        prefix = self.wire[
            :start + len(varint(signature.R)) + len(varint(signature.z))
        ]
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
                out += u32(1)
                out += body
            with self.assertRaises(ValueError, msg=label):
                decode_hdsc_archive_proof_bundle(bytes(out))

    def test_nested_bundle_trailing_bytes_rejected(self):
        # An over-long declared nested frame swallows part of the next
        # framing, so the nested decoder rejects the frame.
        proof = self.bundle.proof
        offset = len(BUNDLE_TAG) + len(varint(proof.total)) + 4
        for index in proof.indices:
            offset += len(varint(index))
        offset += 4  # bundle count
        first_frame_length = int.from_bytes(
            self.wire[offset:offset + 4], "big"
        )
        bad = bytearray(self.wire)
        bad[offset:offset + 4] = u32(first_frame_length + 1)
        with self.assertRaises(ValueError):
            decode_hdsc_archive_proof_bundle(bytes(bad))


class VerifyArchiveProofBundleTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.other = make_other_key()
        self.archive = archive_of_size(8, self.key, seed_base=11300)

    def test_honest_bundles_verify_for_every_size_and_subset(self):
        for n in range(1, 9):
            archive = prefix_archive(self.archive, n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                bundle = signed_root_bundle(
                    archive, indices, self.key, seed=11400 + n
                )
                self.assertTrue(
                    verify_hdsc_archive_proof_bundle(bundle, self.key),
                    msg=f"n={n} indices={indices}",
                )

    def test_result_equals_check_hdsc_archive_proof(self):
        for n in range(1, 9):
            archive = prefix_archive(self.archive, n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                bundle = signed_root_bundle(
                    archive, indices, self.key, seed=11500 + n
                )
                self.assertEqual(
                    verify_hdsc_archive_proof_bundle(bundle, self.key),
                    check_hdsc_archive_proof(
                        bundle.proof, bundle.signature, self.key
                    ),
                    msg=f"n={n} indices={indices}",
                )

    def test_wrong_key_returns_false(self):
        bundle = signed_root_bundle(
            self.archive, (1, 3), self.key, seed=11510
        )
        self.assertFalse(
            verify_hdsc_archive_proof_bundle(bundle, self.other)
        )

    def test_swapped_bundles_return_false(self):
        bundle = signed_root_bundle(
            self.archive, (1, 2), self.key, seed=11600
        )
        swapped = (
            bundle.proof.bundles[1],
            bundle.proof.bundles[0],
        )
        bad = HDSCArchiveProofBundle(
            dataclasses.replace(bundle.proof, bundles=swapped),
            bundle.signature,
        )
        self.assertFalse(
            verify_hdsc_archive_proof_bundle(bad, self.key)
        )

    def test_foreign_bundle_returns_false(self):
        # A real bundle signed under another key: the nested
        # verify_hdsc_proof_bundle fails before the root signature.
        foreign = make_signed_bundle(self.other, 8, (0, 2), seed=11610)
        bundle = signed_root_bundle(
            self.archive, (0,), self.key, seed=11620
        )
        bad = HDSCArchiveProofBundle(
            dataclasses.replace(bundle.proof, bundles=(foreign,)),
            bundle.signature,
        )
        self.assertFalse(
            verify_hdsc_archive_proof_bundle(bad, self.key)
        )

    def test_flipped_sibling_returns_false(self):
        bundle = signed_root_bundle(
            self.archive, (0, 2), self.key, seed=11700
        )
        self.assertTrue(bundle.proof.siblings)
        flipped = bytearray(bundle.proof.siblings[0])
        flipped[0] ^= 1
        bad = HDSCArchiveProofBundle(
            dataclasses.replace(
                bundle.proof,
                siblings=(bytes(flipped),) + bundle.proof.siblings[1:],
            ),
            bundle.signature,
        )
        self.assertFalse(
            verify_hdsc_archive_proof_bundle(bad, self.key)
        )

    def test_missing_and_extra_sibling_return_false(self):
        proof, signature = signed_proof(
            self.archive, (0, 2, 4), self.key, seed=11800
        )
        missing = HDSCArchiveProofBundle(
            dataclasses.replace(proof, siblings=proof.siblings[:-1]),
            signature,
        )
        extra = HDSCArchiveProofBundle(
            dataclasses.replace(
                proof, siblings=proof.siblings + (b"x" * 32,)
            ),
            signature,
        )
        self.assertFalse(
            verify_hdsc_archive_proof_bundle(missing, self.key)
        )
        self.assertFalse(
            verify_hdsc_archive_proof_bundle(extra, self.key)
        )

    def test_tampered_signature_returns_false(self):
        bundle = signed_root_bundle(
            self.archive, (0, 2, 4), self.key, seed=11900
        )
        tampered = AggregateSignature(
            R=bundle.signature.R,
            z=bundle.signature.z,
            signer_ids=bundle.signature.signer_ids[:-1]
            + (bundle.signature.signer_ids[-1] ^ 0xFF,),
        )
        bad = HDSCArchiveProofBundle(bundle.proof, tampered)
        self.assertFalse(
            verify_hdsc_archive_proof_bundle(bad, self.key)
        )

    def test_signature_over_another_statement_returns_false(self):
        bundle = signed_root_bundle(
            self.archive, (0, 2), self.key, seed=12000
        )
        other_message, _other = make_hdsc_archive_proof(
            prefix_archive(self.archive, 4), (0, 2)
        )
        other_signature = sign_message(self.key, other_message, seed=12010)
        bad = HDSCArchiveProofBundle(bundle.proof, other_signature)
        self.assertFalse(
            verify_hdsc_archive_proof_bundle(bad, self.key)
        )

    def test_decoded_bundle_verifies_identically(self):
        bundle = signed_root_bundle(
            self.archive, (1, 4), self.key, seed=12100
        )
        decoded = decode_hdsc_archive_proof_bundle(
            encode_hdsc_archive_proof_bundle(bundle)
        )
        self.assertEqual(
            verify_hdsc_archive_proof_bundle(decoded, self.key),
            verify_hdsc_archive_proof_bundle(bundle, self.key),
        )

    def test_non_bundle_type_error(self):
        _message, proof = make_hdsc_archive_proof(self.archive, (0,))
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        for bad in ((proof, signature), "bundle", None, proof):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_hdsc_archive_proof_bundle(bad, self.key)

    def test_bad_nested_structure_value_error(self):
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        bad_proof = HDSCArchiveProof((1, 2), 0, (), ())
        bundle = HDSCArchiveProofBundle(bad_proof, signature)
        with self.assertRaises(ValueError):
            verify_hdsc_archive_proof_bundle(bundle, self.key)

    def test_structurally_illegal_signature_raises_value_error(self):
        _message, proof = make_hdsc_archive_proof(self.archive, (1, 2))
        for bad_sig in (
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=-1, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=7, signer_ids=()),
            AggregateSignature(R=5, z=7, signer_ids=(3, 1)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad_sig)):
                verify_hdsc_archive_proof_bundle(
                    HDSCArchiveProofBundle(proof, bad_sig), self.key
                )


if __name__ == "__main__":
    unittest.main()
