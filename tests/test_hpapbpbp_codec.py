"""Tests for the canonical HPAPBPBP proof transport encoding
encode_hpapbpbp / decode_hpapbpbp and the HPAPBPBPB proof-plus-signature
bundle HPAPBPBPB / encode_hpapbpbpb / decode_hpapbpbpb /
verify_hpapbpbpb over the HPAPBPB archive membership proofs."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    HPAPBP,
    HPAPBPB,
    HPAPBPBP,
    HPAPBPBPB,
    HPAPBPBArchive,
    check_hpapbpbp,
    decode_hpapbpbp,
    decode_hpapbpbpb,
    encode_hpapbpbp,
    encode_hpapbpbpb,
    encode_hpapbpb,
    make_hpapbpbp,
    verify_hpapbpbpb,
)

from test_audit_chain import sign_message
from test_audit_extension_proof_bundle_codec import make_other_key
from test_nonce_reuse import make_key
from test_hpapbpbp import (
    DUMMY_OUTER_SIGNATURE,
    archive_of_packets,
    signed_proof,
)
from test_hpapbp import archive_of_size
from test_hpapbp_codec import signed_hpapbpb

PROOF_TAG = b"ts/hpapbpbp/v1"
BUNDLE_TAG = b"ts/hpapbpbpb/v1"

DUMMY_SIGNATURE = AggregateSignature(R=5, z=7, signer_ids=(1, 3))


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def prefix_archive(archive, n):
    """A truncated view of a shared archive with its placeholder signature."""
    return HPAPBPBArchive(archive.items[:n], archive.signature)


def signed_hpapbpbpb(archive, indices, key, *, seed=95000):
    proof, signature = signed_proof(archive, indices, key, seed=seed)
    return HPAPBPBPB(proof, signature)


def build_proof_wire(proof):
    """Independently build the HPAPBPBP wire format straight from the spec.

    Serializes the fields verbatim without structural validation, so
    proofs the encoder rejects can still be rendered into bytes to probe
    the decoder.
    """
    out = bytearray(PROOF_TAG)
    out += varint(proof.total)
    out += u32(len(proof.indices))
    for index in proof.indices:
        out += varint(index)
    out += u32(len(proof.packets))
    for packet in proof.packets:
        out += frame(encode_hpapbpb(packet))
    out += u32(len(proof.siblings))
    for sibling in proof.siblings:
        out += sibling
    return bytes(out)


def build_bundle_wire(bundle):
    """Independently build the HPAPBPBPB wire format straight from the spec."""
    signature = bundle.signature
    out = bytearray(BUNDLE_TAG)
    out += frame(build_proof_wire(bundle.proof))
    out += varint(signature.R)
    out += varint(signature.z)
    out += u32(len(signature.signer_ids))
    for signer_id in signature.signer_ids:
        out += varint(signer_id)
    return bytes(out)


def signature_offset(wire: bytes, signature: AggregateSignature) -> int:
    """Start of the trailing signature frame in an independently built wire."""
    tail = (
        len(varint(signature.R))
        + len(varint(signature.z))
        + 4
        + sum(len(varint(signer_id)) for signer_id in signature.signer_ids)
    )
    return len(wire) - tail


class HPAPBPBPBDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(HPAPBPBPB)],
            ["proof", "signature"],
        )
        key = make_key()
        archive = archive_of_packets(3, key)
        proof, signature = signed_proof(archive, (0, 2), key)
        bundle = HPAPBPBPB(proof, signature)
        self.assertIs(bundle.proof, proof)
        self.assertIs(bundle.signature, signature)

    def test_frozen_value_equality_and_hash(self):
        key = make_key()
        archive = archive_of_packets(3, key)
        proof, signature = signed_proof(archive, (1,), key)
        bundle = HPAPBPBPB(proof, signature)
        same = HPAPBPBPB(proof=proof, signature=signature)
        self.assertEqual(bundle, same)
        self.assertEqual(hash(bundle), hash(same))
        other_proof, _ = signed_proof(archive, (0, 2), key)
        self.assertNotEqual(bundle, HPAPBPBPB(other_proof, signature))
        self.assertNotEqual(
            bundle,
            HPAPBPBPB(
                proof, AggregateSignature(R=6, z=7, signer_ids=(1, 3))
            ),
        )
        with self.assertRaises(FrozenInstanceError):
            bundle.signature = signature

    def test_construction_does_not_validate(self):
        HPAPBPBPB("not-a-proof", "not-a-signature")
        HPAPBPBPB(None, None)


class EncodeHPAPBPBPTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_packets(8, self.key)

    def test_layout_matches_independent_builder(self):
        cases = (
            (1, (0,)),
            (2, (0, 1)),
            (3, (0, 2)),
            (4, (1, 3)),
            (5, (0, 2, 4)),
            (6, (0, 1, 2, 3, 4, 5)),
            (7, (0, 6)),
            (8, (0, 2, 4, 6)),
            (8, tuple(range(8))),
        )
        for n, indices in cases:
            archive = prefix_archive(self.archive, n)
            proof, _signature = signed_proof(archive, indices, self.key)
            self.assertEqual(
                encode_hpapbpbp(proof),
                build_proof_wire(proof),
                msg=f"n={n} indices={indices}",
            )

    def test_encoding_starts_with_tag_and_contains_hpapbpb_frames(self):
        proof, _signature = signed_proof(
            self.archive, (0, 2), self.key
        )
        blob = encode_hpapbpbp(proof)
        self.assertTrue(blob.startswith(PROOF_TAG))
        # Each packet frame body is an existing HPAPBPB transport encoding.
        for packet in proof.packets:
            self.assertIn(encode_hpapbpb(packet), blob)
            self.assertTrue(
                encode_hpapbpb(packet).startswith(b"ts/hpapbpb/v1")
            )

    def test_deterministic_and_unique_output(self):
        proof, _ = signed_proof(self.archive, (0, 2, 4), self.key)
        self.assertEqual(encode_hpapbpbp(proof), encode_hpapbpbp(proof))
        other, _ = signed_proof(self.archive, (0, 2, 5), self.key)
        self.assertNotEqual(
            encode_hpapbpbp(proof), encode_hpapbpbp(other)
        )

    def test_type_errors(self):
        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        with self.assertRaises(TypeError):
            encode_hpapbpbp("not-a-proof")
        with self.assertRaises(TypeError):
            encode_hpapbpbp(None)
        for bad in (
            HPAPBPBP([0, 2], proof.total, proof.packets, proof.siblings),
            HPAPBPBP((0, 2), "8", proof.packets, proof.siblings),
            HPAPBPBP((0, 2), True, proof.packets, proof.siblings),
            HPAPBPBP((0, True), proof.total, proof.packets, proof.siblings),
            HPAPBPBP(
                (0, 2), proof.total, list(proof.packets), proof.siblings
            ),
            HPAPBPBP(
                (0, 2), proof.total, proof.packets, list(proof.siblings)
            ),
            HPAPBPBP((0, 2), proof.total, ("x",) * 2, proof.siblings),
            HPAPBPBP(
                (0, 2), proof.total, proof.packets, (b"x" * 32, 9)
            ),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_hpapbpbp(bad)

    def test_structure_value_errors(self):
        proof, _signature = signed_proof(
            self.archive, (0, 2, 4), self.key
        )
        for bad in (
            HPAPBPBP((), proof.total, (), ()),
            HPAPBPBP((0, 2), 0, proof.packets[:2], proof.siblings),
            HPAPBPBP((0, 8), proof.total, proof.packets[:2], proof.siblings),
            HPAPBPBP((2, 0), proof.total, proof.packets[:2], proof.siblings),
            HPAPBPBP((1, 1), proof.total, proof.packets[:2], proof.siblings),
            # A packet tuple that does not pair one-to-one with indices.
            HPAPBPBP(
                proof.indices, proof.total, proof.packets[:2],
                proof.siblings,
            ),
            HPAPBPBP(
                proof.indices,
                proof.total,
                proof.packets + (proof.packets[0],),
                proof.siblings,
            ),
            # A sibling that is not exactly 32 bytes.
            HPAPBPBP(
                proof.indices, proof.total, proof.packets, (b"short",)
            ),
            # A sibling count other than the one total and indices determine.
            HPAPBPBP(
                proof.indices,
                proof.total,
                proof.packets,
                proof.siblings + (b"x" * 32,),
            ),
            HPAPBPBP(
                proof.indices,
                proof.total,
                proof.packets,
                proof.siblings[:-1],
            ),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                encode_hpapbpbp(bad)

    def test_illegal_nested_packet_value_error(self):
        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        bad_packet = HPAPBPB(
            HPAPBP(indices=(), total=0, bundles=(), siblings=()),
            DUMMY_SIGNATURE,
        )
        bad_proof = HPAPBPBP(
            proof.indices,
            proof.total,
            (bad_packet, proof.packets[1]),
            proof.siblings,
        )
        with self.assertRaises(ValueError):
            encode_hpapbpbp(bad_proof)

    def test_mismatched_content_still_encodes(self):
        # A structurally legal proof whose content does not match its
        # root encodes and decodes normally; only verification judges it.
        proof, signature = signed_proof(self.archive, (0, 2), self.key)
        damaged = HPAPBPBP(
            proof.indices,
            proof.total,
            proof.packets,
            (b"\x00" * 32,) + proof.siblings[1:],
        )
        self.assertEqual(
            encode_hpapbpbp(damaged), build_proof_wire(damaged)
        )
        self.assertEqual(decode_hpapbpbp(encode_hpapbpbp(damaged)), damaged)
        self.assertFalse(check_hpapbpbp(damaged, signature, self.key))

    def test_count_at_2_pow_64_boundary_raises_value_error(self):
        class HugeTuple(tuple):
            def __len__(self):
                return 2 ** 64

        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        with self.assertRaises(ValueError):
            encode_hpapbpbp(
                HPAPBPBP(
                    proof.indices, 2 ** 64, proof.packets, proof.siblings
                )
            )
        for bad in (
            HPAPBPBP(
                HugeTuple(proof.indices), proof.total, proof.packets,
                proof.siblings,
            ),
            HPAPBPBP(
                proof.indices, proof.total, HugeTuple(proof.packets),
                proof.siblings,
            ),
            HPAPBPBP(
                proof.indices, proof.total, proof.packets,
                HugeTuple(proof.siblings),
            ),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                encode_hpapbpbp(bad)


class DecodeHPAPBPBPTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_packets(8, self.key)

    def test_roundtrip_for_every_size_and_subset(self):
        for n in range(1, 9):
            archive = prefix_archive(self.archive, n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                proof, _signature = signed_proof(archive, indices, self.key)
                blob = encode_hpapbpbp(proof)
                restored = decode_hpapbpbp(blob)
                self.assertEqual(restored, proof)
                self.assertEqual(encode_hpapbpbp(restored), blob)

    def test_non_bytes_type_error(self):
        for bad in ("x", b"x".hex(), 42, None, bytearray(b"x")):
            with self.assertRaises(TypeError, msg=repr(bad)):
                decode_hpapbpbp(bad)

    def test_bad_tag_and_truncation(self):
        proof, _signature = signed_proof(
            prefix_archive(self.archive, 2), (0,), self.key
        )
        blob = encode_hpapbpbp(proof)
        with self.assertRaises(ValueError):
            decode_hpapbpbp(
                b"ts/hpapbpbp/v2" + blob[len(PROOF_TAG):]
            )
        with self.assertRaises(ValueError):
            decode_hpapbpbp(blob[: len(PROOF_TAG) - 1])
        for cut in range(len(PROOF_TAG), len(blob)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_hpapbpbp(blob[:cut])

    def test_trailing_bytes(self):
        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        blob = encode_hpapbpbp(proof)
        with self.assertRaises(ValueError):
            decode_hpapbpbp(blob + b"\x00")

    def test_zero_and_overlarge_total(self):
        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        blob = encode_hpapbpbp(proof)
        rest = blob[len(PROOF_TAG):]
        rest = rest[len(varint(proof.total)):]
        with self.assertRaises(ValueError):
            decode_hpapbpbp(PROOF_TAG + varint(0) + rest)
        with self.assertRaises(ValueError):
            decode_hpapbpbp(PROOF_TAG + varint(1 << 64) + rest)

    def test_bad_index_and_packet_counts(self):
        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        blob = encode_hpapbpbp(proof)
        head = PROOF_TAG + varint(proof.total)
        # An empty index list is illegal.
        with self.assertRaises(ValueError):
            decode_hpapbpbp(head + u32(0) + blob[len(head) + 4:])
        # A packet count that does not match the index count is illegal.
        head += u32(2) + varint(0) + varint(2)
        with self.assertRaises(ValueError):
            decode_hpapbpbp(head + u32(1) + blob[len(head) + 4:])

    def test_non_increasing_and_out_of_range_indices(self):
        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        for bad_indices in ((2, 0), (1, 1), (0, 8), (9,)):
            wire = bytearray(PROOF_TAG)
            wire += varint(proof.total)
            wire += u32(len(bad_indices))
            for index in bad_indices:
                wire += varint(index)
            wire += u32(len(proof.packets))
            for packet in proof.packets:
                wire += frame(encode_hpapbpb(packet))
            wire += u32(len(proof.siblings))
            for sibling in proof.siblings:
                wire += sibling
            with self.assertRaises(
                ValueError, msg=f"indices={bad_indices}"
            ):
                decode_hpapbpbp(bytes(wire))

    def test_bad_nested_frame(self):
        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        blob = encode_hpapbpbp(proof)
        head = PROOF_TAG + varint(proof.total)
        head += u32(2) + varint(0) + varint(2) + u32(2)
        with self.assertRaises(ValueError):
            decode_hpapbpbp(head + u32(0) + blob[len(head) + 4:])
        with self.assertRaises(ValueError):
            decode_hpapbpbp(
                head + frame(b"garbage") + blob[len(head) + 4:]
            )

    def test_wrong_sibling_count_rejected(self):
        proof, _signature = signed_proof(self.archive, (0, 3), self.key)
        self.assertGreater(len(proof.siblings), 0)
        blob = encode_hpapbpbp(proof)
        sibling_count_offset = (
            len(blob) - 4 - 32 * len(proof.siblings)
        )
        head = blob[:sibling_count_offset]
        tail = blob[sibling_count_offset + 4:]
        for bad_count in (
            len(proof.siblings) - 1,
            len(proof.siblings) + 1,
        ):
            with self.assertRaises(ValueError, msg=f"count={bad_count}"):
                decode_hpapbpbp(head + u32(bad_count) + tail)

    def test_sibling_section_width_mismatch_rejected(self):
        proof, _signature = signed_proof(self.archive, (0, 3), self.key)
        blob = encode_hpapbpbp(proof)
        sibling_count_offset = (
            len(blob) - 4 - 32 * len(proof.siblings)
        )
        head = blob[:sibling_count_offset]
        # The right count but a section that is not exactly 32 bytes per
        # item: one byte short truncates the last digest.
        body = blob[sibling_count_offset + 4:]
        with self.assertRaises(ValueError):
            decode_hpapbpbp(
                head + u32(len(proof.siblings)) + body[:-1]
            )

    def test_non_canonical_integers_rejected(self):
        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        blob = encode_hpapbpbp(proof)
        offset = len(PROOF_TAG)
        self.assertEqual(
            bytes(blob[offset:offset + 5]), varint(proof.total)
        )
        spliced = (
            PROOF_TAG
            + (2).to_bytes(4, "big")
            + b"\x00"
            + bytes([proof.total])
            + blob[offset + 5:]
        )
        with self.assertRaises(ValueError):
            decode_hpapbpbp(spliced)


class EncodeHPAPBPBPBTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_packets(6, self.key)

    def test_layout_matches_independent_builder(self):
        cases = (
            (1, (0,)),
            (3, (0, 2)),
            (5, (0, 2, 4)),
            (6, tuple(range(6))),
            (6, (3, 5)),
        )
        for n, indices in cases:
            archive = prefix_archive(self.archive, n)
            bundle = signed_hpapbpbpb(archive, indices, self.key)
            self.assertEqual(
                encode_hpapbpbpb(bundle),
                build_bundle_wire(bundle),
                msg=f"n={n} indices={indices}",
            )

    def test_encoding_frames_the_proof_encoding(self):
        bundle = signed_hpapbpbpb(self.archive, (0, 2), self.key)
        blob = encode_hpapbpbpb(bundle)
        self.assertTrue(blob.startswith(BUNDLE_TAG))
        encoded_proof = encode_hpapbpbp(bundle.proof)
        self.assertEqual(
            blob[len(BUNDLE_TAG):len(BUNDLE_TAG) + 4],
            u32(len(encoded_proof)),
        )
        self.assertIn(encoded_proof, blob)

    def test_deterministic_and_unique_output(self):
        bundle = signed_hpapbpbpb(self.archive, (0, 2, 4), self.key)
        self.assertEqual(
            encode_hpapbpbpb(bundle), encode_hpapbpbpb(bundle)
        )
        other = signed_hpapbpbpb(self.archive, (0, 2, 5), self.key)
        self.assertNotEqual(
            encode_hpapbpbpb(bundle), encode_hpapbpbpb(other)
        )

    def test_type_errors(self):
        bundle = signed_hpapbpbpb(self.archive, (0, 2), self.key)
        with self.assertRaises(TypeError):
            encode_hpapbpbpb("not-a-bundle")
        with self.assertRaises(TypeError):
            encode_hpapbpbpb(None)
        with self.assertRaises(TypeError):
            encode_hpapbpbpb(HPAPBPBPB("not-a-proof", bundle.signature))
        proof = bundle.proof
        bad_proof = HPAPBPBP(
            [0, 2], proof.total, proof.packets, proof.siblings
        )
        with self.assertRaises(TypeError):
            encode_hpapbpbpb(HPAPBPBPB(bad_proof, bundle.signature))
        with self.assertRaises(TypeError):
            encode_hpapbpbpb(HPAPBPBPB(proof, "not-a-signature"))

    def test_structure_value_errors(self):
        bundle = signed_hpapbpbpb(self.archive, (0, 2, 4), self.key)
        proof = bundle.proof
        for bad_proof in (
            HPAPBPBP((), proof.total, (), ()),
            HPAPBPBP((0, 2), 0, proof.packets[:2], proof.siblings),
            HPAPBPBP(
                proof.indices, proof.total, proof.packets[:2],
                proof.siblings,
            ),
            HPAPBPBP(
                proof.indices, proof.total, proof.packets,
                proof.siblings[:-1],
            ),
        ):
            with self.assertRaises(ValueError, msg=repr(bad_proof)):
                encode_hpapbpbpb(HPAPBPBPB(bad_proof, bundle.signature))

    def test_signature_structure_value_errors(self):
        bundle = signed_hpapbpbpb(self.archive, (0, 2), self.key)
        for bad_signature in (
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=-1, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=-1, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=7, signer_ids=()),
            AggregateSignature(R=5, z=7, signer_ids=(0, 3)),
            AggregateSignature(R=5, z=7, signer_ids=(3, 1)),
            AggregateSignature(R=5, z=7, signer_ids=(1, 1)),
        ):
            with self.assertRaises(
                ValueError, msg=repr(bad_signature)
            ):
                encode_hpapbpbpb(
                    HPAPBPBPB(bundle.proof, bad_signature)
                )

    def test_does_not_verify(self):
        # A structurally legal bundle whose signature signs nothing valid
        # still encodes: encoding checks structure, never signatures.
        proof, _ = signed_proof(self.archive, (0, 2), self.key)
        bundle = HPAPBPBPB(proof, DUMMY_SIGNATURE)
        self.assertEqual(
            encode_hpapbpbpb(bundle), build_bundle_wire(bundle)
        )


class DecodeHPAPBPBPBTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_packets(6, self.key)

    def test_roundtrip_for_every_size_and_subset(self):
        for n in range(1, 7):
            archive = prefix_archive(self.archive, n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                bundle = signed_hpapbpbpb(archive, indices, self.key)
                blob = encode_hpapbpbpb(bundle)
                restored = decode_hpapbpbpb(blob)
                self.assertEqual(restored, bundle)
                self.assertEqual(encode_hpapbpbpb(restored), blob)

    def test_non_bytes_type_error(self):
        for bad in ("x", b"x".hex(), 42, None, bytearray(b"x")):
            with self.assertRaises(TypeError, msg=repr(bad)):
                decode_hpapbpbpb(bad)

    def test_bad_tag_and_truncation(self):
        bundle = signed_hpapbpbpb(
            prefix_archive(self.archive, 2), (0,), self.key
        )
        blob = encode_hpapbpbpb(bundle)
        with self.assertRaises(ValueError):
            decode_hpapbpbpb(
                b"ts/hpapbpbpb/v2" + blob[len(BUNDLE_TAG):]
            )
        with self.assertRaises(ValueError):
            decode_hpapbpbpb(blob[: len(BUNDLE_TAG) - 1])
        for cut in range(len(BUNDLE_TAG), len(blob)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_hpapbpbpb(blob[:cut])

    def test_trailing_bytes(self):
        bundle = signed_hpapbpbpb(self.archive, (0, 2), self.key)
        blob = encode_hpapbpbpb(bundle)
        with self.assertRaises(ValueError):
            decode_hpapbpbpb(blob + b"\x00")

    def test_bad_proof_frame(self):
        bundle = signed_hpapbpbpb(self.archive, (0, 2), self.key)
        blob = encode_hpapbpbpb(bundle)
        head = BUNDLE_TAG
        with self.assertRaises(ValueError):
            decode_hpapbpbpb(head + u32(0) + blob[len(head) + 4:])
        with self.assertRaises(ValueError):
            decode_hpapbpbpb(
                head + frame(b"garbage") + blob[len(head) + 4:]
            )

    def test_bad_signature_frame(self):
        bundle = signed_hpapbpbpb(self.archive, (0, 2), self.key)
        blob = encode_hpapbpbpb(bundle)
        encoded_proof = frame(encode_hpapbpbp(bundle.proof))
        head = BUNDLE_TAG + encoded_proof
        signature = bundle.signature
        # A zero R, a zero signer count and non-increasing signer ids
        # are all illegal.
        with self.assertRaises(ValueError):
            decode_hpapbpbpb(
                head
                + varint(0)
                + varint(signature.z)
                + u32(len(signature.signer_ids))
                + b"".join(varint(i) for i in signature.signer_ids)
            )
        with self.assertRaises(ValueError):
            decode_hpapbpbpb(
                head + varint(signature.R) + varint(signature.z) + u32(0)
            )
        with self.assertRaises(ValueError):
            decode_hpapbpbpb(
                head
                + varint(signature.R)
                + varint(signature.z)
                + u32(2)
                + varint(3)
                + varint(1)
            )

    def test_non_canonical_signature_integer_rejected(self):
        bundle = signed_hpapbpbpb(self.archive, (0, 2), self.key)
        wire = build_bundle_wire(bundle)
        sig_at = signature_offset(wire, bundle.signature)
        head = wire[:sig_at]
        with self.assertRaises(ValueError):
            decode_hpapbpbpb(
                head
                + u32(2)
                + b"\x00\x05"
                + wire[sig_at + len(varint(bundle.signature.R)):]
            )

    def test_mismatched_signature_still_decodes(self):
        # Structure is restored, never verified: a signature from another
        # key over the same statement decodes and round-trips, and verify
        # reports False.
        proof, _ = signed_proof(self.archive, (0, 2), self.key)
        message, _ = make_hpapbpbp(self.archive, (0, 2))
        mismatched = sign_message(make_other_key(), message, seed=95100)
        bundle = HPAPBPBPB(proof, mismatched)
        blob = encode_hpapbpbpb(bundle)
        restored = decode_hpapbpbpb(blob)
        self.assertEqual(restored, bundle)
        self.assertFalse(verify_hpapbpbpb(restored, self.key))

    def test_mismatched_packet_still_restored(self):
        # A tampered packet is structurally legal: decoding restores it
        # byte for byte, re-encoding matches, and only verify says False.
        bundle = signed_hpapbpbpb(self.archive, (0, 2), self.key)
        other_key = make_other_key()
        foreign = signed_hpapbpb(
            archive_of_size(3, other_key),
            (0, 2),
            other_key,
            seed=95150,
        )
        proof = bundle.proof
        mixed = HPAPBPBP(
            proof.indices,
            proof.total,
            (foreign, proof.packets[1]),
            proof.siblings,
        )
        mixed_bundle = HPAPBPBPB(mixed, bundle.signature)
        blob = encode_hpapbpbpb(mixed_bundle)
        restored = decode_hpapbpbpb(blob)
        self.assertEqual(restored, mixed_bundle)
        self.assertEqual(encode_hpapbpbpb(restored), blob)
        self.assertFalse(verify_hpapbpbpb(restored, self.key))


class VerifyHPAPBPBPBTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_packets(8, self.key)

    def test_signed_bundles_verify(self):
        cases = (
            (1, (0,)),
            (2, (0, 1)),
            (3, (0, 2)),
            (4, (1, 3)),
            (5, (0, 2, 4)),
            (6, (3, 5)),
            (7, (0, 6)),
            (8, (0, 2, 4, 6)),
            (8, tuple(range(8))),
        )
        for n, indices in cases:
            archive = prefix_archive(self.archive, n)
            bundle = signed_hpapbpbpb(archive, indices, self.key)
            self.assertTrue(
                verify_hpapbpbpb(bundle, self.key),
                msg=f"n={n} indices={indices}",
            )

    def test_matches_check_hpapbpbp_conclusion(self):
        for n, indices in ((3, (0, 2)), (5, (0, 2, 4)), (8, (1, 3, 5))):
            archive = prefix_archive(self.archive, n)
            bundle = signed_hpapbpbpb(archive, indices, self.key)
            self.assertEqual(
                verify_hpapbpbpb(bundle, self.key),
                check_hpapbpbp(
                    bundle.proof, bundle.signature, self.key
                ),
            )

    def test_tampered_packets_indices_and_siblings_return_false(self):
        indices = (0, 2, 4)
        bundle = signed_hpapbpbpb(self.archive, indices, self.key)
        proof = bundle.proof
        swapped = HPAPBPBP(
            proof.indices,
            proof.total,
            (proof.packets[1], proof.packets[0], proof.packets[2]),
            proof.siblings,
        )
        self.assertFalse(
            verify_hpapbpbpb(
                HPAPBPBPB(swapped, bundle.signature), self.key
            )
        )
        moved = HPAPBPBP(
            (0, 2, 5), proof.total, proof.packets, proof.siblings
        )
        self.assertFalse(
            verify_hpapbpbpb(
                HPAPBPBPB(moved, bundle.signature), self.key
            )
        )
        damaged = HPAPBPBP(
            proof.indices,
            proof.total,
            proof.packets,
            (b"\x00" * 32,) + proof.siblings[1:],
        )
        self.assertFalse(
            verify_hpapbpbpb(
                HPAPBPBPB(damaged, bundle.signature), self.key
            )
        )

    def test_missing_and_extra_siblings_return_false(self):
        indices = (0, 3)
        bundle = signed_hpapbpbpb(self.archive, indices, self.key)
        proof = bundle.proof
        self.assertGreater(len(proof.siblings), 1)
        short = HPAPBPBP(
            proof.indices, proof.total, proof.packets, proof.siblings[:-1]
        )
        self.assertFalse(
            verify_hpapbpbpb(
                HPAPBPBPB(short, bundle.signature), self.key
            )
        )
        long = HPAPBPBP(
            proof.indices,
            proof.total,
            proof.packets,
            proof.siblings + (b"x" * 32,),
        )
        self.assertFalse(
            verify_hpapbpbpb(
                HPAPBPBPB(long, bundle.signature), self.key
            )
        )

    def test_wrong_signature_and_wrong_key_return_false(self):
        indices = (0, 2)
        bundle = signed_hpapbpbpb(self.archive, indices, self.key)
        shortened = prefix_archive(self.archive, 4)
        other_message, _ = make_hpapbpbp(shortened, (0, 2))
        other_signature = sign_message(self.key, other_message, seed=95370)
        self.assertFalse(
            verify_hpapbpbpb(
                HPAPBPBPB(bundle.proof, other_signature), self.key
            )
        )
        self.assertFalse(
            verify_hpapbpbpb(bundle, make_other_key())
        )

    def test_unverifying_nested_packet_returns_false(self):
        indices = (0, 2)
        bundle = signed_hpapbpbpb(self.archive, indices, self.key)
        other_key = make_other_key()
        foreign = signed_hpapbpb(
            archive_of_size(3, other_key),
            (0, 2),
            other_key,
            seed=95380,
        )
        proof = bundle.proof
        mixed = HPAPBPBP(
            proof.indices,
            proof.total,
            (foreign, proof.packets[1]),
            proof.siblings,
        )
        self.assertFalse(
            verify_hpapbpbpb(
                HPAPBPBPB(mixed, bundle.signature), self.key
            )
        )

    def test_bad_packet_does_not_mask_illegal_signature_or_key(self):
        other_key = make_other_key()
        foreign = signed_hpapbpb(
            archive_of_size(3, other_key),
            (0, 2),
            other_key,
            seed=95390,
        )
        bundle = signed_hpapbpbpb(self.archive, (0, 2), self.key)
        proof = bundle.proof
        mixed = HPAPBPBP(
            proof.indices,
            proof.total,
            (foreign, proof.packets[1]),
            proof.siblings,
        )
        for bad_signature in (
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=-1, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=7, signer_ids=()),
            AggregateSignature(R=5, z=7, signer_ids=(3, 1)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad_signature)):
                verify_hpapbpbpb(
                    HPAPBPBPB(mixed, bad_signature), self.key
                )
        for bad_key in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad_key)):
                verify_hpapbpbpb(
                    HPAPBPBPB(
                        mixed,
                        AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
                    ),
                    bad_key,
                )

    def test_illegal_nested_packet_raises_value_error_not_false(self):
        # A structurally illegal disclosed packet is a ValueError from
        # the leaf recomputation, never a plain False.
        bundle = signed_hpapbpbpb(self.archive, (0, 2), self.key)
        illegal = HPAPBPB(
            HPAPBP(indices=(), total=0, bundles=(), siblings=()),
            DUMMY_OUTER_SIGNATURE,
        )
        proof = bundle.proof
        mixed = HPAPBPBP(
            proof.indices,
            proof.total,
            (illegal, proof.packets[1]),
            proof.siblings,
        )
        with self.assertRaises(ValueError):
            verify_hpapbpbpb(
                HPAPBPBPB(mixed, bundle.signature), self.key
            )

    def test_type_errors(self):
        bundle = signed_hpapbpbpb(self.archive, (0, 2), self.key)
        for bad in ("not-a-bundle", None, 42, b"x", bundle.proof):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_hpapbpbpb(bad, self.key)

    def test_structure_value_errors(self):
        bundle = signed_hpapbpbpb(self.archive, (0, 2), self.key)
        proof = bundle.proof
        for bad in (
            HPAPBPBP((0, 2), 0, proof.packets, proof.siblings),
            HPAPBPBP((), 8, (), ()),
            HPAPBPBP((2, 0), 8, proof.packets, proof.siblings),
            HPAPBPBP((1, 1), 8, proof.packets, proof.siblings),
            HPAPBPBP((0, 8), 8, proof.packets, proof.siblings),
            HPAPBPBP(
                (0, 2), 8, proof.packets, (b"short",)
            ),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                verify_hpapbpbpb(
                    HPAPBPBPB(bad, bundle.signature), self.key
                )

    def test_signature_shape_value_errors(self):
        bundle = signed_hpapbpbpb(self.archive, (0, 2), self.key)
        for bad in (
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=-2, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=-1, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=7, signer_ids=()),
            AggregateSignature(R=5, z=7, signer_ids=(0, 3)),
            AggregateSignature(R=5, z=7, signer_ids=(3, 1)),
            AggregateSignature(R=5, z=7, signer_ids=(1, 1)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                verify_hpapbpbpb(
                    HPAPBPBPB(bundle.proof, bad), self.key
                )


if __name__ == "__main__":
    unittest.main()
