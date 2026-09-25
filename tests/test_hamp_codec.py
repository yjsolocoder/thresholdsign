"""Tests for the canonical HAMPB transport encoding:
encode_hampb / decode_hampb (structure-only, canonical round-trip)."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    HAMP,
    HAMPB,
    SMPBundle,
    check_hamp,
    decode_hampb,
    encode_hampb,
    encode_smp_bundle,
    make_hamp,
)

from test_audit_chain import make_key, sign_message
from test_audit_extension_proof_bundle_codec import make_other_key
from test_hamp import (
    archive_of_size,
    bundles_of_size,
    signed_proof,
)

BUNDLE_TAG = b"ts/hampb/v1"

DUMMY_SIGNATURE = AggregateSignature(R=5, z=7, signer_ids=(1, 3))


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def build_wire(bundle: HAMPB) -> bytes:
    """Independently build the HAMPB wire format straight from the spec.

    Serializes the fields verbatim without structural validation, so
    proofs the encoder rejects can still be rendered into bytes to
    probe the decoder.
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
        out += frame(encode_smp_bundle(inner))
    out += u32(len(proof.siblings))
    for sibling in proof.siblings:
        out += sibling
    out += varint(signature.R)
    out += varint(signature.z)
    out += u32(len(signature.signer_ids))
    for signer_id in signature.signer_ids:
        out += varint(signer_id)
    return bytes(out)


def signed_hampb(archive, indices, key, *, seed=9000):
    """Return a signed HAMPB for the given indices."""
    proof, signature = signed_proof(archive, indices, key, seed=seed)
    return HAMPB(proof, signature)


def signature_offset(wire: bytes, signature: AggregateSignature) -> int:
    """Start of the trailing signature frame in an independently built wire."""
    tail = (
        len(varint(signature.R))
        + len(varint(signature.z))
        + 4
        + sum(len(varint(signer_id)) for signer_id in signature.signer_ids)
    )
    return len(wire) - tail


def good_sibling_count(total, indices):
    from thresholdsign import _required_history_multi_proof_siblings
    return range(_required_history_multi_proof_siblings(total, indices))


class HAMPBDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(HAMPB)],
            ["proof", "signature"],
        )
        key = make_key()
        archive = archive_of_size(3, key, seed_base=9010)
        _message, proof = make_hamp(archive, (1,))
        bundle = HAMPB(proof, DUMMY_SIGNATURE)
        self.assertIs(bundle.proof, proof)
        self.assertIs(bundle.signature, DUMMY_SIGNATURE)
        self.assertEqual(
            HAMPB(proof=proof, signature=DUMMY_SIGNATURE),
            bundle,
        )

    def test_fields_have_no_defaults(self):
        for field in dataclasses.fields(HAMPB):
            self.assertIs(field.default, dataclasses.MISSING, msg=field.name)
            self.assertIs(
                field.default_factory, dataclasses.MISSING, msg=field.name
            )

    def test_frozen_value_equality_and_hash(self):
        key = make_key()
        archive = archive_of_size(4, key, seed_base=9020)
        _message, proof = make_hamp(archive, (0, 2))
        bundle = HAMPB(proof, DUMMY_SIGNATURE)
        self.assertEqual(
            bundle, HAMPB(proof, DUMMY_SIGNATURE)
        )
        self.assertEqual(
            hash(bundle), hash(HAMPB(proof, DUMMY_SIGNATURE))
        )
        self.assertNotEqual(
            bundle,
            HAMPB(proof, AggregateSignature(R=6, z=7, signer_ids=(1, 3))),
        )
        self.assertEqual({bundle, HAMPB(proof, DUMMY_SIGNATURE)}, {bundle})
        with self.assertRaises(FrozenInstanceError):
            bundle.proof = proof

    def test_construction_does_not_validate(self):
        HAMPB("not-a-proof", "not-a-signature")
        HAMPB(None, None)


class EncodeHAMPBShapeTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()

    def test_matches_independent_spec_build(self):
        for n, indices in (
            (1, (0,)),
            (2, (0, 1)),
            (3, (2,)),
            (4, (0, 2)),
            (5, (1, 3)),
            (7, (0, 2, 4, 6)),
            (8, tuple(range(8))),
        ):
            archive = archive_of_size(n, self.key, seed_base=9100 + n)
            bundle = signed_hampb(archive, indices, self.key, seed=9110)
            with self.subTest(n=n, indices=indices):
                encoded = encode_hampb(bundle)
                self.assertTrue(encoded.startswith(BUNDLE_TAG))
                self.assertEqual(encoded, build_wire(bundle))

    def test_segment_order_and_nested_frames(self):
        archive = archive_of_size(4, self.key, seed_base=9120)
        bundle = signed_hampb(archive, (0, 2), self.key, seed=9121)
        encoded = encode_hampb(bundle)
        proof = bundle.proof
        offset = len(BUNDLE_TAG)
        # VARINT(total)
        length = int.from_bytes(encoded[offset:offset + 4], "big")
        self.assertEqual(
            int.from_bytes(
                encoded[offset + 4:offset + 4 + length], "big"
            ),
            4,
        )
        offset += 4 + length
        # index count and indices
        self.assertEqual(
            int.from_bytes(encoded[offset:offset + 4], "big"), 2
        )
        offset += 4
        for index in (0, 2):
            length = int.from_bytes(encoded[offset:offset + 4], "big")
            self.assertEqual(
                int.from_bytes(
                    encoded[offset + 4:offset + 4 + length], "big"
                ),
                index,
            )
            offset += 4 + length
        # bundle count, then existing canonical SMP bundle frames
        self.assertEqual(
            int.from_bytes(encoded[offset:offset + 4], "big"), 2
        )
        offset += 4
        for inner in proof.bundles:
            expected = encode_smp_bundle(inner)
            frame_length = int.from_bytes(
                encoded[offset:offset + 4], "big"
            )
            self.assertEqual(frame_length, len(expected))
            offset += 4
            self.assertEqual(
                encoded[offset:offset + frame_length], expected
            )
            self.assertTrue(expected.startswith(b"ts/smpb/v1"))
            offset += frame_length
        # siblings
        self.assertEqual(
            int.from_bytes(encoded[offset:offset + 4], "big"),
            len(proof.siblings),
        )
        offset += 4
        offset += 32 * len(proof.siblings)
        # remaining bytes are exactly the signature frame
        self.assertEqual(offset, signature_offset(encoded, bundle.signature))
        self.assertEqual(
            encoded[offset:],
            varint(bundle.signature.R)
            + varint(bundle.signature.z)
            + u32(len(bundle.signature.signer_ids))
            + b"".join(varint(i) for i in bundle.signature.signer_ids),
        )

    def test_output_is_unique_and_stateless(self):
        archive = archive_of_size(4, self.key, seed_base=9130)
        bundle = signed_hampb(archive, (0, 2), self.key, seed=9131)
        self.assertEqual(encode_hampb(bundle), encode_hampb(bundle))

    def test_zero_signature_z_encodes_single_00(self):
        archive = archive_of_size(2, self.key, seed_base=9140)
        message, proof = make_hamp(archive, (0,))
        signature = AggregateSignature(R=9, z=0, signer_ids=(1, 3))
        encoded = encode_hampb(HAMPB(proof, signature))
        self.assertEqual(encoded, build_wire(HAMPB(proof, signature)))


class EncodeHAMPBErrorTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(4, self.key, seed_base=9200)
        _message, self.proof = make_hamp(self.archive, (0, 2))

    def test_non_bundle_type_error(self):
        for bad in (
            None, 42, "x", b"x", object(),
            (self.proof, DUMMY_SIGNATURE),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_hampb(bad)

    def test_non_proof_type_error(self):
        for bad in (None, 42, "x", b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_hampb(HAMPB(bad, DUMMY_SIGNATURE))

    def test_bad_proof_field_types_type_error(self):
        good = self.proof
        cases = (
            dataclasses.replace(good, indices=[0, 2]),
            dataclasses.replace(good, total=4.0),
            dataclasses.replace(good, total=True),
            dataclasses.replace(good, bundles=list(good.bundles)),
            dataclasses.replace(
                good, bundles=("x", good.bundles[1])
            ),
            dataclasses.replace(good, siblings=list(good.siblings)),
        )
        for bad in cases:
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_hampb(HAMPB(bad, DUMMY_SIGNATURE))

    def test_bad_proof_shapes_value_error(self):
        good = self.proof
        cases = (
            dataclasses.replace(good, total=0),
            dataclasses.replace(good, total=2 ** 64),
            dataclasses.replace(good, indices=()),
            dataclasses.replace(good, indices=(4,)),
            dataclasses.replace(good, indices=(2, 0)),
            dataclasses.replace(good, indices=(2, 2)),
            dataclasses.replace(
                good,
                siblings=(b"x" * 31,) + good.siblings[1:],
            ),
        )
        for bad in cases:
            with self.assertRaises(ValueError, msg=repr(bad)):
                encode_hampb(HAMPB(bad, DUMMY_SIGNATURE))

    def test_bundle_count_mismatch_value_error(self):
        good = self.proof
        too_few = dataclasses.replace(good, bundles=good.bundles[:1])
        with self.assertRaises(ValueError):
            encode_hampb(HAMPB(too_few, DUMMY_SIGNATURE))
        too_many = dataclasses.replace(
            good, bundles=good.bundles + (self.archive.items[1],)
        )
        with self.assertRaises(ValueError):
            encode_hampb(HAMPB(too_many, DUMMY_SIGNATURE))

    def test_sibling_count_mismatch_value_error(self):
        good = self.proof
        missing = dataclasses.replace(good, siblings=good.siblings[:1])
        with self.assertRaises(ValueError):
            encode_hampb(HAMPB(missing, DUMMY_SIGNATURE))
        extra = dataclasses.replace(
            good, siblings=good.siblings + (b"z" * 32,)
        )
        with self.assertRaises(ValueError):
            encode_hampb(HAMPB(extra, DUMMY_SIGNATURE))

    def test_illegal_nested_bundle_value_error(self):
        # A bundle whose own encoding must fail: an SMPBundle with an
        # illegal inner proof structure.
        from thresholdsign import SMP
        illegal_inner = SMPBundle(
            SMP(i=(), n=0, s=(), p=()), DUMMY_SIGNATURE
        )
        bad_proof = HAMP(
            (0,),
            4,
            (illegal_inner,),
            tuple(b"q" * 32 for _ in good_sibling_count(4, (0,))),
        )
        with self.assertRaises(ValueError):
            encode_hampb(HAMPB(bad_proof, DUMMY_SIGNATURE))

    def test_illegal_signature_frame_value_error(self):
        good = self.proof
        for bad in (
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=-1, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=7, signer_ids=()),
            AggregateSignature(R=5, z=7, signer_ids=(3, 1)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                encode_hampb(HAMPB(good, bad))

    def test_bad_signature_field_types_type_error(self):
        good = self.proof
        for bad in ("x", None, 5, 5.0, True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_hampb(HAMPB(good, bad))


class DecodeHAMPBRoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()

    def test_round_trip_for_many_shapes(self):
        for n in range(1, 9):
            archive = archive_of_size(n, self.key, seed_base=9300 + n)
            index_sets = [(0,), (n - 1,), tuple(range(n))]
            if n >= 3:
                index_sets.append((0, n - 1))
            for indices in dict.fromkeys(index_sets):
                bundle = signed_hampb(
                    archive, indices, self.key, seed=9400
                )
                with self.subTest(n=n, indices=indices):
                    encoded = encode_hampb(bundle)
                    restored = decode_hampb(encoded)
                    self.assertEqual(restored, bundle)
                    self.assertEqual(encode_hampb(restored), encoded)

    def test_non_bytes_type_error(self):
        for bad in (None, 42, "x", bytearray(b"x"), object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                decode_hampb(bad)

    def test_bad_tag_value_error(self):
        archive = archive_of_size(2, self.key, seed_base=9410)
        encoded = bytearray(encode_hampb(signed_hampb(
            archive, (0,), self.key, seed=9411
        )))
        encoded[0] ^= 0x01
        with self.assertRaises(ValueError):
            decode_hampb(bytes(encoded))

    def test_truncation_value_error(self):
        archive = archive_of_size(4, self.key, seed_base=9420)
        encoded = encode_hampb(signed_hampb(
            archive, (0, 2), self.key, seed=9421
        ))
        # Every truncation point is rejected.
        for cut in range(len(BUNDLE_TAG), len(encoded)):
            with self.assertRaises(ValueError, msg=cut):
                decode_hampb(encoded[:cut])

    def test_trailing_bytes_value_error(self):
        archive = archive_of_size(3, self.key, seed_base=9430)
        encoded = encode_hampb(signed_hampb(
            archive, (0, 2), self.key, seed=9431
        ))
        with self.assertRaises(ValueError):
            decode_hampb(encoded + b"\x00")
        with self.assertRaises(ValueError):
            decode_hampb(encoded + b"tail")

    def test_zero_or_oversized_index_count_value_error(self):
        archive = archive_of_size(3, self.key, seed_base=9440)
        bundle = signed_hampb(archive, (0,), self.key, seed=9441)
        wire = bytearray(build_wire(bundle))
        # The index count sits right after the tag and the total varint.
        total_body = (3).to_bytes(1, "big")
        count_at = len(BUNDLE_TAG) + 4 + len(total_body)
        wire[count_at:count_at + 4] = u32(0)
        with self.assertRaises(ValueError):
            decode_hampb(bytes(wire))
        wire[count_at:count_at + 4] = u32(2)
        # Declares two indices but only one varint follows: truncated.
        with self.assertRaises(ValueError):
            decode_hampb(bytes(wire))

    def test_bundle_count_mismatch_value_error(self):
        archive = archive_of_size(3, self.key, seed_base=9450)
        bundle = signed_hampb(archive, (0, 2), self.key, seed=9451)
        wire = bytearray(build_wire(bundle))
        # Find the bundle count: tag + total varint + index count + 2
        # index varints (each 5 bytes for 0,2).
        at = len(BUNDLE_TAG) + 4 + 1 + 4 + 5 + 5
        self.assertEqual(int.from_bytes(wire[at:at + 4], "big"), 2)
        wire[at:at + 4] = u32(1)
        with self.assertRaises(ValueError):
            decode_hampb(bytes(wire))
        wire[at:at + 4] = u32(3)
        with self.assertRaises(ValueError):
            decode_hampb(bytes(wire))

    def test_zero_length_nested_frame_value_error(self):
        archive = archive_of_size(3, self.key, seed_base=9460)
        bundle = signed_hampb(archive, (0, 2), self.key, seed=9461)
        wire = bytearray(build_wire(bundle))
        at = len(BUNDLE_TAG) + 4 + 1 + 4 + 5 + 5 + 4
        wire[at:at + 4] = u32(0)
        with self.assertRaises(ValueError):
            decode_hampb(bytes(wire))

    def test_illegal_nested_frame_value_error(self):
        archive = archive_of_size(3, self.key, seed_base=9470)
        bundle = signed_hampb(archive, (0, 2), self.key, seed=9471)
        wire = bytearray(build_wire(bundle))
        at = len(BUNDLE_TAG) + 4 + 1 + 4 + 5 + 5 + 4
        length = int.from_bytes(wire[at:at + 4], "big")
        # Corrupt the nested SMP bundle's tag.
        wire[at + 4] ^= 0x01
        with self.assertRaises(ValueError):
            decode_hampb(bytes(wire))
        # A declared frame longer than the remainder is truncation.
        wire[at:at + 4] = u32(length + 1)
        with self.assertRaises(ValueError):
            decode_hampb(bytes(wire))

    def test_non_canonical_varint_value_error(self):
        archive = archive_of_size(3, self.key, seed_base=9480)
        bundle = signed_hampb(archive, (0, 2), self.key, seed=9481)
        wire = bytearray(build_wire(bundle))
        # total sits immediately after the tag as a one-byte varint;
        # rewrite it as a leading-zero two-byte body.
        at = len(BUNDLE_TAG)
        wire[at:at + 5] = b"\x00\x00\x00\x02\x00\x03"
        with self.assertRaises(ValueError):
            decode_hampb(bytes(wire))

    def test_sibling_count_mismatch_value_error(self):
        archive = archive_of_size(4, self.key, seed_base=9490)
        bundle = signed_hampb(archive, (0, 2), self.key, seed=9491)
        wire = bytearray(build_wire(bundle))
        # Locate the sibling count by parsing forward with the same
        # segment layout build_wire uses.
        offset = len(BUNDLE_TAG) + 4 + 1  # tag + total varint(4)
        index_count = int.from_bytes(wire[offset:offset + 4], "big")
        offset += 4 + 5 * index_count
        bundle_count = int.from_bytes(wire[offset:offset + 4], "big")
        offset += 4
        for _ in range(bundle_count):
            length = int.from_bytes(wire[offset:offset + 4], "big")
            offset += 4 + length
        sibling_at = offset
        actual = int.from_bytes(wire[sibling_at:sibling_at + 4], "big")
        wire[sibling_at:sibling_at + 4] = u32(actual + 1)
        with self.assertRaises(ValueError):
            decode_hampb(bytes(wire))
        # Declared count of zero when siblings are required.
        wire[sibling_at:sibling_at + 4] = u32(0)
        with self.assertRaises(ValueError):
            decode_hampb(bytes(wire))

    def test_sibling_wrong_width_value_error(self):
        # Siblings are fixed 32-byte raw entries: a count that matches
        # the required one but truncated bodies is rejected.
        archive = archive_of_size(4, self.key, seed_base=9500)
        bundle = signed_hampb(archive, (0, 2), self.key, seed=9501)
        wire = bytes(build_wire(bundle))
        # Drop one byte inside the sibling region (before the signature
        # frame): either sibling parsing or canonical re-encoding fails.
        offset = signature_offset(wire, bundle.signature)
        damaged = wire[:offset - 1] + wire[offset:]
        with self.assertRaises(ValueError):
            decode_hampb(damaged)

    def test_zero_R_value_error(self):
        archive = archive_of_size(2, self.key, seed_base=9510)
        good = signed_hampb(archive, (0,), self.key, seed=9511)
        bad = HAMPB(
            good.proof,
            AggregateSignature(
                R=0, z=good.signature.z,
                signer_ids=good.signature.signer_ids,
            ),
        )
        wire = build_wire(bad)
        with self.assertRaises(ValueError):
            decode_hampb(wire)

    def test_empty_or_non_increasing_signers_value_error(self):
        archive = archive_of_size(2, self.key, seed_base=9520)
        good = signed_hampb(archive, (0,), self.key, seed=9521)
        for ids in ((), (2, 1), (1, 1), (0, 1)):
            bad = HAMPB(
                good.proof,
                AggregateSignature(
                    R=good.signature.R, z=good.signature.z, signer_ids=ids
                ),
            )
            with self.assertRaises(ValueError, msg=repr(ids)):
                decode_hampb(build_wire(bad))

    def test_non_canonical_signature_integer_value_error(self):
        archive = archive_of_size(2, self.key, seed_base=9530)
        _message, proof = make_hamp(archive, (0,))
        # Structure-only decoding checks no signature; a small R keeps
        # its canonical body to one byte, easy to de-canonicalize.
        good = HAMPB(
            proof, AggregateSignature(R=7, z=5, signer_ids=(1, 3))
        )
        wire = bytearray(build_wire(good))
        offset = signature_offset(bytes(wire), good.signature)
        # Replace the canonical one-byte R (07) with a leading-zero
        # two-byte body (00 07).
        wire[offset:offset + 5] = b"\x00\x00\x00\x02\x00\x07"
        with self.assertRaises(ValueError):
            decode_hampb(bytes(wire))


class DecodeHAMPBStructureOnlyTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.other = make_other_key()

    def test_mismatched_but_structural_bundle_still_round_trips(self):
        # A structurally legal bundle whose proof bundles do not
        # verify (inner root signatures under another key) and whose
        # outer root signature does not sign the root must still
        # decode; check_hamp returns False afterwards.
        archive = archive_of_size(2, self.key, seed_base=9600)
        foreign_bundles = bundles_of_size(2, self.other, seed_base=9601)
        message, real_proof = make_hamp(archive, (0,))
        import dataclasses
        proof = dataclasses.replace(
            real_proof, bundles=(foreign_bundles[0],)
        )
        # Root signature over an unrelated message.
        other_archive = archive_of_size(3, self.key, seed_base=9602)
        other_message, _other = make_hamp(other_archive, (0,))
        signature = sign_message(
            self.key, other_message, seed=9603
        )
        bundle = HAMPB(proof, signature)
        encoded = encode_hampb(bundle)
        restored = decode_hampb(encoded)
        self.assertEqual(restored, bundle)
        self.assertEqual(encode_hampb(restored), encoded)
        self.assertFalse(check_hamp(restored.proof, signature, self.key))

    def test_decoding_does_not_verify(self):
        # A validly shaped bundle presented under another key decodes
        # without any key argument at all.
        archive = archive_of_size(3, self.other, seed_base=9610)
        bundle = signed_hampb(archive, (0, 2), self.other, seed=9611)
        restored = decode_hampb(encode_hampb(bundle))
        self.assertEqual(restored, bundle)


if __name__ == "__main__":
    unittest.main()
