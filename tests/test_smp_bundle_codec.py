"""Tests for the canonical SMPBundle transport encoding:
encode_smp_bundle / decode_smp_bundle / verify_smp_bundle."""

import dataclasses
import itertools
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    DeltaReportBundleArchive,
    DeltaReportBundleArchiveSeal,
    DeltaReportBundleArchiveSealChain,
    SMP,
    SMPBundle,
    check_smp,
    decode_smp_bundle,
    encode_delta_report_bundle_archive_seal,
    encode_smp_bundle,
    make_smp,
    verify_smp_bundle,
)

from test_audit_chain import make_key
from test_audit_extension_proof_bundle_codec import make_other_key
from test_smp import build_items, sign_root

BUNDLE_TAG = b"ts/smpb/v1"


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def build_wire(n, indices, encoded_seals, companions, signature) -> bytes:
    """Independently build the SMP bundle wire format straight from the spec.

    Seal bodies are passed already encoded so the builder can also emit
    deliberately malformed frames.
    """
    out = bytearray(BUNDLE_TAG)
    out += varint(n)
    out += u32(len(indices))
    for index in indices:
        out += varint(index)
    out += u32(len(encoded_seals))
    for encoded_seal in encoded_seals:
        out += frame(encoded_seal)
    out += u32(len(companions))
    for companion in companions:
        out += companion
    out += varint(signature.R)
    out += varint(signature.z)
    out += u32(len(signature.signer_ids))
    for signer_id in signature.signer_ids:
        out += varint(signer_id)
    return bytes(out)


def make_signed_bundle(key, items, n, indices, *, seed):
    message, proof = make_smp(
        DeltaReportBundleArchiveSealChain(items[:n], None), indices
    )
    signature = sign_root(key, message, seed=seed)
    return SMPBundle(proof, signature)


class BundleDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(SMPBundle)],
            ["proof", "signature"],
        )
        key = make_key()
        bundle = make_signed_bundle(key, build_items(key), 4, (0, 2), seed=100)
        proof, signature = bundle.proof, bundle.signature
        self.assertIs(bundle.proof, proof)
        self.assertIs(bundle.signature, signature)
        self.assertEqual(
            SMPBundle(proof=proof, signature=signature),
            bundle,
        )

    def test_frozen_value_equality_and_hash(self):
        key = make_key()
        bundle = make_signed_bundle(key, build_items(key), 4, (0, 2), seed=200)
        same = SMPBundle(bundle.proof, bundle.signature)
        self.assertEqual(bundle, same)
        self.assertEqual(hash(bundle), hash(same))
        self.assertNotEqual(
            bundle,
            SMPBundle(
                bundle.proof,
                AggregateSignature(
                    R=bundle.signature.R + 1,
                    z=bundle.signature.z,
                    signer_ids=bundle.signature.signer_ids,
                ),
            ),
        )
        with self.assertRaises(FrozenInstanceError):
            bundle.proof = bundle.proof

    def test_construction_does_not_validate(self):
        # A plain frozen value: non-proof and non-signature fields
        # construct; the codec and verifier reject them.
        SMPBundle("not-a-proof", "not-a-signature")
        SMPBundle(None, None)


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.items = build_items(self.key)

    def _bundle(self, n, indices, *, seed):
        return make_signed_bundle(self.key, self.items, n, indices, seed=seed)

    def test_round_trip_for_every_size_and_subset(self):
        counter = 0
        for n in range(1, 8):
            for width in range(1, n + 1):
                for indices in itertools.combinations(range(n), width):
                    counter += 1
                    bundle = self._bundle(n, indices, seed=2000 + counter)
                    wire = encode_smp_bundle(bundle)
                    decoded = decode_smp_bundle(wire)
                    self.assertEqual(
                        decoded, bundle, msg=f"n={n} indices={indices}"
                    )
                    self.assertEqual(encode_smp_bundle(decoded), wire)

    def test_encoding_matches_independent_builder(self):
        counter = 0
        for n in range(1, 8):
            for width in range(1, n + 1):
                for indices in itertools.combinations(range(n), width):
                    counter += 1
                    bundle = self._bundle(n, indices, seed=3000 + counter)
                    expected = build_wire(
                        bundle.proof.n,
                        bundle.proof.i,
                        [
                            encode_delta_report_bundle_archive_seal(seal)
                            for seal in bundle.proof.s
                        ],
                        bundle.proof.p,
                        bundle.signature,
                    )
                    self.assertEqual(
                        encode_smp_bundle(bundle),
                        expected,
                        msg=f"n={n} indices={indices}",
                    )

    def test_prefix_layout_is_tag_varint_n_and_index_frame(self):
        bundle = self._bundle(5, (0, 2, 4), seed=4000)
        wire = encode_smp_bundle(bundle)
        self.assertTrue(wire.startswith(BUNDLE_TAG))
        offset = len(BUNDLE_TAG)
        self.assertEqual(wire[offset:offset + len(varint(5))], varint(5))
        offset += len(varint(5))
        self.assertEqual(wire[offset:offset + 4], u32(3))
        offset += 4
        for index in (0, 2, 4):
            self.assertEqual(wire[offset:offset + len(varint(index))],
                             varint(index))
            offset += len(varint(index))
        # The seals follow, one U32-length frame each.
        self.assertEqual(wire[offset:offset + 4], u32(3))
        offset += 4
        for seal in bundle.proof.s:
            encoded = encode_delta_report_bundle_archive_seal(seal)
            self.assertEqual(wire[offset:offset + 4], u32(len(encoded)))
            offset += 4
            self.assertEqual(wire[offset:offset + len(encoded)], encoded)
            offset += len(encoded)

    def test_seals_are_existing_single_seal_transport_encodings(self):
        bundle = self._bundle(5, (1, 3), seed=4100)
        wire = encode_smp_bundle(bundle)
        decoded = decode_smp_bundle(wire)
        for original, restored in zip(bundle.proof.s, decoded.proof.s):
            self.assertEqual(restored, original)
            self.assertEqual(
                encode_delta_report_bundle_archive_seal(restored),
                encode_delta_report_bundle_archive_seal(original),
            )
            # The nested seal keeps its own distinct wire tag.
            self.assertTrue(
                encode_delta_report_bundle_archive_seal(restored)
                .startswith(b"ts/dra/w1")
            )

    def test_p_are_raw_32_byte_digests_in_proof_order(self):
        bundle = self._bundle(7, (3, 6), seed=4200)
        wire = encode_smp_bundle(bundle)
        decoded = decode_smp_bundle(wire)
        self.assertEqual(decoded.proof.p, bundle.proof.p)
        self.assertTrue(all(len(entry) == 32 for entry in decoded.proof.p))

    def test_suffix_is_the_audit_proof_bundle_signature_frame(self):
        bundle = self._bundle(5, (0, 2, 4), seed=4300)
        wire = encode_smp_bundle(bundle)
        prefix = (
            len(BUNDLE_TAG)
            + len(varint(bundle.proof.n))
            + 4
            + sum(len(varint(i)) for i in bundle.proof.i)
            + 4
            + sum(
                4 + len(encode_delta_report_bundle_archive_seal(seal))
                for seal in bundle.proof.s
            )
            + 4
            + 32 * len(bundle.proof.p)
        )
        signature = bundle.signature
        expected = bytearray()
        expected += varint(signature.R)
        expected += varint(signature.z)
        expected += u32(len(signature.signer_ids))
        for signer_id in signature.signer_ids:
            expected += varint(signer_id)
        self.assertEqual(wire[prefix:], bytes(expected))

    def test_zero_z_encodes_as_single_body_byte(self):
        bundle = self._bundle(3, (0,), seed=4400)
        bundle = SMPBundle(
            bundle.proof,
            AggregateSignature(
                R=bundle.signature.R,
                z=0,
                signer_ids=bundle.signature.signer_ids,
            ),
        )
        wire = encode_smp_bundle(bundle)
        # The frame ends on VARINT(R) || VARINT(0) || U32(k) ...; z = 0 is
        # the five bytes 00 00 00 01 00 and sits right before the id count.
        id_count_offset = len(wire) - 4 - sum(
            len(varint(i)) for i in bundle.signature.signer_ids
        )
        self.assertEqual(wire[id_count_offset - 5:id_count_offset],
                         b"\x00\x00\x00\x01\x00")

    def test_decoded_bundle_still_verifies(self):
        counter = 0
        for n in range(1, 8):
            for indices in itertools.combinations(range(n), 2):
                counter += 1
                bundle = self._bundle(n, indices, seed=5000 + counter)
                decoded = decode_smp_bundle(encode_smp_bundle(bundle))
                self.assertTrue(
                    verify_smp_bundle(decoded, self.key),
                    msg=f"n={n} indices={indices}",
                )

    def test_encoding_is_unique_and_stateless(self):
        bundle = self._bundle(5, (1, 3), seed=5100)
        self.assertEqual(
            encode_smp_bundle(bundle),
            encode_smp_bundle(bundle),
        )

    def test_full_disclosure_and_single_item_trees_round_trip(self):
        for n in range(1, 8):
            bundle = self._bundle(n, tuple(range(n)), seed=5200 + n)
            decoded = decode_smp_bundle(encode_smp_bundle(bundle))
            self.assertEqual(decoded, bundle)
            self.assertEqual(decoded.proof.p, ())


class StructureOnlyTest(unittest.TestCase):
    def test_decode_checks_neither_seals_nor_root_signature(self):
        # Structurally legal synthetic companions that never rebuilt a
        # root, and a signature from no real round, round-trip untouched.
        key = make_key()
        items = build_items(key)
        proof = SMP(
            i=(0, 2),
            n=4,
            s=(items[0], items[2]),
            p=(b"a" * 32, b"b" * 32),
        )
        signature = AggregateSignature(R=9, z=11, signer_ids=(2, 4))
        bundle = SMPBundle(proof, signature)
        decoded = decode_smp_bundle(encode_smp_bundle(bundle))
        self.assertEqual(decoded, bundle)

    def test_encoding_does_not_check_signature_against_root(self):
        # A bundle signed by one key but presented under another encodes
        # fine — structure alone is checked; verify reports it as False.
        key = make_key()
        bundle = make_signed_bundle(
            key, build_items(key), 4, (0, 2), seed=6000
        )
        self.assertTrue(encode_smp_bundle(bundle))
        self.assertFalse(verify_smp_bundle(bundle, make_other_key()))


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.items = build_items(self.key)
        self.bundle = make_signed_bundle(
            self.key, self.items, 4, (0, 2), seed=6100
        )

    def test_non_bundle_type_error(self):
        with self.assertRaises(TypeError):
            encode_smp_bundle((self.bundle.proof, self.bundle.signature))
        with self.assertRaises(TypeError):
            encode_smp_bundle(None)

    def test_non_proof_field_type_error(self):
        with self.assertRaises(TypeError):
            encode_smp_bundle(
                SMPBundle("not-a-proof", self.bundle.signature)
            )
        with self.assertRaises(TypeError):
            encode_smp_bundle(SMPBundle(None, self.bundle.signature))

    def test_non_signature_field_type_error(self):
        with self.assertRaises(TypeError):
            encode_smp_bundle(SMPBundle(self.bundle.proof, "no"))
        with self.assertRaises(TypeError):
            encode_smp_bundle(SMPBundle(self.bundle.proof, None))

    def test_proof_field_type_errors(self):
        good = self.bundle.proof
        cases = (
            SMP(list(good.i), good.n, good.s, good.p),
            SMP(good.i, True, good.s, good.p),
            SMP(good.i, good.n, list(good.s), good.p),
            SMP(good.i, good.n, good.s, list(good.p)),
            SMP((False,) + good.i[1:], good.n, good.s, good.p),
            SMP(good.i, good.n, ("not-a-seal",) * len(good.s), good.p),
            SMP(good.i, good.n, good.s, ("not-bytes",) * len(good.p)),
        )
        for bad_proof in cases:
            with self.assertRaises(TypeError, msg=repr(bad_proof)):
                encode_smp_bundle(SMPBundle(bad_proof, self.bundle.signature))

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
                encode_smp_bundle(SMPBundle(self.bundle.proof, bad))

    def test_bad_proof_structure_value_error(self):
        good = self.bundle.proof
        bad_signature = self.bundle.signature
        cases = (
            SMP((), good.n, (), ()),
            SMP(good.i, 0, good.s, good.p),
            SMP(good.i, 2 ** 64, good.s, good.p),
            SMP((1, 0), good.n, good.s[::-1], ()),
            SMP((0, 4), good.n, good.s, ()),
            SMP(good.i, good.n, good.s + (self.items[1],), good.p),
            SMP(good.i, good.n, good.s, ()),
            SMP(good.i, good.n, good.s, good.p + (b"\x09" * 32,)),
            SMP(good.i, good.n, good.s, (b"\x00" * 31,) + good.p[1:]),
        )
        for bad_proof in cases:
            with self.assertRaises(ValueError, msg=repr(bad_proof)):
                encode_smp_bundle(SMPBundle(bad_proof, bad_signature))

    def test_illegal_nested_seal_structure_value_error(self):
        bad_signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        bad_seal = DeltaReportBundleArchiveSeal(
            DeltaReportBundleArchive(()), bad_signature
        )
        good = self.bundle.proof
        bad_proof = SMP(good.i, good.n, (bad_seal, good.s[1]), good.p)
        with self.assertRaises(ValueError):
            encode_smp_bundle(SMPBundle(bad_proof, self.bundle.signature))

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
                encode_smp_bundle(SMPBundle(self.bundle.proof, bad))


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.items = build_items(self.key)
        self.bundle = make_signed_bundle(
            self.key, self.items, 5, (0, 2, 4), seed=6200
        )
        self.wire = encode_smp_bundle(self.bundle)

    def test_non_bytes_type_error(self):
        with self.assertRaises(TypeError):
            decode_smp_bundle("not bytes")
        with self.assertRaises(TypeError):
            decode_smp_bundle(bytearray(self.wire))

    def test_bad_tag(self):
        rest = self.wire[len(BUNDLE_TAG):]
        with self.assertRaises(ValueError):
            decode_smp_bundle(b"ts/smpb/v2" + rest)
        with self.assertRaises(ValueError):
            decode_smp_bundle(b"x" + self.wire[1:])

    def test_truncation(self):
        for cut in range(len(BUNDLE_TAG), len(self.wire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_smp_bundle(self.wire[:cut])

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_smp_bundle(self.wire + b"\x00")

    def test_n_zero_rejected(self):
        with self.assertRaises(ValueError):
            decode_smp_bundle(BUNDLE_TAG + varint(0))

    def test_n_at_2_to_the_64_rejected(self):
        # The n bound is checked before anything else is consumed.
        with self.assertRaises(ValueError):
            decode_smp_bundle(BUNDLE_TAG + varint(2 ** 64))

    def test_non_canonical_n_leading_zero(self):
        non_canonical_n = (2).to_bytes(4, "big") + b"\x00\x05"
        with self.assertRaises(ValueError):
            decode_smp_bundle(
                BUNDLE_TAG + non_canonical_n + self.wire[
                    len(BUNDLE_TAG) + len(varint(5)):
                ]
            )

    def test_zero_index_count_rejected(self):
        bad = (
            BUNDLE_TAG
            + varint(self.bundle.proof.n)
            + u32(0)
        )
        with self.assertRaises(ValueError):
            decode_smp_bundle(bad)

    def test_indices_not_strict_or_out_of_range_rejected(self):
        signature = AggregateSignature(R=9, z=7, signer_ids=(1,))
        encoded_seal = encode_delta_report_bundle_archive_seal(self.items[0])
        base = BUNDLE_TAG
        cases = (
            # duplicated indices
            (4, (1, 1), (encoded_seal, encoded_seal)),
            # out of order
            (4, (2, 0), (encoded_seal, encoded_seal)),
            # index equals n
            (3, (3,), (encoded_seal,)),
            # index above n
            (3, (4,), (encoded_seal,)),
        )
        for n, indices, seals in cases:
            # Companion validation is never reached: the index check fires
            # first, so the trailing companion/signature content can be
            # absent as long as parsing raises before consuming it.
            wire = build_wire(n, indices, seals, (), signature)
            with self.assertRaises(ValueError, msg=f"n={n} i={indices}"):
                decode_smp_bundle(wire)

    def test_seal_count_must_match_index_count(self):
        # Declare three indices but only two seal frames; the missing seal
        # would otherwise be read out of the companion bytes.
        good = self.bundle.proof
        encoded_seals = [
            encode_delta_report_bundle_archive_seal(seal) for seal in good.s
        ]
        wire = build_wire(
            good.n,
            good.i,
            encoded_seals[:2],
            good.p,
            self.bundle.signature,
        )
        with self.assertRaises(ValueError):
            decode_smp_bundle(wire)

    def test_zero_seal_frame_rejected(self):
        good = self.bundle.proof
        encoded_seals = [
            encode_delta_report_bundle_archive_seal(seal) for seal in good.s
        ]
        wire = build_wire(
            good.n,
            good.i,
            [encoded_seals[0], b"", encoded_seals[2]],
            good.p,
            self.bundle.signature,
        )
        with self.assertRaises(ValueError):
            decode_smp_bundle(wire)

    def test_junk_seal_frame_rejected(self):
        good = self.bundle.proof
        encoded_seals = [
            encode_delta_report_bundle_archive_seal(seal) for seal in good.s
        ]
        wire = build_wire(
            good.n,
            good.i,
            [encoded_seals[0], b"not-a-seal", encoded_seals[2]],
            good.p,
            self.bundle.signature,
        )
        with self.assertRaises(ValueError):
            decode_smp_bundle(wire)

    def test_companion_count_mismatch_rejected(self):
        good = self.bundle.proof
        encoded_seals = [
            encode_delta_report_bundle_archive_seal(seal) for seal in good.s
        ]
        required = len(good.p)
        # One fewer companion than n and the indices require, with a
        # complete signature frame afterwards.
        too_few = build_wire(
            good.n,
            good.i,
            encoded_seals,
            good.p[:required - 1],
            self.bundle.signature,
        )
        with self.assertRaises(ValueError):
            decode_smp_bundle(too_few)
        too_many = build_wire(
            good.n,
            good.i,
            encoded_seals,
            good.p + (b"\x09" * 32,),
            self.bundle.signature,
        )
        with self.assertRaises(ValueError):
            decode_smp_bundle(too_many)

    def test_truncated_companion_digest_rejected(self):
        good = self.bundle.proof
        encoded_seals = [
            encode_delta_report_bundle_archive_seal(seal) for seal in good.s
        ]
        # Declare the required companion count but cut the raw digest
        # stream 10 bytes short before the signature frame.
        head = (
            BUNDLE_TAG
            + varint(good.n)
            + u32(len(good.i))
            + b"".join(varint(i) for i in good.i)
            + u32(len(encoded_seals))
            + b"".join(frame(e) for e in encoded_seals)
            + u32(len(good.p))
            + b"".join(good.p[:-1])
            + good.p[-1][:-10]
        )
        with self.assertRaises(ValueError):
            decode_smp_bundle(head)

    def test_zero_R_rejected(self):
        good = self.bundle.proof
        encoded_seals = [
            encode_delta_report_bundle_archive_seal(seal) for seal in good.s
        ]
        bad_signature = AggregateSignature(
            R=0, z=7, signer_ids=self.bundle.signature.signer_ids
        )
        wire = build_wire(
            good.n, good.i, encoded_seals, good.p, bad_signature
        )
        with self.assertRaises(ValueError):
            decode_smp_bundle(wire)

    def test_non_canonical_R_leading_zero(self):
        good = self.bundle.proof
        encoded_seals = [
            encode_delta_report_bundle_archive_seal(seal) for seal in good.s
        ]
        signature = AggregateSignature(
            R=9, z=7, signer_ids=self.bundle.signature.signer_ids
        )
        wire = bytearray(
            build_wire(good.n, good.i, encoded_seals, good.p, signature)
        )
        # Locate the signature frame: it starts right after the companions.
        prefix = (
            len(BUNDLE_TAG)
            + len(varint(good.n))
            + 4
            + sum(len(varint(i)) for i in good.i)
            + 4
            + sum(4 + len(e) for e in encoded_seals)
            + 4
            + 32 * len(good.p)
        )
        canonical = varint(9)
        non_canonical = (2).to_bytes(4, "big") + b"\x00\x09"
        wire[prefix:prefix + len(canonical)] = non_canonical
        with self.assertRaises(ValueError):
            decode_smp_bundle(bytes(wire))

    def test_zero_signer_count_rejected(self):
        good = self.bundle.proof
        encoded_seals = [
            encode_delta_report_bundle_archive_seal(seal) for seal in good.s
        ]
        prefix = (
            BUNDLE_TAG
            + varint(good.n)
            + u32(len(good.i))
            + b"".join(varint(i) for i in good.i)
            + u32(len(encoded_seals))
            + b"".join(frame(e) for e in encoded_seals)
            + u32(len(good.p))
            + b"".join(good.p)
            + varint(self.bundle.signature.R)
            + varint(self.bundle.signature.z)
        )
        with self.assertRaises(ValueError):
            decode_smp_bundle(prefix + u32(0))

    def test_signer_count_too_large_then_truncated(self):
        good = self.bundle.proof
        encoded_seals = [
            encode_delta_report_bundle_archive_seal(seal) for seal in good.s
        ]
        signature = self.bundle.signature
        prefix = (
            BUNDLE_TAG
            + varint(good.n)
            + u32(len(good.i))
            + b"".join(varint(i) for i in good.i)
            + u32(len(encoded_seals))
            + b"".join(frame(e) for e in encoded_seals)
            + u32(len(good.p))
            + b"".join(good.p)
            + varint(signature.R)
            + varint(signature.z)
        )
        bad = prefix + u32(len(signature.signer_ids) + 1)
        for signer_id in signature.signer_ids:
            bad += varint(signer_id)
        with self.assertRaises(ValueError):
            decode_smp_bundle(bad)

    def test_non_positive_and_unsorted_signer_ids_rejected(self):
        good = self.bundle.proof
        encoded_seals = [
            encode_delta_report_bundle_archive_seal(seal) for seal in good.s
        ]
        head = (
            BUNDLE_TAG
            + varint(good.n)
            + u32(len(good.i))
            + b"".join(varint(i) for i in good.i)
            + u32(len(encoded_seals))
            + b"".join(frame(e) for e in encoded_seals)
            + u32(len(good.p))
            + b"".join(good.p)
            + varint(self.bundle.signature.R)
            + varint(self.bundle.signature.z)
        )
        cases = {
            "zero": (b"\x00", b"\x03"),
            "ff_then_small": (b"\xff", b"\x03"),
            "unsorted": (b"\x03", b"\x01"),
            "duplicate": (b"\x01", b"\x01"),
        }
        for label, bodies in cases.items():
            out = bytearray(head)
            out += u32(len(bodies))
            for body in bodies:
                out += (1).to_bytes(4, "big")
                out += body
            with self.assertRaises(ValueError, msg=label):
                decode_smp_bundle(bytes(out))


class VerifyBundleTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.other = make_other_key()
        self.items = build_items(self.key)

    def _bundle(self, n, indices, *, seed):
        return make_signed_bundle(self.key, self.items, n, indices, seed=seed)

    def test_honest_bundles_verify_for_every_size_and_subset(self):
        counter = 0
        for n in range(1, 8):
            for width in range(1, n + 1):
                for indices in itertools.combinations(range(n), width):
                    counter += 1
                    bundle = self._bundle(n, indices, seed=7000 + counter)
                    self.assertTrue(
                        verify_smp_bundle(bundle, self.key),
                        msg=f"n={n} indices={indices}",
                    )

    def test_result_equals_check_smp(self):
        counter = 0
        for n in range(1, 8):
            for indices in itertools.combinations(range(n), 3):
                counter += 1
                bundle = self._bundle(n, indices, seed=8000 + counter)
                self.assertEqual(
                    verify_smp_bundle(bundle, self.key),
                    check_smp(
                        bundle.proof, bundle.signature, self.key
                    ),
                    msg=f"n={n} indices={indices}",
                )

    def test_wrong_key_returns_false(self):
        bundle = self._bundle(5, (1, 3), seed=8100)
        self.assertFalse(verify_smp_bundle(bundle, self.other))

    def test_tampered_signature_returns_false(self):
        bundle = self._bundle(5, (1, 3), seed=8200)
        tampered = AggregateSignature(
            R=bundle.signature.R,
            z=bundle.signature.z,
            signer_ids=bundle.signature.signer_ids[:-1]
            + (bundle.signature.signer_ids[-1] ^ 0xFF,),
        )
        self.assertFalse(
            verify_smp_bundle(
                SMPBundle(bundle.proof, tampered), self.key
            )
        )

    def test_signature_for_another_n_returns_false(self):
        bundle = self._bundle(5, (0, 2), seed=8300)
        foreign = self._bundle(4, (0, 2), seed=8301)
        self.assertFalse(
            verify_smp_bundle(
                SMPBundle(bundle.proof, foreign.signature), self.key
            )
        )

    def test_tampered_companion_returns_false(self):
        bundle = self._bundle(5, (0, 2, 4), seed=8400)
        self.assertTrue(bundle.proof.p)
        tampered_p = (
            (bundle.proof.p[0][:-1] + bytes([bundle.proof.p[0][-1] ^ 0xFF]),)
            + bundle.proof.p[1:]
        )
        self.assertFalse(
            verify_smp_bundle(
                SMPBundle(
                    SMP(
                        bundle.proof.i,
                        bundle.proof.n,
                        bundle.proof.s,
                        tampered_p,
                    ),
                    bundle.signature,
                ),
                self.key,
            )
        )

    def test_decoded_bundle_verifies_identically(self):
        bundle = self._bundle(6, (0, 2, 4), seed=8500)
        decoded = decode_smp_bundle(encode_smp_bundle(bundle))
        self.assertEqual(
            verify_smp_bundle(decoded, self.key),
            verify_smp_bundle(bundle, self.key),
        )

    def test_non_bundle_type_error(self):
        for bad in (
            (self._bundle(2, (0,), seed=8600).proof, None),
            "bundle",
            None,
            self._bundle(2, (0,), seed=8601).proof,
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_smp_bundle(bad, self.key)

    def test_bad_nested_structure_value_error(self):
        good = self._bundle(4, (0, 2), seed=8700)
        bad_proof = SMP((), good.proof.n, (), ())
        bundle = SMPBundle(bad_proof, good.signature)
        with self.assertRaises(ValueError):
            verify_smp_bundle(bundle, self.key)


if __name__ == "__main__":
    unittest.main()
