"""Tests for the canonical SMPBundle transport encoding:
encode_smp_bundle / decode_smp_bundle / verify_smp_bundle."""

import dataclasses
import itertools
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
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


def read_varint(stream: bytes, offset: int) -> tuple[int, int]:
    length = int.from_bytes(stream[offset:offset + 4], "big")
    offset += 4
    return int.from_bytes(stream[offset:offset + length], "big"), offset + length


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def build_wire(bundle: SMPBundle) -> bytes:
    """Independently build the bundle wire format straight from the spec."""
    proof = bundle.proof
    signature = bundle.signature
    out = bytearray(BUNDLE_TAG)
    out += varint(proof.n)
    out += u32(len(proof.i))
    for index in proof.i:
        out += varint(index)
    out += u32(len(proof.s))
    for seal in proof.s:
        encoded = encode_delta_report_bundle_archive_seal(seal)
        out += frame(encoded)
    out += u32(len(proof.p))
    for sibling in proof.p:
        out += sibling
    out += varint(signature.R)
    out += varint(signature.z)
    out += u32(len(signature.signer_ids))
    for signer_id in signature.signer_ids:
        out += varint(signer_id)
    return bytes(out)


def signed_bundle(items, n, indices, key, *, seed=800):
    """Return a root-signed SMPBundle for the given chain and indices."""
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
        items = build_items(key)
        _message, proof = make_smp(
            DeltaReportBundleArchiveSealChain(items[:3], None), (0, 2)
        )
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        bundle = SMPBundle(proof, signature)
        self.assertIs(bundle.proof, proof)
        self.assertIs(bundle.signature, signature)
        self.assertEqual(
            SMPBundle(proof=proof, signature=signature), bundle
        )

    def test_frozen_value_equality_and_hash(self):
        key = make_key()
        items = build_items(key)
        _message, proof = make_smp(
            DeltaReportBundleArchiveSealChain(items[:3], None), (0, 2)
        )
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        bundle = SMPBundle(proof, signature)
        same = SMPBundle(proof, signature)
        self.assertEqual(bundle, same)
        self.assertEqual(hash(bundle), hash(same))
        self.assertNotEqual(
            bundle,
            SMPBundle(
                proof, AggregateSignature(R=6, z=7, signer_ids=(1, 3))
            ),
        )
        self.assertEqual({bundle, same}, {same})
        with self.assertRaises(FrozenInstanceError):
            bundle.proof = proof

    def test_construction_does_not_validate(self):
        # A plain frozen value: non-proof and non-signature fields
        # construct; the codec and verifier reject them.
        SMPBundle("not-a-proof", "not-a-signature")
        SMPBundle(None, None)


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.items = build_items(self.key)

    def test_round_trip_for_every_size_and_subset(self):
        for n in range(1, 8):
            for width in range(1, n + 1):
                for counter, indices in enumerate(
                    itertools.combinations(range(n), width)
                ):
                    bundle = signed_bundle(
                        self.items,
                        n,
                        indices,
                        self.key,
                        seed=2000 + n * 64 + width * 8 + counter,
                    )
                    wire = encode_smp_bundle(bundle)
                    decoded = decode_smp_bundle(wire)
                    self.assertEqual(
                        decoded, bundle, msg=f"n={n} indices={indices}"
                    )
                    self.assertEqual(
                        encode_smp_bundle(decoded), wire
                    )

    def test_encoding_matches_independent_builder(self):
        for n in range(1, 8):
            for width in range(1, n + 1):
                for counter, indices in enumerate(
                    itertools.combinations(range(n), width)
                ):
                    bundle = signed_bundle(
                        self.items,
                        n,
                        indices,
                        self.key,
                        seed=3000 + n * 64 + width * 8 + counter,
                    )
                    self.assertEqual(
                        encode_smp_bundle(bundle),
                        build_wire(bundle),
                        msg=f"n={n} indices={indices}",
                    )

    def test_prefix_layout_is_n_indices_seals_and_companions(self):
        bundle = signed_bundle(self.items, 7, (3, 6), self.key, seed=4000)
        wire = encode_smp_bundle(bundle)
        proof = bundle.proof
        offset = len(BUNDLE_TAG)
        self.assertTrue(wire.startswith(BUNDLE_TAG))

        n, offset = read_varint(wire, offset)
        self.assertEqual(n, proof.n)

        self.assertEqual(
            wire[offset:offset + 4], u32(len(proof.i))
        )
        offset += 4
        for index in proof.i:
            value, offset = read_varint(wire, offset)
            self.assertEqual(value, index)

        self.assertEqual(
            wire[offset:offset + 4], u32(len(proof.s))
        )
        offset += 4
        self.assertEqual(len(proof.s), len(proof.i))
        for seal in proof.s:
            length = int.from_bytes(wire[offset:offset + 4], "big")
            offset += 4
            encoded = wire[offset:offset + length]
            offset += length
            self.assertEqual(
                encoded, encode_delta_report_bundle_archive_seal(seal)
            )

        self.assertEqual(
            wire[offset:offset + 4], u32(len(proof.p))
        )
        offset += 4
        for sibling in proof.p:
            self.assertEqual(wire[offset:offset + 32], sibling)
            offset += 32

        signature = bundle.signature
        R, offset = read_varint(wire, offset)
        z, offset = read_varint(wire, offset)
        self.assertEqual(R, signature.R)
        self.assertEqual(z, signature.z)
        self.assertEqual(
            wire[offset:offset + 4], u32(len(signature.signer_ids))
        )
        offset += 4
        signer_ids = []
        for _ in signature.signer_ids:
            signer_id, offset = read_varint(wire, offset)
            signer_ids.append(signer_id)
        self.assertEqual(tuple(signer_ids), signature.signer_ids)
        self.assertEqual(offset, len(wire))

    def test_seal_count_equals_index_count(self):
        bundle = signed_bundle(self.items, 5, (0, 2, 4), self.key, seed=4100)
        wire = encode_smp_bundle(bundle)
        offset = len(BUNDLE_TAG)
        _n, offset = read_varint(wire, offset)
        index_count = int.from_bytes(wire[offset:offset + 4], "big")
        # Skip the index varints to reach the seal count.
        offset += 4
        for _ in range(index_count):
            _index, offset = read_varint(wire, offset)
        seal_count = int.from_bytes(wire[offset:offset + 4], "big")
        self.assertEqual(seal_count, index_count)

    def test_zero_z_encodes_as_single_body_byte(self):
        bundle = signed_bundle(self.items, 3, (0,), self.key, seed=4200)
        bundle = SMPBundle(
            bundle.proof,
            AggregateSignature(
                R=bundle.signature.R,
                z=0,
                signer_ids=bundle.signature.signer_ids,
            ),
        )
        wire = encode_smp_bundle(bundle)
        proof = bundle.proof
        # Walk to the signature frame the same way the decoder does.
        offset = len(BUNDLE_TAG)
        _n, offset = read_varint(wire, offset)
        offset += 4
        for _ in proof.i:
            offset += 5  # small single-byte indices: 4-byte length + body
        seal_count = int.from_bytes(wire[offset:offset + 4], "big")
        offset += 4
        for _ in range(seal_count):
            length = int.from_bytes(wire[offset:offset + 4], "big")
            offset += 4 + length
        sibling_count = int.from_bytes(wire[offset:offset + 4], "big")
        offset += 4 + 32 * sibling_count
        offset += len(varint(bundle.signature.R))
        # z = 0 -> VARINT 00 00 00 01 00.
        self.assertEqual(wire[offset:offset + 5], b"\x00\x00\x00\x01\x00")

    def test_decoded_bundle_still_verifies(self):
        for n in range(1, 8):
            for width in range(1, n + 1):
                for counter, indices in enumerate(
                    itertools.combinations(range(n), width)
                ):
                    bundle = signed_bundle(
                        self.items,
                        n,
                        indices,
                        self.key,
                        seed=5000 + n * 64 + width * 8 + counter,
                    )
                    decoded = decode_smp_bundle(
                        encode_smp_bundle(bundle)
                    )
                    self.assertTrue(
                        verify_smp_bundle(decoded, self.key),
                        msg=f"n={n} indices={indices}",
                    )

    def test_encoding_is_unique_and_stateless(self):
        bundle = signed_bundle(self.items, 5, (1, 3), self.key, seed=4300)
        self.assertEqual(
            encode_smp_bundle(bundle), encode_smp_bundle(bundle)
        )


class StructureOnlyTest(unittest.TestCase):
    def test_decode_does_not_verify_seals_or_signature(self):
        key = make_key()
        items = build_items(key)
        _message, proof = make_smp(
            DeltaReportBundleArchiveSealChain(items[:4], None), (0, 2)
        )
        # A real threshold signature over a *different* root statement:
        # R stays a subgroup element, so check_smp runs and returns False
        # instead of raising.
        other_message, _other_proof = make_smp(
            DeltaReportBundleArchiveSealChain(items[:5], None), (1, 3)
        )
        signature = sign_root(key, other_message, seed=4399)
        bundle = SMPBundle(proof, signature)
        decoded = decode_smp_bundle(encode_smp_bundle(bundle))
        self.assertEqual(decoded, bundle)
        self.assertFalse(verify_smp_bundle(decoded, key))

    def test_encoding_does_not_check_the_signature_against_the_root(self):
        # A bundle signed by one key but presented under another encodes
        # fine — structure alone is checked; verify reports it as False.
        key = make_key()
        bundle = signed_bundle(build_items(key), 3, (0,), key, seed=4400)
        self.assertTrue(encode_smp_bundle(bundle))
        self.assertFalse(
            verify_smp_bundle(bundle, make_other_key())
        )


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.items = build_items(self.key)
        self.bundle = signed_bundle(
            self.items, 5, (1, 3), self.key, seed=4500
        )

    def test_non_bundle_type_error(self):
        for bad in (
            (self.bundle.proof, self.bundle.signature),
            None,
            "bundle",
            self.bundle.proof,
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_smp_bundle(bad)

    def test_non_proof_field_type_error(self):
        with self.assertRaises(TypeError):
            encode_smp_bundle(
                SMPBundle("not-a-proof", self.bundle.signature)
            )
        with self.assertRaises(TypeError):
            encode_smp_bundle(
                SMPBundle(None, self.bundle.signature)
            )

    def test_non_signature_field_type_error(self):
        with self.assertRaises(TypeError):
            encode_smp_bundle(SMPBundle(self.bundle.proof, "no"))
        with self.assertRaises(TypeError):
            encode_smp_bundle(SMPBundle(self.bundle.proof, None))

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
                encode_smp_bundle(
                    SMPBundle(self.bundle.proof, bad)
                )

    def test_bad_nested_proof_structure_value_error(self):
        signature = self.bundle.signature
        good = self.bundle.proof
        bad_proofs = (
            SMP((), good.n, (), ()),
            SMP(good.i, 0, good.s, good.p),
            SMP(good.i, 2 ** 64, good.s, good.p),
            SMP((0, 0), good.n, good.s, good.p),
            SMP(good.i, good.n, good.s + (good.s[0],), good.p),
            SMP(good.i, good.n, good.s, ()),
        )
        for bad_proof in bad_proofs:
            with self.assertRaises(ValueError, msg=repr(bad_proof)):
                encode_smp_bundle(SMPBundle(bad_proof, signature))

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
                encode_smp_bundle(
                    SMPBundle(self.bundle.proof, bad)
                )


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.items = build_items(self.key)
        self.bundle = signed_bundle(
            self.items, 4, (0, 2), self.key, seed=4600
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

    def test_zero_n_rejected(self):
        bad = BUNDLE_TAG + varint(0) + self.wire[
            len(BUNDLE_TAG) + len(varint(self.bundle.proof.n)):
        ]
        with self.assertRaises(ValueError):
            decode_smp_bundle(bad)

    def test_over_large_n_rejected(self):
        bad = BUNDLE_TAG + varint(2 ** 64) + self.wire[
            len(BUNDLE_TAG) + len(varint(self.bundle.proof.n)):
        ]
        with self.assertRaises(ValueError):
            decode_smp_bundle(bad)

    def test_non_canonical_n_leading_zero(self):
        suffix_offset = len(BUNDLE_TAG) + len(varint(self.bundle.proof.n))
        non_canonical = (1).to_bytes(4, "big") + b"\x00\x04"
        bad = self.wire[:len(BUNDLE_TAG)] + non_canonical + self.wire[suffix_offset:]
        with self.assertRaises(ValueError):
            decode_smp_bundle(bad)

    def test_zero_index_count_rejected(self):
        offset = len(BUNDLE_TAG) + len(varint(self.bundle.proof.n))
        bad = self.wire[:offset] + u32(0) + self.wire[offset + 4:]
        with self.assertRaises(ValueError):
            decode_smp_bundle(bad)

    def test_index_count_above_n_rejected(self):
        n = self.bundle.proof.n
        offset = len(BUNDLE_TAG) + len(varint(n))
        bad = self.wire[:offset] + u32(n + 1) + self.wire[offset + 4:]
        with self.assertRaises(ValueError):
            decode_smp_bundle(bad)

    def test_indices_out_of_range_or_not_increasing_rejected(self):
        proof = self.bundle.proof
        prefix = (
            BUNDLE_TAG
            + varint(proof.n)
        )
        encoded_seals = [
            frame(encode_delta_report_bundle_archive_seal(seal))
            for seal in proof.s
        ]
        companions = u32(len(proof.p)) + b"".join(proof.p)
        signature = (
            varint(self.bundle.signature.R)
            + varint(self.bundle.signature.z)
            + u32(len(self.bundle.signature.signer_ids))
            + b"".join(
                varint(signer_id)
                for signer_id in self.bundle.signature.signer_ids
            )
        )
        for label, indices in (
            ("out_of_range", (0, proof.n)),
            ("unsorted", (2, 0)),
            ("duplicate", (0, 0)),
        ):
            out = bytearray(prefix)
            out += u32(len(indices))
            for index in indices:
                out += varint(index)
            out += u32(len(encoded_seals))
            for encoded in encoded_seals:
                out += encoded
            out += companions
            out += signature
            with self.assertRaises(ValueError, msg=label):
                decode_smp_bundle(bytes(out))

    def test_seal_count_mismatch_rejected(self):
        proof = self.bundle.proof
        offset = len(BUNDLE_TAG) + len(varint(proof.n)) + 4
        for _ in proof.i:
            _index, offset = read_varint(self.wire, offset)
        # Declare zero seals where the wire actually names two.
        bad = self.wire[:offset] + u32(0) + self.wire[offset + 4:]
        with self.assertRaises(ValueError):
            decode_smp_bundle(bad)

    def test_junk_seal_frame_rejected(self):
        proof = self.bundle.proof
        offset = len(BUNDLE_TAG) + len(varint(proof.n)) + 4
        for _ in proof.i:
            _index, offset = read_varint(self.wire, offset)
        offset += 4  # seal count
        suffix_offset = offset + 4  # inside the first seal frame
        bad = (
            self.wire[:offset]
            + frame(b"not-a-seal")
            + self.wire[suffix_offset:]
        )
        with self.assertRaises(ValueError):
            decode_smp_bundle(bad)

    def test_companion_count_mismatch_rejected(self):
        proof = self.bundle.proof
        encoded_seals = b"".join(
            frame(encode_delta_report_bundle_archive_seal(seal))
            for seal in proof.s
        )
        head = (
            BUNDLE_TAG
            + varint(proof.n)
            + u32(len(proof.i))
            + b"".join(varint(index) for index in proof.i)
            + u32(len(proof.s))
            + encoded_seals
        )
        signature_tail = self.wire[
            len(BUNDLE_TAG)
            + len(varint(proof.n))
            + 4
            + sum(len(varint(index)) for index in proof.i)
            + 4
            + len(encoded_seals)
            + 4
            + 32 * len(proof.p):
        ]
        # One too few companions: the signature tail then misparses.
        bad_few = (
            head + u32(len(proof.p) - 1) + b"".join(proof.p[:-1]) + signature_tail
        )
        with self.assertRaises(ValueError):
            decode_smp_bundle(bad_few)

    def test_zero_R_rejected(self):
        proof = self.bundle.proof
        encoded_seals = b"".join(
            frame(encode_delta_report_bundle_archive_seal(seal))
            for seal in proof.s
        )
        suffix_offset = (
            len(BUNDLE_TAG)
            + len(varint(proof.n))
            + 4
            + sum(len(varint(index)) for index in proof.i)
            + 4
            + len(encoded_seals)
            + 4
            + 32 * len(proof.p)
        )
        bad = (
            self.wire[:suffix_offset]
            + varint(0)
            + self.wire[suffix_offset + len(varint(self.bundle.signature.R)):]
        )
        with self.assertRaises(ValueError):
            decode_smp_bundle(bad)

    def test_non_canonical_R_leading_zero(self):
        bundle = SMPBundle(
            self.bundle.proof,
            AggregateSignature(R=9, z=7, signer_ids=(1, 3)),
        )
        wire = encode_smp_bundle(bundle)
        proof = bundle.proof
        encoded_seals = b"".join(
            frame(encode_delta_report_bundle_archive_seal(seal))
            for seal in proof.s
        )
        suffix_offset = (
            len(BUNDLE_TAG)
            + len(varint(proof.n))
            + 4
            + sum(len(varint(index)) for index in proof.i)
            + 4
            + len(encoded_seals)
            + 4
            + 32 * len(proof.p)
        )
        non_canonical_R = (1).to_bytes(4, "big") + b"\x00\x09"
        canonical_R = varint(9)
        bad = (
            wire[:suffix_offset]
            + non_canonical_R
            + wire[suffix_offset + len(canonical_R):]
        )
        with self.assertRaises(ValueError):
            decode_smp_bundle(bad)

    def test_zero_signer_count_rejected(self):
        proof = self.bundle.proof
        encoded_seals = b"".join(
            frame(encode_delta_report_bundle_archive_seal(seal))
            for seal in proof.s
        )
        tail_offset = (
            len(BUNDLE_TAG)
            + len(varint(proof.n))
            + 4
            + sum(len(varint(index)) for index in proof.i)
            + 4
            + len(encoded_seals)
            + 4
            + 32 * len(proof.p)
            + len(varint(self.bundle.signature.R))
            + len(varint(self.bundle.signature.z))
        )
        bad = self.wire[:tail_offset] + u32(0)
        with self.assertRaises(ValueError):
            decode_smp_bundle(bad)

    def test_non_positive_and_unsorted_signer_ids_rejected(self):
        proof = self.bundle.proof
        encoded_seals = b"".join(
            frame(encode_delta_report_bundle_archive_seal(seal))
            for seal in proof.s
        )
        prefix = (
            BUNDLE_TAG
            + varint(proof.n)
            + u32(len(proof.i))
            + b"".join(varint(index) for index in proof.i)
            + u32(len(proof.s))
            + encoded_seals
            + u32(len(proof.p))
            + b"".join(proof.p)
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
            out = bytearray(prefix)
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
        self.bundle = signed_bundle(
            self.items, 5, (1, 3), self.key, seed=7050
        )

    def test_honest_bundles_verify_for_every_size_and_subset(self):
        for n in range(1, 8):
            for width in range(1, n + 1):
                for counter, indices in enumerate(
                    itertools.combinations(range(n), width)
                ):
                    bundle = signed_bundle(
                        self.items,
                        n,
                        indices,
                        self.key,
                        seed=6000 + n * 64 + width * 8 + counter,
                    )
                    self.assertTrue(
                        verify_smp_bundle(bundle, self.key),
                        msg=f"n={n} indices={indices}",
                    )

    def test_result_equals_check_smp(self):
        for n in range(1, 8):
            for width in range(1, n + 1):
                for counter, indices in enumerate(
                    itertools.combinations(range(n), width)
                ):
                    bundle = signed_bundle(
                        self.items,
                        n,
                        indices,
                        self.key,
                        seed=7000 + n * 64 + width * 8 + counter,
                    )
                    self.assertEqual(
                        verify_smp_bundle(bundle, self.key),
                        check_smp(
                            bundle.proof, bundle.signature, self.key
                        ),
                        msg=f"n={n} indices={indices}",
                    )

    def test_wrong_key_returns_false(self):
        bundle = signed_bundle(self.items, 5, (0, 2), self.key, seed=7100)
        self.assertFalse(verify_smp_bundle(bundle, self.other))

    def test_tampered_signature_returns_false(self):
        bundle = signed_bundle(self.items, 5, (1, 3), self.key, seed=7200)
        tampered = SMPBundle(
            bundle.proof,
            AggregateSignature(
                R=bundle.signature.R,
                z=bundle.signature.z,
                signer_ids=bundle.signature.signer_ids[:-1]
                + (bundle.signature.signer_ids[-1] ^ 0xFF,),
            ),
        )
        self.assertFalse(verify_smp_bundle(tampered, self.key))

    def test_signature_over_another_statement_returns_false(self):
        # The root binds (n, seals); a signature for a same-n chain with
        # one resealed item does not validate the original proof.
        from test_delta_report_bundle_archive_seal_codec import make_seal

        bundle_a = signed_bundle(self.items, 5, (1, 3), self.key, seed=7300)
        foreign_items = (
            self.items[0],
            make_seal(self.items[1].archive, self.key, seed=7310),
        ) + self.items[2:5]
        message_foreign, proof_foreign = make_smp(
            DeltaReportBundleArchiveSealChain(foreign_items, None), (1, 3)
        )
        signature_foreign = sign_root(
            self.key, message_foreign, seed=7311
        )
        mixed = SMPBundle(bundle_a.proof, signature_foreign)
        self.assertFalse(verify_smp_bundle(mixed, self.key))
        self.assertTrue(
            verify_smp_bundle(
                SMPBundle(proof_foreign, signature_foreign), self.key
            )
        )

    def test_tampered_companion_returns_false(self):
        bundle = signed_bundle(self.items, 5, (0, 2, 4), self.key, seed=7400)
        self.assertTrue(len(bundle.proof.p) >= 1)
        tampered_p = (
            (bundle.proof.p[0][:-1] + bytes([bundle.proof.p[0][-1] ^ 0xFF]),)
            + bundle.proof.p[1:]
        )
        tampered = SMPBundle(
            SMP(
                bundle.proof.i,
                bundle.proof.n,
                bundle.proof.s,
                tampered_p,
            ),
            bundle.signature,
        )
        self.assertFalse(verify_smp_bundle(tampered, self.key))

    def test_decoded_bundle_verifies_identically(self):
        bundle = signed_bundle(self.items, 6, (0, 2, 4), self.key, seed=7500)
        decoded = decode_smp_bundle(encode_smp_bundle(bundle))
        self.assertEqual(
            verify_smp_bundle(decoded, self.key),
            verify_smp_bundle(bundle, self.key),
        )

    def test_non_bundle_type_error(self):
        proof, signature = self.bundle.proof, self.bundle.signature
        for bad in ((proof, signature), "bundle", None, proof):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_smp_bundle(bad, self.key)

    def test_bad_nested_structure_value_error(self):
        bad_proof = SMP((), 5, (), ())
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        with self.assertRaises(ValueError):
            verify_smp_bundle(SMPBundle(bad_proof, signature), self.key)


if __name__ == "__main__":
    unittest.main()
