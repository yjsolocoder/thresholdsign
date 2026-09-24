"""Tests for the self-contained seal-history extension bundle transport:
encode_history_extension_bundle / decode_history_extension_bundle /
verify_history_extension_bundle."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    SealHistoryExtension,
    SealHistoryExtensionBundle,
    check_history_extension,
    decode_history_extension_bundle,
    encode_history_extension,
    encode_history_extension_bundle,
    encode_seal,
    make_history_extension,
    verify_history_extension_bundle,
)

from test_nonce_reuse import GROUP_PRIME, make_key
from test_nonce_leak_codec import make_other_key
from test_seal_history import sign_message
from test_seal_history_extension import history_of_size, seal_extension

BUNDLE_TAG = b"ts/sheb/v1"
EXTENSION_TAG = b"thresholdsign/seal-history-extension/v1"


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def signature_frame(signature) -> bytes:
    out = bytearray()
    out += varint(signature.R)
    out += varint(signature.z)
    out += u32(len(signature.signer_ids))
    for signer_id in signature.signer_ids:
        out += varint(signer_id)
    return bytes(out)


def build_wire(bundle: SealHistoryExtensionBundle) -> bytes:
    """Independently build the bundle wire format straight from the spec."""
    out = bytearray(BUNDLE_TAG)
    out += frame(encode_history_extension(bundle.extension))
    out += signature_frame(bundle.old_sig)
    out += signature_frame(bundle.new_sig)
    return bytes(out)


def signed_bundle(key, history, old_total, *, seed=800):
    """Return a signed SealHistoryExtensionBundle for the given split."""
    proof, old_sig, new_sig = seal_extension(
        key, history, old_total, seed=seed
    )
    return SealHistoryExtensionBundle(proof, old_sig, new_sig)


class BundleDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [
                field.name
                for field in dataclasses.fields(SealHistoryExtensionBundle)
            ],
            ["extension", "old_sig", "new_sig"],
        )
        extension = SealHistoryExtension(1, (b"a" * 32, b"b" * 32))
        old_sig = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        new_sig = AggregateSignature(R=9, z=11, signer_ids=(2, 4))
        bundle = SealHistoryExtensionBundle(extension, old_sig, new_sig)
        self.assertIs(bundle.extension, extension)
        self.assertIs(bundle.old_sig, old_sig)
        self.assertIs(bundle.new_sig, new_sig)
        self.assertEqual(
            SealHistoryExtensionBundle(
                extension=extension, old_sig=old_sig, new_sig=new_sig
            ),
            bundle,
        )

    def test_frozen_value_equality_and_hash(self):
        extension = SealHistoryExtension(1, (b"a" * 32, b"b" * 32))
        old_sig = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        new_sig = AggregateSignature(R=9, z=11, signer_ids=(2, 4))
        bundle = SealHistoryExtensionBundle(extension, old_sig, new_sig)
        same = SealHistoryExtensionBundle(extension, old_sig, new_sig)
        self.assertEqual(bundle, same)
        self.assertEqual(hash(bundle), hash(same))
        self.assertNotEqual(
            bundle,
            SealHistoryExtensionBundle(
                SealHistoryExtension(2, (b"a" * 32, b"b" * 32)),
                old_sig,
                new_sig,
            ),
        )
        self.assertNotEqual(
            bundle,
            SealHistoryExtensionBundle(extension, new_sig, old_sig),
        )
        with self.assertRaises(FrozenInstanceError):
            bundle.extension = extension

    def test_no_field_defaults(self):
        for field in dataclasses.fields(SealHistoryExtensionBundle):
            self.assertIs(field.default, dataclasses.MISSING)
            self.assertIs(field.default_factory, dataclasses.MISSING)

    def test_construction_does_not_validate(self):
        # A plain frozen value: non-extension and non-signature fields
        # construct; the codec and verifier reject them.
        SealHistoryExtensionBundle("not-a-proof", "not-old", "not-new")
        SealHistoryExtensionBundle(None, None, None)


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()

    def test_round_trip_for_every_size_and_split(self):
        seed = 2000
        for n in range(2, 10):
            history = history_of_size(self.key, n)
            for old_total in range(1, n):
                bundle = signed_bundle(
                    self.key, history, old_total, seed=seed
                )
                seed += 10
                wire = encode_history_extension_bundle(bundle)
                decoded = decode_history_extension_bundle(wire)
                self.assertEqual(
                    decoded, bundle, msg=f"n={n} old={old_total}"
                )
                self.assertEqual(
                    encode_history_extension_bundle(decoded), wire
                )

    def test_encoding_matches_independent_builder(self):
        seed = 3000
        for n in range(2, 10):
            history = history_of_size(self.key, n)
            for old_total in range(1, n):
                bundle = signed_bundle(
                    self.key, history, old_total, seed=seed
                )
                seed += 10
                self.assertEqual(
                    encode_history_extension_bundle(bundle),
                    build_wire(bundle),
                    msg=f"n={n} old={old_total}",
                )

    def test_prefix_is_tag_length_and_full_extension_encoding(self):
        history = history_of_size(self.key, 6)
        bundle = signed_bundle(self.key, history, 4, seed=4000)
        wire = encode_history_extension_bundle(bundle)
        self.assertTrue(wire.startswith(BUNDLE_TAG))
        offset = len(BUNDLE_TAG)
        extension_bytes = encode_history_extension(bundle.extension)
        self.assertEqual(wire[offset:offset + 4], u32(len(extension_bytes)))
        offset += 4
        self.assertEqual(
            wire[offset:offset + len(extension_bytes)], extension_bytes
        )
        # The nested extension keeps its own distinct wire tag.
        self.assertTrue(extension_bytes.startswith(EXTENSION_TAG))

    def test_suffix_is_old_then_new_signature_frame(self):
        history = history_of_size(self.key, 6)
        bundle = signed_bundle(self.key, history, 4, seed=4100)
        wire = encode_history_extension_bundle(bundle)
        extension_bytes = encode_history_extension(bundle.extension)
        suffix = wire[len(BUNDLE_TAG) + 4 + len(extension_bytes):]
        expected = signature_frame(bundle.old_sig)
        expected += signature_frame(bundle.new_sig)
        self.assertEqual(suffix, expected)

    def test_zero_z_encodes_as_single_body_byte(self):
        history = history_of_size(self.key, 6)
        bundle = signed_bundle(self.key, history, 3, seed=4200)
        bundle = SealHistoryExtensionBundle(
            bundle.extension,
            AggregateSignature(
                R=bundle.old_sig.R,
                z=0,
                signer_ids=bundle.old_sig.signer_ids,
            ),
            bundle.new_sig,
        )
        wire = encode_history_extension_bundle(bundle)
        extension_bytes = encode_history_extension(bundle.extension)
        offset = len(BUNDLE_TAG) + 4 + len(extension_bytes)
        # R varint precedes z; z = 0 -> VARINT 00 00 00 01 00.
        offset += len(varint(bundle.old_sig.R))
        self.assertEqual(wire[offset:offset + 5], b"\x00\x00\x00\x01\x00")

    def test_decoded_bundle_still_verifies(self):
        seed = 5000
        for n in range(2, 9):
            history = history_of_size(self.key, n)
            for old_total in range(1, n):
                bundle = signed_bundle(
                    self.key, history, old_total, seed=seed
                )
                seed += 10
                decoded = decode_history_extension_bundle(
                    encode_history_extension_bundle(bundle)
                )
                self.assertTrue(
                    verify_history_extension_bundle(decoded, self.key),
                    msg=f"n={n} old={old_total}",
                )

    def test_encoding_is_unique_and_stateless(self):
        history = history_of_size(self.key, 6)
        bundle = signed_bundle(self.key, history, 5, seed=4300)
        self.assertEqual(
            encode_history_extension_bundle(bundle),
            encode_history_extension_bundle(bundle),
        )

    def test_encoding_carries_no_secret_material(self):
        history = history_of_size(self.key, 3)
        bundle = signed_bundle(self.key, history, 2, seed=4350)
        wire = encode_history_extension_bundle(bundle)
        # The bundle embeds leaf digests only: neither any full canonical
        # seal encoding nor any raw report bytes appear in the wire bytes.
        for item in history.items:
            self.assertNotIn(encode_seal(item), wire)


class StructureOnlyTest(unittest.TestCase):
    def test_decode_does_not_parse_leaves_or_check_signatures(self):
        # Structurally legal synthetic leaf digests and signatures that
        # never went through a real key round-trip.
        extension = SealHistoryExtension(
            1, (b"a" * 32, b"b" * 32, b"c" * 32)
        )
        old_sig = AggregateSignature(R=9, z=11, signer_ids=(2, 4))
        new_sig = AggregateSignature(R=13, z=15, signer_ids=(1,))
        bundle = SealHistoryExtensionBundle(extension, old_sig, new_sig)
        decoded = decode_history_extension_bundle(
            encode_history_extension_bundle(bundle)
        )
        self.assertEqual(decoded, bundle)

    def test_mismatched_bundle_encodes_and_decodes_but_verifies_false(self):
        key = make_key()
        history = history_of_size(key, 4)
        bundle = signed_bundle(key, history, 2, seed=4400)
        tampered = SealHistoryExtensionBundle(
            dataclasses.replace(bundle.extension, old_total=1),
            bundle.old_sig,
            bundle.new_sig,
        )
        wire = encode_history_extension_bundle(tampered)
        self.assertEqual(decode_history_extension_bundle(wire), tampered)
        self.assertFalse(
            verify_history_extension_bundle(tampered, key)
        )


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        history = history_of_size(self.key, 5)
        self.bundle = signed_bundle(self.key, history, 2, seed=4500)

    def test_non_bundle_type_error(self):
        for bad in (
            ("extension", "old_sig", "new_sig"),
            None,
            object(),
            7,
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_history_extension_bundle(bad)

    def test_non_extension_field_type_error(self):
        for bad in ("not-a-proof", None, 7):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_history_extension_bundle(
                    SealHistoryExtensionBundle(
                        bad, self.bundle.old_sig, self.bundle.new_sig
                    )
                )

    def test_non_signature_field_type_error(self):
        for position in ("old", "new"):
            fields = {
                "extension": self.bundle.extension,
                "old_sig": self.bundle.old_sig,
                "new_sig": self.bundle.new_sig,
            }
            for bad in ("no", None):
                fields[position + "_sig"] = bad
                with self.assertRaises(TypeError, msg=f"{position}={bad!r}"):
                    encode_history_extension_bundle(
                        SealHistoryExtensionBundle(**fields)
                    )

    def test_signature_field_type_errors(self):
        old_sig = self.bundle.old_sig
        for bad in (
            AggregateSignature(True, old_sig.z, old_sig.signer_ids),
            AggregateSignature("5", old_sig.z, old_sig.signer_ids),
            AggregateSignature(old_sig.R, False, old_sig.signer_ids),
            AggregateSignature(old_sig.R, "7", old_sig.signer_ids),
            AggregateSignature(old_sig.R, old_sig.z, [1, 3]),
            AggregateSignature(old_sig.R, old_sig.z, (1, "3")),
            AggregateSignature(old_sig.R, old_sig.z, (True, 3)),
        ):
            for fields in (
                (bad, self.bundle.new_sig),
                (self.bundle.old_sig, bad),
            ):
                bundle = SealHistoryExtensionBundle(
                    self.bundle.extension, *fields
                )
                with self.assertRaises(TypeError, msg=repr(bad)):
                    encode_history_extension_bundle(bundle)

    def test_extension_field_type_errors_propagate(self):
        extension = self.bundle.extension
        leaves = extension.leaves
        for bad in (
            dataclasses.replace(extension, old_total=True),
            dataclasses.replace(extension, old_total="2"),
            dataclasses.replace(extension, leaves=list(leaves)),
            dataclasses.replace(
                extension, leaves=(b"a" * 32, 33, b"c" * 32)
            ),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_history_extension_bundle(
                    SealHistoryExtensionBundle(
                        bad, self.bundle.old_sig, self.bundle.new_sig
                    )
                )

    def test_bad_nested_extension_structure_value_error(self):
        leaves = self.bundle.extension.leaves
        for bad_extension in (
            SealHistoryExtension(0, leaves),
            SealHistoryExtension(len(leaves), leaves),
            SealHistoryExtension(1, ()),
            SealHistoryExtension(1, (b"a" * 31, b"b" * 32)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad_extension)):
                encode_history_extension_bundle(
                    SealHistoryExtensionBundle(
                        bad_extension,
                        self.bundle.old_sig,
                        self.bundle.new_sig,
                    )
                )

    def test_signature_value_errors(self):
        old_sig = self.bundle.old_sig
        for bad in (
            AggregateSignature(0, old_sig.z, old_sig.signer_ids),
            AggregateSignature(-1, old_sig.z, old_sig.signer_ids),
            AggregateSignature(old_sig.R, -1, old_sig.signer_ids),
            AggregateSignature(old_sig.R, old_sig.z, ()),
            AggregateSignature(old_sig.R, old_sig.z, (0, 3)),
            AggregateSignature(old_sig.R, old_sig.z, (-1, 3)),
            AggregateSignature(old_sig.R, old_sig.z, (3, 1)),
            AggregateSignature(old_sig.R, old_sig.z, (1, 1)),
        ):
            for fields in (
                (bad, self.bundle.new_sig),
                (self.bundle.old_sig, bad),
            ):
                bundle = SealHistoryExtensionBundle(
                    self.bundle.extension, *fields
                )
                with self.assertRaises(ValueError, msg=repr(bad)):
                    encode_history_extension_bundle(bundle)


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        history = history_of_size(self.key, 5)
        self.bundle = signed_bundle(self.key, history, 2, seed=4600)
        self.wire = encode_history_extension_bundle(self.bundle)
        self.extension_bytes = encode_history_extension(
            self.bundle.extension
        )
        self.old_frame = signature_frame(self.bundle.old_sig)
        self.new_frame = signature_frame(self.bundle.new_sig)
        self.suffix_offset = (
            len(BUNDLE_TAG) + 4 + len(self.extension_bytes)
        )

    def test_non_bytes_type_error(self):
        for bad in ("not bytes", bytearray(self.wire), None, 7):
            with self.assertRaises(TypeError, msg=repr(bad)):
                decode_history_extension_bundle(bad)

    def test_bad_tag(self):
        rest = self.wire[len(BUNDLE_TAG):]
        with self.assertRaises(ValueError):
            decode_history_extension_bundle(b"ts/sheb/v2" + rest)
        with self.assertRaises(ValueError):
            decode_history_extension_bundle(b"x" + self.wire[1:])
        with self.assertRaises(ValueError):
            decode_history_extension_bundle(self.wire[1:])

    def test_truncation(self):
        for cut in range(len(BUNDLE_TAG), len(self.wire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_history_extension_bundle(self.wire[:cut])

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_history_extension_bundle(self.wire + b"\x00")
        with self.assertRaises(ValueError):
            decode_history_extension_bundle(self.wire + b"ab")

    def test_tag_only_and_partial_length(self):
        for length in (0, 1, 3):
            with self.assertRaises(ValueError, msg=f"length={length}"):
                decode_history_extension_bundle(
                    BUNDLE_TAG + b"\x00" * length
                )

    def test_zero_extension_frame_rejected(self):
        bad = BUNDLE_TAG + u32(0) + self.wire[self.suffix_offset:]
        with self.assertRaises(ValueError):
            decode_history_extension_bundle(bad)

    def test_junk_extension_frame_rejected(self):
        bad = (
            BUNDLE_TAG
            + frame(b"not-an-extension")
            + self.old_frame
            + self.new_frame
        )
        with self.assertRaises(ValueError):
            decode_history_extension_bundle(bad)

    def test_frame_with_trailing_byte_rejected(self):
        # The frame length delimits the nested extension, so an extra byte
        # inside the frame is trailing data to decode_history_extension.
        bad = (
            BUNDLE_TAG
            + frame(self.extension_bytes + b"\x00")
            + self.old_frame
            + self.new_frame
        )
        with self.assertRaises(ValueError):
            decode_history_extension_bundle(bad)

    def test_nested_extension_tag_corrupted(self):
        bad = bytearray(self.wire)
        inner = len(BUNDLE_TAG) + 4
        bad[inner] ^= 0xFF
        with self.assertRaises(ValueError):
            decode_history_extension_bundle(bytes(bad))

    def test_declared_extension_frame_length_mismatch(self):
        # Declaring the frame one byte shorter hides an extension byte
        # inside what the parser then reads as the old R varint length.
        bad = bytearray(self.wire)
        length_offset = len(BUNDLE_TAG)
        declared = len(self.extension_bytes) - 1
        bad[length_offset:length_offset + 4] = u32(declared)
        with self.assertRaises(ValueError):
            decode_history_extension_bundle(bytes(bad))

    def test_zero_R_rejected_in_either_frame(self):
        for sig, offset in (
            (self.bundle.old_sig, self.suffix_offset),
            (
                self.bundle.new_sig,
                self.suffix_offset + len(self.old_frame),
            ),
        ):
            bad = (
                self.wire[:offset]
                + varint(0)
                + self.wire[offset + len(varint(sig.R)):]
            )
            with self.assertRaises(ValueError):
                decode_history_extension_bundle(bad)

    def test_non_canonical_R_leading_zero(self):
        # Use a structurally legal small-R signature so the one-byte
        # canonical body 09 can be padded to the non-canonical 00 09.
        bundle = SealHistoryExtensionBundle(
            self.bundle.extension,
            AggregateSignature(R=9, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=13, z=15, signer_ids=(2,)),
        )
        wire = encode_history_extension_bundle(bundle)
        non_canonical_R = (2).to_bytes(4, "big") + b"\x00\x09"
        canonical_R = varint(9)
        bad = (
            wire[:self.suffix_offset]
            + non_canonical_R
            + wire[self.suffix_offset + len(canonical_R):]
        )
        with self.assertRaises(ValueError):
            decode_history_extension_bundle(bad)

    def test_zero_signer_count_rejected(self):
        for sig, offset in (
            (self.bundle.old_sig, self.suffix_offset),
            (
                self.bundle.new_sig,
                self.suffix_offset + len(self.old_frame),
            ),
        ):
            count_offset = offset + len(varint(sig.R)) + len(varint(sig.z))
            bad = self.wire[:count_offset] + u32(0)
            with self.assertRaises(ValueError):
                decode_history_extension_bundle(bad)

    def test_signer_count_too_large_then_truncated(self):
        sig = self.bundle.old_sig
        tail_offset = (
            self.suffix_offset + len(varint(sig.R)) + len(varint(sig.z))
        )
        bad = self.wire[:tail_offset] + u32(len(sig.signer_ids) + 1)
        for signer_id in sig.signer_ids:
            bad += varint(signer_id)
        with self.assertRaises(ValueError):
            decode_history_extension_bundle(bad)

    def test_non_positive_and_unsorted_signer_ids_rejected(self):
        sig = self.bundle.old_sig
        prefix = (
            BUNDLE_TAG
            + frame(self.extension_bytes)
            + varint(sig.R)
            + varint(sig.z)
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
            out += self.new_frame
            with self.assertRaises(ValueError, msg=label):
                decode_history_extension_bundle(bytes(out))


class VerifyBundleTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.other = make_other_key()
        self.history = history_of_size(self.key, 8)

    def test_honest_bundles_verify_for_every_size_and_split(self):
        seed = 6000
        for n in range(2, 9):
            history = history_of_size(self.key, n)
            for old_total in range(1, n):
                bundle = signed_bundle(
                    self.key, history, old_total, seed=seed
                )
                seed += 10
                self.assertTrue(
                    verify_history_extension_bundle(bundle, self.key),
                    msg=f"n={n} old={old_total}",
                )

    def test_result_equals_check_history_extension(self):
        seed = 7000
        for n in range(2, 9):
            history = history_of_size(self.key, n)
            for old_total in range(1, n):
                bundle = signed_bundle(
                    self.key, history, old_total, seed=seed
                )
                seed += 10
                self.assertEqual(
                    verify_history_extension_bundle(bundle, self.key),
                    check_history_extension(
                        bundle.extension,
                        bundle.old_sig,
                        bundle.new_sig,
                        self.key,
                    ),
                    msg=f"n={n} old={old_total}",
                )

    def test_wrong_key_returns_false(self):
        bundle = signed_bundle(self.key, self.history, 3, seed=7100)
        self.assertFalse(
            verify_history_extension_bundle(bundle, self.other)
        )

    def test_swapped_signatures_return_false(self):
        bundle = signed_bundle(self.key, self.history, 3, seed=7150)
        swapped = SealHistoryExtensionBundle(
            bundle.extension, bundle.new_sig, bundle.old_sig
        )
        self.assertFalse(
            verify_history_extension_bundle(swapped, self.key)
        )

    def test_tampered_signature_returns_false(self):
        bundle = signed_bundle(self.key, self.history, 3, seed=7200)
        # A valid R of a different real round is still a subgroup element,
        # so the check runs and returns False rather than raising.
        other_message = make_history_extension(
            history_of_size(self.key, 4), 2
        )[0]
        other_signature = sign_message(
            other_message, self.key, seed=7210
        )
        tampered = SealHistoryExtensionBundle(
            bundle.extension,
            AggregateSignature(
                R=other_signature.R,
                z=bundle.old_sig.z,
                signer_ids=bundle.old_sig.signer_ids,
            ),
            bundle.new_sig,
        )
        self.assertFalse(
            verify_history_extension_bundle(tampered, self.key)
        )

    def test_signature_over_another_statement_returns_false(self):
        # The statements bind (total, root), so signatures of two different
        # histories are not interchangeable even under the same key.
        bundle_a = signed_bundle(
            self.key, history_of_size(self.key, 6), 3, seed=7300
        )
        bundle_b = signed_bundle(
            self.key, history_of_size(self.key, 5), 2, seed=7400
        )
        mixed = SealHistoryExtensionBundle(
            bundle_a.extension, bundle_a.old_sig, bundle_b.new_sig
        )
        self.assertFalse(
            verify_history_extension_bundle(mixed, self.key)
        )

    def test_tampered_leaf_returns_false(self):
        bundle = signed_bundle(self.key, self.history, 3, seed=7450)
        extension = SealHistoryExtension(
            old_total=bundle.extension.old_total,
            leaves=(b"x" * 32,) + bundle.extension.leaves[1:],
        )
        tampered = SealHistoryExtensionBundle(
            extension, bundle.old_sig, bundle.new_sig
        )
        self.assertFalse(
            verify_history_extension_bundle(tampered, self.key)
        )

    def test_changed_old_total_returns_false(self):
        bundle = signed_bundle(self.key, self.history, 3, seed=7460)
        tampered = SealHistoryExtensionBundle(
            dataclasses.replace(bundle.extension, old_total=2),
            bundle.old_sig,
            bundle.new_sig,
        )
        self.assertFalse(
            verify_history_extension_bundle(tampered, self.key)
        )

    def test_decoded_bundle_verifies_identically(self):
        bundle = signed_bundle(self.key, self.history, 4, seed=7500)
        decoded = decode_history_extension_bundle(
            encode_history_extension_bundle(bundle)
        )
        self.assertEqual(
            verify_history_extension_bundle(decoded, self.key),
            verify_history_extension_bundle(bundle, self.key),
        )

    def test_non_bundle_type_error(self):
        extension = SealHistoryExtension(1, (b"a" * 32, b"b" * 32))
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        for bad in (
            (extension, signature, signature),
            "bundle",
            None,
            extension,
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_history_extension_bundle(bad, self.key)

    def test_bad_nested_structure_value_error(self):
        bad_extension = SealHistoryExtension(
            0, (b"a" * 32, b"b" * 32)
        )
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        bundle = SealHistoryExtensionBundle(
            bad_extension, signature, signature
        )
        with self.assertRaises(ValueError):
            verify_history_extension_bundle(bundle, self.key)

    def test_bad_key_type_error(self):
        bundle = signed_bundle(self.key, self.history, 3, seed=7600)
        with self.assertRaises(TypeError):
            verify_history_extension_bundle(bundle, "key")

    def test_structurally_illegal_signature_value_error(self):
        bundle = signed_bundle(self.key, self.history, 3, seed=7650)
        # R equal to the group prime is never a subgroup element, so
        # verify_signature rejects the structurally presented signature.
        bad_sig = AggregateSignature(
            R=GROUP_PRIME, z=0, signer_ids=(1, 3)
        )
        with self.assertRaises(ValueError):
            verify_history_extension_bundle(
                SealHistoryExtensionBundle(
                    bundle.extension, bad_sig, bundle.new_sig
                ),
                self.key,
            )


if __name__ == "__main__":
    unittest.main()
