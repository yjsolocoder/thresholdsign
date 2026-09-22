"""Tests for the threshold-Schnorr-authenticated whole-archive seal:
DeltaReportBundleArchiveSeal / archive_seal_message /
encode_delta_report_bundle_archive_seal /
decode_delta_report_bundle_archive_seal /
verify_delta_report_bundle_archive_seal."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    DeltaDiagnosis,
    DeltaReport,
    DeltaReportBundle,
    DeltaReportBundleArchive,
    DeltaReportBundleArchiveSeal,
    archive_seal_message,
    decode_delta_report_bundle_archive,
    decode_delta_report_bundle_archive_seal,
    encode_delta_report_bundle_archive,
    encode_delta_report_bundle_archive_seal,
    verify_delta_report_bundle_archive_seal,
)

from test_audit_chain import sign_message
from test_audit_extension_proof_bundle_codec import make_other_key
from test_delta_report_bundle_archive_codec import build_archives

SEAL_TAG = b"ts/dra/v1"
WIRE_TAG = b"ts/dra/w1"


def u32(value):
    return value.to_bytes(4, "big")


def varint(value):
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def frame(body):
    return len(body).to_bytes(4, "big") + body


def build_message(archive, public_key):
    """Independently build the sealed message straight from the spec."""
    encoded = encode_delta_report_bundle_archive(archive)
    return SEAL_TAG + hashlib.sha256(encoded).digest() + varint(public_key)


def build_wire(seal):
    """Independently build the archive-seal wire format from the spec."""
    encoded_archive = encode_delta_report_bundle_archive(seal.archive)
    signature = seal.signature
    out = bytearray(WIRE_TAG)
    out += u32(len(encoded_archive))
    out += encoded_archive
    out += varint(signature.R)
    out += varint(signature.z)
    out += u32(len(signature.signer_ids))
    for signer_id in signature.signer_ids:
        out += varint(signer_id)
    return bytes(out)


def make_seal(archive, key, seed=500):
    """Seal ``archive`` with a real threshold signature of ``key``."""
    message = archive_seal_message(archive, key.public_key)
    signature = sign_message(key, message, seed=seed)
    return DeltaReportBundleArchiveSeal(archive, signature)


class ArchiveSealValueTest(unittest.TestCase):
    def test_frozen_fields_value_equality(self):
        key, _s, full, first, _second, _a = build_archives()
        archive = DeltaReportBundleArchive((full, first))
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        seal = DeltaReportBundleArchiveSeal(archive, signature)  # positional
        self.assertEqual(
            [
                field.name
                for field in dataclasses.fields(DeltaReportBundleArchiveSeal)
            ],
            ["archive", "signature"],
        )
        self.assertEqual(
            seal,
            DeltaReportBundleArchiveSeal(
                archive=archive, signature=signature
            ),
        )
        self.assertEqual(seal.archive, archive)
        self.assertEqual(seal.signature, signature)
        self.assertNotEqual(
            seal,
            DeltaReportBundleArchiveSeal(
                DeltaReportBundleArchive((full,)), signature
            ),
        )
        self.assertNotEqual(
            seal,
            DeltaReportBundleArchiveSeal(
                archive, AggregateSignature(5, 8, (1, 3))
            ),
        )
        self.assertEqual(
            hash(seal),
            hash(DeltaReportBundleArchiveSeal(archive, signature)),
        )
        with self.assertRaises(FrozenInstanceError):
            seal.archive = archive

    def test_construction_does_not_validate(self):
        # The container is a plain value: an illegal archive or signature
        # both construct; the codec and verifier reject them.
        DeltaReportBundleArchiveSeal(
            DeltaReportBundleArchive(()), AggregateSignature(0, -1, ())
        )
        DeltaReportBundleArchiveSeal("not-an-archive", "not-a-signature")


class ArchiveSealMessageTest(unittest.TestCase):
    def setUp(self):
        self.key, _s, self.full, self.first, _second, _a = build_archives()
        self.archive = DeltaReportBundleArchive((self.full, self.first))

    def test_matches_independent_builder(self):
        self.assertEqual(
            archive_seal_message(self.archive, self.key.public_key),
            build_message(self.archive, self.key.public_key),
        )

    def test_layout(self):
        message = archive_seal_message(self.archive, self.key.public_key)
        self.assertTrue(message.startswith(SEAL_TAG))
        offset = len(SEAL_TAG)
        encoded = encode_delta_report_bundle_archive(self.archive)
        self.assertEqual(
            message[offset:offset + 32], hashlib.sha256(encoded).digest()
        )
        offset += 32
        length = int.from_bytes(message[offset:offset + 4], "big")
        self.assertEqual(
            message[offset + 4:],
            self.key.public_key.to_bytes(length, "big"),
        )

    def test_zero_public_key_encodes_as_single_zero_byte(self):
        message = archive_seal_message(self.archive, 0)
        self.assertEqual(message[len(SEAL_TAG) + 32:], u32(1) + b"\x00")

    def test_message_is_unique_and_stateless(self):
        first = archive_seal_message(self.archive, self.key.public_key)
        second = archive_seal_message(self.archive, self.key.public_key)
        self.assertEqual(first, second)
        self.assertNotEqual(
            first, archive_seal_message(self.archive, self.key.public_key + 1)
        )

    def test_binds_the_archive_encoding(self):
        other = DeltaReportBundleArchive(
            (self.first, self.full)
        )  # same bundles, reordered
        self.assertNotEqual(
            archive_seal_message(self.archive, self.key.public_key),
            archive_seal_message(other, self.key.public_key),
        )
        other = DeltaReportBundleArchive((self.full,))
        self.assertNotEqual(
            archive_seal_message(self.archive, self.key.public_key),
            archive_seal_message(other, self.key.public_key),
        )

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            archive_seal_message((self.full,), self.key.public_key)
        with self.assertRaises(TypeError):
            archive_seal_message("archive", self.key.public_key)
        with self.assertRaises(TypeError):
            archive_seal_message(self.full, self.key.public_key)
        with self.assertRaises(TypeError):
            archive_seal_message(self.archive, "key")
        with self.assertRaises(TypeError):
            archive_seal_message(self.archive, True)

    def test_structure_errors(self):
        with self.assertRaises(ValueError):
            archive_seal_message(
                DeltaReportBundleArchive(()), self.key.public_key
            )
        with self.assertRaises(ValueError):
            archive_seal_message(self.archive, -1)


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key, _s, self.full, self.first, _second, _a = build_archives()
        self.archive = DeltaReportBundleArchive((self.full, self.first))
        self.seal = make_seal(self.archive, self.key)

    def test_round_trip_real_seal(self):
        wire = encode_delta_report_bundle_archive_seal(self.seal)
        decoded = decode_delta_report_bundle_archive_seal(wire)
        self.assertEqual(decoded, self.seal)
        self.assertEqual(
            encode_delta_report_bundle_archive_seal(decoded), wire
        )
        self.assertIsInstance(decoded, DeltaReportBundleArchiveSeal)
        self.assertIsInstance(decoded.archive, DeltaReportBundleArchive)
        self.assertIsInstance(decoded.signature, AggregateSignature)

    def test_encoding_matches_independent_builder(self):
        self.assertEqual(
            encode_delta_report_bundle_archive_seal(self.seal),
            build_wire(self.seal),
        )

    def test_starts_with_tag_and_layout(self):
        wire = encode_delta_report_bundle_archive_seal(self.seal)
        self.assertTrue(wire.startswith(WIRE_TAG))
        offset = len(WIRE_TAG)
        encoded = encode_delta_report_bundle_archive(self.archive)
        self.assertEqual(wire[offset:offset + 4], u32(len(encoded)))
        offset += 4
        self.assertEqual(wire[offset:offset + len(encoded)], encoded)
        # The embedded archive frame decodes standalone.
        self.assertEqual(
            decode_delta_report_bundle_archive(
                wire[offset:offset + len(encoded)]
            ),
            self.archive,
        )

    def test_large_signature_integers_round_trip(self):
        signature = AggregateSignature(
            R=(1 << 256) - 77,
            z=(1 << 200) + 9,
            signer_ids=(1, 3, (1 << 64) + 5),
        )
        seal = DeltaReportBundleArchiveSeal(self.archive, signature)
        decoded = decode_delta_report_bundle_archive_seal(
            encode_delta_report_bundle_archive_seal(seal)
        )
        self.assertEqual(decoded, seal)

    def test_zero_z_round_trips(self):
        seal = DeltaReportBundleArchiveSeal(
            self.archive,
            AggregateSignature(R=486, z=0, signer_ids=(1, 3)),
        )
        wire = encode_delta_report_bundle_archive_seal(seal)
        self.assertEqual(decode_delta_report_bundle_archive_seal(wire), seal)

    def test_encoding_is_structure_only(self):
        # An archive of structurally legal bundles whose reports diagnose
        # nothing, plus a signature that seals nothing, travels verbatim;
        # verify_..._seal remains the sole verifier.
        diagnosis = DeltaDiagnosis(False, "sig", 0, None)
        bad_report = DeltaReport(
            diagnosis,
            self.full.report.public_key,
            self.full.report.signature,
        )
        bad_bundle = DeltaReportBundle(self.full.segments, bad_report)
        archive = DeltaReportBundleArchive((bad_bundle,))
        seal = DeltaReportBundleArchiveSeal(
            archive, AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        )
        decoded = decode_delta_report_bundle_archive_seal(
            encode_delta_report_bundle_archive_seal(seal)
        )
        self.assertEqual(decoded, seal)
        self.assertFalse(
            verify_delta_report_bundle_archive_seal(decoded, self.key)
        )

    def test_single_item_archive_round_trip(self):
        archive = DeltaReportBundleArchive((self.full,))
        seal = make_seal(archive, self.key, seed=510)
        wire = encode_delta_report_bundle_archive_seal(seal)
        decoded = decode_delta_report_bundle_archive_seal(wire)
        self.assertEqual(decoded, seal)
        self.assertTrue(
            verify_delta_report_bundle_archive_seal(decoded, self.key)
        )


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key, _s, self.full, self.first, _second, _a = build_archives()
        self.archive = DeltaReportBundleArchive((self.full, self.first))
        self.signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))

    def test_non_seal_type_error(self):
        with self.assertRaises(TypeError):
            encode_delta_report_bundle_archive_seal(
                (self.archive, self.signature)
            )
        with self.assertRaises(TypeError):
            encode_delta_report_bundle_archive_seal(self.archive)

    def test_field_type_errors(self):
        for bad_seal in (
            DeltaReportBundleArchiveSeal("archive", self.signature),
            DeltaReportBundleArchiveSeal(
                DeltaReportBundleArchive((self.full,)), "signature"
            ),
            DeltaReportBundleArchiveSeal(
                self.archive, AggregateSignature(True, 7, (1, 3))
            ),
            DeltaReportBundleArchiveSeal(
                self.archive, AggregateSignature(5, True, (1, 3))
            ),
            DeltaReportBundleArchiveSeal(
                self.archive, AggregateSignature(5, 7, [1, 3])
            ),
            DeltaReportBundleArchiveSeal(
                self.archive, AggregateSignature(5, 7, (1, True))
            ),
        ):
            with self.assertRaises(TypeError, msg=repr(bad_seal)):
                encode_delta_report_bundle_archive_seal(bad_seal)

    def test_archive_structure_value_error(self):
        with self.assertRaises(ValueError):
            encode_delta_report_bundle_archive_seal(
                DeltaReportBundleArchiveSeal(
                    DeltaReportBundleArchive(()), self.signature
                )
            )

    def test_signature_structure_value_error(self):
        for bad_signature in (
            AggregateSignature(0, 7, (1, 3)),      # R must be positive
            AggregateSignature(-1, 7, (1, 3)),
            AggregateSignature(5, -1, (1, 3)),     # z non-negative
            AggregateSignature(5, 7, ()),          # at least one signer
            AggregateSignature(5, 7, (0, 3)),      # positive ids
            AggregateSignature(5, 7, (3, 1)),      # ascending
            AggregateSignature(5, 7, (1, 1)),      # unique
        ):
            with self.assertRaises(ValueError, msg=repr(bad_signature)):
                encode_delta_report_bundle_archive_seal(
                    DeltaReportBundleArchiveSeal(
                        self.archive, bad_signature
                    )
                )


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key, _s, self.full, self.first, _second, _a = build_archives()
        self.archive = DeltaReportBundleArchive((self.full, self.first))
        self.seal = make_seal(self.archive, self.key)
        self.wire = encode_delta_report_bundle_archive_seal(self.seal)

    def test_non_bytes_type_error(self):
        with self.assertRaises(TypeError):
            decode_delta_report_bundle_archive_seal("not bytes")
        with self.assertRaises(TypeError):
            decode_delta_report_bundle_archive_seal(bytearray(self.wire))

    def test_bad_tag(self):
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(
                b"ts/dra/w2" + self.wire[len(WIRE_TAG):]
            )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(b"")
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(b"x" + self.wire[1:])
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(self.wire[5:])

    def test_truncation(self):
        for cut in range(len(WIRE_TAG), len(self.wire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_delta_report_bundle_archive_seal(self.wire[:cut])

    def test_header_truncation(self):
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(WIRE_TAG)
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(WIRE_TAG + b"\x00\x00")

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(self.wire + b"\x00")

    def test_zero_or_oversized_archive_length(self):
        offset = len(WIRE_TAG)
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(
                self.wire[:offset] + u32(0)
            )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(
                self.wire[:offset] + u32(0xFFFFFFFF) + b"a"
            )

    def test_archive_frame_truncated(self):
        offset = len(WIRE_TAG) + 4
        encoded = encode_delta_report_bundle_archive(self.archive)
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(
                self.wire[:len(WIRE_TAG)]
                + u32(len(encoded))
                + encoded[:-1]
            )

    def test_nested_archive_bad_tag_rejected(self):
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(
                WIRE_TAG
                + frame(b"thresholdsign/delta-report-bundle-archive/v0")
            )

    def test_nested_archive_non_canonical_rejected(self):
        encoded = encode_delta_report_bundle_archive(self.archive)
        # Flip the declared item count: the nested framing no longer
        # round-trips canonically.
        tag = b"thresholdsign/delta-report-bundle-archive/v1"
        bad = tag + u32(99) + encoded[len(tag) + 4:]
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(WIRE_TAG + frame(bad))

    def test_zero_R_rejected(self):
        encoded = encode_delta_report_bundle_archive(self.archive)
        bad = (
            WIRE_TAG
            + frame(encoded)
            + varint(0)
            + varint(7)
            + u32(2)
            + varint(1)
            + varint(3)
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(bad)

    def test_non_canonical_varint_rejected(self):
        encoded = encode_delta_report_bundle_archive(self.archive)
        # A two-byte R body starting with 00 carries a forbidden leading zero.
        bad = (
            WIRE_TAG
            + frame(encoded)
            + u32(2) + b"\x00\x05"
            + varint(7)
            + u32(1)
            + varint(1)
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(bad)

    def test_zero_signer_count_rejected(self):
        encoded = encode_delta_report_bundle_archive(self.archive)
        bad = (
            WIRE_TAG
            + frame(encoded)
            + varint(5)
            + varint(7)
            + u32(0)
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(bad)

    def test_signer_count_mismatch_rejected(self):
        encoded = encode_delta_report_bundle_archive(self.archive)
        head = WIRE_TAG + frame(encoded) + varint(5) + varint(7)
        # Declares two ids, one follows.
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(
                head + u32(2) + varint(1)
            )
        # Declares one id, two follow (the second varint becomes trailing).
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(
                head + u32(1) + varint(1) + varint(3)
            )

    def test_unordered_duplicate_or_zero_ids_rejected(self):
        encoded = encode_delta_report_bundle_archive(self.archive)
        head = WIRE_TAG + frame(encoded) + varint(5) + varint(7)
        for ids in ((3, 1), (1, 1), (0, 3)):
            body = head + u32(len(ids)) + b"".join(varint(i) for i in ids)
            with self.assertRaises(ValueError, msg=repr(ids)):
                decode_delta_report_bundle_archive_seal(body)

    def test_tampered_archive_bytes_never_restores_original(self):
        # Adding, deleting, reordering or substituting changes the archive
        # frame bytes: a tampered frame either fails to decode or restores
        # a different, non-verifying seal — never the original seal.
        tampered = bytearray(self.wire)
        # Flip a byte well inside the archive frame.
        tampered[len(WIRE_TAG) + 4 + 4] ^= 0x01
        try:
            restored = decode_delta_report_bundle_archive_seal(bytes(tampered))
        except ValueError:
            pass
        else:
            self.assertNotEqual(restored, self.seal)
            self.assertFalse(
                verify_delta_report_bundle_archive_seal(restored, self.key)
            )


class VerifyArchiveSealTest(unittest.TestCase):
    def setUp(self):
        self.key, _s, self.full, self.first, self.second, _a = build_archives()
        self.archive = DeltaReportBundleArchive(
            (self.full, self.first, self.second)
        )
        self.seal = make_seal(self.archive, self.key)

    def test_real_seal_verifies(self):
        self.assertTrue(
            verify_delta_report_bundle_archive_seal(self.seal, self.key)
        )

    def test_decoded_seal_verifies(self):
        decoded = decode_delta_report_bundle_archive_seal(
            encode_delta_report_bundle_archive_seal(self.seal)
        )
        self.assertTrue(
            verify_delta_report_bundle_archive_seal(decoded, self.key)
        )

    def test_seal_message_is_what_the_signature_covers(self):
        from thresholdsign import verify_signature

        key = self.key
        self.assertTrue(
            verify_signature(
                archive_seal_message(self.archive, key.public_key),
                self.seal.signature,
                key.public_key,
                prime=key.result.commitment.field_prime,
                group_prime=key.result.commitment.group_prime,
                generator=key.result.commitment.generator,
            )
        )

    def test_reordered_archive_returns_false(self):
        swapped = DeltaReportBundleArchive(
            (self.second, self.first, self.full)
        )
        self.assertFalse(
            verify_delta_report_bundle_archive_seal(
                DeltaReportBundleArchiveSeal(
                    swapped, self.seal.signature
                ),
                self.key,
            )
        )

    def test_added_or_deleted_item_returns_false(self):
        shorter = DeltaReportBundleArchive((self.full, self.first))
        longer = DeltaReportBundleArchive(
            (self.full, self.first, self.second, self.full)
        )
        self.assertFalse(
            verify_delta_report_bundle_archive_seal(
                DeltaReportBundleArchiveSeal(
                    shorter, self.seal.signature
                ),
                self.key,
            )
        )
        self.assertFalse(
            verify_delta_report_bundle_archive_seal(
                DeltaReportBundleArchiveSeal(
                    longer, self.seal.signature
                ),
                self.key,
            )
        )

    def test_substituted_item_returns_false(self):
        # Every item of the replaced archive still verifies under the
        # key; only the encoding differs (the middle bundle changed),
        # so the signature over the original digest fails.
        replaced = DeltaReportBundleArchive(
            (self.full, self.full, self.second)
        )
        self.assertNotEqual(replaced, self.archive)
        self.assertFalse(
            verify_delta_report_bundle_archive_seal(
                DeltaReportBundleArchiveSeal(
                    replaced, self.seal.signature
                ),
                self.key,
            )
        )

    def test_archive_with_failing_bundle_returns_false(self):
        diagnosis = DeltaDiagnosis(False, "sig", 0, None)
        bad_bundle = DeltaReportBundle(
            self.full.segments,
            DeltaReport(
                diagnosis,
                self.full.report.public_key,
                self.full.report.signature,
            ),
        )
        archive = DeltaReportBundleArchive((self.first, bad_bundle))
        self.assertFalse(
            verify_delta_report_bundle_archive_seal(
                DeltaReportBundleArchiveSeal(
                    archive, self.seal.signature
                ),
                self.key,
            )
        )

    def test_tampered_signature_returns_false(self):
        key = self.key
        tampered = dataclasses.replace(
            self.seal.signature,
            z=(self.seal.signature.z + 1)
            % key.result.commitment.field_prime,
        )
        self.assertFalse(
            verify_delta_report_bundle_archive_seal(
                DeltaReportBundleArchiveSeal(self.archive, tampered),
                self.key,
            )
        )

    def test_signature_over_another_archive_returns_false(self):
        other_archive = DeltaReportBundleArchive((self.first,))
        other_seal = make_seal(other_archive, self.key, seed=530)
        self.assertTrue(
            verify_delta_report_bundle_archive_seal(other_seal, self.key)
        )
        self.assertFalse(
            verify_delta_report_bundle_archive_seal(
                DeltaReportBundleArchiveSeal(
                    self.archive, other_seal.signature
                ),
                self.key,
            )
        )

    def test_foreign_key_returns_false(self):
        other_key = make_other_key()
        self.assertNotEqual(other_key.public_key, self.key.public_key)
        self.assertFalse(
            verify_delta_report_bundle_archive_seal(self.seal, other_key)
        )

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            verify_delta_report_bundle_archive_seal(
                (self.archive, self.seal.signature), self.key
            )
        with self.assertRaises(TypeError):
            verify_delta_report_bundle_archive_seal("seal", self.key)
        with self.assertRaises(TypeError):
            verify_delta_report_bundle_archive_seal(
                DeltaReportBundleArchiveSeal(
                    self.archive, "signature"
                ),
                self.key,
            )
        with self.assertRaises(TypeError):
            verify_delta_report_bundle_archive_seal(self.seal, "key")
        with self.assertRaises(TypeError):
            verify_delta_report_bundle_archive_seal(self.seal, None)

    def test_structure_errors(self):
        with self.assertRaises(ValueError):
            verify_delta_report_bundle_archive_seal(
                DeltaReportBundleArchiveSeal(
                    DeltaReportBundleArchive(()), self.seal.signature
                ),
                self.key,
            )
        with self.assertRaises(ValueError):
            verify_delta_report_bundle_archive_seal(
                DeltaReportBundleArchiveSeal(
                    self.archive, AggregateSignature(0, 7, (1, 3))
                ),
                self.key,
            )
        with self.assertRaises(ValueError):
            verify_delta_report_bundle_archive_seal(
                DeltaReportBundleArchiveSeal(
                    self.archive, AggregateSignature(5, 7, ())
                ),
                self.key,
            )


if __name__ == "__main__":
    unittest.main()
