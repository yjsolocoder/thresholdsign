"""Tests for the threshold-Schnorr seal over a whole delta report
bundle archive: DeltaReportBundleArchiveSeal / archive_seal_message /
encode_delta_report_bundle_archive_seal /
decode_delta_report_bundle_archive_seal /
verify_delta_report_bundle_archive_seal."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    AuditProofBundle,
    DeltaDiagnosis,
    DeltaReport,
    DeltaReportBundle,
    DeltaReportBundleArchive,
    DeltaReportBundleArchiveSeal,
    archive_seal_message,
    decode_delta_report_bundle_archive,
    decode_delta_report_bundle_archive_seal,
    encode_audit_proof,
    encode_audit_proof_bundle,
    encode_delta_report_bundle_archive,
    encode_delta_report_bundle_archive_seal,
    make_proof,
    verify_delta_report_bundle_archive,
    verify_delta_report_bundle_archive_seal,
)

from test_audit_chain import make_key, sign_message
from test_audit_extension_proof_bundle_codec import (
    make_other_key,
    make_records,
)
from test_delta_report_bundle_archive_codec import (
    TAG as ARCHIVE_TAG,
    build_archives,
)

SEAL_TAG = b"ts/dra/v1"
WIRE_TAG = b"ts/dra/w1"
APB_TAG = b"ts/apb/v1"


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def build_message(archive: DeltaReportBundleArchive, public_key: int) -> bytes:
    """Independently build the sealed message straight from the spec."""
    encoded = encode_delta_report_bundle_archive(archive)
    return SEAL_TAG + hashlib.sha256(encoded).digest() + varint(public_key)


def build_wire(seal: DeltaReportBundleArchiveSeal) -> bytes:
    """Independently build the archive-seal wire format straight from spec."""
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


def make_seal(
    archive: DeltaReportBundleArchive, key, *, signer_ids=(1, 3), seed=600
) -> DeltaReportBundleArchiveSeal:
    """Seal ``archive`` with a real threshold signature of ``key``."""
    message = archive_seal_message(archive, key.public_key)
    signature = sign_message(key, message, signer_ids=signer_ids, seed=seed)
    return DeltaReportBundleArchiveSeal(archive, signature)


class ArchiveSealShapeTest(unittest.TestCase):
    def test_fields_in_order(self):
        self.assertEqual(
            [
                field.name
                for field in dataclasses.fields(DeltaReportBundleArchiveSeal)
            ],
            ["archive", "signature"],
        )

    def test_frozen_positional_and_value_equal(self):
        key, _s, full, first, _second, _archives = build_archives()
        archive = DeltaReportBundleArchive((full, first))
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        seal = DeltaReportBundleArchiveSeal(archive, signature)
        self.assertIs(seal.archive, archive)
        self.assertIs(seal.signature, signature)
        self.assertEqual(
            seal,
            DeltaReportBundleArchiveSeal(
                archive=archive, signature=signature
            ),
        )
        self.assertEqual(hash(seal), hash(
            DeltaReportBundleArchiveSeal(archive, signature)
        ))
        self.assertNotEqual(
            seal,
            DeltaReportBundleArchiveSeal(
                DeltaReportBundleArchive((full,)), signature
            ),
        )
        self.assertNotEqual(
            seal,
            DeltaReportBundleArchiveSeal(
                archive, AggregateSignature(R=6, z=7, signer_ids=(1, 3))
            ),
        )
        self.assertEqual(
            {seal, DeltaReportBundleArchiveSeal(archive, signature)},
            {DeltaReportBundleArchiveSeal(archive, signature)},
        )
        with self.assertRaises(FrozenInstanceError):
            seal.archive = archive

    def test_construction_does_not_validate(self):
        # A plain frozen value: non-archive and non-signature fields
        # construct; the codec and verifier reject them.
        DeltaReportBundleArchiveSeal("not-an-archive", "not-a-signature")
        DeltaReportBundleArchiveSeal(None, None)


class ArchiveSealMessageTest(unittest.TestCase):
    def setUp(self):
        (
            self.key,
            _segments,
            self.full,
            self.first,
            self.second,
            self.archives,
        ) = build_archives()

    def test_matches_independent_spec_build(self):
        for archive in self.archives:
            with self.subTest(n=len(archive.items)):
                message = archive_seal_message(archive, self.key.public_key)
                self.assertEqual(
                    message, build_message(archive, self.key.public_key)
                )
                self.assertTrue(message.startswith(SEAL_TAG))

    def test_layout_is_tag_digest_then_key_varint(self):
        archive = DeltaReportBundleArchive((self.full, self.first))
        message = archive_seal_message(archive, self.key.public_key)
        encoded = encode_delta_report_bundle_archive(archive)
        offset = 0
        self.assertEqual(message[offset:len(SEAL_TAG)], SEAL_TAG)
        offset += len(SEAL_TAG)
        self.assertEqual(
            message[offset:offset + 32],
            hashlib.sha256(encoded).digest(),
        )
        offset += 32
        length = int.from_bytes(message[offset:offset + 4], "big")
        self.assertEqual(
            message[offset + 4:offset + 4 + length],
            varint(self.key.public_key)[4:],
        )
        self.assertEqual(offset + 4 + length, len(message))

    def test_commits_to_archive_and_key(self):
        archive = DeltaReportBundleArchive((self.first, self.second))
        reordered = DeltaReportBundleArchive((self.second, self.first))
        single = DeltaReportBundleArchive((self.first,))
        message = archive_seal_message(archive, self.key.public_key)
        self.assertNotEqual(
            message, archive_seal_message(reordered, self.key.public_key)
        )
        self.assertNotEqual(
            message, archive_seal_message(single, self.key.public_key)
        )
        self.assertNotEqual(
            message, archive_seal_message(archive, self.key.public_key + 1)
        )
        self.assertEqual(
            archive_seal_message(archive, self.key.public_key), message
        )

    def test_zero_public_key_encodes_as_single_00(self):
        archive = DeltaReportBundleArchive((self.full,))
        message = archive_seal_message(archive, 0)
        self.assertEqual(
            message,
            SEAL_TAG
            + hashlib.sha256(
                encode_delta_report_bundle_archive(archive)
            ).digest()
            + b"\x00\x00\x00\x01\x00",
        )

    def test_non_archive_type_error(self):
        for bad in ("x", None, 42, b"x", object(), (self.full,), self.full):
            with self.assertRaises(TypeError, msg=repr(bad)):
                archive_seal_message(bad, self.key.public_key)

    def test_illegal_archive_value_error(self):
        with self.assertRaises(ValueError):
            archive_seal_message(
                DeltaReportBundleArchive(()), self.key.public_key
            )

    def test_bad_public_key_type_or_value(self):
        archive = DeltaReportBundleArchive((self.full,))
        for bad in ("x", None, b"x", 1.5, True, False):
            with self.assertRaises(TypeError, msg=repr(bad)):
                archive_seal_message(archive, bad)
        with self.assertRaises(ValueError):
            archive_seal_message(archive, -1)


class EncodeDecodeArchiveSealTest(unittest.TestCase):
    def setUp(self):
        (
            self.key,
            _segments,
            self.full,
            self.first,
            self.second,
            self.archives,
        ) = build_archives()
        self.seals = tuple(
            make_seal(archive, self.key, seed=700 + index)
            for index, archive in enumerate(self.archives)
        )

    def test_wire_matches_independent_spec_build(self):
        for seal in self.seals:
            with self.subTest(n=len(seal.archive.items)):
                blob = encode_delta_report_bundle_archive_seal(seal)
                self.assertEqual(blob, build_wire(seal))
                self.assertTrue(blob.startswith(WIRE_TAG))

    def test_wire_layout_is_tag_frame_then_signature_frame(self):
        seal = self.seals[1]
        blob = encode_delta_report_bundle_archive_seal(seal)
        encoded_archive = encode_delta_report_bundle_archive(seal.archive)
        offset = 0
        self.assertEqual(blob[offset:len(WIRE_TAG)], WIRE_TAG)
        offset += len(WIRE_TAG)
        self.assertEqual(blob[offset:offset + 4], u32(len(encoded_archive)))
        offset += 4
        self.assertEqual(
            blob[offset:offset + len(encoded_archive)], encoded_archive
        )
        offset += len(encoded_archive)
        signature = seal.signature
        self.assertEqual(
            blob[offset:offset + len(varint(signature.R))],
            varint(signature.R),
        )

    def test_signature_frame_matches_audit_proof_bundle_frame(self):
        # The bytes after the archive frame are exactly the signature
        # frame encode_audit_proof_bundle writes for the same signature.
        seal = self.seals[0]
        records = make_records(self.key, 1)
        _message, proof = make_proof(records, 0)
        bundle = AuditProofBundle(proof, seal.signature)
        bundle_blob = encode_audit_proof_bundle(bundle)
        proof_body = encode_audit_proof(proof)
        bundle_tail = bundle_blob[len(APB_TAG) + 4 + len(proof_body):]

        archive_body = encode_delta_report_bundle_archive(seal.archive)
        seal_blob = encode_delta_report_bundle_archive_seal(seal)
        seal_tail = seal_blob[len(WIRE_TAG) + 4 + len(archive_body):]
        self.assertEqual(seal_tail, bundle_tail)
        self.assertEqual(seal_blob, WIRE_TAG + u32(len(archive_body))
                         + archive_body + bundle_tail)

    def test_round_trip_byte_for_byte(self):
        for seal in self.seals:
            with self.subTest(n=len(seal.archive.items)):
                blob = encode_delta_report_bundle_archive_seal(seal)
                restored = decode_delta_report_bundle_archive_seal(blob)
                self.assertIsInstance(
                    restored, DeltaReportBundleArchiveSeal
                )
                self.assertEqual(restored, seal)
                self.assertEqual(
                    encode_delta_report_bundle_archive_seal(restored), blob
                )

    def test_nested_archive_decodes_standalone(self):
        seal = self.seals[1]
        blob = encode_delta_report_bundle_archive_seal(seal)
        offset = len(WIRE_TAG)
        length = int.from_bytes(blob[offset:offset + 4], "big")
        frame = blob[offset + 4:offset + 4 + length]
        self.assertEqual(
            decode_delta_report_bundle_archive(bytes(frame)), seal.archive
        )

    def test_order_is_preserved(self):
        forward = DeltaReportBundleArchive((self.first, self.second))
        reverse = DeltaReportBundleArchive((self.second, self.first))
        forward_seal = make_seal(forward, self.key, seed=810)
        reverse_seal = make_seal(reverse, self.key, seed=811)
        restored = decode_delta_report_bundle_archive_seal(
            encode_delta_report_bundle_archive_seal(forward_seal)
        )
        self.assertEqual(restored.archive.items, (self.first, self.second))
        self.assertNotEqual(restored, reverse_seal)
        self.assertEqual(
            decode_delta_report_bundle_archive_seal(
                encode_delta_report_bundle_archive_seal(reverse_seal)
            ).archive.items,
            (self.second, self.first),
        )

    def test_encoding_is_deterministic_and_unique(self):
        seal_a = make_seal(
            DeltaReportBundleArchive((self.full, self.first)), self.key,
            seed=820,
        )
        seal_b = make_seal(
            DeltaReportBundleArchive((self.first, self.full)), self.key,
            seed=821,
        )
        seal_c = make_seal(
            DeltaReportBundleArchive((self.full,)), self.key, seed=822
        )
        self.assertEqual(
            encode_delta_report_bundle_archive_seal(seal_a),
            encode_delta_report_bundle_archive_seal(seal_a),
        )
        self.assertNotEqual(
            encode_delta_report_bundle_archive_seal(seal_a),
            encode_delta_report_bundle_archive_seal(seal_b),
        )
        self.assertNotEqual(
            encode_delta_report_bundle_archive_seal(seal_a),
            encode_delta_report_bundle_archive_seal(seal_c),
        )

    def test_z_zero_is_structurally_legal_and_round_trips(self):
        # z may be zero and encodes as the single body byte 00; such a
        # seal is structurally legal for the codec even though no real
        # signature is carried.
        archive = DeltaReportBundleArchive((self.full,))
        seal = DeltaReportBundleArchiveSeal(
            archive, AggregateSignature(R=5, z=0, signer_ids=(1,))
        )
        blob = encode_delta_report_bundle_archive_seal(seal)
        restored = decode_delta_report_bundle_archive_seal(blob)
        self.assertEqual(restored, seal)
        self.assertEqual(
            encode_delta_report_bundle_archive_seal(restored), blob
        )

    def test_structurally_legal_but_wrong_signature_decodes(self):
        seal = make_seal(
            DeltaReportBundleArchive((self.full, self.first)), self.key,
            seed=830,
        )
        blob = bytearray(encode_delta_report_bundle_archive_seal(seal))
        # Flip the last signer-id body byte: still a canonical legal
        # structure, but no longer the signing signature.
        blob[-1] ^= 0xFF
        restored = decode_delta_report_bundle_archive_seal(bytes(blob))
        self.assertNotEqual(restored, seal)
        self.assertFalse(
            verify_delta_report_bundle_archive_seal(restored, self.key)
        )


class EncodeArchiveSealErrorTest(unittest.TestCase):
    def setUp(self):
        (
            self.key,
            _segments,
            self.full,
            self.first,
            _second,
            _archives,
        ) = build_archives()
        self.archive = DeltaReportBundleArchive((self.full, self.first))
        self.signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))

    def test_non_seal_type_error(self):
        for bad in ("x", None, 42, b"x", object(), self.archive):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_delta_report_bundle_archive_seal(bad)

    def test_non_archive_field_type_error(self):
        for bad in ("x", None, 42, b"x", object(), (self.full,), self.full):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_delta_report_bundle_archive_seal(
                    DeltaReportBundleArchiveSeal(bad, self.signature)
                )

    def test_non_signature_field_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_delta_report_bundle_archive_seal(
                    DeltaReportBundleArchiveSeal(self.archive, bad)
                )

    def test_illegal_archive_value_error(self):
        with self.assertRaises(ValueError):
            encode_delta_report_bundle_archive_seal(
                DeltaReportBundleArchiveSeal(
                    DeltaReportBundleArchive(()), self.signature
                )
            )

    def test_illegal_signature_value_error(self):
        bad_signatures = (
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=-1, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=-1, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=7, signer_ids=()),
            AggregateSignature(R=5, z=7, signer_ids=(0, 1)),
            AggregateSignature(R=5, z=7, signer_ids=(3, 1)),
            AggregateSignature(R=5, z=7, signer_ids=(1, 1)),
        )
        for bad in bad_signatures:
            with self.assertRaises(ValueError, msg=repr(bad)):
                encode_delta_report_bundle_archive_seal(
                    DeltaReportBundleArchiveSeal(self.archive, bad)
                )

    def test_bad_signature_nested_field_type_error(self):
        for bad in ("x", None, 5.0, True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_delta_report_bundle_archive_seal(
                    DeltaReportBundleArchiveSeal(
                        self.archive,
                        AggregateSignature(R=bad, z=7, signer_ids=(1, 3)),
                    )
                )
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_delta_report_bundle_archive_seal(
                    DeltaReportBundleArchiveSeal(
                        self.archive,
                        AggregateSignature(R=5, z=bad, signer_ids=(1, 3)),
                    )
                )
        with self.assertRaises(TypeError):
            encode_delta_report_bundle_archive_seal(
                DeltaReportBundleArchiveSeal(
                    self.archive,
                    AggregateSignature(R=5, z=7, signer_ids=[1, 3]),
                )
            )
        with self.assertRaises(TypeError):
            encode_delta_report_bundle_archive_seal(
                DeltaReportBundleArchiveSeal(
                    self.archive,
                    AggregateSignature(R=5, z=7, signer_ids=(1, "3")),
                )
            )


class DecodeArchiveSealErrorTest(unittest.TestCase):
    def setUp(self):
        (
            self.key,
            _segments,
            self.full,
            self.first,
            _second,
            _archives,
        ) = build_archives()
        self.archive = DeltaReportBundleArchive((self.full, self.first))
        self.seal = make_seal(self.archive, self.key, seed=900)
        self.blob = encode_delta_report_bundle_archive_seal(self.seal)
        self.archive_body = encode_delta_report_bundle_archive(self.archive)
        self.body_offset = len(WIRE_TAG) + 4

    def test_non_bytes_type_error(self):
        for bad in (
            self.blob.decode("latin1"),
            bytearray(self.blob),
            None,
            42,
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                decode_delta_report_bundle_archive_seal(bad)

    def test_bad_tag(self):
        swap = b"ts/dra/w0"
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(
                swap + self.blob[len(WIRE_TAG):]
            )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(b"")
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(self.blob[3:])

    def test_zero_or_overlong_archive_frame(self):
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(
                WIRE_TAG + u32(0) + varint(5) + varint(7) + u32(1)
                + varint(1)
            )
        bad = (
            WIRE_TAG
            + u32(len(self.archive_body) + 1)
            + self.archive_body
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(bad)

    def test_truncation(self):
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(WIRE_TAG)
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(self.blob[:-1])
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(
                self.blob[: self.body_offset + 3]
            )

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(self.blob + b"\x00")

    def test_illegal_nested_archive_frame(self):
        # An archive frame that declares an empty item set is rejected
        # by the nested archive decoder even though the outer framing
        # lines up.
        empty_archive = ARCHIVE_TAG + u32(0)
        signature = self.seal.signature
        bad = (
            WIRE_TAG
            + u32(len(empty_archive))
            + empty_archive
            + varint(signature.R)
            + varint(signature.z)
            + u32(len(signature.signer_ids))
            + b"".join(varint(sid) for sid in signature.signer_ids)
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(bad)

    def test_tampered_nested_archive_frame(self):
        tampered = bytearray(self.blob)
        tampered[self.body_offset + 5] ^= 0x01
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(bytes(tampered))

    def test_zero_R_is_illegal(self):
        bad = bytearray(self.blob)
        offset = self.body_offset + len(self.archive_body)
        length = int.from_bytes(bad[offset:offset + 4], "big")
        end = offset + 4 + length
        self.assertEqual(
            bytes(bad[offset:end]), varint(self.seal.signature.R)
        )
        bad[offset:end] = varint(0)
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(bytes(bad))

    def test_non_canonical_leading_zero_integer(self):
        # Lengthen the R body to two bytes with a forbidden leading 00.
        bad = bytearray(self.blob)
        offset = self.body_offset + len(self.archive_body)
        body = bytes(bad[offset + 4:offset + 5])
        bad[offset:offset + 5] = u32(2) + b"\x00" + body
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(bytes(bad))

    def test_zero_signer_count_is_illegal(self):
        signature = AggregateSignature(R=5, z=7, signer_ids=(1,))
        bad = (
            WIRE_TAG
            + u32(len(self.archive_body))
            + self.archive_body
            + varint(signature.R)
            + varint(signature.z)
            + u32(0)
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(bad)

    def test_signer_count_mismatch(self):
        signature = AggregateSignature(R=5, z=7, signer_ids=(1,))
        bad = (
            WIRE_TAG
            + u32(len(self.archive_body))
            + self.archive_body
            + varint(signature.R)
            + varint(signature.z)
            + u32(2)
            + varint(1)
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(bad)

    def test_non_increasing_signer_ids(self):
        signature = AggregateSignature(R=5, z=7, signer_ids=(3, 1))
        bad = (
            WIRE_TAG
            + u32(len(self.archive_body))
            + self.archive_body
            + varint(signature.R)
            + varint(signature.z)
            + u32(2)
            + varint(3)
            + varint(1)
        )
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(bad)

    def test_short_garbage(self):
        with self.assertRaises(ValueError):
            decode_delta_report_bundle_archive_seal(
                WIRE_TAG + u32(1) + b"x"
            )


class VerifyArchiveSealTest(unittest.TestCase):
    def setUp(self):
        (
            self.key,
            _segments,
            self.full,
            self.first,
            self.second,
            _archives,
        ) = build_archives()
        self.archive = DeltaReportBundleArchive(
            (self.full, self.first, self.second)
        )
        self.seal = make_seal(self.archive, self.key, seed=950)

    def test_verifying_seal_is_true(self):
        self.assertTrue(
            verify_delta_report_bundle_archive_seal(self.seal, self.key)
        )

    def test_decoded_seal_keeps_verdict(self):
        restored = decode_delta_report_bundle_archive_seal(
            encode_delta_report_bundle_archive_seal(self.seal)
        )
        self.assertTrue(
            verify_delta_report_bundle_archive_seal(restored, self.key)
        )

    def test_archive_must_verify_under_key(self):
        # A seal over an archive containing a bundle its report does not
        # diagnose structurally encodes, but verification is False.
        diagnosis = DeltaDiagnosis(False, "sig", 0, None)
        bad_bundle = DeltaReportBundle(
            self.full.segments,
            DeltaReport(
                diagnosis,
                self.full.report.public_key,
                self.full.report.signature,
            ),
        )
        bad_archive = DeltaReportBundleArchive((self.first, bad_bundle))
        seal = make_seal(bad_archive, self.key, seed=960)
        restored = decode_delta_report_bundle_archive_seal(
            encode_delta_report_bundle_archive_seal(seal)
        )
        self.assertTrue(
            verify_delta_report_bundle_archive(bad_archive, self.key)
            is False
        )
        self.assertFalse(
            verify_delta_report_bundle_archive_seal(restored, self.key)
        )

    def test_tampered_signature_is_false(self):
        blob = bytearray(encode_delta_report_bundle_archive_seal(self.seal))
        blob[-1] ^= 0xFF
        restored = decode_delta_report_bundle_archive_seal(bytes(blob))
        self.assertFalse(
            verify_delta_report_bundle_archive_seal(restored, self.key)
        )

    def test_deleting_a_bundle_is_false(self):
        # The same signature presented over a strict sub-archive: the
        # signed message commits to the archive digest, so deletion fails.
        smaller = DeltaReportBundleArchive(
            (self.full, self.first)
        )
        self.assertFalse(
            verify_delta_report_bundle_archive_seal(
                DeltaReportBundleArchiveSeal(
                    smaller, self.seal.signature
                ),
                self.key,
            )
        )

    def test_reordering_bundles_is_false(self):
        reordered = DeltaReportBundleArchive(
            tuple(reversed(self.archive.items))
        )
        self.assertFalse(
            verify_delta_report_bundle_archive_seal(
                DeltaReportBundleArchiveSeal(
                    reordered, self.seal.signature
                ),
                self.key,
            )
        )

    def test_substituting_a_bundle_is_false(self):
        substituted = DeltaReportBundleArchive(
            (self.first, self.first, self.second)
        )
        self.assertFalse(
            verify_delta_report_bundle_archive_seal(
                DeltaReportBundleArchiveSeal(
                    substituted, self.seal.signature
                ),
                self.key,
            )
        )

    def test_other_key_is_false(self):
        self.assertFalse(
            verify_delta_report_bundle_archive_seal(
                self.seal, make_other_key()
            )
        )

    def test_non_seal_type_error(self):
        for bad in ("x", None, 42, b"x", object(), self.archive):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_delta_report_bundle_archive_seal(bad, self.key)

    def test_non_archive_field_type_error(self):
        for bad in ("x", None, 42, b"x", object(), (self.full,)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_delta_report_bundle_archive_seal(
                    DeltaReportBundleArchiveSeal(
                        bad, self.seal.signature
                    ),
                    self.key,
                )

    def test_non_signature_field_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_delta_report_bundle_archive_seal(
                    DeltaReportBundleArchiveSeal(self.archive, bad),
                    self.key,
                )

    def test_non_key_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_delta_report_bundle_archive_seal(self.seal, bad)

    def test_illegal_archive_value_error(self):
        with self.assertRaises(ValueError):
            verify_delta_report_bundle_archive_seal(
                DeltaReportBundleArchiveSeal(
                    DeltaReportBundleArchive(()), self.seal.signature
                ),
                self.key,
            )

    def test_illegal_signature_value_error(self):
        bad_signatures = (
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=-1, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=7, signer_ids=()),
            AggregateSignature(R=5, z=7, signer_ids=(3, 1)),
        )
        for bad in bad_signatures:
            with self.assertRaises(ValueError, msg=repr(bad)):
                verify_delta_report_bundle_archive_seal(
                    DeltaReportBundleArchiveSeal(self.archive, bad),
                    self.key,
                )


if __name__ == "__main__":
    unittest.main()
