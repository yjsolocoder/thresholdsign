"""Tests for the threshold-Schnorr-authenticated delta report:
DeltaReport / dr_message / encode_dr / decode_dr / verify_dr."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    AuditExtensionDeltaCheckpointChain,
    DeltaDiagnosis,
    DeltaReport,
    decode_delta_chain_segments,
    decode_dr,
    diagnose_delta_chain_segments,
    dr_message,
    encode_delta_chain_segments,
    encode_dr,
    partition_delta_chain,
    verify_delta_chain_segments,
    verify_dr,
)

from test_audit_chain import make_key, sign_message
from test_audit_extension_proof_bundle_codec import (
    make_other_key,
    make_records,
)
from test_audit_extension_delta_checkpoint_chain_segment import make_delta

DR_TAG = b"ts/dr/v1"
WIRE_TAG = b"ts/dr/w1"
ABSENT = (1 << 64) - 1
KINDS = ("ok", "segment", "leaf", "sig", "proof")


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def build_diagnosis_block(diagnosis: DeltaDiagnosis) -> bytes:
    """Independently build the fixed-width D block straight from the spec."""
    return b"".join(
        u64(value)
        for value in (
            1 if diagnosis.ok else 0,
            KINDS.index(diagnosis.kind),
            ABSENT if diagnosis.segment is None else diagnosis.segment,
            ABSENT if diagnosis.proof is None else diagnosis.proof,
        )
    )


def build_message(segments, diagnosis: DeltaDiagnosis, public_key: int) -> bytes:
    """Independently build the signed message straight from the spec."""
    encoded = encode_delta_chain_segments(segments)
    return (
        DR_TAG
        + hashlib.sha256(encoded).digest()
        + varint(public_key)
        + build_diagnosis_block(diagnosis)
    )


def build_wire(report: DeltaReport) -> bytes:
    """Independently build the delta report wire format from the spec."""
    out = bytearray(WIRE_TAG)
    out += build_diagnosis_block(report.diagnosis)
    out += varint(report.public_key)
    signature = report.signature
    out += varint(signature.R)
    out += varint(signature.z)
    out += u32(len(signature.signer_ids))
    for signer_id in signature.signer_ids:
        out += varint(signer_id)
    return bytes(out)


def build_segments(cuts=(1, 3)):
    key = make_key()
    records = make_records(key, 7)
    splits = [(2, 3), (3, 5), (5, 6), (6, 7)]
    delta = make_delta(key, records, splits)
    return key, records, splits, delta, partition_delta_chain(delta, cuts)


def make_report(segments, diagnosis, key, *, seed=100):
    message = dr_message(segments, diagnosis, key.public_key)
    return DeltaReport(
        diagnosis, key.public_key, sign_message(key, message, seed=seed)
    )


class DeltaReportShapeTest(unittest.TestCase):
    def test_fields_in_order(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(DeltaReport)],
            ["diagnosis", "public_key", "signature"],
        )

    def test_frozen_positional_and_value_equal(self):
        diagnosis = DeltaDiagnosis(True, "ok", None, None)
        signature = AggregateSignature(R=70001, z=70002, signer_ids=(1, 3))
        report = DeltaReport(diagnosis, 5, signature)
        self.assertEqual(
            report,
            DeltaReport(
                diagnosis=diagnosis, public_key=5, signature=signature
            ),
        )
        self.assertEqual(
            (report.diagnosis, report.public_key, report.signature),
            (diagnosis, 5, signature),
        )
        self.assertEqual(report, DeltaReport(diagnosis, 5, signature))
        self.assertNotEqual(report, DeltaReport(diagnosis, 6, signature))
        self.assertEqual(
            {report, DeltaReport(diagnosis, 5, signature)},
            {DeltaReport(diagnosis, 5, signature)},
        )
        with self.assertRaises(FrozenInstanceError):
            report.public_key = 6


class DrMessageTest(unittest.TestCase):
    def setUp(self):
        self.key, _r, _s, _d, self.segments = build_segments()

    def test_message_matches_independent_spec_build(self):
        cases = (
            DeltaDiagnosis(True, "ok", None, None),
            DeltaDiagnosis(False, "segment", 0, 1),
            DeltaDiagnosis(False, "leaf", 2, None),
            DeltaDiagnosis(False, "sig", 1, None),
            DeltaDiagnosis(False, "proof", 1, 2),
        )
        for diagnosis in cases:
            with self.subTest(kind=diagnosis.kind):
                message = dr_message(
                    self.segments, diagnosis, self.key.public_key
                )
                self.assertEqual(
                    message,
                    build_message(
                        self.segments, diagnosis, self.key.public_key
                    ),
                )

    def test_message_layout_fields(self):
        diagnosis = DeltaDiagnosis(False, "proof", 1, 2)
        message = dr_message(
            self.segments, diagnosis, self.key.public_key
        )
        self.assertTrue(message.startswith(DR_TAG))
        offset = len(DR_TAG)
        digest = hashlib.sha256(
            encode_delta_chain_segments(self.segments)
        ).digest()
        self.assertEqual(message[offset:offset + 32], digest)
        offset += 32
        length = int.from_bytes(message[offset:offset + 4], "big")
        offset += 4
        self.assertEqual(
            int.from_bytes(message[offset:offset + length], "big"),
            self.key.public_key,
        )
        offset += length
        self.assertEqual(
            message[offset:offset + 32],
            build_diagnosis_block(diagnosis),
        )
        self.assertEqual(len(message), offset + 32)

    def test_diagnosis_block_kind_codes(self):
        for code, kind in enumerate(KINDS):
            with self.subTest(kind=kind):
                if kind == "ok":
                    diagnosis = DeltaDiagnosis(True, kind, None, None)
                elif kind in ("leaf", "sig"):
                    diagnosis = DeltaDiagnosis(False, kind, 3, None)
                else:
                    diagnosis = DeltaDiagnosis(False, kind, 3, 5)
                block = dr_message(
                    self.segments, diagnosis, self.key.public_key
                )[-32:]
                self.assertEqual(block[0:8], u64(0 if kind != "ok" else 1))
                self.assertEqual(block[8:16], u64(code))

    def test_absent_index_is_all_ones_sentinel(self):
        diagnosis = DeltaDiagnosis(False, "sig", 9, None)
        block = dr_message(
            self.segments, diagnosis, self.key.public_key
        )[-32:]
        self.assertEqual(block[16:24], u64(9))
        self.assertEqual(block[24:32], u64(ABSENT))
        ok_block = dr_message(
            self.segments, DeltaDiagnosis(True, "ok", None, None), 0
        )[-32:]
        self.assertEqual(ok_block[16:24], u64(ABSENT))
        self.assertEqual(ok_block[24:32], u64(ABSENT))

    def test_zero_public_key_encodes_as_single_00(self):
        message = dr_message(
            self.segments, DeltaDiagnosis(True, "ok", None, None), 0
        )
        digest = hashlib.sha256(
            encode_delta_chain_segments(self.segments)
        ).digest()
        self.assertEqual(
            message,
            DR_TAG + digest + b"\x00\x00\x00\x01\x00"
            + u64(1) + u64(0) + u64(ABSENT) + u64(ABSENT),
        )

    def test_message_is_deterministic(self):
        diagnosis = DeltaDiagnosis(True, "ok", None, None)
        first = dr_message(self.segments, diagnosis, self.key.public_key)
        second = dr_message(self.segments, diagnosis, self.key.public_key)
        self.assertEqual(first, second)


class DrMessageErrorTest(unittest.TestCase):
    def setUp(self):
        self.key, _r, _s, _d, self.segments = build_segments()
        self.diagnosis = DeltaDiagnosis(True, "ok", None, None)

    def test_non_tuple_segments_type_error(self):
        for bad in (
            list(self.segments),
            iter(self.segments),
            [self.segments[0]],
            self.segments[0],
            "segments",
            None,
            42,
            object(),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dr_message(bad, self.diagnosis, self.key.public_key)

    def test_non_segment_element_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dr_message(
                    (bad,), self.diagnosis, self.key.public_key
                )

    def test_non_diagnosis_type_error(self):
        for bad in ("x", None, 42, b"x", object(), (True, "ok", None, None)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dr_message(
                    self.segments, bad, self.key.public_key
                )

    def test_non_integer_public_key_type_error(self):
        for bad in (True, False, 1.0, "x", None, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dr_message(
                    self.segments, self.diagnosis, bad
                )

    def test_empty_segments_value_error(self):
        with self.assertRaises(ValueError):
            dr_message((), self.diagnosis, self.key.public_key)

    def test_illegal_segment_value_error(self):
        good = self.segments[0]
        bad = AuditExtensionDeltaCheckpointChain(
            good.first, ((),) + good.additions[1:], good.signatures
        )
        with self.assertRaises(ValueError):
            dr_message((bad,), self.diagnosis, self.key.public_key)

    def test_negative_public_key_value_error(self):
        with self.assertRaises(ValueError):
            dr_message(self.segments, self.diagnosis, -1)

    def test_bad_diagnosis_field_types(self):
        for bad in (
            DeltaDiagnosis(1, "ok", None, None),
            DeltaDiagnosis(0, "ok", None, None),
            DeltaDiagnosis(False, 7, None, None),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dr_message(self.segments, bad, self.key.public_key)
        for bad in (
            DeltaDiagnosis(False, "leaf", "x", None),
            DeltaDiagnosis(False, "proof", 0, "x"),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dr_message(self.segments, bad, self.key.public_key)

    def test_inconsistent_diagnosis_value_error(self):
        cases = (
            DeltaDiagnosis(True, "proof", 1, 2),
            DeltaDiagnosis(False, "ok", None, None),
            DeltaDiagnosis(False, "leaf", None, None),
            DeltaDiagnosis(False, "sig", 2, 3),
            DeltaDiagnosis(False, "proof", 2, None),
            DeltaDiagnosis(True, "ok", 1, None),
            DeltaDiagnosis(False, "nope", None, None),
            DeltaDiagnosis(False, "leaf", ABSENT, None),
        )
        for bad in cases:
            with self.assertRaises(ValueError, msg=repr(bad)):
                dr_message(self.segments, bad, self.key.public_key)


class EncodeDecodeDrTest(unittest.TestCase):
    def setUp(self):
        self.key, _r, _s, _d, self.segments = build_segments()

    def _reports(self):
        signature = sign_message(
            self.key,
            dr_message(
                self.segments,
                DeltaDiagnosis(True, "ok", None, None),
                self.key.public_key,
            ),
        )
        return (
            DeltaReport(
                DeltaDiagnosis(True, "ok", None, None),
                self.key.public_key,
                signature,
            ),
            DeltaReport(
                DeltaDiagnosis(False, "segment", 0, 1),
                self.key.public_key,
                signature,
            ),
            DeltaReport(
                DeltaDiagnosis(False, "leaf", 7, None),
                self.key.public_key,
                signature,
            ),
            DeltaReport(
                DeltaDiagnosis(False, "sig", 2, None),
                self.key.public_key,
                signature,
            ),
            DeltaReport(
                DeltaDiagnosis(False, "proof", 1, 2),
                self.key.public_key,
                signature,
            ),
            DeltaReport(
                DeltaDiagnosis(True, "ok", None, None), 0, signature
            ),
        )

    def test_wire_matches_independent_spec_build(self):
        for report in self._reports():
            with self.subTest(kind=report.diagnosis.kind):
                self.assertEqual(encode_dr(report), build_wire(report))
                self.assertTrue(encode_dr(report).startswith(WIRE_TAG))

    def test_round_trip_byte_for_byte(self):
        for report in self._reports():
            with self.subTest(kind=report.diagnosis.kind):
                blob = encode_dr(report)
                decoded = decode_dr(blob)
                self.assertEqual(decoded, report)
                self.assertEqual(encode_dr(decoded), blob)

    def test_zero_public_key_wire_form(self):
        report = [r for r in self._reports() if r.public_key == 0][0]
        blob = encode_dr(report)
        # tag (8) + D (32) + V(0)
        self.assertEqual(blob[40:45], b"\x00\x00\x00\x01\x00")

    def test_decode_non_bytes_type_error(self):
        for bad in ("x", bytearray(b"x"), None, 42, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                decode_dr(bad)

    def test_encode_non_report_type_error(self):
        for bad in ("x", None, 42, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_dr(bad)

    def test_encode_bad_field_types(self):
        good = self._reports()[0]
        for bad in (
            DeltaReport("x", good.public_key, good.signature),
            DeltaReport(good.diagnosis, "x", good.signature),
            DeltaReport(good.diagnosis, True, good.signature),
            DeltaReport(good.diagnosis, good.public_key, "x"),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_dr(bad)

    def test_encode_bad_structure_value_error(self):
        good = self._reports()[0]
        for bad in (
            DeltaReport(
                DeltaDiagnosis(False, "ok", None, None),
                good.public_key,
                good.signature,
            ),
            DeltaReport(good.diagnosis, -1, good.signature),
            DeltaReport(
                good.diagnosis,
                good.public_key,
                AggregateSignature(R=0, z=1, signer_ids=(1,)),
            ),
            DeltaReport(
                good.diagnosis,
                good.public_key,
                AggregateSignature(R=1, z=-1, signer_ids=(1,)),
            ),
            DeltaReport(
                good.diagnosis,
                good.public_key,
                AggregateSignature(R=1, z=1, signer_ids=()),
            ),
            DeltaReport(
                good.diagnosis,
                good.public_key,
                AggregateSignature(R=1, z=1, signer_ids=(2, 1)),
            ),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                encode_dr(bad)

    def test_decode_bad_tag_and_framing(self):
        blob = encode_dr(self._reports()[0])
        cases = (
            b"",
            WIRE_TAG,
            b"ts/dr/x1" + blob[len(WIRE_TAG):],
            blob[:-1],
            blob + b"\x00",
            blob[:39],
        )
        for bad in cases:
            with self.assertRaises(ValueError, msg=repr(bad[:12])):
                decode_dr(bad)

    def test_decode_bad_diagnosis_block(self):
        blob = encode_dr(self._reports()[0])
        # Flip the ok verdict 01 -> 00 while kind stays "ok".
        bad = blob[:15] + b"\x00" + blob[16:]
        with self.assertRaises(ValueError):
            decode_dr(bad)
        # Kind code out of range.
        bad = blob[:16] + b"\xff" + blob[17:]
        with self.assertRaises(ValueError):
            decode_dr(bad)
        # ok diagnosis must carry the absent sentinel in both index slots.
        bad = blob[:23] + b"\x01" + blob[24:]
        with self.assertRaises(ValueError):
            decode_dr(bad)

    def test_decode_non_canonical_varint(self):
        blob = encode_dr(self._reports()[0])
        length = int.from_bytes(blob[40:44], "big")
        # Inject a leading zero into the public key body.
        bad = (
            blob[:40]
            + (length + 1).to_bytes(4, "big")
            + b"\x00"
            + blob[44:]
        )
        with self.assertRaises(ValueError):
            decode_dr(bad)

    def test_decode_zero_signature_R(self):
        report = self._reports()[0]
        blob = bytearray(encode_dr(report))
        key_length = int.from_bytes(blob[40:44], "big")
        r_offset = 44 + key_length
        r_length = int.from_bytes(
            blob[r_offset:r_offset + 4], "big"
        )
        # Splice a canonical zero frame in place of the R frame.
        blob[r_offset:r_offset + 4 + r_length] = u32(1) + b"\x00"
        with self.assertRaises(ValueError):
            decode_dr(bytes(blob))


class VerifyDrTest(unittest.TestCase):
    def setUp(self):
        self.key, _r, _s, _d, self.segments = build_segments()
        self.diagnosis = DeltaDiagnosis(True, "ok", None, None)
        self.report = make_report(
            self.segments, self.diagnosis, self.key
        )

    def test_verifying_report_is_true(self):
        self.assertTrue(verify_dr(self.report, self.segments, self.key))

    def test_ok_matches_verifier(self):
        self.assertIs(
            verify_dr(self.report, self.segments, self.key),
            verify_delta_chain_segments(self.segments, self.key),
        )

    def test_report_for_failing_set_is_true(self):
        # A correctly signed report of a failing diagnosis verifies for
        # the exact failing set it describes.
        failing = (self.segments[1], self.segments[0])
        diagnosis = diagnose_delta_chain_segments(failing, self.key)
        self.assertEqual(
            diagnosis, DeltaDiagnosis(False, "leaf", 0, None)
        )
        report = make_report(failing, diagnosis, self.key)
        self.assertTrue(verify_dr(report, failing, self.key))
        # The same report presented over the verifying set is False.
        self.assertFalse(verify_dr(report, self.segments, self.key))

    def test_diagnosis_mismatch_is_false(self):
        for claimed in (
            DeltaDiagnosis(False, "sig", 0, None),
            DeltaDiagnosis(False, "leaf", 0, None),
            DeltaDiagnosis(False, "proof", 0, 0),
        ):
            with self.subTest(kind=claimed.kind):
                report = DeltaReport(
                    claimed,
                    self.report.public_key,
                    self.report.signature,
                )
                self.assertFalse(
                    verify_dr(report, self.segments, self.key)
                )

    def test_other_key_is_false(self):
        self.assertFalse(
            verify_dr(
                self.report, self.segments, make_other_key()
            )
        )

    def test_public_key_mismatch_is_false(self):
        report = DeltaReport(
            self.report.diagnosis,
            self.report.public_key + 1,
            self.report.signature,
        )
        self.assertFalse(verify_dr(report, self.segments, self.key))

    def test_tampered_signature_is_false(self):
        foreign = sign_message(self.key, b"unrelated", seed=7)
        report = DeltaReport(
            self.report.diagnosis, self.report.public_key, foreign
        )
        self.assertFalse(verify_dr(report, self.segments, self.key))

    def test_tampered_segments_is_false(self):
        segment = self.segments[1]
        batch = segment.additions[0]
        tampered_segment = AuditExtensionDeltaCheckpointChain(
            segment.first,
            ((b"\x00" * 32,) + batch[1:],) + segment.additions[1:],
            segment.signatures,
        )
        tampered = (self.segments[0], tampered_segment) + self.segments[2:]
        self.assertFalse(verify_dr(self.report, tampered, self.key))
        # And a report freshly built over the tampered set matches the
        # diagnoser's located failure.
        diagnosis = diagnose_delta_chain_segments(tampered, self.key)
        self.assertEqual(
            diagnosis, DeltaDiagnosis(False, "proof", 1, 1)
        )
        report = make_report(tampered, diagnosis, self.key)
        self.assertTrue(verify_dr(report, tampered, self.key))

    def test_segments_round_trip_keeps_verdict(self):
        blob = encode_delta_chain_segments(self.segments)
        restored = decode_delta_chain_segments(blob)
        self.assertTrue(verify_dr(self.report, restored, self.key))

    def test_non_report_type_error(self):
        for bad in ("x", None, 42, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_dr(bad, self.segments, self.key)

    def test_non_tuple_segments_type_error(self):
        for bad in (
            list(self.segments),
            self.segments[0],
            "x",
            None,
            42,
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_dr(self.report, bad, self.key)

    def test_non_key_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_dr(self.report, self.segments, bad)

    def test_empty_segments_value_error(self):
        with self.assertRaises(ValueError):
            verify_dr(self.report, (), self.key)

    def test_illegal_segment_value_error(self):
        good = self.segments[0]
        bad = AuditExtensionDeltaCheckpointChain(
            good.first, ((),) + good.additions[1:], good.signatures
        )
        with self.assertRaises(ValueError):
            verify_dr(self.report, (bad,), self.key)

    def test_illegal_report_value_error(self):
        bad = DeltaReport(
            DeltaDiagnosis(False, "ok", None, None),
            self.report.public_key,
            self.report.signature,
        )
        with self.assertRaises(ValueError):
            verify_dr(bad, self.segments, self.key)


if __name__ == "__main__":
    unittest.main()
