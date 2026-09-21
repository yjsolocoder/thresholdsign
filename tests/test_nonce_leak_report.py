"""Tests for the canonical batched NonceLeak transport encoding and the
key-only batch verifier: NonceLeakReport / encode_nonce_leak_report /
decode_nonce_leak_report / verify_nonce_leak_report."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    NonceLeak,
    NonceLeakReport,
    SigningAudit,
    decode_nonce_leak_report,
    encode_nonce_leak,
    encode_nonce_leak_report,
    recover_leaks,
    verify_nonce_leak_report,
)

from test_nonce_reuse import (
    FIELD_PRIME,
    MESSAGE_A,
    MESSAGE_B,
    make_key,
    make_record,
)
from test_nonce_leak_codec import make_leak, make_other_key

WIRE_TAG = b"thresholdsign/nlr/v1"
NL_WIRE_TAG = b"thresholdsign/nl/v1"


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def build_wire(report: NonceLeakReport) -> bytes:
    """Independently build the nonce-leak-report wire format from the spec."""
    out = bytearray(WIRE_TAG)
    out += u32(len(report.items))
    for item in report.items:
        out += frame(encode_nonce_leak(item))
    return bytes(out)


def make_leak_for(key, signer: int, nonce: int):
    """A real NonceLeak for ``signer`` recovered from reused-nonce records."""
    record_a = make_record(
        key, MESSAGE_A + bytes([signer]), seed=100 + signer, nonces={signer: nonce}
    )
    record_b = make_record(
        key, MESSAGE_B + bytes([signer]), seed=200 + signer, nonces={signer: nonce}
    )
    return recover_leaks([record_a, record_b], key)[0]


def synthetic(signer_id, commitment, share=7):
    return NonceLeak(
        signer_id,
        commitment,
        share,
        (
            SigningAudit(f"a-{signer_id}-{commitment}".encode()),
            SigningAudit(f"b-{signer_id}-{commitment}".encode()),
        ),
    )


class NonceLeakReportValueTest(unittest.TestCase):
    def test_frozen_fields_value_equality(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(NonceLeakReport)],
            ["items"],
        )
        a = synthetic(1, 10)
        b = synthetic(2, 20)
        report = NonceLeakReport((a, b))  # positional construction
        self.assertEqual(report, NonceLeakReport((a, b)))
        self.assertEqual(report, NonceLeakReport(items=(a, b)))
        self.assertEqual(report.items, (a, b))
        self.assertNotEqual(report, NonceLeakReport((a,)))
        self.assertEqual(hash(report), hash(NonceLeakReport((a, b))))
        with self.assertRaises(FrozenInstanceError):
            report.items = (a,)

    def test_construction_does_not_validate(self):
        # The container is a plain value: empty, unordered and non-tuple
        # contents all construct; the codecs and verifier reject them.
        NonceLeakReport(())
        a = synthetic(2, 20)
        b = synthetic(1, 10)
        NonceLeakReport((a, b))
        NonceLeakReport([a])


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.leak = make_leak(self.key)

    def test_round_trip_single_real_finding(self):
        report = NonceLeakReport((self.leak,))
        wire = encode_nonce_leak_report(report)
        decoded = decode_nonce_leak_report(wire)
        self.assertEqual(decoded, report)
        self.assertEqual(encode_nonce_leak_report(decoded), wire)
        self.assertIsInstance(decoded, NonceLeakReport)
        self.assertEqual(decoded.items, (self.leak,))

    def test_round_trip_multiple_real_findings(self):
        # make_record rows cover signers (1, 3), so recover leaks for both.
        first = make_leak_for(self.key, 1, 777)
        second = make_leak_for(self.key, 3, 555)
        report = NonceLeakReport((first, second))
        wire = encode_nonce_leak_report(report)
        self.assertEqual(decode_nonce_leak_report(wire), report)
        self.assertEqual(encode_nonce_leak_report(decode_nonce_leak_report(wire)), wire)

    def test_encoding_matches_independent_builder(self):
        report = NonceLeakReport(
            (synthetic(1, 10), synthetic(1, 11), synthetic(2, 1))
        )
        self.assertEqual(encode_nonce_leak_report(report), build_wire(report))

    def test_starts_with_tag_and_layout(self):
        item = synthetic(1, 42)
        wire = encode_nonce_leak_report(NonceLeakReport((item,)))
        self.assertTrue(wire.startswith(WIRE_TAG))
        offset = len(WIRE_TAG)
        self.assertEqual(wire[offset:offset + 4], u32(1))
        offset += 4
        nested = encode_nonce_leak(item)
        self.assertEqual(wire[offset:], u32(len(nested)) + nested)

    def test_large_findings_round_trip(self):
        item = NonceLeak(
            3,
            (1 << 200) - 123457,
            (1 << 160) + 987654321,
            (SigningAudit(b"first"), SigningAudit(b"second")),
        )
        report = NonceLeakReport((item,))
        self.assertEqual(
            decode_nonce_leak_report(encode_nonce_leak_report(report)), report
        )

    def test_encoding_is_unique_and_stateless(self):
        report = NonceLeakReport((synthetic(1, 10), synthetic(2, 20)))
        self.assertEqual(
            encode_nonce_leak_report(report), encode_nonce_leak_report(report)
        )

    def test_encode_does_not_sort(self):
        # The wire preserves the tuple order; the reordering must be
        # rejected, not silently fixed.
        first = make_leak_for(self.key, 1, 777)
        second = make_leak_for(self.key, 3, 555)
        with self.assertRaises(ValueError):
            encode_nonce_leak_report(NonceLeakReport((second, first)))


class StructureOnlyTest(unittest.TestCase):
    def test_nested_receipts_kept_opaque_and_leaks_not_verified(self):
        item = NonceLeak(
            9,
            3,
            11,
            (SigningAudit(b"not-an-audit"), SigningAudit(b"still-not")),
        )
        report = NonceLeakReport((item,))
        decoded = decode_nonce_leak_report(encode_nonce_leak_report(report))
        self.assertEqual(decoded, report)
        self.assertEqual(decoded.items[0].receipts[0].payload, b"not-an-audit")


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.item = synthetic(1, 10)
        self.other = synthetic(2, 20)
        self.report = NonceLeakReport((self.item, self.other))

    def test_non_report_type_error(self):
        with self.assertRaises(TypeError):
            encode_nonce_leak_report((self.item,))
        with self.assertRaises(TypeError):
            encode_nonce_leak_report(SigningAudit(b"a"))
        with self.assertRaises(TypeError):
            encode_nonce_leak_report(self.item)

    def test_items_type_errors(self):
        for bad_items in (
            [self.item],
            "x",
            (self.item, "not-a-leak"),
            None,
            True,
        ):
            with self.assertRaises(TypeError, msg=repr(bad_items)):
                encode_nonce_leak_report(NonceLeakReport(bad_items))

    def test_nested_field_type_errors(self):
        bad = dataclasses.replace(self.item, signer_id=True)
        with self.assertRaises(TypeError):
            encode_nonce_leak_report(NonceLeakReport((bad, self.other)))
        bad = dataclasses.replace(
            self.item,
            receipts=[SigningAudit(b"a"), SigningAudit(b"b")],
        )
        with self.assertRaises(TypeError):
            encode_nonce_leak_report(NonceLeakReport((bad,)))

    def test_empty_report_value_error(self):
        with self.assertRaises(ValueError):
            encode_nonce_leak_report(NonceLeakReport(()))

    def test_unordered_or_duplicate_keys_value_error(self):
        a1 = synthetic(1, 10)
        a2 = synthetic(1, 11)
        b1 = synthetic(2, 1)
        for items in (
            (a2, a1),           # same signer, commitment descending
            (b1, a1),           # signer descending
            (a1, a1),           # duplicate key
            (a1, synthetic(1, 10, share=9)),  # duplicate key, other fields
            (a2, b1, a1),       # not globally sorted
        ):
            with self.assertRaises(ValueError, msg=repr(items)):
                encode_nonce_leak_report(NonceLeakReport(items))

    def test_nested_structure_value_error(self):
        bad = dataclasses.replace(self.item, signer_id=0)
        with self.assertRaises(ValueError):
            encode_nonce_leak_report(NonceLeakReport((bad,)))
        bad = NonceLeak(
            1, 10, 7, (SigningAudit(b"a"), SigningAudit(b"a"))
        )
        with self.assertRaises(ValueError):
            encode_nonce_leak_report(NonceLeakReport((bad,)))


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.item = synthetic(1, 10)
        self.wire = encode_nonce_leak_report(NonceLeakReport((self.item,)))

    def test_non_bytes_type_error(self):
        with self.assertRaises(TypeError):
            decode_nonce_leak_report("not bytes")
        with self.assertRaises(TypeError):
            decode_nonce_leak_report(bytearray(self.wire))

    def test_bad_tag(self):
        with self.assertRaises(ValueError):
            decode_nonce_leak_report(
                b"thresholdsign/nlr/v2" + self.wire[len(WIRE_TAG):]
            )
        with self.assertRaises(ValueError):
            decode_nonce_leak_report(b"x" + self.wire[1:])

    def test_truncation(self):
        for cut in range(len(WIRE_TAG), len(self.wire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_nonce_leak_report(self.wire[:cut])

    def test_header_truncation(self):
        with self.assertRaises(ValueError):
            decode_nonce_leak_report(WIRE_TAG)
        with self.assertRaises(ValueError):
            decode_nonce_leak_report(WIRE_TAG + b"\x00\x00")

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_nonce_leak_report(self.wire + b"\x00")

    def test_zero_count_rejected(self):
        with self.assertRaises(ValueError):
            decode_nonce_leak_report(WIRE_TAG + u32(0))

    def test_count_mismatch_rejected(self):
        nested = encode_nonce_leak(self.item)
        body = u32(len(nested)) + nested
        # Declares more items than frames follow.
        with self.assertRaises(ValueError):
            decode_nonce_leak_report(WIRE_TAG + u32(2) + body)
        # Declares fewer items than frames follow.
        second = encode_nonce_leak(synthetic(2, 20))
        with self.assertRaises(ValueError):
            decode_nonce_leak_report(
                WIRE_TAG + u32(1) + body + u32(len(second)) + second
            )

    def test_zero_or_oversized_frame_rejected(self):
        with self.assertRaises(ValueError):
            decode_nonce_leak_report(WIRE_TAG + u32(1) + u32(0))
        with self.assertRaises(ValueError):
            decode_nonce_leak_report(
                WIRE_TAG + u32(1) + u32(0xFFFFFFFF) + b"a"
            )

    def test_frame_truncated_mid_body(self):
        nested = encode_nonce_leak(self.item)
        with self.assertRaises(ValueError):
            decode_nonce_leak_report(
                WIRE_TAG + u32(1) + u32(len(nested)) + nested[:-1]
            )

    def test_nested_bad_tag_rejected(self):
        with self.assertRaises(ValueError):
            decode_nonce_leak_report(
                WIRE_TAG + u32(1) + frame(NL_WIRE_TAG + b"/v2")
            )

    def test_nested_non_canonical_rejected(self):
        # Replace the nested signer_id VARINT (00 00 00 01 01) with a
        # two-byte body carrying a forbidden leading zero.
        nested = encode_nonce_leak(self.item)
        offset = len(NL_WIRE_TAG)
        bad_nested = (
            nested[:offset] + u32(2) + b"\x00\x01" + nested[offset + 5:]
        )
        with self.assertRaises(ValueError):
            decode_nonce_leak_report(WIRE_TAG + u32(1) + frame(bad_nested))

    def test_unordered_or_duplicate_decoded_keys_rejected(self):
        first = synthetic(1, 10)
        second = synthetic(2, 20)
        reversed_wire = (
            WIRE_TAG
            + u32(2)
            + frame(encode_nonce_leak(second))
            + frame(encode_nonce_leak(first))
        )
        with self.assertRaises(ValueError):
            decode_nonce_leak_report(reversed_wire)

        nested = encode_nonce_leak(first)
        with self.assertRaises(ValueError):
            decode_nonce_leak_report(
                WIRE_TAG + u32(2) + frame(nested) + frame(nested)
            )

    def test_nested_trailing_bytes_rejected(self):
        # The outer frame grows by one byte; the nested decoder sees
        # trailing bytes and must refuse the non-canonical frame body.
        nested = encode_nonce_leak(self.item)
        with self.assertRaises(ValueError):
            decode_nonce_leak_report(
                WIRE_TAG + u32(1) + u32(len(nested) + 1) + nested + b"\x00"
            )


class VerifyNonceLeakReportTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.first = make_leak_for(self.key, 1, 777)
        self.second = make_leak_for(self.key, 3, 555)
        self.report = NonceLeakReport((self.first, self.second))

    def test_real_report_verifies(self):
        self.assertTrue(verify_nonce_leak_report(self.report, self.key))

    def test_single_finding_report_verifies(self):
        self.assertTrue(
            verify_nonce_leak_report(NonceLeakReport((self.first,)), self.key)
        )

    def test_decoded_report_verifies(self):
        decoded = decode_nonce_leak_report(encode_nonce_leak_report(self.report))
        self.assertTrue(verify_nonce_leak_report(decoded, self.key))

    def test_one_tampered_finding_returns_false(self):
        tampered = dataclasses.replace(
            self.second, share=(self.second.share + 1) % FIELD_PRIME
        )
        self.assertFalse(
            verify_nonce_leak_report(
                NonceLeakReport((self.first, tampered)), self.key
            )
        )

    def test_other_key_returns_false(self):
        other_key = make_other_key()
        self.assertNotEqual(other_key.public_key, self.key.public_key)
        self.assertFalse(verify_nonce_leak_report(self.report, other_key))

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            verify_nonce_leak_report((self.first,), self.key)
        with self.assertRaises(TypeError):
            verify_nonce_leak_report("report", self.key)
        with self.assertRaises(TypeError):
            verify_nonce_leak_report(
                NonceLeakReport([self.first]), self.key
            )
        with self.assertRaises(TypeError):
            verify_nonce_leak_report(self.report, "key")
        with self.assertRaises(TypeError):
            verify_nonce_leak_report(self.report, None)

    def test_structure_errors(self):
        with self.assertRaises(ValueError):
            verify_nonce_leak_report(NonceLeakReport(()), self.key)
        with self.assertRaises(ValueError):
            verify_nonce_leak_report(
                NonceLeakReport((self.second, self.first)), self.key
            )
        with self.assertRaises(ValueError):
            verify_nonce_leak_report(
                NonceLeakReport((self.first, self.first)), self.key
            )
        # Ordering is checked before verification: an unordered report
        # containing a non-participant still raises rather than returns.
        foreign = dataclasses.replace(self.first, signer_id=42)
        with self.assertRaises(ValueError):
            verify_nonce_leak_report(
                NonceLeakReport((foreign, self.second)), self.key
            )


if __name__ == "__main__":
    unittest.main()
