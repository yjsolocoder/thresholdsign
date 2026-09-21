"""Tests for the canonical batched NonceLeak transport:
NonceLeakReport / encode_nonce_leak_report / decode_nonce_leak_report /
verify_nonce_leak_report."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    NonceLeak,
    NonceLeakReport,
    SigningAudit,
    decode_nonce_leak,
    decode_nonce_leak_report,
    encode_nonce_leak,
    encode_nonce_leak_report,
    recover_leaks,
    verify_nonce_leak,
    verify_nonce_leak_report,
)

from test_nonce_reuse import (
    FIELD_PRIME,
    MESSAGE_A,
    MESSAGE_B,
    MESSAGE_C,
    MESSAGE_D,
    make_key,
    make_record,
)
from test_nonce_leak_codec import (
    WIRE_TAG as LEAK_TAG,
    build_wire as build_leak_wire,
    make_other_key,
)

REPORT_TAG = b"thresholdsign/nlr/v1"


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def build_report_wire(items) -> bytes:
    """Independently build the report wire format straight from the spec."""
    out = bytearray(REPORT_TAG)
    out += u32(len(items))
    for item in items:
        x = build_leak_wire(item)
        out += frame(x)
    return bytes(out)


def make_leak(key, message_pair=(MESSAGE_A, MESSAGE_B), nonce=777, signer=1):
    """A real NonceLeak recovered from two reused-nonce records."""
    nonces = {signer: nonce}
    record_a = make_record(key, message_pair[0], nonces=nonces)
    record_b = make_record(key, message_pair[1], nonces=nonces)
    leaks = recover_leaks([record_a, record_b], key)
    return next(leak for leak in leaks if leak.signer_id == signer)


def sorted_by_key(items):
    return tuple(sorted(items, key=lambda item: (item.signer_id, item.commitment)))


def make_report(key):
    """A two-item report over the same key: two distinct signer-1 leaks."""
    first = make_leak(key, (MESSAGE_A, MESSAGE_B), nonce=777)
    second = make_leak(key, (MESSAGE_C, MESSAGE_D), nonce=888)
    return NonceLeakReport(sorted_by_key((first, second)))


def make_three_item_report(key):
    """A three-item report spanning two different signers."""
    leak_1a = make_leak(key, (MESSAGE_A, MESSAGE_B), nonce=777, signer=1)
    leak_1b = make_leak(key, (MESSAGE_C, MESSAGE_D), nonce=888, signer=1)
    leak_3 = make_leak(key, (MESSAGE_A, MESSAGE_B), nonce=555, signer=3)
    return NonceLeakReport(sorted_by_key((leak_1a, leak_1b, leak_3)))


class ValueSemanticsTest(unittest.TestCase):
    def test_positional_construction_and_equality(self):
        item = NonceLeak(1, 42, 7, (SigningAudit(b"a"), SigningAudit(b"b")))
        report = NonceLeakReport((item,))
        self.assertEqual(report, NonceLeakReport((item,)))
        self.assertEqual(report.items, (item,))
        self.assertNotEqual(report, NonceLeakReport(()))
        self.assertNotEqual(report, (item,))

    def test_frozen(self):
        report = NonceLeakReport(
            (NonceLeak(1, 42, 7, (SigningAudit(b"a"), SigningAudit(b"b"))),)
        )
        with self.assertRaises(FrozenInstanceError):
            report.items = ()


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()

    def test_round_trip_real_report(self):
        report = make_report(self.key)
        wire = encode_nonce_leak_report(report)
        decoded = decode_nonce_leak_report(wire)
        self.assertEqual(decoded, report)
        self.assertIsInstance(decoded, NonceLeakReport)
        self.assertEqual(encode_nonce_leak_report(decoded), wire)
        self.assertEqual(len(decoded.items), 2)
        self.assertTrue(all(isinstance(item, NonceLeak) for item in decoded.items))

    def test_round_trip_three_items_two_signers(self):
        report = make_three_item_report(self.key)
        decoded = decode_nonce_leak_report(encode_nonce_leak_report(report))
        self.assertEqual(decoded, report)

    def test_each_decoded_item_round_trips_through_single_codec(self):
        report = make_report(self.key)
        wire = encode_nonce_leak_report(report)
        decoded = decode_nonce_leak_report(wire)
        for original, item in zip(report.items, decoded.items):
            self.assertEqual(item, original)
            self.assertEqual(encode_nonce_leak(item), encode_nonce_leak(original))
            self.assertEqual(decode_nonce_leak(encode_nonce_leak(item)), item)

    def test_encoding_matches_independent_builder(self):
        report = make_report(self.key)
        self.assertEqual(
            encode_nonce_leak_report(report), build_report_wire(report.items)
        )

    def test_starts_with_tag_and_layout(self):
        first = NonceLeak(1, 42, 7, (SigningAudit(b"a"), SigningAudit(b"b")))
        second = NonceLeak(2, 9, 3, (SigningAudit(b"c"), SigningAudit(b"d")))
        report = NonceLeakReport((first, second))
        wire = encode_nonce_leak_report(report)
        self.assertTrue(wire.startswith(REPORT_TAG))
        offset = len(REPORT_TAG)
        self.assertEqual(wire[offset:offset + 4], u32(2))
        offset += 4
        nested_first = build_leak_wire(first)
        self.assertEqual(wire[offset:offset + 4], u32(len(nested_first)))
        offset += 4
        self.assertEqual(wire[offset:offset + len(nested_first)], nested_first)
        offset += len(nested_first)
        nested_second = build_leak_wire(second)
        self.assertEqual(wire[offset:offset + 4], u32(len(nested_second)))
        offset += 4
        self.assertEqual(wire[offset:offset + len(nested_second)], nested_second)
        self.assertEqual(offset + len(nested_second), len(wire))

    def test_order_is_preserved_not_sorted(self):
        # Ordering is by the (signer_id, commitment) pair, not by signer
        # alone: (1, large) followed by (2, small) is increasing and the
        # exact item order must survive.
        first = NonceLeak(
            1, 2**33 + 1, 7, (SigningAudit(b"a"), SigningAudit(b"ab"))
        )
        second = NonceLeak(
            2, 3, 11, (SigningAudit(b"c"), SigningAudit(b"cd"))
        )
        report = NonceLeakReport((first, second))
        decoded = decode_nonce_leak_report(encode_nonce_leak_report(report))
        self.assertEqual(decoded.items, (first, second))

    def test_opaque_nested_payloads_not_parsed_or_verified(self):
        # Arbitrary nested receipt bytes ride along untouched; neither the
        # nested receipts nor the leak claims are checked at decode time.
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

    def test_encoding_is_unique_and_stateless(self):
        report = make_report(self.key)
        self.assertEqual(
            encode_nonce_leak_report(report), encode_nonce_leak_report(report)
        )


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.item = NonceLeak(
            1, 42, 7, (SigningAudit(b"a"), SigningAudit(b"b"))
        )

    def test_non_report_type_error(self):
        with self.assertRaises(TypeError):
            encode_nonce_leak_report((self.item,))
        with self.assertRaises(TypeError):
            encode_nonce_leak_report(self.item)
        with self.assertRaises(TypeError):
            encode_nonce_leak_report(SigningAudit(b"a"))
        with self.assertRaises(TypeError):
            encode_nonce_leak_report(None)

    def test_items_not_tuple_type_error(self):
        with self.assertRaises(TypeError):
            encode_nonce_leak_report(NonceLeakReport([self.item]))
        with self.assertRaises(TypeError):
            encode_nonce_leak_report(NonceLeakReport(iter((self.item,))))

    def test_non_leak_element_type_error(self):
        with self.assertRaises(TypeError):
            encode_nonce_leak_report(NonceLeakReport(("not a leak",)))
        with self.assertRaises(TypeError):
            encode_nonce_leak_report(NonceLeakReport((self.item, b"x")))

    def test_nested_bool_field_type_error(self):
        bad = dataclasses.replace(self.item, share=True)
        with self.assertRaises(TypeError):
            encode_nonce_leak_report(NonceLeakReport((bad,)))

    def test_empty_report_value_error(self):
        with self.assertRaises(ValueError):
            encode_nonce_leak_report(NonceLeakReport(()))

    def test_out_of_order_keys_value_error(self):
        second = NonceLeak(
            1, 43, 7, (SigningAudit(b"c"), SigningAudit(b"d"))
        )
        with self.assertRaises(ValueError):
            encode_nonce_leak_report(NonceLeakReport((second, self.item)))
        # A smaller commitment under the same signer after a larger one.
        big = NonceLeak(
            2, 100, 7, (SigningAudit(b"c"), SigningAudit(b"d"))
        )
        small = NonceLeak(
            2, 99, 7, (SigningAudit(b"e"), SigningAudit(b"f"))
        )
        with self.assertRaises(ValueError):
            encode_nonce_leak_report(NonceLeakReport((big, small)))

    def test_duplicate_key_value_error(self):
        duplicate = NonceLeak(
            1, 42, 99, (SigningAudit(b"c"), SigningAudit(b"d"))
        )
        with self.assertRaises(ValueError):
            encode_nonce_leak_report(NonceLeakReport((self.item, duplicate)))

    def test_nested_structure_value_error(self):
        bad = NonceLeak(1, 42, 7, (SigningAudit(b"a"),))
        with self.assertRaises(ValueError):
            encode_nonce_leak_report(NonceLeakReport((bad,)))
        bad = NonceLeak(
            1, 42, 7,
            (SigningAudit(b"a"), SigningAudit(b"b"), SigningAudit(b"c")),
        )
        with self.assertRaises(ValueError):
            encode_nonce_leak_report(NonceLeakReport((bad,)))


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.report = make_report(self.key)
        self.wire = encode_nonce_leak_report(self.report)

    def test_non_bytes_type_error(self):
        with self.assertRaises(TypeError):
            decode_nonce_leak_report("not bytes")
        with self.assertRaises(TypeError):
            decode_nonce_leak_report(bytearray(self.wire))

    def test_bad_tag(self):
        with self.assertRaises(ValueError):
            decode_nonce_leak_report(
                b"thresholdsign/nlr/v2" + self.wire[len(REPORT_TAG):]
            )
        with self.assertRaises(ValueError):
            decode_nonce_leak_report(b"x" + self.wire[1:])

    def test_truncation(self):
        for cut in range(len(REPORT_TAG), len(self.wire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_nonce_leak_report(self.wire[:cut])

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_nonce_leak_report(self.wire + b"\x00")

    def test_zero_item_count_rejected(self):
        body = self.wire[len(REPORT_TAG) + 4:]
        with self.assertRaises(ValueError):
            decode_nonce_leak_report(REPORT_TAG + u32(0) + body)

    def test_count_smaller_than_frames(self):
        # Declared count 1 but two complete frames follow -> trailing bytes.
        with self.assertRaises(ValueError):
            decode_nonce_leak_report(
                REPORT_TAG + u32(1) + self.wire[len(REPORT_TAG) + 4:]
            )

    def test_count_larger_than_frames(self):
        # Declared count 3 but only two frames follow -> truncation.
        with self.assertRaises(ValueError):
            decode_nonce_leak_report(
                REPORT_TAG + u32(3) + self.wire[len(REPORT_TAG) + 4:]
            )

    def test_zero_length_frame_rejected(self):
        nested = build_leak_wire(self.report.items[0])
        bad = REPORT_TAG + u32(1) + u32(0) + nested
        with self.assertRaises(ValueError):
            decode_nonce_leak_report(bad)

    def test_nested_bad_tag_rejected(self):
        offset = len(REPORT_TAG) + 4
        wire = bytearray(self.wire)
        # First byte of the first nested frame body is its tag.
        wire[offset + 4] ^= 0xFF
        with self.assertRaises(ValueError):
            decode_nonce_leak_report(bytes(wire))

    def test_nested_truncated_frame_rejected(self):
        nested = build_leak_wire(self.report.items[0])
        # Frame length announces the full item but one nested byte is
        # missing, then the blob ends: report-level truncation.
        bad = REPORT_TAG + u32(1) + u32(len(nested)) + nested[:-1]
        with self.assertRaises(ValueError):
            decode_nonce_leak_report(bad)
        # Frame itself shortened: the nested decoder sees a partial item.
        bad = REPORT_TAG + u32(1) + frame(nested[:-1])
        with self.assertRaises(ValueError):
            decode_nonce_leak_report(bad)

    def test_nested_non_canonical_integer_rejected(self):
        nested = bytearray(build_leak_wire(self.report.items[0]))
        # signer_id VARINT sits right after the nested tag; replace its
        # 00 00 00 01 <body> prefix with a two-byte leading-zero body.
        pos = len(LEAK_TAG)
        nested[pos:pos + 5] = u32(2) + b"\x00\x01"
        bad = REPORT_TAG + u32(1) + frame(bytes(nested))
        with self.assertRaises(ValueError):
            decode_nonce_leak_report(bad)

    def test_duplicate_key_rejected(self):
        item = self.report.items[0]
        nested = build_leak_wire(item)
        bad = REPORT_TAG + u32(2) + frame(nested) + frame(nested)
        with self.assertRaises(ValueError):
            decode_nonce_leak_report(bad)

    def test_out_of_order_keys_rejected(self):
        first = build_leak_wire(self.report.items[0])
        second = build_leak_wire(self.report.items[1])
        keys = sorted(
            (item.signer_id, item.commitment) for item in self.report.items
        )
        self.assertLess(keys[0], keys[1])
        bad = REPORT_TAG + u32(2) + frame(second) + frame(first)
        with self.assertRaises(ValueError):
            decode_nonce_leak_report(bad)

    def test_nested_receipt_order_violation_rejected(self):
        # Illegal even when the outer report keys are fine: nesting must be
        # canonical too.
        bad_nested_item = NonceLeak(
            1, 42, 7, (SigningAudit(b"b"), SigningAudit(b"a"))
        )
        wire = REPORT_TAG + u32(1) + frame(build_leak_wire(bad_nested_item))
        # build_leak_wire serializes raw; decoding must reject it.
        with self.assertRaises(ValueError):
            decode_nonce_leak_report(wire)


class VerifyReportTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.report = make_three_item_report(self.key)

    def test_real_report_verifies(self):
        self.assertTrue(verify_nonce_leak_report(self.report, self.key))

    def test_decoded_report_verifies(self):
        decoded = decode_nonce_leak_report(
            encode_nonce_leak_report(self.report)
        )
        self.assertTrue(verify_nonce_leak_report(decoded, self.key))

    def test_one_tampered_item_returns_false(self):
        items = list(self.report.items)
        items[1] = dataclasses.replace(
            items[1], share=(items[1].share + 1) % FIELD_PRIME
        )
        # Tampering the share keeps the keys ordered; verification must not.
        bad_report = NonceLeakReport(tuple(items))
        self.assertFalse(verify_nonce_leak_report(bad_report, self.key))
        # Every other item still verifies on its own.
        self.assertTrue(verify_nonce_leak(items[0], self.key))
        self.assertTrue(verify_nonce_leak(items[2], self.key))

    def test_other_key_returns_false(self):
        other_key = make_other_key()
        self.assertNotEqual(other_key.public_key, self.key.public_key)
        self.assertFalse(verify_nonce_leak_report(self.report, other_key))

    def test_non_report_type_error(self):
        with self.assertRaises(TypeError):
            verify_nonce_leak_report(self.report.items, self.key)
        with self.assertRaises(TypeError):
            verify_nonce_leak_report(None, self.key)

    def test_items_not_tuple_type_error(self):
        with self.assertRaises(TypeError):
            verify_nonce_leak_report(
                NonceLeakReport(list(self.report.items)), self.key
            )

    def test_non_leak_element_type_error(self):
        with self.assertRaises(TypeError):
            verify_nonce_leak_report(
                NonceLeakReport(("not a leak",)), self.key
            )

    def test_nested_bool_field_type_error(self):
        items = list(self.report.items)
        items[0] = dataclasses.replace(items[0], share=True)
        with self.assertRaises(TypeError):
            verify_nonce_leak_report(NonceLeakReport(tuple(items)), self.key)

    def test_empty_report_value_error(self):
        with self.assertRaises(ValueError):
            verify_nonce_leak_report(NonceLeakReport(()), self.key)

    def test_out_of_order_keys_value_error(self):
        items = self.report.items
        reversed_report = NonceLeakReport(items[::-1])
        with self.assertRaises(ValueError):
            verify_nonce_leak_report(reversed_report, self.key)

    def test_duplicate_key_value_error(self):
        items = self.report.items
        with self.assertRaises(ValueError):
            verify_nonce_leak_report(
                NonceLeakReport((items[0], items[0])), self.key
            )

    def test_nested_structure_value_error(self):
        bad_item = NonceLeak(
            self.report.items[0].signer_id,
            self.report.items[0].commitment,
            self.report.items[0].share,
            self.report.items[0].receipts[:1],
        )
        with self.assertRaises(ValueError):
            verify_nonce_leak_report(
                NonceLeakReport((bad_item,)), self.key
            )

    def test_wrong_key_type_error(self):
        with self.assertRaises(TypeError):
            verify_nonce_leak_report(self.report, "key")
        with self.assertRaises(TypeError):
            verify_nonce_leak_report(self.report, None)


if __name__ == "__main__":
    unittest.main()
