"""Tests for the canonical NonceReuse transport encoding:
encode_nonce_reuse / decode_nonce_reuse."""

import unittest

from thresholdsign import (
    NonceReuse,
    SigningAudit,
    decode_nonce_reuse,
    encode_nonce_reuse,
    find_nonce_reuse,
)

from test_nonce_reuse import make_key, make_record

WIRE_TAG = b"thresholdsign/nr/v1"


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def build_wire(item: NonceReuse) -> bytes:
    """Independently build the nonce-reuse wire format straight from the spec."""
    out = bytearray(WIRE_TAG)
    out += varint(item.signer_id)
    out += varint(item.nonce_commitment)
    out += u32(len(item.receipts))
    for receipt in item.receipts:
        out += frame(receipt.payload)
    return bytes(out)


def sample_finding():
    """A real NonceReuse finding: signer 1 reuses nonce 777 across messages."""
    key = make_key()
    record_a = make_record(key, b"first audited message", seed=100, nonces={1: 777})
    record_b = make_record(key, b"second audited message", seed=200, nonces={1: 777})
    findings = find_nonce_reuse([record_a, record_b], key)
    assert len(findings) == 1
    return findings[0]


class RoundTripTest(unittest.TestCase):
    def test_round_trip_real_finding(self):
        item = sample_finding()
        wire = encode_nonce_reuse(item)
        decoded = decode_nonce_reuse(wire)
        self.assertEqual(decoded, item)
        self.assertEqual(encode_nonce_reuse(decoded), wire)

    def test_encoding_matches_independent_builder(self):
        item = sample_finding()
        self.assertEqual(encode_nonce_reuse(item), build_wire(item))

    def test_layout(self):
        item = NonceReuse(1, 42, (SigningAudit(b"a"), SigningAudit(b"b")))
        wire = encode_nonce_reuse(item)
        self.assertTrue(wire.startswith(WIRE_TAG))
        offset = len(WIRE_TAG)
        # signer_id = 1 -> VARINT 00 00 00 01 01
        self.assertEqual(wire[offset:offset + 5], b"\x00\x00\x00\x01\x01")
        # nonce_commitment = 42 -> VARINT 00 00 00 01 2a
        self.assertEqual(wire[offset + 5:offset + 10], b"\x00\x00\x00\x01\x2a")
        # receipt count = 2
        self.assertEqual(wire[offset + 10:offset + 14], u32(2))
        self.assertEqual(
            wire[offset + 14:], frame(b"a") + frame(b"b")
        )

    def test_large_values(self):
        item = NonceReuse(
            2 ** 64,
            2 ** 127 - 1,
            (SigningAudit(b"\x00" * 300), SigningAudit(b"\x01" * 5)),
        )
        self.assertEqual(decode_nonce_reuse(encode_nonce_reuse(item)), item)

    def test_many_receipts(self):
        receipts = tuple(
            SigningAudit(bytes([i])) for i in range(2, 40)
        )
        item = NonceReuse(7, 9, receipts)
        self.assertEqual(decode_nonce_reuse(encode_nonce_reuse(item)), item)

    def test_encoding_is_unique_and_stateless(self):
        item = sample_finding()
        self.assertEqual(encode_nonce_reuse(item), encode_nonce_reuse(item))


class StructureOnlyTest(unittest.TestCase):
    def test_decode_does_not_parse_receipts_or_verify_reuse(self):
        # Opaque, non-receipt payloads decode fine; no reuse check happens.
        item = NonceReuse(3, 5, (SigningAudit(b"x"), SigningAudit(b"y")))
        decoded = decode_nonce_reuse(encode_nonce_reuse(item))
        self.assertEqual(decoded.receipts[0].payload, b"x")
        self.assertEqual(decoded, item)


class EncodeValidationTest(unittest.TestCase):
    def test_non_item_type_error(self):
        with self.assertRaises(TypeError):
            encode_nonce_reuse(("not", "a", "finding"))

    def test_field_type_errors(self):
        good = NonceReuse(1, 42, (SigningAudit(b"a"), SigningAudit(b"b")))
        for bad in (
            NonceReuse(True, 42, good.receipts),
            NonceReuse("1", 42, good.receipts),
            NonceReuse(1, True, good.receipts),
            NonceReuse(1, "42", good.receipts),
            NonceReuse(1, 42, [SigningAudit(b"a"), SigningAudit(b"b")]),
            NonceReuse(1, 42, (SigningAudit(b"a"), "b")),
            NonceReuse(1, 42, (SigningAudit(bytearray(b"a")), SigningAudit(b"b"))),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_nonce_reuse(bad)

    def test_value_errors(self):
        a, b, c = (SigningAudit(p) for p in (b"a", b"b", b"c"))
        for bad in (
            NonceReuse(0, 42, (a, b)),
            NonceReuse(-1, 42, (a, b)),
            NonceReuse(1, 0, (a, b)),
            NonceReuse(1, -2, (a, b)),
            NonceReuse(1, 42, ()),
            NonceReuse(1, 42, (a,)),
            NonceReuse(1, 42, (SigningAudit(b""), a)),
            NonceReuse(1, 42, (a, SigningAudit(b""))),
            NonceReuse(1, 42, (b, a)),  # out of order
            NonceReuse(1, 42, (a, a)),  # duplicate
            NonceReuse(1, 42, (b, b, a)),
            NonceReuse(1, 42, (a, c, b)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                encode_nonce_reuse(bad)


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.item = NonceReuse(
            1, 42, (SigningAudit(b"a"), SigningAudit(b"b"), SigningAudit(b"c"))
        )
        self.wire = encode_nonce_reuse(self.item)

    def test_non_bytes_type_error(self):
        with self.assertRaises(TypeError):
            decode_nonce_reuse("not bytes")
        with self.assertRaises(TypeError):
            decode_nonce_reuse(bytearray(self.wire))

    def test_bad_tag(self):
        bad = b"thresholdsign/nr/v2" + self.wire[len(WIRE_TAG):]
        with self.assertRaises(ValueError):
            decode_nonce_reuse(bad)
        with self.assertRaises(ValueError):
            decode_nonce_reuse(b"x" + self.wire[1:])

    def test_truncation(self):
        for cut in range(len(WIRE_TAG), len(self.wire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_nonce_reuse(self.wire[:cut])

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_nonce_reuse(self.wire + b"\x00")

    def test_non_positive_integers(self):
        for signer_id, commitment in ((0, 42), (1, 0), (0, 0)):
            out = bytearray(WIRE_TAG)
            out += varint(signer_id) + varint(commitment)
            out += u32(2) + frame(b"a") + frame(b"b")
            with self.assertRaises(ValueError):
                decode_nonce_reuse(bytes(out))

    def test_non_canonical_varint(self):
        # signer_id = 1 with a leading zero body.
        out = bytearray(WIRE_TAG)
        out += (2).to_bytes(4, "big") + b"\x00\x01"
        out += varint(42)
        out += u32(2) + frame(b"a") + frame(b"b")
        with self.assertRaises(ValueError):
            decode_nonce_reuse(bytes(out))

    def test_too_few_receipts(self):
        for count, frames in (
            (0, b""),
            (1, frame(b"a")),
        ):
            out = bytearray(WIRE_TAG)
            out += varint(1) + varint(42)
            out += u32(count) + frames
            with self.assertRaises(ValueError):
                decode_nonce_reuse(bytes(out))

    def test_count_mismatch(self):
        # Count claims three, only two frames follow.
        out = bytearray(WIRE_TAG)
        out += varint(1) + varint(42)
        out += u32(3) + frame(b"a") + frame(b"b")
        with self.assertRaises(ValueError):
            decode_nonce_reuse(bytes(out))

    def test_empty_payload_rejected(self):
        out = bytearray(WIRE_TAG)
        out += varint(1) + varint(42)
        out += u32(2) + frame(b"") + frame(b"b")
        with self.assertRaises(ValueError):
            decode_nonce_reuse(bytes(out))

    def test_duplicate_and_out_of_order_payloads(self):
        for count, frames in (
            (2, frame(b"a") + frame(b"a")),
            (2, frame(b"b") + frame(b"a")),
            (3, frame(b"a") + frame(b"c") + frame(b"b")),
        ):
            out = bytearray(WIRE_TAG)
            out += varint(1) + varint(42)
            out += u32(count)
            out += frames
            with self.assertRaises(ValueError, msg=repr(frames)):
                decode_nonce_reuse(bytes(out))


if __name__ == "__main__":
    unittest.main()
