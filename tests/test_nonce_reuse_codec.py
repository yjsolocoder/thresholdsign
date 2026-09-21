"""Tests for the canonical NonceReuse transport encoding:
encode_nonce_reuse / decode_nonce_reuse."""

import dataclasses
import unittest

from thresholdsign import (
    NonceReuse,
    SigningAudit,
    decode_nonce_reuse,
    encode_nonce_reuse,
    find_nonce_reuse,
)

from test_nonce_reuse import (
    MESSAGE_A,
    MESSAGE_B,
    MESSAGE_C,
    make_key,
    make_record,
)

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


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()

    def test_round_trip_real_findings(self):
        record_a = make_record(self.key, MESSAGE_A, seed=100, nonces={1: 777})
        record_b = make_record(self.key, MESSAGE_B, seed=200, nonces={1: 777})
        finding = find_nonce_reuse([record_a, record_b], self.key)[0]
        wire = encode_nonce_reuse(finding)
        decoded = decode_nonce_reuse(wire)
        self.assertEqual(decoded, finding)
        self.assertEqual(encode_nonce_reuse(decoded), wire)
        self.assertIsInstance(decoded, NonceReuse)
        self.assertEqual(decoded.signer_id, finding.signer_id)
        self.assertEqual(decoded.nonce_commitment, finding.nonce_commitment)

    def test_encoding_matches_independent_builder(self):
        item = NonceReuse(
            7,
            2**33 + 1,
            (SigningAudit(b"a"), SigningAudit(b"ab"), SigningAudit(b"b")),
        )
        self.assertEqual(encode_nonce_reuse(item), build_wire(item))

    def test_starts_with_tag_and_layout(self):
        item = NonceReuse(1, 42, (SigningAudit(b"a"), SigningAudit(b"b")))
        wire = encode_nonce_reuse(item)
        self.assertTrue(wire.startswith(WIRE_TAG))
        offset = len(WIRE_TAG)
        # signer_id 1 -> VARINT 00 00 00 01 01
        self.assertEqual(wire[offset:offset + 5], b"\x00\x00\x00\x01\x01")
        # nonce_commitment 42 -> 00 00 00 01 2a
        self.assertEqual(wire[offset + 5:offset + 10], b"\x00\x00\x00\x01\x2a")
        # receipt count 2
        self.assertEqual(wire[offset + 10:offset + 14], u32(2))
        # then U32(1) a U32(1) b
        self.assertEqual(wire[offset + 14:], u32(1) + b"a" + u32(1) + b"b")

    def test_large_commitment_round_trips(self):
        commitment = (1 << 200) - 123457
        item = NonceReuse(
            3,
            commitment,
            (SigningAudit(b"first"), SigningAudit(b"second")),
        )
        decoded = decode_nonce_reuse(encode_nonce_reuse(item))
        self.assertEqual(decoded, item)
        self.assertEqual(
            encode_nonce_reuse(item),
            WIRE_TAG
            + varint(3)
            + varint(commitment)
            + u32(2)
            + frame(b"first")
            + frame(b"second"),
        )

    def test_three_receipts_round_trip(self):
        record_a = make_record(self.key, MESSAGE_A, seed=100, nonces={1: 555})
        record_b = make_record(self.key, MESSAGE_B, seed=200, nonces={1: 555})
        record_c = make_record(self.key, MESSAGE_C, seed=300, nonces={1: 555})
        finding = find_nonce_reuse(
            [record_c, record_a, record_b, record_a], self.key
        )[0]
        self.assertEqual(len(finding.receipts), 3)
        decoded = decode_nonce_reuse(encode_nonce_reuse(finding))
        self.assertEqual(decoded, finding)

    def test_encoding_is_unique_and_stateless(self):
        item = NonceReuse(1, 42, (SigningAudit(b"a"), SigningAudit(b"b")))
        self.assertEqual(encode_nonce_reuse(item), encode_nonce_reuse(item))


class StructureOnlyTest(unittest.TestCase):
    def test_receipts_kept_opaque_and_reuse_not_verified(self):
        # Two arbitrary, distinct non-audit bytes are accepted as-is: the
        # codec neither parses the receipts nor checks that any reuse exists.
        item = NonceReuse(
            9,
            3,
            (SigningAudit(b"not-an-audit"), SigningAudit(b"still-not")),
        )
        decoded = decode_nonce_reuse(encode_nonce_reuse(item))
        self.assertEqual(decoded, item)
        self.assertEqual(decoded.receipts[0].payload, b"not-an-audit")


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.item = NonceReuse(
            1, 42, (SigningAudit(b"a"), SigningAudit(b"b"))
        )

    def test_non_item_type_error(self):
        with self.assertRaises(TypeError):
            encode_nonce_reuse(("not", "a", "finding"))
        with self.assertRaises(TypeError):
            encode_nonce_reuse(SigningAudit(b"a"))

    def test_field_type_errors(self):
        item = self.item
        for bad in (
            dataclasses.replace(item, signer_id=True),
            dataclasses.replace(item, signer_id="1"),
            dataclasses.replace(item, signer_id=1.0),
            dataclasses.replace(item, nonce_commitment=True),
            dataclasses.replace(item, nonce_commitment="42"),
            dataclasses.replace(
                item, receipts=[SigningAudit(b"a"), SigningAudit(b"b")]
            ),
            dataclasses.replace(
                item, receipts=(SigningAudit(b"a"), b"b")
            ),
            dataclasses.replace(
                item,
                receipts=(
                    SigningAudit(b"a"),
                    SigningAudit(bytearray(b"b")),
                ),
            ),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_nonce_reuse(bad)

    def test_value_errors(self):
        item = self.item
        for bad in (
            dataclasses.replace(item, signer_id=0),
            dataclasses.replace(item, signer_id=-1),
            dataclasses.replace(item, nonce_commitment=0),
            dataclasses.replace(item, nonce_commitment=-2),
            NonceReuse(1, 42, (SigningAudit(b"a"),)),
            NonceReuse(1, 42, ()),
            NonceReuse(1, 42, (SigningAudit(b""), SigningAudit(b"b"))),
            NonceReuse(1, 42, (SigningAudit(b"b"), SigningAudit(b"a"))),
            NonceReuse(1, 42, (SigningAudit(b"a"), SigningAudit(b"a"))),
            NonceReuse(
                1,
                42,
                (
                    SigningAudit(b"a"),
                    SigningAudit(b"c"),
                    SigningAudit(b"b"),
                ),
            ),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                encode_nonce_reuse(bad)


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.item = NonceReuse(
            1, 42, (SigningAudit(b"a"), SigningAudit(b"b"))
        )
        self.wire = encode_nonce_reuse(self.item)

    def test_non_bytes_type_error(self):
        with self.assertRaises(TypeError):
            decode_nonce_reuse("not bytes")
        with self.assertRaises(TypeError):
            decode_nonce_reuse(bytearray(self.wire))

    def test_bad_tag(self):
        with self.assertRaises(ValueError):
            decode_nonce_reuse(
                b"thresholdsign/nr/v2" + self.wire[len(WIRE_TAG):]
            )
        with self.assertRaises(ValueError):
            decode_nonce_reuse(b"x" + self.wire[1:])

    def test_truncation(self):
        for cut in range(len(WIRE_TAG), len(self.wire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_nonce_reuse(self.wire[:cut])

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_nonce_reuse(self.wire + b"\x00")

    def test_zero_signer_id_and_commitment_rejected(self):
        out = bytearray(WIRE_TAG)
        out += varint(0)
        out += varint(self.item.nonce_commitment)
        out += u32(2)
        out += frame(b"a") + frame(b"b")
        with self.assertRaises(ValueError):
            decode_nonce_reuse(bytes(out))

        out = bytearray(WIRE_TAG)
        out += varint(self.item.signer_id)
        out += varint(0)
        out += u32(2)
        out += frame(b"a") + frame(b"b")
        with self.assertRaises(ValueError):
            decode_nonce_reuse(bytes(out))

    def test_less_than_two_receipts_rejected(self):
        for count in (0, 1):
            out = bytearray(WIRE_TAG)
            out += varint(self.item.signer_id)
            out += varint(self.item.nonce_commitment)
            out += u32(count)
            if count:
                out += frame(b"a")
            with self.assertRaises(ValueError, msg=f"count={count}"):
                decode_nonce_reuse(bytes(out))

    def test_count_mismatch(self):
        # Declares three receipts but carries two.
        prefix = self.wire[: len(WIRE_TAG) + 10]
        body = self.wire[len(WIRE_TAG) + 14 :]
        with self.assertRaises(ValueError):
            decode_nonce_reuse(prefix + u32(3) + body)
        # Declares two but carries three.
        with self.assertRaises(ValueError):
            decode_nonce_reuse(prefix + u32(2) + body + frame(b"c"))

    def test_empty_receipt_rejected(self):
        out = bytearray(WIRE_TAG)
        out += varint(self.item.signer_id)
        out += varint(self.item.nonce_commitment)
        out += u32(2)
        out += frame(b"") + frame(b"b")
        with self.assertRaises(ValueError):
            decode_nonce_reuse(bytes(out))

    def test_duplicate_or_unordered_receipts_rejected(self):
        base = bytearray(WIRE_TAG)
        base += varint(self.item.signer_id)
        base += varint(self.item.nonce_commitment)
        base += u32(2)
        ordered = bytes(base) + frame(b"a") + frame(b"b")
        self.assertEqual(decode_nonce_reuse(ordered), self.item)

        duplicate = bytes(base) + frame(b"a") + frame(b"a")
        with self.assertRaises(ValueError):
            decode_nonce_reuse(duplicate)

        reversed_order = bytes(base) + frame(b"b") + frame(b"a")
        with self.assertRaises(ValueError):
            decode_nonce_reuse(reversed_order)

    def test_non_canonical_varint_leading_zero(self):
        body = self.wire[len(WIRE_TAG):]
        # signer_id VARINT at offset 0: replace its 00 00 00 01 01 with a
        # two-byte body carrying a forbidden leading zero.
        bad = WIRE_TAG + u32(2) + b"\x00\x01" + body[5:]
        with self.assertRaises(ValueError):
            decode_nonce_reuse(bad)

    def test_oversized_frame_rejected(self):
        # Frame length that runs past the end of the blob.
        out = bytearray(WIRE_TAG)
        out += varint(self.item.signer_id)
        out += varint(self.item.nonce_commitment)
        out += u32(2)
        out += u32(0xFFFFFFFF) + b"a"
        with self.assertRaises(ValueError):
            decode_nonce_reuse(bytes(out))


if __name__ == "__main__":
    unittest.main()
