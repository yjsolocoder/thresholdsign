"""Tests for the canonical NonceLeak transport encoding and the key-only
leak verifier: encode_nonce_leak / decode_nonce_leak / verify_nonce_leak."""

import dataclasses
import unittest

from thresholdsign import (
    NonceLeak,
    SignatureShare,
    SigningAudit,
    aggregate_signing_dkg,
    create_audit,
    create_signing_contribution,
    decode_nonce_leak,
    encode_nonce_leak,
    recover_leaks,
    verify_nonce_leak,
)

from test_nonce_reuse import (
    BLINDING_GENERATOR,
    FIELD_PRIME,
    GROUP_PRIME,
    GENERATOR,
    MESSAGE_A,
    MESSAGE_B,
    fixed_random,
    make_key,
    make_record,
    make_round,
)

WIRE_TAG = b"thresholdsign/nl/v1"


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def build_wire(item: NonceLeak) -> bytes:
    """Independently build the nonce-leak wire format straight from the spec."""
    out = bytearray(WIRE_TAG)
    out += varint(item.signer_id)
    out += varint(item.commitment)
    out += varint(item.share)
    out += u32(2)
    for receipt in item.receipts:
        out += frame(receipt.payload)
    return bytes(out)


def make_leak(key, nonce=777):
    """A real NonceLeak for signer 1 recovered from two reused-nonce records."""
    record_a = make_record(key, MESSAGE_A, seed=100, nonces={1: nonce})
    record_b = make_record(key, MESSAGE_B, seed=200, nonces={1: nonce})
    return recover_leaks([record_a, record_b], key)[0]


def make_other_key(participant_ids=(1, 2, 3), threshold=2):
    """A different key over the same toy group (different randomness)."""
    contributions = [
        create_signing_contribution(
            pid,
            participant_ids,
            threshold,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            blinding_generator=BLINDING_GENERATOR,
            randbelow=fixed_random(1000 + pid),
        )
        for pid in participant_ids
    ]
    return aggregate_signing_dkg(contributions)


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()

    def test_round_trip_real_finding(self):
        leak = make_leak(self.key)
        wire = encode_nonce_leak(leak)
        decoded = decode_nonce_leak(wire)
        self.assertEqual(decoded, leak)
        self.assertEqual(encode_nonce_leak(decoded), wire)
        self.assertIsInstance(decoded, NonceLeak)
        self.assertEqual(decoded.signer_id, leak.signer_id)
        self.assertEqual(decoded.commitment, leak.commitment)
        self.assertEqual(decoded.share, leak.share)

    def test_encoding_matches_independent_builder(self):
        item = NonceLeak(
            7,
            2**33 + 1,
            2**40 + 3,
            (SigningAudit(b"a"), SigningAudit(b"ab")),
        )
        self.assertEqual(encode_nonce_leak(item), build_wire(item))

    def test_starts_with_tag_and_layout(self):
        item = NonceLeak(1, 42, 7, (SigningAudit(b"a"), SigningAudit(b"b")))
        wire = encode_nonce_leak(item)
        self.assertTrue(wire.startswith(WIRE_TAG))
        offset = len(WIRE_TAG)
        # signer_id 1 -> VARINT 00 00 00 01 01
        self.assertEqual(wire[offset:offset + 5], b"\x00\x00\x00\x01\x01")
        # commitment 42 -> 00 00 00 01 2a
        self.assertEqual(wire[offset + 5:offset + 10], b"\x00\x00\x00\x01\x2a")
        # share 7 -> 00 00 00 01 07
        self.assertEqual(wire[offset + 10:offset + 15], b"\x00\x00\x00\x01\x07")
        # constant receipt count 2
        self.assertEqual(wire[offset + 15:offset + 19], u32(2))
        # then U32(1) a U32(1) b
        self.assertEqual(wire[offset + 19:], u32(1) + b"a" + u32(1) + b"b")

    def test_zero_share_round_trips(self):
        item = NonceLeak(1, 42, 0, (SigningAudit(b"a"), SigningAudit(b"b")))
        wire = encode_nonce_leak(item)
        # share 0 -> VARINT with the single body byte 00
        offset = len(WIRE_TAG) + 10
        self.assertEqual(wire[offset:offset + 5], b"\x00\x00\x00\x01\x00")
        self.assertEqual(decode_nonce_leak(wire), item)

    def test_large_fields_round_trip(self):
        item = NonceLeak(
            3,
            (1 << 200) - 123457,
            (1 << 160) + 987654321,
            (SigningAudit(b"first"), SigningAudit(b"second")),
        )
        decoded = decode_nonce_leak(encode_nonce_leak(item))
        self.assertEqual(decoded, item)
        self.assertEqual(encode_nonce_leak(item), build_wire(item))

    def test_encoding_is_unique_and_stateless(self):
        item = NonceLeak(1, 42, 7, (SigningAudit(b"a"), SigningAudit(b"b")))
        self.assertEqual(encode_nonce_leak(item), encode_nonce_leak(item))


class StructureOnlyTest(unittest.TestCase):
    def test_receipts_kept_opaque_and_leak_not_verified(self):
        # Two arbitrary, distinct non-audit bytes are accepted as-is: the
        # codec neither parses the receipts nor checks that any leak exists.
        item = NonceLeak(
            9,
            3,
            11,
            (SigningAudit(b"not-an-audit"), SigningAudit(b"still-not")),
        )
        decoded = decode_nonce_leak(encode_nonce_leak(item))
        self.assertEqual(decoded, item)
        self.assertEqual(decoded.receipts[0].payload, b"not-an-audit")


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.item = NonceLeak(1, 42, 7, (SigningAudit(b"a"), SigningAudit(b"b")))

    def test_non_item_type_error(self):
        with self.assertRaises(TypeError):
            encode_nonce_leak(("not", "a", "finding"))
        with self.assertRaises(TypeError):
            encode_nonce_leak(SigningAudit(b"a"))

    def test_field_type_errors(self):
        item = self.item
        for bad in (
            dataclasses.replace(item, signer_id=True),
            dataclasses.replace(item, signer_id="1"),
            dataclasses.replace(item, signer_id=1.0),
            dataclasses.replace(item, commitment=True),
            dataclasses.replace(item, commitment="42"),
            dataclasses.replace(item, share=True),
            dataclasses.replace(item, share="7"),
            dataclasses.replace(
                item, receipts=[SigningAudit(b"a"), SigningAudit(b"b")]
            ),
            dataclasses.replace(item, receipts=(SigningAudit(b"a"), b"b")),
            dataclasses.replace(
                item,
                receipts=(
                    SigningAudit(b"a"),
                    SigningAudit(bytearray(b"b")),
                ),
            ),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_nonce_leak(bad)

    def test_value_errors(self):
        item = self.item
        for bad in (
            dataclasses.replace(item, signer_id=0),
            dataclasses.replace(item, signer_id=-1),
            dataclasses.replace(item, commitment=0),
            dataclasses.replace(item, commitment=-2),
            dataclasses.replace(item, share=-1),
            NonceLeak(1, 42, 7, (SigningAudit(b"a"),)),
            NonceLeak(1, 42, 7, ()),
            NonceLeak(
                1,
                42,
                7,
                (SigningAudit(b"a"), SigningAudit(b"b"), SigningAudit(b"c")),
            ),
            NonceLeak(1, 42, 7, (SigningAudit(b""), SigningAudit(b"b"))),
            NonceLeak(1, 42, 7, (SigningAudit(b"b"), SigningAudit(b"a"))),
            NonceLeak(1, 42, 7, (SigningAudit(b"a"), SigningAudit(b"a"))),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                encode_nonce_leak(bad)


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.item = NonceLeak(1, 42, 7, (SigningAudit(b"a"), SigningAudit(b"b")))
        self.wire = encode_nonce_leak(self.item)

    def test_non_bytes_type_error(self):
        with self.assertRaises(TypeError):
            decode_nonce_leak("not bytes")
        with self.assertRaises(TypeError):
            decode_nonce_leak(bytearray(self.wire))

    def test_bad_tag(self):
        with self.assertRaises(ValueError):
            decode_nonce_leak(
                b"thresholdsign/nl/v2" + self.wire[len(WIRE_TAG):]
            )
        with self.assertRaises(ValueError):
            decode_nonce_leak(b"x" + self.wire[1:])

    def test_truncation(self):
        for cut in range(len(WIRE_TAG), len(self.wire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_nonce_leak(self.wire[:cut])

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_nonce_leak(self.wire + b"\x00")

    def test_zero_signer_id_and_commitment_rejected(self):
        out = bytearray(WIRE_TAG)
        out += varint(0)
        out += varint(self.item.commitment)
        out += varint(self.item.share)
        out += u32(2)
        out += frame(b"a") + frame(b"b")
        with self.assertRaises(ValueError):
            decode_nonce_leak(bytes(out))

        out = bytearray(WIRE_TAG)
        out += varint(self.item.signer_id)
        out += varint(0)
        out += varint(self.item.share)
        out += u32(2)
        out += frame(b"a") + frame(b"b")
        with self.assertRaises(ValueError):
            decode_nonce_leak(bytes(out))

    def test_receipt_count_other_than_two_rejected(self):
        for count in (0, 1, 3):
            out = bytearray(WIRE_TAG)
            out += varint(self.item.signer_id)
            out += varint(self.item.commitment)
            out += varint(self.item.share)
            out += u32(count)
            out += frame(b"a") + frame(b"b")
            with self.assertRaises(ValueError, msg=f"count={count}"):
                decode_nonce_leak(bytes(out))

    def test_empty_receipt_rejected(self):
        out = bytearray(WIRE_TAG)
        out += varint(self.item.signer_id)
        out += varint(self.item.commitment)
        out += varint(self.item.share)
        out += u32(2)
        out += frame(b"") + frame(b"b")
        with self.assertRaises(ValueError):
            decode_nonce_leak(bytes(out))

    def test_duplicate_or_unordered_receipts_rejected(self):
        base = bytearray(WIRE_TAG)
        base += varint(self.item.signer_id)
        base += varint(self.item.commitment)
        base += varint(self.item.share)
        base += u32(2)
        ordered = bytes(base) + frame(b"a") + frame(b"b")
        self.assertEqual(decode_nonce_leak(ordered), self.item)

        duplicate = bytes(base) + frame(b"a") + frame(b"a")
        with self.assertRaises(ValueError):
            decode_nonce_leak(duplicate)

        reversed_order = bytes(base) + frame(b"b") + frame(b"a")
        with self.assertRaises(ValueError):
            decode_nonce_leak(reversed_order)

    def test_non_canonical_varint_leading_zero(self):
        body = self.wire[len(WIRE_TAG):]
        # signer_id VARINT at offset 0: replace its 00 00 00 01 01 with a
        # two-byte body carrying a forbidden leading zero.
        bad = WIRE_TAG + u32(2) + b"\x00\x01" + body[5:]
        with self.assertRaises(ValueError):
            decode_nonce_leak(bad)

    def test_oversized_frame_rejected(self):
        # Frame length that runs past the end of the blob.
        out = bytearray(WIRE_TAG)
        out += varint(self.item.signer_id)
        out += varint(self.item.commitment)
        out += varint(self.item.share)
        out += u32(2)
        out += u32(0xFFFFFFFF) + b"a"
        with self.assertRaises(ValueError):
            decode_nonce_leak(bytes(out))


class VerifyNonceLeakTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.leak = make_leak(self.key)

    def test_real_leak_verifies(self):
        self.assertTrue(verify_nonce_leak(self.leak, self.key))

    def test_decoded_leak_verifies(self):
        decoded = decode_nonce_leak(encode_nonce_leak(self.leak))
        self.assertTrue(verify_nonce_leak(decoded, self.key))

    def test_verification_share_matches(self):
        self.assertEqual(
            pow(GENERATOR, self.leak.share, GROUP_PRIME),
            self.key.verification_shares[0],
        )

    def test_tampered_share_returns_false(self):
        bad = dataclasses.replace(
            self.leak, share=(self.leak.share + 1) % FIELD_PRIME
        )
        self.assertFalse(verify_nonce_leak(bad, self.key))

    def test_tampered_commitment_returns_false(self):
        bad = dataclasses.replace(self.leak, commitment=self.leak.commitment + 1)
        self.assertFalse(verify_nonce_leak(bad, self.key))

    def test_distinct_commitments_return_false(self):
        # Two valid status-1 receipts without nonce reuse: the row
        # commitments differ, so no share can be solved out.
        record_a = make_record(self.key, MESSAGE_A, seed=100, nonces={1: 111})
        record_b = make_record(self.key, MESSAGE_B, seed=200, nonces={1: 222})
        receipts = tuple(sorted((record_a[1], record_b[1]), key=lambda a: a.payload))
        item = NonceLeak(1, pow(GENERATOR, 111, GROUP_PRIME), 7, receipts)
        self.assertFalse(verify_nonce_leak(item, self.key))

    def test_failed_status_receipt_returns_false(self):
        round_info, shares = make_round(
            self.key, MESSAGE_B, seed=200, nonces={1: 777}
        )
        bad = SignatureShare(
            signer_id=shares[0].signer_id,
            nonce_commitment=shares[0].nonce_commitment,
            z=(shares[0].z + 1) % FIELD_PRIME,
        )
        failing = create_audit(MESSAGE_B, [bad, shares[1]], round_info, self.key)
        passing = make_record(self.key, MESSAGE_A, seed=100, nonces={1: 777})[1]
        receipts = tuple(sorted((passing, failing), key=lambda a: a.payload))
        item = NonceLeak(
            1, pow(GENERATOR, 777, GROUP_PRIME), self.leak.share, receipts
        )
        self.assertFalse(verify_nonce_leak(item, self.key))

    def test_equal_coefficients_return_false(self):
        # Two distinct messages whose challenges collide over the same
        # signer set give a1 == a2: no invertible pair, claim unverifiable.
        by_challenge = {}
        pair = None
        for index in range(500):
            message = b"collision hunt " + str(index).encode()
            round_info, shares = make_round(
                self.key, message, seed=100, nonces={1: 777}
            )
            receipt = create_audit(message, shares, round_info, self.key)
            if round_info.challenge in by_challenge:
                pair = (by_challenge[round_info.challenge], receipt)
                break
            by_challenge[round_info.challenge] = receipt
        self.assertIsNotNone(pair)
        receipts = tuple(sorted(pair, key=lambda a: a.payload))
        item = NonceLeak(
            1, pow(GENERATOR, 777, GROUP_PRIME), self.leak.share, receipts
        )
        self.assertFalse(verify_nonce_leak(item, self.key))

    def test_other_key_returns_false(self):
        other_key = make_other_key()
        self.assertNotEqual(other_key.public_key, self.key.public_key)
        self.assertFalse(verify_nonce_leak(self.leak, other_key))

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            verify_nonce_leak("item", self.key)
        with self.assertRaises(TypeError):
            verify_nonce_leak(self.leak, "key")
        with self.assertRaises(TypeError):
            verify_nonce_leak(self.leak, None)
        with self.assertRaises(TypeError):
            verify_nonce_leak(
                dataclasses.replace(self.leak, share=True), self.key
            )
        with self.assertRaises(TypeError):
            verify_nonce_leak(
                dataclasses.replace(self.leak, receipts=list(self.leak.receipts)),
                self.key,
            )

    def test_structure_errors(self):
        with self.assertRaises(ValueError):
            verify_nonce_leak(dataclasses.replace(self.leak, share=-1), self.key)
        with self.assertRaises(ValueError):
            verify_nonce_leak(
                dataclasses.replace(self.leak, signer_id=0), self.key
            )
        with self.assertRaises(ValueError):
            verify_nonce_leak(
                dataclasses.replace(self.leak, commitment=0), self.key
            )
        with self.assertRaises(ValueError):
            verify_nonce_leak(
                dataclasses.replace(self.leak, receipts=self.leak.receipts[:1]),
                self.key,
            )
        # Receipts out of payload order.
        with self.assertRaises(ValueError):
            verify_nonce_leak(
                dataclasses.replace(
                    self.leak, receipts=self.leak.receipts[::-1]
                ),
                self.key,
            )
        # A signer that is not a DKG participant.
        with self.assertRaises(ValueError):
            verify_nonce_leak(dataclasses.replace(self.leak, signer_id=4), self.key)
        # A structurally illegal receipt payload.
        with self.assertRaises(ValueError):
            verify_nonce_leak(
                dataclasses.replace(
                    self.leak,
                    receipts=(
                        SigningAudit(self.leak.receipts[0].payload[:-1]),
                        self.leak.receipts[1],
                    ),
                ),
                self.key,
            )
        # Receipt rows naming a non-participant signer.
        other_key = make_key(participant_ids=(1, 2, 4))
        with self.assertRaises(ValueError):
            verify_nonce_leak(self.leak, other_key)


if __name__ == "__main__":
    unittest.main()
