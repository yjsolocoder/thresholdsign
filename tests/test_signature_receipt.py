"""Tests for the self-contained SignatureReceipt and its codec."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    SignatureReceipt,
    aggregate_signature,
    create_signature_receipt,
    decode_signature_receipt,
    encode_signature_receipt,
    verify_signature,
    verify_signature_receipt,
)
from tests.test_signing import (
    FIELD_PRIME,
    GENERATOR,
    GROUP_PRIME,
    LARGE_FIELD,
    LARGE_G,
    LARGE_GROUP,
    LARGE_H,
    MESSAGE,
    make_round,
    make_shares,
    make_signing_dkg,
)


def make_receipt(dkg=None, signer_ids=(1, 2), message=MESSAGE):
    dkg = dkg or make_signing_dkg()
    round_info, _commitments, nonces = make_round(dkg, signer_ids, message)
    shares = make_shares(dkg, round_info, nonces)
    signature = aggregate_signature(shares, round_info, dkg)
    assert isinstance(signature, AggregateSignature)
    receipt = create_signature_receipt(message, signature, dkg)
    return dkg, signature, receipt


class CreateSignatureReceiptTest(unittest.TestCase):
    def test_fields_come_from_dkg_and_signature(self):
        dkg, signature, receipt = make_receipt()
        self.assertIsInstance(receipt, SignatureReceipt)
        self.assertEqual(receipt.message, MESSAGE)
        self.assertEqual(receipt.signature, signature)
        self.assertEqual(receipt.public_key, dkg.public_key)
        self.assertEqual(receipt.field_prime, FIELD_PRIME)
        self.assertEqual(receipt.group_prime, GROUP_PRIME)
        self.assertEqual(receipt.generator, GENERATOR)

    def test_large_group(self):
        dkg = make_signing_dkg(
            (1, 2, 3), 2,
            field_prime=LARGE_FIELD, group_prime=LARGE_GROUP,
            generator=LARGE_G, blinding_generator=LARGE_H,
        )
        _dkg, _signature, receipt = make_receipt(dkg)
        self.assertTrue(verify_signature_receipt(receipt))
        self.assertEqual(receipt.field_prime, LARGE_FIELD)
        self.assertEqual(receipt.group_prime, LARGE_GROUP)
        self.assertEqual(receipt.generator, LARGE_G)

    def test_empty_message(self):
        _dkg, _signature, receipt = make_receipt(message=b"")
        self.assertTrue(verify_signature_receipt(receipt))

    def test_binary_message(self):
        _dkg, _signature, receipt = make_receipt(message=bytes(range(256)))
        self.assertTrue(verify_signature_receipt(receipt))

    def test_nonconsecutive_signers_and_threshold_one(self):
        dkg = make_signing_dkg((1, 2, 3, 4), 2)
        _dkg, _sig, receipt = make_receipt(dkg, signer_ids=(2, 4))
        self.assertEqual(receipt.signature.signer_ids, (2, 4))
        self.assertTrue(verify_signature_receipt(receipt))

        dkg1 = make_signing_dkg((1, 2), 1)
        _dkg, _sig, receipt1 = make_receipt(dkg1, signer_ids=(1,))
        self.assertTrue(verify_signature_receipt(receipt1))

    def test_frozen_and_no_secret_fields(self):
        _dkg, _signature, receipt = make_receipt()
        with self.assertRaises(FrozenInstanceError):
            receipt.public_key = 1  # type: ignore[misc]
        self.assertEqual(
            {f.name for f in dataclasses.fields(receipt)},
            {"message", "signature", "public_key", "field_prime",
             "group_prime", "generator"},
        )
        self.assertFalse(hasattr(receipt, "dkg_result"))
        self.assertFalse(hasattr(receipt, "nonce"))
        self.assertFalse(hasattr(receipt, "secret_share"))

    def test_bad_signature_raises_value_error(self):
        dkg, signature, _receipt = make_receipt()
        bad = dataclasses.replace(signature, z=(signature.z + 1) % FIELD_PRIME)
        with self.assertRaises(ValueError):
            create_signature_receipt(MESSAGE, bad, dkg)
        # Signature for a different message.
        with self.assertRaises(ValueError):
            create_signature_receipt(b"another message", signature, dkg)
        # Signature under a different key.
        other_dkg = make_signing_dkg(seed_base=5000)
        with self.assertRaises(ValueError):
            create_signature_receipt(MESSAGE, signature, other_dkg)

    def test_wrong_types_raise_type_error(self):
        dkg, signature, _receipt = make_receipt()
        with self.assertRaises(TypeError):
            create_signature_receipt("not bytes", signature, dkg)
        with self.assertRaises(TypeError):
            create_signature_receipt(MESSAGE, (signature.R, signature.z), dkg)
        with self.assertRaises(TypeError):
            create_signature_receipt(MESSAGE, signature, "not a dkg")
        with self.assertRaises(TypeError):
            create_signature_receipt(MESSAGE, signature, object())

    def test_bool_is_not_an_integer(self):
        dkg, signature, _receipt = make_receipt()
        bad = dataclasses.replace(dkg, public_key=True)
        with self.assertRaises(TypeError):
            create_signature_receipt(MESSAGE, signature, bad)
        bad_sig = dataclasses.replace(signature, z=True)
        with self.assertRaises(TypeError):
            create_signature_receipt(MESSAGE, bad_sig, dkg)


class SignatureReceiptCodecTest(unittest.TestCase):
    def setUp(self):
        self.dkg, self.signature, self.receipt = make_receipt()

    def test_round_trip_is_byte_exact(self):
        blob = encode_signature_receipt(self.receipt)
        self.assertIsInstance(blob, bytes)
        decoded = decode_signature_receipt(blob)
        self.assertEqual(decoded, self.receipt)
        self.assertTrue(verify_signature_receipt(decoded))
        # Re-encoding a decoded receipt must reproduce the exact bytes.
        self.assertEqual(encode_signature_receipt(decoded), blob)
        # Deterministic: same input always yields the same bytes.
        self.assertEqual(encode_signature_receipt(self.receipt), blob)

    def test_starts_with_tag(self):
        blob = encode_signature_receipt(self.receipt)
        self.assertTrue(blob.startswith(b"thresholdsign/signature-receipt/v1"))

    def test_round_trip_empty_and_binary_message(self):
        for message in (b"", bytes(range(256)), b"\x00" * 1000):
            dkg, _sig, receipt = make_receipt(message=message)
            blob = encode_signature_receipt(receipt)
            decoded = decode_signature_receipt(blob)
            self.assertEqual(decoded, receipt)
            self.assertEqual(encode_signature_receipt(decoded), blob)

    def test_encoding_carries_no_secret_material(self):
        # Rebuild the encoding solely from the receipt's public fields: any
        # extra byte would mean a share, nonce or other hidden state leaked.
        from thresholdsign import SIGNATURE_RECEIPT_TAG

        def varint(value):
            body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
            return len(body).to_bytes(4, "big") + body

        r = self.receipt
        expected = bytearray(SIGNATURE_RECEIPT_TAG)
        expected += len(r.message).to_bytes(4, "big") + r.message
        for value in (r.field_prime, r.group_prime, r.generator,
                      r.public_key, r.signature.R, r.signature.z):
            expected += varint(value)
        expected += len(r.signature.signer_ids).to_bytes(4, "big")
        for signer_id in r.signature.signer_ids:
            expected += varint(signer_id)
        self.assertEqual(encode_signature_receipt(r), bytes(expected))

    def test_decode_non_bytes_raises_type_error(self):
        with self.assertRaises(TypeError):
            decode_signature_receipt("bytes only")
        with self.assertRaises(TypeError):
            decode_signature_receipt(bytearray(b"x"))
        with self.assertRaises(TypeError):
            decode_signature_receipt(None)

    def test_bad_tag_raises_value_error(self):
        blob = encode_signature_receipt(self.receipt)
        with self.assertRaises(ValueError):
            decode_signature_receipt(b"x" + blob)
        with self.assertRaises(ValueError):
            decode_signature_receipt(b"")
        with self.assertRaises(ValueError):
            decode_signature_receipt(blob[:10])

    def test_truncation_raises_value_error(self):
        blob = encode_signature_receipt(self.receipt)
        for cut in range(len(blob) - 1):
            # Byte-exact prefixes are all structurally incomplete.
            with self.assertRaises(ValueError):
                decode_signature_receipt(blob[:cut])

    def test_trailing_bytes_raise_value_error(self):
        blob = encode_signature_receipt(self.receipt)
        with self.assertRaises(ValueError):
            decode_signature_receipt(blob + b"\x00")
        with self.assertRaises(ValueError):
            decode_signature_receipt(blob + b"tail")

    def test_declared_message_length_too_large(self):
        blob = bytearray(encode_signature_receipt(self.receipt))
        tag_len = len(b"thresholdsign/signature-receipt/v1")
        declared = int.from_bytes(blob[tag_len:tag_len + 4], "big")
        blob[tag_len + 3] = (declared + 1) & 0xFF
        with self.assertRaises(ValueError):
            decode_signature_receipt(bytes(blob))

    def test_non_canonical_integer_raises_value_error(self):
        blob = bytearray(encode_signature_receipt(self.receipt))
        # Find the first length-prefixed integer after the message.
        tag_len = len(b"thresholdsign/signature-receipt/v1")
        message_length = int.from_bytes(blob[tag_len:tag_len + 4], "big")
        first_int_len = tag_len + 4 + message_length
        length = int.from_bytes(blob[first_int_len:first_int_len + 4], "big")
        self.assertGreaterEqual(length, 1)
        # Inflate the declared body length and prefix a leading zero.
        blob[first_int_len:first_int_len + 4] = (length + 1).to_bytes(4, "big")
        blob[first_int_len + 4:first_int_len + 4] = b"\x00"
        with self.assertRaises(ValueError):
            decode_signature_receipt(bytes(blob))

    def test_zero_length_integer_body_rejected(self):
        blob = bytearray(encode_signature_receipt(self.receipt))
        tag_len = len(b"thresholdsign/signature-receipt/v1")
        message_length = int.from_bytes(blob[tag_len:tag_len + 4], "big")
        first_int_len = tag_len + 4 + message_length
        blob[first_int_len:first_int_len + 4] = (0).to_bytes(4, "big")
        with self.assertRaises(ValueError):
            decode_signature_receipt(bytes(blob))

    def test_duplicate_and_unordered_signer_ids_rejected(self):
        # Hand-build encodings with signer ids (1, 1) and (2, 1) by reusing
        # the valid blob and rewriting its final id slots.
        blob = encode_signature_receipt(self.receipt)
        self.assertEqual(self.receipt.signature.signer_ids, (1, 2))
        id2_offset = len(blob) - 1
        id1_offset = len(blob) - 6

        duplicate = bytearray(blob)
        duplicate[id2_offset] = 1
        with self.assertRaises(ValueError):
            decode_signature_receipt(bytes(duplicate))

        swapped = bytearray(blob)
        swapped[id1_offset] = 2
        swapped[id2_offset] = 1
        with self.assertRaises(ValueError):
            decode_signature_receipt(bytes(swapped))

    def test_empty_signer_set_rejected(self):
        # Build via the dataclass: encoder must reject an empty id tuple.
        bad = dataclasses.replace(
            self.receipt,
            signature=dataclasses.replace(self.receipt.signature, signer_ids=()),
        )
        with self.assertRaises(ValueError):
            encode_signature_receipt(bad)

    def test_out_of_range_R_z_public_key_rejected(self):
        cases = {
            "R": (0, GROUP_PRIME),
            "z": (-1, FIELD_PRIME),
            "public_key": (0, GROUP_PRIME),
        }
        for name, bad_values in cases.items():
            for bad_value in bad_values:
                if name == "R":
                    altered = dataclasses.replace(
                        self.receipt,
                        signature=dataclasses.replace(self.receipt.signature, R=bad_value),
                    )
                elif name == "z":
                    altered = dataclasses.replace(
                        self.receipt,
                        signature=dataclasses.replace(self.receipt.signature, z=bad_value),
                    )
                else:
                    altered = dataclasses.replace(self.receipt, public_key=bad_value)
                with self.assertRaises(ValueError, msg=f"{name}={bad_value}"):
                    encode_signature_receipt(altered)

    def test_illegal_primes_and_generator_rejected(self):
        for field, value in (
            ("field_prime", 2018),       # not prime
            ("field_prime", 2),          # does not divide p - 1... check structure
            ("group_prime", 8070),       # not prime
            ("group_prime", FIELD_PRIME),  # q does not divide p - 1
            ("generator", 1),            # identity
            ("generator", 0),
            ("generator", 17),           # not an order-field_prime element
        ):
            altered = dataclasses.replace(self.receipt, **{field: value})
            with self.assertRaises((ValueError, TypeError), msg=f"{field}={value}"):
                encode_signature_receipt(altered)

    def test_encode_wrong_type_raises_type_error(self):
        with self.assertRaises(TypeError):
            encode_signature_receipt("not a receipt")
        with self.assertRaises(TypeError):
            encode_signature_receipt(None)

    def test_encode_field_type_errors(self):
        bad = dataclasses.replace(self.receipt, message="not bytes")
        with self.assertRaises(TypeError):
            encode_signature_receipt(bad)
        bad = dataclasses.replace(self.receipt, public_key="1")
        with self.assertRaises(TypeError):
            encode_signature_receipt(bad)
        bad = dataclasses.replace(self.receipt, field_prime=True)
        with self.assertRaises(TypeError):
            encode_signature_receipt(bad)
        bad = dataclasses.replace(
            self.receipt,
            signature=dataclasses.replace(self.receipt.signature, signer_ids=[1, 2]),
        )
        with self.assertRaises(TypeError):
            encode_signature_receipt(bad)
        bad = dataclasses.replace(
            self.receipt,
            signature=dataclasses.replace(self.receipt.signature, signer_ids=(1, True)),
        )
        with self.assertRaises(TypeError):
            encode_signature_receipt(bad)

    def test_decode_does_not_verify_signature(self):
        # A structurally legal receipt whose z was forged: decode succeeds,
        # verification returns False.
        blob = bytearray(encode_signature_receipt(self.receipt))
        z_offset = None
        # z is the sixth length-prefixed integer; easier to build the bad
        # receipt structurally and check that encode/decode still accept it.
        forged = dataclasses.replace(
            self.receipt,
            signature=dataclasses.replace(
                self.receipt.signature, z=(self.receipt.signature.z + 1) % FIELD_PRIME
            ),
        )
        forged_blob = encode_signature_receipt(forged)
        decoded = decode_signature_receipt(forged_blob)
        self.assertEqual(decoded, forged)
        self.assertFalse(verify_signature_receipt(decoded))


class VerifySignatureReceiptTest(unittest.TestCase):
    def setUp(self):
        self.dkg, self.signature, self.receipt = make_receipt()

    def test_valid_receipt_is_true(self):
        self.assertIs(verify_signature_receipt(self.receipt), True)

    def test_result_matches_verify_signature(self):
        self.assertEqual(
            verify_signature_receipt(self.receipt),
            verify_signature(
                self.receipt.message,
                self.receipt.signature,
                self.receipt.public_key,
                group_prime=self.receipt.group_prime,
                generator=self.receipt.generator,
                prime=self.receipt.field_prime,
            ),
        )

    def test_decoded_receipt_verifies(self):
        decoded = decode_signature_receipt(encode_signature_receipt(self.receipt))
        self.assertIs(verify_signature_receipt(decoded), True)

    def test_tampered_message_is_false(self):
        blob = bytearray(encode_signature_receipt(self.receipt))
        tag_len = len(b"thresholdsign/signature-receipt/v1")
        # Flip a message byte (message starts right after the length prefix).
        offset = tag_len + 4
        original = blob[offset]
        blob[offset] = original ^ 0x01
        decoded = decode_signature_receipt(bytes(blob))
        self.assertNotEqual(decoded.message, self.receipt.message)
        self.assertFalse(verify_signature_receipt(decoded))

    def test_other_message_constructed_directly_is_false(self):
        bad = dataclasses.replace(self.receipt, message=b"another message")
        self.assertFalse(verify_signature_receipt(bad))

    def test_tampered_public_key_is_false(self):
        other_dkg = make_signing_dkg(seed_base=4242)
        swapped = dataclasses.replace(self.receipt, public_key=other_dkg.public_key)
        if other_dkg.public_key != self.receipt.public_key:
            self.assertFalse(verify_signature_receipt(swapped))
        # Identity key is structurally illegal.
        identity = dataclasses.replace(self.receipt, public_key=1)
        self.assertFalse(verify_signature_receipt(identity))

    def test_tampered_R_and_z_are_false(self):
        sig = self.receipt.signature
        bad_R = dataclasses.replace(
            self.receipt,
            signature=dataclasses.replace(sig, R=1),  # identity: well-formed
        )
        self.assertFalse(verify_signature_receipt(bad_R))
        bad_z = dataclasses.replace(
            self.receipt,
            signature=dataclasses.replace(sig, z=(sig.z + 1) % FIELD_PRIME),
        )
        self.assertFalse(verify_signature_receipt(bad_z))

    def test_tampered_signer_ids_are_false(self):
        sig = self.receipt.signature
        dkg = make_signing_dkg((1, 2, 3), 2)
        # (1, 3) is a legal signing set in the same group but binds a
        # different challenge.
        bad = dataclasses.replace(
            self.receipt,
            signature=dataclasses.replace(sig, signer_ids=(1, 3)),
        )
        self.assertFalse(verify_signature_receipt(bad))

    def test_tampered_group_parameters_are_false(self):
        # Same primes, a different generator of the same-order subgroup.
        other_g = pow(GENERATOR, 2, GROUP_PRIME)
        bad = dataclasses.replace(self.receipt, generator=other_g)
        self.assertFalse(verify_signature_receipt(bad))

    def test_receipt_under_another_key_is_false(self):
        other_dkg = make_signing_dkg(seed_base=9876)
        bad = dataclasses.replace(self.receipt, public_key=other_dkg.public_key)
        self.assertFalse(verify_signature_receipt(bad))

    def test_wrong_type_raises_type_error(self):
        with self.assertRaises(TypeError):
            verify_signature_receipt("not a receipt")
        with self.assertRaises(TypeError):
            verify_signature_receipt(None)
        with self.assertRaises(TypeError):
            verify_signature_receipt(
                AggregateSignature(R=1, z=1, signer_ids=(1,))
            )

    def test_field_type_errors_raise_type_error(self):
        bad = dataclasses.replace(self.receipt, message="not bytes")
        with self.assertRaises(TypeError):
            verify_signature_receipt(bad)
        bad = dataclasses.replace(self.receipt, public_key=1.5)
        with self.assertRaises(TypeError):
            verify_signature_receipt(bad)
        bad = dataclasses.replace(self.receipt, group_prime=True)
        with self.assertRaises(TypeError):
            verify_signature_receipt(bad)

    def test_out_of_range_values_raise_value_error(self):
        sig = self.receipt.signature
        bad = dataclasses.replace(
            self.receipt,
            signature=dataclasses.replace(sig, R=0),
        )
        with self.assertRaises(ValueError):
            verify_signature_receipt(bad)
        bad = dataclasses.replace(
            self.receipt,
            signature=dataclasses.replace(sig, z=FIELD_PRIME),
        )
        with self.assertRaises(ValueError):
            verify_signature_receipt(bad)
        bad = dataclasses.replace(self.receipt, public_key=GROUP_PRIME)
        with self.assertRaises(ValueError):
            verify_signature_receipt(bad)
        bad = dataclasses.replace(
            self.receipt,
            signature=dataclasses.replace(sig, signer_ids=(0, 2)),
        )
        with self.assertRaises(ValueError):
            verify_signature_receipt(bad)
        bad = dataclasses.replace(self.receipt, field_prime=2018)
        with self.assertRaises(ValueError):
            verify_signature_receipt(bad)


class ReceiptIndependentFlowTest(unittest.TestCase):
    """The receiver needs only the receipt — no DKG, shares or nonces."""

    def test_verify_without_signing_context(self):
        dkg, _signature, receipt = make_receipt()
        blob = encode_signature_receipt(receipt)
        # A fresh party: decode and verify with nothing but the bytes.
        decoded = decode_signature_receipt(blob)
        self.assertIsInstance(decoded, SignatureReceipt)
        self.assertFalse(hasattr(decoded, "result"))
        self.assertTrue(verify_signature_receipt(decoded))


if __name__ == "__main__":
    unittest.main()
