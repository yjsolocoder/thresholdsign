"""Tests for the self-contained SignatureShareReceipt and its codec."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    SIGNATURE_SHARE_RECEIPT_TAG,
    SignatureShare,
    SignatureShareReceipt,
    create_signature_share_receipt,
    decode_signature_share_receipt,
    encode_signature_share_receipt,
    verify_signature_share,
    verify_signature_share_receipt,
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


def make_share_receipt(dkg=None, signer_ids=(1, 2), message=MESSAGE, index=0):
    dkg = dkg or make_signing_dkg()
    round_info, commitments, nonces = make_round(dkg, signer_ids, message)
    shares = make_shares(dkg, round_info, nonces)
    share = shares[index]
    receipt = create_signature_share_receipt(message, share, round_info, dkg)
    return dkg, round_info, commitments, nonces, shares, share, receipt


class CreateSignatureShareReceiptTest(unittest.TestCase):
    def test_fields_come_from_dkg_round_and_share(self):
        dkg, round_info, commitments, nonces, shares, share, receipt = (
            make_share_receipt()
        )
        self.assertIsInstance(receipt, SignatureShareReceipt)
        self.assertEqual(receipt.message, MESSAGE)
        self.assertEqual(receipt.R, round_info.R)
        self.assertEqual(receipt.signer_ids, round_info.signer_ids)
        self.assertEqual(receipt.signer_id, share.signer_id)
        self.assertEqual(receipt.R_i, share.nonce_commitment)
        self.assertEqual(receipt.R_i, commitments[0].commitment)
        self.assertEqual(receipt.z_i, share.z)
        position = dkg.result.participant_ids.index(share.signer_id)
        self.assertEqual(receipt.Y_i, dkg.verification_shares[position])
        self.assertEqual(receipt.Y, dkg.public_key)
        self.assertEqual((receipt.q, receipt.p, receipt.g),
                         (FIELD_PRIME, GROUP_PRIME, GENERATOR))

    def test_each_share_in_round_verifies(self):
        for index in (0, 1):
            _dkg, _r, _c, _n, _s, _sh, receipt = make_share_receipt(index=index)
            self.assertTrue(verify_signature_share_receipt(receipt))

    def test_large_group(self):
        dkg = make_signing_dkg(
            (1, 2, 3), 2,
            field_prime=LARGE_FIELD, group_prime=LARGE_GROUP,
            generator=LARGE_G, blinding_generator=LARGE_H,
        )
        _dkg, _r, _c, _n, _s, _sh, receipt = make_share_receipt(dkg)
        self.assertTrue(verify_signature_share_receipt(receipt))
        self.assertEqual((receipt.q, receipt.p, receipt.g),
                         (LARGE_FIELD, LARGE_GROUP, LARGE_G))

    def test_empty_and_binary_message(self):
        for message in (b"", bytes(range(256))):
            _dkg, _r, _c, _n, _s, _sh, receipt = make_share_receipt(message=message)
            self.assertTrue(verify_signature_share_receipt(receipt))

    def test_nonconsecutive_signers_threshold_one_and_last_position(self):
        dkg = make_signing_dkg((1, 2, 3, 4), 2)
        _dkg, _r, _c, _n, _s, _sh, receipt = make_share_receipt(
            dkg, signer_ids=(2, 4), index=1
        )
        self.assertEqual(receipt.signer_ids, (2, 4))
        self.assertEqual(receipt.signer_id, 4)
        self.assertTrue(verify_signature_share_receipt(receipt))

        dkg1 = make_signing_dkg((1, 2), 1)
        _dkg, _r, _c, _n, _s, _sh, receipt1 = make_share_receipt(
            dkg1, signer_ids=(2,)
        )
        self.assertTrue(verify_signature_share_receipt(receipt1))

    def test_frozen_and_no_secret_fields(self):
        _dkg, _r, _c, _n, _s, _sh, receipt = make_share_receipt()
        with self.assertRaises(FrozenInstanceError):
            receipt.z_i = 1  # type: ignore[misc]
        self.assertEqual(
            {f.name for f in dataclasses.fields(receipt)},
            {"message", "R", "signer_ids", "signer_id", "Y_i", "Y",
             "q", "p", "g", "R_i", "z_i"},
        )
        for name in ("dkg_result", "nonce", "secret_share", "result"):
            self.assertFalse(hasattr(receipt, name))

    def test_matches_verify_signature_share(self):
        dkg, round_info, _c, _n, _s, share, receipt = make_share_receipt()
        self.assertEqual(
            verify_signature_share_receipt(receipt),
            verify_signature_share(share, round_info, dkg),
        )

    def test_wrong_message_raises_value_error(self):
        dkg, round_info, _c, _n, _s, share, _receipt = make_share_receipt()
        with self.assertRaises(ValueError):
            create_signature_share_receipt(b"another message", share, round_info, dkg)

    def test_bad_share_equation_raises_value_error(self):
        dkg, round_info, _c, _n, _s, share, _receipt = make_share_receipt()
        bad = dataclasses.replace(share, z=(share.z + 1) % FIELD_PRIME)
        with self.assertRaises(ValueError):
            create_signature_share_receipt(MESSAGE, bad, round_info, dkg)

    def test_wrong_commitment_raises_value_error(self):
        dkg, round_info, _c, _n, shares, _share, _receipt = make_share_receipt()
        # A share repeating the other signer's R_i fails the commitment check.
        bad = dataclasses.replace(shares[0], nonce_commitment=shares[1].nonce_commitment)
        with self.assertRaises(ValueError):
            create_signature_share_receipt(MESSAGE, bad, round_info, dkg)

    def test_share_from_another_round_raises_value_error(self):
        dkg = make_signing_dkg()
        round_a, _c, nonces_a = make_round(dkg, (1, 2), MESSAGE)
        round_b, _c2, nonces_b = make_round(dkg, (1, 2), MESSAGE, seed=99)
        shares_b = make_shares(dkg, round_b, nonces_b)
        with self.assertRaises(ValueError):
            create_signature_share_receipt(MESSAGE, shares_b[0], round_a, dkg)
        # Same shares, a round bound to a different message.
        round_msg, _c3, nonces_msg = make_round(dkg, (1, 2), b"other message")
        shares_msg = make_shares(dkg, round_msg, nonces_msg)
        with self.assertRaises(ValueError):
            create_signature_share_receipt(MESSAGE, shares_msg[0], round_msg, dkg)

    def test_share_under_another_dkg_raises_value_error(self):
        dkg, round_info, _c, _n, _s, share, _receipt = make_share_receipt()
        other_dkg = make_signing_dkg(seed_base=5000)
        with self.assertRaises(ValueError):
            create_signature_share_receipt(MESSAGE, share, round_info, other_dkg)

    def test_wrong_types_raise_type_error(self):
        dkg, round_info, _c, _n, _s, share, _receipt = make_share_receipt()
        with self.assertRaises(TypeError):
            create_signature_share_receipt("not bytes", share, round_info, dkg)
        with self.assertRaises(TypeError):
            create_signature_share_receipt(MESSAGE, (share.signer_id,), round_info, dkg)
        with self.assertRaises(TypeError):
            create_signature_share_receipt(MESSAGE, "share", round_info, dkg)
        with self.assertRaises(TypeError):
            create_signature_share_receipt(MESSAGE, share, "round", dkg)
        with self.assertRaises(TypeError):
            create_signature_share_receipt(MESSAGE, share, round_info, "dkg")
        with self.assertRaises(TypeError):
            create_signature_share_receipt(MESSAGE, share, round_info, object())

    def test_bool_is_not_an_integer(self):
        dkg, round_info, _c, _n, _s, share, _receipt = make_share_receipt()
        with self.assertRaises(TypeError):
            create_signature_share_receipt(
                MESSAGE, dataclasses.replace(share, z=True), round_info, dkg
            )
        bad_dkg = dataclasses.replace(dkg, public_key=True)
        with self.assertRaises(TypeError):
            create_signature_share_receipt(MESSAGE, share, round_info, bad_dkg)

    def test_failure_returns_nothing(self):
        dkg, round_info, _c, _n, _s, share, _receipt = make_share_receipt()
        bad = dataclasses.replace(share, z=(share.z + 1) % FIELD_PRIME)
        with self.assertRaises(ValueError) as context:
            create_signature_share_receipt(MESSAGE, bad, round_info, dkg)
        self.assertNotIsInstance(context.exception, SignatureShareReceipt)


class SignatureShareReceiptCodecTest(unittest.TestCase):
    def setUp(self):
        (_dkg, _r, _c, _n, _s, _sh, self.receipt) = make_share_receipt()

    def test_round_trip_is_byte_exact(self):
        blob = encode_signature_share_receipt(self.receipt)
        self.assertIsInstance(blob, bytes)
        decoded = decode_signature_share_receipt(blob)
        self.assertEqual(decoded, self.receipt)
        self.assertTrue(verify_signature_share_receipt(decoded))
        self.assertEqual(encode_signature_share_receipt(decoded), blob)
        self.assertEqual(encode_signature_share_receipt(self.receipt), blob)

    def test_starts_with_tag(self):
        blob = encode_signature_share_receipt(self.receipt)
        self.assertTrue(
            blob.startswith(b"thresholdsign/signature-share-receipt/v1")
        )

    def test_round_trip_empty_and_binary_message(self):
        for message in (b"", bytes(range(256)), b"\x00" * 1000):
            _dkg, _r, _c, _n, _s, _sh, receipt = make_share_receipt(message=message)
            blob = encode_signature_share_receipt(receipt)
            decoded = decode_signature_share_receipt(blob)
            self.assertEqual(decoded, receipt)
            self.assertEqual(encode_signature_share_receipt(decoded), blob)

    def test_encoding_carries_no_secret_material(self):
        # Rebuild the encoding solely from the receipt's public fields.
        def varint(value):
            body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
            return len(body).to_bytes(4, "big") + body

        r = self.receipt
        expected = bytearray(SIGNATURE_SHARE_RECEIPT_TAG)
        expected += len(r.message).to_bytes(4, "big") + r.message
        for value in (r.q, r.p, r.g, r.Y, r.R):
            expected += varint(value)
        expected += len(r.signer_ids).to_bytes(4, "big")
        for member_id in r.signer_ids:
            expected += varint(member_id)
        for value in (r.signer_id, r.Y_i, r.R_i, r.z_i):
            expected += varint(value)
        self.assertEqual(encode_signature_share_receipt(r), bytes(expected))

    def test_decode_non_bytes_raises_type_error(self):
        with self.assertRaises(TypeError):
            decode_signature_share_receipt("bytes only")
        with self.assertRaises(TypeError):
            decode_signature_share_receipt(bytearray(b"x"))
        with self.assertRaises(TypeError):
            decode_signature_share_receipt(None)

    def test_bad_tag_raises_value_error(self):
        blob = encode_signature_share_receipt(self.receipt)
        with self.assertRaises(ValueError):
            decode_signature_share_receipt(b"x" + blob)
        with self.assertRaises(ValueError):
            decode_signature_share_receipt(b"")
        with self.assertRaises(ValueError):
            decode_signature_share_receipt(blob[:10])

    def test_truncation_raises_value_error(self):
        blob = encode_signature_share_receipt(self.receipt)
        for cut in range(len(blob) - 1):
            with self.assertRaises(ValueError):
                decode_signature_share_receipt(blob[:cut])

    def test_trailing_bytes_raise_value_error(self):
        blob = encode_signature_share_receipt(self.receipt)
        with self.assertRaises(ValueError):
            decode_signature_share_receipt(blob + b"\x00")
        with self.assertRaises(ValueError):
            decode_signature_share_receipt(blob + b"tail")

    def test_declared_message_length_too_large(self):
        blob = bytearray(encode_signature_share_receipt(self.receipt))
        tag_len = len(SIGNATURE_SHARE_RECEIPT_TAG)
        declared = int.from_bytes(blob[tag_len:tag_len + 4], "big")
        blob[tag_len + 3] = (declared + 1) & 0xFF
        with self.assertRaises(ValueError):
            decode_signature_share_receipt(bytes(blob))

    def test_non_canonical_integer_raises_value_error(self):
        blob = bytearray(encode_signature_share_receipt(self.receipt))
        tag_len = len(SIGNATURE_SHARE_RECEIPT_TAG)
        message_length = int.from_bytes(blob[tag_len:tag_len + 4], "big")
        first_int_len = tag_len + 4 + message_length
        length = int.from_bytes(blob[first_int_len:first_int_len + 4], "big")
        self.assertGreaterEqual(length, 1)
        blob[first_int_len:first_int_len + 4] = (length + 1).to_bytes(4, "big")
        blob[first_int_len + 4:first_int_len + 4] = b"\x00"
        with self.assertRaises(ValueError):
            decode_signature_share_receipt(bytes(blob))

    def test_zero_length_integer_body_rejected(self):
        blob = bytearray(encode_signature_share_receipt(self.receipt))
        tag_len = len(SIGNATURE_SHARE_RECEIPT_TAG)
        message_length = int.from_bytes(blob[tag_len:tag_len + 4], "big")
        first_int_len = tag_len + 4 + message_length
        blob[first_int_len:first_int_len + 4] = (0).to_bytes(4, "big")
        with self.assertRaises(ValueError):
            decode_signature_share_receipt(bytes(blob))

    def test_duplicate_and_unordered_signer_ids_rejected(self):
        def assemble(ids):
            r = self.receipt

            def varint(value):
                body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
                return len(body).to_bytes(4, "big") + body

            out = bytearray(SIGNATURE_SHARE_RECEIPT_TAG)
            out += len(r.message).to_bytes(4, "big") + r.message
            for value in (r.q, r.p, r.g, r.Y, r.R):
                out += varint(value)
            out += len(ids).to_bytes(4, "big")
            for member_id in ids:
                out += varint(member_id)
            for value in (r.signer_id, r.Y_i, r.R_i, r.z_i):
                out += varint(value)
            return bytes(out)

        self.assertEqual(self.receipt.signer_ids, (1, 2))
        with self.assertRaises(ValueError):
            decode_signature_share_receipt(assemble((1, 1)))
        with self.assertRaises(ValueError):
            decode_signature_share_receipt(assemble((2, 1)))

    def test_empty_signer_set_rejected(self):
        bad = dataclasses.replace(self.receipt, signer_ids=())
        with self.assertRaises(ValueError):
            encode_signature_share_receipt(bad)

    def test_signer_id_outside_set_rejected(self):
        # 3 is in field range but absent from the (1, 2) signing set.
        bad = dataclasses.replace(self.receipt, signer_id=3)
        with self.assertRaises(ValueError):
            encode_signature_share_receipt(bad)

        # Hand-assemble an otherwise-canonical blob whose trailing
        # signer_id field names the absent signer 3.
        r = dataclasses.replace(self.receipt, signer_id=2)

        def varint(value):
            body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
            return len(body).to_bytes(4, "big") + body

        out = bytearray(SIGNATURE_SHARE_RECEIPT_TAG)
        out += len(r.message).to_bytes(4, "big") + r.message
        for value in (r.q, r.p, r.g, r.Y, r.R):
            out += varint(value)
        out += len(r.signer_ids).to_bytes(4, "big")
        for member_id in r.signer_ids:
            out += varint(member_id)
        for value in (3, r.Y_i, r.R_i, r.z_i):
            out += varint(value)
        with self.assertRaises(ValueError):
            decode_signature_share_receipt(bytes(out))

    def test_out_of_range_values_rejected(self):
        cases = {
            "R": (0, GROUP_PRIME),
            "R_i": (1, GROUP_PRIME),
            "Y_i": (0, GROUP_PRIME),
            "Y": (0, GROUP_PRIME),
            "z_i": (-1, FIELD_PRIME),
            "signer_id": (0, 3),
        }
        for name, bad_values in cases.items():
            for bad_value in bad_values:
                altered = dataclasses.replace(self.receipt, **{name: bad_value})
                with self.assertRaises(
                    (ValueError, TypeError), msg=f"{name}={bad_value}"
                ):
                    encode_signature_share_receipt(altered)

    def test_illegal_primes_and_generator_rejected(self):
        for field, value in (
            ("q", 2018),
            ("q", 2),
            ("p", 8070),
            ("p", FIELD_PRIME),
            ("g", 1),
            ("g", 0),
            ("g", 17),
        ):
            altered = dataclasses.replace(self.receipt, **{field: value})
            with self.assertRaises((ValueError, TypeError), msg=f"{field}={value}"):
                encode_signature_share_receipt(altered)

    def test_encode_wrong_type_raises_type_error(self):
        with self.assertRaises(TypeError):
            encode_signature_share_receipt("not a receipt")
        with self.assertRaises(TypeError):
            encode_signature_share_receipt(None)
        with self.assertRaises(TypeError):
            encode_signature_share_receipt(
                SignatureShare(signer_id=1, nonce_commitment=2, z=3)
            )

    def test_encode_field_type_errors(self):
        bad = dataclasses.replace(self.receipt, message="not bytes")
        with self.assertRaises(TypeError):
            encode_signature_share_receipt(bad)
        bad = dataclasses.replace(self.receipt, Y="1")
        with self.assertRaises(TypeError):
            encode_signature_share_receipt(bad)
        bad = dataclasses.replace(self.receipt, q=True)
        with self.assertRaises(TypeError):
            encode_signature_share_receipt(bad)
        bad = dataclasses.replace(self.receipt, signer_ids=[1, 2])
        with self.assertRaises(TypeError):
            encode_signature_share_receipt(bad)
        bad = dataclasses.replace(self.receipt, signer_ids=(1, True))
        with self.assertRaises(TypeError):
            encode_signature_share_receipt(bad)

    def test_decode_does_not_verify_share_equation(self):
        forged = dataclasses.replace(
            self.receipt, z_i=(self.receipt.z_i + 1) % FIELD_PRIME
        )
        forged_blob = encode_signature_share_receipt(forged)
        decoded = decode_signature_share_receipt(forged_blob)
        self.assertEqual(decoded, forged)
        self.assertFalse(verify_signature_share_receipt(decoded))


class VerifySignatureShareReceiptTest(unittest.TestCase):
    def setUp(self):
        (self.dkg, self.round_info, self.commitments, self.nonces,
         self.shares, self.share, self.receipt) = make_share_receipt()

    def test_valid_receipt_is_true(self):
        self.assertIs(verify_signature_share_receipt(self.receipt), True)

    def test_result_matches_verify_signature_share(self):
        self.assertEqual(
            verify_signature_share_receipt(self.receipt),
            verify_signature_share(
                self.share, self.round_info, self.dkg
            ),
        )

    def test_decoded_receipt_verifies(self):
        decoded = decode_signature_share_receipt(
            encode_signature_share_receipt(self.receipt)
        )
        self.assertIs(verify_signature_share_receipt(decoded), True)

    def test_tampered_message_is_false(self):
        bad = dataclasses.replace(self.receipt, message=b"another message")
        self.assertFalse(verify_signature_share_receipt(bad))

    def test_tampered_message_byte_is_false(self):
        blob = bytearray(encode_signature_share_receipt(self.receipt))
        tag_len = len(SIGNATURE_SHARE_RECEIPT_TAG)
        offset = tag_len + 4
        original = blob[offset]
        blob[offset] = original ^ 0x01
        decoded = decode_signature_share_receipt(bytes(blob))
        self.assertNotEqual(decoded.message, self.receipt.message)
        self.assertFalse(verify_signature_share_receipt(decoded))

    def test_tampered_aggregate_R_is_false(self):
        bad = dataclasses.replace(self.receipt, R=1)  # identity: structurally legal
        self.assertFalse(verify_signature_share_receipt(bad))

    def test_tampered_z_i_is_false(self):
        bad = dataclasses.replace(
            self.receipt, z_i=(self.receipt.z_i + 1) % FIELD_PRIME
        )
        self.assertFalse(verify_signature_share_receipt(bad))

    def test_tampered_R_i_is_false(self):
        other = self.commitments[1].commitment
        self.assertNotEqual(other, self.receipt.R_i)
        bad = dataclasses.replace(self.receipt, R_i=other)
        self.assertFalse(verify_signature_share_receipt(bad))

    def test_tampered_Y_i_is_false(self):
        other = self.dkg.verification_shares[1]
        self.assertNotEqual(other, self.receipt.Y_i)
        bad = dataclasses.replace(self.receipt, Y_i=other)
        self.assertFalse(verify_signature_share_receipt(bad))

    def test_tampered_Y_is_false(self):
        other_dkg = make_signing_dkg(seed_base=4242)
        bad = dataclasses.replace(self.receipt, Y=other_dkg.public_key)
        if other_dkg.public_key != self.receipt.Y:
            self.assertFalse(verify_signature_share_receipt(bad))
        identity = dataclasses.replace(self.receipt, Y=1)
        self.assertFalse(verify_signature_share_receipt(identity))

    def test_tampered_signer_ids_is_false(self):
        # (1, 3) is a legal signing set in the same group but binds a
        # different challenge and a different Lagrange weight.
        bad = dataclasses.replace(self.receipt, signer_ids=(1, 3))
        self.assertFalse(verify_signature_share_receipt(bad))

    def test_tampered_signer_id_is_false(self):
        # Keep signer_id inside the set: switch 1 -> 2. The weight and Y_i
        # no longer agree, so the equation must fail.
        bad = dataclasses.replace(self.receipt, signer_id=2)
        self.assertFalse(verify_signature_share_receipt(bad))

    def test_tampered_group_parameters_are_false(self):
        other_g = pow(GENERATOR, 2, GROUP_PRIME)
        bad = dataclasses.replace(self.receipt, g=other_g)
        self.assertFalse(verify_signature_share_receipt(bad))

    def test_receipt_under_another_key_is_false(self):
        other_dkg = make_signing_dkg(seed_base=9876)
        bad = dataclasses.replace(self.receipt, Y=other_dkg.public_key)
        self.assertFalse(verify_signature_share_receipt(bad))

    def test_wrong_type_raises_type_error(self):
        with self.assertRaises(TypeError):
            verify_signature_share_receipt("not a receipt")
        with self.assertRaises(TypeError):
            verify_signature_share_receipt(None)
        with self.assertRaises(TypeError):
            verify_signature_share_receipt(
                SignatureShare(signer_id=1, nonce_commitment=2, z=3)
            )

    def test_field_type_errors_raise_type_error(self):
        bad = dataclasses.replace(self.receipt, message="not bytes")
        with self.assertRaises(TypeError):
            verify_signature_share_receipt(bad)
        bad = dataclasses.replace(self.receipt, Y=1.5)
        with self.assertRaises(TypeError):
            verify_signature_share_receipt(bad)
        bad = dataclasses.replace(self.receipt, p=True)
        with self.assertRaises(TypeError):
            verify_signature_share_receipt(bad)

    def test_out_of_range_values_raise_value_error(self):
        for field, value in (
            ("R", 0),
            ("R_i", 1),
            ("Y_i", 0),
            ("Y", GROUP_PRIME),
            ("z_i", FIELD_PRIME),
            ("signer_id", 0),
        ):
            bad = dataclasses.replace(self.receipt, **{field: value})
            with self.assertRaises(ValueError, msg=f"{field}={value}"):
                verify_signature_share_receipt(bad)

    def test_signer_id_outside_set_raises_value_error(self):
        bad = dataclasses.replace(self.receipt, signer_id=3)
        with self.assertRaises(ValueError):
            verify_signature_share_receipt(bad)

    def test_illegal_group_parameters_raise_value_error(self):
        with self.assertRaises(ValueError):
            verify_signature_share_receipt(
                dataclasses.replace(self.receipt, q=2018)
            )


class ShareReceiptIndependentFlowTest(unittest.TestCase):
    """The receiver needs only the receipt — no DKG, round, shares or nonces."""

    def test_verify_without_signing_context(self):
        _dkg, _r, _c, _n, _s, _sh, receipt = make_share_receipt()
        blob = encode_signature_share_receipt(receipt)
        decoded = decode_signature_share_receipt(blob)
        self.assertIsInstance(decoded, SignatureShareReceipt)
        self.assertFalse(hasattr(decoded, "result"))
        self.assertFalse(hasattr(decoded, "nonce"))
        self.assertTrue(verify_signature_share_receipt(decoded))


if __name__ == "__main__":
    unittest.main()
