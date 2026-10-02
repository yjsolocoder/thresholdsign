"""Tests for the self-contained SignatureShareReceipt and its codec."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    SignatureShareReceipt,
    aggregate_signature,
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


def make_share_receipt(dkg=None, signer_ids=(1, 2), message=MESSAGE, signer_index=0):
    dkg = dkg or make_signing_dkg()
    round_info, _commitments, nonces = make_round(dkg, signer_ids, message)
    shares = make_shares(dkg, round_info, nonces)
    share = shares[signer_index]
    receipt = create_signature_share_receipt(message, share, round_info, dkg)
    return dkg, round_info, share, receipt


class CreateSignatureShareReceiptTest(unittest.TestCase):
    def test_fields_come_from_round_share_and_dkg(self):
        dkg, round_info, share, receipt = make_share_receipt()
        self.assertIsInstance(receipt, SignatureShareReceipt)
        self.assertEqual(receipt.message, MESSAGE)
        self.assertEqual(receipt.R, round_info.R)
        self.assertEqual(receipt.signer_ids, (1, 2))
        self.assertEqual(receipt.signer_id, share.signer_id)
        self.assertEqual(receipt.verification_share, dkg.verification_shares[0])
        self.assertEqual(receipt.public_key, dkg.public_key)
        self.assertEqual(receipt.field_prime, FIELD_PRIME)
        self.assertEqual(receipt.group_prime, GROUP_PRIME)
        self.assertEqual(receipt.generator, GENERATOR)
        self.assertEqual(receipt.nonce_commitment, share.nonce_commitment)
        self.assertEqual(receipt.z, share.z)

    def test_each_signer_gets_own_receipt(self):
        dkg, round_info, _share, first = make_share_receipt(signer_index=0)
        _dkg, _round, _share2, second = make_share_receipt(dkg, signer_index=1)
        self.assertEqual(first.signer_id, 1)
        self.assertEqual(second.signer_id, 2)
        self.assertEqual(first.R, second.R)
        self.assertEqual(first.signer_ids, second.signer_ids)
        self.assertNotEqual(first.nonce_commitment, second.nonce_commitment)
        self.assertNotEqual(first.verification_share, second.verification_share)
        self.assertTrue(verify_signature_share_receipt(first))
        self.assertTrue(verify_signature_share_receipt(second))

    def test_large_group(self):
        dkg = make_signing_dkg(
            (1, 2, 3), 2,
            field_prime=LARGE_FIELD, group_prime=LARGE_GROUP,
            generator=LARGE_G, blinding_generator=LARGE_H,
        )
        _dkg, _round, _share, receipt = make_share_receipt(dkg)
        self.assertTrue(verify_signature_share_receipt(receipt))
        self.assertEqual(receipt.field_prime, LARGE_FIELD)
        self.assertEqual(receipt.group_prime, LARGE_GROUP)
        self.assertEqual(receipt.generator, LARGE_G)

    def test_empty_message(self):
        _dkg, _round, _share, receipt = make_share_receipt(message=b"")
        self.assertTrue(verify_signature_share_receipt(receipt))

    def test_binary_message(self):
        _dkg, _round, _share, receipt = make_share_receipt(message=bytes(range(256)))
        self.assertTrue(verify_signature_share_receipt(receipt))

    def test_nonconsecutive_signers_and_threshold_one(self):
        dkg = make_signing_dkg((1, 2, 3, 4), 2)
        _dkg, _round, _share, receipt = make_share_receipt(dkg, signer_ids=(2, 4))
        self.assertEqual(receipt.signer_ids, (2, 4))
        self.assertEqual(receipt.signer_id, 2)
        self.assertTrue(verify_signature_share_receipt(receipt))

        dkg1 = make_signing_dkg((1, 2), 1)
        _dkg, _round, _share, receipt1 = make_share_receipt(dkg1, signer_ids=(1,))
        self.assertTrue(verify_signature_share_receipt(receipt1))

    def test_frozen_and_no_secret_fields(self):
        _dkg, _round, _share, receipt = make_share_receipt()
        with self.assertRaises(FrozenInstanceError):
            receipt.public_key = 1  # type: ignore[misc]
        self.assertEqual(
            {f.name for f in dataclasses.fields(receipt)},
            {"message", "R", "signer_ids", "signer_id", "verification_share",
             "public_key", "field_prime", "group_prime", "generator",
             "nonce_commitment", "z"},
        )
        self.assertFalse(hasattr(receipt, "dkg_result"))
        self.assertFalse(hasattr(receipt, "nonce"))
        self.assertFalse(hasattr(receipt, "secret_share"))
        self.assertFalse(hasattr(receipt, "coefficients"))

    def test_message_must_match_round(self):
        dkg, round_info, share, _receipt = make_share_receipt()
        with self.assertRaises(ValueError):
            create_signature_share_receipt(b"another message", share, round_info, dkg)

    def test_tampered_share_z_raises_value_error(self):
        dkg, round_info, share, _receipt = make_share_receipt()
        bad = dataclasses.replace(share, z=(share.z + 1) % FIELD_PRIME)
        with self.assertRaises(ValueError):
            create_signature_share_receipt(MESSAGE, bad, round_info, dkg)

    def test_wrong_nonce_commitment_raises_value_error(self):
        dkg, round_info, share, _receipt = make_share_receipt()
        other_index = 1 - round_info.signer_ids.index(share.signer_id)
        other_R = round_info.nonce_commitments[other_index].commitment
        bad = dataclasses.replace(share, nonce_commitment=other_R)
        with self.assertRaises(ValueError):
            create_signature_share_receipt(MESSAGE, bad, round_info, dkg)

    def test_signer_outside_round_raises_value_error(self):
        dkg = make_signing_dkg((1, 2, 3), 2)
        round_info, _commitments, nonces = make_round(dkg, (1, 2))
        shares = make_shares(dkg, round_info, nonces)
        # A share naming signer 3, who takes no part in this round.
        bad = dataclasses.replace(shares[0], signer_id=3)
        with self.assertRaises(ValueError):
            create_signature_share_receipt(MESSAGE, bad, round_info, dkg)

    def test_tampered_round_R_or_challenge_raises_value_error(self):
        dkg, round_info, share, _receipt = make_share_receipt()
        bad_R = dataclasses.replace(
            round_info, R=round_info.R * GENERATOR % GROUP_PRIME
        )
        with self.assertRaises(ValueError):
            create_signature_share_receipt(MESSAGE, share, bad_R, dkg)
        bad_c = dataclasses.replace(
            round_info, challenge=(round_info.challenge + 1) % FIELD_PRIME
        )
        with self.assertRaises(ValueError):
            create_signature_share_receipt(MESSAGE, share, bad_c, dkg)

    def test_out_of_range_share_fields_raise_value_error(self):
        dkg, round_info, share, _receipt = make_share_receipt()
        for field, value in (
            ("signer_id", 0),
            ("signer_id", FIELD_PRIME),
            ("z", -1),
            ("z", FIELD_PRIME),
            ("nonce_commitment", 1),
            ("nonce_commitment", GROUP_PRIME),
        ):
            bad = dataclasses.replace(share, **{field: value})
            with self.assertRaises(ValueError, msg=f"{field}={value}"):
                create_signature_share_receipt(MESSAGE, bad, round_info, dkg)

    def test_wrong_types_raise_type_error(self):
        dkg, round_info, share, _receipt = make_share_receipt()
        with self.assertRaises(TypeError):
            create_signature_share_receipt("not bytes", share, round_info, dkg)
        with self.assertRaises(TypeError):
            create_signature_share_receipt(MESSAGE, (share.signer_id, share.z), round_info, dkg)
        with self.assertRaises(TypeError):
            create_signature_share_receipt(MESSAGE, share, "not a round", dkg)
        with self.assertRaises(TypeError):
            create_signature_share_receipt(MESSAGE, share, round_info, "not a dkg")
        with self.assertRaises(TypeError):
            create_signature_share_receipt(MESSAGE, share, round_info, object())

    def test_bool_is_not_an_integer(self):
        dkg, round_info, share, _receipt = make_share_receipt()
        bad = dataclasses.replace(share, z=True)
        with self.assertRaises(TypeError):
            create_signature_share_receipt(MESSAGE, bad, round_info, dkg)
        bad_dkg = dataclasses.replace(dkg, public_key=True)
        with self.assertRaises(TypeError):
            create_signature_share_receipt(MESSAGE, share, round_info, bad_dkg)


class SignatureShareReceiptCodecTest(unittest.TestCase):
    def setUp(self):
        self.dkg, self.round_info, self.share, self.receipt = make_share_receipt()

    def test_round_trip_is_byte_exact(self):
        blob = encode_signature_share_receipt(self.receipt)
        self.assertIsInstance(blob, bytes)
        decoded = decode_signature_share_receipt(blob)
        self.assertEqual(decoded, self.receipt)
        self.assertTrue(verify_signature_share_receipt(decoded))
        # Re-encoding a decoded receipt must reproduce the exact bytes.
        self.assertEqual(encode_signature_share_receipt(decoded), blob)
        # Deterministic: same input always yields the same bytes.
        self.assertEqual(encode_signature_share_receipt(self.receipt), blob)

    def test_starts_with_tag(self):
        blob = encode_signature_share_receipt(self.receipt)
        self.assertTrue(blob.startswith(b"thresholdsign/signature-share-receipt/v1"))

    def test_round_trip_empty_and_binary_message(self):
        for message in (b"", bytes(range(256)), b"\x00" * 1000):
            _dkg, _round, _share, receipt = make_share_receipt(message=message)
            blob = encode_signature_share_receipt(receipt)
            decoded = decode_signature_share_receipt(blob)
            self.assertEqual(decoded, receipt)
            self.assertEqual(encode_signature_share_receipt(decoded), blob)

    def test_encoding_carries_no_secret_material(self):
        # Rebuild the encoding solely from the receipt's public fields: any
        # extra byte would mean a share, nonce or other hidden state leaked.
        from thresholdsign import SIGNATURE_SHARE_RECEIPT_TAG

        def varint(value):
            body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
            return len(body).to_bytes(4, "big") + body

        r = self.receipt
        expected = bytearray(SIGNATURE_SHARE_RECEIPT_TAG)
        expected += len(r.message).to_bytes(4, "big") + r.message
        for value in (r.field_prime, r.group_prime, r.generator, r.public_key,
                      r.R, r.verification_share, r.nonce_commitment, r.z,
                      r.signer_id):
            expected += varint(value)
        expected += len(r.signer_ids).to_bytes(4, "big")
        for signer_id in r.signer_ids:
            expected += varint(signer_id)
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
            # Byte-exact prefixes are all structurally incomplete.
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
        tag_len = len(b"thresholdsign/signature-share-receipt/v1")
        declared = int.from_bytes(blob[tag_len:tag_len + 4], "big")
        blob[tag_len + 3] = (declared + 1) & 0xFF
        with self.assertRaises(ValueError):
            decode_signature_share_receipt(bytes(blob))

    def test_non_canonical_integer_raises_value_error(self):
        blob = bytearray(encode_signature_share_receipt(self.receipt))
        # Find the first length-prefixed integer after the message.
        tag_len = len(b"thresholdsign/signature-share-receipt/v1")
        message_length = int.from_bytes(blob[tag_len:tag_len + 4], "big")
        first_int_len = tag_len + 4 + message_length
        length = int.from_bytes(blob[first_int_len:first_int_len + 4], "big")
        self.assertGreaterEqual(length, 1)
        # Inflate the declared body length and prefix a leading zero.
        blob[first_int_len:first_int_len + 4] = (length + 1).to_bytes(4, "big")
        blob[first_int_len + 4:first_int_len + 4] = b"\x00"
        with self.assertRaises(ValueError):
            decode_signature_share_receipt(bytes(blob))

    def test_zero_length_integer_body_rejected(self):
        blob = bytearray(encode_signature_share_receipt(self.receipt))
        tag_len = len(b"thresholdsign/signature-share-receipt/v1")
        message_length = int.from_bytes(blob[tag_len:tag_len + 4], "big")
        first_int_len = tag_len + 4 + message_length
        blob[first_int_len:first_int_len + 4] = (0).to_bytes(4, "big")
        with self.assertRaises(ValueError):
            decode_signature_share_receipt(bytes(blob))

    def test_duplicate_and_unordered_signer_ids_rejected(self):
        # Hand-build encodings with signer ids (1, 1) and (2, 1) by reusing
        # the valid blob and rewriting its final id slots.
        blob = encode_signature_share_receipt(self.receipt)
        self.assertEqual(self.receipt.signer_ids, (1, 2))
        id2_offset = len(blob) - 1
        id1_offset = len(blob) - 6

        duplicate = bytearray(blob)
        duplicate[id2_offset] = 1
        with self.assertRaises(ValueError):
            decode_signature_share_receipt(bytes(duplicate))

        swapped = bytearray(blob)
        swapped[id1_offset] = 2
        swapped[id2_offset] = 1
        with self.assertRaises(ValueError):
            decode_signature_share_receipt(bytes(swapped))

    def test_empty_signer_set_rejected(self):
        bad = dataclasses.replace(self.receipt, signer_ids=())
        with self.assertRaises(ValueError):
            encode_signature_share_receipt(bad)

    def test_out_of_range_values_rejected(self):
        cases = {
            "R": (0, GROUP_PRIME),
            "z": (-1, FIELD_PRIME),
            "public_key": (0, GROUP_PRIME),
            "verification_share": (0, GROUP_PRIME),
            "nonce_commitment": (0, 1, GROUP_PRIME),
            "signer_id": (0, FIELD_PRIME),
        }
        for name, bad_values in cases.items():
            for bad_value in bad_values:
                altered = dataclasses.replace(self.receipt, **{name: bad_value})
                with self.assertRaises(ValueError, msg=f"{name}={bad_value}"):
                    encode_signature_share_receipt(altered)

    def test_illegal_primes_and_generator_rejected(self):
        for field, value in (
            ("field_prime", 2018),         # not prime
            ("field_prime", 2),            # does not divide p - 1
            ("group_prime", 8070),         # not prime
            ("group_prime", FIELD_PRIME),  # q does not divide p - 1
            ("generator", 1),              # identity
            ("generator", 0),
            ("generator", 17),             # not an order-field_prime element
        ):
            altered = dataclasses.replace(self.receipt, **{field: value})
            with self.assertRaises((ValueError, TypeError), msg=f"{field}={value}"):
                encode_signature_share_receipt(altered)

    def test_encode_wrong_type_raises_type_error(self):
        with self.assertRaises(TypeError):
            encode_signature_share_receipt("not a receipt")
        with self.assertRaises(TypeError):
            encode_signature_share_receipt(None)

    def test_encode_field_type_errors(self):
        bad = dataclasses.replace(self.receipt, message="not bytes")
        with self.assertRaises(TypeError):
            encode_signature_share_receipt(bad)
        bad = dataclasses.replace(self.receipt, public_key="1")
        with self.assertRaises(TypeError):
            encode_signature_share_receipt(bad)
        bad = dataclasses.replace(self.receipt, field_prime=True)
        with self.assertRaises(TypeError):
            encode_signature_share_receipt(bad)
        bad = dataclasses.replace(self.receipt, signer_ids=[1, 2])
        with self.assertRaises(TypeError):
            encode_signature_share_receipt(bad)
        bad = dataclasses.replace(self.receipt, signer_ids=(1, True))
        with self.assertRaises(TypeError):
            encode_signature_share_receipt(bad)

    def test_decode_does_not_verify_share(self):
        # A structurally legal receipt whose z was forged: decode succeeds,
        # verification returns False.
        forged = dataclasses.replace(
            self.receipt, z=(self.receipt.z + 1) % FIELD_PRIME
        )
        forged_blob = encode_signature_share_receipt(forged)
        decoded = decode_signature_share_receipt(forged_blob)
        self.assertEqual(decoded, forged)
        self.assertFalse(verify_signature_share_receipt(decoded))


class VerifySignatureShareReceiptTest(unittest.TestCase):
    def setUp(self):
        self.dkg, self.round_info, self.share, self.receipt = make_share_receipt()

    def test_valid_receipt_is_true(self):
        self.assertIs(verify_signature_share_receipt(self.receipt), True)

    def test_result_matches_verify_signature_share(self):
        self.assertEqual(
            verify_signature_share_receipt(self.receipt),
            verify_signature_share(self.share, self.round_info, self.dkg),
        )

    def test_decoded_receipt_verifies(self):
        decoded = decode_signature_share_receipt(
            encode_signature_share_receipt(self.receipt)
        )
        self.assertIs(verify_signature_share_receipt(decoded), True)

    def test_tampered_message_is_false(self):
        bad = dataclasses.replace(self.receipt, message=b"another message")
        self.assertFalse(verify_signature_share_receipt(bad))

    def test_tampered_signer_ids_are_false(self):
        # (1, 3) is a legal signing set in the same group but binds a
        # different challenge and a different Lagrange weight.
        bad = dataclasses.replace(self.receipt, signer_ids=(1, 3))
        self.assertFalse(verify_signature_share_receipt(bad))

    def test_tampered_R_is_false(self):
        # Another element of the same subgroup: structurally legal.
        bad = dataclasses.replace(
            self.receipt, R=self.receipt.R * GENERATOR % GROUP_PRIME
        )
        self.assertFalse(verify_signature_share_receipt(bad))

    def test_tampered_verification_share_is_false(self):
        other_Y_i = self.dkg.verification_shares[1]
        self.assertNotEqual(other_Y_i, self.receipt.verification_share)
        bad = dataclasses.replace(self.receipt, verification_share=other_Y_i)
        self.assertFalse(verify_signature_share_receipt(bad))

    def test_tampered_nonce_commitment_is_false(self):
        other_R_i = self.round_info.nonce_commitments[1].commitment
        self.assertNotEqual(other_R_i, self.receipt.nonce_commitment)
        bad = dataclasses.replace(self.receipt, nonce_commitment=other_R_i)
        self.assertFalse(verify_signature_share_receipt(bad))

    def test_tampered_z_is_false(self):
        bad = dataclasses.replace(
            self.receipt, z=(self.receipt.z + 1) % FIELD_PRIME
        )
        self.assertFalse(verify_signature_share_receipt(bad))

    def test_tampered_public_key_is_false(self):
        other_dkg = make_signing_dkg(seed_base=4242)
        bad = dataclasses.replace(self.receipt, public_key=other_dkg.public_key)
        self.assertFalse(verify_signature_share_receipt(bad))

    def test_tampered_group_parameters_are_false(self):
        # Same primes, a different generator of the same-order subgroup.
        other_g = pow(GENERATOR, 2, GROUP_PRIME)
        bad = dataclasses.replace(self.receipt, generator=other_g)
        self.assertFalse(verify_signature_share_receipt(bad))

    def test_signer_id_outside_set_is_false(self):
        # Signer 3 is a legal id in this group but not part of the set (1, 2).
        bad = dataclasses.replace(self.receipt, signer_id=3)
        self.assertFalse(verify_signature_share_receipt(bad))

    def test_wrong_type_raises_type_error(self):
        with self.assertRaises(TypeError):
            verify_signature_share_receipt("not a receipt")
        with self.assertRaises(TypeError):
            verify_signature_share_receipt(None)
        with self.assertRaises(TypeError):
            verify_signature_share_receipt(self.share)

    def test_field_type_errors_raise_type_error(self):
        bad = dataclasses.replace(self.receipt, message="not bytes")
        with self.assertRaises(TypeError):
            verify_signature_share_receipt(bad)
        bad = dataclasses.replace(self.receipt, public_key=1.5)
        with self.assertRaises(TypeError):
            verify_signature_share_receipt(bad)
        bad = dataclasses.replace(self.receipt, group_prime=True)
        with self.assertRaises(TypeError):
            verify_signature_share_receipt(bad)
        bad = dataclasses.replace(self.receipt, z=True)
        with self.assertRaises(TypeError):
            verify_signature_share_receipt(bad)

    def test_out_of_range_values_raise_value_error(self):
        bad = dataclasses.replace(self.receipt, R=0)
        with self.assertRaises(ValueError):
            verify_signature_share_receipt(bad)
        bad = dataclasses.replace(self.receipt, z=FIELD_PRIME)
        with self.assertRaises(ValueError):
            verify_signature_share_receipt(bad)
        bad = dataclasses.replace(self.receipt, public_key=GROUP_PRIME)
        with self.assertRaises(ValueError):
            verify_signature_share_receipt(bad)
        bad = dataclasses.replace(self.receipt, nonce_commitment=1)
        with self.assertRaises(ValueError):
            verify_signature_share_receipt(bad)
        bad = dataclasses.replace(self.receipt, signer_ids=(0, 2))
        with self.assertRaises(ValueError):
            verify_signature_share_receipt(bad)
        bad = dataclasses.replace(self.receipt, field_prime=2018)
        with self.assertRaises(ValueError):
            verify_signature_share_receipt(bad)


class ShareReceiptIndependentFlowTest(unittest.TestCase):
    """The receiver needs only the receipt — no DKG, shares or nonces."""

    def test_verify_without_signing_context(self):
        _dkg, _round, _share, receipt = make_share_receipt()
        blob = encode_signature_share_receipt(receipt)
        # A fresh party: decode and verify with nothing but the bytes.
        decoded = decode_signature_share_receipt(blob)
        self.assertIsInstance(decoded, SignatureShareReceipt)
        self.assertFalse(hasattr(decoded, "result"))
        self.assertTrue(verify_signature_share_receipt(decoded))

    def test_receipt_coexists_with_aggregate_signature(self):
        # Creating share receipts changes nothing about the existing flow.
        dkg = make_signing_dkg()
        round_info, _commitments, nonces = make_round(dkg, (1, 2), MESSAGE)
        shares = make_shares(dkg, round_info, nonces)
        receipt = create_signature_share_receipt(MESSAGE, shares[0], round_info, dkg)
        self.assertTrue(verify_signature_share_receipt(receipt))
        signature = aggregate_signature(shares, round_info, dkg)
        self.assertFalse(isinstance(signature, list))


if __name__ == "__main__":
    unittest.main()
