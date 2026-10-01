"""Tests for self-contained threshold Schnorr signature receipts."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    SignatureReceipt,
    aggregate_signature,
    aggregate_signing_dkg,
    create_signing_contribution,
    create_signature_receipt,
    create_signature_share,
    create_signing_nonce_commitment,
    create_signing_round,
    decode_signature_receipt,
    encode_signature_receipt,
    verify_signature,
    verify_signature_receipt,
)

# Same toy group as the signing tests: 8069 = 4 * 2017 + 1 is prime, 16 and
# 256 = 16 ** 2 are distinct generators of the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

# A 3-byte group prime (L = 3) for encoding tests, same as the signing tests.
LARGE_FIELD = 1000151
LARGE_GROUP = 2000303
LARGE_G = 9
LARGE_H = 81

MESSAGE = b"threshold schnorr signature receipt message"
RECEIPT_TAG = b"thresholdsign/signature-receipt/v1"


def fixed_random(seed=1):
    """Deterministic stand-in for secrets.randbelow (same LCG as DKG tests)."""
    state = {"value": seed}

    def randbelow(upper: int) -> int:
        state["value"] = (
            state["value"] * 6364136223846793005 + 1442695040888963407
        ) % upper
        return state["value"]

    return randbelow


def make_key(
    participant_ids=(1, 2, 3),
    threshold=2,
    field_prime=FIELD_PRIME,
    group_prime=GROUP_PRIME,
    generator=GENERATOR,
    blinding_generator=BLINDING_GENERATOR,
):
    contributions = [
        create_signing_contribution(
            pid,
            participant_ids,
            threshold,
            prime=field_prime,
            group_prime=group_prime,
            generator=generator,
            blinding_generator=blinding_generator,
            randbelow=fixed_random(pid),
        )
        for pid in participant_ids
    ]
    return aggregate_signing_dkg(contributions)


def make_signature(
    key,
    message=MESSAGE,
    signer_ids=(1, 3),
    seed=100,
):
    commitments = []
    nonces = {}
    for index, pid in enumerate(signer_ids):
        commitment, nonce = create_signing_nonce_commitment(
            pid,
            prime=key.result.commitment.field_prime,
            group_prime=key.result.commitment.group_prime,
            generator=key.result.commitment.generator,
            randbelow=fixed_random(seed + index),
        )
        commitments.append(commitment)
        nonces[pid] = nonce
    round_info = create_signing_round(message, signer_ids, commitments, key)
    shares = [
        create_signature_share(
            pid,
            key.result.shares[key.result.participant_ids.index(pid)].y,
            nonces[pid],
            round_info,
            key,
        )
        for pid in signer_ids
    ]
    signature = aggregate_signature(shares, round_info, key)
    assert isinstance(signature, AggregateSignature)
    return signature


class SignatureReceiptDataTest(unittest.TestCase):
    def test_frozen_named_fields_value_equality(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(SignatureReceipt)],
            ["message", "signature", "public_key", "field_prime", "group_prime", "generator"],
        )
        signature = AggregateSignature(R=3, z=4, signer_ids=(1, 2))
        receipt = SignatureReceipt(
            MESSAGE, signature, 5, FIELD_PRIME, GROUP_PRIME, GENERATOR
        )
        self.assertEqual(receipt.message, MESSAGE)
        self.assertEqual(receipt.signature, signature)
        self.assertEqual(receipt.public_key, 5)
        self.assertEqual(receipt.field_prime, FIELD_PRIME)
        self.assertEqual(receipt.group_prime, GROUP_PRIME)
        self.assertEqual(receipt.generator, GENERATOR)
        self.assertEqual(
            receipt,
            SignatureReceipt(
                message=MESSAGE,
                signature=signature,
                public_key=5,
                field_prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            ),
        )
        self.assertEqual(hash(receipt), hash(SignatureReceipt(
            MESSAGE, signature, 5, FIELD_PRIME, GROUP_PRIME, GENERATOR
        )))
        with self.assertRaises(FrozenInstanceError):
            receipt.message = b"other"


class CreateSignatureReceiptTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.signature = make_signature(self.key)
        self.receipt = create_signature_receipt(MESSAGE, self.signature, self.key)

    def test_receipt_carries_public_material_only(self):
        self.assertEqual(self.receipt.message, MESSAGE)
        self.assertEqual(self.receipt.signature, self.signature)
        self.assertEqual(self.receipt.public_key, self.key.public_key)
        self.assertEqual(
            self.receipt.field_prime, self.key.result.commitment.field_prime
        )
        self.assertEqual(
            self.receipt.group_prime, self.key.result.commitment.group_prime
        )
        self.assertEqual(
            self.receipt.generator, self.key.result.commitment.generator
        )

    def test_created_receipt_verifies_and_matches_verify_signature(self):
        self.assertTrue(verify_signature_receipt(self.receipt))
        self.assertTrue(
            verify_signature(
                MESSAGE,
                self.signature,
                self.key.public_key,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
                prime=FIELD_PRIME,
            )
        )

    def test_empty_message(self):
        signature = make_signature(self.key, message=b"")
        receipt = create_signature_receipt(b"", signature, self.key)
        self.assertEqual(receipt.message, b"")
        self.assertTrue(verify_signature_receipt(receipt))

    def test_large_group_receipt(self):
        key = make_key(
            participant_ids=(1, 2, 3, 4),
            threshold=3,
            field_prime=LARGE_FIELD,
            group_prime=LARGE_GROUP,
            generator=LARGE_G,
            blinding_generator=LARGE_H,
        )
        signature = make_signature(key, signer_ids=(2, 3, 4), seed=200)
        receipt = create_signature_receipt(MESSAGE, signature, key)
        self.assertTrue(verify_signature_receipt(receipt))

    def test_rejects_foreign_key(self):
        # A distinct participant set yields a distinct joint public key.
        other_key = make_key(participant_ids=(1, 2, 4))
        self.assertNotEqual(other_key.public_key, self.key.public_key)
        with self.assertRaises(ValueError):
            create_signature_receipt(MESSAGE, self.signature, other_key)

    def test_rejects_wrong_message(self):
        with self.assertRaises(ValueError):
            create_signature_receipt(b"another message", self.signature, self.key)

    def test_rejects_bad_signature(self):
        bad_signature = dataclasses.replace(
            self.signature, z=(self.signature.z + 1) % FIELD_PRIME
        )
        with self.assertRaises(ValueError):
            create_signature_receipt(MESSAGE, bad_signature, self.key)

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            create_signature_receipt("not bytes", self.signature, self.key)
        with self.assertRaises(TypeError):
            create_signature_receipt(MESSAGE, "not a signature", self.key)
        with self.assertRaises(TypeError):
            create_signature_receipt(MESSAGE, self.signature, "not a key")
        with self.assertRaises(TypeError):
            create_signature_receipt(True, self.signature, self.key)
        with self.assertRaises(TypeError):
            create_signature_receipt(MESSAGE, True, self.key)


class SignatureReceiptEncodingTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.signature = make_signature(self.key)
        self.receipt = create_signature_receipt(MESSAGE, self.signature, self.key)
        self.payload = encode_signature_receipt(self.receipt)

    def test_tag_prefix_and_framed_layout(self):
        self.assertTrue(self.payload.startswith(RECEIPT_TAG))
        offset = len(RECEIPT_TAG)
        length = int.from_bytes(
            self.payload[offset:offset + 4], "big"
        )
        self.assertEqual(length, len(MESSAGE))
        self.assertEqual(
            self.payload[offset + 4:offset + 4 + length], MESSAGE
        )

    def test_layout_matches_independent_builder(self):
        def varint(value):
            body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
            return len(body).to_bytes(4, "big") + body

        expected = bytearray(RECEIPT_TAG)
        expected += len(MESSAGE).to_bytes(4, "big")
        expected += MESSAGE
        expected += varint(self.key.public_key)
        expected += varint(FIELD_PRIME)
        expected += varint(GROUP_PRIME)
        expected += varint(GENERATOR)
        expected += varint(self.signature.R)
        expected += varint(self.signature.z)
        expected += len(self.signature.signer_ids).to_bytes(4, "big")
        for signer_id in self.signature.signer_ids:
            expected += varint(signer_id)
        self.assertEqual(bytes(expected), self.payload)

    def test_deterministic_unique_output(self):
        self.assertEqual(
            encode_signature_receipt(self.receipt), self.payload
        )
        self.assertEqual(
            encode_signature_receipt(
                dataclasses.replace(self.receipt, message=MESSAGE + b"!")
            )[:len(RECEIPT_TAG)],
            RECEIPT_TAG,
        )

    def test_roundtrip_is_byte_identical(self):
        decoded = decode_signature_receipt(self.payload)
        self.assertEqual(decoded, self.receipt)
        self.assertEqual(encode_signature_receipt(decoded), self.payload)

    def test_empty_message_roundtrip(self):
        signature = make_signature(self.key, message=b"")
        receipt = create_signature_receipt(b"", signature, self.key)
        payload = encode_signature_receipt(receipt)
        self.assertEqual(decode_signature_receipt(payload), receipt)
        self.assertEqual(encode_signature_receipt(decode_signature_receipt(payload)), payload)

    def test_structurally_legal_bad_signature_roundtrips(self):
        bad = dataclasses.replace(
            self.receipt,
            signature=dataclasses.replace(
                self.signature, z=(self.signature.z + 1) % FIELD_PRIME
            ),
        )
        payload = encode_signature_receipt(bad)
        decoded = decode_signature_receipt(payload)
        self.assertEqual(decoded, bad)
        self.assertFalse(verify_signature_receipt(decoded))

    def test_decode_non_bytes_raises_type_error(self):
        for bad in ("bytes", bytearray(self.payload), 1234, None, [self.payload]):
            with self.assertRaises(TypeError):
                decode_signature_receipt(bad)

    def test_rejects_bad_tag(self):
        bad = bytearray(self.payload)
        bad[0] ^= 0xFF
        with self.assertRaises(ValueError):
            decode_signature_receipt(bytes(bad))
        with self.assertRaises(ValueError):
            decode_signature_receipt(b"thresholdsign/signature-receipt/v2")

    def test_rejects_truncation_at_every_cut(self):
        for cut in range(len(self.payload)):
            with self.assertRaises(ValueError):
                decode_signature_receipt(self.payload[:cut])

    def test_rejects_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_signature_receipt(self.payload + b"\x00")
        with self.assertRaises(ValueError):
            decode_signature_receipt(self.payload + b"extra")

    def test_rejects_truncated_message_frame(self):
        offset = len(RECEIPT_TAG)
        oversized = (len(MESSAGE) + 5).to_bytes(4, "big")
        bad = self.payload[:offset] + oversized + MESSAGE
        with self.assertRaises(ValueError):
            decode_signature_receipt(bad)

    def test_rejects_non_canonical_integer(self):
        # The first VARINT (public_key) starts right after the message frame.
        offset = len(RECEIPT_TAG) + 4 + len(MESSAGE)
        body_length = int.from_bytes(self.payload[offset:offset + 4], "big")
        body = self.payload[offset + 4:offset + 4 + body_length]
        # Declare one extra byte and prefix a forbidden leading zero.
        bad = (
            self.payload[:offset]
            + (body_length + 1).to_bytes(4, "big")
            + b"\x00"
            + body
            + self.payload[offset + 4 + body_length:]
        )
        with self.assertRaises(ValueError):
            decode_signature_receipt(bad)
        # A zero body length is never canonical (zero is the single byte 00).
        bad = self.payload[:offset] + b"\x00\x00\x00\x00"
        with self.assertRaises(ValueError):
            decode_signature_receipt(bad)

    def test_rejects_zero_or_unordered_or_duplicate_wire_signer_ids(self):
        # Build a payload and tamper the trailing signer-id VARINTs.
        def build_with_ids(ids):
            signature = AggregateSignature(
                R=self.signature.R, z=self.signature.z, signer_ids=ids
            )
            receipt = dataclasses.replace(self.receipt, signature=signature)
            return encode_signature_receipt(receipt)

        for ids in ((), (0, 3), (3, 3), (3, 1)):
            with self.assertRaises(ValueError):
                build_with_ids(ids)

        # Same defects injected purely on the wire must also fail to decode:
        # take the real payload and rewrite the trailing signer count/ids.
        head = self.payload[:-4 - sum(
            4 + max(1, (identifier.bit_length() + 7) // 8)
            for identifier in self.signature.signer_ids
        )]

        def varint(value):
            body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
            return len(body).to_bytes(4, "big") + body

        for ids in ((), (0,), (3, 1), (1, 1)):
            wire = bytearray(head)
            wire += len(ids).to_bytes(4, "big")
            for identifier in ids:
                wire += varint(identifier)
            with self.assertRaises(ValueError):
                decode_signature_receipt(bytes(wire))

    def test_rejects_out_of_range_values(self):
        cases = {
            "R zero": dataclasses.replace(
                self.receipt,
                signature=dataclasses.replace(self.signature, R=0),
            ),
            "R too large": dataclasses.replace(
                self.receipt,
                signature=dataclasses.replace(
                    self.signature, R=GROUP_PRIME - 1
                ),
            ),
            "z too large": dataclasses.replace(
                self.receipt,
                signature=dataclasses.replace(
                    self.signature, z=FIELD_PRIME
                ),
            ),
            "public key zero": dataclasses.replace(self.receipt, public_key=0),
            "signer id out of field": dataclasses.replace(
                self.receipt,
                signature=dataclasses.replace(
                    self.signature, signer_ids=(1, FIELD_PRIME)
                ),
            ),
        }
        for label, bad in cases.items():
            with self.subTest(label):
                with self.assertRaises(ValueError):
                    encode_signature_receipt(bad)

    def test_rejects_illegal_primes_and_group(self):
        for label, changes in {
            "non-prime field": dict(field_prime=FIELD_PRIME + 1),
            "non-prime group": dict(group_prime=GROUP_PRIME + 2),
            "divisibility broken": dict(field_prime=FIELD_PRIME - 2),
            "generator identity": dict(generator=1),
            "generator too large": dict(generator=GROUP_PRIME),
            "generator out of subgroup": dict(generator=2),
        }.items():
            with self.subTest(label):
                with self.assertRaises(ValueError):
                    encode_signature_receipt(
                        dataclasses.replace(self.receipt, **changes)
                    )

    def test_encode_rejects_wrong_types(self):
        with self.assertRaises(TypeError):
            encode_signature_receipt("not a receipt")
        with self.assertRaises(TypeError):
            encode_signature_receipt(
                dataclasses.replace(self.receipt, message="not bytes")
            )
        with self.assertRaises(TypeError):
            encode_signature_receipt(
                dataclasses.replace(self.receipt, public_key=True)
            )

    def test_large_group_roundtrip(self):
        key = make_key(
            participant_ids=(1, 2, 3, 4),
            threshold=3,
            field_prime=LARGE_FIELD,
            group_prime=LARGE_GROUP,
            generator=LARGE_G,
            blinding_generator=LARGE_H,
        )
        signature = make_signature(key, signer_ids=(2, 3, 4), seed=200)
        receipt = create_signature_receipt(MESSAGE, signature, key)
        payload = encode_signature_receipt(receipt)
        self.assertEqual(decode_signature_receipt(payload), receipt)
        self.assertEqual(encode_signature_receipt(decode_signature_receipt(payload)), payload)


class VerifySignatureReceiptTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.signature = make_signature(self.key)
        self.receipt = create_signature_receipt(MESSAGE, self.signature, self.key)

    def test_valid_receipt(self):
        self.assertTrue(verify_signature_receipt(self.receipt))

    def test_tampered_message_returns_false(self):
        tampered = dataclasses.replace(self.receipt, message=MESSAGE + b"!")
        self.assertFalse(verify_signature_receipt(tampered))
        self.assertFalse(
            verify_signature_receipt(dataclasses.replace(self.receipt, message=b""))
        )

    def test_tampered_public_key_returns_false(self):
        # 2 is a non-identity subgroup element distinct from the real key.
        self.assertNotEqual(pow(2, FIELD_PRIME, GROUP_PRIME), 1)
        alternative = pow(GENERATOR, 7, GROUP_PRIME)
        tampered = dataclasses.replace(self.receipt, public_key=alternative)
        self.assertFalse(verify_signature_receipt(tampered))

    def test_tampered_group_elements_raise_or_return_false(self):
        # z is free within the field: a changed z stays structurally legal
        # but fails the equation.
        tampered_z = dataclasses.replace(
            self.receipt,
            signature=dataclasses.replace(
                self.signature, z=(self.signature.z + 1) % FIELD_PRIME
            ),
        )
        self.assertFalse(verify_signature_receipt(tampered_z))

        # Dropping a signer keeps the structure legal but changes the
        # challenge and the signer set.
        dropped = dataclasses.replace(
            self.receipt,
            signature=dataclasses.replace(self.signature, signer_ids=(3,)),
        )
        self.assertFalse(verify_signature_receipt(dropped))

        # Out-of-range edits are structural defects, not false verdicts.
        for label, bad in {
            "R zero": dataclasses.replace(
                self.receipt,
                signature=dataclasses.replace(self.signature, R=0),
            ),
            "z too large": dataclasses.replace(
                self.receipt,
                signature=dataclasses.replace(self.signature, z=FIELD_PRIME),
            ),
            "public key too large": dataclasses.replace(
                self.receipt, public_key=GROUP_PRIME
            ),
            "reordered signers": dataclasses.replace(
                self.receipt,
                signature=dataclasses.replace(
                    self.signature, signer_ids=(3, 1)
                ),
            ),
        }.items():
            with self.subTest(label):
                with self.assertRaises(ValueError):
                    verify_signature_receipt(bad)

    def test_tampered_group_parameters_raise_or_return_false(self):
        # Illegal primes/divisibility are structural defects -> ValueError.
        for label, changes in {
            "field prime": dict(field_prime=FIELD_PRIME + 1),
            "group prime": dict(group_prime=GROUP_PRIME + 2),
        }.items():
            with self.subTest(label):
                with self.assertRaises(ValueError):
                    verify_signature_receipt(
                        dataclasses.replace(self.receipt, **changes)
                    )
        # The blinding generator 256 is itself a legal, distinct order-q
        # generator: the receipt stays structurally legal but no longer
        # verifies, so a swapped generator returns False.
        swapped = dataclasses.replace(self.receipt, generator=BLINDING_GENERATOR)
        self.assertFalse(verify_signature_receipt(swapped))

    def test_decoded_receipt_verdict_matches_verify_signature(self):
        payload = encode_signature_receipt(self.receipt)
        decoded = decode_signature_receipt(payload)
        self.assertEqual(
            verify_signature_receipt(decoded),
            verify_signature(
                MESSAGE,
                self.signature,
                self.key.public_key,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
                prime=FIELD_PRIME,
            ),
        )

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            verify_signature_receipt("not a receipt")
        with self.assertRaises(TypeError):
            verify_signature_receipt(
                dataclasses.replace(self.receipt, message="not bytes")
            )
        with self.assertRaises(TypeError):
            verify_signature_receipt(
                dataclasses.replace(self.receipt, public_key="no")
            )
        with self.assertRaises(TypeError):
            verify_signature_receipt(
                SignatureReceipt(
                    MESSAGE,
                    "not a signature",
                    self.key.public_key,
                    FIELD_PRIME,
                    GROUP_PRIME,
                    GENERATOR,
                )
            )


if __name__ == "__main__":
    unittest.main()
