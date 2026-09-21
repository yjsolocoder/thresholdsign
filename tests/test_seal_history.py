"""Tests for the order-preserving batch of whole-report seals:
SealHistory / history_message / check_history / encode_history /
decode_history."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    NonceLeakReport,
    ReportSeal,
    SealHistory,
    aggregate_signature,
    check_history,
    create_signature_share,
    create_signing_nonce_commitment,
    create_signing_round,
    decode_history,
    encode_history,
    encode_seal,
    history_message,
    verify_signature,
)

from test_nonce_reuse import (
    FIELD_PRIME,
    GENERATOR,
    GROUP_PRIME,
    fixed_random,
    make_key,
)
from test_nonce_leak_codec import make_leak, make_other_key
from test_report_seal import make_seal, synthetic

SEAL_HISTORY_TAG = b"ts/sh/v1"
WIRE_TAG = b"thresholdsign/seal-history/v1"


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def build_message(history: SealHistory, public_key: int) -> bytes:
    """Independently build the history message straight from the spec."""
    encoded = encode_history(history)
    return SEAL_HISTORY_TAG + hashlib.sha256(encoded).digest() + varint(public_key)


def build_wire(history: SealHistory) -> bytes:
    """Independently build the seal-history wire format straight from the spec."""
    out = bytearray(WIRE_TAG)
    out += u32(len(history.items))
    for item in history.items:
        out += frame(encode_seal(item))
    return bytes(out)


def sign_message(message: bytes, key, signer_ids=(1, 3), seed=900):
    """Sign ``message`` with a real threshold signature of ``key``."""
    commitments = []
    nonce_map = {}
    for index, signer_id in enumerate(signer_ids):
        commitment, nonce = create_signing_nonce_commitment(
            signer_id,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            randbelow=fixed_random(seed + index),
        )
        commitments.append(commitment)
        nonce_map[signer_id] = nonce
    round_info = create_signing_round(message, signer_ids, commitments, key)
    shares = [
        create_signature_share(
            signer_id,
            key.result.shares[key.result.participant_ids.index(signer_id)].y,
            nonce_map[signer_id],
            round_info,
            key,
        )
        for signer_id in signer_ids
    ]
    signature = aggregate_signature(shares, round_info, key)
    assert isinstance(signature, AggregateSignature)
    return signature


def make_history(key, nonces=(777, 888)) -> SealHistory:
    """A history of real seals, one distinct leaked-nonce report per item."""
    seals = []
    for index, nonce in enumerate(nonces):
        report = NonceLeakReport((make_leak(key, nonce=nonce),))
        seals.append(make_seal(report, key, seed=500 + 10 * index))
    return SealHistory(tuple(seals))


class SealHistoryValueTest(unittest.TestCase):
    def test_frozen_single_field_value_equality(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(SealHistory)],
            ["items"],
        )
        seal = ReportSeal(
            NonceLeakReport((synthetic(1, 10),)),
            AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
        )
        history = SealHistory((seal,))  # positional construction
        self.assertEqual(history, SealHistory((seal,)))
        self.assertEqual(history, SealHistory(items=(seal,)))
        self.assertEqual(history.items, (seal,))
        self.assertNotEqual(history, SealHistory((seal, seal)))
        self.assertEqual(hash(history), hash(SealHistory((seal,))))
        with self.assertRaises(FrozenInstanceError):
            history.items = ()

    def test_construction_does_not_validate(self):
        # The container is a plain value: an empty, non-tuple or
        # non-seal item sequence all construct; the codec, the message
        # builder and the checker reject them.
        SealHistory(())
        SealHistory("not-a-tuple")
        SealHistory(("not-a-seal",))


class HistoryMessageTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = make_history(self.key)

    def test_matches_independent_builder(self):
        self.assertEqual(
            history_message(self.history, self.key.public_key),
            build_message(self.history, self.key.public_key),
        )

    def test_layout(self):
        message = history_message(self.history, self.key.public_key)
        self.assertTrue(message.startswith(SEAL_HISTORY_TAG))
        offset = len(SEAL_HISTORY_TAG)
        encoded = encode_history(self.history)
        self.assertEqual(
            message[offset:offset + 32], hashlib.sha256(encoded).digest()
        )
        offset += 32
        length = int.from_bytes(message[offset:offset + 4], "big")
        self.assertEqual(
            message[offset + 4:],
            self.key.public_key.to_bytes(length, "big"),
        )

    def test_message_is_unique_and_stateless(self):
        first = history_message(self.history, self.key.public_key)
        second = history_message(self.history, self.key.public_key)
        self.assertEqual(first, second)
        self.assertNotEqual(
            first, history_message(self.history, self.key.public_key + 1)
        )

    def test_binds_the_exact_item_sequence(self):
        reordered = SealHistory((self.history.items[1], self.history.items[0]))
        self.assertNotEqual(
            history_message(self.history, self.key.public_key),
            history_message(reordered, self.key.public_key),
        )
        extended = SealHistory(self.history.items + self.history.items[:1])
        self.assertNotEqual(
            history_message(self.history, self.key.public_key),
            history_message(extended, self.key.public_key),
        )

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            history_message(tuple(self.history.items), self.key.public_key)
        with self.assertRaises(TypeError):
            history_message("history", self.key.public_key)
        with self.assertRaises(TypeError):
            history_message(self.history, "key")
        with self.assertRaises(TypeError):
            history_message(self.history, True)
        with self.assertRaises(TypeError):
            history_message(SealHistory("not-a-tuple"), self.key.public_key)
        with self.assertRaises(TypeError):
            history_message(
                SealHistory(("not-a-seal",)), self.key.public_key
            )

    def test_structure_errors(self):
        with self.assertRaises(ValueError):
            history_message(SealHistory(()), self.key.public_key)
        with self.assertRaises(ValueError):
            history_message(self.history, 0)
        with self.assertRaises(ValueError):
            history_message(self.history, -1)
        # A structurally illegal seal inside the history.
        bad = ReportSeal(
            NonceLeakReport((synthetic(1, 10),)),
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
        )
        with self.assertRaises(ValueError):
            history_message(SealHistory((bad,)), self.key.public_key)


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = make_history(self.key)

    def test_round_trip_real_history(self):
        wire = encode_history(self.history)
        decoded = decode_history(wire)
        self.assertEqual(decoded, self.history)
        self.assertEqual(encode_history(decoded), wire)
        self.assertIsInstance(decoded, SealHistory)
        self.assertIsInstance(decoded.items, tuple)
        self.assertTrue(
            all(isinstance(item, ReportSeal) for item in decoded.items)
        )

    def test_encoding_matches_independent_builder(self):
        self.assertEqual(encode_history(self.history), build_wire(self.history))

    def test_starts_with_tag_and_layout(self):
        wire = encode_history(self.history)
        self.assertTrue(wire.startswith(WIRE_TAG))
        offset = len(WIRE_TAG)
        self.assertEqual(wire[offset:offset + 4], u32(len(self.history.items)))
        offset += 4
        for item in self.history.items:
            encoded = encode_seal(item)
            self.assertEqual(wire[offset:offset + 4], u32(len(encoded)))
            offset += 4
            self.assertEqual(wire[offset:offset + len(encoded)], encoded)
            offset += len(encoded)
        self.assertEqual(offset, len(wire))

    def test_single_item_history_round_trip(self):
        history = SealHistory(self.history.items[:1])
        wire = encode_history(history)
        self.assertEqual(decode_history(wire), history)
        self.assertEqual(encode_history(decode_history(wire)), wire)

    def test_encoding_is_structure_only(self):
        # Seals that seal nothing are transported verbatim; check_history
        # remains the sole verifier.
        seal = ReportSeal(
            NonceLeakReport((synthetic(9, 3),)),
            AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
        )
        history = SealHistory((seal,))
        decoded = decode_history(encode_history(history))
        self.assertEqual(decoded, history)
        self.assertEqual(decoded.items[0].signature.z, 7)


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = make_history(self.key)

    def test_non_history_type_error(self):
        with self.assertRaises(TypeError):
            encode_history(tuple(self.history.items))
        with self.assertRaises(TypeError):
            encode_history(self.history.items[0])

    def test_items_type_errors(self):
        with self.assertRaises(TypeError):
            encode_history(SealHistory("not-a-tuple"))
        with self.assertRaises(TypeError):
            encode_history(SealHistory(list(self.history.items)))
        with self.assertRaises(TypeError):
            encode_history(SealHistory(("not-a-seal",)))
        with self.assertRaises(TypeError):
            encode_history(
                SealHistory((self.history.items[0], "not-a-seal"))
            )

    def test_empty_history_value_error(self):
        with self.assertRaises(ValueError):
            encode_history(SealHistory(()))

    def test_illegal_nested_seal_value_error(self):
        bad = ReportSeal(
            NonceLeakReport((synthetic(1, 10),)),
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
        )
        with self.assertRaises(ValueError):
            encode_history(SealHistory((bad,)))
        with self.assertRaises(ValueError):
            encode_history(
                SealHistory((self.history.items[0], bad))
            )


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = make_history(self.key)
        self.wire = encode_history(self.history)

    def test_non_bytes_type_error(self):
        with self.assertRaises(TypeError):
            decode_history("not bytes")
        with self.assertRaises(TypeError):
            decode_history(bytearray(self.wire))

    def test_bad_tag(self):
        with self.assertRaises(ValueError):
            decode_history(
                b"thresholdsign/seal-history/v2" + self.wire[len(WIRE_TAG):]
            )
        with self.assertRaises(ValueError):
            decode_history(b"x" + self.wire[1:])

    def test_truncation(self):
        for cut in range(len(WIRE_TAG), len(self.wire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_history(self.wire[:cut])

    def test_header_truncation(self):
        with self.assertRaises(ValueError):
            decode_history(WIRE_TAG)
        with self.assertRaises(ValueError):
            decode_history(WIRE_TAG + b"\x00\x00")

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_history(self.wire + b"\x00")

    def test_zero_count_rejected(self):
        with self.assertRaises(ValueError):
            decode_history(WIRE_TAG + u32(0))

    def test_count_mismatch_rejected(self):
        first = frame(encode_seal(self.history.items[0]))
        second = frame(encode_seal(self.history.items[1]))
        # Declares two items, one frame follows.
        with self.assertRaises(ValueError):
            decode_history(WIRE_TAG + u32(2) + first)
        # Declares one item, two frames follow (the second is trailing).
        with self.assertRaises(ValueError):
            decode_history(WIRE_TAG + u32(1) + first + second)

    def test_zero_length_frame_rejected(self):
        with self.assertRaises(ValueError):
            decode_history(WIRE_TAG + u32(1) + u32(0))

    def test_nested_seal_bad_tag_rejected(self):
        encoded = encode_seal(self.history.items[0])
        bad = b"ts/nlrs/w2" + encoded[len(b"ts/nlrs/w1"):]
        with self.assertRaises(ValueError):
            decode_history(WIRE_TAG + u32(1) + frame(bad))

    def test_nested_seal_non_canonical_rejected(self):
        encoded = encode_seal(self.history.items[0])
        # A trailing byte inside the nested seal frame.
        with self.assertRaises(ValueError):
            decode_history(WIRE_TAG + u32(1) + frame(encoded + b"\x00"))
        # A truncated nested seal.
        with self.assertRaises(ValueError):
            decode_history(WIRE_TAG + u32(1) + frame(encoded[:-1]))


class CheckHistoryTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = make_history(self.key)
        self.signature = sign_message(
            history_message(self.history, self.key.public_key), self.key
        )

    def test_real_history_verifies(self):
        self.assertTrue(
            check_history(self.history, self.signature, self.key)
        )

    def test_decoded_history_verifies(self):
        decoded = decode_history(encode_history(self.history))
        self.assertTrue(check_history(decoded, self.signature, self.key))

    def test_single_item_history_verifies(self):
        history = SealHistory(self.history.items[:1])
        signature = sign_message(
            history_message(history, self.key.public_key), self.key, seed=910
        )
        self.assertTrue(check_history(history, signature, self.key))

    def test_history_message_is_what_the_signature_covers(self):
        self.assertTrue(
            verify_signature(
                history_message(self.history, self.key.public_key),
                self.signature,
                self.key.public_key,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            )
        )

    def test_deleted_item_returns_false(self):
        deleted = SealHistory(self.history.items[:1])
        self.assertFalse(check_history(deleted, self.signature, self.key))

    def test_inserted_item_returns_false(self):
        inserted = SealHistory(self.history.items + self.history.items[:1])
        self.assertFalse(check_history(inserted, self.signature, self.key))

    def test_reordered_items_return_false(self):
        reordered = SealHistory((self.history.items[1], self.history.items[0]))
        self.assertFalse(check_history(reordered, self.signature, self.key))

    def test_tampered_seal_returns_false(self):
        # The first seal's signature over a different, tampered report:
        # the per-item verify_seal fails before the signature is checked.
        leak = self.history.items[0].report.items[0]
        tampered = dataclasses.replace(
            leak, share=(leak.share + 1) % FIELD_PRIME
        )
        bad_seal = ReportSeal(
            NonceLeakReport((tampered,)), self.history.items[0].signature
        )
        history = SealHistory((bad_seal,) + self.history.items[1:])
        self.assertFalse(check_history(history, self.signature, self.key))

    def test_tampered_signature_returns_false(self):
        tampered = dataclasses.replace(
            self.signature, z=(self.signature.z + 1) % FIELD_PRIME
        )
        self.assertFalse(check_history(self.history, tampered, self.key))

    def test_foreign_key_returns_false(self):
        other_key = make_other_key()
        self.assertNotEqual(other_key.public_key, self.key.public_key)
        self.assertFalse(check_history(self.history, self.signature, other_key))

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            check_history(tuple(self.history.items), self.signature, self.key)
        with self.assertRaises(TypeError):
            check_history("history", self.signature, self.key)
        with self.assertRaises(TypeError):
            check_history(self.history, "signature", self.key)
        with self.assertRaises(TypeError):
            check_history(self.history, self.signature, "key")
        with self.assertRaises(TypeError):
            check_history(self.history, self.signature, None)
        with self.assertRaises(TypeError):
            check_history(
                SealHistory(("not-a-seal",)), self.signature, self.key
            )

    def test_structure_errors(self):
        with self.assertRaises(ValueError):
            check_history(SealHistory(()), self.signature, self.key)
        with self.assertRaises(ValueError):
            check_history(
                self.history,
                AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
                self.key,
            )
        with self.assertRaises(ValueError):
            check_history(
                self.history,
                AggregateSignature(R=5, z=7, signer_ids=()),
                self.key,
            )


if __name__ == "__main__":
    unittest.main()
