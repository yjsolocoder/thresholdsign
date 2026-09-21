"""Tests for the order-preserving, threshold-Schnorr-sealed seal history:
SealHistory / history_message / check_history and the canonical transport
encoding encode_history / decode_history."""

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
    decode_seal,
    encode_history,
    encode_nonce_leak_report,
    encode_seal,
    history_message,
)

from test_nonce_reuse import (
    FIELD_PRIME,
    GENERATOR,
    GROUP_PRIME,
    fixed_random,
    make_key,
)
from test_nonce_leak_codec import make_leak, make_other_key
from test_report_seal import WIRE_TAG as SEAL_WIRE_TAG, frame, make_seal, u32, varint

HISTORY_TAG = b"ts/sh/v1"
HISTORY_WIRE_TAG = b"thresholdsign/seal-history/v1"


def build_history_wire(history: SealHistory) -> bytes:
    """Independently build the seal-history wire format straight from the spec."""
    out = bytearray(HISTORY_WIRE_TAG)
    out += u32(len(history.items))
    for item in history.items:
        out += frame(encode_seal(item))
    return bytes(out)


def build_history_message(history: SealHistory, pk: int) -> bytes:
    """Independently build the sealed history message straight from the spec."""
    encoded = build_history_wire(history)
    return HISTORY_TAG + hashlib.sha256(encoded).digest() + varint(pk)


def sign_history(history, key, signer_ids=(1, 3), seed=900) -> AggregateSignature:
    """Seal ``history`` with a real threshold signature of ``key``."""
    message = history_message(history, key.public_key)
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


def make_history(key, seeds=(500, 600), nonces=(777, 778)) -> SealHistory:
    """A two-item history of distinct real seals made by ``key``."""
    seals = tuple(
        make_seal(
            NonceLeakReport((make_leak(key, nonce=nonce),)),
            key,
            seed=seed,
        )
        for seed, nonce in zip(seeds, nonces)
    )
    return SealHistory(seals)


class SealHistoryValueTest(unittest.TestCase):
    def test_single_items_field_value_equality(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(SealHistory)],
            ["items"],
        )
        history_a = make_history(make_key())
        history_b = SealHistory(history_a.items)  # positional construction
        self.assertEqual(history_b, history_a)
        self.assertEqual(history_b, SealHistory(items=history_a.items))
        self.assertEqual(history_b.items, history_a.items)
        self.assertEqual(hash(history_b), hash(history_a))
        self.assertNotEqual(history_a, SealHistory(history_a.items[:1]))
        self.assertNotEqual(
            history_a, SealHistory((history_a.items[1], history_a.items[0]))
        )

    def test_frozen(self):
        history = make_history(make_key())
        with self.assertRaises(FrozenInstanceError):
            history.items = ()

    def test_construction_does_not_validate(self):
        # The container is a plain value: empty and mistyped histories both
        # construct; the codec, message builder and verifier reject them.
        SealHistory(())
        SealHistory(("not-a-seal",))
        SealHistory((ReportSeal("report", "signature"),))


class HistoryMessageTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = make_history(self.key)

    def test_matches_independent_builder(self):
        self.assertEqual(
            history_message(self.history, self.key.public_key),
            build_history_message(self.history, self.key.public_key),
        )

    def test_layout(self):
        message = history_message(self.history, self.key.public_key)
        self.assertTrue(message.startswith(HISTORY_TAG))
        offset = len(HISTORY_TAG)
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

    def test_binds_the_item_sequence_and_order(self):
        items = self.history.items
        message = history_message(self.history, self.key.public_key)
        self.assertNotEqual(
            message,
            history_message(SealHistory(items[:1]), self.key.public_key),
        )
        self.assertNotEqual(
            message,
            history_message(
                SealHistory((items[1], items[0])), self.key.public_key
            ),
        )
        third = make_seal(
            NonceLeakReport((make_leak(self.key, nonce=779),)),
            self.key,
            seed=700,
        )
        self.assertNotEqual(
            message,
            history_message(SealHistory(items + (third,)), self.key.public_key),
        )

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            history_message(self.history.items, self.key.public_key)
        with self.assertRaises(TypeError):
            history_message("history", self.key.public_key)
        with self.assertRaises(TypeError):
            history_message(self.history, "pk")
        with self.assertRaises(TypeError):
            history_message(self.history, True)
        with self.assertRaises(TypeError):
            history_message(SealHistory(("seal",)), self.key.public_key)
        with self.assertRaises(TypeError):
            history_message(SealHistory(["seal"]), self.key.public_key)

    def test_structure_errors(self):
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        with self.assertRaises(ValueError):
            history_message(SealHistory(()), self.key.public_key)
        with self.assertRaises(ValueError):
            history_message(self.history, 0)
        with self.assertRaises(ValueError):
            history_message(self.history, -1)
        with self.assertRaises(ValueError):
            history_message(
                SealHistory(
                    (ReportSeal(NonceLeakReport(()), signature),)
                ),
                self.key.public_key,
            )


class HistoryRoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = make_history(self.key)
        self.wire = encode_history(self.history)

    def test_round_trip_real_history(self):
        decoded = decode_history(self.wire)
        self.assertEqual(decoded, self.history)
        self.assertEqual(encode_history(decoded), self.wire)
        self.assertIsInstance(decoded, SealHistory)
        self.assertEqual(len(decoded.items), 2)
        self.assertIsInstance(decoded.items[0], ReportSeal)

    def test_encoding_matches_independent_builder(self):
        self.assertEqual(self.wire, build_history_wire(self.history))

    def test_starts_with_tag_and_layout(self):
        self.assertTrue(self.wire.startswith(HISTORY_WIRE_TAG))
        offset = len(HISTORY_WIRE_TAG)
        self.assertEqual(self.wire[offset:offset + 4], u32(2))
        offset += 4
        for item in self.history.items:
            encoded_item = encode_seal(item)
            self.assertEqual(self.wire[offset:offset + 4], u32(len(encoded_item)))
            offset += 4
            self.assertEqual(self.wire[offset:offset + len(encoded_item)], encoded_item)
            offset += len(encoded_item)
        self.assertEqual(offset, len(self.wire))

    def test_single_item_round_trip(self):
        history = SealHistory(self.history.items[:1])
        wire = encode_history(history)
        self.assertEqual(decode_history(wire), history)
        self.assertEqual(encode_history(decode_history(wire)), wire)

    def test_order_is_preserved(self):
        reordered = SealHistory(
            (self.history.items[1], self.history.items[0])
        )
        decoded = decode_history(encode_history(reordered))
        self.assertEqual(decoded, reordered)
        self.assertNotEqual(decoded, self.history)

    def test_encoding_is_structure_only(self):
        # decode_history never calls verify_seal: a structurally legal
        # seal whose signature seals nothing is transported byte-for-byte.
        seal = make_seal(
            NonceLeakReport((make_leak(self.key),)), self.key
        )
        bogus = ReportSeal(
            seal.report, AggregateSignature(R=486, z=1858, signer_ids=(1, 3))
        )
        history = SealHistory((bogus, seal))
        wire = encode_history(history)
        self.assertEqual(decode_history(wire), history)
        self.assertEqual(encode_history(decode_history(wire)), wire)


class EncodeHistoryValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = make_history(self.key)

    def test_non_history_type_error(self):
        with self.assertRaises(TypeError):
            encode_history(self.history.items)
        with self.assertRaises(TypeError):
            encode_history("history")

    def test_items_container_type_error(self):
        with self.assertRaises(TypeError):
            encode_history(SealHistory(list(self.history.items)))

    def test_item_type_error(self):
        with self.assertRaises(TypeError):
            encode_history(SealHistory(("not-a-seal",)))
        with self.assertRaises(TypeError):
            encode_history(SealHistory((self.history.items[0], "seal")))

    def test_empty_history_value_error(self):
        with self.assertRaises(ValueError):
            encode_history(SealHistory(()))

    def test_nested_illegal_seal_value_error(self):
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        with self.assertRaises(ValueError):
            encode_history(
                SealHistory((ReportSeal(NonceLeakReport(()), signature),))
            )
        with self.assertRaises(ValueError):
            encode_history(
                SealHistory(
                    (
                        self.history.items[0],
                        ReportSeal(
                            self.history.items[0].report,
                            AggregateSignature(0, 7, (1, 3)),
                        ),
                    )
                )
            )


class DecodeHistoryValidationTest(unittest.TestCase):
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
                b"thresholdsign/seal-history/v2" + self.wire[len(HISTORY_WIRE_TAG):]
            )
        with self.assertRaises(ValueError):
            decode_history(b"x" + self.wire[1:])

    def test_truncation(self):
        for cut in range(len(HISTORY_WIRE_TAG), len(self.wire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_history(self.wire[:cut])

    def test_header_truncation(self):
        with self.assertRaises(ValueError):
            decode_history(HISTORY_WIRE_TAG)
        with self.assertRaises(ValueError):
            decode_history(HISTORY_WIRE_TAG + b"\x00\x00")

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_history(self.wire + b"\x00")

    def test_zero_item_count_rejected(self):
        with self.assertRaises(ValueError):
            decode_history(HISTORY_WIRE_TAG + u32(0))

    def test_oversized_item_count_rejected(self):
        with self.assertRaises(ValueError):
            decode_history(HISTORY_WIRE_TAG + u32(0xFFFFFFFF) + b"\x00")

    def test_empty_frame_rejected(self):
        with self.assertRaises(ValueError):
            decode_history(HISTORY_WIRE_TAG + u32(1) + u32(0))

    def test_item_count_mismatch_rejected(self):
        offset = len(HISTORY_WIRE_TAG) + 4
        first_frame = self.wire[offset:offset + 4 + int.from_bytes(
            self.wire[offset:offset + 4], "big"
        )]
        # Declares two items, one frame follows.
        with self.assertRaises(ValueError):
            decode_history(HISTORY_WIRE_TAG + u32(2) + first_frame)
        # Declares one item, two frames follow (the second frame is trailing).
        with self.assertRaises(ValueError):
            decode_history(HISTORY_WIRE_TAG + u32(1) + first_frame + first_frame)

    def test_frame_truncated(self):
        offset = len(HISTORY_WIRE_TAG) + 4
        with self.assertRaises(ValueError):
            decode_history(self.wire[:offset] + self.wire[offset:-1])

    def test_nested_seal_bad_tag_rejected(self):
        with self.assertRaises(ValueError):
            decode_history(
                HISTORY_WIRE_TAG + u32(1) + frame(b"ts/nlrs/w2")
            )

    def test_nested_seal_non_canonical_rejected(self):
        # A nested seal frame with a zero R fails decode_seal.
        encoded_report = encode_nonce_leak_report(
            self.history.items[0].report
        )
        bad_seal = (
            SEAL_WIRE_TAG
            + frame(encoded_report)
            + varint(0)
            + varint(7)
            + u32(2)
            + varint(1)
            + varint(3)
        )
        with self.assertRaises(ValueError):
            decode_history(HISTORY_WIRE_TAG + u32(1) + frame(bad_seal))

    def test_nested_seal_truncated_rejected(self):
        encoded_seal = encode_seal(self.history.items[0])
        with self.assertRaises(ValueError):
            decode_history(
                HISTORY_WIRE_TAG + u32(1) + frame(encoded_seal[:-1])
            )

    def test_nested_report_non_canonical_rejected(self):
        # Flip the nested report's item count: decode_seal must reject it.
        encoded_seal = bytearray(encode_seal(self.history.items[0]))
        nlr_tag = b"thresholdsign/nlr/v1"
        count_offset = len(SEAL_WIRE_TAG) + 4 + len(nlr_tag)
        encoded_seal[count_offset:count_offset + 4] = u32(99)
        with self.assertRaises(ValueError):
            decode_history(
                HISTORY_WIRE_TAG + u32(1) + frame(bytes(encoded_seal))
            )


class CheckHistoryTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = make_history(self.key)
        self.signature = sign_history(self.history, self.key)

    def test_real_history_checks(self):
        self.assertTrue(check_history(self.history, self.signature, self.key))

    def test_decoded_history_checks(self):
        decoded = decode_history(encode_history(self.history))
        self.assertTrue(check_history(decoded, self.signature, self.key))

    def test_history_message_is_what_the_signature_covers(self):
        from thresholdsign import verify_signature

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
        self.assertFalse(
            check_history(
                SealHistory(self.history.items[:1]), self.signature, self.key
            )
        )

    def test_inserted_item_returns_false(self):
        third = make_seal(
            NonceLeakReport((make_leak(self.key, nonce=779),)),
            self.key,
            seed=700,
        )
        self.assertFalse(
            check_history(
                SealHistory(self.history.items + (third,)),
                self.signature,
                self.key,
            )
        )

    def test_reordered_items_returns_false(self):
        self.assertFalse(
            check_history(
                SealHistory((self.history.items[1], self.history.items[0])),
                self.signature,
                self.key,
            )
        )

    def test_cross_key_substituted_item_returns_false(self):
        other_key = make_other_key()
        foreign = make_seal(
            NonceLeakReport((make_leak(other_key),)), other_key, seed=500
        )
        swapped = SealHistory((self.history.items[0], foreign))
        foreign_signature = sign_history(swapped, self.key, seed=910)
        # Even a signature freshly sealing the swapped sequence cannot
        # rescue the item sealed by the other key.
        self.assertFalse(
            check_history(swapped, foreign_signature, self.key)
        )

    def test_tampered_item_returns_false(self):
        tampered_seal = ReportSeal(
            dataclasses.replace(
                self.history.items[0].report,
                items=(
                    dataclasses.replace(
                        self.history.items[0].report.items[0],
                        share=(
                            self.history.items[0].report.items[0].share + 1
                        )
                        % FIELD_PRIME,
                    ),
                ),
            ),
            self.history.items[0].signature,
        )
        self.assertFalse(
            check_history(
                SealHistory((tampered_seal, self.history.items[1])),
                self.signature,
                self.key,
            )
        )

    def test_tampered_signature_returns_false(self):
        tampered = dataclasses.replace(
            self.signature, z=(self.signature.z + 1) % FIELD_PRIME
        )
        self.assertFalse(check_history(self.history, tampered, self.key))

    def test_foreign_key_returns_false(self):
        other_key = make_other_key()
        self.assertNotEqual(other_key.public_key, self.key.public_key)
        self.assertFalse(
            check_history(self.history, self.signature, other_key)
        )

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            check_history(self.history.items, self.signature, self.key)
        with self.assertRaises(TypeError):
            check_history("history", self.signature, self.key)
        with self.assertRaises(TypeError):
            check_history(self.history, "signature", self.key)
        with self.assertRaises(TypeError):
            check_history(self.history, self.signature, "key")
        with self.assertRaises(TypeError):
            check_history(self.history, self.signature, None)

    def test_structure_errors(self):
        with self.assertRaises(ValueError):
            check_history(SealHistory(()), self.signature, self.key)
        with self.assertRaises(ValueError):
            check_history(
                SealHistory(
                    (
                        ReportSeal(
                            NonceLeakReport(()),
                            AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
                        ),
                    )
                ),
                self.signature,
                self.key,
            )
        with self.assertRaises(ValueError):
            check_history(
                self.history,
                AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
                self.key,
            )


if __name__ == "__main__":
    unittest.main()
