"""Tests for the threshold-Schnorr-authenticated whole nonce-leak report
seal: ReportSeal / seal_message / encode_seal / decode_seal / verify_seal."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    NonceLeak,
    NonceLeakReport,
    ReportSeal,
    SigningAudit,
    aggregate_signature,
    create_signing_nonce_commitment,
    create_signing_round,
    create_signature_share,
    decode_seal,
    encode_nonce_leak_report,
    encode_seal,
    seal_message,
    verify_seal,
    verify_signature,
)

from test_nonce_reuse import (
    FIELD_PRIME,
    GROUP_PRIME,
    GENERATOR,
    fixed_random,
    make_key,
)
from test_nonce_leak_codec import make_leak, make_other_key
from test_nonce_leak_report import make_leak_for, synthetic

SEAL_TAG = b"ts/nlrs/v1"
WIRE_TAG = b"ts/nlrs/w1"
NLR_WIRE_TAG = b"thresholdsign/nlr/v1"


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def read_wire_varint(stream, offset):
    """Read one length-prefixed integer from a wire encoding in tests."""
    length = int.from_bytes(stream[offset:offset + 4], "big")
    offset += 4
    value = int.from_bytes(stream[offset:offset + length], "big")
    return value, offset + length


def build_wire(seal: ReportSeal) -> bytes:
    """Independently build the report-seal wire format straight from the spec."""
    encoded_report = encode_nonce_leak_report(seal.report)
    out = bytearray(WIRE_TAG)
    out += u32(len(encoded_report))
    out += encoded_report
    signature = seal.signature
    out += varint(signature.R)
    out += varint(signature.z)
    out += u32(len(signature.signer_ids))
    for signer_id in signature.signer_ids:
        out += varint(signer_id)
    return bytes(out)


def build_message(report: NonceLeakReport, public_key: int) -> bytes:
    """Independently build the signed seal message straight from the spec."""
    encoded_report = encode_nonce_leak_report(report)
    return SEAL_TAG + hashlib.sha256(encoded_report).digest() + varint(public_key)


def sign_message(key, message, signer_ids=(1, 3), seed=500):
    """Threshold-sign ``message`` with ``signer_ids`` of ``key``."""
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


def make_report(key):
    """A real two-finding report over signers 1 and 3."""
    first = make_leak_for(key, 1, 777)
    second = make_leak_for(key, 3, 555)
    return NonceLeakReport((first, second))


def make_seal(key, report=None, signer_ids=(1, 3), seed=500):
    """Seal a real report with a threshold signature of the key."""
    if report is None:
        report = make_report(key)
    signature = sign_message(
        key, seal_message(report, key.public_key), signer_ids=signer_ids, seed=seed
    )
    return ReportSeal(report, signature)


class ReportSealValueTest(unittest.TestCase):
    def test_frozen_fields_value_equality(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(ReportSeal)],
            ["report", "signature"],
        )
        report = NonceLeakReport((synthetic(1, 10),))
        sig = AggregateSignature(R=2, z=3, signer_ids=(1, 3))
        seal = ReportSeal(report, sig)  # positional construction
        same = ReportSeal(report=report, signature=sig)
        self.assertEqual(seal, same)
        self.assertEqual(hash(seal), hash(same))
        self.assertNotEqual(seal, ReportSeal(report, dataclasses.replace(sig, z=4)))
        self.assertEqual(seal.report, report)
        self.assertEqual(seal.signature, sig)
        with self.assertRaises(FrozenInstanceError):
            seal.report = NonceLeakReport((synthetic(2, 20),))

    def test_construction_does_not_validate(self):
        # The container is a plain value: an empty/unordered report and a
        # loose signature all construct; the codec and verifier reject them.
        ReportSeal(NonceLeakReport(()), AggregateSignature(0, -1, ()))
        first = synthetic(1, 10)
        second = synthetic(2, 20)
        ReportSeal(NonceLeakReport((second, first)), "not-a-signature")
        ReportSeal("not-a-report", object())


class SealMessageTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.report = make_report(self.key)

    def test_layout_matches_independent_builder(self):
        message = seal_message(self.report, self.key.public_key)
        self.assertEqual(message, build_message(self.report, self.key.public_key))
        self.assertTrue(message.startswith(SEAL_TAG))
        offset = len(SEAL_TAG)
        self.assertEqual(
            message[offset:offset + 32],
            hashlib.sha256(encode_nonce_leak_report(self.report)).digest(),
        )
        offset += 32
        self.assertEqual(message[offset:], varint(self.key.public_key))
        # The key is a length-prefixed VARINT, not a bare minimal BE value.
        key_length = int.from_bytes(message[offset:offset + 4], "big")
        self.assertEqual(message[offset + 4:offset + 4 + key_length],
                         self.key.public_key.to_bytes(key_length, "big"))
        self.assertEqual(offset + 4 + key_length, len(message))

    def test_single_finding_layout(self):
        report = NonceLeakReport((make_leak(self.key),))
        message = seal_message(report, self.key.public_key)
        self.assertEqual(message, build_message(report, self.key.public_key))

    def test_deterministic(self):
        self.assertEqual(
            seal_message(self.report, self.key.public_key),
            seal_message(self.report, self.key.public_key),
        )

    def test_report_order_matters(self):
        first, second = self.report.items
        reordered = NonceLeakReport((second, first))
        # The reordered report itself is not a legal encoding input.
        with self.assertRaises(ValueError):
            seal_message(reordered, self.key.public_key)

    def test_key_is_bound(self):
        other_key = make_other_key()
        self.assertNotEqual(other_key.public_key, self.key.public_key)
        self.assertNotEqual(
            seal_message(self.report, self.key.public_key),
            seal_message(self.report, other_key.public_key),
        )

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            seal_message(self.report.items, self.key.public_key)
        with self.assertRaises(TypeError):
            seal_message("report", self.key.public_key)
        with self.assertRaises(TypeError):
            seal_message(None, self.key.public_key)
        with self.assertRaises(TypeError):
            seal_message(self.report, str(self.key.public_key))
        with self.assertRaises(TypeError):
            seal_message(self.report, True)

    def test_value_errors(self):
        with self.assertRaises(ValueError):
            seal_message(NonceLeakReport(()), self.key.public_key)
        with self.assertRaises(ValueError):
            seal_message(self.report, 0)
        with self.assertRaises(ValueError):
            seal_message(self.report, -1)
        first, second = self.report.items
        with self.assertRaises(ValueError):
            seal_message(NonceLeakReport((second, first)), self.key.public_key)


class EncodeSealTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.seal = make_seal(self.key)

    def test_layout_matches_independent_builder(self):
        self.assertEqual(encode_seal(self.seal), build_wire(self.seal))

    def test_tag_report_frame_and_signature_frame_in_order(self):
        wire = encode_seal(self.seal)
        self.assertTrue(wire.startswith(WIRE_TAG))
        offset = len(WIRE_TAG)
        encoded_report = encode_nonce_leak_report(self.seal.report)
        self.assertEqual(int.from_bytes(wire[offset:offset + 4], "big"),
                         len(encoded_report))
        offset += 4
        self.assertEqual(wire[offset:offset + len(encoded_report)], encoded_report)
        offset += len(encoded_report)
        R, offset = read_wire_varint(wire, offset)
        z, offset = read_wire_varint(wire, offset)
        self.assertEqual(R, self.seal.signature.R)
        self.assertEqual(z, self.seal.signature.z)
        signer_count = int.from_bytes(wire[offset:offset + 4], "big")
        offset += 4
        signer_ids = []
        for _ in range(signer_count):
            signer_id, offset = read_wire_varint(wire, offset)
            signer_ids.append(signer_id)
        self.assertEqual(tuple(signer_ids), self.seal.signature.signer_ids)
        self.assertEqual(offset, len(wire))

    def test_deterministic_and_order_bound(self):
        wire = encode_seal(self.seal)
        self.assertEqual(wire, encode_seal(self.seal))
        first, second = self.seal.report.items
        reordered = ReportSeal(
            NonceLeakReport((second, first)), self.seal.signature
        )
        with self.assertRaises(ValueError):
            encode_seal(reordered)

    def test_roundtrip(self):
        decoded = decode_seal(encode_seal(self.seal))
        self.assertEqual(decoded, self.seal)
        self.assertEqual(encode_seal(decoded), encode_seal(self.seal))

    def test_zero_z_encodes_as_single_00(self):
        report = NonceLeakReport((synthetic(1, 10),))
        sig = AggregateSignature(R=2, z=0, signer_ids=(1,))
        seal = ReportSeal(report, sig)
        wire = encode_seal(seal)
        self.assertIn(b"\x00\x00\x00\x01\x00", wire)
        self.assertEqual(decode_seal(wire), seal)

    def test_encode_does_not_require_matching_findings_or_signature(self):
        # Opaque receipts that are not real audits still encode and
        # round-trip; verify_seal is the first thing to inspect them.
        report = NonceLeakReport((synthetic(9, 3, share=11),))
        seal = ReportSeal(report, self.seal.signature)
        decoded = decode_seal(encode_seal(seal))
        self.assertEqual(decoded, seal)

    def test_signer_count_overflow_raises_value_error(self):
        class HugeIds(tuple):
            def __len__(self):
                return 2 ** 32

        sig = dataclasses.replace(self.seal.signature, signer_ids=HugeIds((1,)))
        with self.assertRaises(ValueError):
            encode_seal(ReportSeal(self.seal.report, sig))

    def test_type_errors(self):
        report, sig = self.seal.report, self.seal.signature
        for bad in ("seal", None, 42, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_seal(bad)
        with self.assertRaises(TypeError):
            encode_seal(ReportSeal(report.items, sig))
        with self.assertRaises(TypeError):
            encode_seal(ReportSeal(report, "sig"))
        with self.assertRaises(TypeError):
            encode_seal(ReportSeal(report, object()))
        with self.assertRaises(TypeError):
            encode_seal(ReportSeal(NonceLeakReport([report.items[0]]), sig))
        with self.assertRaises(TypeError):
            encode_seal(ReportSeal(report, dataclasses.replace(sig, R="1")))
        with self.assertRaises(TypeError):
            encode_seal(ReportSeal(report, dataclasses.replace(sig, R=True)))
        with self.assertRaises(TypeError):
            encode_seal(
                ReportSeal(report, dataclasses.replace(sig, signer_ids=[1, 3]))
            )
        with self.assertRaises(TypeError):
            encode_seal(
                ReportSeal(report, dataclasses.replace(sig, signer_ids=(1, "3")))
            )

    def test_value_errors(self):
        report, sig = self.seal.report, self.seal.signature
        with self.assertRaises(ValueError):
            encode_seal(ReportSeal(NonceLeakReport(()), sig))
        first, second = report.items
        with self.assertRaises(ValueError):
            encode_seal(
                ReportSeal(NonceLeakReport((second, first)), sig)
            )
        with self.assertRaises(ValueError):
            encode_seal(ReportSeal(report, dataclasses.replace(sig, R=0)))
        with self.assertRaises(ValueError):
            encode_seal(ReportSeal(report, dataclasses.replace(sig, R=-1)))
        with self.assertRaises(ValueError):
            encode_seal(ReportSeal(report, dataclasses.replace(sig, z=-1)))
        with self.assertRaises(ValueError):
            encode_seal(ReportSeal(report, dataclasses.replace(sig, signer_ids=())))
        with self.assertRaises(ValueError):
            encode_seal(
                ReportSeal(report, dataclasses.replace(sig, signer_ids=(0, 1)))
            )
        with self.assertRaises(ValueError):
            encode_seal(
                ReportSeal(report, dataclasses.replace(sig, signer_ids=(3, 1)))
            )
        with self.assertRaises(ValueError):
            encode_seal(
                ReportSeal(report, dataclasses.replace(sig, signer_ids=(1, 1)))
            )


class DecodeSealTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.seal = make_seal(self.key)

    def test_roundtrip_value_equality(self):
        decoded = decode_seal(encode_seal(self.seal))
        self.assertEqual(decoded, self.seal)
        self.assertEqual(encode_seal(decoded), encode_seal(self.seal))

    def test_decoded_seal_still_verifies(self):
        decoded = decode_seal(encode_seal(self.seal))
        self.assertTrue(verify_seal(decoded, self.key))

    def test_bad_signature_decodes_without_verification(self):
        bad_sig = dataclasses.replace(
            self.seal.signature, z=(self.seal.signature.z + 1) % FIELD_PRIME
        )
        seal = ReportSeal(self.seal.report, bad_sig)
        decoded = decode_seal(encode_seal(seal))
        self.assertEqual(decoded, seal)
        self.assertFalse(verify_seal(decoded, self.key))

    def test_opaque_nested_receipts_kept(self):
        item = synthetic(9, 3, share=11)
        report = NonceLeakReport((item,))
        seal = ReportSeal(report, self.seal.signature)
        decoded = decode_seal(encode_seal(seal))
        self.assertEqual(decoded, seal)
        self.assertEqual(decoded.report.items[0].receipts[0].payload,
                         item.receipts[0].payload)

    def test_rejects_bad_argument_types(self):
        wire = encode_seal(self.seal)
        for bad in ("wire", bytearray(wire), None, 42):
            with self.assertRaises(TypeError, msg=repr(bad)):
                decode_seal(bad)

    def test_rejects_bad_tag(self):
        wire = encode_seal(self.seal)
        with self.assertRaises(ValueError):
            decode_seal(b"x" + wire[1:])
        with self.assertRaises(ValueError):
            decode_seal(WIRE_TAG[:-1] + b"2" + wire[len(WIRE_TAG):])
        with self.assertRaises(ValueError):
            decode_seal(WIRE_TAG)
        with self.assertRaises(ValueError):
            decode_seal(b"")
        # The signed message tag must not be accepted as the wire tag.
        with self.assertRaises(ValueError):
            decode_seal(SEAL_TAG + wire[len(WIRE_TAG):])
        # The nested report tag must not be accepted at the outer level.
        with self.assertRaises(ValueError):
            decode_seal(NLR_WIRE_TAG + wire[len(WIRE_TAG):])

    def test_rejects_truncation_at_every_cut(self):
        wire = encode_seal(self.seal)
        for cut in range(len(wire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_seal(wire[:cut])

    def test_rejects_trailing_bytes(self):
        wire = encode_seal(self.seal)
        with self.assertRaises(ValueError):
            decode_seal(wire + b"\x00")
        with self.assertRaises(ValueError):
            decode_seal(wire + b"extra")

    def test_rejects_zero_or_oversized_report_frame(self):
        with self.assertRaises(ValueError):
            decode_seal(WIRE_TAG + u32(0))
        with self.assertRaises(ValueError):
            decode_seal(WIRE_TAG + u32(0xFFFFFFFF) + b"a")

    def test_rejects_truncated_report_frame(self):
        encoded_report = encode_nonce_leak_report(self.seal.report)
        with self.assertRaises(ValueError):
            decode_seal(
                WIRE_TAG + u32(len(encoded_report)) + encoded_report[:-1]
            )

    def test_rejects_nested_trailing_bytes(self):
        encoded_report = encode_nonce_leak_report(self.seal.report)
        with self.assertRaises(ValueError):
            decode_seal(
                WIRE_TAG + u32(len(encoded_report) + 1) + encoded_report + b"\x00"
            )

    def test_rejects_nested_non_canonical_report(self):
        encoded_report = bytearray(encode_nonce_leak_report(self.seal.report))
        # Flip the nested item count to zero: structurally illegal report.
        pos = len(NLR_WIRE_TAG)
        encoded_report[pos:pos + 4] = u32(0)
        with self.assertRaises(ValueError):
            decode_seal(WIRE_TAG + u32(len(encoded_report)) + bytes(encoded_report))

    def test_rejects_zero_R(self):
        report = NonceLeakReport((synthetic(1, 10),))
        seal = ReportSeal(report, AggregateSignature(R=2, z=0, signer_ids=(1,)))
        wire = bytearray(encode_seal(seal))
        encoded_report = encode_nonce_leak_report(report)
        pos = len(WIRE_TAG) + 4 + len(encoded_report)
        self.assertEqual(bytes(wire[pos:pos + 5]), u32(1) + b"\x02")
        wire[pos + 4] = 0
        with self.assertRaises(ValueError):
            decode_seal(bytes(wire))

    def test_rejects_non_canonical_integer(self):
        report = NonceLeakReport((synthetic(1, 10),))
        seal = ReportSeal(report, AggregateSignature(R=256, z=3, signer_ids=(1, 3)))
        wire = bytearray(encode_seal(seal))
        encoded_report = encode_nonce_leak_report(report)
        pos = len(WIRE_TAG) + 4 + len(encoded_report)
        self.assertEqual(bytes(wire[pos:pos + 4]), u32(2))
        wire[pos:pos + 6] = u32(3) + b"\x00\x01\x00"
        with self.assertRaises(ValueError):
            decode_seal(bytes(wire))

    def test_rejects_bad_signer_sets(self):
        item = synthetic(1, 10)
        encoded_report = encode_nonce_leak_report(NonceLeakReport((item,)))
        base = (
            WIRE_TAG
            + u32(len(encoded_report)) + encoded_report
            + varint(5) + varint(7)
        )
        # Zero signers.
        with self.assertRaises(ValueError):
            decode_seal(base + u32(0))
        # Zero id.
        with self.assertRaises(ValueError):
            decode_seal(base + u32(1) + varint(0))
        # Non-increasing and duplicate ids.
        with self.assertRaises(ValueError):
            decode_seal(base + u32(2) + varint(3) + varint(2))
        with self.assertRaises(ValueError):
            decode_seal(base + u32(2) + varint(2) + varint(2))
        # Two signers declared but one id follows -> truncation.
        with self.assertRaises(ValueError):
            decode_seal(base + u32(2) + varint(2))


class VerifySealTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.report = make_report(self.key)
        self.seal = make_seal(self.key, self.report)

    def test_honest_seal_verifies(self):
        self.assertTrue(verify_seal(self.seal, self.key))

    def test_single_finding_seal_verifies(self):
        report = NonceLeakReport((self.report.items[0],))
        self.assertTrue(verify_seal(make_seal(self.key, report, seed=510), self.key))

    def test_decoded_seal_verifies(self):
        decoded = decode_seal(encode_seal(self.seal))
        self.assertTrue(verify_seal(decoded, self.key))

    def test_message_was_signed_under_the_key(self):
        # The signature is an ordinary threshold Schnorr signature on the
        # canonical seal message, independently verifiable.
        message = seal_message(self.report, self.key.public_key)
        self.assertTrue(
            verify_signature(
                message,
                self.seal.signature,
                self.key.public_key,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            )
        )

    def test_tampered_finding_returns_false(self):
        tampered = dataclasses.replace(
            self.report.items[1],
            share=(self.report.items[1].share + 1) % FIELD_PRIME,
        )
        seal = ReportSeal(
            NonceLeakReport((self.report.items[0], tampered)),
            self.seal.signature,
        )
        self.assertFalse(verify_seal(seal, self.key))

    def test_signature_over_another_report_returns_false(self):
        other_report = NonceLeakReport((self.report.items[0],))
        foreign_signature = sign_message(
            self.key, seal_message(other_report, self.key.public_key), seed=520
        )
        seal = ReportSeal(self.report, foreign_signature)
        self.assertFalse(verify_seal(seal, self.key))

    def test_bad_signature_returns_false(self):
        bad_sig = dataclasses.replace(
            self.seal.signature, z=(self.seal.signature.z + 1) % FIELD_PRIME
        )
        self.assertFalse(
            verify_seal(ReportSeal(self.report, bad_sig), self.key)
        )

    def test_verification_under_another_key_returns_false(self):
        other_key = make_other_key()
        self.assertNotEqual(other_key.public_key, self.key.public_key)
        self.assertFalse(verify_seal(self.seal, other_key))

    def test_structurally_illegal_nested_receipt_raises_value_error(self):
        item = NonceLeak(
            9, 3, 11,
            (SigningAudit(b"not-an-audit"), SigningAudit(b"still-not")),
        )
        seal = make_seal(self.key, NonceLeakReport((item,)), seed=530)
        with self.assertRaises(ValueError):
            verify_seal(seal, self.key)

    def test_type_errors(self):
        report, sig = self.report, self.seal.signature
        with self.assertRaises(TypeError):
            verify_seal("seal", self.key)
        with self.assertRaises(TypeError):
            verify_seal(None, self.key)
        with self.assertRaises(TypeError):
            verify_seal(ReportSeal(report.items, sig), self.key)
        with self.assertRaises(TypeError):
            verify_seal(ReportSeal("report", sig), self.key)
        with self.assertRaises(TypeError):
            verify_seal(ReportSeal(report, "sig"), self.key)
        with self.assertRaises(TypeError):
            verify_seal(ReportSeal(report, None), self.key)
        with self.assertRaises(TypeError):
            verify_seal(self.seal, "key")
        with self.assertRaises(TypeError):
            verify_seal(self.seal, None)

    def test_structure_errors(self):
        sig = self.seal.signature
        with self.assertRaises(ValueError):
            verify_seal(ReportSeal(NonceLeakReport(()), sig), self.key)
        first, second = self.report.items
        with self.assertRaises(ValueError):
            verify_seal(
                ReportSeal(NonceLeakReport((second, first)), sig), self.key
            )
        # An R outside the group is a structurally illegal signature.
        bad_sig = AggregateSignature(R=GROUP_PRIME, z=0, signer_ids=(1, 3))
        with self.assertRaises(ValueError):
            verify_seal(ReportSeal(self.report, bad_sig), self.key)


if __name__ == "__main__":
    unittest.main()
