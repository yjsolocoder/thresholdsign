"""Tests for key-rotation authorization: Rotation / rotation_payload / verify_rotation."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    Rotation,
    aggregate_signature,
    aggregate_signing_dkg,
    create_signature_share,
    create_signing_contribution,
    create_signing_nonce_commitment,
    create_signing_round,
    decode_rotation,
    encode_rotation,
    rotation_payload,
    verify_rotation,
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

ROTATION_TAG = b"thresholdsign/rotation/v1"
ROTATION_CERT_TAG = b"thresholdsign/rotation-cert/v1"
L = (GROUP_PRIME.bit_length() + 7) // 8


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


def sign_message(key, message, signer_ids, seed=100):
    """Run the two-round protocol of ``key`` over ``message``."""
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


def encode(value, length=L):
    return value.to_bytes(length, "big", signed=False)


class RotationTest(unittest.TestCase):
    def test_frozen_positional_value_equality(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(Rotation)],
            ["old", "new", "ids", "t", "q", "p", "g", "sig"],
        )
        sig = AggregateSignature(R=2, z=3, signer_ids=(1, 2))
        cert = Rotation(4, 5, (1, 2), 2, FIELD_PRIME, GROUP_PRIME, GENERATOR, sig)
        same = Rotation(
            old=4,
            new=5,
            ids=(1, 2),
            t=2,
            q=FIELD_PRIME,
            p=GROUP_PRIME,
            g=GENERATOR,
            sig=sig,
        )
        self.assertEqual(cert, same)
        self.assertEqual(hash(cert), hash(same))
        self.assertNotEqual(cert, Rotation(4, 6, (1, 2), 2, FIELD_PRIME, GROUP_PRIME, GENERATOR, sig))
        with self.assertRaises(FrozenInstanceError):
            cert.new = 6


class RotationPayloadTest(unittest.TestCase):
    def test_layout(self):
        old_key, new_key = GENERATOR, BLINDING_GENERATOR  # both in the subgroup
        payload = rotation_payload(
            old_key, new_key, (2, 3, 5), 2, FIELD_PRIME, GROUP_PRIME, GENERATOR
        )
        expected = bytearray(ROTATION_TAG)
        for value in (FIELD_PRIME, GROUP_PRIME, GENERATOR, old_key, new_key):
            expected += encode(value)
        expected += (3).to_bytes(4, "big")
        expected += encode(2)
        for member_id in (2, 3, 5):
            expected += encode(member_id)
        self.assertEqual(payload, bytes(expected))

    def test_no_signature_in_payload(self):
        payload = rotation_payload(
            GENERATOR, BLINDING_GENERATOR, (1,), 1, FIELD_PRIME, GROUP_PRIME, GENERATOR
        )
        self.assertEqual(len(payload), len(ROTATION_TAG) + 5 * L + 4 + L + L)

    def test_large_group_width(self):
        large_L = (LARGE_GROUP.bit_length() + 7) // 8
        self.assertEqual(large_L, 3)
        payload = rotation_payload(
            LARGE_G, LARGE_H, (1, 2), 2, LARGE_FIELD, LARGE_GROUP, LARGE_G
        )
        self.assertEqual(len(payload), len(ROTATION_TAG) + 5 * large_L + 4 + 3 * large_L)
        offset = len(ROTATION_TAG)
        self.assertEqual(int.from_bytes(payload[offset:offset + large_L], "big"), LARGE_FIELD)
        self.assertEqual(
            int.from_bytes(payload[offset + large_L:offset + 2 * large_L], "big"),
            LARGE_GROUP,
        )

    def test_type_errors(self):
        good = (GENERATOR, BLINDING_GENERATOR, (1, 2), 2, FIELD_PRIME, GROUP_PRIME, GENERATOR)
        for position, bad in (
            (0, "100"),
            (1, 2.5),
            (2, [1, 2]),
            (2, (1, "2")),
            (2, (1, True)),
            (3, "2"),
            (4, "q"),
            (5, None),
            (6, True),
        ):
            args = list(good)
            args[position] = bad
            with self.assertRaises(TypeError, msg=f"position {position}"):
                rotation_payload(*args)

    def test_group_errors(self):
        with self.assertRaises(ValueError):  # q not prime
            rotation_payload(100, 200, (1, 2), 2, 2018, GROUP_PRIME, GENERATOR)
        with self.assertRaises(ValueError):  # p not prime
            rotation_payload(100, 200, (1, 2), 2, FIELD_PRIME, 8071, GENERATOR)
        with self.assertRaises(ValueError):  # q does not divide p - 1
            rotation_payload(100, 200, (1, 2), 2, 2017, 8111, GENERATOR)
        with self.assertRaises(ValueError):  # g not in the order-q subgroup
            rotation_payload(100, 200, (1, 2), 2, FIELD_PRIME, GROUP_PRIME, 3)

    def test_public_key_errors(self):
        good = (GENERATOR, BLINDING_GENERATOR, (1, 2), 2, FIELD_PRIME, GROUP_PRIME, GENERATOR)
        for position in (0, 1):
            for bad_key in (0, GROUP_PRIME, GROUP_PRIME + 1, 3):  # 3 not in subgroup
                args = list(good)
                args[position] = bad_key
                with self.assertRaises(ValueError, msg=f"position {position} key {bad_key}"):
                    rotation_payload(*args)

    def test_id_errors(self):
        good = (GENERATOR, BLINDING_GENERATOR, (1, 2), 2, FIELD_PRIME, GROUP_PRIME, GENERATOR)
        for bad_ids in ((), (0,), (FIELD_PRIME,), (2, 1), (1, 1), (3, 2, 1)):
            args = list(good)
            args[2] = bad_ids
            with self.assertRaises(ValueError, msg=f"ids {bad_ids}"):
                rotation_payload(*args)

    def test_threshold_errors(self):
        good = (GENERATOR, BLINDING_GENERATOR, (1, 2), 2, FIELD_PRIME, GROUP_PRIME, GENERATOR)
        for bad_t in (0, -1, 3):
            args = list(good)
            args[3] = bad_t
            with self.assertRaises(ValueError, msg=f"t {bad_t}"):
                rotation_payload(*args)


class VerifyRotationTest(unittest.TestCase):
    def setUp(self):
        self.old_key = make_key(participant_ids=(1, 2, 3), threshold=2)
        self.new_key = make_key(participant_ids=(2, 3, 4, 5), threshold=3)
        self.ids = (2, 3, 4, 5)
        self.t = 3
        payload = rotation_payload(
            self.old_key.public_key,
            self.new_key.public_key,
            self.ids,
            self.t,
            FIELD_PRIME,
            GROUP_PRIME,
            GENERATOR,
        )
        self.payload = payload
        self.sig = sign_message(self.old_key, payload, (1, 3))
        self.cert = Rotation(
            self.old_key.public_key,
            self.new_key.public_key,
            self.ids,
            self.t,
            FIELD_PRIME,
            GROUP_PRIME,
            GENERATOR,
            self.sig,
        )

    def test_honest_certificate_verifies(self):
        self.assertTrue(verify_rotation(self.cert))

    def test_payload_is_signing_round_message(self):
        # The payload was signed through the ordinary two-round protocol, so
        # the certificate signature is a plain threshold signature on it.
        self.assertEqual(self.sig.signer_ids, (1, 3))

    def test_threshold_one_rotation(self):
        old_key = make_key(participant_ids=(1, 2), threshold=1)
        new_key = make_key(participant_ids=(4,), threshold=1)
        payload = rotation_payload(
            old_key.public_key, new_key.public_key, (4,), 1,
            FIELD_PRIME, GROUP_PRIME, GENERATOR,
        )
        sig = sign_message(old_key, payload, (2,), seed=7)
        cert = Rotation(
            old_key.public_key, new_key.public_key, (4,), 1,
            FIELD_PRIME, GROUP_PRIME, GENERATOR, sig,
        )
        self.assertTrue(verify_rotation(cert))

    def test_tampered_fields_return_false(self):
        good = (
            self.old_key.public_key,
            self.new_key.public_key,
            self.ids,
            self.t,
            FIELD_PRIME,
            GROUP_PRIME,
            GENERATOR,
        )
        # Another legal new public key (the old key's own key works).
        for position, bad in (
            (0, self.new_key.public_key),  # old swapped with new
            (1, self.old_key.public_key),  # new swapped with old
            (2, (2, 3, 4)),                # fewer members
            (2, (2, 3, 4, 6)),             # different member
            (3, 2),                        # different threshold
        ):
            args = list(good) + [self.sig]
            args[position] = bad
            self.assertFalse(verify_rotation(Rotation(*args)), msg=f"position {position}")

    def test_tampered_signature_returns_false(self):
        bad_sig = AggregateSignature(
            R=self.sig.R,
            z=(self.sig.z + 1) % FIELD_PRIME,
            signer_ids=self.sig.signer_ids,
        )
        cert = Rotation(
            self.old_key.public_key,
            self.new_key.public_key,
            self.ids,
            self.t,
            FIELD_PRIME,
            GROUP_PRIME,
            GENERATOR,
            bad_sig,
        )
        self.assertFalse(verify_rotation(cert))

    def test_signature_by_wrong_key_returns_false(self):
        # A signature of the same payload by the *new* key must not pass as
        # the old key's authorization.
        sig = sign_message(self.new_key, self.payload, (2, 3, 4), seed=13)
        cert = Rotation(
            self.old_key.public_key,
            self.new_key.public_key,
            self.ids,
            self.t,
            FIELD_PRIME,
            GROUP_PRIME,
            GENERATOR,
            sig,
        )
        self.assertFalse(verify_rotation(cert))

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            verify_rotation("cert")
        good = [
            self.old_key.public_key,
            self.new_key.public_key,
            self.ids,
            self.t,
            FIELD_PRIME,
            GROUP_PRIME,
            GENERATOR,
            self.sig,
        ]
        for position, bad in (
            (0, "1"),
            (1, True),
            (2, [2, 3, 4, 5]),
            (2, (2, "3")),
            (3, 2.0),
            (4, "q"),
            (5, None),
            (6, "g"),
            (7, "sig"),
        ):
            args = list(good)
            args[position] = bad
            with self.assertRaises(TypeError, msg=f"position {position}"):
                verify_rotation(Rotation(*args))

    def test_structure_errors(self):
        good = [
            self.old_key.public_key,
            self.new_key.public_key,
            self.ids,
            self.t,
            FIELD_PRIME,
            GROUP_PRIME,
            GENERATOR,
            self.sig,
        ]
        for position, bad in (
            (0, 3),                    # old not in the subgroup
            (1, GROUP_PRIME),          # new out of range
            (2, (2, 3, 4, 4)),         # duplicate member id
            (2, (3, 2, 4, 5)),         # ids not increasing
            (2, (0, 2, 3, 4)),         # id out of range
            (3, 5),                    # threshold above member count
            (3, 0),                    # threshold below 1
            (4, 2018),                 # q not prime
            (6, 3),                    # g not in the subgroup
        ):
            args = list(good)
            args[position] = bad
            with self.assertRaises(ValueError, msg=f"position {position}"):
                verify_rotation(Rotation(*args))
        # Malformed signature structure: z out of range.
        bad_sig = AggregateSignature(R=self.sig.R, z=FIELD_PRIME, signer_ids=self.sig.signer_ids)
        args = list(good)
        args[7] = bad_sig
        with self.assertRaises(ValueError):
            verify_rotation(Rotation(*args))

    def test_large_group_rotation(self):
        old_key = make_key(
            participant_ids=(1, 2, 3),
            threshold=2,
            field_prime=LARGE_FIELD,
            group_prime=LARGE_GROUP,
            generator=LARGE_G,
            blinding_generator=LARGE_H,
        )
        new_key = make_key(
            participant_ids=(1, 2, 3),
            threshold=2,
            field_prime=LARGE_FIELD,
            group_prime=LARGE_GROUP,
            generator=LARGE_G,
            blinding_generator=LARGE_H,
        )
        # Distinct keys: re-seed the new key's contributions.
        contributions = [
            create_signing_contribution(
                pid,
                (1, 2, 3),
                2,
                prime=LARGE_FIELD,
                group_prime=LARGE_GROUP,
                generator=LARGE_G,
                blinding_generator=LARGE_H,
                randbelow=fixed_random(pid + 50),
            )
            for pid in (1, 2, 3)
        ]
        new_key = aggregate_signing_dkg(contributions)
        payload = rotation_payload(
            old_key.public_key, new_key.public_key, (1, 2, 3), 2,
            LARGE_FIELD, LARGE_GROUP, LARGE_G,
        )
        sig = sign_message(old_key, payload, (2, 3), seed=21)
        cert = Rotation(
            old_key.public_key, new_key.public_key, (1, 2, 3), 2,
            LARGE_FIELD, LARGE_GROUP, LARGE_G, sig,
        )
        self.assertTrue(verify_rotation(cert))


class RotationEncodingTest(unittest.TestCase):
    """Layout, canonicity and rejection tests for encode/decode_rotation."""

    def build_wire(
        self,
        *,
        old=GENERATOR,
        new=BLINDING_GENERATOR,
        ids=(1, 2),
        t=2,
        q=FIELD_PRIME,
        p=GROUP_PRIME,
        g=GENERATOR,
        R=GENERATOR,
        z=3,
        signer_ids=(1, 3),
    ):
        """Hand-build a cert wire encoding independently of encode_rotation."""
        out = bytearray(ROTATION_CERT_TAG)
        out += vint(old) + vint(new)
        out += len(ids).to_bytes(4, "big")
        for member_id in ids:
            out += vint(member_id)
        out += vint(t) + vint(q) + vint(p) + vint(g)
        out += vint(R) + vint(z)
        out += len(signer_ids).to_bytes(4, "big")
        for signer_id in signer_ids:
            out += vint(signer_id)
        return bytes(out)

    def structurally_legal_cert(self, **replacements):
        sig = AggregateSignature(R=GENERATOR, z=3, signer_ids=(1, 3))
        fields = dict(
            old=GENERATOR,
            new=BLINDING_GENERATOR,
            ids=(1, 2),
            t=2,
            q=FIELD_PRIME,
            p=GROUP_PRIME,
            g=GENERATOR,
            sig=sig,
        )
        fields.update(replacements)
        return Rotation(**fields)

    def test_layout_matches_independent_builder(self):
        cert = self.structurally_legal_cert()
        self.assertEqual(encode_rotation(cert), self.build_wire())

    def test_tag_prefix_and_order(self):
        cert = self.structurally_legal_cert()
        wire = encode_rotation(cert)
        self.assertTrue(wire.startswith(ROTATION_CERT_TAG))
        offset = len(ROTATION_CERT_TAG)
        prefix, body = _varint_piece(wire, offset)
        self.assertEqual(int.from_bytes(body, "big"), GENERATOR)  # old
        offset += len(prefix) + len(body)
        prefix, body = _varint_piece(wire, offset)
        self.assertEqual(int.from_bytes(body, "big"), BLINDING_GENERATOR)  # new
        offset += len(prefix) + len(body)
        # ids: 4-byte count, then 1, 2.
        self.assertEqual(int.from_bytes(wire[offset:offset + 4], "big"), 2)
        offset += 4
        prefix, body = _varint_piece(wire, offset)
        self.assertEqual(int.from_bytes(body, "big"), 1)
        offset += len(prefix) + len(body)
        prefix, body = _varint_piece(wire, offset)
        self.assertEqual(int.from_bytes(body, "big"), 2)
        offset += len(prefix) + len(body)
        # t, q, p, g in that order.
        for expected in (2, FIELD_PRIME, GROUP_PRIME, GENERATOR):
            prefix, body = _varint_piece(wire, offset)
            self.assertEqual(int.from_bytes(body, "big"), expected)
            offset += len(prefix) + len(body)

    def test_zero_encodes_as_single_00(self):
        self.assertEqual(vint(0), b"\x00\x00\x00\x01\x00")
        cert = self.structurally_legal_cert(
            sig=AggregateSignature(R=GENERATOR, z=0, signer_ids=(1,))
        )
        wire = encode_rotation(cert)
        self.assertIn(b"\x00\x00\x00\x01\x00", wire)
        decoded = decode_rotation(wire)
        self.assertEqual(decoded.sig.z, 0)

    def test_minimal_positive_encoding(self):
        self.assertEqual(vint(0x07E1), b"\x00\x00\x00\x02\x07\xe1")
        self.assertEqual(vint(256), b"\x00\x00\x00\x02\x01\x00")
        cert = self.structurally_legal_cert()
        wire = encode_rotation(cert)
        self.assertIn(vint(FIELD_PRIME), wire)

    def test_deterministic_unique_output(self):
        cert = self.structurally_legal_cert()
        self.assertEqual(encode_rotation(cert), encode_rotation(cert))
        other = self.structurally_legal_cert(new=GENERATOR)
        self.assertNotEqual(encode_rotation(cert), encode_rotation(other))

    def test_roundtrip_structural_cert(self):
        cert = self.structurally_legal_cert()
        decoded = decode_rotation(encode_rotation(cert))
        self.assertEqual(decoded, cert)
        self.assertEqual(encode_rotation(decoded), encode_rotation(cert))

    def test_rejects_leading_zero_body(self):
        wire = self.build_wire()
        good = vint(FIELD_PRIME)
        # Re-encode the 2-byte q body with a forbidden leading zero.
        bad = b"\x00\x00\x00\x03\x00" + good[4:]
        self.assertRaises(ValueError, decode_rotation, wire.replace(good, bad, 1))

    def test_rejects_zero_length_prefix(self):
        wire = self.build_wire()
        good = vint(FIELD_PRIME)
        self.assertRaises(ValueError, decode_rotation, wire.replace(good, b"\x00\x00\x00\x00", 1))

    def test_rejects_truncation_at_every_cut(self):
        wire = self.build_wire()
        for cut in range(len(wire)):
            with self.assertRaises(ValueError, msg=f"cut {cut}"):
                decode_rotation(wire[:cut])

    def test_rejects_trailing_bytes(self):
        wire = self.build_wire()
        self.assertRaises(ValueError, decode_rotation, wire + b"\x00")
        self.assertRaises(ValueError, decode_rotation, wire + b"extra")

    def test_rejects_bad_tag(self):
        wire = self.build_wire()
        self.assertRaises(ValueError, decode_rotation, b"x" + wire[1:])
        self.assertRaises(ValueError, decode_rotation, ROTATION_CERT_TAG)
        self.assertRaises(ValueError, decode_rotation, b"")

    def test_rejects_declared_count_mismatch(self):
        wire = self.build_wire()
        # Declare three ids right after tag/old/new; the remaining bytes
        # cannot realign into a valid certificate.
        offset = len(ROTATION_CERT_TAG) + 5 + 5
        bad = (
            wire[:offset]
            + (3).to_bytes(4, "big")
            + wire[offset + 4:]
        )
        self.assertRaises(ValueError, decode_rotation, bad)

    def test_rejects_empty_id_lists(self):
        self.assertRaises(ValueError, decode_rotation, self.build_wire(ids=()))
        self.assertRaises(ValueError, decode_rotation, self.build_wire(signer_ids=()))

    def test_rejects_non_positive_or_unordered_wire_ids(self):
        for ids in ((0, 1), (2, 2), (2, 1)):
            with self.assertRaises(ValueError, msg=f"ids {ids}"):
                decode_rotation(self.build_wire(ids=ids, t=1))
        for signer_ids in ((0,), (3, 3), (3, 1)):
            with self.assertRaises(ValueError, msg=f"signer_ids {signer_ids}"):
                decode_rotation(self.build_wire(signer_ids=signer_ids))

    def test_rejects_id_outside_field(self):
        self.assertRaises(ValueError, decode_rotation, self.build_wire(ids=(2017,), t=1))
        self.assertRaises(ValueError, decode_rotation, self.build_wire(signer_ids=(2017,)))

    def test_rejects_illegal_structures(self):
        cases = {
            "old not in subgroup": dict(old=3),
            "new zero": dict(new=0),
            "threshold above count": dict(t=5),
            "q not prime": dict(q=2018),
            "g not in subgroup": dict(g=3),
            "R not in subgroup": dict(R=3),
            "z out of range": dict(z=FIELD_PRIME),
        }
        for label, replacements in cases.items():
            with self.assertRaises(ValueError, msg=label):
                decode_rotation(self.build_wire(**replacements))

    def test_encode_rejects_bad_types(self):
        good = self.structurally_legal_cert()
        self.assertRaises(TypeError, encode_rotation, "cert")
        for label, replacements in (
            ("old str", dict(old="16")),
            ("new bool", dict(new=True)),
            ("ids list", dict(ids=[1, 2])),
            ("id str", dict(ids=(1, "2"))),
            ("t float", dict(t=2.0)),
            ("q str", dict(q="2017")),
            ("p none", dict(p=None)),
            ("sig str", dict(sig="sig")),
            ("R str", dict(sig=AggregateSignature(R="1", z=3, signer_ids=(1,)))),
            ("z float", dict(sig=AggregateSignature(R=GENERATOR, z=3.0, signer_ids=(1,)))),
            ("signer ids list", dict(sig=AggregateSignature(R=GENERATOR, z=3, signer_ids=[1]))),
            ("signer id bool", dict(sig=AggregateSignature(R=GENERATOR, z=3, signer_ids=(True,)))),
        ):
            with self.assertRaises(TypeError, msg=label):
                encode_rotation(dataclasses.replace(good, **replacements))

    def test_encode_rejects_negative_values(self):
        good = self.structurally_legal_cert()
        for label, replacements in (
            ("old", dict(old=-1)),
            ("t", dict(t=-1)),
            ("id", dict(ids=(-2,), t=1)),
            ("z", dict(sig=AggregateSignature(R=GENERATOR, z=-1, signer_ids=(1,)))),
        ):
            with self.assertRaises(ValueError, msg=label):
                encode_rotation(dataclasses.replace(good, **replacements))

    def test_decode_rejects_bad_types(self):
        wire = encode_rotation(self.structurally_legal_cert())
        for bad in ("wire", bytearray(wire), None, 42):
            self.assertRaises(TypeError, decode_rotation, bad)


def vint(value: int) -> bytes:
    """Minimal length-prefixed unsigned big-endian integer (test reference)."""
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def _varint_piece(wire: bytes, offset: int) -> tuple[bytes, bytes]:
    """Return ``(length_prefix, body)`` of the varint starting at ``offset``."""
    length = int.from_bytes(wire[offset:offset + 4], "big")
    return wire[offset:offset + 4], wire[offset + 4:offset + 4 + length]


class RotationEncodingRoundTripTest(unittest.TestCase):
    """Honest certificates survive transport and still verify afterwards."""

    def setUp(self):
        self.old_key = make_key(participant_ids=(1, 2, 3), threshold=2)
        self.new_key = make_key(participant_ids=(2, 3, 4, 5), threshold=3)
        self.ids = (2, 3, 4, 5)
        self.t = 3
        payload = rotation_payload(
            self.old_key.public_key,
            self.new_key.public_key,
            self.ids,
            self.t,
            FIELD_PRIME,
            GROUP_PRIME,
            GENERATOR,
        )
        sig = sign_message(self.old_key, payload, (1, 3))
        self.cert = Rotation(
            self.old_key.public_key,
            self.new_key.public_key,
            self.ids,
            self.t,
            FIELD_PRIME,
            GROUP_PRIME,
            GENERATOR,
            sig,
        )

    def test_honest_cert_roundtrip_and_verifies(self):
        wire = encode_rotation(self.cert)
        decoded = decode_rotation(wire)
        self.assertEqual(decoded, self.cert)
        self.assertEqual(encode_rotation(decoded), wire)
        self.assertTrue(verify_rotation(decoded))

    def test_bad_signature_roundtrips_but_fails_verification(self):
        bad_sig = AggregateSignature(
            R=self.cert.sig.R,
            z=(self.cert.sig.z + 1) % FIELD_PRIME,
            signer_ids=self.cert.sig.signer_ids,
        )
        bad_cert = dataclasses.replace(self.cert, sig=bad_sig)
        decoded = decode_rotation(encode_rotation(bad_cert))
        self.assertEqual(decoded, bad_cert)
        self.assertFalse(verify_rotation(decoded))

    def test_large_group_roundtrip(self):
        old_key = make_key(
            participant_ids=(1, 2, 3),
            threshold=2,
            field_prime=LARGE_FIELD,
            group_prime=LARGE_GROUP,
            generator=LARGE_G,
            blinding_generator=LARGE_H,
        )
        contributions = [
            create_signing_contribution(
                pid,
                (1, 2, 3),
                2,
                prime=LARGE_FIELD,
                group_prime=LARGE_GROUP,
                generator=LARGE_G,
                blinding_generator=LARGE_H,
                randbelow=fixed_random(pid + 50),
            )
            for pid in (1, 2, 3)
        ]
        new_key = aggregate_signing_dkg(contributions)
        payload = rotation_payload(
            old_key.public_key, new_key.public_key, (1, 2, 3), 2,
            LARGE_FIELD, LARGE_GROUP, LARGE_G,
        )
        sig = sign_message(old_key, payload, (2, 3), seed=21)
        cert = Rotation(
            old_key.public_key, new_key.public_key, (1, 2, 3), 2,
            LARGE_FIELD, LARGE_GROUP, LARGE_G, sig,
        )
        wire = encode_rotation(cert)
        decoded = decode_rotation(wire)
        self.assertEqual(decoded, cert)
        self.assertEqual(encode_rotation(decoded), wire)
        self.assertTrue(verify_rotation(decoded))


if __name__ == "__main__":
    unittest.main()
