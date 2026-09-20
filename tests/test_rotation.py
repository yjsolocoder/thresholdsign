"""Tests for key rotation certificates: Rotation / rotation_payload / verify_rotation."""

import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    Rotation,
    SigningDKGResult,
    aggregate_signature,
    aggregate_signing_dkg,
    create_signature_share,
    create_signing_contribution,
    create_signing_nonce_commitment,
    create_signing_round,
    rotation_payload,
    verify_rotation,
)

# Same toy group as the signing tests: 8069 = 4 * 2017 + 1 is prime, 16 and
# 256 = 16 ** 2 are distinct generators of the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

ROTATION_TAG = b"thresholdsign/rotation/v1"
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


def make_key(participant_ids, threshold, seed=1):
    """Run a full signing DKG and return the SigningDKGResult."""
    contributions = [
        create_signing_contribution(
            participant_id,
            participant_ids,
            threshold,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            blinding_generator=BLINDING_GENERATOR,
            prime=FIELD_PRIME,
            randbelow=fixed_random(seed + participant_id),
        )
        for participant_id in participant_ids
    ]
    result = aggregate_signing_dkg(contributions)
    assert isinstance(result, SigningDKGResult)
    return result


def sign_message(key, message, signer_ids, seed=100):
    """Run a full two-round signing protocol over ``message``."""
    commitments = []
    nonces = {}
    for signer_id in signer_ids:
        commitment, nonce = create_signing_nonce_commitment(
            signer_id,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            prime=FIELD_PRIME,
            randbelow=fixed_random(seed + signer_id),
        )
        commitments.append(commitment)
        nonces[signer_id] = nonce
    signing_round = create_signing_round(message, signer_ids, commitments, key)
    shares = [
        create_signature_share(
            signer_id,
            key.result.shares[key.result.participant_ids.index(signer_id)].y,
            nonces[signer_id],
            signing_round,
            key,
        )
        for signer_id in signer_ids
    ]
    signature = aggregate_signature(shares, signing_round, key)
    assert isinstance(signature, AggregateSignature)
    return signature


OLD_IDS = (1, 2, 3)
NEW_IDS = (2, 3, 4, 5)
OLD_THRESHOLD = 2
NEW_THRESHOLD = 3


def make_cert(signer_ids=(1, 2), seed=100):
    """A valid rotation certificate from the old key to the new key."""
    old_key = make_key(OLD_IDS, OLD_THRESHOLD, seed=10)
    new_key = make_key(NEW_IDS, NEW_THRESHOLD, seed=50)
    payload = rotation_payload(
        old_key.public_key,
        new_key.public_key,
        NEW_IDS,
        NEW_THRESHOLD,
        FIELD_PRIME,
        GROUP_PRIME,
        GENERATOR,
    )
    signature = sign_message(old_key, payload, signer_ids, seed=seed)
    return old_key, new_key, Rotation(
        old_key.public_key,
        new_key.public_key,
        NEW_IDS,
        NEW_THRESHOLD,
        FIELD_PRIME,
        GROUP_PRIME,
        GENERATOR,
        signature,
    )


class TestRotationPayloadLayout(unittest.TestCase):
    def setUp(self):
        self.old = pow(GENERATOR, 123, GROUP_PRIME)
        self.new = pow(GENERATOR, 456, GROUP_PRIME)
        self.args = (
            self.old,
            self.new,
            NEW_IDS,
            NEW_THRESHOLD,
            FIELD_PRIME,
            GROUP_PRIME,
            GENERATOR,
        )

    def test_exact_byte_layout(self):
        manual = bytearray(ROTATION_TAG)
        for value in (FIELD_PRIME, GROUP_PRIME, GENERATOR, self.old, self.new):
            manual += value.to_bytes(L, "big")
        manual += len(NEW_IDS).to_bytes(4, "big")
        manual += NEW_THRESHOLD.to_bytes(L, "big")
        for member_id in NEW_IDS:
            manual += member_id.to_bytes(L, "big")
        self.assertEqual(rotation_payload(*self.args), bytes(manual))

    def test_ids_sorted_canonically(self):
        payload = rotation_payload(*self.args)
        self.assertEqual(
            rotation_payload(self.old, self.new, (5, 2, 4, 3), *self.args[3:]), payload
        )

    def test_any_iterable_of_ids(self):
        payload = rotation_payload(*self.args)
        self.assertEqual(
            rotation_payload(self.old, self.new, list(NEW_IDS), *self.args[3:]), payload
        )
        self.assertEqual(
            rotation_payload(self.old, self.new, iter(NEW_IDS), *self.args[3:]), payload
        )

    def test_payload_has_no_signature_or_separators(self):
        payload = rotation_payload(*self.args)
        self.assertEqual(len(payload), len(ROTATION_TAG) + 5 * L + 4 + L + len(NEW_IDS) * L)


class TestRotationPayloadErrors(unittest.TestCase):
    def setUp(self):
        self.old = pow(GENERATOR, 123, GROUP_PRIME)
        self.new = pow(GENERATOR, 456, GROUP_PRIME)

        def payload(**overrides):
            arguments = dict(
                old=self.old,
                new=self.new,
                ids=NEW_IDS,
                t=NEW_THRESHOLD,
                q=FIELD_PRIME,
                p=GROUP_PRIME,
                g=GENERATOR,
            )
            arguments.update(overrides)
            return rotation_payload(**arguments)

        self.payload = payload

    def test_type_errors(self):
        for override in (
            {"old": "1"},
            {"old": True},
            {"new": 2.5},
            {"t": "3"},
            {"q": None},
            {"p": GROUP_PRIME + 0.5},
            {"g": b"16"},
            {"ids": "2345"},
            {"ids": 5},
            {"ids": (2, "3", 4, 5)},
            {"ids": (2, True, 4, 5)},
        ):
            with self.subTest(override=override):
                with self.assertRaises(TypeError):
                    self.payload(**override)

    def test_group_value_errors(self):
        for override in (
            {"q": 2016},  # not prime
            {"p": 8070},  # not prime
            {"q": 2017, "p": 8081},  # prime, but q does not divide p - 1
            {"g": 1},
            {"g": GROUP_PRIME},
            {"g": 5},  # not in the order-q subgroup
        ):
            with self.subTest(override=override):
                with self.assertRaises(ValueError):
                    self.payload(**override)

    def test_public_key_value_errors(self):
        for override in (
            {"old": 0},
            {"old": GROUP_PRIME},
            {"old": 4},  # not in the order-q subgroup
            {"new": 0},
            {"new": 4},
        ):
            with self.subTest(override=override):
                with self.assertRaises(ValueError):
                    self.payload(**override)

    def test_id_value_errors(self):
        for override in (
            {"ids": ()},
            {"ids": (2, 2, 4, 5)},
            {"ids": (0, 2, 3)},
            {"ids": (2, FIELD_PRIME)},
        ):
            with self.subTest(override=override):
                with self.assertRaises(ValueError):
                    self.payload(**override)

    def test_threshold_value_errors(self):
        for override in ({"t": 0}, {"t": -1}, {"t": len(NEW_IDS) + 1}):
            with self.subTest(override=override):
                with self.assertRaises(ValueError):
                    self.payload(**override)


class TestRotationCertificate(unittest.TestCase):
    def test_frozen_positional_value_equality(self):
        _old_key, _new_key, cert = make_cert()
        twin = Rotation(
            cert.old, cert.new, cert.ids, cert.t, cert.q, cert.p, cert.g, cert.sig
        )
        self.assertEqual(cert, twin)
        with self.assertRaises(FrozenInstanceError):
            cert.old = 1

    def test_valid_certificate_verifies(self):
        _old_key, _new_key, cert = make_cert()
        self.assertIs(verify_rotation(cert), True)

    def test_larger_quorum_verifies(self):
        _old_key, _new_key, cert = make_cert(signer_ids=(1, 2, 3), seed=400)
        self.assertIs(verify_rotation(cert), True)

    def test_self_rotation_verifies(self):
        old_key = make_key(OLD_IDS, OLD_THRESHOLD, seed=10)
        payload = rotation_payload(
            old_key.public_key,
            old_key.public_key,
            OLD_IDS,
            OLD_THRESHOLD,
            FIELD_PRIME,
            GROUP_PRIME,
            GENERATOR,
        )
        signature = sign_message(old_key, payload, (2, 3), seed=300)
        cert = Rotation(
            old_key.public_key,
            old_key.public_key,
            OLD_IDS,
            OLD_THRESHOLD,
            FIELD_PRIME,
            GROUP_PRIME,
            GENERATOR,
            signature,
        )
        self.assertIs(verify_rotation(cert), True)

    def test_tampered_values_return_false(self):
        old_key, new_key, cert = make_cert()
        other_key = make_key((1, 2), 2, seed=90)
        replacements = (
            {"new": other_key.public_key},
            {"old": new_key.public_key},
            {"ids": (2, 3, 4)},
            {"t": 2},
        )
        for replacement in replacements:
            with self.subTest(replacement=replacement):
                fields = dict(
                    old=cert.old,
                    new=cert.new,
                    ids=cert.ids,
                    t=cert.t,
                    q=cert.q,
                    p=cert.p,
                    g=cert.g,
                    sig=cert.sig,
                )
                fields.update(replacement)
                self.assertIs(verify_rotation(Rotation(**fields)), False)

    def test_signature_over_another_payload_returns_false(self):
        old_key, new_key, cert = make_cert()
        other_payload = rotation_payload(
            old_key.public_key,
            new_key.public_key,
            NEW_IDS,
            2,
            FIELD_PRIME,
            GROUP_PRIME,
            GENERATOR,
        )
        other_signature = sign_message(old_key, other_payload, (1, 2), seed=500)
        tampered = Rotation(
            cert.old, cert.new, cert.ids, cert.t, cert.q, cert.p, cert.g, other_signature
        )
        self.assertIs(verify_rotation(tampered), False)

    def test_signature_by_new_key_returns_false(self):
        old_key, new_key, cert = make_cert()
        payload = rotation_payload(
            old_key.public_key,
            new_key.public_key,
            NEW_IDS,
            NEW_THRESHOLD,
            FIELD_PRIME,
            GROUP_PRIME,
            GENERATOR,
        )
        new_signature = sign_message(new_key, payload, (2, 3, 4), seed=600)
        tampered = Rotation(
            cert.old, cert.new, cert.ids, cert.t, cert.q, cert.p, cert.g, new_signature
        )
        self.assertIs(verify_rotation(tampered), False)


class TestVerifyRotationErrors(unittest.TestCase):
    def setUp(self):
        _old_key, _new_key, cert = make_cert()
        self.cert = cert

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            verify_rotation("not a certificate")
        with self.assertRaises(TypeError):
            verify_rotation(
                Rotation(
                    self.cert.old,
                    self.cert.new,
                    list(self.cert.ids),
                    self.cert.t,
                    self.cert.q,
                    self.cert.p,
                    self.cert.g,
                    self.cert.sig,
                )
            )
        with self.assertRaises(TypeError):
            verify_rotation(
                Rotation(
                    self.cert.old,
                    self.cert.new,
                    self.cert.ids,
                    self.cert.t,
                    self.cert.q,
                    self.cert.p,
                    self.cert.g,
                    "sig",
                )
            )
        with self.assertRaises(TypeError):
            verify_rotation(
                Rotation(
                    self.cert.old,
                    self.cert.new,
                    self.cert.ids,
                    True,
                    self.cert.q,
                    self.cert.p,
                    self.cert.g,
                    self.cert.sig,
                )
            )

    def test_structure_value_errors(self):
        with self.assertRaises(ValueError):
            verify_rotation(
                Rotation(
                    self.cert.old,
                    self.cert.new,
                    self.cert.ids,
                    len(self.cert.ids) + 1,
                    self.cert.q,
                    self.cert.p,
                    self.cert.g,
                    self.cert.sig,
                )
            )
        with self.assertRaises(ValueError):
            verify_rotation(
                Rotation(
                    self.cert.old,
                    self.cert.new,
                    self.cert.ids,
                    self.cert.t,
                    self.cert.q,
                    self.cert.p,
                    self.cert.g,
                    AggregateSignature(R=0, z=self.cert.sig.z, signer_ids=(1, 2)),
                )
            )

    def test_wellformed_wrong_signature_is_false_not_error(self):
        wrong = Rotation(
            self.cert.old,
            self.cert.new,
            self.cert.ids,
            self.cert.t,
            self.cert.q,
            self.cert.p,
            self.cert.g,
            AggregateSignature(
                R=pow(GENERATOR, 7, GROUP_PRIME), z=1, signer_ids=(1, 2)
            ),
        )
        self.assertIs(verify_rotation(wrong), False)


if __name__ == "__main__":
    unittest.main()
