"""Tests for the rotation chain failure diagnoser: RotationFault /
RotationChainDiagnosis / diagnose_rotation_chain."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    Rotation,
    RotationChain,
    RotationChainDiagnosis,
    RotationFault,
    aggregate_signature,
    aggregate_signing_dkg,
    create_signature_share,
    create_signing_contribution,
    create_signing_nonce_commitment,
    create_signing_round,
    diagnose_rotation_chain,
    rotation_payload,
    verify_rotation,
    verify_rotation_chain,
)

# Same toy group as test_rotation_chain: 8069 = 4 * 2017 + 1 is prime, 16 and
# 256 = 16 ** 2 are distinct generators of the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256


def fixed_random(seed=1):
    """Deterministic stand-in for secrets.randbelow (same LCG as DKG tests)."""
    state = {"value": seed}

    def randbelow(upper: int) -> int:
        state["value"] = (
            state["value"] * 6364136223846793005 + 1442695040888963407
        ) % upper
        return state["value"]

    return randbelow


def make_key(participant_ids, threshold, seed_offset=0):
    contributions = [
        create_signing_contribution(
            pid,
            participant_ids,
            threshold,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            blinding_generator=BLINDING_GENERATOR,
            randbelow=fixed_random(pid + seed_offset),
        )
        for pid in participant_ids
    ]
    return aggregate_signing_dkg(contributions)


def sign_message(key, message, signer_ids, seed=100):
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


def make_cert(old_key, new_key, signer_ids, *, t, seed):
    payload = rotation_payload(
        old_key.public_key,
        new_key.public_key,
        new_key.result.participant_ids,
        t,
        FIELD_PRIME,
        GROUP_PRIME,
        GENERATOR,
    )
    sig = sign_message(old_key, payload, signer_ids, seed=seed)
    return Rotation(
        old_key.public_key,
        new_key.public_key,
        new_key.result.participant_ids,
        t,
        FIELD_PRIME,
        GROUP_PRIME,
        GENERATOR,
        sig,
    )


def with_bad_signature(cert):
    return dataclasses.replace(
        cert,
        sig=AggregateSignature(
            R=cert.sig.R,
            z=(cert.sig.z + 1) % FIELD_PRIME,
            signer_ids=cert.sig.signer_ids,
        ),
    )


class RotationFaultDataTest(unittest.TestCase):
    def test_fields_and_positional_value_equality(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(RotationFault)],
            ["index", "check"],
        )
        fault = RotationFault(2, "link")
        self.assertEqual(fault, RotationFault(index=2, check="link"))
        self.assertEqual(hash(fault), hash(RotationFault(2, "link")))
        self.assertNotEqual(fault, RotationFault(1, "link"))
        self.assertNotEqual(fault, RotationFault(2, "anchor"))

    def test_frozen(self):
        fault = RotationFault(0, "anchor")
        with self.assertRaises(FrozenInstanceError):
            fault.index = 1
        with self.assertRaises(FrozenInstanceError):
            fault.check = "authorization"


class RotationChainDiagnosisDataTest(unittest.TestCase):
    def test_fields_and_positional_value_equality(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(RotationChainDiagnosis)],
            ["valid", "faults"],
        )
        ok = RotationChainDiagnosis(True, ())
        self.assertEqual(ok, RotationChainDiagnosis(valid=True, faults=()))
        self.assertEqual(hash(ok), hash(RotationChainDiagnosis(True, ())))
        faults = (RotationFault(0, "anchor"), RotationFault(1, "authorization"))
        report = RotationChainDiagnosis(False, faults)
        self.assertEqual(report, RotationChainDiagnosis(False, tuple(faults)))
        self.assertNotEqual(report, ok)
        self.assertNotEqual(
            report, RotationChainDiagnosis(False, (RotationFault(0, "anchor"),))
        )

    def test_frozen(self):
        report = RotationChainDiagnosis(True, ())
        with self.assertRaises(FrozenInstanceError):
            report.valid = False
        with self.assertRaises(FrozenInstanceError):
            report.faults = (RotationFault(0, "anchor"),)


class DiagnoseRotationChainTest(unittest.TestCase):
    def setUp(self):
        self.k0 = make_key((1, 2, 3), 2, seed_offset=0)
        self.k1 = make_key((2, 3, 4, 5), 3, seed_offset=10)
        self.k2 = make_key((3, 4, 5, 6), 2, seed_offset=20)
        self.k3 = make_key((1, 4, 5, 6), 2, seed_offset=30)
        self.cert0 = make_cert(self.k0, self.k1, (1, 3), t=3, seed=100)
        self.cert1 = make_cert(self.k1, self.k2, (2, 4, 5), t=2, seed=200)
        self.cert2 = make_cert(self.k2, self.k3, (3, 5), t=2, seed=300)
        self.chain = RotationChain(
            self.k0.public_key, (self.cert0, self.cert1, self.cert2)
        )

    def test_honest_chain_is_valid_with_empty_faults(self):
        report = diagnose_rotation_chain(self.chain)
        self.assertEqual(report, RotationChainDiagnosis(True, ()))
        self.assertTrue(report.valid)
        self.assertEqual(report.faults, ())
        self.assertTrue(verify_rotation_chain(self.chain))

    def test_single_hop_honest(self):
        chain = RotationChain(self.k0.public_key, (self.cert0,))
        self.assertEqual(diagnose_rotation_chain(chain), RotationChainDiagnosis(True, ()))

    def test_valid_matches_verifier_on_every_permutation_style_break(self):
        broken_chains = [
            RotationChain(self.k1.public_key, (self.cert0, self.cert1, self.cert2)),
            RotationChain(self.k0.public_key, (self.cert0, with_bad_signature(self.cert1))),
            RotationChain(
                self.k0.public_key,
                (with_bad_signature(self.cert0), self.cert1, self.cert2),
            ),
            RotationChain(self.k0.public_key, (self.cert1, self.cert0)),
        ]
        for chain in broken_chains:
            report = diagnose_rotation_chain(chain)
            self.assertFalse(
                report.valid,
                f"expected invalid report for broken chain, got {report}",
            )
            self.assertEqual(report.valid, verify_rotation_chain(chain))

    def test_anchor_mismatch_fault_at_index_zero(self):
        chain = RotationChain(self.k1.public_key, (self.cert0, self.cert1))
        report = diagnose_rotation_chain(chain)
        self.assertEqual(report.faults, (RotationFault(0, "anchor"),))
        self.assertFalse(report.valid)

    def test_link_faults_from_swapped_certificates_with_valid_signatures(self):
        # Both certs still verify individually; only anchor and the new-to-old
        # seam are broken.
        chain = RotationChain(self.k0.public_key, (self.cert1, self.cert0))
        report = diagnose_rotation_chain(chain)
        self.assertEqual(
            report.faults,
            (RotationFault(0, "anchor"), RotationFault(1, "link")),
        )

    def test_link_and_authorization_co_occur_at_same_index_link_first(self):
        # cert1 claiming cert0's old key: the seam at index 1 is broken and the
        # signature no longer matches either.
        moved = dataclasses.replace(self.cert1, old=self.k0.public_key)
        chain = RotationChain(self.k0.public_key, (self.cert0, moved))
        report = diagnose_rotation_chain(chain)
        self.assertEqual(
            report.faults,
            (RotationFault(1, "link"), RotationFault(1, "authorization")),
        )

    def test_authorization_fault_at_own_index(self):
        bad_cert = with_bad_signature(self.cert1)
        chain = RotationChain(self.k0.public_key, (self.cert0, bad_cert, self.cert2))
        report = diagnose_rotation_chain(chain)
        self.assertEqual(report.faults, (RotationFault(1, "authorization"),))

    def test_anchor_plus_authorization_faults_at_index_zero(self):
        bad_cert = with_bad_signature(self.cert0)
        chain = RotationChain(self.k1.public_key, (bad_cert, self.cert1))
        report = diagnose_rotation_chain(chain)
        self.assertEqual(
            report.faults,
            (RotationFault(0, "anchor"), RotationFault(0, "authorization")),
        )

    def test_diagnosis_continues_past_first_failure_in_chain_order(self):
        # Broken anchor, a bad signature at index 0 and another at index 2;
        # every fault must be reported, none masked.
        chain = RotationChain(
            self.k1.public_key,
            (with_bad_signature(self.cert0), self.cert1, with_bad_signature(self.cert2)),
        )
        report = diagnose_rotation_chain(chain)
        self.assertEqual(
            report.faults,
            (
                RotationFault(0, "anchor"),
                RotationFault(0, "authorization"),
                RotationFault(2, "authorization"),
            ),
        )
        self.assertFalse(verify_rotation_chain(chain))

    def test_every_signature_bad_reports_every_index(self):
        chain = RotationChain(
            self.k0.public_key,
            (
                with_bad_signature(self.cert0),
                with_bad_signature(self.cert1),
                with_bad_signature(self.cert2),
            ),
        )
        report = diagnose_rotation_chain(chain)
        self.assertEqual(
            report.faults,
            tuple(RotationFault(i, "authorization") for i in range(3)),
        )

    def test_deterministic_equal_reports_for_equal_inputs(self):
        chain = RotationChain(
            self.k1.public_key,
            (self.cert0, with_bad_signature(self.cert1), self.cert2),
        )
        first = diagnose_rotation_chain(chain)
        second = diagnose_rotation_chain(
            RotationChain(self.k1.public_key, (self.cert0, with_bad_signature(self.cert1), self.cert2))
        )
        self.assertEqual(first, second)
        self.assertEqual(first.faults, tuple(first.faults))
        self.assertEqual(first, diagnose_rotation_chain(chain))

    # --- rejection boundary, identical to verify_rotation_chain -----------

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            diagnose_rotation_chain("chain")
        with self.assertRaises(TypeError):
            diagnose_rotation_chain(RotationChain("x", (self.cert0,)))
        with self.assertRaises(TypeError):
            diagnose_rotation_chain(RotationChain(True, (self.cert0,)))
        with self.assertRaises(TypeError):
            diagnose_rotation_chain(RotationChain(self.k0.public_key, ["x"]))
        with self.assertRaises(TypeError):
            diagnose_rotation_chain(
                RotationChain(self.k0.public_key, (self.cert0, "x"))
            )

    def test_empty_chain_value_error(self):
        with self.assertRaises(ValueError):
            diagnose_rotation_chain(RotationChain(self.k0.public_key, ()))

    def test_structurally_illegal_cert_raises_value_error(self):
        bad_cert = Rotation(
            3,  # not in the order-q subgroup
            self.k1.public_key,
            (1, 2),
            2,
            FIELD_PRIME,
            GROUP_PRIME,
            GENERATOR,
            self.cert0.sig,
        )
        chain = RotationChain(3, (self.cert0, bad_cert))
        with self.assertRaises(ValueError):
            diagnose_rotation_chain(chain)

    def test_illegal_signature_structure_raises_value_error(self):
        bad_sig = AggregateSignature(
            R=GROUP_PRIME,  # out of range
            z=1,
            signer_ids=(1,),
        )
        bad_cert = dataclasses.replace(self.cert0, sig=bad_sig)
        with self.assertRaises(ValueError):
            diagnose_rotation_chain(
                RotationChain(self.k0.public_key, (bad_cert,))
            )

    def test_illegal_threshold_and_members_raise_value_error(self):
        bad_cert = Rotation(
            self.k0.public_key,
            self.k1.public_key,
            (1, 2),
            5,  # greater than member count
            FIELD_PRIME,
            GROUP_PRIME,
            GENERATOR,
            self.cert0.sig,
        )
        with self.assertRaises(ValueError):
            diagnose_rotation_chain(
                RotationChain(self.k0.public_key, (bad_cert,))
            )

    def test_cryptographic_mismatches_do_not_raise(self):
        chain = RotationChain(
            self.k1.public_key,
            (self.cert0, with_bad_signature(self.cert1), self.cert2),
        )
        report = diagnose_rotation_chain(chain)
        self.assertFalse(report.valid)
        self.assertTrue(report.faults)


if __name__ == "__main__":
    unittest.main()
