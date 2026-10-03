"""Cross-entry compatibility tests for the shared rotation-chain diagnosis:
the chain faults diagnose_rhe reports for an RHE must correspond
item-by-item with what diagnose_rotation_chain reports for the same chain,
across honest, single-hop, multi-hop and multi-failure chains, and both
entries must share the same exception boundary."""

import dataclasses
import unittest

from thresholdsign import (
    AggregateSignature,
    RHE,
    Rotation,
    RotationChain,
    RotationChainDiagnosis,
    RHEDiagnosis,
    SealHistoryExtension,
    check_rhe,
    diagnose_rhe,
    diagnose_rotation_chain,
    verify_rotation_chain,
)

from test_nonce_reuse import FIELD_PRIME
from test_rotation_chain import make_cert
from test_rhe import RheFixture, make_other_key


def tampered(cert):
    """The same certificate with its Schnorr z bumped, so verification fails."""
    bad_sig = AggregateSignature(
        R=cert.sig.R,
        z=(cert.sig.z + 1) % FIELD_PRIME,
        signer_ids=cert.sig.signer_ids,
    )
    return dataclasses.replace(cert, sig=bad_sig)


def bump(signature):
    """The same aggregate signature with z bumped, so verification fails."""
    return AggregateSignature(
        R=signature.R,
        z=(signature.z + 1) % FIELD_PRIME,
        signer_ids=signature.signer_ids,
    )


def chain_fault_projection(diagnosis):
    """The (index, check) pairs of one report, in report order."""
    if isinstance(diagnosis, RotationChainDiagnosis):
        return [(fault.index, fault.check) for fault in diagnosis.faults]
    if isinstance(diagnosis, RHEDiagnosis):
        return [
            (fault.index, fault.check)
            for fault in diagnosis.faults
            if fault.index is not None
        ]
    raise AssertionError("unexpected diagnosis type")


class ChainFaultCorrespondenceTest(unittest.TestCase):
    """diagnose_rhe's chain faults must equal diagnose_rotation_chain's."""

    def setUp(self):
        self.f = RheFixture()
        self.k3 = make_other_key((4, 5, 6, 7), 2, 30)
        self.cert2 = make_cert(self.f.k2, self.k3, (3, 5), t=2, seed=400)

    def assert_chain_faults_correspond(self, chain, rhe):
        chain_diagnosis = diagnose_rotation_chain(chain)
        rhe_diagnosis = diagnose_rhe(rhe)
        self.assertEqual(
            chain_fault_projection(rhe_diagnosis),
            chain_fault_projection(chain_diagnosis),
        )
        self.assertEqual(rhe_diagnosis.valid, check_rhe(rhe))
        self.assertEqual(
            chain_diagnosis.valid, verify_rotation_chain(chain)
        )

    def test_honest_single_and_multi_hop(self):
        self.assert_chain_faults_correspond(
            self.f.single_chain, self.f.single
        )
        self.assert_chain_faults_correspond(
            self.f.multi_chain, self.f.multi
        )
        self.assertEqual(
            diagnose_rotation_chain(self.f.single_chain),
            RotationChainDiagnosis(True, ()),
        )
        self.assertEqual(diagnose_rhe(self.f.multi), RHEDiagnosis(True, ()))

    def test_single_hop_anchor_and_authorization(self):
        chain = RotationChain(
            self.f.k1.public_key, (tampered(self.f.cert0),)
        )
        rhe = dataclasses.replace(self.f.single, rotations=chain)
        self.assert_chain_faults_correspond(chain, rhe)
        self.assertEqual(
            chain_fault_projection(diagnose_rhe(rhe)),
            [(0, "anchor"), (0, "authorization")],
        )

    def test_multi_hop_link_and_authorization(self):
        moved_bad = dataclasses.replace(
            tampered(self.f.cert1), old=self.f.k0.public_key
        )
        chain = RotationChain(
            self.f.k0.public_key, (self.f.cert0, moved_bad)
        )
        rhe = RHE(self.f.proof, chain, self.f.old_sig, self.f.new_sig_2)
        self.assert_chain_faults_correspond(chain, rhe)
        self.assertEqual(
            chain_fault_projection(diagnose_rhe(rhe)),
            [(1, "link"), (1, "authorization")],
        )

    def test_simultaneous_failures_across_three_positions(self):
        moved_bad2 = dataclasses.replace(
            tampered(self.cert2), old=self.f.k0.public_key
        )
        chain = RotationChain(
            self.k3.public_key,
            (tampered(self.f.cert0), tampered(self.f.cert1), moved_bad2),
        )
        rhe = RHE(self.f.proof, chain, self.f.old_sig, self.f.new_sig_2)
        self.assert_chain_faults_correspond(chain, rhe)
        self.assertEqual(
            chain_fault_projection(diagnose_rhe(rhe)),
            [
                (0, "anchor"),
                (0, "authorization"),
                (1, "authorization"),
                (2, "link"),
                (2, "authorization"),
            ],
        )

    def test_endpoint_faults_follow_chain_faults_with_none_index(self):
        chain = RotationChain(self.f.k1.public_key, (self.f.cert0,))
        rhe = RHE(
            self.f.proof,
            chain,
            bump(self.f.old_sig),
            bump(self.f.new_sig),
        )
        diagnosis = diagnose_rhe(rhe)
        self.assertEqual(
            [(fault.check, fault.index) for fault in diagnosis.faults],
            [
                ("anchor", 0),
                ("old-signature", None),
                ("new-signature", None),
            ],
        )
        # The chain-prefixed projection still matches the standalone report.
        self.assertEqual(
            chain_fault_projection(diagnosis),
            chain_fault_projection(diagnose_rotation_chain(chain)),
        )


class SharedErrorBoundaryTest(unittest.TestCase):
    """Both entries reject the same malformed chains identically."""

    def setUp(self):
        self.f = RheFixture()

    def rhe_with(self, chain):
        return RHE(self.f.proof, chain, self.f.old_sig, self.f.new_sig)

    def test_type_errors_match(self):
        bad_containers = (
            RotationChain("x", (self.f.cert0,)),
            RotationChain(True, (self.f.cert0,)),
            RotationChain(self.f.k0.public_key, [self.f.cert0]),
            RotationChain(self.f.k0.public_key, (self.f.cert0, "cert")),
        )
        for chain in bad_containers:
            with self.subTest(chain=chain):
                with self.assertRaises(TypeError):
                    diagnose_rotation_chain(chain)
                with self.assertRaises(TypeError):
                    diagnose_rhe(self.rhe_with(chain))

    def test_value_errors_match(self):
        bad_cert = dataclasses.replace(self.f.cert0, old=3)
        bad_chains = (
            RotationChain(self.f.k0.public_key, ()),
            RotationChain(3, (bad_cert,)),
        )
        for chain in bad_chains:
            with self.subTest(chain=chain):
                with self.assertRaises(ValueError):
                    diagnose_rotation_chain(chain)
                with self.assertRaises(ValueError):
                    diagnose_rhe(self.rhe_with(chain))

    def test_negative_anchor_is_a_fault_in_both_entries(self):
        chain = RotationChain(-1, (self.f.cert0,))
        rhe = self.rhe_with(chain)
        self.assertEqual(
            chain_fault_projection(diagnose_rotation_chain(chain)),
            [(0, "anchor")],
        )
        self.assertEqual(
            chain_fault_projection(diagnose_rhe(rhe)),
            [(0, "anchor")],
        )

    def test_rhe_specific_boundaries_unchanged(self):
        # Old prefix length out of range and a non-32-byte leaf stay
        # ValueError in diagnose_rhe.
        zero_prefix = SealHistoryExtension(
            old_total=0, leaves=self.f.proof.leaves
        )
        with self.assertRaises(ValueError):
            diagnose_rhe(
                RHE(
                    zero_prefix,
                    self.f.single_chain,
                    self.f.old_sig,
                    self.f.new_sig,
                )
            )
        narrow_leaf = SealHistoryExtension(
            old_total=1, leaves=(b"a" * 31, b"b" * 32)
        )
        with self.assertRaises(ValueError):
            diagnose_rhe(
                RHE(
                    narrow_leaf,
                    self.f.single_chain,
                    self.f.old_sig,
                    self.f.new_sig,
                )
            )

    def test_endpoint_range_error_even_when_chain_broken(self):
        # A signature integer outside its endpoint group is an input error,
        # never a fault, even with a disconnected chain.
        broken = RotationChain(self.f.k1.public_key, (self.f.cert0,))
        bad_z = AggregateSignature(
            R=self.f.old_sig.R,
            z=FIELD_PRIME,
            signer_ids=self.f.old_sig.signer_ids,
        )
        with self.assertRaises(ValueError):
            diagnose_rhe(
                RHE(self.f.proof, broken, bad_z, self.f.new_sig)
            )

    def test_check_rhe_short_circuit_unchanged(self):
        broken = dataclasses.replace(
            self.f.single,
            rotations=RotationChain(self.f.k1.public_key, (self.f.cert0,)),
        )
        self.assertFalse(check_rhe(broken))
        self.assertFalse(verify_rotation_chain(broken.rotations))


if __name__ == "__main__":
    unittest.main()
