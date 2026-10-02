"""Tests for the stateless failure diagnoser of cross-key append proofs:
diagnose_rhe and its RHEDiagnosis / RHEFault results."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    RHE,
    RHEDiagnosis,
    RHEFault,
    RotationChain,
    SealHistoryExtension,
    check_rhe,
    diagnose_rhe,
)

from test_nonce_reuse import FIELD_PRIME, GROUP_PRIME
from test_rotation_chain import make_cert
from test_rhe import RheFixture, make_other_key
from test_seal_history import sign_message


def tampered(cert):
    """The same certificate with its Schnorr z bumped, so verify_rotation fails."""
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


def fault_projection(diagnosis):
    return [(fault.check, fault.index) for fault in diagnosis.faults]


class ExtendedRheFixture(RheFixture):
    """Adds a fourth key and a k3-signed new root for pure-link cases."""

    def __init__(self):
        super().__init__()
        self.k3 = make_other_key((4, 5, 6, 7), 2, 30)
        # An honestly signed certificate k2 -> k3: independently valid, but
        # its old key does not meet cert0.new (k1), so the seam is a pure
        # link break while its own authorization still verifies.
        self.cert_other = make_cert(self.k2, self.k3, (3, 5), t=2, seed=400)
        self.new_sig_3 = sign_message(
            self.new_message, self.k3, signer_ids=(5, 7), seed=900
        )


class DiagnosisResultShapeTest(unittest.TestCase):
    def test_fault_fields_in_order(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(RHEFault)],
            ["check", "index"],
        )

    def test_diagnosis_fields_in_order(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(RHEDiagnosis)],
            ["valid", "faults"],
        )

    def test_frozen_positional_value_equality(self):
        fault = RHEFault("anchor", 0)
        self.assertEqual(fault, RHEFault(check="anchor", index=0))
        self.assertEqual(hash(fault), hash(RHEFault("anchor", 0)))
        self.assertNotEqual(fault, RHEFault("link", 0))
        self.assertEqual(
            RHEFault("old-signature", None),
            RHEFault(check="old-signature", index=None),
        )
        self.assertNotEqual(RHEFault("anchor", 0), RHEFault("anchor", None))
        with self.assertRaises(FrozenInstanceError):
            fault.index = 2

        diagnosis = RHEDiagnosis(False, (fault,))
        self.assertEqual(
            diagnosis, RHEDiagnosis(valid=False, faults=(RHEFault("anchor", 0),))
        )
        self.assertEqual(
            hash(diagnosis),
            hash(RHEDiagnosis(False, (RHEFault("anchor", 0),))),
        )
        self.assertNotEqual(diagnosis, RHEDiagnosis(True, ()))
        with self.assertRaises(FrozenInstanceError):
            diagnosis.valid = True


class DiagnoseHonestProofTest(unittest.TestCase):
    def setUp(self):
        self.f = RheFixture()

    def test_honest_single_hop_has_no_faults(self):
        diagnosis = diagnose_rhe(self.f.single)
        self.assertEqual(diagnosis, RHEDiagnosis(True, ()))
        self.assertTrue(diagnosis.valid)
        self.assertEqual(diagnosis.faults, ())
        self.assertIsInstance(diagnosis.faults, tuple)
        self.assertTrue(check_rhe(self.f.single))

    def test_honest_multi_hop_has_no_faults(self):
        diagnosis = diagnose_rhe(self.f.multi)
        self.assertEqual(diagnosis, RHEDiagnosis(True, ()))
        self.assertTrue(check_rhe(self.f.multi))

    def test_valid_agrees_with_check_rhe_on_honest_proofs(self):
        for rhe in (self.f.single, self.f.multi):
            with self.subTest():
                self.assertEqual(diagnose_rhe(rhe).valid, check_rhe(rhe))


class DiagnoseChainFaultTest(unittest.TestCase):
    def setUp(self):
        self.f = ExtendedRheFixture()

    def test_wrong_anchor_reports_anchor_at_index_zero(self):
        rhe = dataclasses.replace(
            self.f.single,
            rotations=RotationChain(self.f.k1.public_key, (self.f.cert0,)),
        )
        diagnosis = diagnose_rhe(rhe)
        self.assertFalse(diagnosis.valid)
        self.assertEqual(fault_projection(diagnosis), [("anchor", 0)])
        for fault in diagnosis.faults:
            self.assertIsInstance(fault.index, int)

    def test_anchor_fault_comes_before_authorization_at_same_index(self):
        chain = RotationChain(
            self.f.k1.public_key, (tampered(self.f.cert0),)
        )
        rhe = dataclasses.replace(self.f.single, rotations=chain)
        self.assertEqual(
            fault_projection(diagnose_rhe(rhe)),
            [("anchor", 0), ("authorization", 0)],
        )

    def test_pure_link_fault_authorizations_and_endpoints_hold(self):
        # The seam cert0 -> cert_other does not link, yet cert_other itself
        # verifies and the new root is signed by the chain's actual last key
        # k3, so only the link fault is reported.
        chain = RotationChain(
            self.f.k0.public_key, (self.f.cert0, self.f.cert_other)
        )
        rhe = RHE(self.f.proof, chain, self.f.old_sig, self.f.new_sig_3)
        diagnosis = diagnose_rhe(rhe)
        self.assertFalse(diagnosis.valid)
        self.assertEqual(fault_projection(diagnosis), [("link", 1)])
        self.assertFalse(check_rhe(rhe))

    def test_link_then_authorization_at_same_index(self):
        # Break the seam into cert1 and tamper its signature as well; the
        # endpoint signatures still match their endpoints.
        moved_bad = dataclasses.replace(
            tampered(self.f.cert1), old=self.f.k0.public_key
        )
        chain = RotationChain(
            self.f.k0.public_key, (self.f.cert0, moved_bad)
        )
        rhe = RHE(self.f.proof, chain, self.f.old_sig, self.f.new_sig_2)
        self.assertEqual(
            fault_projection(diagnose_rhe(rhe)),
            [("link", 1), ("authorization", 1)],
        )

    def test_bad_rotation_authorization_reports_only_that_index(self):
        chain = RotationChain(
            self.f.k0.public_key, (self.f.cert0, tampered(self.f.cert1))
        )
        rhe = dataclasses.replace(self.f.multi, rotations=chain)
        self.assertEqual(
            fault_projection(diagnose_rhe(rhe)),
            [("authorization", 1)],
        )

    def test_bad_authorization_on_single_hop_certificate(self):
        chain = RotationChain(self.f.k0.public_key, (tampered(self.f.cert0),))
        rhe = dataclasses.replace(self.f.single, rotations=chain)
        self.assertEqual(
            fault_projection(diagnose_rhe(rhe)),
            [("authorization", 0)],
        )

    def test_negative_anchor_is_diagnosed_not_rejected(self):
        chain = RotationChain(-1, (self.f.cert0,))
        rhe = dataclasses.replace(self.f.single, rotations=chain)
        diagnosis = diagnose_rhe(rhe)
        self.assertFalse(diagnosis.valid)
        self.assertEqual(fault_projection(diagnosis), [("anchor", 0)])
        self.assertFalse(check_rhe(rhe))

    def test_full_chain_fault_ordering_across_positions(self):
        # Wrong anchor, tampered authorization on both certificates and a
        # broken seam into cert1; both endpoint signatures stay valid.
        moved_bad = dataclasses.replace(
            tampered(self.f.cert1), old=self.f.k0.public_key
        )
        chain = RotationChain(
            self.f.k3.public_key,
            (tampered(self.f.cert0), moved_bad),
        )
        rhe = RHE(self.f.proof, chain, self.f.old_sig, self.f.new_sig_2)
        self.assertEqual(
            fault_projection(diagnose_rhe(rhe)),
            [
                ("anchor", 0),
                ("authorization", 0),
                ("link", 1),
                ("authorization", 1),
            ],
        )


class DiagnoseEndpointSignatureFaultTest(unittest.TestCase):
    def setUp(self):
        self.f = RheFixture()

    def test_tampered_old_root_signature(self):
        rhe = dataclasses.replace(self.f.single, old_sig=bump(self.f.old_sig))
        diagnosis = diagnose_rhe(rhe)
        self.assertEqual(fault_projection(diagnosis), [("old-signature", None)])
        self.assertIsNone(diagnosis.faults[0].index)
        self.assertFalse(check_rhe(rhe))

    def test_tampered_new_root_signature(self):
        rhe = dataclasses.replace(self.f.single, new_sig=bump(self.f.new_sig))
        diagnosis = diagnose_rhe(rhe)
        self.assertEqual(fault_projection(diagnosis), [("new-signature", None)])
        self.assertFalse(check_rhe(rhe))

    def test_swapped_signature_pair_reports_both_endpoints(self):
        rhe = RHE(
            self.f.proof,
            self.f.single_chain,
            self.f.new_sig,
            self.f.old_sig,
        )
        self.assertEqual(
            fault_projection(diagnose_rhe(rhe)),
            [("old-signature", None), ("new-signature", None)],
        )

    def test_signature_under_other_endpoint_key(self):
        # new_sig produced by k2 but the single-hop chain ends at k1.
        rhe = RHE(
            self.f.proof,
            self.f.single_chain,
            self.f.old_sig,
            self.f.new_sig_2,
        )
        self.assertEqual(
            fault_projection(diagnose_rhe(rhe)),
            [("new-signature", None)],
        )

    def test_old_and_new_faults_reported_together_after_chain(self):
        rhe = RHE(
            self.f.proof,
            self.f.single_chain,
            bump(self.f.old_sig),
            bump(self.f.new_sig),
        )
        self.assertEqual(
            fault_projection(diagnose_rhe(rhe)),
            [("old-signature", None), ("new-signature", None)],
        )

    def test_tampered_old_total_fails_only_old_root(self):
        # The new root is rebuilt from all leaves with an unchanged U64(n),
        # so moving the prefix boundary breaks only the old root statement.
        bad_proof = dataclasses.replace(self.f.proof, old_total=1)
        rhe = RHE(
            bad_proof,
            self.f.single_chain,
            self.f.old_sig,
            self.f.new_sig,
        )
        self.assertEqual(
            fault_projection(diagnose_rhe(rhe)),
            [("old-signature", None)],
        )

    def test_tampered_new_leaf_fails_only_new_root(self):
        # old_total == 2 and the last (index 3) leaf is flipped, leaving the
        # old prefix root untouched.
        leaves = self.f.proof.leaves
        flipped = leaves[-1][:-1] + bytes([leaves[-1][-1] ^ 1])
        bad_proof = SealHistoryExtension(
            old_total=self.f.proof.old_total,
            leaves=leaves[:-1] + (flipped,),
        )
        rhe = RHE(
            bad_proof,
            self.f.single_chain,
            self.f.old_sig,
            self.f.new_sig,
        )
        self.assertEqual(
            fault_projection(diagnose_rhe(rhe)),
            [("new-signature", None)],
        )


class DiagnoseIndependenceTest(unittest.TestCase):
    def setUp(self):
        self.f = ExtendedRheFixture()

    def test_broken_chain_does_not_mask_either_endpoint_check(self):
        # Wrong anchor plus both root signatures tampered: all three
        # observable failures must appear, old-signature before new-signature.
        chain = RotationChain(self.f.k1.public_key, (self.f.cert0,))
        rhe = RHE(
            self.f.proof,
            chain,
            bump(self.f.old_sig),
            bump(self.f.new_sig),
        )
        self.assertEqual(
            fault_projection(diagnose_rhe(rhe)),
            [
                ("anchor", 0),
                ("old-signature", None),
                ("new-signature", None),
            ],
        )

    def test_every_check_collected_in_one_report(self):
        # Wrong anchor, both authorizations broken, a broken seam and both
        # endpoint signatures tampered: six faults, in the mandated order.
        moved_bad = dataclasses.replace(
            tampered(self.f.cert1), old=self.f.k0.public_key
        )
        chain = RotationChain(
            self.f.k3.public_key,
            (tampered(self.f.cert0), moved_bad),
        )
        rhe = RHE(
            self.f.proof,
            chain,
            bump(self.f.old_sig),
            bump(self.f.new_sig_2),
        )
        self.assertEqual(
            fault_projection(diagnose_rhe(rhe)),
            [
                ("anchor", 0),
                ("authorization", 0),
                ("link", 1),
                ("authorization", 1),
                ("old-signature", None),
                ("new-signature", None),
            ],
        )

    def test_endpoint_signatures_checked_even_when_chain_disconnected(self):
        # Pure link break with both endpoint signatures intact: no endpoint
        # fault (proving they were actually checked against their endpoints).
        chain = RotationChain(
            self.f.k0.public_key, (self.f.cert0, self.f.cert_other)
        )
        rhe = RHE(self.f.proof, chain, self.f.old_sig, self.f.new_sig_3)
        checks = [fault.check for fault in diagnose_rhe(rhe).faults]
        self.assertNotIn("old-signature", checks)
        self.assertNotIn("new-signature", checks)


class DiagnoseDeterminismTest(unittest.TestCase):
    def setUp(self):
        self.f = ExtendedRheFixture()

    def test_equal_inputs_give_equal_ordered_reports(self):
        moved_bad = dataclasses.replace(
            tampered(self.f.cert1), old=self.f.k0.public_key
        )
        variants = (
            self.f.single,
            self.f.multi,
            dataclasses.replace(
                self.f.single,
                rotations=RotationChain(
                    self.f.k1.public_key, (self.f.cert0,)
                ),
            ),
            RHE(
                self.f.proof,
                RotationChain(
                    self.f.k3.public_key,
                    (tampered(self.f.cert0), moved_bad),
                ),
                bump(self.f.old_sig),
                bump(self.f.new_sig_2),
            ),
        )
        for rhe in variants:
            with self.subTest():
                first = diagnose_rhe(rhe)
                second = diagnose_rhe(rhe)
                self.assertEqual(first, second)
                self.assertEqual(hash(first), hash(second))
                chain_indices = [
                    fault.index
                    for fault in first.faults
                    if fault.index is not None
                ]
                self.assertEqual(chain_indices, sorted(chain_indices))
                tail = [
                    fault.check
                    for fault in first.faults
                    if fault.index is None
                ]
                self.assertEqual(
                    tail,
                    [
                        check
                        for check in ("old-signature", "new-signature")
                        if check in tail
                    ],
                )

    def test_valid_matches_check_rhe_across_variants(self):
        # Every damaged-but-structurally-legal variant must give the same
        # boolean verdict as check_rhe.
        variants = [
            self.f.single,
            self.f.multi,
            dataclasses.replace(
                self.f.single, old_sig=bump(self.f.old_sig)
            ),
            dataclasses.replace(
                self.f.single, new_sig=bump(self.f.new_sig)
            ),
            RHE(
                self.f.proof,
                self.f.single_chain,
                self.f.new_sig,
                self.f.old_sig,
            ),
            dataclasses.replace(
                self.f.single,
                rotations=RotationChain(
                    self.f.k1.public_key, (self.f.cert0,)
                ),
            ),
            dataclasses.replace(
                self.f.multi,
                rotations=RotationChain(
                    self.f.k0.public_key,
                    (self.f.cert0, tampered(self.f.cert1)),
                ),
            ),
            RHE(
                self.f.proof,
                RotationChain(
                    self.f.k0.public_key,
                    (self.f.cert0, self.f.cert_other),
                ),
                self.f.old_sig,
                self.f.new_sig_3,
            ),
        ]
        for rhe in variants:
            with self.subTest():
                self.assertEqual(
                    diagnose_rhe(rhe).valid,
                    check_rhe(rhe),
                )


class DiagnoseErrorBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.f = RheFixture()

    def test_non_rhe_argument_type_error(self):
        for bad in ("rhe", None, 42, self.f.proof, self.f.single_chain):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    diagnose_rhe(bad)

    def test_bad_field_types_type_error(self):
        with self.assertRaises(TypeError):
            diagnose_rhe(
                RHE("x", self.f.single_chain, self.f.old_sig, self.f.new_sig)
            )
        with self.assertRaises(TypeError):
            diagnose_rhe(
                RHE(self.f.proof, "chain", self.f.old_sig, self.f.new_sig)
            )
        with self.assertRaises(TypeError):
            diagnose_rhe(
                RHE(self.f.proof, self.f.single_chain, "sig", self.f.new_sig)
            )
        with self.assertRaises(TypeError):
            diagnose_rhe(
                RHE(self.f.proof, self.f.single_chain, self.f.old_sig, "sig")
            )

    def test_empty_chain_value_error(self):
        with self.assertRaises(ValueError):
            diagnose_rhe(
                RHE(
                    self.f.proof,
                    RotationChain(self.f.k0.public_key, ()),
                    self.f.old_sig,
                    self.f.new_sig,
                )
            )

    def test_bad_extension_bounds_value_error(self):
        bad_proof = SealHistoryExtension(
            old_total=1, leaves=(b"a" * 31, b"b" * 32)
        )
        with self.assertRaises(ValueError):
            diagnose_rhe(
                RHE(
                    bad_proof,
                    self.f.single_chain,
                    self.f.old_sig,
                    self.f.new_sig,
                )
            )
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

    def test_illegal_chain_certificate_value_error(self):
        bad_cert = dataclasses.replace(self.f.cert0, old=3)
        with self.assertRaises(ValueError):
            diagnose_rhe(
                RHE(
                    self.f.proof,
                    RotationChain(3, (bad_cert,)),
                    self.f.old_sig,
                    self.f.new_sig,
                )
            )

    def test_endpoint_signature_integer_outside_group_value_error(self):
        # Structurally encodable signatures whose integers do not fit the
        # endpoint's parameters are input errors, never diagnostic faults.
        bad_z = AggregateSignature(
            R=self.f.old_sig.R,
            z=FIELD_PRIME,
            signer_ids=self.f.old_sig.signer_ids,
        )
        rhe_z = RHE(
            self.f.proof, self.f.single_chain, bad_z, self.f.new_sig
        )
        with self.assertRaises(ValueError):
            diagnose_rhe(rhe_z)
        with self.assertRaises(ValueError):
            check_rhe(rhe_z)

        bad_R = AggregateSignature(
            R=GROUP_PRIME,
            z=self.f.new_sig.z,
            signer_ids=self.f.new_sig.signer_ids,
        )
        rhe_R = RHE(
            self.f.proof, self.f.single_chain, self.f.old_sig, bad_R
        )
        with self.assertRaises(ValueError):
            diagnose_rhe(rhe_R)
        with self.assertRaises(ValueError):
            check_rhe(rhe_R)

        bad_signer = AggregateSignature(
            R=self.f.old_sig.R, z=self.f.old_sig.z, signer_ids=(FIELD_PRIME,)
        )
        rhe_signer = RHE(
            self.f.proof, self.f.single_chain, bad_signer, self.f.new_sig
        )
        with self.assertRaises(ValueError):
            diagnose_rhe(rhe_signer)
        with self.assertRaises(ValueError):
            check_rhe(rhe_signer)

    def test_endpoint_integer_range_enforced_even_when_chain_broken(self):
        # The diagnoser reaches both endpoint checks unconditionally: a
        # non-fitting signature integer is an input error, not a fault,
        # regardless of the chain short circuit check_rhe keeps.
        broken = RotationChain(self.f.k1.public_key, (self.f.cert0,))
        bad_z = AggregateSignature(
            R=self.f.old_sig.R,
            z=FIELD_PRIME,
            signer_ids=self.f.old_sig.signer_ids,
        )
        with self.assertRaises(ValueError):
            diagnose_rhe(
                RHE(
                    self.f.proof, broken, bad_z, self.f.new_sig
                )
            )

    def test_error_boundary_matches_check_rhe(self):
        # Deterministic input damage must reject check_rhe identically.
        bad_cert = dataclasses.replace(self.f.cert0, old=3)
        cases = (
            RHE(
                self.f.proof,
                RotationChain(self.f.k0.public_key, ()),
                self.f.old_sig,
                self.f.new_sig,
            ),
            RHE(
                self.f.proof,
                RotationChain(3, (bad_cert,)),
                self.f.old_sig,
                self.f.new_sig,
            ),
        )
        for rhe in cases:
            with self.subTest():
                with self.assertRaises(ValueError):
                    check_rhe(rhe)
                with self.assertRaises(ValueError):
                    diagnose_rhe(rhe)

    def test_check_rhe_remains_short_circuited(self):
        # The diagnoser's all-failures collection does not change check_rhe's
        # own short-circuit verdict on a broken chain.
        broken = dataclasses.replace(
            self.f.single,
            rotations=RotationChain(self.f.k1.public_key, (self.f.cert0,)),
        )
        self.assertFalse(check_rhe(broken))
        self.assertFalse(diagnose_rhe(broken).valid)


if __name__ == "__main__":
    unittest.main()
