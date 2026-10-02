"""Tests for the stateless failure diagnoser of cross-key seal-history
append proofs: diagnose_rhe and its RHEDiagnosis / RHEFault results."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    RHE,
    RHEFault,
    RHEDiagnosis,
    RotationChain,
    SealHistoryExtension,
    check_rhe,
    diagnose_rhe,
)

from test_nonce_reuse import FIELD_PRIME, GROUP_PRIME
from test_rotation_chain import make_cert
from test_rhe import RheFixture


def fault_projection(diagnosis):
    return [(fault.check, fault.index) for fault in diagnosis.faults]


def tampered_signature(signature):
    """The same aggregate signature with its Schnorr z bumped."""
    return AggregateSignature(
        R=signature.R,
        z=(signature.z + 1) % FIELD_PRIME,
        signer_ids=signature.signer_ids,
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
        fault = RHEFault("link", 1)
        self.assertEqual(fault, RHEFault(check="link", index=1))
        self.assertEqual(hash(fault), hash(RHEFault("link", 1)))
        self.assertNotEqual(fault, RHEFault("anchor", 1))
        self.assertNotEqual(fault, RHEFault("link", 0))
        self.assertEqual(
            hash(RHEFault("old-signature", None)),
            hash(RHEFault("old-signature", None)),
        )
        with self.assertRaises(FrozenInstanceError):
            fault.check = "anchor"

        diagnosis = RHEDiagnosis(False, (fault,))
        self.assertEqual(
            diagnosis,
            RHEDiagnosis(valid=False, faults=(RHEFault("link", 1),)),
        )
        self.assertEqual(
            hash(diagnosis),
            hash(RHEDiagnosis(False, (RHEFault("link", 1),))),
        )
        self.assertNotEqual(diagnosis, RHEDiagnosis(True, ()))
        with self.assertRaises(FrozenInstanceError):
            diagnosis.valid = True

    def test_endpoint_faults_pin_no_certificate_index(self):
        for check in ("old-signature", "new-signature"):
            fault = RHEFault(check, None)
            self.assertIsNone(fault.index)
            self.assertEqual((fault.check, fault.index), (check, None))


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
        self.assertTrue(diagnosis.valid)
        self.assertTrue(check_rhe(self.f.multi))

    def test_valid_agrees_with_check_rhe_on_honest_proofs(self):
        for rhe in (self.f.single, self.f.multi):
            with self.subTest():
                self.assertEqual(diagnose_rhe(rhe).valid, check_rhe(rhe))


class DiagnoseChainFaultTest(unittest.TestCase):
    def setUp(self):
        self.f = RheFixture()

    def test_wrong_anchor_reports_anchor_at_index_zero_only(self):
        rhe = dataclasses.replace(
            self.f.single,
            rotations=RotationChain(
                self.f.k1.public_key, (self.f.cert0,)
            ),
        )
        diagnosis = diagnose_rhe(rhe)
        self.assertFalse(diagnosis.valid)
        # The endpoint signatures are still sound: cert0.old is still k0
        # and cert0.new is still k1, so only the anchor fault appears.
        self.assertEqual(fault_projection(diagnosis), [("anchor", 0)])
        self.assertEqual(diagnosis.valid, check_rhe(rhe))

    def test_severed_link_reports_link_at_index_one_only(self):
        cert2 = make_cert(self.f.k2, self.f.k1, (3, 5), t=2, seed=900)
        chain = RotationChain(
            self.f.k0.public_key, (self.f.cert0, cert2)
        )
        rhe = RHE(self.f.proof, chain, self.f.old_sig, self.f.new_sig)
        diagnosis = diagnose_rhe(rhe)
        self.assertFalse(diagnosis.valid)
        # cert2 is honestly signed by k2 and ends at k1, so the new
        # endpoint signature still verifies; only the seam is broken.
        self.assertEqual(fault_projection(diagnosis), [("link", 1)])
        self.assertEqual(diagnosis.valid, check_rhe(rhe))

    def test_bad_rotation_authorization_reports_authorization(self):
        bad_cert = dataclasses.replace(
            self.f.cert0, sig=tampered_signature(self.f.cert0.sig)
        )
        rhe = dataclasses.replace(
            self.f.single,
            rotations=RotationChain(self.f.k0.public_key, (bad_cert,)),
        )
        diagnosis = diagnose_rhe(rhe)
        self.assertEqual(
            fault_projection(diagnosis), [("authorization", 0)]
        )
        self.assertEqual(diagnosis.valid, check_rhe(rhe))

    def test_anchor_before_authorization_at_same_index(self):
        bad_cert = dataclasses.replace(
            self.f.cert0, sig=tampered_signature(self.f.cert0.sig)
        )
        rhe = dataclasses.replace(
            self.f.single,
            rotations=RotationChain(
                self.f.k1.public_key, (bad_cert,)
            ),
        )
        diagnosis = diagnose_rhe(rhe)
        self.assertEqual(
            fault_projection(diagnosis),
            [("anchor", 0), ("authorization", 0)],
        )

    def test_full_chain_fault_ordering_across_positions(self):
        bad_cert1 = dataclasses.replace(
            self.f.cert1, sig=tampered_signature(self.f.cert1.sig)
        )
        # Break the seam cert0.new -> cert1.old as well by moving cert1's
        # old key onto k0; its signature then fails under that key too.
        moved_bad1 = dataclasses.replace(bad_cert1, old=self.f.k0.public_key)
        chain = RotationChain(
            self.f.k1.public_key, (self.f.cert0, moved_bad1)
        )
        rhe = RHE(
            self.f.proof, chain, self.f.old_sig, self.f.new_sig_2
        )
        diagnosis = diagnose_rhe(rhe)
        chain_faults = [
            fault for fault in fault_projection(diagnosis)
            if fault[0] in ("anchor", "link", "authorization")
        ]
        self.assertEqual(
            chain_faults,
            [
                ("anchor", 0),
                ("link", 1),
                ("authorization", 1),
            ],
        )
        self.assertEqual(diagnosis.valid, check_rhe(rhe))


class DiagnoseEndpointSignatureFaultTest(unittest.TestCase):
    def setUp(self):
        self.f = RheFixture()

    def test_tampered_old_root_signature(self):
        rhe = dataclasses.replace(
            self.f.single, old_sig=tampered_signature(self.f.old_sig)
        )
        diagnosis = diagnose_rhe(rhe)
        self.assertFalse(diagnosis.valid)
        self.assertEqual(
            fault_projection(diagnosis), [("old-signature", None)]
        )
        self.assertEqual(diagnosis.valid, check_rhe(rhe))

    def test_tampered_new_root_signature(self):
        rhe = dataclasses.replace(
            self.f.single, new_sig=tampered_signature(self.f.new_sig)
        )
        diagnosis = diagnose_rhe(rhe)
        self.assertFalse(diagnosis.valid)
        self.assertEqual(
            fault_projection(diagnosis), [("new-signature", None)]
        )
        self.assertEqual(diagnosis.valid, check_rhe(rhe))

    def test_both_root_signatures_bad_are_both_reported_in_order(self):
        rhe = RHE(
            self.f.proof,
            self.f.single_chain,
            tampered_signature(self.f.old_sig),
            tampered_signature(self.f.new_sig),
        )
        diagnosis = diagnose_rhe(rhe)
        self.assertEqual(
            fault_projection(diagnosis),
            [("old-signature", None), ("new-signature", None)],
        )
        self.assertEqual(diagnosis.valid, check_rhe(rhe))

    def test_swapped_signature_pair_reports_both_endpoints(self):
        swapped = RHE(
            self.f.proof,
            self.f.single_chain,
            self.f.new_sig,
            self.f.old_sig,
        )
        diagnosis = diagnose_rhe(swapped)
        self.assertFalse(diagnosis.valid)
        self.assertEqual(
            fault_projection(diagnosis),
            [("old-signature", None), ("new-signature", None)],
        )
        self.assertFalse(check_rhe(swapped))

    def test_signature_under_other_endpoint_key_is_new_signature_fault(self):
        # new_sig_2 was produced by k2 but the chain ends at k1.
        rhe = RHE(
            self.f.proof,
            self.f.single_chain,
            self.f.old_sig,
            self.f.new_sig_2,
        )
        diagnosis = diagnose_rhe(rhe)
        self.assertEqual(
            fault_projection(diagnosis), [("new-signature", None)]
        )
        self.assertEqual(diagnosis.valid, check_rhe(rhe))

    def test_endpoint_signatures_checked_even_when_chain_broken(self):
        broken_chain = RotationChain(
            self.f.k1.public_key, (self.f.cert0,)
        )
        rhe = RHE(
            self.f.proof,
            broken_chain,
            tampered_signature(self.f.old_sig),
            tampered_signature(self.f.new_sig),
        )
        diagnosis = diagnose_rhe(rhe)
        # check_rhe short-circuits at the chain; the diagnosis must still
        # re-verify both endpoint root signatures independently.
        self.assertEqual(
            fault_projection(diagnosis),
            [
                ("anchor", 0),
                ("old-signature", None),
                ("new-signature", None),
            ],
        )
        self.assertEqual(diagnosis.valid, check_rhe(rhe))

    def test_everything_broken_collects_every_fault_once(self):
        bad_cert0 = dataclasses.replace(
            self.f.cert0, sig=tampered_signature(self.f.cert0.sig)
        )
        rhe = RHE(
            self.f.proof,
            RotationChain(self.f.k1.public_key, (bad_cert0,)),
            tampered_signature(self.f.old_sig),
            tampered_signature(self.f.new_sig),
        )
        diagnosis = diagnose_rhe(rhe)
        self.assertEqual(
            fault_projection(diagnosis),
            [
                ("anchor", 0),
                ("authorization", 0),
                ("old-signature", None),
                ("new-signature", None),
            ],
        )
        self.assertEqual(len(diagnosis.faults), 4)
        self.assertFalse(diagnosis.valid)
        self.assertEqual(diagnosis.valid, check_rhe(rhe))

    def test_tampered_leaves_mismatch_both_root_signatures(self):
        leaves = self.f.proof.leaves
        flipped = leaves[-1][:-1] + bytes([leaves[-1][-1] ^ 1])
        bad_leaves = leaves[:-1] + (flipped,)
        bad_proof = SealHistoryExtension(
            old_total=self.f.proof.old_total, leaves=bad_leaves
        )
        rhe = RHE(
            bad_proof,
            self.f.single_chain,
            self.f.old_sig,
            self.f.new_sig,
        )
        diagnosis = diagnose_rhe(rhe)
        # The new leaf changes both roots (the old prefix ends exactly at
        # old_total == 2 and the flipped leaf is index 3), so only the new
        # root moves: verify with a prefix-contained tamper below too.
        self.assertEqual(
            fault_projection(diagnosis), [("new-signature", None)]
        )
        self.assertFalse(check_rhe(rhe))

        flipped_old = leaves[0][:-1] + bytes([leaves[0][-1] ^ 1])
        bad_old_leaves = (flipped_old,) + leaves[1:]
        bad_old_proof = SealHistoryExtension(
            old_total=self.f.proof.old_total, leaves=bad_old_leaves
        )
        rhe_old = RHE(
            bad_old_proof,
            self.f.single_chain,
            self.f.old_sig,
            self.f.new_sig,
        )
        self.assertEqual(
            fault_projection(diagnose_rhe(rhe_old)),
            [("old-signature", None), ("new-signature", None)],
        )
        self.assertFalse(check_rhe(rhe_old))


class DiagnoseMultiHopEndpointTest(unittest.TestCase):
    def setUp(self):
        self.f = RheFixture()

    def test_bad_authorization_middle_hop_plus_bad_new_signature(self):
        bad_cert1 = dataclasses.replace(
            self.f.cert1, sig=tampered_signature(self.f.cert1.sig)
        )
        chain = RotationChain(
            self.f.k0.public_key, (self.f.cert0, bad_cert1)
        )
        rhe = RHE(
            self.f.proof,
            chain,
            self.f.old_sig,
            tampered_signature(self.f.new_sig_2),
        )
        diagnosis = diagnose_rhe(rhe)
        self.assertEqual(
            fault_projection(diagnosis),
            [
                ("authorization", 1),
                ("new-signature", None),
            ],
        )
        self.assertEqual(diagnosis.valid, check_rhe(rhe))

    def test_multi_hop_endpoints_use_chain_endpoint_groups(self):
        # An honest multi-hop proof diagnoses clean; swapping the k2 new
        # signature for the k1 one is a new-signature fault under the last
        # certificate's (q, p, g, new) endpoint.
        rhe = RHE(
            self.f.proof,
            self.f.multi_chain,
            self.f.old_sig,
            self.f.new_sig,
        )
        diagnosis = diagnose_rhe(rhe)
        self.assertEqual(
            fault_projection(diagnosis), [("new-signature", None)]
        )
        self.assertFalse(check_rhe(rhe))


class DiagnoseDeterminismTest(unittest.TestCase):
    def setUp(self):
        self.f = RheFixture()

    def test_equal_inputs_give_equal_ordered_reports(self):
        broken_chain = RotationChain(
            self.f.k1.public_key, (self.f.cert0,)
        )
        cases = (
            self.f.single,
            self.f.multi,
            RHE(
                self.f.proof,
                broken_chain,
                tampered_signature(self.f.old_sig),
                tampered_signature(self.f.new_sig),
            ),
            RHE(
                self.f.proof,
                self.f.single_chain,
                self.f.new_sig,
                self.f.old_sig,
            ),
        )
        for rhe in cases:
            with self.subTest():
                first = diagnose_rhe(rhe)
                second = diagnose_rhe(rhe)
                self.assertEqual(first, second)
                self.assertEqual(hash(first), hash(second))
                # Chain faults precede endpoint faults, and within each
                # region indices are non-decreasing.
                checks = [fault.check for fault in first.faults]
                chain_region = [
                    check in ("anchor", "link", "authorization")
                    for check in checks
                ]
                self.assertEqual(
                    chain_region,
                    sorted(chain_region, reverse=True),
                )
                self.assertEqual(
                    [
                        fault.index
                        for fault in first.faults
                        if fault.index is not None
                    ],
                    sorted(
                        fault.index
                        for fault in first.faults
                        if fault.index is not None
                    ),
                )


class DiagnoseErrorBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.f = RheFixture()

    def test_non_rhe_argument_type_error(self):
        for bad in ("rhe", None, 42, self.f.proof, ()):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    diagnose_rhe(bad)

    def test_bad_field_types_type_error(self):
        with self.assertRaises(TypeError):
            diagnose_rhe(
                RHE(
                    "x",
                    self.f.single_chain,
                    self.f.old_sig,
                    self.f.new_sig,
                )
            )
        with self.assertRaises(TypeError):
            diagnose_rhe(
                RHE(
                    self.f.proof,
                    "chain",
                    self.f.old_sig,
                    self.f.new_sig,
                )
            )
        with self.assertRaises(TypeError):
            diagnose_rhe(
                RHE(
                    self.f.proof,
                    self.f.single_chain,
                    "sig",
                    self.f.new_sig,
                )
            )
        with self.assertRaises(TypeError):
            diagnose_rhe(
                RHE(
                    self.f.proof,
                    self.f.single_chain,
                    self.f.old_sig,
                    "sig",
                )
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
        for bad_proof in (
            SealHistoryExtension(old_total=0, leaves=self.f.proof.leaves),
            SealHistoryExtension(
                old_total=len(self.f.proof.leaves),
                leaves=self.f.proof.leaves,
            ),
            SealHistoryExtension(old_total=1, leaves=()),
            SealHistoryExtension(
                old_total=1,
                leaves=self.f.proof.leaves[:-1]
                + (b"a" * 31,),
            ),
        ):
            with self.subTest():
                with self.assertRaises(ValueError):
                    diagnose_rhe(
                        RHE(
                            bad_proof,
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

    def test_illegal_signature_structure_value_error(self):
        zero_R = AggregateSignature(R=0, z=1, signer_ids=(1,))
        with self.assertRaises(ValueError):
            diagnose_rhe(
                RHE(
                    self.f.proof,
                    self.f.single_chain,
                    zero_R,
                    self.f.new_sig,
                )
            )
        empty_signers = AggregateSignature(R=2, z=3, signer_ids=())
        with self.assertRaises(ValueError):
            diagnose_rhe(
                RHE(
                    self.f.proof,
                    self.f.single_chain,
                    self.f.old_sig,
                    empty_signers,
                )
            )

    def test_signature_integer_out_of_endpoint_range_value_error(self):
        # A structurally framed signature whose z does not fit the
        # endpoint field prime rejects as ValueError, exactly like
        # check_rhe would once it reached verify_signature.
        oversized = AggregateSignature(
            R=self.f.old_sig.R,
            z=FIELD_PRIME,
            signer_ids=self.f.old_sig.signer_ids,
        )
        with self.assertRaises(ValueError):
            diagnose_rhe(
                RHE(
                    self.f.proof,
                    self.f.single_chain,
                    oversized,
                    self.f.new_sig,
                )
            )

    def test_non_subgroup_signature_R_value_error_even_with_broken_chain(self):
        # 2 is not in the order-q subgroup of the toy group; a broken
        # chain makes check_rhe short-circuit before verify_signature,
        # but the diagnoser pre-validates both endpoint signatures and
        # must reject this deterministic damage as ValueError, not fault.
        self.assertNotEqual(pow(2, FIELD_PRIME, GROUP_PRIME), 1)
        bad_R = AggregateSignature(
            R=2,
            z=self.f.old_sig.z,
            signer_ids=self.f.old_sig.signer_ids,
        )
        broken_chain = RotationChain(
            self.f.k1.public_key, (self.f.cert0,)
        )
        rhe = RHE(
            self.f.proof, broken_chain, bad_R, self.f.new_sig
        )
        self.assertFalse(check_rhe(rhe))
        with self.assertRaises(ValueError):
            diagnose_rhe(rhe)

    def test_error_boundary_matches_check_rhe(self):
        # The same malformed inputs must reject check_rhe identically:
        # deterministic damage is never a diagnostic fault.
        for bad in ("rhe", 42, None):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    check_rhe(bad)
        with self.assertRaises(ValueError):
            check_rhe(
                RHE(
                    self.f.proof,
                    RotationChain(self.f.k0.public_key, ()),
                    self.f.old_sig,
                    self.f.new_sig,
                )
            )


if __name__ == "__main__":
    unittest.main()
