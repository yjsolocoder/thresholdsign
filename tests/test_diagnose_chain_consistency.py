"""Cross-entry compatibility tests: diagnose_rotation_chain and diagnose_rhe
must diagnose one and the same rotation chain identically through the
public entry points — same faults at the same indices in the same order —
and must share exactly the same exception boundary."""

import dataclasses
import unittest

from thresholdsign import (
    AggregateSignature,
    RHE,
    Rotation,
    RotationChain,
    RotationChainDiagnosis,
    SealHistoryExtension,
    check_rhe,
    diagnose_rhe,
    diagnose_rotation_chain,
    verify_rotation_chain,
)

from test_rotation_chain import FIELD_PRIME, GROUP_PRIME, GENERATOR, make_cert
from test_rhe import RheFixture, make_other_key
from test_seal_history import sign_message


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


def rotation_projection(diagnosis):
    """A rotation-chain diagnosis as plain (index, check) pairs."""
    return [(fault.index, fault.check) for fault in diagnosis.faults]


def rhe_chain_projection(diagnosis):
    """The chain faults of an RHE diagnosis, in rotation-fault orientation."""
    return [
        (fault.index, fault.check)
        for fault in diagnosis.faults
        if fault.index is not None
    ]


def rhe_endpoint_projection(diagnosis):
    """The endpoint-signature faults of an RHE diagnosis, in order."""
    return [fault.check for fault in diagnosis.faults if fault.index is None]


class ConsistencyFixture(RheFixture):
    """Adds a fourth key and a k3-signed new root for pure-link cases."""

    def __init__(self):
        super().__init__()
        self.k3 = make_other_key((4, 5, 6, 7), 2, 30)
        # An honestly signed certificate k2 -> k3: independently valid, but
        # its old key does not meet cert1's new key unless the seam holds.
        self.cert2 = make_cert(self.k2, self.k3, (3, 5), t=2, seed=400)
        self.new_sig_3 = sign_message(
            self.new_message, self.k3, signer_ids=(5, 7), seed=900
        )


class ChainDiagnosisConsistencyTest(unittest.TestCase):
    """One chain, two public diagnosers: the chain faults must match exactly."""

    def setUp(self):
        self.f = ConsistencyFixture()

    def assert_chain_consistent(self, chain, rhe):
        rotation = diagnose_rotation_chain(chain)
        rhe_diagnosis = diagnose_rhe(rhe)
        self.assertEqual(
            rhe_chain_projection(rhe_diagnosis),
            rotation_projection(rotation),
        )
        self.assertEqual(
            rhe_diagnosis.valid,
            rotation.valid and not rhe_endpoint_projection(rhe_diagnosis),
        )
        return rotation, rhe_diagnosis

    def rhe_with(self, chain, old_sig=None, new_sig=None):
        return RHE(
            self.f.proof,
            chain,
            self.f.old_sig if old_sig is None else old_sig,
            self.f.new_sig_2 if new_sig is None else new_sig,
        )

    def test_honest_single_hop(self):
        chain = self.f.single_chain
        rotation, rhe_diagnosis = self.assert_chain_consistent(
            chain, self.rhe_with(chain, new_sig=self.f.new_sig)
        )
        self.assertEqual(rotation, RotationChainDiagnosis(True, ()))
        self.assertEqual(rhe_diagnosis.faults, ())
        self.assertTrue(verify_rotation_chain(chain))

    def test_honest_multi_hop(self):
        chain = self.f.multi_chain
        rotation, rhe_diagnosis = self.assert_chain_consistent(
            chain, self.rhe_with(chain)
        )
        self.assertEqual(rotation, RotationChainDiagnosis(True, ()))
        self.assertEqual(rhe_diagnosis.faults, ())
        self.assertTrue(check_rhe(self.rhe_with(chain)))

    def test_wrong_anchor_single_hop(self):
        chain = RotationChain(self.f.k1.public_key, (self.f.cert0,))
        rotation, rhe_diagnosis = self.assert_chain_consistent(
            chain, self.rhe_with(chain, new_sig=self.f.new_sig)
        )
        self.assertEqual(rotation_projection(rotation), [(0, "anchor")])
        self.assertEqual(rhe_endpoint_projection(rhe_diagnosis), [])

    def test_anchor_and_authorization_at_same_index(self):
        chain = RotationChain(self.f.k1.public_key, (tampered(self.f.cert0),))
        rotation, rhe_diagnosis = self.assert_chain_consistent(
            chain, self.rhe_with(chain, new_sig=self.f.new_sig)
        )
        self.assertEqual(
            rotation_projection(rotation),
            [(0, "anchor"), (0, "authorization")],
        )

    def test_pure_link_fault_multi_hop(self):
        # cert2 is honestly signed but its old key does not meet cert0.new.
        chain = RotationChain(
            self.f.k0.public_key, (self.f.cert0, self.f.cert2)
        )
        rotation, rhe_diagnosis = self.assert_chain_consistent(
            chain, self.rhe_with(chain, new_sig=self.f.new_sig_3)
        )
        self.assertEqual(rotation_projection(rotation), [(1, "link")])
        self.assertEqual(rhe_endpoint_projection(rhe_diagnosis), [])

    def test_link_and_authorization_at_same_index(self):
        moved_bad = dataclasses.replace(
            tampered(self.f.cert1), old=self.f.k0.public_key
        )
        chain = RotationChain(self.f.k0.public_key, (self.f.cert0, moved_bad))
        rotation, _ = self.assert_chain_consistent(chain, self.rhe_with(chain))
        self.assertEqual(
            rotation_projection(rotation),
            [(1, "link"), (1, "authorization")],
        )

    def test_multiple_simultaneous_failures_across_three_positions(self):
        # Wrong anchor, tampered authorizations everywhere and a broken seam
        # into the third certificate: five chain faults, in chain order.
        moved_bad2 = dataclasses.replace(
            tampered(self.f.cert2), old=self.f.k0.public_key
        )
        chain = RotationChain(
            self.f.k3.public_key,
            (tampered(self.f.cert0), tampered(self.f.cert1), moved_bad2),
        )
        rotation, rhe_diagnosis = self.assert_chain_consistent(
            chain, self.rhe_with(chain, new_sig=self.f.new_sig_3)
        )
        self.assertEqual(
            rotation_projection(rotation),
            [
                (0, "anchor"),
                (0, "authorization"),
                (1, "authorization"),
                (2, "link"),
                (2, "authorization"),
            ],
        )
        self.assertEqual(rhe_endpoint_projection(rhe_diagnosis), [])
        self.assertFalse(verify_rotation_chain(chain))

    def test_endpoint_faults_follow_chain_faults_with_none_index(self):
        # A broken chain plus both endpoint signatures tampered: the chain
        # faults come first, then old-signature and new-signature, each
        # with index None.
        chain = RotationChain(
            self.f.k1.public_key, (tampered(self.f.cert0),)
        )
        rhe = self.rhe_with(
            chain, old_sig=bump(self.f.old_sig), new_sig=bump(self.f.new_sig)
        )
        rhe_diagnosis = diagnose_rhe(rhe)
        self.assertEqual(
            [(fault.check, fault.index) for fault in rhe_diagnosis.faults],
            [
                ("anchor", 0),
                ("authorization", 0),
                ("old-signature", None),
                ("new-signature", None),
            ],
        )
        for fault in rhe_diagnosis.faults[2:]:
            self.assertIsNone(fault.index)
        # The chain part still matches the standalone chain diagnosis.
        self.assertEqual(
            rhe_chain_projection(rhe_diagnosis),
            rotation_projection(diagnose_rotation_chain(chain)),
        )

    def test_valid_agrees_with_boolean_verifiers_across_variants(self):
        moved_bad = dataclasses.replace(
            tampered(self.f.cert1), old=self.f.k0.public_key
        )
        cases = [
            (self.f.single_chain, self.rhe_with(self.f.single_chain, new_sig=self.f.new_sig)),
            (self.f.multi_chain, self.rhe_with(self.f.multi_chain)),
            (
                RotationChain(self.f.k1.public_key, (self.f.cert0,)),
                self.rhe_with(
                    RotationChain(self.f.k1.public_key, (self.f.cert0,)),
                    new_sig=self.f.new_sig,
                ),
            ),
            (
                RotationChain(self.f.k0.public_key, (self.f.cert0, moved_bad)),
                self.rhe_with(
                    RotationChain(self.f.k0.public_key, (self.f.cert0, moved_bad))
                ),
            ),
            (
                RotationChain(self.f.k0.public_key, (self.f.cert0, self.f.cert2)),
                self.rhe_with(
                    RotationChain(self.f.k0.public_key, (self.f.cert0, self.f.cert2)),
                    new_sig=self.f.new_sig_3,
                ),
            ),
        ]
        for chain, rhe in cases:
            with self.subTest():
                self.assertEqual(
                    diagnose_rotation_chain(chain).valid,
                    verify_rotation_chain(chain),
                )
                self.assertEqual(diagnose_rhe(rhe).valid, check_rhe(rhe))
                self.assert_chain_consistent(chain, rhe)

    def test_equal_inputs_give_equal_reports_from_both_entries(self):
        moved_bad = dataclasses.replace(
            tampered(self.f.cert1), old=self.f.k0.public_key
        )
        chain = RotationChain(
            self.f.k3.public_key, (tampered(self.f.cert0), moved_bad)
        )
        rhe = self.rhe_with(
            chain, old_sig=bump(self.f.old_sig), new_sig=bump(self.f.new_sig_2)
        )
        for first, second in (
            (diagnose_rotation_chain(chain), diagnose_rotation_chain(chain)),
            (diagnose_rhe(rhe), diagnose_rhe(rhe)),
        ):
            with self.subTest():
                self.assertEqual(first, second)
                self.assertEqual(hash(first), hash(second))


class SharedExceptionBoundaryTest(unittest.TestCase):
    """Both diagnosers reject the same malformed chains with the same errors."""

    def setUp(self):
        self.f = ConsistencyFixture()

    def assert_same_exception(self, chain, exception):
        rhe = RHE(self.f.proof, chain, self.f.old_sig, self.f.new_sig_2)
        with self.assertRaises(exception):
            diagnose_rotation_chain(chain)
        with self.assertRaises(exception):
            diagnose_rhe(rhe)

    def test_non_chain_argument_type_error(self):
        for bad in ("chain", None, 42, self.f.cert0, (self.f.cert0,)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    diagnose_rotation_chain(bad)
                with self.assertRaises(TypeError):
                    diagnose_rhe(bad)

    def test_bad_anchor_type_error(self):
        for bad in ("x", True, False, 1.5):
            with self.subTest(bad=bad):
                self.assert_same_exception(
                    RotationChain(bad, (self.f.cert0,)), TypeError
                )

    def test_bad_certificates_container_type_error(self):
        self.assert_same_exception(
            RotationChain(self.f.k0.public_key, [self.f.cert0]), TypeError
        )

    def test_non_rotation_element_type_error(self):
        self.assert_same_exception(
            RotationChain(self.f.k0.public_key, (self.f.cert0, "cert")),
            TypeError,
        )

    def test_empty_chain_value_error(self):
        self.assert_same_exception(
            RotationChain(self.f.k0.public_key, ()), ValueError
        )

    def test_illegal_group_and_public_key_value_error(self):
        bad_cert = Rotation(
            3,  # not in the order-q subgroup
            self.f.k1.public_key,
            (1, 2),
            2,
            FIELD_PRIME,
            GROUP_PRIME,
            GENERATOR,
            self.f.cert0.sig,
        )
        self.assert_same_exception(RotationChain(3, (bad_cert,)), ValueError)

    def test_illegal_members_and_threshold_value_error(self):
        for bad_ids, bad_t in (
            ((), 2),
            ((1, 1), 2),
            ((1, 2), 99),
        ):
            bad_cert = Rotation(
                self.f.k0.public_key,
                self.f.k1.public_key,
                bad_ids,
                bad_t,
                FIELD_PRIME,
                GROUP_PRIME,
                GENERATOR,
                self.f.cert0.sig,
            )
            with self.subTest(bad_ids=bad_ids, bad_t=bad_t):
                self.assert_same_exception(
                    RotationChain(self.f.k0.public_key, (bad_cert,)), ValueError
                )

    def test_illegal_aggregate_signature_structure_value_error(self):
        empty_signers = Rotation(
            self.f.k0.public_key,
            self.f.k1.public_key,
            (1, 2),
            2,
            FIELD_PRIME,
            GROUP_PRIME,
            GENERATOR,
            AggregateSignature(
                R=self.f.cert0.sig.R, z=self.f.cert0.sig.z, signer_ids=()
            ),
        )
        self.assert_same_exception(
            RotationChain(self.f.k0.public_key, (empty_signers,)), ValueError
        )
        bad_z = Rotation(
            self.f.k0.public_key,
            self.f.k1.public_key,
            (1, 2),
            2,
            FIELD_PRIME,
            GROUP_PRIME,
            GENERATOR,
            AggregateSignature(
                R=self.f.cert0.sig.R, z=FIELD_PRIME, signer_ids=(1,)
            ),
        )
        self.assert_same_exception(
            RotationChain(self.f.k0.public_key, (bad_z,)), ValueError
        )

    def test_nested_signature_field_type_error(self):
        bad_cert = Rotation(
            self.f.k0.public_key,
            self.f.k1.public_key,
            (1, 2),
            2,
            FIELD_PRIME,
            GROUP_PRIME,
            GENERATOR,
            AggregateSignature(R="x", z=3, signer_ids=(1,)),
        )
        self.assert_same_exception(
            RotationChain(self.f.k0.public_key, (bad_cert,)), TypeError
        )

    def test_negative_anchor_is_diagnosed_not_rejected_by_either(self):
        chain = RotationChain(-1, (self.f.cert0,))
        rhe = self.rhe_with(chain, new_sig=self.f.new_sig)
        rotation, rhe_diagnosis = (
            diagnose_rotation_chain(chain),
            diagnose_rhe(rhe),
        )
        self.assertEqual(rotation_projection(rotation), [(0, "anchor")])
        self.assertEqual(
            rhe_chain_projection(rhe_diagnosis), [(0, "anchor")]
        )
        self.assertFalse(verify_rotation_chain(chain))
        self.assertFalse(check_rhe(rhe))

    def rhe_with(self, chain, old_sig=None, new_sig=None):
        return RHE(
            self.f.proof,
            chain,
            self.f.old_sig if old_sig is None else old_sig,
            self.f.new_sig_2 if new_sig is None else new_sig,
        )


class RheOnlyBoundaryTest(unittest.TestCase):
    """The RHE-specific boundaries the refactor must leave untouched."""

    def setUp(self):
        self.f = ConsistencyFixture()

    def test_old_prefix_length_out_of_range_value_error(self):
        for bad_total in (0, len(self.f.proof.leaves)):
            bad_proof = SealHistoryExtension(
                old_total=bad_total, leaves=self.f.proof.leaves
            )
            rhe = RHE(
                bad_proof, self.f.single_chain, self.f.old_sig, self.f.new_sig
            )
            with self.subTest(bad_total=bad_total):
                with self.assertRaises(ValueError):
                    diagnose_rhe(rhe)
                with self.assertRaises(ValueError):
                    check_rhe(rhe)

    def test_leaf_width_not_32_bytes_value_error(self):
        bad_proof = SealHistoryExtension(
            old_total=1, leaves=(b"a" * 31, b"b" * 32)
        )
        rhe = RHE(
            bad_proof, self.f.single_chain, self.f.old_sig, self.f.new_sig
        )
        with self.assertRaises(ValueError):
            diagnose_rhe(rhe)
        with self.assertRaises(ValueError):
            check_rhe(rhe)

    def test_endpoint_integer_range_enforced_even_when_chain_broken(self):
        # The diagnoser reaches both endpoint checks unconditionally: a
        # non-fitting signature integer is an input error, not a fault,
        # even though the chain is already broken.
        broken = RotationChain(self.f.k1.public_key, (self.f.cert0,))
        bad_z = AggregateSignature(
            R=self.f.old_sig.R,
            z=FIELD_PRIME,
            signer_ids=self.f.old_sig.signer_ids,
        )
        rhe = RHE(self.f.proof, broken, bad_z, self.f.new_sig)
        with self.assertRaises(ValueError):
            diagnose_rhe(rhe)

    def test_check_rhe_keeps_its_chain_short_circuit(self):
        # check_rhe still returns False on a broken chain without ever
        # reaching the endpoint checks — even an out-of-group endpoint
        # signature integer does not surface.
        broken = RotationChain(self.f.k1.public_key, (self.f.cert0,))
        bad_z = AggregateSignature(
            R=self.f.old_sig.R,
            z=FIELD_PRIME,
            signer_ids=self.f.old_sig.signer_ids,
        )
        self.assertFalse(check_rhe(RHE(self.f.proof, broken, bad_z, self.f.new_sig)))
        self.assertFalse(
            check_rhe(
                RHE(self.f.proof, broken, self.f.old_sig, self.f.new_sig)
            )
        )


if __name__ == "__main__":
    unittest.main()
