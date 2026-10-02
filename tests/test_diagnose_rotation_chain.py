"""Tests for the stateless failure diagnoser of persistent rotation chains:
diagnose_rotation_chain and its RotationChainDiagnosis / RotationFault
results."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    Rotation,
    RotationChain,
    RotationChainDiagnosis,
    RotationFault,
    diagnose_rotation_chain,
    verify_rotation_chain,
)

from test_rotation_chain import (
    FIELD_PRIME,
    GROUP_PRIME,
    GENERATOR,
    make_cert,
    make_key,
)


def tampered(cert):
    """The same certificate with its Schnorr z bumped, so verification fails."""
    bad_sig = AggregateSignature(
        R=cert.sig.R,
        z=(cert.sig.z + 1) % FIELD_PRIME,
        signer_ids=cert.sig.signer_ids,
    )
    return dataclasses.replace(cert, sig=bad_sig)


def fault_projection(diagnosis):
    return [(fault.index, fault.check) for fault in diagnosis.faults]


class DiagnosisResultShapeTest(unittest.TestCase):
    def test_fault_fields_in_order(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(RotationFault)],
            ["index", "check"],
        )

    def test_diagnosis_fields_in_order(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(RotationChainDiagnosis)],
            ["valid", "faults"],
        )

    def test_frozen_positional_value_equality(self):
        fault = RotationFault(1, "link")
        self.assertEqual(fault, RotationFault(index=1, check="link"))
        self.assertEqual(hash(fault), hash(RotationFault(1, "link")))
        self.assertNotEqual(fault, RotationFault(0, "link"))
        self.assertNotEqual(fault, RotationFault(1, "anchor"))
        with self.assertRaises(FrozenInstanceError):
            fault.check = "anchor"

        diagnosis = RotationChainDiagnosis(False, (fault,))
        self.assertEqual(
            diagnosis,
            RotationChainDiagnosis(valid=False, faults=(RotationFault(1, "link"),)),
        )
        self.assertEqual(
            hash(diagnosis),
            hash(RotationChainDiagnosis(False, (RotationFault(1, "link"),))),
        )
        self.assertNotEqual(diagnosis, RotationChainDiagnosis(True, ()))
        with self.assertRaises(FrozenInstanceError):
            diagnosis.valid = True


class DiagnoseHonestChainTest(unittest.TestCase):
    def setUp(self):
        self.k0 = make_key((1, 2, 3), 2, seed_offset=0)
        self.k1 = make_key((2, 3, 4, 5), 3, seed_offset=10)
        self.k2 = make_key((3, 4, 5, 6), 2, seed_offset=20)
        self.cert0 = make_cert(self.k0, self.k1, (1, 3), t=3, seed=100)
        self.cert1 = make_cert(self.k1, self.k2, (2, 4, 5), t=2, seed=200)
        self.chain = RotationChain(self.k0.public_key, (self.cert0, self.cert1))

    def test_honest_chain_has_no_faults(self):
        diagnosis = diagnose_rotation_chain(self.chain)
        self.assertEqual(diagnosis, RotationChainDiagnosis(True, ()))
        self.assertTrue(diagnosis.valid)
        self.assertEqual(diagnosis.faults, ())
        self.assertIsInstance(diagnosis.faults, tuple)
        self.assertTrue(verify_rotation_chain(self.chain))

    def test_single_hop_honest_chain(self):
        chain = RotationChain(self.k0.public_key, (self.cert0,))
        self.assertEqual(diagnose_rotation_chain(chain), RotationChainDiagnosis(True, ()))

    def test_valid_agrees_with_boolean_verifier_everywhere(self):
        for chain in (self.chain, RotationChain(self.k0.public_key, (self.cert0,))):
            with self.subTest():
                self.assertEqual(
                    diagnose_rotation_chain(chain).valid,
                    verify_rotation_chain(chain),
                )


class DiagnoseAnchorFaultTest(unittest.TestCase):
    def setUp(self):
        self.k0 = make_key((1, 2, 3), 2, seed_offset=0)
        self.k1 = make_key((2, 3, 4, 5), 2, seed_offset=10)
        self.cert0 = make_cert(self.k0, self.k1, (1, 3), t=2, seed=100)

    def test_wrong_anchor_reports_anchor_at_index_zero(self):
        chain = RotationChain(self.k1.public_key, (self.cert0,))
        diagnosis = diagnose_rotation_chain(chain)
        self.assertFalse(diagnosis.valid)
        self.assertEqual(fault_projection(diagnosis), [(0, "anchor")])
        self.assertFalse(verify_rotation_chain(chain))

    def test_anchor_fault_comes_before_authorization_at_same_index(self):
        chain = RotationChain(self.k1.public_key, (tampered(self.cert0),))
        diagnosis = diagnose_rotation_chain(chain)
        self.assertEqual(
            fault_projection(diagnosis),
            [(0, "anchor"), (0, "authorization")],
        )
        self.assertIsInstance(diagnosis.faults[0], RotationFault)
        self.assertEqual(
            diagnose_rotation_chain(chain), diagnose_rotation_chain(chain)
        )


class DiagnoseLinkFaultTest(unittest.TestCase):
    def setUp(self):
        self.k0 = make_key((1, 2, 3), 2, seed_offset=0)
        self.k1 = make_key((2, 3, 4, 5), 3, seed_offset=10)
        self.k2 = make_key((3, 4, 5, 6), 2, seed_offset=20)
        self.k3 = make_key((4, 5, 6, 7), 2, seed_offset=30)
        self.cert0 = make_cert(self.k0, self.k1, (1, 3), t=3, seed=100)
        self.cert1 = make_cert(self.k1, self.k2, (2, 4, 5), t=2, seed=200)

    def test_pure_link_fault_signature_still_valid(self):
        # An honestly signed, independently valid certificate whose old key
        # simply does not meet the previous certificate's new key.
        other = make_cert(self.k2, self.k3, (3, 5), t=2, seed=300)
        chain = RotationChain(self.k0.public_key, (self.cert0, other))
        diagnosis = diagnose_rotation_chain(chain)
        self.assertFalse(diagnosis.valid)
        self.assertEqual(fault_projection(diagnosis), [(1, "link")])
        self.assertFalse(verify_rotation_chain(chain))

    def test_moved_old_key_gives_link_then_authorization_at_same_index(self):
        # The seam is broken and the signature no longer verifies under the
        # moved old key either; both faults appear, link first.
        moved = dataclasses.replace(self.cert1, old=self.k0.public_key)
        chain = RotationChain(self.k0.public_key, (self.cert0, moved))
        diagnosis = diagnose_rotation_chain(chain)
        self.assertEqual(
            fault_projection(diagnosis),
            [(1, "link"), (1, "authorization")],
        )
        self.assertFalse(verify_rotation_chain(chain))


class DiagnoseAuthorizationFaultTest(unittest.TestCase):
    def setUp(self):
        self.k0 = make_key((1, 2, 3), 2, seed_offset=0)
        self.k1 = make_key((2, 3, 4, 5), 3, seed_offset=10)
        self.k2 = make_key((3, 4, 5, 6), 2, seed_offset=20)
        self.cert0 = make_cert(self.k0, self.k1, (1, 3), t=3, seed=100)
        self.cert1 = make_cert(self.k1, self.k2, (2, 4, 5), t=2, seed=200)

    def test_bad_signature_on_second_cert(self):
        chain = RotationChain(self.k0.public_key, (self.cert0, tampered(self.cert1)))
        diagnosis = diagnose_rotation_chain(chain)
        self.assertEqual(fault_projection(diagnosis), [(1, "authorization")])
        self.assertFalse(verify_rotation_chain(chain))

    def test_bad_signature_on_first_cert(self):
        chain = RotationChain(self.k0.public_key, (tampered(self.cert0), self.cert1))
        diagnosis = diagnose_rotation_chain(chain)
        self.assertEqual(fault_projection(diagnosis), [(0, "authorization")])
        self.assertFalse(verify_rotation_chain(chain))

    def test_bad_signature_does_not_raise_on_single_hop(self):
        chain = RotationChain(self.k0.public_key, (tampered(self.cert0),))
        diagnosis = diagnose_rotation_chain(chain)
        self.assertFalse(diagnosis.valid)
        self.assertEqual(fault_projection(diagnosis), [(0, "authorization")])

    def test_diagnosis_continues_past_every_cryptographic_mismatch(self):
        k3 = make_key((4, 5, 6, 7), 2, seed_offset=40)
        cert2 = make_cert(self.k2, k3, (3, 5), t=2, seed=400)
        # Wrong anchor, tampered signatures on cert1 and cert2; cert0's
        # signature stays valid and every seam stays linked. All four faults
        # must still be reported in chain order.
        chain = RotationChain(
            k3.public_key,
            (self.cert0, tampered(self.cert1), tampered(cert2)),
        )
        diagnosis = diagnose_rotation_chain(chain)
        self.assertEqual(
            fault_projection(diagnosis),
            [(0, "anchor"), (1, "authorization"), (2, "authorization")],
        )
        self.assertEqual(len(diagnosis.faults), 3)
        self.assertFalse(verify_rotation_chain(chain))

    def test_full_fault_ordering_across_three_positions(self):
        k3 = make_key((4, 5, 6, 7), 2, seed_offset=40)
        cert2 = make_cert(self.k2, k3, (3, 5), t=2, seed=400)
        # Break the seam into cert2 as well: point cert2's old key at k0; its
        # signature then fails under that old key too.
        moved_bad2 = dataclasses.replace(tampered(cert2), old=self.k0.public_key)
        chain = RotationChain(
            k3.public_key,
            (tampered(self.cert0), tampered(self.cert1), moved_bad2),
        )
        diagnosis = diagnose_rotation_chain(chain)
        self.assertEqual(
            fault_projection(diagnosis),
            [
                (0, "anchor"),
                (0, "authorization"),
                (1, "authorization"),
                (2, "link"),
                (2, "authorization"),
            ],
        )


class DiagnoseDeterminismTest(unittest.TestCase):
    def setUp(self):
        self.k0 = make_key((1, 2, 3), 2, seed_offset=0)
        self.k1 = make_key((2, 3, 4, 5), 3, seed_offset=10)
        self.k2 = make_key((3, 4, 5, 6), 2, seed_offset=20)
        self.cert0 = make_cert(self.k0, self.k1, (1, 3), t=3, seed=100)
        self.cert1 = make_cert(self.k1, self.k2, (2, 4, 5), t=2, seed=200)

    def test_equal_inputs_give_equal_ordered_reports(self):
        chains = (
            RotationChain(self.k0.public_key, (self.cert0, self.cert1)),
            RotationChain(self.k1.public_key, (self.cert0, tampered(self.cert1))),
        )
        for chain in chains:
            with self.subTest():
                first = diagnose_rotation_chain(chain)
                second = diagnose_rotation_chain(chain)
                self.assertEqual(first, second)
                self.assertEqual(hash(first), hash(second))
                indices = [fault.index for fault in first.faults]
                self.assertEqual(indices, sorted(indices))


class DiagnoseErrorBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.k0 = make_key((1, 2, 3), 2, seed_offset=0)
        self.k1 = make_key((2, 3, 4, 5), 2, seed_offset=10)
        self.cert0 = make_cert(self.k0, self.k1, (1, 3), t=2, seed=100)

    def test_non_chain_argument_type_error(self):
        for bad in ("chain", None, 42, self.cert0, (self.cert0,)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    diagnose_rotation_chain(bad)

    def test_bad_anchor_type_error(self):
        for bad in ("x", True, False, 1.5):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    diagnose_rotation_chain(RotationChain(bad, (self.cert0,)))

    def test_bad_certificates_container_type_error(self):
        with self.assertRaises(TypeError):
            diagnose_rotation_chain(RotationChain(self.k0.public_key, [self.cert0]))

    def test_non_rotation_element_type_error(self):
        with self.assertRaises(TypeError):
            diagnose_rotation_chain(
                RotationChain(self.k0.public_key, (self.cert0, "cert"))
            )

    def test_empty_chain_value_error(self):
        with self.assertRaises(ValueError):
            diagnose_rotation_chain(RotationChain(self.k0.public_key, ()))

    def test_negative_anchor_is_diagnosed_not_rejected_like_verifier(self):
        # verify_rotation_chain accepts any non-bool integer anchor; the
        # mismatch then shows up cryptographically, never as an exception.
        chain = RotationChain(-1, (self.cert0,))
        diagnosis = diagnose_rotation_chain(chain)
        self.assertFalse(diagnosis.valid)
        self.assertEqual(fault_projection(diagnosis), [(0, "anchor")])
        self.assertFalse(verify_rotation_chain(chain))

    def test_illegal_group_and_public_key_value_error(self):
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
        with self.assertRaises(ValueError):
            diagnose_rotation_chain(RotationChain(3, (bad_cert,)))

    def test_illegal_members_and_threshold_value_error(self):
        for bad_ids, bad_t in (
            ((), 2),
            ((1, 1), 2),
            ((1, 2), 99),
        ):
            bad_cert = Rotation(
                self.k0.public_key,
                self.k1.public_key,
                bad_ids,
                bad_t,
                FIELD_PRIME,
                GROUP_PRIME,
                GENERATOR,
                self.cert0.sig,
            )
            with self.subTest(bad_ids=bad_ids, bad_t=bad_t):
                with self.assertRaises(ValueError):
                    diagnose_rotation_chain(
                        RotationChain(self.k0.public_key, (bad_cert,))
                    )

    def test_illegal_aggregate_signature_structure_value_error(self):
        # Empty signer set.
        empty_signers = Rotation(
            self.k0.public_key,
            self.k1.public_key,
            (1, 2),
            2,
            FIELD_PRIME,
            GROUP_PRIME,
            GENERATOR,
            AggregateSignature(
                R=self.cert0.sig.R, z=self.cert0.sig.z, signer_ids=()
            ),
        )
        with self.assertRaises(ValueError):
            diagnose_rotation_chain(
                RotationChain(self.k0.public_key, (empty_signers,))
            )
        # z outside [0, q).
        bad_z = Rotation(
            self.k0.public_key,
            self.k1.public_key,
            (1, 2),
            2,
            FIELD_PRIME,
            GROUP_PRIME,
            GENERATOR,
            AggregateSignature(
                R=self.cert0.sig.R, z=FIELD_PRIME, signer_ids=(1,)
            ),
        )
        with self.assertRaises(ValueError):
            diagnose_rotation_chain(RotationChain(self.k0.public_key, (bad_z,)))

    def test_nested_signature_field_type_error(self):
        bad_cert = Rotation(
            self.k0.public_key,
            self.k1.public_key,
            (1, 2),
            2,
            FIELD_PRIME,
            GROUP_PRIME,
            GENERATOR,
            AggregateSignature(R="x", z=3, signer_ids=(1,)),
        )
        with self.assertRaises(TypeError):
            diagnose_rotation_chain(RotationChain(self.k0.public_key, (bad_cert,)))

    def test_error_boundary_matches_boolean_verifier(self):
        # The same malformed inputs must reject the plain verifier identically:
        # deterministic damage is never a diagnostic fault.
        with self.assertRaises(ValueError):
            verify_rotation_chain(RotationChain(self.k0.public_key, ()))
        bad_cert = Rotation(
            3,
            self.k1.public_key,
            (1, 2),
            2,
            FIELD_PRIME,
            GROUP_PRIME,
            GENERATOR,
            self.cert0.sig,
        )
        with self.assertRaises(ValueError):
            verify_rotation_chain(RotationChain(3, (bad_cert,)))


if __name__ == "__main__":
    unittest.main()
