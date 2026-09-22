"""Tests for the incremental audit-extension checkpoint chain:
AuditExtensionDeltaCheckpointChain /
expand_audit_extension_delta_checkpoint_chain /
compact_audit_extension_delta_checkpoint_chain."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    AuditExtensionCheckpointChain,
    AuditExtensionDeltaCheckpointChain,
    AuditExtensionProof,
    compact_audit_extension_delta_checkpoint_chain,
    expand_audit_extension_delta_checkpoint_chain,
    verify_audit_extension_checkpoint_chain,
)

from test_audit_chain import make_key, make_record
from test_audit_extension_checkpoint_chain_codec import linked_chain, make_hop
from test_audit_extension_proof_bundle_codec import (
    make_other_key,
    make_records,
)


def make_delta(key, records, splits, *, seed=20000):
    """Build the delta form of ``linked_chain(key, records, splits)``."""
    chain = linked_chain(key, records, splits, seed=seed)
    return chain, compact_audit_extension_delta_checkpoint_chain(chain)


class DeltaChainDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [
                field.name
                for field in dataclasses.fields(
                    AuditExtensionDeltaCheckpointChain
                )
            ],
            ["first", "additions", "signatures"],
        )
        proof = AuditExtensionProof(1, (b"a" * 32, b"b" * 32))
        sig0 = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        sig1 = AggregateSignature(R=6, z=8, signer_ids=(1, 3))
        sig2 = AggregateSignature(R=9, z=11, signer_ids=(2, 4))
        chain = AuditExtensionDeltaCheckpointChain(
            proof, ((b"c" * 32,),), (sig0, sig1, sig2)
        )
        self.assertEqual(chain.first, proof)
        self.assertEqual(chain.additions, ((b"c" * 32,),))
        self.assertEqual(chain.signatures, (sig0, sig1, sig2))
        self.assertEqual(
            AuditExtensionDeltaCheckpointChain(
                first=proof,
                additions=((b"c" * 32,),),
                signatures=(sig0, sig1, sig2),
            ),
            chain,
        )

    def test_frozen_value_equality_and_hash(self):
        proof = AuditExtensionProof(1, (b"a" * 32, b"b" * 32))
        sig0 = AggregateSignature(R=5, z=7, signer_ids=(1,))
        sig1 = AggregateSignature(R=6, z=8, signer_ids=(1,))
        first = AuditExtensionDeltaCheckpointChain(proof, (), (sig0, sig1))
        same = AuditExtensionDeltaCheckpointChain(proof, (), (sig0, sig1))
        self.assertEqual(first, same)
        self.assertEqual(hash(first), hash(same))
        self.assertNotEqual(
            first,
            AuditExtensionDeltaCheckpointChain(
                proof, ((b"c" * 32,),), (sig0, sig1, sig0)
            ),
        )
        with self.assertRaises(FrozenInstanceError):
            first.first = proof

    def test_construction_does_not_validate(self):
        # A plain frozen value: the conversions do the checking.
        proof = AuditExtensionProof(1, (b"a" * 32, b"b" * 32))
        sig = AggregateSignature(R=5, z=7, signer_ids=(1,))
        AuditExtensionDeltaCheckpointChain(proof, (), (sig, sig))
        AuditExtensionDeltaCheckpointChain("not-a-proof", (), ())
        AuditExtensionDeltaCheckpointChain(proof, ((),), (sig, sig, sig))
        AuditExtensionDeltaCheckpointChain(None, None, None)


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = make_records(self.key, 8)

    def test_compact_expand_round_trip_at_every_length(self):
        seed = 21000
        for m in range(2, 9):
            splits = tuple((i, i + 1) for i in range(1, m))
            chain = linked_chain(self.key, self.records[:m], splits, seed=seed)
            seed += 100
            delta = compact_audit_extension_delta_checkpoint_chain(chain)
            self.assertEqual(delta.first, chain.proofs[0])
            self.assertEqual(len(delta.additions), len(chain.proofs) - 1)
            self.assertEqual(delta.signatures, chain.signatures)
            for hop, batch in zip(chain.proofs[1:], delta.additions):
                self.assertEqual(batch, hop.leaves[hop.old_n:])
            self.assertEqual(
                expand_audit_extension_delta_checkpoint_chain(delta), chain
            )

    def test_expand_compact_round_trip(self):
        chain = linked_chain(
            self.key, self.records, ((1, 3), (3, 5), (5, 8)), seed=22000
        )
        delta = compact_audit_extension_delta_checkpoint_chain(chain)
        self.assertEqual(
            compact_audit_extension_delta_checkpoint_chain(
                expand_audit_extension_delta_checkpoint_chain(delta)
            ),
            delta,
        )

    def test_single_hop_chain_has_no_additions(self):
        proof, old_sig, new_sig = make_hop(
            self.key, self.records[:4], 2, seed=23000
        )
        chain = AuditExtensionCheckpointChain((proof,), (old_sig, new_sig))
        delta = compact_audit_extension_delta_checkpoint_chain(chain)
        self.assertEqual(delta.first, proof)
        self.assertEqual(delta.additions, ())
        self.assertEqual(delta.signatures, (old_sig, new_sig))
        self.assertEqual(
            expand_audit_extension_delta_checkpoint_chain(delta), chain
        )

    def test_expanded_chain_verifies_under_existing_verifier(self):
        chain, delta = make_delta(
            self.key, self.records, ((2, 4), (4, 6), (6, 8)), seed=24000
        )
        expanded = expand_audit_extension_delta_checkpoint_chain(delta)
        self.assertTrue(
            verify_audit_extension_checkpoint_chain(expanded, self.key)
        )
        self.assertTrue(
            verify_audit_extension_checkpoint_chain(chain, self.key)
        )

    def test_tampered_addition_fails_existing_verifier(self):
        chain = linked_chain(
            self.key, self.records, ((2, 4), (4, 6)), seed=25000
        )
        delta = compact_audit_extension_delta_checkpoint_chain(chain)
        tampered = AuditExtensionDeltaCheckpointChain(
            delta.first,
            ((b"x" * 32,),) + delta.additions[1:],
            delta.signatures,
        )
        expanded = expand_audit_extension_delta_checkpoint_chain(tampered)
        self.assertFalse(
            verify_audit_extension_checkpoint_chain(expanded, self.key)
        )


class ExpandValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = make_records(self.key, 6)
        chain = linked_chain(
            self.key, self.records, ((1, 3), (3, 5)), seed=26000
        )
        self.delta = compact_audit_extension_delta_checkpoint_chain(chain)
        self.proof = chain.proofs[0]
        self.sig = chain.signatures[0]

    def test_non_chain_type_error(self):
        for bad in (
            (self.proof, (), (self.sig, self.sig)),
            [self.proof],
            None,
            "chain",
            AuditExtensionCheckpointChain(
                (self.proof,), (self.sig, self.sig)
            ),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                expand_audit_extension_delta_checkpoint_chain(bad)

    def test_non_proof_first_type_error(self):
        for bad in ("x", None, self.sig):
            with self.assertRaises(TypeError, msg=repr(bad)):
                expand_audit_extension_delta_checkpoint_chain(
                    AuditExtensionDeltaCheckpointChain(
                        bad, (), (self.sig, self.sig)
                    )
                )

    def test_non_tuple_fields_type_error(self):
        with self.assertRaises(TypeError):
            expand_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    self.proof, [self.delta.additions[0]], self.delta.signatures
                )
            )
        with self.assertRaises(TypeError):
            expand_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    self.proof,
                    self.delta.additions,
                    list(self.delta.signatures),
                )
            )
        with self.assertRaises(TypeError):
            expand_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    self.proof,
                    ([b"a" * 32],),
                    (self.sig, self.sig, self.sig),
                )
            )

    def test_non_bytes_digest_type_error(self):
        with self.assertRaises(TypeError):
            expand_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    self.proof, ((1, 2),), (self.sig,) * 3
                )
            )

    def test_non_signature_element_type_error(self):
        with self.assertRaises(TypeError):
            expand_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    self.proof, (), (self.sig, "x")
                )
            )

    def test_signature_count_mismatch_value_error(self):
        # No additions: exactly two signatures.
        with self.assertRaises(ValueError):
            expand_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    self.proof, (), (self.sig,)
                )
            )
        with self.assertRaises(ValueError):
            expand_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    self.proof, (), (self.sig,) * 3
                )
            )
        # One batch: exactly three signatures.
        with self.assertRaises(ValueError):
            expand_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    self.proof, ((b"a" * 32,),), (self.sig,) * 2
                )
            )
        with self.assertRaises(ValueError):
            expand_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    self.proof, ((b"a" * 32,),), (self.sig,) * 4
                )
            )

    def test_empty_batch_value_error(self):
        with self.assertRaises(ValueError):
            expand_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    self.proof, ((),), (self.sig,) * 3
                )
            )

    def test_bad_digest_width_value_error(self):
        for digest in (b"", b"a" * 31, b"a" * 33):
            with self.assertRaises(ValueError, msg=repr(digest)):
                expand_audit_extension_delta_checkpoint_chain(
                    AuditExtensionDeltaCheckpointChain(
                        self.proof, ((digest,),), (self.sig,) * 3
                    )
                )

    def test_illegal_nested_proof_value_error(self):
        bad_proof = AuditExtensionProof(0, (b"a" * 32, b"b" * 32))
        with self.assertRaises(ValueError):
            expand_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    bad_proof, (), (self.sig, self.sig)
                )
            )

    def test_illegal_nested_signature_value_error(self):
        bad_sig = AggregateSignature(R=0, z=7, signer_ids=(1, 3))
        with self.assertRaises(ValueError):
            expand_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    self.proof, (), (bad_sig, self.sig)
                )
            )


class CompactValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = make_records(self.key, 8)
        self.chain = linked_chain(
            self.key, self.records, ((2, 4), (4, 6)), seed=27000
        )
        self.proof = self.chain.proofs[0]
        self.sig = self.chain.signatures[0]

    def test_non_chain_type_error(self):
        for bad in (
            ((self.proof,), (self.sig, self.sig)),
            None,
            "chain",
            AuditExtensionDeltaCheckpointChain(
                self.proof, (), (self.sig, self.sig)
            ),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                compact_audit_extension_delta_checkpoint_chain(bad)

    def test_empty_chain_value_error(self):
        with self.assertRaises(ValueError):
            compact_audit_extension_delta_checkpoint_chain(
                AuditExtensionCheckpointChain((), ())
            )

    def test_non_tuple_fields_type_error(self):
        with self.assertRaises(TypeError):
            compact_audit_extension_delta_checkpoint_chain(
                AuditExtensionCheckpointChain(
                    [self.proof], (self.sig, self.sig)
                )
            )

    def test_signature_count_mismatch_value_error(self):
        with self.assertRaises(ValueError):
            compact_audit_extension_delta_checkpoint_chain(
                AuditExtensionCheckpointChain((self.proof,), (self.sig,))
            )

    def test_illegal_nested_proof_value_error(self):
        bad_proof = AuditExtensionProof(0, (b"a" * 32, b"b" * 32))
        with self.assertRaises(ValueError):
            compact_audit_extension_delta_checkpoint_chain(
                AuditExtensionCheckpointChain(
                    (bad_proof,), (self.sig, self.sig)
                )
            )

    def test_illegal_nested_signature_value_error(self):
        bad_sig = AggregateSignature(R=0, z=7, signer_ids=(1, 3))
        with self.assertRaises(ValueError):
            compact_audit_extension_delta_checkpoint_chain(
                AuditExtensionCheckpointChain(
                    (self.proof,), (bad_sig, self.sig)
                )
            )

    def test_prefix_break_value_error(self):
        # 2 -> 4 then 5 -> 8: the counts do not line up.
        first, old0, new0 = make_hop(
            self.key, self.records[:4], 2, seed=28000
        )
        second, _old1, new1 = make_hop(
            self.key, self.records[:8], 5, seed=28010
        )
        chain = AuditExtensionCheckpointChain(
            (first, second), (old0, new0, new1)
        )
        with self.assertRaises(ValueError):
            compact_audit_extension_delta_checkpoint_chain(chain)

    def test_same_count_different_leaves_value_error(self):
        first, old0, new0 = make_hop(
            self.key, self.records[:4], 2, seed=28100
        )
        other = tuple(
            make_record(self.key, b"other-%d" % i, seed=900 + i)
            for i in range(6)
        )
        second, _old1, new1 = make_hop(self.key, other, 4, seed=28110)
        self.assertEqual(len(first.leaves), second.old_n)
        self.assertNotEqual(first.leaves, second.leaves[:4])
        chain = AuditExtensionCheckpointChain(
            (first, second), (old0, new0, new1)
        )
        with self.assertRaises(ValueError):
            compact_audit_extension_delta_checkpoint_chain(chain)

    def test_compact_does_not_verify_signatures(self):
        # A linked chain signed under another key still compacts; the
        # expanded chain is the existing verifier's problem.
        other = make_other_key()
        chain = linked_chain(
            other, self.records, ((2, 4), (4, 6)), seed=29000
        )
        delta = compact_audit_extension_delta_checkpoint_chain(chain)
        self.assertEqual(
            expand_audit_extension_delta_checkpoint_chain(delta), chain
        )
        self.assertFalse(
            verify_audit_extension_checkpoint_chain(chain, self.key)
        )


if __name__ == "__main__":
    unittest.main()
