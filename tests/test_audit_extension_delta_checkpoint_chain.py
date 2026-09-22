"""Tests for the incremental AuditExtensionDeltaCheckpointChain and the
expand_audit_extension_delta_checkpoint_chain /
compact_audit_extension_delta_checkpoint_chain conversions."""

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
    make_extension,
    verify_audit_extension_checkpoint_chain,
)

from test_audit_chain import make_key, sign_message
from test_audit_extension_checkpoint_chain_codec import linked_chain
from test_audit_extension_proof_bundle_codec import make_other_key, make_records


def make_delta(key, records, splits, *, seed=9000):
    """Build a delta chain equivalent to linked_chain(key, records, splits)."""
    chain = linked_chain(key, records, splits, seed=seed)
    return compact_audit_extension_delta_checkpoint_chain(chain)


class DeltaChainDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [
                field.name
                for field in dataclasses.fields(AuditExtensionDeltaCheckpointChain)
            ],
            ["first", "additions", "signatures"],
        )
        first = AuditExtensionProof(1, (b"a" * 32, b"b" * 32))
        additions = ((b"c" * 32,), (b"d" * 32, b"e" * 32))
        signatures = tuple(
            AggregateSignature(R=5 + 2 * i, z=7 + 2 * i, signer_ids=(1, 3))
            for i in range(4)
        )
        chain = AuditExtensionDeltaCheckpointChain(first, additions, signatures)
        self.assertEqual(chain.first, first)
        self.assertEqual(chain.additions, additions)
        self.assertEqual(chain.signatures, signatures)
        self.assertEqual(
            AuditExtensionDeltaCheckpointChain(
                first=first, additions=additions, signatures=signatures
            ),
            chain,
        )

    def test_frozen_value_equality_and_hash(self):
        first = AuditExtensionProof(1, (b"a" * 32, b"b" * 32))
        signatures = (
            AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=9, z=11, signer_ids=(1, 3)),
        )
        left = AuditExtensionDeltaCheckpointChain(first, (), signatures)
        right = AuditExtensionDeltaCheckpointChain(first, (), signatures)
        self.assertEqual(left, right)
        self.assertEqual(hash(left), hash(right))
        with self.assertRaises(FrozenInstanceError):
            left.first = first
        other = AuditExtensionDeltaCheckpointChain(
            first, ((b"c" * 32,),), signatures + (signatures[0],)
        )
        self.assertNotEqual(left, other)


class ExpandTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = make_records(self.key, 6)

    def test_expand_round_trip_matches_plain_chain(self):
        splits = [(2, 4), (4, 5), (5, 6)]
        plain = linked_chain(self.key, self.records, splits)
        delta = make_delta(self.key, self.records, splits)
        self.assertEqual(delta.first, plain.proofs[0])
        self.assertEqual(
            delta.additions,
            tuple(
                proof.leaves[proof.old_n:] for proof in plain.proofs[1:]
            ),
        )
        self.assertEqual(delta.signatures, plain.signatures)
        expanded = expand_audit_extension_delta_checkpoint_chain(delta)
        self.assertEqual(expanded, plain)
        self.assertTrue(
            verify_audit_extension_checkpoint_chain(expanded, self.key)
        )

    def test_expand_empty_additions_single_hop(self):
        plain = linked_chain(self.key, self.records, [(2, 4)])
        delta = make_delta(self.key, self.records, [(2, 4)])
        self.assertEqual(delta.additions, ())
        self.assertEqual(len(delta.signatures), 2)
        expanded = expand_audit_extension_delta_checkpoint_chain(delta)
        self.assertEqual(expanded, plain)
        self.assertTrue(
            verify_audit_extension_checkpoint_chain(expanded, self.key)
        )

    def test_expand_cumulative_old_n(self):
        delta = make_delta(self.key, self.records, [(2, 3), (3, 5), (5, 6)])
        expanded = expand_audit_extension_delta_checkpoint_chain(delta)
        self.assertEqual([p.old_n for p in expanded.proofs], [2, 3, 5])
        self.assertEqual(
            [len(p.leaves) for p in expanded.proofs], [3, 5, 6]
        )
        for previous, proof in zip(expanded.proofs, expanded.proofs[1:]):
            self.assertEqual(proof.leaves[: proof.old_n], previous.leaves)

    def test_expand_does_not_verify_signatures(self):
        # Structurally legal but root-mismatched signatures expand fine;
        # verification is left to verify_audit_extension_checkpoint_chain.
        delta = make_delta(self.key, self.records, [(2, 4), (4, 6)])
        other = make_other_key()
        bad = sign_message(other, b"unrelated", seed=5)
        tampered = AuditExtensionDeltaCheckpointChain(
            delta.first, delta.additions, (bad,) + delta.signatures[1:]
        )
        expanded = expand_audit_extension_delta_checkpoint_chain(tampered)
        self.assertFalse(
            verify_audit_extension_checkpoint_chain(expanded, self.key)
        )

    def test_expand_type_errors(self):
        delta = make_delta(self.key, self.records, [(2, 4), (4, 6)])
        good_first = delta.first
        good_additions = delta.additions
        good_signatures = delta.signatures
        bad_cases = [
            AuditExtensionDeltaCheckpointChain(
                "not a proof", good_additions, good_signatures
            ),
            AuditExtensionDeltaCheckpointChain(
                good_first, list(good_additions), good_signatures
            ),
            AuditExtensionDeltaCheckpointChain(
                good_first, (list(good_additions[0]),), good_signatures
            ),
            AuditExtensionDeltaCheckpointChain(
                good_first, ((1, 2),), good_signatures
            ),
            AuditExtensionDeltaCheckpointChain(
                good_first, good_additions, list(good_signatures)
            ),
            AuditExtensionDeltaCheckpointChain(
                good_first, good_additions, good_signatures[:-1] + ("x",)
            ),
        ]
        for chain in bad_cases:
            with self.assertRaises(TypeError, msg=repr(chain)):
                expand_audit_extension_delta_checkpoint_chain(chain)
        with self.assertRaises(TypeError):
            expand_audit_extension_delta_checkpoint_chain("not a chain")
        with self.assertRaises(TypeError):
            expand_audit_extension_delta_checkpoint_chain(None)

    def test_expand_nested_field_type_errors(self):
        delta = make_delta(self.key, self.records, [(2, 4)])
        # old_n of the wrong type inside the nested first proof.
        bad_first = AuditExtensionProof("1", delta.first.leaves)
        chain = AuditExtensionDeltaCheckpointChain(
            bad_first, (), delta.signatures[:2]
        )
        with self.assertRaises(TypeError):
            expand_audit_extension_delta_checkpoint_chain(chain)
        # Non-integer R inside a nested signature.
        bad_sig = AggregateSignature(R="r", z=1, signer_ids=(1, 3))
        chain = AuditExtensionDeltaCheckpointChain(
            delta.first, (), (bad_sig, delta.signatures[1])
        )
        with self.assertRaises(TypeError):
            expand_audit_extension_delta_checkpoint_chain(chain)

    def test_expand_value_errors(self):
        delta = make_delta(self.key, self.records, [(2, 4), (4, 6)])
        first = delta.first
        additions = delta.additions
        signatures = delta.signatures
        # Empty batch.
        with self.assertRaises(ValueError):
            expand_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(first, ((),), signatures)
            )
        # Digest of the wrong width.
        with self.assertRaises(ValueError):
            expand_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    first, ((b"x" * 31,),), signatures
                )
            )
        # Signature count mismatch (both directions).
        with self.assertRaises(ValueError):
            expand_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    first, additions, signatures[:-1]
                )
            )
        with self.assertRaises(ValueError):
            expand_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    first, additions, signatures + (signatures[0],)
                )
            )
        # Illegal nested proof: old_n out of range.
        with self.assertRaises(ValueError):
            expand_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    AuditExtensionProof(0, first.leaves), (), signatures[:2]
                )
            )
        # Illegal nested proof: empty leaves.
        with self.assertRaises(ValueError):
            expand_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    AuditExtensionProof(1, ()), (), signatures[:2]
                )
            )
        # Illegal nested signature: non-positive R.
        bad_sig = AggregateSignature(R=0, z=1, signer_ids=(1, 3))
        with self.assertRaises(ValueError):
            expand_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    first, (), (bad_sig, signatures[1])
                )
            )
        # Illegal nested signature: unordered signer ids.
        bad_sig = AggregateSignature(R=5, z=1, signer_ids=(3, 1))
        with self.assertRaises(ValueError):
            expand_audit_extension_delta_checkpoint_chain(
                AuditExtensionDeltaCheckpointChain(
                    first, (), (bad_sig, signatures[1])
                )
            )


class CompactTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = make_records(self.key, 6)

    def test_compact_round_trip(self):
        splits = [(2, 4), (4, 5), (5, 6)]
        plain = linked_chain(self.key, self.records, splits)
        delta = compact_audit_extension_delta_checkpoint_chain(plain)
        self.assertEqual(delta.first, plain.proofs[0])
        self.assertEqual(
            delta.additions,
            tuple(proof.leaves[proof.old_n:] for proof in plain.proofs[1:]),
        )
        self.assertEqual(delta.signatures, plain.signatures)
        self.assertEqual(
            expand_audit_extension_delta_checkpoint_chain(delta), plain
        )

    def test_compact_single_hop_chain(self):
        plain = linked_chain(self.key, self.records, [(3, 6)])
        delta = compact_audit_extension_delta_checkpoint_chain(plain)
        self.assertEqual(delta.additions, ())
        self.assertEqual(delta.signatures, plain.signatures)
        self.assertEqual(
            expand_audit_extension_delta_checkpoint_chain(delta), plain
        )

    def test_compact_does_not_verify_signatures(self):
        # A structurally legal chain whose signatures do not match the roots
        # still compacts; verification stays with the expanded form.
        plain = linked_chain(self.key, self.records, [(2, 4), (4, 6)])
        other = make_other_key()
        bad = sign_message(other, b"unrelated", seed=7)
        tampered = AuditExtensionCheckpointChain(
            plain.proofs, (bad,) + plain.signatures[1:]
        )
        delta = compact_audit_extension_delta_checkpoint_chain(tampered)
        self.assertEqual(delta.signatures, tampered.signatures)
        self.assertFalse(
            verify_audit_extension_checkpoint_chain(
                expand_audit_extension_delta_checkpoint_chain(delta), self.key
            )
        )

    def test_compact_type_errors(self):
        plain = linked_chain(self.key, self.records, [(2, 4), (4, 6)])
        with self.assertRaises(TypeError):
            compact_audit_extension_delta_checkpoint_chain("not a chain")
        with self.assertRaises(TypeError):
            compact_audit_extension_delta_checkpoint_chain(None)
        with self.assertRaises(TypeError):
            compact_audit_extension_delta_checkpoint_chain(
                AuditExtensionCheckpointChain(
                    list(plain.proofs), plain.signatures
                )
            )
        with self.assertRaises(TypeError):
            compact_audit_extension_delta_checkpoint_chain(
                AuditExtensionCheckpointChain(
                    plain.proofs, list(plain.signatures)
                )
            )
        with self.assertRaises(TypeError):
            compact_audit_extension_delta_checkpoint_chain(
                AuditExtensionCheckpointChain(
                    ("x",) + plain.proofs[1:], plain.signatures
                )
            )
        with self.assertRaises(TypeError):
            compact_audit_extension_delta_checkpoint_chain(
                AuditExtensionCheckpointChain(
                    plain.proofs, plain.signatures[:-1] + ("x",)
                )
            )

    def test_compact_value_errors(self):
        plain = linked_chain(self.key, self.records, [(2, 4), (4, 6)])
        proofs = plain.proofs
        signatures = plain.signatures
        # Empty chain.
        with self.assertRaises(ValueError):
            compact_audit_extension_delta_checkpoint_chain(
                AuditExtensionCheckpointChain((), signatures[:1])
            )
        # Signature count mismatch.
        with self.assertRaises(ValueError):
            compact_audit_extension_delta_checkpoint_chain(
                AuditExtensionCheckpointChain(proofs, signatures[:-1])
            )
        # Illegal nested proof: leaf of the wrong width.
        bad_proof = AuditExtensionProof(
            proofs[1].old_n, proofs[1].leaves[:-1] + (b"x" * 31,)
        )
        with self.assertRaises(ValueError):
            compact_audit_extension_delta_checkpoint_chain(
                AuditExtensionCheckpointChain(
                    (proofs[0], bad_proof), signatures
                )
            )
        # Illegal nested signature: negative z.
        bad_sig = AggregateSignature(R=5, z=-1, signer_ids=(1, 3))
        with self.assertRaises(ValueError):
            compact_audit_extension_delta_checkpoint_chain(
                AuditExtensionCheckpointChain(
                    proofs, (bad_sig,) + signatures[1:]
                )
            )

    def test_compact_broken_prefix(self):
        # Gap: the second hop's old_n does not match the first hop's count.
        proof0, _, _ = self._hop(self.records[:4], 2)
        proof1, _, _ = self._hop(self.records[:6], 3)
        signatures = self._dummy_signatures(3)
        with self.assertRaises(ValueError):
            compact_audit_extension_delta_checkpoint_chain(
                AuditExtensionCheckpointChain((proof0, proof1), signatures)
            )
        # Overlap: old_n matches but the shared leaves differ.
        tampered = AuditExtensionProof(
            4, (b"z" * 32,) * 4 + proof1.leaves[4:]
        )
        with self.assertRaises(ValueError):
            compact_audit_extension_delta_checkpoint_chain(
                AuditExtensionCheckpointChain(
                    (proof0, tampered), signatures
                )
            )

    def _hop(self, records, old_n):
        _old_message, _new_message, proof = make_extension(records, old_n)
        return proof, _old_message, _new_message

    @staticmethod
    def _dummy_signatures(count):
        return tuple(
            AggregateSignature(R=5 + i, z=7 + i, signer_ids=(1, 3))
            for i in range(count)
        )


if __name__ == "__main__":
    unittest.main()
