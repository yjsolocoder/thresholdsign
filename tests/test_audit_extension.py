"""Tests for append-only consistency proofs over audit-chain records:
AuditExtensionProof / make_extension / check_extension."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    AuditExtensionProof,
    check_extension,
    make_extension,
    verify_signature,
)

from test_audit_chain import (
    FIELD_PRIME,
    GROUP_PRIME,
    make_key,
    make_record,
    sign_message,
)
from test_audit_proof import ROOT_TAG, independent_tree, u64


def seal_extension(key, records, old_n, *, seed=700):
    """Return (proof, old_sig, new_sig) for a threshold-signed extension."""
    old_message, new_message, proof = make_extension(records, old_n)
    old_sig = sign_message(key, old_message, seed=seed)
    new_sig = sign_message(key, new_message, seed=seed + 1)
    return proof, old_sig, new_sig


class AuditExtensionProofDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(AuditExtensionProof)],
            ["old_n", "leaves"],
        )
        leaves = (b"a" * 32, b"b" * 32)
        proof = AuditExtensionProof(1, leaves)
        self.assertEqual((proof.old_n, proof.leaves), (1, leaves))

    def test_frozen_value_equality_and_hash(self):
        leaves = (b"a" * 32, b"b" * 32)
        proof = AuditExtensionProof(1, leaves)
        same = AuditExtensionProof(old_n=1, leaves=leaves)
        self.assertEqual(proof, same)
        self.assertEqual(hash(proof), hash(same))
        for changed in (
            AuditExtensionProof(2, leaves + (b"c" * 32,)),
            AuditExtensionProof(1, (b"a" * 32, b"c" * 32)),
            AuditExtensionProof(1, (b"a" * 32,)),
        ):
            self.assertNotEqual(proof, changed)
        with self.assertRaises(FrozenInstanceError):
            proof.old_n = 2


class MakeExtensionTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = tuple(
            make_record(self.key, f"message-{i}".encode(), seed=100 + 10 * i)
            for i in range(6)
        )

    def test_statement_layout_for_every_size_and_split(self):
        for n in range(2, 8):
            records = self._records_of_size(n)
            leaves = independent_tree(records)[0]
            for old_n in range(1, n):
                old_message, new_message, proof = make_extension(records, old_n)
                self.assertEqual(
                    old_message,
                    ROOT_TAG + u64(old_n) + independent_tree(records[:old_n])[-1][0],
                    msg=f"n={n} old_n={old_n}",
                )
                self.assertEqual(
                    new_message,
                    ROOT_TAG + u64(n) + independent_tree(records)[-1][0],
                    msg=f"n={n} old_n={old_n}",
                )
                self.assertEqual(len(old_message), 4 + 8 + 32)
                self.assertEqual(len(new_message), 4 + 8 + 32)
                self.assertEqual(proof.old_n, old_n)
                self.assertEqual(proof.leaves, leaves)
                self.assertTrue(all(len(leaf) == 32 for leaf in proof.leaves))

    def _records_of_size(self, n):
        base = list(self.records)
        if n > len(base):
            base.extend(
                make_record(self.key, f"extra-{j}".encode(), seed=400 + j)
                for j in range(n - len(base))
            )
        return tuple(base[:n])

    def test_old_root_of_single_leaf_prefix_is_the_leaf(self):
        old_message, _new_message, proof = make_extension(self.records, 1)
        self.assertEqual(old_message, ROOT_TAG + u64(1) + proof.leaves[0])

    def test_deterministic(self):
        self.assertEqual(
            make_extension(self.records, 3), make_extension(self.records, 3)
        )

    def test_proof_carries_no_messages_or_receipts(self):
        _old, _new, proof = make_extension(self.records, 3)
        for leaf, (message, audit) in zip(proof.leaves, self.records):
            self.assertNotIn(message, leaf)
            self.assertNotIn(audit.payload, leaf)

    def test_old_n_type_errors(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=f"old_n={bad!r}"):
                make_extension(self.records, bad)

    def test_records_type_errors(self):
        with self.assertRaises(TypeError):
            make_extension([self.records[0], self.records[1]], 1)
        with self.assertRaises(TypeError):
            make_extension((b"only-message",), 1)
        with self.assertRaises(TypeError):
            make_extension((self.records[0], (b"m", b"not-an-audit")), 1)
        with self.assertRaises(TypeError):
            make_extension(
                (self.records[0], (bytearray(b"m"), self.records[1][1])), 1
            )

    def test_old_n_out_of_range_raises_value_error(self):
        for bad in (0, -1, 6, 7, 100):
            with self.assertRaises(ValueError, msg=f"old_n={bad}"):
                make_extension(self.records, bad)

    def test_empty_records_raise_value_error(self):
        with self.assertRaises(ValueError):
            make_extension((), 1)

    def test_record_count_overflow_raises_value_error(self):
        class HugeTuple(tuple):
            def __len__(self):
                return 2 ** 64

        records = HugeTuple((self.records[0],))
        with self.assertRaises(ValueError):
            make_extension(records, 1)


class CheckExtensionTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = tuple(
            make_record(self.key, f"message-{i}".encode(), seed=100 + 10 * i)
            for i in range(6)
        )

    def test_honest_proofs_verify_for_every_size_and_split(self):
        for n in range(2, 8):
            records = self.records[:n] if n <= 6 else self.records + tuple(
                make_record(self.key, f"extra-{j}".encode(), seed=400 + j)
                for j in range(n - 6)
            )
            for old_n in range(1, n):
                proof, old_sig, new_sig = seal_extension(
                    self.key, records, old_n, seed=700 + 10 * n + old_n
                )
                self.assertTrue(
                    check_extension(proof, old_sig, new_sig, self.key),
                    msg=f"n={n} old_n={old_n}",
                )

    def test_statements_are_ordinary_schnorr_messages(self):
        old_message, new_message, proof = make_extension(self.records, 3)
        old_sig = sign_message(self.key, old_message, seed=900)
        new_sig = sign_message(self.key, new_message, seed=901)
        for message, signature in ((old_message, old_sig), (new_message, new_sig)):
            self.assertTrue(
                verify_signature(
                    message,
                    signature,
                    self.key.public_key,
                    prime=FIELD_PRIME,
                    group_prime=GROUP_PRIME,
                    generator=16,
                )
            )
        self.assertTrue(check_extension(proof, old_sig, new_sig, self.key))

    def test_tampered_leaf_returns_false(self):
        proof, old_sig, new_sig = seal_extension(self.key, self.records, 3)
        flipped = bytearray(proof.leaves[4])
        flipped[0] ^= 1
        bad = dataclasses.replace(
            proof, leaves=proof.leaves[:4] + (bytes(flipped),) + proof.leaves[5:]
        )
        self.assertFalse(check_extension(bad, old_sig, new_sig, self.key))

    def test_tampered_prefix_leaf_returns_false(self):
        proof, old_sig, new_sig = seal_extension(self.key, self.records, 3)
        flipped = bytearray(proof.leaves[0])
        flipped[0] ^= 1
        bad = dataclasses.replace(
            proof, leaves=(bytes(flipped),) + proof.leaves[1:]
        )
        self.assertFalse(check_extension(bad, old_sig, new_sig, self.key))

    def test_changed_old_n_returns_false(self):
        proof, old_sig, new_sig = seal_extension(self.key, self.records, 3)
        bad = dataclasses.replace(proof, old_n=2)
        self.assertFalse(check_extension(bad, old_sig, new_sig, self.key))

    def test_swapped_signatures_return_false(self):
        proof, old_sig, new_sig = seal_extension(self.key, self.records, 3)
        self.assertFalse(check_extension(proof, new_sig, old_sig, self.key))

    def test_bad_signature_returns_false(self):
        proof, old_sig, new_sig = seal_extension(self.key, self.records, 3)
        bad_old = AggregateSignature(
            R=old_sig.R, z=(old_sig.z + 1) % FIELD_PRIME, signer_ids=old_sig.signer_ids
        )
        self.assertFalse(check_extension(proof, bad_old, new_sig, self.key))
        bad_new = AggregateSignature(
            R=new_sig.R, z=(new_sig.z + 1) % FIELD_PRIME, signer_ids=new_sig.signer_ids
        )
        self.assertFalse(check_extension(proof, old_sig, bad_new, self.key))

    def test_signature_from_another_statement_returns_false(self):
        proof, old_sig, new_sig = seal_extension(self.key, self.records, 3)
        other_message, _other, _proof = make_extension(self.records[:4], 2)
        other_sig = sign_message(self.key, other_message, seed=902)
        self.assertFalse(check_extension(proof, other_sig, new_sig, self.key))
        self.assertFalse(check_extension(proof, old_sig, other_sig, self.key))

    def test_wrong_key_returns_false(self):
        proof, old_sig, new_sig = seal_extension(self.key, self.records, 3)
        other_key = make_key(seed_offset=10)
        self.assertNotEqual(other_key.public_key, self.key.public_key)
        self.assertFalse(check_extension(proof, old_sig, new_sig, other_key))

    def test_cross_key_extension_returns_false(self):
        # Sealed under a foreign key but presented with ours.
        other_key = make_key(seed_offset=10)
        records = tuple(
            make_record(other_key, f"foreign-{i}".encode(), seed=300 + i)
            for i in range(4)
        )
        proof, old_sig, new_sig = seal_extension(other_key, records, 2)
        self.assertFalse(check_extension(proof, old_sig, new_sig, self.key))
        self.assertTrue(check_extension(proof, old_sig, new_sig, other_key))

    def test_entry_type_errors(self):
        proof, old_sig, new_sig = seal_extension(self.key, self.records, 3)
        with self.assertRaises(TypeError):
            check_extension("proof", old_sig, new_sig, self.key)
        with self.assertRaises(TypeError):
            check_extension(proof, "signature", new_sig, self.key)
        with self.assertRaises(TypeError):
            check_extension(proof, old_sig, "signature", self.key)
        with self.assertRaises(TypeError):
            check_extension(proof, old_sig, new_sig, "key")
        for bad in (
            dataclasses.replace(proof, old_n=True),
            dataclasses.replace(proof, old_n="3"),
            dataclasses.replace(proof, leaves=list(proof.leaves)),
            dataclasses.replace(proof, leaves=(proof.leaves[0], 33)),
            dataclasses.replace(proof, leaves=(bytearray(proof.leaves[0]),) + proof.leaves[1:]),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                check_extension(bad, old_sig, new_sig, self.key)

    def test_structure_and_boundary_value_errors(self):
        proof, old_sig, new_sig = seal_extension(self.key, self.records, 3)
        thirty_two = b"s" * 32
        for bad in (
            dataclasses.replace(proof, leaves=()),
            dataclasses.replace(proof, leaves=(thirty_two,)),
            dataclasses.replace(proof, leaves=(b"s" * 31,) + proof.leaves[1:]),
            dataclasses.replace(proof, leaves=(b"s" * 33,) + proof.leaves[1:]),
            dataclasses.replace(proof, old_n=0),
            dataclasses.replace(proof, old_n=-1),
            dataclasses.replace(proof, old_n=6),
            dataclasses.replace(proof, old_n=7),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                check_extension(bad, old_sig, new_sig, self.key)

    def test_structurally_illegal_signature_raises_value_error(self):
        _old, _new, proof = make_extension(self.records, 3)
        _good, old_sig, new_sig = seal_extension(self.key, self.records, 3)
        bad_sig = AggregateSignature(R=GROUP_PRIME, z=0, signer_ids=(1, 3))
        with self.assertRaises(ValueError):
            check_extension(proof, bad_sig, new_sig, self.key)
        with self.assertRaises(ValueError):
            check_extension(proof, old_sig, bad_sig, self.key)


if __name__ == "__main__":
    unittest.main()
