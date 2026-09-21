"""Tests for append-only consistency proofs over the audit Merkle tree:
AuditExtensionProof / make_extension / check_extension."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    AuditExtensionProof,
    check_extension,
    make_extension,
)

from test_audit_chain import (
    FIELD_PRIME,
    GROUP_PRIME,
    make_key,
    make_record,
    sign_message,
)

LEAF_TAG = b"am/l"
NODE_TAG = b"am/n"
ROOT_TAG = b"am/r"


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big", signed=False)


def digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def independent_leaves(records):
    return tuple(
        digest(LEAF_TAG + u64(i) + digest(m) + digest(a.payload))
        for i, (m, a) in enumerate(records)
    )


def independent_root(leaves):
    """Root of the AuditProof tree built straight from leaf digests."""
    current = leaves
    while len(current) > 1:
        seq = list(current)
        if len(seq) % 2 == 1:
            seq.append(seq[-1])
        current = tuple(
            digest(NODE_TAG + seq[j] + seq[j + 1]) for j in range(0, len(seq), 2)
        )
    return current[0]


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
            AuditExtensionProof(2, leaves),
            AuditExtensionProof(1, (b"a" * 32,)),
            AuditExtensionProof(1, (b"b" * 32, b"a" * 32)),
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

    def test_statement_layout_for_every_split(self):
        leaves = independent_leaves(self.records)
        for old_n in range(1, len(self.records)):
            old_message, new_message, proof = make_extension(self.records, old_n)
            self.assertEqual(
                old_message, ROOT_TAG + u64(old_n) + independent_root(leaves[:old_n])
            )
            self.assertEqual(
                new_message,
                ROOT_TAG + u64(len(self.records)) + independent_root(leaves),
            )
            self.assertEqual(len(old_message), 4 + 8 + 32)
            self.assertEqual(len(new_message), 4 + 8 + 32)
            self.assertEqual(proof.old_n, old_n)
            self.assertEqual(proof.leaves, leaves)

    def test_old_root_matches_make_proof_statement(self):
        # The old statement is exactly the record-root statement make_proof
        # would build for the shortened sequence.
        from thresholdsign import make_proof

        old_message, _new_message, _proof = make_extension(self.records, 3)
        self.assertEqual(old_message, make_proof(self.records[:3], 0)[0])

    def test_deterministic(self):
        first = make_extension(self.records, 2)
        second = make_extension(self.records, 2)
        self.assertEqual(first, second)

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
            make_extension(((b"m", b"not-an-audit"),) * 2, 1)
        with self.assertRaises(TypeError):
            make_extension(
                ((bytearray(b"m"), self.records[0][1]),) * 2, 1
            )

    def test_empty_records_and_bad_old_n_raise_value_error(self):
        with self.assertRaises(ValueError):
            make_extension((), 0)
        for bad in (-1, 0, 6, 7, 100):
            with self.assertRaises(ValueError, msg=f"old_n={bad}"):
                make_extension(self.records, bad)

    def test_record_count_overflow_raises_value_error(self):
        class HugeTuple(tuple):
            def __len__(self):
                return 2 ** 64

        records = HugeTuple((self.records[0],))
        with self.assertRaises(ValueError):
            make_extension(records, 0)


class CheckExtensionTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = tuple(
            make_record(self.key, f"message-{i}".encode(), seed=100 + 10 * i)
            for i in range(6)
        )

    def test_honest_proofs_verify_for_every_split_and_size(self):
        seed = 700
        for n in range(2, 9):
            records = self._records_of_size(n)
            for old_n in range(1, n):
                proof, old_sig, new_sig = seal_extension(
                    self.key, records, old_n, seed=seed
                )
                seed += 10
                self.assertTrue(
                    check_extension(proof, old_sig, new_sig, self.key),
                    msg=f"n={n} old_n={old_n}",
                )

    def _records_of_size(self, n):
        base = list(self.records)
        if n > len(base):
            base.extend(
                make_record(self.key, f"extra-{j}".encode(), seed=400 + j)
                for j in range(n - len(base))
            )
        return tuple(base[:n])

    def test_swapped_signatures_return_false(self):
        proof, old_sig, new_sig = seal_extension(self.key, self.records, 3)
        self.assertFalse(check_extension(proof, new_sig, old_sig, self.key))

    def test_tampered_leaf_returns_false(self):
        proof, old_sig, new_sig = seal_extension(self.key, self.records, 3)
        flipped = bytearray(proof.leaves[1])
        flipped[0] ^= 1
        bad = dataclasses.replace(
            proof, leaves=proof.leaves[:1] + (bytes(flipped),) + proof.leaves[2:]
        )
        self.assertFalse(check_extension(bad, old_sig, new_sig, self.key))

    def test_leaf_order_matters(self):
        proof, old_sig, new_sig = seal_extension(self.key, self.records, 3)
        reordered = (proof.leaves[1], proof.leaves[0]) + proof.leaves[2:]
        bad = dataclasses.replace(proof, leaves=reordered)
        self.assertFalse(check_extension(bad, old_sig, new_sig, self.key))

    def test_changed_old_n_returns_false(self):
        proof, old_sig, new_sig = seal_extension(self.key, self.records, 3)
        bad = dataclasses.replace(proof, old_n=2)
        self.assertFalse(check_extension(bad, old_sig, new_sig, self.key))

    def test_truncated_leaves_return_false(self):
        # Dropping a tail leaf keeps the structure legal but changes the
        # new root.
        proof, old_sig, new_sig = seal_extension(self.key, self.records, 3)
        bad = dataclasses.replace(proof, leaves=proof.leaves[:-1])
        self.assertFalse(check_extension(bad, old_sig, new_sig, self.key))

    def test_bad_signature_returns_false(self):
        proof, old_sig, new_sig = seal_extension(self.key, self.records, 3)
        bad_new = AggregateSignature(
            R=new_sig.R,
            z=(new_sig.z + 1) % FIELD_PRIME,
            signer_ids=new_sig.signer_ids,
        )
        self.assertFalse(check_extension(proof, old_sig, bad_new, self.key))
        bad_old = AggregateSignature(
            R=old_sig.R,
            z=(old_sig.z + 1) % FIELD_PRIME,
            signer_ids=old_sig.signer_ids,
        )
        self.assertFalse(check_extension(proof, bad_old, new_sig, self.key))

    def test_signature_from_another_statement_returns_false(self):
        # The new statement binds (n, root), so a signature over a different
        # record set's statement must not carry over.
        proof, old_sig, _new_sig = seal_extension(self.key, self.records, 3)
        other_message = make_extension(self.records[:5], 2)[1]
        other_sig = sign_message(self.key, other_message, seed=901)
        self.assertFalse(check_extension(proof, old_sig, other_sig, self.key))

    def test_wrong_key_returns_false(self):
        proof, old_sig, new_sig = seal_extension(self.key, self.records, 3)
        other_key = make_key(seed_offset=10)
        self.assertNotEqual(other_key.public_key, self.key.public_key)
        self.assertFalse(check_extension(proof, old_sig, new_sig, other_key))

    def test_entry_type_errors(self):
        proof, old_sig, new_sig = seal_extension(self.key, self.records, 3)
        with self.assertRaises(TypeError):
            check_extension("proof", old_sig, new_sig, self.key)
        with self.assertRaises(TypeError):
            check_extension(proof, "old_sig", new_sig, self.key)
        with self.assertRaises(TypeError):
            check_extension(proof, old_sig, "new_sig", self.key)
        with self.assertRaises(TypeError):
            check_extension(proof, old_sig, new_sig, "key")
        for bad in (
            dataclasses.replace(proof, old_n=True),
            dataclasses.replace(proof, old_n="3"),
            dataclasses.replace(proof, leaves=list(proof.leaves)),
            dataclasses.replace(proof, leaves=(b"a" * 32, 33)),
            dataclasses.replace(proof, leaves=(bytearray(b"a" * 32),) * 6),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                check_extension(bad, old_sig, new_sig, self.key)

    def test_structure_and_boundary_value_errors(self):
        proof, old_sig, new_sig = seal_extension(self.key, self.records, 3)
        for bad in (
            dataclasses.replace(proof, old_n=0),
            dataclasses.replace(proof, old_n=-1),
            dataclasses.replace(proof, old_n=6),
            dataclasses.replace(proof, old_n=7),
            dataclasses.replace(proof, leaves=()),
            dataclasses.replace(proof, leaves=(b"a" * 31,) * 6),
            dataclasses.replace(proof, leaves=(b"a" * 33,) * 6),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                check_extension(bad, old_sig, new_sig, self.key)

    def test_structurally_illegal_signature_raises_value_error(self):
        proof, old_sig, new_sig = seal_extension(self.key, self.records, 3)
        bad_sig = AggregateSignature(R=GROUP_PRIME, z=0, signer_ids=(1, 3))
        with self.assertRaises(ValueError):
            check_extension(proof, bad_sig, new_sig, self.key)
        with self.assertRaises(ValueError):
            check_extension(proof, old_sig, bad_sig, self.key)


if __name__ == "__main__":
    unittest.main()
