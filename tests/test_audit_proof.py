"""Tests for Merkle inclusion proofs over audit-chain records:
AuditProof / make_proof / check_proof."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    AuditProof,
    SigningAudit,
    check_proof,
    make_proof,
    verify_signature,
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


def independent_tree(records):
    """Build leaf level, internal levels (odd tail duplicated) and root."""
    leaves = tuple(
        digest(LEAF_TAG + u64(i) + digest(m) + digest(a.payload))
        for i, (m, a) in enumerate(records)
    )
    levels = [leaves]
    current = leaves
    while len(current) > 1:
        seq = list(current)
        if len(seq) % 2 == 1:
            seq.append(seq[-1])
        current = tuple(
            digest(NODE_TAG + seq[j] + seq[j + 1]) for j in range(0, len(seq), 2)
        )
        levels.append(current)
    return levels


def independent_path(levels, index):
    """Sibling digests from the leaf level up to (but excluding) the root."""
    path = []
    position = index
    for level in levels[:-1]:
        seq = list(level)
        if len(seq) % 2 == 1:
            seq.append(seq[-1])
        path.append(seq[position ^ 1])
        position //= 2
    return tuple(path)


def seal_proof(key, records, index, *, seed=700):
    """Return (proof, signature) for a threshold-signed proof statement."""
    message, proof = make_proof(records, index)
    signature = sign_message(key, message, seed=seed + index)
    return proof, signature


class AuditProofDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(AuditProof)],
            ["i", "n", "m", "a", "p"],
        )
        audit = SigningAudit(b"a")
        path = (b"s" * 32,)
        proof = AuditProof(1, 3, b"m", audit, path)
        self.assertEqual((proof.i, proof.n, proof.m, proof.a, proof.p),
                         (1, 3, b"m", audit, path))

    def test_frozen_value_equality_and_hash(self):
        audit = SigningAudit(b"a")
        path = (b"s" * 32, b"t" * 32)
        proof = AuditProof(1, 3, b"m", audit, path)
        same = AuditProof(i=1, n=3, m=b"m", a=audit, p=path)
        self.assertEqual(proof, same)
        self.assertEqual(hash(proof), hash(same))
        for changed in (
            AuditProof(2, 3, b"m", audit, path),
            AuditProof(1, 4, b"m", audit, path),
            AuditProof(1, 3, b"x", audit, path),
            AuditProof(1, 3, b"m", SigningAudit(b"b"), path),
            AuditProof(1, 3, b"m", audit, (b"s" * 32,)),
        ):
            self.assertNotEqual(proof, changed)
        with self.assertRaises(FrozenInstanceError):
            proof.i = 2


class MakeProofTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = tuple(
            make_record(self.key, f"message-{i}".encode(), seed=100 + 10 * i)
            for i in range(5)
        )

    def test_statement_layout_for_every_size(self):
        for n in range(1, 9):
            records = self._records_of_size(n)
            root = independent_tree(records)[-1][0]
            message, proof = make_proof(records, 0)
            self.assertEqual(message, ROOT_TAG + u64(n) + root)
            self.assertEqual(len(message), 4 + 8 + 32)
            self.assertEqual(proof.n, n)
            self.assertEqual(len(proof.p), (n - 1).bit_length())
            self.assertTrue(all(len(sibling) == 32 for sibling in proof.p))

    def _records_of_size(self, n):
        base = list(self.records)
        if n > len(base):
            base.extend(
                make_record(self.key, f"extra-{j}".encode(), seed=400 + j)
                for j in range(n - len(base))
            )
        return tuple(base[:n])

    def test_paths_match_independent_builder(self):
        for n in range(1, 9):
            records = self._records_of_size(n)
            levels = independent_tree(records)
            root = levels[-1][0]
            for index in range(n):
                message, proof = make_proof(records, index)
                self.assertEqual(message, ROOT_TAG + u64(n) + root)
                self.assertEqual(proof.i, index)
                self.assertIs(proof.m, records[index][0])
                self.assertEqual(proof.a, records[index][1])
                self.assertEqual(proof.p, independent_path(levels, index))

    def test_deterministic(self):
        message, proof = make_proof(self.records, 2)
        message2, proof2 = make_proof(self.records, 2)
        self.assertEqual(message, message2)
        self.assertEqual(proof, proof2)

    def test_root_is_order_and_content_bound(self):
        message, _ = make_proof(self.records, 0)
        reordered = (
            self.records[1], self.records[0]
        ) + self.records[2:]
        self.assertNotEqual(message, make_proof(reordered, 0)[0])
        shortened = self.records[:4]
        self.assertNotEqual(message, make_proof(shortened, 0)[0])

    def test_single_record_has_empty_path(self):
        message, proof = make_proof(self.records[:1], 0)
        self.assertEqual(proof.p, ())
        m, a = self.records[0]
        self.assertEqual(
            message,
            ROOT_TAG + u64(1) + digest(LEAF_TAG + u64(0) + digest(m) + digest(a.payload)),
        )

    def test_index_type_errors(self):
        for bad in (True, "0", 1.0, None):
            with self.assertRaises(TypeError, msg=f"index={bad!r}"):
                make_proof(self.records, bad)

    def test_records_type_errors(self):
        with self.assertRaises(TypeError):
            make_proof([self.records[0]], 0)
        with self.assertRaises(TypeError):
            make_proof((b"only-message",), 0)
        with self.assertRaises(TypeError):
            make_proof(((b"m", b"not-an-audit"),), 0)
        with self.assertRaises(TypeError):
            make_proof(((bytearray(b"m"), self.records[0][1]),), 0)

    def test_empty_records_and_bad_index_raise_value_error(self):
        with self.assertRaises(ValueError):
            make_proof((), 0)
        for bad in (-1, 5, 100):
            with self.assertRaises(ValueError, msg=f"index={bad}"):
                make_proof(self.records, bad)

    def test_record_count_overflow_raises_value_error(self):
        class HugeTuple(tuple):
            def __len__(self):
                return 2 ** 64

        records = HugeTuple((self.records[0],))
        with self.assertRaises(ValueError):
            make_proof(records, 0)


class CheckProofTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = tuple(
            make_record(self.key, f"message-{i}".encode(), seed=100 + 10 * i)
            for i in range(5)
        )

    def test_honest_proofs_verify_for_every_leaf_and_size(self):
        for n in range(1, 9):
            records = self._records_of_size(n)
            for index in range(n):
                proof, signature = seal_proof(self.key, records, index)
                self.assertTrue(
                    check_proof(proof, signature, self.key),
                    msg=f"n={n} index={index}",
                )

    def _records_of_size(self, n):
        base = list(self.records)
        if n > len(base):
            base.extend(
                make_record(self.key, f"extra-{j}".encode(), seed=400 + j)
                for j in range(n - len(base))
            )
        return tuple(base[:n])

    def test_statement_is_an_ordinary_schnorr_message(self):
        message, proof = make_proof(self.records, 3)
        signature = sign_message(self.key, message, seed=900)
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
        self.assertTrue(check_proof(proof, signature, self.key))

    def test_failure_receipt_still_verifies_in_a_proof(self):
        failing = make_record(self.key, b"failing-message", seed=150, bad_share=True)
        records = (self.records[0], failing) + self.records[2:]
        proof, signature = seal_proof(self.key, records, 1)
        self.assertTrue(check_proof(proof, signature, self.key))

    def test_tampered_message_returns_false(self):
        proof, signature = seal_proof(self.key, self.records, 2)
        bad = dataclasses.replace(proof, m=b"wrong-message")
        self.assertFalse(check_proof(bad, signature, self.key))

    def test_tampered_receipt_returns_false(self):
        proof, signature = seal_proof(self.key, self.records, 2)
        message, audit = self.records[2]
        length = (GROUP_PRIME.bit_length() + 7) // 8
        bad_z = (int.from_bytes(audit.payload[-length:], "big") + 1) % FIELD_PRIME
        bad = dataclasses.replace(
            proof, a=SigningAudit(audit.payload[:-length] + bad_z.to_bytes(length, "big"))
        )
        self.assertFalse(check_proof(bad, signature, self.key))

    def test_changed_index_returns_false(self):
        proof, signature = seal_proof(self.key, self.records, 2)
        bad = dataclasses.replace(proof, i=3)
        self.assertFalse(check_proof(bad, signature, self.key))

    def test_changed_count_returns_false_when_path_still_fits(self):
        # n=6 has the same tree depth as n=5, so the path length stays
        # structurally legal but rebuilds a different root.
        proof, signature = seal_proof(self.key, self.records, 2)
        bad = dataclasses.replace(proof, n=6)
        self.assertFalse(check_proof(bad, signature, self.key))

    def test_flipped_sibling_returns_false(self):
        proof, signature = seal_proof(self.key, self.records, 2)
        flipped = bytearray(proof.p[0])
        flipped[0] ^= 1
        bad = dataclasses.replace(
            proof, p=(bytes(flipped),) + proof.p[1:]
        )
        self.assertFalse(check_proof(bad, signature, self.key))

    def test_path_order_matters(self):
        proof, signature = seal_proof(self.key, self.records, 2)
        reversed_path = tuple(reversed(proof.p))
        bad = dataclasses.replace(proof, p=reversed_path)
        self.assertFalse(check_proof(bad, signature, self.key))

    def test_sibling_from_another_leaf_returns_false(self):
        _message, proof_other = make_proof(self.records, 3)
        proof, signature = seal_proof(self.key, self.records, 2)
        bad = dataclasses.replace(proof, p=proof_other.p)
        self.assertFalse(check_proof(bad, signature, self.key))

    def test_bad_signature_returns_false(self):
        proof, signature = seal_proof(self.key, self.records, 2)
        bad_sig = AggregateSignature(
            R=signature.R,
            z=(signature.z + 1) % FIELD_PRIME,
            signer_ids=signature.signer_ids,
        )
        self.assertFalse(check_proof(proof, bad_sig, self.key))

    def test_signature_from_another_statement_returns_false(self):
        # The signed statement binds only (n, root), so a signature from a
        # different record set (a different root) must not carry over.
        _message, proof = make_proof(self.records, 2)
        other_message, _other = make_proof(self.records[:4], 0)
        other_signature = sign_message(self.key, other_message, seed=901)
        self.assertFalse(check_proof(proof, other_signature, self.key))

    def test_one_signature_covers_every_leaf_of_the_same_tree(self):
        # The statement carries just n and the root: every inclusion proof
        # in the same tree is backed by the one root signature.
        message, _ = make_proof(self.records, 0)
        signature = sign_message(self.key, message, seed=903)
        for index in range(len(self.records)):
            _msg, proof = make_proof(self.records, index)
            self.assertTrue(check_proof(proof, signature, self.key))

    def test_wrong_key_returns_false(self):
        proof, signature = seal_proof(self.key, self.records, 2)
        other_key = make_key(seed_offset=10)
        self.assertNotEqual(other_key.public_key, self.key.public_key)
        self.assertFalse(check_proof(proof, signature, other_key))

    def test_cross_key_receipt_returns_false(self):
        other_key = make_key(seed_offset=10)
        foreign = make_record(other_key, b"foreign-message", seed=300)
        records = (self.records[0], foreign) + self.records[2:]
        message, proof = make_proof(records, 1)
        signature = sign_message(other_key, message, seed=902)
        # Signed and sealed under the foreign key, but presented with ours.
        self.assertFalse(check_proof(proof, signature, self.key))
        self.assertTrue(check_proof(proof, signature, other_key))

    def test_entry_type_errors(self):
        proof, signature = seal_proof(self.key, self.records, 2)
        with self.assertRaises(TypeError):
            check_proof("proof", signature, self.key)
        with self.assertRaises(TypeError):
            check_proof(proof, "signature", self.key)
        with self.assertRaises(TypeError):
            check_proof(proof, signature, "key")
        for bad in (
            dataclasses.replace(proof, i=True),
            dataclasses.replace(proof, i="2"),
            dataclasses.replace(proof, n=True),
            dataclasses.replace(proof, m=bytearray(b"m")),
            dataclasses.replace(proof, a=b"receipt"),
            dataclasses.replace(proof, p=[b"s" * 32, b"t" * 32]),
            dataclasses.replace(proof, p=(b"s" * 32, 33)),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                check_proof(bad, signature, self.key)

    def test_structure_and_boundary_value_errors(self):
        proof, signature = seal_proof(self.key, self.records, 2)
        thirty_two = b"s" * 32
        for bad in (
            dataclasses.replace(proof, n=0),
            dataclasses.replace(proof, n=-1),
            dataclasses.replace(proof, n=2 ** 64),
            dataclasses.replace(proof, i=-1),
            dataclasses.replace(proof, i=5),
            dataclasses.replace(proof, p=()),
            dataclasses.replace(proof, p=(thirty_two,)),
            dataclasses.replace(proof, p=(thirty_two,) * 2),
            dataclasses.replace(proof, p=(b"s" * 31,) * 3),
            dataclasses.replace(proof, p=(b"s" * 33,) * 3),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                check_proof(bad, signature, self.key)

    def test_structurally_illegal_receipt_raises_value_error(self):
        proof, signature = seal_proof(self.key, self.records, 2)
        bad = dataclasses.replace(proof, a=SigningAudit(b"not-an-audit"))
        with self.assertRaises(ValueError):
            check_proof(bad, signature, self.key)

    def test_structurally_illegal_signature_raises_value_error(self):
        _message, proof = make_proof(self.records, 2)
        bad_sig = AggregateSignature(R=GROUP_PRIME, z=0, signer_ids=(1, 3))
        with self.assertRaises(ValueError):
            check_proof(proof, bad_sig, self.key)


if __name__ == "__main__":
    unittest.main()
