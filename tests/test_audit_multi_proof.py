"""Tests for compact multi-record Merkle inclusion proofs:
AuditMultiProof / make_multi_proof / check_multi_proof."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    AuditMultiProof,
    AuditProof,
    SigningAudit,
    check_multi_proof,
    check_proof,
    make_multi_proof,
    make_proof,
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


def independent_siblings(levels, indices):
    """Reference compact sibling list: ascending levels, disclosed or
    odd-tail companions omitted."""
    siblings = []
    positions = set(indices)
    for level in levels[:-1]:
        width = len(level)
        seq = list(level)
        if width % 2 == 1:
            seq.append(seq[-1])
        next_positions = set()
        for position in sorted(positions):
            if width % 2 == 1 and position == width - 1:
                pass
            elif (position ^ 1) in positions:
                pass
            else:
                siblings.append(seq[position ^ 1])
            next_positions.add(position // 2)
        positions = next_positions
    return tuple(siblings)


def seal_multi(key, records, indices, *, seed=800):
    """Return (proof, signature) for a threshold-signed multi-proof statement."""
    message, proof = make_multi_proof(records, indices)
    signature = sign_message(key, message, seed=seed + sum(indices))
    return proof, signature


class AuditMultiProofDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(AuditMultiProof)],
            ["indices", "n", "records", "siblings"],
        )
        audit = SigningAudit(b"a")
        records = ((b"m", audit),)
        siblings = (b"s" * 32,)
        proof = AuditMultiProof((1,), 3, records, siblings)
        self.assertEqual(
            (proof.indices, proof.n, proof.records, proof.siblings),
            ((1,), 3, records, siblings),
        )

    def test_frozen_value_equality_and_hash(self):
        audit = SigningAudit(b"a")
        records = ((b"m", audit),)
        siblings = (b"s" * 32, b"t" * 32)
        proof = AuditMultiProof((1, 3), 4, records, siblings)
        same = AuditMultiProof(indices=(1, 3), n=4, records=records, siblings=siblings)
        self.assertEqual(proof, same)
        self.assertEqual(hash(proof), hash(same))
        for changed in (
            AuditMultiProof((1, 2), 4, records, siblings),
            AuditMultiProof((1, 3), 5, records, siblings),
            AuditMultiProof((1, 3), 4, ((b"x", audit),), siblings),
            AuditMultiProof((1, 3), 4, records, (b"s" * 32,)),
        ):
            self.assertNotEqual(proof, changed)
        with self.assertRaises(FrozenInstanceError):
            proof.n = 5


class MakeMultiProofTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = tuple(
            make_record(self.key, f"message-{i}".encode(), seed=100 + 10 * i)
            for i in range(5)
        )

    def _records_of_size(self, n):
        base = list(self.records)
        if n > len(base):
            base.extend(
                make_record(self.key, f"extra-{j}".encode(), seed=400 + j)
                for j in range(n - len(base))
            )
        return tuple(base[:n])

    def test_statement_layout_for_every_size_and_subset(self):
        for n in range(1, 9):
            records = self._records_of_size(n)
            root = independent_tree(records)[-1][0]
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                message, proof = make_multi_proof(records, indices)
                self.assertEqual(message, ROOT_TAG + u64(n) + root)
                self.assertEqual(len(message), 4 + 8 + 32)
                self.assertEqual(proof.n, n)
                self.assertTrue(all(len(s) == 32 for s in proof.siblings))

    def test_same_statement_as_single_proof(self):
        for n in range(1, 9):
            records = self._records_of_size(n)
            single_message, _ = make_proof(records, 0)
            multi_message, _ = make_multi_proof(records, tuple(range(n)))
            self.assertEqual(multi_message, single_message)

    def test_records_pair_one_to_one_with_indices(self):
        records = self.records
        indices = (0, 2, 4)
        _message, proof = make_multi_proof(records, indices)
        self.assertEqual(proof.indices, indices)
        self.assertEqual(proof.records, tuple(records[i] for i in indices))
        self.assertIs(proof.records[1][0], records[2][0])

    def test_siblings_match_independent_builder(self):
        for n in range(1, 9):
            records = self._records_of_size(n)
            levels = independent_tree(records)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                _message, proof = make_multi_proof(records, indices)
                self.assertEqual(
                    proof.siblings,
                    independent_siblings(levels, indices),
                    msg=f"n={n} indices={indices}",
                )

    def test_single_index_matches_single_proof_path_except_odd_tails(self):
        # The single-leaf AuditProof always carries a (redundant) sibling
        # digest on odd-tail levels; the compact proof omits them.
        for n in range(1, 9):
            records = self._records_of_size(n)
            levels = independent_tree(records)
            for index in range(n):
                _m, single = make_proof(records, index)
                _message, multi = make_multi_proof(records, (index,))
                self.assertEqual(
                    multi.siblings, independent_siblings(levels, (index,))
                )
                self.assertEqual(multi.records, ((single.m, single.a),))
                self.assertLessEqual(len(multi.siblings), len(single.p))

    def test_proving_every_record_needs_no_siblings(self):
        for n in range(1, 9):
            records = self._records_of_size(n)
            _message, proof = make_multi_proof(records, tuple(range(n)))
            self.assertEqual(proof.siblings, ())

    def test_deterministic(self):
        message, proof = make_multi_proof(self.records, (0, 2, 4))
        message2, proof2 = make_multi_proof(self.records, (0, 2, 4))
        self.assertEqual(message, message2)
        self.assertEqual(proof, proof2)

    def test_root_is_order_and_content_bound(self):
        message, _ = make_multi_proof(self.records, (0, 2))
        reordered = (
            self.records[1], self.records[0]
        ) + self.records[2:]
        self.assertNotEqual(message, make_multi_proof(reordered, (0, 2))[0])
        shortened = self.records[:4]
        self.assertNotEqual(message, make_multi_proof(shortened, (0, 2))[0])

    def test_indices_type_errors(self):
        for bad in ([0, 2], (True,), ("0",), (1.0,), (None,)):
            with self.assertRaises(TypeError, msg=f"indices={bad!r}"):
                make_multi_proof(self.records, bad)

    def test_records_type_errors(self):
        with self.assertRaises(TypeError):
            make_multi_proof([self.records[0]], (0,))
        with self.assertRaises(TypeError):
            make_multi_proof((b"only-message",), (0,))
        with self.assertRaises(TypeError):
            make_multi_proof(((b"m", b"not-an-audit"),), (0,))
        with self.assertRaises(TypeError):
            make_multi_proof(((bytearray(b"m"), self.records[0][1]),), (0,))

    def test_empty_unsorted_duplicate_and_out_of_range_raise_value_error(self):
        with self.assertRaises(ValueError):
            make_multi_proof(self.records, ())
        with self.assertRaises(ValueError):
            make_multi_proof((), (0,))
        for bad in ((2, 1), (1, 1), (-1,), (5,), (0, 5), (3, 3, 4)):
            with self.assertRaises(ValueError, msg=f"indices={bad}"):
                make_multi_proof(self.records, bad)

    def test_record_count_overflow_raises_value_error(self):
        class HugeTuple(tuple):
            def __len__(self):
                return 2 ** 64

        records = HugeTuple((self.records[0],))
        with self.assertRaises(ValueError):
            make_multi_proof(records, (0,))


class CheckMultiProofTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = tuple(
            make_record(self.key, f"message-{i}".encode(), seed=100 + 10 * i)
            for i in range(5)
        )

    def _records_of_size(self, n):
        base = list(self.records)
        if n > len(base):
            base.extend(
                make_record(self.key, f"extra-{j}".encode(), seed=400 + j)
                for j in range(n - len(base))
            )
        return tuple(base[:n])

    def test_honest_proofs_verify_for_every_size_and_subset(self):
        for n in range(1, 9):
            records = self._records_of_size(n)
            message, _ = make_multi_proof(records, (0,))
            signature = sign_message(self.key, message, seed=1000 + n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                _msg, proof = make_multi_proof(records, indices)
                self.assertTrue(
                    check_multi_proof(proof, signature, self.key),
                    msg=f"n={n} indices={indices}",
                )

    def test_one_signature_covers_single_and_multi_proofs(self):
        message, _ = make_proof(self.records, 1)
        signature = sign_message(self.key, message, seed=1100)
        for index in range(len(self.records)):
            _m, single = make_proof(self.records, index)
            self.assertTrue(check_proof(single, signature, self.key))
        for indices in ((0, 4), (1, 2, 3), (0, 1, 2, 3, 4)):
            _m, multi = make_multi_proof(self.records, indices)
            self.assertTrue(check_multi_proof(multi, signature, self.key))

    def test_failure_receipt_still_verifies_in_a_multi_proof(self):
        failing = make_record(self.key, b"failing-message", seed=150, bad_share=True)
        records = (self.records[0], failing) + self.records[2:]
        proof, signature = seal_multi(self.key, records, (0, 1, 2))
        self.assertTrue(check_multi_proof(proof, signature, self.key))

    def test_tampered_message_returns_false(self):
        proof, signature = seal_multi(self.key, self.records, (1, 2))
        message, audit = proof.records[0]
        bad_records = ((b"wrong-message", audit),) + proof.records[1:]
        bad = dataclasses.replace(proof, records=bad_records)
        self.assertFalse(check_multi_proof(bad, signature, self.key))

    def test_tampered_receipt_returns_false(self):
        proof, signature = seal_multi(self.key, self.records, (1, 2))
        message, audit = proof.records[1]
        length = (GROUP_PRIME.bit_length() + 7) // 8
        bad_z = (int.from_bytes(audit.payload[-length:], "big") + 1) % FIELD_PRIME
        bad_audit = SigningAudit(
            audit.payload[:-length] + bad_z.to_bytes(length, "big")
        )
        bad_records = proof.records[:1] + ((message, bad_audit),)
        bad = dataclasses.replace(proof, records=bad_records)
        self.assertFalse(check_multi_proof(bad, signature, self.key))

    def test_swapped_records_return_false(self):
        proof, signature = seal_multi(self.key, self.records, (1, 2))
        swapped = (proof.records[1], proof.records[0])
        bad = dataclasses.replace(proof, records=swapped)
        self.assertFalse(check_multi_proof(bad, signature, self.key))

    def test_changed_index_returns_false_when_shape_still_fits(self):
        # n=5 -> n=6 keeps the same depth and sibling count for indices
        # (1, 3), so the proof stays structurally legal but rebuilds wrong.
        proof, signature = seal_multi(self.key, self.records, (1, 3))
        bad = dataclasses.replace(proof, n=6)
        self.assertEqual(len(bad.siblings), 3)
        self.assertFalse(check_multi_proof(bad, signature, self.key))

    def test_flipped_sibling_returns_false(self):
        proof, signature = seal_multi(self.key, self.records, (0, 2))
        self.assertTrue(proof.siblings)
        flipped = bytearray(proof.siblings[0])
        flipped[0] ^= 1
        bad = dataclasses.replace(
            proof, siblings=(bytes(flipped),) + proof.siblings[1:]
        )
        self.assertFalse(check_multi_proof(bad, signature, self.key))

    def test_sibling_order_matters(self):
        proof, signature = seal_multi(self.key, self.records, (0, 2))
        self.assertGreaterEqual(len(proof.siblings), 2)
        reordered = (
            proof.siblings[1::-1] + proof.siblings[2:]
        )
        bad = dataclasses.replace(proof, siblings=reordered)
        self.assertFalse(check_multi_proof(bad, signature, self.key))

    def test_missing_sibling_raises_value_error(self):
        proof, signature = seal_multi(self.key, self.records, (0, 2, 4))
        bad = dataclasses.replace(proof, siblings=proof.siblings[:-1])
        with self.assertRaises(ValueError):
            check_multi_proof(bad, signature, self.key)

    def test_extra_sibling_raises_value_error(self):
        proof, signature = seal_multi(self.key, self.records, (0, 2, 4))
        bad = dataclasses.replace(proof, siblings=proof.siblings + (b"x" * 32,))
        with self.assertRaises(ValueError):
            check_multi_proof(bad, signature, self.key)

    def test_bad_signature_returns_false(self):
        proof, signature = seal_multi(self.key, self.records, (0, 2, 4))
        bad_sig = AggregateSignature(
            R=signature.R,
            z=(signature.z + 1) % FIELD_PRIME,
            signer_ids=signature.signer_ids,
        )
        self.assertFalse(check_multi_proof(proof, bad_sig, self.key))

    def test_signature_from_another_statement_returns_false(self):
        _message, proof = make_multi_proof(self.records, (0, 2))
        other_message, _other = make_multi_proof(self.records[:4], (0, 2))
        other_signature = sign_message(self.key, other_message, seed=1200)
        self.assertFalse(check_multi_proof(proof, other_signature, self.key))

    def test_wrong_key_returns_false(self):
        proof, signature = seal_multi(self.key, self.records, (0, 2))
        other_key = make_key(seed_offset=10)
        self.assertNotEqual(other_key.public_key, self.key.public_key)
        self.assertFalse(check_multi_proof(proof, signature, other_key))

    def test_cross_key_receipt_returns_false(self):
        other_key = make_key(seed_offset=10)
        foreign = make_record(other_key, b"foreign-message", seed=300)
        records = (self.records[0], foreign) + self.records[2:]
        message, proof = make_multi_proof(records, (1,))
        signature = sign_message(other_key, message, seed=1300)
        self.assertFalse(check_multi_proof(proof, signature, self.key))
        self.assertTrue(check_multi_proof(proof, signature, other_key))

    def test_entry_type_errors(self):
        proof, signature = seal_multi(self.key, self.records, (1, 2))
        audit = SigningAudit(b"a")
        with self.assertRaises(TypeError):
            check_multi_proof("proof", signature, self.key)
        with self.assertRaises(TypeError):
            check_multi_proof(proof, "signature", self.key)
        with self.assertRaises(TypeError):
            check_multi_proof(proof, signature, "key")
        for bad in (
            dataclasses.replace(proof, indices=[1, 2]),
            dataclasses.replace(proof, indices=(True, 2)),
            dataclasses.replace(proof, indices=("1", 2)),
            dataclasses.replace(proof, n=True),
            dataclasses.replace(proof, n="5"),
            dataclasses.replace(proof, records=[proof.records[0]] * 2),
            dataclasses.replace(
                proof, records=((b"m", b"not-an-audit"),) * 2
            ),
            dataclasses.replace(
                proof,
                records=((bytearray(b"m"), audit),) * 2,
            ),
            dataclasses.replace(proof, siblings=[b"s" * 32]),
            dataclasses.replace(proof, siblings=(b"s" * 32, 33)),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                check_multi_proof(bad, signature, self.key)

    def test_structure_and_boundary_value_errors(self):
        proof, signature = seal_multi(self.key, self.records, (1, 2))
        (msg0, audit0), (_msg1, _audit1) = proof.records
        thirty_two = b"s" * 32
        for bad in (
            AuditMultiProof((1, 2), 0, proof.records, ()),
            AuditMultiProof((1, 2), -1, proof.records, ()),
            AuditMultiProof((1, 2), 2 ** 64, proof.records, ()),
            AuditMultiProof((), 5, (), ()),
            AuditMultiProof((-1, 2), 5, proof.records, ()),
            AuditMultiProof((1, 5), 5, proof.records, ()),
            AuditMultiProof((2, 1), 5, proof.records, ()),
            AuditMultiProof((1, 1), 5, ((msg0, audit0),), ()),
            AuditMultiProof((1,), 5, (), ()),
            AuditMultiProof((1, 2, 3), 5, proof.records + proof.records[0:1], ()),
            AuditMultiProof(
                (1, 2), 5, ((msg0, SigningAudit(b"")),) + proof.records[1:], ()
            ),
            dataclasses.replace(proof, siblings=(b"s" * 31,) * 3),
            dataclasses.replace(proof, siblings=(b"s" * 33,) * 3),
            dataclasses.replace(proof, siblings=proof.siblings[:-1]),
            dataclasses.replace(proof, siblings=proof.siblings + (thirty_two,)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                check_multi_proof(bad, signature, self.key)

    def test_structurally_illegal_receipt_raises_value_error(self):
        proof, signature = seal_multi(self.key, self.records, (1, 2))
        bad_records = (
            (proof.records[0][0], SigningAudit(b"not-an-audit")),
        ) + proof.records[1:]
        bad = dataclasses.replace(proof, records=bad_records)
        with self.assertRaises(ValueError):
            check_multi_proof(bad, signature, self.key)

    def test_structurally_illegal_signature_raises_value_error(self):
        _message, proof = make_multi_proof(self.records, (1, 2))
        bad_sig = AggregateSignature(R=GROUP_PRIME, z=0, signer_ids=(1, 3))
        with self.assertRaises(ValueError):
            check_multi_proof(proof, bad_sig, self.key)


if __name__ == "__main__":
    unittest.main()
