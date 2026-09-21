"""Tests for compact multi-record Merkle inclusion proofs over audit-chain
records: AuditMultiProof / make_multi_proof / check_multi_proof."""

import dataclasses
import hashlib
import itertools
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    AuditMultiProof,
    SigningAudit,
    check_multi_proof,
    make_multi_proof,
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


def independent_multi(levels, indices, count):
    """Expected per-level sibling digests under the ascending selection rule."""
    known = set(indices)
    width = count
    siblings = []
    for level in levels[:-1]:
        padded = width % 2 == 1
        for position in sorted(known):
            if padded and position == width - 1:
                continue  # odd tail paired with itself
            companion = position ^ 1
            if companion not in known:
                siblings.append(level[companion])
        known = {position // 2 for position in known}
        width = (width + 1) // 2
    return tuple(siblings)


def seal_multi(key, records, indices, *, seed=700):
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
        records = ((b"m0", audit), (b"m2", audit))
        siblings = (b"s" * 32,)
        proof = AuditMultiProof((0, 2), 3, records, siblings)
        self.assertEqual(
            (proof.indices, proof.n, proof.records, proof.siblings),
            ((0, 2), 3, records, siblings),
        )

    def test_frozen_value_equality_and_hash(self):
        audit = SigningAudit(b"a")
        records = ((b"m0", audit), (b"m2", audit))
        siblings = (b"s" * 32, b"t" * 32)
        proof = AuditMultiProof((0, 2), 5, records, siblings)
        same = AuditMultiProof(
            indices=(0, 2), n=5, records=records, siblings=siblings
        )
        self.assertEqual(proof, same)
        self.assertEqual(hash(proof), hash(same))
        for changed in (
            AuditMultiProof((0, 3), 5, records, siblings),
            AuditMultiProof((0, 2), 6, records, siblings),
            AuditMultiProof((0, 2), 5, ((b"m0", audit),), siblings),
            AuditMultiProof((0, 2), 5, records, (b"s" * 32,)),
        ):
            self.assertNotEqual(proof, changed)
        with self.assertRaises(FrozenInstanceError):
            proof.n = 2


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

    def test_statement_layout_matches_single_tree_for_every_size(self):
        for n in range(1, 9):
            records = self._records_of_size(n)
            root = independent_tree(records)[-1][0]
            message, proof = make_multi_proof(records, (0,))
            self.assertEqual(message, ROOT_TAG + u64(n) + root)
            self.assertEqual(len(message), 4 + 8 + 32)
            self.assertEqual(proof.n, n)

    def test_exhaustive_subsets_match_independent_builder(self):
        for n in range(1, 9):
            records = self._records_of_size(n)
            levels = independent_tree(records)
            root = levels[-1][0]
            for size in range(1, n + 1):
                for indices in itertools.combinations(range(n), size):
                    message, proof = make_multi_proof(records, indices)
                    self.assertEqual(message, ROOT_TAG + u64(n) + root)
                    self.assertEqual(proof.indices, tuple(indices))
                    self.assertEqual(
                        proof.records, tuple(records[i] for i in indices)
                    )
                    self.assertTrue(
                        all(len(s) == 32 for s in proof.siblings),
                        msg=f"n={n} indices={indices}",
                    )
                    self.assertEqual(
                        proof.siblings,
                        independent_multi(levels, indices, n),
                        msg=f"n={n} indices={indices}",
                    )

    def test_single_index_matches_single_proof_path_minus_odd_tail(self):
        for n in range(1, 9):
            records = self._records_of_size(n)
            for index in range(n):
                _message, single = make_proof(records, index)
                _msg, multi = make_multi_proof(records, (index,))
                self.assertEqual(multi.records, (records[index],))
                position, width = index, n
                expected = []
                for sibling in single.p:
                    if not (width % 2 == 1 and position == width - 1):
                        expected.append(sibling)
                    position //= 2
                    width = (width + 1) // 2
                self.assertEqual(multi.siblings, tuple(expected))

    def test_all_leaves_disclosed_needs_no_siblings(self):
        for n in range(1, 9):
            records = self._records_of_size(n)
            _message, proof = make_multi_proof(records, tuple(range(n)))
            self.assertEqual(proof.siblings, ())

    def test_adjacent_and_odd_tail_indices_share_siblings(self):
        # n=5, indices (0,1,4): leaf level supplies nothing for the (0,1)
        # pair or the odd tail 4; level 1 supplies the companion of node 2.
        levels = independent_tree(self.records)
        _message, proof = make_multi_proof(self.records, (0, 1, 4))
        self.assertEqual(
            proof.siblings, independent_multi(levels, (0, 1, 4), 5)
        )
        self.assertEqual(len(proof.siblings), 1)

    def test_deterministic(self):
        a = make_multi_proof(self.records, (1, 3))
        b = make_multi_proof(self.records, (1, 3))
        self.assertEqual(a, b)

    def test_root_is_order_and_content_bound(self):
        message, _ = make_multi_proof(self.records, (0, 1))
        reordered = self.records[1], self.records[0]
        self.assertNotEqual(message, make_multi_proof(reordered + self.records[2:], (0, 1))[0])
        self.assertNotEqual(message, make_multi_proof(self.records[:4], (0, 1))[0])

    def test_indices_type_errors(self):
        for bad in ([0, 1], "01", 1, None, {0}):
            with self.assertRaises(TypeError, msg=f"indices={bad!r}"):
                make_multi_proof(self.records, bad)
        for bad in (True, "0", 1.0, None):
            with self.assertRaises(TypeError, msg=f"entry={bad!r}"):
                make_multi_proof(self.records, (bad,))

    def test_records_type_errors(self):
        with self.assertRaises(TypeError):
            make_multi_proof([self.records[0]], (0,))
        with self.assertRaises(TypeError):
            make_multi_proof((b"only-message",), (0,))
        with self.assertRaises(TypeError):
            make_multi_proof(((b"m", b"not-an-audit"),), (0,))
        with self.assertRaises(TypeError):
            make_multi_proof(((bytearray(b"m"), self.records[0][1]),), (0,))

    def test_empty_and_bad_indices_raise_value_error(self):
        with self.assertRaises(ValueError):
            make_multi_proof(self.records, ())
        with self.assertRaises(ValueError):
            make_multi_proof((), (0,))
        for bad in ((-1,), (5,), (100,), (0, 0), (1, 1), (2, 1), (0, 2, 2)):
            with self.assertRaises(ValueError, msg=f"indices={bad}"):
                make_multi_proof(self.records, bad)

    def test_record_count_overflow_raises_value_error(self):
        class HugeTuple(tuple):
            def __len__(self):
                return 2 ** 64

        with self.assertRaises(ValueError):
            make_multi_proof(HugeTuple((self.records[0],)), (0,))


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

    def test_honest_proofs_verify_exhaustively(self):
        for n in range(1, 9):
            records = self._records_of_size(n)
            for size in range(1, n + 1):
                for indices in itertools.combinations(range(n), size):
                    proof, signature = seal_multi(self.key, records, indices)
                    self.assertTrue(
                        check_multi_proof(proof, signature, self.key),
                        msg=f"n={n} indices={indices}",
                    )

    def test_statement_is_an_ordinary_schnorr_message(self):
        message, proof = make_multi_proof(self.records, (1, 3))
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
        self.assertTrue(check_multi_proof(proof, signature, self.key))

    def test_failure_receipt_still_verifies(self):
        failing = make_record(self.key, b"failing-message", seed=150, bad_share=True)
        records = (self.records[0], failing) + self.records[2:]
        proof, signature = seal_multi(self.key, records, (0, 1))
        self.assertTrue(check_multi_proof(proof, signature, self.key))

    def test_one_signature_covers_every_multi_proof_of_one_tree(self):
        message, _ = make_multi_proof(self.records, (0,))
        signature = sign_message(self.key, message, seed=903)
        for indices in ((0,), (2, 4), (1, 3, 4), tuple(range(5))):
            _msg, proof = make_multi_proof(self.records, indices)
            self.assertTrue(check_multi_proof(proof, signature, self.key))

    def test_single_record_tree(self):
        message, proof = make_multi_proof(self.records[:1], (0,))
        self.assertEqual(proof.siblings, ())
        self.assertTrue(
            check_multi_proof(
                proof, sign_message(self.key, message, seed=910), self.key
            )
        )

    def test_swapped_records_between_indices_return_false(self):
        proof, signature = seal_multi(self.key, self.records, (0, 2, 4))
        swapped = tuple(self.records[i] for i in (4, 2, 0))
        bad = dataclasses.replace(proof, records=swapped)
        self.assertFalse(check_multi_proof(bad, signature, self.key))

    def test_permuted_indices_return_false(self):
        proof, signature = seal_multi(self.key, self.records, (0, 2, 4))
        bad = dataclasses.replace(proof, indices=(1, 2, 4))
        # Records keep their original payloads, now bound to index 1: the
        # rebuilt leaves differ while the sibling stream stays the width the
        # layout requires (both sets need two siblings here).
        if len(bad.siblings) == 2:
            self.assertFalse(check_multi_proof(bad, signature, self.key))

    def test_tampered_message_returns_false(self):
        proof, signature = seal_multi(self.key, self.records, (0, 2))
        bad_records = ((b"wrong", proof.records[0][1]),) + proof.records[1:]
        self.assertFalse(
            check_multi_proof(
                dataclasses.replace(proof, records=bad_records),
                signature,
                self.key,
            )
        )

    def test_tampered_receipt_returns_false(self):
        proof, signature = seal_multi(self.key, self.records, (0, 2))
        message, audit = proof.records[1]
        length = (GROUP_PRIME.bit_length() + 7) // 8
        bad_z = (int.from_bytes(audit.payload[-length:], "big") + 1) % FIELD_PRIME
        bad_records = (
            proof.records[0],
            (message, SigningAudit(audit.payload[:-length] + bad_z.to_bytes(length, "big"))),
        )
        self.assertFalse(
            check_multi_proof(
                dataclasses.replace(proof, records=bad_records),
                signature,
                self.key,
            )
        )

    def test_flipped_sibling_returns_false(self):
        proof, signature = seal_multi(self.key, self.records, (0, 2, 4))
        self.assertTrue(proof.siblings)
        flipped = bytearray(proof.siblings[0])
        flipped[0] ^= 1
        bad = dataclasses.replace(
            proof, siblings=(bytes(flipped),) + proof.siblings[1:]
        )
        self.assertFalse(check_multi_proof(bad, signature, self.key))

    def test_sibling_order_matters(self):
        proof, signature = seal_multi(self.key, self.records, (0, 2))
        if len(proof.siblings) >= 2:
            bad = dataclasses.replace(
                proof, siblings=tuple(reversed(proof.siblings))
            )
            self.assertFalse(check_multi_proof(bad, signature, self.key))

    def test_bad_signature_returns_false(self):
        proof, signature = seal_multi(self.key, self.records, (0, 2))
        bad_sig = AggregateSignature(
            R=signature.R,
            z=(signature.z + 1) % FIELD_PRIME,
            signer_ids=signature.signer_ids,
        )
        self.assertFalse(check_multi_proof(proof, bad_sig, self.key))

    def test_signature_from_another_statement_returns_false(self):
        _message, proof = make_multi_proof(self.records, (0, 2))
        other_message, _other = make_multi_proof(self.records[:4], (0,))
        other_signature = sign_message(self.key, other_message, seed=901)
        self.assertFalse(check_multi_proof(proof, other_signature, self.key))

    def test_wrong_key_returns_false(self):
        proof, signature = seal_multi(self.key, self.records, (0, 2))
        other_key = make_key(seed_offset=10)
        self.assertNotEqual(other_key.public_key, self.key.public_key)
        self.assertFalse(check_multi_proof(proof, signature, other_key))

    def test_cross_key_record_returns_false(self):
        other_key = make_key(seed_offset=10)
        foreign = make_record(other_key, b"foreign-message", seed=300)
        records = (self.records[0], foreign) + self.records[2:]
        message, proof = make_multi_proof(records, (1,))
        signature = sign_message(other_key, message, seed=902)
        self.assertFalse(check_multi_proof(proof, signature, self.key))
        self.assertTrue(check_multi_proof(proof, signature, other_key))

    def test_entry_type_errors(self):
        proof, signature = seal_multi(self.key, self.records, (0, 2))
        with self.assertRaises(TypeError):
            check_multi_proof("proof", signature, self.key)
        with self.assertRaises(TypeError):
            check_multi_proof(proof, "signature", self.key)
        with self.assertRaises(TypeError):
            check_multi_proof(proof, signature, "key")
        for bad in (
            dataclasses.replace(proof, indices=[0, 2]),
            dataclasses.replace(proof, indices=(True, 2)),
            dataclasses.replace(proof, indices=("2",)),
            dataclasses.replace(proof, n=True),
            dataclasses.replace(proof, n="5"),
            dataclasses.replace(proof, records=[self.records[0], self.records[2]]),
            dataclasses.replace(
                proof,
                records=((b"m", b"receipt"),) * len(proof.records),
            ),
            dataclasses.replace(
                proof,
                records=tuple(
                    (bytearray(b"m"), audit) for _m, audit in proof.records
                ),
            ),
            dataclasses.replace(proof, siblings=[b"s" * 32]),
            dataclasses.replace(proof, siblings=(b"s" * 32, 33)),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                check_multi_proof(bad, signature, self.key)

    def test_structure_and_boundary_value_errors(self):
        proof, signature = seal_multi(self.key, self.records, (0, 2, 4))
        thirty_two = b"s" * 32
        for bad in (
            dataclasses.replace(proof, n=0),
            dataclasses.replace(proof, n=-1),
            dataclasses.replace(proof, n=2 ** 64),
            dataclasses.replace(proof, indices=()),
            dataclasses.replace(proof, indices=(-1, 2, 4)),
            dataclasses.replace(proof, indices=(5, 6, 7)),
            dataclasses.replace(proof, indices=(0, 0, 2)),
            dataclasses.replace(proof, indices=(2, 0, 4)),
            dataclasses.replace(proof, records=proof.records[:2]),
            dataclasses.replace(proof, siblings=()),
            dataclasses.replace(proof, siblings=proof.siblings + (thirty_two,)),
            dataclasses.replace(proof, siblings=(thirty_two,) * 5),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                check_multi_proof(bad, signature, self.key)

    def test_wrong_width_sibling_raises_value_error(self):
        proof, signature = seal_multi(self.key, self.records, (0, 2))
        self.assertTrue(proof.siblings)
        for width_bytes in (0, 1, 31, 33, 64):
            bad = dataclasses.replace(
                proof,
                siblings=(b"s" * width_bytes,) + proof.siblings[1:],
            )
            with self.assertRaises(ValueError, msg=f"width={width_bytes}"):
                check_multi_proof(bad, signature, self.key)

    def test_empty_receipt_raises_value_error(self):
        proof, signature = seal_multi(self.key, self.records, (0, 2))
        bad_records = tuple(
            (message, SigningAudit(b"")) for message, _audit in proof.records
        )
        bad = dataclasses.replace(proof, records=bad_records)
        with self.assertRaises(ValueError):
            check_multi_proof(bad, signature, self.key)

    def test_structurally_illegal_receipt_raises_value_error(self):
        proof, signature = seal_multi(self.key, self.records, (0, 2))
        bad_records = (
            (proof.records[0][0], SigningAudit(b"not-an-audit")),
        ) + proof.records[1:]
        with self.assertRaises(ValueError):
            check_multi_proof(
                dataclasses.replace(proof, records=bad_records),
                signature,
                self.key,
            )

    def test_structurally_illegal_signature_raises_value_error(self):
        _message, proof = make_multi_proof(self.records, (0, 2))
        bad_sig = AggregateSignature(R=GROUP_PRIME, z=0, signer_ids=(1, 3))
        with self.assertRaises(ValueError):
            check_multi_proof(proof, bad_sig, self.key)


if __name__ == "__main__":
    unittest.main()
