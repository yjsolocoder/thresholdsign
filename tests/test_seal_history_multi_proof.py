"""Tests for compact multi-seal Merkle inclusion proofs over seal histories:
SealHistoryMultiProof / make_history_multi_proof /
check_history_multi_proof."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    NonceLeakReport,
    ReportSeal,
    SealHistory,
    SealHistoryMultiProof,
    SealHistoryProof,
    check_history_multi_proof,
    check_history_proof,
    encode_seal,
    make_history_multi_proof,
    make_history_proof,
)

from test_nonce_leak_codec import make_other_key
from test_nonce_reuse import FIELD_PRIME, make_key
from test_report_seal import synthetic
from test_seal_history import make_history, sign_message

LEAF_TAG = b"sh/l"
NODE_TAG = b"sh/n"
ROOT_TAG = b"sh/r"


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big", signed=False)


def digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def independent_tree(items):
    """Build leaf level, internal levels (odd tail duplicated) and root."""
    leaves = tuple(
        digest(LEAF_TAG + u64(i) + digest(encode_seal(item)))
        for i, item in enumerate(items)
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


def sealed_multi(history, indices, key, *, seed=800):
    """Return (proof, signature) for a threshold-signed multi-proof statement."""
    message, proof = make_history_multi_proof(history, indices)
    signature = sign_message(message, key, seed=seed + sum(indices))
    return proof, signature


class SealHistoryMultiProofDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(SealHistoryMultiProof)],
            ["indices", "total", "seals", "siblings"],
        )
        seal = ReportSeal(
            NonceLeakReport((synthetic(1, 10),)),
            AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
        )
        seals = (seal,)
        siblings = (b"s" * 32,)
        proof = SealHistoryMultiProof((1,), 3, seals, siblings)
        self.assertEqual(
            (proof.indices, proof.total, proof.seals, proof.siblings),
            ((1,), 3, seals, siblings),
        )

    def test_frozen_value_equality_and_hash(self):
        seal = ReportSeal(
            NonceLeakReport((synthetic(1, 10),)),
            AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
        )
        other = ReportSeal(
            NonceLeakReport((synthetic(2, 10),)),
            AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
        )
        seals = (seal,)
        siblings = (b"s" * 32, b"t" * 32)
        proof = SealHistoryMultiProof((1, 3), 4, seals, siblings)
        same = SealHistoryMultiProof(
            indices=(1, 3), total=4, seals=seals, siblings=siblings
        )
        self.assertEqual(proof, same)
        self.assertEqual(hash(proof), hash(same))
        for changed in (
            SealHistoryMultiProof((1, 2), 4, seals, siblings),
            SealHistoryMultiProof((1, 3), 5, seals, siblings),
            SealHistoryMultiProof((1, 3), 4, (other,), siblings),
            SealHistoryMultiProof((1, 3), 4, seals, (b"s" * 32,)),
        ):
            self.assertNotEqual(proof, changed)
        with self.assertRaises(FrozenInstanceError):
            proof.total = 5

    def test_construction_does_not_validate(self):
        # A plain value: out-of-range indices, non-tuple fields and
        # non-seal values all construct; the maker and checker reject them.
        seal = ReportSeal(
            NonceLeakReport((synthetic(1, 10),)),
            AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
        )
        SealHistoryMultiProof((9,), 1, (seal,), ())
        SealHistoryMultiProof((0,), 0, ("not-a-seal",), b"x")
        SealHistoryMultiProof((), 3, (seal,), (b"",))


class MakeHistoryMultiProofTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = make_history(
            self.key, nonces=tuple(100 + i for i in range(8))
        )

    def _history_of_size(self, n):
        return SealHistory(self.history.items[:n])

    def test_statement_layout_for_every_size_and_subset(self):
        for n in range(1, 9):
            history = self._history_of_size(n)
            root = independent_tree(history.items)[-1][0]
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                message, proof = make_history_multi_proof(history, indices)
                self.assertTrue(message.startswith(ROOT_TAG))
                self.assertEqual(message[len(ROOT_TAG):len(ROOT_TAG) + 8], u64(n))
                self.assertEqual(message[len(ROOT_TAG) + 8:], root)
                self.assertEqual(len(message), len(ROOT_TAG) + 8 + 32)
                self.assertEqual(proof.total, n)
                self.assertTrue(all(len(s) == 32 for s in proof.siblings))

    def test_same_statement_as_single_proof(self):
        for n in range(1, 9):
            history = self._history_of_size(n)
            single_message, _ = make_history_proof(history, 0)
            multi_message, _ = make_history_multi_proof(
                history, tuple(range(n))
            )
            self.assertEqual(multi_message, single_message)

    def test_seals_pair_one_to_one_with_indices(self):
        indices = (0, 2, 4)
        _message, proof = make_history_multi_proof(self.history, indices)
        self.assertEqual(proof.indices, indices)
        self.assertEqual(
            proof.seals, tuple(self.history.items[i] for i in indices)
        )
        self.assertIs(proof.seals[1], self.history.items[2])

    def test_siblings_match_independent_builder(self):
        for n in range(1, 9):
            history = self._history_of_size(n)
            levels = independent_tree(history.items)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                _message, proof = make_history_multi_proof(history, indices)
                self.assertEqual(
                    proof.siblings,
                    independent_siblings(levels, indices),
                    msg=f"n={n} indices={indices}",
                )

    def test_single_index_matches_single_proof_path_except_odd_tails(self):
        # The single-seal SealHistoryProof always carries a (redundant)
        # sibling digest on odd-tail levels; the compact proof omits them.
        for n in range(1, 9):
            history = self._history_of_size(n)
            levels = independent_tree(history.items)
            for index in range(n):
                _m, single = make_history_proof(history, index)
                _message, multi = make_history_multi_proof(history, (index,))
                self.assertEqual(
                    multi.siblings, independent_siblings(levels, (index,))
                )
                self.assertEqual(multi.seals, (single.seal,))
                self.assertLessEqual(len(multi.siblings), len(single.siblings))

    def test_proving_every_seal_needs_no_siblings(self):
        for n in range(1, 9):
            history = self._history_of_size(n)
            _message, proof = make_history_multi_proof(
                history, tuple(range(n))
            )
            self.assertEqual(proof.siblings, ())

    def test_deterministic(self):
        message, proof = make_history_multi_proof(self.history, (0, 2, 4))
        message2, proof2 = make_history_multi_proof(self.history, (0, 2, 4))
        self.assertEqual(message, message2)
        self.assertEqual(proof, proof2)

    def test_root_is_order_and_content_bound(self):
        message, _ = make_history_multi_proof(self.history, (0, 2))
        reordered = SealHistory(
            (self.history.items[1], self.history.items[0])
            + self.history.items[2:]
        )
        self.assertNotEqual(
            message, make_history_multi_proof(reordered, (0, 2))[0]
        )
        shortened = SealHistory(self.history.items[:4])
        self.assertNotEqual(
            message, make_history_multi_proof(shortened, (0, 2))[0]
        )

    def test_non_history_type_error(self):
        with self.assertRaises(TypeError):
            make_history_multi_proof(tuple(self.history.items), (0,))
        with self.assertRaises(TypeError):
            make_history_multi_proof("history", (0,))

    def test_indices_type_errors(self):
        for bad in ([0, 2], (True,), ("0",), (1.0,), (None,)):
            with self.assertRaises(TypeError, msg=f"indices={bad!r}"):
                make_history_multi_proof(self.history, bad)

    def test_empty_unsorted_duplicate_and_out_of_range_raise_value_error(self):
        with self.assertRaises(ValueError):
            make_history_multi_proof(self.history, ())
        with self.assertRaises(ValueError):
            make_history_multi_proof(SealHistory(()), (0,))
        for bad in ((2, 1), (1, 1), (-1,), (8,), (0, 8), (3, 3, 4)):
            with self.assertRaises(ValueError, msg=f"indices={bad}"):
                make_history_multi_proof(self.history, bad)

    def test_illegal_nested_seal_value_error(self):
        bad = ReportSeal(
            NonceLeakReport((synthetic(1, 10),)),
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
        )
        with self.assertRaises(ValueError):
            make_history_multi_proof(SealHistory((bad,)), (0,))


class CheckHistoryMultiProofTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = make_history(
            self.key, nonces=tuple(200 + i for i in range(8))
        )

    def _history_of_size(self, n):
        return SealHistory(self.history.items[:n])

    def test_honest_proofs_verify_for_every_size_and_subset(self):
        for n in range(1, 9):
            history = self._history_of_size(n)
            message, _ = make_history_multi_proof(history, (0,))
            signature = sign_message(message, self.key, seed=1000 + n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                _msg, proof = make_history_multi_proof(history, indices)
                self.assertTrue(
                    check_history_multi_proof(proof, signature, self.key),
                    msg=f"n={n} indices={indices}",
                )

    def test_single_item_history_verifies_with_empty_siblings(self):
        history = self._history_of_size(1)
        proof, signature = sealed_multi(history, (0,), self.key)
        self.assertEqual(proof.siblings, ())
        self.assertTrue(
            check_history_multi_proof(proof, signature, self.key)
        )

    def test_one_signature_covers_single_and_multi_proofs(self):
        history = self._history_of_size(5)
        message, _ = make_history_proof(history, 1)
        signature = sign_message(message, self.key, seed=1100)
        for index in range(len(history.items)):
            _m, single = make_history_proof(history, index)
            self.assertTrue(check_history_proof(single, signature, self.key))
        for indices in ((0, 4), (1, 2, 3), (0, 1, 2, 3, 4)):
            _m, multi = make_history_multi_proof(history, indices)
            self.assertTrue(
                check_history_multi_proof(multi, signature, self.key)
            )

    def test_tampered_seal_returns_false(self):
        proof, signature = sealed_multi(self.history, (1, 2), self.key)
        bad = dataclasses.replace(
            proof, seals=(self.history.items[0],) + proof.seals[1:]
        )
        self.assertFalse(
            check_history_multi_proof(bad, signature, self.key)
        )

    def test_swapped_seals_return_false(self):
        proof, signature = sealed_multi(self.history, (1, 2), self.key)
        swapped = (proof.seals[1], proof.seals[0])
        bad = dataclasses.replace(proof, seals=swapped)
        self.assertFalse(
            check_history_multi_proof(bad, signature, self.key)
        )

    def test_changed_total_returns_false_when_shape_still_fits(self):
        # n=5 -> n=6 keeps the same depth and sibling count for indices
        # (1, 3), so the proof stays structurally legal but rebuilds wrong.
        proof, signature = sealed_multi(self.history, (1, 3), self.key)
        bad = dataclasses.replace(proof, total=6)
        self.assertEqual(len(bad.siblings), 3)
        self.assertFalse(
            check_history_multi_proof(bad, signature, self.key)
        )

    def test_flipped_sibling_returns_false(self):
        proof, signature = sealed_multi(self.history, (0, 2), self.key)
        self.assertTrue(proof.siblings)
        flipped = bytearray(proof.siblings[0])
        flipped[0] ^= 1
        bad = dataclasses.replace(
            proof, siblings=(bytes(flipped),) + proof.siblings[1:]
        )
        self.assertFalse(
            check_history_multi_proof(bad, signature, self.key)
        )

    def test_sibling_order_matters(self):
        proof, signature = sealed_multi(self.history, (0, 2), self.key)
        self.assertGreaterEqual(len(proof.siblings), 2)
        reordered = proof.siblings[1::-1] + proof.siblings[2:]
        bad = dataclasses.replace(proof, siblings=reordered)
        self.assertFalse(
            check_history_multi_proof(bad, signature, self.key)
        )

    def test_missing_sibling_raises_value_error(self):
        proof, signature = sealed_multi(
            self.history, (0, 2, 4), self.key
        )
        bad = dataclasses.replace(proof, siblings=proof.siblings[:-1])
        with self.assertRaises(ValueError):
            check_history_multi_proof(bad, signature, self.key)

    def test_extra_sibling_raises_value_error(self):
        proof, signature = sealed_multi(
            self.history, (0, 2, 4), self.key
        )
        bad = dataclasses.replace(
            proof, siblings=proof.siblings + (b"x" * 32,)
        )
        with self.assertRaises(ValueError):
            check_history_multi_proof(bad, signature, self.key)

    def test_bad_signature_returns_false(self):
        proof, signature = sealed_multi(
            self.history, (0, 2, 4), self.key
        )
        bad_sig = AggregateSignature(
            R=signature.R,
            z=(signature.z + 1) % FIELD_PRIME,
            signer_ids=signature.signer_ids,
        )
        self.assertFalse(
            check_history_multi_proof(proof, bad_sig, self.key)
        )

    def test_signature_from_another_tree_returns_false(self):
        _message, proof = make_history_multi_proof(self.history, (0, 2))
        other_history = SealHistory(tuple(reversed(self.history.items[:5])))
        other_message, _other = make_history_multi_proof(
            other_history, (0, 2)
        )
        other_signature = sign_message(other_message, self.key, seed=1200)
        self.assertFalse(
            check_history_multi_proof(proof, other_signature, self.key)
        )

    def test_wrong_key_returns_false(self):
        proof, signature = sealed_multi(self.history, (0, 2), self.key)
        other_key = make_other_key()
        self.assertNotEqual(other_key.public_key, self.key.public_key)
        self.assertFalse(
            check_history_multi_proof(proof, signature, other_key)
        )

    def test_cross_key_seal_returns_false(self):
        # A well-formed proof carrying a real seal of another key:
        # verify_seal fails before the signature is even consulted.
        other_key = make_other_key()
        other_history = make_history(other_key, nonces=(301, 302))
        _, foreign = make_history_multi_proof(other_history, (0,))
        proof, signature = sealed_multi(self.history, (0,), self.key)
        mixed = dataclasses.replace(proof, seals=foreign.seals)
        self.assertFalse(
            check_history_multi_proof(mixed, signature, self.key)
        )

    def test_proof_does_not_need_the_full_history(self):
        proof, signature = sealed_multi(self.history, (2, 5), self.key)
        self.assertTrue(
            check_history_multi_proof(proof, signature, self.key)
        )

    def test_entry_type_errors(self):
        proof, signature = sealed_multi(self.history, (1, 2), self.key)
        with self.assertRaises(TypeError):
            check_history_multi_proof("proof", signature, self.key)
        with self.assertRaises(TypeError):
            check_history_multi_proof(proof, "signature", self.key)
        with self.assertRaises(TypeError):
            check_history_multi_proof(proof, signature, "key")
        for bad in (
            dataclasses.replace(proof, indices=[1, 2]),
            dataclasses.replace(proof, indices=(True, 2)),
            dataclasses.replace(proof, indices=("1", 2)),
            dataclasses.replace(proof, total=True),
            dataclasses.replace(proof, total="5"),
            dataclasses.replace(proof, seals=[proof.seals[0]] * 2),
            dataclasses.replace(proof, seals=("not-a-seal",) * 2),
            dataclasses.replace(proof, siblings=[b"s" * 32]),
            dataclasses.replace(proof, siblings=(b"s" * 32, 33)),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                check_history_multi_proof(bad, signature, self.key)

    def test_structure_and_boundary_value_errors(self):
        proof, signature = sealed_multi(self.history, (1, 2), self.key)
        seal1, seal2 = proof.seals
        thirty_two = b"s" * 32
        for bad in (
            SealHistoryMultiProof((1, 2), 0, proof.seals, ()),
            SealHistoryMultiProof((1, 2), -1, proof.seals, ()),
            SealHistoryMultiProof((1, 2), 2 ** 64, proof.seals, ()),
            SealHistoryMultiProof((), 5, (), ()),
            SealHistoryMultiProof((-1, 2), 5, proof.seals, ()),
            SealHistoryMultiProof((1, 5), 5, proof.seals, ()),
            SealHistoryMultiProof((2, 1), 5, proof.seals, ()),
            SealHistoryMultiProof((1, 1), 5, (seal1,), ()),
            SealHistoryMultiProof((1,), 5, (), ()),
            SealHistoryMultiProof(
                (1, 2, 3), 5, proof.seals + proof.seals[0:1], ()
            ),
            dataclasses.replace(proof, siblings=(b"s" * 31,) * 3),
            dataclasses.replace(proof, siblings=(b"s" * 33,) * 3),
            dataclasses.replace(proof, siblings=proof.siblings[:-1]),
            dataclasses.replace(proof, siblings=proof.siblings + (thirty_two,)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                check_history_multi_proof(bad, signature, self.key)

    def test_structurally_illegal_seal_raises_value_error(self):
        proof, signature = sealed_multi(self.history, (1, 2), self.key)
        bad_seal = ReportSeal(
            NonceLeakReport((synthetic(1, 10),)),
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
        )
        bad = dataclasses.replace(
            proof, seals=(bad_seal,) + proof.seals[1:]
        )
        with self.assertRaises(ValueError):
            check_history_multi_proof(bad, signature, self.key)

    def test_structurally_illegal_signature_raises_value_error(self):
        _message, proof = make_history_multi_proof(self.history, (1, 2))
        bad_sig = AggregateSignature(R=5, z=7, signer_ids=())
        with self.assertRaises(ValueError):
            check_history_multi_proof(proof, bad_sig, self.key)


if __name__ == "__main__":
    unittest.main()
