"""Tests for append-only consistency proofs over seal histories:
SealHistoryExtension / make_history_extension / check_history_extension."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    ReportSeal,
    SealHistory,
    SealHistoryExtension,
    check_history_extension,
    encode_seal,
    make_history_extension,
    make_history_proof,
)

from test_nonce_reuse import FIELD_PRIME, GROUP_PRIME, make_key
from test_nonce_leak_codec import make_other_key
from test_seal_history import make_history, sign_message

LEAF_TAG = b"sh/l"
NODE_TAG = b"sh/n"
ROOT_TAG = b"sh/r"


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big", signed=False)


def digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def independent_leaves(items):
    return tuple(
        digest(LEAF_TAG + u64(i) + digest(encode_seal(item)))
        for i, item in enumerate(items)
    )


def independent_root(leaves):
    """Root of the SealHistoryProof tree built straight from leaf digests."""
    current = leaves
    while len(current) > 1:
        seq = list(current)
        if len(seq) % 2 == 1:
            seq.append(seq[-1])
        current = tuple(
            digest(NODE_TAG + seq[j] + seq[j + 1]) for j in range(0, len(seq), 2)
        )
    return current[0]


def history_of_size(key, n):
    nonces = tuple(600 + i for i in range(n))
    return make_history(key, nonces=nonces)


def seal_extension(key, history, old_total, *, seed=700):
    """Return (proof, old_sig, new_sig) for a threshold-signed extension."""
    old_message, new_message, proof = make_history_extension(history, old_total)
    old_sig = sign_message(old_message, key, seed=seed)
    new_sig = sign_message(new_message, key, seed=seed + 1)
    return proof, old_sig, new_sig


class SealHistoryExtensionDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(SealHistoryExtension)],
            ["old_total", "leaves"],
        )
        leaves = (b"a" * 32, b"b" * 32)
        proof = SealHistoryExtension(1, leaves)
        self.assertEqual((proof.old_total, proof.leaves), (1, leaves))

    def test_frozen_value_equality_and_hash(self):
        leaves = (b"a" * 32, b"b" * 32)
        proof = SealHistoryExtension(1, leaves)
        same = SealHistoryExtension(old_total=1, leaves=leaves)
        self.assertEqual(proof, same)
        self.assertEqual(hash(proof), hash(same))
        for changed in (
            SealHistoryExtension(2, leaves),
            SealHistoryExtension(1, (b"a" * 32,)),
            SealHistoryExtension(1, (b"b" * 32, b"a" * 32)),
        ):
            self.assertNotEqual(proof, changed)
        with self.assertRaises(FrozenInstanceError):
            proof.old_total = 2

    def test_no_field_defaults(self):
        for field in dataclasses.fields(SealHistoryExtension):
            self.assertTrue(
                dataclasses.is_dataclass(SealHistoryExtension)
            )
            self.assertIs(field.default, dataclasses.MISSING)
            self.assertIs(field.default_factory, dataclasses.MISSING)


class MakeHistoryExtensionTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = history_of_size(self.key, 6)

    def test_statement_layout_for_every_split(self):
        leaves = independent_leaves(self.history.items)
        for old_total in range(1, len(self.history.items)):
            old_message, new_message, proof = make_history_extension(
                self.history, old_total
            )
            self.assertEqual(
                old_message,
                ROOT_TAG + u64(old_total) + independent_root(leaves[:old_total]),
            )
            self.assertEqual(
                new_message,
                ROOT_TAG
                + u64(len(self.history.items))
                + independent_root(leaves),
            )
            self.assertEqual(len(old_message), 4 + 8 + 32)
            self.assertEqual(len(new_message), 4 + 8 + 32)
            self.assertEqual(proof.old_total, old_total)
            self.assertEqual(proof.leaves, leaves)

    def test_old_root_matches_make_history_proof_statement(self):
        # The old statement is exactly the root statement make_history_proof
        # would build for the shortened prefix history.
        old_history = SealHistory(self.history.items[:3])
        old_message, _new_message, _proof = make_history_extension(
            self.history, 3
        )
        self.assertEqual(old_message, make_history_proof(old_history, 0)[0])

    def test_leaves_are_digests_not_seals(self):
        _old_message, _new_message, proof = make_history_extension(
            self.history, 2
        )
        for leaf in proof.leaves:
            self.assertIsInstance(leaf, bytes)
            self.assertEqual(len(leaf), 32)
            for item in self.history.items:
                self.assertNotIn(encode_seal(item), (leaf,))

    def test_deterministic(self):
        first = make_history_extension(self.history, 2)
        second = make_history_extension(self.history, 2)
        self.assertEqual(first, second)

    def test_old_total_type_errors(self):
        for bad in (True, False, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=f"old_total={bad!r}"):
                make_history_extension(self.history, bad)

    def test_history_type_errors(self):
        with self.assertRaises(TypeError):
            make_history_extension(list(self.history.items), 1)
        with self.assertRaises(TypeError):
            make_history_extension("history", 1)
        with self.assertRaises(TypeError):
            make_history_extension(None, 1)

    def test_empty_history_and_bad_old_total_raise_value_error(self):
        with self.assertRaises(ValueError):
            make_history_extension(SealHistory(()), 0)
        for bad in (-1, 0, 6, 7, 100):
            with self.assertRaises(ValueError, msg=f"old_total={bad}"):
                make_history_extension(self.history, bad)

    def test_structurally_illegal_nested_seal_raises_value_error(self):
        bad_sig = AggregateSignature(R=0, z=7, signer_ids=(1, 3))
        bad_seal = ReportSeal(
            report=self.history.items[0].report, signature=bad_sig
        )
        with self.assertRaises(ValueError):
            make_history_extension(SealHistory((bad_seal,)), 0)

    def test_item_count_overflow_raises_value_error(self):
        class HugeTuple(tuple):
            def __len__(self):
                return 2 ** 64

        history = SealHistory(HugeTuple((self.history.items[0],)))
        with self.assertRaises(ValueError):
            make_history_extension(history, 0)


class CheckHistoryExtensionTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = history_of_size(self.key, 6)

    def test_honest_proofs_verify_for_every_split_and_size(self):
        seed = 700
        for n in range(2, 9):
            history = history_of_size(self.key, n)
            for old_total in range(1, n):
                proof, old_sig, new_sig = seal_extension(
                    self.key, history, old_total, seed=seed
                )
                seed += 10
                self.assertTrue(
                    check_history_extension(
                        proof, old_sig, new_sig, self.key
                    ),
                    msg=f"n={n} old_total={old_total}",
                )

    def test_swapped_signatures_return_false(self):
        proof, old_sig, new_sig = seal_extension(self.key, self.history, 3)
        self.assertFalse(
            check_history_extension(proof, new_sig, old_sig, self.key)
        )

    def test_tampered_leaf_returns_false(self):
        proof, old_sig, new_sig = seal_extension(self.key, self.history, 3)
        flipped = bytearray(proof.leaves[1])
        flipped[0] ^= 1
        bad = dataclasses.replace(
            proof,
            leaves=proof.leaves[:1] + (bytes(flipped),) + proof.leaves[2:],
        )
        self.assertFalse(
            check_history_extension(bad, old_sig, new_sig, self.key)
        )

    def test_tampered_prefix_leaf_returns_false(self):
        proof, old_sig, new_sig = seal_extension(self.key, self.history, 3)
        flipped = bytearray(proof.leaves[0])
        flipped[0] ^= 1
        bad = dataclasses.replace(
            proof, leaves=(bytes(flipped),) + proof.leaves[1:]
        )
        self.assertFalse(
            check_history_extension(bad, old_sig, new_sig, self.key)
        )

    def test_leaf_order_matters(self):
        proof, old_sig, new_sig = seal_extension(self.key, self.history, 3)
        reordered = (proof.leaves[1], proof.leaves[0]) + proof.leaves[2:]
        bad = dataclasses.replace(proof, leaves=reordered)
        self.assertFalse(
            check_history_extension(bad, old_sig, new_sig, self.key)
        )

    def test_changed_old_total_returns_false(self):
        proof, old_sig, new_sig = seal_extension(self.key, self.history, 3)
        bad = dataclasses.replace(proof, old_total=2)
        self.assertFalse(
            check_history_extension(bad, old_sig, new_sig, self.key)
        )

    def test_truncated_leaves_return_false(self):
        # Dropping a tail leaf keeps the structure legal but changes the
        # new root.
        proof, old_sig, new_sig = seal_extension(self.key, self.history, 3)
        bad = dataclasses.replace(proof, leaves=proof.leaves[:-1])
        self.assertFalse(
            check_history_extension(bad, old_sig, new_sig, self.key)
        )

    def test_bad_signature_returns_false(self):
        proof, old_sig, new_sig = seal_extension(self.key, self.history, 3)
        bad_new = AggregateSignature(
            R=new_sig.R,
            z=(new_sig.z + 1) % FIELD_PRIME,
            signer_ids=new_sig.signer_ids,
        )
        self.assertFalse(
            check_history_extension(proof, old_sig, bad_new, self.key)
        )
        bad_old = AggregateSignature(
            R=old_sig.R,
            z=(old_sig.z + 1) % FIELD_PRIME,
            signer_ids=old_sig.signer_ids,
        )
        self.assertFalse(
            check_history_extension(proof, bad_old, new_sig, self.key)
        )

    def test_signature_from_another_statement_returns_false(self):
        # The new statement binds (n, root), so a signature over a different
        # history's statement must not carry over.
        proof, old_sig, _new_sig = seal_extension(self.key, self.history, 3)
        other_history = history_of_size(self.key, 5)
        other_message = make_history_extension(other_history, 2)[1]
        other_sig = sign_message(other_message, self.key, seed=901)
        self.assertFalse(
            check_history_extension(proof, old_sig, other_sig, self.key)
        )

    def test_wrong_key_returns_false(self):
        proof, old_sig, new_sig = seal_extension(self.key, self.history, 3)
        other_key = make_other_key()
        self.assertNotEqual(other_key.public_key, self.key.public_key)
        self.assertFalse(
            check_history_extension(proof, old_sig, new_sig, other_key)
        )

    def test_entry_type_errors(self):
        proof, old_sig, new_sig = seal_extension(self.key, self.history, 3)
        with self.assertRaises(TypeError):
            check_history_extension("proof", old_sig, new_sig, self.key)
        with self.assertRaises(TypeError):
            check_history_extension(proof, "old_sig", new_sig, self.key)
        with self.assertRaises(TypeError):
            check_history_extension(proof, old_sig, "new_sig", self.key)
        with self.assertRaises(TypeError):
            check_history_extension(proof, old_sig, new_sig, "key")
        for bad in (
            dataclasses.replace(proof, old_total=True),
            dataclasses.replace(proof, old_total=False),
            dataclasses.replace(proof, old_total="3"),
            dataclasses.replace(proof, leaves=list(proof.leaves)),
            dataclasses.replace(proof, leaves=(b"a" * 32, 33)),
            dataclasses.replace(proof, leaves=(bytearray(b"a" * 32),) * 6),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                check_history_extension(bad, old_sig, new_sig, self.key)

    def test_structure_and_boundary_value_errors(self):
        proof, old_sig, new_sig = seal_extension(self.key, self.history, 3)
        for bad in (
            dataclasses.replace(proof, old_total=0),
            dataclasses.replace(proof, old_total=-1),
            dataclasses.replace(proof, old_total=6),
            dataclasses.replace(proof, old_total=7),
            dataclasses.replace(proof, leaves=()),
            dataclasses.replace(proof, leaves=(b"a" * 31,) * 6),
            dataclasses.replace(proof, leaves=(b"a" * 33,) * 6),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                check_history_extension(bad, old_sig, new_sig, self.key)

    def test_structurally_illegal_signature_raises_value_error(self):
        proof, old_sig, new_sig = seal_extension(self.key, self.history, 3)
        bad_sig = AggregateSignature(R=GROUP_PRIME, z=0, signer_ids=(1, 3))
        with self.assertRaises(ValueError):
            check_history_extension(proof, bad_sig, new_sig, self.key)
        with self.assertRaises(ValueError):
            check_history_extension(proof, old_sig, bad_sig, self.key)


if __name__ == "__main__":
    unittest.main()
