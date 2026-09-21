"""Tests for single-item Merkle inclusion proofs over a seal history:
SealHistoryProof / make_history_proof / check_history_proof."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    NonceLeakReport,
    ReportSeal,
    SealHistory,
    SealHistoryProof,
    check_history_proof,
    encode_seal,
    make_history_proof,
    verify_seal,
    verify_signature,
)

from test_nonce_reuse import (
    FIELD_PRIME,
    GENERATOR,
    GROUP_PRIME,
    make_key,
)
from test_nonce_leak_codec import make_other_key
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


def seal_history_proof(key, history, index, *, seed=800):
    """Return (proof, signature) for a threshold-signed root statement."""
    message, proof = make_history_proof(history, index)
    signature = sign_message(message, key, seed=seed + index)
    return proof, signature


class SealHistoryProofDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(SealHistoryProof)],
            ["index", "total", "seal", "siblings"],
        )
        seal = ReportSeal(
            NonceLeakReport((synthetic(1, 10),)),
            AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
        )
        path = (b"s" * 32,)
        proof = SealHistoryProof(1, 3, seal, path)
        self.assertEqual(
            (proof.index, proof.total, proof.seal, proof.siblings),
            (1, 3, seal, path),
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
        path = (b"s" * 32, b"t" * 32)
        proof = SealHistoryProof(1, 3, seal, path)
        same = SealHistoryProof(index=1, total=3, seal=seal, siblings=path)
        self.assertEqual(proof, same)
        self.assertEqual(hash(proof), hash(same))
        for changed in (
            SealHistoryProof(2, 3, seal, path),
            SealHistoryProof(1, 4, seal, path),
            SealHistoryProof(1, 3, other, path),
            SealHistoryProof(1, 3, seal, (b"s" * 32,)),
        ):
            self.assertNotEqual(proof, changed)
        with self.assertRaises(FrozenInstanceError):
            proof.index = 2


class MakeHistoryProofTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = make_history(
            self.key, nonces=tuple(700 + 11 * i for i in range(9))
        )

    def _history_of_size(self, n):
        return SealHistory(self.history.items[:n])

    def test_statement_layout_for_every_size(self):
        for n in range(1, 10):
            history = self._history_of_size(n)
            root = independent_tree(history.items)[-1][0]
            message, proof = make_history_proof(history, 0)
            self.assertEqual(message, ROOT_TAG + u64(n) + root)
            self.assertEqual(len(message), 4 + 8 + 32)
            self.assertEqual(proof.total, n)
            self.assertEqual(len(proof.siblings), (n - 1).bit_length())
            self.assertTrue(all(len(s) == 32 for s in proof.siblings))

    def test_paths_match_independent_builder(self):
        for n in range(1, 10):
            history = self._history_of_size(n)
            levels = independent_tree(history.items)
            root = levels[-1][0]
            for index in range(n):
                message, proof = make_history_proof(history, index)
                self.assertEqual(message, ROOT_TAG + u64(n) + root)
                self.assertEqual(proof.index, index)
                self.assertEqual(proof.total, n)
                self.assertEqual(proof.seal, history.items[index])
                self.assertEqual(
                    proof.siblings, independent_path(levels, index)
                )

    def test_deterministic(self):
        message, proof = make_history_proof(self.history, 2)
        message2, proof2 = make_history_proof(self.history, 2)
        self.assertEqual(message, message2)
        self.assertEqual(proof, proof2)

    def test_root_is_order_and_content_bound(self):
        message, _ = make_history_proof(self.history, 0)
        reordered = SealHistory(
            (self.history.items[1], self.history.items[0])
            + self.history.items[2:]
        )
        self.assertNotEqual(message, make_history_proof(reordered, 0)[0])
        shortened = SealHistory(self.history.items[:4])
        self.assertNotEqual(message, make_history_proof(shortened, 0)[0])

    def test_single_item_has_empty_path(self):
        history = self._history_of_size(1)
        message, proof = make_history_proof(history, 0)
        self.assertEqual(proof.siblings, ())
        seal = history.items[0]
        self.assertEqual(
            message,
            ROOT_TAG
            + u64(1)
            + digest(LEAF_TAG + u64(0) + digest(encode_seal(seal))),
        )

    def test_odd_tail_sibling_is_the_current_node(self):
        # n=3: leaf 2 is the odd tail of level 0; its first sibling is the
        # leaf itself (the duplicated tail), not a distinct neighbour.
        history = self._history_of_size(3)
        levels = independent_tree(history.items)
        _message, proof = make_history_proof(history, 2)
        self.assertEqual(proof.siblings[0], levels[0][2])
        # n=5, index 4: leaf 4 is the odd tail of level 0 (so its first
        # sibling is its own duplicated leaf), and the surviving node is
        # again the odd tail of level 1 (width 3, position 2).
        history = self._history_of_size(5)
        levels = independent_tree(history.items)
        _message, proof = make_history_proof(history, 4)
        self.assertEqual(proof.siblings[0], levels[0][4])
        current_level_1 = digest(NODE_TAG + levels[0][4] + levels[0][4])
        self.assertEqual(current_level_1, levels[1][2])
        self.assertEqual(proof.siblings[1], current_level_1)

    def test_index_type_errors(self):
        for bad in (True, "0", 1.0, None):
            with self.assertRaises(TypeError, msg=f"index={bad!r}"):
                make_history_proof(self.history, bad)

    def test_history_type_errors(self):
        with self.assertRaises(TypeError):
            make_history_proof(tuple(self.history.items), 0)
        with self.assertRaises(TypeError):
            make_history_proof("history", 0)
        with self.assertRaises(TypeError):
            make_history_proof(SealHistory("not-a-tuple"), 0)
        with self.assertRaises(TypeError):
            make_history_proof(SealHistory(("not-a-seal",)), 0)
        with self.assertRaises(TypeError):
            make_history_proof(
                SealHistory((self.history.items[0], "not-a-seal")), 0
            )

    def test_empty_history_and_bad_index_raise_value_error(self):
        with self.assertRaises(ValueError):
            make_history_proof(SealHistory(()), 0)
        for bad in (-1, 9, 100):
            with self.assertRaises(ValueError, msg=f"index={bad}"):
                make_history_proof(self.history, bad)

    def test_illegal_nested_seal_raises_value_error(self):
        bad = ReportSeal(
            NonceLeakReport((synthetic(1, 10),)),
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
        )
        with self.assertRaises(ValueError):
            make_history_proof(SealHistory((bad,)), 0)

    def test_item_count_overflow_raises_value_error(self):
        class HugeTuple(tuple):
            def __len__(self):
                return 2 ** 64

        history = SealHistory(HugeTuple((self.history.items[0],)))
        with self.assertRaises(ValueError):
            make_history_proof(history, 0)


class CheckHistoryProofTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = make_history(
            self.key, nonces=tuple(700 + 11 * i for i in range(9))
        )

    def _history_of_size(self, n):
        return SealHistory(self.history.items[:n])

    def test_honest_proofs_verify_for_every_leaf_and_size(self):
        for n in range(1, 10):
            history = self._history_of_size(n)
            for index in range(n):
                proof, signature = seal_history_proof(
                    self.key, history, index, seed=600 + 10 * n
                )
                self.assertTrue(
                    check_history_proof(proof, signature, self.key),
                    msg=f"n={n} index={index}",
                )

    def test_statement_is_an_ordinary_schnorr_message(self):
        message, proof = make_history_proof(self.history, 3)
        signature = sign_message(message, self.key, seed=900)
        self.assertTrue(
            verify_signature(
                message,
                signature,
                self.key.public_key,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            )
        )
        self.assertTrue(check_history_proof(proof, signature, self.key))

    def test_one_signature_covers_every_item_of_the_same_history(self):
        message, _ = make_history_proof(self.history, 0)
        signature = sign_message(message, self.key, seed=903)
        for index in range(len(self.history.items)):
            _msg, proof = make_history_proof(self.history, index)
            self.assertTrue(check_history_proof(proof, signature, self.key))

    def test_proof_embeds_a_real_verifying_seal(self):
        proof, signature = seal_history_proof(self.key, self.history, 2)
        self.assertTrue(verify_seal(proof.seal, self.key))

    def test_tampered_seal_returns_false(self):
        proof, signature = seal_history_proof(self.key, self.history, 2)
        bad_seal = ReportSeal(
            proof.seal.report,
            dataclasses.replace(proof.seal.signature, z=proof.seal.signature.z + 1),
        )
        bad = dataclasses.replace(proof, seal=bad_seal)
        self.assertFalse(check_history_proof(bad, signature, self.key))

    def test_changed_index_returns_false(self):
        proof, signature = seal_history_proof(self.key, self.history, 2)
        bad = dataclasses.replace(proof, index=3)
        self.assertFalse(check_history_proof(bad, signature, self.key))

    def test_changed_total_returns_false_when_path_still_fits(self):
        # total=6 has the same tree depth as total=5, so the path length
        # stays structurally legal but rebuilds a different root.
        history = self._history_of_size(5)
        proof, signature = seal_history_proof(self.key, history, 2)
        bad = dataclasses.replace(proof, total=6)
        self.assertFalse(check_history_proof(bad, signature, self.key))

    def test_flipped_sibling_returns_false(self):
        proof, signature = seal_history_proof(self.key, self.history, 2)
        flipped = bytearray(proof.siblings[0])
        flipped[0] ^= 1
        bad = dataclasses.replace(
            proof, siblings=(bytes(flipped),) + proof.siblings[1:]
        )
        self.assertFalse(check_history_proof(bad, signature, self.key))

    def test_path_order_matters(self):
        proof, signature = seal_history_proof(self.key, self.history, 2)
        bad = dataclasses.replace(
            proof, siblings=tuple(reversed(proof.siblings))
        )
        self.assertFalse(check_history_proof(bad, signature, self.key))

    def test_odd_tail_sibling_must_equal_current_node(self):
        # n=3, index 2: the level-0 sibling is the leaf itself. Supplying a
        # different 32-byte value is structurally legal but must fail.
        history = self._history_of_size(3)
        proof, signature = seal_history_proof(self.key, history, 2)
        self.assertEqual(proof.siblings[0], make_history_proof(history, 2)[1].siblings[0])
        wrong_tail = (b"w" * 32,) + proof.siblings[1:]
        bad = dataclasses.replace(proof, siblings=wrong_tail)
        self.assertFalse(check_history_proof(bad, signature, self.key))

    def test_bad_signature_returns_false(self):
        proof, signature = seal_history_proof(self.key, self.history, 2)
        bad_sig = dataclasses.replace(
            signature, z=(signature.z + 1) % FIELD_PRIME
        )
        self.assertFalse(check_history_proof(proof, bad_sig, self.key))

    def test_signature_from_another_statement_returns_false(self):
        _message, proof = make_history_proof(self.history, 2)
        other_message, _other = make_history_proof(self._history_of_size(4), 0)
        other_signature = sign_message(other_message, self.key, seed=901)
        self.assertFalse(check_history_proof(proof, other_signature, self.key))

    def test_wrong_key_returns_false(self):
        proof, signature = seal_history_proof(self.key, self.history, 2)
        other_key = make_other_key()
        self.assertNotEqual(other_key.public_key, self.key.public_key)
        self.assertFalse(check_history_proof(proof, signature, other_key))

    def test_entry_type_errors(self):
        proof, signature = seal_history_proof(self.key, self.history, 2)
        with self.assertRaises(TypeError):
            check_history_proof("proof", signature, self.key)
        with self.assertRaises(TypeError):
            check_history_proof(proof, "signature", self.key)
        with self.assertRaises(TypeError):
            check_history_proof(proof, signature, "key")
        for bad in (
            dataclasses.replace(proof, index=True),
            dataclasses.replace(proof, index="2"),
            dataclasses.replace(proof, total=True),
            dataclasses.replace(proof, seal="seal"),
            dataclasses.replace(proof, siblings=[b"s" * 32, b"t" * 32]),
            dataclasses.replace(proof, siblings=(b"s" * 32, 33)),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                check_history_proof(bad, signature, self.key)

    def test_structure_and_boundary_value_errors(self):
        proof, signature = seal_history_proof(self.key, self.history, 2)
        thirty_two = b"s" * 32
        for bad in (
            dataclasses.replace(proof, total=0),
            dataclasses.replace(proof, total=-1),
            dataclasses.replace(proof, total=2 ** 64),
            dataclasses.replace(proof, index=-1),
            dataclasses.replace(proof, index=9),
            dataclasses.replace(proof, siblings=()),
            dataclasses.replace(proof, siblings=(thirty_two,)),
            dataclasses.replace(proof, siblings=(thirty_two,) * 2),
            dataclasses.replace(proof, siblings=(b"s" * 31,) * 4),
            dataclasses.replace(proof, siblings=(b"s" * 33,) * 4),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                check_history_proof(bad, signature, self.key)

    def test_structurally_illegal_seal_raises_value_error(self):
        proof, signature = seal_history_proof(self.key, self.history, 2)
        bad_seal = ReportSeal(
            proof.seal.report,
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
        )
        bad = dataclasses.replace(proof, seal=bad_seal)
        with self.assertRaises(ValueError):
            check_history_proof(bad, signature, self.key)

    def test_structurally_illegal_signature_raises_value_error(self):
        _message, proof = make_history_proof(self.history, 2)
        bad_sig = AggregateSignature(R=GROUP_PRIME, z=0, signer_ids=(1, 3))
        with self.assertRaises(ValueError):
            check_history_proof(proof, bad_sig, self.key)


if __name__ == "__main__":
    unittest.main()
