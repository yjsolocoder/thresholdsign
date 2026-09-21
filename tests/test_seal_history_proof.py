"""Tests for single-seal Merkle inclusion proofs over seal histories:
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
    verify_signature,
)

from test_nonce_reuse import FIELD_PRIME, GENERATOR, GROUP_PRIME, make_key
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


def signed_proof(history, index, key, *, seed=800):
    """Return (message, proof, signature) for one history position."""
    message, proof = make_history_proof(history, index)
    signature = sign_message(message, key, seed=seed + index)
    return message, proof, signature


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
        siblings = (b"s" * 32,)
        proof = SealHistoryProof(1, 3, seal, siblings)
        self.assertEqual(
            (proof.index, proof.total, proof.seal, proof.siblings),
            (1, 3, seal, siblings),
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

    def test_construction_does_not_validate(self):
        # A plain value: out-of-range indices, non-tuple paths and
        # non-seal values all construct; the maker and checker reject them.
        seal = ReportSeal(
            NonceLeakReport((synthetic(1, 10),)),
            AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
        )
        SealHistoryProof(9, 1, seal, ())
        SealHistoryProof(0, 0, "not-a-seal", b"x")
        SealHistoryProof(-1, 3, seal, (b"",))


class MakeHistoryProofTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = make_history(self.key, nonces=tuple(100 + i for i in range(8)))

    def test_statement_layout_for_every_size(self):
        for n in range(1, 9):
            history = SealHistory(self.history.items[:n])
            levels = independent_tree(history.items)
            root = levels[-1][0]
            message, proof = make_history_proof(history, n - 1)
            self.assertTrue(message.startswith(ROOT_TAG))
            self.assertEqual(message[len(ROOT_TAG):len(ROOT_TAG) + 8], u64(n))
            self.assertEqual(message[len(ROOT_TAG) + 8:], root)
            self.assertEqual(len(message), len(ROOT_TAG) + 8 + 32)

    def test_path_matches_independent_builder_for_every_position(self):
        for n in range(1, 9):
            history = SealHistory(self.history.items[:n])
            levels = independent_tree(history.items)
            for index in range(n):
                _, proof = make_history_proof(history, index)
                self.assertEqual(
                    proof,
                    SealHistoryProof(
                        index=index,
                        total=n,
                        seal=history.items[index],
                        siblings=independent_path(levels, index),
                    ),
                    msg=f"n={n} index={index}",
                )

    def test_path_depth_and_digest_width(self):
        for n in range(1, 9):
            history = SealHistory(self.history.items[:n])
            for index in range(n):
                _, proof = make_history_proof(history, index)
                self.assertEqual(
                    len(proof.siblings), (n - 1).bit_length()
                )
                self.assertTrue(
                    all(len(sibling) == 32 for sibling in proof.siblings)
                )

    def test_odd_tail_sibling_is_the_node_itself(self):
        # n = 5: the leaf level has odd width; index 4 is the odd tail,
        # so its first sibling must equal its own leaf digest; at level
        # width 3 the same position (2) is the odd tail once more.
        history = SealHistory(self.history.items[:5])
        levels = independent_tree(history.items)
        _, proof = make_history_proof(history, 4)
        leaf = levels[0][4]
        self.assertEqual(proof.siblings[0], leaf)
        self.assertEqual(proof.siblings[1], levels[1][2])
        self.assertEqual(
            proof.siblings,
            independent_path(levels, 4),
        )

    def test_non_history_type_error(self):
        with self.assertRaises(TypeError):
            make_history_proof(tuple(self.history.items), 0)
        with self.assertRaises(TypeError):
            make_history_proof("history", 0)

    def test_index_type_errors(self):
        with self.assertRaises(TypeError):
            make_history_proof(self.history, "0")
        with self.assertRaises(TypeError):
            make_history_proof(self.history, True)
        with self.assertRaises(TypeError):
            make_history_proof(self.history, 0.0)

    def test_empty_history_value_error(self):
        with self.assertRaises(ValueError):
            make_history_proof(SealHistory(()), 0)

    def test_index_out_of_range_value_error(self):
        history = SealHistory(self.history.items[:5])
        for bad in (-1, 5, 6):
            with self.assertRaises(ValueError, msg=f"index={bad}"):
                make_history_proof(history, bad)
        single = SealHistory(self.history.items[:1])
        with self.assertRaises(ValueError):
            make_history_proof(single, 1)

    def test_illegal_nested_seal_value_error(self):
        bad = ReportSeal(
            NonceLeakReport((synthetic(1, 10),)),
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
        )
        with self.assertRaises(ValueError):
            make_history_proof(SealHistory((bad,)), 0)

    def test_maker_is_stateless_and_unique(self):
        first_message, first_proof = make_history_proof(self.history, 2)
        second_message, second_proof = make_history_proof(self.history, 2)
        self.assertEqual(first_message, second_message)
        self.assertEqual(first_proof, second_proof)


class CheckHistoryProofTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = make_history(self.key, nonces=tuple(200 + i for i in range(8)))

    def test_every_position_of_every_size_verifies(self):
        for n in range(1, 9):
            history = SealHistory(self.history.items[:n])
            for index in range(n):
                message, proof, signature = signed_proof(
                    history, index, self.key, seed=900 + 17 * n
                )
                self.assertTrue(
                    check_history_proof(proof, signature, self.key),
                    msg=f"n={n} index={index}",
                )
                # The signed message is exactly the root statement.
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

    def test_single_item_history_verifies_with_empty_path(self):
        history = SealHistory(self.history.items[:1])
        _, proof, signature = signed_proof(history, 0, self.key)
        self.assertEqual(proof.siblings, ())
        self.assertTrue(check_history_proof(proof, signature, self.key))

    def test_odd_tail_path_sibling_must_equal_node(self):
        # index 4 in a 5-item tree rides two odd-tail levels.
        history = SealHistory(self.history.items[:5])
        _, proof, signature = signed_proof(history, 4, self.key)
        tampered = dataclasses.replace(
            proof, siblings=proof.siblings[:1] + (b"x" * 32,) + proof.siblings[2:]
        )
        self.assertFalse(check_history_proof(tampered, signature, self.key))

    def test_wrong_sibling_returns_false(self):
        _, proof, signature = signed_proof(self.history, 0, self.key)
        bad_sibling = bytes(proof.siblings[0][:-1]) + bytes(
            [proof.siblings[0][-1] ^ 1]
        )
        tampered = dataclasses.replace(
            proof, siblings=(bad_sibling,) + proof.siblings[1:]
        )
        self.assertFalse(check_history_proof(tampered, signature, self.key))

    def test_wrong_index_returns_false(self):
        _, proof, signature = signed_proof(self.history, 0, self.key)
        tampered = dataclasses.replace(proof, index=1)
        self.assertFalse(check_history_proof(tampered, signature, self.key))

    def test_wrong_total_returns_false(self):
        # The proof was made for 3 items; claiming total = 4 keeps the
        # legal path depth ((4 - 1).bit_length() == 2, same as n = 3)
        # but rebuilds a different (or odd-tail-mismatched) root.
        _, proof, signature = signed_proof(
            SealHistory(self.history.items[:3]), 0, self.key
        )
        tampered = dataclasses.replace(proof, total=4)
        self.assertFalse(check_history_proof(tampered, signature, self.key))

    def test_tampered_seal_returns_false(self):
        # The seal first goes through verify_seal: swapping in another
        # structurally legal seal invalidates the proof.
        _, other = make_history_proof(self.history, 1)
        _, proof, signature = signed_proof(self.history, 0, self.key)
        tampered = dataclasses.replace(proof, seal=other.seal)
        self.assertFalse(check_history_proof(tampered, signature, self.key))

    def test_tampered_signature_returns_false(self):
        _, proof, signature = signed_proof(self.history, 2, self.key)
        tampered = dataclasses.replace(
            signature, z=(signature.z + 1) % FIELD_PRIME
        )
        self.assertFalse(check_history_proof(proof, tampered, self.key))

    def test_same_root_signature_covers_every_position(self):
        # The root statement binds only total and root: one signature
        # authenticates a valid inclusion proof for any of its leaves.
        history = SealHistory(self.history.items[:5])
        message, _ = make_history_proof(history, 0)
        signature = sign_message(message, self.key, seed=950)
        for index in range(5):
            _, proof = make_history_proof(history, index)
            self.assertTrue(
                check_history_proof(proof, signature, self.key),
                msg=f"index={index}",
            )

    def test_signature_from_another_tree_returns_false(self):
        # Same total, different leaf set: the same-position proof does
        # not rebuild the other tree's root.
        other_history = SealHistory(
            tuple(reversed(self.history.items[:5]))
        )
        other_message, _ = make_history_proof(other_history, 0)
        other_signature = sign_message(other_message, self.key, seed=951)
        _, proof, _ = signed_proof(
            SealHistory(self.history.items[:5]), 0, self.key, seed=952
        )
        self.assertFalse(check_history_proof(proof, other_signature, self.key))

    def test_foreign_key_returns_false(self):
        other_key = make_other_key()
        self.assertNotEqual(other_key.public_key, self.key.public_key)
        _, proof, signature = signed_proof(self.history, 3, self.key)
        self.assertFalse(check_history_proof(proof, signature, other_key))

    def test_seal_must_itself_verify(self):
        # A well-formed proof whose seal is a real seal of another key:
        # verify_seal fails before the signature is even consulted.
        other_key = make_other_key()
        other_history = make_history(other_key, nonces=(301, 302))
        _, foreign = make_history_proof(other_history, 0)
        _, proof, signature = signed_proof(self.history, 0, self.key)
        mixed = dataclasses.replace(proof, seal=foreign.seal)
        self.assertFalse(check_history_proof(mixed, signature, self.key))

    def test_proof_does_not_need_the_full_history(self):
        # The checker takes only the one seal plus digests: build a proof
        # from a history the verifier never holds.
        _, proof, signature = signed_proof(self.history, 2, self.key)
        self.assertTrue(check_history_proof(proof, signature, self.key))


class CheckHistoryProofValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.history = make_history(self.key, nonces=(401, 402, 403))
        _, self.proof, self.signature = signed_proof(
            self.history, 1, self.key
        )

    def _check(self, proof=..., signature=..., key=...):
        return check_history_proof(
            self.proof if proof is ... else proof,
            self.signature if signature is ... else signature,
            self.key if key is ... else key,
        )

    def test_argument_type_errors(self):
        with self.assertRaises(TypeError):
            self._check(proof="proof")
        with self.assertRaises(TypeError):
            self._check(proof=None)
        with self.assertRaises(TypeError):
            self._check(signature="signature")
        with self.assertRaises(TypeError):
            self._check(signature=None)
        with self.assertRaises(TypeError):
            self._check(key="key")
        with self.assertRaises(TypeError):
            self._check(key=None)

    def test_field_type_errors(self):
        good = self.proof
        cases = (
            dataclasses.replace(good, index="1"),
            dataclasses.replace(good, index=True),
            dataclasses.replace(good, total="3"),
            dataclasses.replace(good, total=False),
            dataclasses.replace(good, seal="seal"),
            dataclasses.replace(good, seal=self.history.items[1].signature),
            SealHistoryProof(1, 3, good.seal, list(good.siblings)),
        )
        for bad in cases:
            with self.assertRaises(TypeError, msg=bad):
                self._check(proof=bad)

    def test_total_structure_errors(self):
        good = self.proof
        for total in (0, -1, 2 ** 64):
            with self.assertRaises(ValueError, msg=f"total={total}"):
                self._check(
                    proof=SealHistoryProof(
                        good.index, total, good.seal, good.siblings
                    )
                )

    def test_index_structure_errors(self):
        good = self.proof
        for index in (-1, 3, 4):
            with self.assertRaises(ValueError, msg=f"index={index}"):
                self._check(
                    proof=SealHistoryProof(
                        index, good.total, good.seal, good.siblings
                    )
                )

    def test_path_length_errors(self):
        good = self.proof
        with self.assertRaises(ValueError):
            self._check(
                proof=SealHistoryProof(
                    good.index, good.total, good.seal, ()
                )
            )
        with self.assertRaises(ValueError):
            self._check(
                proof=SealHistoryProof(
                    good.index,
                    good.total,
                    good.seal,
                    good.siblings + (b"z" * 32,),
                )
            )

    def test_path_entry_width_errors(self):
        good = self.proof
        with self.assertRaises(ValueError):
            self._check(
                proof=SealHistoryProof(
                    good.index,
                    good.total,
                    good.seal,
                    (b"x" * 31,) + good.siblings[1:],
                )
            )
        with self.assertRaises(ValueError):
            self._check(
                proof=SealHistoryProof(
                    good.index,
                    good.total,
                    good.seal,
                    (b"x" * 33,) + good.siblings[1:],
                )
            )

    def test_illegal_nested_seal_value_error(self):
        bad = ReportSeal(
            NonceLeakReport((synthetic(1, 10),)),
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
        )
        with self.assertRaises(ValueError):
            self._check(
                proof=SealHistoryProof(
                    self.proof.index,
                    self.proof.total,
                    bad,
                    self.proof.siblings,
                )
            )

    def test_illegal_signature_value_error(self):
        with self.assertRaises(ValueError):
            self._check(
                signature=AggregateSignature(R=0, z=7, signer_ids=(1, 3))
            )
        with self.assertRaises(ValueError):
            self._check(
                signature=AggregateSignature(R=5, z=7, signer_ids=())
            )


if __name__ == "__main__":
    unittest.main()
