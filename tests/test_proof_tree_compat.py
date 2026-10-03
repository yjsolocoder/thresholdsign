"""Refactor-compatibility tests for the audit and seal-history Merkle proofs.

The audit-record proofs (make_proof / make_multi_proof / make_extension)
and the seal-history proofs (make_history_proof / make_history_multi_proof /
make_history_extension) now share one tree-construction and leaf-digest-root
implementation. This module pins the public behavior to fixed expectations:

* GOLDEN holds root messages, per-index paths, multi-proof sibling
  sequences, extension leaf sets and canonical encodings captured from the
  pre-refactor implementation, so identical inputs must keep producing
  byte-identical outputs (roots, leaf digests, sibling order, wire bytes).
* An independent reference tree, written straight from the documented
  tags and pairing rules, recomputes every root and path without touching
  the package's tree code.
* Cross-checks assert that single, multi and extension proofs over the
  same prefix point at the same root, that old signatures and encodings
  still verify, and that the error and tamper behavior is unchanged.
"""

import hashlib
import unittest

from thresholdsign import (
    AuditExtensionProof,
    AuditMultiProof,
    AuditProof,
    SealHistoryExtension,
    SealHistoryMultiProof,
    SealHistoryProof,
    check_extension,
    check_history_extension,
    check_history_multi_proof,
    check_history_proof,
    check_multi_proof,
    check_proof,
    decode_audit_multi_proof,
    decode_audit_proof,
    decode_extension,
    decode_history_extension,
    decode_history_multi_proof,
    decode_history_proof,
    encode_audit_multi_proof,
    encode_audit_proof,
    encode_extension,
    encode_history_extension,
    encode_history_multi_proof,
    encode_history_proof,
    encode_seal,
    make_extension,
    make_history_extension,
    make_history_multi_proof,
    make_history_proof,
    make_multi_proof,
    make_proof,
)

from proof_tree_golden import GOLDEN
from test_audit_chain import make_key as make_audit_key
from test_audit_chain import make_record, sign_message as sign_audit
from test_nonce_reuse import make_key as make_history_key
from test_seal_history import make_history, sign_message as sign_history

SIZES = (1, 2, 3, 5, 7, 13, 27)
MULTI_INDICES = {
    1: [(0,)],
    2: [(0,), (1,), (0, 1)],
    3: [(0,), (2,), (0, 2), (0, 1, 2)],
    5: [(0,), (4,), (1, 3), (0, 2, 4), (1, 2, 3)],
    7: [(0,), (6,), (0, 6), (1, 3, 5), (0, 1, 2, 3, 4, 5, 6)],
    13: [(0,), (12,), (2, 5, 9), (0, 6, 12), tuple(range(13))],
    27: [(0,), (26,), (3, 11, 19), (0, 13, 26), tuple(range(0, 27, 2))],
}
EXTENSIONS = {
    2: [1],
    3: [1, 2],
    5: [1, 2, 4],
    7: [1, 3, 6],
    13: [1, 6, 12],
    27: [1, 13, 26],
}

AUDIT_LEAF_TAG = b"am/l"
AUDIT_NODE_TAG = b"am/n"
AUDIT_ROOT_TAG = b"am/r"
HISTORY_LEAF_TAG = b"sh/l"
HISTORY_NODE_TAG = b"sh/n"
HISTORY_ROOT_TAG = b"sh/r"


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big", signed=False)


def digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def reference_root(leaves, node_tag):
    """Root of the documented pairing tree, rebuilt straight from the spec."""
    current = tuple(leaves)
    while len(current) > 1:
        if len(current) % 2 == 1:
            current = current + current[-1:]
        current = tuple(
            digest(node_tag + current[j] + current[j + 1])
            for j in range(0, len(current), 2)
        )
    return current[0]


def reference_path(leaves, node_tag, index):
    """Sibling digests leaf-to-root per the documented pairing rules."""
    path = []
    position = index
    width = len(leaves)
    level = tuple(leaves)
    while width > 1:
        padded = level if width % 2 == 0 else level + level[-1:]
        path.append(padded[position ^ 1])
        position //= 2
        level = tuple(
            digest(node_tag + padded[j] + padded[j + 1])
            for j in range(0, len(padded), 2)
        )
        width = (width + 1) // 2
    return tuple(path)


def audit_leaf(index, message, audit):
    return digest(
        AUDIT_LEAF_TAG + u64(index) + digest(message) + digest(audit.payload)
    )


def history_leaf(index, seal):
    return digest(HISTORY_LEAF_TAG + u64(index) + digest(encode_seal(seal)))


def unhex(entries):
    return tuple(bytes.fromhex(entry) for entry in entries)


class Fixtures:
    """Deterministic records and histories, identical to the golden capture."""

    audit_key = None
    audit_records = None
    history_key = None
    histories = None

    @classmethod
    def load(cls):
        if cls.audit_key is None:
            cls.audit_key = make_audit_key()
            cls.audit_records = {
                n: tuple(
                    make_record(
                        cls.audit_key,
                        f"message-{i}".encode(),
                        seed=1000 + 10 * i,
                    )
                    for i in range(n)
                )
                for n in SIZES
            }
            cls.history_key = make_history_key()
            cls.histories = {
                n: make_history(
                    cls.history_key,
                    nonces=tuple(100 + 37 * i for i in range(n)),
                )
                for n in SIZES
            }


class AuditGoldenTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Fixtures.load()
        cls.key = Fixtures.audit_key
        cls.records = Fixtures.audit_records

    def test_single_root_and_path_match_golden(self):
        for n in SIZES:
            records = self.records[n]
            leaves = tuple(
                audit_leaf(i, m, a) for i, (m, a) in enumerate(records)
            )
            for index in range(n):
                message, proof = make_proof(records, index)
                golden = GOLDEN["audit"][n]["single"][index]
                self.assertEqual(message.hex(), golden["message"])
                self.assertEqual(
                    [p.hex() for p in proof.p], golden["path"]
                )
                self.assertEqual((proof.i, proof.n), (index, n))
                self.assertEqual(proof.m, records[index][0])
                self.assertEqual(proof.a, records[index][1])
                # Independent recomputation from the documented rules.
                self.assertEqual(
                    message,
                    AUDIT_ROOT_TAG
                    + u64(n)
                    + reference_root(leaves, AUDIT_NODE_TAG),
                )
                self.assertEqual(
                    proof.p, reference_path(leaves, AUDIT_NODE_TAG, index)
                )
                # The single-element tree carries an empty path.
                if n == 1:
                    self.assertEqual(proof.p, ())

    def test_single_proof_still_verifies(self):
        for n in SIZES:
            for index in (0, n - 1):
                message, proof = make_proof(self.records[n], index)
                signature = sign_audit(self.key, message, seed=5000 + index)
                self.assertTrue(check_proof(proof, signature, self.key))

    def test_multi_root_and_siblings_match_golden(self):
        for n in SIZES:
            records = self.records[n]
            for indices in MULTI_INDICES[n]:
                message, proof = make_multi_proof(records, indices)
                golden = GOLDEN["audit"][n]["multi"][indices]
                self.assertEqual(message.hex(), golden["message"])
                self.assertEqual(
                    [s.hex() for s in proof.siblings], golden["siblings"]
                )
                self.assertEqual(proof.indices, tuple(indices))
                self.assertEqual(proof.n, n)
                self.assertEqual(
                    proof.records, tuple(records[i] for i in indices)
                )
                # The multi-proof root statement is the single-proof one.
                single_message, _ = make_proof(records, indices[0])
                self.assertEqual(message, single_message)

    def test_multi_proof_still_verifies(self):
        for n in SIZES:
            for indices in MULTI_INDICES[n]:
                message, proof = make_multi_proof(self.records[n], indices)
                signature = sign_audit(self.key, message, seed=5100)
                self.assertTrue(
                    check_multi_proof(proof, signature, self.key)
                )

    def test_extension_roots_match_golden_and_prefix_proofs(self):
        for n, old_counts in EXTENSIONS.items():
            records = self.records[n]
            for old_n in old_counts:
                old_message, new_message, proof = make_extension(
                    records, old_n
                )
                golden = GOLDEN["audit"][n]["extension"][old_n]
                self.assertEqual(old_message.hex(), golden["old_message"])
                self.assertEqual(new_message.hex(), golden["new_message"])
                self.assertEqual(
                    [leaf.hex() for leaf in proof.leaves], golden["leaves"]
                )
                self.assertEqual(proof.old_n, old_n)
                # Leaf digests are the documented index-bound digests.
                self.assertEqual(
                    proof.leaves,
                    tuple(
                        audit_leaf(i, m, a)
                        for i, (m, a) in enumerate(records)
                    ),
                )
                # The new root is the full set's inclusion-proof root and
                # the old root the prefix's, on the same data.
                full_message, _ = make_proof(records, 0)
                prefix_message, _ = make_proof(records[:old_n], 0)
                self.assertEqual(new_message, full_message)
                self.assertEqual(old_message, prefix_message)

    def test_extension_still_verifies(self):
        for n, old_counts in EXTENSIONS.items():
            for old_n in old_counts:
                old_message, new_message, proof = make_extension(
                    self.records[n], old_n
                )
                old_sig = sign_audit(self.key, old_message, seed=5200)
                new_sig = sign_audit(self.key, new_message, seed=5300)
                self.assertTrue(
                    check_extension(proof, old_sig, new_sig, self.key)
                )

    def test_canonical_encodings_match_golden_and_roundtrip(self):
        message, proof = make_proof(self.records[7], 3)
        blob = encode_audit_proof(proof)
        self.assertEqual(blob.hex(), GOLDEN["audit"]["encode_single"])
        self.assertEqual(encode_audit_proof(decode_audit_proof(blob)), blob)
        self.assertEqual(decode_audit_proof(blob), proof)

        message, proof = make_multi_proof(self.records[13], (2, 5, 9))
        blob = encode_audit_multi_proof(proof)
        self.assertEqual(blob.hex(), GOLDEN["audit"]["encode_multi"])
        self.assertEqual(
            encode_audit_multi_proof(decode_audit_multi_proof(blob)), blob
        )
        self.assertEqual(decode_audit_multi_proof(blob), proof)

        _old, _new, proof = make_extension(self.records[7], 3)
        blob = encode_extension(proof)
        self.assertEqual(blob.hex(), GOLDEN["audit"]["encode_extension"])
        self.assertEqual(encode_extension(decode_extension(blob)), blob)
        self.assertEqual(decode_extension(blob), proof)

    def test_decoded_pre_refactor_proof_still_verifies(self):
        # The golden wire bytes stand in for a persisted pre-refactor
        # proof: decoding must restore a proof that still verifies.
        blob = bytes.fromhex(GOLDEN["audit"]["encode_single"])
        proof = decode_audit_proof(blob)
        message, _ = make_proof(self.records[7], 3)
        signature = sign_audit(self.key, message, seed=5400)
        self.assertTrue(check_proof(proof, signature, self.key))


class HistoryGoldenTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Fixtures.load()
        cls.key = Fixtures.history_key
        cls.histories = Fixtures.histories

    def test_single_root_and_path_match_golden(self):
        for n in SIZES:
            history = self.histories[n]
            leaves = tuple(
                history_leaf(i, seal) for i, seal in enumerate(history.items)
            )
            for index in range(n):
                message, proof = make_history_proof(history, index)
                golden = GOLDEN["history"][n]["single"][index]
                self.assertEqual(message.hex(), golden["message"])
                self.assertEqual(
                    [s.hex() for s in proof.siblings], golden["path"]
                )
                self.assertEqual((proof.index, proof.total), (index, n))
                self.assertEqual(proof.seal, history.items[index])
                self.assertEqual(
                    message,
                    HISTORY_ROOT_TAG
                    + u64(n)
                    + reference_root(leaves, HISTORY_NODE_TAG),
                )
                self.assertEqual(
                    proof.siblings,
                    reference_path(leaves, HISTORY_NODE_TAG, index),
                )
                if n == 1:
                    self.assertEqual(proof.siblings, ())

    def test_single_proof_still_verifies(self):
        for n in SIZES:
            for index in (0, n - 1):
                message, proof = make_history_proof(
                    self.histories[n], index
                )
                signature = sign_history(message, self.key, seed=6000 + index)
                self.assertTrue(
                    check_history_proof(proof, signature, self.key)
                )

    def test_multi_root_and_siblings_match_golden(self):
        for n in SIZES:
            history = self.histories[n]
            for indices in MULTI_INDICES[n]:
                message, proof = make_history_multi_proof(history, indices)
                golden = GOLDEN["history"][n]["multi"][indices]
                self.assertEqual(message.hex(), golden["message"])
                self.assertEqual(
                    [s.hex() for s in proof.siblings], golden["siblings"]
                )
                self.assertEqual(proof.indices, tuple(indices))
                self.assertEqual(proof.total, n)
                self.assertEqual(
                    proof.seals, tuple(history.items[i] for i in indices)
                )
                single_message, _ = make_history_proof(history, indices[0])
                self.assertEqual(message, single_message)

    def test_multi_proof_still_verifies(self):
        for n in SIZES:
            for indices in MULTI_INDICES[n]:
                message, proof = make_history_multi_proof(
                    self.histories[n], indices
                )
                signature = sign_history(message, self.key, seed=6100)
                self.assertTrue(
                    check_history_multi_proof(proof, signature, self.key)
                )

    def test_extension_roots_match_golden_and_prefix_proofs(self):
        for n, old_counts in EXTENSIONS.items():
            history = self.histories[n]
            for old_total in old_counts:
                old_message, new_message, proof = make_history_extension(
                    history, old_total
                )
                golden = GOLDEN["history"][n]["extension"][old_total]
                self.assertEqual(old_message.hex(), golden["old_message"])
                self.assertEqual(new_message.hex(), golden["new_message"])
                self.assertEqual(
                    [leaf.hex() for leaf in proof.leaves], golden["leaves"]
                )
                self.assertEqual(proof.old_total, old_total)
                self.assertEqual(
                    proof.leaves,
                    tuple(
                        history_leaf(i, seal)
                        for i, seal in enumerate(history.items)
                    ),
                )
                full_message, _ = make_history_proof(history, 0)
                prefix_message, _ = make_history_proof(
                    type(history)(history.items[:old_total]), 0
                )
                self.assertEqual(new_message, full_message)
                self.assertEqual(old_message, prefix_message)

    def test_extension_still_verifies(self):
        for n, old_counts in EXTENSIONS.items():
            for old_total in old_counts:
                old_message, new_message, proof = make_history_extension(
                    self.histories[n], old_total
                )
                old_sig = sign_history(old_message, self.key, seed=6200)
                new_sig = sign_history(new_message, self.key, seed=6300)
                self.assertTrue(
                    check_history_extension(
                        proof, old_sig, new_sig, self.key
                    )
                )

    def test_canonical_encodings_match_golden_and_roundtrip(self):
        message, proof = make_history_proof(self.histories[7], 3)
        blob = encode_history_proof(proof)
        self.assertEqual(blob.hex(), GOLDEN["history"]["encode_single"])
        self.assertEqual(
            encode_history_proof(decode_history_proof(blob)), blob
        )
        self.assertEqual(decode_history_proof(blob), proof)

        message, proof = make_history_multi_proof(
            self.histories[13], (2, 5, 9)
        )
        blob = encode_history_multi_proof(proof)
        self.assertEqual(blob.hex(), GOLDEN["history"]["encode_multi"])
        self.assertEqual(
            encode_history_multi_proof(decode_history_multi_proof(blob)),
            blob,
        )
        self.assertEqual(decode_history_multi_proof(blob), proof)

        _old, _new, proof = make_history_extension(self.histories[7], 3)
        blob = encode_history_extension(proof)
        self.assertEqual(blob.hex(), GOLDEN["history"]["encode_extension"])
        self.assertEqual(
            encode_history_extension(decode_history_extension(blob)), blob
        )
        self.assertEqual(decode_history_extension(blob), proof)

    def test_decoded_pre_refactor_proof_still_verifies(self):
        blob = bytes.fromhex(GOLDEN["history"]["encode_single"])
        proof = decode_history_proof(blob)
        message, _ = make_history_proof(self.histories[7], 3)
        signature = sign_history(message, self.key, seed=6400)
        self.assertTrue(check_history_proof(proof, signature, self.key))


class DomainSeparationTest(unittest.TestCase):
    """The shared tree rules must not blur the two proof families."""

    @classmethod
    def setUpClass(cls):
        Fixtures.load()

    def test_root_statements_differ_between_families(self):
        for n in SIZES:
            audit_message, _ = make_proof(Fixtures.audit_records[n], 0)
            history_message, _ = make_history_proof(
                Fixtures.histories[n], 0
            )
            self.assertNotEqual(audit_message, history_message)
            self.assertTrue(audit_message.startswith(AUDIT_ROOT_TAG))
            self.assertTrue(history_message.startswith(HISTORY_ROOT_TAG))

    def test_leaf_and_node_tags_stay_family_specific(self):
        records = Fixtures.audit_records[3]
        history = Fixtures.histories[3]
        audit_leaves = tuple(
            audit_leaf(i, m, a) for i, (m, a) in enumerate(records)
        )
        history_leaves = tuple(
            history_leaf(i, seal) for i, seal in enumerate(history.items)
        )
        self.assertNotEqual(audit_leaves, history_leaves)
        self.assertNotEqual(
            reference_root(audit_leaves, AUDIT_NODE_TAG),
            reference_root(audit_leaves, HISTORY_NODE_TAG),
        )
        # The extension leaf sets keep their family-specific bindings.
        _ao, _an, audit_proof = make_extension(records, 2)
        _ho, _hn, history_proof = make_history_extension(history, 2)
        self.assertEqual(audit_proof.leaves, audit_leaves)
        self.assertEqual(history_proof.leaves, history_leaves)


class TamperAndErrorTest(unittest.TestCase):
    """Structural mismatches stay False; bad shapes keep their exceptions."""

    @classmethod
    def setUpClass(cls):
        Fixtures.load()
        cls.audit_key = Fixtures.audit_key
        cls.history_key = Fixtures.history_key
        cls.records = Fixtures.audit_records[7]
        cls.history = Fixtures.histories[7]

    def test_tampered_single_proof_returns_false(self):
        message, proof = make_proof(self.records, 3)
        signature = sign_audit(self.audit_key, message, seed=7000)
        bad_path = list(proof.p)
        bad_path[0] = bytes([bad_path[0][0] ^ 1]) + bad_path[0][1:]
        tampered = AuditProof(proof.i, proof.n, proof.m, proof.a,
                              tuple(bad_path))
        self.assertFalse(check_proof(tampered, signature, self.audit_key))

        message, proof = make_history_proof(self.history, 3)
        signature = sign_history(message, self.history_key, seed=7001)
        bad_path = list(proof.siblings)
        bad_path[0] = bytes([bad_path[0][0] ^ 1]) + bad_path[0][1:]
        tampered = SealHistoryProof(
            proof.index, proof.total, proof.seal, tuple(bad_path)
        )
        self.assertFalse(
            check_history_proof(tampered, signature, self.history_key)
        )

    def test_tampered_multi_proof_returns_false(self):
        message, proof = make_multi_proof(self.records, (1, 3, 5))
        signature = sign_audit(self.audit_key, message, seed=7002)
        bad = list(proof.siblings)
        bad[0] = bytes([bad[0][0] ^ 1]) + bad[0][1:]
        tampered = AuditMultiProof(
            proof.indices, proof.n, proof.records, tuple(bad)
        )
        self.assertFalse(
            check_multi_proof(tampered, signature, self.audit_key)
        )

        message, proof = make_history_multi_proof(self.history, (1, 3, 5))
        signature = sign_history(message, self.history_key, seed=7003)
        bad = list(proof.siblings)
        bad[0] = bytes([bad[0][0] ^ 1]) + bad[0][1:]
        tampered = SealHistoryMultiProof(
            proof.indices, proof.total, proof.seals, tuple(bad)
        )
        self.assertFalse(
            check_history_multi_proof(tampered, signature, self.history_key)
        )

    def test_tampered_extension_returns_false(self):
        old_message, new_message, proof = make_extension(self.records, 3)
        old_sig = sign_audit(self.audit_key, old_message, seed=7004)
        new_sig = sign_audit(self.audit_key, new_message, seed=7005)
        bad = list(proof.leaves)
        bad[1] = bytes([bad[1][0] ^ 1]) + bad[1][1:]
        tampered = AuditExtensionProof(proof.old_n, tuple(bad))
        self.assertFalse(
            check_extension(tampered, old_sig, new_sig, self.audit_key)
        )

        old_message, new_message, proof = make_history_extension(
            self.history, 3
        )
        old_sig = sign_history(old_message, self.history_key, seed=7006)
        new_sig = sign_history(new_message, self.history_key, seed=7007)
        bad = list(proof.leaves)
        bad[1] = bytes([bad[1][0] ^ 1]) + bad[1][1:]
        tampered = SealHistoryExtension(proof.old_total, tuple(bad))
        self.assertFalse(
            check_history_extension(
                tampered, old_sig, new_sig, self.history_key
            )
        )

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            make_proof(self.records, True)
        with self.assertRaises(TypeError):
            make_history_proof(self.history, True)
        with self.assertRaises(TypeError):
            make_multi_proof(self.records, [0, 1])
        with self.assertRaises(TypeError):
            make_history_multi_proof(self.history, [0, 1])
        with self.assertRaises(TypeError):
            make_multi_proof(self.records, (0, True))
        with self.assertRaises(TypeError):
            make_extension(self.records, True)
        with self.assertRaises(TypeError):
            make_history_extension(self.history, True)
        with self.assertRaises(TypeError):
            make_history_proof(tuple(self.history.items), 0)

    def test_value_errors(self):
        with self.assertRaises(ValueError):
            make_proof((), 0)
        with self.assertRaises(ValueError):
            make_proof(self.records, 7)
        with self.assertRaises(ValueError):
            make_multi_proof(self.records, ())
        with self.assertRaises(ValueError):
            make_multi_proof(self.records, (3, 3))
        with self.assertRaises(ValueError):
            make_multi_proof(self.records, (5, 2))
        with self.assertRaises(ValueError):
            make_multi_proof(self.records, (7,))
        with self.assertRaises(ValueError):
            make_extension(self.records, 0)
        with self.assertRaises(ValueError):
            make_extension(self.records, 7)
        with self.assertRaises(ValueError):
            make_history_extension(self.history, 0)
        with self.assertRaises(ValueError):
            make_history_extension(self.history, 7)

    def test_structural_value_errors_on_check(self):
        message, proof = make_proof(self.records, 3)
        signature = sign_audit(self.audit_key, message, seed=7008)
        # A path of the wrong length or entry width is a ValueError.
        with self.assertRaises(ValueError):
            check_proof(
                AuditProof(proof.i, proof.n, proof.m, proof.a, proof.p[:-1]),
                signature,
                self.audit_key,
            )
        with self.assertRaises(ValueError):
            check_proof(
                AuditProof(proof.i, proof.n, proof.m, proof.a,
                           (b"short",) + proof.p[1:]),
                signature,
                self.audit_key,
            )
        # Records not pairing one-to-one with indices is a ValueError.
        multi_message, multi = make_multi_proof(self.records, (1, 3, 5))
        with self.assertRaises(ValueError):
            check_multi_proof(
                AuditMultiProof(
                    multi.indices, multi.n, multi.records[:-1],
                    multi.siblings,
                ),
                signature,
                self.audit_key,
            )
        # A sibling count that does not match n and indices is a ValueError.
        with self.assertRaises(ValueError):
            check_multi_proof(
                AuditMultiProof(
                    multi.indices, multi.n, multi.records,
                    multi.siblings + (b"x" * 32,),
                ),
                signature,
                self.audit_key,
            )


if __name__ == "__main__":
    unittest.main()
