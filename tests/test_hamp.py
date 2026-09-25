"""Tests for compact multi-bundle Merkle membership proofs over the
non-empty order-preserving archive of whole HDSC archive proof bundles:
HAMP / make_hamp / check_hamp."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    HAMP,
    HDSCArchiveProof,
    HDSCArchiveProofBundle,
    HDSCArchiveProofBundleArchive,
    check_hamp,
    encode_hdsc_archive_proof_bundle,
    make_hamp,
)

from test_audit_chain import sign_message
from test_audit_extension_proof_bundle_codec import make_other_key
from test_nonce_reuse import make_key
from test_hdsc_archive_proof_bundle_codec import signed_root_bundle
from test_hdsc_proof_bundle_archive import (
    build_bundles,
    make_archive as make_proof_bundle_archive,
)

LEAF_TAG = b"hamp/l"
NODE_TAG = b"hamp/n"
ROOT_TAG = b"hamp/r"

DUMMY_OUTER_SIGNATURE = AggregateSignature(R=5, z=7, signer_ids=(1, 3))


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big", signed=False)


def digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# Distinct (source indices, seed) combinations so each archive proof
# bundle encodes differently at every position.
COMBOS = (
    ((0,), 8100),
    ((1, 2), 8200),
    ((0, 1, 2), 8300),
    ((0, 2), 8400),
    ((1,), 8500),
    ((0, 1), 8600),
    ((2,), 8700),
    ((1, 2), 8800),
)


def source_archive(key):
    """A properly outer-signed HDSCProofBundleArchive to prove against."""
    return make_proof_bundle_archive(build_bundles(key), key, seed=6400)


def bundles_of_size(n, key, seed_base=9000):
    """Build ``n`` distinct structurally legal, key-verifying archive proof bundles."""
    source = source_archive(key)
    return tuple(
        signed_root_bundle(
            source,
            COMBOS[position % len(COMBOS)][0],
            key,
            seed=seed_base + COMBOS[position % len(COMBOS)][1] + position * 37,
        )
        for position in range(n)
    )


def archive_of_size(n, key, seed_base=9100):
    """An archive of ``n`` distinct bundles with a placeholder outer signature."""
    return HDSCArchiveProofBundleArchive(
        bundles_of_size(n, key, seed_base=seed_base),
        DUMMY_OUTER_SIGNATURE,
    )


def independent_tree(bundles):
    """Build leaf level, internal levels (odd tail duplicated) and root."""
    leaves = tuple(
        digest(
            LEAF_TAG + u64(i) + digest(encode_hdsc_archive_proof_bundle(bundle))
        )
        for i, bundle in enumerate(bundles)
    )
    levels = [leaves]
    current = leaves
    while len(current) > 1:
        seq = list(current)
        if len(seq) % 2 == 1:
            seq.append(seq[-1])
        current = tuple(
            digest(NODE_TAG + seq[j] + seq[j + 1])
            for j in range(0, len(seq), 2)
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


def signed_proof(archive, indices, key, *, seed=9300):
    """Return (proof, root signature) for a threshold-signed statement."""
    message, proof = make_hamp(archive, indices)
    signature = sign_message(key, message, seed=seed + sum(indices))
    return proof, signature


class HAMPDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(HAMP)],
            ["indices", "total", "bundles", "siblings"],
        )
        key = make_key()
        bundles = bundles_of_size(2, key)
        siblings = (b"s" * 32,)
        proof = HAMP((1,), 3, bundles, siblings)
        self.assertEqual(
            (proof.indices, proof.total, proof.bundles, proof.siblings),
            ((1,), 3, bundles, siblings),
        )

    def test_frozen_value_equality_and_hash(self):
        key = make_key()
        bundles = bundles_of_size(2, key, seed_base=9400)
        siblings = (b"s" * 32, b"t" * 32)
        proof = HAMP((1, 3), 4, bundles, siblings)
        same = HAMP(
            indices=(1, 3), total=4, bundles=bundles, siblings=siblings
        )
        self.assertEqual(proof, same)
        self.assertEqual(hash(proof), hash(same))
        for changed in (
            HAMP((1, 2), 4, bundles, siblings),
            HAMP((1, 3), 5, bundles, siblings),
            HAMP((1, 3), 4, (bundles[0], bundles[0]), siblings),
            HAMP((1, 3), 4, bundles, (b"s" * 32,)),
        ):
            self.assertNotEqual(proof, changed)
        with self.assertRaises(FrozenInstanceError):
            proof.total = 5

    def test_construction_does_not_validate(self):
        # A plain value: out-of-range indices, non-tuple fields and
        # non-bundle values all construct; the maker and checker reject them.
        key = make_key()
        bundles = bundles_of_size(1, key, seed_base=9450)
        HAMP((9,), 1, bundles, ())
        HAMP((0,), 0, ("not-a-bundle",), b"x")
        HAMP((), 3, bundles, (b"",))


class MakeHAMPTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(8, self.key, seed_base=9500)

    def _archive_of_size(self, n):
        return HDSCArchiveProofBundleArchive(
            self.archive.items[:n], self.archive.signature
        )

    def test_statement_layout_for_every_size_and_subset(self):
        for n in range(1, 9):
            archive = self._archive_of_size(n)
            root = independent_tree(archive.items)[-1][0]
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                message, proof = make_hamp(archive, indices)
                self.assertTrue(message.startswith(ROOT_TAG))
                self.assertEqual(
                    message[len(ROOT_TAG):len(ROOT_TAG) + 8], u64(n)
                )
                self.assertEqual(message[len(ROOT_TAG) + 8:], root)
                self.assertEqual(len(message), len(ROOT_TAG) + 8 + 32)
                self.assertEqual(proof.total, n)
                self.assertTrue(all(len(s) == 32 for s in proof.siblings))

    def test_bundles_pair_one_to_one_with_indices(self):
        indices = (0, 2, 4)
        _message, proof = make_hamp(self.archive, indices)
        self.assertEqual(proof.indices, indices)
        self.assertEqual(
            proof.bundles, tuple(self.archive.items[i] for i in indices)
        )
        self.assertIs(proof.bundles[1], self.archive.items[2])

    def test_siblings_match_independent_builder(self):
        for n in range(1, 9):
            archive = self._archive_of_size(n)
            levels = independent_tree(archive.items)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                _message, proof = make_hamp(archive, indices)
                self.assertEqual(
                    proof.siblings,
                    independent_siblings(levels, indices),
                    msg=f"n={n} indices={indices}",
                )

    def test_proving_every_bundle_needs_no_siblings(self):
        for n in range(1, 9):
            archive = self._archive_of_size(n)
            _message, proof = make_hamp(archive, tuple(range(n)))
            self.assertEqual(proof.siblings, ())

    def test_deterministic(self):
        message, proof = make_hamp(self.archive, (0, 2, 4))
        message2, proof2 = make_hamp(self.archive, (0, 2, 4))
        self.assertEqual(message, message2)
        self.assertEqual(proof, proof2)

    def test_root_is_order_and_content_bound(self):
        message, _ = make_hamp(self.archive, (0, 2))
        reordered = HDSCArchiveProofBundleArchive(
            (self.archive.items[1], self.archive.items[0])
            + self.archive.items[2:],
            self.archive.signature,
        )
        self.assertNotEqual(message, make_hamp(reordered, (0, 2))[0])
        shortened = self._archive_of_size(4)
        self.assertNotEqual(message, make_hamp(shortened, (0, 2))[0])

    def test_archive_outer_signature_is_not_consulted(self):
        # The proof comes from the bundles alone: an archive with no
        # usable outer signature builds the same statement.
        unsigned = HDSCArchiveProofBundleArchive(
            self.archive.items, "not-a-signature"
        )
        self.assertEqual(
            make_hamp(unsigned, (0, 2))[0],
            make_hamp(self.archive, (0, 2))[0],
        )

    def test_non_archive_type_error(self):
        for bad in (
            tuple(self.archive.items),
            list(self.archive.items),
            "archive",
            None,
            42,
            b"x",
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                make_hamp(bad, (0,))

    def test_indices_type_errors(self):
        for bad in ([0, 2], (True,), ("0",), (1.0,), (None,)):
            with self.assertRaises(TypeError, msg=f"indices={bad!r}"):
                make_hamp(self.archive, bad)

    def test_empty_unsorted_duplicate_and_out_of_range_raise_value_error(self):
        with self.assertRaises(ValueError):
            make_hamp(self.archive, ())
        empty = HDSCArchiveProofBundleArchive((), self.archive.signature)
        with self.assertRaises(ValueError):
            make_hamp(empty, (0,))
        for bad in ((2, 1), (1, 1), (-1,), (8,), (0, 8), (3, 3, 4)):
            with self.assertRaises(ValueError, msg=f"indices={bad}"):
                make_hamp(self.archive, bad)

    def test_non_tuple_items_type_error(self):
        archive = HDSCArchiveProofBundleArchive(
            list(self.archive.items), self.archive.signature
        )
        with self.assertRaises(TypeError):
            make_hamp(archive, (0,))

    def test_non_bundle_element_type_error(self):
        archive = HDSCArchiveProofBundleArchive(
            ("not-a-bundle",) + self.archive.items[1:],
            self.archive.signature,
        )
        with self.assertRaises(TypeError):
            make_hamp(archive, (0,))

    def test_illegal_nested_bundle_value_error(self):
        bad_bundle = HDSCArchiveProofBundle(
            HDSCArchiveProof(indices=(), total=0, bundles=(), siblings=()),
            DUMMY_OUTER_SIGNATURE,
        )
        archive = HDSCArchiveProofBundleArchive(
            (bad_bundle,) + self.archive.items[1:],
            self.archive.signature,
        )
        with self.assertRaises(ValueError):
            make_hamp(archive, (0,))


class CheckHAMPTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(8, self.key, seed_base=9600)

    def test_signed_proofs_verify(self):
        cases = (
            (1, (0,)),
            (2, (0, 1)),
            (3, (0, 2)),
            (4, (1, 3)),
            (5, (0, 2, 4)),
            (6, (3, 5)),
            (7, (0, 6)),
            (8, (0, 2, 4, 6)),
            (8, tuple(range(8))),
        )
        for n, indices in cases:
            archive = HDSCArchiveProofBundleArchive(
                self.archive.items[:n], self.archive.signature
            )
            proof, signature = signed_proof(archive, indices, self.key)
            self.assertTrue(
                check_hamp(proof, signature, self.key),
                msg=f"n={n} indices={indices}",
            )

    def test_one_signature_covers_every_subset(self):
        archive = HDSCArchiveProofBundleArchive(
            self.archive.items[:5], self.archive.signature
        )
        message, _ = make_hamp(archive, (0,))
        signature = sign_message(self.key, message, seed=9750)
        for mask in range(1, 1 << 5):
            indices = tuple(i for i in range(5) if mask & (1 << i))
            _statement, proof = make_hamp(archive, indices)
            self.assertTrue(
                check_hamp(proof, signature, self.key),
                msg=f"indices={indices}",
            )

    def test_tampered_bundles_indices_and_siblings_return_false(self):
        indices = (0, 2, 4)
        proof, signature = signed_proof(self.archive, indices, self.key)
        swapped = HAMP(
            proof.indices,
            proof.total,
            (proof.bundles[1], proof.bundles[0], proof.bundles[2]),
            proof.siblings,
        )
        self.assertFalse(check_hamp(swapped, signature, self.key))
        moved = HAMP(
            (0, 2, 5), proof.total, proof.bundles, proof.siblings
        )
        self.assertFalse(check_hamp(moved, signature, self.key))
        damaged = HAMP(
            proof.indices,
            proof.total,
            proof.bundles,
            (b"\x00" * 32,) + proof.siblings[1:],
        )
        self.assertFalse(check_hamp(damaged, signature, self.key))

    def test_missing_extra_and_misaligned_siblings_return_false(self):
        indices = (0, 3)
        proof, signature = signed_proof(self.archive, indices, self.key)
        self.assertGreater(len(proof.siblings), 1)
        short = HAMP(
            proof.indices, proof.total, proof.bundles, proof.siblings[:-1]
        )
        self.assertFalse(check_hamp(short, signature, self.key))
        long = HAMP(
            proof.indices,
            proof.total,
            proof.bundles,
            proof.siblings + (b"x" * 32,),
        )
        self.assertFalse(check_hamp(long, signature, self.key))
        rotated = HAMP(
            proof.indices,
            proof.total,
            proof.bundles,
            proof.siblings[1:] + proof.siblings[:1],
        )
        self.assertFalse(check_hamp(rotated, signature, self.key))

    def test_bundle_count_mismatch_returns_false(self):
        indices = (0, 2, 4)
        proof, signature = signed_proof(self.archive, indices, self.key)
        fewer = HAMP(
            proof.indices, proof.total, proof.bundles[:2], proof.siblings
        )
        self.assertFalse(check_hamp(fewer, signature, self.key))
        more = HAMP(
            proof.indices,
            proof.total,
            proof.bundles + (proof.bundles[0],),
            proof.siblings,
        )
        self.assertFalse(check_hamp(more, signature, self.key))

    def test_wrong_signature_and_wrong_key_return_false(self):
        indices = (0, 2)
        proof, signature = signed_proof(self.archive, indices, self.key)
        # The root statement is index-independent over one archive, so the
        # wrong signature must come from a different archive's statement.
        shortened = HDSCArchiveProofBundleArchive(
            self.archive.items[:4], self.archive.signature
        )
        other_message, _ = make_hamp(shortened, (0, 2))
        other_signature = sign_message(self.key, other_message, seed=9701)
        self.assertFalse(check_hamp(proof, other_signature, self.key))
        self.assertFalse(
            check_hamp(proof, signature, make_other_key())
        )

    def test_unverifying_nested_bundle_returns_false(self):
        indices = (0, 2)
        proof, signature = signed_proof(self.archive, indices, self.key)
        foreign = signed_root_bundle(
            source_archive(make_other_key()), (0,), make_other_key(), seed=9800
        )
        mixed = HAMP(
            proof.indices,
            proof.total,
            (foreign, proof.bundles[1]),
            proof.siblings,
        )
        self.assertFalse(check_hamp(mixed, signature, self.key))

    def test_type_errors(self):
        proof, signature = signed_proof(self.archive, (0, 2), self.key)
        with self.assertRaises(TypeError):
            check_hamp("not-a-proof", signature, self.key)
        with self.assertRaises(TypeError):
            check_hamp(proof, "not-a-signature", self.key)
        for bad in (
            HAMP([0, 2], 8, proof.bundles, proof.siblings),
            HAMP((0, 2), "8", proof.bundles, proof.siblings),
            HAMP((0, 2), True, proof.bundles, proof.siblings),
            HAMP((0, True), 8, proof.bundles, proof.siblings),
            HAMP((0, 2), 8, list(proof.bundles), proof.siblings),
            HAMP((0, 2), 8, proof.bundles, list(proof.siblings)),
            HAMP((0, 2), 8, ("not-a-bundle",) * 2, proof.siblings),
            HAMP((0, 2), 8, proof.bundles, (b"x" * 32, 7)),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                check_hamp(bad, signature, self.key)

    def test_structure_value_errors(self):
        proof, signature = signed_proof(self.archive, (0, 2), self.key)
        for bad in (
            HAMP((0, 2), 0, proof.bundles, proof.siblings),
            HAMP((), 8, (), ()),
            HAMP((2, 0), 8, proof.bundles, proof.siblings),
            HAMP((1, 1), 8, proof.bundles, proof.siblings),
            HAMP((0, 8), 8, proof.bundles, proof.siblings),
            HAMP((0, 2), 8, proof.bundles, (b"short",)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                check_hamp(bad, signature, self.key)


if __name__ == "__main__":
    unittest.main()
