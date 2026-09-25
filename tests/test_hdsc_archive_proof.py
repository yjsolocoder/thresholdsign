"""Tests for compact multi-bundle Merkle membership proofs over the
non-empty order-preserving archive of whole HDSC proof bundles:
HDSCArchiveProof / make_hdsc_archive_proof / check_hdsc_archive_proof."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    HDSCArchiveProof,
    HDSCProof,
    HDSCProofBundle,
    HDSCProofBundleArchive,
    check_hdsc_archive_proof,
    encode_hdsc_proof_bundle,
    hdsc_proof_bundle_archive_message,
    make_hdsc_archive_proof,
)

from test_audit_chain import sign_message
from test_audit_extension_proof_bundle_codec import make_other_key
from test_nonce_reuse import FIELD_PRIME, make_key
from test_hdsc_proof_bundle_archive import make_signed_bundle

LEAF_TAG = b"ts/hdscba/l1"
NODE_TAG = b"ts/hdscba/n1"
ROOT_TAG = b"ts/hdscba/r1"

DUMMY_OUTER_SIGNATURE = AggregateSignature(R=5, z=7, signer_ids=(1, 3))


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big", signed=False)


def digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# Distinct (chain size, indices) combinations so each bundle encodes
# differently at every position.
COMBOS = (
    (8, (0, 2)),
    (7, (1, 3)),
    (6, (3, 5)),
    (5, (0, 2, 4)),
    (8, (1, 7)),
    (7, (0, 6)),
    (6, (2, 4)),
    (5, (1, 3)),
)


def bundles_of_size(n, key, seed_base=7000):
    """Build ``n`` distinct structurally legal, key-verifying bundles."""
    return tuple(
        make_signed_bundle(
            key,
            COMBOS[position % len(COMBOS)][0],
            COMBOS[position % len(COMBOS)][1],
            seed=seed_base + position * 37,
        )
        for position in range(n)
    )


def archive_of_size(n, key, seed_base=7100):
    """An archive of ``n`` distinct bundles with a placeholder outer signature."""
    return HDSCProofBundleArchive(
        bundles_of_size(n, key, seed_base=seed_base),
        DUMMY_OUTER_SIGNATURE,
    )


def independent_tree(bundles):
    """Build leaf level, internal levels (odd tail duplicated) and root."""
    leaves = tuple(
        digest(LEAF_TAG + u64(i) + digest(encode_hdsc_proof_bundle(bundle)))
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


def signed_proof(archive, indices, key, *, seed=7300):
    """Return (proof, root signature) for a threshold-signed statement."""
    message, proof = make_hdsc_archive_proof(archive, indices)
    signature = sign_message(key, message, seed=seed + sum(indices))
    return proof, signature


class HDSCArchiveProofDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(HDSCArchiveProof)],
            ["indices", "total", "bundles", "siblings"],
        )
        key = make_key()
        bundles = bundles_of_size(2, key)
        siblings = (b"s" * 32,)
        proof = HDSCArchiveProof((1,), 3, bundles, siblings)
        self.assertEqual(
            (proof.indices, proof.total, proof.bundles, proof.siblings),
            ((1,), 3, bundles, siblings),
        )

    def test_frozen_value_equality_and_hash(self):
        key = make_key()
        bundles = bundles_of_size(2, key, seed_base=7400)
        siblings = (b"s" * 32, b"t" * 32)
        proof = HDSCArchiveProof((1, 3), 4, bundles, siblings)
        same = HDSCArchiveProof(
            indices=(1, 3), total=4, bundles=bundles, siblings=siblings
        )
        self.assertEqual(proof, same)
        self.assertEqual(hash(proof), hash(same))
        for changed in (
            HDSCArchiveProof((1, 2), 4, bundles, siblings),
            HDSCArchiveProof((1, 3), 5, bundles, siblings),
            HDSCArchiveProof((1, 3), 4, (bundles[0], bundles[0]), siblings),
            HDSCArchiveProof((1, 3), 4, bundles, (b"s" * 32,)),
        ):
            self.assertNotEqual(proof, changed)
        with self.assertRaises(FrozenInstanceError):
            proof.total = 5

    def test_construction_does_not_validate(self):
        # A plain value: out-of-range indices, non-tuple fields and
        # non-bundle values all construct; the maker and checker reject them.
        key = make_key()
        bundles = bundles_of_size(1, key, seed_base=7450)
        HDSCArchiveProof((9,), 1, bundles, ())
        HDSCArchiveProof((0,), 0, ("not-a-bundle",), b"x")
        HDSCArchiveProof((), 3, bundles, (b"",))


class MakeHDSCArchiveProofTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(8, self.key, seed_base=7500)

    def _archive_of_size(self, n):
        return HDSCProofBundleArchive(
            self.archive.items[:n], self.archive.signature
        )

    def test_statement_layout_for_every_size_and_subset(self):
        for n in range(1, 9):
            archive = self._archive_of_size(n)
            root = independent_tree(archive.items)[-1][0]
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                message, proof = make_hdsc_archive_proof(archive, indices)
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
        _message, proof = make_hdsc_archive_proof(self.archive, indices)
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
                _message, proof = make_hdsc_archive_proof(archive, indices)
                self.assertEqual(
                    proof.siblings,
                    independent_siblings(levels, indices),
                    msg=f"n={n} indices={indices}",
                )

    def test_proving_every_bundle_needs_no_siblings(self):
        for n in range(1, 9):
            archive = self._archive_of_size(n)
            _message, proof = make_hdsc_archive_proof(
                archive, tuple(range(n))
            )
            self.assertEqual(proof.siblings, ())

    def test_deterministic(self):
        message, proof = make_hdsc_archive_proof(self.archive, (0, 2, 4))
        message2, proof2 = make_hdsc_archive_proof(self.archive, (0, 2, 4))
        self.assertEqual(message, message2)
        self.assertEqual(proof, proof2)

    def test_root_is_order_and_content_bound(self):
        message, _ = make_hdsc_archive_proof(self.archive, (0, 2))
        reordered = HDSCProofBundleArchive(
            (self.archive.items[1], self.archive.items[0])
            + self.archive.items[2:],
            self.archive.signature,
        )
        self.assertNotEqual(
            message, make_hdsc_archive_proof(reordered, (0, 2))[0]
        )
        shortened = self._archive_of_size(4)
        self.assertNotEqual(
            message, make_hdsc_archive_proof(shortened, (0, 2))[0]
        )

    def test_archive_outer_signature_is_not_consulted(self):
        # The proof comes from the bundles alone: an archive with no
        # usable outer signature builds the same statement.
        unsigned = HDSCProofBundleArchive(
            self.archive.items, "not-a-signature"
        )
        self.assertEqual(
            make_hdsc_archive_proof(unsigned, (0, 2))[0],
            make_hdsc_archive_proof(self.archive, (0, 2))[0],
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
                make_hdsc_archive_proof(bad, (0,))

    def test_indices_type_errors(self):
        for bad in ([0, 2], (True,), ("0",), (1.0,), (None,)):
            with self.assertRaises(TypeError, msg=f"indices={bad!r}"):
                make_hdsc_archive_proof(self.archive, bad)

    def test_empty_unsorted_duplicate_and_out_of_range_raise_value_error(self):
        with self.assertRaises(ValueError):
            make_hdsc_archive_proof(self.archive, ())
        empty = HDSCProofBundleArchive((), self.archive.signature)
        with self.assertRaises(ValueError):
            make_hdsc_archive_proof(empty, (0,))
        for bad in ((2, 1), (1, 1), (-1,), (8,), (0, 8), (3, 3, 4)):
            with self.assertRaises(ValueError, msg=f"indices={bad}"):
                make_hdsc_archive_proof(self.archive, bad)

    def test_non_tuple_items_value_error(self):
        archive = HDSCProofBundleArchive(
            list(self.archive.items), self.archive.signature
        )
        with self.assertRaises(TypeError):
            make_hdsc_archive_proof(archive, (0,))

    def test_non_bundle_element_type_error(self):
        archive = HDSCProofBundleArchive(
            ("not-a-bundle",) + self.archive.items[1:],
            self.archive.signature,
        )
        with self.assertRaises(TypeError):
            make_hdsc_archive_proof(archive, (0,))

    def test_illegal_nested_bundle_value_error(self):
        bad_bundle = HDSCProofBundle(
            HDSCProof(indices=(), total=0, seals=(), siblings=()),
            DUMMY_OUTER_SIGNATURE,
        )
        archive = HDSCProofBundleArchive(
            (bad_bundle,) + self.archive.items[1:],
            self.archive.signature,
        )
        with self.assertRaises(ValueError):
            make_hdsc_archive_proof(archive, (0,))


class CheckHDSCArchiveProofTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(8, self.key, seed_base=7600)

    def _archive_of_size(self, n):
        return HDSCProofBundleArchive(
            self.archive.items[:n], self.archive.signature
        )

    def test_honest_proofs_verify_for_every_size_and_subset(self):
        for n in range(1, 9):
            archive = self._archive_of_size(n)
            message, _ = make_hdsc_archive_proof(archive, (0,))
            signature = sign_message(self.key, message, seed=7700 + n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                _msg, proof = make_hdsc_archive_proof(archive, indices)
                self.assertTrue(
                    check_hdsc_archive_proof(proof, signature, self.key),
                    msg=f"n={n} indices={indices}",
                )

    def test_single_bundle_archive_verifies_with_empty_siblings(self):
        archive = self._archive_of_size(1)
        proof, signature = signed_proof(archive, (0,), self.key, seed=7800)
        self.assertEqual(proof.siblings, ())
        self.assertTrue(
            check_hdsc_archive_proof(proof, signature, self.key)
        )

    def test_one_signature_covers_every_subset(self):
        archive = self._archive_of_size(5)
        message, _ = make_hdsc_archive_proof(archive, (1,))
        signature = sign_message(self.key, message, seed=7900)
        for indices in (
            (0,),
            (4,),
            (0, 4),
            (1, 2, 3),
            (0, 1, 2, 3, 4),
        ):
            _m, proof = make_hdsc_archive_proof(archive, indices)
            self.assertTrue(
                check_hdsc_archive_proof(proof, signature, self.key),
                msg=f"indices={indices}",
            )

    def test_works_over_a_fully_outer_signed_archive(self):
        # End to end: the archive carries a genuine outer signature; the
        # membership proof neither needs nor re-checks it, but every
        # disclosed bundle still verifies and the root signature checks.
        items = self.archive.items
        outer_message = hdsc_proof_bundle_archive_message(
            items, self.key.public_key
        )
        outer_signature = sign_message(
            self.key, outer_message, seed=7950
        )
        archive = HDSCProofBundleArchive(items, outer_signature)
        proof, signature = signed_proof(
            archive, (1, 4, 6), self.key, seed=7951
        )
        self.assertTrue(
            check_hdsc_archive_proof(proof, signature, self.key)
        )

    def test_tampered_bundle_returns_false(self):
        proof, signature = signed_proof(
            self.archive, (1, 2), self.key, seed=8000
        )
        bad = dataclasses.replace(
            proof, bundles=(self.archive.items[0],) + proof.bundles[1:]
        )
        self.assertFalse(
            check_hdsc_archive_proof(bad, signature, self.key)
        )

    def test_swapped_bundles_return_false(self):
        proof, signature = signed_proof(
            self.archive, (1, 2), self.key, seed=8100
        )
        swapped = (proof.bundles[1], proof.bundles[0])
        bad = dataclasses.replace(proof, bundles=swapped)
        self.assertFalse(
            check_hdsc_archive_proof(bad, signature, self.key)
        )

    def test_changed_total_returns_false_when_shape_still_fits(self):
        # n=5 -> n=6 keeps the same depth and sibling count for indices
        # (1, 3), so the proof stays structurally legal but rebuilds wrong.
        archive = self._archive_of_size(5)
        _message, proof = make_hdsc_archive_proof(archive, (1, 3))
        signature = sign_message(self.key, _message, seed=8200)
        bad = dataclasses.replace(proof, total=6)
        self.assertEqual(len(bad.siblings), 3)
        self.assertFalse(
            check_hdsc_archive_proof(bad, signature, self.key)
        )

    def test_flipped_sibling_returns_false(self):
        proof, signature = signed_proof(
            self.archive, (0, 2), self.key, seed=8300
        )
        self.assertTrue(proof.siblings)
        flipped = bytearray(proof.siblings[0])
        flipped[0] ^= 1
        bad = dataclasses.replace(
            proof, siblings=(bytes(flipped),) + proof.siblings[1:]
        )
        self.assertFalse(
            check_hdsc_archive_proof(bad, signature, self.key)
        )

    def test_sibling_order_matters(self):
        proof, signature = signed_proof(
            self.archive, (0, 2), self.key, seed=8400
        )
        self.assertGreaterEqual(len(proof.siblings), 2)
        reordered = proof.siblings[1::-1] + proof.siblings[2:]
        bad = dataclasses.replace(proof, siblings=reordered)
        self.assertFalse(
            check_hdsc_archive_proof(bad, signature, self.key)
        )

    def test_missing_sibling_returns_false(self):
        proof, signature = signed_proof(
            self.archive, (0, 2, 4), self.key, seed=8500
        )
        bad = dataclasses.replace(proof, siblings=proof.siblings[:-1])
        self.assertFalse(
            check_hdsc_archive_proof(bad, signature, self.key)
        )

    def test_extra_sibling_returns_false(self):
        proof, signature = signed_proof(
            self.archive, (0, 2, 4), self.key, seed=8600
        )
        bad = dataclasses.replace(
            proof, siblings=proof.siblings + (b"x" * 32,)
        )
        self.assertFalse(
            check_hdsc_archive_proof(bad, signature, self.key)
        )

    def test_bundle_count_mismatch_returns_false(self):
        proof, signature = signed_proof(
            self.archive, (1, 2), self.key, seed=8700
        )
        for bad_bundles in (
            (),
            proof.bundles[:1],
            proof.bundles + proof.bundles[:1],
        ):
            bad = dataclasses.replace(proof, bundles=bad_bundles)
            self.assertFalse(
                check_hdsc_archive_proof(bad, signature, self.key),
                msg=f"bundles={len(bad_bundles)}",
            )

    def test_tampered_inner_root_signature_returns_false(self):
        proof, signature = signed_proof(
            self.archive, (0, 2), self.key, seed=8800
        )
        inner = proof.bundles[0].signature
        tampered_inner = AggregateSignature(
            R=inner.R,
            z=inner.z,
            signer_ids=inner.signer_ids[:-1]
            + (inner.signer_ids[-1] ^ 0xFF,),
        )
        bad_bundle = HDSCProofBundle(proof.bundles[0].proof, tampered_inner)
        bad = dataclasses.replace(
            proof, bundles=(bad_bundle,) + proof.bundles[1:]
        )
        self.assertFalse(
            check_hdsc_archive_proof(bad, signature, self.key)
        )

    def test_bad_signature_returns_false(self):
        proof, signature = signed_proof(
            self.archive, (0, 2, 4), self.key, seed=8900
        )
        bad_sig = AggregateSignature(
            R=signature.R,
            z=(signature.z + 1) % FIELD_PRIME,
            signer_ids=signature.signer_ids,
        )
        self.assertFalse(
            check_hdsc_archive_proof(proof, bad_sig, self.key)
        )

    def test_tampered_signature_returns_false(self):
        proof, signature = signed_proof(
            self.archive, (0, 2, 4), self.key, seed=9000
        )
        tampered = AggregateSignature(
            R=signature.R,
            z=signature.z,
            signer_ids=signature.signer_ids[:-1]
            + (signature.signer_ids[-1] ^ 0xFF,),
        )
        self.assertFalse(
            check_hdsc_archive_proof(proof, tampered, self.key)
        )

    def test_signature_from_another_tree_returns_false(self):
        _message, proof = make_hdsc_archive_proof(self.archive, (0, 2))
        other_archive = HDSCProofBundleArchive(
            tuple(reversed(self.archive.items[:5])),
            self.archive.signature,
        )
        other_message, _other = make_hdsc_archive_proof(
            other_archive, (0, 2)
        )
        other_signature = sign_message(self.key, other_message, seed=9100)
        self.assertFalse(
            check_hdsc_archive_proof(proof, other_signature, self.key)
        )

    def test_wrong_key_returns_false(self):
        proof, signature = signed_proof(
            self.archive, (0, 2), self.key, seed=9200
        )
        other_key = make_other_key()
        self.assertNotEqual(other_key.public_key, self.key.public_key)
        self.assertFalse(
            check_hdsc_archive_proof(proof, signature, other_key)
        )

    def test_cross_key_bundle_returns_false(self):
        # A well-formed proof carrying a real bundle signed under another
        # key: verify_hdsc_proof_bundle fails before the root signature is
        # consulted.
        other_key = make_other_key()
        foreign = make_signed_bundle(
            other_key, 8, (0, 2), seed=9300
        )
        proof, signature = signed_proof(
            self.archive, (0,), self.key, seed=9301
        )
        mixed = dataclasses.replace(proof, bundles=(foreign,))
        self.assertFalse(
            check_hdsc_archive_proof(mixed, signature, self.key)
        )

    def test_proof_does_not_need_the_full_archive(self):
        proof, signature = signed_proof(
            self.archive, (2, 5), self.key, seed=9400
        )
        self.assertTrue(
            check_hdsc_archive_proof(proof, signature, self.key)
        )

    def test_entry_type_errors(self):
        proof, signature = signed_proof(
            self.archive, (1, 2), self.key, seed=9500
        )
        with self.assertRaises(TypeError):
            check_hdsc_archive_proof("proof", signature, self.key)
        with self.assertRaises(TypeError):
            check_hdsc_archive_proof(proof, "signature", self.key)
        with self.assertRaises(TypeError):
            check_hdsc_archive_proof(proof, signature, "key")
        for bad in (
            dataclasses.replace(proof, indices=[1, 2]),
            dataclasses.replace(proof, indices=(True, 2)),
            dataclasses.replace(proof, indices=("1", 2)),
            dataclasses.replace(proof, total=True),
            dataclasses.replace(proof, total="5"),
            dataclasses.replace(proof, bundles=[proof.bundles[0]] * 2),
            dataclasses.replace(proof, bundles=("not-a-bundle",) * 2),
            dataclasses.replace(proof, siblings=[b"s" * 32]),
            dataclasses.replace(proof, siblings=(b"s" * 32, 33)),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                check_hdsc_archive_proof(bad, signature, self.key)

    def test_structure_and_boundary_value_errors(self):
        proof, signature = signed_proof(
            self.archive, (1, 2), self.key, seed=9600
        )
        thirty_two = b"s" * 32
        for bad in (
            HDSCArchiveProof((1, 2), 0, proof.bundles, ()),
            HDSCArchiveProof((1, 2), -1, proof.bundles, ()),
            HDSCArchiveProof((1, 2), 2 ** 64, proof.bundles, ()),
            HDSCArchiveProof((), 5, (), ()),
            HDSCArchiveProof((-1, 2), 5, proof.bundles, ()),
            HDSCArchiveProof((1, 5), 5, proof.bundles, ()),
            HDSCArchiveProof((2, 1), 5, proof.bundles, ()),
            dataclasses.replace(proof, siblings=(b"s" * 31,) * 3),
            dataclasses.replace(proof, siblings=(b"s" * 33,) * 3),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                check_hdsc_archive_proof(bad, signature, self.key)
        # Bundle/index count mismatches and a wrong sibling count stay a
        # plain False, even when every entry is a correctly sized value.
        for bad in (
            HDSCArchiveProof(
                (1,), 5, proof.bundles[:1] + proof.bundles[:1], ()
            ),
            dataclasses.replace(proof, siblings=proof.siblings[:-1]),
            dataclasses.replace(
                proof, siblings=proof.siblings + (thirty_two,)
            ),
        ):
            self.assertFalse(
                check_hdsc_archive_proof(bad, signature, self.key)
            )

    def test_structurally_illegal_bundle_raises_value_error(self):
        proof, signature = signed_proof(
            self.archive, (1, 2), self.key, seed=9700
        )
        bad_bundle = HDSCProofBundle(
            HDSCProof(indices=(), total=0, seals=(), siblings=()),
            DUMMY_OUTER_SIGNATURE,
        )
        bad = dataclasses.replace(
            proof, bundles=(bad_bundle,) + proof.bundles[1:]
        )
        with self.assertRaises(ValueError):
            check_hdsc_archive_proof(bad, signature, self.key)

    def test_structurally_illegal_signature_raises_value_error(self):
        _message, proof = make_hdsc_archive_proof(self.archive, (1, 2))
        for bad_sig in (
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=-1, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=7, signer_ids=()),
            AggregateSignature(R=5, z=7, signer_ids=(3, 1)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad_sig)):
                check_hdsc_archive_proof(proof, bad_sig, self.key)

    def test_illegal_key_structure_raises_value_error(self):
        proof, signature = signed_proof(
            self.archive, (1, 2), self.key, seed=9800
        )
        broken_key = dataclasses.replace(self.key, public_key=0)
        with self.assertRaises(ValueError):
            check_hdsc_archive_proof(proof, signature, broken_key)


if __name__ == "__main__":
    unittest.main()
