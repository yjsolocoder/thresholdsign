"""Tests for compact multi-bundle Merkle membership proofs over the
non-empty order-preserving archive of whole HPAPBPB membership-proof
transport bundles: HPAPBPBP / make_hpapbpbp / check_hpapbpbp."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    HPAPBP,
    HPAPBPB,
    HPAPBPBArchive,
    HPAPBPBP,
    check_hpapbpbp,
    encode_hpapbpb,
    make_hpapbpbp,
)

from test_audit_chain import sign_message
from test_audit_extension_proof_bundle_codec import make_other_key
from test_nonce_reuse import make_key
from test_hpapbp import archive_of_size as hpapb_archive_of_size
from test_hpapbp_codec import signed_hpapbpb

LEAF_TAG = b"hpapbpbp/l"
NODE_TAG = b"hpapbpbp/n"
ROOT_TAG = b"hpapbpbp/r"

DUMMY_OUTER_SIGNATURE = AggregateSignature(R=5, z=7, signer_ids=(1, 3))

# Distinct (archive prefix size, index subset, seed) triples so every
# HPAPBPB bundle's proof, and therefore its canonical encoding, differs.
BUNDLE_SPECS = (
    (2, (0, 1), 82100),
    (3, (0, 2), 82200),
    (5, (0, 2, 4), 82300),
    (6, (1, 3, 5), 82400),
    (4, (1, 2), 82500),
    (6, (0, 5), 82600),
    (5, (3,), 82700),
    (3, (1,), 82800),
)


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big", signed=False)


def digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def bundles_of_size(n, key):
    """Build ``n`` distinct structurally legal, key-verifying HPAPBPB bundles."""
    return tuple(
        signed_hpapbpb(
            hpapb_archive_of_size(size, key),
            indices,
            key,
            seed=seed,
        )
        for size, indices, seed in BUNDLE_SPECS[:n]
    )


def archive_of_size(n, key):
    """An HPAPBPB archive of ``n`` distinct bundles, placeholder outer signature."""
    return HPAPBPBArchive(bundles_of_size(n, key), DUMMY_OUTER_SIGNATURE)


def independent_tree(bundles):
    """Build leaf level, internal levels (odd tail duplicated) and root."""
    leaves = tuple(
        digest(LEAF_TAG + u64(i) + digest(encode_hpapbpb(bundle)))
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


def signed_proof(archive, indices, key, *, seed=83000):
    """Return (proof, root signature) for a threshold-signed statement."""
    message, proof = make_hpapbpbp(archive, indices)
    signature = sign_message(key, message, seed=seed + sum(indices))
    return proof, signature


class HPAPBPBPDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(HPAPBPBP)],
            ["indices", "total", "bundles", "siblings"],
        )
        key = make_key()
        bundles = bundles_of_size(2, key)
        siblings = (b"s" * 32,)
        proof = HPAPBPBP((1,), 3, bundles, siblings)
        self.assertEqual(
            (proof.indices, proof.total, proof.bundles, proof.siblings),
            ((1,), 3, bundles, siblings),
        )

    def test_frozen_value_equality_and_hash(self):
        key = make_key()
        bundles = bundles_of_size(2, key)
        siblings = (b"s" * 32, b"t" * 32)
        proof = HPAPBPBP((1, 3), 4, bundles, siblings)
        same = HPAPBPBP(indices=(1, 3), total=4, bundles=bundles, siblings=siblings)
        self.assertEqual(proof, same)
        self.assertEqual(hash(proof), hash(same))
        self.assertNotEqual(proof, HPAPBPBP((1, 2), 4, bundles, siblings))
        with self.assertRaises(FrozenInstanceError):
            proof.total = 5

    def test_construction_does_not_validate(self):
        key = make_key()
        bundles = bundles_of_size(1, key)
        HPAPBPBP((9,), 1, bundles, ())
        HPAPBPBP((0,), 0, ("not-a-bundle",), b"x")
        HPAPBPBP((), 3, bundles, (b"",))


class MakeHPAPBPBPTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(8, self.key)

    def _archive_of_size(self, n):
        return HPAPBPBArchive(self.archive.items[:n], self.archive.signature)

    def test_statement_layout_for_every_size_and_subset(self):
        for n in range(1, 9):
            archive = self._archive_of_size(n)
            root = independent_tree(archive.items)[-1][0]
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                message, proof = make_hpapbpbp(archive, indices)
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
        _message, proof = make_hpapbpbp(self.archive, indices)
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
                _message, proof = make_hpapbpbp(archive, indices)
                self.assertEqual(
                    proof.siblings,
                    independent_siblings(levels, indices),
                    msg=f"n={n} indices={indices}",
                )

    def test_proving_every_bundle_needs_no_siblings(self):
        for n in range(1, 9):
            archive = self._archive_of_size(n)
            _message, proof = make_hpapbpbp(archive, tuple(range(n)))
            self.assertEqual(proof.siblings, ())

    def test_domain_tags_are_distinct_from_lower_layers(self):
        message, _proof = make_hpapbpbp(self.archive, (0, 2))
        self.assertTrue(message.startswith(b"hpapbpbp/r"))
        self.assertFalse(message.startswith(b"hpapbp/r"))
        self.assertFalse(message.startswith(b"hpap/r"))

    def test_deterministic(self):
        message, proof = make_hpapbpbp(self.archive, (0, 2, 4))
        message2, proof2 = make_hpapbpbp(self.archive, (0, 2, 4))
        self.assertEqual(message, message2)
        self.assertEqual(proof, proof2)

    def test_archive_outer_signature_is_not_consulted(self):
        unsigned = HPAPBPBArchive(self.archive.items, "not-a-signature")
        self.assertEqual(
            make_hpapbpbp(unsigned, (0, 2))[0],
            make_hpapbpbp(self.archive, (0, 2))[0],
        )

    def test_non_archive_type_error(self):
        wrong_layer_archive = hpapb_archive_of_size(4, self.key)
        for bad in (
            tuple(self.archive.items),
            list(self.archive.items),
            wrong_layer_archive,
            "archive",
            None,
            42,
            b"x",
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                make_hpapbpbp(bad, (0,))

    def test_indices_type_errors(self):
        for bad in ([0, 2], (True,), ("0",), (1.0,), (None,)):
            with self.assertRaises(TypeError, msg=f"indices={bad!r}"):
                make_hpapbpbp(self.archive, bad)

    def test_empty_unsorted_duplicate_and_out_of_range_raise_value_error(self):
        with self.assertRaises(ValueError):
            make_hpapbpbp(self.archive, ())
        empty = HPAPBPBArchive((), self.archive.signature)
        with self.assertRaises(ValueError):
            make_hpapbpbp(empty, (0,))
        for bad in ((2, 1), (1, 1), (-1,), (8,), (0, 8), (3, 3, 4)):
            with self.assertRaises(ValueError, msg=f"indices={bad}"):
                make_hpapbpbp(self.archive, bad)

    def test_non_tuple_items_type_error(self):
        archive = HPAPBPBArchive(
            list(self.archive.items), self.archive.signature
        )
        with self.assertRaises(TypeError):
            make_hpapbpbp(archive, (0,))

    def test_non_bundle_element_type_error(self):
        archive = HPAPBPBArchive(
            ("not-a-bundle",) + self.archive.items[1:],
            self.archive.signature,
        )
        with self.assertRaises(TypeError):
            make_hpapbpbp(archive, (0,))

    def test_illegal_nested_bundle_errors(self):
        # A non-HPAPBPB item is a TypeError; an HPAPBPB whose own proof is
        # structurally illegal is a ValueError straight from encode_hpapbpb.
        bad_type_bundle = "not-an-hpapbpb"
        archive = HPAPBPBArchive(
            (bad_type_bundle,) + self.archive.items[1:],
            self.archive.signature,
        )
        with self.assertRaises(TypeError):
            make_hpapbpbp(archive, (0,))
        bad_value_bundle = HPAPBPB(
            HPAPBP(indices=(), total=0, bundles=(), siblings=()),
            DUMMY_OUTER_SIGNATURE,
        )
        archive = HPAPBPBArchive(
            (bad_value_bundle,) + self.archive.items[1:],
            self.archive.signature,
        )
        with self.assertRaises(ValueError):
            make_hpapbpbp(archive, (0,))

    def test_total_at_2_pow_64_boundary_raises_value_error(self):
        # A count at or above 2**64 is a plain ValueError on every
        # HPAPBPBP construction path, never an OverflowError leaking from
        # a bare len()/U64 conversion.
        class HugeTuple(tuple):
            def __len__(self):
                return 2 ** 64

        huge_archive = HPAPBPBArchive(
            HugeTuple((self.archive.items[0],)),
            self.archive.signature,
        )
        with self.assertRaises(ValueError):
            make_hpapbpbp(huge_archive, (0,))
        with self.assertRaises(ValueError):
            make_hpapbpbp(self.archive, HugeTuple((0,)))


class CheckHPAPBPBPTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(8, self.key)

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
            archive = HPAPBPBArchive(
                self.archive.items[:n], self.archive.signature
            )
            proof, signature = signed_proof(archive, indices, self.key)
            self.assertTrue(
                check_hpapbpbp(proof, signature, self.key),
                msg=f"n={n} indices={indices}",
            )

    def test_one_signature_covers_every_subset(self):
        archive = HPAPBPBArchive(
            self.archive.items[:5], self.archive.signature
        )
        message, _ = make_hpapbpbp(archive, (0,))
        signature = sign_message(self.key, message, seed=83350)
        for mask in range(1, 1 << 5):
            indices = tuple(i for i in range(5) if mask & (1 << i))
            _statement, proof = make_hpapbpbp(archive, indices)
            self.assertTrue(
                check_hpapbpbp(proof, signature, self.key),
                msg=f"indices={indices}",
            )

    def test_tampered_bundles_indices_and_siblings_return_false(self):
        indices = (0, 2, 4)
        proof, signature = signed_proof(self.archive, indices, self.key)
        swapped = HPAPBPBP(
            proof.indices,
            proof.total,
            (proof.bundles[1], proof.bundles[0], proof.bundles[2]),
            proof.siblings,
        )
        self.assertFalse(check_hpapbpbp(swapped, signature, self.key))
        moved = HPAPBPBP((0, 2, 5), proof.total, proof.bundles, proof.siblings)
        self.assertFalse(check_hpapbpbp(moved, signature, self.key))
        damaged = HPAPBPBP(
            proof.indices,
            proof.total,
            proof.bundles,
            (b"\x00" * 32,) + proof.siblings[1:],
        )
        self.assertFalse(check_hpapbpbp(damaged, signature, self.key))

    def test_missing_extra_and_misaligned_siblings_return_false(self):
        indices = (0, 3)
        proof, signature = signed_proof(self.archive, indices, self.key)
        self.assertGreater(len(proof.siblings), 1)
        short = HPAPBPBP(
            proof.indices, proof.total, proof.bundles, proof.siblings[:-1]
        )
        self.assertFalse(check_hpapbpbp(short, signature, self.key))
        long = HPAPBPBP(
            proof.indices,
            proof.total,
            proof.bundles,
            proof.siblings + (b"x" * 32,),
        )
        self.assertFalse(check_hpapbpbp(long, signature, self.key))
        rotated = HPAPBPBP(
            proof.indices,
            proof.total,
            proof.bundles,
            proof.siblings[1:] + proof.siblings[:1],
        )
        self.assertFalse(check_hpapbpbp(rotated, signature, self.key))

    def test_bundle_count_mismatch_returns_false(self):
        indices = (0, 2, 4)
        proof, signature = signed_proof(self.archive, indices, self.key)
        fewer = HPAPBPBP(
            proof.indices, proof.total, proof.bundles[:2], proof.siblings
        )
        self.assertFalse(check_hpapbpbp(fewer, signature, self.key))
        more = HPAPBPBP(
            proof.indices,
            proof.total,
            proof.bundles + (proof.bundles[0],),
            proof.siblings,
        )
        self.assertFalse(check_hpapbpbp(more, signature, self.key))

    def test_wrong_signature_and_wrong_key_return_false(self):
        indices = (0, 2)
        proof, signature = signed_proof(self.archive, indices, self.key)
        shortened = HPAPBPBArchive(
            self.archive.items[:4], self.archive.signature
        )
        other_message, _ = make_hpapbpbp(shortened, (0, 2))
        other_signature = sign_message(self.key, other_message, seed=83370)
        self.assertFalse(check_hpapbpbp(proof, other_signature, self.key))
        self.assertFalse(check_hpapbpbp(proof, signature, make_other_key()))

    def test_unverifying_nested_bundle_returns_false(self):
        indices = (0, 2)
        proof, signature = signed_proof(self.archive, indices, self.key)
        other_key = make_other_key()
        foreign = signed_hpapbpb(
            hpapb_archive_of_size(3, other_key),
            (0, 2),
            other_key,
            seed=83380,
        )
        mixed = HPAPBPBP(
            proof.indices,
            proof.total,
            (foreign, proof.bundles[1]),
            proof.siblings,
        )
        self.assertFalse(check_hpapbpbp(mixed, signature, self.key))

    def test_tampered_inner_root_signature_returns_false(self):
        # Swapping a disclosed bundle's own root signature for a
        # well-shaped but wrong one keeps the leaf encodable and the
        # rebuilt root intact, but the per-bundle verify_hpapbpb fails.
        indices = (0, 2)
        proof, signature = signed_proof(self.archive, indices, self.key)
        good = proof.bundles[0]
        tampered_inner = AggregateSignature(
            R=good.signature.R,
            z=good.signature.z + 1,
            signer_ids=good.signature.signer_ids,
        )
        bad_bundle = HPAPBPB(good.proof, tampered_inner)
        mixed = HPAPBPBP(
            proof.indices,
            proof.total,
            (bad_bundle, proof.bundles[1]),
            proof.siblings,
        )
        self.assertFalse(check_hpapbpbp(mixed, signature, self.key))

    def test_bad_bundle_does_not_mask_illegal_signature_or_key(self):
        # A structurally legal proof whose nested bundle merely fails
        # verification must not turn an illegal root signature or key
        # into a plain False: both structures are checked first.
        other_key = make_other_key()
        foreign = signed_hpapbpb(
            hpapb_archive_of_size(3, other_key),
            (0, 2),
            other_key,
            seed=83390,
        )
        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        mixed = HPAPBPBP(
            proof.indices,
            proof.total,
            (foreign, proof.bundles[1]),
            proof.siblings,
        )
        for bad_signature in (
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=-1, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=7, signer_ids=()),
            AggregateSignature(R=5, z=7, signer_ids=(3, 1)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad_signature)):
                check_hpapbpbp(mixed, bad_signature, self.key)
        for bad_key in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad_key)):
                check_hpapbpbp(
                    mixed,
                    AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
                    bad_key,
                )

    def test_illegal_nested_bundle_raises_value_error_not_false(self):
        # A structurally illegal disclosed bundle is a ValueError from the
        # leaf recomputation, never a plain False.
        proof, signature = signed_proof(self.archive, (0, 2), self.key)
        illegal = HPAPBPB(
            HPAPBP(indices=(), total=0, bundles=(), siblings=()),
            DUMMY_OUTER_SIGNATURE,
        )
        mixed = HPAPBPBP(
            proof.indices,
            proof.total,
            (illegal, proof.bundles[1]),
            proof.siblings,
        )
        with self.assertRaises(ValueError):
            check_hpapbpbp(mixed, signature, self.key)

    def test_type_errors(self):
        proof, signature = signed_proof(self.archive, (0, 2), self.key)
        with self.assertRaises(TypeError):
            check_hpapbpbp("not-a-proof", signature, self.key)
        with self.assertRaises(TypeError):
            check_hpapbpbp(proof, "not-a-signature", self.key)
        for bad in (
            HPAPBPBP([0, 2], 8, proof.bundles, proof.siblings),
            HPAPBPBP((0, 2), "8", proof.bundles, proof.siblings),
            HPAPBPBP((0, 2), True, proof.bundles, proof.siblings),
            HPAPBPBP((0, True), 8, proof.bundles, proof.siblings),
            HPAPBPBP((0, 2), 8, list(proof.bundles), proof.siblings),
            HPAPBPBP((0, 2), 8, proof.bundles, list(proof.siblings)),
            HPAPBPBP((0, 2), 8, ("not-a-bundle",) * 2, proof.siblings),
            HPAPBPBP((0, 2), 8, proof.bundles, (b"x" * 32, 7)),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                check_hpapbpbp(bad, signature, self.key)

    def test_structure_value_errors(self):
        proof, signature = signed_proof(self.archive, (0, 2), self.key)
        for bad in (
            HPAPBPBP((0, 2), 0, proof.bundles, proof.siblings),
            HPAPBPBP((), 8, (), ()),
            HPAPBPBP((2, 0), 8, proof.bundles, proof.siblings),
            HPAPBPBP((1, 1), 8, proof.bundles, proof.siblings),
            HPAPBPBP((0, 8), 8, proof.bundles, proof.siblings),
            HPAPBPBP((0, 2), 8, proof.bundles, (b"short",)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                check_hpapbpbp(bad, signature, self.key)

    def test_signature_shape_value_errors(self):
        # The root signature's shape is judged on exactly three points:
        # R positive, z non-negative, signer ids a non-empty strictly
        # increasing tuple of positive integers; anything else is a
        # ValueError, while a well-shaped but wrong signature is False.
        proof, signature = signed_proof(self.archive, (0, 2), self.key)
        for bad in (
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=-2, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=-1, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=7, signer_ids=()),
            AggregateSignature(R=5, z=7, signer_ids=(0, 3)),
            AggregateSignature(R=5, z=7, signer_ids=(3, 1)),
            AggregateSignature(R=5, z=7, signer_ids=(1, 1)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                check_hpapbpbp(proof, bad, self.key)
        wrong_content = AggregateSignature(
            R=signature.R, z=signature.z + 1, signer_ids=signature.signer_ids
        )
        self.assertFalse(check_hpapbpbp(proof, wrong_content, self.key))

    def test_count_at_2_pow_64_boundary_raises_value_error(self):
        # Every count at or above 2**64 surfaces as ValueError, whether
        # it arrives through the plain integer field or a tuple subclass
        # whose len() reports 2**64 (which would leak OverflowError from
        # a bare len()).
        class HugeTuple(tuple):
            def __len__(self):
                return 2 ** 64

        proof, signature = signed_proof(self.archive, (0, 2), self.key)
        integer_boundary = (
            HPAPBPBP((0,), 2 ** 64, proof.bundles[:1], ()),
            HPAPBPBP((0,), 2 ** 64 + 1, proof.bundles[:1], ()),
        )
        for bad in integer_boundary:
            with self.assertRaises(ValueError, msg=repr(bad)):
                check_hpapbpbp(bad, signature, self.key)
        huge_fields = (
            HPAPBPBP(HugeTuple((0, 2)), 8, proof.bundles, proof.siblings),
            HPAPBPBP((0, 2), 8, HugeTuple(proof.bundles), proof.siblings),
            HPAPBPBP((0, 2), 8, proof.bundles, HugeTuple(proof.siblings)),
        )
        for bad in huge_fields:
            with self.assertRaises(ValueError, msg=repr(bad)):
                check_hpapbpbp(bad, signature, self.key)


if __name__ == "__main__":
    unittest.main()
