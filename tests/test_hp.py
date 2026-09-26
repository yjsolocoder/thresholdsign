"""Tests for compact multi-bundle Merkle membership proofs over the
non-empty order-preserving archive of whole HBPB transport bundles:
HP / make_hp / check_hp."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    HBP,
    HBPB,
    HBPBArchive,
    HP,
    check_hp,
    encode_hbpb,
    make_hp,
)

from test_audit_chain import sign_message
from test_audit_extension_proof_bundle_codec import make_other_key
from test_nonce_reuse import make_key
from test_hbp import archive_of_size as hbapb_archive_of_size, signed_hbpb

LEAF_TAG = b"hp/l"
NODE_TAG = b"hp/n"
ROOT_TAG = b"hp/r"

DUMMY_OUTER_SIGNATURE = AggregateSignature(R=5, z=7, signer_ids=(1, 3))


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big", signed=False)


def digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def bundles_of_size(n, key, seed_base=51000):
    """Build ``n`` distinct structurally legal, key-verifying HBPB bundles."""
    source = hbapb_archive_of_size(8, key, seed_base=seed_base)
    combos = ((0,), (1, 2), (0, 1, 2), (0, 2), (1,), (0, 1), (2,), (1, 2))
    return tuple(
        signed_hbpb(
            source,
            combos[position % len(combos)],
            key,
            seed=seed_base + 400 + position * 53,
        )
        for position in range(n)
    )


def archive_of_size(n, key, seed_base=51000):
    """An HBPB archive of ``n`` distinct bundles, placeholder outer signature."""
    return HBPBArchive(
        bundles_of_size(n, key, seed_base=seed_base), DUMMY_OUTER_SIGNATURE
    )


def independent_tree(bundles):
    """Build leaf level, internal levels (odd tail duplicated) and root."""
    leaves = tuple(
        digest(LEAF_TAG + u64(i) + digest(encode_hbpb(bundle)))
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


def signed_proof(archive, indices, key, *, seed=52000):
    """Return (proof, root signature) for a threshold-signed statement."""
    message, proof = make_hp(archive, indices)
    signature = sign_message(key, message, seed=seed + sum(indices))
    return proof, signature


class HPDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(HP)],
            ["indices", "total", "bundles", "siblings"],
        )
        key = make_key()
        bundles = bundles_of_size(2, key)
        siblings = (b"s" * 32,)
        proof = HP((1,), 3, bundles, siblings)
        self.assertEqual(
            (proof.indices, proof.total, proof.bundles, proof.siblings),
            ((1,), 3, bundles, siblings),
        )

    def test_frozen_value_equality_and_hash(self):
        key = make_key()
        bundles = bundles_of_size(2, key, seed_base=51100)
        siblings = (b"s" * 32, b"t" * 32)
        proof = HP((1, 3), 4, bundles, siblings)
        same = HP(indices=(1, 3), total=4, bundles=bundles, siblings=siblings)
        self.assertEqual(proof, same)
        self.assertEqual(hash(proof), hash(same))
        self.assertNotEqual(proof, HP((1, 2), 4, bundles, siblings))
        with self.assertRaises(FrozenInstanceError):
            proof.total = 5

    def test_construction_does_not_validate(self):
        key = make_key()
        bundles = bundles_of_size(1, key, seed_base=51150)
        HP((9,), 1, bundles, ())
        HP((0,), 0, ("not-a-bundle",), b"x")
        HP((), 3, bundles, (b"",))


class MakeHPTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(8, self.key, seed_base=51200)

    def _archive_of_size(self, n):
        return HBPBArchive(self.archive.items[:n], self.archive.signature)

    def test_statement_layout_for_every_size_and_subset(self):
        for n in range(1, 9):
            archive = self._archive_of_size(n)
            root = independent_tree(archive.items)[-1][0]
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                message, proof = make_hp(archive, indices)
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
        _message, proof = make_hp(self.archive, indices)
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
                _message, proof = make_hp(archive, indices)
                self.assertEqual(
                    proof.siblings,
                    independent_siblings(levels, indices),
                    msg=f"n={n} indices={indices}",
                )

    def test_proving_every_bundle_needs_no_siblings(self):
        for n in range(1, 9):
            archive = self._archive_of_size(n)
            _message, proof = make_hp(archive, tuple(range(n)))
            self.assertEqual(proof.siblings, ())

    def test_domain_tags_are_distinct_from_hbp_tags(self):
        message, _proof = make_hp(self.archive, (0, 2))
        self.assertTrue(message.startswith(b"hp/r"))
        self.assertFalse(message.startswith(b"hbp/r"))

    def test_deterministic(self):
        message, proof = make_hp(self.archive, (0, 2, 4))
        message2, proof2 = make_hp(self.archive, (0, 2, 4))
        self.assertEqual(message, message2)
        self.assertEqual(proof, proof2)

    def test_archive_outer_signature_is_not_consulted(self):
        unsigned = HBPBArchive(self.archive.items, "not-a-signature")
        self.assertEqual(
            make_hp(unsigned, (0, 2))[0],
            make_hp(self.archive, (0, 2))[0],
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
                make_hp(bad, (0,))

    def test_indices_type_errors(self):
        for bad in ([0, 2], (True,), ("0",), (1.0,), (None,)):
            with self.assertRaises(TypeError, msg=f"indices={bad!r}"):
                make_hp(self.archive, bad)

    def test_empty_unsorted_duplicate_and_out_of_range_raise_value_error(self):
        with self.assertRaises(ValueError):
            make_hp(self.archive, ())
        empty = HBPBArchive((), self.archive.signature)
        with self.assertRaises(ValueError):
            make_hp(empty, (0,))
        for bad in ((2, 1), (1, 1), (-1,), (8,), (0, 8), (3, 3, 4)):
            with self.assertRaises(ValueError, msg=f"indices={bad}"):
                make_hp(self.archive, bad)

    def test_non_tuple_items_type_error(self):
        archive = HBPBArchive(list(self.archive.items), self.archive.signature)
        with self.assertRaises(TypeError):
            make_hp(archive, (0,))

    def test_non_bundle_element_type_error(self):
        archive = HBPBArchive(
            ("not-a-bundle",) + self.archive.items[1:], self.archive.signature
        )
        with self.assertRaises(TypeError):
            make_hp(archive, (0,))

    def test_illegal_nested_bundle_errors(self):
        # A non-HBPB item is a TypeError; an HBPB whose own proof is
        # structurally illegal is a ValueError straight from encode_hbpb.
        bad_type_bundle = "not-an-hbpb"
        archive = HBPBArchive(
            (bad_type_bundle,) + self.archive.items[1:], self.archive.signature
        )
        with self.assertRaises(TypeError):
            make_hp(archive, (0,))
        bad_value_bundle = HBPB(
            HBP(indices=(), total=0, bundles=(), siblings=()),
            DUMMY_OUTER_SIGNATURE,
        )
        archive = HBPBArchive(
            (bad_value_bundle,) + self.archive.items[1:], self.archive.signature
        )
        with self.assertRaises(ValueError):
            make_hp(archive, (0,))

    def test_total_at_2_pow_64_boundary_raises_value_error(self):
        # A count at or above 2**64 is a plain ValueError on every HP
        # construction path, never an OverflowError leaking from a bare
        # len()/U64 conversion.
        class HugeTuple(tuple):
            def __len__(self):
                return 2 ** 64

        huge_archive = HBPBArchive(
            HugeTuple((self.archive.items[0],)),
            self.archive.signature,
        )
        with self.assertRaises(ValueError):
            make_hp(huge_archive, (0,))
        with self.assertRaises(ValueError):
            make_hp(self.archive, HugeTuple((0,)))


class CheckHPTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(8, self.key, seed_base=51300)

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
            archive = HBPBArchive(
                self.archive.items[:n], self.archive.signature
            )
            proof, signature = signed_proof(archive, indices, self.key)
            self.assertTrue(
                check_hp(proof, signature, self.key),
                msg=f"n={n} indices={indices}",
            )

    def test_one_signature_covers_every_subset(self):
        archive = HBPBArchive(
            self.archive.items[:5], self.archive.signature
        )
        message, _ = make_hp(archive, (0,))
        signature = sign_message(self.key, message, seed=51350)
        for mask in range(1, 1 << 5):
            indices = tuple(i for i in range(5) if mask & (1 << i))
            _statement, proof = make_hp(archive, indices)
            self.assertTrue(
                check_hp(proof, signature, self.key),
                msg=f"indices={indices}",
            )

    def test_tampered_bundles_indices_and_siblings_return_false(self):
        indices = (0, 2, 4)
        proof, signature = signed_proof(self.archive, indices, self.key)
        swapped = HP(
            proof.indices,
            proof.total,
            (proof.bundles[1], proof.bundles[0], proof.bundles[2]),
            proof.siblings,
        )
        self.assertFalse(check_hp(swapped, signature, self.key))
        moved = HP((0, 2, 5), proof.total, proof.bundles, proof.siblings)
        self.assertFalse(check_hp(moved, signature, self.key))
        damaged = HP(
            proof.indices,
            proof.total,
            proof.bundles,
            (b"\x00" * 32,) + proof.siblings[1:],
        )
        self.assertFalse(check_hp(damaged, signature, self.key))

    def test_missing_extra_and_misaligned_siblings_return_false(self):
        indices = (0, 3)
        proof, signature = signed_proof(self.archive, indices, self.key)
        self.assertGreater(len(proof.siblings), 1)
        short = HP(
            proof.indices, proof.total, proof.bundles, proof.siblings[:-1]
        )
        self.assertFalse(check_hp(short, signature, self.key))
        long = HP(
            proof.indices,
            proof.total,
            proof.bundles,
            proof.siblings + (b"x" * 32,),
        )
        self.assertFalse(check_hp(long, signature, self.key))
        rotated = HP(
            proof.indices,
            proof.total,
            proof.bundles,
            proof.siblings[1:] + proof.siblings[:1],
        )
        self.assertFalse(check_hp(rotated, signature, self.key))

    def test_bundle_count_mismatch_returns_false(self):
        indices = (0, 2, 4)
        proof, signature = signed_proof(self.archive, indices, self.key)
        fewer = HP(
            proof.indices, proof.total, proof.bundles[:2], proof.siblings
        )
        self.assertFalse(check_hp(fewer, signature, self.key))
        more = HP(
            proof.indices,
            proof.total,
            proof.bundles + (proof.bundles[0],),
            proof.siblings,
        )
        self.assertFalse(check_hp(more, signature, self.key))

    def test_wrong_signature_and_wrong_key_return_false(self):
        indices = (0, 2)
        proof, signature = signed_proof(self.archive, indices, self.key)
        shortened = HBPBArchive(
            self.archive.items[:4], self.archive.signature
        )
        other_message, _ = make_hp(shortened, (0, 2))
        other_signature = sign_message(self.key, other_message, seed=51370)
        self.assertFalse(check_hp(proof, other_signature, self.key))
        self.assertFalse(check_hp(proof, signature, make_other_key()))

    def test_unverifying_nested_bundle_returns_false(self):
        indices = (0, 2)
        proof, signature = signed_proof(self.archive, indices, self.key)
        other_key = make_other_key()
        foreign = signed_hbpb(
            hbapb_archive_of_size(8, other_key, seed_base=51380),
            (0,),
            other_key,
            seed=51390,
        )
        mixed = HP(
            proof.indices,
            proof.total,
            (foreign, proof.bundles[1]),
            proof.siblings,
        )
        self.assertFalse(check_hp(mixed, signature, self.key))

    def test_bad_bundle_does_not_mask_illegal_signature_or_key(self):
        # A structurally legal proof whose nested bundle merely fails
        # verification must not turn an illegal root signature or key
        # into a plain False: both structures are checked first.
        other_key = make_other_key()
        foreign = signed_hbpb(
            hbapb_archive_of_size(8, other_key, seed_base=51400),
            (0,),
            other_key,
            seed=51401,
        )
        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        mixed = HP(
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
                check_hp(mixed, bad_signature, self.key)
        for bad_key in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad_key)):
                check_hp(
                    mixed,
                    AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
                    bad_key,
                )

    def test_type_errors(self):
        proof, signature = signed_proof(self.archive, (0, 2), self.key)
        with self.assertRaises(TypeError):
            check_hp("not-a-proof", signature, self.key)
        with self.assertRaises(TypeError):
            check_hp(proof, "not-a-signature", self.key)
        for bad in (
            HP([0, 2], 8, proof.bundles, proof.siblings),
            HP((0, 2), "8", proof.bundles, proof.siblings),
            HP((0, 2), True, proof.bundles, proof.siblings),
            HP((0, True), 8, proof.bundles, proof.siblings),
            HP((0, 2), 8, list(proof.bundles), proof.siblings),
            HP((0, 2), 8, proof.bundles, list(proof.siblings)),
            HP((0, 2), 8, ("not-a-bundle",) * 2, proof.siblings),
            HP((0, 2), 8, proof.bundles, (b"x" * 32, 7)),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                check_hp(bad, signature, self.key)

    def test_structure_value_errors(self):
        proof, signature = signed_proof(self.archive, (0, 2), self.key)
        for bad in (
            HP((0, 2), 0, proof.bundles, proof.siblings),
            HP((), 8, (), ()),
            HP((2, 0), 8, proof.bundles, proof.siblings),
            HP((1, 1), 8, proof.bundles, proof.siblings),
            HP((0, 8), 8, proof.bundles, proof.siblings),
            HP((0, 2), 8, proof.bundles, (b"short",)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                check_hp(bad, signature, self.key)

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
            HP((0,), 2 ** 64, proof.bundles[:1], ()),
            HP((0,), 2 ** 64 + 1, proof.bundles[:1], ()),
        )
        for bad in integer_boundary:
            with self.assertRaises(ValueError, msg=repr(bad)):
                check_hp(bad, signature, self.key)
        huge_fields = (
            HP(HugeTuple((0, 2)), 8, proof.bundles, proof.siblings),
            HP((0, 2), 8, HugeTuple(proof.bundles), proof.siblings),
            HP((0, 2), 8, proof.bundles, HugeTuple(proof.siblings)),
        )
        for bad in huge_fields:
            with self.assertRaises(ValueError, msg=repr(bad)):
                check_hp(bad, signature, self.key)


if __name__ == "__main__":
    unittest.main()
