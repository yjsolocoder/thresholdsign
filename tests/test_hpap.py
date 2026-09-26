"""Tests for compact multi-bundle Merkle membership proofs over the
non-empty order-preserving archive of whole HPB transport bundles:
HPAP / make_hpap / check_hpap."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    HPAP,
    HPBArchive,
    check_hpap,
    encode_hpb,
    make_hpap,
)

from test_audit_chain import sign_message
from test_audit_extension_proof_bundle_codec import make_other_key
from test_nonce_reuse import make_key
from test_hp import archive_of_size as hpb_archive_source
from test_hpb import signed_hpb

LEAF_TAG = b"hpap/l"
NODE_TAG = b"hpap/n"
ROOT_TAG = b"hpap/r"

DUMMY_OUTER_SIGNATURE = AggregateSignature(R=5, z=7, signer_ids=(1, 3))

# Distinct (index subset, seed, seed_base) triples so every HPB bundle
# encodes differently.
BUNDLE_SPECS = (
    ((0, 2, 5), 72000, 71000),
    ((1, 3), 72097, 75000),
    ((0, 1, 2, 3, 4, 5), 72194, 79000),
    ((4,), 72291, 83000),
    ((0, 4), 72388, 87000),
    ((2, 3, 5), 72485, 91000),
    ((1,), 72582, 95000),
    ((0, 1, 3, 5), 72679, 99000),
)


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big", signed=False)


def digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def bundles_of_size(n, key):
    """Build ``n`` distinct structurally legal, key-verifying HPB bundles."""
    return tuple(
        signed_hpb(
            hpb_archive_source(6, key, seed_base=seed_base),
            indices,
            key,
            seed=seed,
        )
        for indices, seed, seed_base in BUNDLE_SPECS[:n]
    )


def archive_of_size(n, key):
    """An HPB archive of ``n`` distinct bundles, placeholder outer signature."""
    return HPBArchive(bundles_of_size(n, key), DUMMY_OUTER_SIGNATURE)


def independent_tree(bundles):
    """Build leaf level, internal levels (odd tail duplicated) and root."""
    leaves = tuple(
        digest(LEAF_TAG + u64(i) + digest(encode_hpb(bundle)))
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
    message, proof = make_hpap(archive, indices)
    signature = sign_message(key, message, seed=seed + sum(indices))
    return proof, signature


class HPAPDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(HPAP)],
            ["indices", "total", "bundles", "siblings"],
        )
        key = make_key()
        bundles = bundles_of_size(2, key)
        siblings = (b"s" * 32,)
        proof = HPAP((1,), 3, bundles, siblings)
        self.assertEqual(
            (proof.indices, proof.total, proof.bundles, proof.siblings),
            ((1,), 3, bundles, siblings),
        )

    def test_frozen_value_equality_and_hash(self):
        key = make_key()
        bundles = bundles_of_size(2, key)
        siblings = (b"s" * 32, b"t" * 32)
        proof = HPAP((1, 3), 4, bundles, siblings)
        same = HPAP(indices=(1, 3), total=4, bundles=bundles, siblings=siblings)
        self.assertEqual(proof, same)
        self.assertEqual(hash(proof), hash(same))
        self.assertNotEqual(proof, HPAP((1, 2), 4, bundles, siblings))
        with self.assertRaises(FrozenInstanceError):
            proof.total = 5

    def test_construction_does_not_validate(self):
        key = make_key()
        bundles = bundles_of_size(1, key)
        HPAP((9,), 1, bundles, ())
        HPAP((0,), 0, ("not-a-bundle",), b"x")
        HPAP((), 3, bundles, (b"",))


class MakeHPAPTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(8, self.key)

    def _archive_of_size(self, n):
        return HPBArchive(self.archive.items[:n], self.archive.signature)

    def test_statement_layout_for_every_size_and_subset(self):
        for n in range(1, 9):
            archive = self._archive_of_size(n)
            root = independent_tree(archive.items)[-1][0]
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                message, proof = make_hpap(archive, indices)
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
        _message, proof = make_hpap(self.archive, indices)
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
                _message, proof = make_hpap(archive, indices)
                self.assertEqual(
                    proof.siblings,
                    independent_siblings(levels, indices),
                    msg=f"n={n} indices={indices}",
                )

    def test_proving_every_bundle_needs_no_siblings(self):
        for n in range(1, 9):
            archive = self._archive_of_size(n)
            _message, proof = make_hpap(archive, tuple(range(n)))
            self.assertEqual(proof.siblings, ())

    def test_domain_tags_are_distinct_from_hp_tags(self):
        message, _proof = make_hpap(self.archive, (0, 2))
        self.assertTrue(message.startswith(b"hpap/r"))
        self.assertFalse(message.startswith(b"hp/r"))

    def test_deterministic(self):
        message, proof = make_hpap(self.archive, (0, 2, 4))
        message2, proof2 = make_hpap(self.archive, (0, 2, 4))
        self.assertEqual(message, message2)
        self.assertEqual(proof, proof2)

    def test_archive_outer_signature_is_not_consulted(self):
        unsigned = HPBArchive(self.archive.items, "not-a-signature")
        self.assertEqual(
            make_hpap(unsigned, (0, 2))[0],
            make_hpap(self.archive, (0, 2))[0],
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
                make_hpap(bad, (0,))

    def test_indices_type_errors(self):
        for bad in ([0, 2], (True,), ("0",), (1.0,), (None,)):
            with self.assertRaises(TypeError, msg=f"indices={bad!r}"):
                make_hpap(self.archive, bad)

    def test_empty_unsorted_duplicate_and_out_of_range_raise_value_error(self):
        with self.assertRaises(ValueError):
            make_hpap(self.archive, ())
        empty = HPBArchive((), self.archive.signature)
        with self.assertRaises(ValueError):
            make_hpap(empty, (0,))
        for bad in ((2, 1), (1, 1), (-1,), (8,), (0, 8), (3, 3, 4)):
            with self.assertRaises(ValueError, msg=f"indices={bad}"):
                make_hpap(self.archive, bad)

    def test_non_tuple_items_type_error(self):
        archive = HPBArchive(list(self.archive.items), self.archive.signature)
        with self.assertRaises(TypeError):
            make_hpap(archive, (0,))

    def test_non_bundle_element_type_error(self):
        archive = HPBArchive(
            ("not-a-bundle",) + self.archive.items[1:], self.archive.signature
        )
        with self.assertRaises(TypeError):
            make_hpap(archive, (0,))

    def test_illegal_nested_bundle_errors(self):
        # A non-HPB item is a TypeError; an HPB whose own proof is
        # structurally illegal is a ValueError straight from encode_hpb.
        from thresholdsign import HP, HPB

        bad_type_bundle = "not-an-hpb"
        archive = HPBArchive(
            (bad_type_bundle,) + self.archive.items[1:], self.archive.signature
        )
        with self.assertRaises(TypeError):
            make_hpap(archive, (0,))
        bad_value_bundle = HPB(
            HP(indices=(), total=0, bundles=(), siblings=()),
            DUMMY_OUTER_SIGNATURE,
        )
        archive = HPBArchive(
            (bad_value_bundle,) + self.archive.items[1:], self.archive.signature
        )
        with self.assertRaises(ValueError):
            make_hpap(archive, (0,))

    def test_total_at_2_pow_64_boundary_raises_value_error(self):
        # A count at or above 2**64 is a plain ValueError on every HPAP
        # construction path, never an OverflowError leaking from a bare
        # len()/U64 conversion.
        class HugeTuple(tuple):
            def __len__(self):
                return 2 ** 64

        huge_archive = HPBArchive(
            HugeTuple((self.archive.items[0],)),
            self.archive.signature,
        )
        with self.assertRaises(ValueError):
            make_hpap(huge_archive, (0,))
        with self.assertRaises(ValueError):
            make_hpap(self.archive, HugeTuple((0,)))


class CheckHPAPTest(unittest.TestCase):
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
            archive = HPBArchive(
                self.archive.items[:n], self.archive.signature
            )
            proof, signature = signed_proof(archive, indices, self.key)
            self.assertTrue(
                check_hpap(proof, signature, self.key),
                msg=f"n={n} indices={indices}",
            )

    def test_one_signature_covers_every_subset(self):
        archive = HPBArchive(
            self.archive.items[:5], self.archive.signature
        )
        message, _ = make_hpap(archive, (0,))
        signature = sign_message(self.key, message, seed=51350)
        for mask in range(1, 1 << 5):
            indices = tuple(i for i in range(5) if mask & (1 << i))
            _statement, proof = make_hpap(archive, indices)
            self.assertTrue(
                check_hpap(proof, signature, self.key),
                msg=f"indices={indices}",
            )

    def test_tampered_bundles_indices_and_siblings_return_false(self):
        indices = (0, 2, 4)
        proof, signature = signed_proof(self.archive, indices, self.key)
        swapped = HPAP(
            proof.indices,
            proof.total,
            (proof.bundles[1], proof.bundles[0], proof.bundles[2]),
            proof.siblings,
        )
        self.assertFalse(check_hpap(swapped, signature, self.key))
        moved = HPAP((0, 2, 5), proof.total, proof.bundles, proof.siblings)
        self.assertFalse(check_hpap(moved, signature, self.key))
        damaged = HPAP(
            proof.indices,
            proof.total,
            proof.bundles,
            (b"\x00" * 32,) + proof.siblings[1:],
        )
        self.assertFalse(check_hpap(damaged, signature, self.key))

    def test_missing_extra_and_misaligned_siblings_return_false(self):
        indices = (0, 3)
        proof, signature = signed_proof(self.archive, indices, self.key)
        self.assertGreater(len(proof.siblings), 1)
        short = HPAP(
            proof.indices, proof.total, proof.bundles, proof.siblings[:-1]
        )
        self.assertFalse(check_hpap(short, signature, self.key))
        long = HPAP(
            proof.indices,
            proof.total,
            proof.bundles,
            proof.siblings + (b"x" * 32,),
        )
        self.assertFalse(check_hpap(long, signature, self.key))
        rotated = HPAP(
            proof.indices,
            proof.total,
            proof.bundles,
            proof.siblings[1:] + proof.siblings[:1],
        )
        self.assertFalse(check_hpap(rotated, signature, self.key))

    def test_bundle_count_mismatch_returns_false(self):
        indices = (0, 2, 4)
        proof, signature = signed_proof(self.archive, indices, self.key)
        fewer = HPAP(
            proof.indices, proof.total, proof.bundles[:2], proof.siblings
        )
        self.assertFalse(check_hpap(fewer, signature, self.key))
        more = HPAP(
            proof.indices,
            proof.total,
            proof.bundles + (proof.bundles[0],),
            proof.siblings,
        )
        self.assertFalse(check_hpap(more, signature, self.key))

    def test_wrong_signature_and_wrong_key_return_false(self):
        indices = (0, 2)
        proof, signature = signed_proof(self.archive, indices, self.key)
        shortened = HPBArchive(
            self.archive.items[:4], self.archive.signature
        )
        other_message, _ = make_hpap(shortened, (0, 2))
        other_signature = sign_message(self.key, other_message, seed=51370)
        self.assertFalse(check_hpap(proof, other_signature, self.key))
        self.assertFalse(check_hpap(proof, signature, make_other_key()))

    def test_unverifying_nested_bundle_returns_false(self):
        indices = (0, 2)
        proof, signature = signed_proof(self.archive, indices, self.key)
        other_key = make_other_key()
        foreign = signed_hpb(
            hpb_archive_source(6, other_key, seed_base=51380),
            (0,),
            other_key,
            seed=51390,
        )
        mixed = HPAP(
            proof.indices,
            proof.total,
            (foreign, proof.bundles[1]),
            proof.siblings,
        )
        self.assertFalse(check_hpap(mixed, signature, self.key))

    def test_bad_bundle_does_not_mask_illegal_signature_or_key(self):
        # A structurally legal proof whose nested bundle merely fails
        # verification must not turn an illegal root signature or key
        # into a plain False: both structures are checked first.
        other_key = make_other_key()
        foreign = signed_hpb(
            hpb_archive_source(6, other_key, seed_base=51400),
            (0,),
            other_key,
            seed=51401,
        )
        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        mixed = HPAP(
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
                check_hpap(mixed, bad_signature, self.key)
        for bad_key in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad_key)):
                check_hpap(
                    mixed,
                    AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
                    bad_key,
                )

    def test_type_errors(self):
        proof, signature = signed_proof(self.archive, (0, 2), self.key)
        with self.assertRaises(TypeError):
            check_hpap("not-a-proof", signature, self.key)
        with self.assertRaises(TypeError):
            check_hpap(proof, "not-a-signature", self.key)
        for bad in (
            HPAP([0, 2], 8, proof.bundles, proof.siblings),
            HPAP((0, 2), "8", proof.bundles, proof.siblings),
            HPAP((0, 2), True, proof.bundles, proof.siblings),
            HPAP((0, True), 8, proof.bundles, proof.siblings),
            HPAP((0, 2), 8, list(proof.bundles), proof.siblings),
            HPAP((0, 2), 8, proof.bundles, list(proof.siblings)),
            HPAP((0, 2), 8, ("not-a-bundle",) * 2, proof.siblings),
            HPAP((0, 2), 8, proof.bundles, (b"x" * 32, 7)),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                check_hpap(bad, signature, self.key)

    def test_structure_value_errors(self):
        proof, signature = signed_proof(self.archive, (0, 2), self.key)
        for bad in (
            HPAP((0, 2), 0, proof.bundles, proof.siblings),
            HPAP((), 8, (), ()),
            HPAP((2, 0), 8, proof.bundles, proof.siblings),
            HPAP((1, 1), 8, proof.bundles, proof.siblings),
            HPAP((0, 8), 8, proof.bundles, proof.siblings),
            HPAP((0, 2), 8, proof.bundles, (b"short",)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                check_hpap(bad, signature, self.key)

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
            HPAP((0,), 2 ** 64, proof.bundles[:1], ()),
            HPAP((0,), 2 ** 64 + 1, proof.bundles[:1], ()),
        )
        for bad in integer_boundary:
            with self.assertRaises(ValueError, msg=repr(bad)):
                check_hpap(bad, signature, self.key)
        huge_fields = (
            HPAP(HugeTuple((0, 2)), 8, proof.bundles, proof.siblings),
            HPAP((0, 2), 8, HugeTuple(proof.bundles), proof.siblings),
            HPAP((0, 2), 8, proof.bundles, HugeTuple(proof.siblings)),
        )
        for bad in huge_fields:
            with self.assertRaises(ValueError, msg=repr(bad)):
                check_hpap(bad, signature, self.key)


if __name__ == "__main__":
    unittest.main()
