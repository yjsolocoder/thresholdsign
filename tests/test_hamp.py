"""Tests for compact multi-bundle Merkle membership proofs over the
non-empty order-preserving archive of whole SMP bundles:
HAMP / make_hamp / check_hamp."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    HAMP,
    SMP,
    SMPBundle,
    SMPBundleArchive,
    check_hamp,
    encode_smp_bundle,
    make_hamp,
)

from test_audit_chain import make_key, sign_message
from test_audit_extension_proof_bundle_codec import make_other_key
from test_smp import build_items, sign_root
from test_smp_bundle_archive import make_signed_bundle

LEAF_TAG = b"hamp/l"
NODE_TAG = b"hamp/n"
ROOT_TAG = b"hamp/r"

DUMMY_OUTER_SIGNATURE = AggregateSignature(R=5, z=7, signer_ids=(1, 3))


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big", signed=False)


def digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# Distinct (chain size, indices) combinations so each bundle encodes
# differently at every position.
COMBOS = (
    (7, (0, 2, 4)),
    (6, (1, 3)),
    (5, (3,)),
    (4, (0, 1, 2, 3)),
    (7, (1, 6)),
    (6, (2, 4)),
    (5, (0, 2)),
    (4, (1, 3)),
)


def bundles_of_size(n, key, seed_base=8000):
    """Build ``n`` distinct structurally legal, key-verifying SMP bundles."""
    seals = build_items(key)
    return tuple(
        make_signed_bundle(
            key,
            seals,
            COMBOS[position % len(COMBOS)][0],
            COMBOS[position % len(COMBOS)][1],
            seed=seed_base + position * 37,
        )
        for position in range(n)
    )


def archive_of_size(n, key, seed_base=8100):
    """An archive of ``n`` distinct bundles with a placeholder outer
    signature — make_hamp must never consult the archive's outer sign."""
    return SMPBundleArchive(
        bundles_of_size(n, key, seed_base=seed_base),
        DUMMY_OUTER_SIGNATURE,
    )


def independent_tree(bundles):
    """Build leaf level, internal levels (odd tail duplicated) and root."""
    leaves = tuple(
        digest(LEAF_TAG + u64(i) + digest(encode_smp_bundle(bundle)))
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


def signed_proof(archive, indices, key, *, seed=8300):
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

    def test_fields_have_no_defaults(self):
        for field in dataclasses.fields(HAMP):
            self.assertIs(field.default, dataclasses.MISSING, msg=field.name)
            self.assertIs(
                field.default_factory, dataclasses.MISSING, msg=field.name
            )

    def test_frozen_value_equality_and_hash(self):
        key = make_key()
        bundles = bundles_of_size(3, key, seed_base=8110)
        siblings = (b"a" * 32, b"b" * 32)
        proof = HAMP((0, 2), 3, (bundles[0], bundles[2]), siblings)
        self.assertEqual(
            proof,
            HAMP((0, 2), 3, (bundles[0], bundles[2]), siblings),
        )
        self.assertEqual(
            hash(proof),
            hash(HAMP((0, 2), 3, (bundles[0], bundles[2]), siblings)),
        )
        self.assertNotEqual(
            proof,
            HAMP((1, 2), 3, (bundles[1], bundles[2]), siblings),
        )
        self.assertNotEqual(
            proof,
            HAMP((0, 2), 3, (bundles[0], bundles[2]), siblings[::-1]),
        )
        self.assertEqual(
            {proof, HAMP((0, 2), 3, (bundles[0], bundles[2]), siblings)},
            {proof},
        )
        with self.assertRaises(FrozenInstanceError):
            proof.total = 4

    def test_construction_does_not_validate(self):
        # A plain frozen value: bogus fields construct; check_hamp is the
        # boundary that rejects them.
        HAMP("not-a-tuple", "not-an-int", None, b"not-a-tuple")
        HAMP((), 0, (), ())


class MakeHAMPTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()

    def test_returns_root_message_and_proof_for_many_shapes(self):
        for n in range(1, 9):
            archive = archive_of_size(n, self.key, seed_base=8200 + n)
            levels = independent_tree(archive.items)
            root = levels[-1][0]
            for indices in self._index_sets(n):
                with self.subTest(n=n, indices=indices):
                    message, proof = make_hamp(archive, indices)
                    self.assertEqual(
                        message, ROOT_TAG + u64(n) + root
                    )
                    self.assertEqual(proof.indices, tuple(indices))
                    self.assertEqual(proof.total, n)
                    self.assertEqual(
                        proof.bundles,
                        tuple(archive.items[i] for i in indices),
                    )
                    self.assertEqual(
                        proof.siblings,
                        independent_siblings(levels, tuple(indices)),
                    )
                    for sibling in proof.siblings:
                        self.assertIsInstance(sibling, bytes)
                        self.assertEqual(len(sibling), 32)

    @staticmethod
    def _index_sets(n):
        sets = [
            (0,), (n - 1,), tuple(range(n)),
        ]
        if n >= 2:
            sets += [(0, n - 1), (0, 1), (n - 2, n - 1)]
        if n >= 3:
            sets += [(0, n - 2), (1,), (n - 2,)]
        if n >= 4:
            sets += [(0, 2), (1, n - 1)]
        # Deduplicate while preserving order.
        seen = set()
        unique = []
        for value in sets:
            if value not in seen:
                seen.add(value)
                unique.append(value)
        return unique

    def test_single_leaf_tree_has_no_siblings(self):
        archive = archive_of_size(1, self.key, seed_base=8240)
        message, proof = make_hamp(archive, (0,))
        self.assertEqual(proof.siblings, ())
        levels = independent_tree(archive.items)
        self.assertEqual(
            message, ROOT_TAG + u64(1) + levels[-1][0]
        )

    def test_all_leaves_have_no_siblings(self):
        for n in (2, 3, 4, 5, 7, 8):
            archive = archive_of_size(n, self.key, seed_base=8250 + n)
            _message, proof = make_hamp(archive, tuple(range(n)))
            self.assertEqual(proof.siblings, (), msg=n)

    def test_odd_tail_self_pair_collects_no_sibling(self):
        # Width 3, only the tail disclosed: leaf 2 pairs with itself,
        # then its parent (position 1) needs one companion at level 1.
        archive = archive_of_size(3, self.key, seed_base=8260)
        levels = independent_tree(archive.items)
        _message, proof = make_hamp(archive, (2,))
        self.assertEqual(
            proof.siblings, independent_siblings(levels, (2,))
        )
        self.assertEqual(len(proof.siblings), 1)
        # The sole sibling is the level-1 left node H(L0 || L1).
        leaves = levels[0]
        self.assertEqual(
            proof.siblings[0],
            digest(NODE_TAG + leaves[0] + leaves[1]),
        )

    def test_bundles_follow_original_archive_order(self):
        archive = archive_of_size(5, self.key, seed_base=8270)
        _message, proof = make_hamp(archive, (4, 1, 0)[::-1])
        self.assertEqual(
            proof.bundles,
            (archive.items[0], archive.items[1], archive.items[4]),
        )

    def test_archive_outer_signature_is_never_consulted(self):
        # A structurally legal archive carrying a deliberately bogus
        # outer signature still produces the proof.
        archive = SMPBundleArchive(
            bundles_of_size(4, self.key, seed_base=8280),
            "not-even-a-signature",
        )
        message, proof = make_hamp(archive, (0, 3))
        self.assertEqual(proof.total, 4)
        self.assertTrue(message.startswith(ROOT_TAG))

    def test_same_input_is_deterministic_and_stateless(self):
        archive = archive_of_size(4, self.key, seed_base=8290)
        first_message, first = make_hamp(archive, (0, 2))
        second_message, second = make_hamp(archive, (0, 2))
        self.assertEqual(first_message, second_message)
        self.assertEqual(first, second)


class MakeHAMPErrorTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(4, self.key, seed_base=8320)

    def test_non_archive_type_error(self):
        for bad in (
            None, 42, "x", b"x", object(),
            self.archive.items,
            (self.archive.items, self.archive.signature),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                make_hamp(bad, (0,))

    def test_non_tuple_indices_type_error(self):
        for bad in ([0], iter((0,)), {0}, None, "indices", 0):
            with self.assertRaises(TypeError, msg=repr(bad)):
                make_hamp(self.archive, bad)

    def test_non_integer_index_type_error(self):
        for bad in (0.0, 1.5, "0", None, b"0"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                make_hamp(self.archive, (bad,))

    def test_boolean_index_type_error(self):
        with self.assertRaises(TypeError):
            make_hamp(self.archive, (False,))
        with self.assertRaises(TypeError):
            make_hamp(self.archive, (True,))

    def test_non_tuple_archive_items_type_error(self):
        archive = SMPBundleArchive(
            list(self.archive.items), DUMMY_OUTER_SIGNATURE
        )
        with self.assertRaises(TypeError):
            make_hamp(archive, (0,))

    def test_non_bundle_archive_element_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            archive = SMPBundleArchive(
                (bad,) + self.archive.items[1:], DUMMY_OUTER_SIGNATURE
            )
            with self.assertRaises(TypeError, msg=repr(bad)):
                make_hamp(archive, (0,))

    def test_empty_indices_value_error(self):
        with self.assertRaises(ValueError):
            make_hamp(self.archive, ())

    def test_index_out_of_range_value_error(self):
        for bad in ((4,), (5,), (0, 4), (-1,)):
            with self.assertRaises(ValueError, msg=repr(bad)):
                make_hamp(self.archive, bad)

    def test_non_increasing_or_duplicate_indices_value_error(self):
        for bad in ((2, 2), (3, 1), (0, 0), (1, 0, 2)):
            with self.assertRaises(ValueError, msg=repr(bad)):
                make_hamp(self.archive, bad)

    def test_illegal_nested_bundle_value_error(self):
        bad_bundle = SMPBundle(
            SMP(i=(), n=0, s=(), p=()),
            AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
        )
        archive = SMPBundleArchive(
            (bad_bundle,) + self.archive.items[1:], DUMMY_OUTER_SIGNATURE
        )
        with self.assertRaises(ValueError):
            make_hamp(archive, (0,))


class CheckHAMPVerdictTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.other = make_other_key()

    def test_verifying_proofs_are_true(self):
        for n in range(1, 9):
            archive = archive_of_size(n, self.key, seed_base=8400 + n)
            for indices in ((0,), (n - 1,), tuple(range(n))):
                proof, signature = signed_proof(
                    archive, indices, self.key, seed=8500
                )
                with self.subTest(n=n, indices=indices):
                    self.assertTrue(
                        check_hamp(proof, signature, self.key)
                    )

    def test_disclosed_companions_and_odd_tails_rebuild(self):
        for n, indices in (
            (3, (2,)),
            (3, (0, 2)),
            (5, (0, 4)),
            (5, (1, 3)),
            (7, (0, 2, 4, 6)),
            (7, (3,)),
        ):
            archive = archive_of_size(n, self.key, seed_base=8520 + n)
            proof, signature = signed_proof(
                archive, indices, self.key, seed=8530
            )
            self.assertTrue(check_hamp(proof, signature, self.key))

    def test_swap_bundles_is_false(self):
        archive = archive_of_size(4, self.key, seed_base=8540)
        proof, signature = signed_proof(
            archive, (0, 2), self.key, seed=8541
        )
        swapped = dataclasses.replace(
            proof, bundles=(proof.bundles[1], proof.bundles[0])
        )
        self.assertFalse(check_hamp(swapped, signature, self.key))

    def test_alter_bundle_content_is_false(self):
        archive = archive_of_size(4, self.key, seed_base=8550)
        replacement = archive_of_size(1, self.key, seed_base=8551).items[0]
        proof, signature = signed_proof(
            archive, (0, 2), self.key, seed=8552
        )
        altered = dataclasses.replace(
            proof,
            bundles=(replacement, proof.bundles[1]),
        )
        self.assertFalse(check_hamp(altered, signature, self.key))

    def test_alter_indices_is_false(self):
        archive = archive_of_size(4, self.key, seed_base=8560)
        proof, signature = signed_proof(
            archive, (0, 2), self.key, seed=8561
        )
        # Same bundles, different (still in-range, increasing) slots.
        altered = dataclasses.replace(proof, indices=(1, 2))
        self.assertFalse(check_hamp(altered, signature, self.key))
        altered = dataclasses.replace(proof, indices=(0, 3))
        self.assertFalse(check_hamp(altered, signature, self.key))

    def test_alter_total_is_false(self):
        archive = archive_of_size(4, self.key, seed_base=8570)
        proof, signature = signed_proof(
            archive, (0, 2), self.key, seed=8571
        )
        for total in (3, 5, 8):
            altered = dataclasses.replace(proof, total=total)
            self.assertFalse(
                check_hamp(altered, signature, self.key), msg=total
            )

    def test_flip_sibling_is_false(self):
        archive = archive_of_size(4, self.key, seed_base=8580)
        proof, signature = signed_proof(
            archive, (0, 2), self.key, seed=8581
        )
        raw = bytearray(proof.siblings[0])
        raw[-1] ^= 0x01
        altered = dataclasses.replace(
            proof,
            siblings=(bytes(raw),) + proof.siblings[1:],
        )
        self.assertFalse(check_hamp(altered, signature, self.key))

    def test_extra_sibling_is_false_without_raising(self):
        archive = archive_of_size(4, self.key, seed_base=8590)
        proof, signature = signed_proof(
            archive, (0, 2), self.key, seed=8591
        )
        altered = dataclasses.replace(
            proof, siblings=proof.siblings + (b"z" * 32,)
        )
        self.assertFalse(check_hamp(altered, signature, self.key))

    def test_missing_sibling_is_false_without_raising(self):
        archive = archive_of_size(4, self.key, seed_base=8600)
        proof, signature = signed_proof(
            archive, (0, 2), self.key, seed=8601
        )
        altered = dataclasses.replace(proof, siblings=proof.siblings[:1])
        self.assertFalse(check_hamp(altered, signature, self.key))

    def test_bundle_count_mismatch_is_false_without_raising(self):
        archive = archive_of_size(4, self.key, seed_base=8610)
        proof, signature = signed_proof(
            archive, (0, 2), self.key, seed=8611
        )
        too_few = dataclasses.replace(proof, bundles=proof.bundles[:1])
        self.assertFalse(check_hamp(too_few, signature, self.key))
        too_many = dataclasses.replace(
            proof, bundles=proof.bundles + (archive.items[1],)
        )
        self.assertFalse(check_hamp(too_many, signature, self.key))

    def test_tampered_root_signature_is_false(self):
        archive = archive_of_size(4, self.key, seed_base=8620)
        proof, signature = signed_proof(
            archive, (0, 2), self.key, seed=8621
        )
        tampered = AggregateSignature(
            R=signature.R,
            z=signature.z ^ 1 or 1,
            signer_ids=signature.signer_ids,
        )
        self.assertFalse(check_hamp(proof, tampered, self.key))

    def test_root_signature_over_another_statement_is_false(self):
        archive = archive_of_size(4, self.key, seed_base=8630)
        _message, proof = make_hamp(archive, (0, 2))
        # The root statement is ``tag || U64(total) || root`` over the
        # archive's bundles, so a signature over a different archive (a
        # different item count/root) cannot validate this proof.
        other_archive = archive_of_size(5, self.key, seed_base=8632)
        other_message, _other = make_hamp(other_archive, (1, 3))
        foreign = sign_root(self.key, other_message, seed=8631)
        self.assertFalse(check_hamp(proof, foreign, self.key))

    def test_other_key_is_false(self):
        archive = archive_of_size(4, self.key, seed_base=8640)
        proof, signature = signed_proof(
            archive, (0, 2), self.key, seed=8641
        )
        self.assertFalse(check_hamp(proof, signature, self.other))

    def test_inner_bundle_signed_under_other_key_is_false(self):
        # Structurally legal proof, but one disclosed bundle's own root
        # signature belongs to another key.
        archive = archive_of_size(2, self.key, seed_base=8650)
        foreign = archive_of_size(1, self.other, seed_base=8651).items[0]
        message, good_proof = make_hamp(archive, (0,))
        mixed = dataclasses.replace(good_proof, bundles=(foreign,))
        signature = sign_root(self.key, message, seed=8652)
        self.assertFalse(check_hamp(mixed, signature, self.key))


class CheckHAMPErrorTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(4, self.key, seed_base=8700)
        self.proof, self.signature = signed_proof(
            self.archive, (0, 2), self.key, seed=8701
        )

    def test_non_proof_type_error(self):
        for bad in (
            None, 42, "x", b"x", object(),
            (self.proof.indices, self.proof.total,
             self.proof.bundles, self.proof.siblings),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                check_hamp(bad, self.signature, self.key)

    def test_non_signature_type_error(self):
        for bad in (None, 42, "x", b"x", object(), (5, 7, (1, 3))):
            with self.assertRaises(TypeError, msg=repr(bad)):
                check_hamp(self.proof, bad, self.key)

    def test_non_key_type_error(self):
        for bad in (None, 42, "x", b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                check_hamp(self.proof, self.signature, bad)

    def test_bad_field_types_type_error(self):
        signature = self.signature
        good = self.proof
        cases = (
            dataclasses.replace(good, indices=[0, 2]),
            dataclasses.replace(good, indices=(0.0, 2.0)),
            dataclasses.replace(good, total=4.0),
            dataclasses.replace(good, total=True),
            dataclasses.replace(good, bundles=list(good.bundles)),
            dataclasses.replace(
                good, bundles=("not-a-bundle", good.bundles[1])
            ),
            dataclasses.replace(good, siblings=list(good.siblings)),
            dataclasses.replace(
                good,
                siblings=("not-bytes",) + good.siblings[1:],
            ),
        )
        for bad in cases:
            with self.assertRaises(TypeError, msg=repr(bad)):
                check_hamp(bad, signature, self.key)

    def test_bad_shapes_value_error(self):
        signature = self.signature
        good = self.proof
        cases = (
            dataclasses.replace(good, total=0),
            dataclasses.replace(good, total=-1),
            dataclasses.replace(good, total=2 ** 64),
            dataclasses.replace(good, indices=()),
            dataclasses.replace(good, indices=(4,)),
            dataclasses.replace(good, indices=(-1, 2)),
            dataclasses.replace(good, indices=(2, 0)),
            dataclasses.replace(good, indices=(2, 2)),
            dataclasses.replace(
                good,
                siblings=(b"short",) + good.siblings[1:],
            ),
            dataclasses.replace(
                good,
                siblings=tuple(b"x" * 33 for _ in good.siblings),
            ),
        )
        for bad in cases:
            with self.assertRaises(ValueError, msg=repr(bad)):
                check_hamp(bad, signature, self.key)

    def test_illegal_signature_structure_value_error(self):
        good = self.proof
        for bad in (
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=-1, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=7, signer_ids=()),
            AggregateSignature(R=5, z=7, signer_ids=(3, 1)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                check_hamp(good, bad, self.key)

    def test_bad_bundle_does_not_mask_illegal_signature_or_key(self):
        # Structure checks of signature/key happen before any verdict is
        # returned, so even with a tampered proof they must surface.
        flipped = bytearray(self.proof.siblings[0])
        flipped[0] ^= 1
        tampered = dataclasses.replace(
            self.proof,
            siblings=(bytes(flipped),) + self.proof.siblings[1:],
        )
        bad_signature = AggregateSignature(
            R=0, z=7, signer_ids=(1, 3)
        )
        with self.assertRaises(ValueError):
            check_hamp(tampered, bad_signature, self.key)
        with self.assertRaises(TypeError):
            check_hamp(tampered, self.signature, "not-a-key")
        broken_key = dataclasses.replace(self.key, public_key=0)
        with self.assertRaises(ValueError):
            check_hamp(tampered, self.signature, broken_key)


if __name__ == "__main__":
    unittest.main()
