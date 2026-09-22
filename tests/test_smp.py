"""Tests for compact multi-seal inclusion proofs over a chain of whole
delta report bundle archive seals: SMP / make_smp / check_smp."""

import dataclasses
import hashlib
import itertools
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    DeltaDiagnosis,
    DeltaReport,
    DeltaReportBundle,
    DeltaReportBundleArchive,
    DeltaReportBundleArchiveSeal,
    DeltaReportBundleArchiveSealChain,
    SMP,
    check_smp,
    encode_delta_report_bundle_archive_seal,
    make_smp,
)

from test_audit_chain import make_key, sign_message
from test_audit_extension_proof_bundle_codec import make_other_key
from test_delta_report_bundle_archive_codec import build_archives
from test_delta_report_bundle_archive_seal_codec import make_seal

LEAF_TAG = b"ds/l1"
NODE_TAG = b"ds/n1"
ROOT_TAG = b"ds/r1"


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def independent_leaf(index: int, seal: DeltaReportBundleArchiveSeal) -> bytes:
    """Build H(b"ds/l1" || U64(j) || H(E_j)) straight from the spec."""
    encoded = encode_delta_report_bundle_archive_seal(seal)
    return hashlib.sha256(
        LEAF_TAG + u64(index) + hashlib.sha256(encoded).digest()
    ).digest()


def independent_node(left: bytes, right: bytes) -> bytes:
    """Build H(b"ds/n1" || left || right) straight from the spec."""
    return hashlib.sha256(NODE_TAG + left + right).digest()


def independent_levels(items) -> list:
    """Build every tree level straight from the spec, odd tails copied."""
    level = tuple(
        independent_leaf(index, seal) for index, seal in enumerate(items)
    )
    levels = [level]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level = level + level[-1:]
        level = tuple(
            independent_node(level[index], level[index + 1])
            for index in range(0, len(level), 2)
        )
        levels.append(level)
    return levels


def independent_proof_p(items, indices) -> tuple:
    """Collect p exactly as the spec states: level by level leaf to root,
    positions left to right; disclosed companions and odd tails omitted."""
    levels = independent_levels(items)
    siblings = []
    positions = set(indices)
    for level in levels[:-1]:
        width = len(level)
        padded = level if width % 2 == 0 else level + level[-1:]
        next_positions = set()
        for position in sorted(positions):
            if width % 2 == 1 and position == width - 1:
                pass
            elif (position ^ 1) in positions:
                pass
            else:
                siblings.append(padded[position ^ 1])
            next_positions.add(position // 2)
        positions = next_positions
    return tuple(siblings)


def build_items(key):
    """Seven distinct structurally legal, key-verifying archive seals."""
    _key, _segments, full, first, second, _archives = build_archives()
    archives = (
        DeltaReportBundleArchive((full,)),
        DeltaReportBundleArchive((first, second)),
        DeltaReportBundleArchive((second, full, first)),
        DeltaReportBundleArchive((second, full)),
        DeltaReportBundleArchive((first,)),
        DeltaReportBundleArchive((full, second)),
        DeltaReportBundleArchive((full, first, second)),
    )
    return tuple(
        make_seal(archive, key, seed=2100 + index)
        for index, archive in enumerate(archives)
    )


def sign_root(key, message, *, seed):
    return sign_message(key, message, signer_ids=(1, 3), seed=seed)


class SMPShapeTest(unittest.TestCase):
    def test_fields_in_order(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(SMP)],
            ["i", "n", "s", "p"],
        )

    def test_frozen_positional_and_value_equal(self):
        key = make_key()
        items = build_items(key)
        indices = (0, 2)
        seals = (items[0], items[2])
        p = (b"\x01" * 32, b"\x02" * 32)
        proof = SMP(indices, 3, seals, p)
        self.assertIs(proof.i, indices)
        self.assertEqual(proof.n, 3)
        self.assertIs(proof.s, seals)
        self.assertIs(proof.p, p)
        self.assertEqual(proof, SMP(i=indices, n=3, s=seals, p=p))
        self.assertEqual(hash(proof), hash(SMP(indices, 3, seals, p)))
        self.assertNotEqual(proof, SMP((0, 1), 3, seals, p))
        self.assertNotEqual(proof, SMP(indices, 4, seals, p))
        self.assertNotEqual(proof, SMP(indices, 3, seals[::-1], p))
        self.assertNotEqual(
            proof, SMP(indices, 3, seals, (b"\x01" * 32, b"\x03" * 32))
        )
        self.assertEqual(
            {proof, SMP(indices, 3, seals, p)},
            {SMP(indices, 3, seals, p)},
        )
        with self.assertRaises(FrozenInstanceError):
            proof.n = 4

    def test_construction_does_not_validate(self):
        # A plain frozen value: junk fields construct; check_smp rejects.
        SMP("not-a-tuple", -1, None, "not-a-tuple")
        SMP(None, None, None, None)


class MakeSmpTreeTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.items = build_items(self.key)

    def _make(self, n, indices, *, chain_signature=None):
        chain = DeltaReportBundleArchiveSealChain(
            self.items[:n], chain_signature
        )
        return make_smp(chain, indices)

    def test_fields_take_n_and_items_by_indices(self):
        message, proof = self._make(5, (0, 2, 4))
        self.assertEqual(proof.n, 5)
        self.assertEqual(proof.i, (0, 2, 4))
        self.assertEqual(proof.s, (self.items[0], self.items[2], self.items[4]))
        for entry in proof.p:
            self.assertIsInstance(entry, bytes)
            self.assertEqual(len(entry), 32)

    def test_root_message_matches_independent_build(self):
        for n in range(1, 8):
            levels = independent_levels(self.items[:n])
            expected = ROOT_TAG + u64(n) + levels[-1][0]
            message, proof = self._make(n, (0,))
            self.assertEqual(message, expected, msg=f"n={n}")
            self.assertTrue(message.startswith(ROOT_TAG))
            self.assertEqual(len(message), 5 + 8 + 32)

    def test_p_matches_independent_level_walk_for_every_subset(self):
        for n in range(1, 8):
            for width in range(1, n + 1):
                for indices in itertools.combinations(range(n), width):
                    message, proof = self._make(n, indices)
                    expected_p = independent_proof_p(self.items[:n], indices)
                    self.assertEqual(
                        proof.p,
                        expected_p,
                        msg=f"n={n} indices={indices}",
                    )
                    # The same message/p no matter how the subset is chosen.
                    levels = independent_levels(self.items[:n])
                    self.assertEqual(
                        message,
                        ROOT_TAG + u64(n) + levels[-1][0],
                    )

    def test_disclosed_companions_are_never_in_p(self):
        # Both members of a pair disclosed: nothing sent at the leaf level.
        _message, proof = self._make(4, (0, 1))
        leaf0 = independent_leaf(0, self.items[0])
        leaf1 = independent_leaf(1, self.items[1])
        self.assertNotIn(leaf0, proof.p)
        self.assertNotIn(leaf1, proof.p)
        # Only the level-above companion remains.
        node_23 = independent_node(
            independent_leaf(2, self.items[2]),
            independent_leaf(3, self.items[3]),
        )
        self.assertEqual(proof.p, (node_23,))

    def test_odd_tail_is_copied_never_sent(self):
        # n=3, only the tail disclosed: at the leaf level the tail is
        # paired with itself, so neither leaf2 nor any copy of it is
        # sent; the only companion is the level-above node(0,1).
        _message, proof = self._make(3, (2,))
        node_01 = independent_node(
            independent_leaf(0, self.items[0]),
            independent_leaf(1, self.items[1]),
        )
        self.assertEqual(proof.p, (node_01,))
        tail_leaf = independent_leaf(2, self.items[2])
        self.assertNotIn(tail_leaf, proof.p)

    def test_full_disclosure_and_single_item_tree_send_nothing(self):
        for n in range(1, 8):
            _message, proof = self._make(n, tuple(range(n)))
            self.assertEqual(proof.p, (), msg=f"n={n}")
        _message, one = self._make(1, (0,))
        self.assertEqual(one.p, ())

    def test_p_order_is_level_by_level_left_to_right(self):
        # n=7, leaves 3 and 6 disclosed:
        # level 0 (width 7): pos 3 sends leaf2; pos 6 is the odd tail and
        #   sends nothing; the proven level-1 positions are 1 and 3.
        # level 1 (width 4): pos 1 sends node(0,1); pos 3 sends node(4,5)
        #   (the width is even, so the copied tail node has a companion).
        # level 2 (width 2): positions 0 and 1 are both disclosed, nothing.
        leaves = [independent_leaf(j, self.items[j]) for j in range(7)]
        node_01 = independent_node(leaves[0], leaves[1])
        node_23 = independent_node(leaves[2], leaves[3])
        node_45 = independent_node(leaves[4], leaves[5])
        _message, proof = self._make(7, (3, 6))
        self.assertEqual(
            proof.p,
            (leaves[2], node_01, node_45),
        )
        # The node never sent: both of its children were disclosed at
        # level 2.
        node_2345 = independent_node(node_23, node_45)
        self.assertNotIn(node_2345, proof.p)

    def test_deterministic_and_stateless(self):
        chain = DeltaReportBundleArchiveSealChain(self.items[:5], None)
        message_a, proof_a = make_smp(chain, (1, 3))
        message_b, proof_b = make_smp(chain, (1, 3))
        self.assertEqual(message_a, message_b)
        self.assertEqual(proof_a, proof_b)


class MakeSmpErrorTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.items = build_items(self.key)
        self.signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))

    def test_non_chain_type_error(self):
        for bad in ("x", None, 42, b"x", object(), self.items, self.items[0]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                make_smp(bad, (0,))

    def test_non_tuple_items_type_error(self):
        for bad in (list(self.items), iter(self.items), None, "items"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                make_smp(
                    DeltaReportBundleArchiveSealChain(bad, self.signature),
                    (0,),
                )

    def test_non_seal_element_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                make_smp(
                    DeltaReportBundleArchiveSealChain(
                        (bad,) + self.items[1:3], self.signature
                    ),
                    (0,),
                )

    def test_non_tuple_indices_type_error(self):
        chain = DeltaReportBundleArchiveSealChain(
            self.items[:3], self.signature
        )
        for bad in ([0, 1], iter((0, 1)), {0, 1}, (x for x in (0,))):
            with self.assertRaises(TypeError, msg=repr(bad)):
                make_smp(chain, bad)

    def test_boolean_index_type_error(self):
        chain = DeltaReportBundleArchiveSealChain(
            self.items[:3], self.signature
        )
        with self.assertRaises(TypeError):
            make_smp(chain, (False,))
        with self.assertRaises(TypeError):
            make_smp(chain, (0, True))

    def test_empty_chain_value_error(self):
        with self.assertRaises(ValueError):
            make_smp(
                DeltaReportBundleArchiveSealChain((), self.signature),
                (0,),
            )

    def test_empty_indices_value_error(self):
        chain = DeltaReportBundleArchiveSealChain(
            self.items[:3], self.signature
        )
        with self.assertRaises(ValueError):
            make_smp(chain, ())

    def test_indices_must_be_strictly_increasing(self):
        chain = DeltaReportBundleArchiveSealChain(
            self.items[:4], self.signature
        )
        for bad in ((1, 1), (2, 1), (0, 2, 2), (3, 2, 1)):
            with self.assertRaises(ValueError, msg=repr(bad)):
                make_smp(chain, bad)

    def test_index_out_of_range_value_error(self):
        chain = DeltaReportBundleArchiveSealChain(
            self.items[:3], self.signature
        )
        for bad in ((-1,), (3,), (4,), (0, 3)):
            with self.assertRaises(ValueError, msg=repr(bad)):
                make_smp(chain, bad)

    def test_illegal_nested_seal_value_error(self):
        bad_seal = DeltaReportBundleArchiveSeal(
            DeltaReportBundleArchive(()), self.signature
        )
        chain = DeltaReportBundleArchiveSealChain(
            (bad_seal,) + self.items[1:3], self.signature
        )
        with self.assertRaises(ValueError):
            make_smp(chain, (0, 1))


class CheckSmpVerdictTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.items = build_items(self.key)

    def _proof(self, n, indices, *, seed=2300):
        message, proof = make_smp(
            DeltaReportBundleArchiveSealChain(self.items[:n], None), indices
        )
        signature = sign_root(self.key, message, seed=seed)
        return proof, signature

    def test_every_subset_of_every_small_tree_verifies(self):
        for n in range(1, 8):
            for width in range(1, n + 1):
                for counter, indices in enumerate(
                    itertools.combinations(range(n), width)
                ):
                    proof, signature = self._proof(
                        n, indices, seed=4000 + n * 64 + width * 8 + counter
                    )
                    self.assertTrue(
                        check_smp(proof, signature, self.key),
                        msg=f"n={n} indices={indices}",
                    )

    def test_single_item_tree_verifies(self):
        proof, signature = self._proof(1, (0,))
        self.assertTrue(check_smp(proof, signature, self.key))

    def test_odd_tail_rebuilds_with_copy(self):
        # n=3 tail-only proof exercises the odd-tail self-pair branch on
        # both sides of the proof; the copy itself is not carried.
        proof, signature = self._proof(3, (2,))
        self.assertEqual(len(proof.p), 1)
        self.assertTrue(check_smp(proof, signature, self.key))

    def test_tampered_root_signature_is_false(self):
        proof, signature = self._proof(5, (1, 3))
        tampered = AggregateSignature(
            R=signature.R,
            z=signature.z,
            signer_ids=signature.signer_ids[:-1]
            + (signature.signer_ids[-1] ^ 0xFF,),
        )
        self.assertFalse(check_smp(proof, tampered, self.key))

    def test_signature_over_another_root_is_false(self):
        # The root depends only on n and the chain items, not on the
        # disclosed subset; a signature over a same-n chain with one
        # resealed item (a different canonical seal encoding) therefore
        # signs a different root and must not validate the proof.
        proof_a, _sig_a = self._proof(5, (1, 3), seed=2400)
        foreign_items = (
            self.items[0],
            make_seal(self.items[1].archive, self.key, seed=2402),
        ) + self.items[2:5]
        message_foreign, proof_foreign = make_smp(
            DeltaReportBundleArchiveSealChain(foreign_items, None), (1, 3)
        )
        signature_foreign = sign_root(
            self.key, message_foreign, seed=2403
        )
        self.assertFalse(check_smp(proof_a, signature_foreign, self.key))
        self.assertTrue(check_smp(proof_foreign, signature_foreign, self.key))

    def test_signature_for_another_n_is_false(self):
        proof, _signature = self._proof(5, (0, 2), seed=2410)
        message_other, _proof_other = make_smp(
            DeltaReportBundleArchiveSealChain(self.items[:4], None), (0, 2)
        )
        foreign = sign_root(self.key, message_other, seed=2411)
        self.assertFalse(check_smp(proof, foreign, self.key))

    def test_swapped_disclosed_seals_is_false(self):
        proof, signature = self._proof(6, (0, 2, 4), seed=2420)
        swapped = SMP(
            proof.i, proof.n, (proof.s[1], proof.s[0], proof.s[2]), proof.p
        )
        self.assertFalse(check_smp(swapped, signature, self.key))

    def test_seal_at_wrong_position_is_false(self):
        proof, signature = self._proof(5, (0, 2), seed=2430)
        moved = SMP(
            proof.i, proof.n, (self.items[2], self.items[0]), proof.p
        )
        self.assertFalse(check_smp(moved, signature, self.key))

    def test_tampered_companion_is_false(self):
        proof, signature = self._proof(5, (0, 2, 4), seed=2440)
        self.assertTrue(len(proof.p) >= 1)
        tampered_p = (
            (proof.p[0][:-1] + bytes([proof.p[0][-1] ^ 0xFF]),)
            + proof.p[1:]
        )
        tampered = SMP(proof.i, proof.n, proof.s, tampered_p)
        self.assertFalse(check_smp(tampered, signature, self.key))

    def test_companion_reordered_is_false(self):
        proof, signature = self._proof(7, (3, 6), seed=2450)
        self.assertGreaterEqual(len(proof.p), 2)
        reordered = SMP(
            proof.i,
            proof.n,
            proof.s,
            (proof.p[1], proof.p[0]) + proof.p[2:],
        )
        self.assertFalse(check_smp(reordered, signature, self.key))

    def test_failing_nested_seal_is_false_not_raised(self):
        _key, _segments, full, first, _second, _archives = build_archives()
        diagnosis = DeltaDiagnosis(False, "sig", 0, None)
        bad_bundle = DeltaReportBundle(
            full.segments,
            DeltaReport(
                diagnosis,
                full.report.public_key,
                full.report.signature,
            ),
        )
        bad_seal = make_seal(
            DeltaReportBundleArchive((first, bad_bundle)),
            self.key,
            seed=2460,
        )
        items = (self.items[0], bad_seal, self.items[2])
        message, proof = make_smp(
            DeltaReportBundleArchiveSealChain(items, None), (0, 1, 2)
        )
        signature = sign_root(self.key, message, seed=2461)
        self.assertFalse(check_smp(proof, signature, self.key))

    def test_other_key_is_false(self):
        proof, signature = self._proof(4, (1,), seed=2470)
        self.assertFalse(check_smp(proof, signature, make_other_key()))


class CheckSmpErrorTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.items = build_items(self.key)
        message, self.proof = make_smp(
            DeltaReportBundleArchiveSealChain(self.items[:4], None), (0, 2)
        )
        self.signature = sign_root(self.key, message, seed=2500)

    def test_non_proof_type_error(self):
        for bad in ("x", None, 42, b"x", object(), self.proof.i):
            with self.assertRaises(TypeError, msg=repr(bad)):
                check_smp(bad, self.signature, self.key)

    def test_non_signature_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                check_smp(self.proof, bad, self.key)

    def test_non_key_type_error(self):
        for bad in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                check_smp(self.proof, self.signature, bad)

    def test_wrong_field_types_type_error(self):
        good = self.proof
        for bad_proof in (
            SMP(list(good.i), good.n, good.s, good.p),
            SMP(good.i, True, good.s, good.p),
            SMP(good.i, good.n, list(good.s), good.p),
            SMP(good.i, good.n, good.s, list(good.p)),
            SMP((False,) + good.i[1:], good.n, good.s, good.p),
        ):
            with self.assertRaises(TypeError, msg=repr(bad_proof)):
                check_smp(bad_proof, self.signature, self.key)
        for bad_proof in (
            SMP(good.i, good.n, ("not-a-seal",) * len(good.s), good.p),
            SMP(good.i, good.n, good.s, ("not-bytes",) * len(good.p)),
        ):
            with self.assertRaises(TypeError, msg=repr(bad_proof)):
                check_smp(bad_proof, self.signature, self.key)

    def test_bad_n_value_error(self):
        good = self.proof
        for bad_n in (0, -1, 2 ** 64, 2 ** 65):
            with self.assertRaises(ValueError, msg=repr(bad_n)):
                check_smp(
                    SMP(good.i, bad_n, good.s, good.p),
                    self.signature,
                    self.key,
                )

    def test_empty_indices_value_error(self):
        with self.assertRaises(ValueError):
            check_smp(
                SMP((), self.proof.n, (), ()),
                self.signature,
                self.key,
            )

    def test_indices_not_strict_or_out_of_range_value_error(self):
        good = self.proof
        for bad_indices in (
            (2, 0),
            (0, 0),
            (-1, 2),
            (0, 4),
            (4,),
        ):
            seals = tuple(self.items[j] if 0 <= j < good.n else self.items[0]
                          for j in bad_indices)
            with self.assertRaises(ValueError, msg=repr(bad_indices)):
                check_smp(
                    SMP(bad_indices, good.n, seals, ()),
                    self.signature,
                    self.key,
                )

    def test_s_length_mismatch_value_error(self):
        good = self.proof
        with self.assertRaises(ValueError):
            check_smp(
                SMP(good.i, good.n, good.s + (self.items[1],), good.p),
                self.signature,
                self.key,
            )
        with self.assertRaises(ValueError):
            check_smp(
                SMP(good.i, good.n, good.s[:1], ()),
                self.signature,
                self.key,
            )

    def test_illegal_nested_seal_structure_value_error(self):
        bad_signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        bad_seal = DeltaReportBundleArchiveSeal(
            DeltaReportBundleArchive(()), bad_signature
        )
        good = self.proof
        bad_proof = SMP(
            good.i, good.n, (bad_seal, good.s[1]), ()
        )
        with self.assertRaises(ValueError):
            check_smp(bad_proof, self.signature, self.key)

    def test_p_entries_must_be_exactly_32_bytes(self):
        good = self.proof
        for bad_entry in (b"", b"\x00" * 31, b"\x00" * 33):
            bad_p = (bad_entry,) + good.p[1:]
            with self.assertRaises(ValueError, msg=repr(bad_entry)):
                check_smp(
                    SMP(good.i, good.n, good.s, bad_p),
                    self.signature,
                    self.key,
                )

    def test_p_count_must_be_the_one_determined_by_n_and_i(self):
        good = self.proof
        # n=4, i=(0,2) carries exactly two companions (leaf 1 and leaf 3;
        # the level above is fully disclosed). One extra or two fewer is
        # a structural ValueError, not a False verdict.
        self.assertEqual(len(good.p), 2)
        with self.assertRaises(ValueError):
            check_smp(
                SMP(good.i, good.n, good.s, ()),
                self.signature,
                self.key,
            )
        with self.assertRaises(ValueError):
            check_smp(
                SMP(good.i, good.n, good.s, good.p + (b"\x09" * 32,)),
                self.signature,
                self.key,
            )

    def test_illegal_root_signature_structure_value_error(self):
        good_seal = self.items[0].signature
        for bad_signature in (
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=good_seal.R, z=-1, signer_ids=(1, 3)),
            AggregateSignature(R=good_seal.R, z=7, signer_ids=()),
            AggregateSignature(R=good_seal.R, z=7, signer_ids=(3, 1)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad_signature)):
                check_smp(self.proof, bad_signature, self.key)

    def test_bad_illegal_key_structure_value_error(self):
        broken_key = dataclasses.replace(self.key, public_key=0)
        with self.assertRaises(ValueError):
            check_smp(self.proof, self.signature, broken_key)


if __name__ == "__main__":
    unittest.main()
