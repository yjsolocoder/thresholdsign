"""Tests for compact multi-seal Merkle inclusion proofs over chains of
whole delta report bundle archive seals: SMP / make_smp / check_smp."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    DeltaReportBundleArchive,
    DeltaReportBundleArchiveSeal,
    DeltaReportBundleArchiveSealChain,
    SMP,
    check_smp,
    drasc_message,
    encode_delta_report_bundle_archive_seal,
    make_smp,
    verify_dc,
)

from test_audit_chain import sign_message
from test_audit_extension_proof_bundle_codec import make_other_key
from test_delta_report_bundle_archive_codec import build_archives
from test_delta_report_bundle_archive_seal_codec import make_seal

LEAF_TAG = b"ds/l1"
NODE_TAG = b"ds/n1"
ROOT_TAG = b"ds/r1"


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big", signed=False)


def digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def make_chain(items, key, *, signer_ids=(1, 3), seed=5100):
    """Seal a tuple of archive seals with one outer signature of ``key``."""
    message = drasc_message(items, key.public_key)
    signature = sign_message(
        key, message, signer_ids=signer_ids, seed=seed
    )
    return DeltaReportBundleArchiveSealChain(items, signature)


def build_seals(key, count):
    """``count`` distinct, genuinely sealed archives over ``key``."""
    _key, _segments, full, first, _second, _archives = build_archives()
    seals = []
    for index in range(count):
        archive = DeltaReportBundleArchive(
            (full, first) if index % 2 else (full,)
        )
        seals.append(make_seal(archive, key, seed=5200 + index))
    return tuple(seals)


def independent_tree(items):
    """Build leaf level, internal levels (odd tail duplicated) and root."""
    leaves = tuple(
        digest(
            LEAF_TAG
            + u64(index)
            + digest(encode_delta_report_bundle_archive_seal(item))
        )
        for index, item in enumerate(items)
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


def independent_root_message(levels, count):
    """The root statement ``b"ds/r1" || U64(n) || root`` straight from spec."""
    return ROOT_TAG + u64(count) + levels[-1][0]


def independent_siblings(levels, indices):
    """Reference compact companion list: ascending levels, left to right,
    disclosed companions and odd-tail self-pairs omitted."""
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


class SMPShapeTest(unittest.TestCase):
    def setUp(self):
        self.key, _s, _f, _first, _second, _a = build_archives()
        self.seals = build_seals(self.key, 4)

    def test_fields_in_order(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(SMP)],
            ["i", "n", "s", "p"],
        )

    def test_frozen_positional_and_value_equal(self):
        indices = (0, 2)
        seals = (self.seals[0], self.seals[2])
        path = (b"a" * 32, b"b" * 32)
        proof = SMP(indices, 4, seals, path)
        self.assertIs(proof.i, indices)
        self.assertEqual(proof.n, 4)
        self.assertIs(proof.s, seals)
        self.assertIs(proof.p, path)
        self.assertEqual(proof, SMP(indices, 4, seals, path))
        self.assertEqual(hash(proof), hash(SMP(indices, 4, seals, path)))
        self.assertNotEqual(proof, SMP((0,), 4, seals[:1], path))
        self.assertNotEqual(proof, SMP(indices, 3, seals, path))
        self.assertNotEqual(
            proof,
            SMP(indices, 4, (self.seals[1], self.seals[3]), path),
        )
        self.assertNotEqual(
            proof,
            SMP(indices, 4, seals, (b"c" * 32, b"b" * 32)),
        )
        self.assertEqual({proof, SMP(indices, 4, seals, path)}, {proof})
        for field in ("i", "n", "s", "p"):
            with self.subTest(field=field):
                with self.assertRaises(FrozenInstanceError):
                    setattr(proof, field, None)

    def test_construction_does_not_validate(self):
        # A plain frozen value: anything constructs; check_smp validates.
        SMP("not-a-tuple", "not-an-int", "not-a-tuple", "not-a-tuple")
        SMP(None, None, None, None)


class MakeSMPTest(unittest.TestCase):
    def setUp(self):
        self.key, _s, _f, _first, _second, _a = build_archives()
        self.count = 7
        self.seals = build_seals(self.key, self.count)
        self.chain = make_chain(self.seals, self.key, seed=5300)
        self.levels = independent_tree(self.seals)

    def test_matches_independent_spec_build(self):
        cases = [
            (0,), (6,), (0, 6), (0, 2, 4), (1, 3, 5),
            (0, 1, 2, 3, 4, 5, 6), (3,), (2, 3), (5, 6),
            (0, 1), (2, 3, 4), (0, 6),
        ]
        for indices in cases:
            with self.subTest(indices=indices):
                message, proof = make_smp(self.chain, indices)
                self.assertEqual(
                    message,
                    independent_root_message(self.levels, self.count),
                )
                self.assertEqual(proof.i, indices)
                self.assertEqual(proof.n, self.count)
                self.assertEqual(
                    proof.s, tuple(self.seals[j] for j in indices)
                )
                self.assertEqual(
                    proof.p, independent_siblings(self.levels, indices)
                )
                for entry in proof.p:
                    self.assertIsInstance(entry, bytes)
                    self.assertEqual(len(entry), 32)

    def test_single_item_chain_has_empty_companions(self):
        chain = make_chain(self.seals[:1], self.key, seed=5301)
        levels = independent_tree(self.seals[:1])
        message, proof = make_smp(chain, (0,))
        self.assertEqual(message, independent_root_message(levels, 1))
        self.assertEqual(proof.p, ())
        self.assertEqual(proof.s, (self.seals[0],))

    def test_all_leaves_disclosed_carries_no_companions(self):
        indices = tuple(range(self.count))
        _message, proof = make_smp(self.chain, indices)
        self.assertEqual(proof.p, ())

    def test_odd_tail_adds_no_companion(self):
        # n = 5: index 4 is the odd tail at leaf level and never needs a
        # companion on any level it survives alone.
        seals = self.seals[:5]
        chain = make_chain(seals, self.key, seed=5302)
        levels = independent_tree(seals)
        for indices in ((4,), (0, 4), (2, 4), (0, 2, 4)):
            with self.subTest(indices=indices):
                _message, proof = make_smp(chain, indices)
                self.assertEqual(
                    proof.p, independent_siblings(levels, indices)
                )

    def test_companions_sent_once_and_ordered_levels_left_to_right(self):
        # n = 4, proving (0, 3): leaf companions are positions 1 and 2
        # (level 0, left to right), then nodes 1 and 2 pair into parent 1,
        # disclosed nodes 0 and 3 pair to parent 0; parent 0 needs parent
        # 1 once at level 1.
        _message, proof = make_smp(self.chain, (0, 3))
        expected = independent_siblings(self.levels, (0, 3))
        self.assertEqual(proof.p, expected)
        self.assertEqual(len(proof.p), 3)

    def test_does_not_require_outer_chain_signature(self):
        # make_smp is structural: a chain with a junk outer signature still
        # produces the same proof; check_smp never inspects the chain.
        junk = AggregateSignature(R=1, z=1, signer_ids=(1,))
        chain = DeltaReportBundleArchiveSealChain(self.seals, junk)
        message, proof = make_smp(chain, (0, 2))
        good_message, good_proof = make_smp(self.chain, (0, 2))
        self.assertEqual(message, good_message)
        self.assertEqual(proof, good_proof)

    def test_wrong_argument_types(self):
        with self.assertRaises(TypeError):
            make_smp("not-a-chain", (0,))
        with self.assertRaises(TypeError):
            make_smp(self.seals, (0,))
        with self.assertRaises(TypeError):
            make_smp(self.chain, [0])
        with self.assertRaises(TypeError):
            make_smp(self.chain, (b"0",))
        with self.assertRaises(TypeError):
            make_smp(self.chain, (0, "1"))

    def test_boolean_index_is_a_type_error(self):
        with self.assertRaises(TypeError):
            make_smp(self.chain, (False,))
        with self.assertRaises(TypeError):
            make_smp(self.chain, (True,))
        # A boolean appearing after a valid index is still rejected.
        with self.assertRaises(TypeError):
            make_smp(self.chain, (0, True))

    def test_bad_index_values(self):
        with self.assertRaises(ValueError):
            make_smp(self.chain, ())
        with self.assertRaises(ValueError):
            make_smp(self.chain, (0, 0))
        with self.assertRaises(ValueError):
            make_smp(self.chain, (2, 1))
        with self.assertRaises(ValueError):
            make_smp(self.chain, (-1,))
        with self.assertRaises(ValueError):
            make_smp(self.chain, (self.count,))

    def test_bad_chain_structure(self):
        junk = AggregateSignature(R=1, z=1, signer_ids=(1,))
        # Non-tuple items: TypeError on the field.
        chain = DeltaReportBundleArchiveSealChain("items", junk)
        with self.assertRaises(TypeError):
            make_smp(chain, (0,))
        # Non-seal element: TypeError.
        chain = DeltaReportBundleArchiveSealChain(("seal",), junk)
        with self.assertRaises(TypeError):
            make_smp(chain, (0,))
        # Empty tuple: ValueError.
        chain = DeltaReportBundleArchiveSealChain((), junk)
        with self.assertRaises(ValueError):
            make_smp(chain, (0,))


class CheckSMPTest(unittest.TestCase):
    def setUp(self):
        self.key, _s, _f, _first, _second, _a = build_archives()
        self.count = 7
        self.seals = build_seals(self.key, self.count)
        self.chain = make_chain(self.seals, self.key, seed=5400)
        self.assertTrue(verify_dc(self.chain, self.key))

    def _sign(self, message, seed=5450):
        return sign_message(
            self.key, message, signer_ids=(1, 3), seed=seed
        )

    def test_accepts_every_disclosure_pattern(self):
        cases = [
            (0,), (6,), (0, 6), (0, 2, 4), (1, 3, 5),
            tuple(range(self.count)), (3,), (2, 3), (5, 6),
        ]
        for offset, indices in enumerate(cases):
            with self.subTest(indices=indices):
                message, proof = make_smp(self.chain, indices)
                self.assertTrue(
                    check_smp(proof, self._sign(message, 5500 + offset), self.key)
                )

    def test_single_item_chain(self):
        chain = make_chain(self.seals[:1], self.key, seed=5401)
        message, proof = make_smp(chain, (0,))
        self.assertTrue(check_smp(proof, self._sign(message, 5590), self.key))

    def test_signature_on_other_message_fails(self):
        _message, proof = make_smp(self.chain, (0, 2))
        signature = self._sign(b"a different message", 5600)
        self.assertFalse(check_smp(proof, signature, self.key))

    def test_wrong_key_fails(self):
        message, proof = make_smp(self.chain, (0, 2))
        other = make_other_key()
        self.assertFalse(check_smp(proof, self._sign(message, 5601), other))

    def test_swapped_seal_fails_without_raising(self):
        message, proof = make_smp(self.chain, (0,))
        swapped = SMP((0,), proof.n, (self.seals[1],), proof.p)
        self.assertFalse(
            check_smp(swapped, self._sign(message, 5602), self.key)
        )

    def test_seal_for_other_key_fails(self):
        other = make_other_key()
        foreign = build_seals(other, 1)[0]
        message, proof = make_smp(self.chain, (0,))
        substituted = SMP((0,), proof.n, (foreign,), proof.p)
        self.assertFalse(
            check_smp(substituted, self._sign(message, 5603), self.key)
        )

    def test_tampered_companion_fails(self):
        message, proof = make_smp(self.chain, (0,))
        self.assertTrue(proof.p)
        bad_p = (bytes(32),) + proof.p[1:]
        tampered = SMP(proof.i, proof.n, proof.s, bad_p)
        self.assertFalse(
            check_smp(tampered, self._sign(message, 5604), self.key)
        )

    def test_changed_count_fails(self):
        message, proof = make_smp(self.chain, (0,))
        # Claiming n = 4 changes the pairing structure: (0,) then needs two
        # companions, but the proof for n = 7 carries three, so structure
        # validation rejects the mismatch before any root is rebuilt.
        changed = SMP(proof.i, 4, proof.s, proof.p)
        with self.assertRaises(ValueError):
            check_smp(changed, self._sign(message, 5605), self.key)

    def test_wrong_field_types_raise_type_error(self):
        message, proof = make_smp(self.chain, (0,))
        signature = self._sign(message, 5610)
        cases = [
            ("proof", signature, self.key),
            (proof, "signature", self.key),
            (proof, signature, "key"),
        ]
        for args in cases:
            with self.subTest(args=args):
                with self.assertRaises(TypeError):
                    check_smp(*args)
        bad_proofs = [
            SMP("indices", proof.n, proof.s, proof.p),
            SMP(proof.i, "n", proof.s, proof.p),
            SMP(proof.i, True, proof.s, proof.p),
            SMP(proof.i, proof.n, "seals", proof.p),
            SMP(proof.i, proof.n, proof.s, "path"),
        ]
        for bad in bad_proofs:
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    check_smp(bad, signature, self.key)

    def test_bad_structure_raises_value_error(self):
        message, proof = make_smp(self.chain, (0,))
        signature = self._sign(message, 5620)
        bad_proofs = [
            SMP((), proof.n, (), ()),                          # empty i
            SMP((0, 0), proof.n, proof.s + proof.s, ()),       # not unique
            SMP((1, 0), proof.n, (self.seals[1], self.seals[0]), ()),
            SMP((-1,), proof.n, proof.s[:1], proof.p),         # negative
            SMP((proof.n,), proof.n, proof.s[:1], proof.p),    # out of range
            SMP((0,), 0, proof.s, proof.p),                    # non-positive n
            SMP((0,), 2 ** 64, proof.s, proof.p),              # n too large
            SMP((0,), proof.n, proof.s[:1], (b"short",)),      # bad p width
            SMP(proof.i, proof.n, proof.s, proof.p + (bytes(32),)),  # extra p
            SMP(proof.i, proof.n, proof.s, ()),                # missing p
        ]
        for bad in bad_proofs:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    check_smp(bad, signature, self.key)

    def test_wrong_element_types_raise_type_error(self):
        message, proof = make_smp(self.chain, (0,))
        signature = self._sign(message, 5630)
        with self.assertRaises(TypeError):
            check_smp(
                SMP((0,), proof.n, ("seal",), proof.p),
                signature,
                self.key,
            )
        with self.assertRaises(TypeError):
            check_smp(
                SMP((0,), proof.n, proof.s, (1,)),
                signature,
                self.key,
            )
        with self.assertRaises(TypeError):
            check_smp(
                SMP((False,), proof.n, proof.s[:1], ()),
                signature,
                self.key,
            )

    def test_illegal_signature_structure_raises_value_error(self):
        _message, proof = make_smp(self.chain, (0,))
        signature = AggregateSignature(R=0, z=0, signer_ids=(1,))
        with self.assertRaises(ValueError):
            check_smp(proof, signature, self.key)


if __name__ == "__main__":
    unittest.main()
