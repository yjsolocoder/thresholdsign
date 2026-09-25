"""Tests for compact multi-seal Merkle membership proofs over the
non-empty order-preserving chain of whole history-delta-segments seals:
HDSCProof / make_hdsc_proof / check_hdsc_proof."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    HDSCProof,
    HistoryDeltaSegmentsSeal,
    HistoryDeltaSegmentsSealChain,
    check_hdsc_proof,
    encode_hds,
    encode_hdsc_proof,
    decode_hdsc_proof,
    make_hdsc_proof,
)

from test_nonce_leak_codec import make_other_key
from test_nonce_reuse import FIELD_PRIME, make_key
from test_audit_chain import sign_message
from test_history_delta_segments_codec import build_segments
from test_history_delta_segments_seal import make_seal
from test_history_delta_segments_seal_chain import make_chain

LEAF_TAG = b"ts/hdscp/l1"
NODE_TAG = b"ts/hdscp/n1"
ROOT_TAG = b"ts/hdscp/r1"


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big", signed=False)


def digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def independent_tree(seals):
    """Build leaf level, internal levels (odd tail duplicated) and root."""
    leaves = tuple(
        digest(LEAF_TAG + u64(i) + digest(encode_hds(seal)))
        for i, seal in enumerate(seals)
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


def seals_of_size(n, key, seed_base=3200):
    """Build ``n`` distinct structurally legal seals for ``key``."""
    _other_key, _delta, segments = build_segments()
    combos = (
        (segments[0],),
        (segments[1],),
        (segments[2],),
        (segments[0], segments[1]),
        (segments[1], segments[2]),
        segments,
    )
    return tuple(
        make_seal(combos[position % len(combos)], key, seed=seed_base + position)
        for position in range(n)
    )


def chain_of_size(n, key, seed_base=3400):
    """Seal a chain of ``n`` distinct seals with one outer signature."""
    return make_chain(
        seals_of_size(n, key), key, seed=seed_base + n
    )


def signed_proof(chain, indices, key, *, seed=3600):
    """Return (proof, signature) for a threshold-signed proof statement."""
    message, proof = make_hdsc_proof(chain, indices)
    signature = sign_message(key, message, seed=seed + sum(indices))
    return proof, signature


class HDSCProofDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(HDSCProof)],
            ["indices", "total", "seals", "siblings"],
        )
        key, _delta, segments = build_segments()
        seal = make_seal((segments[0],), key, seed=3010)
        seals = (seal,)
        siblings = (b"s" * 32,)
        proof = HDSCProof((1,), 3, seals, siblings)
        self.assertEqual(
            (proof.indices, proof.total, proof.seals, proof.siblings),
            ((1,), 3, seals, siblings),
        )

    def test_frozen_value_equality_and_hash(self):
        key, _delta, segments = build_segments()
        seal_a = make_seal((segments[0],), key, seed=3020)
        seal_b = make_seal((segments[1],), key, seed=3021)
        seals = (seal_a, seal_b)
        siblings = (b"s" * 32, b"t" * 32)
        proof = HDSCProof((1, 3), 4, seals, siblings)
        same = HDSCProof(
            indices=(1, 3), total=4, seals=seals, siblings=siblings
        )
        self.assertEqual(proof, same)
        self.assertEqual(hash(proof), hash(same))
        for changed in (
            HDSCProof((1, 2), 4, seals, siblings),
            HDSCProof((1, 3), 5, seals, siblings),
            HDSCProof((1, 3), 4, (seal_a, seal_a), siblings),
            HDSCProof((1, 3), 4, seals, (b"s" * 32,)),
        ):
            self.assertNotEqual(proof, changed)
        with self.assertRaises(FrozenInstanceError):
            proof.total = 5

    def test_construction_does_not_validate(self):
        # A plain value: out-of-range indices, non-tuple fields and
        # non-seal values all construct; the maker and checker reject them.
        key, _delta, segments = build_segments()
        seal = make_seal((segments[0],), key, seed=3030)
        HDSCProof((9,), 1, (seal,), ())
        HDSCProof((0,), 0, ("not-a-seal",), b"x")
        HDSCProof((), 3, (seal,), (b"",))


class MakeHDSCProofTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.chain = chain_of_size(8, self.key)

    def _chain_of_size(self, n):
        return HistoryDeltaSegmentsSealChain(
            self.chain.seals[:n], self.chain.signature
        )

    def test_statement_layout_for_every_size_and_subset(self):
        for n in range(1, 9):
            chain = self._chain_of_size(n)
            root = independent_tree(chain.seals)[-1][0]
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                message, proof = make_hdsc_proof(chain, indices)
                self.assertTrue(message.startswith(ROOT_TAG))
                self.assertEqual(
                    message[len(ROOT_TAG):len(ROOT_TAG) + 8], u64(n)
                )
                self.assertEqual(message[len(ROOT_TAG) + 8:], root)
                self.assertEqual(len(message), len(ROOT_TAG) + 8 + 32)
                self.assertEqual(proof.total, n)
                self.assertTrue(all(len(s) == 32 for s in proof.siblings))

    def test_seals_pair_one_to_one_with_indices(self):
        indices = (0, 2, 4)
        _message, proof = make_hdsc_proof(self.chain, indices)
        self.assertEqual(proof.indices, indices)
        self.assertEqual(
            proof.seals, tuple(self.chain.seals[i] for i in indices)
        )
        self.assertIs(proof.seals[1], self.chain.seals[2])

    def test_siblings_match_independent_builder(self):
        for n in range(1, 9):
            chain = self._chain_of_size(n)
            levels = independent_tree(chain.seals)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                _message, proof = make_hdsc_proof(chain, indices)
                self.assertEqual(
                    proof.siblings,
                    independent_siblings(levels, indices),
                    msg=f"n={n} indices={indices}",
                )

    def test_proving_every_seal_needs_no_siblings(self):
        for n in range(1, 9):
            chain = self._chain_of_size(n)
            _message, proof = make_hdsc_proof(chain, tuple(range(n)))
            self.assertEqual(proof.siblings, ())

    def test_deterministic(self):
        message, proof = make_hdsc_proof(self.chain, (0, 2, 4))
        message2, proof2 = make_hdsc_proof(self.chain, (0, 2, 4))
        self.assertEqual(message, message2)
        self.assertEqual(proof, proof2)

    def test_root_is_order_and_content_bound(self):
        message, _ = make_hdsc_proof(self.chain, (0, 2))
        reordered = HistoryDeltaSegmentsSealChain(
            (self.chain.seals[1], self.chain.seals[0])
            + self.chain.seals[2:],
            self.chain.signature,
        )
        self.assertNotEqual(
            message, make_hdsc_proof(reordered, (0, 2))[0]
        )
        shortened = self._chain_of_size(4)
        self.assertNotEqual(
            message, make_hdsc_proof(shortened, (0, 2))[0]
        )

    def test_chain_outer_signature_is_not_consulted(self):
        # The proof comes from the seals alone: a chain with no usable
        # outer signature still builds the same statement.
        unsigned = HistoryDeltaSegmentsSealChain(
            self.chain.seals, "not-a-signature"
        )
        self.assertEqual(
            make_hdsc_proof(unsigned, (0, 2))[0],
            make_hdsc_proof(self.chain, (0, 2))[0],
        )

    def test_non_chain_type_error(self):
        for bad in (
            tuple(self.chain.seals),
            list(self.chain.seals),
            "chain",
            None,
            42,
            b"x",
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                make_hdsc_proof(bad, (0,))

    def test_indices_type_errors(self):
        for bad in ([0, 2], (True,), ("0",), (1.0,), (None,)):
            with self.assertRaises(TypeError, msg=f"indices={bad!r}"):
                make_hdsc_proof(self.chain, bad)

    def test_empty_unsorted_duplicate_and_out_of_range_raise_value_error(self):
        with self.assertRaises(ValueError):
            make_hdsc_proof(self.chain, ())
        empty = HistoryDeltaSegmentsSealChain((), self.chain.signature)
        with self.assertRaises(ValueError):
            make_hdsc_proof(empty, (0,))
        for bad in ((2, 1), (1, 1), (-1,), (8,), (0, 8), (3, 3, 4)):
            with self.assertRaises(ValueError, msg=f"indices={bad}"):
                make_hdsc_proof(self.chain, bad)

    def test_illegal_nested_seal_value_error(self):
        bad_seal = HistoryDeltaSegmentsSeal(
            (), AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        )
        chain = HistoryDeltaSegmentsSealChain(
            (bad_seal,) + self.chain.seals[1:], self.chain.signature
        )
        with self.assertRaises(ValueError):
            make_hdsc_proof(chain, (0,))


class CheckHDSCProofTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.chain = chain_of_size(8, self.key, seed_base=3800)

    def _chain_of_size(self, n):
        return HistoryDeltaSegmentsSealChain(
            self.chain.seals[:n], self.chain.signature
        )

    def test_honest_proofs_verify_for_every_size_and_subset(self):
        for n in range(1, 9):
            chain = self._chain_of_size(n)
            message, _ = make_hdsc_proof(chain, (0,))
            signature = sign_message(self.key, message, seed=4000 + n)
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                _msg, proof = make_hdsc_proof(chain, indices)
                self.assertTrue(
                    check_hdsc_proof(proof, signature, self.key),
                    msg=f"n={n} indices={indices}",
                )

    def test_single_seal_chain_verifies_with_empty_siblings(self):
        chain = self._chain_of_size(1)
        proof, signature = signed_proof(chain, (0,), self.key, seed=4100)
        self.assertEqual(proof.siblings, ())
        self.assertTrue(check_hdsc_proof(proof, signature, self.key))

    def test_one_signature_covers_every_subset(self):
        chain = self._chain_of_size(5)
        message, _ = make_hdsc_proof(chain, (1,))
        signature = sign_message(self.key, message, seed=4200)
        for indices in (
            (0,),
            (4,),
            (0, 4),
            (1, 2, 3),
            (0, 1, 2, 3, 4),
        ):
            _m, proof = make_hdsc_proof(chain, indices)
            self.assertTrue(
                check_hdsc_proof(proof, signature, self.key),
                msg=f"indices={indices}",
            )

    def test_decoded_proof_still_checks(self):
        chain = self._chain_of_size(6)
        proof, signature = signed_proof(
            chain, (0, 2, 5), self.key, seed=4300
        )
        restored = decode_hdsc_proof(encode_hdsc_proof(proof))
        self.assertEqual(restored, proof)
        self.assertTrue(check_hdsc_proof(restored, signature, self.key))

    def test_tampered_seal_returns_false(self):
        proof, signature = signed_proof(
            self.chain, (1, 2), self.key, seed=4400
        )
        bad = dataclasses.replace(
            proof, seals=(self.chain.seals[0],) + proof.seals[1:]
        )
        self.assertFalse(check_hdsc_proof(bad, signature, self.key))

    def test_swapped_seals_return_false(self):
        proof, signature = signed_proof(
            self.chain, (1, 2), self.key, seed=4500
        )
        swapped = (proof.seals[1], proof.seals[0])
        bad = dataclasses.replace(proof, seals=swapped)
        self.assertFalse(check_hdsc_proof(bad, signature, self.key))

    def test_changed_total_returns_false_when_shape_still_fits(self):
        # n=5 -> n=6 keeps the same depth and sibling count for indices
        # (1, 3), so the proof stays structurally legal but rebuilds wrong.
        chain = self._chain_of_size(5)
        _message, proof = make_hdsc_proof(chain, (1, 3))
        signature = sign_message(self.key, _message, seed=4600)
        bad = dataclasses.replace(proof, total=6)
        self.assertEqual(len(bad.siblings), 3)
        self.assertFalse(check_hdsc_proof(bad, signature, self.key))

    def test_flipped_sibling_returns_false(self):
        proof, signature = signed_proof(
            self.chain, (0, 2), self.key, seed=4700
        )
        self.assertTrue(proof.siblings)
        flipped = bytearray(proof.siblings[0])
        flipped[0] ^= 1
        bad = dataclasses.replace(
            proof, siblings=(bytes(flipped),) + proof.siblings[1:]
        )
        self.assertFalse(check_hdsc_proof(bad, signature, self.key))

    def test_sibling_order_matters(self):
        proof, signature = signed_proof(
            self.chain, (0, 2), self.key, seed=4800
        )
        self.assertGreaterEqual(len(proof.siblings), 2)
        reordered = proof.siblings[1::-1] + proof.siblings[2:]
        bad = dataclasses.replace(proof, siblings=reordered)
        self.assertFalse(check_hdsc_proof(bad, signature, self.key))

    def test_missing_sibling_returns_false(self):
        proof, signature = signed_proof(
            self.chain, (0, 2, 4), self.key, seed=4900
        )
        bad = dataclasses.replace(proof, siblings=proof.siblings[:-1])
        self.assertFalse(check_hdsc_proof(bad, signature, self.key))

    def test_extra_sibling_returns_false(self):
        proof, signature = signed_proof(
            self.chain, (0, 2, 4), self.key, seed=5000
        )
        bad = dataclasses.replace(
            proof, siblings=proof.siblings + (b"x" * 32,)
        )
        self.assertFalse(check_hdsc_proof(bad, signature, self.key))

    def test_seal_count_mismatch_returns_false(self):
        proof, signature = signed_proof(
            self.chain, (1, 2), self.key, seed=5100
        )
        for bad_seals in ((), proof.seals[:1], proof.seals + proof.seals[:1]):
            bad = dataclasses.replace(proof, seals=bad_seals)
            self.assertFalse(
                check_hdsc_proof(bad, signature, self.key),
                msg=f"seals={len(bad_seals)}",
            )

    def test_bad_signature_returns_false(self):
        proof, signature = signed_proof(
            self.chain, (0, 2, 4), self.key, seed=5200
        )
        bad_sig = AggregateSignature(
            R=signature.R,
            z=(signature.z + 1) % FIELD_PRIME,
            signer_ids=signature.signer_ids,
        )
        self.assertFalse(check_hdsc_proof(proof, bad_sig, self.key))

    def test_tampered_signature_returns_false(self):
        proof, signature = signed_proof(
            self.chain, (0, 2, 4), self.key, seed=5300
        )
        tampered = AggregateSignature(
            R=signature.R,
            z=signature.z,
            signer_ids=signature.signer_ids[:-1]
            + (signature.signer_ids[-1] ^ 0xFF,),
        )
        self.assertFalse(check_hdsc_proof(proof, tampered, self.key))

    def test_signature_from_another_tree_returns_false(self):
        _message, proof = make_hdsc_proof(self.chain, (0, 2))
        other_chain = HistoryDeltaSegmentsSealChain(
            tuple(reversed(self.chain.seals[:5])), self.chain.signature
        )
        other_message, _other = make_hdsc_proof(other_chain, (0, 2))
        other_signature = sign_message(self.key, other_message, seed=5400)
        self.assertFalse(
            check_hdsc_proof(proof, other_signature, self.key)
        )

    def test_wrong_key_returns_false(self):
        proof, signature = signed_proof(
            self.chain, (0, 2), self.key, seed=5500
        )
        other_key = make_other_key()
        self.assertNotEqual(other_key.public_key, self.key.public_key)
        self.assertFalse(check_hdsc_proof(proof, signature, other_key))

    def test_cross_key_seal_returns_false(self):
        # A well-formed proof carrying a real seal of another key:
        # verify_hds fails before the signature is even consulted.
        other_key = make_other_key()
        foreign_chain = chain_of_size(2, other_key, seed_base=5600)
        _message, foreign = make_hdsc_proof(foreign_chain, (0,))
        proof, signature = signed_proof(
            self.chain, (0,), self.key, seed=5700
        )
        mixed = dataclasses.replace(proof, seals=foreign.seals)
        self.assertFalse(check_hdsc_proof(mixed, signature, self.key))

    def test_proof_does_not_need_the_full_chain(self):
        proof, signature = signed_proof(
            self.chain, (2, 5), self.key, seed=5800
        )
        self.assertTrue(check_hdsc_proof(proof, signature, self.key))

    def test_entry_type_errors(self):
        proof, signature = signed_proof(
            self.chain, (1, 2), self.key, seed=5900
        )
        with self.assertRaises(TypeError):
            check_hdsc_proof("proof", signature, self.key)
        with self.assertRaises(TypeError):
            check_hdsc_proof(proof, "signature", self.key)
        with self.assertRaises(TypeError):
            check_hdsc_proof(proof, signature, "key")
        for bad in (
            dataclasses.replace(proof, indices=[1, 2]),
            dataclasses.replace(proof, indices=(True, 2)),
            dataclasses.replace(proof, indices=("1", 2)),
            dataclasses.replace(proof, total=True),
            dataclasses.replace(proof, total="5"),
            dataclasses.replace(proof, seals=[proof.seals[0]] * 2),
            dataclasses.replace(proof, seals=("not-a-seal",) * 2),
            dataclasses.replace(proof, siblings=[b"s" * 32]),
            dataclasses.replace(proof, siblings=(b"s" * 32, 33)),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                check_hdsc_proof(bad, signature, self.key)

    def test_structure_and_boundary_value_errors(self):
        proof, signature = signed_proof(
            self.chain, (1, 2), self.key, seed=6000
        )
        thirty_two = b"s" * 32
        for bad in (
            HDSCProof((1, 2), 0, proof.seals, ()),
            HDSCProof((1, 2), -1, proof.seals, ()),
            HDSCProof((1, 2), 2 ** 64, proof.seals, ()),
            HDSCProof((), 5, (), ()),
            HDSCProof((-1, 2), 5, proof.seals, ()),
            HDSCProof((1, 5), 5, proof.seals, ()),
            HDSCProof((2, 1), 5, proof.seals, ()),
            dataclasses.replace(proof, siblings=(b"s" * 31,) * 3),
            dataclasses.replace(proof, siblings=(b"s" * 33,) * 3),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                check_hdsc_proof(bad, signature, self.key)
        # Seal/index count mismatches and a wrong sibling count stay a
        # plain False, even when every entry is a correctly sized value.
        for bad in (
            HDSCProof((1,), 5, proof.seals[:1] + proof.seals[:1], ()),
            dataclasses.replace(proof, siblings=proof.siblings[:-1]),
            dataclasses.replace(proof, siblings=proof.siblings + (thirty_two,)),
        ):
            self.assertFalse(check_hdsc_proof(bad, signature, self.key))

    def test_structurally_illegal_seal_raises_value_error(self):
        proof, signature = signed_proof(
            self.chain, (1, 2), self.key, seed=6100
        )
        bad_seal = HistoryDeltaSegmentsSeal(
            (), AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        )
        bad = dataclasses.replace(
            proof, seals=(bad_seal,) + proof.seals[1:]
        )
        with self.assertRaises(ValueError):
            check_hdsc_proof(bad, signature, self.key)

    def test_structurally_illegal_signature_raises_value_error(self):
        _message, proof = make_hdsc_proof(self.chain, (1, 2))
        for bad_sig in (
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=-1, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=7, signer_ids=()),
            AggregateSignature(R=5, z=7, signer_ids=(3, 1)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad_sig)):
                check_hdsc_proof(proof, bad_sig, self.key)


if __name__ == "__main__":
    unittest.main()
