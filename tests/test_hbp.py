"""Tests for compact multi-bundle Merkle membership proofs over the
non-empty order-preserving archive of whole HBAPB transport bundles:
HBP / make_hbp / check_hbp and the HBPB transport
encode_hbpb / decode_hbpb / verify_hbpb."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    HBAP,
    HBAPB,
    HBAPBArchive,
    HBP,
    HBPB,
    check_hbp,
    decode_hbpb,
    encode_hbapb,
    encode_hbpb,
    make_hbp,
    verify_hbpb,
)

from test_audit_chain import sign_message
from test_audit_extension_proof_bundle_codec import make_other_key
from test_nonce_reuse import make_key
from test_hbap import archive_of_size as hampb_archive_of_size, signed_hbapb

LEAF_TAG = b"hbp/l"
NODE_TAG = b"hbp/n"
ROOT_TAG = b"hbp/r"
BUNDLE_TAG = b"ts/hbpb/v1"

DUMMY_OUTER_SIGNATURE = AggregateSignature(R=5, z=7, signer_ids=(1, 3))


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big", signed=False)


def digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def bundles_of_size(n, key, seed_base=41000):
    """Build ``n`` distinct structurally legal, key-verifying HBAPB bundles."""
    source = hampb_archive_of_size(8, key, seed_base=seed_base)
    combos = ((0,), (1, 2), (0, 1, 2), (0, 2), (1,), (0, 1), (2,), (1, 2))
    return tuple(
        signed_hbapb(
            source,
            combos[position % len(combos)],
            key,
            seed=seed_base + 400 + position * 53,
        )
        for position in range(n)
    )


def archive_of_size(n, key, seed_base=41000):
    """An HBAPB archive of ``n`` distinct bundles, placeholder outer signature."""
    return HBAPBArchive(
        bundles_of_size(n, key, seed_base=seed_base), DUMMY_OUTER_SIGNATURE
    )


def independent_tree(bundles):
    """Build leaf level, internal levels (odd tail duplicated) and root."""
    leaves = tuple(
        digest(LEAF_TAG + u64(i) + digest(encode_hbapb(bundle)))
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


def signed_proof(archive, indices, key, *, seed=42000):
    """Return (proof, root signature) for a threshold-signed statement."""
    message, proof = make_hbp(archive, indices)
    signature = sign_message(key, message, seed=seed + sum(indices))
    return proof, signature


def signed_hbpb(archive, indices, key, *, seed=42000):
    proof, signature = signed_proof(archive, indices, key, seed=seed)
    return HBPB(proof, signature)


def build_wire(bundle):
    """Independently build the HBPB wire format straight from the spec."""
    proof = bundle.proof
    signature = bundle.signature
    out = bytearray(BUNDLE_TAG)
    out += varint(proof.total)
    out += u32(len(proof.indices))
    for index in proof.indices:
        out += varint(index)
    out += u32(len(proof.bundles))
    for inner in proof.bundles:
        out += frame(encode_hbapb(inner))
    out += u32(len(proof.siblings))
    for sibling in proof.siblings:
        out += sibling
    out += varint(signature.R)
    out += varint(signature.z)
    out += u32(len(signature.signer_ids))
    for signer_id in signature.signer_ids:
        out += varint(signer_id)
    return bytes(out)


class HBPDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(HBP)],
            ["indices", "total", "bundles", "siblings"],
        )
        key = make_key()
        bundles = bundles_of_size(2, key)
        siblings = (b"s" * 32,)
        proof = HBP((1,), 3, bundles, siblings)
        self.assertEqual(
            (proof.indices, proof.total, proof.bundles, proof.siblings),
            ((1,), 3, bundles, siblings),
        )

    def test_frozen_value_equality_and_hash(self):
        key = make_key()
        bundles = bundles_of_size(2, key, seed_base=41100)
        siblings = (b"s" * 32, b"t" * 32)
        proof = HBP((1, 3), 4, bundles, siblings)
        same = HBP(indices=(1, 3), total=4, bundles=bundles, siblings=siblings)
        self.assertEqual(proof, same)
        self.assertEqual(hash(proof), hash(same))
        self.assertNotEqual(proof, HBP((1, 2), 4, bundles, siblings))
        with self.assertRaises(FrozenInstanceError):
            proof.total = 5

    def test_construction_does_not_validate(self):
        key = make_key()
        bundles = bundles_of_size(1, key, seed_base=41150)
        HBP((9,), 1, bundles, ())
        HBP((0,), 0, ("not-a-bundle",), b"x")
        HBP((), 3, bundles, (b"",))


class MakeHBPTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(8, self.key, seed_base=41200)

    def _archive_of_size(self, n):
        return HBAPBArchive(self.archive.items[:n], self.archive.signature)

    def test_statement_layout_for_every_size_and_subset(self):
        for n in range(1, 9):
            archive = self._archive_of_size(n)
            root = independent_tree(archive.items)[-1][0]
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                message, proof = make_hbp(archive, indices)
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
        _message, proof = make_hbp(self.archive, indices)
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
                _message, proof = make_hbp(archive, indices)
                self.assertEqual(
                    proof.siblings,
                    independent_siblings(levels, indices),
                    msg=f"n={n} indices={indices}",
                )

    def test_proving_every_bundle_needs_no_siblings(self):
        for n in range(1, 9):
            archive = self._archive_of_size(n)
            _message, proof = make_hbp(archive, tuple(range(n)))
            self.assertEqual(proof.siblings, ())

    def test_domain_tags_are_distinct_from_hbap_tags(self):
        message, _proof = make_hbp(self.archive, (0, 2))
        self.assertTrue(message.startswith(b"hbp/r"))
        self.assertFalse(message.startswith(b"hbap/r"))

    def test_deterministic(self):
        message, proof = make_hbp(self.archive, (0, 2, 4))
        message2, proof2 = make_hbp(self.archive, (0, 2, 4))
        self.assertEqual(message, message2)
        self.assertEqual(proof, proof2)

    def test_archive_outer_signature_is_not_consulted(self):
        unsigned = HBAPBArchive(self.archive.items, "not-a-signature")
        self.assertEqual(
            make_hbp(unsigned, (0, 2))[0],
            make_hbp(self.archive, (0, 2))[0],
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
                make_hbp(bad, (0,))

    def test_indices_type_errors(self):
        for bad in ([0, 2], (True,), ("0",), (1.0,), (None,)):
            with self.assertRaises(TypeError, msg=f"indices={bad!r}"):
                make_hbp(self.archive, bad)

    def test_empty_unsorted_duplicate_and_out_of_range_raise_value_error(self):
        with self.assertRaises(ValueError):
            make_hbp(self.archive, ())
        empty = HBAPBArchive((), self.archive.signature)
        with self.assertRaises(ValueError):
            make_hbp(empty, (0,))
        for bad in ((2, 1), (1, 1), (-1,), (8,), (0, 8), (3, 3, 4)):
            with self.assertRaises(ValueError, msg=f"indices={bad}"):
                make_hbp(self.archive, bad)

    def test_non_tuple_items_type_error(self):
        archive = HBAPBArchive(list(self.archive.items), self.archive.signature)
        with self.assertRaises(TypeError):
            make_hbp(archive, (0,))

    def test_non_bundle_element_type_error(self):
        archive = HBAPBArchive(
            ("not-a-bundle",) + self.archive.items[1:], self.archive.signature
        )
        with self.assertRaises(TypeError):
            make_hbp(archive, (0,))

    def test_illegal_nested_bundle_errors(self):
        # A non-HBAPB item is a TypeError; an HBAPB whose own proof is
        # structurally illegal is a ValueError straight from encode_hbapb.
        bad_type_bundle = "not-an-hbapb"
        archive = HBAPBArchive(
            (bad_type_bundle,) + self.archive.items[1:], self.archive.signature
        )
        with self.assertRaises(TypeError):
            make_hbp(archive, (0,))
        bad_value_bundle = HBAPB(
            HBAP(indices=(), total=0, bundles=(), siblings=()),
            DUMMY_OUTER_SIGNATURE,
        )
        archive = HBAPBArchive(
            (bad_value_bundle,) + self.archive.items[1:], self.archive.signature
        )
        with self.assertRaises(ValueError):
            make_hbp(archive, (0,))

    def test_count_at_two_pow_64_raises_value_error(self):
        class HugeTuple(tuple):
            def __len__(self):
                return 2 ** 64

        archive = HBAPBArchive(
            HugeTuple((self.archive.items[0],)), self.archive.signature
        )
        with self.assertRaises(ValueError):
            make_hbp(archive, (0,))


class CheckHBPTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(8, self.key, seed_base=41300)

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
            archive = HBAPBArchive(
                self.archive.items[:n], self.archive.signature
            )
            proof, signature = signed_proof(archive, indices, self.key)
            self.assertTrue(
                check_hbp(proof, signature, self.key),
                msg=f"n={n} indices={indices}",
            )

    def test_one_signature_covers_every_subset(self):
        archive = HBAPBArchive(
            self.archive.items[:5], self.archive.signature
        )
        message, _ = make_hbp(archive, (0,))
        signature = sign_message(self.key, message, seed=41350)
        for mask in range(1, 1 << 5):
            indices = tuple(i for i in range(5) if mask & (1 << i))
            _statement, proof = make_hbp(archive, indices)
            self.assertTrue(
                check_hbp(proof, signature, self.key),
                msg=f"indices={indices}",
            )

    def test_tampered_bundles_indices_and_siblings_return_false(self):
        indices = (0, 2, 4)
        proof, signature = signed_proof(self.archive, indices, self.key)
        swapped = HBP(
            proof.indices,
            proof.total,
            (proof.bundles[1], proof.bundles[0], proof.bundles[2]),
            proof.siblings,
        )
        self.assertFalse(check_hbp(swapped, signature, self.key))
        moved = HBP((0, 2, 5), proof.total, proof.bundles, proof.siblings)
        self.assertFalse(check_hbp(moved, signature, self.key))
        damaged = HBP(
            proof.indices,
            proof.total,
            proof.bundles,
            (b"\x00" * 32,) + proof.siblings[1:],
        )
        self.assertFalse(check_hbp(damaged, signature, self.key))

    def test_missing_extra_and_misaligned_siblings_return_false(self):
        indices = (0, 3)
        proof, signature = signed_proof(self.archive, indices, self.key)
        self.assertGreater(len(proof.siblings), 1)
        short = HBP(
            proof.indices, proof.total, proof.bundles, proof.siblings[:-1]
        )
        self.assertFalse(check_hbp(short, signature, self.key))
        long = HBP(
            proof.indices,
            proof.total,
            proof.bundles,
            proof.siblings + (b"x" * 32,),
        )
        self.assertFalse(check_hbp(long, signature, self.key))
        rotated = HBP(
            proof.indices,
            proof.total,
            proof.bundles,
            proof.siblings[1:] + proof.siblings[:1],
        )
        self.assertFalse(check_hbp(rotated, signature, self.key))

    def test_bundle_count_mismatch_returns_false(self):
        indices = (0, 2, 4)
        proof, signature = signed_proof(self.archive, indices, self.key)
        fewer = HBP(
            proof.indices, proof.total, proof.bundles[:2], proof.siblings
        )
        self.assertFalse(check_hbp(fewer, signature, self.key))
        more = HBP(
            proof.indices,
            proof.total,
            proof.bundles + (proof.bundles[0],),
            proof.siblings,
        )
        self.assertFalse(check_hbp(more, signature, self.key))

    def test_wrong_signature_and_wrong_key_return_false(self):
        indices = (0, 2)
        proof, signature = signed_proof(self.archive, indices, self.key)
        shortened = HBAPBArchive(
            self.archive.items[:4], self.archive.signature
        )
        other_message, _ = make_hbp(shortened, (0, 2))
        other_signature = sign_message(self.key, other_message, seed=41370)
        self.assertFalse(check_hbp(proof, other_signature, self.key))
        self.assertFalse(check_hbp(proof, signature, make_other_key()))

    def test_unverifying_nested_bundle_returns_false(self):
        indices = (0, 2)
        proof, signature = signed_proof(self.archive, indices, self.key)
        other_key = make_other_key()
        foreign = signed_hbapb(
            hampb_archive_of_size(8, other_key, seed_base=41380),
            (0,),
            other_key,
            seed=41390,
        )
        mixed = HBP(
            proof.indices,
            proof.total,
            (foreign, proof.bundles[1]),
            proof.siblings,
        )
        self.assertFalse(check_hbp(mixed, signature, self.key))

    def test_bad_bundle_does_not_mask_illegal_signature_or_key(self):
        # A structurally legal proof whose nested bundle merely fails
        # verification must not turn an illegal root signature or key
        # into a plain False: both structures are checked first.
        other_key = make_other_key()
        foreign = signed_hbapb(
            hampb_archive_of_size(8, other_key, seed_base=41400),
            (0,),
            other_key,
            seed=41401,
        )
        proof, _signature = signed_proof(self.archive, (0, 2), self.key)
        mixed = HBP(
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
                check_hbp(mixed, bad_signature, self.key)
        for bad_key in ("x", None, 42, b"x", object()):
            with self.assertRaises(TypeError, msg=repr(bad_key)):
                check_hbp(
                    mixed,
                    AggregateSignature(R=5, z=7, signer_ids=(1, 3)),
                    bad_key,
                )

    def test_type_errors(self):
        proof, signature = signed_proof(self.archive, (0, 2), self.key)
        with self.assertRaises(TypeError):
            check_hbp("not-a-proof", signature, self.key)
        with self.assertRaises(TypeError):
            check_hbp(proof, "not-a-signature", self.key)
        for bad in (
            HBP([0, 2], 8, proof.bundles, proof.siblings),
            HBP((0, 2), "8", proof.bundles, proof.siblings),
            HBP((0, 2), True, proof.bundles, proof.siblings),
            HBP((0, True), 8, proof.bundles, proof.siblings),
            HBP((0, 2), 8, list(proof.bundles), proof.siblings),
            HBP((0, 2), 8, proof.bundles, list(proof.siblings)),
            HBP((0, 2), 8, ("not-a-bundle",) * 2, proof.siblings),
            HBP((0, 2), 8, proof.bundles, (b"x" * 32, 7)),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                check_hbp(bad, signature, self.key)

    def test_structure_value_errors(self):
        proof, signature = signed_proof(self.archive, (0, 2), self.key)
        for bad in (
            HBP((0, 2), 0, proof.bundles, proof.siblings),
            HBP((), 8, (), ()),
            HBP((2, 0), 8, proof.bundles, proof.siblings),
            HBP((1, 1), 8, proof.bundles, proof.siblings),
            HBP((0, 8), 8, proof.bundles, proof.siblings),
            HBP((0, 2), 8, proof.bundles, (b"short",)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                check_hbp(bad, signature, self.key)


class HBPBDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(HBPB)],
            ["proof", "signature"],
        )
        key = make_key()
        archive = archive_of_size(3, key, seed_base=41410)
        proof, signature = signed_proof(archive, (0, 2), key)
        bundle = HBPB(proof, signature)
        self.assertIs(bundle.proof, proof)
        self.assertIs(bundle.signature, signature)

    def test_frozen_value_equality_and_hash(self):
        key = make_key()
        archive = archive_of_size(3, key, seed_base=41420)
        proof, signature = signed_proof(archive, (1,), key)
        bundle = HBPB(proof, signature)
        same = HBPB(proof=proof, signature=signature)
        self.assertEqual(bundle, same)
        self.assertEqual(hash(bundle), hash(same))
        with self.assertRaises(FrozenInstanceError):
            bundle.signature = signature

    def test_construction_does_not_validate(self):
        HBPB("not-a-proof", "not-a-signature")
        HBPB(None, None)


class EncodeHBPBTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(6, self.key, seed_base=41500)

    def test_layout_matches_independent_builder(self):
        cases = (
            (1, (0,)),
            (2, (0, 1)),
            (3, (0, 2)),
            (4, (1, 3)),
            (5, (0, 2, 4)),
            (6, (0, 1, 2, 3, 4, 5)),
            (6, (3, 5)),
        )
        for n, indices in cases:
            archive = HBAPBArchive(
                self.archive.items[:n], self.archive.signature
            )
            bundle = signed_hbpb(archive, indices, self.key)
            self.assertEqual(
                encode_hbpb(bundle),
                build_wire(bundle),
                msg=f"n={n} indices={indices}",
            )

    def test_encoding_starts_with_tag_and_contains_hbapb_frames(self):
        bundle = signed_hbpb(self.archive, (0, 2), self.key)
        blob = encode_hbpb(bundle)
        self.assertTrue(blob.startswith(BUNDLE_TAG))
        # Each bundle frame body is an existing HBAPB transport encoding.
        for inner in bundle.proof.bundles:
            self.assertIn(encode_hbapb(inner), blob)
            self.assertTrue(encode_hbapb(inner).startswith(b"ts/hbapb/v1"))

    def test_type_errors(self):
        bundle = signed_hbpb(self.archive, (0, 2), self.key)
        with self.assertRaises(TypeError):
            encode_hbpb("not-a-bundle")
        with self.assertRaises(TypeError):
            encode_hbpb(HBPB("not-a-proof", bundle.signature))
        proof = bundle.proof
        for bad in (
            HBP([0, 2], proof.total, proof.bundles, proof.siblings),
            HBP((0, 2), "6", proof.bundles, proof.siblings),
            HBP((0, 2), proof.total, list(proof.bundles), proof.siblings),
            HBP((0, 2), proof.total, proof.bundles, list(proof.siblings)),
            HBP((0, True), proof.total, proof.bundles, proof.siblings),
            HBP((0, 2), proof.total, ("x",) * 2, proof.siblings),
            HBP((0, 2), proof.total, proof.bundles, (b"x" * 32, 9)),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_hbpb(HBPB(bad, bundle.signature))
        with self.assertRaises(TypeError):
            encode_hbpb(HBPB(proof, "not-a-signature"))

    def test_structure_value_errors(self):
        bundle = signed_hbpb(self.archive, (0, 2, 4), self.key)
        proof = bundle.proof
        for bad_proof in (
            HBP((), proof.total, (), ()),
            HBP((0, 2), 0, proof.bundles[:2], proof.siblings),
            HBP((0, 6), proof.total, proof.bundles[:2], proof.siblings),
            HBP((2, 0), proof.total, proof.bundles[:2], proof.siblings),
            HBP((1, 1), proof.total, proof.bundles[:2], proof.siblings),
            HBP(proof.indices, proof.total, proof.bundles[:2], proof.siblings),
            HBP(
                proof.indices,
                proof.total,
                proof.bundles + (proof.bundles[0],),
                proof.siblings,
            ),
            HBP(proof.indices, proof.total, proof.bundles, (b"short",)),
            HBP(
                proof.indices,
                proof.total,
                proof.bundles,
                proof.siblings + (b"x" * 32,),
            ),
            HBP(proof.indices, proof.total, proof.bundles, proof.siblings[:-1]),
        ):
            with self.assertRaises(ValueError, msg=repr(bad_proof)):
                encode_hbpb(HBPB(bad_proof, bundle.signature))

    def test_signature_structure_value_errors(self):
        bundle = signed_hbpb(self.archive, (0, 2), self.key)
        for bad_signature in (
            AggregateSignature(R=0, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=-1, z=7, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=-1, signer_ids=(1, 3)),
            AggregateSignature(R=5, z=7, signer_ids=()),
            AggregateSignature(R=5, z=7, signer_ids=(0, 3)),
            AggregateSignature(R=5, z=7, signer_ids=(3, 1)),
            AggregateSignature(R=5, z=7, signer_ids=(1, 1)),
        ):
            with self.assertRaises(ValueError, msg=repr(bad_signature)):
                encode_hbpb(HBPB(bundle.proof, bad_signature))

    def test_does_not_verify(self):
        proof, _ = signed_proof(self.archive, (0, 2), self.key)
        bundle = HBPB(proof, DUMMY_OUTER_SIGNATURE)
        self.assertEqual(encode_hbpb(bundle), build_wire(bundle))


class DecodeHBPBTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(6, self.key, seed_base=41600)

    def test_roundtrip_for_every_size_and_subset(self):
        for n in range(1, 7):
            archive = HBAPBArchive(
                self.archive.items[:n], self.archive.signature
            )
            for mask in range(1, 1 << n):
                indices = tuple(i for i in range(n) if mask & (1 << i))
                bundle = signed_hbpb(archive, indices, self.key)
                blob = encode_hbpb(bundle)
                restored = decode_hbpb(blob)
                self.assertEqual(restored, bundle)
                self.assertEqual(encode_hbpb(restored), blob)

    def test_non_bytes_type_error(self):
        for bad in ("x", b"x".hex(), 42, None, bytearray(b"x")):
            with self.assertRaises(TypeError, msg=repr(bad)):
                decode_hbpb(bad)

    def test_bad_tag_and_truncation(self):
        small_archive = HBAPBArchive(
            self.archive.items[:2], self.archive.signature
        )
        bundle = signed_hbpb(small_archive, (0,), self.key)
        blob = encode_hbpb(bundle)
        with self.assertRaises(ValueError):
            decode_hbpb(b"ts/hbpb/v2" + blob[len(BUNDLE_TAG):])
        with self.assertRaises(ValueError):
            decode_hbpb(blob[: len(BUNDLE_TAG) - 1])
        for cut in range(len(BUNDLE_TAG), len(blob)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_hbpb(blob[:cut])

    def test_trailing_bytes(self):
        bundle = signed_hbpb(self.archive, (0, 2), self.key)
        blob = encode_hbpb(bundle)
        with self.assertRaises(ValueError):
            decode_hbpb(blob + b"\x00")

    def test_zero_and_overlarge_total(self):
        bundle = signed_hbpb(self.archive, (0, 2), self.key)
        blob = encode_hbpb(bundle)
        rest = blob[len(BUNDLE_TAG):]
        rest = rest[len(varint(bundle.proof.total)):]
        with self.assertRaises(ValueError):
            decode_hbpb(BUNDLE_TAG + varint(0) + rest)
        with self.assertRaises(ValueError):
            decode_hbpb(BUNDLE_TAG + varint(1 << 64) + rest)

    def test_bad_nested_frame(self):
        bundle = signed_hbpb(self.archive, (0, 2), self.key)
        blob = encode_hbpb(bundle)
        head = BUNDLE_TAG + varint(bundle.proof.total)
        head += u32(2) + varint(0) + varint(2) + u32(2)
        with self.assertRaises(ValueError):
            decode_hbpb(head + u32(0) + blob[len(head) + 4:])
        with self.assertRaises(ValueError):
            decode_hbpb(head + frame(b"garbage") + blob[len(head) + 4:])

    def test_non_canonical_integers_rejected(self):
        bundle = signed_hbpb(self.archive, (0, 2), self.key)
        blob = encode_hbpb(bundle)
        offset = len(BUNDLE_TAG)
        self.assertEqual(
            bytes(blob[offset:offset + 5]), varint(bundle.proof.total)
        )
        # A two-byte body starting with 00 for a small total is a
        # forbidden leading zero rather than the shortest encoding.
        spliced = (
            BUNDLE_TAG
            + (2).to_bytes(4, "big")
            + b"\x00"
            + bytes([bundle.proof.total])
            + blob[offset + 5:]
        )
        with self.assertRaises(ValueError):
            decode_hbpb(spliced)

    def test_mismatched_signature_still_decodes(self):
        proof, _ = signed_proof(self.archive, (0, 2), self.key)
        message, _ = make_hbp(self.archive, (0, 2))
        mismatched = sign_message(make_other_key(), message, seed=41650)
        bundle = HBPB(proof, mismatched)
        blob = encode_hbpb(bundle)
        restored = decode_hbpb(blob)
        self.assertEqual(restored, bundle)
        self.assertFalse(verify_hbpb(restored, self.key))


class VerifyHBPBTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.archive = archive_of_size(6, self.key, seed_base=41700)

    def test_signed_bundles_verify(self):
        for n, indices in (
            (1, (0,)),
            (3, (0, 2)),
            (5, (0, 2, 4)),
            (6, tuple(range(6))),
        ):
            archive = HBAPBArchive(
                self.archive.items[:n], self.archive.signature
            )
            bundle = signed_hbpb(archive, indices, self.key)
            self.assertTrue(verify_hbpb(bundle, self.key))
            restored = decode_hbpb(encode_hbpb(bundle))
            self.assertTrue(verify_hbpb(restored, self.key))

    def test_tampered_and_wrong_key_return_false(self):
        bundle = signed_hbpb(self.archive, (0, 2, 4), self.key)
        proof = bundle.proof
        moved = HBPB(
            HBP((0, 2, 5), proof.total, proof.bundles, proof.siblings),
            bundle.signature,
        )
        self.assertFalse(verify_hbpb(moved, self.key))
        swapped = HBPB(
            HBP(
                proof.indices,
                proof.total,
                (proof.bundles[1], proof.bundles[0], proof.bundles[2]),
                proof.siblings,
            ),
            bundle.signature,
        )
        self.assertFalse(verify_hbpb(swapped, self.key))
        self.assertFalse(verify_hbpb(bundle, make_other_key()))

    def test_matches_check_hbp(self):
        bundle = signed_hbpb(self.archive, (1, 4), self.key)
        self.assertEqual(
            verify_hbpb(bundle, self.key),
            check_hbp(bundle.proof, bundle.signature, self.key),
        )

    def test_type_errors(self):
        bundle = signed_hbpb(self.archive, (0,), self.key)
        with self.assertRaises(TypeError):
            verify_hbpb("not-a-bundle", self.key)
        with self.assertRaises(TypeError):
            verify_hbpb(HBPB("not-a-proof", bundle.signature), self.key)


if __name__ == "__main__":
    unittest.main()
