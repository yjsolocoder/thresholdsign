"""Tests for the canonical AuditExtensionProofBundleChain transport encoding:
encode_audit_extension_proof_bundle_chain /
decode_audit_extension_proof_bundle_chain /
verify_audit_extension_proof_bundle_chain."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    AuditExtensionProof,
    AuditExtensionProofBundle,
    AuditExtensionProofBundleChain,
    decode_audit_extension_proof_bundle_chain,
    encode_audit_extension_proof_bundle,
    encode_audit_extension_proof_bundle_chain,
    make_extension,
    verify_audit_extension_proof_bundle,
    verify_audit_extension_proof_bundle_chain,
)

from test_audit_chain import make_key, make_record, sign_message

CHAIN_TAG = b"ts/aepbc/v1"
BUNDLE_TAG = b"ts/aepb/v1"


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def make_other_key():
    """A different key over the same toy group (different randomness)."""
    return make_key(seed_offset=1000)


def make_records(key, n, *, seed_base=100):
    return tuple(
        make_record(key, b"msg-%d" % i, seed=seed_base + i) for i in range(n)
    )


def sealed_bundle(key, records, old_n, *, seed=800):
    """Return a signed AuditExtensionProofBundle for the given split."""
    old_message, new_message, proof = make_extension(records, old_n)
    old_sig = sign_message(key, old_message, seed=seed)
    new_sig = sign_message(key, new_message, seed=seed + 1)
    return AuditExtensionProofBundle(proof, old_sig, new_sig)


def sealed_chain(key, records, sizes, *, seed=8000):
    """Build an honestly linked chain over successive append sizes.

    ``sizes`` is the strictly increasing sequence of record counts the
    chain certifies; bundle i extends from sizes[i - 1] to sizes[i], the
    first from 1 to sizes[0] (so sizes[0] must be at least 2).
    """
    splits = [sizes[0] - 1] + list(sizes[:-1])
    items = tuple(
        sealed_bundle(key, records[:size], old_n, seed=seed + 10 * index)
        for index, (old_n, size) in enumerate(zip(splits, sizes))
    )
    return AuditExtensionProofBundleChain(items)


def build_wire(chain: AuditExtensionProofBundleChain) -> bytes:
    """Independently build the chain wire format straight from the spec."""
    out = bytearray(CHAIN_TAG)
    out += u32(len(chain.items))
    for item in chain.items:
        out += frame(encode_audit_extension_proof_bundle(item))
    return bytes(out)


class ChainDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [
                field.name
                for field in dataclasses.fields(AuditExtensionProofBundleChain)
            ],
            ["items"],
        )
        proof = AuditExtensionProof(1, (b"a" * 32, b"b" * 32))
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        bundle = AuditExtensionProofBundle(proof, signature, signature)
        items = (bundle,)
        chain = AuditExtensionProofBundleChain(items)
        self.assertIs(chain.items, items)
        self.assertEqual(AuditExtensionProofBundleChain(items=items), chain)

    def test_frozen_value_equality_and_hash(self):
        proof = AuditExtensionProof(1, (b"a" * 32, b"b" * 32))
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        bundle_a = AuditExtensionProofBundle(proof, signature, signature)
        signature_b = AggregateSignature(R=9, z=11, signer_ids=(2, 4))
        bundle_b = AuditExtensionProofBundle(proof, signature_b, signature_b)
        chain = AuditExtensionProofBundleChain((bundle_a, bundle_b))
        same = AuditExtensionProofBundleChain((bundle_a, bundle_b))
        self.assertEqual(chain, same)
        self.assertEqual(hash(chain), hash(same))
        self.assertNotEqual(
            chain, AuditExtensionProofBundleChain((bundle_b, bundle_a))
        )
        self.assertNotEqual(chain, AuditExtensionProofBundleChain((bundle_a,)))
        with self.assertRaises(FrozenInstanceError):
            chain.items = (bundle_a,)

    def test_construction_does_not_validate(self):
        # A plain frozen value: non-tuple, empty and non-bundle items
        # construct; the codec and verifier reject them.
        AuditExtensionProofBundleChain("not-a-tuple")
        AuditExtensionProofBundleChain(())
        AuditExtensionProofBundleChain(("not-a-bundle",))


class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = make_records(self.key, 10)

    def test_round_trip_for_chains_of_every_length(self):
        seed = 20000
        for length in range(1, 5):
            sizes = tuple(2 * (index + 1) for index in range(length))
            chain = sealed_chain(self.key, self.records, sizes, seed=seed)
            seed += 100
            wire = encode_audit_extension_proof_bundle_chain(chain)
            decoded = decode_audit_extension_proof_bundle_chain(wire)
            self.assertEqual(decoded, chain, msg=f"length={length}")
            self.assertEqual(
                encode_audit_extension_proof_bundle_chain(decoded), wire
            )

    def test_encoding_matches_independent_builder(self):
        chain = sealed_chain(self.key, self.records, (2, 4, 6, 8), seed=21000)
        self.assertEqual(
            encode_audit_extension_proof_bundle_chain(chain),
            build_wire(chain),
        )

    def test_prefix_is_tag_and_u32_count(self):
        chain = sealed_chain(self.key, self.records, (2, 4, 6), seed=22000)
        wire = encode_audit_extension_proof_bundle_chain(chain)
        self.assertTrue(wire.startswith(CHAIN_TAG))
        offset = len(CHAIN_TAG)
        self.assertEqual(wire[offset:offset + 4], u32(len(chain.items)))

    def test_body_is_one_u32_prefixed_frame_per_item_in_order(self):
        chain = sealed_chain(self.key, self.records, (2, 4, 6), seed=22500)
        wire = encode_audit_extension_proof_bundle_chain(chain)
        offset = len(CHAIN_TAG) + 4
        for item in chain.items:
            body = encode_audit_extension_proof_bundle(item)
            self.assertTrue(body.startswith(BUNDLE_TAG))
            self.assertEqual(wire[offset:offset + 4], u32(len(body)))
            offset += 4
            self.assertEqual(wire[offset:offset + len(body)], body)
            offset += len(body)
        self.assertEqual(offset, len(wire))

    def test_single_item_chain_round_trips(self):
        bundle = sealed_bundle(self.key, self.records[:4], 2, seed=23000)
        chain = AuditExtensionProofBundleChain((bundle,))
        wire = encode_audit_extension_proof_bundle_chain(chain)
        decoded = decode_audit_extension_proof_bundle_chain(wire)
        self.assertEqual(decoded, chain)
        self.assertEqual(len(wire), len(CHAIN_TAG) + 4 + 4 + len(
            encode_audit_extension_proof_bundle(bundle)
        ))

    def test_decoded_chain_still_verifies(self):
        chain = sealed_chain(self.key, self.records, (2, 4, 6, 8), seed=24000)
        decoded = decode_audit_extension_proof_bundle_chain(
            encode_audit_extension_proof_bundle_chain(chain)
        )
        self.assertTrue(
            verify_audit_extension_proof_bundle_chain(decoded, self.key)
        )

    def test_encoding_is_unique_and_stateless(self):
        chain = sealed_chain(self.key, self.records, (2, 4, 6), seed=25000)
        self.assertEqual(
            encode_audit_extension_proof_bundle_chain(chain),
            encode_audit_extension_proof_bundle_chain(chain),
        )

    def test_nested_items_decode_through_bundle_codec(self):
        chain = sealed_chain(self.key, self.records, (2, 4), seed=25500)
        decoded = decode_audit_extension_proof_bundle_chain(
            encode_audit_extension_proof_bundle_chain(chain)
        )
        for item in decoded.items:
            self.assertIsInstance(item, AuditExtensionProofBundle)
            self.assertEqual(
                encode_audit_extension_proof_bundle(item),
                encode_audit_extension_proof_bundle(item),
            )


class StructureOnlyTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = make_records(self.key, 8)

    def test_decode_does_not_check_linkage_or_signatures(self):
        # Three structurally legal bundles that neither link nor verify
        # under self.key: each is honestly signed by another key over a
        # different record prefix. Decode restores them anyway; only
        # verify reports False (it does not raise).
        other = make_other_key()
        bundles = []
        for size in (3, 5, 7):
            records = make_records(other, size, seed_base=500 + size)
            bundles.append(sealed_bundle(other, records, 1, seed=26000 + size))
        chain = AuditExtensionProofBundleChain(tuple(bundles))
        decoded = decode_audit_extension_proof_bundle_chain(
            encode_audit_extension_proof_bundle_chain(chain)
        )
        self.assertEqual(decoded, chain)
        self.assertFalse(
            verify_audit_extension_proof_bundle_chain(decoded, self.key)
        )

    def test_encoding_does_not_check_linkage(self):
        # Two individually honest bundles with a gap between them encode
        # fine; structure alone is checked; verify reports it as False.
        first = sealed_bundle(self.key, self.records[:4], 2, seed=26000)
        second = sealed_bundle(self.key, self.records[:6], 5, seed=26100)
        chain = AuditExtensionProofBundleChain((first, second))
        self.assertTrue(encode_audit_extension_proof_bundle_chain(chain))
        self.assertFalse(
            verify_audit_extension_proof_bundle_chain(chain, self.key)
        )

    def test_encoding_does_not_check_signatures_against_the_roots(self):
        chain = sealed_chain(self.key, self.records, (2, 4), seed=26500)
        self.assertTrue(encode_audit_extension_proof_bundle_chain(chain))
        self.assertFalse(
            verify_audit_extension_proof_bundle_chain(chain, make_other_key())
        )


class EncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = make_records(self.key, 6)
        self.chain = sealed_chain(self.key, self.records, (2, 4), seed=27000)

    def test_non_chain_type_error(self):
        for bad in (self.chain.items, list(self.chain.items), None, "chain"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_audit_extension_proof_bundle_chain(bad)

    def test_non_tuple_items_type_error(self):
        with self.assertRaises(TypeError):
            encode_audit_extension_proof_bundle_chain(
                AuditExtensionProofBundleChain(list(self.chain.items))
            )

    def test_empty_items_value_error(self):
        with self.assertRaises(ValueError):
            encode_audit_extension_proof_bundle_chain(
                AuditExtensionProofBundleChain(())
            )

    def test_non_bundle_item_type_error(self):
        for bad in ("not-a-bundle", None, self.chain.items[0].proof):
            with self.assertRaises(TypeError, msg=repr(bad)):
                encode_audit_extension_proof_bundle_chain(
                    AuditExtensionProofBundleChain((bad,))
                )

    def test_bad_nested_bundle_structure_value_error(self):
        proof = AuditExtensionProof(0, (b"a" * 32, b"b" * 32))
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        bad_bundle = AuditExtensionProofBundle(proof, signature, signature)
        with self.assertRaises(ValueError):
            encode_audit_extension_proof_bundle_chain(
                AuditExtensionProofBundleChain(
                    (self.chain.items[0], bad_bundle)
                )
            )


class DecodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = make_records(self.key, 8)
        self.chain = sealed_chain(self.key, self.records, (2, 4, 6), seed=28000)
        self.wire = encode_audit_extension_proof_bundle_chain(self.chain)

    def test_non_bytes_type_error(self):
        with self.assertRaises(TypeError):
            decode_audit_extension_proof_bundle_chain("not bytes")
        with self.assertRaises(TypeError):
            decode_audit_extension_proof_bundle_chain(bytearray(self.wire))

    def test_bad_tag(self):
        rest = self.wire[len(CHAIN_TAG):]
        with self.assertRaises(ValueError):
            decode_audit_extension_proof_bundle_chain(b"ts/aepbc/v2" + rest)
        with self.assertRaises(ValueError):
            decode_audit_extension_proof_bundle_chain(b"x" + self.wire[1:])

    def test_truncation(self):
        for cut in range(len(CHAIN_TAG), len(self.wire)):
            with self.assertRaises(ValueError, msg=f"cut={cut}"):
                decode_audit_extension_proof_bundle_chain(self.wire[:cut])

    def test_trailing_bytes(self):
        with self.assertRaises(ValueError):
            decode_audit_extension_proof_bundle_chain(self.wire + b"\x00")

    def test_zero_item_count_rejected(self):
        bad = CHAIN_TAG + u32(0)
        with self.assertRaises(ValueError):
            decode_audit_extension_proof_bundle_chain(bad)
        bad = CHAIN_TAG + u32(0) + self.wire[len(CHAIN_TAG) + 4:]
        with self.assertRaises(ValueError):
            decode_audit_extension_proof_bundle_chain(bad)

    def test_declared_count_too_large_then_truncated(self):
        bad = bytearray(self.wire)
        bad[len(CHAIN_TAG):len(CHAIN_TAG) + 4] = u32(
            len(self.chain.items) + 1
        )
        with self.assertRaises(ValueError):
            decode_audit_extension_proof_bundle_chain(bytes(bad))

    def test_declared_count_too_small_leaves_trailing_bytes(self):
        bad = bytearray(self.wire)
        bad[len(CHAIN_TAG):len(CHAIN_TAG) + 4] = u32(
            len(self.chain.items) - 1
        )
        with self.assertRaises(ValueError):
            decode_audit_extension_proof_bundle_chain(bytes(bad))

    def test_zero_item_frame_rejected(self):
        suffix = self.wire[len(CHAIN_TAG) + 4:]
        bad = CHAIN_TAG + u32(1) + u32(0) + suffix
        with self.assertRaises(ValueError):
            decode_audit_extension_proof_bundle_chain(bad)

    def test_junk_item_frame_rejected(self):
        bad = CHAIN_TAG + u32(1) + frame(b"not-a-bundle")
        with self.assertRaises(ValueError):
            decode_audit_extension_proof_bundle_chain(bad)

    def test_declared_frame_length_mismatch(self):
        # Declaring the first frame one byte short hides a bundle byte in
        # what the parser then reads as the next frame's length.
        bad = bytearray(self.wire)
        length_offset = len(CHAIN_TAG) + 4
        first_body = encode_audit_extension_proof_bundle(self.chain.items[0])
        bad[length_offset:length_offset + 4] = u32(len(first_body) - 1)
        with self.assertRaises(ValueError):
            decode_audit_extension_proof_bundle_chain(bytes(bad))

    def test_nested_bundle_with_trailing_byte_rejected(self):
        first_body = encode_audit_extension_proof_bundle(self.chain.items[0])
        bad = (
            CHAIN_TAG
            + u32(1)
            + frame(first_body + b"\x00")
        )
        with self.assertRaises(ValueError):
            decode_audit_extension_proof_bundle_chain(bad)


class VerifyChainTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.other = make_other_key()
        self.records = make_records(self.key, 10)

    def test_honest_chains_verify_for_every_length(self):
        for length in range(1, 5):
            sizes = tuple(2 * (index + 1) for index in range(length))
            chain = sealed_chain(self.key, self.records, sizes, seed=30000 + 100 * length)
            self.assertTrue(
                verify_audit_extension_proof_bundle_chain(chain, self.key),
                msg=f"length={length}",
            )

    def test_result_equals_per_bundle_and_linkage_checks(self):
        chain = sealed_chain(self.key, self.records, (2, 4, 6, 8), seed=31000)
        expected = True
        for item in chain.items:
            expected = verify_audit_extension_proof_bundle(item, self.key) and expected
        previous = chain.items[0]
        for item in chain.items[1:]:
            linked = (
                len(previous.proof.leaves) == item.proof.old_n
                and previous.proof.leaves
                == item.proof.leaves[:item.proof.old_n]
            )
            expected = linked and expected
            previous = item
        self.assertEqual(
            verify_audit_extension_proof_bundle_chain(chain, self.key),
            expected,
        )
        self.assertTrue(expected)

    def test_wrong_key_returns_false(self):
        chain = sealed_chain(self.key, self.records, (2, 4, 6), seed=32000)
        self.assertFalse(
            verify_audit_extension_proof_bundle_chain(chain, self.other)
        )

    def test_gap_between_items_returns_false(self):
        # First extends 2 -> 4, second honestly extends 5 -> 7: every
        # bundle verifies alone, but old_n=5 != predecessor leaf count 4.
        first = sealed_bundle(self.key, self.records[:4], 2, seed=33000)
        second = sealed_bundle(self.key, self.records[:7], 5, seed=33100)
        chain = AuditExtensionProofBundleChain((first, second))
        self.assertTrue(
            verify_audit_extension_proof_bundle(second, self.key)
        )
        self.assertFalse(
            verify_audit_extension_proof_bundle_chain(chain, self.key)
        )

    def test_overlapping_old_n_returns_false(self):
        # Second extends 3 -> 6: old_n=3 != predecessor leaf count 4.
        first = sealed_bundle(self.key, self.records[:4], 2, seed=33200)
        second = sealed_bundle(self.key, self.records[:6], 3, seed=33300)
        chain = AuditExtensionProofBundleChain((first, second))
        self.assertFalse(
            verify_audit_extension_proof_bundle_chain(chain, self.key)
        )

    def test_diverging_leaves_returns_false(self):
        # Same boundary (old_n == 4), but the successor's shared leaves
        # come from a different record sequence, so leaves[:4] differs.
        first = sealed_bundle(self.key, self.records[:4], 2, seed=33400)
        other_records = make_records(self.key, 6, seed_base=900)
        second = sealed_bundle(self.key, other_records[:6], 4, seed=33500)
        self.assertEqual(second.proof.old_n, len(first.proof.leaves))
        self.assertNotEqual(
            first.proof.leaves, second.proof.leaves[: second.proof.old_n]
        )
        chain = AuditExtensionProofBundleChain((first, second))
        self.assertTrue(
            verify_audit_extension_proof_bundle(second, self.key)
        )
        self.assertFalse(
            verify_audit_extension_proof_bundle_chain(chain, self.key)
        )

    def test_reordered_items_return_false(self):
        chain = sealed_chain(self.key, self.records, (2, 4, 6), seed=34000)
        reordered = AuditExtensionProofBundleChain(
            (chain.items[0], chain.items[2], chain.items[1])
        )
        self.assertFalse(
            verify_audit_extension_proof_bundle_chain(reordered, self.key)
        )

    def test_one_tampered_bundle_returns_false(self):
        chain = sealed_chain(self.key, self.records, (2, 4, 6), seed=35000)
        middle = chain.items[1]
        tampered = AuditExtensionProofBundle(
            middle.proof, middle.new_signature, middle.old_signature
        )
        broken = AuditExtensionProofBundleChain(
            (chain.items[0], tampered, chain.items[2])
        )
        self.assertFalse(
            verify_audit_extension_proof_bundle_chain(broken, self.key)
        )

    def test_single_item_chain_returns_false_when_bundle_does(self):
        bundle = sealed_bundle(self.key, self.records[:4], 2, seed=36000)
        swapped = AuditExtensionProofBundle(
            bundle.proof, bundle.new_signature, bundle.old_signature
        )
        self.assertFalse(
            verify_audit_extension_proof_bundle_chain(
                AuditExtensionProofBundleChain((swapped,)), self.key
            )
        )

    def test_decoded_chain_verifies_identically(self):
        chain = sealed_chain(self.key, self.records, (2, 4, 6), seed=37000)
        decoded = decode_audit_extension_proof_bundle_chain(
            encode_audit_extension_proof_bundle_chain(chain)
        )
        self.assertEqual(
            verify_audit_extension_proof_bundle_chain(decoded, self.key),
            verify_audit_extension_proof_bundle_chain(chain, self.key),
        )

    def test_non_chain_type_error(self):
        proof = AuditExtensionProof(1, (b"a" * 32, b"b" * 32))
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        bundle = AuditExtensionProofBundle(proof, signature, signature)
        for bad in ((bundle,), [bundle], "chain", None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_audit_extension_proof_bundle_chain(bad, self.key)

    def test_non_tuple_items_type_error(self):
        bundle = sealed_bundle(self.key, self.records[:4], 2, seed=38000)
        with self.assertRaises(TypeError):
            verify_audit_extension_proof_bundle_chain(
                AuditExtensionProofBundleChain([bundle]), self.key
            )

    def test_non_bundle_item_type_error(self):
        with self.assertRaises(TypeError):
            verify_audit_extension_proof_bundle_chain(
                AuditExtensionProofBundleChain(("not-a-bundle",)), self.key
            )

    def test_empty_items_value_error(self):
        with self.assertRaises(ValueError):
            verify_audit_extension_proof_bundle_chain(
                AuditExtensionProofBundleChain(()), self.key
            )

    def test_bad_nested_structure_value_error(self):
        bad_proof = AuditExtensionProof(0, (b"a" * 32, b"b" * 32))
        signature = AggregateSignature(R=5, z=7, signer_ids=(1, 3))
        bad_bundle = AuditExtensionProofBundle(bad_proof, signature, signature)
        with self.assertRaises(ValueError):
            verify_audit_extension_proof_bundle_chain(
                AuditExtensionProofBundleChain((bad_bundle,)), self.key
            )


if __name__ == "__main__":
    unittest.main()
