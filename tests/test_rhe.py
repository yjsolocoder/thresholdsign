"""Tests for cross-key seal-history append proofs:
RHE / encode_rhe / decode_rhe / check_rhe."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    RHE,
    RotationChain,
    SealHistoryExtension,
    check_rhe,
    create_signing_contribution,
    aggregate_signing_dkg,
    decode_rhe,
    decode_rotation_chain,
    encode_rhe,
    encode_rotation,
    encode_rotation_chain,
    make_history_extension,
)

from test_nonce_reuse import (
    FIELD_PRIME,
    GROUP_PRIME,
    GENERATOR,
    BLINDING_GENERATOR,
    fixed_random,
    make_key,
)
from test_rotation_chain import make_cert
from test_seal_history import make_history, sign_message

RHE_TAG = b"ts/rhe/v1"
CHAIN_TAG = b"thresholdsign/rotation-chain/v1"
LEAF_TAG = b"sh/l"
NODE_TAG = b"sh/n"
ROOT_TAG = b"sh/r"


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def make_other_key(participant_ids, threshold, seed_offset):
    contributions = [
        create_signing_contribution(
            pid,
            participant_ids,
            threshold,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            blinding_generator=BLINDING_GENERATOR,
            randbelow=fixed_random(pid + seed_offset),
        )
        for pid in participant_ids
    ]
    return aggregate_signing_dkg(contributions)


def independent_root(leaves):
    current = leaves
    while len(current) > 1:
        seq = list(current)
        if len(seq) % 2 == 1:
            seq.append(seq[-1])
        current = tuple(
            digest(NODE_TAG + seq[j] + seq[j + 1])
            for j in range(0, len(seq), 2)
        )
    return current[0]


def independent_signature_frame(signature: AggregateSignature) -> bytes:
    out = bytearray(varint(signature.R))
    out += varint(signature.z)
    out += u32(len(signature.signer_ids))
    for signer_id in signature.signer_ids:
        out += varint(signer_id)
    return bytes(out)


class RheFixture:
    """Honest single- and multi-hop cross-key proofs."""

    def __init__(self):
        self.k0 = make_key((1, 2, 3), 2)
        self.k1 = make_other_key((2, 3, 4, 5), 3, 10)
        self.k2 = make_other_key((3, 4, 5, 6), 2, 20)
        self.cert0 = make_cert(self.k0, self.k1, (1, 3), t=3, seed=100)
        self.cert1 = make_cert(self.k1, self.k2, (2, 4, 5), t=2, seed=200)

        self.history = make_history(self.k0, nonces=(600, 601, 602, 603))
        self.old_message, self.new_message, self.proof = (
            make_history_extension(self.history, 2)
        )
        self.old_sig = sign_message(
            self.old_message, self.k0, signer_ids=(1, 3), seed=700
        )
        self.new_sig = sign_message(
            self.new_message, self.k1, signer_ids=(2, 4, 5), seed=701
        )
        self.new_sig_2 = sign_message(
            self.new_message, self.k2, signer_ids=(3, 5), seed=800
        )

        self.single_chain = RotationChain(
            self.k0.public_key, (self.cert0,)
        )
        self.multi_chain = RotationChain(
            self.k0.public_key, (self.cert0, self.cert1)
        )
        self.single = RHE(
            self.proof, self.single_chain, self.old_sig, self.new_sig
        )
        self.multi = RHE(
            self.proof, self.multi_chain, self.old_sig, self.new_sig_2
        )


class RheDataTest(unittest.TestCase):
    def test_field_order_and_positional_construction(self):
        f = RheFixture()
        self.assertEqual(
            [field.name for field in dataclasses.fields(RHE)],
            ["extension", "rotations", "old_sig", "new_sig"],
        )
        rhe = RHE(f.proof, f.single_chain, f.old_sig, f.new_sig)
        self.assertIs(rhe.extension, f.proof)
        self.assertIs(rhe.rotations, f.single_chain)
        self.assertIs(rhe.old_sig, f.old_sig)
        self.assertIs(rhe.new_sig, f.new_sig)
        self.assertEqual(
            rhe,
            RHE(
                extension=f.proof,
                rotations=f.single_chain,
                old_sig=f.old_sig,
                new_sig=f.new_sig,
            ),
        )

    def test_no_field_defaults(self):
        for field in dataclasses.fields(RHE):
            self.assertIs(field.default, dataclasses.MISSING)
            self.assertIs(field.default_factory, dataclasses.MISSING)

    def test_frozen_value_equality_and_hash(self):
        f = RheFixture()
        self.assertEqual(hash(f.single), hash(RHE(
            f.proof, f.single_chain, f.old_sig, f.new_sig
        )))
        self.assertNotEqual(f.single, f.multi)
        self.assertNotEqual(
            f.single,
            RHE(f.proof, f.single_chain, f.new_sig, f.old_sig),
        )
        with self.assertRaises(FrozenInstanceError):
            f.single.extension = f.proof

    def test_construction_does_not_validate(self):
        # The container is a plain value with no hidden state.
        rhe = RHE("extension", "chain", "old", "new")
        self.assertEqual(
            (rhe.extension, rhe.rotations, rhe.old_sig, rhe.new_sig),
            ("extension", "chain", "old", "new"),
        )


class CheckRheTest(unittest.TestCase):
    def setUp(self):
        self.f = RheFixture()

    def test_honest_single_hop_verifies(self):
        self.assertTrue(check_rhe(self.f.single))

    def test_honest_multi_hop_verifies(self):
        self.assertTrue(check_rhe(self.f.multi))

    def test_roots_are_the_seal_history_tree_roots(self):
        leaves = self.f.proof.leaves
        self.assertEqual(
            self.f.old_message,
            ROOT_TAG
            + u64(self.f.proof.old_total)
            + independent_root(leaves[: self.f.proof.old_total]),
        )
        self.assertEqual(
            self.f.new_message,
            ROOT_TAG + u64(len(leaves)) + independent_root(leaves),
        )

    def test_broken_chain_returns_false(self):
        bad = dataclasses.replace(
            self.f.single,
            rotations=RotationChain(self.f.k1.public_key, (self.f.cert0,)),
        )
        self.assertFalse(check_rhe(bad))

    def test_one_bad_rotation_signature_returns_false(self):
        bad_cert = dataclasses.replace(
            self.f.cert1,
            sig=AggregateSignature(
                R=self.f.cert1.sig.R,
                z=(self.f.cert1.sig.z + 1) % FIELD_PRIME,
                signer_ids=self.f.cert1.sig.signer_ids,
            ),
        )
        bad = dataclasses.replace(
            self.f.multi,
            rotations=RotationChain(
                self.f.k0.public_key, (self.f.cert0, bad_cert)
            ),
        )
        self.assertFalse(check_rhe(bad))

    def test_tampered_old_signature_returns_false(self):
        bad = dataclasses.replace(
            self.f.single,
            old_sig=AggregateSignature(
                R=self.f.old_sig.R,
                z=(self.f.old_sig.z + 1) % FIELD_PRIME,
                signer_ids=self.f.old_sig.signer_ids,
            ),
        )
        self.assertFalse(check_rhe(bad))

    def test_tampered_new_signature_returns_false(self):
        bad = dataclasses.replace(
            self.f.single,
            new_sig=AggregateSignature(
                R=self.f.new_sig.R,
                z=(self.f.new_sig.z + 1) % FIELD_PRIME,
                signer_ids=self.f.new_sig.signer_ids,
            ),
        )
        self.assertFalse(check_rhe(bad))

    def test_swapped_signature_pair_returns_false(self):
        swapped = RHE(
            self.f.proof,
            self.f.single_chain,
            self.f.new_sig,
            self.f.old_sig,
        )
        self.assertFalse(check_rhe(swapped))

    def test_signature_under_other_endpoint_key_returns_false(self):
        # new_sig produced by k2 but the chain ends at k1.
        bad = RHE(
            self.f.proof,
            self.f.single_chain,
            self.f.old_sig,
            self.f.new_sig_2,
        )
        self.assertFalse(check_rhe(bad))

    def test_tampered_old_total_returns_false(self):
        bad_proof = dataclasses.replace(self.f.proof, old_total=1)
        bad = RHE(
            bad_proof,
            self.f.single_chain,
            self.f.old_sig,
            self.f.new_sig,
        )
        self.assertFalse(check_rhe(bad))

    def test_tampered_leaf_returns_false(self):
        leaves = self.f.proof.leaves
        flipped = leaves[-1][:-1] + bytes([leaves[-1][-1] ^ 1])
        bad_leaves = leaves[:-1] + (flipped,)
        bad_proof = SealHistoryExtension(
            old_total=self.f.proof.old_total, leaves=bad_leaves
        )
        bad = RHE(
            bad_proof,
            self.f.single_chain,
            self.f.old_sig,
            self.f.new_sig,
        )
        self.assertFalse(check_rhe(bad))

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            check_rhe("rhe")
        with self.assertRaises(TypeError):
            check_rhe(
                RHE(
                    "x",
                    self.f.single_chain,
                    self.f.old_sig,
                    self.f.new_sig,
                )
            )
        with self.assertRaises(TypeError):
            check_rhe(
                RHE(
                    self.f.proof,
                    "chain",
                    self.f.old_sig,
                    self.f.new_sig,
                )
            )
        with self.assertRaises(TypeError):
            check_rhe(
                RHE(
                    self.f.proof,
                    self.f.single_chain,
                    "sig",
                    self.f.new_sig,
                )
            )
        with self.assertRaises(TypeError):
            check_rhe(
                RHE(
                    self.f.proof,
                    self.f.single_chain,
                    self.f.old_sig,
                    "sig",
                )
            )

    def test_empty_chain_raises_value_error(self):
        with self.assertRaises(ValueError):
            check_rhe(
                RHE(
                    self.f.proof,
                    RotationChain(self.f.k0.public_key, ()),
                    self.f.old_sig,
                    self.f.new_sig,
                )
            )

    def test_bad_leaf_width_raises_value_error(self):
        bad_proof = SealHistoryExtension(
            old_total=1, leaves=(b"a" * 31, b"b" * 32)
        )
        with self.assertRaises(ValueError):
            check_rhe(
                RHE(
                    bad_proof,
                    self.f.single_chain,
                    self.f.old_sig,
                    self.f.new_sig,
                )
            )

    def test_illegal_chain_certificate_raises_value_error(self):
        bad_cert = dataclasses.replace(self.f.cert0, old=3)
        with self.assertRaises(ValueError):
            check_rhe(
                RHE(
                    self.f.proof,
                    RotationChain(3, (bad_cert,)),
                    self.f.old_sig,
                    self.f.new_sig,
                )
            )


class RheEncodingTest(unittest.TestCase):
    def setUp(self):
        self.f = RheFixture()

    def build_wire(self, rhe: RHE) -> bytes:
        """Hand-build the RHE wire format independently of the encoder."""
        extension_body = (
            u64(rhe.extension.old_total)
            + u64(len(rhe.extension.leaves))
            + b"".join(rhe.extension.leaves)
        )
        chain_body = encode_rotation_chain(rhe.rotations)
        out = bytearray(RHE_TAG)
        out += frame(extension_body)
        out += frame(chain_body)
        out += independent_signature_frame(rhe.old_sig)
        out += independent_signature_frame(rhe.new_sig)
        return bytes(out)

    def test_layout_matches_independent_builder(self):
        wire = encode_rhe(self.f.single)
        self.assertEqual(wire, self.build_wire(self.f.single))
        self.assertEqual(encode_rhe(self.f.multi), self.build_wire(self.f.multi))

    def test_tag_frames_and_order(self):
        wire = encode_rhe(self.f.single)
        self.assertTrue(wire.startswith(RHE_TAG))
        offset = len(RHE_TAG)

        e_len = int.from_bytes(wire[offset:offset + 4], "big")
        offset += 4
        body = wire[offset:offset + e_len]
        offset += e_len
        self.assertEqual(
            int.from_bytes(body[:8], "big"), self.f.proof.old_total
        )
        n = int.from_bytes(body[8:16], "big")
        self.assertEqual(n, len(self.f.proof.leaves))
        self.assertEqual(len(body), 16 + 32 * n)
        self.assertEqual(
            tuple(body[16 + 32 * i:16 + 32 * (i + 1)] for i in range(n)),
            self.f.proof.leaves,
        )

        c_len = int.from_bytes(wire[offset:offset + 4], "big")
        offset += 4
        chain_body = wire[offset:offset + c_len]
        offset += c_len
        self.assertTrue(chain_body.startswith(CHAIN_TAG))
        self.assertEqual(
            decode_rotation_chain(chain_body), self.f.single_chain
        )

        self.assertEqual(
            offset,
            len(wire)
            - len(independent_signature_frame(self.f.old_sig))
            - len(independent_signature_frame(self.f.new_sig)),
        )

    def test_deterministic_unique_output(self):
        wire = encode_rhe(self.f.single)
        self.assertEqual(wire, encode_rhe(self.f.single))
        self.assertNotEqual(wire, encode_rhe(self.f.multi))

    def test_roundtrip(self):
        for rhe in (self.f.single, self.f.multi):
            decoded = decode_rhe(encode_rhe(rhe))
            self.assertEqual(decoded, rhe)
            self.assertEqual(encode_rhe(decoded), encode_rhe(rhe))

    def test_decode_does_not_verify(self):
        # Broken chain linkage but legal structure: decodes, verifies False.
        bad_chain = RotationChain(self.f.k1.public_key, (self.f.cert0,))
        rhe = RHE(
            self.f.proof, bad_chain, self.f.old_sig, self.f.new_sig
        )
        decoded = decode_rhe(encode_rhe(rhe))
        self.assertEqual(decoded, rhe)
        self.assertFalse(check_rhe(decoded))

        # A tampered root signature also decodes but verifies False.
        bad_sig = AggregateSignature(
            R=self.f.old_sig.R,
            z=(self.f.old_sig.z + 1) % FIELD_PRIME,
            signer_ids=self.f.old_sig.signer_ids,
        )
        rhe2 = RHE(
            self.f.proof, self.f.single_chain, bad_sig, self.f.new_sig
        )
        decoded2 = decode_rhe(encode_rhe(rhe2))
        self.assertEqual(decoded2, rhe2)
        self.assertFalse(check_rhe(decoded2))

    # --- rejection tests -------------------------------------------------

    def test_encode_rejects_bad_types(self):
        self.assertRaises(TypeError, encode_rhe, "rhe")
        self.assertRaises(
            TypeError,
            encode_rhe,
            RHE("x", self.f.single_chain, self.f.old_sig, self.f.new_sig),
        )
        self.assertRaises(
            TypeError,
            encode_rhe,
            RHE(self.f.proof, "chain", self.f.old_sig, self.f.new_sig),
        )
        self.assertRaises(
            TypeError,
            encode_rhe,
            RHE(self.f.proof, self.f.single_chain, "sig", self.f.new_sig),
        )
        self.assertRaises(
            TypeError,
            encode_rhe,
            RHE(self.f.proof, self.f.single_chain, self.f.old_sig, "sig"),
        )
        # Boolean counts are not integers.
        bool_extension = SealHistoryExtension(
            old_total=True, leaves=self.f.proof.leaves
        )
        self.assertRaises(
            TypeError,
            encode_rhe,
            RHE(
                bool_extension,
                self.f.single_chain,
                self.f.old_sig,
                self.f.new_sig,
            ),
        )
        # Non-tuple leaves / certificates.
        list_extension = SealHistoryExtension(
            old_total=1, leaves=list(self.f.proof.leaves)
        )
        self.assertRaises(
            TypeError,
            encode_rhe,
            RHE(
                list_extension,
                self.f.single_chain,
                self.f.old_sig,
                self.f.new_sig,
            ),
        )

    def test_encode_rejects_empty_chain(self):
        self.assertRaises(
            ValueError,
            encode_rhe,
            RHE(
                self.f.proof,
                RotationChain(self.f.k0.public_key, ()),
                self.f.old_sig,
                self.f.new_sig,
            ),
        )

    def test_encode_rejects_bad_extension_bounds(self):
        # old_total == n (no actual extension).
        n = len(self.f.proof.leaves)
        bad = SealHistoryExtension(old_total=n, leaves=self.f.proof.leaves)
        self.assertRaises(
            ValueError,
            encode_rhe,
            RHE(
                bad, self.f.single_chain, self.f.old_sig, self.f.new_sig
            ),
        )
        # Wrong-width leaf.
        bad_leaves = self.f.proof.leaves[:-1] + (b"a" * 31,)
        bad2 = SealHistoryExtension(old_total=1, leaves=bad_leaves)
        self.assertRaises(
            ValueError,
            encode_rhe,
            RHE(
                bad2, self.f.single_chain, self.f.old_sig, self.f.new_sig
            ),
        )

    def test_encode_rejects_bad_signature_structure(self):
        zero_R = AggregateSignature(
            R=0, z=1, signer_ids=(1,)
        )
        self.assertRaises(
            ValueError,
            encode_rhe,
            RHE(
                self.f.proof, self.f.single_chain, zero_R, self.f.new_sig
            ),
        )
        empty_signers = AggregateSignature(R=2, z=3, signer_ids=())
        self.assertRaises(
            ValueError,
            encode_rhe,
            RHE(
                self.f.proof,
                self.f.single_chain,
                self.f.old_sig,
                empty_signers,
            ),
        )
        unsorted = AggregateSignature(R=2, z=3, signer_ids=(3, 1))
        self.assertRaises(
            ValueError,
            encode_rhe,
            RHE(
                self.f.proof, self.f.single_chain, unsorted, self.f.new_sig
            ),
        )

    def test_decode_rejects_bad_types(self):
        wire = encode_rhe(self.f.single)
        for bad in ("wire", bytearray(wire), None, 42):
            self.assertRaises(TypeError, decode_rhe, bad)

    def test_decode_rejects_bad_tag(self):
        wire = encode_rhe(self.f.single)
        self.assertRaises(ValueError, decode_rhe, b"x" + wire[1:])
        self.assertRaises(ValueError, decode_rhe, RHE_TAG)
        self.assertRaises(ValueError, decode_rhe, b"")

    def test_decode_rejects_zero_length_frames(self):
        wire = encode_rhe(self.f.single)
        # Zero extension frame length.
        bad_e = RHE_TAG + (0).to_bytes(4, "big") + wire[len(RHE_TAG) + 4 + 48:]
        self.assertRaises(ValueError, decode_rhe, bad_e)
        # Zero chain frame length (extension body is 16 + 4*32 = 144 bytes).
        offset = len(RHE_TAG) + 4 + 144
        bad_c = (
            wire[:offset]
            + (0).to_bytes(4, "big")
            + wire[offset + 4 + len(encode_rotation_chain(self.f.single_chain)):]
        )
        self.assertRaises(ValueError, decode_rhe, bad_c)

    def test_decode_rejects_huge_frame_length(self):
        wire = encode_rhe(self.f.single)
        offset = len(RHE_TAG)
        bad = (
            wire[:offset]
            + (0xFFFFFFFF).to_bytes(4, "big")
            + wire[offset + 4:]
        )
        self.assertRaises(ValueError, decode_rhe, bad)

    def test_decode_rejects_leaf_count_mismatch(self):
        wire = bytearray(encode_rhe(self.f.single))
        n_offset = len(RHE_TAG) + 4 + 8
        # Claim one more leaf than the frame actually carries.
        n = len(self.f.proof.leaves)
        wire[n_offset:n_offset + 8] = u64(n + 1)
        self.assertRaises(ValueError, decode_rhe, bytes(wire))
        # Claim one fewer leaf: the trailing 32 bytes cannot be parsed.
        wire[n_offset:n_offset + 8] = u64(n - 1)
        self.assertRaises(ValueError, decode_rhe, bytes(wire))

    def test_decode_rejects_zero_leaf_count(self):
        wire = bytearray(encode_rhe(self.f.single))
        n_offset = len(RHE_TAG) + 4 + 8
        wire[n_offset:n_offset + 8] = u64(0)
        self.assertRaises(ValueError, decode_rhe, bytes(wire))

    def test_decode_rejects_bad_old_total(self):
        wire = bytearray(encode_rhe(self.f.single))
        ot_offset = len(RHE_TAG) + 4
        # old_total == n.
        wire[ot_offset:ot_offset + 8] = u64(len(self.f.proof.leaves))
        self.assertRaises(ValueError, decode_rhe, bytes(wire))
        # old_total == 0.
        wire[ot_offset:ot_offset + 8] = u64(0)
        self.assertRaises(ValueError, decode_rhe, bytes(wire))

    def test_decode_rejects_non_32_byte_leaf_stride(self):
        # A body whose leaf region is 33 bytes for n=1: width mismatch.
        bad = (
            RHE_TAG
            + frame(u64(1) + u64(1) + b"a" * 33)
            + frame(encode_rotation_chain(self.f.single_chain))
            + independent_signature_frame(self.f.old_sig)
            + independent_signature_frame(self.f.new_sig)
        )
        self.assertRaises(ValueError, decode_rhe, bad)

    def test_decode_rejects_bad_nested_chain(self):
        good_chain = encode_rotation_chain(self.f.single_chain)
        bad_chain = b"x" + good_chain[1:]
        bad = (
            RHE_TAG
            + frame(
                u64(self.f.proof.old_total)
                + u64(len(self.f.proof.leaves))
                + b"".join(self.f.proof.leaves)
            )
            + frame(bad_chain)
            + independent_signature_frame(self.f.old_sig)
            + independent_signature_frame(self.f.new_sig)
        )
        self.assertRaises(ValueError, decode_rhe, bad)

    def test_decode_rejects_empty_nested_chain(self):
        # decode_rotation_chain rejects a zero certificate count.
        empty_chain = CHAIN_TAG + (0).to_bytes(4, "big")
        bad = (
            RHE_TAG
            + frame(
                u64(self.f.proof.old_total)
                + u64(len(self.f.proof.leaves))
                + b"".join(self.f.proof.leaves)
            )
            + frame(empty_chain)
            + independent_signature_frame(self.f.old_sig)
            + independent_signature_frame(self.f.new_sig)
        )
        self.assertRaises(ValueError, decode_rhe, bad)

    def test_decode_rejects_non_canonical_signature_integer(self):
        wire = bytearray(encode_rhe(self.f.single))
        # Find the first signature R varint inside the old signature frame
        # (immediately after the chain frame) and prepend a leading zero.
        chain_body = encode_rotation_chain(self.f.single_chain)
        extension_body_len = 16 + 32 * len(self.f.proof.leaves)
        r_offset = (
            len(RHE_TAG)
            + 4 + extension_body_len
            + 4 + len(chain_body)
        )
        length = int.from_bytes(wire[r_offset:r_offset + 4], "big")
        wire[r_offset:r_offset + 4 + length] = (
            (length + 1).to_bytes(4, "big") + b"\x00"
            + bytes(wire[r_offset + 4:r_offset + 4 + length])
        )
        self.assertRaises(ValueError, decode_rhe, bytes(wire))

    def test_decode_rejects_zero_signer_count(self):
        chain_body = encode_rotation_chain(self.f.single_chain)
        extension_body_len = 16 + 32 * len(self.f.proof.leaves)
        prefix = (
            RHE_TAG
            + frame(
                u64(self.f.proof.old_total)
                + u64(len(self.f.proof.leaves))
                + b"".join(self.f.proof.leaves)
            )
            + frame(chain_body)
        )
        # Old frame with R, z then a zero signer count.
        bad_old = varint(self.f.old_sig.R) + varint(self.f.old_sig.z) + u32(0)
        bad = prefix + bad_old
        self.assertRaises(ValueError, decode_rhe, bad)

    def test_decode_rejects_truncation_at_every_cut(self):
        wire = encode_rhe(self.f.single)
        for cut in range(len(wire)):
            with self.assertRaises(ValueError, msg=f"cut {cut}"):
                decode_rhe(wire[:cut])

    def test_decode_rejects_trailing_bytes(self):
        wire = encode_rhe(self.f.single)
        self.assertRaises(ValueError, decode_rhe, wire + b"\x00")
        self.assertRaises(ValueError, decode_rhe, wire + b"extra")


if __name__ == "__main__":
    unittest.main()
