"""Tests for the cross-key seal-history append proof:
RHE / check_rhe / encode_rhe / decode_rhe."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    RHE,
    RotationChain,
    SealHistoryExtension,
    check_rhe,
    decode_rhe,
    decode_rotation_chain,
    encode_rhe,
    encode_rotation_chain,
    verify_signature,
)

from test_nonce_reuse import FIELD_PRIME, GROUP_PRIME  # noqa: F401
from test_rotation_chain import make_cert, make_key
from test_seal_history import make_history, sign_message

RHE_TAG = b"ts/rhe/v1"
ROTATION_CHAIN_TAG = b"thresholdsign/rotation-chain/v1"
ROOT_TAG = b"sh/r"


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def varint(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def sig_frame(signature: AggregateSignature) -> bytes:
    out = bytearray(varint(signature.R))
    out += varint(signature.z)
    out += u32(len(signature.signer_ids))
    for signer_id in signature.signer_ids:
        out += varint(signer_id)
    return bytes(out)


def extension_body(extension: SealHistoryExtension) -> bytes:
    out = bytearray(u64(extension.old_total))
    out += u64(len(extension.leaves))
    for leaf in extension.leaves:
        out += leaf
    return bytes(out)


def build_wire(x: RHE) -> bytes:
    """Hand-build the RHE wire format independently of the encoder."""
    e = extension_body(x.extension)
    c = encode_rotation_chain(x.rotations)
    return (
        RHE_TAG
        + frame(e)
        + frame(c)
        + sig_frame(x.old_sig)
        + sig_frame(x.new_sig)
    )


def history_of_size(key, n):
    return make_history(key, nonces=tuple(600 + i for i in range(n)))


class RHEFixture(unittest.TestCase):
    def setUp(self):
        self.k0 = make_key((1, 2, 3), 2, seed_offset=0)
        self.k1 = make_key((2, 3, 4, 5), 3, seed_offset=10)
        self.k2 = make_key((3, 4, 5, 6), 2, seed_offset=20)
        self.cert0 = make_cert(self.k0, self.k1, (1, 3), t=3, seed=100)
        self.cert1 = make_cert(self.k1, self.k2, (2, 4, 5), t=2, seed=200)
        self.chain = RotationChain(
            self.k0.public_key, (self.cert0, self.cert1)
        )
        self.history = history_of_size(self.k0, 6)

    def make_extension(self, n=6, old_total=3):
        history = history_of_size(self.k0, n)
        return self._extension(history, old_total)

    @staticmethod
    def _extension(history, old_total):
        from thresholdsign import make_history_extension

        old_message, new_message, extension = make_history_extension(
            history, old_total
        )
        return old_message, new_message, extension

    def make_rhe(self, *, n=6, old_total=3, chain=None, old_seed=700,
                 new_signers=(4, 5), new_seed=710):
        from thresholdsign import make_history_extension

        history = history_of_size(self.k0, n)
        old_message, new_message, extension = make_history_extension(
            history, old_total
        )
        chain = chain or self.chain
        last_key = self.k2 if len(chain.certificates) == 2 else self.k1
        old_sig = sign_message(old_message, self.k0, seed=old_seed)
        new_sig = sign_message(
            new_message, last_key, signer_ids=new_signers, seed=new_seed
        )
        return RHE(extension, chain, old_sig, new_sig)


class RHEDataTest(RHEFixture):
    def test_field_order_and_positional_construction(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(RHE)],
            ["extension", "rotations", "old_sig", "new_sig"],
        )
        old_message, new_message, extension = self.make_extension()
        old_sig = sign_message(old_message, self.k0, seed=1)
        new_sig = sign_message(
            new_message, self.k2, signer_ids=(4, 5), seed=2
        )
        x = RHE(extension, self.chain, old_sig, new_sig)
        self.assertIs(x.extension, extension)
        self.assertIs(x.rotations, self.chain)
        self.assertIs(x.old_sig, old_sig)
        self.assertIs(x.new_sig, new_sig)

    def test_no_field_defaults(self):
        for field in dataclasses.fields(RHE):
            self.assertIs(field.default, dataclasses.MISSING)
            self.assertIs(field.default_factory, dataclasses.MISSING)

    def test_frozen_value_equality_and_hash(self):
        x = self.make_rhe()
        same = RHE(
            extension=x.extension,
            rotations=x.rotations,
            old_sig=x.old_sig,
            new_sig=x.new_sig,
        )
        self.assertEqual(x, same)
        self.assertEqual(hash(x), hash(same))
        self.assertNotEqual(x, dataclasses.replace(x, new_sig=x.old_sig))
        with self.assertRaises(FrozenInstanceError):
            x.extension = x.extension

    def test_no_hidden_state(self):
        self.assertEqual(encode_rhe(self.make_rhe()), encode_rhe(self.make_rhe()))


class CheckRheTest(RHEFixture):
    def test_honest_single_and_two_hop_verify(self):
        self.assertTrue(check_rhe(self.make_rhe()))
        single = RotationChain(self.k0.public_key, (self.cert0,))
        self.assertTrue(
            check_rhe(
                self.make_rhe(chain=single, new_signers=(2, 4, 5), new_seed=720)
            )
        )

    def test_honest_for_every_split_and_size(self):
        seed = 700
        for n in range(2, 9):
            for old_total in range(1, n):
                x = self.make_rhe(n=n, old_total=old_total, old_seed=seed)
                seed += 1
                self.assertTrue(
                    check_rhe(x), msg=f"n={n} old_total={old_total}"
                )

    def test_roots_and_group_parameters_checked_independently(self):
        # Re-derive the two statements straight from the leaves and verify
        # each signature under its own chain-end key and group parameters.
        x = self.make_rhe()
        ext = x.extension
        first_cert = x.rotations.certificates[0]
        last_cert = x.rotations.certificates[-1]
        from test_seal_history_extension import independent_root

        leaves = ext.leaves
        old_root = independent_root(leaves[:ext.old_total])
        new_root = independent_root(leaves)
        self.assertTrue(
            verify_signature(
                ROOT_TAG + u64(ext.old_total) + old_root,
                x.old_sig,
                first_cert.old,
                group_prime=first_cert.p,
                generator=first_cert.g,
                prime=first_cert.q,
            )
        )
        self.assertTrue(
            verify_signature(
                ROOT_TAG + u64(len(leaves)) + new_root,
                x.new_sig,
                last_cert.new,
                group_prime=last_cert.p,
                generator=last_cert.g,
                prime=last_cert.q,
            )
        )

    def test_swapped_signatures_return_false(self):
        x = self.make_rhe()
        self.assertFalse(
            check_rhe(dataclasses.replace(x, old_sig=x.new_sig, new_sig=x.old_sig))
        )

    def test_tampered_leaf_returns_false(self):
        x = self.make_rhe()
        flipped = bytearray(x.extension.leaves[1])
        flipped[0] ^= 1
        bad_ext = dataclasses.replace(
            x.extension,
            leaves=x.extension.leaves[:1]
            + (bytes(flipped),)
            + x.extension.leaves[2:],
        )
        self.assertFalse(
            check_rhe(dataclasses.replace(x, extension=bad_ext))
        )

    def test_tampered_prefix_leaf_returns_false(self):
        x = self.make_rhe()
        flipped = bytearray(x.extension.leaves[0])
        flipped[0] ^= 1
        bad_ext = dataclasses.replace(
            x.extension,
            leaves=(bytes(flipped),) + x.extension.leaves[1:],
        )
        self.assertFalse(
            check_rhe(dataclasses.replace(x, extension=bad_ext))
        )

    def test_leaf_order_matters(self):
        x = self.make_rhe()
        reordered = (
            x.extension.leaves[1],
            x.extension.leaves[0],
        ) + x.extension.leaves[2:]
        bad_ext = dataclasses.replace(x.extension, leaves=reordered)
        self.assertFalse(
            check_rhe(dataclasses.replace(x, extension=bad_ext))
        )

    def test_changed_old_total_returns_false(self):
        x = self.make_rhe()
        bad_ext = dataclasses.replace(x.extension, old_total=2)
        self.assertFalse(
            check_rhe(dataclasses.replace(x, extension=bad_ext))
        )

    def test_truncated_leaves_return_false(self):
        x = self.make_rhe()
        bad_ext = dataclasses.replace(
            x.extension, leaves=x.extension.leaves[:-1]
        )
        self.assertFalse(
            check_rhe(dataclasses.replace(x, extension=bad_ext))
        )

    def test_bad_signature_returns_false(self):
        x = self.make_rhe()
        bad_new = AggregateSignature(
            R=x.new_sig.R,
            z=(x.new_sig.z + 1) % FIELD_PRIME,
            signer_ids=x.new_sig.signer_ids,
        )
        self.assertFalse(
            check_rhe(dataclasses.replace(x, new_sig=bad_new))
        )
        bad_old = AggregateSignature(
            R=x.old_sig.R,
            z=(x.old_sig.z + 1) % FIELD_PRIME,
            signer_ids=x.old_sig.signer_ids,
        )
        self.assertFalse(
            check_rhe(dataclasses.replace(x, old_sig=bad_old))
        )

    def test_signature_from_another_statement_returns_false(self):
        x = self.make_rhe()
        other_message, _other_new, _ext = self._extension(
            history_of_size(self.k0, 5), 2
        )
        other_sig = sign_message(other_message, self.k0, seed=901)
        self.assertFalse(
            check_rhe(dataclasses.replace(x, old_sig=other_sig))
        )

    def test_old_signature_under_wrong_key_returns_false(self):
        x = self.make_rhe()
        from test_seal_history_extension import independent_root

        leaves = x.extension.leaves
        real_old_message = (
            ROOT_TAG
            + u64(x.extension.old_total)
            + independent_root(leaves[:x.extension.old_total])
        )
        # A genuine middle-key signature over the genuine old statement must
        # not be accepted as old_sig: check_rhe pins it to first_cert.old.
        middle_sig = sign_message(
            real_old_message, self.k1, signer_ids=(2, 4, 5), seed=902
        )
        self.assertFalse(
            check_rhe(dataclasses.replace(x, old_sig=middle_sig))
        )

    def test_wrong_anchor_returns_false(self):
        x = self.make_rhe()
        bad_chain = RotationChain(
            self.k1.public_key, (self.cert0, self.cert1)
        )
        self.assertFalse(
            check_rhe(dataclasses.replace(x, rotations=bad_chain))
        )

    def test_broken_linkage_returns_false(self):
        x = self.make_rhe()
        moved = dataclasses.replace(self.cert1, old=self.k0.public_key)
        bad_chain = RotationChain(
            self.k0.public_key, (self.cert0, moved)
        )
        self.assertFalse(
            check_rhe(dataclasses.replace(x, rotations=bad_chain))
        )

    def test_one_bad_certificate_signature_returns_false(self):
        x = self.make_rhe()
        bad_sig = AggregateSignature(
            R=self.cert1.sig.R,
            z=(self.cert1.sig.z + 1) % FIELD_PRIME,
            signer_ids=self.cert1.sig.signer_ids,
        )
        bad_cert = dataclasses.replace(self.cert1, sig=bad_sig)
        bad_chain = RotationChain(
            self.k0.public_key, (self.cert0, bad_cert)
        )
        self.assertFalse(
            check_rhe(dataclasses.replace(x, rotations=bad_chain))
        )

    # --- type / structure boundary --------------------------------------

    def test_entry_type_errors(self):
        x = self.make_rhe()
        for bad in ("x", 42, None, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                check_rhe(bad)
        with self.assertRaises(TypeError):
            check_rhe(RHE("ext", x.rotations, x.old_sig, x.new_sig))
        with self.assertRaises(TypeError):
            check_rhe(RHE(x.extension, "chain", x.old_sig, x.new_sig))
        with self.assertRaises(TypeError):
            check_rhe(RHE(x.extension, x.rotations, "sig", x.new_sig))
        with self.assertRaises(TypeError):
            check_rhe(RHE(x.extension, x.rotations, x.old_sig, "sig"))

    def test_nested_field_type_errors(self):
        x = self.make_rhe()
        leaves = x.extension.leaves
        bad_extensions = (
            dataclasses.replace(x.extension, old_total=True),
            dataclasses.replace(x.extension, old_total="3"),
            dataclasses.replace(x.extension, leaves=list(leaves)),
            dataclasses.replace(x.extension, leaves=(b"a" * 32, 33)),
            dataclasses.replace(x.extension, leaves=(bytearray(b"a" * 32),) * 6),
        )
        for bad_ext in bad_extensions:
            with self.assertRaises(TypeError, msg=repr(bad_ext)):
                check_rhe(RHE(bad_ext, x.rotations, x.old_sig, x.new_sig))
        bad_chains = (
            RotationChain("x", (self.cert0, self.cert1)),
            RotationChain(True, (self.cert0, self.cert1)),
            RotationChain(self.k0.public_key, ["x"]),
            RotationChain(self.k0.public_key, (self.cert0, "x")),
        )
        for bad_chain in bad_chains:
            with self.assertRaises(TypeError, msg=repr(bad_chain)):
                check_rhe(RHE(x.extension, bad_chain, x.old_sig, x.new_sig))
        bad_signatures = (
            AggregateSignature(R="2", z=3, signer_ids=(1, 3)),
            AggregateSignature(R=2, z=True, signer_ids=(1, 3)),
            AggregateSignature(R=2, z=3, signer_ids=[1, 3]),
            AggregateSignature(R=2, z=3, signer_ids=(1, True)),
        )
        for bad_sig in bad_signatures:
            with self.assertRaises(TypeError, msg=repr(bad_sig)):
                check_rhe(RHE(x.extension, x.rotations, bad_sig, x.new_sig))

    def test_structure_value_errors(self):
        x = self.make_rhe()
        leaves = x.extension.leaves
        with self.assertRaises(ValueError):
            check_rhe(
                RHE(
                    x.extension,
                    RotationChain(self.k0.public_key, ()),
                    x.old_sig,
                    x.new_sig,
                )
            )
        for bad_ext in (
            dataclasses.replace(x.extension, old_total=0),
            dataclasses.replace(x.extension, old_total=6),
            dataclasses.replace(x.extension, leaves=()),
            dataclasses.replace(x.extension, leaves=(b"a" * 31,) * 6),
            dataclasses.replace(x.extension, leaves=(b"a" * 33,) * 6),
        ):
            with self.assertRaises(ValueError, msg=repr(bad_ext)):
                check_rhe(RHE(bad_ext, x.rotations, x.old_sig, x.new_sig))

    def test_structurally_illegal_certificate_raises_value_error(self):
        x = self.make_rhe()
        bad_cert = dataclasses.replace(self.cert0, old=3)  # not in subgroup
        bad_chain = RotationChain(3, (bad_cert, self.cert1))
        with self.assertRaises(ValueError):
            check_rhe(RHE(x.extension, bad_chain, x.old_sig, x.new_sig))

    def test_structurally_illegal_signature_raises_value_error(self):
        x = self.make_rhe()
        bad_sig = AggregateSignature(
            R=GROUP_PRIME, z=0, signer_ids=(4, 5)
        )
        with self.assertRaises(ValueError):
            check_rhe(dataclasses.replace(x, new_sig=bad_sig))
        empty_ids = AggregateSignature(R=16, z=0, signer_ids=())
        with self.assertRaises(ValueError):
            check_rhe(dataclasses.replace(x, old_sig=empty_ids))


class RHEEncodingTest(RHEFixture):
    def setUp(self):
        super().setUp()
        self.x = self.make_rhe()

    def test_layout_matches_independent_builder(self):
        self.assertEqual(encode_rhe(self.x), build_wire(self.x))

    def test_tag_frames_and_order(self):
        wire = encode_rhe(self.x)
        self.assertTrue(wire.startswith(RHE_TAG))
        offset = len(RHE_TAG)

        e_len = int.from_bytes(wire[offset:offset + 4], "big")
        offset += 4
        e_body = wire[offset:offset + e_len]
        offset += e_len
        self.assertEqual(
            int.from_bytes(e_body[0:8], "big"), self.x.extension.old_total
        )
        n = int.from_bytes(e_body[8:16], "big")
        self.assertEqual(n, len(self.x.extension.leaves))
        self.assertEqual(len(e_body), 16 + 32 * n)
        self.assertEqual(e_body[16:], b"".join(self.x.extension.leaves))

        c_len = int.from_bytes(wire[offset:offset + 4], "big")
        offset += 4
        c_body = wire[offset:offset + c_len]
        offset += c_len
        self.assertEqual(
            decode_rotation_chain(c_body), self.x.rotations
        )

        # The two remaining bytes are exactly the two signature frames.
        tails = wire[offset:]
        self.assertEqual(
            tails,
            sig_frame(self.x.old_sig) + sig_frame(self.x.new_sig),
        )

    def test_roundtrip(self):
        wire = encode_rhe(self.x)
        decoded = decode_rhe(wire)
        self.assertEqual(decoded, self.x)
        self.assertEqual(encode_rhe(decoded), wire)

    def test_deterministic_unique_output(self):
        wire = encode_rhe(self.x)
        self.assertEqual(wire, encode_rhe(self.x))
        other = dataclasses.replace(self.x, new_sig=self.x.old_sig)
        self.assertNotEqual(wire, encode_rhe(other))

    def test_decode_does_not_verify(self):
        # A tampered cert signature still decodes; check_rhe then says False.
        bad_sig = AggregateSignature(
            R=self.cert0.sig.R,
            z=(self.cert0.sig.z + 1) % FIELD_PRIME,
            signer_ids=self.cert0.sig.signer_ids,
        )
        bad_cert = dataclasses.replace(self.cert0, sig=bad_sig)
        bad_chain = RotationChain(
            self.k0.public_key, (bad_cert, self.cert1)
        )
        bad = dataclasses.replace(self.x, rotations=bad_chain)
        decoded = decode_rhe(encode_rhe(bad))
        self.assertEqual(decoded, bad)
        self.assertFalse(check_rhe(decoded))

        # Anchor mismatch likewise decodes normally.
        mismatched = RotationChain(
            self.k1.public_key, (self.cert0, self.cert1)
        )
        bad2 = dataclasses.replace(self.x, rotations=mismatched)
        decoded2 = decode_rhe(encode_rhe(bad2))
        self.assertEqual(decoded2, bad2)
        self.assertFalse(check_rhe(decoded2))

    # --- encode rejection -------------------------------------------------

    def test_encode_rejects_bad_types(self):
        x = self.x
        with self.assertRaises(TypeError):
            encode_rhe("x")
        with self.assertRaises(TypeError):
            encode_rhe(RHE("ext", x.rotations, x.old_sig, x.new_sig))
        with self.assertRaises(TypeError):
            encode_rhe(RHE(x.extension, "chain", x.old_sig, x.new_sig))
        with self.assertRaises(TypeError):
            encode_rhe(RHE(x.extension, x.rotations, "sig", x.new_sig))
        with self.assertRaises(TypeError):
            encode_rhe(RHE(x.extension, x.rotations, x.old_sig, "sig"))

    def test_encode_rejects_bad_structure(self):
        x = self.x
        leaves = x.extension.leaves
        with self.assertRaises(ValueError):
            encode_rhe(
                RHE(
                    x.extension,
                    RotationChain(self.k0.public_key, ()),
                    x.old_sig,
                    x.new_sig,
                )
            )
        for bad_ext in (
            SealHistoryExtension(0, leaves),
            SealHistoryExtension(6, leaves),
            SealHistoryExtension(3, (b"a" * 31,) * 6),
        ):
            with self.assertRaises(ValueError):
                encode_rhe(RHE(bad_ext, x.rotations, x.old_sig, x.new_sig))
        with self.assertRaises(ValueError):
            encode_rhe(
                RHE(
                    x.extension,
                    x.rotations,
                    AggregateSignature(R=0, z=3, signer_ids=(1, 3)),
                    x.new_sig,
                )
            )
        with self.assertRaises(ValueError):
            encode_rhe(
                RHE(
                    x.extension,
                    x.rotations,
                    x.old_sig,
                    AggregateSignature(R=2, z=-1, signer_ids=(1, 3)),
                )
            )
        with self.assertRaises(ValueError):
            encode_rhe(
                RHE(
                    x.extension,
                    x.rotations,
                    AggregateSignature(R=2, z=3, signer_ids=()),
                    x.new_sig,
                )
            )

    # --- decode rejection -------------------------------------------------

    def test_decode_rejects_bad_types(self):
        wire = encode_rhe(self.x)
        for bad in ("wire", bytearray(wire), None, 42):
            with self.assertRaises(TypeError):
                decode_rhe(bad)

    def test_decode_rejects_bad_tag(self):
        wire = encode_rhe(self.x)
        with self.assertRaises(ValueError):
            decode_rhe(b"x" + wire[1:])
        with self.assertRaises(ValueError):
            decode_rhe(RHE_TAG)
        with self.assertRaises(ValueError):
            decode_rhe(b"")

    def test_decode_rejects_truncation_at_every_cut(self):
        wire = encode_rhe(self.x)
        for cut in range(len(wire)):
            with self.assertRaises(ValueError, msg=f"cut {cut}"):
                decode_rhe(wire[:cut])

    def test_decode_rejects_trailing_bytes(self):
        wire = encode_rhe(self.x)
        with self.assertRaises(ValueError):
            decode_rhe(wire + b"\x00")
        with self.assertRaises(ValueError):
            decode_rhe(wire + b"extra")

    def test_decode_rejects_zero_length_frames(self):
        e = extension_body(self.x.extension)
        c = encode_rotation_chain(self.x.rotations)
        with self.assertRaises(ValueError):
            decode_rhe(RHE_TAG + u32(0) + frame(c))
        with self.assertRaises(ValueError):
            decode_rhe(RHE_TAG + frame(e) + u32(0))

    def test_decode_rejects_huge_frame_length(self):
        e = extension_body(self.x.extension)
        with self.assertRaises(ValueError):
            decode_rhe(RHE_TAG + u32(0xFFFFFFFF) + e[:32])
        c = encode_rotation_chain(self.x.rotations)
        with self.assertRaises(ValueError):
            decode_rhe(RHE_TAG + frame(e) + u32(0xFFFFFFFF) + c[:32])

    def test_decode_rejects_empty_extension_and_bad_counts(self):
        leaves = self.x.extension.leaves
        # n = 0 (and old_total = 0).
        with self.assertRaises(ValueError):
            decode_rhe(
                RHE_TAG + frame(u64(0) + u64(0) + b"")
                + frame(encode_rotation_chain(self.x.rotations))
                + sig_frame(self.x.old_sig)
                + sig_frame(self.x.new_sig)
            )
        # old_total == n.
        bad_e = u64(len(leaves)) + u64(len(leaves)) + b"".join(leaves)
        with self.assertRaises(ValueError):
            decode_rhe(
                RHE_TAG
                + frame(bad_e)
                + frame(encode_rotation_chain(self.x.rotations))
                + sig_frame(self.x.old_sig)
                + sig_frame(self.x.new_sig)
            )

    def test_decode_rejects_leaf_width_mismatch(self):
        leaves = self.x.extension.leaves
        # Body one byte short of 16 + 32*n.
        bad_e = u64(3) + u64(len(leaves)) + b"".join(leaves)[:-1]
        with self.assertRaises(ValueError):
            decode_rhe(
                RHE_TAG
                + frame(bad_e)
                + frame(encode_rotation_chain(self.x.rotations))
            )
        # One stray trailing byte in the extension body.
        bad_e = (
            u64(3)
            + u64(len(leaves))
            + b"".join(leaves)
            + b"\x00"
        )
        with self.assertRaises(ValueError):
            decode_rhe(
                RHE_TAG
                + frame(bad_e)
                + frame(encode_rotation_chain(self.x.rotations))
            )

    def test_decode_rejects_bad_nested_chain(self):
        e = extension_body(self.x.extension)
        # A syntactically framed body that decode_rotation_chain rejects:
        # the right tag but a zero certificate count.
        empty_chain = ROTATION_CHAIN_TAG + u32(0)
        wire = (
            RHE_TAG
            + frame(e)
            + frame(empty_chain)
            + sig_frame(self.x.old_sig)
            + sig_frame(self.x.new_sig)
        )
        with self.assertRaises(ValueError):
            decode_rhe(wire)
        # Wrong nested tag entirely.
        wire = (
            RHE_TAG
            + frame(e)
            + frame(b"thresholdsign/not-a-chain" + b"\x00" * 8)
            + sig_frame(self.x.old_sig)
            + sig_frame(self.x.new_sig)
        )
        with self.assertRaises(ValueError):
            decode_rhe(wire)

    def test_decode_rejects_zero_R(self):
        e = extension_body(self.x.extension)
        c = encode_rotation_chain(self.x.rotations)
        bad_sig = AggregateSignature(
            R=0, z=self.x.old_sig.z, signer_ids=self.x.old_sig.signer_ids
        )
        wire = (
            RHE_TAG
            + frame(e)
            + frame(c)
            + sig_frame(bad_sig)
            + sig_frame(self.x.new_sig)
        )
        with self.assertRaises(ValueError):
            decode_rhe(wire)

    def test_decode_rejects_non_canonical_integer(self):
        e = extension_body(self.x.extension)
        c = encode_rotation_chain(self.x.rotations)

        def leading_zero_varint(value: int) -> bytes:
            body = value.to_bytes(
                (value.bit_length() + 7) // 8 or 1, "big"
            )
            return (len(body) + 1).to_bytes(4, "big") + b"\x00" + body

        sig = self.x.old_sig
        bad_frame = (
            leading_zero_varint(sig.R)
            + varint(sig.z)
            + u32(len(sig.signer_ids))
            + b"".join(varint(i) for i in sig.signer_ids)
        )
        wire = (
            RHE_TAG
            + frame(e)
            + frame(c)
            + bad_frame
            + sig_frame(self.x.new_sig)
        )
        with self.assertRaises(ValueError):
            decode_rhe(wire)

    def test_decode_rejects_bad_signer_sets(self):
        e = extension_body(self.x.extension)
        c = encode_rotation_chain(self.x.rotations)

        def frame_with_ids(R, z, ids):
            out = bytearray(varint(R) + varint(z) + u32(len(ids)))
            for signer_id in ids:
                out += varint(signer_id)
            return bytes(out)

        base = RHE_TAG + frame(e) + frame(c)
        # Empty signer set.
        wire_empty = (
            base
            + frame_with_ids(self.x.old_sig.R, self.x.old_sig.z, ())
            + sig_frame(self.x.new_sig)
        )
        with self.assertRaises(ValueError):
            decode_rhe(wire_empty)
        # Non-increasing / duplicate ids.
        wire_unordered = (
            base
            + frame_with_ids(self.x.old_sig.R, self.x.old_sig.z, (3, 1))
            + sig_frame(self.x.new_sig)
        )
        with self.assertRaises(ValueError):
            decode_rhe(wire_unordered)
        # Zero id.
        wire_zero = (
            base
            + frame_with_ids(self.x.old_sig.R, self.x.old_sig.z, (0, 3))
            + sig_frame(self.x.new_sig)
        )
        with self.assertRaises(ValueError):
            decode_rhe(wire_zero)


if __name__ == "__main__":
    unittest.main()
