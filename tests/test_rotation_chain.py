"""Tests for persistent rotation chains: RotationChain / verify_rotation_chain /
encode_rotation_chain / decode_rotation_chain."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    Rotation,
    RotationChain,
    aggregate_signature,
    create_signing_nonce_commitment,
    create_signing_round,
    create_signature_share,
    create_signing_contribution,
    aggregate_signing_dkg,
    decode_rotation,
    decode_rotation_chain,
    encode_rotation,
    encode_rotation_chain,
    rotation_payload,
    verify_rotation,
    verify_rotation_chain,
)

# Same toy group as test_rotation: 8069 = 4 * 2017 + 1 is prime, 16 and
# 256 = 16 ** 2 are distinct generators of the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

CHAIN_TAG = b"thresholdsign/rotation-chain/v1"


def fixed_random(seed=1):
    """Deterministic stand-in for secrets.randbelow (same LCG as DKG tests)."""
    state = {"value": seed}

    def randbelow(upper: int) -> int:
        state["value"] = (
            state["value"] * 6364136223846793005 + 1442695040888963407
        ) % upper
        return state["value"]

    return randbelow


def make_key(participant_ids, threshold, seed_offset=0):
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


def sign_message(key, message, signer_ids, seed=100):
    commitments = []
    nonces = {}
    for index, pid in enumerate(signer_ids):
        commitment, nonce = create_signing_nonce_commitment(
            pid,
            prime=key.result.commitment.field_prime,
            group_prime=key.result.commitment.group_prime,
            generator=key.result.commitment.generator,
            randbelow=fixed_random(seed + index),
        )
        commitments.append(commitment)
        nonces[pid] = nonce
    round_info = create_signing_round(message, signer_ids, commitments, key)
    shares = [
        create_signature_share(
            pid,
            key.result.shares[key.result.participant_ids.index(pid)].y,
            nonces[pid],
            round_info,
            key,
        )
        for pid in signer_ids
    ]
    signature = aggregate_signature(shares, round_info, key)
    assert isinstance(signature, AggregateSignature)
    return signature


def make_cert(old_key, new_key, signer_ids, *, t, seed):
    payload = rotation_payload(
        old_key.public_key,
        new_key.public_key,
        new_key.result.participant_ids,
        t,
        FIELD_PRIME,
        GROUP_PRIME,
        GENERATOR,
    )
    sig = sign_message(old_key, payload, signer_ids, seed=seed)
    return Rotation(
        old_key.public_key,
        new_key.public_key,
        new_key.result.participant_ids,
        t,
        FIELD_PRIME,
        GROUP_PRIME,
        GENERATOR,
        sig,
    )


def minimal_be(value: int) -> bytes:
    return value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")


def frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


class RotationChainDataTest(unittest.TestCase):
    def test_frozen_positional_value_equality(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(RotationChain)],
            ["anchor", "certificates"],
        )
        sig = AggregateSignature(R=2, z=3, signer_ids=(1, 2))
        cert = Rotation(4, 5, (1, 2), 2, FIELD_PRIME, GROUP_PRIME, GENERATOR, sig)
        chain = RotationChain(4, (cert,))
        same = RotationChain(anchor=4, certificates=(cert,))
        self.assertEqual(chain, same)
        self.assertEqual(hash(chain), hash(same))
        self.assertNotEqual(chain, RotationChain(5, (cert,)))
        with self.assertRaises(FrozenInstanceError):
            chain.anchor = 5

    def test_non_empty_and_order_preserved(self):
        sig = AggregateSignature(R=2, z=3, signer_ids=(1, 2))
        c0 = Rotation(4, 5, (1, 2), 2, FIELD_PRIME, GROUP_PRIME, GENERATOR, sig)
        c1 = Rotation(5, 6, (1, 2), 2, FIELD_PRIME, GROUP_PRIME, GENERATOR, sig)
        chain = RotationChain(4, (c0, c1))
        self.assertEqual(len(chain.certificates), 2)
        self.assertIs(chain.certificates[0], c0)
        self.assertIs(chain.certificates[1], c1)
        self.assertNotEqual(chain, RotationChain(4, (c1, c0)))


class VerifyRotationChainTest(unittest.TestCase):
    def setUp(self):
        self.k0 = make_key((1, 2, 3), 2, seed_offset=0)
        self.k1 = make_key((2, 3, 4, 5), 3, seed_offset=10)
        self.k2 = make_key((3, 4, 5, 6), 2, seed_offset=20)
        self.cert0 = make_cert(self.k0, self.k1, (1, 3), t=3, seed=100)
        self.cert1 = make_cert(self.k1, self.k2, (2, 4, 5), t=2, seed=200)
        self.chain = RotationChain(
            self.k0.public_key, (self.cert0, self.cert1)
        )

    def test_honest_chain_verifies(self):
        self.assertTrue(verify_rotation(self.cert0))
        self.assertTrue(verify_rotation(self.cert1))
        self.assertTrue(verify_rotation_chain(self.chain))

    def test_single_hop_chain(self):
        chain = RotationChain(self.k0.public_key, (self.cert0,))
        self.assertTrue(verify_rotation_chain(chain))

    def test_anchor_mismatch_returns_false(self):
        chain = RotationChain(self.k1.public_key, (self.cert0, self.cert1))
        self.assertFalse(verify_rotation_chain(chain))

    def test_broken_linkage_returns_false(self):
        # cert1 claiming a different old key: linkage fails and its own
        # signature no longer matches either.
        moved = dataclasses.replace(self.cert1, old=self.k0.public_key)
        chain = RotationChain(self.k0.public_key, (self.cert0, moved))
        self.assertFalse(verify_rotation_chain(chain))

    def test_one_bad_signature_returns_false(self):
        bad_sig = AggregateSignature(
            R=self.cert1.sig.R,
            z=(self.cert1.sig.z + 1) % FIELD_PRIME,
            signer_ids=self.cert1.sig.signer_ids,
        )
        bad_cert = dataclasses.replace(self.cert1, sig=bad_sig)
        chain = RotationChain(self.k0.public_key, (self.cert0, bad_cert))
        self.assertFalse(verify_rotation_chain(chain))

    def test_first_cert_bad_signature_returns_false(self):
        bad_sig = AggregateSignature(
            R=self.cert0.sig.R,
            z=(self.cert0.sig.z + 1) % FIELD_PRIME,
            signer_ids=self.cert0.sig.signer_ids,
        )
        bad_cert = dataclasses.replace(self.cert0, sig=bad_sig)
        chain = RotationChain(self.k0.public_key, (bad_cert, self.cert1))
        self.assertFalse(verify_rotation_chain(chain))

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            verify_rotation_chain("chain")
        with self.assertRaises(TypeError):
            verify_rotation_chain(RotationChain("x", (self.cert0,)))
        with self.assertRaises(TypeError):
            verify_rotation_chain(RotationChain(True, (self.cert0,)))
        with self.assertRaises(TypeError):
            verify_rotation_chain(RotationChain(self.k0.public_key, ["x"]))
        with self.assertRaises(TypeError):
            verify_rotation_chain(
                RotationChain(self.k0.public_key, (self.cert0, "x"))
            )

    def test_empty_chain_value_error(self):
        with self.assertRaises(ValueError):
            verify_rotation_chain(RotationChain(self.k0.public_key, ()))

    def test_structurally_illegal_cert_raires_value_error(self):
        bad_cert = Rotation(
            3,  # not in the order-q subgroup
            self.k1.public_key,
            (1, 2),
            2,
            FIELD_PRIME,
            GROUP_PRIME,
            GENERATOR,
            self.cert0.sig,
        )
        chain = RotationChain(3, (bad_cert,))
        with self.assertRaises(ValueError):
            verify_rotation_chain(chain)


class RotationChainEncodingTest(unittest.TestCase):
    def setUp(self):
        self.k0 = make_key((1, 2, 3), 2, seed_offset=0)
        self.k1 = make_key((2, 3, 4, 5), 2, seed_offset=30)
        self.cert0 = make_cert(self.k0, self.k1, (1, 3), t=2, seed=300)
        self.chain = RotationChain(self.k0.public_key, (self.cert0,))

    def build_wire(self, anchor, certificates):
        """Hand-build the chain wire format independently of the encoder."""
        out = bytearray(CHAIN_TAG)
        out += len(certificates).to_bytes(4, "big")
        out += frame(minimal_be(anchor))
        for cert in certificates:
            out += frame(encode_rotation(cert))
        return bytes(out)

    def test_layout_matches_independent_builder(self):
        wire = encode_rotation_chain(self.chain)
        self.assertEqual(wire, self.build_wire(self.k0.public_key, (self.cert0,)))

    def test_tag_count_and_frames_in_order(self):
        k2 = make_key((4, 5, 6), 2, seed_offset=40)
        cert1 = make_cert(self.k1, k2, (2, 4), t=2, seed=310)
        chain = RotationChain(self.k0.public_key, (self.cert0, cert1))
        wire = encode_rotation_chain(chain)
        offset = 0
        self.assertTrue(wire.startswith(CHAIN_TAG))
        offset = len(CHAIN_TAG)
        self.assertEqual(int.from_bytes(wire[offset:offset + 4], "big"), 2)
        offset += 4
        anchor_len = int.from_bytes(wire[offset:offset + 4], "big")
        offset += 4
        self.assertEqual(
            int.from_bytes(wire[offset:offset + anchor_len], "big"),
            self.k0.public_key,
        )
        offset += anchor_len
        for cert in (self.cert0, cert1):
            cert_len = int.from_bytes(wire[offset:offset + 4], "big")
            offset += 4
            self.assertEqual(
                decode_rotation(wire[offset:offset + cert_len]), cert
            )
            offset += cert_len
        self.assertEqual(offset, len(wire))

    def test_zero_anchor_encodes_as_single_00(self):
        sig = AggregateSignature(R=GENERATOR, z=3, signer_ids=(1,))
        cert = Rotation(
            1, GENERATOR, (1,), 1, FIELD_PRIME, GROUP_PRIME, GENERATOR, sig
        )
        wire = encode_rotation_chain(RotationChain(0, (cert,)))
        # Frame: length 1 then body 00.
        offset = len(CHAIN_TAG) + 4
        self.assertEqual(wire[offset:offset + 5], b"\x00\x00\x00\x01\x00")
        decoded = decode_rotation_chain(wire)
        self.assertEqual(decoded.anchor, 0)

    def test_deterministic_unique_output(self):
        wire = encode_rotation_chain(self.chain)
        self.assertEqual(wire, encode_rotation_chain(self.chain))
        other = RotationChain(self.k1.public_key, (self.cert0,))
        self.assertNotEqual(wire, encode_rotation_chain(other))

    def test_roundtrip(self):
        decoded = decode_rotation_chain(encode_rotation_chain(self.chain))
        self.assertEqual(decoded, self.chain)
        self.assertEqual(encode_rotation_chain(decoded), encode_rotation_chain(self.chain))

    def test_multi_hop_roundtrip(self):
        k2 = make_key((4, 5, 6), 2, seed_offset=40)
        cert1 = make_cert(self.k1, k2, (2, 4), t=2, seed=310)
        chain = RotationChain(self.k0.public_key, (self.cert0, cert1))
        decoded = decode_rotation_chain(encode_rotation_chain(chain))
        self.assertEqual(decoded, chain)
        self.assertEqual(encode_rotation_chain(decoded), encode_rotation_chain(chain))

    def test_decode_does_not_verify(self):
        # Bad signature, linkage consistent: decodes normally, verifies False.
        bad_sig = AggregateSignature(
            R=self.cert0.sig.R,
            z=(self.cert0.sig.z + 1) % FIELD_PRIME,
            signer_ids=self.cert0.sig.signer_ids,
        )
        bad_cert = dataclasses.replace(self.cert0, sig=bad_sig)
        chain = RotationChain(self.k0.public_key, (bad_cert,))
        decoded = decode_rotation_chain(encode_rotation_chain(chain))
        self.assertEqual(decoded, chain)
        self.assertFalse(verify_rotation_chain(decoded))

    def test_anchor_mismatch_decodes_without_verification(self):
        chain = RotationChain(self.k1.public_key, (self.cert0,))
        decoded = decode_rotation_chain(encode_rotation_chain(chain))
        self.assertEqual(decoded, chain)
        self.assertFalse(verify_rotation_chain(decoded))

    # --- rejection tests -------------------------------------------------

    def test_encode_rejects_bad_types(self):
        self.assertRaises(TypeError, encode_rotation_chain, "chain")
        self.assertRaises(
            TypeError, encode_rotation_chain, RotationChain("1", (self.cert0,))
        )
        self.assertRaises(
            TypeError, encode_rotation_chain, RotationChain(True, (self.cert0,))
        )
        self.assertRaises(
            TypeError,
            encode_rotation_chain,
            RotationChain(self.k0.public_key, [self.cert0]),
        )
        self.assertRaises(
            TypeError,
            encode_rotation_chain,
            RotationChain(self.k0.public_key, ("cert",)),
        )

    def test_encode_rejects_empty_and_negative(self):
        self.assertRaises(
            ValueError,
            encode_rotation_chain,
            RotationChain(self.k0.public_key, ()),
        )
        self.assertRaises(
            ValueError,
            encode_rotation_chain,
            RotationChain(-1, (self.cert0,)),
        )

    def test_encode_rejects_illegal_certificate(self):
        bad_cert = Rotation(
            3,  # not in the order-q subgroup
            self.k1.public_key,
            (1, 2),
            2,
            FIELD_PRIME,
            GROUP_PRIME,
            GENERATOR,
            self.cert0.sig,
        )
        self.assertRaises(
            ValueError, encode_rotation_chain, RotationChain(3, (bad_cert,))
        )

    def test_decode_rejects_bad_types(self):
        wire = encode_rotation_chain(self.chain)
        for bad in ("wire", bytearray(wire), None, 42):
            self.assertRaises(TypeError, decode_rotation_chain, bad)

    def test_decode_rejects_bad_tag(self):
        wire = encode_rotation_chain(self.chain)
        self.assertRaises(ValueError, decode_rotation_chain, b"x" + wire[1:])
        self.assertRaises(ValueError, decode_rotation_chain, CHAIN_TAG)
        self.assertRaises(ValueError, decode_rotation_chain, b"")

    def test_decode_rejects_zero_count(self):
        self.assertRaises(
            ValueError, decode_rotation_chain, CHAIN_TAG + (0).to_bytes(4, "big")
        )

    def test_decode_rejects_truncation_at_every_cut(self):
        wire = encode_rotation_chain(self.chain)
        for cut in range(len(wire)):
            with self.assertRaises(ValueError, msg=f"cut {cut}"):
                decode_rotation_chain(wire[:cut])

    def test_decode_rejects_trailing_bytes(self):
        wire = encode_rotation_chain(self.chain)
        self.assertRaises(ValueError, decode_rotation_chain, wire + b"\x00")
        self.assertRaises(ValueError, decode_rotation_chain, wire + b"extra")

    def test_decode_rejects_count_mismatch(self):
        k2 = make_key((4, 5, 6), 2, seed_offset=40)
        cert1 = make_cert(self.k1, k2, (2, 4), t=2, seed=310)
        chain = RotationChain(self.k0.public_key, (self.cert0, cert1))
        wire = bytearray(encode_rotation_chain(chain))
        count_offset = len(CHAIN_TAG)
        # Declare three certificates but only two frames follow -> truncated.
        wire[count_offset:count_offset + 4] = (3).to_bytes(4, "big")
        self.assertRaises(ValueError, decode_rotation_chain, bytes(wire))
        # Declare one certificate but two frames follow -> trailing bytes.
        wire[count_offset:count_offset + 4] = (1).to_bytes(4, "big")
        self.assertRaises(ValueError, decode_rotation_chain, bytes(wire))

    def test_decode_rejects_non_canonical_anchor(self):
        wire = bytearray(encode_rotation_chain(self.chain))
        anchor_frame_offset = len(CHAIN_TAG) + 4
        body = minimal_be(self.k0.public_key)
        bad_frame = (len(body) + 1).to_bytes(4, "big") + b"\x00" + body
        wire[anchor_frame_offset:anchor_frame_offset + 4 + len(body)] = bad_frame
        self.assertRaises(ValueError, decode_rotation_chain, bytes(wire))

    def test_decode_rejects_zero_length_anchor_frame(self):
        wire = CHAIN_TAG + (1).to_bytes(4, "big") + (0).to_bytes(4, "big")
        self.assertRaises(ValueError, decode_rotation_chain, wire)

    def test_decode_rejects_huge_frame_length(self):
        wire = (
            CHAIN_TAG
            + (1).to_bytes(4, "big")
            + (0xFFFFFFFF).to_bytes(4, "big")
            + minimal_be(self.k0.public_key)
        )
        self.assertRaises(ValueError, decode_rotation_chain, wire)

    def test_decode_rejects_illegal_certificate_frame(self):
        good = encode_rotation_chain(self.chain)
        # Locate the certificate frame and replace its body with bytes of the
        # same length that decode_rotation rejects.
        offset = len(CHAIN_TAG) + 4
        anchor_len = int.from_bytes(good[offset:offset + 4], "big")
        offset += 4 + anchor_len
        cert_len = int.from_bytes(good[offset:offset + 4], "big")
        bad_body = b"\xff" * cert_len
        bad = (
            good[:offset + 4]
            + bad_body
            + good[offset + 4 + cert_len:]
        )
        self.assertRaises(ValueError, decode_rotation_chain, bad)


if __name__ == "__main__":
    unittest.main()
