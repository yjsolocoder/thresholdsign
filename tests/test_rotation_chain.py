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
    aggregate_signing_dkg,
    create_signature_share,
    create_signing_contribution,
    create_signing_nonce_commitment,
    create_signing_round,
    decode_rotation,
    decode_rotation_chain,
    encode_rotation,
    encode_rotation_chain,
    rotation_payload,
    verify_rotation,
    verify_rotation_chain,
)

# Same toy group as the rotation tests: 8069 = 4 * 2017 + 1 is prime, 16 and
# 256 = 16 ** 2 are distinct generators of the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

# A 3-byte group prime (L = 3) for encoding tests, same as the signing tests.
LARGE_FIELD = 1000151
LARGE_GROUP = 2000303
LARGE_G = 9
LARGE_H = 81

ROTATION_CHAIN_TAG = b"thresholdsign/rotation-chain/v1"


def fixed_random(seed=1):
    """Deterministic stand-in for secrets.randbelow (same LCG as DKG tests)."""
    state = {"value": seed}

    def randbelow(upper: int) -> int:
        state["value"] = (
            state["value"] * 6364136223846793005 + 1442695040888963407
        ) % upper
        return state["value"]

    return randbelow


def make_key(participant_ids, threshold, seed_base=0):
    contributions = [
        create_signing_contribution(
            pid,
            participant_ids,
            threshold,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            blinding_generator=BLINDING_GENERATOR,
            randbelow=fixed_random(seed_base + pid),
        )
        for pid in participant_ids
    ]
    return aggregate_signing_dkg(contributions)


def sign_message(key, message, signer_ids, seed=100):
    """Run the two-round protocol of ``key`` over ``message``."""
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


def make_rotation(old_key, new_key, signer_ids, seed):
    """Build an honest Rotation certificate from ``old_key`` to ``new_key``."""
    ids = new_key.result.participant_ids
    t = len(new_key.result.commitment.values)
    payload = rotation_payload(
        old_key.public_key,
        new_key.public_key,
        ids,
        t,
        FIELD_PRIME,
        GROUP_PRIME,
        GENERATOR,
    )
    sig = sign_message(old_key, payload, signer_ids, seed=seed)
    return Rotation(
        old_key.public_key,
        new_key.public_key,
        ids,
        t,
        FIELD_PRIME,
        GROUP_PRIME,
        GENERATOR,
        sig,
    )


def vint(value: int) -> bytes:
    """Minimal length-prefixed unsigned big-endian integer (test reference)."""
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return len(body).to_bytes(4, "big") + body


def frame(content: bytes) -> bytes:
    """A 4-byte unsigned big-endian length followed by the frame content."""
    return len(content).to_bytes(4, "big") + content


class HonestChainFixture:
    """A three-hop chain key0 -> key1 -> key2 -> key3."""

    def __init__(self):
        self.key0 = make_key((1, 2, 3), 2, seed_base=0)
        self.key1 = make_key((2, 3, 4, 5), 3, seed_base=10)
        self.key2 = make_key((4, 5, 6), 2, seed_base=20)
        self.key3 = make_key((1, 6, 7), 2, seed_base=30)
        self.cert0 = make_rotation(self.key0, self.key1, (1, 3), seed=100)
        self.cert1 = make_rotation(self.key1, self.key2, (2, 4, 5), seed=200)
        self.cert2 = make_rotation(self.key2, self.key3, (4, 6), seed=300)
        self.chain = RotationChain(
            anchor=self.key0.public_key,
            certificates=(self.cert0, self.cert1, self.cert2),
        )


class RotationChainDataTest(unittest.TestCase):
    def test_field_order_positional_value_equality(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(RotationChain)],
            ["anchor", "certificates"],
        )
        fixture = HonestChainFixture()
        chain = RotationChain(fixture.key0.public_key, (fixture.cert0, fixture.cert1))
        same = RotationChain(
            anchor=fixture.key0.public_key,
            certificates=(fixture.cert0, fixture.cert1),
        )
        self.assertEqual(chain, same)
        self.assertEqual(hash(chain), hash(same))
        # Order is significant.
        self.assertNotEqual(
            chain,
            RotationChain(fixture.key0.public_key, (fixture.cert1, fixture.cert0)),
        )
        # Anchor is significant.
        self.assertNotEqual(
            chain,
            RotationChain(fixture.key1.public_key, (fixture.cert0, fixture.cert1)),
        )

    def test_frozen(self):
        fixture = HonestChainFixture()
        with self.assertRaises(FrozenInstanceError):
            fixture.chain.anchor = 5
        with self.assertRaises(FrozenInstanceError):
            fixture.chain.certificates = (fixture.cert0,)


class VerifyRotationChainTest(unittest.TestCase):
    def setUp(self):
        self.fixture = HonestChainFixture()

    def test_honest_chain_verifies(self):
        self.assertTrue(verify_rotation_chain(self.fixture.chain))

    def test_single_certificate_chain_verifies(self):
        chain = RotationChain(
            anchor=self.fixture.key0.public_key,
            certificates=(self.fixture.cert0,),
        )
        self.assertTrue(verify_rotation_chain(chain))

    def test_wrong_anchor_returns_false(self):
        chain = RotationChain(
            anchor=self.fixture.key1.public_key,
            certificates=(self.fixture.cert0, self.fixture.cert1, self.fixture.cert2),
        )
        self.assertFalse(verify_rotation_chain(chain))

    def test_broken_link_returns_false(self):
        # Reorder the certificates: anchor matches cert0.old, but the
        # new/old links no longer line up.
        chain = RotationChain(
            anchor=self.fixture.key0.public_key,
            certificates=(self.fixture.cert0, self.fixture.cert2, self.fixture.cert1),
        )
        self.assertFalse(verify_rotation_chain(chain))

    def test_dropped_middle_certificate_returns_false(self):
        chain = RotationChain(
            anchor=self.fixture.key0.public_key,
            certificates=(self.fixture.cert0, self.fixture.cert2),
        )
        self.assertFalse(verify_rotation_chain(chain))

    def test_tampered_signature_returns_false(self):
        bad_sig = AggregateSignature(
            R=self.fixture.cert1.sig.R,
            z=(self.fixture.cert1.sig.z + 1) % FIELD_PRIME,
            signer_ids=self.fixture.cert1.sig.signer_ids,
        )
        bad_cert = dataclasses.replace(self.fixture.cert1, sig=bad_sig)
        chain = RotationChain(
            anchor=self.fixture.key0.public_key,
            certificates=(self.fixture.cert0, bad_cert, self.fixture.cert2),
        )
        self.assertFalse(verify_rotation_chain(chain))

    def test_tampered_cert_field_returns_false(self):
        # Swap the new key of the middle certificate: the link breaks and the
        # signature no longer matches.
        bad_cert = dataclasses.replace(
            self.fixture.cert1, new=self.fixture.key3.public_key
        )
        chain = RotationChain(
            anchor=self.fixture.key0.public_key,
            certificates=(self.fixture.cert0, bad_cert, self.fixture.cert2),
        )
        self.assertFalse(verify_rotation_chain(chain))

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            verify_rotation_chain("chain")
        with self.assertRaises(TypeError):
            verify_rotation_chain(RotationChain("1", (self.fixture.cert0,)))
        with self.assertRaises(TypeError):
            verify_rotation_chain(RotationChain(True, (self.fixture.cert0,)))
        with self.assertRaises(TypeError):
            verify_rotation_chain(
                RotationChain(self.fixture.key0.public_key, [self.fixture.cert0])
            )
        with self.assertRaises(TypeError):
            verify_rotation_chain(
                RotationChain(self.fixture.key0.public_key, ("cert",))
            )

    def test_structure_errors(self):
        with self.assertRaises(ValueError):  # empty chain
            verify_rotation_chain(RotationChain(self.fixture.key0.public_key, ()))
        with self.assertRaises(ValueError):  # negative anchor
            verify_rotation_chain(
                RotationChain(-1, (self.fixture.cert0,))
            )
        # A structurally illegal certificate surfaces ValueError exactly as
        # verify_rotation would raise.
        bad_cert = dataclasses.replace(self.fixture.cert0, q=2018)
        with self.assertRaises(ValueError):
            verify_rotation_chain(
                RotationChain(self.fixture.key0.public_key, (bad_cert,))
            )


class RotationChainEncodingTest(unittest.TestCase):
    def setUp(self):
        self.fixture = HonestChainFixture()

    def build_wire(self, chain):
        """Hand-build the chain wire encoding independently of the library."""
        out = bytearray(ROTATION_CHAIN_TAG)
        out += len(chain.certificates).to_bytes(4, "big")
        out += vint(chain.anchor)
        for cert in chain.certificates:
            out += frame(encode_rotation(cert))
        return bytes(out)

    def test_layout_matches_independent_builder(self):
        wire = encode_rotation_chain(self.fixture.chain)
        self.assertEqual(wire, self.build_wire(self.fixture.chain))

    def test_tag_count_anchor_frames_order(self):
        wire = encode_rotation_chain(self.fixture.chain)
        self.assertTrue(wire.startswith(ROTATION_CHAIN_TAG))
        offset = len(ROTATION_CHAIN_TAG)
        self.assertEqual(int.from_bytes(wire[offset:offset + 4], "big"), 3)
        offset += 4
        # Anchor frame.
        length = int.from_bytes(wire[offset:offset + 4], "big")
        offset += 4
        self.assertEqual(
            int.from_bytes(wire[offset:offset + length], "big"),
            self.fixture.key0.public_key,
        )
        offset += length
        # Three certificate frames in chain order.
        for cert in self.fixture.chain.certificates:
            length = int.from_bytes(wire[offset:offset + 4], "big")
            offset += 4
            body = wire[offset:offset + length]
            self.assertEqual(body, encode_rotation(cert))
            offset += length
        self.assertEqual(offset, len(wire))

    def test_zero_anchor_is_single_00_body(self):
        chain = RotationChain(anchor=0, certificates=(self.fixture.cert0,))
        wire = encode_rotation_chain(chain)
        offset = len(ROTATION_CHAIN_TAG) + 4
        self.assertEqual(wire[offset:offset + 5], b"\x00\x00\x00\x01\x00")
        decoded = decode_rotation_chain(wire)
        self.assertEqual(decoded.anchor, 0)
        # Anchor zero never matches a positive certificate old key.
        self.assertFalse(verify_rotation_chain(decoded))

    def test_deterministic_unique_output(self):
        chain = self.fixture.chain
        self.assertEqual(encode_rotation_chain(chain), encode_rotation_chain(chain))
        other = RotationChain(
            anchor=self.fixture.key1.public_key,
            certificates=chain.certificates,
        )
        self.assertNotEqual(
            encode_rotation_chain(chain), encode_rotation_chain(other)
        )

    def test_roundtrip(self):
        chain = self.fixture.chain
        wire = encode_rotation_chain(chain)
        decoded = decode_rotation_chain(wire)
        self.assertEqual(decoded, chain)
        self.assertEqual(encode_rotation_chain(decoded), wire)
        self.assertTrue(verify_rotation_chain(decoded))

    def test_decode_does_not_verify(self):
        # Broken link but every certificate structurally legal: decoding
        # succeeds, verification reports False.
        chain = RotationChain(
            anchor=self.fixture.key0.public_key,
            certificates=(self.fixture.cert0, self.fixture.cert2),
        )
        decoded = decode_rotation_chain(encode_rotation_chain(chain))
        self.assertEqual(decoded, chain)
        self.assertFalse(verify_rotation_chain(decoded))

        # A structurally legal certificate with a bad signature also
        # round-trips and fails verification only afterwards.
        bad_sig = AggregateSignature(
            R=self.fixture.cert0.sig.R,
            z=(self.fixture.cert0.sig.z + 1) % FIELD_PRIME,
            signer_ids=self.fixture.cert0.sig.signer_ids,
        )
        bad_chain = RotationChain(
            anchor=self.fixture.key0.public_key,
            certificates=(dataclasses.replace(self.fixture.cert0, sig=bad_sig),),
        )
        decoded = decode_rotation_chain(encode_rotation_chain(bad_chain))
        self.assertEqual(decoded, bad_chain)
        self.assertFalse(verify_rotation_chain(decoded))

    def test_rejects_bad_tag(self):
        wire = encode_rotation_chain(self.fixture.chain)
        self.assertRaises(ValueError, decode_rotation_chain, b"x" + wire[1:])
        self.assertRaises(ValueError, decode_rotation_chain, ROTATION_CHAIN_TAG)
        self.assertRaises(ValueError, decode_rotation_chain, b"")

    def test_rejects_empty_chain(self):
        wire = self.build_wire(
            RotationChain(self.fixture.key0.public_key, (self.fixture.cert0,))
        )
        # Rewrite the count to zero.
        offset = len(ROTATION_CHAIN_TAG)
        bad = wire[:offset] + (0).to_bytes(4, "big") + wire[offset + 4:]
        self.assertRaises(ValueError, decode_rotation_chain, bad)

    def test_rejects_noncanonical_anchor(self):
        chain = RotationChain(
            anchor=self.fixture.key0.public_key, certificates=(self.fixture.cert0,)
        )
        wire = self.build_wire(chain)
        offset = len(ROTATION_CHAIN_TAG) + 4
        body_length = int.from_bytes(wire[offset:offset + 4], "big")
        # Over-long length with a leading zero in the body.
        bad = (
            wire[:offset]
            + (body_length + 1).to_bytes(4, "big")
            + b"\x00"
            + wire[offset + 4:]
        )
        self.assertRaises(ValueError, decode_rotation_chain, bad)
        # Zero-length anchor body.
        bad = wire[:offset] + (0).to_bytes(4, "big") + wire[offset + 4:]
        self.assertRaises(ValueError, decode_rotation_chain, bad)

    def test_rejects_declared_count_mismatch(self):
        chain = RotationChain(
            anchor=self.fixture.key0.public_key,
            certificates=(self.fixture.cert0, self.fixture.cert1),
        )
        wire = self.build_wire(chain)
        offset = len(ROTATION_CHAIN_TAG)
        # Declare three certificates while only two frames follow.
        too_many = wire[:offset] + (3).to_bytes(4, "big") + wire[offset + 4:]
        self.assertRaises(ValueError, decode_rotation_chain, too_many)
        # Declare one certificate: the second frame is trailing bytes.
        too_few = wire[:offset] + (1).to_bytes(4, "big") + wire[offset + 4:]
        self.assertRaises(ValueError, decode_rotation_chain, too_few)

    def test_rejects_illegal_certificate_frame(self):
        chain = RotationChain(
            anchor=self.fixture.key0.public_key, certificates=(self.fixture.cert0,)
        )
        wire = self.build_wire(chain)
        # Replace the sole certificate frame's content with bytes that are
        # not a rotation certificate.
        offset = len(wire) - len(frame(encode_rotation(self.fixture.cert0)))
        bad = wire[:offset] + frame(b"not-a-certificate")
        self.assertRaises(ValueError, decode_rotation_chain, bad)

    def test_rejects_oversized_frame_length(self):
        chain = RotationChain(
            anchor=self.fixture.key0.public_key, certificates=(self.fixture.cert0,)
        )
        wire = self.build_wire(chain)
        offset = len(ROTATION_CHAIN_TAG) + 4 + len(vint(chain.anchor))
        bad = wire[:offset] + (0xFFFFFFFF).to_bytes(4, "big") + wire[offset + 4:]
        self.assertRaises(ValueError, decode_rotation_chain, bad)

    def test_rejects_truncation_at_every_cut(self):
        wire = encode_rotation_chain(self.fixture.chain)
        for cut in range(len(wire)):
            with self.assertRaises(ValueError, msg=f"cut {cut}"):
                decode_rotation_chain(wire[:cut])

    def test_rejects_trailing_bytes(self):
        wire = encode_rotation_chain(self.fixture.chain)
        self.assertRaises(ValueError, decode_rotation_chain, wire + b"\x00")
        self.assertRaises(ValueError, decode_rotation_chain, wire + b"extra")

    def test_decode_rejects_bad_types(self):
        wire = encode_rotation_chain(self.fixture.chain)
        for bad in ("wire", bytearray(wire), None, 42):
            with self.assertRaises(TypeError, msg=f"{bad!r}"):
                decode_rotation_chain(bad)

    def test_encode_rejects_bad_types(self):
        chain = self.fixture.chain
        self.assertRaises(TypeError, encode_rotation_chain, "chain")
        self.assertRaises(
            TypeError,
            encode_rotation_chain,
            RotationChain("1", chain.certificates),
        )
        self.assertRaises(
            TypeError,
            encode_rotation_chain,
            RotationChain(True, chain.certificates),
        )
        self.assertRaises(
            TypeError,
            encode_rotation_chain,
            RotationChain(chain.anchor, [self.fixture.cert0]),
        )
        self.assertRaises(
            TypeError,
            encode_rotation_chain,
            RotationChain(chain.anchor, (b"cert",)),
        )

    def test_encode_rejects_empty_or_negative(self):
        with self.assertRaises(ValueError):
            encode_rotation_chain(RotationChain(self.fixture.key0.public_key, ()))
        with self.assertRaises(ValueError):
            encode_rotation_chain(RotationChain(-1, (self.fixture.cert0,)))
        # A structurally illegal certificate is rejected at encode time.
        bad_cert = dataclasses.replace(self.fixture.cert0, t=99)
        with self.assertRaises(ValueError):
            encode_rotation_chain(RotationChain(self.fixture.key0.public_key, (bad_cert,)))


class RotationChainLargeGroupTest(unittest.TestCase):
    def _make_large_key(self, participant_ids, threshold, seed_base):
        contributions = [
            create_signing_contribution(
                pid,
                participant_ids,
                threshold,
                prime=LARGE_FIELD,
                group_prime=LARGE_GROUP,
                generator=LARGE_G,
                blinding_generator=LARGE_H,
                randbelow=fixed_random(seed_base + pid),
            )
            for pid in participant_ids
        ]
        return aggregate_signing_dkg(contributions)

    def test_large_group_honest_chain_roundtrip(self):
        old_key = self._make_large_key((1, 2, 3), 2, 0)
        new_key = self._make_large_key((2, 3, 4), 2, 40)
        ids = new_key.result.participant_ids
        t = 2
        payload = rotation_payload(
            old_key.public_key, new_key.public_key, ids, t,
            LARGE_FIELD, LARGE_GROUP, LARGE_G,
        )
        sig = sign_message(old_key, payload, (1, 3), seed=500)
        cert = Rotation(
            old_key.public_key, new_key.public_key, ids, t,
            LARGE_FIELD, LARGE_GROUP, LARGE_G, sig,
        )
        chain = RotationChain(anchor=old_key.public_key, certificates=(cert,))
        self.assertTrue(verify_rotation(chain.certificates[0]))
        wire = encode_rotation_chain(chain)
        decoded = decode_rotation_chain(wire)
        self.assertEqual(decoded, chain)
        self.assertEqual(encode_rotation_chain(decoded), wire)
        self.assertTrue(verify_rotation_chain(decoded))


if __name__ == "__main__":
    unittest.main()
