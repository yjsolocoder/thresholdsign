"""Regression tests: signature share receipts across a member resharing.

The joint public key stays fixed while the membership and the individual
verification shares change. These tests build an old key from the public
signing DKG entry points, run create_reshare/reshare onto a new, larger
member set with a raised threshold, and exercise signing and
SignatureShareReceipt creation on both sides of the transition.
"""

import dataclasses
import hashlib
import unittest

from thresholdsign import (
    SigningDKGResult,
    SignatureShareReceipt,
    aggregate_signature,
    aggregate_signing_dkg,
    create_reshare,
    create_signature_share,
    create_signature_share_receipt,
    create_signing_contribution,
    create_signing_nonce_commitment,
    create_signing_round,
    decode_signature_share_receipt,
    encode_signature_share_receipt,
    reconstruct_secret,
    reshare,
    verify_signature,
    verify_signature_share_receipt,
)

# Same toy group as the signing/reshare tests: 8069 = 4 * 2017 + 1 is prime
# and 16, 256 = 16 ** 2 generate the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

OLD_MEMBERS = (10, 20, 30)
OLD_THRESHOLD = 2
DEALERS = (10, 20)
NEW_MEMBERS = (10, 20, 40, 50)
NEW_THRESHOLD = 3
RETAINED_MEMBER = 10
REMOVED_MEMBER = 30
OLD_SIGNERS = (10, 20)
NEW_SIGNERS = (10, 20, 40)

OLD_MESSAGE = b"receipt regression: before resharing"
NEW_MESSAGE = b"receipt regression: after resharing"


def fixed_random(seed=1):
    """Deterministic stand-in for secrets.randbelow (same LCG as the suites)."""
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
            randbelow=fixed_random(pid + seed_base),
        )
        for pid in participant_ids
    ]
    outcome = aggregate_signing_dkg(contributions)
    assert isinstance(outcome, SigningDKGResult), outcome
    return outcome


def secret_share_of(key, participant_id):
    index = key.result.participant_ids.index(participant_id)
    return key.result.shares[index].y


def make_round_and_shares(key, signer_ids, message, seed):
    """Run both Schnorr rounds with deterministic nonces."""
    commitments = []
    nonces = {}
    for offset, signer_id in enumerate(signer_ids):
        commitment, nonce = create_signing_nonce_commitment(
            signer_id,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            randbelow=fixed_random(seed + 100 * offset + signer_id),
        )
        commitments.append(commitment)
        nonces[signer_id] = nonce
    round_info = create_signing_round(
        message, tuple(signer_ids), commitments, key
    )
    shares = [
        create_signature_share(
            signer_id,
            secret_share_of(key, signer_id),
            nonces[signer_id],
            round_info,
            key,
        )
        for signer_id in signer_ids
    ]
    return round_info, commitments, nonces, shares


def lagrange_weight(signer_id, signer_ids, prime):
    """Lagrange weight at zero, exactly as documented in the README."""
    numerator = 1
    denominator = 1
    for other in signer_ids:
        if other == signer_id:
            continue
        numerator = numerator * (-other) % prime
        denominator = denominator * (signer_id - other) % prime
    return numerator * pow(denominator, -1, prime) % prime


def documented_challenge(message, public_key, R, signer_ids):
    """Recompute the Fiat-Shamir challenge straight from the README spec."""
    length = (GROUP_PRIME.bit_length() + 7) // 8
    buffer = b"thresholdsign/schnorr/v1" + hashlib.sha256(message).digest()
    buffer += public_key.to_bytes(length, "big")
    buffer += R.to_bytes(length, "big")
    for signer_id in signer_ids:
        buffer += signer_id.to_bytes(length, "big")
    return int.from_bytes(hashlib.sha256(buffer).digest(), "big") % FIELD_PRIME


def share_equation_holds(receipt):
    """Check g^z_i == R_i * Y_i ** (c * lambda_i) straight from the docs."""
    challenge = documented_challenge(
        receipt.message, receipt.Y, receipt.R, receipt.signer_ids
    )
    weight = lagrange_weight(
        receipt.signer_id, receipt.signer_ids, receipt.q
    )
    left = pow(receipt.g, receipt.z_i, receipt.p)
    right = (
        receipt.R_i
        * pow(receipt.Y_i, challenge * weight % receipt.q, receipt.p)
        % receipt.p
    )
    return left == right


def assert_share_equation(test_case, receipt):
    test_case.assertTrue(
        share_equation_holds(receipt),
        "documented share equation does not hold",
    )


class ReshareFixture:
    """Builds both stages deterministically; fresh state for every test."""

    def setUp(self):
        # Member numbers are deliberately non-consecutive: a signer id must
        # never be mistaken for a share-list position.
        self.old_key = make_key(OLD_MEMBERS, OLD_THRESHOLD)
        (
            self.old_round,
            self.old_commitments,
            self.old_nonces,
            self.old_shares,
        ) = make_round_and_shares(
            self.old_key, OLD_SIGNERS, OLD_MESSAGE, seed=10
        )
        self.old_signature = aggregate_signature(
            self.old_shares, self.old_round, self.old_key
        )
        self.old_receipts = tuple(
            create_signature_share_receipt(
                OLD_MESSAGE, share, self.old_round, self.old_key
            )
            for share in self.old_shares
        )

        contributions = [
            create_reshare(
                dealer,
                secret_share_of(self.old_key, dealer),
                DEALERS,
                NEW_MEMBERS,
                NEW_THRESHOLD,
                self.old_key,
                rng=fixed_random(dealer + 100),
            )
            for dealer in DEALERS
        ]
        outcome = reshare(contributions, DEALERS, self.old_key)
        assert isinstance(outcome, SigningDKGResult), outcome
        self.new_key = outcome

        (
            self.new_round,
            self.new_commitments,
            self.new_nonces,
            self.new_shares,
        ) = make_round_and_shares(
            self.new_key, NEW_SIGNERS, NEW_MESSAGE, seed=80
        )
        self.new_signature = aggregate_signature(
            self.new_shares, self.new_round, self.new_key
        )
        self.new_receipts = tuple(
            create_signature_share_receipt(
                NEW_MESSAGE, share, self.new_round, self.new_key
            )
            for share in self.new_shares
        )

    def verification_share(self, key, participant_id):
        return key.verification_shares[
            key.result.participant_ids.index(participant_id)
        ]


class ReshareScenarioTest(ReshareFixture, unittest.TestCase):
    def test_scenario_invariants(self):
        # The old quorum has exactly the old threshold, both dealers carry
        # over into the new membership, and the removed old member never
        # dealt.
        self.assertEqual(len(DEALERS), OLD_THRESHOLD)
        self.assertTrue(set(DEALERS) <= set(OLD_MEMBERS))
        self.assertTrue(set(DEALERS) <= set(NEW_MEMBERS))
        self.assertIn(RETAINED_MEMBER, NEW_MEMBERS)
        self.assertIn(RETAINED_MEMBER, DEALERS)
        self.assertNotIn(REMOVED_MEMBER, NEW_MEMBERS)
        self.assertNotIn(REMOVED_MEMBER, DEALERS)
        # Non-consecutive numbering: id and share position never coincide.
        for participant_id in OLD_MEMBERS + NEW_MEMBERS:
            self.assertGreaterEqual(participant_id, len(NEW_MEMBERS))
        # The new set mixes retained and freshly added members.
        self.assertEqual(
            set(NEW_MEMBERS) - set(OLD_MEMBERS), {40, 50}
        )
        self.assertEqual(
            set(NEW_MEMBERS) & set(OLD_MEMBERS), {10, 20}
        )

    def test_reshare_preserves_joint_public_key_and_group_parameters(self):
        self.assertEqual(self.new_key.public_key, self.old_key.public_key)
        old_commitment = self.old_key.result.commitment
        new_commitment = self.new_key.result.commitment
        self.assertEqual(
            (
                new_commitment.field_prime,
                new_commitment.group_prime,
                new_commitment.generator,
                new_commitment.blinding_generator,
            ),
            (
                old_commitment.field_prime,
                old_commitment.group_prime,
                old_commitment.generator,
                old_commitment.blinding_generator,
            ),
        )
        self.assertEqual(
            len(self.new_key.result.commitment.values), NEW_THRESHOLD
        )
        self.assertEqual(
            self.new_key.result.participant_ids, NEW_MEMBERS
        )

    def test_new_threshold_shares_rebuild_the_old_secret(self):
        old_secret = reconstruct_secret(
            self.old_key.result.shares[:OLD_THRESHOLD], prime=FIELD_PRIME
        )
        # Every NEW_THRESHOLD-sized subset of the four new shares rebuilds
        # the same value, including subsets with no retained dealer.
        new_shares = self.new_key.result.shares
        for subset in (
            (0, 1, 2),
            (0, 1, 3),
            (0, 2, 3),
            (1, 2, 3),
        ):
            rebuilt = reconstruct_secret(
                [new_shares[index] for index in subset], prime=FIELD_PRIME
            )
            self.assertEqual(rebuilt, old_secret)
        # Independent Feldman check from the documentation: Y = g ** s.
        self.assertEqual(
            pow(GENERATOR, old_secret, GROUP_PRIME), self.old_key.public_key
        )
        self.assertEqual(
            pow(GENERATOR, old_secret, GROUP_PRIME), self.new_key.public_key
        )

    def test_reshare_constant_terms_combine_into_the_joint_key(self):
        # The documented resharing identity: product over the dealers of
        # Y_i ** lambda_i == Y (their weighted shares interpolate s at zero).
        expected = 1
        for dealer in DEALERS:
            weight = lagrange_weight(
                dealer, DEALERS, FIELD_PRIME
            )
            expected = (
                expected
                * pow(
                    self.verification_share(self.old_key, dealer),
                    weight,
                    GROUP_PRIME,
                )
                % GROUP_PRIME
            )
        self.assertEqual(expected, self.old_key.public_key)

    def test_new_signature_verifies_under_original_joint_public_key(self):
        for message, signature in (
            (OLD_MESSAGE, self.old_signature),
            (NEW_MESSAGE, self.new_signature),
        ):
            self.assertTrue(
                verify_signature(
                    message,
                    signature,
                    self.old_key.public_key,
                    prime=FIELD_PRIME,
                    group_prime=GROUP_PRIME,
                    generator=GENERATOR,
                )
            )
            # Independent aggregate equation from the docs: g^z = R * Y^c.
            challenge = documented_challenge(
                message, self.old_key.public_key, signature.R,
                signature.signer_ids,
            )
            self.assertEqual(
                pow(GENERATOR, signature.z, GROUP_PRIME),
                signature.R
                * pow(self.old_key.public_key, challenge, GROUP_PRIME)
                % GROUP_PRIME,
            )

    def test_every_stage_share_produces_a_receipt_with_stage_key_data(self):
        stages = (
            (self.old_key, self.old_round, self.old_shares, self.old_receipts),
            (self.new_key, self.new_round, self.new_shares, self.new_receipts),
        )
        for key, round_info, shares, receipts in stages:
            self.assertEqual(len(receipts), len(shares))
            for share, receipt in zip(shares, receipts):
                self.assertIsInstance(receipt, SignatureShareReceipt)
                self.assertEqual(receipt.signer_id, share.signer_id)
                self.assertEqual(receipt.R_i, share.nonce_commitment)
                self.assertEqual(receipt.z_i, share.z)
                self.assertEqual(receipt.R, round_info.R)
                self.assertEqual(receipt.signer_ids, round_info.signer_ids)
                # The individual verification share is looked up by the
                # member's *position in that stage's participant list*,
                # never by its (non-consecutive) id.
                position = key.result.participant_ids.index(share.signer_id)
                self.assertEqual(
                    receipt.Y_i, key.verification_shares[position]
                )
                self.assertEqual(receipt.Y, key.public_key)
                self.assertEqual(
                    (receipt.q, receipt.p, receipt.g),
                    (FIELD_PRIME, GROUP_PRIME, GENERATOR),
                )

    def test_receipts_roundtrip_byte_exact_and_verify_when_restored(self):
        for receipt in self.old_receipts + self.new_receipts:
            blob = encode_signature_share_receipt(receipt)
            self.assertIsInstance(blob, bytes)
            restored = decode_signature_share_receipt(blob)
            self.assertEqual(restored, receipt)
            self.assertEqual(
                encode_signature_share_receipt(restored), blob
            )
            self.assertIs(
                verify_signature_share_receipt(restored), True
            )

    def test_saved_old_receipts_remain_valid_after_the_reshare(self):
        # Members leaving and individual shares changing must not be read as
        # automatic revocation of receipts minted earlier.
        self.assertNotIn(REMOVED_MEMBER, self.new_key.result.participant_ids)
        for receipt in self.old_receipts:
            blob = encode_signature_share_receipt(receipt)
            restored = decode_signature_share_receipt(blob)
            self.assertIs(
                verify_signature_share_receipt(restored), True
            )

    def test_each_valid_receipt_satisfies_the_documented_share_equation(self):
        for receipt in self.old_receipts + self.new_receipts:
            assert_share_equation(self, receipt)
            # The independent equation and the public verifier agree, but
            # the equation above is the primary, documentation-derived check.
            self.assertIs(
                verify_signature_share_receipt(receipt), True
            )

    def test_retained_member_gets_a_different_individual_share(self):
        old_Y_i = self.verification_share(self.old_key, RETAINED_MEMBER)
        new_Y_i = self.verification_share(self.new_key, RETAINED_MEMBER)
        self.assertNotEqual(old_Y_i, new_Y_i)
        # The secret share behind it changed as well.
        self.assertNotEqual(
            secret_share_of(self.old_key, RETAINED_MEMBER),
            secret_share_of(self.new_key, RETAINED_MEMBER),
        )
        # Other retained member changes too; the removed member has no new share.
        self.assertNotEqual(
            self.verification_share(self.old_key, 20),
            self.verification_share(self.new_key, 20),
        )


class ReceiptMismatchBoundaryTest(ReshareFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.retained_new_receipt = next(
            receipt
            for receipt in self.new_receipts
            if receipt.signer_id == RETAINED_MEMBER
        )
        self.retained_old_Y_i = self.verification_share(
            self.old_key, RETAINED_MEMBER
        )

    def _snapshot(self):
        return (
            self.old_key.public_key,
            tuple(self.old_key.verification_shares),
            tuple(share.y for share in self.old_key.result.shares),
            self.new_key.public_key,
            tuple(self.new_key.verification_shares),
            tuple(share.y for share in self.new_key.result.shares),
            tuple(
                (share.signer_id, share.nonce_commitment, share.z)
                for share in self.old_shares + self.new_shares
            ),
        )

    def test_round_challenges_are_nonzero(self):
        # The Y_i mismatch below only has its documented meaning when the
        # challenge multiplying Y_i is nonzero.
        self.assertNotEqual(self.old_round.challenge, 0)
        self.assertNotEqual(self.new_round.challenge, 0)

    def test_old_and_new_Y_i_of_retained_member_really_differ(self):
        self.assertNotEqual(
            self.retained_old_Y_i, self.retained_new_receipt.Y_i
        )

    def test_replacing_new_Y_i_with_old_value_roundtrips_but_fails(self):
        mismatched = dataclasses.replace(
            self.retained_new_receipt, Y_i=self.retained_old_Y_i
        )
        # Structure is untouched: encode and decode still succeed.
        blob = encode_signature_share_receipt(mismatched)
        restored = decode_signature_share_receipt(blob)
        self.assertEqual(restored, mismatched)
        self.assertEqual(encode_signature_share_receipt(restored), blob)
        # The share equation no longer holds.
        self.assertIs(
            verify_signature_share_receipt(restored), False
        )
        # And it fails the documentation-derived equation as well, rather
        # than merely disagreeing with some other verifier entry.
        self.assertFalse(share_equation_holds(restored))
        # Every other field is unchanged: the genuine receipt still satisfies
        # the same equation and the public verifier.
        self.assertTrue(
            share_equation_holds(self.retained_new_receipt)
        )
        self.assertTrue(
            verify_signature_share_receipt(self.retained_new_receipt)
        )

    def test_new_round_share_handed_to_old_key_raises_value_error(self):
        # The new quorum (10, 20, 40) mixes retained members with member 40,
        # whom the old key never knew. Presenting any share of this valid new
        # round together with the old key is a context inconsistency rather
        # than a verifiable receipt — including shares from retained members,
        # whose individual verification share has since changed.
        for share in self.new_shares:
            with self.assertRaises(ValueError):
                create_signature_share_receipt(
                    NEW_MESSAGE,
                    share,
                    self.new_round,
                    self.old_key,
                )

    def test_round_below_new_threshold_raises_value_error(self):
        # Two new members cannot open a threshold-three round.
        with self.assertRaises(ValueError):
            make_round_and_shares(
                self.new_key, (10, 40), NEW_MESSAGE, seed=80
            )

    def test_decode_non_bytes_raises_type_error(self):
        with self.assertRaises(TypeError):
            decode_signature_share_receipt("not bytes")
        with self.assertRaises(TypeError):
            decode_signature_share_receipt(bytearray(b"x"))
        with self.assertRaises(TypeError):
            decode_signature_share_receipt(None)

    def test_trailing_bytes_raise_value_error(self):
        blob = encode_signature_share_receipt(self.retained_new_receipt)
        with self.assertRaises(ValueError):
            decode_signature_share_receipt(blob + b"\x00")
        with self.assertRaises(ValueError):
            decode_signature_share_receipt(blob + b"tail")

    def test_failures_leave_valid_receipts_and_inputs_intact(self):
        before = self._snapshot()
        # Exercise every failing boundary above.
        self.assertFalse(
            share_equation_holds(
                dataclasses.replace(
                    self.retained_new_receipt, Y_i=self.retained_old_Y_i
                )
            )
        )
        with self.assertRaises(ValueError):
            create_signature_share_receipt(
                NEW_MESSAGE,
                next(s for s in self.new_shares if s.signer_id == 40),
                self.new_round,
                self.old_key,
            )
        with self.assertRaises(ValueError):
            make_round_and_shares(
                self.new_key, (10, 40), NEW_MESSAGE, seed=80
            )
        with self.assertRaises(TypeError):
            decode_signature_share_receipt("not bytes")
        with self.assertRaises(ValueError):
            decode_signature_share_receipt(
                encode_signature_share_receipt(self.retained_new_receipt)
                + b"\x00"
            )
        self.assertEqual(self._snapshot(), before)
        # Both stages' saved receipts still verify.
        for receipt in self.old_receipts + self.new_receipts:
            self.assertIs(
                verify_signature_share_receipt(
                    decode_signature_share_receipt(
                        encode_signature_share_receipt(receipt)
                    )
                ),
                True,
            )


if __name__ == "__main__":
    unittest.main()
