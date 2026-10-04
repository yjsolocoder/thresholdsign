"""Regression tests tying signature share receipts to the reshare boundary.

The joint public key stays fixed across a member resharing while individual
verification shares may change; these tests pin down what that means for the
self-contained ``SignatureShareReceipt``: receipts are bound to the personal
verification share of *their* signing stage, but a receipt that verified
before the resharing keeps verifying afterwards — members leaving or shares
being rerandomised must not retroactively invalidate a saved receipt.

Everything runs through the public DKG / signing / resharing / receipt
entry points with deterministic injected randomness; the success
conclusions are also recomputed directly from the share equation documented
in the README rather than only comparing two library verifiers.
"""

import dataclasses
import hashlib
import unittest
from dataclasses import dataclass

from thresholdsign import (
    SigningDKGResult,
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

# Same toy group as the reshare tests: 8069 = 4 * 2017 + 1 is prime and
# 16, 256 = 16 ** 2 generate the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

# Non-consecutive member numbers on purpose: an id must never be confused
# with a share's tuple position. The old member 27 does not deal and is not
# part of the new member set; the dealers meet the old threshold (2) and are
# all retained members; the new threshold is raised to 3.
OLD_IDS = (3, 11, 27)
OLD_THRESHOLD = 2
DEALERS = (3, 11)
NEW_IDS = (3, 11, 42, 59)
NEW_THRESHOLD = 3
REMOVED_MEMBER = 27

OLD_MESSAGE = b"pay before member resharing"
NEW_MESSAGE = b"pay after member resharing"
OLD_SIGNERS = (3, 11)
NEW_SIGNERS = (3, 42, 59)


def fixed_random(seed=1):
    """Deterministic stand-in for secrets.randbelow (same LCG as the other tests)."""
    state = {"value": seed}

    def randbelow(upper: int) -> int:
        state["value"] = (
            state["value"] * 6364136223846793005 + 1442695040888963407
        ) % upper
        return state["value"]

    return randbelow


def secret_share_of(key, participant_id):
    index = key.result.participant_ids.index(participant_id)
    return key.result.shares[index].y


def verification_share_of(key, participant_id):
    index = key.result.participant_ids.index(participant_id)
    return key.verification_shares[index]


@dataclass(frozen=True)
class SignedStage:
    message: bytes
    signer_ids: tuple[int, ...]
    round_info: object
    shares: tuple
    receipts: tuple
    signature: object


@dataclass(frozen=True)
class ReshareScenario:
    old_key: SigningDKGResult
    new_key: SigningDKGResult
    old_stage: SignedStage
    new_stage: SignedStage

    @property
    def old_secret(self):
        return reconstruct_secret(self.old_key.result.shares[:OLD_THRESHOLD],
                                  prime=FIELD_PRIME)


def make_old_key():
    contributions = [
        create_signing_contribution(
            pid,
            OLD_IDS,
            OLD_THRESHOLD,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            blinding_generator=BLINDING_GENERATOR,
            randbelow=fixed_random(pid),
        )
        for pid in OLD_IDS
    ]
    outcome = aggregate_signing_dkg(contributions)
    assert isinstance(outcome, SigningDKGResult), outcome
    return outcome


def make_new_key(old_key):
    contributions = [
        create_reshare(
            dealer,
            secret_share_of(old_key, dealer),
            DEALERS,
            NEW_IDS,
            NEW_THRESHOLD,
            old_key,
            rng=fixed_random(300 + dealer),
        )
        for dealer in DEALERS
    ]
    outcome = reshare(contributions, DEALERS, old_key)
    assert isinstance(outcome, SigningDKGResult), outcome
    return outcome


def sign_stage(key, signer_ids, message, seed):
    """Run both Schnorr rounds deterministically and build every receipt."""
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
    round_info = create_signing_round(message, tuple(signer_ids), commitments, key)
    shares = tuple(
        create_signature_share(
            signer_id,
            secret_share_of(key, signer_id),
            nonces[signer_id],
            round_info,
            key,
        )
        for signer_id in signer_ids
    )
    receipts = tuple(
        create_signature_share_receipt(message, share, round_info, key)
        for share in shares
    )
    signature = aggregate_signature(shares, round_info, key)
    assert not isinstance(signature, list), signature
    return SignedStage(message, tuple(signer_ids), round_info, shares,
                       receipts, signature)


def build_scenario():
    old_key = make_old_key()
    # Sign with the old key and freeze its receipts before the resharing.
    old_stage = sign_stage(old_key, OLD_SIGNERS, OLD_MESSAGE, seed=10)
    new_key = make_new_key(old_key)
    new_stage = sign_stage(new_key, NEW_SIGNERS, NEW_MESSAGE, seed=70)
    return ReshareScenario(old_key, new_key, old_stage, new_stage)


# ---------------------------------------------------------------------------
# Independent recomputation of the documented mathematics. These helpers use
# only hashlib and field/group arithmetic on public receipt fields, so a
# passing assertion below is not just two library entry points agreeing.
# ---------------------------------------------------------------------------

def documented_challenge(message, public_key, R, signer_ids, q, p):
    """c as specified in the README: SHA256(tag || SHA256(message) || Y || R || ids)."""
    length = (p.bit_length() + 7) // 8

    def be(value):
        return value.to_bytes(length, "big", signed=False)

    preimage = bytearray(b"thresholdsign/schnorr/v1")
    preimage += hashlib.sha256(message).digest()
    preimage += be(public_key)
    preimage += be(R)
    for signer_id in signer_ids:
        preimage += be(signer_id)
    return int.from_bytes(hashlib.sha256(bytes(preimage)).digest(), "big") % q


def documented_lagrange_weight(signer_id, signer_ids, q):
    numerator = 1
    denominator = 1
    for other in signer_ids:
        if other == signer_id:
            continue
        numerator = numerator * (-other) % q
        denominator = denominator * (signer_id - other) % q
    return numerator * pow(denominator, -1, q) % q


def share_equation_holds(receipt):
    """g ** z_i == R_i * Y_i ** (c * lambda_i) (mod p), straight from the README."""
    c = documented_challenge(
        receipt.message, receipt.Y, receipt.R, receipt.signer_ids,
        receipt.q, receipt.p,
    )
    weight = documented_lagrange_weight(
        receipt.signer_id, receipt.signer_ids, receipt.q
    )
    expected = (
        receipt.R_i * pow(receipt.Y_i, c * weight % receipt.q, receipt.p)
    ) % receipt.p
    return pow(receipt.g, receipt.z_i, receipt.p) == expected and c != 0


def aggregate_equation_holds(message, signature, public_key, q, p, g):
    """g ** z == R * Y ** c (mod p) for the aggregate signature."""
    c = documented_challenge(
        message, public_key, signature.R, signature.signer_ids, q, p
    )
    return pow(g, signature.z, p) == (
        signature.R * pow(public_key, c, p) % p
    )


class ReshareReceiptInvariantTest(unittest.TestCase):
    def setUp(self):
        self.scenario = build_scenario()

    def test_reshare_preserves_public_key_and_group_parameters(self):
        old_key = self.scenario.old_key
        new_key = self.scenario.new_key
        self.assertEqual(new_key.public_key, old_key.public_key)
        old_pedersen = old_key.result.commitment
        new_pedersen = new_key.result.commitment
        self.assertEqual(new_pedersen.field_prime, old_pedersen.field_prime)
        self.assertEqual(new_pedersen.group_prime, old_pedersen.group_prime)
        self.assertEqual(new_pedersen.generator, old_pedersen.generator)
        self.assertEqual(
            new_pedersen.blinding_generator, old_pedersen.blinding_generator
        )
        # The resharing really did change the membership and raise the
        # threshold; only the joint key is meant to be fixed.
        self.assertEqual(new_key.result.participant_ids, NEW_IDS)
        self.assertEqual(len(new_pedersen.values), NEW_THRESHOLD)
        self.assertEqual(len(old_pedersen.values), OLD_THRESHOLD)
        self.assertNotIn(REMOVED_MEMBER, new_key.result.participant_ids)

    def test_new_threshold_shares_rebuild_the_old_secret(self):
        old_key = self.scenario.old_key
        new_key = self.scenario.new_key
        old_secret = self.scenario.old_secret
        # The old secret is itself recovered from exactly old-threshold
        # shares, independently of the DKG that built the key.
        self.assertEqual(
            reconstruct_secret(old_key.result.shares[1:3], prime=FIELD_PRIME),
            old_secret,
        )
        # Every new-threshold-sized subset rebuilds the same secret,
        # including quorums made mainly of genuinely new members.
        triples = (
            (3, 42, 59),
            (11, 42, 59),
            (3, 11, 59),
            (3, 11, 42),
        )
        for members in triples:
            picked = [
                new_key.result.shares[new_key.result.participant_ids.index(member)]
                for member in members
            ]
            self.assertEqual(
                reconstruct_secret(picked, prime=FIELD_PRIME),
                old_secret,
                members,
            )
        # g ** old_secret must be the preserved joint public key.
        self.assertEqual(
            pow(GENERATOR, old_secret, GROUP_PRIME), old_key.public_key
        )

    def test_signatures_from_both_stages_verify_under_original_public_key(self):
        scenario = self.scenario
        for stage in (scenario.old_stage, scenario.new_stage):
            self.assertIs(
                verify_signature(
                    stage.message,
                    stage.signature,
                    scenario.old_key.public_key,
                    prime=FIELD_PRIME,
                    group_prime=GROUP_PRIME,
                    generator=GENERATOR,
                ),
                True,
            )
            # Independent check of the documented aggregate equation, with
            # the challenge recomputed from scratch.
            self.assertTrue(
                aggregate_equation_holds(
                    stage.message,
                    stage.signature,
                    scenario.old_key.public_key,
                    FIELD_PRIME,
                    GROUP_PRIME,
                    GENERATOR,
                )
            )

    def test_every_valid_share_in_each_stage_yields_a_receipt(self):
        scenario = self.scenario
        for key, stage in (
            (scenario.old_key, scenario.old_stage),
            (scenario.new_key, scenario.new_stage),
        ):
            self.assertEqual(len(stage.receipts), len(stage.signer_ids))
            for share, receipt in zip(stage.shares, stage.receipts):
                self.assertEqual(receipt.signer_id, share.signer_id)
                self.assertEqual(receipt.z_i, share.z)
                self.assertEqual(receipt.R_i, share.nonce_commitment)
                self.assertEqual(receipt.Y, key.public_key)
                self.assertEqual(
                    (receipt.q, receipt.p, receipt.g),
                    (FIELD_PRIME, GROUP_PRIME, GENERATOR),
                )
                # Y_i is the personal verification share of THIS stage,
                # located by member id rather than tuple position.
                self.assertEqual(
                    receipt.Y_i,
                    verification_share_of(key, share.signer_id),
                )
                position = key.result.participant_ids.index(share.signer_id)
                self.assertEqual(
                    receipt.Y_i, key.verification_shares[position]
                )
                self.assertEqual(
                    pow(
                        GENERATOR,
                        key.result.shares[position].y,
                        GROUP_PRIME,
                    ),
                    receipt.Y_i,
                )
                self.assertIs(verify_signature_share_receipt(receipt), True)

    def test_receipt_for_new_member_is_id_bound_not_position_bound(self):
        # New member 42 sits at tuple position 2 of the new key; its receipt
        # must carry g ** s_42, not the verification share at position 0.
        new_key = self.scenario.new_key
        receipt_42 = next(
            receipt
            for receipt in self.scenario.new_stage.receipts
            if receipt.signer_id == 42
        )
        self.assertEqual(receipt_42.Y_i, verification_share_of(new_key, 42))
        self.assertNotEqual(receipt_42.Y_i, new_key.verification_shares[0])
        self.assertEqual(
            new_key.result.shares[new_key.result.participant_ids.index(42)].x,
            42,
        )

    def test_receipt_codec_round_trips_by_value_and_bytes(self):
        for stage in (self.scenario.old_stage, self.scenario.new_stage):
            for receipt in stage.receipts:
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

    def test_success_follows_independently_from_documented_share_equation(self):
        for stage in (self.scenario.old_stage, self.scenario.new_stage):
            for receipt in stage.receipts:
                # Recomputed solely from the documented challenge format and
                # the g ** z_i == R_i * Y_i ** (c * lambda_i) equation.
                self.assertTrue(share_equation_holds(receipt))
                blob = encode_signature_share_receipt(receipt)
                self.assertTrue(
                    share_equation_holds(decode_signature_share_receipt(blob))
                )
                # And the documented equation agrees with the public
                # verifier rather than being tested in isolation.
                self.assertEqual(
                    share_equation_holds(receipt),
                    verify_signature_share_receipt(receipt),
                )

    def test_retained_member_has_different_shares_but_same_joint_key(self):
        old_key = self.scenario.old_key
        new_key = self.scenario.new_key
        for retained in DEALERS:
            old_Y = verification_share_of(old_key, retained)
            new_Y = verification_share_of(new_key, retained)
            self.assertNotEqual(old_Y, new_Y)
            self.assertNotEqual(
                secret_share_of(old_key, retained),
                secret_share_of(new_key, retained),
            )
            self.assertEqual(new_key.public_key, old_key.public_key)

    def test_saved_old_receipts_keep_verifying_after_the_resharing(self):
        # The receipts were frozen before reshare(); neither the removed
        # member nor the changed personal shares may retire a receipt whose
        # share equation held at its own stage.
        for receipt in self.scenario.old_stage.receipts:
            self.assertIs(verify_signature_share_receipt(receipt), True)
            restored = decode_signature_share_receipt(
                encode_signature_share_receipt(receipt)
            )
            self.assertIs(verify_signature_share_receipt(restored), True)
            self.assertTrue(share_equation_holds(restored))


class ReshareReceiptMismatchTest(unittest.TestCase):
    def setUp(self):
        self.scenario = build_scenario()
        self.old_key = self.scenario.old_key
        self.new_key = self.scenario.new_key
        self.old_stage = self.scenario.old_stage
        self.new_stage = self.scenario.new_stage
        self.retained_receipt = next(
            receipt
            for receipt in self.new_stage.receipts
            if receipt.signer_id == 3
        )
        self.old_Y_3 = verification_share_of(self.old_key, 3)
        self.new_Y_3 = verification_share_of(self.new_key, 3)

    def test_challenge_is_nonzero_in_both_stages(self):
        # The Y_i mismatch boundary is only meaningful when c != 0: with a
        # zero challenge the personal verification share drops out.
        self.assertNotEqual(self.old_stage.round_info.challenge, 0)
        self.assertNotEqual(self.new_stage.round_info.challenge, 0)
        self.assertNotEqual(self.old_Y_3, self.new_Y_3)

    def test_replacing_new_Y_i_with_old_value_round_trips_but_fails(self):
        tampered = dataclasses.replace(
            self.retained_receipt, Y_i=self.old_Y_3
        )
        # Every other field stays from the new round; the stale Y_i is still
        # a structurally legal group element, so codec work must succeed.
        blob = encode_signature_share_receipt(tampered)
        decoded = decode_signature_share_receipt(blob)
        self.assertEqual(decoded, tampered)
        self.assertEqual(encode_signature_share_receipt(decoded), blob)
        self.assertIs(verify_signature_share_receipt(decoded), False)
        self.assertFalse(share_equation_holds(decoded))
        # The untouched new receipt is unaffected.
        self.assertIs(
            verify_signature_share_receipt(self.retained_receipt), True
        )

    def test_new_round_share_handed_to_old_key_raises_value_error(self):
        share = next(
            share
            for share in self.new_stage.shares
            if share.signer_id == 3
        )
        with self.assertRaises(ValueError):
            create_signature_share_receipt(
                self.new_stage.message,
                share,
                self.new_stage.round_info,
                self.old_key,
            )

    def test_round_with_fewer_than_new_threshold_signers_raises(self):
        commitments = []
        for offset, signer_id in enumerate((42, 59)):
            commitment, _nonce = create_signing_nonce_commitment(
                signer_id,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
                randbelow=fixed_random(5 + 100 * offset + signer_id),
            )
            commitments.append(commitment)
        with self.assertRaises(ValueError):
            create_signing_round(
                self.new_stage.message,
                (42, 59),
                commitments,
                self.new_key,
            )

    def test_decode_non_bytes_raises_type_error(self):
        blob = encode_signature_share_receipt(self.retained_receipt)
        for bad in (blob.decode("latin-1"), bytearray(blob), None, 1234):
            with self.assertRaises(TypeError):
                decode_signature_share_receipt(bad)

    def test_trailing_bytes_raise_value_error(self):
        blob = encode_signature_share_receipt(self.retained_receipt)
        with self.assertRaises(ValueError):
            decode_signature_share_receipt(blob + b"\x00")
        with self.assertRaises(ValueError):
            decode_signature_share_receipt(blob + b"tail")


class FailureNonInterferenceTest(unittest.TestCase):
    """Rejected operations must not mutate keys, shares or saved receipts."""

    def setUp(self):
        self.scenario = build_scenario()

    def snapshot(self):
        scenario = self.scenario
        return {
            "old_public": scenario.old_key.public_key,
            "new_public": scenario.new_key.public_key,
            "old_Y": tuple(scenario.old_key.verification_shares),
            "new_Y": tuple(scenario.new_key.verification_shares),
            "old_secret_3": secret_share_of(scenario.old_key, 3),
            "new_secret_3": secret_share_of(scenario.new_key, 3),
            "new_secret_42": secret_share_of(scenario.new_key, 42),
            "old_blobs": tuple(
                encode_signature_share_receipt(receipt)
                for receipt in scenario.old_stage.receipts
            ),
            "new_blobs": tuple(
                encode_signature_share_receipt(receipt)
                for receipt in scenario.new_stage.receipts
            ),
        }

    def assertInputsAndValidReceiptsIntact(self, before):
        scenario = self.scenario
        self.assertEqual(scenario.old_key.public_key, before["old_public"])
        self.assertEqual(scenario.new_key.public_key, before["new_public"])
        self.assertEqual(
            tuple(scenario.old_key.verification_shares), before["old_Y"]
        )
        self.assertEqual(
            tuple(scenario.new_key.verification_shares), before["new_Y"]
        )
        self.assertEqual(
            secret_share_of(scenario.old_key, 3), before["old_secret_3"]
        )
        self.assertEqual(
            secret_share_of(scenario.new_key, 3), before["new_secret_3"]
        )
        self.assertEqual(
            secret_share_of(scenario.new_key, 42), before["new_secret_42"]
        )
        for stage_name, blobs in (
            ("old", before["old_blobs"]),
            ("new", before["new_blobs"]),
        ):
            stage = (
                scenario.old_stage if stage_name == "old"
                else scenario.new_stage
            )
            self.assertEqual(
                tuple(
                    encode_signature_share_receipt(receipt)
                    for receipt in stage.receipts
                ),
                blobs,
            )
            for blob in blobs:
                self.assertIs(
                    verify_signature_share_receipt(
                        decode_signature_share_receipt(blob)
                    ),
                    True,
                )

    def test_all_failures_leave_everything_intact(self):
        scenario = self.scenario
        before = self.snapshot()

        # 1. Stale personal verification share on a new-round receipt.
        old_Y_3 = verification_share_of(scenario.old_key, 3)
        retained_receipt = next(
            receipt
            for receipt in scenario.new_stage.receipts
            if receipt.signer_id == 3
        )
        tampered = dataclasses.replace(retained_receipt, Y_i=old_Y_3)
        tampered_blob = encode_signature_share_receipt(tampered)
        self.assertFalse(
            verify_signature_share_receipt(
                decode_signature_share_receipt(tampered_blob)
            )
        )
        self.assertInputsAndValidReceiptsIntact(before)

        # 2. A new-round share presented to the old key.
        share_3 = next(
            share
            for share in scenario.new_stage.shares
            if share.signer_id == 3
        )
        with self.assertRaises(ValueError):
            create_signature_share_receipt(
                scenario.new_stage.message,
                share_3,
                scenario.new_stage.round_info,
                scenario.old_key,
            )
        self.assertInputsAndValidReceiptsIntact(before)

        # 3. Fewer than the new threshold of new members.
        commitments = [
            create_signing_nonce_commitment(
                signer_id,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
                randbelow=fixed_random(5 + 100 * offset + signer_id),
            )[0]
            for offset, signer_id in enumerate((42, 59))
        ]
        with self.assertRaises(ValueError):
            create_signing_round(
                scenario.new_stage.message,
                (42, 59),
                commitments,
                scenario.new_key,
            )
        self.assertInputsAndValidReceiptsIntact(before)

        # 4. Decoder type and trailing-byte failures.
        valid_blob = before["new_blobs"][0]
        for bad in ("not bytes", bytearray(valid_blob), None):
            with self.assertRaises(TypeError):
                decode_signature_share_receipt(bad)
        for tail in (b"\x00", b"tail"):
            with self.assertRaises(ValueError):
                decode_signature_share_receipt(valid_blob + tail)
        self.assertInputsAndValidReceiptsIntact(before)


class ScenarioDeterminismTest(unittest.TestCase):
    def test_public_data_is_reproducible(self):
        first = build_scenario()
        second = build_scenario()
        self.assertEqual(first.old_key.public_key, second.old_key.public_key)
        self.assertEqual(first.new_key.public_key, second.new_key.public_key)
        self.assertEqual(
            tuple(first.old_key.verification_shares),
            tuple(second.old_key.verification_shares),
        )
        self.assertEqual(
            tuple(first.new_key.verification_shares),
            tuple(second.new_key.verification_shares),
        )
        for stage_a, stage_b in (
            (first.old_stage, second.old_stage),
            (first.new_stage, second.new_stage),
        ):
            self.assertEqual(
                tuple(
                    encode_signature_share_receipt(receipt)
                    for receipt in stage_a.receipts
                ),
                tuple(
                    encode_signature_share_receipt(receipt)
                    for receipt in stage_b.receipts
                ),
            )
            self.assertEqual(stage_a.signature, stage_b.signature)


if __name__ == "__main__":
    unittest.main()
