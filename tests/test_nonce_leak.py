"""Tests for leaked-share recovery: NonceLeak / recover_leaks."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    NonceLeak,
    SigningAudit,
    SigningNonceCommitment,
    aggregate_signing_dkg,
    create_audit,
    create_signature_share,
    create_signing_contribution,
    create_signing_nonce_commitment,
    create_signing_round,
    find_nonce_reuse,
    recover_leaks,
    schnorr_challenge,
)

# Same toy group as the nonce-reuse tests: 8069 = 4 * 2017 + 1 is prime,
# 16 and 256 = 16 ** 2 are distinct generators of the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

MESSAGE_A = b"first audited message"
MESSAGE_B = b"second audited message"
MESSAGE_C = b"third audited message"
MESSAGE_D = b"fourth audited message"


def fixed_random(seed=1):
    """Deterministic stand-in for secrets.randbelow (same LCG as DKG tests)."""
    state = {"value": seed}

    def randbelow(upper: int) -> int:
        state["value"] = (
            state["value"] * 6364136223846793005 + 1442695040888963407
        ) % upper
        return state["value"]

    return randbelow


def make_key(participant_ids=(1, 2, 3), threshold=2):
    contributions = [
        create_signing_contribution(
            pid,
            participant_ids,
            threshold,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            blinding_generator=BLINDING_GENERATOR,
            randbelow=fixed_random(pid),
        )
        for pid in participant_ids
    ]
    return aggregate_signing_dkg(contributions)


def make_round(key, message, signer_ids=(1, 3), seed=100, nonces=None):
    """Build a full signing round; ``nonces`` pins explicit per-signer nonces."""
    commitments = []
    nonce_map = {}
    for index, pid in enumerate(signer_ids):
        if nonces is not None and pid in nonces:
            nonce = nonces[pid]
            commitment = SigningNonceCommitment(
                pid, pow(GENERATOR, nonce, GROUP_PRIME)
            )
        else:
            commitment, nonce = create_signing_nonce_commitment(
                pid,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
                randbelow=fixed_random(seed + index),
            )
        commitments.append(commitment)
        nonce_map[pid] = nonce
    round_info = create_signing_round(message, signer_ids, commitments, key)
    shares = [
        create_signature_share(
            pid,
            key.result.shares[key.result.participant_ids.index(pid)].y,
            nonce_map[pid],
            round_info,
            key,
        )
        for pid in signer_ids
    ]
    return round_info, shares


def make_record(key, message, signer_ids=(1, 3), seed=100, nonces=None):
    round_info, shares = make_round(key, message, signer_ids, seed, nonces)
    return message, create_audit(message, shares, round_info, key)


def challenge_for(key, message, nonces, signer_ids=(1, 3)):
    """Recompute a round challenge without building the round itself."""
    aggregate_R = 1
    for pid in signer_ids:
        aggregate_R = aggregate_R * pow(GENERATOR, nonces[pid], GROUP_PRIME) % GROUP_PRIME
    return schnorr_challenge(
        message,
        key.public_key,
        aggregate_R,
        signer_ids,
        field_prime=FIELD_PRIME,
        group_prime=GROUP_PRIME,
    )


def find_challenge_collision(key, nonces, signer_ids=(1, 3)):
    """Two distinct messages with equal Fiat-Shamir challenges (birthday over q)."""
    seen = {}
    for index in range(10000):
        message = f"collision candidate {index}".encode()
        challenge = challenge_for(key, message, nonces, signer_ids)
        if challenge in seen:
            return seen[challenge], message, challenge
        seen[challenge] = message
    raise AssertionError("no challenge collision found")


class NonceLeakTest(unittest.TestCase):
    def test_frozen_fields_value_equality(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(NonceLeak)],
            ["signer_id", "commitment", "share", "receipts"],
        )
        receipts = (SigningAudit(b"a"), SigningAudit(b"b"))
        leak = NonceLeak(1, 42, 7, receipts)  # positional construction
        self.assertEqual(leak, NonceLeak(1, 42, 7, receipts))
        self.assertEqual(
            leak,
            NonceLeak(signer_id=1, commitment=42, share=7, receipts=receipts),
        )
        self.assertNotEqual(leak, NonceLeak(2, 42, 7, receipts))
        self.assertNotEqual(leak, NonceLeak(1, 43, 7, receipts))
        self.assertNotEqual(leak, NonceLeak(1, 42, 8, receipts))
        self.assertNotEqual(leak, NonceLeak(1, 42, 7, (SigningAudit(b"a"),)))
        self.assertEqual(hash(leak), hash(NonceLeak(1, 42, 7, receipts)))
        with self.assertRaises(FrozenInstanceError):
            leak.signer_id = 2


class RecoverLeaksTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.share_1 = self.key.result.shares[
            self.key.result.participant_ids.index(1)
        ].y
        self.share_3 = self.key.result.shares[
            self.key.result.participant_ids.index(3)
        ].y

    def test_no_reuse_recovers_nothing(self):
        records = [
            make_record(self.key, MESSAGE_A, seed=100),
            make_record(self.key, MESSAGE_B, seed=200),
        ]
        self.assertEqual(recover_leaks(records, self.key), ())

    def test_empty_records(self):
        self.assertEqual(recover_leaks([], self.key), ())
        self.assertEqual(recover_leaks((), self.key), ())

    def test_recovered_share_matches_the_real_secret_share(self):
        record_a = make_record(self.key, MESSAGE_A, nonces={1: 777})
        record_b = make_record(self.key, MESSAGE_B, seed=200, nonces={1: 777})
        leaks = recover_leaks([record_a, record_b], self.key)
        self.assertEqual(len(leaks), 1)
        leak = leaks[0]
        self.assertIsInstance(leak, NonceLeak)
        self.assertEqual(leak.signer_id, 1)
        self.assertEqual(leak.commitment, pow(GENERATOR, 777, GROUP_PRIME))
        self.assertEqual(leak.share, self.share_1)
        # The recovered value is publicly checked against Y_i.
        self.assertEqual(
            pow(GENERATOR, leak.share, GROUP_PRIME),
            self.key.verification_shares[
                self.key.result.participant_ids.index(1)
            ],
        )

    def test_receipts_are_the_two_used_sorted_by_payload(self):
        record_a = make_record(self.key, MESSAGE_A, nonces={1: 555})
        record_b = make_record(self.key, MESSAGE_B, seed=200, nonces={1: 555})
        leaks = recover_leaks([record_b, record_a], self.key)
        self.assertEqual(len(leaks), 1)
        expected = tuple(
            sorted((record_a[1], record_b[1]), key=lambda receipt: receipt.payload)
        )
        self.assertEqual(leaks[0].receipts, expected)
        self.assertEqual(len(leaks[0].receipts), 2)

    def test_recovery_works_with_differing_signer_sets(self):
        # The Lagrange weight differs between the rounds, so the recovery
        # must take each receipt's own signer set into account.
        record_a = make_record(self.key, MESSAGE_A, (1, 3), nonces={1: 777})
        record_b = make_record(
            self.key, MESSAGE_B, (1, 2), seed=200, nonces={1: 777}
        )
        leaks = recover_leaks([record_a, record_b], self.key)
        self.assertEqual(len(leaks), 1)
        self.assertEqual(leaks[0].share, self.share_1)

    def test_payload_smallest_invertible_pair_is_used(self):
        fixed_nonces = {1: 777, 3: 313}
        message_one, message_two, challenge = find_challenge_collision(
            self.key, fixed_nonces
        )
        self.assertNotEqual(message_one, message_two)
        # Same signer set and equal challenges -> equal a values.
        record_one = make_record(
            self.key, message_one, (1, 3), nonces=fixed_nonces
        )
        record_two = make_record(
            self.key, message_two, (1, 3), nonces=fixed_nonces
        )
        # A third receipt over a different signer set has a different weight,
        # hence a different a; search until its payload sorts last, so the
        # skipped equal pair is exactly the payload-smallest one.
        pair_small = min(record_one[1].payload, record_two[1].payload)
        pair_large = max(record_one[1].payload, record_two[1].payload)
        record_three = None
        for index in range(1000):
            candidate = make_record(
                self.key,
                f"third receipt {index}".encode(),
                (1, 2),
                seed=500 + index,
                nonces={1: 777},
            )
            if candidate[1].payload > pair_large:
                record_three = candidate
                break
        self.assertIsNotNone(record_three)

        leaks = recover_leaks(
            [record_three, record_two, record_one], self.key
        )
        self.assertEqual(len(leaks), 1)
        leak = leaks[0]
        self.assertEqual(leak.share, self.share_1)
        # The (smallest, middle) pair shares its a value and is skipped; the
        # recovery uses the payload-smallest receipt together with the third.
        self.assertEqual(
            [receipt.payload for receipt in leak.receipts],
            [pair_small, record_three[1].payload],
        )

    def test_group_without_invertible_pair_is_ignored(self):
        fixed_nonces = {1: 777, 3: 313}
        message_one, message_two, challenge = find_challenge_collision(
            self.key, fixed_nonces
        )
        record_one = make_record(
            self.key, message_one, (1, 3), nonces=fixed_nonces
        )
        record_two = make_record(
            self.key, message_two, (1, 3), nonces=fixed_nonces
        )
        # The reuse audit reports both signers' groups, but equal challenges
        # over the same signer set give a1 == a2: no invertible pair, no
        # leak for either of them.
        self.assertEqual(
            len(find_nonce_reuse([record_one, record_two], self.key)), 2
        )
        self.assertEqual(recover_leaks([record_one, record_two], self.key), ())

    def test_one_leak_per_group_even_with_many_receipts(self):
        records = [
            make_record(self.key, MESSAGE_A, seed=100, nonces={1: 777}),
            make_record(self.key, MESSAGE_B, seed=200, nonces={1: 777}),
            make_record(self.key, MESSAGE_C, seed=300, nonces={1: 777}),
        ]
        leaks = recover_leaks(records, self.key)
        self.assertEqual(len(leaks), 1)
        self.assertEqual(leaks[0].share, self.share_1)

    def test_multiple_leaks_sorted_by_signer_id_then_commitment(self):
        record_a = make_record(
            self.key, MESSAGE_A, seed=100, nonces={1: 111, 3: 222}
        )
        record_b = make_record(
            self.key, MESSAGE_B, seed=200, nonces={1: 111, 3: 222}
        )
        leaks = recover_leaks([record_b, record_a], self.key)
        self.assertEqual(
            [(leak.signer_id, leak.commitment) for leak in leaks],
            [
                (1, pow(GENERATOR, 111, GROUP_PRIME)),
                (3, pow(GENERATOR, 222, GROUP_PRIME)),
            ],
        )
        shares = dict(zip(self.key.result.participant_ids,
                          (share.y for share in self.key.result.shares)))
        self.assertEqual(leaks[0].share, shares[1])
        self.assertEqual(leaks[1].share, shares[3])

    def test_same_receipt_twice_yields_nothing(self):
        record = make_record(self.key, MESSAGE_A, nonces={1: 777})
        self.assertEqual(recover_leaks([record, record], self.key), ())

    def test_non_invertible_group_alongside_recoverable_one(self):
        # Signer 3's group cannot be inverted (equal challenges, same set),
        # signer 1's group can: only signer 1 is reported.
        fixed_nonces = {1: 414, 3: 313}
        message_one, message_two, _challenge = find_challenge_collision(
            self.key, fixed_nonces
        )
        colliding_one = make_record(
            self.key, message_one, (1, 3), nonces=fixed_nonces
        )
        colliding_two = make_record(
            self.key, message_two, (1, 3), nonces=fixed_nonces
        )
        # Two more receipts make signer 1's group span a different signer
        # set, while signer 3 stays inside the equal-challenge pair.
        record_c = make_record(
            self.key, MESSAGE_C, (1, 2), seed=300, nonces={1: 414}
        )
        record_d = make_record(
            self.key, MESSAGE_D, (1, 2), seed=400, nonces={1: 414}
        )
        leaks = recover_leaks(
            [colliding_one, colliding_two, record_c, record_d], self.key
        )
        self.assertEqual([leak.signer_id for leak in leaks], [1])
        self.assertEqual(leaks[0].share, self.share_1)

    def test_type_errors(self):
        record = make_record(self.key, MESSAGE_A)
        with self.assertRaises(TypeError):
            recover_leaks("records", self.key)
        with self.assertRaises(TypeError):
            recover_leaks(b"records", self.key)
        with self.assertRaises(TypeError):
            recover_leaks([MESSAGE_A], self.key)
        with self.assertRaises(TypeError):
            recover_leaks([(MESSAGE_A, record[1], record[1])], self.key)
        with self.assertRaises(TypeError):
            recover_leaks([("message", record[1])], self.key)
        with self.assertRaises(TypeError):
            recover_leaks([(MESSAGE_A, "receipt")], self.key)
        with self.assertRaises(TypeError):
            recover_leaks([record], "key")
        with self.assertRaises(TypeError):
            recover_leaks([record], None)

    def test_mismatched_message_raises_value_error(self):
        record = make_record(self.key, MESSAGE_A)
        with self.assertRaises(ValueError):
            recover_leaks([(MESSAGE_B, record[1])], self.key)

    def test_mismatched_key_raises_value_error(self):
        other_key = make_key(participant_ids=(1, 2, 4))
        record = make_record(self.key, MESSAGE_A)
        with self.assertRaises(ValueError):
            recover_leaks([record], other_key)

    def test_structurally_illegal_receipt_raises_value_error(self):
        record = make_record(self.key, MESSAGE_A)
        with self.assertRaises(ValueError):
            recover_leaks(
                [(MESSAGE_A, SigningAudit(record[1].payload[:-1]))], self.key
            )
        with self.assertRaises(ValueError):
            recover_leaks(
                [(MESSAGE_A, SigningAudit(b"wrong" + record[1].payload[5:]))],
                self.key,
            )


if __name__ == "__main__":
    unittest.main()
