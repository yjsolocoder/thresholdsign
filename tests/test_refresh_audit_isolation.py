"""Regression tests: audit isolation across a proactive share refresh.

A refresh with unchanged members and threshold keeps the joint public key
but re-randomises every secret share and verification share. These tests
pin the combined behaviour of the public entries (create_signing_contribution,
aggregate_signing_dkg, create_refresh, refresh, the two signing rounds,
create_audit, check_audit, find_nonce_reuse and recover_leaks): audit
records must be analysed against the verification shares of their own
stage, a refresh never revokes historical signatures, and a legitimate
all-zero increment changes nothing. Every expectation is recomputed from
public data with plain finite-field and group operations; no private
library helper is consulted.
"""

import unittest

from thresholdsign import (
    SigningDKGResult,
    SigningNonceCommitment,
    aggregate_signature,
    aggregate_signing_dkg,
    check_audit,
    create_audit,
    create_refresh,
    create_signature_share,
    create_signing_contribution,
    create_signing_round,
    find_nonce_reuse,
    reconstruct_secret,
    recover_leaks,
    refresh,
    schnorr_challenge,
    verify_signature,
)

# Same toy group as the signing and refresh tests: 8069 = 4 * 2017 + 1 is
# prime and 16, 256 = 16 ** 2 generate the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

PARTICIPANTS = (1, 2, 3)
THRESHOLD = 2
SIGNERS = (1, 3)
REUSING_SIGNER = 1
OTHER_SIGNER = 3

PRE_MESSAGES = (b"pre-refresh audited message one", b"pre-refresh audited message two")
POST_MESSAGES = (b"post-refresh audited message one", b"post-refresh audited message two")

# The reusing signer republishes one nonce per stage; every other nonce in
# the fixture is used exactly once across all four rounds.
PRE_REUSED_NONCE = 777
POST_REUSED_NONCE = 888
OTHER_NONCES = (1001, 1002, 1003, 1004)

AUDIT_TAG = b"thresholdsign/audit/v1"


def fixed_random(seed=1):
    """Deterministic stand-in for secrets.randbelow (same LCG as signing tests)."""
    state = {"value": seed}

    def randbelow(upper: int) -> int:
        state["value"] = (
            state["value"] * 6364136223846793005 + 1442695040888963407
        ) % upper
        return state["value"]

    return randbelow


def make_key():
    contributions = [
        create_signing_contribution(
            pid,
            PARTICIPANTS,
            THRESHOLD,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            blinding_generator=BLINDING_GENERATOR,
            randbelow=fixed_random(pid),
        )
        for pid in PARTICIPANTS
    ]
    outcome = aggregate_signing_dkg(contributions)
    assert isinstance(outcome, SigningDKGResult), outcome
    return outcome


def lagrange_weight(signer_id, signer_ids):
    """The signer's Lagrange weight at zero, recomputed over GF(FIELD_PRIME)."""
    numerator, denominator = 1, 1
    for other in signer_ids:
        if other != signer_id:
            numerator = numerator * other % FIELD_PRIME
            denominator = denominator * (other - signer_id) % FIELD_PRIME
    return numerator * pow(denominator, -1, FIELD_PRIME) % FIELD_PRIME


def parse_audit(payload):
    """Independently decode the public audit payload format of create_audit."""
    assert payload.startswith(AUDIT_TAG)
    length = (GROUP_PRIME.bit_length() + 7) // 8
    offset = len(AUDIT_TAG)

    def take(count):
        nonlocal offset
        chunk = payload[offset:offset + count]
        assert len(chunk) == count
        offset += count
        return chunk

    digest = take(32)
    public_key = int.from_bytes(take(length), "big")
    R = int.from_bytes(take(length), "big")
    challenge = int.from_bytes(take(length), "big")
    row_count = int.from_bytes(take(4), "big")
    rows = [
        tuple(int.from_bytes(take(length), "big") for _ in range(3))
        for _ in range(row_count)
    ]
    status = take(1)[0]
    present = take(1)[0]
    z = int.from_bytes(take(length), "big") if present else None
    assert offset == len(payload)
    return digest, public_key, R, challenge, rows, status, z


def secret_share_of(key, signer_id):
    return key.result.shares[key.result.participant_ids.index(signer_id)].y


def verification_share_of(key, signer_id):
    return key.verification_shares[key.result.participant_ids.index(signer_id)]


class Stage:
    """One stage's signing rounds, audit records and aggregate signatures."""

    def __init__(self, key, messages, reused_nonce, other_nonces):
        self.key = key
        self.records = []
        self.rounds = []
        self.shares = []
        self.signatures = []
        for message, other_nonce in zip(messages, other_nonces):
            nonces = {REUSING_SIGNER: reused_nonce, OTHER_SIGNER: other_nonce}
            commitments = [
                SigningNonceCommitment(pid, pow(GENERATOR, nonces[pid], GROUP_PRIME))
                for pid in SIGNERS
            ]
            round_info = create_signing_round(message, SIGNERS, commitments, key)
            shares = [
                create_signature_share(
                    pid, secret_share_of(key, pid), nonces[pid], round_info, key
                )
                for pid in SIGNERS
            ]
            signature = aggregate_signature(shares, round_info, key)
            self.rounds.append(round_info)
            self.shares.append(shares)
            self.signatures.append(signature)
            self.records.append((message, create_audit(message, shares, round_info, key)))


class Fixture:
    """Pre/post-refresh keys plus one two-record audit stage for each."""

    def __init__(self):
        self.old_key = make_key()
        contributions = [
            create_refresh(pid, self.old_key, randbelow=fixed_random(pid + 100))
            for pid in PARTICIPANTS
        ]
        self.new_key = refresh(contributions, self.old_key)
        assert isinstance(self.new_key, SigningDKGResult), self.new_key
        self.pre = Stage(self.old_key, PRE_MESSAGES, PRE_REUSED_NONCE, OTHER_NONCES[:2])
        self.post = Stage(self.new_key, POST_MESSAGES, POST_REUSED_NONCE, OTHER_NONCES[2:])


class RefreshSampleTest(unittest.TestCase):
    """The chosen sample must actually exercise the refresh."""

    def setUp(self):
        self.fx = Fixture()

    def test_secret_shares_changed_for_every_participant(self):
        old_shares = [share.y for share in self.fx.old_key.result.shares]
        new_shares = [share.y for share in self.fx.new_key.result.shares]
        for old_y, new_y in zip(old_shares, new_shares):
            self.assertNotEqual(old_y, new_y)
        # In particular the reusing signer's share changed.
        self.assertNotEqual(
            secret_share_of(self.fx.old_key, REUSING_SIGNER),
            secret_share_of(self.fx.new_key, REUSING_SIGNER),
        )

    def test_joint_public_key_and_secret_are_unchanged(self):
        self.assertEqual(self.fx.new_key.public_key, self.fx.old_key.public_key)
        self.assertEqual(
            reconstruct_secret(self.fx.new_key.result.shares[:THRESHOLD], prime=FIELD_PRIME),
            reconstruct_secret(self.fx.old_key.result.shares[:THRESHOLD], prime=FIELD_PRIME),
        )

    def test_verification_shares_changed_and_match_new_shares(self):
        self.assertNotEqual(
            list(self.fx.new_key.verification_shares),
            list(self.fx.old_key.verification_shares),
        )
        for share, Y_i in zip(
            self.fx.new_key.result.shares, self.fx.new_key.verification_shares
        ):
            self.assertEqual(pow(GENERATOR, share.y, GROUP_PRIME), Y_i)

    def test_other_signer_nonces_never_repeat(self):
        self.assertEqual(len(set(OTHER_NONCES)), len(OTHER_NONCES))
        self.assertNotIn(PRE_REUSED_NONCE, OTHER_NONCES)
        self.assertNotIn(POST_REUSED_NONCE, OTHER_NONCES)

    def test_challenges_nonzero_and_weight_products_differ(self):
        for stage in (self.fx.pre, self.fx.post):
            products = []
            for (message, receipt), round_info in zip(stage.records, stage.rounds):
                digest, Y, R, challenge, rows, status, z = parse_audit(receipt.payload)
                # The header agrees with the round and recomputes from public data.
                self.assertEqual(status, 1)
                self.assertEqual(Y, stage.key.public_key)
                self.assertEqual(R, round_info.R)
                self.assertEqual(challenge, round_info.challenge)
                self.assertEqual(
                    challenge,
                    schnorr_challenge(
                        message,
                        stage.key.public_key,
                        R,
                        SIGNERS,
                        field_prime=FIELD_PRIME,
                        group_prime=GROUP_PRIME,
                    ),
                )
                self.assertNotEqual(challenge, 0)
                products.append(
                    challenge * lagrange_weight(REUSING_SIGNER, SIGNERS) % FIELD_PRIME
                )
            # Recovery needs two distinct c * lambda_i coefficients per stage.
            self.assertNotEqual(products[0], products[1])


class SignatureSurvivesRefreshTest(unittest.TestCase):
    def setUp(self):
        self.fx = Fixture()

    def test_both_stages_signatures_verify_under_one_public_key(self):
        public_key = self.fx.old_key.public_key
        self.assertEqual(self.fx.new_key.public_key, public_key)
        for stage, messages in (
            (self.fx.pre, PRE_MESSAGES),
            (self.fx.post, POST_MESSAGES),
        ):
            for message, signature in zip(messages, stage.signatures):
                self.assertTrue(
                    verify_signature(
                        message,
                        signature,
                        public_key,
                        prime=FIELD_PRIME,
                        group_prime=GROUP_PRIME,
                        generator=GENERATOR,
                    )
                )
                # Independently: g ** z == R * Y ** c (mod group_prime).
                challenge = schnorr_challenge(
                    message,
                    public_key,
                    signature.R,
                    signature.signer_ids,
                    field_prime=FIELD_PRIME,
                    group_prime=GROUP_PRIME,
                )
                self.assertEqual(
                    pow(GENERATOR, signature.z, GROUP_PRIME),
                    signature.R * pow(public_key, challenge, GROUP_PRIME) % GROUP_PRIME,
                )


class StageReuseAnalysisTest(unittest.TestCase):
    def setUp(self):
        self.fx = Fixture()

    def test_find_reports_only_the_reusing_signer(self):
        for stage, reused_nonce in (
            (self.fx.pre, PRE_REUSED_NONCE),
            (self.fx.post, POST_REUSED_NONCE),
        ):
            findings = find_nonce_reuse(stage.records, stage.key)
            self.assertEqual(len(findings), 1)
            finding = findings[0]
            self.assertEqual(finding.signer_id, REUSING_SIGNER)
            self.assertEqual(
                finding.nonce_commitment, pow(GENERATOR, reused_nonce, GROUP_PRIME)
            )
            self.assertEqual(
                finding.receipts,
                tuple(sorted((record[1] for record in stage.records), key=lambda a: a.payload)),
            )

    def test_recover_yields_each_stages_own_share(self):
        leaks_pre = recover_leaks(self.fx.pre.records, self.fx.old_key)
        leaks_post = recover_leaks(self.fx.post.records, self.fx.new_key)
        self.assertEqual(len(leaks_pre), 1)
        self.assertEqual(len(leaks_post), 1)
        # Each leak is the stage's actual secret share of the reusing signer.
        self.assertEqual(leaks_pre[0].share, secret_share_of(self.fx.old_key, REUSING_SIGNER))
        self.assertEqual(leaks_post[0].share, secret_share_of(self.fx.new_key, REUSING_SIGNER))
        # The two stages recover different values...
        self.assertNotEqual(leaks_pre[0].share, leaks_post[0].share)
        # ...and each satisfies its own stage's public verification share.
        self.assertEqual(
            pow(GENERATOR, leaks_pre[0].share, GROUP_PRIME),
            verification_share_of(self.fx.old_key, REUSING_SIGNER),
        )
        self.assertEqual(
            pow(GENERATOR, leaks_post[0].share, GROUP_PRIME),
            verification_share_of(self.fx.new_key, REUSING_SIGNER),
        )

    def test_recovery_recomputed_independently_from_public_rows(self):
        for stage in (self.fx.pre, self.fx.post):
            leak = recover_leaks(stage.records, stage.key)[0]
            weight = lagrange_weight(REUSING_SIGNER, SIGNERS)
            coefficients = []
            responses = []
            for _message, receipt in stage.records:
                _digest, _Y, _R, challenge, rows, status, _z = parse_audit(receipt.payload)
                self.assertEqual(status, 1)
                row = next(row for row in rows if row[0] == REUSING_SIGNER)
                coefficients.append(challenge * weight % FIELD_PRIME)
                responses.append(row[2])
            self.assertNotEqual(coefficients[0], coefficients[1])
            share = (
                (responses[0] - responses[1])
                * pow(coefficients[0] - coefficients[1], -1, FIELD_PRIME)
                % FIELD_PRIME
            )
            self.assertEqual(leak.share, share)
            self.assertEqual(
                pow(GENERATOR, share, GROUP_PRIME),
                verification_share_of(stage.key, REUSING_SIGNER),
            )

    def test_order_and_duplicates_do_not_change_the_report(self):
        for stage in (self.fx.pre, self.fx.post):
            reference_find = find_nonce_reuse(stage.records, stage.key)
            reference_leaks = recover_leaks(stage.records, stage.key)
            shuffled = [stage.records[1], stage.records[0]]
            duplicated = [stage.records[1], stage.records[0], stage.records[1]]
            self.assertEqual(find_nonce_reuse(shuffled, stage.key), reference_find)
            self.assertEqual(find_nonce_reuse(duplicated, stage.key), reference_find)
            self.assertEqual(recover_leaks(shuffled, stage.key), reference_leaks)
            self.assertEqual(recover_leaks(duplicated, stage.key), reference_leaks)

    def test_single_record_calls_return_empty(self):
        for stage in (self.fx.pre, self.fx.post):
            for record in stage.records:
                self.assertEqual(find_nonce_reuse([record], stage.key), ())
                self.assertEqual(recover_leaks([record], stage.key), ())


class CrossStageIsolationTest(unittest.TestCase):
    def setUp(self):
        self.fx = Fixture()

    def test_records_verify_only_under_their_own_stage_key(self):
        for message, receipt in self.fx.pre.records:
            self.assertTrue(check_audit(message, receipt, self.fx.old_key))
            self.assertFalse(check_audit(message, receipt, self.fx.new_key))
        for message, receipt in self.fx.post.records:
            self.assertTrue(check_audit(message, receipt, self.fx.new_key))
            self.assertFalse(check_audit(message, receipt, self.fx.old_key))

    def test_mixed_stage_batch_raises_value_error(self):
        mixed = [self.fx.pre.records[0], self.fx.post.records[0]]
        for key in (self.fx.old_key, self.fx.new_key):
            with self.assertRaises(ValueError):
                find_nonce_reuse(mixed, key)
            with self.assertRaises(ValueError):
                recover_leaks(mixed, key)

    def test_replaced_message_raises_value_error(self):
        for stage in (self.fx.pre, self.fx.post):
            message, receipt = stage.records[0]
            replaced = [(b"replaced message", receipt)]
            with self.assertRaises(ValueError):
                find_nonce_reuse(replaced, stage.key)
            with self.assertRaises(ValueError):
                recover_leaks(replaced, stage.key)

    def test_string_message_raises_type_error(self):
        for stage in (self.fx.pre, self.fx.post):
            _message, receipt = stage.records[0]
            with self.assertRaises(TypeError):
                find_nonce_reuse([("not bytes", receipt)], stage.key)
            with self.assertRaises(TypeError):
                recover_leaks([("not bytes", receipt)], stage.key)

    def test_failed_calls_leave_original_records_usable(self):
        expected_find_pre = find_nonce_reuse(self.fx.pre.records, self.fx.old_key)
        expected_leaks_pre = recover_leaks(self.fx.pre.records, self.fx.old_key)
        expected_find_post = find_nonce_reuse(self.fx.post.records, self.fx.new_key)
        expected_leaks_post = recover_leaks(self.fx.post.records, self.fx.new_key)
        # A batch of failing calls, none of which may disturb later analysis.
        for key in (self.fx.old_key, self.fx.new_key):
            with self.assertRaises(ValueError):
                find_nonce_reuse(
                    [self.fx.pre.records[0], self.fx.post.records[0]], key
                )
            with self.assertRaises(ValueError):
                recover_leaks([(b"replaced message", self.fx.pre.records[0][1])], key)
            with self.assertRaises(TypeError):
                find_nonce_reuse([("not bytes", self.fx.post.records[0][1])], key)
        self.assertEqual(
            find_nonce_reuse(self.fx.pre.records, self.fx.old_key), expected_find_pre
        )
        self.assertEqual(
            recover_leaks(self.fx.pre.records, self.fx.old_key), expected_leaks_pre
        )
        self.assertEqual(
            find_nonce_reuse(self.fx.post.records, self.fx.new_key), expected_find_post
        )
        self.assertEqual(
            recover_leaks(self.fx.post.records, self.fx.new_key), expected_leaks_post
        )


class ZeroIncrementRefreshTest(unittest.TestCase):
    """A legitimate refresh whose increments are all zero changes nothing."""

    def setUp(self):
        self.key = make_key()
        contributions = [
            create_refresh(pid, self.key, randbelow=lambda upper: 0)
            for pid in PARTICIPANTS
        ]
        self.zero_key = refresh(contributions, self.key)
        assert isinstance(self.zero_key, SigningDKGResult), self.zero_key
        self.stage = Stage(self.key, PRE_MESSAGES, PRE_REUSED_NONCE, OTHER_NONCES[:2])

    def test_shares_and_verification_shares_are_unchanged(self):
        self.assertEqual(
            [share.y for share in self.zero_key.result.shares],
            [share.y for share in self.key.result.shares],
        )
        self.assertEqual(
            list(self.zero_key.verification_shares),
            list(self.key.verification_shares),
        )
        self.assertEqual(self.zero_key.public_key, self.key.public_key)

    def test_old_audit_records_still_verify(self):
        for message, receipt in self.stage.records:
            self.assertTrue(check_audit(message, receipt, self.key))
            self.assertTrue(check_audit(message, receipt, self.zero_key))

    def test_reuse_analysis_is_identical(self):
        self.assertEqual(
            find_nonce_reuse(self.stage.records, self.zero_key),
            find_nonce_reuse(self.stage.records, self.key),
        )
        leaks = recover_leaks(self.stage.records, self.zero_key)
        self.assertEqual(leaks, recover_leaks(self.stage.records, self.key))
        self.assertEqual(len(leaks), 1)
        self.assertEqual(leaks[0].share, secret_share_of(self.key, REUSING_SIGNER))
        self.assertEqual(
            pow(GENERATOR, leaks[0].share, GROUP_PRIME),
            verification_share_of(self.zero_key, REUSING_SIGNER),
        )


if __name__ == "__main__":
    unittest.main()
