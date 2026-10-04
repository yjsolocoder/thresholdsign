"""Regression tests: audit isolation across a proactive share refresh.

A proactive refresh (create_refresh / refresh) rerandomises the secret
shares while the joint public key stays put. These tests pin the combined
behaviour of the existing public entry points across that boundary, all
with reproducible deterministic inputs:

* each phase's audit records verify (check_audit) only against that
  phase's verification shares — old records fail under the refreshed key
  and vice versa, without the refresh revoking historical signatures;
* find_nonce_reuse / recover_leaks on one phase's records report only the
  reusing signer and recover that phase's secret share, and the two
  phases recover different values;
* mixed-phase record batches make both reuse-analysis entry points raise
  ValueError instead of returning partial findings;
* a legal refresh whose increments are all zero changes nothing: old
  records still verify and the reuse analysis is identical.

Every expectation is recomputed from public data (the audit payload bytes,
the verification shares and the group parameters) with independent finite
field and group operations; no private library helper is consulted.
"""

import unittest
from collections import namedtuple

from thresholdsign import (
    AggregateSignature,
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
    recover_leaks,
    refresh,
    verify_signature,
)

# Same toy group as the signing/audit/refresh tests: 8069 = 4 * 2017 + 1 is
# prime and 16, 256 = 16 ** 2 generate the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

PARTICIPANT_IDS = (1, 2, 3)
THRESHOLD = 2
SIGNER_IDS = (1, 3)
REUSING_SIGNER = 1

PRE_MESSAGE_A = b"pre-refresh audited message A"
PRE_MESSAGE_B = b"pre-refresh audited message B"
POST_MESSAGE_A = b"post-refresh audited message A"
POST_MESSAGE_B = b"post-refresh audited message B"

# The reusing signer republishes one nonce per phase across two messages;
# the honest signer's nonce is distinct in every round of both phases.
PRE_REUSED_NONCE = 777
POST_REUSED_NONCE = 888
PRE_NONCES_A = {1: PRE_REUSED_NONCE, 3: 901}
PRE_NONCES_B = {1: PRE_REUSED_NONCE, 3: 902}
POST_NONCES_A = {1: POST_REUSED_NONCE, 3: 903}
POST_NONCES_B = {1: POST_REUSED_NONCE, 3: 904}

AUDIT_TAG = b"thresholdsign/audit/v1"
L = (GROUP_PRIME.bit_length() + 7) // 8


def fixed_random(seed=1):
    """Deterministic stand-in for secrets.randbelow (same LCG as DKG tests)."""
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
            PARTICIPANT_IDS,
            THRESHOLD,
            prime=FIELD_PRIME,
            group_prime=GROUP_PRIME,
            generator=GENERATOR,
            blinding_generator=BLINDING_GENERATOR,
            randbelow=fixed_random(pid),
        )
        for pid in PARTICIPANT_IDS
    ]
    outcome = aggregate_signing_dkg(contributions)
    assert isinstance(outcome, SigningDKGResult), outcome
    return outcome


def make_refresh_contributions(key, seed_base=100):
    return [
        create_refresh(pid, key, randbelow=fixed_random(pid + seed_base))
        for pid in key.result.participant_ids
    ]


def make_zero_refresh_contributions(key):
    # Legal zero-secret contributions whose drawn coefficients are all zero,
    # so every share increment is zero as well.
    return [
        create_refresh(pid, key, randbelow=lambda upper: 0)
        for pid in key.result.participant_ids
    ]


def make_round(key, message, nonces):
    """Run both Schnorr rounds with explicitly pinned per-signer nonces."""
    commitments = [
        SigningNonceCommitment(pid, pow(GENERATOR, nonces[pid], GROUP_PRIME))
        for pid in SIGNER_IDS
    ]
    round_info = create_signing_round(message, SIGNER_IDS, commitments, key)
    shares = [
        create_signature_share(
            pid,
            key.result.shares[key.result.participant_ids.index(pid)].y,
            nonces[pid],
            round_info,
            key,
        )
        for pid in SIGNER_IDS
    ]
    return round_info, shares


def lagrange_weight(signer_id, signer_ids, prime):
    """Independent recomputation of the Lagrange weight at zero mod prime."""
    numerator = 1
    denominator = 1
    for other in signer_ids:
        if other == signer_id:
            continue
        numerator = numerator * (-other) % prime
        denominator = denominator * (signer_id - other) % prime
    return numerator * pow(denominator, -1, prime) % prime


ParsedAudit = namedtuple(
    "ParsedAudit",
    ["digest", "public_key", "R", "challenge", "rows", "status", "present", "z"],
)


def parse_audit_payload(payload):
    """Read the public audit payload layout with no library helper."""
    assert payload[: len(AUDIT_TAG)] == AUDIT_TAG
    offset = len(AUDIT_TAG)
    digest = payload[offset:offset + 32]
    offset += 32
    public_key = int.from_bytes(payload[offset:offset + L], "big")
    offset += L
    R = int.from_bytes(payload[offset:offset + L], "big")
    offset += L
    challenge = int.from_bytes(payload[offset:offset + L], "big")
    offset += L
    count = int.from_bytes(payload[offset:offset + 4], "big")
    offset += 4
    rows = []
    for _ in range(count):
        signer_id = int.from_bytes(payload[offset:offset + L], "big")
        r_i = int.from_bytes(payload[offset + L:offset + 2 * L], "big")
        z_i = int.from_bytes(payload[offset + 2 * L:offset + 3 * L], "big")
        rows.append((signer_id, r_i, z_i))
        offset += 3 * L
    status = payload[offset]
    present = payload[offset + 1]
    offset += 2
    z = int.from_bytes(payload[offset:offset + L], "big") if present else None
    return ParsedAudit(digest, public_key, R, challenge, rows, status, present, z)


def challenge_weight_product(record, signer_id):
    """The coefficient a = c * lambda_i mod q, from public payload bytes."""
    parsed = parse_audit_payload(record[1].payload)
    signer_ids = tuple(row[0] for row in parsed.rows)
    weight = lagrange_weight(signer_id, signer_ids, FIELD_PRIME)
    return parsed.challenge * weight % FIELD_PRIME


def recover_share_independently(record_first, record_second, signer_id):
    """Solve z_i = r_i + c * lambda_i * s_i for s_i from two public receipts."""
    parsed_first = parse_audit_payload(record_first[1].payload)
    parsed_second = parse_audit_payload(record_second[1].payload)
    a_first = challenge_weight_product(record_first, signer_id)
    a_second = challenge_weight_product(record_second, signer_id)
    z_first = next(row[2] for row in parsed_first.rows if row[0] == signer_id)
    z_second = next(row[2] for row in parsed_second.rows if row[0] == signer_id)
    return (
        (z_first - z_second)
        * pow(a_first - a_second, -1, FIELD_PRIME)
        % FIELD_PRIME
    )


def share_of(key, signer_id):
    return key.result.shares[key.result.participant_ids.index(signer_id)].y


def verification_share_of(key, signer_id):
    return key.verification_shares[key.result.participant_ids.index(signer_id)]


def scenario():
    """Build the full deterministic fixture once per test class setUp."""
    old_key = make_key()

    contributions = make_refresh_contributions(old_key)
    new_key = refresh(contributions, old_key)
    assert isinstance(new_key, SigningDKGResult), new_key

    zero_contributions = make_zero_refresh_contributions(old_key)
    zero_key = refresh(zero_contributions, old_key)
    assert isinstance(zero_key, SigningDKGResult), zero_key

    rounds = {}
    for label, key, message, nonces in (
        ("pre_a", old_key, PRE_MESSAGE_A, PRE_NONCES_A),
        ("pre_b", old_key, PRE_MESSAGE_B, PRE_NONCES_B),
        ("post_a", new_key, POST_MESSAGE_A, POST_NONCES_A),
        ("post_b", new_key, POST_MESSAGE_B, POST_NONCES_B),
    ):
        round_info, shares = make_round(key, message, nonces)
        record = (message, create_audit(message, shares, round_info, key))
        rounds[label] = (round_info, shares, record)

    return {
        "old_key": old_key,
        "new_key": new_key,
        "zero_key": zero_key,
        "zero_contributions": zero_contributions,
        "pre_record_a": rounds["pre_a"][2],
        "pre_record_b": rounds["pre_b"][2],
        "post_record_a": rounds["post_a"][2],
        "post_record_b": rounds["post_b"][2],
        "pre_round_a": rounds["pre_a"][0],
        "pre_round_b": rounds["pre_b"][0],
        "post_round_a": rounds["post_a"][0],
        "post_round_b": rounds["post_b"][0],
        "pre_shares_a": rounds["pre_a"][1],
        "post_shares_a": rounds["post_a"][1],
    }


class ScenarioFixtureTest(unittest.TestCase):
    """The chosen sample: shares really change, challenges are non-zero."""

    def setUp(self):
        self.data = scenario()

    def test_refresh_keeps_membership_threshold_and_public_key(self):
        old_key = self.data["old_key"]
        new_key = self.data["new_key"]
        self.assertEqual(new_key.result.participant_ids, PARTICIPANT_IDS)
        self.assertEqual(
            len(new_key.result.commitment.values),
            len(old_key.result.commitment.values),
        )
        self.assertEqual(new_key.public_key, old_key.public_key)

    def test_reusing_signers_share_and_verification_share_changed(self):
        old_key = self.data["old_key"]
        new_key = self.data["new_key"]
        old_share = share_of(old_key, REUSING_SIGNER)
        new_share = share_of(new_key, REUSING_SIGNER)
        self.assertNotEqual(new_share, old_share)
        self.assertNotEqual(
            verification_share_of(new_key, REUSING_SIGNER),
            verification_share_of(old_key, REUSING_SIGNER),
        )
        # Independent group check: each phase's verification share is the
        # discrete-log commitment to that phase's secret share.
        self.assertEqual(
            pow(GENERATOR, old_share, GROUP_PRIME),
            verification_share_of(old_key, REUSING_SIGNER),
        )
        self.assertEqual(
            pow(GENERATOR, new_share, GROUP_PRIME),
            verification_share_of(new_key, REUSING_SIGNER),
        )

    def test_every_round_challenge_is_nonzero(self):
        for label in ("pre_round_a", "pre_round_b", "post_round_a", "post_round_b"):
            with self.subTest(round=label):
                round_info = self.data[label]
                self.assertNotEqual(round_info.challenge, 0)
                self.assertTrue(0 < round_info.challenge < FIELD_PRIME)

    def test_payload_challenge_matches_round_and_is_nonzero(self):
        for label in ("a", "b"):
            for phase in ("pre", "post"):
                with self.subTest(phase=phase, record=label):
                    record = self.data[f"{phase}_record_{label}"]
                    round_info = self.data[f"{phase}_round_{label}"]
                    parsed = parse_audit_payload(record[1].payload)
                    self.assertNotEqual(parsed.challenge, 0)
                    self.assertEqual(parsed.challenge, round_info.challenge)
                    self.assertEqual(parsed.public_key, self.data["old_key"].public_key)
                    self.assertEqual(parsed.R, round_info.R)
                    self.assertEqual(parsed.status, 1)
                    self.assertEqual(parsed.present, 1)

    def test_same_phase_records_have_distinct_challenge_weight_products(self):
        pre_a = challenge_weight_product(self.data["pre_record_a"], REUSING_SIGNER)
        pre_b = challenge_weight_product(self.data["pre_record_b"], REUSING_SIGNER)
        post_a = challenge_weight_product(self.data["post_record_a"], REUSING_SIGNER)
        post_b = challenge_weight_product(self.data["post_record_b"], REUSING_SIGNER)
        self.assertNotEqual(pre_a, pre_b)
        self.assertNotEqual(post_a, post_b)

    def test_both_phase_signatures_verify_under_the_same_joint_public_key(self):
        old_key = self.data["old_key"]
        new_key = self.data["new_key"]
        self.assertEqual(new_key.public_key, old_key.public_key)

        pre_signature = aggregate_signature(
            self.data["pre_shares_a"], self.data["pre_round_a"], old_key
        )
        self.assertIsInstance(pre_signature, AggregateSignature)
        post_signature = aggregate_signature(
            self.data["post_shares_a"], self.data["post_round_a"], new_key
        )
        self.assertIsInstance(post_signature, AggregateSignature)

        joint_public_key = old_key.public_key
        for message, signature in (
            (PRE_MESSAGE_A, pre_signature),
            (POST_MESSAGE_A, post_signature),
        ):
            with self.subTest(message=message):
                self.assertTrue(
                    verify_signature(
                        message,
                        signature,
                        joint_public_key,
                        prime=FIELD_PRIME,
                        group_prime=GROUP_PRIME,
                        generator=GENERATOR,
                    )
                )


class PhaseReuseAnalysisTest(unittest.TestCase):
    """Per-phase nonce-reuse findings and leaked-share recovery."""

    def setUp(self):
        self.data = scenario()
        self.old_key = self.data["old_key"]
        self.new_key = self.data["new_key"]
        self.pre_records = [self.data["pre_record_a"], self.data["pre_record_b"]]
        self.post_records = [self.data["post_record_a"], self.data["post_record_b"]]

    def test_find_reports_only_the_reusing_signer_per_phase(self):
        for key, records, nonce in (
            (self.old_key, self.pre_records, PRE_REUSED_NONCE),
            (self.new_key, self.post_records, POST_REUSED_NONCE),
        ):
            with self.subTest(key=id(key)):
                findings = find_nonce_reuse(records, key)
                self.assertEqual(len(findings), 1)
                finding = findings[0]
                self.assertEqual(finding.signer_id, REUSING_SIGNER)
                self.assertEqual(
                    finding.nonce_commitment, pow(GENERATOR, nonce, GROUP_PRIME)
                )
                self.assertEqual(
                    finding.receipts,
                    tuple(
                        sorted(
                            (records[0][1], records[1][1]),
                            key=lambda audit: audit.payload,
                        )
                    ),
                )

    def test_recover_yields_each_phases_own_share(self):
        pre_leaks = recover_leaks(self.pre_records, self.old_key)
        post_leaks = recover_leaks(self.post_records, self.new_key)
        self.assertEqual(len(pre_leaks), 1)
        self.assertEqual(len(post_leaks), 1)
        pre_leak = pre_leaks[0]
        post_leak = post_leaks[0]

        # The recovered values are the phase's actual secret shares, and the
        # refresh really separated them.
        self.assertEqual(pre_leak.share, share_of(self.old_key, REUSING_SIGNER))
        self.assertEqual(post_leak.share, share_of(self.new_key, REUSING_SIGNER))
        self.assertNotEqual(pre_leak.share, post_leak.share)

        # Independent finite-field recovery from the public payload bytes.
        self.assertEqual(
            pre_leak.share,
            recover_share_independently(
                self.data["pre_record_a"], self.data["pre_record_b"], REUSING_SIGNER
            ),
        )
        self.assertEqual(
            post_leak.share,
            recover_share_independently(
                self.data["post_record_a"], self.data["post_record_b"], REUSING_SIGNER
            ),
        )

        # Independent group check against each phase's verification share.
        self.assertEqual(
            pow(GENERATOR, pre_leak.share, GROUP_PRIME),
            verification_share_of(self.old_key, REUSING_SIGNER),
        )
        self.assertEqual(
            pow(GENERATOR, post_leak.share, GROUP_PRIME),
            verification_share_of(self.new_key, REUSING_SIGNER),
        )

    def test_shuffled_or_duplicated_submission_keeps_findings(self):
        for key, records in (
            (self.old_key, self.pre_records),
            (self.new_key, self.post_records),
        ):
            with self.subTest(key=id(key)):
                reference_reuse = find_nonce_reuse(records, key)
                reference_leaks = recover_leaks(records, key)
                shuffled = [records[1], records[0], records[1]]
                self.assertEqual(find_nonce_reuse(shuffled, key), reference_reuse)
                self.assertEqual(recover_leaks(shuffled, key), reference_leaks)

    def test_single_record_calls_return_empty_tuples(self):
        for key, records in (
            (self.old_key, self.pre_records),
            (self.new_key, self.post_records),
        ):
            for record in records:
                with self.subTest(key=id(key), message=record[0]):
                    self.assertEqual(find_nonce_reuse([record], key), ())
                    self.assertEqual(recover_leaks([record], key), ())


class CrossPhaseIsolationTest(unittest.TestCase):
    """Records of one phase must not verify or analyse under the other key."""

    def setUp(self):
        self.data = scenario()
        self.old_key = self.data["old_key"]
        self.new_key = self.data["new_key"]
        self.pre_records = [self.data["pre_record_a"], self.data["pre_record_b"]]
        self.post_records = [self.data["post_record_a"], self.data["post_record_b"]]

    def test_old_records_fail_check_audit_under_new_key(self):
        for message, audit in self.pre_records:
            with self.subTest(message=message):
                self.assertFalse(check_audit(message, audit, self.new_key))

    def test_new_records_fail_check_audit_under_old_key(self):
        for message, audit in self.post_records:
            with self.subTest(message=message):
                self.assertFalse(check_audit(message, audit, self.old_key))

    def test_mixed_batches_raise_value_error_in_both_entries(self):
        mixed_with_old = self.pre_records + [self.data["post_record_a"]]
        mixed_with_new = self.post_records + [self.data["pre_record_a"]]
        for records, key in (
            (mixed_with_old, self.old_key),
            (mixed_with_new, self.new_key),
        ):
            with self.subTest(key=id(key)):
                with self.assertRaises(ValueError):
                    find_nonce_reuse(records, key)
                with self.assertRaises(ValueError):
                    recover_leaks(records, key)

    def test_replaced_message_raises_value_error_in_both_entries(self):
        for key, records in (
            (self.old_key, self.pre_records),
            (self.new_key, self.post_records),
        ):
            replaced = [(b"replaced message", records[0][1]), records[1]]
            with self.subTest(key=id(key)):
                with self.assertRaises(ValueError):
                    find_nonce_reuse(replaced, key)
                with self.assertRaises(ValueError):
                    recover_leaks(replaced, key)

    def test_string_message_raises_type_error_in_both_entries(self):
        for key, records in (
            (self.old_key, self.pre_records),
            (self.new_key, self.post_records),
        ):
            string_message = [("a string message", records[0][1]), records[1]]
            with self.subTest(key=id(key)):
                with self.assertRaises(TypeError):
                    find_nonce_reuse(string_message, key)
                with self.assertRaises(TypeError):
                    recover_leaks(string_message, key)

    def test_failed_calls_leave_original_phase_results_unchanged(self):
        # Reference results before any failing call.
        reference = {}
        for phase, key, records in (
            ("pre", self.old_key, self.pre_records),
            ("post", self.new_key, self.post_records),
        ):
            reference[phase] = (
                find_nonce_reuse(records, key),
                recover_leaks(records, key),
            )

        # Failing calls: mixed batches, replaced and string messages.
        for key, records in (
            (self.old_key, self.pre_records),
            (self.new_key, self.post_records),
        ):
            foreign = self.post_records[0] if key is self.old_key else self.pre_records[0]
            for bad_records in (
                records + [foreign],
                [(b"replaced message", records[0][1]), records[1]],
            ):
                with self.assertRaises(ValueError):
                    find_nonce_reuse(bad_records, key)
                with self.assertRaises(ValueError):
                    recover_leaks(bad_records, key)
            with self.assertRaises(TypeError):
                find_nonce_reuse([("string", records[0][1])], key)
            with self.assertRaises(TypeError):
                recover_leaks([("string", records[0][1])], key)

        # The original records still verify and analyse exactly as before.
        for phase, key, records in (
            ("pre", self.old_key, self.pre_records),
            ("post", self.new_key, self.post_records),
        ):
            with self.subTest(phase=phase):
                for message, audit in records:
                    self.assertTrue(check_audit(message, audit, key))
                self.assertEqual(find_nonce_reuse(records, key), reference[phase][0])
                self.assertEqual(recover_leaks(records, key), reference[phase][1])


class ZeroIncrementRefreshTest(unittest.TestCase):
    """A legal all-zero refresh must not invalidate or alter anything."""

    def setUp(self):
        self.data = scenario()
        self.old_key = self.data["old_key"]
        self.zero_key = self.data["zero_key"]
        self.pre_records = [self.data["pre_record_a"], self.data["pre_record_b"]]

    def test_zero_contributions_carry_zero_increments(self):
        for contribution in self.data["zero_contributions"]:
            self.assertEqual(
                [share.y for share in contribution.contribution.shares], [0, 0, 0]
            )
            self.assertEqual(contribution.feldman_commitment.values[0], 1)

    def test_shares_and_verification_shares_are_unchanged(self):
        self.assertEqual(
            [share.y for share in self.zero_key.result.shares],
            [share.y for share in self.old_key.result.shares],
        )
        self.assertEqual(
            list(self.zero_key.verification_shares),
            list(self.old_key.verification_shares),
        )
        self.assertEqual(self.zero_key.public_key, self.old_key.public_key)

    def test_old_records_still_verify_under_zero_refreshed_key(self):
        for message, audit in self.pre_records:
            with self.subTest(message=message):
                self.assertTrue(check_audit(message, audit, self.zero_key))

    def test_reuse_analysis_is_identical_under_zero_refreshed_key(self):
        self.assertEqual(
            find_nonce_reuse(self.pre_records, self.zero_key),
            find_nonce_reuse(self.pre_records, self.old_key),
        )
        self.assertEqual(
            recover_leaks(self.pre_records, self.zero_key),
            recover_leaks(self.pre_records, self.old_key),
        )
        # And the recovered share is still the (unchanged) secret share.
        leaks = recover_leaks(self.pre_records, self.zero_key)
        self.assertEqual(len(leaks), 1)
        self.assertEqual(leaks[0].share, share_of(self.old_key, REUSING_SIGNER))
        self.assertEqual(
            pow(GENERATOR, leaks[0].share, GROUP_PRIME),
            verification_share_of(self.zero_key, REUSING_SIGNER),
        )


if __name__ == "__main__":
    unittest.main()
