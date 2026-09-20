"""Tests for the stateless nonce-reuse audit: NonceReuse / find_nonce_reuse."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    NonceReuse,
    SignatureShare,
    SigningAudit,
    SigningNonceCommitment,
    aggregate_signing_dkg,
    create_audit,
    create_signature_share,
    create_signing_contribution,
    create_signing_nonce_commitment,
    create_signing_round,
    find_nonce_reuse,
)

# Same toy group as the audit tests: 8069 = 4 * 2017 + 1 is prime, 16 and
# 256 = 16 ** 2 are distinct generators of the order-2017 subgroup.
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


class NonceReuseTest(unittest.TestCase):
    def test_frozen_fields_value_equality(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(NonceReuse)],
            ["signer_id", "nonce_commitment", "receipts"],
        )
        receipts = (SigningAudit(b"a"), SigningAudit(b"b"))
        reuse = NonceReuse(1, 42, receipts)  # positional construction
        self.assertEqual(reuse, NonceReuse(1, 42, receipts))
        self.assertEqual(
            reuse,
            NonceReuse(signer_id=1, nonce_commitment=42, receipts=receipts),
        )
        self.assertNotEqual(reuse, NonceReuse(2, 42, receipts))
        self.assertNotEqual(reuse, NonceReuse(1, 43, receipts))
        self.assertNotEqual(reuse, NonceReuse(1, 42, (SigningAudit(b"a"),)))
        self.assertEqual(hash(reuse), hash(NonceReuse(1, 42, receipts)))
        with self.assertRaises(FrozenInstanceError):
            reuse.signer_id = 2


class FindNonceReuseTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()

    def test_no_reuse_reports_nothing(self):
        records = [
            make_record(self.key, MESSAGE_A, seed=100),
            make_record(self.key, MESSAGE_B, seed=200),
        ]
        self.assertEqual(find_nonce_reuse(records, self.key), ())

    def test_empty_records(self):
        self.assertEqual(find_nonce_reuse([], self.key), ())
        self.assertEqual(find_nonce_reuse((), self.key), ())

    def test_reused_nonce_across_messages_is_reported(self):
        record_a = make_record(self.key, MESSAGE_A, seed=100, nonces={1: 777})
        record_b = make_record(self.key, MESSAGE_B, seed=200, nonces={1: 777})
        findings = find_nonce_reuse([record_a, record_b], self.key)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertIsInstance(finding, NonceReuse)
        self.assertEqual(finding.signer_id, 1)
        self.assertEqual(
            finding.nonce_commitment, pow(GENERATOR, 777, GROUP_PRIME)
        )
        self.assertEqual(
            finding.receipts,
            tuple(sorted((record_a[1], record_b[1]), key=lambda a: a.payload)),
        )

    def test_reuse_requires_two_distinct_payloads(self):
        # The same receipt submitted twice is one payload: no alert.
        record = make_record(self.key, MESSAGE_A, nonces={1: 777})
        self.assertEqual(find_nonce_reuse([record, record], self.key), ())
        self.assertEqual(find_nonce_reuse([record, record, record], self.key), ())

    def test_receipts_deduplicated_and_sorted_by_payload(self):
        record_a = make_record(self.key, MESSAGE_A, seed=100, nonces={1: 555})
        record_b = make_record(self.key, MESSAGE_B, seed=200, nonces={1: 555})
        # record_b submitted twice, input reversed: still exactly the two
        # distinct receipts, ordered by payload bytes.
        findings = find_nonce_reuse([record_b, record_a, record_b], self.key)
        self.assertEqual(len(findings), 1)
        expected = tuple(
            sorted((record_a[1], record_b[1]), key=lambda a: a.payload)
        )
        self.assertEqual(findings[0].receipts, expected)
        self.assertEqual(
            len({receipt.payload for receipt in findings[0].receipts}), 2
        )

    def test_input_order_does_not_matter(self):
        record_a = make_record(self.key, MESSAGE_A, seed=100, nonces={1: 111})
        record_b = make_record(
            self.key, MESSAGE_B, seed=200, nonces={1: 111, 3: 222}
        )
        record_c = make_record(self.key, MESSAGE_C, seed=300, nonces={3: 222})
        forward = find_nonce_reuse([record_a, record_b, record_c], self.key)
        backward = find_nonce_reuse([record_c, record_b, record_a], self.key)
        self.assertEqual(forward, backward)
        self.assertEqual(
            [(finding.signer_id, finding.nonce_commitment) for finding in forward],
            [
                (1, pow(GENERATOR, 111, GROUP_PRIME)),
                (3, pow(GENERATOR, 222, GROUP_PRIME)),
            ],
        )

    def test_findings_sorted_by_signer_id_then_nonce_commitment(self):
        # Signer 3 reuses two different nonces and signer 1 reuses one;
        # findings order is (signer_id, nonce_commitment) ascending.
        nonce_1, nonce_3a, nonce_3b = 41, 42, 43
        r_1 = pow(GENERATOR, nonce_1, GROUP_PRIME)
        r_3a = pow(GENERATOR, nonce_3a, GROUP_PRIME)
        r_3b = pow(GENERATOR, nonce_3b, GROUP_PRIME)
        records = [
            make_record(
                self.key, MESSAGE_A, seed=100, nonces={1: nonce_1, 3: nonce_3a}
            ),
            make_record(
                self.key, MESSAGE_B, seed=200, nonces={1: nonce_1, 3: nonce_3b}
            ),
            make_record(
                self.key, MESSAGE_C, seed=300, nonces={1: 901, 3: nonce_3a}
            ),
            make_record(
                self.key, MESSAGE_D, seed=400, nonces={1: 902, 3: nonce_3b}
            ),
        ]
        findings = find_nonce_reuse(records, self.key)
        self.assertEqual(
            [(finding.signer_id, finding.nonce_commitment) for finding in findings],
            [(1, r_1), (3, min(r_3a, r_3b)), (3, max(r_3a, r_3b))],
        )

    def test_failed_status_receipts_do_not_participate(self):
        # A status-0 receipt records its rows verbatim but must not count.
        round_info, shares = make_round(
            self.key, MESSAGE_B, seed=200, nonces={1: 777}
        )
        bad = SignatureShare(
            signer_id=shares[0].signer_id,
            nonce_commitment=shares[0].nonce_commitment,
            z=(shares[0].z + 1) % FIELD_PRIME,
        )
        failing = (
            MESSAGE_B,
            create_audit(MESSAGE_B, [bad, shares[1]], round_info, self.key),
        )
        passing = make_record(self.key, MESSAGE_A, seed=100, nonces={1: 777})
        self.assertEqual(find_nonce_reuse([passing, failing], self.key), ())
        # Two copies of the failing receipt still stay silent.
        self.assertEqual(find_nonce_reuse([failing, failing], self.key), ())

    def test_function_keeps_no_history(self):
        record_a = make_record(self.key, MESSAGE_A, seed=100, nonces={1: 777})
        record_b = make_record(self.key, MESSAGE_B, seed=200, nonces={1: 777})
        self.assertEqual(find_nonce_reuse([record_a], self.key), ())
        # A later call sees only its own batch: no cross-call memory.
        self.assertEqual(find_nonce_reuse([record_b], self.key), ())
        self.assertEqual(len(find_nonce_reuse([record_a, record_b], self.key)), 1)

    def test_type_errors(self):
        record = make_record(self.key, MESSAGE_A)
        with self.assertRaises(TypeError):
            find_nonce_reuse("records", self.key)
        with self.assertRaises(TypeError):
            find_nonce_reuse(b"records", self.key)
        with self.assertRaises(TypeError):
            find_nonce_reuse([MESSAGE_A], self.key)
        with self.assertRaises(TypeError):
            find_nonce_reuse([(MESSAGE_A, record[1], record[1])], self.key)
        with self.assertRaises(TypeError):
            find_nonce_reuse([("message", record[1])], self.key)
        with self.assertRaises(TypeError):
            find_nonce_reuse([(MESSAGE_A, "receipt")], self.key)
        with self.assertRaises(TypeError):
            find_nonce_reuse([record], "key")
        with self.assertRaises(TypeError):
            find_nonce_reuse([record], None)

    def test_mismatched_message_raises_value_error(self):
        record = make_record(self.key, MESSAGE_A)
        with self.assertRaises(ValueError):
            find_nonce_reuse([(MESSAGE_B, record[1])], self.key)

    def test_mismatched_key_raises_value_error(self):
        other_key = make_key(participant_ids=(1, 2, 4))
        record = make_record(self.key, MESSAGE_A)
        with self.assertRaises(ValueError):
            find_nonce_reuse([record], other_key)

    def test_structurally_illegal_receipt_raises_value_error(self):
        record = make_record(self.key, MESSAGE_A)
        # Truncated payload.
        with self.assertRaises(ValueError):
            find_nonce_reuse(
                [(MESSAGE_A, SigningAudit(record[1].payload[:-1]))], self.key
            )
        # Wrong tag.
        with self.assertRaises(ValueError):
            find_nonce_reuse(
                [(MESSAGE_A, SigningAudit(b"wrong" + record[1].payload[5:]))],
                self.key,
            )
        # Tampered row z_i: well-formed encoding, but the recorded status no
        # longer matches the recomputed one.
        length = (GROUP_PRIME.bit_length() + 7) // 8
        row_offset = len(b"thresholdsign/audit/v1") + 32 + 3 * length + 4
        z_i = int.from_bytes(
            record[1].payload[row_offset + 2 * length:row_offset + 3 * length],
            "big",
        )
        bad_z = (z_i + 1) % FIELD_PRIME
        tampered = SigningAudit(
            record[1].payload[:row_offset + 2 * length]
            + bad_z.to_bytes(length, "big")
            + record[1].payload[row_offset + 3 * length:]
        )
        with self.assertRaises(ValueError):
            find_nonce_reuse([(MESSAGE_A, tampered)], self.key)


if __name__ == "__main__":
    unittest.main()
