"""Tests for per-record audit Merkle inclusion proofs: AuditProof /
make_proof / check_proof, plus the audit-chain codec edge cases (R=0,
counter overflow)."""

import dataclasses
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from thresholdsign import (
    AggregateSignature,
    AuditChain,
    AuditProof,
    SigningAudit,
    SignatureShare,
    aggregate_signature,
    aggregate_signing_dkg,
    check_audit,
    check_proof,
    create_audit,
    create_signature_share,
    create_signing_contribution,
    create_signing_nonce_commitment,
    create_signing_round,
    decode_audit_chain,
    encode_audit_chain,
    make_proof,
    verify_signature,
)

# Same toy group as the audit tests: 8069 = 4 * 2017 + 1 is prime, 16 and
# 256 = 16 ** 2 are distinct generators of the order-2017 subgroup.
FIELD_PRIME = 2017
GROUP_PRIME = 8069
GENERATOR = 16
BLINDING_GENERATOR = 256

LEAF_TAG = b"am/l"
NODE_TAG = b"am/n"
ROOT_TAG = b"am/r"


def fixed_random(seed=1):
    """Deterministic stand-in for secrets.randbelow (same LCG as DKG tests)."""
    state = {"value": seed}

    def randbelow(upper: int) -> int:
        state["value"] = (
            state["value"] * 6364136223846793005 + 1442695040888963407
        ) % upper
        return state["value"]

    return randbelow


def make_key(participant_ids=(1, 2, 3), threshold=2, seed_offset=0):
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


def make_record(key, message, *, signer_ids=(1, 3), seed=100, bad_share=False):
    """Create one (message, SigningAudit) pair; bad_share records a status-0 receipt."""
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
    if bad_share:
        shares[1] = SignatureShare(
            signer_id=shares[1].signer_id,
            nonce_commitment=shares[1].nonce_commitment,
            z=(shares[1].z + 1) % FIELD_PRIME,
        )
    audit = create_audit(message, shares, round_info, key)
    return message, audit


def sign_message(key, message, *, signer_ids=(1, 3), seed=500):
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
    return aggregate_signature(shares, round_info, key)


def digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def reference_leaf(index, message, audit):
    return hashlib.sha256(
        LEAF_TAG
        + index.to_bytes(8, "big")
        + hashlib.sha256(message).digest()
        + hashlib.sha256(audit.payload).digest()
    ).digest()


def reference_node(left, right):
    return hashlib.sha256(NODE_TAG + left + right).digest()


def reference_levels(records):
    """All Merkle levels of the independent reference builder."""
    levels = [
        [reference_leaf(i, m, a) for i, (m, a) in enumerate(records)]
    ]
    while len(levels[-1]) > 1:
        level = levels[-1]
        if len(level) % 2:
            level = level + [level[-1]]
        levels.append(
            [
                reference_node(level[pos], level[pos + 1])
                for pos in range(0, len(level), 2)
            ]
        )
    return levels


def reference_root(records):
    return reference_levels(records)[-1][0]


def reference_path(records, i):
    levels = reference_levels(records)
    path = []
    index = i
    for level in levels[:-1]:
        paired = level
        if len(paired) % 2:
            paired = paired + [paired[-1]]
        path.append(paired[index ^ 1])
        index //= 2
    return tuple(path)


def reference_message(records):
    n = len(records)
    return ROOT_TAG + n.to_bytes(8, "big") + reference_root(records)


class AuditProofDataTest(unittest.TestCase):
    def test_field_order_and_types(self):
        self.assertEqual(
            [(field.name, field.type) for field in dataclasses.fields(AuditProof)],
            [
                ("i", "int"),
                ("n", "int"),
                ("m", "bytes"),
                ("a", "SigningAudit"),
                ("p", "tuple[bytes, ...]"),
            ],
        )

    def test_frozen_positional_value_equality(self):
        audit = SigningAudit(b"a")
        path = (b"s" * 32, b"t" * 32)
        proof = AuditProof(1, 3, b"m", audit, path)
        same = AuditProof(i=1, n=3, m=b"m", a=audit, p=path)
        self.assertEqual(proof, same)
        self.assertEqual(hash(proof), hash(same))
        self.assertNotEqual(proof, AuditProof(0, 3, b"m", audit, path))
        self.assertNotEqual(proof, AuditProof(1, 4, b"m", audit, path))
        self.assertNotEqual(proof, AuditProof(1, 3, b"x", audit, path))
        self.assertNotEqual(
            proof, AuditProof(1, 3, b"m", SigningAudit(b"b"), path)
        )
        self.assertNotEqual(
            proof, AuditProof(1, 3, b"m", audit, (b"u" * 32, b"t" * 32))
        )
        with self.assertRaises(FrozenInstanceError):
            proof.i = 2


class MakeProofTest(unittest.TestCase):
    def test_matches_independent_builder_for_many_sizes(self):
        for n in range(1, 9):
            records = tuple(
                (f"message-{i}".encode(), SigningAudit(f"receipt-{i}".encode()))
                for i in range(n)
            )
            expected_message = reference_message(records)
            for i in range(n):
                message, proof = make_proof(records, i)
                self.assertEqual(message, expected_message, (n, i))
                self.assertEqual(
                    proof,
                    AuditProof(
                        i=i,
                        n=n,
                        m=records[i][0],
                        a=records[i][1],
                        p=reference_path(records, i),
                    ),
                )
                self.assertTrue(all(len(node) == 32 for node in proof.p))

    def test_path_empty_only_for_single_record(self):
        records = ((b"m", SigningAudit(b"a")),)
        _message, proof = make_proof(records, 0)
        self.assertEqual(proof.p, ())

    def test_path_length_is_tree_depth(self):
        for n, depth in ((1, 0), (2, 1), (3, 2), (4, 2), (5, 3), (7, 3), (8, 3)):
            records = tuple(
                (b"m", SigningAudit(f"a{i}".encode())) for i in range(n)
            )
            _message, proof = make_proof(records, 0)
            self.assertEqual(len(proof.p), depth, n)

    def test_signed_message_layout(self):
        records = tuple(
            (f"m{i}".encode(), SigningAudit(f"a{i}".encode())) for i in range(4)
        )
        message, _proof = make_proof(records, 0)
        self.assertTrue(message.startswith(ROOT_TAG))
        self.assertEqual(int.from_bytes(message[4:12], "big"), 4)
        self.assertEqual(message[12:], reference_root(records))
        self.assertEqual(len(message), 4 + 8 + 32)

    def test_all_positions_share_one_message(self):
        records = tuple(
            (f"m{i}".encode(), SigningAudit(f"a{i}".encode())) for i in range(6)
        )
        messages = {make_proof(records, i)[0] for i in range(6)}
        self.assertEqual(messages, {reference_message(records)})

    def test_duplicated_odd_tail(self):
        # n=3: the level-0 tail (leaf 2) is its own sibling, so the first
        # path entry of proof 2 is leaf 2 itself.
        records = tuple(
            (f"m{i}".encode(), SigningAudit(f"a{i}".encode())) for i in range(3)
        )
        _message, proof = make_proof(records, 2)
        self.assertEqual(proof.p[0], reference_leaf(2, records[2][0], records[2][1]))

    def test_type_errors(self):
        records = ((b"m", SigningAudit(b"a")),)
        with self.assertRaises(TypeError):
            make_proof([records[0]], 0)
        with self.assertRaises(TypeError):
            make_proof((b"only-message",), 0)
        with self.assertRaises(TypeError):
            make_proof(((b"m", b"not-an-audit"),), 0)
        with self.assertRaises(TypeError):
            make_proof(((b"m", records[0][1], None),), 0)
        with self.assertRaises(TypeError):
            make_proof(records, "0")
        with self.assertRaises(TypeError):
            make_proof(records, True)

    def test_value_errors(self):
        records = tuple(
            (f"m{i}".encode(), SigningAudit(f"a{i}".encode())) for i in range(3)
        )
        with self.assertRaises(ValueError):
            make_proof((), 0)
        with self.assertRaises(ValueError):
            make_proof(records, -1)
        with self.assertRaises(ValueError):
            make_proof(records, 3)
        with self.assertRaises(ValueError):
            make_proof(records, 10**40)

    def test_counter_overflow_raises_value_error(self):
        class HugeTuple(tuple):
            def __len__(self):
                return 2**64

        with self.assertRaises(ValueError):
            make_proof(HugeTuple(((b"m", SigningAudit(b"a")),)), 0)


class CheckProofTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = tuple(
            make_record(self.key, f"message-{i}".encode(), seed=100 + 10 * i)
            for i in range(5)
        )

    def sealed(self, i, *, records=None, seed=900):
        records = self.records if records is None else records
        message, proof = make_proof(records, i)
        signature = sign_message(self.key, message, seed=seed + i)
        return message, proof, signature

    def test_honest_proof_verifies_at_every_position(self):
        for i in range(5):
            _message, proof, signature = self.sealed(i)
            self.assertTrue(check_proof(proof, signature, self.key), i)

    def test_single_record_proof_verifies(self):
        records = (make_record(self.key, b"solo", seed=150),)
        _message, proof, signature = self.sealed(0, records=records, seed=950)
        self.assertEqual(proof.p, ())
        self.assertTrue(check_proof(proof, signature, self.key))

    def test_failure_receipt_proof_verifies(self):
        failing = make_record(self.key, b"failing", seed=160, bad_share=True)
        self.assertTrue(check_audit(failing[0], failing[1], self.key))
        records = (failing,) + self.records[1:]
        _message, proof, signature = self.sealed(0, records=records, seed=960)
        self.assertTrue(check_proof(proof, signature, self.key))

    def test_message_is_an_ordinary_signature_message(self):
        message, proof, signature = self.sealed(2)
        self.assertTrue(
            verify_signature(
                message,
                signature,
                self.key.public_key,
                prime=FIELD_PRIME,
                group_prime=GROUP_PRIME,
                generator=GENERATOR,
            )
        )

    def test_one_signature_covers_every_position(self):
        message = make_proof(self.records, 0)[0]
        signature = sign_message(self.key, message, seed=970)
        for i in range(5):
            _msg, proof = make_proof(self.records, i)
            self.assertTrue(check_proof(proof, signature, self.key), i)

    def test_wrong_message_returns_false(self):
        _message, proof, signature = self.sealed(2)
        self.assertFalse(
            check_proof(dataclasses.replace(proof, m=b"other"), signature, self.key)
        )

    def test_tampered_receipt_returns_false(self):
        _message, proof, signature = self.sealed(2)
        tampered = SigningAudit(
            proof.a.payload[:-1] + bytes([(proof.a.payload[-1] + 1) % 256])
        )
        self.assertFalse(
            check_proof(dataclasses.replace(proof, a=tampered), signature, self.key)
        )

    def test_wrong_position_returns_false(self):
        _message, proof, signature = self.sealed(2)
        self.assertFalse(
            check_proof(dataclasses.replace(proof, i=3), signature, self.key)
        )

    def test_wrong_count_returns_false_when_depth_still_fits(self):
        _message, proof, signature = self.sealed(2)
        # n=6 has the same depth as n=5; the rebuilt U64(n) prefix differs.
        self.assertFalse(
            check_proof(dataclasses.replace(proof, n=6), signature, self.key)
        )

    def test_replaced_sibling_returns_false(self):
        _message, proof, signature = self.sealed(2)
        bad_path = (bytes(32),) + proof.p[1:]
        self.assertFalse(
            check_proof(dataclasses.replace(proof, p=bad_path), signature, self.key)
        )

    def test_bad_signature_returns_false(self):
        _message, proof, signature = self.sealed(2)
        bad_signature = dataclasses.replace(
            signature, z=(signature.z + 1) % FIELD_PRIME
        )
        self.assertFalse(check_proof(proof, bad_signature, self.key))

    def test_signature_from_another_tree_returns_false(self):
        other = tuple(
            make_record(self.key, f"other-{i}".encode(), seed=300 + 10 * i)
            for i in range(5)
        )
        other_message, other_proof = make_proof(other, 2)
        other_signature = sign_message(self.key, other_message, seed=980)
        self.assertTrue(check_proof(other_proof, other_signature, self.key))
        _message, proof, _signature = self.sealed(2)
        self.assertFalse(check_proof(proof, other_signature, self.key))
        self.assertFalse(check_proof(other_proof, _signature, self.key))

    def test_verification_under_another_key_returns_false(self):
        _message, proof, signature = self.sealed(2)
        other_key = make_key(seed_offset=10)
        self.assertFalse(check_proof(proof, signature, other_key))

    def test_type_errors(self):
        _message, proof, signature = self.sealed(2)
        with self.assertRaises(TypeError):
            check_proof("proof", signature, self.key)
        with self.assertRaises(TypeError):
            check_proof(proof, "signature", self.key)
        with self.assertRaises(TypeError):
            check_proof(proof, signature, "key")
        with self.assertRaises(TypeError):
            check_proof(dataclasses.replace(proof, i="2"), signature, self.key)
        with self.assertRaises(TypeError):
            check_proof(dataclasses.replace(proof, n=5.0), signature, self.key)
        with self.assertRaises(TypeError):
            check_proof(
                dataclasses.replace(proof, m=bytearray(b"m")), signature, self.key
            )
        with self.assertRaises(TypeError):
            check_proof(dataclasses.replace(proof, a="audit"), signature, self.key)
        with self.assertRaises(TypeError):
            check_proof(
                dataclasses.replace(proof, p=[b"x" * 32] * len(proof.p)),
                signature,
                self.key,
            )
        with self.assertRaises(TypeError):
            check_proof(
                dataclasses.replace(proof, p=("x",) * len(proof.p)),
                signature,
                self.key,
            )

    def test_value_errors(self):
        _message, proof, signature = self.sealed(2)
        with self.assertRaises(ValueError):
            check_proof(dataclasses.replace(proof, n=0), signature, self.key)
        with self.assertRaises(ValueError):
            check_proof(dataclasses.replace(proof, n=2**64), signature, self.key)
        with self.assertRaises(ValueError):
            check_proof(dataclasses.replace(proof, i=-1), signature, self.key)
        with self.assertRaises(ValueError):
            check_proof(dataclasses.replace(proof, i=5), signature, self.key)
        with self.assertRaises(ValueError):
            check_proof(
                dataclasses.replace(proof, p=(b"x",) * len(proof.p)),
                signature,
                self.key,
            )
        with self.assertRaises(ValueError):
            check_proof(
                dataclasses.replace(proof, p=proof.p[:-1]), signature, self.key
            )
        with self.assertRaises(ValueError):
            check_proof(
                dataclasses.replace(proof, p=proof.p + (b"x" * 32,)),
                signature,
                self.key,
            )
        with self.assertRaises(ValueError):
            check_proof(
                dataclasses.replace(proof, a=SigningAudit(b"junk")),
                signature,
                self.key,
            )
        with self.assertRaises(ValueError):
            check_proof(
                proof,
                dataclasses.replace(signature, R=GROUP_PRIME),
                self.key,
            )
        with self.assertRaises(ValueError):
            check_proof(
                proof, signature, dataclasses.replace(self.key, public_key=GROUP_PRIME + 1)
            )


class AuditChainCodecEdgeTest(unittest.TestCase):
    def setUp(self):
        self.key = make_key()
        self.records = tuple(
            make_record(self.key, f"message-{i}".encode(), seed=100 + 10 * i)
            for i in range(3)
        )
        message = make_proof(self.records, 0)[0]
        self.signature = sign_message(self.key, message, seed=900)

    def test_zero_R_rejected_on_encode(self):
        sig = AggregateSignature(R=0, z=0, signer_ids=(1,))
        chain = AuditChain(((b"m", SigningAudit(b"a")),), sig)
        with self.assertRaises(ValueError):
            encode_audit_chain(chain)

    def test_negative_R_still_rejected_on_encode(self):
        sig = AggregateSignature(R=-1, z=0, signer_ids=(1,))
        chain = AuditChain(((b"m", SigningAudit(b"a")),), sig)
        with self.assertRaises(ValueError):
            encode_audit_chain(chain)

    def test_zero_z_still_encodes_as_single_00(self):
        sig = AggregateSignature(R=2, z=0, signer_ids=(1,))
        chain = AuditChain(((b"m", SigningAudit(b"a")),), sig)
        wire = encode_audit_chain(chain)
        self.assertIn(b"\x00\x00\x00\x01\x00", wire)
        self.assertEqual(decode_audit_chain(wire), chain)

    def test_decoded_zero_R_rejected(self):
        def varint(value):
            body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
            return len(body).to_bytes(4, "big") + body

        wire = (
            b"thresholdsign/audit-chain/v1"
            + (1).to_bytes(4, "big")
            + (1).to_bytes(4, "big") + b"m"
            + (1).to_bytes(4, "big") + b"a"
            + varint(0) + varint(0)
            + (1).to_bytes(4, "big") + varint(1)
        )
        with self.assertRaises(ValueError):
            decode_audit_chain(wire)

    def test_signer_count_u32_overflow_raises_value_error(self):
        class HugeIds(tuple):
            def __len__(self):
                return 2**32

        sig = AggregateSignature(R=2, z=3, signer_ids=HugeIds((1,)))
        chain = AuditChain(((b"m", SigningAudit(b"a")),), sig)
        with self.assertRaises(ValueError):
            encode_audit_chain(chain)

    def test_record_count_u32_overflow_raises_value_error(self):
        class HugeTuple(tuple):
            def __len__(self):
                return 2**32

        chain = AuditChain(
            HugeTuple(((b"m", SigningAudit(b"a")),)), self.signature
        )
        with self.assertRaises(ValueError):
            encode_audit_chain(chain)


if __name__ == "__main__":
    unittest.main()
