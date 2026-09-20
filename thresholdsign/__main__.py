"""Self-contained demo: python3 -m thresholdsign"""

from __future__ import annotations

from itertools import combinations

from . import (
    AggregateSignature,
    DKGResult,
    SigningDKGResult,
    aggregate_dkg,
    aggregate_signature,
    aggregate_signing_dkg,
    check_audit,
    create_audit,
    create_dkg_contribution,
    create_signature_share,
    create_signing_contribution,
    create_signing_nonce_commitment,
    create_signing_round,
    reconstruct_secret,
    split_secret,
    verify_signature,
    verify_signature_share,
)

SECRET = 0x5EC12E7
THRESHOLD = 3
SHARE_COUNT = 5

# Toy Pedersen group setup (see README): 8069 = 4 * 2017 + 1 is prime and
# 16, 256 = 16 ** 2 are distinct generators of the order-2017 subgroup.
DKG_FIELD_PRIME = 2017
DKG_GROUP_PRIME = 8069
DKG_GENERATOR = 16
DKG_BLINDING_GENERATOR = 256
DKG_PARTICIPANT_IDS = (1, 2, 3)
DKG_THRESHOLD = 2


def main() -> int:
    shares = split_secret(SECRET, THRESHOLD, SHARE_COUNT)
    print(f"secret={SECRET}  threshold={THRESHOLD}  shares={SHARE_COUNT}")
    for share in shares:
        print(f"  share x={share.x} y={share.y}")

    print()
    print(f"reconstruct from the first {THRESHOLD} shares:")
    rebuilt = reconstruct_secret(shares[:THRESHOLD])
    print(f"  -> {rebuilt}  match={rebuilt == SECRET}")

    print()
    print("reconstruct from every 3-of-5 combination:")
    ok = 0
    for combination in combinations(shares, THRESHOLD):
        if reconstruct_secret(combination) == SECRET:
            ok += 1
    print(f"  {ok}/{len(list(combinations(shares, THRESHOLD)))} combinations rebuilt the secret")

    print()
    print("reconstruct from too few shares (informational):")
    for count in (1, 2):
        guess = reconstruct_secret(shares[:count])
        print(f"  {count} share(s) -> {guess}  match={guess == SECRET}")

    print()
    print(
        f"single-round Pedersen DKG: {len(DKG_PARTICIPANT_IDS)} participants, "
        f"threshold {DKG_THRESHOLD}"
    )
    contributions = [
        create_dkg_contribution(
            participant_id,
            DKG_PARTICIPANT_IDS,
            DKG_THRESHOLD,
            prime=DKG_FIELD_PRIME,
            group_prime=DKG_GROUP_PRIME,
            generator=DKG_GENERATOR,
            blinding_generator=DKG_BLINDING_GENERATOR,
        )
        for participant_id in DKG_PARTICIPANT_IDS
    ]
    outcome = aggregate_dkg(contributions)
    if isinstance(outcome, DKGResult):
        print(f"  joint commitment values={list(outcome.commitment.values)}")
        rebuilt_joint = reconstruct_secret(
            outcome.shares[:DKG_THRESHOLD], prime=DKG_FIELD_PRIME
        )
        other_pair = reconstruct_secret(
            outcome.shares[1:], prime=DKG_FIELD_PRIME
        )
        print(f"  joint secret rebuilt by two receiver pairs: "
              f"{rebuilt_joint} == {other_pair} -> {rebuilt_joint == other_pair}")
        print("  (no single participant ever knew it)")
    else:
        print(f"  rejected contributions from: {[r.sender_id for r in outcome]}")

    print()
    print(
        f"threshold Schnorr signing on the same {len(DKG_PARTICIPANT_IDS)} "
        f"participants, threshold {DKG_THRESHOLD}"
    )
    signing_contributions = [
        create_signing_contribution(
            participant_id,
            DKG_PARTICIPANT_IDS,
            DKG_THRESHOLD,
            prime=DKG_FIELD_PRIME,
            group_prime=DKG_GROUP_PRIME,
            generator=DKG_GENERATOR,
            blinding_generator=DKG_BLINDING_GENERATOR,
        )
        for participant_id in DKG_PARTICIPANT_IDS
    ]
    signing_outcome = aggregate_signing_dkg(signing_contributions)
    if not isinstance(signing_outcome, SigningDKGResult):
        print(f"  rejected contributions from: {signing_outcome}")
        return 0
    print(f"  joint public key Y={signing_outcome.public_key}")
    print(f"  verification shares Y_i={list(signing_outcome.verification_shares)}")

    # Any threshold participants sign; each keeps its own one-off nonce.
    signer_ids = tuple(DKG_PARTICIPANT_IDS[:DKG_THRESHOLD])
    message = b"thresholdsign demo message"
    nonce_commitments = []
    nonces = {}
    for index, participant_id in enumerate(signer_ids, start=1):
        commitment, nonce = create_signing_nonce_commitment(
            participant_id,
            prime=DKG_FIELD_PRIME,
            group_prime=DKG_GROUP_PRIME,
            generator=DKG_GENERATOR,
            randbelow=lambda upper, seed=index: (
                seed * 7919 + 17
            ) % (upper - 1),
        )
        nonce_commitments.append(commitment)
        nonces[participant_id] = nonce
    round_info = create_signing_round(
        message, signer_ids, nonce_commitments, signing_outcome
    )
    print(f"  round R={round_info.R}  challenge c={round_info.challenge}")

    signature_shares = []
    for participant_id in signer_ids:
        position = signing_outcome.result.participant_ids.index(participant_id)
        secret_share = signing_outcome.result.shares[position].y
        share = create_signature_share(
            participant_id, secret_share, nonces[participant_id],
            round_info, signing_outcome,
        )
        signature_shares.append(share)
        print(
            f"  signer {participant_id}: z_i={share.z}  "
            f"share_verifies={verify_signature_share(share, round_info, signing_outcome)}"
        )

    signature = aggregate_signature(signature_shares, round_info, signing_outcome)
    if isinstance(signature, AggregateSignature):
        print(f"  aggregate z={signature.z}")
        valid = verify_signature(
            message,
            signature,
            signing_outcome.public_key,
            prime=DKG_FIELD_PRIME,
            group_prime=DKG_GROUP_PRIME,
            generator=DKG_GENERATOR,
        )
        print(f"  g^z == R * Y^c -> {valid}")
        tampered = bytes([message[0] ^ 1]) + message[1:]
        print(
            f"  verification on a different message -> "
            f"{verify_signature(tampered, signature, signing_outcome.public_key, prime=DKG_FIELD_PRIME, group_prime=DKG_GROUP_PRIME, generator=DKG_GENERATOR)}"
        )
        audit = create_audit(message, signature_shares, round_info, signing_outcome)
        print(
            f"  audit payload: {len(audit.payload)} bytes, "
            f"checks={check_audit(message, audit, signing_outcome)}"
        )
        print(
            f"  audit check on a different message -> "
            f"{check_audit(tampered, audit, signing_outcome)}"
        )
    else:
        print(f"  rejected signature shares from: {[r.signer_id for r in signature]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
