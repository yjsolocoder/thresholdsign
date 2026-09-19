"""Self-contained demo: python3 -m thresholdsign"""

from __future__ import annotations

from itertools import combinations

from . import (
    DKGResult,
    Signature,
    SigningDKGResult,
    aggregate_dkg,
    aggregate_signatures,
    aggregate_signing_dkg,
    create_dkg_contribution,
    create_nonce_commitment,
    create_signature_share,
    create_signing_contribution,
    reconstruct_secret,
    split_secret,
    verify_signature,
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
        f"two-round threshold Schnorr signature: {DKG_THRESHOLD}-of-"
        f"{len(DKG_PARTICIPANT_IDS)} over the DKG key"
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
    if isinstance(signing_outcome, SigningDKGResult):
        print(f"  joint public key Y={signing_outcome.public_key}")
        message = b"threshold signatures are fun"
        signer_ids = DKG_PARTICIPANT_IDS[:DKG_THRESHOLD]
        # Round 1: every signer publishes a one-time nonce commitment.
        nonces = {}
        nonce_commitments = []
        for signer_id in signer_ids:
            nonce, commitment = create_nonce_commitment(
                signer_id,
                prime=DKG_FIELD_PRIME,
                group_prime=DKG_GROUP_PRIME,
                generator=DKG_GENERATOR,
            )
            nonces[signer_id] = nonce
            nonce_commitments.append(commitment)
        # Round 2: every signer publishes a signature share.
        signature_shares = []
        for signer_id in signer_ids:
            index = signing_outcome.dkg_result.participant_ids.index(signer_id)
            signature_shares.append(
                create_signature_share(
                    signer_id,
                    message,
                    nonce=nonces[signer_id],
                    share=signing_outcome.dkg_result.shares[index],
                    nonce_commitments=nonce_commitments,
                    result=signing_outcome,
                )
            )
        signature = aggregate_signatures(
            signature_shares,
            message,
            nonce_commitments=nonce_commitments,
            result=signing_outcome,
        )
        if isinstance(signature, Signature):
            print(f"  signers={list(signature.signer_ids)}  R={signature.nonce}  z={signature.value}")
            valid = verify_signature(
                signature,
                message,
                public_key=signing_outcome.public_key,
                prime=DKG_FIELD_PRIME,
                group_prime=DKG_GROUP_PRIME,
                generator=DKG_GENERATOR,
            )
            print(f"  signature verifies against the joint public key: {valid}")
        else:
            print(f"  rejected shares from: {[r.signer_id for r in signature]}")
    else:
        print(f"  rejected contributions from: {[r.sender_id for r in signing_outcome]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
