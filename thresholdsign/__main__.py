"""Self-contained demo: python3 -m thresholdsign"""

from __future__ import annotations

from itertools import combinations

from . import reconstruct_secret, split_secret

SECRET = 0x5EC12E7
THRESHOLD = 3
SHARE_COUNT = 5


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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
