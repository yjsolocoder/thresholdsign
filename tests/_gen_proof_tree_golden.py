"""One-shot generator: capture golden proof digests from the current build.

Run with: PYTHONPATH=repo:repo/tests python3 tests/_gen_proof_tree_golden.py
Prints a Python literal to paste into test_proof_tree_compat.py.
"""

import sys

from thresholdsign import (
    encode_audit_multi_proof,
    encode_audit_proof,
    encode_extension,
    encode_history_extension,
    encode_history_multi_proof,
    encode_history_proof,
    make_extension,
    make_history_extension,
    make_history_multi_proof,
    make_history_proof,
    make_multi_proof,
    make_proof,
)

from test_audit_chain import make_key as make_audit_key, make_record
from test_nonce_reuse import make_key as make_history_key
from test_seal_history import make_history

SIZES = (1, 2, 3, 5, 7, 13, 27)
MULTI_INDICES = {
    1: [(0,)],
    2: [(0,), (1,), (0, 1)],
    3: [(0,), (2,), (0, 2), (0, 1, 2)],
    5: [(0,), (4,), (1, 3), (0, 2, 4), (1, 2, 3)],
    7: [(0,), (6,), (0, 6), (1, 3, 5), (0, 1, 2, 3, 4, 5, 6)],
    13: [(0,), (12,), (2, 5, 9), (0, 6, 12), tuple(range(13))],
    27: [(0,), (26,), (3, 11, 19), (0, 13, 26), tuple(range(0, 27, 2))],
}
EXTENSIONS = {
    2: [1],
    3: [1, 2],
    5: [1, 2, 4],
    7: [1, 3, 6],
    13: [1, 6, 12],
    27: [1, 13, 26],
}


def hx(data):
    return data.hex()


def main():
    out = {"audit": {}, "history": {}}

    audit_key = make_audit_key()
    audit_records = {
        n: tuple(
            make_record(audit_key, f"message-{i}".encode(), seed=1000 + 10 * i)
            for i in range(n)
        )
        for n in SIZES
    }
    for n, records in audit_records.items():
        entry = {"single": {}, "multi": {}, "extension": {}}
        for i in range(n):
            message, proof = make_proof(records, i)
            entry["single"][i] = {
                "message": hx(message),
                "path": [hx(p) for p in proof.p],
            }
        for indices in MULTI_INDICES[n]:
            message, proof = make_multi_proof(records, indices)
            entry["multi"][indices] = {
                "message": hx(message),
                "siblings": [hx(s) for s in proof.siblings],
            }
        for old_n in EXTENSIONS.get(n, []):
            old_message, new_message, proof = make_extension(records, old_n)
            entry["extension"][old_n] = {
                "old_message": hx(old_message),
                "new_message": hx(new_message),
                "leaves": [hx(leaf) for leaf in proof.leaves],
            }
        out["audit"][n] = entry

    # Canonical encodings of one representative proof per family.
    message, proof = make_proof(audit_records[7], 3)
    out["audit"]["encode_single"] = hx(encode_audit_proof(proof))
    message, proof = make_multi_proof(audit_records[13], (2, 5, 9))
    out["audit"]["encode_multi"] = hx(encode_audit_multi_proof(proof))
    _old, _new, proof = make_extension(audit_records[7], 3)
    out["audit"]["encode_extension"] = hx(encode_extension(proof))

    history_key = make_history_key()
    histories = {
        n: make_history(
            history_key, nonces=tuple(100 + 37 * i for i in range(n))
        )
        for n in SIZES
    }
    for n, history in histories.items():
        entry = {"single": {}, "multi": {}, "extension": {}}
        for i in range(n):
            message, proof = make_history_proof(history, i)
            entry["single"][i] = {
                "message": hx(message),
                "path": [hx(p) for p in proof.siblings],
            }
        for indices in MULTI_INDICES[n]:
            message, proof = make_history_multi_proof(history, indices)
            entry["multi"][indices] = {
                "message": hx(message),
                "siblings": [hx(s) for s in proof.siblings],
            }
        for old_total in EXTENSIONS.get(n, []):
            old_message, new_message, proof = make_history_extension(
                history, old_total
            )
            entry["extension"][old_total] = {
                "old_message": hx(old_message),
                "new_message": hx(new_message),
                "leaves": [hx(leaf) for leaf in proof.leaves],
            }
        out["history"][n] = entry

    message, proof = make_history_proof(histories[7], 3)
    out["history"]["encode_single"] = hx(encode_history_proof(proof))
    message, proof = make_history_multi_proof(histories[13], (2, 5, 9))
    out["history"]["encode_multi"] = hx(encode_history_multi_proof(proof))
    _old, _new, proof = make_history_extension(histories[7], 3)
    out["history"]["encode_extension"] = hx(encode_history_extension(proof))

    import pprint

    print(
        '"""Golden proof digests captured from the pre-refactor public API.\n'
        "\n"
        "Independent expected values for test_proof_tree_compat.py: every\n"
        "root message, path, sibling sequence, extension leaf set and\n"
        "canonical encoding below was produced once by the original\n"
        "implementation and frozen here, so the shared-tree refactor is\n"
        "checked against fixed external expectations rather than against\n"
        "itself. Regenerate only intentionally, with\n"
        "tests/_gen_proof_tree_golden.py.\n"
        '"""\n'
    )
    print("GOLDEN = " + pprint.pformat(out, width=100, sort_dicts=False))


if __name__ == "__main__":
    main()
