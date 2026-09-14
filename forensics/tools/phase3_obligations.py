#!/usr/bin/env python3
"""openssl-rs — the Phase 3 obligation ledger, and what is deliberately deferred.

`forensics/phase-state.json` may only call a stratum `complete` when its evidence
exists and nothing in it is unaccounted for. This tool makes that checkable for
Phase 3 instead of asserted in prose:

  * it enumerates the authority's libcrypto exports that belong to the Phase 3
    subsystems, by the prefixes those subsystems own;
  * it subtracts the symbols the crate actually defines
    (`forensics/atlas/implemented-surface.json`);
  * every remainder must appear in `DEFERRED` below with the phase that owns it
    and the reason it cannot be built here. A remainder with no entry is a hard
    error, so the deferral list cannot silently rot: adding a new export to a
    Phase 3 family forces a decision.

A deferred entry is not a claim that the obligation has been met. It is a
recorded, phase-scoped hand-off, which is the same device Phase 1 used for
`deferred planes`.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    envelope,
    rel,
    resolve_authority,
    InputRef,
    write_json,
)

OUT = REPO_ROOT / "forensics" / "phase3-obligations.json"
GENERATOR = "forensics/tools/phase3_obligations.py"

# The symbol families the Phase 3 modules own. Each entry is (module, prefixes).
# The prefixes are matched against the authority's libcrypto exports.
FAMILIES = [
    ("src/runtime/mem.rs", ("CRYPTO_malloc", "CRYPTO_zalloc", "CRYPTO_calloc",
                            "CRYPTO_realloc", "CRYPTO_free", "CRYPTO_strdup",
                            "CRYPTO_strndup", "CRYPTO_memdup", "CRYPTO_memcmp",
                            "CRYPTO_clear_", "CRYPTO_secure_", "CRYPTO_set_mem_",
                            "CRYPTO_get_mem_", "CRYPTO_aligned_alloc",
                            "CRYPTO_mem_ctrl", "CRYPTO_mem_leaks", "CRYPTO_mem_debug")),
    ("src/runtime/err.rs", ("ERR_",)),
    ("src/runtime/lhash.rs", ("OPENSSL_LH_",)),
    ("src/runtime/stack.rs", ("OPENSSL_sk_",)),
    ("src/runtime/ex_data.rs", ("CRYPTO_get_ex_new_index", "CRYPTO_free_ex_index",
                                "CRYPTO_new_ex_data", "CRYPTO_dup_ex_data",
                                "CRYPTO_free_ex_data", "CRYPTO_get_ex_data",
                                "CRYPTO_set_ex_data")),
    ("src/runtime/thread.rs", ("CRYPTO_THREAD_", "CRYPTO_atomic_", "CRYPTO_ONCE",
                               "CRYPTO_THREAD_run_once")),
    ("src/runtime/init.rs", ("OPENSSL_init", "OPENSSL_cleanup", "OpenSSL_version",
                             "OpenSSL_version_num", "OPENSSL_info",
                             "OPENSSL_version_major", "OPENSSL_version_minor",
                             "OPENSSL_version_patch", "OPENSSL_version_pre_release",
                             "OPENSSL_version_build_metadata")),
    ("src/runtime/obj.rs", ("OBJ_", "NID_", "OBJ_NAME_")),
]

# Every symbol in the Phase 3 families that the crate does not define, with the
# phase that owns it and why it cannot be built in Phase 3. A symbol that is not
# here and not implemented is an error, not a warning.
#
# These ten need a `BIO *` (or a `FILE *`) to do their job, and BIO is Phase 4 by
# the same ordering that puts ERR here. They are *not* faked and not scaffolded
# into looking present: they stay `SCAFFOLDED` in the shell.
_BIO_COUPLED = [
    "ERR_print_errors",
    "ERR_print_errors_cb",
    "ERR_print_errors_fp",
    "ERR_add_error_mem_bio",
    "OPENSSL_LH_stats",
    "OPENSSL_LH_stats_bio",
    "OPENSSL_LH_node_stats",
    "OPENSSL_LH_node_stats_bio",
    "OPENSSL_LH_node_usage_stats",
    "OPENSSL_LH_node_usage_stats_bio",
]

# One further symbol needs a subsystem this stratum does not contain.
_EXTRA_DEFERRED = [
    ("/work/forensics/authorities/src/openssl-3.6.4/crypto/objects/obj_dat.c",
     "OBJ_create_objects",
     4,
     "reads an object description stream from a BIO; BIO is Phase 4"),
]


def deferred_table() -> dict[str, tuple[int, str]]:
    """The hand-off table, built once so the reasons stay aligned."""
    table = {name: (4, "writes to a BIO/FILE sink; BIO is Phase 4") for name in _BIO_COUPLED}
    for _site, name, phase, reason in _EXTRA_DEFERRED:
        table[name] = (phase, reason)
    return table


def authority_exports(authority: Path) -> list[str]:
    """The symbols the authority actually *exports* from libcrypto.

    The record list also contains declarations that are deliberately not
    exported (`ERR_put_error`, `ERR_load_DSO_strings` are `NOEXIST`; a handful of
    others are `EXIST` in the `.num` file but absent from the DSO). Those are not
    obligations to define, and the candidate must not define them either — the
    ABI symbol court would report them as unexpected exports.
    """
    doc = json.loads((authority / "symbols-libcrypto.json").read_text(encoding="utf-8"))
    return sorted(r["symbol"] for r in doc["body"]["records"] if r["dso"]["present"])


def implemented() -> set[str]:
    doc = json.loads(
        (REPO_ROOT / "forensics" / "atlas" / "implemented-surface.json").read_text(encoding="utf-8")
    )
    return set(doc["body"]["libraries"]["libcrypto"]["implemented_symbols"])


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    exports = authority_exports(REPO_ROOT / "forensics" / "atlas" / auth.id)
    done = implemented()
    table = deferred_table()

    owned: dict[str, str] = {}
    for module, prefixes in FAMILIES:
        for sym in exports:
            if any(sym == p or sym.startswith(p) for p in prefixes):
                owned.setdefault(sym, module)

    implemented_here = sorted(s for s in owned if s in done)
    remaining = sorted(s for s in owned if s not in done)
    unassigned = [s for s in remaining if s not in table]
    if unassigned:
        raise SystemExit(
            "phase3-obligations: these Phase 3 family exports are neither "
            "implemented nor deferred; add them to DEFERRED with the owning "
            "phase and a reason:\n  " + "\n  ".join(unassigned)
        )

    deferred_rows = []
    for sym in remaining:
        phase, reason = table[sym]
        if phase <= 3:
            raise SystemExit(f"phase3-obligations: {sym} is deferred to phase {phase}, not later")
        deferred_rows.append({
            "symbol": sym,
            "owning_phase": phase,
            "reason": reason,
            "module": owned[sym],
        })

    body = {
        "families": [{"module": m, "prefixes": list(p)} for m, p in FAMILIES],
        "counts": {
            "owned": len(owned),
            "implemented": len(implemented_here),
            "deferred": len(deferred_rows),
        },
        "implemented": implemented_here,
        "deferred": deferred_rows,
        "note": (
            "A deferred symbol is a recorded hand-off to the phase that owns the "
            "subsystem it needs, not a parity claim. `phase_state.py` treats Phase "
            "3 as complete only when every symbol in these families is either "
            "implemented or deferred to a later phase."
        ),
    }

    inputs = [
        InputRef(name="authority-symbols", path=REPO_ROOT / "forensics" / "atlas" / auth.id / "symbols-libcrypto.json"),
        InputRef(name="implemented-surface", path=REPO_ROOT / "forensics" / "atlas" / "implemented-surface.json"),
    ]
    doc = envelope(
        kind="phase3-obligations",
        authority=auth.id,
        inputs=inputs,
        body=body,
        generator=GENERATOR,
    )
    write_json(OUT, doc)
    print(f"[phase3-obligations] owned={len(owned)} implemented={len(implemented_here)} "
          f"deferred={len(deferred_rows)}")
    for row in deferred_rows:
        print(f"  deferred -> phase {row['owning_phase']:<2} {row['symbol']}: {row['reason']}")
    print(f"  -> {rel(OUT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
