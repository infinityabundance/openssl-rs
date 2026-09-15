#!/usr/bin/env python3
"""openssl-rs — the Phase 3 obligation ledger, and it is a *projection*.

This ledger does not decide its own universe
--------------------------------------------
It used to, with a `(module, prefixes)` family list. A prefix list decides two
different things with one mechanism -- which symbols the stratum owns, and which
module of it owns each -- and it does neither safely: a prefix that matches nothing
reports nothing. That is how sixty-nine Phase 3 exports were invisible to this
ledger *and* to `ownership_audit.py` at the same time, while the stratum's seal
called it complete (docs/DECISIONS.md D97).

The universe now comes from `forensics/atlas/symbol-ownership.json`, which assigns
**every one of the authority's 6,499 exports** to exactly one stratum by one stated
rule (`forensics/tools/ownership_rules.py`, D72). This file selects the rows that
atlas assigns to Phase 3 and reports them as implemented / open / handed-on. The
prefixes survive only as a *label* -- which module is expected to hold a symbol --
and an unlabelled symbol is reported rather than silently filed under "other",
because a labelling mechanism that can drop a symbol is the defect being removed.

Four situations, kept apart
---------------------------
  * **implemented** -- the crate defines the symbol and the atlas gives it to this
    stratum. At most `IMPLEMENTED` in `docs/PARITY_MODEL.md` terms; the courts decide
    everything beyond that.
  * **open** -- this stratum's, not built yet. The only list that blocks the stratum.
  * **deferred** -- a recorded hand-off to a later stratum with the dependency named.
    Sticky: the receiving stratum implementing it later does not move the obligation
    back here, and `implemented_by_owner` records whether the hand-off has been
    discharged.
  * **handoffs_discharged** -- the reverse edge: symbols an earlier stratum handed to
    this one. Phase 3 receives none; the field is present so that
    `ownership_audit.py` can reconcile every edge in both directions without a
    special case.

Failure is loud. An empty projection, an atlas that cannot be read, or an export the
atlas could not assign stops the run; none of them quietly becomes "unowned".

Outputs
-------
  forensics/phase3-obligations.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    envelope,
    implemented_surface_input,
    rel,
    resolve_authority,
    write_json,
)

OUT = REPO_ROOT / "forensics" / "phase3-obligations.json"
GENERATOR = "forensics/tools/phase3_obligations.py"

ATLAS_OWNERSHIP = "forensics/atlas/symbol-ownership.json"

# Which module of the stratum is expected to hold a symbol. This is a **label**, not
# a discovery mechanism: the universe comes from the atlas, and `main` fails if any
# symbol the atlas gives this stratum fits no entry here. `src/runtime/` is a real
# label because that is where the whole stratum lives; the finer entries are what
# make `open` readable per file.
MODULE_PREFIXES: list[tuple[str, tuple[str, ...]]] = [
    ("src/runtime/mem.rs", ("CRYPTO_", "OPENSSL_cleanse")),
    ("src/runtime/err.rs", ("ERR_", "OSSL_ERR_STATE_", "err_free_strings_int")),
    ("src/runtime/lhash.rs", ("OPENSSL_LH_",)),
    ("src/runtime/stack.rs", ("OPENSSL_sk_",)),
    ("src/runtime/ex_data.rs", ("CRYPTO_get_ex_new_index", "CRYPTO_free_ex_index",
                                "CRYPTO_new_ex_data", "CRYPTO_dup_ex_data",
                                "CRYPTO_free_ex_data", "CRYPTO_get_ex_data",
                                "CRYPTO_set_ex_data", "CRYPTO_alloc_ex_data")),
    ("src/runtime/thread.rs", ("CRYPTO_THREAD_", "CRYPTO_atomic_", "CRYPTO_ONCE",
                               "CRYPTO_THREAD_run_once", "OSSL_get_max_threads",
                               "OSSL_set_max_threads",
                               "OSSL_get_thread_support_flags", "OSSL_sleep",
                               "OPENSSL_thread_stop")),
    ("src/runtime/trace.rs", ("OSSL_trace_",)),
    ("src/runtime/init.rs", ("OPENSSL_init", "OPENSSL_cleanup", "OpenSSL_version",
                             "OPENSSL_version", "OpenSSL_version_num",
                             "OPENSSL_info", "OPENSSL_atexit", "OPENSSL_die",
                             "OPENSSL_fork_", "OPENSSL_INIT_")),
    # `crypto/async/`. Deferred to Phase 13 (see HANDED_ON), but the label has to name
    # where the stratum would put it, because the label is what makes a deferred row
    # readable as "this stratum's, waiting on that one".
    ("src/runtime/async/", ("ASYNC_",)),
    ("src/runtime/getenv.rs", ("OPENSSL_isservice", "OPENSSL_issetugid")),
    ("src/runtime/obj.rs", ("OBJ_", "NID_", "OBJ_NAME_")),
    # `crypto/o_str.c` and `crypto/o_dir.c`, admitted to this stratum by D51 after
    # the ownership audit found their thirteen exports in no family at all.
    ("src/runtime/str.rs", ("OPENSSL_str", "OPENSSL_hexchar2int",
                            "OPENSSL_hexstr2buf", "OPENSSL_buf2hexstr",
                            "OPENSSL_strcasecmp", "OPENSSL_strncasecmp")),
    ("src/runtime/dir.rs", ("OPENSSL_DIR_",)),
    ("src/runtime/time.rs", ("OPENSSL_gmtime",)),
]

# Symbols whose behaviour belongs to a later stratum, with the dependency that
# places it there. Every reason names a *dependency*, not a difficulty; a reason
# that does not name one is a deferral wearing a reason's clothes.
HANDED_ON: dict[str, tuple[int, str]] = {}

# The eleven BIO-coupled members of this stratum's families. Each does its job
# through a `BIO *` (or a `FILE *`) sink, and BIO is Phase 4 by the same ordering
# that puts ERR here. Phase 4 implemented every one of them, so the hand-off is
# discharged -- but it stays recorded here, because a hand-off is sticky and
# counting Phase 4's work as Phase 3's would make this ledger claim work this
# stratum did not do. See docs/DECISIONS.md D57.
HANDED_ON.update({
    sym: (4, "writes to a BIO/FILE sink; BIO is Phase 4")
    for sym in (
        "ERR_print_errors", "ERR_print_errors_cb", "ERR_print_errors_fp",
        "ERR_add_error_mem_bio",
        "OPENSSL_LH_stats", "OPENSSL_LH_stats_bio",
        "OPENSSL_LH_node_stats", "OPENSSL_LH_node_stats_bio",
        "OPENSSL_LH_node_usage_stats", "OPENSSL_LH_node_usage_stats_bio",
    )
})
HANDED_ON["OBJ_create_objects"] = (
    4, "reads an object description stream from a BIO; BIO is Phase 4",
)

# `crypto/conf/conf_lib.c`. The `OPENSSL_INIT_SETTINGS` object is an opaque handle
# over the CONF module loader's options, so the five exports that construct
# and fill it belong to the stratum that owns CONF. Phase 4 implemented them; they
# were invisible to this ledger entirely until the ownership atlas was read against
# it (D97), which is why they appear here rather than having been deferred at the
# time Phase 3 closed.
HANDED_ON.update({
    sym: (4, "constructs and fills the OPENSSL_INIT_SETTINGS handle that "
             "crypto/conf/conf_lib.c defines; CONF is Phase 4")
    for sym in (
        "OPENSSL_INIT_new", "OPENSSL_INIT_free",
        "OPENSSL_INIT_set_config_filename", "OPENSSL_INIT_set_config_appname",
        "OPENSSL_INIT_set_config_file_flags",
    )
})

# `crypto/o_time.c`. Implemented in `src/runtime/time.rs`, which is this stratum's
# own module: the ASN.1 time family in Phase 5 *calls* these three calendar
# primitives (D85), it does not own them. They were in neither ledger until D97,
# because the file was in no `FAMILIES` prefix list either.

# `crypto/async/`. The async job framework is core-runtime-shaped and is *not*
# deferred for difficulty: `OPENSSL_NO_ASYNC` is not defined in the pinned profile,
# so it is real functionality waiting for a real dependent. The authority's own tree
# shows every in-tree caller is either an asynchronous engine
# (`engines/e_dasync.c`, `engines/e_afalg.c`) or the SSL async API
# (`ssl/ssl_lib.c`), so the earliest stratum whose own obligations require it is
# Phase 13. Deferring it there names the dependency rather than the distance.
HANDED_ON.update({
    sym: (13, "the async job framework; its in-tree callers are the async engines "
              "(engines/e_dasync.c, engines/e_afalg.c) and the SSL async API, and "
              "the engines are Phase 13")
    for sym in (
        "ASYNC_WAIT_CTX_clear_fd", "ASYNC_WAIT_CTX_free",
        "ASYNC_WAIT_CTX_get_all_fds", "ASYNC_WAIT_CTX_get_callback",
        "ASYNC_WAIT_CTX_get_changed_fds", "ASYNC_WAIT_CTX_get_fd",
        "ASYNC_WAIT_CTX_get_status", "ASYNC_WAIT_CTX_new",
        "ASYNC_WAIT_CTX_set_callback", "ASYNC_WAIT_CTX_set_status",
        "ASYNC_WAIT_CTX_set_wait_fd", "ASYNC_block_pause",
        "ASYNC_cleanup_thread", "ASYNC_get_current_job", "ASYNC_get_mem_functions",
        "ASYNC_get_wait_ctx", "ASYNC_init_thread", "ASYNC_is_capable",
        "ASYNC_pause_job", "ASYNC_set_mem_functions", "ASYNC_start_job",
        "ASYNC_unblock_pause",
    )
})


def load(atlas: Path, name: str) -> dict:
    return json.loads((atlas / name).read_text(encoding="utf-8"))["body"]


def implemented() -> set[str]:
    doc = json.loads(
        (REPO_ROOT / "forensics" / "atlas" / "implemented-surface.json").read_text(
            encoding="utf-8"
        )
    )
    return set(doc["body"]["libraries"]["libcrypto"]["implemented_symbols"])


def module_of(symbol: str) -> str | None:
    for module, prefixes in MODULE_PREFIXES:
        for pre in prefixes:
            if symbol == pre or symbol.startswith(pre):
                return module
    return None


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    atlas = REPO_ROOT / "forensics" / "atlas" / auth.id
    done = implemented()

    ownership = json.loads(
        (REPO_ROOT / ATLAS_OWNERSHIP).read_text(encoding="utf-8")
    )["body"]
    mine = [r for r in ownership["records"]
            if r["owner_phase"] == 3 and r["library"] == "libcrypto"]
    if not mine:
        raise SystemExit(
            "phase3-obligations: the ownership atlas assigns this stratum no "
            "exports, which means the atlas or this tool is wrong"
        )

    unlabelled: list[str] = []
    owned: dict[str, dict] = {}
    deferred: list[dict] = []
    for row in mine:
        sym = row["symbol"]
        module = module_of(sym)
        if module is None:
            unlabelled.append(sym)
            continue
        handed = HANDED_ON.get(sym)
        if handed is not None:
            phase, reason = handed
            if phase <= 3:
                raise SystemExit(
                    f"phase3-obligations: {sym} is deferred to phase {phase}, "
                    "not later"
                )
            deferred.append({
                "symbol": sym, "owning_phase": phase, "reason": reason,
                "module": module, "declaring_header": row.get("declaring_header"),
                "implemented_by_owner": sym in done,
            })
            owned[sym] = {"module": module, "declaring_header":
                          row.get("declaring_header")}
            continue
        owned[sym] = {"module": module, "declaring_header":
                      row.get("declaring_header")}

    if unlabelled:
        raise SystemExit(
            "phase3-obligations: the ownership atlas gives this stratum exports "
            "that no entry in MODULE_PREFIXES labels, so the ledger cannot say "
            "which module is expected to hold them -- add a label:\n  "
            + "\n  ".join(sorted(unlabelled))
        )

    handed_on = {r["symbol"] for r in deferred}
    implemented_here = sorted(s for s in owned if s in done and s not in handed_on)
    open_rows = [
        {"symbol": s, "module": owned[s]["module"],
         "declaring_header": owned[s]["declaring_header"]}
        for s in sorted(owned) if s not in done and s not in handed_on
    ]

    if len(owned) != len(implemented_here) + len(handed_on) + len(open_rows):
        raise SystemExit(
            "phase3-obligations: the ledger does not account for exactly its own "
            f"projection: owned={len(owned)} implemented={len(implemented_here)} "
            f"deferred={len(handed_on)} open={len(open_rows)}"
        )

    body = {
        "rule": (
            "the stratum's scope is the projection of forensics/atlas/"
            "symbol-ownership.json for phase 3: a symbol belongs to the stratum that "
            "owns the header declaring it, `pem.h`'s typed names resolve through the "
            "type's header, the exports no installed header declares are dispositioned "
            "in ownership_rules.ABI_ONLY_OWNER, and the exports whose declaring header "
            "is too coarse are named in ownership_rules.SYMBOL_PHASE"
        ),
        "module_prefixes": [{"module": m, "prefixes": list(p)}
                            for m, p in MODULE_PREFIXES],
        "counts": {
            "atlas_owned": len(mine),
            "owned": len(owned),
            "implemented": len(implemented_here),
            "deferred_to_later_phase": len(deferred),
            "open_in_this_stratum": len(open_rows),
        },
        "implemented": implemented_here,
        "deferred": sorted(deferred, key=lambda r: r["symbol"]),
        "open": open_rows,
        "handoffs_discharged": {},
        "owned_by_module": dict(
            sorted(Counter(v["module"] for v in owned.values()).items())
        ),
        "deferred_by_phase": dict(
            sorted(Counter(r["owning_phase"] for r in deferred).items())
        ),
        "complete": not open_rows,
        "note": (
            "A deferred symbol is a recorded hand-off to the phase that owns the "
            "subsystem it needs, not a parity claim, and the hand-off is sticky: the "
            "owning stratum implementing it later does not move the obligation back "
            "here (`implemented_by_owner` records that the hand-off has been "
            "discharged). `open` is the only list that blocks the stratum, and it is "
            "the whole reason this stratum returns to `in-progress` after D97. "
            "Nothing here is a parity claim."
        ),
    }

    inputs = [
        InputRef(name="authority-symbols",
                 path=atlas / "symbols-libcrypto.json"),
        InputRef(name="symbol-ownership", path=REPO_ROOT / ATLAS_OWNERSHIP),
        implemented_surface_input(),
    ]
    doc = envelope(kind="phase3-obligations", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    c = body["counts"]
    print(f"[phase3-obligations] atlas={c['atlas_owned']} owned={c['owned']} "
          f"implemented={c['implemented']} deferred={c['deferred_to_later_phase']} "
          f"open={c['open_in_this_stratum']}")
    print(f"  complete={body['complete']}")
    print(f"  owned by module: {body['owned_by_module']}")
    print(f"  deferred by phase: {body['deferred_by_phase']}")
    for row in open_rows[:40]:
        print(f"  OPEN {row['symbol']} [{row['module']}]")
    if len(open_rows) > 40:
        print(f"  ... and {len(open_rows) - 40} more")
    print(f"  -> {rel(OUT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
