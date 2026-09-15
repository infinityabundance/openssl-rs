#!/usr/bin/env python3
"""openssl-rs — the Phase 6 obligation ledger, and it is a *projection*.

Phase 6 is `OSSL_LIB_CTX` and the provider core. `docs/PROVIDER_MODEL.md` is its
constitution, and `docs/PHASE-6-SUBPHASES.md` is its plan. This ledger is the
machine-checkable arithmetic behind both.

This ledger does not decide its own universe
--------------------------------------------
The universe comes from `forensics/atlas/symbol-ownership.json`, which assigns every
one of the authority's 6,499 exports to exactly one stratum by one stated rule
(`forensics/tools/ownership_rules.py`, D72). This file selects the rows the atlas
assigns to Phase 6 and reports them, and it adds the symbols earlier strata handed
over -- a stratum's ledger has to contain the work it owes *and* the work it built.

Four situations, kept apart
---------------------------
  * **implemented** -- the crate defines the symbol.
  * **open** -- this stratum's, not built yet. The only list that blocks the stratum.
    Phase 6 starts with every one of its 156 owned exports here, which is the honest
    starting state and is what `docs/PHASE-6-SUBPHASES.md` §1 records.
  * **deferred** -- a recorded hand-off to a later stratum with the dependency named.
  * **handoffs_discharged** -- the reverse edge: symbols Phase 4 and Phase 5 handed to
    this one.

The prefix table below is a *label* -- which module is expected to hold a symbol --
not a discovery mechanism, and an unlabelled symbol is a hard failure rather than a
row filed under "other".

Outputs
-------
  forensics/phase6-obligations.json

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

OUT = REPO_ROOT / "forensics" / "phase6-obligations.json"
GENERATOR = "forensics/tools/phase6_obligations.py"
ATLAS_OWNERSHIP = "forensics/atlas/symbol-ownership.json"

# Which module of the stratum is expected to hold a symbol. A **label**: the universe
# comes from the atlas, and `main` fails when any symbol the atlas gives this stratum
# fits no entry here.
MODULE_PREFIXES: list[tuple[str, tuple[str, ...]]] = [
    ("src/context/mod.rs", ("OSSL_LIB_CTX_",)),
    ("src/params/build.rs", ("OSSL_PARAM_BLD_",)),
    ("src/params/mod.rs", ("OSSL_PARAM_",)),
    ("src/provider/mod.rs", ("OSSL_PROVIDER_",)),
    ("src/selftest/indicator.rs", ("OSSL_INDICATOR_",)),
    ("src/selftest/mod.rs", ("OSSL_SELF_TEST_",)),
    ("src/dso/mod.rs", ("DSO_",)),
    ("src/confmod/mod.rs", ("CONF_", "OPENSSL_load_builtin_modules")),
    ("src/confmod/asn1.rs", ("ASN1_add_oid_module",)),
    ("src/context/core_bio.rs", ("BIO_s_core", "BIO_new_from_core_bio")),
    # The five Phase 3 handed over. They are labels for rows this stratum *owes*,
    # and they name where the machinery each one needs lives: the library context
    # and its thread slot, and the loader `OPENSSL_atexit` pins through.
    ("src/context/thread_data.rs", ("OSSL_get_max_threads", "OSSL_set_max_threads",
                                    "OPENSSL_thread_stop", "OPENSSL_thread_stop_ex")),
    ("src/dso/mod.rs", ("OPENSSL_atexit",)),
]

# Symbols earlier strata hand to this one. Each edge is declared here as discharged
# *and* recorded in the deferring stratum's `deferred` list; `ownership_audit.py`
# reconciles the two readings in both directions, so an edge that exists on only one
# side fails the audit rather than sitting half-recorded.
#
# Phase 4's seventeen are `crypto/conf/conf_mod.c` and the two core-BIO bindings: the
# module registry cannot be built without the library context or the loader, and the
# core BIO is what a provider uses to write to a BIO the application created. Phase
# 4's eighteenth, `OPENSSL_load_builtin_modules`, is the registry's own registration
# loop. Phase 5's one is `ASN1_add_oid_module`, which registers a `CONF_MODULE` and
# therefore needs `CONF_module_add`.
HANDED_OFF_IN: dict[int, tuple[str, ...]] = {
    4: (
        "BIO_new_from_core_bio",
        "BIO_s_core",
        "CONF_imodule_get_flags",
        "CONF_imodule_get_module",
        "CONF_imodule_get_name",
        "CONF_imodule_get_usr_data",
        "CONF_imodule_get_value",
        "CONF_imodule_set_flags",
        "CONF_imodule_set_usr_data",
        "CONF_module_add",
        "CONF_module_get_usr_data",
        "CONF_module_set_usr_data",
        "CONF_modules_finish",
        "CONF_modules_load",
        "CONF_modules_load_file",
        "CONF_modules_load_file_ex",
        "CONF_modules_unload",
        "OPENSSL_load_builtin_modules",
    ),
    5: ("ASN1_add_oid_module",),
    # Phase 3's five, deferred by 6.0 rather than by the stratum at seal time: the
    # reconnaissance found them `open` in Phase 3's ledger, and the dependencies
    # below are what moved them. Each was read from the authority's source rather
    # than guessed -- `crypto/thread/api.c` for the two count accessors,
    # `crypto/initthread.c` for the thread-stop pair, and `crypto/init.c`'s DSO
    # pinning block for `OPENSSL_atexit`.
    3: (
        "OPENSSL_atexit",
        "OPENSSL_thread_stop",
        "OPENSSL_thread_stop_ex",
        "OSSL_get_max_threads",
        "OSSL_set_max_threads",
    ),
}

# Symbols of the projection this stratum owns and hands to a later one, with the
# dependency that places them there. Empty at the start of the stratum: everything
# Phase 6 owns, it implements. A future row here must name a dependency, not a
# distance.
HANDED_ON: dict[str, tuple[int, str]] = {}


def load(atlas: Path, name: str) -> dict:
    return json.loads((atlas / name).read_text(encoding="utf-8"))["body"]


def implemented() -> set[str]:
    doc = json.loads(
        (REPO_ROOT / "forensics" / "atlas" / "implemented-surface.json").read_text(
            encoding="utf-8"
        )
    )
    return set(doc["body"]["libraries"]["libcrypto"]["implemented_symbols"])


def declared_headers(atlas: Path) -> dict[str, str]:
    return {r["name"]: r["header"] for r in load(atlas, "functions.json")["records"]}


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
    headers = declared_headers(atlas)

    ownership = json.loads(
        (REPO_ROOT / ATLAS_OWNERSHIP).read_text(encoding="utf-8")
    )["body"]
    mine = [r for r in ownership["records"]
            if r["owner_phase"] == 6 and r["library"] == "libcrypto"]
    if not mine:
        raise SystemExit(
            "phase6-obligations: the ownership atlas assigns this stratum no "
            "exports, which means the atlas or this tool is wrong"
        )

    owned: dict[str, dict] = {}

    def claim(sym: str, header: str | None) -> None:
        owned[sym] = {"module": module_of(sym), "declaring_header": header}

    for row in mine:
        claim(row["symbol"], row.get("declaring_header"))

    for source, symbols in sorted(HANDED_OFF_IN.items()):
        for sym in symbols:
            if sym in owned:
                continue
            owned[sym] = {
                "module": module_of(sym),
                "declaring_header": headers.get(sym),
            }

    unlabelled = sorted(s for s, v in owned.items() if v["module"] is None)
    if unlabelled:
        raise SystemExit(
            "phase6-obligations: the ownership atlas gives this stratum (or an earlier "
            "stratum handed it) exports that no entry in MODULE_PREFIXES labels, so "
            "the ledger cannot say which module is expected to hold them -- add a "
            "label:\n  " + "\n  ".join(unlabelled)
        )

    deferred: list[dict] = []
    for sym in sorted(owned):
        handed = HANDED_ON.get(sym)
        if handed is None:
            continue
        phase, reason = handed
        if phase <= 6:
            raise SystemExit(
                f"phase6-obligations: {sym} is deferred to phase {phase}, not later"
            )
        deferred.append({
            "symbol": sym, "owning_phase": phase, "reason": reason,
            "module": owned[sym]["module"],
            "declaring_header": owned[sym]["declaring_header"],
            "implemented_by_owner": sym in done,
        })

    handed_on = {r["symbol"] for r in deferred}
    implemented_here = sorted(s for s in owned if s in done and s not in handed_on)
    open_rows = [
        {"symbol": s, "module": owned[s]["module"],
         "declaring_header": owned[s]["declaring_header"]}
        for s in sorted(owned) if s not in done and s not in handed_on
    ]

    if len(owned) != len(implemented_here) + len(handed_on) + len(open_rows):
        raise SystemExit(
            "phase6-obligations: the ledger does not account for exactly its own "
            f"working set: owned={len(owned)} implemented={len(implemented_here)} "
            f"deferred={len(handed_on)} open={len(open_rows)}"
        )

    body = {
        "rule": (
            "the stratum's working set is the projection of forensics/atlas/"
            "symbol-ownership.json for phase 6, plus the symbols Phases 4 and 5 handed "
            "it: a symbol belongs to the stratum that owns the header declaring it, and "
            "a discharged hand-off belongs to the stratum that built it"
        ),
        "module_prefixes": [{"module": m, "prefixes": list(p)}
                            for m, p in MODULE_PREFIXES],
        "counts": {
            "atlas_owned": len(mine),
            "received_by_handoff": sum(len(v) for v in HANDED_OFF_IN.values()),
            "owned": len(owned),
            "implemented": len(implemented_here),
            "deferred_to_later_phase": len(deferred),
            "open_in_this_stratum": len(open_rows),
        },
        "implemented": implemented_here,
        "deferred": sorted(deferred, key=lambda r: r["symbol"]),
        "open": open_rows,
        "handoffs_discharged": {
            str(source): sorted(syms) for source, syms in sorted(HANDED_OFF_IN.items())
        },
        "owned_by_module": dict(
            sorted(Counter(v["module"] for v in owned.values()).items())
        ),
        "deferred_by_phase": dict(
            sorted(Counter(r["owning_phase"] for r in deferred).items())
        ),
        "complete": not open_rows,
        "note": (
            "`complete` is true only when every export in the working set is either "
            "implemented or handed to a later stratum. `open` is the only list that "
            "blocks the stratum. Nothing here is a parity claim: a symbol in "
            "`implemented` is at most `IMPLEMENTED` in docs/PARITY_MODEL.md terms, and "
            "docs/PROVIDER_MODEL.md §5 decides when the stratum may be called complete."
        ),
    }

    inputs = [
        InputRef(name="authority-symbols", path=atlas / "symbols-libcrypto.json"),
        InputRef(name="authority-functions", path=atlas / "functions.json"),
        InputRef(name="symbol-ownership", path=REPO_ROOT / ATLAS_OWNERSHIP),
        implemented_surface_input(),
    ]
    doc = envelope(kind="phase6-obligations", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    c = body["counts"]
    print(f"[phase6-obligations] atlas={c['atlas_owned']} "
          f"received={c['received_by_handoff']} owned={c['owned']} "
          f"implemented={c['implemented']} deferred={c['deferred_to_later_phase']} "
          f"open={c['open_in_this_stratum']}")
    print(f"  complete={body['complete']}")
    print(f"  owned by module: {body['owned_by_module']}")
    print(f"  -> {rel(OUT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
