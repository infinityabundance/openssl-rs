#!/usr/bin/env python3
"""openssl-rs — the Phase 15 obligation ledger, and it is a *projection*.

Phase 15 is the QUIC/ECH stratum: the modern `libssl` surface the atlas gives the `quic.h`
declaring header. Its name in `docs/RELEASE_GATES.md` section 1 is "QUIC / ECH and modern SSL
surface". `docs/PHASE-15-SUBPHASES.md` is its plan and this ledger is the machine-checkable
arithmetic behind it.

This ledger does not decide its own universe
--------------------------------------------
The universe comes from `forensics/atlas/symbol-ownership.json`, which assigns every one of the
authority's exports to exactly one stratum by one stated rule (`forensics/tools/ownership_rules.py`,
D72). This file selects the rows the atlas assigns to Phase 15 and reports them, and it adds the
symbols earlier strata handed over.

**The atlas gives Phase 15 exactly three exports, all `libssl`, over one header** — `quic.h`:
`OSSL_QUIC_client_method`, `OSSL_QUIC_client_thread_method` and `OSSL_QUIC_server_method`.
**No earlier stratum hands it a symbol**: the ledger discovers the edges rather than listing them,
and no `forensics/phase*-obligations.json` records an `owning_phase == 15` row. Phase 14's plan and
seal name the three as this stratum's by their declaring header
(`docs/PHASE-14-SUBPHASES.md` sections 1 and 4.1, `docs/PHASE-14-TLS-SEAL.md` section 9), and
`forensics/prerequisites.json` defers two *authority units* (`ssl/statem/statem_clnt.c` and
`ssl/statem/statem_srvr.c`) to this stratum's engine; a unit deferral is not an export hand-off, so
it does not move this ledger's `received_by_handoff`.

**This stratum inherits a landed `libssl` substrate and lands its own three constructors on it.**
Phase 14 is `complete`, so `forensics/atlas/implemented-surface.json` already records its 600
`libssl` exports as implemented; the three `quic.h` names were the only `libssl` exports that
stratum did not own, and at activation they are present only as the Phase 2 ABI scaffold
(`artifacts/phase2/shell/libssl.shell.rs`), which aborts when called. So the ledger's `open` count
opens at the whole working set — three — and moves to zero as this stratum lands them. The split
moves as the stratum lands its own units, so this docstring does not restate its counts -- the
`counts` block below is the live record.

Four situations, kept apart
---------------------------
  * **implemented** -- the crate defines the symbol.
  * **open** -- this stratum's, not built yet. The only list that blocks the stratum.
  * **deferred** -- a recorded hand-off to a later stratum with the dependency named.
  * **handoffs_discharged** -- the reverse edge, discovered above.

Outputs
-------
  forensics/phase15-obligations.json

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

OUT = REPO_ROOT / "forensics" / "phase15-obligations.json"
GENERATOR = "forensics/tools/phase15_obligations.py"
PHASE = 15
ATLAS_OWNERSHIP = "forensics/atlas/symbol-ownership.json"
DEFINING_UNITS = "forensics/atlas/export-defining-units.json"
PROVIDER_ALGORITHMS = "forensics/atlas/provider-algorithms.json"

# Which crate module is expected to hold a symbol. **A label, and here the label is the
# authority translation unit that defines it.** `forensics/atlas/export-defining-units.json`
# records that unit for every export, and the crate lays one module out per unit
# (`ssl/quic/quic_method.c` -> `src/ssl/quic/quic_method.rs`), so the unit *is* the label. All
# three of this stratum's exports are defined by `ssl/quic/quic_method.c`, so no prefix table is
# needed. `MODULE_OVERRIDES` is kept only for the exceptions, a symbol whose crate module the unit
# layout does not name, and it is **empty** because measurement finds none.
MODULE_OVERRIDES: list[tuple[str, tuple[str, ...]]] = []


# ---------------------------------------------------------------------------------------------
# The blocked hand-offs. **Empty, and here that is a measurement rather than an omission.**
#
# The rule is Phase 8's through Phase 14's: a symbol whose declaring header is this stratum's but
# whose *body* needs a name no module of this crate defines is recorded here with the reason naming
# the callee, the authority file and line the call sits on, and the stratum that owns the callee.
# This stratum's three constructors need no crate name of their own -- they build a static method
# table from constants -- so nothing here is withheld. The table is therefore empty, and the
# mechanism below is kept true rather than deleted.
# ---------------------------------------------------------------------------------------------

BLOCKED_HANDOFFS: list[tuple[tuple[str, ...], int, str]] = []


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))["body"]


def implemented() -> set[str]:
    doc = json.loads(
        (REPO_ROOT / "forensics" / "atlas" / "implemented-surface.json").read_text(
            encoding="utf-8"
        )
    )
    return set(doc["body"]["libraries"]["libssl"]["implemented_symbols"])


def declared_headers(atlas: Path) -> dict[str, str]:
    return {r["name"]: r["header"] for r in load(atlas / "functions.json")["records"]}


def defining_units() -> dict[str, str]:
    """Symbol -> the authority translation unit that defines it, from the census of units."""
    return {
        r["symbol"]: r["translation_unit"]
        for r in load(REPO_ROOT / DEFINING_UNITS)["records"]
    }


def incoming_handoffs() -> dict[int, list[dict]]:
    """Every recorded edge that hands a symbol to this stratum, read from the ledgers.

    The unit of discovery is a *row*, not a name list, so the reason and the declaring header
    travel with the symbol from wherever it was deferred and are not restated here. A ledger that
    cannot be read is a failure rather than an empty edge set: a missing file would otherwise look
    exactly like "no stratum deferred anything to Phase 15". **For this stratum that reading is the
    measurement**: no earlier stratum's ledger records an `owning_phase == 15` row, so the block is
    empty because the discovery ran, not because it could not.
    """
    out: dict[int, list[dict]] = {}
    found_any = False
    for path in sorted((REPO_ROOT / "forensics").glob("phase*-obligations.json")):
        try:
            source = int(path.stem.split("-")[0].removeprefix("phase"))
        except ValueError:
            continue
        if source >= PHASE:
            continue
        found_any = True
        for row in load(path).get("deferred", []):
            if int(row["owning_phase"]) != PHASE:
                continue
            out.setdefault(source, []).append(row)
    if not found_any:
        raise SystemExit(
            "phase15-obligations: no earlier stratum's ledger is readable, so the incoming "
            "hand-off set would be empty for the wrong reason"
        )
    return out


def crate_module(unit: str) -> str:
    """The crate module the authority unit is laid out as: `<dir>/<stem>.c` -> `src/<dir>/<stem>.rs`.

    The `crypto/` prefix is **dropped** where it is present, because the crate's tree is
    `src/engine/`, `src/ui/`, ... -- one directory per authority *subdirectory* of `crypto/`,
    exactly as `crypto/engine/eng_lib.c` is `src/engine/eng_lib.rs`. `libssl`'s units keep their
    `ssl/` prefix, because the crate lays them out under `src/ssl/` the same way the authority
    lays them out under `ssl/`: `ssl/quic/quic_method.c` -> `src/ssl/quic/quic_method.rs`. A unit
    outside both trees (none in this stratum) keeps its own path, which is what the mapping below
    does by only stripping `crypto/` when it is there.
    """
    stem = unit[len("crypto/"):] if unit.startswith("crypto/") else unit
    return "src/" + stem[:-2] + ".rs"


def module_of(symbol: str, units: dict[str, str]) -> str | None:
    for module, prefixes in MODULE_OVERRIDES:
        for pre in prefixes:
            if symbol == pre or symbol.startswith(pre):
                return module
    unit = units.get(symbol)
    if unit is None:
        return None
    return crate_module(unit)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    atlas = REPO_ROOT / "forensics" / "atlas" / auth.id
    done = implemented()
    headers = declared_headers(atlas)
    units = defining_units()

    ownership = json.loads((REPO_ROOT / ATLAS_OWNERSHIP).read_text(encoding="utf-8"))["body"]
    mine = [r for r in ownership["records"]
            if r["owner_phase"] == PHASE and r["library"] == "libssl"]
    if not mine:
        raise SystemExit(
            "phase15-obligations: the ownership atlas assigns this stratum no exports, "
            "which means the atlas or this tool is wrong"
        )

    incoming = incoming_handoffs()
    owned: dict[str, dict] = {}

    for row in mine:
        owned[row["symbol"]] = {
            "module": module_of(row["symbol"], units),
            "declaring_header": row.get("declaring_header"),
            "from": None,
        }
    for source, rows in sorted(incoming.items()):
        for row in rows:
            sym = row["symbol"]
            if sym in owned:
                raise SystemExit(
                    f"phase15-obligations: {sym} is both the atlas's for phase {PHASE} and "
                    f"deferred here by phase {source}; one of the two is wrong"
                )
            owned[sym] = {
                "module": module_of(sym, units),
                "declaring_header": row.get("declaring_header") or headers.get(sym),
                "from": source,
            }

    unlabelled = sorted(s for s, v in owned.items() if v["module"] is None)
    if unlabelled:
        raise SystemExit(
            "phase15-obligations: the ownership atlas gives this stratum (or an earlier "
            "stratum handed it) exports that no authority translation unit in "
            f"{DEFINING_UNITS} defines, so the ledger cannot say which module is expected to "
            "hold them -- add a label:\n  "
            + "\n  ".join(f"{s}  ({owned[s]['declaring_header']})" for s in unlabelled)
        )

    # The fail-closed deferral mechanism, unchanged from Phases 8 through 14: a symbol in
    # `BLOCKED_HANDOFFS` that the crate now defines is a stale row rather than a harmless one,
    # because a table that can keep covering a landed symbol can hide the next real gap behind it.
    # This stratum's table is empty -- it hands nothing onward -- so the loop is the mechanism
    # kept true rather than a claim of emptiness.
    blocked: dict[str, dict] = {}
    for symbols, phase, reason in BLOCKED_HANDOFFS:
        for sym in symbols:
            if sym not in owned:
                raise SystemExit(
                    f"phase15-obligations: BLOCKED_HANDOFFS names {sym}, which is not in this "
                    f"stratum's working set (or is not an authority export at all)"
                )
            if sym in done:
                raise SystemExit(
                    f"phase15-obligations: BLOCKED_HANDOFFS records {sym} as blocked on phase "
                    f"{phase}, but the crate defines it; retire the row"
                )
            blocked[sym] = {
                "symbol": sym,
                "owning_phase": phase,
                "declaring_header": owned[sym]["declaring_header"],
                "reason": reason,
            }
    deferred_names = set(blocked)
    deferred: list[dict] = sorted(blocked.values(), key=lambda r: r["symbol"])

    implemented_here = sorted(s for s in owned if s in done and s not in deferred_names)
    open_rows = [
        {"symbol": s, "module": owned[s]["module"],
         "declaring_header": owned[s]["declaring_header"],
         "received_from_phase": owned[s]["from"]}
        for s in sorted(owned) if s not in done and s not in deferred_names
    ]

    if len(owned) != len(implemented_here) + len(deferred_names) + len(open_rows):
        raise SystemExit(
            "phase15-obligations: the ledger does not account for exactly its own working "
            f"set: owned={len(owned)} implemented={len(implemented_here)} "
            f"deferred={len(deferred_names)} open={len(open_rows)}"
        )

    # The provider registration rows this stratum owns, read from the census's own
    # `owning_phase`. Phase 15 ships no provider row: QUIC is not a provider and this stratum
    # activates none, so the slice is empty. The count is emitted rather than omitted so a reader
    # need not infer it.
    provider_doc = json.loads((REPO_ROOT / PROVIDER_ALGORITHMS).read_text(encoding="utf-8"))
    provider_owned = [
        r for r in provider_doc["body"]["rows"] if r["owning_phase"] == PHASE
    ]

    body = {
        "rule": (
            "the stratum's working set is the projection of forensics/atlas/"
            "symbol-ownership.json for phase 15, plus every symbol an earlier stratum's "
            "ledger records as handed to it: a symbol belongs to the stratum that owns the "
            "header declaring it, and a discharged hand-off belongs to the stratum that "
            "built it"
        ),
        "module_label_rule": (
            "the module a symbol is expected in is the crate's layout of the authority "
            "translation unit that defines it (forensics/atlas/export-defining-units.json): "
            "crypto/<dir>/<stem>.c -> src/<dir>/<stem>.rs, and ssl/<dir>/<stem>.c -> "
            "src/ssl/<dir>/<stem>.rs. A **label**: the universe comes from the ownership "
            "atlas, and `main` fails when any symbol the atlas gives this stratum (or an "
            "earlier one hands it) has no defining unit"
        ),
        "module_overrides": [{"module": m, "prefixes": list(p)}
                             for m, p in MODULE_OVERRIDES],
        "counts": {
            "atlas_owned": len(mine),
            "received_by_handoff": sum(len(v) for v in incoming.values()),
            "owned": len(owned),
            "implemented": len(implemented_here),
            "deferred_to_later_phase": len(deferred),
            "open_in_this_stratum": len(open_rows),
        },
        "implemented": implemented_here,
        "deferred": deferred,
        "open": open_rows,
        "handoffs_discharged": {
            str(source): sorted(row["symbol"] for row in rows)
            for source, rows in sorted(incoming.items())
        },
        # The reasons, kept as they were written by the stratum that deferred them rather than
        # restated: a second statement of the same reason is a second thing to keep true, and
        # `ownership_audit.py` compares the two sides already.
        "handoffs_discharged_with_reasons": {
            str(source): sorted(rows, key=lambda r: r["symbol"])
            for source, rows in sorted(incoming.items())
        },
        "owned_by_module": dict(sorted(Counter(v["module"] for v in owned.values()).items())),
        "owned_by_header": dict(
            sorted(Counter(v["declaring_header"] or "(none)"
                           for v in owned.values()).items())
        ),
        "deferred_by_phase": dict(
            sorted(Counter(r["owning_phase"] for r in deferred).items())
        ),
        # The provider-row census's phase-15 slice. Empty, measured.
        "provider_rows_owned": len(provider_owned),
        "complete": not open_rows,
        "note": (
            "`complete` is true only when every export in the working set is either "
            "implemented or handed to a later stratum. `open` is the only list that blocks "
            "the stratum. **`complete` here is the ledger-level emptiness check, not the "
            "phase-exit predicate**: like Phase 14 (docs/DECISIONS.md D529), this stratum is "
            "not complete until its seal and its FRF/Gemel chain land, so a reader must not "
            "read the ledger's `complete` as the stratum's state -- `forensics/phase-state.json` "
            "is where that is derived. Phase 15's working set is exactly its atlas-owned "
            "universe -- the three `quic.h` exports `OSSL_QUIC_client_method`, "
            "`OSSL_QUIC_client_thread_method` and `OSSL_QUIC_server_method` -- and no earlier "
            "stratum defers a symbol to it, so `received_by_handoff` is 0. The two authority "
            "*units* `forensics/prerequisites.json` defers to this stratum's engine "
            "(`ssl/statem/statem_clnt.c` and `ssl/statem/statem_srvr.c`) are unit deferrals, "
            "not export hand-offs, and do not move that count. This stratum ships no provider "
            "registration row: QUIC is not a provider and this stratum activates none. Nothing "
            "here is a parity claim: a symbol in `implemented` would be at most `IMPLEMENTED` "
            "in docs/PARITY_MODEL.md terms, and docs/PHASE-15-SUBPHASES.md section 4 decides "
            "when the stratum may be called complete."
        ),
    }

    inputs = [
        InputRef(name="authority-symbols", path=atlas / "symbols-libssl.json"),
        InputRef(name="authority-functions", path=atlas / "functions.json"),
        InputRef(name="symbol-ownership", path=REPO_ROOT / ATLAS_OWNERSHIP),
        InputRef(name="export-defining-units", path=REPO_ROOT / DEFINING_UNITS),
        InputRef(name="provider-algorithms", path=REPO_ROOT / PROVIDER_ALGORITHMS),
        implemented_surface_input(),
        *[
            InputRef(name=f"phase{source}-obligations",
                     path=REPO_ROOT / f"forensics/phase{source}-obligations.json")
            for source in sorted(incoming)
        ],
    ]
    doc = envelope(kind="phase15-obligations", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    c = body["counts"]
    print(f"[phase15-obligations] atlas={c['atlas_owned']} "
          f"received={c['received_by_handoff']} owned={c['owned']} "
          f"implemented={c['implemented']} deferred={c['deferred_to_later_phase']} "
          f"open={c['open_in_this_stratum']}")
    print(f"  complete={body['complete']}  provider_rows_owned={body['provider_rows_owned']}")
    print(f"  owned by header: {body['owned_by_header']}")
    print(f"  hand-offs discharged: "
          f"{ {k: len(v) for k, v in body['handoffs_discharged'].items()} }")
    print(f"  -> {rel(OUT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
