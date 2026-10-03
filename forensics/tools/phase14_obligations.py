#!/usr/bin/env python3
"""openssl-rs — the Phase 14 obligation ledger, and it is a *projection*.

Phase 14 is the TLS/DTLS stratum: the whole of `libssl` -- the `SSL_CTX`/`SSL` object model, the
`TLS_*`/`DTLS_*` method and version tables, the record layer, the handshake state machine, the
BIO pair, the session/certificate plumbing and the DTLS and QUIC bridges. Its name in
`docs/RELEASE_GATES.md` section 1 is "TLS / DTLS (`libssl`)". `docs/PHASE-14-SUBPHASES.md` is its
plan and this ledger is the machine-checkable arithmetic behind it.

This ledger does not decide its own universe
--------------------------------------------
The universe comes from `forensics/atlas/symbol-ownership.json`, which assigns every one of the
authority's exports to exactly one stratum by one stated rule (`forensics/tools/ownership_rules.py`,
D72). This file selects the rows the atlas assigns to Phase 14 and reports them, and it adds the
symbols earlier strata handed over.

**The atlas gives Phase 14 600 exports, all `libssl`, over four headers** -- `ssl.h` (582),
`tls1.h` (13), `srtp.h` (4) and `sslerr_legacy.h` (1) -- and **no earlier stratum hands it a
symbol**: every row of every `forensics/phase*-obligations.json` whose `owning_phase` is 14 is
discovered rather than listed, and there are none. Phase 14 is the first stratum whose working set
is exactly the atlas projection -- there is no recorded edge into it, so `received_by_handoff`
reads 0 and the discovery is reported rather than assumed.

**This stratum is also the first whose whole working set is open at activation, and that is the
finding this ledger exists to make visible.** `libssl` is the candidate distribution's second
namespace: the crate's archive carries no `libssl` symbol, `forensics/atlas/implemented-surface.json`
records `implemented: 0` for it, and every one of the 603 `libssl` exports the authority defines is
present in the candidate only as the Phase 2 ABI scaffold
(`artifacts/phase2/shell/libssl.shell.rs`), which aborts when called. So not one of the 600 is
`implemented` at activation, and the ledger's `implemented` count is `0` and its `open` count is the
whole working set -- unlike every earlier activation, which inherited landings. The split moves as
this stratum lands its own units, so this docstring does not restate its counts -- the `counts`
block below is the live record.

The edges are discovered rather than typed: every row of every `forensics/phase*-obligations.json`
whose `owning_phase` is 14, so a stratum that defers a symbol to this one is recorded on both sides
by construction.

**This stratum ships no provider registration row**, and the census records where the provider rows
went: reading `forensics/atlas/provider-algorithms.json` for `owning_phase == 14` yields nothing,
because libssl is not a provider and this stratum activates none. `provider_rows_owned` therefore
reads `0` -- the mirror of Phases 12 and 13.

Four situations, kept apart
---------------------------
  * **implemented** -- the crate defines the symbol.
  * **open** -- this stratum's, not built yet. The only list that blocks the stratum.
  * **deferred** -- a recorded hand-off to a later stratum with the dependency named.
  * **handoffs_discharged** -- the reverse edge, discovered above.

Outputs
-------
  forensics/phase14-obligations.json

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

OUT = REPO_ROOT / "forensics" / "phase14-obligations.json"
GENERATOR = "forensics/tools/phase14_obligations.py"
PHASE = 14
ATLAS_OWNERSHIP = "forensics/atlas/symbol-ownership.json"
DEFINING_UNITS = "forensics/atlas/export-defining-units.json"
PROVIDER_ALGORITHMS = "forensics/atlas/provider-algorithms.json"

# Which crate module is expected to hold a symbol. **A label, and here the label is the
# authority translation unit that defines it.** `forensics/atlas/export-defining-units.json`
# records that unit for every export, and the crate lays one module out per unit
# (`ssl/ssl_lib.c` -> `src/ssl/ssl_lib.rs`), so the unit *is* the label. Phase 10 could write its
# labels as a short symbol-prefix table because its three areas mapped to three modules; Phase 14's
# 600 symbols are defined across twenty-nine units under `ssl/`, `ssl/record/`, `ssl/statem/`,
# `ssl/quic/` and `ssl/rio/`, so a prefix table here would be the atlas restated as many hand-typed
# entries -- a second thing to keep true. `MODULE_OVERRIDES` is kept only for the exceptions, a
# symbol whose crate module the unit layout does not name, and it is **empty** because measurement
# finds none.
MODULE_OVERRIDES: list[tuple[str, tuple[str, ...]]] = []


# ---------------------------------------------------------------------------------------------
# The blocked hand-offs. **Empty, and here that is a measurement rather than an omission.**
#
# The rule is Phase 8's through Phase 13's: a symbol whose declaring header is this stratum's but
# whose *body* needs a name no module of this crate defines is recorded here with the reason naming
# the callee, the authority file and line the call sits on, and the stratum that owns the callee.
# Phase 14 is the whole of `libssl`, and every symbol in its working set is defined by a unit under
# `ssl/`; its bodies reach `libcrypto` (Phase 7's `EVP`, Phase 8's primitives, Phase 11's X.509),
# but those strata are all `complete`, so nothing here is withheld on a name that does not exist.
# The table is therefore empty, and the mechanism below is kept true rather than deleted.
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
    exactly like "no stratum deferred anything to Phase 14". **For this stratum that reading is the
    measurement**: libssl is a self-contained namespace and no earlier stratum's ledger records an
    `owning_phase == 14` row, so the block is empty because the discovery ran, not because it could
    not.
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
            "phase14-obligations: no earlier stratum's ledger is readable, so the incoming "
            "hand-off set would be empty for the wrong reason"
        )
    return out


def crate_module(unit: str) -> str:
    """The crate module the authority unit is laid out as: `<dir>/<stem>.c` -> `src/<dir>/<stem>.rs`.

    The `crypto/` prefix is **dropped** where it is present, because the crate's tree is
    `src/engine/`, `src/ui/`, ... -- one directory per authority *subdirectory* of `crypto/`,
    exactly as `crypto/engine/eng_lib.c` is `src/engine/eng_lib.rs`. `libssl`'s units keep their
    `ssl/` prefix, because the crate lays them out under `src/ssl/` the same way the authority
    lays them out under `ssl/`: `ssl/ssl_lib.c` -> `src/ssl/ssl_lib.rs` and
    `ssl/record/rec_layer_s3.c` -> `src/ssl/record/rec_layer_s3.rs`. A unit outside both trees
    (none in this stratum) keeps its own path, which is what the mapping below does by only
    stripping `crypto/` when it is there.
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
            "phase14-obligations: the ownership atlas assigns this stratum no exports, "
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
                    f"phase14-obligations: {sym} is both the atlas's for phase {PHASE} and "
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
            "phase14-obligations: the ownership atlas gives this stratum (or an earlier "
            "stratum handed it) exports that no authority translation unit in "
            f"{DEFINING_UNITS} defines, so the ledger cannot say which module is expected to "
            "hold them -- add a label:\n  "
            + "\n  ".join(f"{s}  ({owned[s]['declaring_header']})" for s in unlabelled)
        )

    # The fail-closed deferral mechanism, unchanged from Phases 8 through 13: a symbol in
    # `BLOCKED_HANDOFFS` that the crate now defines is a stale row rather than a harmless one,
    # because a table that can keep covering a landed symbol can hide the next real gap behind it.
    # This stratum's table is empty -- it hands nothing onward -- so the loop is the mechanism
    # kept true rather than a claim of emptiness.
    blocked: dict[str, dict] = {}
    for symbols, phase, reason in BLOCKED_HANDOFFS:
        for sym in symbols:
            if sym not in owned:
                raise SystemExit(
                    f"phase14-obligations: BLOCKED_HANDOFFS names {sym}, which is not in this "
                    f"stratum's working set (or is not an authority export at all)"
                )
            if sym in done:
                raise SystemExit(
                    f"phase14-obligations: BLOCKED_HANDOFFS records {sym} as blocked on phase "
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
            "phase14-obligations: the ledger does not account for exactly its own working "
            f"set: owned={len(owned)} implemented={len(implemented_here)} "
            f"deferred={len(deferred_names)} open={len(open_rows)}"
        )

    # The provider registration rows this stratum owns, read from the census's own
    # `owning_phase`. Phase 14 ships no provider row: libssl is not a provider and this stratum
    # activates none, so the slice is empty. The count is emitted rather than omitted so a reader
    # need not infer it.
    provider_doc = json.loads((REPO_ROOT / PROVIDER_ALGORITHMS).read_text(encoding="utf-8"))
    provider_owned = [
        r for r in provider_doc["body"]["rows"] if r["owning_phase"] == PHASE
    ]

    body = {
        "rule": (
            "the stratum's working set is the projection of forensics/atlas/"
            "symbol-ownership.json for phase 14, plus every symbol an earlier stratum's "
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
        # The provider-row census's phase-14 slice. Empty, measured.
        "provider_rows_owned": len(provider_owned),
        "complete": not open_rows,
        "note": (
            "`complete` is true only when every export in the working set is either "
            "implemented or handed to a later stratum. `open` is the only list that blocks "
            "the stratum. Phase 14's working set is exactly its atlas-owned universe -- 600 "
            "`libssl` exports over `ssl.h` (582), `tls1.h` (13), `srtp.h` (4) and "
            "`sslerr_legacy.h` (1) -- and no earlier stratum defers a symbol to it, so "
            "`received_by_handoff` is 0. **Unlike every earlier activation, not one symbol is "
            "implemented at activation**: libssl is the candidate distribution's second "
            "namespace, its exports are present only as the Phase 2 ABI scaffold, and "
            "`forensics/atlas/implemented-surface.json` records `implemented: 0` for libssl, "
            "so the ledger's `implemented` count is 0 and its `open` count is the whole "
            "working set. That split moves as this stratum lands its own units, so this note "
            "does not restate its counts; `counts` above is the live record and "
            "`forensics/atlas/implemented-surface.json` is the authority behind it. This "
            "stratum ships no provider registration row: libssl is not a provider and this "
            "stratum activates none. Nothing here is a parity claim: a symbol in "
            "`implemented` would be at most `IMPLEMENTED` in docs/PARITY_MODEL.md terms, and "
            "docs/PHASE-14-SUBPHASES.md section 4 decides when the stratum may be called "
            "complete."
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
    doc = envelope(kind="phase14-obligations", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    c = body["counts"]
    print(f"[phase14-obligations] atlas={c['atlas_owned']} "
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
