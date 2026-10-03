#!/usr/bin/env python3
"""openssl-rs — the Phase 13 obligation ledger, and it is a *projection*.

Phase 13 is the legacy/deprecated-compatibility stratum: the `ENGINE` framework, the `UI`
dialog framework, the `TXT_DB` text database the `ca` app reads, and the deprecated
METHOD-era surface the earlier strata hand it rather than transcribe. Its name in
`docs/RELEASE_GATES.md` section 1 is "Legacy / deprecated compatibility".
`docs/PHASE-13-SUBPHASES.md` is its plan and this ledger is the machine-checkable arithmetic
behind it.

This ledger does not decide its own universe
--------------------------------------------
The universe comes from `forensics/atlas/symbol-ownership.json`, which assigns every one of
the authority's 6,499 exports to exactly one stratum by one stated rule
(`forensics/tools/ownership_rules.py`, D72). This file selects the rows the atlas assigns to
Phase 13 and reports them, and it adds the symbols earlier strata handed over.

**The atlas gives Phase 13 189 exports, all `libcrypto`, over three headers** -- `engine.h`
(121), `ui.h` (62) and `txt_db.h` (6) -- and **188 more arrive as recorded edges**: the
`owning_phase 13` rows every earlier stratum's ledger records, which this file discovers rather
than lists. They are the deprecated METHOD-era surface the strata that own the underlying
algorithm declare but hand here: 163 `evp.h`/`pem.h` legacy `EVP_CIPHER`/`EVP_MD` statics and
the four `PEM_read[_bio]_PrivateKey` spellings from Phase 7, 22 `async.h` names from Phase 3,
and the three Phase 12 handed over -- `TS_CONF_set_crypto_device`/`TS_CONF_set_default_engine`
(`ts.h`, blocked on `ENGINE_by_id`/`ENGINE_set_default`) and `SRP_VBASE_init` (`srp.h`, blocked
on `TXT_DB_read`/`TXT_DB_free`).

**The ledger does not start with its whole working set open**, and that is the finding this
ledger exists to make visible: 123 of the atlas-owned exports -- most of the `engine.h` and
`ui.h` object and accessor surface -- were landed before activation as substrate the earlier
strata needed, and the four Phase 7 -> 13 `PEM_read[_bio]_PrivateKey` hand-offs are already
implemented (Phase 8 landed them, D369). The split moves as this stratum lands its own units,
so this docstring does not restate its counts -- the `counts` block below is the live record.

The edges are discovered rather than typed: every row of every `forensics/phase*-obligations.json`
whose `owning_phase` is 13, so a stratum that defers a symbol to this one is recorded on both
sides by construction.

**This stratum owns provider registration rows**, and the census's phase-13 slice is the 39
legacy digest and cipher rows (`forensics/atlas/provider-algorithms.json`), all unimplemented
at activation. Unlike Phase 12, whose slice of that census is empty, this ledger records the
count it reads rather than leaving a reader to infer it.

Four situations, kept apart
---------------------------
  * **implemented** -- the crate defines the symbol.
  * **open** -- this stratum's, not built yet. The only list that blocks the stratum.
  * **deferred** -- a recorded hand-off to a later stratum with the dependency named.
  * **handoffs_discharged** -- the reverse edge, discovered above.

Outputs
-------
  forensics/phase13-obligations.json

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

OUT = REPO_ROOT / "forensics" / "phase13-obligations.json"
GENERATOR = "forensics/tools/phase13_obligations.py"
PHASE = 13
ATLAS_OWNERSHIP = "forensics/atlas/symbol-ownership.json"
DEFINING_UNITS = "forensics/atlas/export-defining-units.json"
PROVIDER_ALGORITHMS = "forensics/atlas/provider-algorithms.json"

# Which crate module is expected to hold a symbol. **A label, and here the label is the
# authority translation unit that defines it.** `forensics/atlas/export-defining-units.json`
# records that unit for every export, and the crate lays one module out per unit
# (`crypto/engine/eng_lib.c` -> `src/engine/eng_lib.rs`), so the unit *is* the label. Phase 10
# could write its labels as a short symbol-prefix table because its three areas mapped to three
# modules; Phase 13's 377 symbols are defined across `crypto/engine/`, `crypto/ui/`,
# `crypto/txt_db/`, the legacy `crypto/evp/` statics, `crypto/async/` and `crypto/pem/`, so a
# prefix table here would be the atlas restated as many hand-typed entries -- a second thing to
# keep true. `MODULE_OVERRIDES` is kept only for the exceptions, a symbol whose crate module the
# unit layout does not name, and it is **empty** because measurement finds none.
MODULE_OVERRIDES: list[tuple[str, tuple[str, ...]]] = []


# ---------------------------------------------------------------------------------------------
# The blocked hand-offs. **Empty, and here that is a measurement rather than an omission.**
#
# The rule is Phase 8's through Phase 12's: a symbol whose declaring header is this stratum's
# but whose *body* needs a name no module of this crate defines is recorded here with the
# reason naming the callee, the authority file and line the call sits on, and the stratum that
# owns the callee. Phase 13 is the *last* export stratum before the CLI and TLS strata, and it
# is where the earlier strata's deferred rows land -- it hands nothing onward. Every symbol in
# its working set is either already in the crate or is work this stratum does itself over the
# ENGINE, UI and TXT_DB objects it owns; the three rows it *receives* from Phase 12
# (`TS_CONF_set_crypto_device`, `TS_CONF_set_default_engine`, `SRP_VBASE_init`) are accounted
# for by `incoming_handoffs` below, not owed onward from here.
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
    return set(doc["body"]["libraries"]["libcrypto"]["implemented_symbols"])


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
    cannot be read is a failure rather than an empty edge set: a missing file would otherwise
    look exactly like "no stratum deferred anything to Phase 13" -- and for this stratum that
    would hide the three Phase-12 rows, the 22 Phase-3 rows and the 163 Phase-7 rows alike.
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
            "phase13-obligations: no earlier stratum's ledger is readable, so the incoming "
            "hand-off set would be empty for the wrong reason"
        )
    return out


def crate_module(unit: str) -> str:
    """The crate module the authority unit is laid out as: `crypto/<dir>/<stem>.c` ->
    `src/<dir>/<stem>.rs`.

    The `crypto/` prefix is **dropped**, because the crate's tree is `src/engine/`, `src/ui/`,
    `src/txt_db/`, ... -- one directory per authority *subdirectory* of `crypto/`, exactly as
    `crypto/engine/eng_lib.c` is `src/engine/eng_lib.rs` and `crypto/ui/ui_lib.c` is
    `src/ui/ui_lib.rs`. Keeping the prefix would label every phase-13 symbol
    `src/crypto/engine/...`, a tree that does not exist, and `plan_reconciliation.py` would then
    read every unit as unreached. A unit outside `crypto/` (none in this stratum) keeps its own
    path with `crypto/` absent, which is what the mapping below does by only stripping the
    prefix when it is there.
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
            if r["owner_phase"] == PHASE and r["library"] == "libcrypto"]
    if not mine:
        raise SystemExit(
            "phase13-obligations: the ownership atlas assigns this stratum no exports, "
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
                    f"phase13-obligations: {sym} is both the atlas's for phase {PHASE} and "
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
            "phase13-obligations: the ownership atlas gives this stratum (or an earlier "
            "stratum handed it) exports that no authority translation unit in "
            f"{DEFINING_UNITS} defines, so the ledger cannot say which module is expected to "
            "hold them -- add a label:\n  "
            + "\n  ".join(f"{s}  ({owned[s]['declaring_header']})" for s in unlabelled)
        )

    # The fail-closed deferral mechanism, unchanged from Phases 8 through 12: a symbol in
    # `BLOCKED_HANDOFFS` that the crate now defines is a stale row rather than a harmless one,
    # because a table that can keep covering a landed symbol can hide the next real gap behind it.
    # This stratum's table is empty -- it hands nothing onward -- so the loop is the mechanism
    # kept true rather than a claim of emptiness.
    blocked: dict[str, dict] = {}
    for symbols, phase, reason in BLOCKED_HANDOFFS:
        for sym in symbols:
            if sym not in owned:
                raise SystemExit(
                    f"phase13-obligations: BLOCKED_HANDOFFS names {sym}, which is not in this "
                    f"stratum's working set (or is not an authority export at all)"
                )
            if sym in done:
                raise SystemExit(
                    f"phase13-obligations: BLOCKED_HANDOFFS records {sym} as blocked on phase "
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
            "phase13-obligations: the ledger does not account for exactly its own working "
            f"set: owned={len(owned)} implemented={len(implemented_here)} "
            f"deferred={len(deferred_names)} open={len(open_rows)}"
        )

    # The provider registration rows this stratum owns, read from the census's own
    # `owning_phase`. Phase 13 owns the 39 legacy digest and cipher rows; at activation all are
    # unimplemented, and the count is emitted rather than omitted so a reader need not infer it.
    provider_doc = json.loads((REPO_ROOT / PROVIDER_ALGORITHMS).read_text(encoding="utf-8"))
    provider_owned = [
        r for r in provider_doc["body"]["rows"] if r["owning_phase"] == PHASE
    ]

    body = {
        "rule": (
            "the stratum's working set is the projection of forensics/atlas/"
            "symbol-ownership.json for phase 13, plus every symbol an earlier stratum's "
            "ledger records as handed to it: a symbol belongs to the stratum that owns the "
            "header declaring it, and a discharged hand-off belongs to the stratum that "
            "built it"
        ),
        "module_label_rule": (
            "the module a symbol is expected in is the crate's layout of the authority "
            "translation unit that defines it (forensics/atlas/export-defining-units.json): "
            "crypto/<dir>/<stem>.c -> src/<dir>/<stem>.rs. A **label**: the universe comes "
            "from the ownership atlas, and `main` fails when any symbol the atlas gives this "
            "stratum (or an earlier one hands it) has no defining unit"
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
        # The provider-row census's phase-13 slice. The legacy digest and cipher rows, measured.
        "provider_rows_owned": len(provider_owned),
        "complete": not open_rows,
        "note": (
            "`complete` is true only when every export in the working set is either "
            "implemented or handed to a later stratum. `open` is the only list that blocks "
            "the stratum. Unlike every earlier activation, this ledger's working set is more "
            "than its atlas-owned universe: 189 exports are `engine.h`'s, `ui.h`'s and "
            "`txt_db.h`'s, and 188 more arrive as recorded hand-offs from phases 3, 7 and 12. "
            "It also does not start with that whole working set open: 123 atlas-owned exports "
            "were landed before activation as substrate the earlier strata needed, and the "
            "four Phase 7 -> 13 `PEM_read[_bio]_PrivateKey` hand-offs are already implemented "
            "(Phase 8 landed them, D369), so the ledger's `implemented` count is not zero and "
            "its `open` count is not the whole working set. That split moves as this stratum "
            "lands its own units, so this note does not restate its counts; `counts` above is "
            "the live record and `forensics/atlas/implemented-surface.json` is the authority "
            "behind it. This stratum owns 39 provider registration rows, all unimplemented at "
            "activation (`forensics/atlas/provider-algorithms.json`). Nothing here is a parity "
            "claim: a symbol in `implemented` is at most `IMPLEMENTED` in docs/PARITY_MODEL.md "
            "terms, and docs/PHASE-13-SUBPHASES.md section 4 decides when the stratum may be "
            "called complete."
        ),
    }

    inputs = [
        InputRef(name="authority-symbols", path=atlas / "symbols-libcrypto.json"),
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
    doc = envelope(kind="phase13-obligations", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    c = body["counts"]
    print(f"[phase13-obligations] atlas={c['atlas_owned']} "
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
