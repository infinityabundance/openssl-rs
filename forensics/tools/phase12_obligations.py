#!/usr/bin/env python3
"""openssl-rs — the Phase 12 obligation ledger, and it is a *projection*.

Phase 12 is the CMS/OCSP/CMP/CT/TS stratum: the signed and encrypted container formats
(`CMS`, `PKCS7`, `PKCS12`'s siblings), the certificate-status and protocol machinery
(`OCSP`, `CMP`, `CRMF`, `TS`, `CT`), the shared S/MIME bridge over them and the remaining
`libcrypto` families the earlier strata left (`SRP`, `ESS`, the HTTP client). Its name in
`docs/RELEASE_GATES.md` section 1 is "CMS / OCSP / CMP / CT / TS and remaining libcrypto
families". `docs/PHASE-12-SUBPHASES.md` is its plan and this ledger is the
machine-checkable arithmetic behind it.

This ledger does not decide its own universe
--------------------------------------------
The universe comes from `forensics/atlas/symbol-ownership.json`, which assigns every one of
the authority's 6,499 exports to exactly one stratum by one stated rule
(`forensics/tools/ownership_rules.py`, D72). This file selects the rows the atlas assigns to
Phase 12 and reports them, and it adds the symbols earlier strata handed over.

**The atlas gives Phase 12 1,024 exports, all `libcrypto`, over twelve headers** --
`ts.h` (184), `ocsp.h` (169), `cmp.h` (157), `cms.h` (149), `pkcs7.h` (118), `crmf.h` (92),
`ct.h` (60), `ess.h` (30), `srp.h` (29), `http.h` (24), `cmp_util.h` (4) and `pem.h` (4),
plus four with no `declaring_header` (`PEM_read[_bio]_CMS`, `PEM_write[_bio]_CMS`, defined in
`crypto/cms/cms_io.c`) -- and **nine more arrive as recorded edges**: five from Phase 5
(`SMIME_read_ASN1`, `SMIME_read_ASN1_ex`, `SMIME_text`, `SMIME_write_ASN1`,
`SMIME_write_ASN1_ex`), two more from Phase 5 (`ASN1_ITEM_get`, `ASN1_ITEM_lookup`) and two
from Phase 11 (`X509_load_http`, `X509_CRL_load_http`).

**The ledger does not start with its whole working set open**, and that is the finding this
ledger exists to make visible: the whole of `ocsp_asn.c`, the five CT units
(`ct_sct.c`, `ct_log.c`, `ct_policy.c`, `ct_oct.c`, `ct_b64.c`, `ct_prn.c`), `pk7_asn1.c` with
`pk7_lib.c` and `http_lib.c`'s `OSSL_parse_url` landed before activation as substrate the
earlier strata needed. The split moves as this stratum lands its own units, so this docstring
does not restate its counts -- the `counts` block below is the live record.

The edges are discovered rather than typed: every row of every `forensics/phase*-obligations.json`
whose `owning_phase` is 12, so a stratum that defers a symbol to this one is recorded on both
sides by construction.

**This stratum owns no provider registration row**, and that is a measurement rather than an
omission: `forensics/atlas/provider-algorithms.json` records rows for owning phases 8, 9, 10 and
13 only, so the phase-12 slice of that census is empty and the ledger records the zero it reads
rather than leaving a reader to infer it.

Four situations, kept apart
---------------------------
  * **implemented** -- the crate defines the symbol.
  * **open** -- this stratum's, not built yet. The only list that blocks the stratum.
  * **deferred** -- a recorded hand-off to a later stratum with the dependency named.
  * **handoffs_discharged** -- the reverse edge, discovered above.

Outputs
-------
  forensics/phase12-obligations.json

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

OUT = REPO_ROOT / "forensics" / "phase12-obligations.json"
GENERATOR = "forensics/tools/phase12_obligations.py"
PHASE = 12
ATLAS_OWNERSHIP = "forensics/atlas/symbol-ownership.json"
DEFINING_UNITS = "forensics/atlas/export-defining-units.json"
PROVIDER_ALGORITHMS = "forensics/atlas/provider-algorithms.json"

# Which crate module is expected to hold a symbol. **A label, and here the label is the
# authority translation unit that defines it.** `forensics/atlas/export-defining-units.json`
# records that unit for every export, and the crate lays one module out per unit
# (`crypto/cms/cms_lib.c` -> `src/cms/cms_lib.rs`), so the unit *is* the label. Phase 10 could
# write its labels as a short symbol-prefix table because its three areas mapped to three
# modules; Phase 12's 1,033 symbols are defined by 58 units, so a prefix table here would be
# the atlas restated as 58 hand-typed entries -- a second thing to keep true. `MODULE_OVERRIDES`
# is kept only for the exceptions, a symbol whose crate module the unit layout does not name, and
# it is **empty** because measurement finds none.
MODULE_OVERRIDES: list[tuple[str, tuple[str, ...]]] = []


# ---------------------------------------------------------------------------------------------
# The blocked hand-offs. **Empty as of 13.8**, which landed the last blocker the two rows named.
#
# The rule is Phase 8's through Phase 11's: a symbol whose declaring header is this stratum's
# but whose *body* needs a name no module of this crate defines is recorded here with the reason
# naming the callee, the authority file and line the call sits on, and the stratum that owns the
# callee. Phase 12 is the *last* export stratum before the CLI and TLS strata, and almost every
# callee its units reach is either already in the crate or owned by this same stratum -- a
# same-stratum blocker is recorded as `open` (a stratum cannot hand a symbol to itself). The two
# hand-offs that were not are `TS_CONF_set_crypto_device`/`TS_CONF_set_default_engine`, whose only
# callees are Phase 13's `ENGINE_by_id`/`ENGINE_set_default`, and 12.8's `SRP_VBASE_init`, whose
# only missing callee is Phase 13's `TXT_DB_read`. Phase 13's 13.1/13.2 landed the engine pair and
# 13.5 the `TXT_DB` codec, so neither is a blocker any longer and both rows move to
# `UNBLOCKED_HANDOFFS` below rather than being retired -- the exports are still Phase 13's to
# write, and only the authority blockers have landed. The mechanism is kept true rather than
# deleted: a future deferral with a file:line claim belongs here.
# ---------------------------------------------------------------------------------------------

BLOCKED_HANDOFFS: list[tuple[tuple[str, ...], int, str]] = [
]

# ---------------------------------------------------------------------------------------------
# The third deferral mechanism, Phase 7's `UNBLOCKED_HANDOFFS` retargeted for Phase 12: a hand-off
# whose blocker has since landed.
#
# `BLOCKED_HANDOFFS` above makes a *structured claim* -- "this export is withheld because file:line
# calls `X`, and `X` is not in the crate" -- and its fail-closed rule fires the moment `X` lands,
# because a table that can keep covering a landed blocker can hide the next real gap behind it. The
# prescription is "retire the row", but **retiring these two rows would be a false statement about
# this stratum, not a correction of one.** The exports are Phase 13's to write in the ledger's
# arithmetic -- this table is what `phase13_obligations.py` reads to put them in Phase 13's working
# set -- so removing it would move built exports into *this* sealed stratum's `implemented` list on
# the strength of work this stratum did not do, and drop them from Phase 13's
# `received_by_handoff`. The honest difference is that the *blocker* is gone, not that the hand-off
# is. So each row is **retargeted** from a blocked claim to an unconditional one -- D173's
# precedent, "a deferral that had to move", the same move 13.2 made for `ENGINE_get_pkey_meth` in
# `phase7_obligations.py` -- and the reason records what landed rather than repeating a claim that
# no longer holds. The rows carry no `blocked_by`, so nothing is left to go stale: an unconditional
# hand-off is falsified by the owner's ledger, which already counts it, rather than by a file:line.
# ---------------------------------------------------------------------------------------------

UNBLOCKED_HANDOFFS: list[tuple[tuple[str, ...], int, str]] = [
    (
        ("TS_CONF_set_crypto_device", "TS_CONF_set_default_engine"),
        13,
        "both are guarded by `#ifndef OPENSSL_NO_ENGINE` in `crypto/ts/ts_conf.c` and their body "
        "is the ENGINE lookup and installation: `TS_CONF_set_default_engine` calls "
        "`ENGINE_by_id(name)` (`crypto/ts/ts_conf.c:188`) and `ENGINE_set_default(e, "
        "ENGINE_METHOD_ALL)` (`:192`), and `TS_CONF_set_crypto_device` delegates to it "
        "(`:171`, `:188`); `ENGINE_by_id` and `ENGINE_set_default` are `engine.h`'s and Phase "
        "13's (`forensics/atlas/symbol-ownership.json`, owner_phase 13). **13.1 landed "
        "`ENGINE_by_id` and 13.2 landed `ENGINE_set_default`, and 13.8 transcribed both readers "
        "in `src/ts/ts_conf.rs`**, so every blocker this row named has landed and the row moves "
        "here from `BLOCKED_HANDOFFS` rather than retiring: the pair is still Phase 13's to "
        "write in the ledger's arithmetic -- this row is what puts the two names in "
        "`forensics/phase13-obligations.json`'s working set -- and retiring it would move two "
        "built exports into this sealed stratum's `implemented` list on the strength of work "
        "this stratum did not do.",
    ),
    (
        ("SRP_VBASE_init",),
        13,
        "its body reads and releases a verifier file through `TXT_DB_read` "
        "(`crypto/srp/srp_vfy.c:423`) and `TXT_DB_free` (`:504`), and both are declared in "
        "`include/openssl/txt_db.h`, which is Phase 13's (`forensics/atlas/symbol-ownership.json`, "
        "owner_phase 13). The rest of `crypto/srp/srp_vfy.c` landed in 12.8, including the private "
        "helpers that only `SRP_VBASE_init` reaches. **13.5 landed `TXT_DB_read`/`TXT_DB_free` and "
        "13.8 transcribed the body in `src/srp/srp_vfy.rs`**, so the blocker this row named has "
        "landed and the row moves here from `BLOCKED_HANDOFFS` rather than retiring: the export "
        "is still Phase 13's to write in the ledger's arithmetic -- this row is what puts the "
        "name in `forensics/phase13-obligations.json`'s working set -- and retiring it would "
        "move a built export into this sealed stratum's `implemented` list on the strength of "
        "work this stratum did not do.",
    ),
]


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
    look exactly like "no stratum deferred anything to Phase 12" -- and for this stratum that
    would hide all nine of its hand-offs.
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
            "phase12-obligations: no earlier stratum's ledger is readable, so the incoming "
            "hand-off set would be empty for the wrong reason"
        )
    return out


def crate_module(unit: str) -> str:
    """The crate module the authority unit is laid out as: `crypto/<dir>/<stem>.c` ->
    `src/<dir>/<stem>.rs`.

    The `crypto/` prefix is **dropped**, because the crate's tree is `src/cms/`, `src/ocsp/`,
    `src/cmp/`, ... -- one directory per authority *subdirectory* of `crypto/`, exactly as
    `crypto/cms/cms_lib.c` is `src/cms/cms_lib.rs` and `crypto/ts/ts_asn1.c` is
    `src/ts/ts_asn1.rs`. Keeping the prefix would label every phase-12 symbol
    `src/crypto/cms/...`, a tree that does not exist, and `plan_reconciliation.py` would then
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
            "phase12-obligations: the ownership atlas assigns this stratum no exports, "
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
                    f"phase12-obligations: {sym} is both the atlas's for phase {PHASE} and "
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
            "phase12-obligations: the ownership atlas gives this stratum (or an earlier "
            "stratum handed it) exports that no authority translation unit in "
            f"{DEFINING_UNITS} defines, so the ledger cannot say which module is expected to "
            "hold them -- add a label:\n  "
            + "\n  ".join(f"{s}  ({owned[s]['declaring_header']})" for s in unlabelled)
        )

    # The fail-closed deferral mechanism, unchanged from Phases 8 through 11: a symbol in
    # `BLOCKED_HANDOFFS` that the crate now defines is a stale row rather than a harmless one,
    # because a table that can keep covering a landed symbol can hide the next real gap behind it.
    # This stratum's table is **empty** as of 13.8, which landed the last blocker the two rows
    # named, so the loop is the mechanism kept true rather than a claim of emptiness.
    blocked: dict[str, dict] = {}
    for symbols, phase, reason in BLOCKED_HANDOFFS:
        for sym in symbols:
            if sym not in owned:
                raise SystemExit(
                    f"phase12-obligations: BLOCKED_HANDOFFS names {sym}, which is not in this "
                    f"stratum's working set (or is not an authority export at all)"
                )
            if sym in done:
                raise SystemExit(
                    f"phase12-obligations: BLOCKED_HANDOFFS records {sym} as blocked on phase "
                    f"{phase}, but the crate defines it; retire the row"
                )
            blocked[sym] = {
                "symbol": sym,
                "owning_phase": phase,
                "declaring_header": owned[sym]["declaring_header"],
                "reason": reason,
            }

    # The third mechanism (see `UNBLOCKED_HANDOFFS`): a hand-off whose blocker has landed. Same
    # fail-closed rule as `BLOCKED_HANDOFFS` for a symbol outside the working set, and **not** the
    # same rule for a symbol the crate now defines -- deliberately, and the asymmetry is the whole
    # point of keeping the two tables apart:
    #
    #   * a `BLOCKED_HANDOFFS` row is falsified by its blocker landing, because its claim IS
    #     "file:line calls X and X is absent";
    #   * an `UNBLOCKED_HANDOFFS` row makes no such claim, so it is not falsified by *itself* being
    #     built. The row is the hand-off **edge**: it is what puts the symbol in the receiving
    #     stratum's working set, and it is what `phase13_obligations.py` reads to count the symbol
    #     as that stratum's. Retiring it the moment the owner lands the symbol would move the
    #     symbol into *this* sealed stratum's `implemented` list on the strength of work this
    #     stratum did not do, and take it off the owner's books at the same time.
    unblocked: dict[str, dict] = {}
    for symbols, owning_phase, reason in UNBLOCKED_HANDOFFS:
        for sym in symbols:
            if sym not in owned:
                raise SystemExit(
                    f"phase12-obligations: UNBLOCKED_HANDOFFS names {sym}, which is not in this "
                    f"stratum's working set (or is not an authority export at all)"
                )
            if sym in blocked:
                raise SystemExit(
                    f"phase12-obligations: {sym} is handed on by both BLOCKED_HANDOFFS and "
                    f"UNBLOCKED_HANDOFFS; one cause per symbol, or the reasons will disagree"
                )
            unblocked[sym] = {
                "symbol": sym,
                "owning_phase": owning_phase,
                "declaring_header": owned[sym]["declaring_header"],
                "reason": reason,
            }

    deferred_names = set(blocked) | set(unblocked)
    deferred: list[dict] = sorted(
        list(blocked.values()) + list(unblocked.values()), key=lambda r: r["symbol"]
    )

    implemented_here = sorted(s for s in owned if s in done and s not in deferred_names)
    open_rows = [
        {"symbol": s, "module": owned[s]["module"],
         "declaring_header": owned[s]["declaring_header"],
         "received_from_phase": owned[s]["from"]}
        for s in sorted(owned) if s not in done and s not in deferred_names
    ]

    if len(owned) != len(implemented_here) + len(deferred_names) + len(open_rows):
        raise SystemExit(
            "phase12-obligations: the ledger does not account for exactly its own working "
            f"set: owned={len(owned)} implemented={len(implemented_here)} "
            f"deferred={len(deferred_names)} open={len(open_rows)}"
        )

    # The provider registration rows this stratum owns, read from the census's own
    # `owning_phase`. Zero is the measurement (the census records rows for phases 8, 9, 10 and
    # 13 only), and it is emitted rather than omitted so a reader need not infer it.
    provider_doc = json.loads((REPO_ROOT / PROVIDER_ALGORITHMS).read_text(encoding="utf-8"))
    provider_owned = [
        r for r in provider_doc["body"]["rows"] if r["owning_phase"] == PHASE
    ]

    body = {
        "rule": (
            "the stratum's working set is the projection of forensics/atlas/"
            "symbol-ownership.json for phase 12, plus every symbol an earlier stratum's "
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
        # The third mechanism, Phase 7's, retargeted: each row is an unconditional hand-off whose
        # blocker has landed. Emitted so the mechanism is visible in the ledger rather than only
        # in the source comments.
        "unblocked_handoffs": [
            {"symbols": list(symbols), "owning_phase": phase, "reason": reason}
            for symbols, phase, reason in UNBLOCKED_HANDOFFS
        ],
        # The provider-row census's phase-12 slice. Zero, measured. See the module doc.
        "provider_rows_owned": len(provider_owned),
        "complete": not open_rows,
        "note": (
            "`complete` is true only when every export in the working set is either "
            "implemented or handed to a later stratum. `open` is the only list that blocks "
            "the stratum. Unlike every earlier activation except Phases 10 and 11, this ledger "
            "does not start with the whole working set open: the `ocsp_asn.c` item group, the "
            "CT `ct_*` units, `pk7_asn1.c`/`pk7_lib.c` and `http_lib.c`'s `OSSL_parse_url` "
            "landed before activation, and the nine hand-offs phases 5 and 11 discharged, are "
            "reported as `implemented` because `implemented-surface.json` says so. That split "
            "moves as this stratum lands its own units, so this note does not restate its "
            "counts; `counts` above is the live record and `forensics/atlas/"
            "implemented-surface.json` is the authority behind it. This stratum owns no "
            "provider registration row (`forensics/atlas/provider-algorithms.json` records rows "
            "for owning phases 8, 9, 10 and 13 only). Nothing here is a parity claim: a symbol "
            "in `implemented` is at most `IMPLEMENTED` in docs/PARITY_MODEL.md terms, and "
            "docs/PHASE-12-SUBPHASES.md section 4 decides when the stratum may be called "
            "complete."
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
    doc = envelope(kind="phase12-obligations", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    c = body["counts"]
    print(f"[phase12-obligations] atlas={c['atlas_owned']} "
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
