#!/usr/bin/env python3
"""openssl-rs — audit symbol ownership across the phase families.

Why this exists
---------------
The per-phase ledgers decide whether a stratum is complete by asking "is every
export *my family* matches implemented or handed to a later phase?". That question
is only answerable for exports that *some* family matches. An export that matches
no family is invisible to every ledger at once, and the ABI shell simply scaffolds
it — which is a fabricated-looking symbol in the one artefact that is supposed to
contain only real ones.

That is not hypothetical. `docs/DECISIONS.md` D49 records it happening to
`OPENSSL_INIT_*` (five exports of `conf_lib.c` that only a human reading the header
noticed), and D51 records it happening to the whole of `crypto/o_str.c` and
`crypto/o_dir.c` — thirteen exports, including three the CONF reader needs. Both
were found by reading, not by a check. This tool is the check.

What it enforces
----------------
The invariant is scoped to what can be true today: phases 5-21 have no families
yet, so most of the authority's exports are legitimately unowned *for now*. What
must never be true is an export being **implemented while owned by nobody** — that
is the state in which work is invisible to the accounting it is supposed to appear
in. So:

  * error: an export the candidate implements that no phase family claims;
  * reported: the unowned remainder, in full, with the counts per phase, so the
    unclaimed scope is a visible fact rather than an implied one;
  * error: an export claimed by two *different* memory locations in one phase's
    family list, which usually means one of the patterns was widened by accident.

The unowned remainder is written to `forensics/atlas/ownership-audit.json`; it is
not a parity claim, it is a census.

Outputs
-------
  forensics/atlas/ownership-audit.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    ATLAS,
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    envelope,
    implemented_surface_input,
    rel,
    resolve_authority,
    write_json,
)

OUT = ATLAS / "ownership-audit.json"
GENERATOR = "forensics/tools/ownership_audit.py"

# The ledgers that publish a family list. Adding a phase means adding its module
# here, which is the point: a new stratum cannot be introduced without its
# families becoming visible to this audit.
LEDGERS = [
    (3, "forensics/tools/phase3_obligations.py"),
    (4, "forensics/tools/phase4_obligations.py"),
    (5, "forensics/tools/phase5_obligations.py"),
]

# The generated ledgers, for the cross-ledger reconciliation below. They are read
# as *results* (who claims to have implemented what), not as family definitions;
# the family scan above uses the generator modules so it sees a prefix that has
# been edited but not yet regenerated.
LEDGER_JSON = {
    3: "forensics/phase3-obligations.json",
    4: "forensics/phase4-obligations.json",
    5: "forensics/phase5-obligations.json",
}

LIBS = ("libcrypto", "libssl")
# Only `libcrypto` is claimed by any family today: every prefix the ledgers list is
# a libcrypto one, and libssl's own families arrive with Phase 14. Counting the
# eight libssl symbols that happen to match a libcrypto prefix (`BIO_ssl_shutdown`,
# `ERR_load_SSL_strings`, `OPENSSL_init_ssl`, ...) would report an ownership that no
# ledger acts on, so the *claim* scan is restricted to libcrypto and libssl is
# reported as unclaimed-by-these-ledgers with that fact stated.
CLAIM_LIBS = ("libcrypto",)


def families(relpath: str) -> list[tuple[str, tuple[str, ...]]]:
    """Load a ledger module and return its `FAMILIES` without running `main`."""
    path = REPO_ROOT / relpath
    spec = importlib.util.spec_from_file_location(f"ownership_audit_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {relpath}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fams = getattr(module, "FAMILIES", None)
    if fams is None:
        raise SystemExit(f"{relpath} has no FAMILIES list")
    return list(fams)


def authority_exports(authority: Path, lib: str) -> list[str]:
    doc = json.loads(
        (authority / f"symbols-{lib}.json").read_text(encoding="utf-8")
    )
    return sorted(r["symbol"] for r in doc["body"]["records"] if r["dso"]["present"])


def implemented() -> dict[str, set[str]]:
    doc = json.loads(
        (REPO_ROOT / "forensics" / "atlas" / "implemented-surface.json").read_text(
            encoding="utf-8"
        )
    )
    return {
        lib: set(doc["body"]["libraries"][lib]["implemented_symbols"]) for lib in LIBS
    }


def family_key(symbol: str) -> str:
    """A coarse classifier for the unowned census, not an identity."""
    m = re.match(r"[A-Za-z0-9_]+?[a-z0-9]?(?=[A-Z_]|$)", symbol)
    if m and m.group(0):
        return m.group(0)
    return symbol[:4]


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    authdir = REPO_ROOT / "forensics" / "atlas" / auth.id

    # (phase, module, prefix) -> the symbols it claims.
    claims: list[dict] = []
    owner: dict[tuple[str, str], list[tuple[int, str, str]]] = {}
    for phase, relpath in LEDGERS:
        for module, prefixes in families(relpath):
            for lib in CLAIM_LIBS:
                for sym in authority_exports(authdir, lib):
                    for pre in prefixes:
                        if sym == pre or sym.startswith(pre):
                            claims.append(
                                {
                                    "phase": phase,
                                    "module": module,
                                    "prefix": pre,
                                    "lib": lib,
                                    "symbol": sym,
                                }
                            )
                            owner.setdefault((lib, sym), []).append(
                                (phase, module, pre)
                            )

    impl = implemented()
    problems: list[str] = []

    # An implemented export must be owned, or its work is invisible.
    unowned_implemented: list[dict] = []
    for lib in CLAIM_LIBS:
        for sym in sorted(impl[lib]):
            if (lib, sym) not in owner:
                unowned_implemented.append({"lib": lib, "symbol": sym})
    if unowned_implemented:
        problems.append(
            "these exports are implemented but no phase family claims them, so no "
            "ledger can account for them:\n  "
            + "\n  ".join(f"{r['lib']}:{r['symbol']}" for r in unowned_implemented)
        )

    # Two patterns in one family list claiming the same symbol usually means a
    # prefix was widened by accident, so it is reported. It is not a failure:
    # `BIO_` and `BUF_` cannot collide, but a future `B` would, and a report is
    # what tells a reader which one is doing the claiming. Two *phases* claiming
    # the same symbol is the deliberate hand-off mechanism — Phase 3 owns `ERR_`
    # and Phase 4 explicitly lists the BIO-coupled members to receive them — so
    # that is recorded as the hand-off list rather than as a defect.
    overlaps: list[dict] = []
    handoffs: list[dict] = []
    for (lib, sym), owners in sorted(owner.items()):
        by_family: dict[tuple[int, str], list[str]] = {}
        for phase, module, pre in owners:
            by_family.setdefault((phase, module), []).append(pre)
        for (phase, module), prefixes in by_family.items():
            if len(set(prefixes)) > 1:
                overlaps.append(
                    {
                        "lib": lib,
                        "symbol": sym,
                        "phase": phase,
                        "module": module,
                        "prefixes": sorted(set(prefixes)),
                    }
                )
        phases = sorted({p for p, _m, _pre in owners})
        if len(phases) > 1:
            handoffs.append({"lib": lib, "symbol": sym, "phases": phases})

    # Cross-ledger reconciliation. Two ledgers counting the same symbol as
    # *implemented by them* double-counts one piece of work and lets both strata
    # report completion over it; and a hand-off recorded by the deferring stratum
    # but not declared by the receiving one is an obligation that fell between
    # them. Both were real: `ERR_print_errors*`, `ERR_add_error_mem_bio`, the six
    # `OPENSSL_LH_*stats*` and `OBJ_create_objects` sat in *both* strata's
    # `implemented` lists until this check existed (docs/DECISIONS.md D57).
    ledger_docs: dict[int, dict] = {}
    for phase, relpath in LEDGER_JSON.items():
        p = REPO_ROOT / relpath
        if not p.exists():
            problems.append(
                f"phase {phase} ledger {relpath} is absent, so no cross-ledger "
                "reconciliation is possible; absence of an evidence plane must "
                "never resemble a satisfied one"
            )
            continue
        ledger_docs[phase] = json.loads(p.read_text(encoding="utf-8"))["body"]

    implemented_by: dict[str, list[int]] = {}
    for phase, body in sorted(ledger_docs.items()):
        for sym in body.get("implemented", []):
            implemented_by.setdefault(sym, []).append(phase)

    double_implemented = [
        {"symbol": s, "phases": ps}
        for s, ps in sorted(implemented_by.items())
        if len(ps) > 1
    ]
    if double_implemented:
        problems.append(
            "these exports are counted as implemented by more than one stratum, so "
            "the work is double-counted and neither ledger's completeness claim is "
            "about the work it actually did:\n  "
            + "\n  ".join(
                f"{r['symbol']}: phases {r['phases']}" for r in double_implemented
            )
        )

    # Each deferring stratum's hand-off edges must equal what the receiving
    # stratum declares it discharged -- but only where the receiving stratum has a
    # ledger to declare it in. `handoffs_discharged` on ledger Q is keyed by the
    # *source* phase, so the edge is (source -> Q). An edge pointing at a stratum
    # that has not been written yet (Phase 4's hand-offs to 5, 6, 7, 9 and 12) is a
    # forward hand-off: recorded by the deferring ledger, receivable by nobody yet,
    # and therefore informational rather than a mismatch.
    declared: dict[tuple[int, int], set[str]] = {}
    for phase, body in ledger_docs.items():
        for source, syms in (body.get("handoffs_discharged") or {}).items():
            declared[(int(source), phase)] = set(syms)
    recorded: dict[tuple[int, int], set[str]] = {}
    for phase, body in ledger_docs.items():
        for row in body.get("deferred", []):
            if isinstance(row, dict) and "owning_phase" in row:
                recorded.setdefault((phase, int(row["owning_phase"])), set()).add(
                    row["symbol"]
                )
    mismatched_handoffs: list[dict] = []
    for edge in sorted(recorded):
        if edge[1] not in ledger_docs:
            continue  # the receiving stratum has no ledger yet
        want, got = recorded[edge], declared.get(edge, set())
        if want != got:
            mismatched_handoffs.append(
                {
                    "from_phase": edge[0],
                    "to_phase": edge[1],
                    "deferred_but_not_declared": sorted(want - got),
                    "declared_but_not_deferred": sorted(got - want),
                }
            )
    if mismatched_handoffs:
        problems.append(
            "these hand-off edges disagree between the deferring and the receiving "
            "stratum, so the obligation is recorded in one ledger only:\n  "
            + "\n  ".join(
                f"phase {r['from_phase']} -> {r['to_phase']}: "
                f"deferred-not-declared={r['deferred_but_not_declared']} "
                f"declared-not-deferred={r['declared_but_not_deferred']}"
                for r in mismatched_handoffs
            )
        )

    # Every ledger must account for exactly its own family exports: implemented
    # plus handed-on plus still-open must equal owned, whatever the split.
    for phase, body in sorted(ledger_docs.items()):
        counts = body.get("counts", {})
        deferred = counts.get("deferred", counts.get("deferred_to_later_phase"))
        if deferred is None:
            problems.append(
                f"phase {phase} ledger publishes no deferred count, so its own "
                "families cannot be shown to be fully accounted for"
            )
            continue
        open_n = counts.get("open_in_this_stratum", 0)
        owned = counts.get("owned", 0)
        accounted = counts.get("implemented", 0) + deferred + open_n
        if accounted != owned:
            problems.append(
                f"phase {phase} ledger accounts for {accounted} of {owned} family "
                f"exports (implemented={counts.get('implemented')} "
                f"deferred={deferred} open={open_n}), so some export it owns is "
                "neither implemented, handed on, nor recorded as open"
            )

    # The unowned remainder: everything the authority exports that no family
    # claims. This is the scope of the phases that have no families yet.
    unowned: dict[str, dict] = {}
    for lib in LIBS:
        symbols = [
            s for s in authority_exports(authdir, lib) if (lib, s) not in owner
        ]
        classes = Counter(family_key(s) for s in symbols)
        unowned[lib] = {
            "count": len(symbols),
            "claimed_by_these_ledgers": len(
                [s for s in authority_exports(authdir, lib) if (lib, s) in owner]
            ),
            "classes": [{"class": k, "count": v} for k, v in classes.most_common()],
            "symbols": symbols,
        }

    body = {
        "invariant": (
            "every implemented export is claimed by at least one phase family"
        ),
        "why": (
            "an export that matches no family is invisible to every ledger at once, "
            "so the shell scaffolds it and no obligation records it (docs/DECISIONS.md "
            "D49, D51)"
        ),
        "ledgers": [{"phase": p, "ledger": rel(REPO_ROOT / r)} for p, r in LEDGERS],
        "claims": len(claims),
        "claim_scope": (
            "libcrypto only: no family listed by any current ledger matches a libssl "
            "export, so libssl is reported as entirely unclaimed rather than counted "
            "through eight accidental prefix matches"
        ),
        "owned_exports": {
            lib: len({s for (l, s) in owner if l == lib}) for lib in LIBS
        },
        "implemented_exports": {lib: len(impl[lib]) for lib in LIBS},
        "unowned_implemented": unowned_implemented,
        "unowned_remainder": unowned,
        "handoffs": handoffs,
        "overlaps": overlaps,
        "implemented_by_two_strata": double_implemented,
        "handoff_reconciliation": {
            "rule": (
                "for every hand-off edge whose receiving stratum has a ledger, the "
                "set the deferring stratum hands over equals the set the receiving "
                "stratum declares it discharged"
            ),
            "recorded": [
                {"from_phase": k[0], "to_phase": k[1], "symbols": sorted(v)}
                for k, v in sorted(recorded.items())
            ],
            "declared": [
                {"from_phase": k[0], "to_phase": k[1], "symbols": sorted(v)}
                for k, v in sorted(declared.items())
            ],
            "forward": [
                {"from_phase": k[0], "to_phase": k[1], "symbols": sorted(v)}
                for k, v in sorted(recorded.items())
                if k[1] not in ledger_docs
            ],
            "mismatched": mismatched_handoffs,
        },
        "problems": problems,
        "note": (
            "The unowned remainder is not a defect: phases 5-21 have no families "
            "yet. It is the scope that no stratum has claimed, recorded as a count "
            "and in full rather than left implied. `handoffs` lists the symbols two "
            "strata coordinate on, which is the deliberate hand-off mechanism; "
            "`overlaps` lists a symbol two prefixes of one family list both match; "
            "`implemented_by_two_strata` and `handoff_reconciliation` are the "
            "cross-ledger invariants that stop one piece of work being counted "
            "twice or falling between two strata. Only `problems` is a defect "
            "list, and a non-empty one fails this tool."
        ),
    }

    inputs = [
        InputRef(name="implemented-surface", path=REPO_ROOT / "forensics" / "atlas"
                 / "implemented-surface.json"),
        InputRef(name="authority-symbols", path=authdir / "symbols-libcrypto.json"),
    ]
    for _phase, relpath in LEDGERS:
        inputs.append(InputRef(name="ledger", path=REPO_ROOT / relpath))
    for _phase, relpath in LEDGER_JSON.items():
        inputs.append(InputRef(name="ledger-result", path=REPO_ROOT / relpath))

    doc = envelope(
        kind="ownership-audit",
        authority=auth.id,
        inputs=inputs,
        body=body,
        generator=GENERATOR,
    )
    write_json(OUT, doc)

    print(f"[ownership-audit] authority={auth.id}")
    for lib in LIBS:
        print(
            f"  {lib:9} exports={len(authority_exports(authdir, lib)):5} "
            f"owned={body['owned_exports'][lib]:5} "
            f"implemented={body['implemented_exports'][lib]:5} "
            f"unowned={unowned[lib]['count']:5}"
        )
    print(f"  -> {rel(OUT)}")
    print(
        f"  cross-ledger: {len(double_implemented)} double-counted symbol(s), "
        f"{len(mismatched_handoffs)} mismatched hand-off edge(s)"
    )
    for edge in sorted(declared):
        print(
            f"  hand-off phase {edge[0]} -> {edge[1]}: "
            f"{len(declared[edge])} discharged"
        )
    forward_edges = sorted(k for k in recorded if k[1] not in ledger_docs)
    for edge in forward_edges:
        print(
            f"  hand-off phase {edge[0]} -> {edge[1]}: "
            f"{len(recorded[edge])} recorded (no ledger yet)"
        )
    if problems:
        print("  FAIL")
        for p in problems:
            print(f"    {p}")
        return 1
    print("  every implemented export is owned by a phase family")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
