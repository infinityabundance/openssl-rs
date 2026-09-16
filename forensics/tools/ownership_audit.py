#!/usr/bin/env python3
"""openssl-rs — audit symbol ownership: the atlas against the ledgers, both ways.

Why this exists
---------------
The per-phase ledgers decide whether a stratum is complete by asking "is every
export I own implemented or handed to a later phase?". That question is only
answerable for exports the stratum knows it owns. Three times in this project an
export has been invisible to *every* ledger at once, and each time the ABI shell
scaffolded it while no obligation recorded it:

  * `OPENSSL_INIT_*`, five exports of `conf_lib.c` that only a human reading the
    header noticed (docs/DECISIONS.md D49);
  * the whole of `crypto/o_str.c` and `crypto/o_dir.c`, thirteen exports including
    three the CONF reader needs (D51);
  * `a2d_ASN1_OBJECT`, declared in `asn1.h` and matching no prefix any ledger listed
    (D72).

D72 replaced per-phase prefix discovery with one generated artifact,
`forensics/atlas/symbol-ownership.json`, whose universe is **every one of the
authority's 6,499 exports**, each assigned to exactly one stratum by one stated rule.
Each ledger then becomes a *projection* of that atlas.

That closed the class from one side. This tool closes it from the other, because a
projection can still be wrong, and because a ledger can claim what it does not own.

What it enforces
----------------
For every phase that publishes a ledger, **both** directions:

1. `atlas-owned -> ledger row`. Every export the atlas assigns a stratum appears in
   that stratum's ledger as implemented, open, or deferred to a named later phase.
   Phases 3 and 4 had 69 and 19 atlas-owned exports with no row anywhere — every
   `ASYNC_*`, every `OSSL_ERR_STATE_*`, every `OSSL_trace_*`, every `COMP_*`, the
   `conf_ssl_*` helpers, `OPENSSL_config` — while their seals called them complete.
   Their ledgers' `FAMILIES` were prefix lists, and a prefix that matches nothing
   reports nothing. See docs/DECISIONS.md D97.
2. `ledger row -> justification`. A row a stratum's ledger carries for an export the
   atlas assigns *elsewhere* must be a discharged hand-off: the atlas's owner must
   list that export as deferred to this stratum. Otherwise two ledgers disagree about
   who owes it.

And, across the ledgers:

3. no export is counted `implemented` by two strata at once, which would
   double-count one piece of work and let both strata report completion over it
   (D57 found `ERR_print_errors*`, `ERR_add_error_mem_bio`, the six
   `OPENSSL_LH_*stats*` and `OBJ_create_objects` in two ledgers' `implemented`
   lists);
4. every hand-off edge agrees in both directions: the set the deferring stratum hands
   over equals the set the receiving stratum declares it discharged. An edge pointing
   at a stratum with no ledger yet is *forward* and informational, not a mismatch;
5. each ledger's own arithmetic holds: every row in exactly one of
   implemented/open/deferred, and the three adding up to the count it publishes.

And the older, weaker invariant is kept because it is cheap and it is what the shell
depends on: an export the candidate *implements* must have an owner in the atlas,
because a symbol with no atlas row could not have been exported at all.

Outputs
-------
  forensics/atlas/ownership-audit.json

It is not a parity claim, it is a census, and `problems` is the only defect list. A
non-empty one fails this tool.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
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
ATLAS_OWNERSHIP = "forensics/atlas/symbol-ownership.json"

LIBS = ("libcrypto", "libssl")
# Every ledger that exists so far is a libcrypto one: libssl's own strata begin at
# Phase 14. Counting the eight libssl symbols that happen to look like libcrypto ones
# (`BIO_ssl_shutdown`, `ERR_load_SSL_strings`, `OPENSSL_init_ssl`, ...) would report an
# ownership no ledger acts on, so the reconciliation is scoped to libcrypto and libssl
# is reported as out-of-scope with that fact stated.
CLAIM_LIBS = ("libcrypto",)


def ledger_paths() -> dict[int, str]:
    """Every `forensics/phase<N>-obligations.json` on disk, by phase number.

    Discovery, not enumeration: a stratum that publishes a ledger is reconciled
    without anyone remembering to add it here, and a ledger that is deleted shows up
    as an atlas phase with no ledger rather than as silence.
    """
    out: dict[int, str] = {}
    for path in sorted((REPO_ROOT / "forensics").glob("phase*-obligations.json")):
        m = re.fullmatch(r"phase(\d+)-obligations\.json", path.name)
        if m is None:
            continue
        out[int(m.group(1))] = rel(path)
    return out


def symbols_of(field: object) -> set[str]:
    """A ledger's symbol list, whether its rows are names or objects."""
    out: set[str] = set()
    for r in field or []:
        if isinstance(r, str):
            out.add(r)
        elif isinstance(r, dict) and "symbol" in r:
            out.add(r["symbol"])
    return out


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

    doc = json.loads((REPO_ROOT / ATLAS_OWNERSHIP).read_text(encoding="utf-8"))["body"]
    atlas_owner: dict[tuple[str, str], int] = {}
    for row in doc["records"]:
        atlas_owner[(row["library"], row["symbol"])] = row["owner_phase"]

    problems: list[str] = []
    for field, expected in (("unknown", 0), ("multiply_owned", 0),
                            ("unassigned_headers", 0)):
        if doc["invariants"].get(field) != expected:
            problems.append(
                f"the ownership atlas reports {field}="
                f"{doc['invariants'].get(field)}, expected {expected}"
            )
    if doc["universe"]["exports"] != len(atlas_owner):
        problems.append(
            "the ownership atlas lists "
            f"{doc['universe']['exports']} exports but has {len(atlas_owner)} rows"
        )

    impl = implemented()

    # An implemented export must be owned, or its work is invisible to the accounting
    # it is supposed to appear in. The atlas answers this directly: a symbol with no
    # atlas row could not have been exported at all, and one the atlas could not
    # assign stopped the atlas run.
    unowned_implemented: list[dict] = []
    for lib in CLAIM_LIBS:
        for sym in sorted(impl[lib]):
            if (lib, sym) not in atlas_owner:
                unowned_implemented.append({"lib": lib, "symbol": sym})
    if unowned_implemented:
        problems.append(
            "these exports are implemented but the ownership atlas does not assign "
            "them, so no ledger can account for them:\n  "
            + "\n  ".join(f"{r['lib']}:{r['symbol']}" for r in unowned_implemented)
        )

    # ---- the ledgers, and their reconciliation against the atlas --------------
    paths = ledger_paths()
    ledger_agreement: list[dict] = []
    ledger_bodies: dict[int, dict] = {}
    deferred_to: dict[tuple[int, str], int] = {}
    implemented_by: dict[str, list[int]] = {}

    for phase in sorted(paths):
        path = REPO_ROOT / paths[phase]
        if not path.is_file():
            problems.append(
                f"phase {phase} ledger {paths[phase]} is absent, so no reconciliation "
                "is possible; absence of an evidence plane must never resemble a "
                "satisfied one"
            )
            continue
        rows = json.loads(path.read_text(encoding="utf-8"))["body"]
        ledger_bodies[phase] = rows

        implemented_rows = symbols_of(rows.get("implemented"))
        open_rows = symbols_of(rows.get("open"))
        deferred_rows = symbols_of(rows.get("deferred"))
        for sym in implemented_rows:
            implemented_by.setdefault(sym, []).append(phase)
        for row in rows.get("deferred") or []:
            if isinstance(row, dict) and "owning_phase" in row:
                deferred_to[(phase, row["symbol"])] = int(row["owning_phase"])
        for source, syms in (rows.get("handoffs_discharged") or {}).items():
            for sym in syms:
                deferred_to.setdefault((int(source), sym), phase)

        ledger_symbols = implemented_rows | open_rows | deferred_rows

        # 5. The ledger's own arithmetic.
        overlap = sorted(
            (implemented_rows & open_rows)
            | (implemented_rows & deferred_rows)
            | (open_rows & deferred_rows)
        )
        if overlap:
            problems.append(
                f"phase {phase}'s ledger lists these exports in more than one of "
                "implemented/open/deferred, so its own arithmetic double-counts "
                "them:\n  " + "\n  ".join(overlap)
            )
        owned_n = (rows.get("counts") or {}).get("owned")
        if owned_n is None:
            problems.append(
                f"phase {phase}'s ledger publishes no owned count, so its own "
                "arithmetic cannot be checked"
            )
        elif owned_n != len(ledger_symbols):
            problems.append(
                f"phase {phase}'s ledger publishes owned={owned_n} but lists "
                f"{len(ledger_symbols)} rows across implemented/open/deferred"
            )

        atlas_symbols = {s for (l, s), p in atlas_owner.items()
                         if p == phase and l in CLAIM_LIBS}

        # 1. Nothing the atlas gives this stratum may be missing from its ledger.
        only_atlas = sorted(atlas_symbols - ledger_symbols)
        if only_atlas:
            problems.append(
                f"phase {phase} is assigned {len(atlas_symbols)} libcrypto exports by "
                f"{ATLAS_OWNERSHIP} and its ledger ({paths[phase]}) has a row for none "
                f"of these {len(only_atlas)}: an export no ledger mentions cannot be "
                "shown to be implemented, open or handed on, so the stratum's "
                "completeness claim does not cover it:\n  "
                + "\n  ".join(only_atlas)
            )

        # 2. A row for an export the atlas gives elsewhere must be justified.
        only_ledger = sorted(ledger_symbols - atlas_symbols)
        unjustified: list[str] = []
        for sym in only_ledger:
            owner_phase = atlas_owner.get((CLAIM_LIBS[0], sym))
            if owner_phase is None:
                problems.append(
                    f"phase {phase}'s ledger lists {sym}, which the ownership atlas "
                    "does not assign to any stratum"
                )
                continue
            if deferred_to.get((owner_phase, sym)) != phase:
                unjustified.append(sym)
        if unjustified:
            problems.append(
                f"phase {phase}'s ledger carries these exports, which the atlas "
                "assigns to another stratum that does not defer them here, so the two "
                "ledgers disagree about who owes them:\n  "
                + "\n  ".join(unjustified)
            )

        ledger_agreement.append({
            "phase": phase,
            "ledger": paths[phase],
            "atlas": len(atlas_symbols),
            "ledger": len(ledger_symbols),
            "implemented": len(implemented_rows),
            "open": len(open_rows),
            "deferred": len(deferred_rows),
            "only_in_atlas": len(only_atlas),
            "only_in_ledger": len(only_ledger),
            "only_in_atlas_examples": only_atlas[:10],
            "only_in_ledger_examples": only_ledger[:10],
        })

    # 3. No export counted `implemented` by two strata.
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

    # 4. Hand-off edges, in both directions. `deferred_to` is the union of the
    # deferring strata's `deferred` rows and the receiving strata's
    # `handoffs_discharged`, so a disagreement between the two readings is itself the
    # signal -- but the reconciliation is done on the two readings separately, so a
    # mismatch names which side is missing.
    recorded: dict[tuple[int, int], set[str]] = {}
    for phase, rows in ledger_bodies.items():
        for row in rows.get("deferred") or []:
            if isinstance(row, dict) and "owning_phase" in row:
                recorded.setdefault((phase, int(row["owning_phase"])), set()).add(
                    row["symbol"]
                )
    declared: dict[tuple[int, int], set[str]] = {}
    for phase, rows in ledger_bodies.items():
        for source, syms in (rows.get("handoffs_discharged") or {}).items():
            declared.setdefault((int(source), phase), set()).update(syms)

    mismatched_handoffs: list[dict] = []
    for edge in sorted(set(recorded) | set(declared)):
        if edge[1] not in ledger_bodies:
            continue  # the receiving stratum has no ledger yet: a forward hand-off
        want, got = recorded.get(edge, set()), declared.get(edge, set())
        if want != got:
            mismatched_handoffs.append({
                "from_phase": edge[0], "to_phase": edge[1],
                "deferred_but_not_declared": sorted(want - got),
                "declared_but_not_deferred": sorted(got - want),
            })
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

    # The remainder: everything the authority exports that no ledger covers, which is
    # the scope of the strata that have not been reached yet. A census, not a defect,
    # but recorded in full rather than left implied.
    unowned: dict[str, dict] = {}
    for lib in LIBS:
        symbols = json.loads(
            (authdir / f"symbols-{lib}.json").read_text(encoding="utf-8")
        )["body"]["records"]
        all_syms = sorted(r["symbol"] for r in symbols if r["dso"]["present"])
        covered_phases = set(ledger_bodies)
        left = [s for s in all_syms
                if atlas_owner.get((lib, s)) not in covered_phases]
        classes = Counter(family_key(s) for s in left)
        unowned[lib] = {
            "count": len(left),
            "covered_by_a_ledger": len(all_syms) - len(left),
            "classes": [{"class": k, "count": v} for k, v in classes.most_common()],
            "symbols": left,
        }

    body = {
        "invariant": (
            "every authority export has exactly one declared owner in "
            "forensics/atlas/symbol-ownership.json; every export the atlas gives a "
            "stratum appears in that stratum's ledger; every row a stratum's ledger "
            "carries for another stratum's export is a hand-off that stratum recorded"
        ),
        "atlas": {
            "artifact": ATLAS_OWNERSHIP,
            "exports": doc["universe"]["exports"],
            "invariants": doc["invariants"],
            "by_phase": doc["by_phase"],
            "rules": doc["rules"],
        },
        "ledgers": [{"phase": p, "ledger": paths[p]} for p in sorted(paths)],
        "ledger_agreement": ledger_agreement,
        "why": (
            "an export that no ledger mentions is invisible to every completeness "
            "claim at once, so the shell scaffolds it and no obligation records it "
            "(docs/DECISIONS.md D49, D51, D72, D97)"
        ),
        "claim_scope": (
            "libcrypto only: no ledger published so far owns a libssl export, so "
            "libssl is reported as covered by no ledger rather than counted through "
            "accidental name matches"
        ),
        "implemented_exports": {lib: len(impl[lib]) for lib in LIBS},
        "unowned_implemented": unowned_implemented,
        "unowned_remainder": unowned,
        "implemented_by_two_strata": double_implemented,
        "handoff_reconciliation": {
            "rule": (
                "for every hand-off edge whose receiving stratum has a ledger, the set "
                "the deferring stratum hands over equals the set the receiving stratum "
                "declares it discharged"
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
                if k[1] not in ledger_bodies
            ],
            "mismatched": mismatched_handoffs,
        },
        "problems": problems,
        "note": (
            "`unowned_remainder` is not a defect: the strata above Phase 6 have no "
            "ledgers yet, so their exports are covered by nothing. It is the scope no "
            "ledger has claimed, recorded as a count and in full rather than left "
            "implied. `implemented_by_two_strata` and `handoff_reconciliation` are the "
            "cross-ledger invariants that stop one piece of work being counted twice "
            "or falling between two strata, and `ledger_agreement` is the atlas "
            "reconciliation in both directions. Only `problems` is a defect list, and "
            "a non-empty one fails this tool."
        ),
    }

    inputs = [
        InputRef(name="implemented-surface", path=REPO_ROOT / "forensics" / "atlas"
                 / "implemented-surface.json"),
        InputRef(name="authority-symbols", path=authdir / "symbols-libcrypto.json"),
        InputRef(name="symbol-ownership", path=REPO_ROOT / ATLAS_OWNERSHIP),
    ]
    for phase in sorted(paths):
        inputs.append(InputRef(name=f"ledger-{phase}", path=REPO_ROOT / paths[phase]))

    write_json(OUT, envelope(kind="ownership-audit", authority=auth.id, inputs=inputs,
                             body=body, generator=GENERATOR))

    print(f"[ownership-audit] authority={auth.id}")
    print(f"  atlas: {doc['universe']['exports']} exports, "
          f"by_phase={doc['by_phase']}")
    for row in ledger_agreement:
        print(f"  phase {row['phase']}: atlas={row['atlas']:4} ledger={row['ledger']:4} "
              f"(impl={row['implemented']} open={row['open']} "
              f"deferred={row['deferred']}) "
              f"only_in_atlas={row['only_in_atlas']} "
              f"only_in_ledger={row['only_in_ledger']}")
    for lib in LIBS:
        print(f"  {lib:9} implemented={body['implemented_exports'][lib]:5} "
              f"covered_by_a_ledger={unowned[lib]['covered_by_a_ledger']:5} "
              f"outside_every_ledger={unowned[lib]['count']:5}")
    print(f"  cross-ledger: {len(double_implemented)} double-counted symbol(s), "
          f"{len(mismatched_handoffs)} mismatched hand-off edge(s)")
    for k, v in sorted(declared.items()):
        print(f"  hand-off phase {k[0]} -> {k[1]}: {len(v)} discharged")
    for k, v in sorted(recorded.items()):
        if k[1] not in ledger_bodies:
            print(f"  hand-off phase {k[0]} -> {k[1]}: {len(v)} recorded "
                  "(receiving stratum has no ledger yet)")
    print(f"  -> {rel(OUT)}")
    if problems:
        print("  FAIL")
        for p in problems:
            print(f"    {p}")
        return 1
    print("  every atlas-owned export has a ledger row, and every ledger row is owned")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
