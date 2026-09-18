#!/usr/bin/env python3
"""openssl-rs — the court coverage atlas: every implemented export's court.

Why this exists
---------------
The Phase-7 seal opened with the claim that every implemented export of the stratum
is "implemented **and observed by a differential court**". The two exit criteria that
were actually machine-checked -- `open_in_this_stratum == 0` and `every court passes`
-- do not imply that claim. They imply *some* set of exports has a court and *every
court that exists* passes; nothing joins the two. At seven hundred and six exports
that is an unproven assertion in a project whose whole discipline is that a claim is
a fact a reader can recompute.

This tool performs the missing join. For every **completed** stratum it partitions
every export that stratum owns into exactly three disjoint sets:

  1. **directly courted** -- the name is an undefined dynamic symbol of a staged
     candidate probe that ran and produced a transcript. The court names are the
     reason.
  2. **indirectly courted** -- reached only through another entry point. The edge is
     explicit: the symbol, the public entry that exercises it, and the court. It is
     *checked*, not asserted: the entry must itself be directly courted by a probe of
     the same court, so an edge cannot name a path no transcript drives.
  3. **explicitly non-observable** -- a reason, and the court that observes the
     symbol's downstream effect. "No observable" is only admissible when it is true.

and it **fails, naming them**, if any implemented export of a completed stratum is in
none of the three.

How set 1 is derived, and precisely what it claims
--------------------------------------------------
Set 1 is read from the ELF **`.dynsym`** of each staged candidate probe
(`forensics/tools/elf_symbols.py`, via the reader this tool added to it), not from the
probe's source. A regex over the probe source cannot tell a call from a comment or a
`#if 0`, and this plane's whole point is that it is derived from what actually ran:
the candidate binary is the one whose imports prove the crate's symbol was linked and
exercised. The authority-side binaries are the comparison and are not read here.

One honesty note is load-bearing and is repeated in the document's own `claim` field.
An undefined dynamic symbol is a name the binary **references**; it is not proof that
every arm of the function ran. A probe that takes a function's address, or stores it
in a dispatch table it later calls through, imports the symbol exactly as a direct call
does. So `directly_courted` claims *"referenced by a probe that ran and produced a
transcript"* and does **not** claim *"every branch was driven"*. Overstating that
would repeat, one level down, the defect this atlas exists to remove.

Inputs and outputs
------------------
    inputs:  forensics/phase<N>-obligations.json        (the implemented sets)
             forensics/atlas/implemented-surface.json   (the universe assertion)
             forensics/atlas/symbol-ownership.json      (owner_phase per symbol)
             artifacts/phase<N>/COURTS.json             (court -> staged candidate)
             forensics/atlas/court-coverage-rows.json   (sets 2 and 3, authored)
    output:  forensics/atlas/court-coverage.json

Sets 2 and 3 are a *committed data file* rather than a table inside this generator.
The reason is that they are evidence: each row is a claim a reader audits, and a row
changed in review reads as a data diff instead of a code diff. This generator
validates every row against the universe above, so the file cannot drift into naming a
symbol no stratum owns or an entry no court drives.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    ATLAS,
    REPO_ROOT,
    InputRef,
    envelope,
    rel,
    write_json,
)

from elf_symbols import ElfError, undefined_dynamic_symbols  # noqa: E402

OUT = ATLAS / "court-coverage.json"
ROWS = ATLAS / "court-coverage-rows.json"
IMPL_SURFACE = ATLAS / "implemented-surface.json"
OWNERSHIP = ATLAS / "symbol-ownership.json"
LEDGER_GLOB = "forensics/phase*-obligations.json"
LEDGER_RE = re.compile(r"phase(\d+)-obligations\.json")

CLAIM = (
    "`directly_courted` means the symbol is an undefined dynamic symbol of a staged "
    "candidate probe that ran and produced a transcript. It does NOT mean every arm "
    "of the symbol was driven: a name that is only address-taken, or stored in a "
    "dispatch table, is imported exactly as a direct call is. `indirectly_courted` is "
    "an explicit, checked edge -- the named entry is itself directly courted by a probe "
    "of the named court. `non_observable` is a symbol whose effect no probe can isolate, "
    "with the reason and the court that observes its downstream effect. A symbol in none "
    "of the three fails this generator by name."
)


class CoverageError(SystemExit):
    """The atlas cannot be derived, and says why."""


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def discover_ledgers() -> dict[int, tuple[Path, dict]]:
    out: dict[int, tuple[Path, dict]] = {}
    for p in sorted(REPO_ROOT.glob(LEDGER_GLOB)):
        m = LEDGER_RE.fullmatch(p.name)
        if m:
            out[int(m.group(1))] = (p, read_json(p))
    return out


def court_binaries(phase: int) -> tuple[dict[str, list[str]], dict[str, dict]]:
    """For one stratum: (court -> staged candidate paths, court -> court row).

    The court rows come from the generated `COURTS.json`, so this reads what the
    runners actually built rather than a list this tool keeps. A court with no staged
    candidate binary is skipped here and reported by the caller, because a court that
    produced no binary proved nothing about the symbols under this derivation.
    """
    path = REPO_ROOT / "artifacts" / f"phase{phase}" / "COURTS.json"
    if not path.is_file():
        return {}, {}
    doc = read_json(path)
    binaries: dict[str, list[str]] = {}
    rows: dict[str, dict] = {}
    for c in doc["body"]["courts"]:
        name = c["court"]
        rows[name] = c
        staged = c.get("staged_binaries", {}).get("candidate")
        if staged:
            binaries.setdefault(name, []).append(staged)
    return binaries, rows


def main() -> int:
    ledgers = discover_ledgers()
    if not ledgers:
        raise CoverageError("[court-coverage] fatal: no obligation ledgers found")

    # The universe assertion: every implemented export in the manifest belongs to
    # exactly one ledger, and the ledgers together are exactly the manifest. If a
    # stratum lands implementations but no ledger, the manifest will carry a symbol the
    # union does not, and this fails rather than silently shrinking the atlas.
    surface = read_json(IMPL_SURFACE)
    implemented_manifest = set(
        surface["body"]["libraries"]["libcrypto"]["implemented_symbols"]
    )
    owner: dict[str, int] = {}
    impl: dict[int, set[str]] = {}
    for phase, (path, doc) in sorted(ledgers.items()):
        body = doc["body"]
        names = set(body["implemented"])
        impl[phase] = names
        for sym in names:
            if sym in owner and owner[sym] != phase:
                raise CoverageError(
                    f"[court-coverage] fatal: {sym} is implemented by both phase "
                    f"{owner[sym]} and phase {phase}"
                )
            owner[sym] = phase
    union = set(owner)
    missing = sorted(implemented_manifest - union)
    extra = sorted(union - implemented_manifest)
    if missing or extra:
        raise CoverageError(
            "[court-coverage] fatal: the ledgers and implemented-surface.json disagree "
            f"about the universe; in the manifest but in no ledger: {missing[:20]}"
            f"{' ...' if len(missing) > 20 else ''}; in a ledger but not the manifest: "
            f"{extra[:20]}{' ...' if len(extra) > 20 else ''}"
        )

    # The ownership atlas is the other half of the universe assertion. It assigns every
    # *authority* export to exactly one owner phase; the ledgers' implemented sets are
    # drawn from it, and a ledger symbol the atlas has never heard of would mean this
    # tool is partitioning a name no authority defines. (A ledger may implement a symbol
    # the atlas assigns another phase -- the crate places `BIO_asn1_*` in a Phase-5
    # module though `bio.h` owns it, and `ownership_audit.py` is the arbiter of whether
    # that placement is a problem, reporting `problems: 0` over the whole tree. It is
    # not this tool's business to re-litigate that here.)
    ownership = read_json(OWNERSHIP)
    owner_by_symbol = {r["symbol"]: r["owner_phase"] for r in ownership["body"]["records"]}
    unknown = sorted(s for s in union if s not in owner_by_symbol)
    if unknown:
        raise CoverageError(
            "[court-coverage] fatal: the ledgers implement symbol(s) symbol-ownership.json "
            f"does not record, so the export universe is not the atlas's: {unknown[:20]}"
            f"{' ...' if len(unknown) > 20 else ''}"
        )

    completed = sorted(
        phase for phase, (_p, doc) in ledgers.items() if doc["body"].get("complete")
    )

    # ---- set 1, from the staged candidate ELF dynamic tables ----
    courts_for: dict[str, set[str]] = {}
    court_index: dict[str, dict] = {}
    per_stratum_probe_count: dict[int, int] = {}
    for phase in completed:
        binaries, rows = court_binaries(phase)
        court_index.update(rows)
        n = 0
        for court, paths in binaries.items():
            for staged in paths:
                p = REPO_ROOT / staged
                if not p.is_file():
                    continue
                n += 1
                try:
                    imported = undefined_dynamic_symbols(p)
                except ElfError as exc:
                    raise CoverageError(
                        f"[court-coverage] fatal: {staged} is not an ELF object this "
                        f"reader understands: {exc}"
                    ) from exc
                for sym in imported:
                    courts_for.setdefault(sym, set()).add(court)
        per_stratum_probe_count[phase] = n

    # ---- sets 2 and 3, authored ----
    if not ROWS.is_file():
        raise CoverageError(f"[court-coverage] fatal: rows file absent: {rel(ROWS)}")
    rows = read_json(ROWS)
    indirect = {r["symbol"]: r for r in rows.get("indirect", [])}
    non_observable = {r["symbol"]: r for r in rows.get("non_observable", [])}
    reference_probes = set(rows.get("reference_probes", []))
    overlap = sorted(set(indirect) & set(non_observable))
    if overlap:
        raise CoverageError(
            f"[court-coverage] fatal: {overlap} appear in both the indirect and the "
            f"non-observable table; the sets must be disjoint"
        )
    unknown_ref = sorted(reference_probes - set(court_index))
    if unknown_ref:
        raise CoverageError(
            f"[court-coverage] fatal: reference_probes names {unknown_ref}, which is not "
            f"a court in any completed stratum's COURTS.json"
        )

    # ---- the partition, and the join that fails closed ----
    strata: list[dict] = []
    unmatched: list[str] = []
    problems: list[str] = []
    totals = {"implemented": 0, "directly_courted": 0, "directly_courted_called": 0,
              "directly_courted_referenced": 0, "indirectly_courted": 0,
              "non_observable": 0}

    for sym, r in sorted(indirect.items()):
        if sym not in owner:
            problems.append(f"indirect row names {sym}, which no stratum implements")
            continue
        if owner[sym] not in completed:
            problems.append(
                f"indirect row names {sym}, owned by phase {owner[sym]}, which is not "
                f"complete"
            )
            continue
        entry = r.get("entry")
        court = r.get("court")
        if not entry or not court:
            problems.append(f"indirect row {sym} needs both `entry` and `court`")
            continue
        if entry not in owner:
            problems.append(
                f"indirect row {sym} names entry {entry}, which no stratum implements"
            )
            continue
        if court not in courts_for.get(entry, set()):
            problems.append(
                f"indirect row {sym} names court {court}, but {court} does not directly "
                f"court the entry {entry}"
            )
        if not r.get("authority"):
            problems.append(f"indirect row {sym} needs an `authority` citation")

    for sym, r in sorted(non_observable.items()):
        if sym not in owner:
            problems.append(f"non-observable row names {sym}, which no stratum implements")
            continue
        if owner[sym] not in completed:
            problems.append(
                f"non-observable row names {sym}, owned by phase {owner[sym]}, which is "
                f"not complete"
            )
            continue
        if not r.get("reason") or not r.get("court") or not r.get("authority"):
            problems.append(
                f"non-observable row {sym} needs `reason`, `court` and `authority`"
            )
        if r.get("court") not in court_index:
            problems.append(
                f"non-observable row {sym} names court {r.get('court')}, which is not a "
                f"court in this atlas"
            )

    for phase in completed:
        direct, ind, non = [], [], []
        for sym in sorted(impl[phase]):
            if sym in courts_for:
                courts = sorted(courts_for[sym])
                # A name is `called` if any behavioural probe imports it; it is
                # `referenced` only if the reference probes are the *only* importers.
                # The distinction is the whole point of the weaker claim: it is
                # derived from which stage produced the import, not asserted.
                called = sorted(set(courts) - reference_probes)
                direct.append({
                    "symbol": sym,
                    "courts": courts,
                    "basis": "called" if called else "referenced",
                })
            elif sym in indirect:
                ind.append(dict(indirect[sym]))
            elif sym in non_observable:
                non.append(dict(non_observable[sym]))
            else:
                unmatched.append(f"phase {phase}: {sym}")
        called_n = sum(1 for d in direct if d["basis"] == "called")
        referenced_n = len(direct) - called_n
        counts = {
            "implemented": len(impl[phase]),
            "directly_courted": len(direct),
            "directly_courted_called": called_n,
            "directly_courted_referenced": referenced_n,
            "indirectly_courted": len(ind),
            "non_observable": len(non),
            "unmatched": len(impl[phase]) - len(direct) - len(ind) - len(non),
        }
        for k in ("implemented", "directly_courted", "directly_courted_called",
                  "directly_courted_referenced", "indirectly_courted",
                  "non_observable"):
            totals[k] += counts[k]
        strata.append({
            "phase": phase,
            "completed": True,
            "staged_candidate_probes": per_stratum_probe_count.get(phase, 0),
            "counts": counts,
            "directly_courted": direct,
            "indirectly_courted": ind,
            "non_observable": non,
        })

    if problems:
        raise CoverageError(
            "[court-coverage] fatal: authored rows do not hold:\n  "
            + "\n  ".join(problems)
        )
    if unmatched:
        raise CoverageError(
            f"[court-coverage] fatal: {len(unmatched)} implemented export(s) of a "
            "completed stratum are in none of directly-courted, indirectly-courted or "
            "non-observable; add a probe arm that makes each observable, an explicit "
            "indirect edge, or a truthful non-observable row:\n  "
            + "\n  ".join(unmatched)
        )

    inputs = [
        InputRef(name="implemented-surface", path=IMPL_SURFACE),
        InputRef(name="symbol-ownership", path=OWNERSHIP),
        InputRef(name="coverage-rows", path=ROWS),
    ]
    for phase in completed:
        inputs.append(InputRef(name=f"phase{phase}-obligations",
                               path=REPO_ROOT / f"forensics/phase{phase}-obligations.json"))
        inputs.append(InputRef(name=f"phase{phase}-courts",
                               path=REPO_ROOT / "artifacts" / f"phase{phase}" / "COURTS.json"))

    body = {
        "authority": surface["authority"],
        "claim": CLAIM,
        "definition": (
            "a completed stratum is one whose obligation ledger records `complete`; "
            "every export that ledger implements is partitioned below"
        ),
        "strata": strata,
        "totals": totals,
        "unmatched": 0,
    }
    doc = envelope(kind="court-coverage", generator="forensics/tools/court_coverage.py",
                   inputs=inputs, body=body, authority=surface["authority"])
    write_json(OUT, doc)

    for s in strata:
        c = s["counts"]
        print(f"  phase {s['phase']}: implemented={c['implemented']} "
              f"direct={c['directly_courted']} "
              f"(called={c['directly_courted_called']},"
              f" referenced={c['directly_courted_referenced']}) "
              f"indirect={c['indirectly_courted']} "
              f"non_observable={c['non_observable']}")
    print(f"  totals: {totals}")
    print(f"  -> {rel(OUT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
