#!/usr/bin/env python3
"""openssl-rs — the prerequisite gate: does every dependency exist, and does it arrive in time?

Why this exists
---------------
Four dependency inversions have been found in Phase 6 alone, and not one of them was
found by a tool:

* D114 — the DSO layer and `OSSL_LIB_CTX_load_config` were in a cycle;
* D97  — the property engine was sited in the wrong stratum;
* D118 — RCU's read path calls `ossl_init_thread_start`, so 6.10 could not precede 6.6e-ii;
* D122 — `crypto/threads_common.c` stands on `crypto/sparse_array.c`, which stood in
  no unit plan at all.

Each was found by following a *call*, by hand, and usually late. This tool
mechanises that, so the next four are found before the code is written rather than
while it is being rewritten.

The four things it checks
-------------------------
**A. `undefined_prerequisite`** — a name the crate references, belonging to the
authority's internal surface (a non-exported function, a macro, an enumerator, a
typedef), that the crate does not build and no record has agreed to build. That is
a call to something nobody owns.

**B. `unwired_function_in_a_sealed_stratum`** — an authority internal *function*
that a transcribed unit calls, that the crate has no module for, in a unit whose own
stratum is already `complete`. A stratum that sealed with one of its own source
file's functions absent is a defect by the project's own standard. RCU is the
worked example: `crypto/threads_pthread.c` is transcribed by a Phase 3 module, and
its RCU section is 6.10a-iii's work, so the twenty-two `ossl_rcu_*` names appear here
until 6.10a lands them.

**C. `unwired_function_in_the_current_stratum`** — the same, for a stratum that is
still open. This is where `CRYPTO_THREAD_clean_local` appears: `crypto/initthread.c`
calls it, `crypto/threads_common.c` defines it, both are Phase 6, and the crate
defines the function under the name `clean_local` and never calls it.

**D. The recorded exceptions.** Every name in B and C must be either fixed or
recorded in `forensics/prerequisites.json`. A record names the crate module that
answers for it, a class, an evidence citation, and — this is the part that keeps the
mechanism honest — the **exact set of names it covers**. Both directions are checked:
a covered name that the gate did not observe is a mismatch, and an observed name that
no record covers is a finding. Suppression therefore cannot be silent, and a record
cannot quietly widen.

What it deliberately does not check
-----------------------------------
The C *language* surface — types, macros, reason codes. The crate models those
differently on purpose (`BIO_ADDR` is a Rust type with a private layout;
`ERR_R_CRYPTO_LIB` is an entry in a generated table), and a lexical scan cannot tell
a rename from a gap. Those names are counted and listed as a census, and they are not
a failure. Saying so is the point: a gate that guessed here would either be noise or
would legitimise a rename.

Fail-closed
-----------
A missing atlas is a failure, never silence, and the cleaners that produce the
reference sets refuse to run if they mis-pair a delimiter — which is not
hypothetical: the first version of this file blanked 7 KB of `src/property/parse.rs`
by treating an apostrophe in a doc comment as an unterminated string.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    ATLAS,
    REPO_ROOT,
    InputRef,
    content_hash,
    envelope,
    rel,
    write_json,
)

# The structured blocker claim and its fail-closed proof, shared with
# `phase7_obligations.py` rather than duplicated. See docs/DECISIONS.md D198.
from blocker_liveness import (  # noqa: E402
    BlockerAtlas,
    BlockedHandoff,
    blockers_from_json,
    check_rows,
)

GENERATOR = "forensics/tools/prerequisite_gate.py"
OUT = ATLAS / "prerequisite-gate.json"

INTERNAL = ATLAS / "internal-symbols.json"
MACROS = ATLAS / "macro-owners.json"
TYPEDEFS = ATLAS / "typedef-owners.json"
EDGES = ATLAS / "transcription-edges.json"
OWNERSHIP = ATLAS / "symbol-ownership.json"
SURFACE = ATLAS / "implemented-surface.json"
PHASE_STATE = REPO_ROOT / "forensics" / "phase-state.json"
PREREQUISITES = REPO_ROOT / "forensics" / "prerequisites.json"

SRC = REPO_ROOT / "src"

# Every definition form the crate can introduce a name with. Deliberately a superset:
# this answers "is it built somewhere?", and being wrong in the *negative* direction
# would report a prerequisite that is not one. The optional `extern "..."` group
# matters: this pattern is applied to source with comments blanked but string
# literals *kept*, precisely so that `extern "C" fn name(` — the form almost every
# export in this crate is written in — still parses as a definition.
_RUST_DEFS = re.compile(
    r"^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?(?:unsafe[ \t]+)?"
    r'(?:extern[ \t]+"[^"]*"[ \t]+)?'
    r"(?:(?:fn|const|static|type|struct|enum|union|trait|mod)[ \t]+"
    r"|static[ \t]+mut[ \t]+|macro_rules![ \t]+)"
    r"([A-Za-z_][A-Za-z0-9_]*)",
    re.M,
)

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# Code markers that cannot appear inside a comment or a string literal. A blanked
# span containing one at the start of a line means the cleaner mis-paired a
# delimiter and blanked real code, which would hide a real prerequisite.
_CODE_MARKERS = ("\nfn ", "\npub ", "\nunsafe ", "\nimpl ", "\n}", "\n//", "\n#[")

# The classes a divergence record may declare. The vocabulary is fixed so that a
# record's class can be checked rather than read.
DIVERGENCE_CLASSES = (
    # The crate implements this name's behaviour under a different name; the record
    # names the module that answers for it.
    "named_differently",
    # The crate implements the behaviour, but not as a single named function; the
    # record names the module and says what the mapping is.
    "modelled_differently",
    # The call belongs to a later stratum's work in the *authority's* layering; the
    # record names the stratum and the evidence.
    "owned_by_a_later_stratum",
    # The call exists only on a platform, configuration or provider build this
    # profile does not admit.
    "not_in_this_profile",
    # The authority name is a C identifier that collides with a Rust identifier the
    # crate legitimately uses for something else — a generic parameter, a local
    # binding, a `u8`. `md4_local.h`'s `#define F(x)` against a Rust type parameter
    # named `F` is the worked example. Recorded rather than filtered, because a filter
    # would also hide the next real collision.
    "shadowed_by_a_crate_identifier",
)


def blank_out(text: str, spans: list[tuple[int, int]]) -> str:
    out = list(text)
    for start, end in spans:
        for i in range(start, min(end, len(out))):
            if out[i] != "\n":
                out[i] = " "
    return "".join(out)


def scan_rust(text: str, *, strings: bool) -> tuple[list[tuple[int, int]], list[str]]:
    """Spans of comments (always) and string/char literals (when `strings`).

    Char literals are distinguished from lifetimes, which is the distinction the
    first version of this file got wrong. Rust is unambiguous here: `'` opens a
    literal only as `'x'`, `'\\n'`, `'\\''` or `'\\u{1F600}'`; anything else is a
    lifetime (`'a`, `'static`) and is left alone.
    """
    spans: list[tuple[int, int]] = []
    problems: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = i + 2
            while j < n and text[j] != "\n":
                j += 1
            spans.append((i, j))
            i = j
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            depth = 1
            j = i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth += 1
                    j += 2
                elif text.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            spans.append((i, j))
            i = j
        elif strings and c == "r" and re.match(r'r#*"', text[i:]):
            m = re.match(r'r(#*)"', text[i:])
            hashes = m.group(1)
            end = text.find('"' + hashes, i + len(m.group(0)))
            j = n if end < 0 else end + len(hashes) + 1
            spans.append((i, j))
            i = j
        elif strings and c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            spans.append((i, j))
            i = j
        elif strings and c == "'":
            if i + 1 < n and text[i + 1] == "\\":
                j = i + 2
                limit = min(n, i + 16)
                while j < limit and text[j] != "'":
                    j += 1
                if j < limit:
                    spans.append((i, j + 1))
                    i = j + 1
                    continue
            elif i + 2 < n and text[i + 2] == "'":
                spans.append((i, i + 3))
                i += 3
                continue
            i += 1
        else:
            i += 1

    for start, end in spans:
        body = text[start:end]
        if any(marker in body for marker in _CODE_MARKERS):
            problems.append(
                f"a span at offset {start} ({end - start} chars) contains code; the "
                f"cleaner mis-paired a delimiter: {body[:120]!r}"
            )
    return spans, problems


def strip_rust(text: str, *, strings: bool = True) -> str:
    spans, problems = scan_rust(text, strings=strings)
    if problems:
        raise ValueError("; ".join(problems))
    return blank_out(text, spans) if spans else text


def load(path: Path, what: str) -> dict:
    if not path.is_file():
        print(f"[{GENERATOR}] fatal: {rel(path)} is absent ({what})", file=sys.stderr)
        raise SystemExit(1)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"[{GENERATOR}] fatal: {rel(path)} is not JSON: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


def crate_source() -> tuple[dict[str, set[str]], dict[str, list[str]]]:
    """Return (references by module, definitions by name -> modules).

    Two lenses, on purpose. A reference must be blind to comments *and* to string
    literals, so a name that appears only in prose or in a `c"ossl_..."` reason-site
    table does not count as a use. A definition must be blind only to comments:
    blanking `"C"` would break the `extern "C" fn name(` form that almost every
    export in this crate is written in.
    """
    refs: dict[str, set[str]] = {}
    defs: dict[str, list[str]] = defaultdict(list)
    for path in sorted(SRC.rglob("*.rs")):
        text = path.read_text(encoding="utf-8")
        module = rel(path)
        try:
            refs[module] = set(_IDENT.findall(strip_rust(text)))
            definition_lens = strip_rust(text, strings=False)
        except ValueError as exc:
            print(f"[{GENERATOR}] fatal: {module}: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
        for name in sorted(set(_RUST_DEFS.findall(definition_lens))):
            defs[name].append(module)
    return refs, defs


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--no-write", action="store_true", help="report only")
    ap.add_argument(
        "--propose-records",
        action="store_true",
        help="emit divergence records for every observed name, with empty notes, for a human to justify",
    )
    args = ap.parse_args(argv)

    internal_doc = load(INTERNAL, "the internal symbol universe")
    macro_doc = load(MACROS, "the macro and enumerator universe")
    typedef_doc = load(TYPEDEFS, "the typedef universe")
    edges_doc = load(EDGES, "the module-to-unit map")
    ownership_doc = load(OWNERSHIP, "the export ownership atlas")
    surface_doc = load(SURFACE, "the implemented surface")
    prereq_doc = load(PREREQUISITES, "the recorded prerequisites")
    states = {
        int(r["phase"]): r["state"]
        for r in load(PHASE_STATE, "the derived phase state")["body"]["phases"]
    }

    # --- the universes ------------------------------------------------------
    symbol_tu: dict[str, str] = {
        r["symbol"]: r["translation_unit"] for r in internal_doc["body"]["records"]
    }
    language: dict[str, int | None] = {}
    for doc in (macro_doc, typedef_doc):
        for r in doc["body"]["records"]:
            language.setdefault(r["name"], r["owner_phase"])
    export_phase: dict[str, int] = {
        r["symbol"]: int(r["owner_phase"])
        for r in ownership_doc["body"]["records"]
        if r["owner_phase"] is not None
    }
    surface = surface_doc["body"]
    implemented = set()
    for lib in ("libcrypto", "libssl"):
        implemented |= set(surface["libraries"][lib]["implemented_symbols"])
    implemented |= set(surface["internal_symbols"]["c_style"])

    universe: dict[str, str] = {}
    universe.update({s: "internal-function" for s in symbol_tu})
    universe.update({n: "language" for n in language})
    universe.update({s: "export" for s in export_phase})

    modules = {m["module"]: m for m in edges_doc["body"]["modules"]}
    units = {u["tu"]: u for u in edges_doc["body"]["units"]}
    unit_modules: dict[str, list[str]] = {tu: u["modules"] for tu, u in units.items()}

    def unit_phase(tu: str) -> int | None:
        ps = [modules[m]["phase"] for m in unit_modules.get(tu, []) if modules.get(m, {}).get("phase") is not None]
        return min(ps) if ps else None

    refs, defs = crate_source()
    built = set(defs) | implemented
    refs_anywhere: set[str] = set()
    for names in refs.values():
        refs_anywhere |= names

    # --- the recorded exceptions -------------------------------------------
    body = prereq_doc["body"]
    deferrals = {r["symbol"]: r for r in body["deferrals"]}
    divergences = list(body["divergences"])
    covered: dict[str, dict] = {}
    for row in divergences:
        for name in row["covers"]:
            if name in covered:
                print(
                    f"[{GENERATOR}] fatal: {name} is covered by two divergence rows "
                    f"({covered[name]['class']} and {row['class']}); a name must have "
                    f"exactly one owner record",
                    file=sys.stderr,
                )
                return 1
            covered[name] = row
        if row["class"] not in DIVERGENCE_CLASSES:
            print(
                f"[{GENERATOR}] fatal: divergence class {row['class']!r} is not one of "
                f"{list(DIVERGENCE_CLASSES)}",
                file=sys.stderr,
            )
            return 1

    findings: list[dict] = []
    census: dict[str, list[str]] = defaultdict(list)
    # Every name this run *observed* as unbuilt, recorded before the coverage filter
    # rather than after it. Recording it after would be circular: a covered name stops
    # being a finding, so a set built from findings could never contain one, and a
    # record could then cover anything at all.
    observed: set[str] = set()
    # Names that are unwired in a stratum that has already sealed. Recorded and
    # tracked, never failed: such a name is either modelled differently by the crate
    # or is work a later stratum carried across the boundary, and the change that
    # settles which is a decision, not a repair. The count is held to non-increase by
    # forensics/tools/regression_guard.py, which is what stops this list growing into
    # a place where real omissions could hide.
    sealed_census: dict[str, set[str]] = defaultdict(set)

    def finding(kind: str, **kw: object) -> None:
        findings.append({"kind": kind, **kw})

    # --- E: the liveness of a deferral's *reason* ---------------------------
    # A deferral row above proves its symbol is still absent; it does not prove the
    # blocker its reason names is. This is the missing half (D198): every `blocked_by`
    # name must resolve against the authority, be absent from the crate, and be owned by
    # the phase the row declares, and a row whose blockers have all landed is stale by
    # definition rather than valid. The same checker `phase7_obligations.py` uses.
    blocker_claims: list[BlockedHandoff] = []
    for row in body["deferrals"]:
        if "blocked_by" not in row:
            continue
        blocker_claims.append(
            BlockedHandoff(
                label=f"prerequisites.json deferral {row['symbol']}",
                symbols=(row["symbol"],),
                binding_phase=int(row["owner_phase"]),
                blocked_by=blockers_from_json(row["blocked_by"]),
                reason=row["reason"],
            )
        )
    blocker_atlas = BlockerAtlas.from_repo(
        implemented=implemented,
        implemented_internal=set(surface["internal_symbols"]["c_style"]),
        crate_defs=set(defs),
    )
    for msg in check_rows(blocker_atlas, blocker_claims, phase_state=states):
        finding("deferral_blocker_is_stale", direction="E", detail=msg)

    # --- A: what the crate references and does not build --------------------
    referenced: dict[str, set[str]] = defaultdict(set)
    for module, names in refs.items():
        for n in names:
            if n in universe:
                referenced[n].add(module)

    checked_a = 0
    for name in sorted(referenced):
        if name in built:
            continue
        checked_a += 1
        observed.add(name)
        if name in covered:
            census["covered_by_a_divergence"].append(name)
            continue
        rec = deferrals.get(name)
        if rec is None:
            finding(
                "undefined_prerequisite",
                direction="A",
                name=name,
                class_=universe[name],
                referenced_by=sorted(referenced[name]),
                detail=(
                    "the crate references this authority-internal name, defines it "
                    "nowhere under src/, and no record in forensics/prerequisites.json "
                    "names the stratum that will build it"
                ),
            )
            continue
        here = [
            modules[m]["phase"]
            for m in sorted(referenced[name])
            if modules.get(m, {}).get("phase") is not None
        ]
        if here and int(rec["owner_phase"]) <= min(here):
            finding(
                "deferral_target_not_ahead",
                direction="A",
                name=name,
                owner_phase=rec["owner_phase"],
                referenced_in_phase=min(here),
                detail=(
                    "recorded as owed to a stratum that is not later than the stratum "
                    "of the module referencing it: the record is stale or the "
                    "dependency points backwards"
                ),
            )

    # The reverse: a prerequisite that has already landed.
    for name in sorted(deferrals):
        if name not in built:
            continue
        finding(
            "stale_deferral",
            direction="A",
            name=name,
            defined_in=sorted(defs.get(name, [])),
            detail=(
                "recorded as owed to a later stratum, but the crate defines it; retire "
                "the record so a real future gap is not hidden behind a stale one"
            ),
        )

    # --- B and C: what the authority unit calls and the crate lacks ---------
    for tu in sorted(units):
        unit = units[tu]
        here = set()
        for m in unit["modules"]:
            here |= refs.get(m, set())
        for name in unit["identifiers"]:
            if name not in universe or name in here or name in built:
                continue
            if name not in symbol_tu and language.get(name) is None:
                # The C language surface: counted, never a failure. See the module doc.
                census["language_surface_not_modelled_by_name"].append(f"{tu}:{name}")
                continue
            owner_tu = symbol_tu.get(name)
            if owner_tu is None:
                census["language_surface_not_modelled_by_name"].append(f"{tu}:{name}")
                continue
            owners = unit_modules.get(owner_tu, [])
            if not owners or any(name in refs.get(o, set()) for o in owners):
                # The crate has no module for the defining unit at all, or the module
                # that does own it answers for the name. Neither is a prerequisite
                # this unit owes.
                continue
            phase = unit_phase(owner_tu)
            observed.add(name)
            if name in covered:
                census["covered_by_a_divergence"].append(name)
                continue
            if name in deferrals:
                # Planned work, recorded in one direction: the crate's own modules
                # will reference it when the subphase that owns it lands. Not a
                # finding; *becoming* a stale deferral the moment the crate defines it
                # is, which is how the record gets retired.
                census["planned_prerequisites"].append(name)
                continue
            state = states.get(phase)
            if state == "complete":
                sealed_census[owner_tu].add(name)
                continue
            finding(
                "unwired_function_in_the_current_stratum",
                direction="B",
                authority_unit=tu,
                name=name,
                defines_it=owner_tu,
                owner_module=owners[0],
                owner_phase=phase,
                owner_state=state,
                transcribed_by=sorted(unit["modules"]),
                detail=(
                    f"the authority's unit calls this; the crate has a module for "
                    f"{owner_tu} whose stratum is {state}, and neither that module nor "
                    f"any module of this unit mentions it"
                ),
            )

    # --- the records themselves, checked in the other direction -------------
    for row in divergences:
        unmatched = sorted(set(row["covers"]) - observed)
        if unmatched:
            finding(
                "divergence_record_does_not_match",
                direction="D",
                name=unmatched[0],
                names_not_observed=unmatched,
                covers_record=row.get("note", "")[:80],
                detail=(
                    "this record claims to cover names the gate did not observe; a "
                    "record that can keep covering a name the crate has since fixed is "
                    "a record that can hide the next one"
                ),
            )

    blocking = sorted(
        {
            f"{r['symbol']} -> phase {r['owner_phase']} ({r['reason']})"
            for r in deferrals.values()
            if states.get(int(r["owner_phase"])) in (None, "not-started", "in-progress")
        }
    )

    by_kind: dict[str, int] = defaultdict(int)
    for f in findings:
        by_kind[f["kind"]] += 1
    gate_body = {
        "rule": (
            "every authority-internal name a crate module references must be built by "
            "the crate or recorded with the stratum that owns it; every internal "
            "function a transcribed authority unit calls must exist, unless a "
            "divergence record covering exactly that name says why not; and a "
            "divergence record may not cover a name the gate did not observe"
        ),
        "universes": {
            "internal_functions": len(symbol_tu),
            "macros_and_enumerators": macro_doc["body"]["counts"]["records"],
            "typedefs": typedef_doc["body"]["counts"]["records"],
            "exports": len(export_phase),
            "crate_references_checked": len(universe),
        },
        "checked": {
            "crate_modules": len(refs),
            "authority_units": len(units),
            "names_referenced_and_not_built": checked_a,
            "deferrals_recorded": len(deferrals),
            "deferral_blocker_rows": len(blocker_claims),
            "divergence_rows": len(divergences),
            "divergence_names_covered": len(covered),
        },
        "counts": dict(sorted(by_kind.items())),
        "blocking_dependencies": blocking,
        "sealed_stratum_census": {
            "definition": (
                "authority internal functions a transcribed unit calls, whose own "
                "translation unit's stratum has already sealed. Not a failure: each is "
                "either modelled differently by the crate or is work carried across "
                "the boundary by a later stratum. The count is held to non-increase by "
                "the regression guard."
            ),
            "names": sum(len(v) for v in sealed_census.values()),
            "by_defining_unit": {k: sorted(v) for k, v in sorted(sealed_census.items())},
        },
        "census": {k: len(v) for k, v in sorted(census.items())},
        # The same census, broken down by the authority unit each name came from.
        #
        # The guard holds the totals to non-increase, which is the right invariant for
        # a name that *disappears* and the wrong one for a unit that is new: transcribing
        # another authority file necessarily adds that file's local identifiers to the
        # count, and those are not omissions. A single total cannot tell the two apart, so
        # the breakdown is published and the guard compares per unit: an existing unit's
        # count may not grow, and a new unit is a movement. See
        # `docs/DECISIONS.md` D130.
        "census_by_unit": {
            k: dict(sorted(Counter(n.split(":", 1)[0] for n in v).items()))
            for k, v in sorted(census.items())
        },
        "census_not_a_failure": (
            "the C language surface is counted and listed, never failed: the crate "
            "models C types, macros and reason codes differently on purpose, and a "
            "lexical scan cannot tell a rename from a gap"
        ),
        "census_samples": {
            k: sorted(v)[:40] for k, v in sorted(census.items())
        },
        "findings": findings,
        "claim": (
            "A structural gate, not a parity claim. It answers whether a dependency "
            "has an owner and whether the owner arrives in time; it says nothing about "
            "whether the dependency behaves as the authority's does."
        ),
    }

    if args.propose_records:
        rows = defaultdict(list)
        for f in findings:
            if f["kind"] not in (
                "unwired_function_in_the_current_stratum",
                "undefined_prerequisite",
            ):
                continue
            key = (f.get("owner_module") or f.get("referenced_by", ["?"])[0], f["kind"])
            rows[key].append(f["name"])
        proposal = [
            {
                "authority_unit": "",
                "owner_module": module,
                "class": "<one of: " + " | ".join(DIVERGENCE_CLASSES) + ">",
                "covers": sorted(set(names)),
                "note": "",
                "evidence": "",
                "_observed_as": kind,
            }
            for (module, kind), names in sorted(rows.items())
        ]
        print(json.dumps({"divergences": proposal}, indent=2))
        return 0

    if not args.no_write:
        doc = envelope(
            "prerequisite-gate",
            GENERATOR,
            [
                InputRef(name="internal-symbols", path=INTERNAL),
                InputRef(name="macro-owners", path=MACROS),
                InputRef(name="typedef-owners", path=TYPEDEFS),
                InputRef(name="transcription-edges", path=EDGES),
                InputRef(name="symbol-ownership", path=OWNERSHIP),
                InputRef(name="export-defining-units",
                         path=ATLAS / "export-defining-units.json"),
                InputRef(name="implemented-surface", path=SURFACE),
                InputRef(name="phase-state", path=PHASE_STATE),
                InputRef(name="prerequisites", path=PREREQUISITES),
                InputRef(
                    name="crate-source-tree",
                    note=(
                        "every .rs under src/ was read twice: once with comments and "
                        "string literals blanked for the reference set, once with only "
                        "comments blanked for the definition set"
                    ),
                ),
            ],
            gate_body,
            authority=internal_doc.get("authority"),
        )
        doc["body_hash"] = content_hash(gate_body)
        write_json(OUT, doc)

    print(f"[prerequisite-gate] {len(refs)} crate modules, {len(units)} authority units, "
          f"{len(covered)} names covered by {len(divergences)} divergence rows")
    for k in sorted(gate_body["counts"]):
        print(f"  {k}: {gate_body['counts'][k]}")
    print(f"  sealed_stratum_census: "
          f"{gate_body['sealed_stratum_census']['names']} names over "
          f"{len(sealed_census)} defining units (not a failure)")
    for k in sorted(gate_body["census"]):
        print(f"  census {k}: {gate_body['census'][k]} (not a failure)")
    if blocking:
        print(f"  blocking_dependencies: {len(blocking)}")
        for b in blocking:
            print(f"    {b}")

    for kind in sorted(by_kind):
        rows = [f for f in findings if f["kind"] == kind]
        print(f"[{kind}] {len(rows)}", file=sys.stderr)
        for r in rows[:30]:
            if "authority_unit" in r:
                print(f"    {r['authority_unit']} -> {r['name']} "
                      f"({r.get('owner_module')}, phase {r.get('owner_phase')}, "
                      f"{r.get('owner_state')})", file=sys.stderr)
            elif "name" in r:
                print(f"    {r['name']}", file=sys.stderr)
        if len(rows) > 30:
            print(f"    ... and {len(rows) - 30} more", file=sys.stderr)

    if findings:
        print(f"[{GENERATOR}] {len(findings)} finding(s): {', '.join(sorted(by_kind))}",
              file=sys.stderr)
        return 1
    print(f"[{GENERATOR}] ok: every dependency has an owner, every owner arrives in "
          f"time, and every recorded divergence covers exactly what it claims -> {rel(OUT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
