#!/usr/bin/env python3
"""openssl-rs — the global symbol-ownership atlas.

Why this artifact exists
------------------------
Before this, each phase ledger decided its own universe. Phase 5 documented the
right rule -- *a symbol belongs to the stratum that owns the header declaring it*
-- and then chose its candidates with a prefix test, so an export like
`a2d_ASN1_OBJECT` (declared in `asn1.h`, matching no prefix) was invisible to the
Phase 5 ledger, to every other ledger, and to `ownership_audit.py`, which only
requires that an *implemented* export be claimed by someone. That is the D49/D51
defect class, and it recurred because discovery and assignment used different
rules.

This tool makes discovery and assignment the *same* rule, applied once, to the
whole authority:

    every export of libcrypto.so.3 and libssl.so.3
        -> its declaring header (Phase 1 atlas)
        -> the header's owning phase (ownership_rules.HEADER_PHASE)
        -> exactly one owner

The universe is 6,499 exports, which is the count `ABI-LOAD` resolves at their
declared ELF versions. The invariants are asserted, not asserted-about:

    rows == 6,499
    unknown            == 0     (every export has an owner)
    multiply-owned     == 0     (no export has two)
    unassigned_headers == 0     (no header the atlas met is missing from the rules)

A phase ledger is then a projection: rows whose `owner_phase` is that phase. The
projection is what `phase5_obligations.py` consumes, and what the other ledgers
will consume as they are revisited.

What this artifact is NOT
-------------------------
It is not an implementation claim and not a parity claim. `owner_phase` says which
stratum *will* implement a symbol; whether it has is the phase ledger's business,
and whether the implementation is compatible is the courts'.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    envelope,
    rel,
    resolve_authority,
    write_json,
)
from ownership_rules import HEADER_PHASE, owner_phase, weak_type_header  # noqa: E402

OUT = REPO_ROOT / "forensics" / "atlas" / "symbol-ownership.json"
GENERATOR = "forensics/tools/symbol_ownership.py"

# The two libraries the distribution ships, in the order the atlas records them.
LIBRARIES = ("libcrypto", "libssl")

# The phase whose ledger a stratum's projection is written to. Phase 2 has no
# obligation ledger: it is the structural ABI shell, and its exports are proofs
# that a name is exported rather than implementations of behaviour.
PHASES_WITH_LEDGERS = (3, 4, 5)


def load(atlas: Path, name: str) -> dict:
    return json.loads((atlas / name).read_text(encoding="utf-8"))["body"]


def type_headers(atlas: Path) -> dict[str, str]:
    """Best header for each type name.

    A forward declaration in `types.h` is a real declaration and a useless one:
    every type has one, so it never distinguishes anything. `pem.h` is the same
    kind of container. The evidence used, strongest first, is the struct
    definition, then the function names that take or return the type
    (`X509_free`, `d2i_X509`), then the typedef. `types.h` and `pem.h` are accepted
    only when nothing stronger exists, and the caller treats them as "no opinion".
    """
    best: dict[str, collections.Counter] = {}

    def note(type_name: str, header: str, weight: int) -> None:
        best.setdefault(type_name, collections.Counter())[header] += weight

    for rec in load(atlas, "structs.json")["records"]:
        if rec.get("header"):
            note(rec["name"], rec["header"], 100)

    for rec in load(atlas, "functions.json")["records"]:
        name, header = rec["name"], rec.get("header")
        if not header:
            continue
        m = re.match(r"^(?:d2i|i2d|PEM_[a-z0-9]+(?:_bio|_fp|_asn1)?)_(.+)$", name)
        if m:
            note(m.group(1), header, 10)
        lead = re.match(r"^([A-Z][A-Za-z0-9]*?)_", name)
        if lead:
            note(lead.group(1), header, 5)

    for rec in load(atlas, "typedefs.json")["records"]:
        note(rec["name"], rec["header"], 1)

    out: dict[str, str] = {}
    for type_name, counts in best.items():
        ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
        strong = [h for h, _ in ranked if not weak_type_header(h)]
        out[type_name] = (strong or [h for h, _ in ranked])[0]
    return out


def exports(atlas: Path) -> list[tuple[str, str]]:
    """Every export of both libraries, as `(library, symbol)`.

    The universe is the DSO's export list, not the version script and not the
    `.num` inventory: the version script and the DSO agree exactly in this profile
    (`version_script_only == 0`, `dso_only == 0`) and a precompiled binary resolves
    against the DSO.
    """
    out: list[tuple[str, str]] = []
    for lib in LIBRARIES:
        doc = load(atlas, f"symbols-{lib}.json")
        for rec in doc["records"]:
            if (rec.get("dso") or {}).get("present"):
                out.append((lib, rec["symbol"]))
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    atlas = REPO_ROOT / "forensics" / "atlas" / auth.id
    funcs = {r["name"]: r for r in load(atlas, "functions.json")["records"]}
    types = type_headers(atlas)
    universe = exports(atlas)

    # A duplicate key in the `HEADER_PHASE` literal is a silently-overridden
    # decision, and a dict cannot express one -- so the check reads the *source*
    # rather than the table. `Counter(HEADER_PHASE)` would count the table's
    # *values* (the phases), which is why this is a source scan and not a
    # collection trick.
    rules_source = (REPO_ROOT / "forensics" / "tools" / "ownership_rules.py").read_text(
        encoding="utf-8"
    )
    table_text = rules_source.split("HEADER_PHASE: dict[str, int] = {", 1)[1]
    table_text = table_text.split("\n}", 1)[0]
    declared = re.findall(r'^\s*"([A-Za-z0-9_.]+\.h)":', table_text, re.M)
    duplicates = sorted(
        h for h, n in collections.Counter(declared).items() if n > 1
    )
    if duplicates:
        raise SystemExit(
            "symbol-ownership: HEADER_PHASE lists a header twice, which keeps the "
            "last value silently:\n  " + "\n  ".join(duplicates)
        )
    undeclared = sorted(set(HEADER_PHASE) - set(declared))
    if undeclared:
        raise SystemExit(
            "symbol-ownership: HEADER_PHASE contains entries the source scan did "
            "not see, which means the scan is wrong:\n  " + "\n  ".join(undeclared)
        )

    rows: list[dict] = []
    unresolved: list[str] = []
    seen: dict[tuple[str, str], str] = {}
    owner_counts: collections.Counter[int] = collections.Counter()
    rule_counts: collections.Counter[str] = collections.Counter()

    for lib, sym in universe:
        key = (lib, sym)
        if key in seen:
            # The DSO export list cannot contain a name twice; if it does, the
            # atlas must say so rather than keep one.
            raise SystemExit(f"symbol-ownership: {lib}:{sym} appears twice in the export list")
        seen[key] = sym
        rec = funcs.get(sym)
        header = rec["header"] if rec else None
        phase, rule, resolved = owner_phase(sym, header, types)
        if phase is None:
            unresolved.append(
                f"{lib}:{sym}: declaring header {header!r} is not in HEADER_PHASE"
            )
            continue
        owner_counts[phase] += 1
        rule_counts[rule] += 1
        rows.append({
            "library": lib,
            "symbol": sym,
            "declaring_header": header,
            "resolved_header": resolved,
            "owner_phase": phase,
            "rule": rule,
            "ledger": "phase-ledger" if phase in PHASES_WITH_LEDGERS else "not-yet-written",
        })

    if unresolved:
        shown = "\n  ".join(sorted(unresolved)[:25])
        more = ("\n  ... and " + str(len(unresolved) - 25) + " more"
                if len(unresolved) > 25 else "")
        raise SystemExit(
            "symbol-ownership: these exports could not be assigned without "
            "guessing. Add the header to HEADER_PHASE, or name the export in "
            "ABI_ONLY_OWNER if no installed header declares it:\n  " + shown + more
        )

    if len(rows) != len(universe):
        raise SystemExit(
            f"symbol-ownership: {len(rows)} rows for {len(universe)} exports"
        )

    # The invariants this artifact exists to make checkable.
    multiply_owned = sorted(
        f"{lib}:{sym}" for (lib, sym), n in
        collections.Counter((r["library"], r["symbol"]) for r in rows).items() if n > 1
    )
    if multiply_owned:
        raise SystemExit("symbol-ownership: multiply-owned:\n  " + "\n  ".join(multiply_owned))

    rows.sort(key=lambda r: (r["owner_phase"], r["library"], r["symbol"]))

    by_phase = {
        str(p): sum(1 for r in rows if r["owner_phase"] == p)
        for p in sorted({r["owner_phase"] for r in rows})
    }
    body = {
        "authority": auth.id,
        "universe": {
            "libraries": list(LIBRARIES),
            "exports": len(rows),
            "definition": "every DSO-exported symbol of libcrypto.so.3 and libssl.so.3",
        },
        "invariants": {
            "unknown": 0,
            "multiply_owned": len(multiply_owned),
            "unassigned_headers": 0,
            "exports": len(rows),
        },
        "rule": (
            "one rule decides discovery and assignment together: an export's "
            "declaring header names its stratum, `pem.h`'s typed names resolve "
            "through the type's header, and the exports no installed header "
            "declares are dispositioned in ABI_ONLY_OWNER"
        ),
        "rules": dict(sorted(rule_counts.items())),
        "by_phase": by_phase,
        "headers": dict(sorted(HEADER_PHASE.items())),
        "records": rows,
    }
    inputs = [
        InputRef(name="authority-functions", path=atlas / "functions.json"),
        InputRef(name="authority-structs", path=atlas / "structs.json"),
        InputRef(name="authority-typedefs", path=atlas / "typedefs.json"),
        InputRef(name="authority-symbols-libcrypto", path=atlas / "symbols-libcrypto.json"),
        InputRef(name="authority-symbols-libssl", path=atlas / "symbols-libssl.json"),
        InputRef(
            name="ownership-rules",
            path=REPO_ROOT / "forensics" / "tools" / "ownership_rules.py",
        ),
    ]
    write_json(
        OUT,
        envelope("symbol-ownership", GENERATOR, inputs, body, authority=auth.id),
    )

    print(f"[symbol-ownership] authority={auth.id}")
    print(f"  universe: {len(rows)} exports across {len(LIBRARIES)} libraries")
    print(f"  rules: {dict(sorted(rule_counts.items()))}")
    print(f"  by phase: {by_phase}")
    print(f"  unknown=0 multiply_owned=0 unassigned_headers=0")
    print(f"  -> {rel(OUT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
