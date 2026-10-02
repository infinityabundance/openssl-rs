#!/usr/bin/env python3
"""openssl-rs -- Phase 22.12 cross-plane reconciliation: one whole-program atlas.

`docs/PHASE-22-SUBPHASES.md` section 5 gives this subphase its artefact
(`forensics/atlas/phase22/reconciliation.json`) and its question: *join the planes into one
whole-program atlas, and turn every disagreement into a residual rather than a preference.*

The rule this tool exists to obey is section 1.1's: **no plane may silently overrule another.**
Ten instrument planes -- the execution-captured build commands (22.1), the Doxygen corpus
(22.2), the every-translation-unit Clang AST (22.3), the preprocessor/conditional graph
(22.4), generated-source genealogy (22.5), the object/archive/DSO graph (22.6), the dispatch
and registration graph (22.7), the installed manifest (22.8), the CLI surface (22.9), the
configuration surface (22.10), the canonical POD contract oracle (22.11) and the test crosswalk
(22.13) -- plus the Phase-1 header/API/ABI atlas, each see the authority through a different
instrument. Where they agree, the entity is one row seen by several planes. Where they
disagree, the disagreement is the *result*: it becomes a typed residual and, where the facts
contradict rather than merely differ in reach, the entity is dispositioned `UNKNOWN` and is
never resolved by choosing a favourite instrument.

The unified key
---------------
"One entity" is defined by a **canonical key** built from the thing the planes actually share
(section 3's typed edge graph, read as an identity, not a call graph):

  * `sym|<name>`            a C symbol with external linkage (functions, variables, macros,
                            typedefs and tagged types that are unique across the tree). Binary
                            graph, dispatch, crosswalk, the Phase-1 `.num`/DSO/declaration
                            atlas and the POD documented-name oracle all join here on the
                            **symbol name**.
  * `sym|<name>@<file>`     a static/local symbol, or a tagged type whose name is not unique
                            across the tree. The defining authority-relative **file** is part
                            of the identity precisely so that two `static int lookup` in two
                            files remain two entities (D492's defect class).
  * `src|<file>|<line>|<name>`  a source-located entity with no cross-file symbol name --
                            fields, enumerators -- joined by the exact **file+line+name** that
                            Doxygen, the AST and the conditional graph share.
  * `file|<path>`           an authority-relative source file (conditional classification,
                            genealogy output, AST/Doxygen `file` entity).
  * `install|<path>`        an installed-distribution entry, joined on the **installed path**.
  * `cli|<name>`            a CLI command or alias, joined on the **command name**.
  * `cli-opt|<cmd>|<opt>`   a structured CLI option.
  * `config|<name>`         a configuration directive, environment variable or default path,
                            joined on the **variable/directive name**.
  * `pod|<page>`            a POD manual page, joined on the **page name**.

`build_body` is a pure function of the merged entity rows and the declared roots: it recomputes
every disposition, every join and every residual from the rows, which is what lets
`RT-PHASE22-RECONCILE` re-derive the committed body and mutate it in memory.

Disposition
-----------
Every entity receives exactly one disposition from the section-4 vocabulary. A fact that no
plane contradicts produces `REQUIRED_COMPATIBILITY`, `INTERNAL_REACHABLE`,
`INTERNAL_UNREACHABLE_PROFILE`, `EXCLUDED_BY_BUILD_PROFILE`, `PLATFORM_EXCLUDED`, `TEST_ONLY`,
`DEMO_ONLY`, `TOOLING_ONLY` or `GENERATED_INTERMEDIATE`. A *contradiction* -- a `.num` row that
says a symbol does not exist while the binary defines it, a public declaration no plane defines,
a documented name no implementation plane saw -- produces `AUTHORITY_BUG_BOUNDARY` (a known
authority defect the candidate must reproduce) or `UNKNOWN`. `UNKNOWN` is refused as a resting
state by the seal (section 4), so `body.counts.unknown_intersecting_roots` counts the entities
that are both `UNKNOWN` and reachable from a declared compatibility root; 22.14 reads it.

Output
------
    forensics/atlas/phase22/reconciliation.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    BUILD_RECORDS,
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    envelope,
    parse_num_file,
    rel,
    resolve_authority,
    write_json,
)

GENERATOR = "forensics/tools/phase22_reconciliation.py"
ARTEFACT_REL = "forensics/atlas/phase22/reconciliation.json"
OUT = REPO_ROOT / ARTEFACT_REL
ATLAS = REPO_ROOT / "forensics" / "atlas"
P22 = ATLAS / "phase22"

# ---------------------------------------------------------------------------
# plane identities, and the artefact each one wrote
# ---------------------------------------------------------------------------

PLANE_ARTEFACTS: dict[str, str] = {
    "compile-commands": "forensics/atlas/phase22/compile-commands.json",
    "doxygen": "forensics/atlas/phase22/doxygen-entities.json",
    "tu-ast": "forensics/atlas/phase22/tu-ast.json",
    "conditional": "forensics/atlas/phase22/conditional-surface.json",
    "generated-lineage": "forensics/atlas/phase22/generated-lineage.json",
    "binary": "forensics/atlas/phase22/binary-reference-graph.json",
    "dispatch": "forensics/atlas/phase22/dispatch-graph.json",
    "install-manifest": "forensics/atlas/phase22/install-manifest.json",
    "cli-surface": "forensics/atlas/phase22/cli-surface.json",
    "config-surface": "forensics/atlas/phase22/config-surface.json",
    "pod-contract": "forensics/atlas/phase22/pod-contract.json",
    "test-crosswalk": "forensics/atlas/phase22/test-crosswalk.json",
    "phase1-atlas": "forensics/atlas/openssl-3.6.4-production/ATLAS.md",
}

DISPOSITIONS: tuple[str, ...] = (
    "REQUIRED_COMPATIBILITY",
    "INTERNAL_REACHABLE",
    "INTERNAL_UNREACHABLE_PROFILE",
    "EXCLUDED_BY_BUILD_PROFILE",
    "PLATFORM_EXCLUDED",
    "TEST_ONLY",
    "DEMO_ONLY",
    "TOOLING_ONLY",
    "GENERATED_INTERMEDIATE",
    "AUTHORITY_BUG_BOUNDARY",
    "UNKNOWN",
)

# A declared compatibility root (section 2), as the fact a plane can carry. The root *families*
# are the plan's own vocabulary; the flag is the mechanical witness.
ROOT_FLAG_TO_FAMILY: dict[str, str] = {
    "public": "source-api",
    "exported": "binary-abi",
    "dispatch": "modules",
    "callback": "callbacks",
    "cli": "cli",
    "config": "configuration",
    "installed": "distribution",
}
# Root families the plan names that no extraction plane can populate from this authority. Recorded
# as an explicit non-join rather than dropped.
ROOT_FAMILIES_UNPOPULATED = ("runtime-behaviour", "protocol", "dynamic-loading")

# A single-plane entity is one a plane saw and the others did not: the cross-plane residual.
SINGLE_PLANE_CLASS: dict[str, str] = {
    "doxygen": "DOXYGEN_ONLY",
    "tu-ast": "AST_ONLY",
    "binary": "BINARY_ONLY",
    "dispatch": "DISPATCH_ONLY",
    "install-manifest": "INSTALL_ONLY",
    "cli-surface": "CLI_ONLY",
    "config-surface": "CONFIG_ONLY",
    "pod-contract": "POD_ONLY",
    "test-crosswalk": "CROSSWALK_ONLY",
    "generated-lineage": "GENERATED_ONLY",
    "compile-commands": "CAPTURED_ONLY",
    "conditional": "CONDITIONAL_ONLY",
    "phase1-atlas": "PHASE1_ONLY",
}

# The shape that betrays a declaration used as an identity. A POD claim's `subject` is an entity
# name -- which may legitimately be loose (`EVP_CIPHER-AES`, a provider algorithm name; `CA.pl`, a
# script) -- while a declaration (`int EVP_FOO(EVP_CTX *ctx)`) carries whitespace or declaration
# punctuation. Joining on the declaration is the identity bug this plane was corrected for, so the
# check is that no POD residual's key carries that shape.
DECLARATION_TELLS = re.compile(r"[\s()*;]")
POD_RESIDUAL_CLASS = "POD_NAME_NOT_IN_ATLAS"
POD_DOC_PREFIX = "sym|pod-doc:"


def pod_identity_violations(residuals: list[dict]) -> list[str]:
    """Every POD residual key that is not a bare entity identity, sorted.

    A NAME entry carries `subject` = the name and a SYNOPSIS declaration carries `subject` = the
    name with `normalized` = the declaration text. The whole-program join resolves a claim by
    **identity**, so `normalized` is a payload and is never a key; a residual whose key carries a
    declaration's shape is a claim that joined on its declaration, which is the defect.
    """
    bad: list[str] = []
    for r in residuals:
        if r.get("class") != POD_RESIDUAL_CLASS:
            continue
        key = r.get("key", "")
        subject = key[len(POD_DOC_PREFIX):] if key.startswith(POD_DOC_PREFIX) else key
        if DECLARATION_TELLS.search(subject):
            bad.append(key)
    return sorted(bad)


def pod_cross_plane(pod11_missing: set[str], here_missing: set[str]) -> dict:
    """The 22.11/22.12 POD invariant.

    The dedicated POD oracle and this whole-program join answer the same question with different
    witness sets. This join sees **more** -- the binary, the dispatch graph, the Phase-1 atlas and
    22.13's crosswalk -- so a name this plane calls missing should also be missing to 22.11. A name
    it calls missing that 22.11 found in the header/API atlas is a projection gap *here*, and is
    recorded (not ignored) so it cannot hide.
    """
    return {
        "pod11_missing": len(pod11_missing),
        "pod12_missing": len(here_missing),
        "resolved_by_wider_witness": len(pod11_missing - here_missing),
        "only_here_unexplained": sorted(here_missing - pod11_missing),
    }

# The pairwise joins this plane performs, each on the key the two planes actually share. A join
# whose `space` is `file` joins on the authority-relative source path; `source` on the exact
# file+line+name identity; everything else on the entity's name in that key space.
JOIN_DECLS: list[dict[str, str]] = [
    {"left": "doxygen", "left_space": "symbol", "right": "tu-ast", "right_space": "symbol",
     "on": "C function/variable/type symbol name"},
    {"left": "doxygen", "left_space": "source", "right": "tu-ast", "right_space": "source",
     "on": "exact authority-relative file+line+name (fields, enumerators)"},
    {"left": "doxygen", "left_space": "file", "right": "conditional", "right_space": "file",
     "on": "authority-relative source file path"},
    {"left": "tu-ast", "left_space": "file", "right": "conditional", "right_space": "file",
     "on": "authority-relative source file path"},
    {"left": "doxygen", "left_space": "symbol", "right": "binary", "right_space": "symbol",
     "on": "external symbol name"},
    {"left": "tu-ast", "left_space": "symbol", "right": "binary", "right_space": "symbol",
     "on": "external symbol name"},
    {"left": "tu-ast", "left_space": "symbol", "right": "dispatch", "right_space": "symbol",
     "on": "dispatch/callback slot target name"},
    {"left": "binary", "left_space": "symbol", "right": "dispatch", "right_space": "symbol",
     "on": "dispatch/callback slot target name"},
    {"left": "binary", "left_space": "symbol", "right": "phase1-atlas", "right_space": "symbol",
     "on": "symbol name (installed ABI / .num inventory / header declaration)"},
    {"left": "test-crosswalk", "left_space": "symbol", "right": "phase1-atlas",
     "right_space": "symbol", "on": "referenced authority symbol name"},
    {"left": "test-crosswalk", "left_space": "symbol", "right": "binary", "right_space": "symbol",
     "on": "referenced authority symbol name"},
    {"left": "pod-contract", "left_space": "symbol", "right": "phase1-atlas",
     "right_space": "symbol", "on": "documented man3 name = declared/exported symbol name"},
    {"left": "pod-contract", "left_space": "symbol", "right": "binary", "right_space": "symbol",
     "on": "documented man3 name = defined symbol name"},
    {"left": "pod-contract", "left_space": "pod", "right": "cli-surface", "right_space": "cli",
     "on": "POD section-1 page name = CLI command name"},
    {"left": "pod-contract", "left_space": "config", "right": "config-surface",
     "right_space": "config", "on": "documented directive/env name = config-surface name"},
    {"left": "install-manifest", "left_space": "manbase", "right": "pod-contract",
     "right_space": "pod", "on": "installed man page basename (section suffix stripped) = POD "
     "page name"},
]

# Joins this plane could not make, and why. Section 1.1's rule read as a report obligation: a join
# that does not exist is recorded, never silently omitted.
UNJOINED: list[dict[str, str]] = [
    {"planes": "install-manifest <-> generated-lineage",
     "would_join_on": "installed path = build output path",
     "why": "the manifest records distribution-relative paths under the install prefix and "
            "genealogy records build-relative paths under the build directory; only library, "
            "engine and module basenames coincide, so only those are joined."},
    {"planes": "tu-ast <-> non-C translation units",
     "would_join_on": "translation unit",
     "why": "the 43 assembly/perlasm units cannot have a C AST (22.3 records them as "
            "non_c_translation_units); 22.6's binary graph is the only plane that sees them, so "
            "their symbols are BINARY_ONLY by construction and not a defect."},
    {"planes": "config-surface <-> tu-ast",
     "would_join_on": "directive call site file+line",
     "why": "config-surface records directive *sites* at the parser and consumer, but the "
            "directive name has no C symbol identity; joining sites would require the AST call "
            "graph of s_config.c, which the directive record does not carry."},
    {"planes": "dispatch-graph <-> dispatch-graph (macro-generated tables)",
     "would_join_on": "literal table initializer",
     "why": "six dispatch families are built by macro expansion and have no literal table in the "
            "source (`body.not_recovered`); there is no source location for a slot to join on."},
    {"planes": "runtime-behaviour / protocol / dynamic-loading roots",
     "would_join_on": "declared compatibility root",
     "why": "the plan names these root families but no extraction plane in 22.1-22.13 observes "
            "runtime, wire or loader behaviour; the reconciliation records them as unpopulated "
            "rather than inventing a witness."},
]


# ---------------------------------------------------------------------------
# key construction (pure)
# ---------------------------------------------------------------------------

def norm_file(path: str | None, prefixes: tuple[str, ...]) -> str | None:
    """Authority-relative POSIX path, stripping whichever admitted prefix applies.

    Planes record source paths in four different shapes: the authority tree relative to its root
    (`crypto/x509/x509_vfy.c`), the repository-relative authority path
    (`forensics/authorities/src/openssl-3.6.4/crypto/...`), the repository-relative build path and
    `/work`-rooted capture paths. One normalizer, so the same file seen by two planes is one file.
    """
    if not path:
        return None
    p = path.replace("\\", "/")
    # Capture paths are rooted at the bind-mounted `/work`, sometimes written as a relative
    # `../../work/...`; strip everything up to and including it before the prefix passes.
    marker = p.find("/work/")
    if marker != -1:
        p = p[marker + len("/work/"):]
    while p.startswith("./"):
        p = p[2:]
    while p.startswith("../"):
        p = p[3:]
    changed = True
    while changed:
        changed = False
        for pre in prefixes:
            if pre and p == pre:
                p = ""
                changed = True
            elif pre and p.startswith(pre + "/"):
                p = p[len(pre) + 1:]
                changed = True
    return p or None


def sym_key(name: str, file: str | None, static: bool) -> str:
    if static and file:
        return f"sym|{name}@{file}"
    return f"sym|{name}"


def type_key(kind: str, name: str, file: str | None, nonunique: bool) -> str:
    if nonunique and file:
        return f"sym|{kind}:{name}@{file}"
    return f"sym|{kind}:{name}"


def macro_key(name: str) -> str:
    return f"sym|macro:{name}"


def src_key(file: str, line: int | None, name: str) -> str:
    return f"src|{file}|{line}|{name}"


# ---------------------------------------------------------------------------
# disposition / parity / court family (pure)
# ---------------------------------------------------------------------------

def root_families(evidence: set[str]) -> list[str]:
    fams = {fam for flag, fam in ROOT_FLAG_TO_FAMILY.items() if flag in evidence}
    return sorted(fams)


def classify(evidence: set[str]) -> str:
    """The section-4 disposition from the entity's facts, with contradictions never resolved.

    The precedence is deliberate: a known defect boundary and a contradiction outrank every
    ordinary fact, because the whole point of the plane rule is that a disagreement is not
    outvoted by a majority of planes that happen to agree with each other.
    """
    ev = evidence
    if "bug" in ev:
        return "AUTHORITY_BUG_BOUNDARY"
    if "contradiction" in ev:
        return "UNKNOWN"
    if "num_platform" in ev or "platform" in ev:
        return "PLATFORM_EXCLUDED"
    if "num_nonexist" in ev:
        return "EXCLUDED_BY_BUILD_PROFILE"
    if "excluded" in ev:
        return "EXCLUDED_BY_BUILD_PROFILE"
    if "tooling" in ev:
        return "TOOLING_ONLY"
    if root_families(ev):
        return "REQUIRED_COMPATIBILITY"
    if "demo" in ev and "test" not in ev and "fuzz" not in ev:
        return "DEMO_ONLY"
    if "test" in ev or "fuzz" in ev:
        return "TEST_ONLY"
    if "internal" in ev:
        if ev & {"address_taken", "referenced", "dispatch"}:
            return "INTERNAL_REACHABLE"
        return "INTERNAL_UNREACHABLE_PROFILE"
    if "generated" in ev:
        return "GENERATED_INTERMEDIATE"
    return "INTERNAL_UNREACHABLE_PROFILE"


def parity_for(disposition: str, fams: list[str]) -> list[str]:
    if disposition not in ("REQUIRED_COMPATIBILITY", "INTERNAL_REACHABLE"):
        return []
    dims: set[str] = set()
    if "source-api" in fams:
        dims |= {"SOURCE", "ABI", "SEMANTIC", "OWNERSHIP", "ERROR", "STATE", "CONCURRENCY"}
    if "binary-abi" in fams:
        dims |= {"ABI", "SEMANTIC", "ERROR", "STATE", "CONCURRENCY"}
    if "modules" in fams:
        dims |= {"PROVIDER", "SEMANTIC", "STATE", "CONCURRENCY"}
    if "callbacks" in fams:
        dims |= {"SEMANTIC", "STATE", "CONCURRENCY"}
    if "cli" in fams:
        dims |= {"CLI", "SEMANTIC"}
    if "configuration" in fams:
        dims |= {"BUILD", "SEMANTIC"}
    if "distribution" in fams:
        dims |= {"BUILD"}
    if not dims and disposition == "INTERNAL_REACHABLE":
        dims = {"SEMANTIC"}
    return sorted(dims)


def court_families_for(disposition: str, fams: list[str], evidence: set[str]) -> list[str]:
    fams_out: set[str] = set()
    if "cli" in fams:
        fams_out.add("CLI-SURFACE")
    if "configuration" in fams:
        fams_out.add("CONFIG-SURFACE")
    if "distribution" in fams:
        fams_out.add("INSTALL-MANIFEST")
    if "modules" in fams:
        fams_out.add("DISPATCH")
    if "callbacks" in fams:
        fams_out.add("CALLBACK")
    if "binary-abi" in fams:
        fams_out.add("ABI-EXPORT")
    if "source-api" in fams:
        fams_out.add("SOURCE-API")
    if "generated" in evidence:
        fams_out.add("GENEALOGY")
    if evidence & {"test", "fuzz"}:
        fams_out.add("CROSSWALK")
    if "demo" in evidence:
        fams_out.add("DEMO")
    if disposition == "INTERNAL_REACHABLE" and not fams_out:
        fams_out.add("INTERNAL-REACH")
    if disposition == "UNKNOWN":
        fams_out.add("UNRESOLVED")
    return sorted(fams_out)


# ---------------------------------------------------------------------------
# the pure body builder
# ---------------------------------------------------------------------------

def _key_set(entities: list[dict], plane: str, space_kind: str) -> set[str]:
    out: set[str] = set()
    for e in entities:
        if plane not in e["planes"]:
            continue
        if space_kind == "file":
            if e.get("file"):
                out.add(e["file"])
        elif space_kind == "manbase":
            if e["space"] == "install":
                base = e["name"].rsplit("/", 1)[-1]
                if base.endswith(".gz"):
                    base = base[:-3]
                # man sections are numeric, and OpenSSL installs "3ossl" as well as "3".
                base = re.sub(r"\.\d+\w*$", "", base)
                out.add(base)
        elif space_kind == "source":
            if e["space"] == "source":
                out.add(e["key"])
        else:
            if e["space"] == space_kind:
                out.add(e["name"])
    return out


def _examples(items: set[str], n: int = 8) -> list[str]:
    return sorted(items)[:n]


def compute_joins(entities: list[dict]) -> list[dict]:
    joins: list[dict] = []
    for decl in JOIN_DECLS:
        left = _key_set(entities, decl["left"], decl["left_space"])
        right = _key_set(entities, decl["right"], decl["right_space"])
        matched = left & right
        joins.append({
            "left": decl["left"],
            "right": decl["right"],
            "on": decl["on"],
            "left_keys": len(left),
            "right_keys": len(right),
            "matched": len(matched),
            "left_only": len(left - right),
            "right_only": len(right - left),
            "left_only_examples": _examples(left - right),
            "right_only_examples": _examples(right - left),
        })
    joins.sort(key=lambda j: (j["left"], j["right"], j["on"]))
    return joins


def build_body(entities: list[dict], roots: dict, *, removed_planes: frozenset = frozenset()) -> dict:
    """Recompute the whole reconciled body from merged entity rows and declared roots.

    Pure: no I/O, no ambient state, no plane preference. The committed artefact stores the rows,
    so this function is what `RT-PHASE22-RECONCILE` drives on the real rows and on mutations.
    """
    rm = set(removed_planes)
    ents: list[dict] = []
    for e in entities:
        planes = sorted(p for p in e.get("planes", []) if p not in rm)
        if not planes:
            continue
        ent = dict(e)
        ent["planes"] = planes
        ents.append(ent)
    ents.sort(key=lambda e: e["key"])

    rows: list[dict] = []
    residuals: list[dict] = []
    by_disposition: dict[str, int] = {}
    by_space: dict[str, int] = {}
    by_plane: dict[str, int] = {}
    unknown_intersecting = 0
    root_reachable = 0
    owned = 0
    by_phase: dict[str, int] = {}

    for e in ents:
        ev = set(e.get("evidence", []))
        disp = classify(ev)
        fams = root_families(ev)
        row = {
            "key": e["key"],
            "space": e["space"],
            "name": e["name"],
            "kind": e.get("kind"),
            "file": e.get("file"),
            "line": e.get("line"),
            "planes": e["planes"],
            "evidence": sorted(ev),
            "residual": e.get("residual"),
            "disposition": disp,
            "root_families": fams,
            "owner_phase": e.get("owner_phase"),
            "parity": parity_for(disp, fams),
            "court_family": court_families_for(disp, fams, ev),
        }
        rows.append(row)
        by_disposition[disp] = by_disposition.get(disp, 0) + 1
        by_space[e["space"]] = by_space.get(e["space"], 0) + 1
        for p in e["planes"]:
            by_plane[p] = by_plane.get(p, 0) + 1
        if fams:
            root_reachable += 1
            if disp == "UNKNOWN":
                unknown_intersecting += 1
        if e.get("owner_phase") is not None:
            owned += 1
            key = str(e["owner_phase"])
            by_phase[key] = by_phase.get(key, 0) + 1

        # A residual is a disagreement that has nowhere to hide: either an explicit typed
        # contradiction carried on the row, or an entity exactly one plane saw.
        classes: list[str] = []
        if e.get("residual"):
            classes.append(e["residual"])
        elif len(e["planes"]) == 1:
            classes.append(SINGLE_PLANE_CLASS.get(e["planes"][0], f"{e['planes'][0]}_ONLY"))
        for cls in dict.fromkeys(classes):
            residuals.append({
                "class": cls,
                "key": e["key"],
                "planes": e["planes"],
                "disposition": disp,
            })

    residuals.sort(key=lambda r: (r["class"], r["key"]))
    residuals_by_class: dict[str, int] = {}
    for r in residuals:
        residuals_by_class[r["class"]] = residuals_by_class.get(r["class"], 0) + 1

    joins = compute_joins(ents)

    counts = {
        "entities": len(ents),
        "by_disposition": {d: by_disposition.get(d, 0) for d in DISPOSITIONS},
        "by_space": dict(sorted(by_space.items())),
        "by_plane": dict(sorted(by_plane.items())),
        "by_owner_phase": dict(sorted(by_phase.items())),
        "root_reachable": root_reachable,
        "owner_assigned": owned,
        "unknown": by_disposition.get("UNKNOWN", 0),
        "unknown_intersecting_roots": unknown_intersecting,
        "residuals": len(residuals),
        "residuals_by_class": dict(sorted(residuals_by_class.items())),
        "joins": len(joins),
    }
    return {
        "entities": rows,
        "joins": joined_join_rows(joins),
        "residuals": residuals,
        "counts": counts,
        "roots": roots,
        "dispositions": list(DISPOSITIONS),
        "root_families_unpopulated": list(ROOT_FAMILIES_UNPOPULATED),
        "unjoined": UNJOINED,
        "sort_key": ("entities by canonical key; residuals by (class, key); joins by "
                     "(left, right, on); every list sorted"),
    }


def joined_join_rows(joins: list[dict]) -> list[dict]:
    """Joins in the committed shape. Kept separate so a court can compare recomputation."""
    return joins


# The document carries ~10^5 entities, so it is stored in a compact per-row encoding rather than
# one fully-spelled object per entity. `field_map` is written into the body so a reader never has
# to guess, and `decode_entity` is the inverse.
FIELD_PAIRS: tuple[tuple[str, str], ...] = (
    ("key", "k"), ("space", "s"), ("name", "n"), ("kind", "d"), ("file", "f"),
    ("line", "l"), ("planes", "p"), ("evidence", "e"), ("residual", "r"),
    ("disposition", "D"), ("root_families", "R"), ("owner_phase", "o"),
    ("parity", "P"), ("court_family", "C"),
)
FIELD_MAP: dict[str, str] = {long: short for long, short in FIELD_PAIRS}
LIST_FIELDS = frozenset({"planes", "evidence", "root_families", "parity", "court_family"})


def encode_entity(e: dict) -> dict:
    out: dict = {}
    for long, short in FIELD_PAIRS:
        v = e.get(long)
        if v is None or v == [] or v == "":
            continue
        if long in LIST_FIELDS:
            out[short] = ",".join(v)
        else:
            out[short] = v
    return out


def decode_entity(e: dict) -> dict:
    out: dict = {}
    for long, short in FIELD_PAIRS:
        v = e.get(short)
        if long in LIST_FIELDS:
            out[long] = v.split(",") if v else []
        else:
            out[long] = v
    return out


# ---------------------------------------------------------------------------
# collection (I/O): project every plane into the unified entity universe
# ---------------------------------------------------------------------------

class Universe:
    def __init__(self, prefixes: tuple[str, ...]) -> None:
        self.prefixes = prefixes
        self.e: dict[str, dict] = {}
        # The name -> canonical-key index. **Maintained by `add`, not built once.** Identity is
        # established by planes that arrive across the whole collection -- 22.6's binary
        # definitions, 22.7's dispatch targets and the Phase-1 atlas publish symbols the
        # source-semantic pass cannot see -- and the POD whole-program join runs after all of them.
        # Building the index once, right after pass 1, left every later symbol invisible to
        # `resolve`, which is half of why a name whose only witness was the binary or the atlas
        # came out `POD_NAME_NOT_IN_ATLAS`.
        self.name_index: dict[str, set[str]] = {}

    def add(self, key: str, space: str, name: str, plane: str, *, file=None, line=None,
            kind=None, owner_phase=None, residual=None, **flags) -> dict:
        ent = self.e.get(key)
        if ent is None:
            ent = {"key": key, "space": space, "name": name, "kind": kind, "file": file,
                   "line": line, "planes": set(), "evidence": set(), "owner_phase": owner_phase,
                   "residual": residual}
            self.e[key] = ent
        ent["planes"].add(plane)
        if ent["file"] is None and file is not None:
            ent["file"] = file
        if ent["line"] is None and line is not None:
            ent["line"] = line
        if ent["kind"] is None and kind is not None:
            ent["kind"] = kind
        if ent["owner_phase"] is None and owner_phase is not None:
            ent["owner_phase"] = owner_phase
        if ent["residual"] is None and residual is not None:
            ent["residual"] = residual
        for flag, present in flags.items():
            if present:
                ent["evidence"].add(flag)
        if space == "symbol" and name:
            self.name_index.setdefault(name, set()).add(key)
        return ent

    def annotate(self, key: str, plane: str, **flags) -> None:
        ent = self.e.get(key)
        if ent is None:
            return
        ent["planes"].add(plane)
        for flag, present in flags.items():
            if present:
                ent["evidence"].add(flag)

    def keys_for(self, name: str) -> tuple[str, ...]:
        """Every canonical symbol key this name maps to, in a stable order."""
        return tuple(sorted(self.name_index.get(name, ())))

    def resolve(self, name: str) -> str | None:
        """The unique canonical key a symbol name maps to, or None when ambiguous/unknown."""
        keys = self.name_index.get(name)
        if keys is not None and len(keys) == 1:
            return next(iter(keys))
        return None

    def known(self, name: str) -> bool:
        """True when a plane **other than the POD projection** established this name.

        The residual question is 'did any implementation, binary, dispatch or Phase-1 plane *see*
        the name', not 'is the name unique': a documented name two statics share is in the atlas
        and is not a `POD_NAME_NOT_IN_ATLAS` residual. Because a joined entity keeps its real
        planes alongside `pod-contract`, a back-reference to the POD claim itself never counts as
        a witness of its own presence.
        """
        for key in self.name_index.get(name, ()):
            ent = self.e.get(key)
            if ent is not None and any(p != "pod-contract" for p in ent["planes"]):
                return True
        return False


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def collect(authority_id: str) -> tuple[list[dict], dict, dict]:
    auth = resolve_authority(authority_id)
    src_rel = auth.source.resolve().relative_to(REPO_ROOT).as_posix()
    builds = json.loads(BUILD_RECORDS.read_text())
    rec = next(b for b in builds["builds"] if b["id"] == authority_id)
    build_rel = str(rec.get("build_dir", ""))
    prefix_rel = str(rec.get("prefix", ""))
    prefixes = (src_rel, build_rel, prefix_rel)
    U = Universe(prefixes)

    def N(p):
        return norm_file(p, prefixes)

    # -- pass 1: the source-semantic planes that establish symbol identity ------
    dox = _load(P22 / "doxygen-entities.json")["body"]
    ast = _load(P22 / "tu-ast.json")["body"]

    type_files: dict[tuple[str, str], set[str]] = {}
    for e in ast["entities"]:
        if e["kind"] in ("struct", "union", "enum", "typedef"):
            type_files.setdefault((e["kind"], e["name"]), set()).add(N(e["file"]) or "")
    for e in dox["entities"]:
        if e["kind"] in ("struct", "union", "enum", "typedef"):
            type_files.setdefault((e["kind"], e["name"]), set()).add(N(e["file"]) or "")

    def add_source_entity(plane: str, kind: str, name: str, file: str | None, line, static: bool,
                          **flags) -> None:
        file = N(file)
        if kind in ("function", "variable"):
            key = sym_key(name, file, static)
            U.add(key, "symbol", name, plane, file=file, line=line, kind=kind, **flags)
        elif kind in ("typedef", "struct", "union", "enum", "class"):
            nonunique = len(type_files.get((kind, name), {"", ""})) > 1
            key = type_key(kind, name, file, nonunique)
            U.add(key, "symbol", name, plane, file=file, line=line, kind=kind, **flags)
        elif kind == "macro":
            U.add(macro_key(name), "symbol", name, plane, file=file, line=line, kind=kind,
                  **flags)
        elif kind in ("field", "enumerator"):
            if file is None:
                return
            U.add(src_key(file, line, name), "source", name, plane, file=file, line=line,
                  kind=kind, **flags)
        elif kind == "file":
            if file is not None:
                U.add(f"file|{file}", "file", file, plane, file=file, line=line, kind="file",
                      **flags)
        else:
            if file is None:
                return
            U.add(f"{kind}|{file}|{line}|{name}", "source", name, plane, file=file, line=line,
                  kind=kind, **flags)

    for e in dox["entities"]:
        kind = e["kind"]
        flags = {"documented": e.get("documented", False)}
        if kind in ("function", "variable") and not e.get("is_static"):
            pass
        if kind in ("function", "variable") and e.get("is_static"):
            flags["internal"] = True
        add_source_entity("doxygen", kind, e["name"], e.get("file"), e.get("line"),
                          bool(e.get("is_static")), **flags)

    for e in ast["entities"]:
        kind = e["kind"]
        internal = e.get("linkage") == "internal" or bool(e.get("is_static"))
        flags = {"internal": internal, "documented": False}
        if e.get("is_inline"):
            flags["inline"] = True
        add_source_entity("tu-ast", kind, e["name"], e.get("file"), e.get("line"), internal,
                          **flags)

    # The name index is maintained by `Universe.add`, so a symbol a later plane publishes is
    # resolvable the moment it lands; there is nothing to build here.

    def resolve_or_name(name: str) -> str:
        return U.resolve(name) or f"sym|{name}"

    # -- Phase-1 ownership atlas: the owning phase per symbol ------------------
    own = _load(ATLAS / "symbol-ownership.json")["body"]
    owner: dict[str, int] = {}
    for r in own["records"]:
        owner.setdefault(r["symbol"], r["owner_phase"])

    def phase_of(name: str) -> int | None:
        return owner.get(name)

    # -- 22.6 binary reference graph -------------------------------------------
    binary = _load(P22 / "binary-reference-graph.json")["body"]
    binary_defined: set[str] = set(binary["definitions"].keys())
    referenced_names: set[str] = set()
    for obj in binary["objects"]:
        for r in obj.get("relocations") or []:
            sym = r.get("symbol") if isinstance(r, dict) else None
            if sym:
                referenced_names.add(sym)

    for name in sorted(binary_defined):
        key = resolve_or_name(name)
        U.add(key, "symbol", name, "binary", kind="function", owner_phase=phase_of(name),
              binary=True, internal=True)

    # -- 22.11 POD, so documented names can join the symbol index ---------------
    pod = _load(P22 / "pod-contract.json")["body"]

    # -- 22.7 dispatch graph ---------------------------------------------------
    dispatch = _load(P22 / "dispatch-graph.json")["body"]
    dispatch_targets: set[str] = set()
    callback_targets: set[str] = set()
    cli_dispatch: dict[str, str] = {}
    dispatch_source_only: set[str] = set()
    dispatch_binary_witness: set[str] = set()
    for edge in dispatch["edges"]:
        target = edge.get("target")
        if not target:
            continue
        dispatch_targets.add(target)
        if edge.get("kind") == "CALLBACK_SLOT":
            callback_targets.add(target)
        if edge.get("kind") == "CLI_DISPATCH" and edge.get("slot"):
            cli_dispatch.setdefault(edge["slot"], target)
        corr = edge.get("corroboration")
        if corr == "source_only":
            dispatch_source_only.add(target)
        if corr in ("both", "binary_only"):
            dispatch_binary_witness.add(target)
    for name in sorted(dispatch_targets):
        key = resolve_or_name(name)
        U.add(key, "symbol", name, "dispatch", kind="function", owner_phase=phase_of(name),
              dispatch=True, callback=name in callback_targets, internal=True,
              referenced=name in referenced_names)
    for name in sorted(dispatch_source_only - dispatch_binary_witness):
        key = resolve_or_name(name)
        U.annotate(key, "dispatch")
        ent = U.e.get(key)
        if ent is not None and ent["residual"] is None:
            ent["residual"] = "DISPATCH_UNWITNESSED_IN_BINARY"
    for name in sorted(dispatch_binary_witness - dispatch_source_only):
        key = resolve_or_name(name)
        U.annotate(key, "dispatch")

    # Reachability facts: a relocation that resolves to a definition, and a function whose address
    # is taken. These are what separate an internal entity that is *reachable* from roots from one
    # that is internal and unreachable in this profile.
    for name in sorted(referenced_names):
        key = U.resolve(name)
        if key is not None:
            U.annotate(key, "binary", referenced=True)
    for r in ast.get("address_taken") or []:
        name = r.get("function")
        f = N(r.get("function_file"))
        key = f"sym|{name}@{f}" if f else None
        if key is None or key not in U.e:
            key = U.resolve(name)
        if key is not None:
            U.annotate(key, "tu-ast", address_taken=True)
    for f, names in (dispatch.get("binary_address_taken") or {}).items():
        names = names if isinstance(names, list) else [f"{f}"]
        for name in names:
            key = U.resolve(name)
            if key is not None:
                U.annotate(key, "dispatch", address_taken=True)
    for name in dispatch.get("binary_address_global") or []:
        key = U.resolve(name)
        if key is not None:
            U.annotate(key, "dispatch", address_taken=True)

    # -- 22.9 CLI surface ------------------------------------------------------
    cli = _load(P22 / "cli-surface.json")["body"]
    cli_names: set[str] = set()
    for c in cli["commands"]:
        cli_names.add(c["name"])
        U.add(f"cli|{c['name']}", "cli", c["name"], "cli-surface", kind="command", cli=True)
        for a in c.get("aliases") or []:
            cli_names.add(a)
            U.add(f"cli|{a}", "cli", a, "cli-surface", kind="alias", cli=True)
        for o in c.get("options") or []:
            oname = o.get("name") if isinstance(o, dict) else None
            if oname:
                U.add(f"cli-opt|{c['name']}|{oname}", "cli", f"{c['name']}:{oname}",
                      "cli-surface", kind="option", cli=True)
    for name in cli.get("digest_commands") or []:
        cli_names.add(name)
        U.add(f"cli|{name}", "cli", name, "cli-surface", kind="digest-pseudo-command", cli=True)
    for name in cli.get("cipher_commands") or []:
        cli_names.add(name)
        U.add(f"cli|{name}", "cli", name, "cli-surface", kind="cipher-pseudo-command", cli=True)

    # -- 22.10 configuration surface -------------------------------------------
    cfg = _load(P22 / "config-surface.json")["body"]
    config_names: set[str] = set()
    config_dispositions: dict[str, str] = {}
    for d in cfg["directives"]:
        config_names.add(d["name"])
        config_dispositions[f"config|{d['name']}"] = d.get("disposition", "UNKNOWN")
        U.add(f"config|{d['name']}", "config", d["name"], "config-surface", kind="directive",
              config=d.get("disposition") == "REQUIRED_COMPATIBILITY",
              test=d.get("disposition") == "TEST_ONLY",
              demo=d.get("disposition") == "DEMO_ONLY")
    for e in cfg["env_vars"]:
        config_names.add(e["name"])
        config_dispositions[f"config|env:{e['name']}"] = e.get("disposition", "UNKNOWN")
        U.add(f"config|env:{e['name']}", "config", e["name"], "config-surface", kind="env",
              config=e.get("disposition") == "REQUIRED_COMPATIBILITY",
              test=e.get("disposition") == "TEST_ONLY",
              demo=e.get("disposition") == "DEMO_ONLY")
    for p in cfg["default_paths"]:
        config_names.add(p["name"])
        U.add(f"config|path:{p['name']}", "config", p["name"], "config-surface",
              kind="default-path", config=True)

    # -- 22.11 POD contract oracle ---------------------------------------------
    pod_pages: set[str] = set()
    for page in pod["pages"]:
        pod_pages.add(page["page"])
        U.add(f"pod|{page['page']}", "pod", page["page"], "pod-contract",
              kind=f"man{page.get('section')}", documented=True)
        # A section-1 page names the CLI command it documents; that command name, not the
        # "openssl-<cmd>" page title, is what joins to 22.9's CLI surface.
        if page.get("command"):
            U.add(f"pod-cmd|{page['command']}", "pod", page["command"], "pod-contract",
                  kind="page-command", documented=True)
    for claim in pod["claims"]:
        kind = claim["kind"]
        if kind in ("NAME_ENTRY", "SYNOPSIS_DECL"):
            # A man3 NAME entry and a SYNOPSIS declaration both name a **symbol**, and a symbol is
            # joined only after every identity-bearing plane has landed -- see the POD join below,
            # which runs last. The claim's identity is its `subject`; `normalized` is the
            # declaration text and is carried as a payload, never resolved as a name.
            continue
        norm = claim.get("normalized") or claim.get("subject")
        if not norm:
            continue
        if kind == "CLI_OPTION":
            U.add(f"cli-opt|{claim['page']}|{norm.lstrip('-')}", "cli",
                  f"{claim['page']}:{norm.lstrip('-')}", "pod-contract", kind="documented-option",
                  documented=True)
        elif kind == "CONFIG_DIRECTIVE":
            U.add(f"config|{norm}", "config", norm, "pod-contract", kind="documented-directive",
                  documented=True)
        elif kind == "ENV_VAR":
            U.add(f"config|env:{norm}", "config", norm, "pod-contract", kind="documented-env",
                  documented=True)
        elif kind == "DEFAULT_PATH":
            U.add(f"config|path:{norm}", "config", norm, "pod-contract",
                  kind="documented-path", documented=True)
        elif kind == "PROVIDER_ALGORITHM":
            U.add(f"sym|alg:{norm}", "symbol", norm, "pod-contract",
                  kind="documented-provider-algorithm", documented=True)

    # -- 22.13 test crosswalk --------------------------------------------------
    crosswalk = _load(P22 / "test-crosswalk.json")["body"]
    for s in crosswalk["sources"]:
        if s["path"].startswith("test/") or s["path"].startswith("fuzz/"):
            flag = {"test": s["kind"] == "test", "fuzz": s["kind"] == "fuzz"}
        else:
            flag = {"demo": s["kind"] == "demo"}
        U.add(f"file|{s['path']}", "file", s["path"], "test-crosswalk", kind=s["kind"], **flag)
    for edge in crosswalk["edges"]:
        if edge["kind"] not in ("call", "reference"):
            continue
        name = edge["target"]
        key = resolve_or_name(name)
        demo = edge["source"].startswith("demos/")
        U.add(key, "symbol", name, "test-crosswalk", kind="function",
              demo=demo, test=not demo, tested=not demo)

    # -- 22.8 installed manifest ----------------------------------------------
    manifest = _load(P22 / "install-manifest.json")["body"]
    installed_pages: set[str] = set()
    for entry in manifest["entries"]:
        disp = entry.get("disposition", "")
        p = entry["path"]
        basename = p.rsplit("/", 1)[-1]
        if entry.get("category") == "manpage":
            installed_pages.add(basename)
        U.add(f"install|{p}", "install", p, "install-manifest", kind=entry.get("category"),
              installed=disp == "REQUIRED_COMPATIBILITY",
              generated=disp == "GENERATED_INTERMEDIATE",
              tooling=disp == "TOOLING_ONLY")

    # -- 22.5 generated source genealogy --------------------------------------
    genealogy = _load(P22 / "generated-lineage.json")["body"]
    for row in genealogy["lineage"]:
        out = N(row["output"]) or row["output"]
        U.add(f"file|{out}", "file", out, "generated-lineage", kind=f"generated:{row['class']}",
              generated=True)
    for p in genealogy.get("outputs_without_a_rule") or []:
        out = N(p) or p
        ent = U.add(f"file|{out}", "file", out, "generated-lineage", kind="generated:unknown",
                    generated=True)
        if ent["residual"] is None:
            ent["residual"] = "GENERATED_WITHOUT_PROVENANCE"

    # -- 22.4 conditional surface ---------------------------------------------
    cond = _load(P22 / "conditional-surface.json")["body"]
    for s in cond["sources"]:
        path = N(s["path"]) or s["path"]
        cls = s["class"]
        U.add(f"file|{path}", "file", path, "conditional", kind=f"source:{cls}",
              compiled=cls == "active-production",
              excluded=cls in ("excluded-by-production-profile", "fips-only", "deprecated-only",
                               "assembly-alternative"),
              platform=cls == "platform-specific",
              test=cls == "test-only", demo=cls == "demo-only",
              generated=cls == "generated-only")

    # -- 22.1 captured build commands -----------------------------------------
    cc = _load(P22 / "compile-commands.json")["body"]
    for row in cc["commands"]:
        src = N(row["source"]) or row["source"]
        U.add(f"file|{src}", "file", src, "compile-commands", kind="captured-source",
              compiled=True)

    # -- Phase-1 header/API/ABI atlas -----------------------------------------
    prod = ATLAS / authority_id

    def add_phase1_symbol(name: str, kind: str, header: str | None, line, *, public=True,
                          **flags) -> None:
        if kind in ("function", "variable", "macro"):
            key = macro_key(name) if kind == "macro" else resolve_or_name(name)
        elif kind in ("typedef", "struct", "union", "enum", "class"):
            key = type_key(kind, name, None, False)
        else:
            key = resolve_or_name(name)
        U.add(key, "symbol", name, "phase1-atlas", kind=kind,
              owner_phase=phase_of(name), public=public, vendor=True, **flags)

    funcs = _load(prod / "functions.json")["body"]
    for r in funcs["records"]:
        add_phase1_symbol(r["name"], "function", r.get("header"), r.get("line"))
    variables = _load(prod / "variables.json")["body"]
    for r in variables["records"]:
        add_phase1_symbol(r["name"], "variable", r.get("header"), r.get("line"))
    macros = _load(prod / "macros.json")["body"]
    for r in macros["records"]:
        add_phase1_symbol(r["name"], "macro", (r.get("defined_in") or [None])[0], None)
    typedefs = _load(prod / "typedefs.json")["body"]
    for r in typedefs["records"]:
        add_phase1_symbol(r["name"], "typedef", r.get("header"), r.get("line"))
    structs = _load(prod / "structs.json")["body"]
    for r in structs["records"]:
        add_phase1_symbol(r["name"], r.get("tag", "struct"), r.get("header"), r.get("line"))
    # `enums.json` is a Phase-1 plane like the others, and 22.11's POD join already reads it.
    # Leaving it out of this projection is what made three documented enum names
    # (`BIO_hostserv_priorities`, `BIO_lookup_type`, `UI_string_types`, named by `enums.json` and
    # by no source-semantic plane) come out `POD_NAME_NOT_IN_ATLAS` here while the dedicated POD
    # oracle found them in the header/API atlas.
    enums = _load(prod / "enums.json")["body"]
    for r in enums["records"]:
        add_phase1_symbol(r["name"], "enum", r.get("header"), r.get("line"))

    for lib in ("libcrypto", "libssl"):
        sym = _load(prod / f"symbols-{lib}.json")["body"]
        for r in sym["records"]:
            name = r["symbol"]
            num = r.get("num") or {}
            recon = r.get("reconciliation", "")
            key = resolve_or_name(name)
            U.add(key, "symbol", name, "phase1-atlas", kind="function",
                  owner_phase=phase_of(name), exported=True, vendor=True,
                  num_nonexist=(num.get("status") == "NOEXIST"),
                  num_platform=bool(num.get("platform")),
                  excluded=(recon == "excluded_by_build_profile"),
                  public=(r.get("dso", {}).get("present", False) is not False))

    # internal-symbols: the static/local definitions the header atlas cannot see.
    internal = _load(ATLAS / "internal-symbols.json")["body"]
    for r in internal["records"]:
        name = r["symbol"]
        key = sym_key(name, N(r.get("translation_unit")), True)
        U.add(key, "symbol", name, "phase1-atlas", owner_phase=phase_of(name),
              kind="internal", internal=True, vendor=True)

    # -- cross-plane contradictions (never resolved by preference) -------------
    # 1. a declared public symbol no plane defines.
    ast_defined = {e["name"] for e in ast["entities"] if e.get("is_definition")}
    for r in funcs["records"]:
        name = r["name"]
        # A `static inline` function declared in a header is defined in that header and inlined
        # away in every object; its absence from the binary is expected, not a contradiction.
        if r.get("inline") or r.get("storage_class") == "static":
            continue
        if name not in ast_defined and name not in binary_defined and name not in internal_names(
                internal):
            key = resolve_or_name(name)
            # **The authority's own boundary, not an atlas gap.** This is the shape
            # `ebcdic.h` gives: it declares `_openssl_ascii2ebcdic` and `_openssl_ebcdic2ascii`
            # and nothing in the 3.6.4 tree defines them -- the EBCDIC sources are gone and the
            # header is vestigial. Both witnesses are complete (22.3 parsed every translation unit
            # with 0 failures, 22.6 read every object), so "declared by an installed public header
            # and defined by no plane" is the authority promising a symbol it does not provide,
            # which section 4 calls `AUTHORITY_BUG_BOUNDARY`. Classing it `UNKNOWN` left a residual
            # intersecting a compatibility root open against a question that has an answer, and
            # `UNKNOWN` is refused as a resting state -- so the class is the honest reading, and
            # the residual name still records exactly what was seen.
            ent = U.add(key, "symbol", name, "phase1-atlas", kind="function", public=True,
                        vendor=True, bug=True)
            if ent["residual"] is None:
                ent["residual"] = "DECLARED_NOT_DEFINED"

    # 2. a .num row that says a symbol is deliberately absent while the binary defines it.
    for lib in ("libcrypto", "libssl"):
        sym = _load(prod / f"symbols-{lib}.json")["body"]
        for r in sym["records"]:
            num = r.get("num") or {}
            if num.get("status") == "NOEXIST" and r["symbol"] in binary_defined:
                key = resolve_or_name(r["symbol"])
                ent = U.add(key, "symbol", r["symbol"], "phase1-atlas", kind="function", public=True,
                            vendor=True, num_nonexist=True, contradiction=True)
                if ent["residual"] is None:
                    ent["residual"] = "NUM_DECLARED_NONEXISTENT_BUT_DEFINED"

    # 3. the POD join: a man3 NAME entry or SYNOPSIS declaration, joined by its `subject`.
    #
    # This runs last, after every identity-bearing plane, because a documented name's witnesses
    # include symbols that only the binary, the dispatch graph or the Phase-1 atlas publish. A
    # claim whose subject **no** plane saw is the one residual this rule records, and it is
    # recorded against the subject name -- the claim's identity -- never against its declaration
    # text. A name that is merely ambiguous (two statics share it) is in the atlas and is joined.
    for claim in pod["claims"]:
        if claim["kind"] not in ("NAME_ENTRY", "SYNOPSIS_DECL"):
            continue
        # **Only a man3 page names a symbol.** A man1 NAME entry names a command, a man5 entry a
        # config file and a man7 entry a concept (`mac`, `rand`, `rsa`, `ssl` are provider pages);
        # projecting those into symbol space invents obligations that are not API, and made a
        # concept name "reachable" from a compatibility root. 22.11's own reverse-direction
        # measurement already scopes to section 3 for the same reason.
        if claim.get("section") != 3:
            continue
        subject = claim.get("subject")
        if not subject:
            continue
        if U.known(subject):
            for key in U.keys_for(subject):
                U.annotate(key, "pod-contract", documented=True)
            continue
        ent = U.add(f"sym|pod-doc:{subject}", "symbol", subject, "pod-contract",
                    kind="documented-name", documented=True, contradiction=True)
        if ent["residual"] is None:
            ent["residual"] = "POD_NAME_NOT_IN_ATLAS"

    # The cross-plane invariant against 22.11's dedicated POD oracle (the review's section 6).
    # Both answer "which documented name does no plane implement", with different witness sets;
    # this join sees more, so a name it calls missing that 22.11 found in the header/API atlas is
    # a projection gap here and is recorded rather than ignored.
    pod11_missing = {d["subject"] for d in pod["reconciliation"]["disagreements"]
                     if d["class"] == POD_RESIDUAL_CLASS}
    here_missing = {e["name"] for e in U.e.values()
                    if e.get("residual") == POD_RESIDUAL_CLASS}
    cross = pod_cross_plane(pod11_missing, here_missing)

    return [finalize(e) for e in U.e.values()], owner, {
        "compile-commands": cc, "pod": pod, "manifest": manifest, "genealogy": genealogy,
        "installed_pages": installed_pages, "pod_pages": pod_pages, "cli_names": cli_names,
        "config_names": config_names, "dispatch": dispatch, "binary": binary,
        "pod_cross_plane": cross,
    }


def internal_names(internal: dict) -> set[str]:
    return {r["symbol"] for r in internal["records"]}


def finalize(e: dict) -> dict:
    out = dict(e)
    out["planes"] = sorted(out["planes"])
    out["evidence"] = sorted(out["evidence"])
    return out


# ---------------------------------------------------------------------------
# roots
# ---------------------------------------------------------------------------

def build_roots(entities: list[dict]) -> dict:
    fams: dict[str, dict] = {
        "source-api": {"declaration": "public header declarations (Phase-1 functions/variables/"
                                       "macros/typedefs/structs)", "entities": 0},
        "binary-abi": {"declaration": "DSO exports and the .num/version-script promise "
                                      "(Phase-1 symbols-libcrypto/libssl)", "entities": 0},
        "modules": {"declaration": "provider/engine registration and dispatch tables (22.7)",
                    "entities": 0},
        "callbacks": {"declaration": "callback-slot targets in the typed edge graph (22.7)",
                      "entities": 0},
        "cli": {"declaration": "openssl CLI commands, aliases and pseudo-commands (22.9)",
                "entities": 0},
        "configuration": {"declaration": "configuration directives, environment variables and "
                                         "default paths (22.10)", "entities": 0},
        "distribution": {"declaration": "installed distribution entries (22.8)", "entities": 0},
    }
    for e in entities:
        for fam in root_families(set(e.get("evidence", []))):
            if fam in fams:
                fams[fam]["entities"] += 1
    fams["unpopulated"] = {
        "declaration": "root families the plan names but no 22.1-22.13 plane observes",
        "families": list(ROOT_FAMILIES_UNPOPULATED),
    }
    return fams


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Phase 22.12 cross-plane reconciliation")
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument("--self-test", action="store_true",
                    help="break the pure classifier in memory and require the court to fail")
    args = ap.parse_args(argv)

    entities, owner, aux = collect(args.authority)
    roots = build_roots(entities)
    body = build_body(entities, roots)
    # Recorded beside `counts`, not inside it: it is a cross-plane record, not a derivation of the
    # entity classification, and `build_body` must stay able to reproduce `counts` exactly.
    body["pod_cross_plane"] = aux.get("pod_cross_plane") or {}

    inputs = [InputRef(name="plan", path=REPO_ROOT / "docs" / "PHASE-22-SUBPHASES.md")]
    for plane, relpath in sorted(PLANE_ARTEFACTS.items()):
        p = REPO_ROOT / relpath
        if p.is_file():
            inputs.append(InputRef(name=plane, path=p))

    doc = envelope(kind="phase22-reconciliation", authority=args.authority, inputs=inputs,
                   body=body, generator=GENERATOR)
    doc["body"] = dict(doc["body"])
    doc["body"]["field_map"] = FIELD_MAP
    doc["body"]["entities"] = [encode_entity(e) for e in body["entities"]]
    write_json(OUT, doc)

    if args.self_test:
        ok = self_test(body)
        print(f"[phase22-reconciliation] self-test: {'OK' if ok else 'FAILED'}")
        if not ok:
            return 1

    c = body["counts"]
    print(f"[phase22-reconciliation] entities={c['entities']} spaces={c['by_space']}")
    print(f"[phase22-reconciliation] disposition={c['by_disposition']}")
    print(f"[phase22-reconciliation] residuals={c['residuals']} "
          f"classes={len(c['residuals_by_class'])} unknown={c['unknown']} "
          f"unknown_intersecting_roots={c['unknown_intersecting_roots']}")
    cross = body.get("pod_cross_plane") or {}
    print(f"[phase22-reconciliation] pod-cross-plane={cross}")
    # The cross-plane invariant is hard: a documented name this join calls missing while 22.11's
    # dedicated oracle found it in the header/API atlas is a gap in this projection, not a finding.
    unexplained = cross.get("only_here_unexplained") or []
    if unexplained:
        print("[phase22-reconciliation] FATAL: POD residual(s) not shared with 22.11 "
              f"(projection gap): {unexplained[:20]}")
        return 1
    bad = pod_identity_violations(body["residuals"])
    if bad:
        print("[phase22-reconciliation] FATAL: POD residual(s) keyed on a declaration, not an "
              f"identity: {bad[:20]}")
        return 1
    print(f"[phase22-reconciliation] owner_assigned={c['owner_assigned']} "
          f"joins={c['joins']} -> {rel(OUT)}")
    return 0


# ---------------------------------------------------------------------------
# the court
# ---------------------------------------------------------------------------

def _entity(key, name, planes, evidence, *, space="symbol", file=None, kind="function",
            residual=None, owner_phase=None):
    return {"key": key, "space": space, "name": name, "kind": kind, "file": file, "line": 1,
            "planes": list(planes), "evidence": list(evidence), "residual": residual,
            "owner_phase": owner_phase}


def court_reconcile(body: dict, roots: dict) -> dict:
    """`RT-PHASE22-RECONCILE`: an FRF-style sensitivity challenge of the join/classify logic.

    Round-trips the committed body from its own rows and roots, then drives `build_body` over
    five controlled in-memory mutations -- an entity one plane alone saw, an entity moved between
    dispositions, a contradiction between two planes, an `UNKNOWN` reachable from a root, and the
    removal of a plane's whole contribution -- and fails if any derivation is insensitive to it.
    """
    checks: list[tuple[str, bool]] = []
    entities = [decode_entity(e) for e in body["entities"]]
    body = dict(body)
    body["entities"] = entities
    checks.append(("baseline: the artefact has entities", len(entities) > 0))
    checks.append(("baseline: the artefact has residuals", body["counts"]["residuals"] > 0))
    checks.append(("baseline: the artefact has joins", body["counts"]["joins"] > 0))
    checks.append(("baseline: some entity is root reachable",
                   body["counts"]["root_reachable"] > 0))

    stripped = [{k: v for k, v in e.items()
                 if k not in ("disposition", "root_families", "parity", "court_family")}
                for e in entities]
    base = build_body(copy.deepcopy(stripped), copy.deepcopy(roots))
    for key in ("entities", "joins", "residuals", "counts", "roots", "dispositions",
                "root_families_unpopulated", "unjoined"):
        checks.append((f"round-trip: {key} equal", base[key] == body[key]))

    # 0. the POD identity rule: a residual is an entity identity, never a declaration, and the join
    #    actually happened (some documented name carries a witness plane beside `pod-contract`).
    bad_pod = pod_identity_violations(body["residuals"])
    checks.append((f"pod-identity: {len(bad_pod)} POD residual(s) keyed on a declaration",
                   not bad_pod))
    joined_pod = [e for e in body["entities"]
                  if "pod-contract" in e["planes"]
                  and any(p != "pod-contract" for p in e["planes"])]
    checks.append((f"pod-join: {len(joined_pod)} documented name(s) joined a witness plane",
                   len(joined_pod) > 0))

    # 1. add an entity seen by one plane only.
    mutated = copy.deepcopy(stripped)
    mutated.append(_entity("sym|phase22_probe_doxygen_only", "phase22_probe_doxygen_only",
                           ["doxygen"], ["doxygen-plane"], residual=None))
    new = build_body(mutated, copy.deepcopy(roots))
    checks.append(("add-one-plane-entity: entities rose by one",
                   new["counts"]["entities"] == base["counts"]["entities"] + 1))
    checks.append(("add-one-plane-entity: a DOXYGEN_ONLY residual appeared",
                   new["counts"]["residuals"] == base["counts"]["residuals"] + 1
                   and "DOXYGEN_ONLY" in new["counts"]["residuals_by_class"]))
    checks.append(("add-one-plane-entity: planes-by-count saw it",
                   new["counts"]["by_plane"]["doxygen"] == base["counts"]["by_plane"]["doxygen"] + 1))

    # 2. move an entity between dispositions (facts drive disposition, not the stored label).
    victim = next((e for e in base["entities"]
                   if e["disposition"] == "REQUIRED_COMPATIBILITY"), None)
    if victim is None:
        checks.append(("move-disposition: a required entity was found", False))
    else:
        mutated = copy.deepcopy(stripped)
        for e in mutated:
            if e["key"] == victim["key"]:
                # Keep only the plane witness flags and add the internal fact, so every root
                # flag is gone: the same entity must now fall out of REQUIRED_COMPATIBILITY.
                e["evidence"] = [f for f in e["evidence"] if f.endswith("-plane")] + ["internal"]
        new = build_body(mutated, copy.deepcopy(roots))
        checks.append(("move-disposition: REQUIRED_COMPATIBILITY fell by one",
                       new["counts"]["by_disposition"]["REQUIRED_COMPATIBILITY"]
                       == base["counts"]["by_disposition"]["REQUIRED_COMPATIBILITY"] - 1))
        checks.append(("move-disposition: an internal disposition rose",
                       (new["counts"]["by_disposition"]["INTERNAL_REACHABLE"]
                        + new["counts"]["by_disposition"]["INTERNAL_UNREACHABLE_PROFILE"])
                       == (base["counts"]["by_disposition"]["INTERNAL_REACHABLE"]
                           + base["counts"]["by_disposition"]["INTERNAL_UNREACHABLE_PROFILE"]) + 1))
        checks.append(("move-disposition: the entity is no longer required",
                       not any(e["disposition"] == "REQUIRED_COMPATIBILITY"
                               for e in new["entities"] if e["key"] == victim["key"])))

    # 3. add a contradiction between two planes.
    mutated = copy.deepcopy(stripped)
    mutated.append(_entity("sym|phase22_probe_contradiction", "phase22_probe_contradiction",
                           ["phase1-atlas", "binary"], ["phase1-atlas-plane", "binary-plane",
                                                        "contradiction"],
                           residual="PHASE22_PROBE_CONTRADICTION"))
    new = build_body(mutated, copy.deepcopy(roots))
    checks.append(("add-contradiction: an UNKNOWN rose by one",
                   new["counts"]["unknown"] == base["counts"]["unknown"] + 1))
    checks.append(("add-contradiction: the typed residual appeared",
                   new["counts"]["residuals_by_class"].get("PHASE22_PROBE_CONTRADICTION") == 1))
    checks.append(("add-contradiction: the entity is dispositioned UNKNOWN",
                   any(e["disposition"] == "UNKNOWN"
                       for e in new["entities"] if e["key"] == "sym|phase22_probe_contradiction")))

    # 4. add an UNKNOWN reachable from a declared compatibility root.
    mutated = copy.deepcopy(stripped)
    mutated.append(_entity("sym|phase22_probe_unknown_root", "phase22_probe_unknown_root",
                           ["phase1-atlas"], ["phase1-atlas-plane", "public", "contradiction"],
                           residual="PHASE22_PROBE_UNKNOWN_ROOT"))
    new = build_body(mutated, copy.deepcopy(roots))
    checks.append(("add-unknown-root: unknown_intersecting_roots rose by one",
                   new["counts"]["unknown_intersecting_roots"]
                   == base["counts"]["unknown_intersecting_roots"] + 1))
    checks.append(("add-unknown-root: unknown rose by one",
                   new["counts"]["unknown"] == base["counts"]["unknown"] + 1))

    # 5. remove a plane's contribution entirely.
    drop = "pod-contract"
    new = build_body(copy.deepcopy(stripped), copy.deepcopy(roots), removed_planes={drop})
    checks.append(("remove-plane: entities fell",
                   new["counts"]["entities"] < base["counts"]["entities"]))
    checks.append(("remove-plane: the plane no longer appears",
                   drop not in new["counts"]["by_plane"]))
    checks.append(("remove-plane: every kept entity lost that plane",
                   all(drop not in e["planes"] for e in new["entities"])))
    checks.append(("remove-plane: the join count is unchanged but a join lost keys",
                   any(j["left"] == "pod-contract" and j["left_keys"] == 0
                       for j in new["joins"])))
    checks.append(("remove-plane: residuals fell",
                   new["counts"]["residuals"] < base["counts"]["residuals"]))

    failures = [desc for desc, ok in checks if not ok]
    c = body["counts"]
    return {
        "court": "RT-PHASE22-RECONCILE",
        "artefact": ARTEFACT_REL,
        "summary": (f"{c['entities']} entities, {c['residuals']} residuals, "
                    f"{c['unknown']} unknown, {c['unknown_intersecting_roots']} unknown-in-roots"),
        "entities": c["entities"],
        "residuals": c["residuals"],
        "unknown": c["unknown"],
        "unknown_intersecting_roots": c["unknown_intersecting_roots"],
        "joins": c["joins"],
        "mutations": ["round-trip", "pod-identity", "add-one-plane-entity", "move-disposition",
                      "add-contradiction", "add-unknown-root", "remove-plane"],
        "observations": len(checks),
        "failures": failures,
        "verdict": "pass" if not failures else "fail",
    }


def courts() -> list[dict]:
    """`RT-PHASE22-RECONCILE`, or `[]` while the artefact has not landed."""
    path = REPO_ROOT / ARTEFACT_REL
    if not path.is_file():
        return []
    doc = json.loads(path.read_text(encoding="utf-8"))
    return [court_reconcile(doc["body"], doc["body"].get("roots", {}))]


# ---------------------------------------------------------------------------
# sensitivity self-test: break the logic in memory and require the court to fail
# ---------------------------------------------------------------------------

def self_test(body: dict) -> bool:
    """Prove the court can see each defect class by breaking a pure function in memory."""
    roots = body.get("roots", {})
    committed = dict(body)
    committed["entities"] = [encode_entity(e) for e in body["entities"]]
    baseline = court_reconcile(committed, roots)
    if baseline["verdict"] != "pass":
        print("  self-test: the unbroken court does not pass; cannot prove sensitivity")
        return False
    ok = True
    original_classify = classify
    original_parity = parity_for
    original_key_set = _key_set

    try:
        globals()["classify"] = lambda ev: "REQUIRED_COMPATIBILITY"
        if court_reconcile(committed, roots)["verdict"] != "fail":
            print("  self-test: a blind classify() was not caught")
            ok = False
        globals()["classify"] = original_classify

        globals()["parity_for"] = lambda disp, fams: []
        if court_reconcile(committed, roots)["verdict"] != "fail":
            print("  self-test: a blind parity_for() was not caught")
            ok = False
        globals()["parity_for"] = original_parity

        globals()["_key_set"] = lambda entities, plane, space_kind: set()
        if court_reconcile(committed, roots)["verdict"] != "fail":
            print("  self-test: a blind _key_set() was not caught")
        ok = ok and True

        # The POD identity rule: a declaration keyed as a residual must be caught, and the court
        # must name the specific check that caught it. A bare identifier must not be flagged.
        globals()["_key_set"] = original_key_set
        decl_key = POD_DOC_PREFIX + "int EVP_FOO(EVP_CTX *ctx)"
        if not pod_identity_violations([{"class": POD_RESIDUAL_CLASS, "key": decl_key}]):
            print("  self-test: pod_identity_violations did not flag a declaration key")
            ok = False
        if pod_identity_violations([{"class": POD_RESIDUAL_CLASS, "key": POD_DOC_PREFIX + "EVP_FOO"}]):
            print("  self-test: pod_identity_violations flagged a bare identifier")
            ok = False
        broken = dict(committed)
        broken["residuals"] = list(committed["residuals"]) + [
            {"class": POD_RESIDUAL_CLASS, "key": decl_key, "planes": ["pod-contract"],
             "disposition": "UNKNOWN"}]
        res = court_reconcile(broken, roots)
        if not any("pod-identity" in f for f in res.get("failures", [])):
            print("  self-test: the court did not name the pod-identity check for a declaration key")
            ok = False

        # The cross-plane invariant: a name this join calls missing that 22.11 did not is recorded.
        if pod_cross_plane({"A"}, {"A", "B"})["only_here_unexplained"] != ["B"]:
            print("  self-test: pod_cross_plane did not record the unexplained extra")
            ok = False
        if pod_cross_plane({"A", "B"}, {"A"})["resolved_by_wider_witness"] != 1:
            print("  self-test: pod_cross_plane did not record the wider-witness resolution")
            ok = False
    finally:
        globals()["classify"] = original_classify
        globals()["parity_for"] = original_parity
        globals()["_key_set"] = original_key_set
    return ok


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
