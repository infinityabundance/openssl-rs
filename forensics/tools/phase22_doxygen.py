#!/usr/bin/env python3
"""openssl-rs -- Phase 22.2 Doxygen entity-graph extractor.

Runs Doxygen, in the court container, over the admitted authority
`openssl-3.6.4-production` in **two views** and normalizes the Doxygen XML into the repository's
standard atlas document at `forensics/atlas/phase22/doxygen-entities.json`.

Why two views, and why Doxygen is one oracle and not the oracle
----------------------------------------------------------------
`docs/PHASE-22-SUBPHASES.md` section 6 makes this subphase's rule explicit: "Doxygen is one
oracle among several. OpenSSL's own policy makes the POD manual canonical for public APIs and the
Doxygen block a navigation aid; Doxygen absence must never be read as surface absence. Two views
are taken: a **configured** view (production profile, compilation database, Clang-assisted) and a
**lexical** view (discovery-only, deliberately reduced preprocessing) for material the production
profile hides."

This tool therefore runs Doxygen twice, with two pinned Doxyfiles
(`forensics/phase22/Doxyfile.configured`, `forensics/phase22/Doxyfile.lexical`):

  * the **configured** view preprocesses the tree with the authority's own build profile -- the
    include directories and preprocessor definitions 22.1 captured in
    `forensics/atlas/phase22/compile-commands.json` -- so it sees the entity set Doxygen resolves
    under the production `#if` graph;
  * the **lexical** view disables preprocessing entirely, so it parses each translation unit as
    written and reveals the branches the production profile removes. It "cannot assert runtime
    relevance" (section 6): an entity seen only here is *discovered*, never *compiled*.

The interesting output is the **lexical-minus-configured** set: the material only the discovery
view saw. It is recorded as its own list, `body.lexical_only`, and is compared against nothing --
it is a finding, not a defect.

Coverage, stated rather than assumed
------------------------------------
A full run is affordable (the whole tree is ~2,167 `*.c`/`*.h` files and Doxygen parses it in
seconds -- the measured times are printed to stdout and are not written into the document, because
a runtime is host-varying and this document must be byte-identical for the same tree). The
document's `body.coverage` records exactly what Doxygen was told to read: the `INPUT` root, the
`FILE_PATTERNS` it was restricted to, the directories and files it actually produced compounds
for, and the entities it found located *outside* the authority (system headers reached through
`#include`) that this tool deliberately does not harvest, because they are not the authority's
surface and their paths are the container's, not the repository's.

Reference resolution, and why the `refid` is resolved rather than dropped
-------------------------------------------------------------------------
A `<references>`/`<referencedby>` occurrence names its target with Doxygen's internal `refid`, and
only incidentally with a display spelling. Recording the spelling alone would collapse two
different authority entities that share it -- the canonical case being two `static` functions
named `lookup` in different files -- into one destination, which is precisely the information loss
this plane exists to prevent: a compatibility path that cannot name its target is a path that can
be lost. So the parse accumulates an index from every recorded `memberdef` and compound `id` to its
`(kind, name, file, line)` identity, and each edge is resolved against that index after the whole
view has been read (the index is only complete once every compound has been visited). A resolved
edge carries the full target identity; an edge whose `refid` is not in the index -- an external or
system target, an enum value, a compound kind this tool does not record -- is persisted explicitly
unresolved with its `refid` and spelling, never dropped. `body.counts.reference_edges_resolved` and
`reference_edges_unresolved` record how much of the graph resolved; an unresolved target is a
measurement, not a failure.

Determinism
-----------
`body.entities` is sorted by `(kind, name, file, line)` and every file path is repository-relative.
`body.references` is keyed by the resolved `kind|file|line|name` identity, its resolved target lists
and each source's keys are sorted, and its unresolved targets are sorted by `(refid, name)`. No
timestamp, PID or scratch path is written. The same source tree produces byte-identical JSON,
which is what lets this module's own `courts()` mutate the parsed rows in memory and check that the
merge, resolution and classification logic moves in exactly the expected way.

Output
------
    forensics/atlas/phase22/doxygen-entities.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    envelope,
    rel,
    resolve_authority,
    sha256_file,
    write_json,
)

GENERATOR = "forensics/tools/phase22_doxygen.py"
CAPTURE_REL = "forensics/atlas/phase22/compile-commands.json"
ARTEFACT_REL = "forensics/atlas/phase22/doxygen-entities.json"
OUT_REL = ARTEFACT_REL
COURT = "RT-PHASE22-DOXYGEN"

# The view order is fixed; it is the order the views are run in and the order they are rendered.
VIEWS = ("configured", "lexical")

DOXYFILE_REL = {
    "configured": "forensics/phase22/Doxyfile.configured",
    "lexical": "forensics/phase22/Doxyfile.lexical",
}

SCRATCH_DEFAULT = "/tmp/phase22-doxygen"
DOXYGEN = "doxygen"

# Which Doxygen compound kinds this tool treats as entities, and to which of the plan's entity
# kinds each maps. Directories, namespaces and pages are not entities of the compatibility
# surface; `dir` compounds are still counted in `coverage`.
_COMPOUND_KIND = {
    "file": "file",
    "struct": "struct",
    "union": "union",
    "group": "group",
    "class": "struct",
}

# Doxygen member kinds -> the plan's entity kinds. `variable` inside a struct/union compound is a
# `field`; inside a file compound it is a file-scope `variable`. That decision needs the parent
# compound, so it is made in `_member_rows`.
_MEMBER_KIND = {
    "function": "function",
    "define": "macro",
    "typedef": "typedef",
    "enum": "enum",
}

_WS = re.compile(r"\s+")


def _plain(elem: ET.Element | None) -> str:
    """The visible text of a description element, whitespace-collapsed to one line."""
    if elem is None:
        return ""
    return _WS.sub(" ", "".join(elem.itertext())).strip()


def _rel_file(abs_file: str | None, src_root: Path) -> str | None:
    """`abs_file` relative to the authority root, or None if it lies outside it.

    An entity located in a system header is not the authority's surface, and its absolute path is
    a property of the court image rather than the repository; both reasons to drop it. `coverage`
    counts what was dropped.
    """
    if not abs_file:
        return None
    try:
        p = Path(abs_file)
        return p.relative_to(src_root).as_posix()
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# profile derivation (the configured view's include paths and defines)
# ---------------------------------------------------------------------------

def derive_profile(capture_body: dict, src_root: Path) -> tuple[list[str], list[str]]:
    """The authority's include directories and preprocessor definitions, from 22.1's capture.

    Doxygen is a project-level parser, so the per-translation-unit flags are aggregated to a
    profile: the union of every `-I` directory and every `-D` definition the build issued. This is
    an approximation and is labelled as one -- Doxygen is not Clang and cannot be told per file.
    Include tokens are resolved against the captured build directory and, failing that, against
    the authority source root (the out-of-tree build's `-Iinclude`, `-Iapps`, ... were symlinks
    into the source tree, which a scratch build directory no longer holds).
    """
    build_dir = capture_body.get("directory") or ""
    includes: set[str] = set()
    defines: set[str] = set()
    for cmd in capture_body.get("commands", []):
        for tok in cmd.get("includes", []):
            path = tok.split(None, 1)[1] if tok.startswith("-I ") else tok[2:]
            cand = Path(path)
            if not cand.is_absolute():
                cand = Path(os.path.normpath(os.path.join(build_dir, path)))
            if not cand.is_dir():
                cand = Path(os.path.normpath(os.path.join(src_root, path)))
            if cand.is_dir():
                includes.add(cand.as_posix())
        for tok in cmd.get("defines", []):
            defn = tok.split(None, 1)[1] if tok.startswith("-D ") else tok[2:]
            if defn:
                defines.add(defn)
    return sorted(includes), sorted(defines)


# ---------------------------------------------------------------------------
# Doxygen invocation
# ---------------------------------------------------------------------------

def _effective_config(pinned: Path, out: Path, *, output_dir: Path, input_dir: Path,
                      extra: list[str]) -> None:
    """Compose the effective Doxyfile: the pinned policy, then the run-time overrides.

    The overrides are appended, not substituted, because Doxygen's configuration parser lets a
    later assignment win; the pinned file therefore stays a readable statement of the view and
    the generated file is the thing Doxygen actually reads.
    """
    lines = [
        "# generated by forensics/tools/phase22_doxygen.py -- do not edit",
        f"OUTPUT_DIRECTORY = {output_dir.as_posix()}",
        f"INPUT = {input_dir.as_posix()}",
        *extra,
    ]
    text = pinned.read_text(encoding="utf-8")
    if not text.endswith("\n"):
        text += "\n"
    out.write_text(text + "\n" + "\n".join(lines) + "\n", encoding="utf-8")


def run_doxygen(view: str, auth, capture_body: dict, scratch: Path) -> dict:
    """Run one view's Doxygen pass. Returns the metadata the document records for it."""
    pinned = REPO_ROOT / DOXYFILE_REL[view]
    output_dir = scratch / view
    effective = scratch / f"Doxyfile.{view}.effective"
    extra: list[str] = []
    if view == "configured":
        includes, defines = derive_profile(capture_body, auth.source)
        extra.append("INCLUDE_PATH = " + " ".join(includes))
        extra.append("PREDEFINED = " + " ".join(defines))
    _effective_config(pinned, effective, output_dir=output_dir, input_dir=auth.source,
                      extra=extra)

    started = time.monotonic()
    proc = subprocess.run([DOXYGEN, str(effective)], cwd=str(scratch),
                          capture_output=True, text=True, check=False)
    seconds = time.monotonic() - started
    if proc.returncode != 0:
        raise SystemExit(
            f"phase22-doxygen: doxygen failed for the {view} view (rc={proc.returncode}); "
            f"see {rel(effective)}; tail:\n" + "\n".join(proc.stderr.splitlines()[-20:])
        )
    xml_dir = output_dir / "xml"
    if not xml_dir.is_dir():
        raise SystemExit(f"phase22-doxygen: no XML produced at {xml_dir}")
    return {
        "view": view,
        "doxyfile": DOXYFILE_REL[view],
        "doxyfile_sha256": sha256_file(pinned),
        "preprocessing": "full-production-profile" if view == "configured"
                         else "disabled-discovery-only",
        "seconds": round(seconds, 1),
        "stdout_lines": len(proc.stdout.splitlines()),
    }


def doxygen_version() -> str:
    proc = subprocess.run([DOXYGEN, "--version"], capture_output=True, text=True, check=False)
    return proc.stdout.strip() or "unknown"


# ---------------------------------------------------------------------------
# XML normalization
# ---------------------------------------------------------------------------

def _identity(kind: str, name: str, file: str | None, line: int | None) -> dict:
    """A target's identity, in the same field order as `body.entities`."""
    return {"kind": kind, "name": name, "file": file, "line": line}


def _identity_str(ident: dict) -> str:
    """The `kind|file|line|name` key an identity is keyed by, everywhere it is stored.

    `line` is empty for an entity Doxygen gave no line (a file compound), so the split is total:
    no file path or entity name contains a `|`.
    """
    line = ident["line"] if ident["line"] is not None else ""
    return f"{ident['kind']}|{ident['file'] or ''}|{line}|{ident['name']}"


def _ident_from_str(key: str) -> dict:
    """The inverse of `_identity_str`, for the round-trip the court drives."""
    kind, file, line, name = key.split("|", 3)
    return _identity(kind, name, file or None, int(line) if line else None)


def _member_rows(compound: ET.Element, parent_kind: str, src_root: Path,
                 external: list[int]) -> tuple[list[dict], list[dict], dict[str, dict]]:
    """One compound's member rows, its raw outgoing edges, and its `id -> identity` index entries.

    Edges are returned **unresolved**: they carry the target `refid` and spelling but not the
    target's identity, because the identity index is only complete once every compound in the view
    has been visited. `parse_view` resolves them after the loop.
    """
    rows: list[dict] = []
    edges: list[dict] = []
    index: dict[str, dict] = {}
    for member in compound.findall("sectiondef/memberdef"):
        mkind = member.get("kind")
        if mkind == "enumvalue":
            continue  # counted via the enum's own kind; not a separate surface entity
        kind = _MEMBER_KIND.get(mkind)
        if kind is None and mkind == "variable":
            kind = "field" if parent_kind in ("struct", "union") else "variable"
        if kind is None:
            continue
        name = _plain(member.find("name"))
        if not name:
            continue
        loc = member.find("location")
        abs_file = loc.get("file") if loc is not None else None
        rel_file = _rel_file(abs_file, src_root)
        if abs_file is not None and rel_file is None:
            external[0] += 1
            continue
        line = None
        if loc is not None and loc.get("line"):
            try:
                line = int(loc.get("line"))
            except ValueError:
                line = None
        brief = _plain(member.find("briefdescription"))
        documented = bool(brief or _plain(member.find("detaileddescription")))
        row = {
            "kind": kind,
            "name": name,
            "file": rel_file,
            "line": line,
            "brief": brief,
            "is_static": member.get("static") == "yes",
            "documented": documented,
        }
        rows.append(row)
        ident = _identity(kind, name, rel_file, line)
        member_id = member.get("id")
        if member_id:
            index[member_id] = ident
        for rel_kind, tag in (("references", "references"), ("referenced_by", "referencedby")):
            for ref in member.findall(tag):
                edges.append({
                    "from": ident,
                    "relation": rel_kind,
                    "target_name": _plain(ref),
                    "target_refid": ref.get("refid"),
                })
    return rows, edges, index


def _resolve_edge(raw: dict, index: dict[str, dict]) -> dict:
    """Resolve a raw edge's `refid` against the identity index, or mark it unresolved.

    A missing `refid`, or one the index does not hold, is recorded as an unresolved target with
    both its spelling and its `refid`. An external or system target is real information about the
    graph even though it is not this authority's surface, and an unparsed internal one is a
    measurement of what the index could not name; neither is a silent drop.
    """
    refid = raw["target_refid"]
    target = index.get(refid) if refid else None
    if target is not None:
        return {"from": raw["from"], "relation": raw["relation"],
                "target": target, "resolved": True}
    return {"from": raw["from"], "relation": raw["relation"], "target_name": raw["target_name"],
            "target_refid": refid, "resolved": False}


def parse_view(xml_dir: Path, src_root: Path) -> dict:
    """Parse one view's Doxygen XML into entity rows, resolved edges and coverage counters.

    Every compound file is read independently (the full XML is ~200 MB, and a single parse of all
    compounds would hold it in memory for no benefit). `index.xml` is skipped: it is the summary,
    and the compound files carry the descriptions, locations and references this tool needs.

    The `id -> identity` index is accumulated while the compounds are read, because a reference may
    point forward to a compound not yet visited; edges are therefore resolved only after the whole
    view has been seen. It is a single pass over the XML, with a second pass over the edges in
    memory (the edge list is a fraction of the XML).
    """
    rows: list[dict] = []
    raw_edges: list[dict] = []
    index: dict[str, dict] = {}
    directories: list[str] = []
    files: list[str] = []
    external = [0]
    for path in sorted(xml_dir.glob("*.xml")):
        if path.name == "index.xml":
            continue
        try:
            root = ET.parse(path).getroot()
        except ET.ParseError as exc:  # a malformed compound is a finding, not a crash
            raise SystemExit(f"phase22-doxygen: cannot parse {path.name}: {exc}")
        compound = root.find("compounddef")
        if compound is None:
            continue
        ckind = compound.get("kind")
        loc = compound.find("location")
        abs_file, rel_file = None, None
        line = None
        if loc is not None:
            abs_file = loc.get("file")
            rel_file = _rel_file(abs_file, src_root)
            if loc.get("line"):
                try:
                    line = int(loc.get("line"))
                except ValueError:
                    line = None
        if ckind == "dir":
            if rel_file:
                directories.append(rel_file)
            continue
        kind = _COMPOUND_KIND.get(ckind)
        if kind is None:
            continue
        if abs_file is not None and rel_file is None:
            external[0] += 1
            continue
        name = _plain(compound.find("compoundname"))
        if kind == "file":
            if rel_file is None:
                continue
            name = rel_file
            files.append(rel_file)
        if not name:
            continue
        ident = _identity(kind, name, rel_file, line)
        compound_id = compound.get("id")
        if compound_id:
            index[compound_id] = ident
        brief = _plain(compound.find("briefdescription"))
        documented = bool(brief or _plain(compound.find("detaileddescription")))
        rows.append({
            "kind": kind,
            "name": name,
            "file": rel_file,
            "line": line,
            "brief": brief,
            "is_static": False,
            "documented": documented,
        })
        member_rows, member_edges, member_index = _member_rows(
            compound, "struct" if kind in ("struct", "union") else "file", src_root,
            external)
        rows.extend(member_rows)
        raw_edges.extend(member_edges)
        index.update(member_index)
    edges = [_resolve_edge(e, index) for e in raw_edges]
    resolved = sum(1 for e in edges if e["resolved"])
    return {"rows": rows, "edges": edges, "directories": sorted(set(directories)),
            "files": sorted(set(files)), "external": external[0],
            "edges_resolved": resolved, "edges_unresolved": len(edges) - resolved}


# ---------------------------------------------------------------------------
# view merge and body assembly (pure; the court drives these on mutated rows)
# ---------------------------------------------------------------------------

def entity_key(row: dict) -> tuple:
    return (row["kind"], row["name"], row["file"], row["line"])


def _sort_key(row: dict) -> tuple:
    line = row["line"] if row["line"] is not None else -1
    return (row["kind"], row["name"], row["file"] or "", line)


def merge_views(configured: list[dict], lexical: list[dict]) -> list[dict]:
    """Join the two views by `(kind, name, file, line)`; each entity carries its views.

    The identity is the source location, not the Doxygen `id`: an entity the same in both views
    must join even though Doxygen may assign it a different compound id. Sorting before the merge
    makes the result independent of the order the XML files were listed in.
    """
    merged: dict[tuple, dict] = {}
    for row in sorted(configured, key=_sort_key):
        merged[entity_key(row)] = {**row, "views": ["configured"]}
    for row in sorted(lexical, key=_sort_key):
        key = entity_key(row)
        if key in merged:
            merged[key]["views"].append("lexical")
        else:
            merged[key] = {**row, "views": ["lexical"]}
    # `views` is emitted in the fixed VIEWS order so it is deterministic.
    for row in merged.values():
        row["views"] = [v for v in VIEWS if v in row["views"]]
    return sorted(merged.values(), key=_sort_key)


def split_views(entities: list[dict]) -> tuple[list[dict], list[dict]]:
    """Reconstruct the per-view rows from a merged `entities` list (the court's round-trip)."""
    configured: list[dict] = []
    lexical: list[dict] = []
    for ent in entities:
        row = {k: v for k, v in ent.items() if k != "views"}
        views = ent.get("views", [])
        if "configured" in views:
            configured.append(row)
        if "lexical" in views:
            lexical.append(row)
    return configured, lexical


def _adjacency(edges: list[dict]) -> dict[str, dict[str, list]]:
    """Collapse the configured view's resolved edges into a per-source adjacency map.

    Doxygen gives a reference from both ends (`references` on the caller, `referenced_by` on the
    callee) and may repeat it per reference site, so the raw XML holds ~323k occurrences over ~70k
    entities; written out one JSON object per occurrence the artefact reached 127 MB, and the same
    information as a per-source adjacency is a fraction of that. Both the source key and every
    resolved destination are the `kind|file|line|name` identity, in the same field order as
    `body.entities`: keying a destination by its display spelling alone would merge two different
    entities that share one -- two `static` functions named `lookup` in different files -- into a
    single compatibility destination, which is exactly the loss this plane exists to prevent. A
    destination whose `refid` did not resolve is kept under `<relation>_unresolved` as `{name,
    refid}`, so an external or unparsed target is recorded rather than dropped. Every list is
    de-duplicated and sorted (`(refid, name)` for the unresolved ones).
    """
    out: dict[str, dict[str, set]] = {}
    for e in edges:
        key = _identity_str(e["from"])
        slot = out.setdefault(key, {"references": set(), "referenced_by": set(),
                                    "references_unresolved": set(),
                                    "referenced_by_unresolved": set()})
        rel = e["relation"]
        if e.get("resolved"):
            slot[rel].add(_identity_str(e["target"]))
        else:
            slot[f"{rel}_unresolved"].add((e.get("target_refid") or "", e.get("target_name") or ""))
    result: dict[str, dict[str, list]] = {}
    for key, slot in sorted(out.items()):
        references = sorted(slot["references"])
        referenced_by = sorted(slot["referenced_by"])
        refs_unresolved = [{"name": name, "refid": refid}
                           for refid, name in sorted(slot["references_unresolved"])]
        refby_unresolved = [{"name": name, "refid": refid}
                            for refid, name in sorted(slot["referenced_by_unresolved"])]
        if not (references or referenced_by or refs_unresolved or refby_unresolved):
            continue
        entry: dict[str, list] = {"references": references, "referenced_by": referenced_by}
        if refs_unresolved:
            entry["references_unresolved"] = refs_unresolved
        if refby_unresolved:
            entry["referenced_by_unresolved"] = refby_unresolved
        result[key] = entry
    return result


def _key_list(rows: list[dict]) -> list[list]:
    """A list of `[kind, name, file, line]` identities, for the view-difference lists.

    The full rows are already in `entities`, so the difference lists carry identities only; this
    avoids storing ~29k duplicated rows and keeps the artefact bounded.
    """
    return [[r["kind"], r["name"], r["file"], r["line"]] for r in rows]


def build_body(configured_rows: list[dict], lexical_rows: list[dict], edges: list[dict]) -> dict:
    """The atlas body from two views' rows and the configured view's edges. A pure function.

    This module's own `courts()` calls it on the committed artefact's own rows and edges and on
    controlled in-memory mutations of them, so it must stay free of I/O.
    """
    entities = merge_views(configured_rows, lexical_rows)
    lexical_only = [e for e in entities if e["views"] == ["lexical"]]
    configured_only = [e for e in entities if e["views"] == ["configured"]]
    shared = [e for e in entities if len(e["views"]) == 2]

    def kind_counts(rows: list[dict]) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in rows:
            out[r["kind"]] = out.get(r["kind"], 0) + 1
        return dict(sorted(out.items()))

    references = _adjacency(edges)
    resolved_total = sum(len(v["references"]) + len(v["referenced_by"])
                         for v in references.values())
    unresolved_total = sum(len(v.get("references_unresolved", []))
                           + len(v.get("referenced_by_unresolved", []))
                           for v in references.values())
    edge_total = resolved_total + unresolved_total
    return {
        "entities": entities,
        "references": references,
        "lexical_only": _key_list(lexical_only),
        "configured_only": _key_list(configured_only),
        "counts": {
            "entities": len(entities),
            "configured": len(configured_rows),
            "lexical": len(lexical_rows),
            "shared": len(shared),
            "lexical_only": len(lexical_only),
            "configured_only": len(configured_only),
            "documented": sum(1 for e in entities if e["documented"]),
            "static": sum(1 for e in entities if e["is_static"]),
            "reference_sources": len(references),
            "reference_edges": edge_total,
            "reference_edges_resolved": resolved_total,
            "reference_edges_unresolved": unresolved_total,
            "reference_resolution_rate": (round(resolved_total / edge_total, 6)
                                         if edge_total else None),
            "entities_by_kind": kind_counts(entities),
            "lexical_only_by_kind": kind_counts(lexical_only),
            "configured_only_by_kind": kind_counts(configured_only),
        },
    }


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument("--scratch", default=SCRATCH_DEFAULT,
                    help="scratch directory for Doxygen output (default: %(default)s)")
    ap.add_argument("--capture", default=CAPTURE_REL,
                    help="22.1's normalized capture (default: %(default)s)")
    ap.add_argument("--keep", action="store_true",
                    help="reuse existing Doxygen XML instead of re-running Doxygen")
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    capture_path = REPO_ROOT / args.capture
    if not capture_path.is_file():
        raise SystemExit(
            f"phase22-doxygen: 22.1's capture is missing: {rel(capture_path)}; run "
            "forensics/tools/phase22_build_commands.py first"
        )
    capture_body = json.loads(capture_path.read_text(encoding="utf-8"))["body"]

    scratch = Path(args.scratch)
    scratch.mkdir(parents=True, exist_ok=True)

    version = doxygen_version()
    view_rows: list[dict] = []
    parsed: dict[str, dict] = {}
    for view in VIEWS:
        print(f"[phase22-doxygen] running the {view} view ...")
        meta = run_doxygen(view, auth, capture_body, scratch) if not args.keep else {
            "view": view,
            "doxyfile": DOXYFILE_REL[view],
            "doxyfile_sha256": sha256_file(REPO_ROOT / DOXYFILE_REL[view]),
            "preprocessing": "full-production-profile" if view == "configured"
                             else "disabled-discovery-only",
            "seconds": None,
            "stdout_lines": None,
        }
        parsed[view] = parse_view(scratch / view / "xml", auth.source)
        meta["counts"] = {"entities": len(parsed[view]["rows"]),
                          "files": len(parsed[view]["files"]),
                          "directories": len(parsed[view]["directories"]),
                          "external_entities_skipped": parsed[view]["external"]}
        if meta.get("seconds") is not None:
            print(f"[phase22-doxygen]   {view}: {meta['seconds']}s, "
                  f"{meta['counts']['entities']} entities in {meta['counts']['files']} files")
        view_rows.append(meta)

    # Only the configured view's references are modeled: a reference resolved with preprocessing
    # disabled is a lexical coincidence, not the authority's include resolution (Doxyfile.lexical
    # sets REFERENCES_RELATION = NO, so `parsed['lexical']['edges']` is empty in practice).
    edges = parsed["configured"]["edges"]
    body = build_body(parsed["configured"]["rows"], parsed["lexical"]["rows"], edges)

    body["doxygen_version"] = version
    body["views"] = [
        {"view": m["view"], "doxyfile": m["doxyfile"], "doxyfile_sha256": m["doxyfile_sha256"],
         "preprocessing": m["preprocessing"], "counts": m["counts"]}
        for m in view_rows
    ]
    body["coverage"] = {
        "input_root": rel(auth.source),
        "recursive": True,
        "file_patterns": ["*.c", "*.h"],
        "directories_parsed": len(parsed["configured"]["directories"]),
        "files_parsed": len(parsed["configured"]["files"]),
        "note": (
            "Doxygen's INPUT is the whole authority source tree with RECURSIVE = YES and "
            "FILE_PATTERNS = *.c *.h, so every directory is parsed and only non-C translation "
            "units and headers are skipped. Entities whose location lies outside the authority "
            "(system headers reached through #include) are counted in each view's "
            "`external_entities_skipped` and are deliberately not harvested: they are not this "
            "authority's surface."
        ),
    }
    body["preprocessing_note"] = (
        "The configured view preprocesses with the authority's captured include paths and "
        "definitions, so it sees the entity set Doxygen resolves under the production #if graph "
        "and it is the only view that yields `#define` entities and reference edges. The "
        "preprocessor doing that work is Doxygen's own, not Clang's -- Doxygen 1.9.4 has no Clang "
        "frontend -- so the capture is fed to it as an aggregated project profile rather than per "
        "translation unit. The Clang-assisted reading of the same captured invocations is 22.3's "
        "every-translation-unit AST, not this plane (docs/PHASE-22-SUBPHASES.md section 6). The "
        "lexical view disables preprocessing, revealing the branches the production profile "
        "removes; a known and recorded consequence is that Doxygen 1.9.4 then recognises no "
        "`#define` at all, so `macro` entities appear only in the configured view. Per "
        "docs/PHASE-22-SUBPHASES.md section 6, neither view is the oracle: `lexical_only` is "
        "discovered material, and Doxygen absence (in either view) is never surface absence."
    )
    body["sort_key"] = "(kind, name, file, line); file is repository-relative; line is null only " \
                       "for compounds Doxygen gives no line (files)"
    body["reference_note"] = (
        "`references` is keyed by the resolved `kind|file|line|name` identity of the referencing "
        "entity, and each resolved destination is that same identity, so two different entities "
        "that happen to share a spelling remain two destinations. A destination whose Doxygen "
        "`refid` was not in the member/compound index is recorded unresolved under "
        "`<relation>_unresolved` as `{name, refid}` rather than dropped; "
        "`counts.reference_edges_resolved`/`reference_edges_unresolved` give the split. Only the "
        "configured view's references are modeled: a reference resolved with preprocessing "
        "disabled is a lexical coincidence, not the authority's include resolution "
        "(Doxyfile.lexical sets REFERENCES_RELATION = NO, so the lexical view yields no edges)."
    )

    doc = envelope(
        kind="phase22-doxygen-entities",
        authority=auth.id,
        inputs=[
            InputRef(name="compile-commands", path=capture_path),
            InputRef(name="doxyfile-configured", path=REPO_ROOT / DOXYFILE_REL["configured"]),
            InputRef(name="doxyfile-lexical", path=REPO_ROOT / DOXYFILE_REL["lexical"]),
        ],
        body=body,
        generator=GENERATOR,
    )
    write_json(REPO_ROOT / OUT_REL, doc)

    c = body["counts"]
    print(f"[phase22-doxygen] doxygen {version}: entities={c['entities']} "
          f"(configured={c['configured']}, lexical={c['lexical']}, shared={c['shared']}, "
          f"lexical_only={c['lexical_only']}, configured_only={c['configured_only']})")
    print(f"[phase22-doxygen] references: {c['reference_sources']} source entities, "
          f"{c['reference_edges']} deduplicated edges "
          f"({c['reference_edges_resolved']} resolved, {c['reference_edges_unresolved']} "
          f"unresolved); documented={c['documented']} "
          f"static={c['static']} -> {rel(REPO_ROOT / OUT_REL)}")
    return 0


# ---------------------------------------------------------------------------
# the court (discovered by forensics/tools/phase22_courts.py; see D490)
# ---------------------------------------------------------------------------

def _identity_list(row: dict) -> list:
    return [row["kind"], row["name"], row["file"], row["line"]]


def _entities_by_identity(entities: list[dict]) -> dict[tuple, dict]:
    return {tuple(_identity_list(e)): e for e in entities}


def _edges_from_references(references: dict) -> list[dict]:
    """Rebuild the flat resolved edge list that `_adjacency` collapsed.

    The round trip re-derives the adjacency from the committed artefact and compares, so the court
    judges the resolver and the collapse rather than trusting the stored copy. A resolved
    destination is an identity string; an unresolved one is a `{name, refid}` object.
    """
    out: list[dict] = []
    for key, slot in references.items():
        src = _ident_from_str(key)
        for relation in ("references", "referenced_by"):
            for dst in slot.get(relation, []):
                out.append({"from": src, "relation": relation, "target": _ident_from_str(dst),
                            "resolved": True})
            for entry in slot.get(f"{relation}_unresolved", []):
                out.append({"from": src, "relation": relation, "resolved": False,
                            "target_refid": entry["refid"], "target_name": entry["name"]})
    return out


def _stable(base: dict, new: dict, moved: set) -> bool:
    """Every entity except those named by `moved` is byte-for-byte identical."""
    a, b = _entities_by_identity(base["entities"]), _entities_by_identity(new["entities"])
    return all(a.get(k) == b.get(k) for k in (set(a) | set(b)) - moved)


def _mutation_add_entity(configured, lexical, edges, base, checks) -> None:
    synth = {"kind": "function", "name": "phase22_synthetic_probe",
             "file": "synthetic/phase22_probe.c", "line": 1, "brief": "",
             "is_static": True, "documented": False}
    new = build_body(configured + [synth], lexical, edges)
    checks.append(("add-entity: entities rose by one",
                   new["counts"]["entities"] == base["counts"]["entities"] + 1))
    checks.append(("add-entity: configured rose by one",
                   new["counts"]["configured"] == base["counts"]["configured"] + 1))
    checks.append(("add-entity: configured_only rose by one",
                   new["counts"]["configured_only"] == base["counts"]["configured_only"] + 1))
    row = _entities_by_identity(new["entities"]).get(tuple(_identity_list(synth)))
    checks.append(("add-entity: the unit is present and configured-only",
                   row is not None and row["views"] == ["configured"]))
    checks.append(("add-entity: nothing else moved",
                   _stable(base, new, {tuple(_identity_list(synth))})))


def _mutation_add_lexical_only(configured, lexical, edges, base, checks) -> None:
    synth = {"kind": "function", "name": "phase22_synthetic_lexical_probe",
             "file": "synthetic/phase22_probe.c", "line": 2, "brief": "",
             "is_static": False, "documented": False}
    new = build_body(configured, lexical + [synth], edges)
    checks.append(("add-lexical-only: entities rose by one",
                   new["counts"]["entities"] == base["counts"]["entities"] + 1))
    checks.append(("add-lexical-only: lexical_only rose by one",
                   new["counts"]["lexical_only"] == base["counts"]["lexical_only"] + 1))
    row = _entities_by_identity(new["entities"]).get(tuple(_identity_list(synth)))
    checks.append(("add-lexical-only: the unit is present and lexical-only",
                   row is not None and row["views"] == ["lexical"]))


def _mutation_clear_documented(configured, lexical, edges, base, checks) -> None:
    idx = next((i for i, e in enumerate(configured) if e["documented"]), None)
    if idx is None:
        checks.append(("clear-documented: a documented configured entity was found", False))
        return
    target = tuple(_identity_list(configured[idx]))
    mutated = copy.deepcopy(configured)
    mutated[idx]["documented"] = False
    new = build_body(mutated, lexical, edges)
    checks.append(("clear-documented: documented count fell by one",
                   new["counts"]["documented"] == base["counts"]["documented"] - 1))
    row = _entities_by_identity(new["entities"]).get(target)
    checks.append(("clear-documented: the entity now reads undocumented",
                   row is not None and not row["documented"]))
    checks.append(("clear-documented: entity count unchanged",
                   new["counts"]["entities"] == base["counts"]["entities"]))
    checks.append(("clear-documented: no other entity moved", _stable(base, new, {target})))


def _mutation_move_location(configured, lexical, edges, base, checks) -> None:
    """Moving a shared entity's line breaks the identity join between the two views."""
    configured_keys = {tuple(_identity_list(e)) for e in configured}
    idx = next((i for i, e in enumerate(lexical) if tuple(_identity_list(e)) in configured_keys),
               None)
    if idx is None:
        checks.append(("move-location: a shared entity was found", False))
        return
    mutated = copy.deepcopy(lexical)
    old = tuple(_identity_list(mutated[idx]))
    mutated[idx]["line"] = (mutated[idx]["line"] or 0) + 10_000_000
    new = build_body(configured, mutated, edges)
    checks.append(("move-location: entities rose by one (the join split)",
                   new["counts"]["entities"] == base["counts"]["entities"] + 1))
    checks.append(("move-location: shared fell by one",
                   new["counts"]["shared"] == base["counts"]["shared"] - 1))
    checks.append(("move-location: lexical_only rose by one",
                   new["counts"]["lexical_only"] == base["counts"]["lexical_only"] + 1))
    checks.append(("move-location: configured_only rose by one",
                   new["counts"]["configured_only"] == base["counts"]["configured_only"] + 1))
    by_id = _entities_by_identity(new["entities"])
    old_row = by_id.get(old)
    new_row = by_id.get(tuple(_identity_list(mutated[idx])))
    checks.append(("move-location: the original key is now configured-only",
                   old_row is not None and old_row["views"] == ["configured"]))
    checks.append(("move-location: the moved key is now lexical-only",
                   new_row is not None and new_row["views"] == ["lexical"]))


def _mutation_add_edge(configured, lexical, edges, base, checks) -> None:
    src = _identity("function", "phase22_probe_fn", "synthetic/phase22_probe.c", 3)
    dst = _identity("function", "EVP_DigestInit_ex", "crypto/evp/digest.c", 1)
    new = build_body(configured, lexical, edges + [
        {"from": src, "relation": "references", "target": dst, "resolved": True}])
    checks.append(("add-edge: reference_sources rose by one",
                   new["counts"]["reference_sources"] == base["counts"]["reference_sources"] + 1))
    checks.append(("add-edge: reference_edges rose by one",
                   new["counts"]["reference_edges"] == base["counts"]["reference_edges"] + 1))
    checks.append(("add-edge: reference_edges_resolved rose by one",
                   new["counts"]["reference_edges_resolved"]
                   == base["counts"]["reference_edges_resolved"] + 1))
    key = _identity_str(src)
    checks.append(("add-edge: the adjacency gained the source with the resolved identity",
                   key in new["references"]
                   and new["references"][key]["references"] == [_identity_str(dst)]))


def _mutation_same_spelling(configured, lexical, edges, base, checks) -> None:
    """Two entities that share a spelling must be two destinations, not one.

    This is the mutation that proves the defect class directly. The canonical case is two `static`
    functions named `lookup` in different files: the extractor resolves each `refid` to a distinct
    identity, so the caller has two destinations. If `_adjacency` keyed targets by the bare name
    the two edges below would collapse into one `lookup`, `len(refs)` would be 1, and every check
    here would fail -- which is what makes this evidence rather than a code change.
    """
    caller = _identity("function", "phase22_spelling_caller", "synthetic/phase22_probe.c", 7)
    a = _identity("function", "lookup", "crypto/phase22_a.c", 11)
    b = _identity("function", "lookup", "crypto/phase22_b.c", 22)
    new = build_body(configured, lexical, edges + [
        {"from": caller, "relation": "references", "target": a, "resolved": True},
        {"from": caller, "relation": "references", "target": b, "resolved": True},
    ])
    refs = new["references"].get(_identity_str(caller), {}).get("references", [])
    checks.append(("same-spelling: two same-named targets are two destinations, not one",
                   len(refs) == 2))
    checks.append(("same-spelling: both target identities are present",
                   _identity_str(a) in refs and _identity_str(b) in refs))
    checks.append(("same-spelling: the two destinations differ",
                   len(refs) == 2 and refs[0] != refs[1]))
    checks.append(("same-spelling: reference_edges rose by two",
                   new["counts"]["reference_edges"] == base["counts"]["reference_edges"] + 2))


def _mutation_unresolved_edge(configured, lexical, edges, base, checks) -> None:
    """A target whose `refid` did not resolve is recorded, not silently dropped."""
    caller = _identity("function", "phase22_external_caller", "synthetic/phase22_probe.c", 9)
    new = build_body(configured, lexical, edges + [
        {"from": caller, "relation": "references", "resolved": False,
         "target_refid": "external_refid_1", "target_name": "printf"}])
    slot = new["references"].get(_identity_str(caller), {})
    checks.append(("unresolved-edge: the unresolved target is recorded with its refid and name",
                   slot.get("references_unresolved")
                   == [{"name": "printf", "refid": "external_refid_1"}]))
    checks.append(("unresolved-edge: reference_edges rose by one",
                   new["counts"]["reference_edges"] == base["counts"]["reference_edges"] + 1))
    checks.append(("unresolved-edge: reference_edges_resolved did not move",
                   new["counts"]["reference_edges_resolved"]
                   == base["counts"]["reference_edges_resolved"]))
    checks.append(("unresolved-edge: reference_edges_unresolved rose by one",
                   new["counts"]["reference_edges_unresolved"]
                   == base["counts"]["reference_edges_unresolved"] + 1))


def court_doxygen(body: dict) -> dict:
    """`RT-PHASE22-DOXYGEN`: the extractor's view-merge, reference resolution and classification."""
    configured, lexical = split_views(copy.deepcopy(body["entities"]))
    edges = _edges_from_references(body["references"])
    checks: list[tuple[str, bool]] = []
    c = body["counts"]

    checks.append(("baseline: the artefact has entities", c["entities"] > 0))
    checks.append(("baseline: the artefact has reference edges", c["reference_edges"] > 0))
    checks.append(("baseline: both views contributed entities",
                   len(configured) > 0 and len(lexical) > 0))
    checks.append(("baseline: some reference targets resolved",
                   c.get("reference_edges_resolved", 0) > 0))

    # Round-trip: re-derive the whole body from the artefact's own rows and edges. This is the
    # freshness gate a tracked raw input would give; here it ties the committed artefact to the
    # logic that produced it rather than to a copy of its output.
    rebuilt = build_body(copy.deepcopy(configured), copy.deepcopy(lexical), edges)
    checks.append(("round-trip: entities equal", rebuilt["entities"] == body["entities"]))
    checks.append(("round-trip: references equal", rebuilt["references"] == body["references"]))
    checks.append(("round-trip: lexical_only equal",
                   rebuilt["lexical_only"] == body["lexical_only"]))
    checks.append(("round-trip: configured_only equal",
                   rebuilt["configured_only"] == body["configured_only"]))
    checks.append(("round-trip: counts equal", rebuilt["counts"] == c))

    base = build_body(copy.deepcopy(configured), copy.deepcopy(lexical), edges)
    _mutation_add_entity(copy.deepcopy(configured), copy.deepcopy(lexical), edges, base, checks)
    _mutation_add_lexical_only(copy.deepcopy(configured), copy.deepcopy(lexical), edges, base,
                               checks)
    _mutation_clear_documented(copy.deepcopy(configured), copy.deepcopy(lexical), edges, base,
                               checks)
    _mutation_move_location(copy.deepcopy(configured), copy.deepcopy(lexical), edges, base,
                            checks)
    _mutation_add_edge(copy.deepcopy(configured), copy.deepcopy(lexical), edges, base, checks)
    _mutation_same_spelling(copy.deepcopy(configured), copy.deepcopy(lexical), edges, base, checks)
    _mutation_unresolved_edge(copy.deepcopy(configured), copy.deepcopy(lexical), edges, base,
                              checks)

    failures = [desc for desc, ok in checks if not ok]
    return {
        "court": COURT,
        "artefact": ARTEFACT_REL,
        "doxygen_version": body.get("doxygen_version"),
        "entities": c["entities"],
        "lexical_only": c["lexical_only"],
        "reference_edges": c["reference_edges"],
        "reference_edges_resolved": c.get("reference_edges_resolved"),
        "reference_edges_unresolved": c.get("reference_edges_unresolved"),
        "mutations": ["round-trip", "add-entity", "add-lexical-only", "clear-documented",
                      "move-location", "add-edge", "same-spelling", "unresolved-edge"],
        "observations": len(checks),
        "failures": failures,
        "verdict": "pass" if not failures else "fail",
        "summary": (f"{c['entities']} entities, {c['lexical_only']} lexical-only, "
                    f"{c['reference_edges']} reference edges "
                    f"({c.get('reference_edges_resolved')} resolved / "
                    f"{c.get('reference_edges_unresolved')} unresolved)"),
    }


def courts() -> list[dict]:
    """`RT-PHASE22-DOXYGEN`, or `[]` while the artefact has not landed.

    Discovered by `forensics/tools/phase22_courts.py` rather than listed there, so landing this
    plane adds a file and nothing else (docs/DECISIONS.md D490).
    """
    path = REPO_ROOT / ARTEFACT_REL
    if not path.is_file():
        return []
    try:
        body = json.loads(path.read_text(encoding="utf-8"))["body"]
    except Exception as exc:  # a court that cannot read its artefact is a failing court
        return [{"court": COURT, "artefact": ARTEFACT_REL, "verdict": "fail",
                 "stage": "artefact-unreadable", "observations": 0, "failures": [str(exc)]}]
    return [court_doxygen(body)]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
