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

Determinism
-----------
`body.entities` is sorted by `(kind, name, file, line)` and every file path is repository-relative.
No timestamp, PID or scratch path is written. The same source tree produces byte-identical JSON,
which is what lets `forensics/tools/phase22_courts.py`'s `RT-PHASE22-DOXYGEN` mutate the parsed
rows in memory and check that the merge and classification logic moves in exactly the expected way.

Output
------
    forensics/atlas/phase22/doxygen-entities.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
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
OUT_REL = "forensics/atlas/phase22/doxygen-entities.json"

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

def _member_rows(compound: ET.Element, parent_kind: str, src_root: Path,
                 external: list[int]) -> tuple[list[dict], list[dict]]:
    """Rows for every memberdef of one compound, plus that compound's outgoing edges."""
    rows: list[dict] = []
    edges: list[dict] = []
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
        for rel_kind, tag in (("references", "references"), ("referenced_by", "referencedby")):
            for ref in member.findall(tag):
                edges.append({
                    "from_kind": kind,
                    "from_name": name,
                    "from_file": rel_file,
                    "from_line": line,
                    "relation": rel_kind,
                    "name": _plain(ref),
                })
    return rows, edges


def parse_view(xml_dir: Path, src_root: Path) -> dict:
    """Parse one view's Doxygen XML into entity rows, edges and coverage counters.

    Every compound file is read independently (the full XML is ~200 MB, and a single parse of all
    compounds would hold it in memory for no benefit). `index.xml` is skipped: it is the summary,
    and the compound files carry the descriptions, locations and references this tool needs.
    """
    rows: list[dict] = []
    edges: list[dict] = []
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
        member_rows, member_edges = _member_rows(
            compound, "struct" if kind in ("struct", "union") else "file", src_root,
            external)
        rows.extend(member_rows)
        edges.extend(member_edges)
    return {"rows": rows, "edges": edges, "directories": sorted(set(directories)),
            "files": sorted(set(files)), "external": external[0]}


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


def _adjacency(edges: list[dict]) -> dict[str, dict[str, list[str]]]:
    """Collapse the configured view's references into a per-entity adjacency map.

    Doxygen gives the same `caller -> callee` reference once per reference site and gives the
    relation from both ends (`references` on the caller, `referenced_by` on the callee), so the
    raw XML holds ~323k occurrences over ~70k entities. Written out one JSON object per
    occurrence the artefact reached 127 MB; the same information as a per-source-entity adjacency
    with de-duplicated target names is a fraction of that, and the Doxygen-internal `refid`, which
    means nothing to any consumer, is dropped. The key is `kind|file|line|name` -- the entity
    identity, in the same field order as `body.entities`.
    """
    out: dict[str, dict[str, set[str]]] = {}
    for e in edges:
        line = e["from_line"] if e["from_line"] is not None else ""
        key = f"{e['from_kind']}|{e['from_file'] or ''}|{line}|{e['from_name']}"
        slot = out.setdefault(key, {"references": set(), "referenced_by": set()})
        if e["name"]:
            slot[e["relation"]].add(e["name"])
    return {
        key: {rel: sorted(vals) for rel, vals in slot.items()}
        for key, slot in sorted(out.items())
        if slot["references"] or slot["referenced_by"]
    }


def _key_list(rows: list[dict]) -> list[list]:
    """A list of `[kind, name, file, line]` identities, for the view-difference lists.

    The full rows are already in `entities`, so the difference lists carry identities only; this
    avoids storing ~29k duplicated rows and keeps the artefact bounded.
    """
    return [[r["kind"], r["name"], r["file"], r["line"]] for r in rows]


def build_body(configured_rows: list[dict], lexical_rows: list[dict], edges: list[dict]) -> dict:
    """The atlas body from two views' rows and the configured view's edges. A pure function.

    `forensics/tools/phase22_courts.py`'s `RT-PHASE22-DOXYGEN` calls this on the committed
    artefact's own rows and on controlled in-memory mutations, so it must stay free of I/O.
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
    edge_total = sum(len(v["references"]) + len(v["referenced_by"])
                     for v in references.values())
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
          f"{c['reference_edges']} deduplicated edges; documented={c['documented']} "
          f"static={c['static']} -> {rel(REPO_ROOT / OUT_REL)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
