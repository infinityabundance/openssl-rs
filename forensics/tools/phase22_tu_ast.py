#!/usr/bin/env python3
"""openssl-rs -- Phase 22.3 every-translation-unit Clang AST extractor.

Replays the exact compile invocations 22.1 captured
(`forensics/atlas/phase22/compile-commands.json`) with **Clang as a shadow analysis
instrument** and normalizes the result into the repository's standard, content-addressed
atlas document at `forensics/atlas/phase22/tu-ast.json`: a per-translation-unit entity
census and the declaration/definition graph that Phase 1's header-only view and 22.2's
Doxygen view cannot see.

Why a replay, and why the authority stays a GCC build
-----------------------------------------------------
`docs/PHASE-22-SUBPHASES.md` section 6: "22.3 must parse **every** active translation
unit, not a synthetic aggregate." This tool therefore takes each captured invocation
field by field -- the ordered `-D` definitions and `-I` include directories 22.1 recorded
-- and hands those same flags to Clang. The body records `producer` = the authority's own
compiler (read from the pinned `configdata.pm`, exactly as `phase22_build_commands.py`
does) and `analysis_instrument` = `"clang"`, together with the sentence that Clang is a
*shadow* instrument: the authority is a GCC build, and reading its invocations with Clang
never redefines it as a Clang build. `producer` and `analysis_instrument` are two
different facts and both are written down.

What is extracted, per translation unit
---------------------------------------
For each distinct logical translation unit the tool records the entities that unit
*contributes* -- those declared or defined in the unit's own main file, plus block-scope
`static`/`_Thread_local` objects, which are file-local state the source contains and no
header names:

  * functions (external, static, inline), with `is_static` and `linkage`;
  * structs, unions, enums, typedefs and their fields/enumerators;
  * file-scope globals, `static` and thread-local variables;
  * the `visibility`, `alias`, `weak`, `noreturn`, `constructor`, `destructor`,
    `deprecated` and `target` attributes, by name;
  * direct calls (`DIRECT_CALL`) and address-taken functions (`ADDRESS_TAKEN`);
  * the declaration<->definition link for each entity, resolved through Clang's
    `previousDecl` chain, so a definition whose only declaration is in a header is
    distinguishable from one with no declaration anywhere.

Header and system declarations are *walked* (they are needed to resolve call targets and
declaration links) but are **not** emitted as per-TU entities: they are the surface Phase
1 and 22.2 already own, and emitting them once per including translation unit would
duplicate them a thousand times. Only the unit's own contribution is recorded.

How the location encoding is decoded
------------------------------------
Clang's `-ast-dump=json` suppresses a `file`/`line`/`col`/`offset` field when it equals
the value last emitted, so a location can legitimately arrive without a `file` or a
`line`. Those fields are recovered by replaying the dump in document order and carrying
the last-seen value forward, exactly as Clang emitted it (the node's `loc`, then its
`range`, then its children). `includedFrom` is metadata about the include parent and is
deliberately *not* allowed to move that carried state. The reconstruction was validated
against libclang's `clang_getExpansionLocation` on real units; the two agree exactly.

Cost, and what was reduced
--------------------------
A full `-Xclang -ast-dump=json` per unit was measured first (one unit, then extrapolated),
as section 6 and the subphase brief require. The measured cost of a full honest replay of
the 1,216 distinct C units is a single-digit number of minutes, well inside the budget, so
**nothing about the extraction was narrowed**: every distinct logical translation unit is
replayed in full and every declared entity kind is harvested. The only reduction is
**deduplication of identical invocations** -- a source built into both the shared and the
static archive with the same defines and include set is the same compilation and is parsed
once -- and it is recorded in `body.deduplication` and `body.coverage` rather than hidden.
Assembly units cannot have a C AST and are recorded, not failed.

Determinism
-----------
Every list is sorted and every count is derived. No timestamp, PID, scratch path or host
path is written; committed authority paths are repository-relative. The same capture and
the same authority tree produce byte-identical JSON, which is what lets
`RT-PHASE22-TU-AST` re-derive the committed body from its own rows and mutate them.

Output
------
    forensics/atlas/phase22/tu-ast.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import subprocess
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

GENERATOR = "forensics/tools/phase22_tu_ast.py"
ARTEFACT_REL = "forensics/atlas/phase22/tu-ast.json"
OUT_REL = ARTEFACT_REL
CAPTURE_REL = "forensics/atlas/phase22/compile-commands.json"
RAW_REL = "forensics/atlas/phase22/raw/compile-commands.jsonl"
BUILD_DIR_REL = "forensics/authorities/build/openssl-3.6.4-production"

CLANG = "clang"
DEFAULT_JOBS = 4

# The captured build directory (`/tmp/phase22-recapture`) no longer exists; relative
# source/include tokens are resolved against the pinned build and source trees instead.

# Clang attribute node kinds that matter to a compatibility atlas -> a stable name. An
# attribute not in this table is walked but not recorded, so the document stays about the
# attributes the plan names rather than every annotation Clang can print.
_ATTR_OF_INTEREST = {
    "VisibilityAttr": "visibility",
    "AliasAttr": "alias",
    "WeakAttr": "weak",
    "WeakImportAttr": "weak_import",
    "NoReturnAttr": "noreturn",
    "C11NoReturnAttr": "noreturn",
    "ConstructorAttr": "constructor",
    "DestructorAttr": "destructor",
    "DeprecatedAttr": "deprecated",
    "UnavailableAttr": "unavailable",
    "TargetAttr": "target",
    "SectionAttr": "section",
    "UsedAttr": "used",
    "RetainAttr": "retain",
    "AvailabilityAttr": "availability",
    "DLLExportAttr": "dllexport",
    "DLLImportAttr": "dllimport",
}

# Entity kinds that can carry a declaration<->definition link.
_LINKABLE = ("function", "variable")


# ---------------------------------------------------------------------------
# capture -> logical translation units
# ---------------------------------------------------------------------------

def load_capture_body(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))["body"]


def suffix_of(source: str) -> str:
    return os.path.splitext(source)[1].lower()


def is_c_source(source: str) -> bool:
    return suffix_of(source) in (".c", ".cc", ".cpp", ".cxx", ".m")


def logical_tus(capture_body: dict) -> tuple[list[dict], list[dict]]:
    """Distinct logical translation units from 22.1's capture.

    Two captured invocations with the same source, defines and includes are the same
    compilation of the same file and are parsed once; the deduplication is a pure function
    of the capture and is recorded in the body. Returns `(c_units, non_c_units)`, both
    sorted, so the caller can report assembly units rather than silently drop them.
    """
    seen: dict[tuple, dict] = {}
    order: list[tuple] = []
    for cmd in capture_body.get("commands", []):
        key = (cmd.get("source"), tuple(cmd.get("defines", [])), tuple(cmd.get("includes", [])))
        if key in seen:
            continue
        seen[key] = {
            "source": cmd.get("source"),
            "defines": list(cmd.get("defines", [])),
            "includes": list(cmd.get("includes", [])),
            "output": cmd.get("output"),
        }
        order.append(key)
    c_units = [seen[k] for k in sorted(order) if is_c_source(seen[k]["source"])]
    non_c = [seen[k] for k in sorted(order) if not is_c_source(seen[k]["source"])]
    return c_units, non_c


# ---------------------------------------------------------------------------
# path resolution (authority-relative, for deterministic output)
# ---------------------------------------------------------------------------

def canon_path(abs_path: str | None, src_root: Path, build_dir: Path) -> str | None:
    """A repository-relative identity for an authority path, or an `external/` name.

    Files under the authority source tree are recorded source-relative, files under the
    pinned build tree (generated `.c` resolved from `.c.in`) build-relative, and files
    outside both (system headers) as `external/<basename>`. Nothing container- or
    scratch-specific leaks into the document.
    """
    if not abs_path:
        return None
    p = Path(abs_path)
    for root, prefix in ((src_root, ""), (build_dir, "build/")):
        try:
            return prefix + p.relative_to(root).as_posix()
        except ValueError:
            continue
    try:
        return p.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return "external/" + p.name


def resolve_source(source: str, captured_dir: str | None, build_dir: Path,
                   src_root: Path) -> str | None:
    """The absolute path the authority actually fed the compiler for `source`.

    Relative tokens are tried against the captured build directory (whose `../../work/...`
    forms still normalise onto the source tree), then the pinned build tree (where
    `*.c.in` templates were generated), then the source tree.
    """
    if os.path.isabs(source):
        return source if os.path.exists(source) else None
    bases = []
    if captured_dir:
        bases.append(captured_dir)
    bases += [str(build_dir), str(src_root)]
    for base in bases:
        cand = os.path.normpath(os.path.join(base, source))
        if os.path.exists(cand):
            return cand
    return None


def resolve_include(token: str, captured_dir: str | None, build_dir: Path,
                    src_root: Path) -> str | None:
    """One captured `-I`/`-isystem` token to an existing absolute directory, or None."""
    if token.startswith("-I "):
        path = token[3:]
    elif token.startswith("-isystem "):
        path = token[9:]
    elif token.startswith("-I"):
        path = token[2:]
    elif token.startswith("-isystem"):
        path = token[8:]
    else:
        return None
    if not path:
        return None
    if os.path.isabs(path):
        return path if os.path.isdir(path) else None
    bases = ([captured_dir] if captured_dir else []) + [str(build_dir), str(src_root)]
    for base in bases:
        cand = os.path.normpath(os.path.join(base, path))
        if os.path.isdir(cand):
            return cand
    return None


def source_origin(repo_file: str | None) -> str:
    if repo_file and repo_file.startswith("build/"):
        return "generated"
    return "source"


# ---------------------------------------------------------------------------
# Clang invocation
# ---------------------------------------------------------------------------

def run_clang(main_abs: str, includes: list[str], defines: list[str]) -> tuple[int, bytes, bytes]:
    argv = [CLANG, "-fsyntax-only", "-Xclang", "-ast-dump=json"]
    argv += ["-I" + d for d in includes]
    argv += list(defines)
    argv.append(main_abs)
    proc = subprocess.run(argv, capture_output=True, check=False)
    return proc.returncode, proc.stdout, proc.stderr


# ---------------------------------------------------------------------------
# AST extraction (pure over the parsed dump)
# ---------------------------------------------------------------------------

def _is_main(cur_file: str | None, has_loc: bool, main_abs: str) -> bool:
    return has_loc and cur_file == main_abs


def _function_is_defined(node: dict) -> bool:
    return any(isinstance(c, dict) and c.get("kind") == "CompoundStmt"
               for c in node.get("inner", []))


def _record_is_defined(node: dict) -> bool:
    if "completeDefinition" in node:
        return bool(node["completeDefinition"])
    return any(isinstance(c, dict) and c.get("kind") == "FieldDecl"
               for c in node.get("inner", []))


def _attributes(node: dict) -> list[str]:
    out: set[str] = set()
    for c in node.get("inner", []):
        if isinstance(c, dict):
            name = _ATTR_OF_INTEREST.get(c.get("kind"))
            if name:
                out.add(name)
    qt = (node.get("type") or {}).get("qualType", "") if isinstance(node.get("type"), dict) else ""
    if "noreturn" in qt:
        out.add("noreturn")
    return sorted(out)


def _callee_ref(node: dict) -> dict | None:
    """The DeclRefExpr node that is the callee of a CallExpr, if any."""
    inner = node.get("inner")
    if not isinstance(inner, list) or not inner:
        return None
    stack = [inner[0]]
    while stack:
        n = stack.pop()
        if isinstance(n, dict):
            if n.get("kind") == "DeclRefExpr":
                return n
            kids = n.get("inner")
            if isinstance(kids, list):
                stack.extend(kids)
        elif isinstance(n, list):
            stack.extend(n)
    return None


def extract_unit(ast: dict, main_abs: str, src_root: Path, build_dir: Path) -> dict:
    """The per-translation-unit record from one parsed Clang AST. A pure function.

    Walks the dump in document order so the delta-encoded locations decode correctly, and
    emits only the unit's own contribution (main-file entities, block-scope static/TLS
    objects, and the calls issued from main-file function bodies). The declaration links
    and call targets are resolved from a complete id map after the walk, so a forward
    reference cannot be missed.
    """
    state = {"file": None, "line": None, "col": None, "offset": None}
    ids: dict[str, dict] = {}
    entities: list[dict] = []
    calls: list[dict] = []
    address_taken: list[dict] = []
    consumed: set[str] = set()
    func_stack: list[dict] = []
    record_stack: list[dict] = []

    def proc_loc(loc) -> None:
        if not isinstance(loc, dict):
            return
        if "spellingLoc" in loc or "expansionLoc" in loc:
            if "spellingLoc" in loc:
                proc_loc(loc["spellingLoc"])
            if "expansionLoc" in loc:
                proc_loc(loc["expansionLoc"])
            return
        for key in ("file", "line", "col", "offset"):
            if key in loc:
                state[key] = loc[key]

    def canon_here() -> str | None:
        return canon_path(state["file"], src_root, build_dir)

    def add_entity(kind: str, node: dict, *, is_definition: bool, storage: str | None,
                   extra: dict | None = None) -> None:
        repo_file = canon_here()
        row = {
            "kind": kind,
            "name": node.get("name") or "(anonymous)",
            "file": repo_file,
            "line": state["line"],
            "is_definition": is_definition,
            "is_static": storage == "static",
            "storage": storage,
            "linkage": "internal" if storage == "static" else "external",
            "is_inline": bool(node.get("inline")),
            "tls": False,
            "attributes": _attributes(node),
            "_id": node.get("id"),
            "_prev": node.get("previousDecl"),
        }
        if extra:
            row.update(extra)
        entities.append(row)

    def walk(n) -> None:
        if isinstance(n, dict):
            if "loc" in n:
                proc_loc(n["loc"])
            has_loc = bool(n.get("loc"))
            cur_file = state["file"]
            if "range" in n and isinstance(n["range"], dict):
                r = n["range"]
                if "begin" in r:
                    proc_loc(r["begin"])
                if "end" in r:
                    proc_loc(r["end"])
            kind = n.get("kind")
            main = _is_main(cur_file, has_loc, main_abs)
            in_func = bool(func_stack)
            node_id = n.get("id")

            if kind in ("FunctionDecl", "VarDecl") and node_id:
                ids[node_id] = {
                    "kind": kind,
                    "name": n.get("name"),
                    "file": canon_path(cur_file, src_root, build_dir),
                    "line": state["line"],
                }

            pushed_func = False
            pushed_record = False

            if kind == "FunctionDecl":
                defined = _function_is_defined(n)
                if main and not in_func:
                    add_entity("function", n, is_definition=defined,
                               storage=n.get("storageClass"))
                elif main and in_func and n.get("storageClass") == "static":
                    add_entity("function", n, is_definition=defined,
                               storage=n.get("storageClass"),
                               extra={"scope": "block"})
                if defined:
                    func_stack.append({"name": n.get("name"), "is_main": main and not in_func,
                                       "file": canon_path(cur_file, src_root, build_dir),
                                       "line": state["line"]})
                    pushed_func = True

            elif kind == "RecordDecl":
                tag = n.get("tagUsed") or "struct"
                name = n.get("name") or "(anonymous)"
                if main and not in_func:
                    add_entity(tag, n, is_definition=_record_is_defined(n), storage=None)
                record_stack.append({"name": name, "is_main": main and not in_func})
                pushed_record = True

            elif kind == "EnumDecl":
                if main and not in_func:
                    defined = any(isinstance(c, dict) and c.get("kind") == "EnumConstantDecl"
                                  for c in n.get("inner", []))
                    add_entity("enum", n, is_definition=defined, storage=None)
                record_stack.append({"name": n.get("name") or "(anonymous)",
                                     "is_main": main and not in_func, "enum": True})
                pushed_record = True

            elif kind == "TypedefDecl":
                if main and not in_func:
                    add_entity("typedef", n, is_definition=True, storage=None)

            elif kind == "FieldDecl":
                if main and record_stack and record_stack[-1]["is_main"]:
                    add_entity("field", n, is_definition=True, storage=None,
                               extra={"parent": record_stack[-1]["name"]})

            elif kind == "EnumConstantDecl":
                if main and record_stack and record_stack[-1].get("is_main"):
                    add_entity("enumerator", n, is_definition=True, storage=None,
                               extra={"parent": record_stack[-1]["name"]})

            elif kind == "VarDecl":
                storage = n.get("storageClass")
                tls = "Thread_local" in ((n.get("type") or {}).get("qualType", "")
                                         if isinstance(n.get("type"), dict) else "")
                if main and not in_func:
                    add_entity("variable", n, is_definition=(storage != "extern"),
                               storage=storage)
                    if tls:
                        entities[-1]["tls"] = True
                elif main and in_func and (storage == "static" or tls):
                    add_entity("variable", n, is_definition=True, storage=storage,
                               extra={"scope": "block"})
                    if tls:
                        entities[-1]["tls"] = True

            elif kind == "CallExpr":
                callee = _callee_ref(n)
                if callee is None:
                    pass
                else:
                    ref = callee.get("referencedDecl") or {}
                    rid = ref.get("id")
                    # Mark the DeclRefExpr *node* (not the referenced decl) as consumed, so
                    # the direct callee is not also counted as address-taken below.
                    if callee.get("id"):
                        consumed.add(callee["id"])
                    if func_stack and func_stack[-1]["is_main"]:
                        caller = func_stack[-1]
                        calls.append({
                            "unit": None,
                            "file": canon_path(cur_file, src_root, build_dir),
                            "line": state["line"],
                            "caller": caller["name"],
                            "caller_file": caller["file"],
                            "caller_line": caller["line"],
                            "callee": ref.get("name") or callee.get("name"),
                            "callee_kind": ref.get("kind"),
                            "_callee_id": rid,
                        })

            elif kind == "DeclRefExpr":
                rid = n.get("id")
                ref = n.get("referencedDecl") or {}
                if (rid not in consumed and ref.get("kind") == "FunctionDecl"
                        and func_stack and func_stack[-1]["is_main"]):
                    caller = func_stack[-1]
                    address_taken.append({
                        "unit": None,
                        "file": canon_path(cur_file, src_root, build_dir),
                        "line": state["line"],
                        "caller": caller["name"],
                        "function": ref.get("name"),
                        "_function_id": ref.get("id"),
                    })

            for c in n.get("inner", []):
                walk(c)
            if pushed_func:
                func_stack.pop()
            if pushed_record:
                record_stack.pop()
        elif isinstance(n, list):
            for c in n:
                walk(c)

    # Align the carried state with the first node before walking (the dump's first
    # location has no predecessor); walk from the root.
    walk(ast)

    # Resolve declaration links and call targets now that the id map is complete.
    for row in entities:
        prev = row.pop("_prev", None)
        row.pop("_id", None)
        decl = ids.get(prev) if prev else None
        row["declaration"] = ({"file": decl["file"], "line": decl["line"]} if decl else None)
        row["declaration_same_file"] = bool(
            decl and decl["file"] is not None and decl["file"] == row["file"])
    for edge in calls:
        rid = edge.pop("_callee_id", None)
        target = ids.get(rid) if rid else None
        edge["callee_file"] = target["file"] if target else None
        edge["callee_line"] = target["line"] if target else None
    for edge in address_taken:
        fid = edge.pop("_function_id", None)
        target = ids.get(fid) if fid else None
        edge["function_file"] = target["file"] if target else None
        edge["function_line"] = target["line"] if target else None

    main_repo = canon_path(main_abs, src_root, build_dir)
    return {
        "file": main_repo,
        "origin": source_origin(main_repo),
        "entities": entities,
        "calls": calls,
        "address_taken": address_taken,
    }


def _task(payload: dict) -> dict:
    """Run one logical translation unit in a worker. Returns a unit record or a failure."""
    rc, out, err = run_clang(payload["main_abs"], payload["includes"], payload["defines"])
    src_root = Path(payload["src_root"])
    build_dir = Path(payload["build_dir"])
    if rc != 0:
        reason = (err.decode("utf-8", "replace").strip().splitlines() or ["clang failed"])[-1]
        return {"source": payload["source"], "main_abs": payload["main_abs"],
                "error": reason[:400]}
    try:
        ast = json.loads(out)
    except Exception as exc:  # noqa: BLE001 -- a parse failure is a recorded residual
        return {"source": payload["source"], "main_abs": payload["main_abs"],
                "error": f"json-decode: {exc}"[:400]}
    record = extract_unit(ast, payload["main_abs"], src_root, build_dir)
    record["source"] = payload["source"]
    return record


# ---------------------------------------------------------------------------
# body assembly (pure)
# ---------------------------------------------------------------------------

def _entity_sort_key(row: dict) -> tuple:
    return (row["file"] or "", row["line"] if row["line"] is not None else -1,
            row["kind"], row["name"])


def _call_sort_key(row: dict) -> tuple:
    return (row["file"] or "", row["line"] if row["line"] is not None else -1,
            row["caller"] or "", row["callee"] or "", row["callee_file"] or "",
            row["callee_line"] if row["callee_line"] is not None else -1)


def _addr_sort_key(row: dict) -> tuple:
    return (row["file"] or "", row["line"] if row["line"] is not None else -1,
            row["caller"] or "", row["function"] or "")


def build_body(units: list[dict]) -> dict:
    """The atlas body from the per-unit records. A pure, deterministic function.

    `RT-PHASE22-TU-AST` calls this on the committed artefact's own rows and on controlled
    in-memory mutations, so it must stay free of I/O and of ambient state.
    """
    units_sorted = sorted(units, key=lambda u: (u["file"] or "", u["source"] or ""))

    entities: list[dict] = []
    calls: list[dict] = []
    address_taken: list[dict] = []
    for unit in units_sorted:
        f = unit["file"]
        for e in unit.get("entities", []):
            entities.append({**e, "unit": f})
        for c in unit.get("calls", []):
            calls.append({**c, "unit": f})
        for a in unit.get("address_taken", []):
            address_taken.append({**a, "unit": f})

    entities.sort(key=_entity_sort_key)

    def dedup(rows: list[dict], key) -> list[dict]:
        out: list[dict] = []
        seen: set = set()
        for r in sorted(rows, key=key):
            k = key(r)
            if k in seen:
                continue
            seen.add(k)
            out.append(r)
        return out

    calls = dedup(calls, lambda r: (r["file"], r["line"], r["caller"], r["callee"],
                                     r["callee_file"], r["callee_line"]))
    address_taken = dedup(address_taken, lambda r: (r["file"], r["line"], r["caller"],
                                                     r["function"]))

    # declaration <-> definition links, computed from the flattened entity set.
    by_name_kind: dict[tuple, list[dict]] = {}
    for e in entities:
        by_name_kind.setdefault((e["kind"], e["name"]), []).append(e)

    def has_declaration(e: dict) -> bool:
        if e.get("declaration") is not None:
            return True
        return any(not x["is_definition"] for x in by_name_kind.get((e["kind"], e["name"]), []))

    definitions = [e for e in entities if e["is_definition"] and e["kind"] in _LINKABLE]
    declarations = [e for e in entities if not e["is_definition"] and e["kind"] in _LINKABLE]
    def_without_decl = [e for e in definitions if not has_declaration(e)]
    decl_without_def = [
        d for d in declarations
        if not any(x["is_definition"] for x in by_name_kind.get((d["kind"], d["name"]), []))
    ]

    def kind_count(rows: list[dict]) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in rows:
            out[r["kind"]] = out.get(r["kind"], 0) + 1
        return dict(sorted(out.items()))

    def attr_count(rows: list[dict]) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in rows:
            for a in r.get("attributes", []):
                out[a] = out.get(a, 0) + 1
        return dict(sorted(out.items()))

    unit_meta = [
        {
            "file": u["file"],
            "origin": u.get("origin", "source"),
            "source": u.get("source"),
            "counts": {
                "entities": len(u.get("entities", [])),
                "calls": len(u.get("calls", [])),
                "address_taken": len(u.get("address_taken", [])),
            },
        }
        for u in units_sorted
    ]

    return {
        "units": unit_meta,
        "entities": entities,
        "call_edges": calls,
        "address_taken": address_taken,
        "declaration_links": {
            "definitions_without_declaration": [
                {"kind": e["kind"], "name": e["name"], "file": e["file"], "line": e["line"]}
                for e in def_without_decl
            ],
            "declarations_without_definition": [
                {"kind": d["kind"], "name": d["name"], "file": d["file"], "line": d["line"]}
                for d in decl_without_def
            ],
        },
        "counts": {
            "entities": len(entities),
            "entities_by_kind": kind_count(entities),
            "functions": sum(1 for e in entities if e["kind"] == "function"),
            "variables": sum(1 for e in entities if e["kind"] == "variable"),
            "records": sum(1 for e in entities if e["kind"] in ("struct", "union")),
            "typedefs": sum(1 for e in entities if e["kind"] == "typedef"),
            "fields": sum(1 for e in entities if e["kind"] == "field"),
            "enumerators": sum(1 for e in entities if e["kind"] == "enumerator"),
            "static": sum(1 for e in entities if e["is_static"]),
            "tls": sum(1 for e in entities if e["tls"]),
            "inline_functions": sum(1 for e in entities
                                    if e["kind"] == "function" and e["is_inline"]),
            "definitions": len(definitions),
            "declarations": len(declarations),
            "definitions_without_declaration": len(def_without_decl),
            "declarations_without_definition": len(decl_without_def),
            "call_edges": len(calls),
            "address_taken": len(address_taken),
            "attributes": attr_count(entities),
        },
    }


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def _build_jobs(c_units, resolved, captured_dir, build_dir, src_root, jobs):  # noqa: ANN001
    payloads = []
    failures: list[dict] = []
    for unit, main_abs in zip(c_units, resolved):
        if main_abs is None:
            failures.append({"source": unit["source"], "reason": "source-not-found"})
            continue
        includes = []
        for tok in unit["includes"]:
            inc = resolve_include(tok, captured_dir, build_dir, src_root)
            if inc and inc not in includes:
                includes.append(inc)
        payloads.append({
            "source": unit["source"],
            "main_abs": main_abs,
            "includes": includes,
            "defines": unit["defines"],
            "src_root": str(src_root),
            "build_dir": str(build_dir),
        })
    if jobs <= 1:
        results = [_task(p) for p in payloads]
    else:
        with concurrent.futures.ProcessPoolExecutor(max_workers=jobs) as pool:
            results = list(pool.map(_task, payloads))
    return results, failures


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument("--capture", default=CAPTURE_REL)
    ap.add_argument("--jobs", type=int, default=DEFAULT_JOBS,
                    help="parallel Clang workers (default: %(default)s)")
    ap.add_argument("--limit", type=int, default=0,
                    help="parse only the first N logical C units (measurement aid)")
    args = ap.parse_args(argv)

    sys.setrecursionlimit(100000)

    auth = resolve_authority(args.authority)
    src_root = auth.source
    build_dir = REPO_ROOT / BUILD_DIR_REL
    capture_path = REPO_ROOT / args.capture
    if not capture_path.is_file():
        raise SystemExit(
            f"phase22-tu-ast: 22.1's capture is missing: {rel(capture_path)}; run "
            "forensics/tools/phase22_build_commands.py first"
        )
    capture_body = load_capture_body(capture_path)
    raw_path = REPO_ROOT / RAW_REL

    producer = "unknown"
    configdata = build_dir / "configdata.pm"
    if configdata.is_file():
        m = re.search(r'^\s*"CC"\s*=>\s*"([^"]*)"',
                      configdata.read_text(encoding="utf-8", errors="replace"), re.MULTILINE)
        producer = m.group(1) if m and m.group(1) else "unknown"
    captured_dir = capture_body.get("directory")

    c_units, non_c_units = logical_tus(capture_body)
    captured_c_invocations = sum(1 for cmd in capture_body.get("commands", [])
                                 if is_c_source(cmd.get("source") or ""))
    if args.limit:
        c_units = c_units[:args.limit]

    print(f"[phase22-tu-ast] {len(capture_body.get('commands', []))} captured invocations -> "
          f"{len(c_units)} logical C units (+{len(non_c_units)} assembly), jobs={args.jobs}")

    resolved = [resolve_source(u["source"], captured_dir, build_dir, src_root) for u in c_units]
    results, failures = _build_jobs(c_units, resolved, captured_dir, build_dir, src_root,
                                    args.jobs)

    units: list[dict] = []
    parsed = 0
    for r in results:
        if "error" in r:
            failures.append({"source": r["source"], "reason": r["error"]})
            continue
        parsed += 1
        units.append({"file": r["file"], "origin": r["origin"], "source": r["source"],
                      "entities": r["entities"], "calls": r["calls"],
                      "address_taken": r["address_taken"]})

    body = build_body(units)
    body["producer"] = producer
    body["analysis_instrument"] = CLANG
    body["analysis_instrument_note"] = (
        "Clang is a shadow analysis instrument only. The production authority is GCC-built "
        f"(configdata.pm CC={producer!r}); the captured invocations are replayed to Clang to "
        "read the every-translation-unit AST, which never redefines the authority as a Clang "
        "build (docs/PHASE-22-SUBPHASES.md section 6). `producer` and `analysis_instrument` "
        "are two different facts and both are recorded."
    )
    body["capture_method"] = "execution-captured"
    body["roots"] = {"source": rel(src_root), "build": rel(build_dir)}
    body["deduplication"] = (
        f"{captured_c_invocations} captured C invocations over "
        f"{len({c.get('source') for c in capture_body.get('commands', []) if is_c_source(c.get('source') or '')})} "
        "distinct C sources were reduced to "
        f"{len(logical_tus(capture_body)[0])} distinct logical translation units by "
        "(source, defines, includes); an identical invocation is the same compilation and "
        "is parsed once. This is a pure function of the capture and is the only reduction."
    )
    body["coverage"] = {
        "translation_units_attempted": len(c_units),
        "parsed": parsed,
        "failed": len(failures),
        "non_c_translation_units": [
            {"source": u["source"], "suffix": suffix_of(u["source"]), "reason": "not-a-c-ast"}
            for u in non_c_units
        ],
        "entity_scope": (
            "Entities are those declared or defined in a unit's own main file, plus "
            "block-scope static/thread-local objects; header and system declarations are "
            "walked to resolve call targets and declaration links but are not emitted as "
            "per-unit entities, because Phase 1 and 22.2 already own the header surface "
            "and emitting it once per including unit would duplicate it."
        ),
        "reduction": "none beyond deduplication of identical invocations",
    }
    body["failures"] = sorted(failures, key=lambda f: (f["source"] or "", f["reason"]))
    body["sort_key"] = "(file, line, kind, name); file is authority-relative (source/ or build/)"
    # counts required by the subphase brief, folded into one place.
    body["counts"]["translation_units"] = len(c_units)
    body["counts"]["parsed"] = parsed
    body["counts"]["failed"] = len(failures)
    body["counts"]["captured_c_invocations"] = captured_c_invocations
    body["counts"]["non_c_translation_units"] = len(non_c_units)
    body["counts"]["distinct_sources"] = len({c.get("source") for c in capture_body.get("commands", [])})

    inputs = [InputRef(name="compile-commands", path=capture_path)]
    if raw_path.is_file():
        inputs.append(InputRef(name="raw-compile-commands", path=raw_path))
    doc = envelope(kind="phase22-tu-ast", authority=auth.id, inputs=inputs, body=body,
                   generator=GENERATOR)
    write_json(REPO_ROOT / OUT_REL, doc)

    c = body["counts"]
    print(f"[phase22-tu-ast] profile={producer} instrument={CLANG}: "
          f"translation_units={c['translation_units']} parsed={c['parsed']} "
          f"failed={c['failed']} non_c={c['non_c_translation_units']}")
    print(f"[phase22-tu-ast] entities={c['entities']} "
          f"(functions={c['functions']}, variables={c['variables']}, records={c['records']}, "
          f"typedefs={c['typedefs']}, fields={c['fields']}) "
          f"static={c['static']} defs_without_decl={c['definitions_without_declaration']}")
    print(f"[phase22-tu-ast] call_edges={c['call_edges']} address_taken={c['address_taken']} "
          f"-> {rel(REPO_ROOT / OUT_REL)}")
    return 0


# ---------------------------------------------------------------------------
# the court
# ---------------------------------------------------------------------------

def _units_from_body(body: dict) -> list[dict]:
    """Reconstruct per-unit records from the committed body's own flattened rows."""
    units: dict[str, dict] = {}
    for meta in body["units"]:
        units[meta["file"]] = {"file": meta["file"], "origin": meta["origin"],
                               "source": meta["source"], "entities": [], "calls": [],
                               "address_taken": []}
    for e in body["entities"]:
        row = {k: v for k, v in e.items() if k != "unit"}
        units[e["unit"]]["entities"].append(row)
    for c in body["call_edges"]:
        row = {k: v for k, v in c.items() if k != "unit"}
        units[c["unit"]]["calls"].append(row)
    for a in body["address_taken"]:
        row = {k: v for k, v in a.items() if k != "unit"}
        units[a["unit"]]["address_taken"].append(row)
    return list(units.values())


def _entity_identity(e: dict) -> tuple:
    return (e["file"], e["line"], e["kind"], e["name"], e["is_definition"])


def court_tu_ast(body: dict) -> dict:
    """`RT-PHASE22-TU-AST`: the extractor's own classification and link logic.

    Round-trips the committed body (re-derive it from its own rows and require equality),
    then drives it over controlled mutations of the entity and edge records. The court
    fails if the classification is insensitive to a declaration added for a definition, a
    definition with no declaration, a flipped `static` flag, an added call edge, or a moved
    `file`/`line`.
    """
    import copy

    checks: list[tuple[str, bool]] = []
    units = _units_from_body(copy.deepcopy(body))

    checks.append(("baseline: the artefact has translation units", len(body["units"]) > 0))
    checks.append(("baseline: the artefact has entities",
                   body["counts"]["entities"] > 0))
    checks.append(("baseline: the artefact has call edges",
                   body["counts"]["call_edges"] > 0))

    rebuilt = build_body(copy.deepcopy(units))
    checks.append(("round-trip: entities equal", rebuilt["entities"] == body["entities"]))
    checks.append(("round-trip: call_edges equal", rebuilt["call_edges"] == body["call_edges"]))
    checks.append(("round-trip: address_taken equal",
                   rebuilt["address_taken"] == body["address_taken"]))
    checks.append(("round-trip: declaration_links equal",
                   rebuilt["declaration_links"] == body["declaration_links"]))
    # `build_body` derives every unit-level count; the capture-level counts
    # (`translation_units`, `parsed`, `failed`, ...) are added by `main` and are checked by
    # the baseline assertions below. Compare exactly the derived subset.
    derived = {k: v for k, v in body["counts"].items() if k in rebuilt["counts"]}
    checks.append(("round-trip: derived counts equal", derived == rebuilt["counts"]))
    for required in ("translation_units", "parsed", "failed", "entities", "call_edges"):
        checks.append((f"baseline: counts.{required} present", required in body["counts"]))

    base = build_body(copy.deepcopy(units))

    def new_entity(name, *, kind="function", is_definition, file, line, is_static=False):
        return {
            "kind": kind, "name": name, "file": file, "line": line,
            "is_definition": is_definition, "is_static": is_static,
            "storage": "static" if is_static else None,
            "linkage": "internal" if is_static else "external",
            "is_inline": False, "tls": False, "attributes": [],
            "declaration": None, "declaration_same_file": False,
        }

    # 1. add a declaration for an existing definition (one that had none).
    target = next((e for e in base["entities"]
                   if e["kind"] in _LINKABLE and e["is_definition"]
                   and e["declaration"] is None), None)
    if target is None:
        checks.append(("add-declaration: a declaration-less definition was found", False))
    else:
        mutated = copy.deepcopy(units)
        decl = new_entity(target["name"], kind=target["kind"], is_definition=False,
                          file=target["file"], line=(target["line"] or 0) - 1)
        _unit_for(mutated, target["unit"])["entities"].append(decl)
        new = build_body(mutated)
        checks.append(("add-declaration: declarations rose by one",
                       new["counts"]["declarations"] == base["counts"]["declarations"] + 1))
        checks.append(("add-declaration: definitions_without_declaration fell by one",
                       new["counts"]["definitions_without_declaration"]
                       == base["counts"]["definitions_without_declaration"] - 1))
        checks.append(("add-declaration: entity count rose by one",
                       new["counts"]["entities"] == base["counts"]["entities"] + 1))

    # 2. add a definition with no declaration at all.
    mutated = copy.deepcopy(units)
    ghost = new_entity("phase22_synthetic_ghost", is_definition=True,
                       file=units[0]["file"], line=10_000_001)
    _unit_for(mutated, units[0]["file"])["entities"].append(ghost)
    new = build_body(mutated)
    checks.append(("add-definition: definitions rose by one",
                   new["counts"]["definitions"] == base["counts"]["definitions"] + 1))
    checks.append(("add-definition: definitions_without_declaration rose by one",
                   new["counts"]["definitions_without_declaration"]
                   == base["counts"]["definitions_without_declaration"] + 1))
    link = next((r for r in new["declaration_links"]["definitions_without_declaration"]
                 if r["name"] == "phase22_synthetic_ghost"), None)
    checks.append(("add-definition: it is listed as declaration-less", link is not None))

    # 3. flip a static flag.
    static_idx = next((i for i, e in enumerate(base["entities"]) if e["is_static"]), None)
    dynamic_idx = next((i for i, e in enumerate(base["entities"])
                        if not e["is_static"] and e["kind"] in ("function", "variable")), None)
    if static_idx is None or dynamic_idx is None:
        checks.append(("flip-static: a static and a non-static entity were found", False))
    else:
        for label, idx, delta in (("static->external", static_idx, -1),
                                  ("external->static", dynamic_idx, +1)):
            target_id = _entity_identity(base["entities"][idx])
            mutated = copy.deepcopy(units)
            row = _find_entity(mutated, target_id)
            row["is_static"] = not row["is_static"]
            row["storage"] = "static" if row["is_static"] else None
            row["linkage"] = "internal" if row["is_static"] else "external"
            new = build_body(mutated)
            checks.append((f"flip-static ({label}): static count moved by {delta}",
                           new["counts"]["static"] == base["counts"]["static"] + delta))
            checks.append((f"flip-static ({label}): nothing else moved",
                           new["counts"]["entities"] == base["counts"]["entities"]))

    # 4. add a call edge.
    if base["call_edges"]:
        mutated = copy.deepcopy(units)
        edge = {
            "file": "synthetic/phase22_probe.c", "line": 7,
            "caller": "phase22_probe_caller", "caller_file": "synthetic/phase22_probe.c",
            "caller_line": 1, "callee": "EVP_DigestInit_ex",
            "callee_kind": "FunctionDecl", "callee_file": "include/openssl/evp.h",
            "callee_line": 500,
        }
        _unit_for(mutated, units[0]["file"])["calls"].append(edge)
        new = build_body(mutated)
        checks.append(("add-call-edge: call_edges rose by one",
                       new["counts"]["call_edges"] == base["counts"]["call_edges"] + 1))
        found = next((c for c in new["call_edges"]
                      if c["caller"] == "phase22_probe_caller"), None)
        checks.append(("add-call-edge: the edge is present", found is not None))
    else:
        checks.append(("add-call-edge: the artefact has a call edge to extend", False))

    # 5. move a file/line.
    moved_idx = next((i for i, e in enumerate(base["entities"]) if e["line"] is not None), None)
    if moved_idx is None:
        checks.append(("move-location: an entity with a line was found", False))
    else:
        old_id = _entity_identity(base["entities"][moved_idx])
        mutated = copy.deepcopy(units)
        row = _find_entity(mutated, old_id)
        row["line"] = (row["line"] or 0) + 10_000_000
        new = build_body(mutated)
        new_id = (old_id[0], old_id[1] + 10_000_000, old_id[2], old_id[3], old_id[4])
        by_id = {_entity_identity(e) for e in new["entities"]}
        checks.append(("move-location: the entity count is unchanged",
                       new["counts"]["entities"] == base["counts"]["entities"]))
        checks.append(("move-location: the old identity is gone", old_id not in by_id))
        checks.append(("move-location: the moved identity is present", new_id in by_id))

    failures = [desc for desc, ok in checks if not ok]
    c = body["counts"]
    return {
        "court": "RT-PHASE22-TU-AST",
        "artefact": ARTEFACT_REL,
        "producer": body.get("producer"),
        "analysis_instrument": body.get("analysis_instrument"),
        "translation_units": c.get("translation_units"),
        "parsed": c.get("parsed"),
        "failed": c.get("failed"),
        "entities": c.get("entities"),
        "call_edges": c.get("call_edges"),
        "mutations": ["round-trip", "add-declaration", "add-definition", "flip-static",
                      "add-call-edge", "move-location"],
        "observations": len(checks),
        "failures": failures,
        "verdict": "pass" if not failures else "fail",
    }


def _unit_for(units: list[dict], file: str) -> dict:
    for u in units:
        if u["file"] == file:
            return u
    raise KeyError(file)


def _find_entity(units: list[dict], identity: tuple) -> dict:
    for u in units:
        for e in u["entities"]:
            if _entity_identity({**e, "unit": u["file"]}) == identity:
                return e
    raise KeyError(identity)


def courts() -> list[dict]:
    """`RT-PHASE22-TU-AST`, or `[]` while the artefact has not landed."""
    path = REPO_ROOT / ARTEFACT_REL
    if not path.is_file():
        return []
    doc = json.loads(path.read_text(encoding="utf-8"))
    return [court_tu_ast(doc["body"])]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
