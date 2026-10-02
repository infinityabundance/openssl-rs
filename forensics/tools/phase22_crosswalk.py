#!/usr/bin/env python3
"""openssl-rs -- Phase 22.13 test / demo / fuzz semantic crosswalk.

`docs/PHASE-22-SUBPHASES.md` section 5 gives this plane its artefact and its question.
22.13 produces `test-crosswalk.json`, and the question it answers is the one the plan
names for the closed stratum: *which authority functionality does every test, demo and
fuzz target actually touch?* It is the `TESTED_BY` / `FUZZED_BY` half of the typed edge
graph of section 3, taken over the authority's own `test/`, `fuzz/` and `demos/` corpora.

What is built
-------------
For every test / fuzz / demo *source* the tool records

  * `path` and `kind` (`test` / `fuzz` / `demo`);
  * the authority symbols it **calls** and the authority symbols it merely
    **references** (address-taken functions and globals: the `ADDRESS_TAKEN` shape that
    has no call site anywhere in the source);
  * whether it **links the authority** or **drives `openssl` as a subprocess** -- a C
    test/fuzz/demo is linked against `libcrypto`/`libssl`, a recipe runs the `openssl`
    binary -- both recorded rather than assumed;
  * the fixture / data files it names.

Each edge carries the **method** that produced it: `clang-ast` for a C source read with
`clang -fsyntax-only -Xclang -ast-dump=json`, `lexical` for the fallback token scan used
when a C source cannot be parsed and for every `openssl` CLI invocation found in a test
script. A method is a fact about how an edge was obtained and is never inferred.

The symbol universe
-------------------
A referenced name is an *authority* symbol only if it is in the Phase-1 atlas's own
universe for the admitted authority: the public declarations (`functions.json`,
`variables.json`), the dynamic exports of the two shared objects
(`symbols-libcrypto.json`, `symbols-libssl.json`, where `dso.present` is true) and the
internal symbols (`internal-symbols.json`). A name that is also defined by the corpus
itself is rejected by resolving the reference's declaration to a file and requiring that
file to be an authority file (`include/`, `crypto/`, `ssl/`, `providers/`, `apps/`,
`engines/`, or the pinned build tree) -- never a `test/`, `fuzz/` or `demos/` file. This
is what stops a test's own static helper from being counted as authority surface.

Why the extraction method is what it is
---------------------------------------
The production authority profile is `...-notests`, so 22.1's execution-captured
invocations do **not** contain a single test, fuzz or demo translation unit; there is no
authority-recorded compile command to replay for them. The C sources are therefore parsed
with Clang as a *shadow analysis instrument* over a minimal, explicitly-listed include set
(recorded in `body.instrument.include_dirs` and `body.instrument.defines`), not over the
authority's own flags -- and a source Clang cannot parse is recorded as `lexical`, not
dropped. The `openssl` CLI invocations inside `test/recipes/*.t`, `test/*.pl` and
`test/*.sh` are found with a lexical pass, because a recipe is a program *about* running
the CLI and has no C AST.

Inverse queries
---------------
The plan asks for the inverse directions as well, and they are emitted as explicit lists
in the body rather than left to a consumer to recompute:

  * `untested_exported_symbols` -- exported authority symbols no `test` or `fuzz` source
    reaches (`demo` and subprocess-only reachability do not count);
  * `public_apis_without_test_edges` -- the same over the Phase-1 public declarations;
  * `targets_with_no_edges` -- sources that touch no authority symbol and invoke no CLI
    command, with `test_fuzz_targets_with_no_symbol_edges` (the plan's literal inverse
    query) and its C-only slice `c_targets_with_no_symbol_edges`;
  * `fuzz_targets_attacking_parser_surfaces` and its complement -- the fuzzers whose
    symbols are decode/parse surfaces (`d2i_`, `_it`, `_decode`, `_parse`, `ASN1_`,
    `PEM_read`, `OSSL_DECODER`, ...).

Determinism
-----------
Every list is sorted, every count derived from the lists, nothing carries a timestamp,
PID, scratch or host path. `build_body` is a pure function of the per-source rows and the
two symbol universes, which is what lets `RT-PHASE22-CROSSWALK` re-derive the committed
body from its own rows and mutate them in memory.

Output
------
    forensics/atlas/phase22/test-crosswalk.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
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

GENERATOR = "forensics/tools/phase22_crosswalk.py"
ARTEFACT_REL = "forensics/atlas/phase22/test-crosswalk.json"
OUT_REL = ARTEFACT_REL
BUILD_DIR_REL = "forensics/authorities/build/openssl-3.6.4-production"

CLANG = "clang"
DEFAULT_JOBS = 4

CORPUS_ROOTS = ("test", "fuzz", "demos")
C_SUFFIXES = (".c", ".cc", ".cpp", ".cxx")
SCRIPT_SUFFIXES = (".t", ".pl", ".sh")

# Include roots handed to the shadow Clang parse. Only those that exist are used; the
# ordered list that was actually passed is written into the body.
INCLUDE_CANDIDATES = (
    "build/include",
    "include",
    ".",
    "test/testutil",
    "apps/include",
    "providers/common/include",
    "providers/implementations/include",
    "providers/fips/include",
    "include/crypto",
    "include/internal",
    "crypto/bn",
    "crypto",
    "ssl",
)
CLANG_DEFINES = ("-D_GNU_SOURCE",)

# A referenced declaration in one of these top-level areas is authority surface. A
# declaration anywhere under the corpus roots is the corpus's own and is not.
_AUTHORITY_AREAS = ("include/", "crypto/", "ssl/", "providers/", "apps/", "engines/",
                    "build/")
_CORPUS_AREAS = ("test/", "fuzz/", "demos/")

# Symbol-name shapes that mark a fuzz target as attacking a *parser* surface. The `_it`
# suffix is the ASN.1 item table, which is what `ASN1_ITEM_ref(TYPE)` expands to and is
# the strongest single signal that a target feeds a decoder.
_PARSER_RE = re.compile(
    r"(^d2i_|^i2d_|^ASN1_|^OSSL_DECODER|^OSSL_ENCODER|^PEM_read|^PEM_write|"
    r"^EVP_Decode|^EVP_Encode|_it$|_parse$|_decode$|_fromdata$)"
)

# Fixture-looking filenames named by a source, by extension. The set is the corpus's own
# data extensions rather than a general path matcher, so a stray string such as "list"
# is not mistaken for a file.
_FIXTURE_RE = re.compile(
    r"^[A-Za-z0-9_./+-]+\.("
    r"pem|der|cnf|txt|crt|key|p12|csr|sct|bin|dat|in|inc|out|json|xml|msb|ors|csv|eml|"
    r"p7b|p7c|srl|rnd|hex|sig|signed|req|kdb|asn1|asn|apk|old|gz|b64)$",
    re.IGNORECASE,
)

_C_STR = re.compile(r'"((?:[^"\\]|\\.)*)"')
_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\'')
_APP_CALL = re.compile(r"\bapp\s*\(([^()]*)\)")
_OPENSSL_WORD = re.compile(r"(?<![\w./-])openssl(?![\w-])")
_BARE = re.compile(r"\$?[A-Za-z0-9_./:-]+")
_C_COMMENT_BLOCK = re.compile(r"/\*.*?\*/", re.DOTALL)
_C_COMMENT_LINE = re.compile(r"//[^\n]*")


# ---------------------------------------------------------------------------
# path canonicalisation (authority-relative, deterministic)
# ---------------------------------------------------------------------------

def canon_path(abs_path: str | None, src_root: Path, build_dir: Path) -> str | None:
    """A repository-authority-relative identity for a path, or an `external/` name.

    Files under the admitted source tree are source-relative, files under the pinned
    build tree are `build/`-prefixed, and anything else (a system header) is
    `external/<basename>`. No container path leaks into the document.
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


def is_authority_file(repo_file: str | None) -> bool:
    if not repo_file:
        return False
    if repo_file.startswith(_CORPUS_AREAS):
        return False
    return repo_file.startswith(_AUTHORITY_AREAS)


# ---------------------------------------------------------------------------
# symbol universe (from the Phase-1 atlas of the admitted authority)
# ---------------------------------------------------------------------------

def _atlas_dir(authority_id: str) -> Path:
    return REPO_ROOT / "forensics" / "atlas" / authority_id


def _phase22_dir() -> Path:
    return REPO_ROOT / "forensics" / "atlas" / "phase22"


def _records(path: Path) -> list[dict]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    return doc["body"]["records"]


def load_universe(authority_id: str) -> dict:
    """The authority symbol universe, its categories, and the two inverse query sets.

    Read from the Phase-1 atlas, not reconstructed here: the public declarations, the two
    shared objects' dynamic exports and the internal symbols. `exported` is the DSO
    export table (the literal reading of "exported authority APIs"); `public` is the
    Phase-1 public declaration set.
    """
    atlas = _atlas_dir(authority_id)
    categories: dict[str, set[str]] = {}
    declared_in: dict[str, str] = {}

    def add(name: str, cat: str, header: str | None = None) -> None:
        if not name:
            return
        categories.setdefault(name, set()).add(cat)
        if header and name not in declared_in:
            declared_in[name] = header

    for rec in _records(atlas / "functions.json"):
        add(rec["name"], "public-function", rec.get("header"))
    for rec in _records(atlas / "variables.json"):
        add(rec["name"], "public-variable", rec.get("header"))
    for rec in _records(atlas / "typedefs.json"):
        add(rec["name"], "public-typedef", rec.get("header"))

    exported: set[str] = set()
    for kind in ("libcrypto", "libssl"):
        for rec in _records(atlas / f"symbols-{kind}.json"):
            if rec.get("dso", {}).get("present"):
                add(rec["symbol"], "exported")
                exported.add(rec["symbol"])

    for rec in _records(REPO_ROOT / "forensics" / "atlas" / "internal-symbols.json"):
        declared = rec.get("declared_in") or []
        add(rec["symbol"], "internal", declared[0] if declared else None)

    public = {n for n, cats in categories.items()
              if "public-function" in cats or "public-variable" in cats}
    return {
        "names": frozenset(categories),
        "categories": {n: sorted(c) for n, c in categories.items()},
        "declared_in": declared_in,
        "exported": sorted(exported),
        "public": sorted(public),
    }


# ---------------------------------------------------------------------------
# corpus enumeration
# ---------------------------------------------------------------------------

def enumerate_corpus(src_root: Path) -> tuple[list[dict], dict]:
    """Every test/fuzz/demo source, plus a coverage census of the roots.

    A source is a C/C++ translation unit or a shell/perl test script. Everything else
    under the roots (fixtures, headers, build.info, corpora) is counted as data and is
    not a target, because it has no code to extract an edge from.
    """
    targets: list[dict] = []
    census: dict[str, int] = {}
    for root in CORPUS_ROOTS:
        base = src_root / root
        total = 0
        if base.is_dir():
            for path in sorted(base.rglob("*")):
                if not path.is_file():
                    continue
                total += 1
                suffix = path.suffix.lower()
                relpath = path.relative_to(src_root).as_posix()
                if suffix in C_SUFFIXES:
                    targets.append({"path": relpath, "kind": _kind_of(relpath),
                                    "form": "c", "abs": str(path)})
                elif suffix in SCRIPT_SUFFIXES:
                    targets.append({"path": relpath, "kind": _kind_of(relpath),
                                    "form": "script", "abs": str(path)})
        census[root] = total
    return targets, census


def _kind_of(relpath: str) -> str:
    if relpath.startswith("fuzz/"):
        return "fuzz"
    if relpath.startswith("demos/"):
        return "demo"
    return "test"


# ---------------------------------------------------------------------------
# Clang AST extraction (pure over the parsed dump)
# ---------------------------------------------------------------------------

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


def extract_c(ast: dict, main_abs: str, src_root: Path, build_dir: Path,
              universe: frozenset[str]) -> dict:
    """Calls and references issued from a C source's own main file. A pure function.

    Header and system declarations are walked (they are needed to resolve a reference's
    declaration file) but only nodes located in the main file are attributed to the
    target, so an inline function in a public header that calls another API is not
    recorded as the test's own edge.
    """
    state = {"file": None, "line": None, "col": None, "offset": None}
    ids: dict[str, str | None] = {}
    calls: list[dict] = []
    refs: list[dict] = []
    consumed: set[str] = set()

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

    def walk(n) -> None:
        if isinstance(n, dict):
            if "loc" in n:
                proc_loc(n["loc"])
            cur_file = state["file"]
            if "range" in n and isinstance(n["range"], dict):
                r = n["range"]
                if "begin" in r:
                    proc_loc(r["begin"])
                if "end" in r:
                    proc_loc(r["end"])
            kind = n.get("kind")
            node_id = n.get("id")
            if kind in ("FunctionDecl", "VarDecl") and node_id:
                ids[node_id] = canon_path(cur_file, src_root, build_dir)
            # Clang suppresses a node's own location when it equals the last emitted one,
            # so a call or reference inside the main file can legitimately arrive with no
            # `loc`; the carried file is the node's file and is what decides attribution.
            is_main = cur_file is not None and cur_file == main_abs
            if is_main and kind == "CallExpr":
                callee = _callee_ref(n)
                if callee is not None:
                    ref = callee.get("referencedDecl") or {}
                    if callee.get("id"):
                        consumed.add(callee["id"])
                    calls.append({"name": ref.get("name") or callee.get("name"),
                                  "_id": ref.get("id")})
            elif is_main and kind == "DeclRefExpr":
                ref = n.get("referencedDecl") or {}
                if (node_id not in consumed
                        and ref.get("kind") in ("FunctionDecl", "VarDecl")
                        and ref.get("name")):
                    refs.append({"name": ref["name"], "_id": ref.get("id")})
            for c in n.get("inner", []):
                walk(c)
        elif isinstance(n, list):
            for c in n:
                walk(c)

    walk(ast)
    called = sorted({c["name"] for c in calls
                     if _is_authority(c["name"], c["_id"], universe, ids)})
    referenced = sorted({r["name"] for r in refs
                         if _is_authority(r["name"], r["_id"], universe, ids)})
    return {"symbols_called": called, "symbols_referenced": referenced}


def _is_authority(name: str | None, ref_id: str | None, universe: frozenset[str],
                  ids: dict[str, str | None]) -> bool:
    if not name or name not in universe:
        return False
    if ref_id and ref_id in ids:
        return is_authority_file(ids[ref_id])
    # A reference with no resolvable declaration id is accepted on the name alone only
    # when the id is absent entirely (a builtin), which the universe excludes anyway.
    return ref_id is None


def _task_c(payload: dict) -> dict:
    argv = [CLANG, "-fsyntax-only", "-Xclang", "-ast-dump=json"]
    argv += list(payload["defines"])
    argv += ["-I" + d for d in payload["include_dirs"]]
    argv.append(payload["main_abs"])
    proc = subprocess.run(argv, capture_output=True, check=False)
    if proc.returncode != 0:
        return {"path": payload["path"], "clang_ok": False}
    try:
        ast = json.loads(proc.stdout)
    except Exception:  # noqa: BLE001 -- a decode failure is a recorded fallback
        return {"path": payload["path"], "clang_ok": False}
    out = extract_c(ast, payload["main_abs"], Path(payload["src_root"]),
                    Path(payload["build_dir"]), payload["universe"])
    out["path"] = payload["path"]
    out["clang_ok"] = True
    return out


# ---------------------------------------------------------------------------
# lexical extraction (C fallback, and the openssl CLI inside test scripts)
# ---------------------------------------------------------------------------

def _strip_c_comments(text: str) -> str:
    text = _C_COMMENT_BLOCK.sub(" ", text)
    text = _C_COMMENT_LINE.sub(" ", text)
    return _C_STR.sub('""', text)


def lexical_c(text: str, universe: frozenset[str]) -> dict:
    """A token scan over comment-stripped C, used when Clang cannot parse the source.

    Calls are recognised by a following `(`, references by name alone. This is a
    deliberately reduced instrument and every edge it produces says so.
    """
    code = _strip_c_comments(text)
    names = {n for n in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", code) if n in universe}
    called = sorted(n for n in names if re.search(r"\b" + re.escape(n) + r"\s*\(", code))
    referenced = sorted(names - set(called))
    return {"symbols_called": called, "symbols_referenced": referenced}


def _fixtures(text: str, quoted: re.Pattern) -> list[str]:
    found: set[str] = set()
    for m in quoted.finditer(text):
        s = m.group(1) if m.group(1) is not None else m.group(2)
        if s and len(s) <= 200 and not re.search(r"\s", s) and _FIXTURE_RE.match(s):
            found.add(s)
    return sorted(found)


def _first_command(tokens: list[str], commands: frozenset[str]) -> str | None:
    """The first token in an invocation fragment that is a real CLI command."""
    for tok in tokens:
        if tok in ("openssl",) or tok.startswith("$") or tok.startswith("-"):
            continue
        if tok in commands:
            return tok
        if "/" in tok or "." in tok:
            continue
    return None


def extract_script(text: str, commands: frozenset[str]) -> dict:
    """`openssl` CLI invocations and named fixtures in a test script. A pure function."""
    invocations: set[tuple[str, tuple[str, ...]]] = set()
    for m in _APP_CALL.finditer(text):
        tokens = _BARE.findall(m.group(1))
        cmd = _first_command(tokens, commands)
        if cmd:
            args = tuple(t for t in tokens[tokens.index(cmd) + 1:] if not t.startswith("$"))
            invocations.add((cmd, args[:8]))
    for m in _OPENSSL_WORD.finditer(text):
        line = text[m.end():].splitlines()[0] if text[m.end():] else ""
        tokens = _BARE.findall(line)
        cmd = _first_command(tokens, commands)
        if cmd:
            args = tuple(t for t in tokens[tokens.index(cmd) + 1:] if not t.startswith("$"))
            invocations.add((cmd, args[:8]))
    cli_invocations = [
        {"command": cmd, "args": list(args)}
        for cmd, args in sorted(invocations)
    ]
    return {
        "cli_commands": sorted({cmd for cmd, _ in invocations}),
        "cli_invocations": cli_invocations,
        "fixtures": _fixtures(text, _QUOTED),
    }


# ---------------------------------------------------------------------------
# body assembly (pure, deterministic)
# ---------------------------------------------------------------------------

def _norm_source(row: dict) -> dict:
    return {
        "path": row["path"],
        "kind": row["kind"],
        "linkage": row.get("linkage", "links-authority"),
        "links_authority": bool(row.get("links_authority")),
        "drives_openssl": bool(row.get("drives_openssl")),
        "symbol_method": row.get("symbol_method"),
        "clang_ok": row.get("clang_ok"),
        "symbols_called": sorted(set(row.get("symbols_called", []))),
        "symbols_referenced": sorted(set(row.get("symbols_referenced", []))),
        "cli_commands": sorted(set(row.get("cli_commands", []))),
        "fixtures": sorted(set(row.get("fixtures", []))),
    }


def build_body(sources: list[dict], exported_symbols: list[str],
               public_symbols: list[str] | None = None) -> dict:
    """The crosswalk body from the per-source rows and the symbol universes.

    A pure function: no I/O, no ambient state. `RT-PHASE22-CROSSWALK` calls it on the
    committed artefact's own rows and on controlled in-memory mutations.
    """
    public_symbols = public_symbols or []
    rows = [_norm_source(s) for s in sources]
    rows.sort(key=lambda r: (r["kind"], r["path"]))

    edges: list[dict] = []
    for s in rows:
        method = s["symbol_method"] or "lexical"
        for name in s["symbols_called"]:
            edges.append({"source": s["path"], "target": name, "kind": "call",
                          "method": method})
        for name in s["symbols_referenced"]:
            edges.append({"source": s["path"], "target": name, "kind": "reference",
                          "method": method})
        for cmd in s["cli_commands"]:
            edges.append({"source": s["path"], "target": cmd, "kind": "cli",
                          "method": "lexical"})
    edges.sort(key=lambda e: (e["source"], e["target"], e["kind"]))

    kind_by_path = {s["path"]: s["kind"] for s in rows}
    reached_tested: set[str] = set()
    for e in edges:
        if e["kind"] in ("call", "reference") and kind_by_path.get(e["source"]) in (
                "test", "fuzz"):
            reached_tested.add(e["target"])

    exported = sorted(set(exported_symbols))
    public = sorted(set(public_symbols))
    untested_exported = sorted(set(exported) - reached_tested)
    untested_public = sorted(set(public) - reached_tested)

    sources_with_edges = {e["source"] for e in edges}
    targets_with_no_edges = sorted(s["path"] for s in rows
                                   if s["path"] not in sources_with_edges)

    # The plan's literal inverse query: test/fuzz targets that reference no authority
    # symbol. A script target has no symbol by construction, so it is listed unless it
    # carries a CLI edge; the C-only subset is the actionable slice.
    def _no_symbol(s: dict) -> bool:
        return not (s["symbols_called"] or s["symbols_referenced"])

    no_symbol_test_fuzz = sorted(s["path"] for s in rows
                                 if s["kind"] in ("test", "fuzz") and _no_symbol(s))
    no_symbol_c = sorted(s["path"] for s in rows
                         if s["kind"] in ("test", "fuzz")
                         and s["symbol_method"] is not None and _no_symbol(s))

    parser_hits: list[dict] = []
    parser_miss: list[str] = []
    for s in rows:
        if s["kind"] != "fuzz":
            continue
        symbols = sorted(set(s["symbols_called"]) | set(s["symbols_referenced"]))
        hits = [n for n in symbols if _PARSER_RE.search(n)]
        if hits:
            parser_hits.append({"path": s["path"], "parser_symbols": hits})
        else:
            parser_miss.append(s["path"])

    method_counts: dict[str, int] = {}
    for s in rows:
        key = s["symbol_method"] or "lexical"
        method_counts[key] = method_counts.get(key, 0) + 1

    counts = {
        "tests": sum(1 for s in rows if s["kind"] == "test"),
        "fuzzers": sum(1 for s in rows if s["kind"] == "fuzz"),
        "demos": sum(1 for s in rows if s["kind"] == "demo"),
        "edges": len(edges),
        "call_edges": sum(1 for e in edges if e["kind"] == "call"),
        "reference_edges": sum(1 for e in edges if e["kind"] == "reference"),
        "cli_edges": sum(1 for e in edges if e["kind"] == "cli"),
        "targets": len(rows),
        "targets_with_no_edges": len(targets_with_no_edges),
        "test_fuzz_targets_with_no_symbol_edges": len(no_symbol_test_fuzz),
        "c_targets_with_no_symbol_edges": len(no_symbol_c),
        "exported_symbols": len(exported),
        "untested_exported_symbols": len(untested_exported),
        "public_apis_without_test_edges": len(untested_public),
        "reachable_tested_symbols": len(reached_tested),
        "fuzz_targets_attacking_parser_surfaces": len(parser_hits),
        "distinct_fixtures": len({f for s in rows for f in s["fixtures"]}),
    }

    return {
        "sources": rows,
        "edges": edges,
        "exported_symbols": exported,
        "public_symbols": public,
        "untested_exported_symbols": untested_exported,
        "public_apis_without_test_edges": untested_public,
        "targets_with_no_edges": targets_with_no_edges,
        "test_fuzz_targets_with_no_symbol_edges": no_symbol_test_fuzz,
        "c_targets_with_no_symbol_edges": no_symbol_c,
        "fuzz_targets_attacking_parser_surfaces": sorted(
            parser_hits, key=lambda r: r["path"]),
        "fuzz_targets_without_parser_surface": sorted(parser_miss),
        "methods": sorted(method_counts),
        "method_counts": dict(sorted(method_counts.items())),
        "counts": counts,
    }


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def _include_dirs(src_root: Path, build_dir: Path) -> list[str]:
    out: list[str] = []
    for relcand in INCLUDE_CANDIDATES:
        if relcand == "build/include":
            cand = build_dir / "include"
        elif relcand == ".":
            cand = src_root
        else:
            cand = src_root / relcand
        if cand.is_dir():
            out.append(str(cand))
    return out


def _cli_commands(authority_id: str) -> frozenset[str]:
    doc = json.loads((_phase22_dir() / "cli-surface.json")
                     .read_text(encoding="utf-8"))
    body = doc["body"]
    names: set[str] = set()
    for rec in body.get("commands", []):
        names.add(rec["name"])
        names.update(rec.get("aliases") or [])
    names.update(body.get("digest_commands") or [])
    names.update(body.get("cipher_commands") or [])
    return frozenset(names)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument("--jobs", type=int, default=DEFAULT_JOBS)
    ap.add_argument("--limit", type=int, default=0,
                    help="process only the first N C sources (measurement aid)")
    args = ap.parse_args(argv)

    sys.setrecursionlimit(100000)
    auth = resolve_authority(args.authority)
    src_root = auth.source
    build_dir = REPO_ROOT / BUILD_DIR_REL
    universe = load_universe(auth.id)
    cli_commands = _cli_commands(auth.id)
    include_dirs = _include_dirs(src_root, build_dir)

    targets, census = enumerate_corpus(src_root)
    c_targets = [t for t in targets if t["form"] == "c"]
    scripts = [t for t in targets if t["form"] == "script"]
    if args.limit:
        c_targets = c_targets[:args.limit]

    print(f"[phase22-crosswalk] corpus test={census.get('test', 0)} "
          f"fuzz={census.get('fuzz', 0)} demos={census.get('demos', 0)}: "
          f"{len(c_targets)} C sources, {len(scripts)} scripts")

    payloads = [
        {"path": t["path"], "main_abs": t["abs"], "include_dirs": include_dirs,
         "defines": list(CLANG_DEFINES), "src_root": str(src_root),
         "build_dir": str(build_dir), "universe": universe["names"]}
        for t in c_targets
    ]
    results: dict[str, dict] = {}
    if payloads:
        if args.jobs <= 1:
            outs = [_task_c(p) for p in payloads]
        else:
            with concurrent.futures.ProcessPoolExecutor(max_workers=args.jobs) as pool:
                outs = list(pool.map(_task_c, payloads))
        for out in outs:
            results[out["path"]] = out

    rows: list[dict] = []
    c_parsed = c_lexical = 0
    for t in c_targets:
        out = results.get(t["path"], {"clang_ok": False})
        text = Path(t["abs"]).read_text(encoding="utf-8", errors="replace")
        fixtures = _fixtures(text, _C_STR)
        if out.get("clang_ok"):
            c_parsed += 1
            sym = {"symbols_called": out["symbols_called"],
                   "symbols_referenced": out["symbols_referenced"]}
            method = "clang-ast"
        else:
            c_lexical += 1
            sym = lexical_c(text, universe["names"])
            method = "lexical"
        rows.append({
            "path": t["path"], "kind": t["kind"], "linkage": "links-authority",
            "links_authority": True, "drives_openssl": False,
            "symbol_method": method, "clang_ok": bool(out.get("clang_ok")),
            "symbols_called": sym["symbols_called"],
            "symbols_referenced": sym["symbols_referenced"],
            "cli_commands": [], "fixtures": fixtures,
        })

    cli_invocations: dict[str, list] = {}
    for t in scripts:
        text = Path(t["abs"]).read_text(encoding="utf-8", errors="replace")
        info = extract_script(text, cli_commands)
        drives = bool(info["cli_commands"])
        rows.append({
            "path": t["path"], "kind": t["kind"],
            "linkage": "drives-openssl" if drives else "harness",
            "links_authority": False, "drives_openssl": drives,
            "symbol_method": None, "clang_ok": None,
            "symbols_called": [], "symbols_referenced": [],
            "cli_commands": info["cli_commands"], "fixtures": info["fixtures"],
        })
        if info["cli_invocations"]:
            cli_invocations[t["path"]] = info["cli_invocations"]

    body = build_body(rows, universe["exported"], universe["public"])
    body["cli_invocations"] = dict(sorted(cli_invocations.items()))

    body["instrument"] = {
        "clang": CLANG,
        "note": (
            "Clang is a shadow analysis instrument. The production authority profile is "
            "'...-notests', so 22.1's execution capture contains no test/fuzz/demo "
            "translation unit and there is no authority-recorded invocation to replay; "
            "the corpus is parsed over the minimal include set below, and a source Clang "
            "cannot parse is extracted lexically instead of dropped."
        ),
        "include_dirs": [rel(Path(d)) for d in include_dirs],
        "defines": list(CLANG_DEFINES),
    }
    body["coverage"] = {
        "roots": list(CORPUS_ROOTS),
        "files_in_roots": census,
        "targets": len(rows),
        "c_sources": len(c_targets),
        "scripts": len(scripts),
        "data_files_not_targets": sum(census.values()) - len(c_targets) - len(scripts),
        "clang_parsed": c_parsed,
        "lexical_fallback": c_lexical,
        "bound": (
            "The corpus is bounded to test/, fuzz/ and demos/ of the admitted source "
            "tree. apps/ is the CLI's own implementation, not a test corpus; its surface "
            "is owned by 22.3 and 22.9, and the app-driving recipes under test/recipes/ "
            "are in scope here."
        ),
        "script_linkage_note": (
            "A recipe that only runs a C test binary (run(test([...]))) drives that "
            "binary, which links the authority; the recipe itself contributes no symbol "
            "edge and is recorded as `harness`, and the C target it runs carries the "
            "symbols. Only a script that invokes the `openssl` CLI is `drives-openssl`."
        ),
        "symbol_universe": {
            "total": len(universe["names"]),
            "exported": len(universe["exported"]),
            "public": len(universe["public"]),
            "note": (
                "A referenced name is authority surface only if it is in the Phase-1 "
                "universe (public declarations, DSO exports, internal symbols) and its "
                "resolved declaration is an authority file, never a test/fuzz/demos file."
            ),
        },
    }
    body["sort_key"] = (
        "sources by (kind, path); edges by (source, target, kind); every list sorted"
    )

    inputs = [
        InputRef(name="plan", path=REPO_ROOT / "docs" / "PHASE-22-SUBPHASES.md"),
        InputRef(name="functions", path=_atlas_dir(auth.id) / "functions.json"),
        InputRef(name="variables", path=_atlas_dir(auth.id) / "variables.json"),
        InputRef(name="typedefs", path=_atlas_dir(auth.id) / "typedefs.json"),
        InputRef(name="symbols-libcrypto",
                 path=_atlas_dir(auth.id) / "symbols-libcrypto.json"),
        InputRef(name="symbols-libssl", path=_atlas_dir(auth.id) / "symbols-libssl.json"),
        InputRef(name="internal-symbols", path=REPO_ROOT / "forensics" / "atlas"
                 / "internal-symbols.json"),
        InputRef(name="cli-surface", path=_phase22_dir() / "cli-surface.json"),
    ]
    doc = envelope(kind="phase22-test-crosswalk", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(REPO_ROOT / OUT_REL, doc)

    c = body["counts"]
    print(f"[phase22-crosswalk] tests={c['tests']} fuzzers={c['fuzzers']} "
          f"demos={c['demos']} edges={c['edges']} "
          f"(call={c['call_edges']} ref={c['reference_edges']} cli={c['cli_edges']})")
    print(f"[phase22-crosswalk] untested_exported={c['untested_exported_symbols']} "
          f"public_without_test={c['public_apis_without_test_edges']} "
          f"targets_with_no_edges={c['targets_with_no_edges']} "
          f"fuzz_parser_targets={c['fuzz_targets_attacking_parser_surfaces']}")
    print(f"[phase22-crosswalk] clang_parsed={c_parsed} lexical_fallback={c_lexical} "
          f"methods={body['method_counts']} -> {rel(REPO_ROOT / OUT_REL)}")
    return 0


# ---------------------------------------------------------------------------
# the court
# ---------------------------------------------------------------------------

def court_crosswalk(body: dict) -> dict:
    """`RT-PHASE22-CROSSWALK`: an FRF-style sensitivity challenge of the edge logic.

    Round-trips the committed body from its own `sources` rows and its two symbol
    universes, then drives `build_body` over five controlled mutations -- add a test
    source, add a symbol edge, move a test to fuzz, add a target with no edges, add an
    untested exported symbol -- and fails if the derivation is insensitive to any of
    them.
    """
    import copy

    checks: list[tuple[str, bool]] = []
    sources = copy.deepcopy(body["sources"])
    exported = copy.deepcopy(body["exported_symbols"])
    public = copy.deepcopy(body.get("public_symbols", []))

    checks.append(("baseline: the artefact has sources", len(sources) > 0))
    checks.append(("baseline: the artefact has edges", body["counts"]["edges"] > 0))
    checks.append(("baseline: the artefact has tests", body["counts"]["tests"] > 0))
    checks.append(("baseline: the artefact has fuzzers", body["counts"]["fuzzers"] > 0))
    checks.append(("baseline: the artefact has demos", body["counts"]["demos"] > 0))

    base = build_body(copy.deepcopy(sources), copy.deepcopy(exported), copy.deepcopy(public))
    for key in ("sources", "edges", "untested_exported_symbols",
                "public_apis_without_test_edges", "targets_with_no_edges",
                "test_fuzz_targets_with_no_symbol_edges", "c_targets_with_no_symbol_edges",
                "fuzz_targets_attacking_parser_surfaces",
                "fuzz_targets_without_parser_surface", "methods", "method_counts",
                "counts"):
        checks.append((f"round-trip: {key} equal", base[key] == body[key]))

    if base["untested_exported_symbols"]:
        synthetic_symbol = base["untested_exported_symbols"][0]
    elif exported:
        synthetic_symbol = exported[0]
    else:
        synthetic_symbol = "phase22_synthetic_symbol"

    # 1. add a test source that calls a symbol.
    mutated = copy.deepcopy(sources)
    mutated.append({
        "path": "test/phase22_synthetic_probe.c", "kind": "test",
        "linkage": "links-authority", "links_authority": True, "drives_openssl": False,
        "symbol_method": "clang-ast", "clang_ok": True,
        "symbols_called": [synthetic_symbol], "symbols_referenced": [],
        "cli_commands": [], "fixtures": [],
    })
    new = build_body(mutated, copy.deepcopy(exported), copy.deepcopy(public))
    checks.append(("add-test-source: tests rose by one",
                   new["counts"]["tests"] == base["counts"]["tests"] + 1))
    checks.append(("add-test-source: edges rose by one",
                   new["counts"]["edges"] == base["counts"]["edges"] + 1))
    if synthetic_symbol in base["untested_exported_symbols"]:
        checks.append(("add-test-source: it reached an untested export",
                       new["counts"]["untested_exported_symbols"]
                       == base["counts"]["untested_exported_symbols"] - 1))

    # 2. add a symbol edge to an existing source.
    victim = next((s for s in base["sources"] if s["symbol_method"] == "clang-ast"), None)
    if victim is None:
        checks.append(("add-symbol-edge: a clang-ast source was found", False))
    else:
        extra = "phase22_synthetic_reference"
        mutated = copy.deepcopy(sources)
        for s in mutated:
            if s["path"] == victim["path"]:
                s["symbols_referenced"] = sorted(set(s["symbols_referenced"]) | {extra})
        new = build_body(mutated, copy.deepcopy(exported), copy.deepcopy(public))
        checks.append(("add-symbol-edge: edges rose by one",
                       new["counts"]["edges"] == base["counts"]["edges"] + 1))
        checks.append(("add-symbol-edge: reference edges rose by one",
                       new["counts"]["reference_edges"]
                       == base["counts"]["reference_edges"] + 1))
        found = any(e["source"] == victim["path"] and e["target"] == extra
                    and e["kind"] == "reference" for e in new["edges"])
        checks.append(("add-symbol-edge: the edge is present", found))

    # 3. move a test source to fuzz.
    test_source = next((s for s in base["sources"] if s["kind"] == "test"), None)
    if test_source is None:
        checks.append(("move-test-to-fuzz: a test source was found", False))
    else:
        mutated = copy.deepcopy(sources)
        for s in mutated:
            if s["path"] == test_source["path"]:
                s["kind"] = "fuzz"
        new = build_body(mutated, copy.deepcopy(exported), copy.deepcopy(public))
        checks.append(("move-test-to-fuzz: tests fell by one",
                       new["counts"]["tests"] == base["counts"]["tests"] - 1))
        checks.append(("move-test-to-fuzz: fuzzers rose by one",
                       new["counts"]["fuzzers"] == base["counts"]["fuzzers"] + 1))
        checks.append(("move-test-to-fuzz: edges unchanged",
                       new["counts"]["edges"] == base["counts"]["edges"]))

    # 4. add a target with no edges.
    mutated = copy.deepcopy(sources)
    mutated.append({
        "path": "fuzz/phase22_synthetic_empty.c", "kind": "fuzz",
        "linkage": "links-authority", "links_authority": True, "drives_openssl": False,
        "symbol_method": "clang-ast", "clang_ok": True,
        "symbols_called": [], "symbols_referenced": [],
        "cli_commands": [], "fixtures": [],
    })
    new = build_body(mutated, copy.deepcopy(exported), copy.deepcopy(public))
    checks.append(("add-empty-target: fuzzers rose by one",
                   new["counts"]["fuzzers"] == base["counts"]["fuzzers"] + 1))
    checks.append(("add-empty-target: targets_with_no_edges rose by one",
                   new["counts"]["targets_with_no_edges"]
                   == base["counts"]["targets_with_no_edges"] + 1))
    checks.append(("add-empty-target: the target is listed",
                   "fuzz/phase22_synthetic_empty.c" in new["targets_with_no_edges"]))

    # 5. add an untested exported symbol.
    mutated_exported = copy.deepcopy(exported) + ["phase22_synthetic_untested_export"]
    new = build_body(copy.deepcopy(sources), mutated_exported, copy.deepcopy(public))
    checks.append(("add-untested-export: untested rose by one",
                   new["counts"]["untested_exported_symbols"]
                   == base["counts"]["untested_exported_symbols"] + 1))
    checks.append(("add-untested-export: the symbol is listed",
                   "phase22_synthetic_untested_export"
                   in new["untested_exported_symbols"]))

    failures = [desc for desc, ok in checks if not ok]
    c = body["counts"]
    return {
        "court": "RT-PHASE22-CROSSWALK",
        "artefact": ARTEFACT_REL,
        "summary": (f"{c.get('tests')} tests, {c.get('fuzzers')} fuzzers, "
                    f"{c.get('demos')} demos, {c.get('edges')} edges, "
                    f"{c.get('untested_exported_symbols')} untested exports"),
        "tests": c.get("tests"),
        "fuzzers": c.get("fuzzers"),
        "demos": c.get("demos"),
        "edges": c.get("edges"),
        "untested_exported_symbols": c.get("untested_exported_symbols"),
        "targets_with_no_edges": c.get("targets_with_no_edges"),
        "mutations": ["round-trip", "add-test-source", "add-symbol-edge",
                      "move-test-to-fuzz", "add-empty-target", "add-untested-export"],
        "observations": len(checks),
        "failures": failures,
        "verdict": "pass" if not failures else "fail",
    }


def courts() -> list[dict]:
    """`RT-PHASE22-CROSSWALK`, or `[]` while the artefact has not landed."""
    path = REPO_ROOT / ARTEFACT_REL
    if not path.is_file():
        return []
    doc = json.loads(path.read_text(encoding="utf-8"))
    return [court_crosswalk(doc["body"])]


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
