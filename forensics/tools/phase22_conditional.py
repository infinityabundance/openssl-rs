#!/usr/bin/env python3
"""openssl-rs -- Phase 22.4 preprocessor and conditional-compilation graph.

Replays the exact compile invocations 22.1 captured
(`forensics/atlas/phase22/compile-commands.json`) and normalizes the preprocessor's
behaviour into the repository's standard, content-addressed atlas document at
`forensics/atlas/phase22/conditional-surface.json`: for every translation unit the
`#define`/`#undef` surface with its defining site, the `#include` directives and their
resolution, the `#if`/`#ifdef`/`#ifndef`/`#elif`/`#else`/`#endif` structure with the
branch this profile actually took and the **source ranges it skipped**, the `defined(...)`
occurrences, and the macros of interest with their final expansion -- then classifies
every authority source surface.

Why this subphase exists, in the plan's own words
-------------------------------------------------
`docs/PHASE-22-SUBPHASES.md` section 6: "**22.4** must answer *why* a function exists in
this build and *why* another does not, with a conditional lineage rather than a
configuration guess." The plan's typed edge graph (section 3) names the relationship this
plane records as `INCLUDED_BY`; and the seal criterion (section 7) requires "every
authority source file classified". This tool is the one that has the conditional lineage:
it does not guess from `Configure`, it asks Clang what the captured invocation's `-D` and
`-I` set actually selected.

The instrument, stated rather than implied
-------------------------------------------
Clang is a **shadow analysis instrument**, exactly as 22.1/22.3 record: the production
authority is a GCC build (`configdata.pm` records `CC=gcc`), and re-reading its captured
invocations with Clang never redefines the authority as a Clang build
(`docs/PHASE-22-SUBPHASES.md` section 6). Three Clang facts are read per unit, and a pure
Python pass supplies the source-range bookkeeping:

  * `clang -E` -- the preprocessed stream. Its `# line "file"` markers are replayed in
    document order to compute, per source file, the set of lines that **contributed** to
    the translation unit. A conditional branch with a contributed content line was taken;
    one with none was skipped. This is the ground truth and does not guess from `-D`.
  * `clang -E -dM` -- the final macro table after preprocessing. It supplies the value of
    every macro of interest (a conditional's condition can reference a macro whose body is
    an expression) and the count of macros the profile defines.
  * the original source text -- parsed line by line for the directive structure, so the
    `#define`/`#undef`/`#include` sites and the `#if` nesting are the source's own, not a
    reconstruction from the preprocessed output.

A branch whose body has no content line at all cannot be resolved by coverage, so a small
C-conditional evaluator (`defined`, `!`, `&&`, `||`, comparisons, integer literals) is
used as the fallback and an unresolved branch is recorded as `null`, never as a guess.

What "exists" and "does not exist" mean here
--------------------------------------------
Every surface is a file of the authority tree. A translation unit's own file is classified
by the conditional lineage this plane recorded for it:

  * `active-production` -- compiled by the profile and carrying live content outside any
    fips/platform/deprecated guard;
  * `excluded-by-production-profile` -- every content line was preprocessed away (the file
    compiles to nothing under this profile);
  * `platform-specific` / `fips-only` / `deprecated-only` -- the file's live content is
    entirely gated by a platform / FIPS / deprecation macro, or its whole body is skipped
    by one;
  * `test-only` / `demo-only` -- under `test/`+`fuzz/` or `demos/`+`doc/`, where the
    production build never looks;
  * `generated-only` -- exists only in the pinned build tree (generated from a `.in`/`.pl`
    template), never in the source tree;
  * `assembly-alternative` -- a `.s`/`.S` perlasm unit, the shape Clang cannot read and
    22.6 is where it is seen.

Determinism
-----------
Every list is sorted and every count is derived from the rows. No timestamp, PID, scratch
path or host path is written; authority paths are repository-relative. The same capture
and the same authority tree produce byte-identical JSON, which is what lets
`RT-PHASE22-CONDITIONAL` re-derive the committed body from its own rows and mutate them.

Output
------
    forensics/atlas/phase22/conditional-surface.json

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
from collections import Counter
from pathlib import Path
from typing import Any

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

GENERATOR = "forensics/tools/phase22_conditional.py"
ARTEFACT_REL = "forensics/atlas/phase22/conditional-surface.json"
OUT_REL = ARTEFACT_REL
CAPTURE_REL = "forensics/atlas/phase22/compile-commands.json"
BUILD_DIR_REL = "forensics/authorities/build/openssl-3.6.4-production"

CLANG = "clang"
DEFAULT_JOBS = 4
INSTRUMENT = ("clang -E (live-line coverage) + clang -E -dM (final macro table) + "
              "Python source-range bookkeeping")

# The plan's classification vocabulary, in a fixed order so the body is deterministic and a
# class with zero members is still reported.
CLASSES = [
    "active-production",
    "excluded-by-production-profile",
    "platform-specific",
    "fips-only",
    "deprecated-only",
    "test-only",
    "demo-only",
    "generated-only",
    "assembly-alternative",
]

# A source surface is any translation unit, header or perlasm file. Headers are classified
# too: they are part of the surface even though Clang never compiles one on its own.
SOURCE_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", ".m", ".h", ".hpp", ".s", ".S")

# Platform macros whose truth decides whether a block is platform-specific. Deliberately a
# named set rather than every `__...__` macro, because `__GNUC__`/`__clang__` are compiler
# facts, not platform facts, and classifying a compiler guard as platform-specific would be a
# wrong answer that looked right.
PLATFORM_MACROS = {
    "__linux__", "__linux", "linux",
    "__APPLE__", "__MACH__", "__MACH_OPT__",
    "_WIN32", "_WIN64", "WIN32", "WIN64", "_MSC_VER", "_UEFI",
    "__FreeBSD__", "__OpenBSD__", "__NetBSD__", "__DragonFly__", "__bsdi__",
    "_AIX", "AIX", "__sun", "__sun__", "__hpux", "__hpux__", "__VMS", "__VXWORKS__",
    "__ANDROID__", "__CYGWIN__", "__MINGW32__", "__MINGW64__", "__EMSCRIPTEN__", "__wasm__",
    "__s390__", "__s390x__", "__x86_64__", "__amd64__", "__i386__", "__i486__", "__i586__",
    "__i686__", "__aarch64__", "__arm__", "__arm64__", "__armv7__", "__powerpc__",
    "__powerpc64__", "__ppc__", "__ppc64__", "__riscv", "__riscv64", "__mips__", "__mips64",
    "__sparc__", "__sparcv9", "__alpha__", "__hppa__", "__ia64__", "__loongarch__",
    "__loongarch64", "__e2k__",
}

# The gating macros worth carrying in the profile summary: the ones a reader uses to ask
# "was this profile built without X". The full final macro table is per-TU and large, so the
# body records this curated subset rather than the whole table (see `body.reduction`).
def _is_gating_macro(name: str) -> bool:
    return (
        name.startswith(("OPENSSL_NO_", "OPENSSL_SYS_", "OPENSSL_USE_"))
        or "FIPS" in name.upper()
        or "DEPRECATED" in name.upper()
        or name in ("NDEBUG", "OPENSSL_BUILDING_OPENSSL")
    )


_COND_RE = re.compile(r"^#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)$")
_INCLUDE_RE = re.compile(r"^#\s*include\s*([<\"])([^>\"]*)[>\"]")
_DEFINE_RE = re.compile(r"^#\s*define\s+([A-Za-z_]\w*)")
_UNDEF_RE = re.compile(r"^#\s*undef\s+([A-Za-z_]\w*)")
_DEFINED_RE = re.compile(r"\bdefined\b\s*(?:\(\s*([A-Za-z_]\w*)\s*\)|([A-Za-z_]\w*))")
_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
_MARKER_RE = re.compile(r'^\s*#\s*(\d+)\s+"([^"]*)"')
_TOKEN_RE = re.compile(r"\s*(&&|\|\||==|!=|<=|>=|<<|>>|[-+*/%()!<>~^&|]|[A-Za-z_]\w*|0[xX][0-9a-fA-F]+|\d+)")

_GUARD_NAME = {"fips": "fips-only", "platform": "platform-specific",
               "deprecated": "deprecated-only"}


# ---------------------------------------------------------------------------
# macro classification (pure)
# ---------------------------------------------------------------------------

def macro_guard_class(name: str) -> str | None:
    """`fips` / `platform` / `deprecated` for a macro that names such a guard, else None."""
    u = name.upper()
    if "FIPS" in u:
        return "fips"
    if "DEPRECATED" in u:
        return "deprecated"
    if name in PLATFORM_MACROS or name.upper().startswith(("OPENSSL_SYS_",)):
        return "platform"
    return None


def node_guard_class(node: dict) -> str | None:
    """The guard class of a conditional node, from the macros its condition names."""
    cond = node.get("condition") or ""
    if node["kind"] in ("ifdef", "ifndef"):
        names = [cond.strip()]
    else:
        # Replace `defined(X)`/`defined X` with the bare name, then take every identifier.
        names = [n for n in _IDENT_RE.findall(cond) if n != "defined"]
    for n in names:
        cls = macro_guard_class(n)
        if cls:
            return cls
    return None


def _dominant_guard_class(counts: dict) -> str | None:
    """The single guard class present, or None if unguarded/mixed.

    `counts` maps a guard class (or `none`) to a line count. A file is platform-specific
    only when *every* relevant line is under exactly one platform guard; a `none` line or a
    second class means the file is not characterized by a single guard.
    """
    keys = {k for k, v in counts.items() if v > 0}
    if len(keys) != 1:
        return None
    return _GUARD_NAME.get(next(iter(keys)))


# ---------------------------------------------------------------------------
# capture -> logical translation units (mirrors 22.3)
# ---------------------------------------------------------------------------

def load_capture_body(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))["body"]


def suffix_of(source: str) -> str:
    return os.path.splitext(source)[1].lower()


def is_c_source(source: str) -> bool:
    return suffix_of(source) in (".c", ".cc", ".cpp", ".cxx", ".m")


def logical_tus(capture_body: dict) -> tuple[list[dict], list[dict]]:
    """Distinct logical translation units from 22.1's capture, `(c_units, non_c_units)`."""
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
# authority-relative path identity (mirrors 22.3)
# ---------------------------------------------------------------------------

def canon_path(abs_path: str | None, src_root: Path, build_dir: Path) -> str | None:
    """A repository-relative identity for an authority path, or an `external/` name."""
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
    """The absolute path the authority fed the compiler for `source`."""
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


def resolve_include_dir(token: str, captured_dir: str | None, build_dir: Path,
                        src_root: Path) -> str | None:
    """One captured `-I`/`-isystem` token to an existing absolute directory, or None."""
    if token.startswith("-I "):
        path = token[3:]
    elif token.startswith("-isystem "):
        path = token[9:]
    elif token.startswith("-isystem"):
        path = token[8:]
    elif token.startswith("-I"):
        path = token[2:]
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


# ---------------------------------------------------------------------------
# the conditional evaluator (pure fallback for branches coverage cannot resolve)
# ---------------------------------------------------------------------------

def _tokenize(expr: str) -> list[str]:
    toks: list[str] = []
    i = 0
    while i < len(expr):
        m = _TOKEN_RE.match(expr, i)
        if not m:
            if expr[i:].strip() == "":
                break
            raise ValueError(f"unexpected character {expr[i]!r}")
        toks.append(m.group(1))
        i = m.end()
    return toks


def _macro_value(name: str, macros: dict) -> object:
    """The integer value of a defined macro, `False` for an undefined one, None if unknown."""
    if name not in macros:
        return False  # an undefined identifier evaluates to 0 in a C conditional
    raw = (macros.get(name) or "").strip()
    if raw == "":
        return None
    raw = re.sub(r"[uUlL]+$", "", raw)
    if re.fullmatch(r"0[xX][0-9a-fA-F]+|\d+", raw):
        try:
            return int(raw, 0)
        except ValueError:
            return None
    return None


def eval_cond(expr: str, macros: dict) -> bool | None:
    """Evaluate a `#if`/`#elif` condition over the final macro table; None if undecidable.

    Only the shapes a conditional actually uses are handled -- `defined`, `!`, `&&`, `||`,
    comparisons, integer arithmetic and literals. Anything else is None, which the caller
    records as an unresolved branch rather than a guess.
    """
    try:
        toks = _tokenize(expr)
    except ValueError:
        return None
    if not toks:
        return None
    pos = [0]

    def peek():
        return toks[pos[0]] if pos[0] < len(toks) else None

    def eat(tok):
        if peek() == tok:
            pos[0] += 1
            return True
        return False

    def as_bool(v):
        return None if v is None else bool(v)

    def parse_or():
        left = as_bool(parse_and())
        while eat("||"):
            right = as_bool(parse_and())
            if left is True or right is True:
                left = True
            elif left is False and right is False:
                left = False
            else:
                left = None
        return left

    def parse_and():
        left = as_bool(parse_cmp())
        while eat("&&"):
            right = as_bool(parse_cmp())
            if left is False or right is False:
                left = False
            elif left is True and right is True:
                left = True
            else:
                left = None
        return left

    def parse_cmp():
        left = parse_add()
        for op in ("==", "!=", "<=", ">=", "<", ">"):
            if eat(op):
                right = parse_add()
                if not isinstance(left, int) or not isinstance(right, int):
                    return None
                return {"==": left == right, "!=": left != right, "<=": left <= right,
                        ">=": left >= right, "<": left < right, ">": left > right}[op]
        return left

    def parse_add():
        left = parse_mul()
        while True:
            if eat("+"):
                right = parse_mul()
                left = left + right if isinstance(left, int) and isinstance(right, int) else None
            elif eat("-"):
                right = parse_mul()
                left = left - right if isinstance(left, int) and isinstance(right, int) else None
            else:
                return left

    def parse_mul():
        left = parse_unary()
        while True:
            if eat("*"):
                right = parse_unary()
                left = left * right if isinstance(left, int) and isinstance(right, int) else None
            elif eat("/"):
                right = parse_unary()
                left = (left // right) if isinstance(left, int) and isinstance(right, int) \
                    and right != 0 else None
            else:
                return left

    def parse_unary():
        if eat("!"):
            v = parse_unary()
            return None if v is None else (not v)
        if eat("~"):
            v = parse_unary()
            return ~v if isinstance(v, int) else None
        if eat("-"):
            v = parse_unary()
            return -v if isinstance(v, int) else None
        return parse_primary()

    def parse_primary():
        tok = peek()
        if tok is None:
            return None
        if tok == "(":
            pos[0] += 1
            v = parse_or()
            eat(")")
            return v
        if re.fullmatch(r"0[xX][0-9a-fA-F]+|\d+", tok):
            pos[0] += 1
            return int(tok, 0)
        if tok == "defined":
            pos[0] += 1
            if eat("("):
                name = peek()
                if name is not None and re.fullmatch(r"[A-Za-z_]\w*", name):
                    pos[0] += 1
                eat(")")
                return name in macros
            name = peek()
            if name is not None:
                pos[0] += 1
            return name in macros
        if re.fullmatch(r"[A-Za-z_]\w*", tok):
            pos[0] += 1
            return _macro_value(tok, macros)
        pos[0] += 1
        return None

    value = parse_or()
    return as_bool(value) if pos[0] == len(toks) else None


# ---------------------------------------------------------------------------
# source analysis (pure over the text, the live set and the macro table)
# ---------------------------------------------------------------------------

def strip_comments(lines: list[str]) -> list[str]:
    """Each line with comments removed, so a `#` inside a comment is not a directive."""
    out: list[str] = []
    in_block = False
    for line in lines:
        i = 0
        buf: list[str] = []
        while i < len(line):
            if in_block:
                j = line.find("*/", i)
                if j < 0:
                    i = len(line)
                else:
                    in_block = False
                    i = j + 2
            elif line.startswith("/*", i):
                in_block = True
                i += 2
            elif line.startswith("//", i):
                break
            else:
                buf.append(line[i])
                i += 1
        out.append("".join(buf))
    return out


def _live_lines(preprocessed: str, main_abs: str) -> set[int]:
    """The 1-based lines of `main_abs` that contributed to the preprocessed output."""
    live: set[int] = set()
    cur: str | None = None
    line = 0
    for ln in preprocessed.split("\n"):
        m = _MARKER_RE.match(ln)
        if m:
            line = int(m.group(1))
            cur = m.group(2)
            continue
        if cur == main_abs:
            live.add(line)
        line += 1
    return live


def analyze_source(text: str, live: set[int], macros: dict) -> dict:
    """The per-unit preprocessor record. A pure function of the text, live set and macros."""
    lines = text.split("\n")
    clean = strip_comments(lines)
    n = len(clean)
    content = [bool(clean[i].strip()) and not clean[i].lstrip().startswith("#")
               for i in range(n)]

    nodes: list[dict] = []
    stack: list[dict] = []
    defines: list[dict] = []
    undefs: list[dict] = []
    includes: list[dict] = []
    defined_occurrences: list[dict] = []
    interest: set[str] = set()

    for i in range(n):
        c = clean[i].strip()
        if not c.startswith("#"):
            continue
        m = _COND_RE.match(c)
        if m:
            kind, rest = m.group(1), m.group(2).strip()
            if kind in ("if", "ifdef", "ifndef"):
                node = {"kind": kind, "line": i + 1, "condition": rest,
                        "parent": stack[-1] if stack else None, "endif": None,
                        "branches": [{"kind": kind, "line": i + 1, "condition": rest,
                                      "first": i + 1, "last": None, "taken": None,
                                      "children": []}]}
                nodes.append(node)
                stack.append(node)
            elif kind in ("elif", "else"):
                if stack:
                    node = stack[-1]
                    node["branches"][-1]["last"] = i
                    node["branches"].append({"kind": kind, "line": i + 1, "condition": rest,
                                             "first": i + 1, "last": None, "taken": None,
                                             "children": []})
            else:  # endif
                if stack:
                    node = stack.pop()
                    node["branches"][-1]["last"] = i
                    node["endif"] = i + 1
            for name in _IDENT_RE.findall(rest):
                if name != "defined":
                    interest.add(name)
            for dm in _DEFINED_RE.finditer(rest):
                name = dm.group(1) or dm.group(2)
                interest.add(name)
                defined_occurrences.append({"name": name, "line": i + 1, "taken": None})
            continue
        m = _INCLUDE_RE.match(c)
        if m:
            includes.append({"kind": "quote" if m.group(1) == '"' else "angle",
                             "path": m.group(2), "line": i + 1, "taken": None})
            continue
        m = _DEFINE_RE.match(c)
        if m:
            defines.append({"macro": m.group(1), "value": c[m.end():].strip(),
                            "line": i + 1, "taken": None})
            interest.add(m.group(1))
            continue
        m = _UNDEF_RE.match(c)
        if m:
            undefs.append({"macro": m.group(1), "line": i + 1, "taken": None})
            interest.add(m.group(1))

    # Close any unclosed node so the ranges are well formed.
    while stack:
        node = stack.pop()
        if node["branches"][-1]["last"] is None:
            node["branches"][-1]["last"] = n - 1
        node["endif"] = node["endif"] or n

    for node in nodes:
        if node["branches"][-1]["last"] is None:
            node["branches"][-1]["last"] = (node["endif"] or n) - 1

    # Attach each nested node to the branch of its parent that contains its start line.
    for node in nodes:
        p = node["parent"]
        if not p:
            continue
        for br in p["branches"]:
            last = br["last"] if br["last"] is not None else n - 1
            if br["first"] <= node["line"] - 1 <= last:
                br["children"].append(node)
                break

    # Taken flags, children first so an enclosing branch sees a taken child as live.
    for node in reversed(nodes):
        prev_taken = False
        for br in node["branches"]:
            if prev_taken:
                br["taken"] = False
                continue
            last = br["last"] if br["last"] is not None else n - 1
            live_hit = any(content[j] and (j + 1) in live for j in range(br["first"], last + 1))
            child_hit = any(any(x["taken"] for x in ch["branches"]) for ch in br["children"])
            if live_hit or child_hit or br["kind"] == "else":
                br["taken"] = True
            elif br["kind"] == "if" and node["kind"] == "ifdef":
                br["taken"] = node["condition"].strip() in macros
            elif br["kind"] == "if" and node["kind"] == "ifndef":
                br["taken"] = node["condition"].strip() not in macros
            else:
                br["taken"] = eval_cond(br["condition"], macros)
            if br["taken"]:
                prev_taken = True

    # Per-line enclosing branches, outermost first (nodes are created outermost first).
    line_branch: list[list[tuple]] = [[] for _ in range(n)]
    for node in nodes:
        for br in node["branches"]:
            last = br["last"] if br["last"] is not None else n - 1
            for j in range(br["first"], min(last, n - 1) + 1):
                line_branch[j].append((node, br))

    # Resolve taken for each recorded directive from the enclosing branch state.
    def taken_at(i: int) -> bool:
        return all(br["taken"] is True for _, br in line_branch[i])

    def guard_at(i: int) -> tuple[bool, str]:
        incl = line_branch[i]
        active = all(br["taken"] is True for _, br in incl)
        if active:
            for node, _br in incl:
                g = node_guard_class(node)
                if g:
                    return True, g
            return True, "none"
        for node, br in incl:
            if br["taken"] is not True:
                return False, node_guard_class(node) or "none"
        return False, "none"

    for row in defines + undefs + includes + defined_occurrences:
        row["taken"] = taken_at(row["line"] - 1)

    # Deduplicate defined() occurrences that were recorded more than once on one line.
    seen_def: set[tuple] = set()
    unique_def: list[dict] = []
    for row in defined_occurrences:
        key = (row["line"], row["name"])
        if key in seen_def:
            continue
        seen_def.add(key)
        unique_def.append(row)
    defined_occurrences = unique_def

    # Evidence counters over content lines.
    active_classes: Counter = Counter()
    skipped_classes: Counter = Counter()
    live_content = 0
    skipped_content = 0
    skipped_ranges: list[dict] = []
    run_start: int | None = None
    for i in range(n):
        if not content[i]:
            if run_start is not None:
                skipped_ranges.append({"start": run_start + 1, "end": i})
                run_start = None
            continue
        active, cls = guard_at(i)
        if active:
            live_content += 1
            active_classes[cls] += 1
            if run_start is not None:
                skipped_ranges.append({"start": run_start + 1, "end": i})
                run_start = None
        else:
            skipped_content += 1
            skipped_classes[cls] += 1
            if run_start is None:
                run_start = i
    if run_start is not None:
        skipped_ranges.append({"start": run_start + 1, "end": n})

    conditionals = []
    for node in nodes:
        for br in node["branches"]:
            last = br["last"] if br["last"] is not None else n - 1
            dead = sum(1 for j in range(br["first"], last + 1) if content[j] and not taken_at(j))
            conditionals.append({
                "kind": br["kind"],
                "line": br["line"],
                "condition": br["condition"],
                "taken": br["taken"],
                "dead_content_lines": dead,
            })
    conditionals.sort(key=lambda c: (c["line"], c["kind"]))

    macros_of_interest = [
        {"name": nm, "defined": nm in macros, "value": macros.get(nm)}
        for nm in sorted(interest) if nm
    ]

    return {
        "defines": sorted(defines, key=lambda d: (d["line"], d["macro"])),
        "undefs": sorted(undefs, key=lambda d: (d["line"], d["macro"])),
        "includes": sorted(includes, key=lambda d: (d["line"], d["path"])),
        "conditionals": conditionals,
        "skipped_ranges": skipped_ranges,
        "defined_occurrences": sorted(defined_occurrences, key=lambda d: (d["line"], d["name"])),
        "macros_of_interest": macros_of_interest,
        "evidence": {
            "live_content_lines": live_content,
            "skipped_content_lines": skipped_content,
            "active_guard_classes": dict(sorted(active_classes.items())),
            "skipped_guard_classes": dict(sorted(skipped_classes.items())),
        },
    }


# ---------------------------------------------------------------------------
# classification (pure)
# ---------------------------------------------------------------------------

def classify_surface(path: str, *, origin: str, suffix: str, compiled: bool,
                     evidence: dict | None) -> str:
    """One authority source surface to one of the plan's classes. A pure function.

    Path and suffix rules are the plan's own kinds (`test/`, `demos/`, generated build-tree
    files, perlasm) and take precedence; the conditional evidence decides the rest.
    """
    base = path.rsplit("/", 1)[-1].lower()
    if path.startswith(("test/", "fuzz/")):
        return "test-only"
    if path.startswith(("demos/", "doc/")):
        return "demo-only"
    if path.startswith("ms/"):
        return "platform-specific"
    if suffix in (".s", ".S"):
        return "assembly-alternative"
    if origin == "generated":
        return "generated-only"
    if "fips" in base:
        return "fips-only"
    if "deprecated" in base:
        return "deprecated-only"
    if compiled and evidence is not None:
        live = evidence.get("live_content_lines", 0)
        skipped = evidence.get("skipped_content_lines", 0)
        if live == 0 and skipped > 0:
            cls = _dominant_guard_class(evidence.get("skipped_guard_classes") or {})
            return cls or "excluded-by-production-profile"
        cls = _dominant_guard_class(evidence.get("active_guard_classes") or {})
        return cls or "active-production"
    # A source file the profile never compiles. A `.c`/`.cc`/... unit is a surface the
    # production build deliberately leaves out (a disabled algorithm, an unused provider
    # implementation); a header is declaration surface consumed by whatever includes it and
    # is treated as part of the active surface by default.
    if suffix in (".c", ".cc", ".cpp", ".cxx", ".m"):
        return "excluded-by-production-profile"
    return "active-production"


# ---------------------------------------------------------------------------
# body assembly (pure)
# ---------------------------------------------------------------------------

def _merge_evidence(units: list[dict]) -> dict[str, dict]:
    """Per-source evidence summed across the source's logical translation units."""
    merged: dict[str, dict] = {}
    for u in units:
        ev = u.get("evidence") or {}
        m = merged.setdefault(u["source"], {"live": 0, "skipped": 0,
                                            "active": Counter(), "skipped_classes": Counter()})
        m["live"] += ev.get("live_content_lines", 0)
        m["skipped"] += ev.get("skipped_content_lines", 0)
        for k, v in (ev.get("active_guard_classes") or {}).items():
            m["active"][k] += v
        for k, v in (ev.get("skipped_guard_classes") or {}).items():
            m["skipped_classes"][k] += v
    return merged


def build_body(units: list[dict], sources: list[dict]) -> dict:
    """The atlas body from the per-unit records and the source census. A pure function.

    `RT-PHASE22-CONDITIONAL` calls this on the committed artefact's own rows and on
    controlled in-memory mutations, so it must stay free of I/O and ambient state.
    """
    units_sorted = sorted(units, key=lambda u: (u["source"], u.get("analysis", "")))
    merged = _merge_evidence(units_sorted)

    sources_out: list[dict] = []
    for s in sorted(sources, key=lambda x: x["path"]):
        ev = None
        if s.get("compiled"):
            m = merged.get(s["path"])
            if m is not None:
                ev = {
                    "live_content_lines": m["live"],
                    "skipped_content_lines": m["skipped"],
                    "active_guard_classes": dict(sorted(m["active"].items())),
                    "skipped_guard_classes": dict(sorted(m["skipped_classes"].items())),
                }
        cls = classify_surface(s["path"], origin=s.get("origin", "source"),
                               suffix=s.get("suffix", ""), compiled=bool(s.get("compiled")),
                               evidence=ev)
        sources_out.append({**s, "class": cls})

    class_counts = {c: 0 for c in CLASSES}
    for s in sources_out:
        class_counts[s["class"]] = class_counts.get(s["class"], 0) + 1

    defines = [d for u in units_sorted for d in u.get("defines", [])]
    undefs = [d for u in units_sorted for d in u.get("undefs", [])]
    includes = [d for u in units_sorted for d in u.get("includes", [])]
    conditionals = [d for u in units_sorted for d in u.get("conditionals", [])]
    skipped = [d for u in units_sorted for d in u.get("skipped_ranges", [])]
    defined_occ = [d for u in units_sorted for d in u.get("defined_occurrences", [])]
    interest = [d for u in units_sorted for d in u.get("macros_of_interest", [])]

    counts = {
        "translation_units": len(units_sorted),
        "surfaces": len(sources_out),
        "compiled_surfaces": sum(1 for s in sources_out if s.get("compiled")),
        "macros_defined": len({d["macro"] for d in defines if d.get("taken")}),
        "defines": len(defines),
        "defines_in_skipped_branches": sum(1 for d in defines if not d.get("taken")),
        "undefs": len(undefs),
        "undefs_in_skipped_branches": sum(1 for d in undefs if not d.get("taken")),
        "includes": len(includes),
        "includes_resolved": sum(1 for d in includes if d.get("resolved")),
        "includes_in_skipped_branches": sum(1 for d in includes if not d.get("taken")),
        "conditionals": len(conditionals),
        "conditionals_taken": sum(1 for d in conditionals if d.get("taken") is True),
        "conditionals_skipped": sum(1 for d in conditionals if d.get("taken") is False),
        "conditionals_unresolved": sum(1 for d in conditionals if d.get("taken") is None),
        "skipped_ranges": len(skipped),
        "defined_occurrences": len(defined_occ),
        "macros_of_interest": len({d["name"] for d in interest}),
        "classifications": dict(sorted(class_counts.items())),
    }

    return {
        "units": units_sorted,
        "sources": sources_out,
        "counts": counts,
    }


# ---------------------------------------------------------------------------
# worker
# ---------------------------------------------------------------------------

def _run_clang(extra: list[str], base: list[str], main_abs: str, cwd: str):
    argv = [CLANG] + extra + base + [main_abs]
    proc = subprocess.run(argv, cwd=cwd, capture_output=True, check=False)
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def parse_macro_table(text: str) -> dict:
    macros: dict[str, str] = {}
    for ln in text.splitlines():
        if ln.startswith("#define "):
            rest = ln[len("#define "):]
            m = re.match(r"([A-Za-z_]\w*)(.*)", rest)
            if m:
                macros[m.group(1)] = m.group(2).strip()
    return macros


def _task(payload: dict) -> dict:
    """Preprocess one logical translation unit. Returns a unit record or a failure."""
    cwd = payload["cwd"]
    base = ["-I" + d for d in payload["includes"]] + list(payload["defines"])
    main_abs = payload["main_abs"]

    rc, out, err = _run_clang(["-E"], base, main_abs, cwd)
    if rc != 0:
        reason = (err.strip().splitlines() or ["clang -E failed"])[-1]
        return {"source": payload["source"], "error": reason[:400]}
    live = _live_lines(out, main_abs)

    rc2, mout, _ = _run_clang(["-E", "-dM"], base, main_abs, cwd)
    macros = parse_macro_table(mout) if rc2 == 0 else {}

    try:
        text = Path(main_abs).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:  # noqa: BLE001
        return {"source": payload["source"], "error": f"read: {exc}"[:400]}

    rec = analyze_source(text, live, macros)

    # Resolve the main file's includes against the file's directory and the captured `-I`s.
    main_dir = os.path.dirname(main_abs)
    for inc in rec["includes"]:
        cand = []
        if inc["kind"] == "quote":
            cand.append(os.path.join(main_dir, inc["path"]))
        cand += [os.path.join(d, inc["path"]) for d in payload["include_dirs"]]
        resolved = None
        for c in cand:
            c = os.path.normpath(c)
            if os.path.isfile(c):
                resolved = canon_path(c, Path(payload["src_root"]), Path(payload["build_dir"]))
                break
        inc["resolved"] = resolved

    rec["source"] = payload["source"]
    rec["analysis"] = "preprocessed"
    rec["final_macro_count"] = len(macros)
    rec["profile_gating_macros"] = sorted(n for n in macros if _is_gating_macro(n))
    return rec


def _build_jobs(c_units, resolved, captured_dir, build_dir, src_root, jobs):
    payloads = []
    failures: list[dict] = []
    for unit, main_abs in zip(c_units, resolved):
        if main_abs is None:
            failures.append({"source": unit["source"], "reason": "source-not-found"})
            continue
        include_dirs = []
        for tok in unit["includes"]:
            inc = resolve_include_dir(tok, captured_dir, build_dir, src_root)
            if inc and inc not in include_dirs:
                include_dirs.append(inc)
        payloads.append({
            "source": canonical_source(unit["source"], captured_dir, build_dir, src_root),
            "raw_source": unit["source"],
            "main_abs": main_abs,
            "includes": include_dirs,
            "include_dirs": include_dirs,
            "defines": unit["defines"],
            "cwd": str(build_dir),
            "src_root": str(src_root),
            "build_dir": str(build_dir),
        })
    if jobs <= 1:
        results = [_task(p) for p in payloads]
    else:
        with concurrent.futures.ProcessPoolExecutor(max_workers=jobs) as pool:
            results = list(pool.map(_task, payloads))
    return results, failures


# ---------------------------------------------------------------------------
# source census
# ---------------------------------------------------------------------------

def canonical_source(source: str, captured_dir, build_dir: Path, src_root: Path) -> str:
    abs_ = resolve_source(source, captured_dir, build_dir, src_root)
    if abs_ is None:
        return os.path.normpath(source.replace("\\", "/"))
    return canon_path(abs_, src_root, build_dir) or source


def tree_census(src_root: Path, build_dir: Path) -> dict[str, dict]:
    """Every source surface in the authority source tree plus its generated build-tree files."""
    out: dict[str, dict] = {}
    if src_root.is_dir():
        for p in sorted(src_root.rglob("*")):
            if not p.is_file() or p.suffix.lower() not in SOURCE_SUFFIXES:
                continue
            rel_path = p.relative_to(src_root).as_posix()
            out[rel_path] = {"path": rel_path, "origin": "source",
                             "suffix": p.suffix}
    if build_dir.is_dir():
        for p in sorted(build_dir.rglob("*")):
            if not p.is_file() or p.suffix.lower() not in (".c", ".s", ".S"):
                continue
            rel_path = p.relative_to(build_dir).as_posix()
            if (src_root / rel_path).exists():
                continue  # the source tree owns this name; only generated files are new
            key = "build/" + rel_path
            out[key] = {"path": key, "origin": "generated", "suffix": p.suffix}
    return out


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def _questions(units, sources_out) -> dict:
    """The plan's two questions, answered from the rows rather than hardcoded."""
    by_source = {s["path"]: s for s in sources_out}
    unit_by_source = {u["source"]: u for u in units}
    exists = next((u for u in units if by_source.get(u["source"], {}).get("class")
                   == "active-production" and u.get("conditionals")), None)

    def guard_lineage(u):
        taken = [c for c in u.get("conditionals", []) if c.get("taken") is True]
        skipped = [c for c in u.get("conditionals", []) if c.get("taken") is False]
        return (f"{len(taken)} conditional branch(es) taken, {len(skipped)} skipped, "
                f"{len(u.get('skipped_ranges', []))} skipped source range(s)")

    why_exists = None
    if exists:
        defs = sorted({d["macro"] for d in exists.get("defines", []) if d.get("taken")})
        why_exists = (
            f"`{exists['source']}` exists in this build because 22.1 captured it as a "
            f"translation unit of the production profile and its content is live under the "
            f"captured `-D` set. Conditional lineage: {guard_lineage(exists)}. The unit's own "
            f"taken `#define`s are {defs or ['none']}; no enclosing guard of its live content "
            "is fips, platform or deprecation scoped, which is why it classifies "
            "`active-production` rather than a scoped class. This is the conditional lineage "
            "the plan requires in place of a configuration guess."
        )

    # Prefer a surface that was actually compiled and then preprocessed away -- that is the
    # case the plan's question is really about. Fall back to a surface the profile never
    # reaches.
    does_not = next((s for s in sources_out
                     if s["class"] == "excluded-by-production-profile"
                     and s["path"] in unit_by_source), None)
    if does_not is None:
        does_not = next((s for s in sources_out
                         if s["class"] in ("test-only", "demo-only", "assembly-alternative")), None)
    if does_not is None:
        does_not = next((s for s in sources_out
                         if s["class"] == "excluded-by-production-profile"), None)

    why_not = None
    if does_not:
        ev = unit_by_source.get(does_not["path"])
        if does_not["class"] in ("test-only", "demo-only"):
            why_not = (
                f"`{does_not['path']}` does not exist in this build because it lies outside "
                "every compatibility root the production profile compiles: the captured "
                "invocations 22.1 recorded contain no translation unit for it, and its path "
                "is not in the production build's source set. It is not preprocessed away by "
                "a conditional -- it is never reached."
            )
        elif does_not["class"] == "assembly-alternative":
            why_not = (
                f"`{does_not['path']}` does not exist as C in this build because it is a "
                "perlasm/assembly surface (`.s`/`.S`): Clang cannot preprocess it, and it is "
                "compiled into the object graph that 22.6 reads, not the C conditional graph "
                "this plane reads."
            )
        elif ev is not None:
            skipped = [c for c in ev.get("conditionals", []) if c.get("taken") is False]
            evid = ev.get("evidence", {})
            why_not = (
                f"`{does_not['path']}` exists as source but not as compiled surface: every "
                f"content line is preprocessed away under this profile "
                f"({evid.get('skipped_content_lines', 0)} skipped, "
                f"{evid.get('live_content_lines', 0)} live). The guarding conditionals that "
                f"evaluated false are {[c['condition'] for c in skipped][:4] or ['none recorded']}; "
                "a false guard that is not a platform/fips/deprecation guard is why the class is "
                "`excluded-by-production-profile` and not one of the scoped classes."
            )
        else:
            why_not = (
                f"`{does_not['path']}` exists in the authority source tree but is never "
                "compiled by the production profile: 22.1's capture contains no translation "
                "unit for it, so its conditional lineage is *not reached* rather than "
                "*preprocessed away*, and it classifies `excluded-by-production-profile`."
            )
    return {"why_this_exists": why_exists, "why_this_does_not": why_not}


def _scrub_scratch(obj: Any, needle: str | None) -> Any:
    """Replace the captured build's scratch directory in every recorded string.

    The authority's captured profile defines `OPENSSLDIR`/`ENGINESDIR`/`MODULESDIR` to the
    scratch prefix 22.1's transparent wrapper rebuilt under. Those are facts about *that*
    capture, not about the source, and a scratch path must not enter a committed artefact,
    so the directory is replaced with a stable placeholder rather than dropped silently.
    """
    if not needle:
        return obj
    if isinstance(obj, dict):
        return {k: _scrub_scratch(v, needle) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_scrub_scratch(v, needle) for v in obj]
    if isinstance(obj, str):
        return obj.replace(needle, "<capture-dir>")
    return obj


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument("--capture", default=CAPTURE_REL)
    ap.add_argument("--jobs", type=int, default=DEFAULT_JOBS,
                    help="parallel Clang workers (default: %(default)s)")
    ap.add_argument("--limit", type=int, default=0,
                    help="preprocess only the first N logical C units (measurement aid)")
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    src_root = auth.source
    build_dir = REPO_ROOT / BUILD_DIR_REL
    capture_path = REPO_ROOT / args.capture
    if not capture_path.is_file():
        raise SystemExit(
            f"phase22-conditional: 22.1's capture is missing: {rel(capture_path)}; run "
            "forensics/tools/phase22_build_commands.py first"
        )
    capture_body = load_capture_body(capture_path)
    captured_dir = capture_body.get("directory")

    producer = "unknown"
    configdata = build_dir / "configdata.pm"
    if configdata.is_file():
        m = re.search(r'^\s*"CC"\s*=>\s*"([^"]*)"', configdata.read_text(encoding="utf-8",
                                                                       errors="replace"),
                      re.MULTILINE)
        producer = m.group(1) if m and m.group(1) else "unknown"

    c_units, non_c_units = logical_tus(capture_body)
    total_c = len(c_units)
    if args.limit:
        c_units = c_units[:args.limit]

    print(f"[phase22-conditional] {len(capture_body.get('commands', []))} captured invocations "
          f"-> {len(c_units)}/{total_c} logical C units (+{len(non_c_units)} assembly), "
          f"jobs={args.jobs}")

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
        units.append(r)

    # Source census: the tree's own files plus every generated file the build created.
    census = tree_census(src_root, build_dir)
    captured = {canonical_source(u["source"], captured_dir, build_dir, src_root)
                for u in logical_tus(capture_body)[0]}
    captured |= {canonical_source(u["source"], captured_dir, build_dir, src_root)
                 for u in non_c_units}
    for path in captured:
        if path not in census:
            census[path] = {"path": path, "origin": "generated" if path.startswith("build/")
                            else "source", "suffix": os.path.splitext(path)[1]}
    sources = list(census.values())
    for s in sources:
        s["compiled"] = s["path"] in captured

    body = build_body(units, sources)
    body = _scrub_scratch(body, captured_dir)

    body["producer"] = producer
    body["analysis_instrument"] = CLANG
    body["analysis_instrument_note"] = (
        "Clang is a shadow analysis instrument only. The production authority is GCC-built "
        f"(configdata.pm CC={producer!r}); the captured invocations are replayed to Clang to "
        "read the preprocessor, which never redefines the authority as a Clang build "
        "(docs/PHASE-22-SUBPHASES.md section 6). `producer` and `analysis_instrument` are two "
        "different facts and both are recorded."
    )
    body["capture_method"] = "execution-captured"
    body["instrument"] = INSTRUMENT
    body["classification_vocabulary"] = list(CLASSES)
    body["classification_rules"] = (
        "Path/suffix rules first: `test/` and `fuzz/` are `test-only`; `demos/` and `doc/` are "
        "`demo-only`; `ms/` is `platform-specific`; `.s`/`.S` are `assembly-alternative`; a file "
        "that exists only in the pinned build tree is `generated-only`; a basename naming fips "
        "or deprecation is that scoped class. Remaining compiled sources are classified by "
        "conditional lineage: no live content means the file's whole body was preprocessed away, "
        "and the outermost false guard's class decides `platform-specific`/`fips-only`/"
        "deprecated-only` or `excluded-by-production-profile`; live content is `active-production` "
        "unless every live content line sits under a single platform/fips/deprecation guard. "
        "A `.c` source the profile never compiles is `excluded-by-production-profile`; "
        "non-compiled headers fall through to `active-production`."
    )
    body["questions"] = _questions(body["units"], body["sources"])
    body["roots"] = {"source": rel(src_root), "build": rel(build_dir)}
    body["counts"]["parsed"] = parsed
    body["counts"]["failed"] = len(failures)
    body["counts"]["captured_c_invocations"] = sum(
        1 for cmd in capture_body.get("commands", []) if is_c_source(cmd.get("source") or ""))
    body["counts"]["non_c_translation_units"] = len(non_c_units)
    body["counts"]["distinct_captured_sources"] = len(captured)

    gating: set[str] = set()
    for u in units:
        gating.update(u.get("profile_gating_macros", []))
    body["profile_gating_macros"] = sorted(gating)
    body["counts"]["profile_gating_macros"] = len(gating)

    body["coverage"] = {
        "translation_units_attempted": len(c_units),
        "translation_units_total": total_c,
        "parsed": parsed,
        "failed": len(failures),
        "non_c_translation_units": [
            {"source": u["source"], "suffix": suffix_of(u["source"]), "reason": "not-a-c-ast"}
            for u in non_c_units
        ],
        "scope": (
            "Per translation unit the recorded directives, conditionals and skipped ranges are "
            "those of the unit's *own main file*; header conditionals are consumed by Clang's "
            "preprocessor (they determine the live-line coverage) but are not re-emitted once "
            "per including unit, because they are the header surface and emitting them per "
            "inclusion would duplicate them a thousand times. The census still classifies every "
            "header and every non-compiled source in the tree."
        ),
        "reduction": (
            f"{total_c - len(c_units)} of {total_c} logical C units were not preprocessed"
            if args.limit else "none; every logical C unit was replayed in full"
        ),
        "macro_table": (
            "The final macro table (`clang -E -dM`) is per-TU; the body records the value of "
            "every macro of interest per unit, the per-unit table size, and the union of the "
            "gating macros (`OPENSSL_NO_*`, `OPENSSL_SYS_*`, `OPENSSL_USE_*`, `*FIPS*`, "
            "`*DEPRECATED*`, `NDEBUG`, `OPENSSL_BUILDING_OPENSSL`) rather than materializing the "
            "full ~10^4-name union, which would transfer tens of millions of names for a count. "
            "The captured build's scratch prefix, which its own profile bakes into "
            "`OPENSSLDIR`/`ENGINESDIR`/`MODULESDIR`, is replaced with `<capture-dir>` so no "
            "scratch path enters the committed artefact."
        ),
    }
    body["failures"] = sorted(failures, key=lambda f: (f["source"] or "", f["reason"]))
    body["sort_key"] = ("units by (source, analysis); sources by path; "
                        "every row list sorted by (line, name)")

    inputs = [InputRef(name="compile-commands", path=capture_path)]
    raw_path = REPO_ROOT / "forensics/atlas/phase22/raw/compile-commands.jsonl"
    if raw_path.is_file():
        inputs.append(InputRef(name="raw-compile-commands", path=raw_path))
    doc = envelope(kind="phase22-conditional-surface", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(REPO_ROOT / OUT_REL, doc)

    c = body["counts"]
    print(f"[phase22-conditional] instrument={INSTRUMENT}")
    print(f"  translation_units={c['translation_units']} parsed={c['parsed']} "
          f"failed={c['failed']} surfaces={c['surfaces']}")
    print(f"  macros_defined={c['macros_defined']} defines={c['defines']} "
          f"(skipped-branch {c['defines_in_skipped_branches']}) includes={c['includes']} "
          f"(resolved {c['includes_resolved']})")
    print(f"  conditionals={c['conditionals']} (taken {c['conditionals_taken']}, "
          f"skipped {c['conditionals_skipped']}, unresolved {c['conditionals_unresolved']}) "
          f"skipped_ranges={c['skipped_ranges']} defined_occurrences={c['defined_occurrences']}")
    print(f"  classifications={c['classifications']}")
    print(f"  -> {rel(REPO_ROOT / OUT_REL)}")
    return 0


# ---------------------------------------------------------------------------
# the court
# ---------------------------------------------------------------------------

def _new_unit(source: str) -> dict:
    return {"source": source, "analysis": "preprocessed", "defines": [], "undefs": [],
            "includes": [], "conditionals": [], "skipped_ranges": [],
            "defined_occurrences": [], "macros_of_interest": [],
            "evidence": {"live_content_lines": 0, "skipped_content_lines": 0,
                         "active_guard_classes": {}, "skipped_guard_classes": {}}}


def court_conditional(body: dict) -> dict:
    """`RT-PHASE22-CONDITIONAL`: the recorder's and classifier's own sensitivity.

    Round-trips the committed body (re-derive it from its own rows and require equality),
    then drives it over controlled mutations: add a macro definition; add a definition under
    an **untaken** branch (which must not raise the taken-macro count); add an include; add
    a conditional with a skipped range; move a surface between classifications by moving its
    guard evidence; and add a path-classified surface. It fails if the recording or
    classification logic is insensitive to any of those.
    """
    import copy

    checks: list[tuple[str, bool]] = []
    units = copy.deepcopy(body["units"])
    sources = copy.deepcopy(body["sources"])

    checks.append(("baseline: the artefact has translation units", len(units) > 0))
    checks.append(("baseline: the artefact has surfaces", len(sources) > 0))
    checks.append(("baseline: the artefact has conditionals",
                   body["counts"]["conditionals"] > 0))

    rebuilt = build_body(copy.deepcopy(units), copy.deepcopy(sources))
    checks.append(("round-trip: units equal", rebuilt["units"] == body["units"]))
    checks.append(("round-trip: sources equal", rebuilt["sources"] == body["sources"]))
    derived = {k: v for k, v in body["counts"].items() if k in rebuilt["counts"]}
    checks.append(("round-trip: derived counts equal", derived == rebuilt["counts"]))
    for required in ("translation_units", "macros_defined", "includes", "conditionals",
                     "skipped_ranges", "classifications"):
        checks.append((f"baseline: counts.{required} present", required in body["counts"]))

    base = rebuilt
    target = next((u for u in units if u["source"]), units[0])

    # 1. add a macro definition (taken) -- the distinct-macro count rises by one.
    mutated = copy.deepcopy(units)
    _unit_for(mutated, target["source"])["defines"].append(
        {"macro": "PHASE22_SYNTHETIC_MACRO", "value": "1", "line": 10_000_001, "taken": True})
    new = build_body(mutated, copy.deepcopy(sources))
    checks.append(("add-macro-definition: defines rose by one",
                   new["counts"]["defines"] == base["counts"]["defines"] + 1))
    checks.append(("add-macro-definition: macros_defined rose by one",
                   new["counts"]["macros_defined"] == base["counts"]["macros_defined"] + 1))

    # 2. add a definition under an UNTAKEN branch -- recorded, but not counted as defined.
    mutated = copy.deepcopy(units)
    _unit_for(mutated, target["source"])["defines"].append(
        {"macro": "PHASE22_DEAD_MACRO", "value": "1", "line": 10_000_002, "taken": False})
    new = build_body(mutated, copy.deepcopy(sources))
    checks.append(("add-dead-define: defines rose by one",
                   new["counts"]["defines"] == base["counts"]["defines"] + 1))
    checks.append(("add-dead-define: macros_defined did NOT rise",
                   new["counts"]["macros_defined"] == base["counts"]["macros_defined"]))
    checks.append(("add-dead-define: skipped-branch defines rose by one",
                   new["counts"]["defines_in_skipped_branches"]
                   == base["counts"]["defines_in_skipped_branches"] + 1))

    # 3. add an include.
    mutated = copy.deepcopy(units)
    _unit_for(mutated, target["source"])["includes"].append(
        {"kind": "angle", "path": "openssl/synthetic.h", "line": 10_000_003,
         "taken": True, "resolved": None})
    new = build_body(mutated, copy.deepcopy(sources))
    checks.append(("add-include: includes rose by one",
                   new["counts"]["includes"] == base["counts"]["includes"] + 1))

    # 4. add a conditional with a skipped range.
    mutated = copy.deepcopy(units)
    u = _unit_for(mutated, target["source"])
    u["conditionals"].append({"kind": "ifdef", "line": 10_000_004,
                              "condition": "PHASE22_NEVER", "taken": False,
                              "dead_content_lines": 3})
    u["skipped_ranges"].append({"start": 10_000_005, "end": 10_000_007})
    new = build_body(mutated, copy.deepcopy(sources))
    checks.append(("add-conditional: conditionals rose by one",
                   new["counts"]["conditionals"] == base["counts"]["conditionals"] + 1))
    checks.append(("add-conditional: skipped conditionals rose by one",
                   new["counts"]["conditionals_skipped"]
                   == base["counts"]["conditionals_skipped"] + 1))
    checks.append(("add-conditional: skipped_ranges rose by one",
                   new["counts"]["skipped_ranges"] == base["counts"]["skipped_ranges"] + 1))

    # 5. move a surface between classifications via its guard evidence.
    #    Take an active-production compiled source and make its whole body platform-skipped.
    move_target = next((s for s in base["sources"]
                        if s["class"] == "active-production" and s.get("compiled")), None)
    if move_target is None:
        checks.append(("move-surface: an active-production compiled source was found", False))
    else:
        mutated_units = copy.deepcopy(units)
        moved = False
        for mu in mutated_units:
            if mu["source"] == move_target["path"]:
                mu["evidence"] = {"live_content_lines": 0, "skipped_content_lines": 7,
                                  "active_guard_classes": {},
                                  "skipped_guard_classes": {"platform": 7}}
                moved = True
        new = build_body(mutated_units, copy.deepcopy(sources))
        now = next((s["class"] for s in new["sources"] if s["path"] == move_target["path"]), None)
        checks.append(("move-surface: the evidence mutation reached a unit", moved))
        checks.append(("move-surface: its class became platform-specific",
                       now == "platform-specific"))
        checks.append(("move-surface: active-production fell by one",
                       new["counts"]["classifications"]["active-production"]
                       == base["counts"]["classifications"]["active-production"] - 1))
        checks.append(("move-surface: platform-specific rose by one",
                       new["counts"]["classifications"]["platform-specific"]
                       == base["counts"]["classifications"]["platform-specific"] + 1))

    # 6. add a path-classified surface -- a `test/` file is test-only by rule.
    mutated_sources = copy.deepcopy(sources)
    mutated_sources.append({"path": "test/phase22_probe.c", "origin": "source",
                            "suffix": ".c", "compiled": False})
    new = build_body(copy.deepcopy(units), mutated_sources)
    checks.append(("add-surface: surfaces rose by one",
                   new["counts"]["surfaces"] == base["counts"]["surfaces"] + 1))
    checks.append(("add-surface: test-only rose by one",
                   new["counts"]["classifications"]["test-only"]
                   == base["counts"]["classifications"]["test-only"] + 1))

    # 7. classifier sensitivity directly: the untaken-branch rule and the guard rule.
    checks.append(("classify: a fips-guarded body is fips-only",
                   classify_surface("crypto/x/y.c", origin="source", suffix=".c", compiled=True,
                                    evidence={"live_content_lines": 0, "skipped_content_lines": 5,
                                              "active_guard_classes": {},
                                              "skipped_guard_classes": {"fips": 5}})
                   == "fips-only"))
    checks.append(("classify: a non-scoped skipped body is excluded-by-production-profile",
                   classify_surface("crypto/x/y.c", origin="source", suffix=".c", compiled=True,
                                    evidence={"live_content_lines": 0, "skipped_content_lines": 5,
                                              "active_guard_classes": {},
                                              "skipped_guard_classes": {"none": 5}})
                   == "excluded-by-production-profile"))
    checks.append(("classify: a perlasm unit is assembly-alternative",
                   classify_surface("crypto/aes/aes-x86_64.s", origin="generated",
                                    suffix=".s", compiled=True, evidence=None)
                   == "assembly-alternative"))
    checks.append(("classify: a generated-only file is generated-only",
                   classify_surface("build/apps/progs.c", origin="generated", suffix=".c",
                                    compiled=True, evidence=None) == "generated-only"))

    # 8. The recording logic itself: `analyze_source` over a synthetic translation unit.
    #    This is what makes the court challenge the recorder, not only the aggregator.
    synth = (
        '#include "a.h"\n'
        "#define ON 1\n"
        "#ifdef ON\n"
        "int live_a;\n"
        "#else\n"
        "#define DEAD 1\n"
        "int dead_a;\n"
        "#endif\n"
        "#if defined(ON)\n"
        "int live_b;\n"
        "#endif\n"
        "#if 0\n"
        "int dead_b;\n"
        "#endif\n"
    )
    rec = analyze_source(synth, {4, 10}, {"ON": "1"})
    dmap = {d["macro"]: d["taken"] for d in rec["defines"]}
    cmap = {(c["kind"], c["condition"]): c["taken"] for c in rec["conditionals"]}
    checks.append(("record: the taken define is taken", dmap.get("ON") is True))
    checks.append(("record: the define under the untaken branch is untaken",
                   dmap.get("DEAD") is False))
    checks.append(("record: the include is recorded",
                   len(rec["includes"]) == 1 and rec["includes"][0]["path"] == "a.h"))
    checks.append(("record: the defined() occurrence is recorded",
                   any(o["name"] == "ON" for o in rec["defined_occurrences"])))
    checks.append(("record: the skipped source ranges are recorded",
                   rec["skipped_ranges"] == [{"start": 7, "end": 7},
                                             {"start": 13, "end": 13}]))
    checks.append(("record: the taken ifdef branch is taken", cmap.get(("ifdef", "ON")) is True))
    checks.append(("record: the else branch is untaken", cmap.get(("else", "")) is False))
    checks.append(("record: the #if 0 branch is untaken", cmap.get(("if", "0")) is False))
    checks.append(("guard: a FIPS macro is fips", macro_guard_class("FIPS_MODULE") == "fips"))
    checks.append(("guard: a deprecation macro is deprecated",
                   macro_guard_class("OPENSSL_NO_DEPRECATED_3_0") == "deprecated"))
    checks.append(("guard: a platform macro is platform",
                   macro_guard_class("__APPLE__") == "platform"))
    checks.append(("guard: a plain macro names no guard",
                   macro_guard_class("OPENSSL_BUILDING_OPENSSL") is None))
    checks.append(("eval: defined() conjunction is true",
                   eval_cond("defined(ON) && 1", {"ON": "1"}) is True))
    checks.append(("eval: a false literal is false", eval_cond("0", {}) is False))
    checks.append(("eval: an undefined macro is false", eval_cond("defined(X)", {}) is False))

    failures = [desc for desc, ok in checks if not ok]
    c = body["counts"]
    return {
        "court": "RT-PHASE22-CONDITIONAL",
        "artefact": ARTEFACT_REL,
        "producer": body.get("producer"),
        "analysis_instrument": body.get("analysis_instrument"),
        "summary": (f"{c.get('translation_units')} TUs, {c.get('surfaces')} surfaces, "
                    f"{c.get('conditionals')} conditionals, {c.get('skipped_ranges')} ranges"),
        "translation_units": c.get("translation_units"),
        "macros_defined": c.get("macros_defined"),
        "includes": c.get("includes"),
        "conditionals": c.get("conditionals"),
        "skipped_ranges": c.get("skipped_ranges"),
        "classifications": c.get("classifications"),
        "mutations": ["round-trip", "add-macro-definition", "add-dead-define", "add-include",
                      "add-conditional", "move-surface", "add-surface", "classify",
                      "record"],
        "observations": len(checks),
        "failures": failures,
        "verdict": "pass" if not failures else "fail",
    }


def _unit_for(units: list[dict], source: str) -> dict:
    for u in units:
        if u["source"] == source:
            return u
    raise KeyError(source)


def courts() -> list[dict]:
    """`RT-PHASE22-CONDITIONAL`, or `[]` while the artefact has not landed."""
    path = REPO_ROOT / ARTEFACT_REL
    if not path.is_file():
        return []
    doc = json.loads(path.read_text(encoding="utf-8"))
    return [court_conditional(doc["body"])]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
