#!/usr/bin/env python3
"""openssl-rs — generate the authority's `ERR_raise*` coordinates.

Why this exists
---------------
`ERR_raise(lib, reason)` is a macro:

    #define ERR_raise_data                                        \\
        (ERR_new(),                                               \\
            ERR_set_debug(OPENSSL_FILE, OPENSSL_LINE, OPENSSL_FUNC), \\
            ERR_set_error)

so every error the authority raises also records **where in the authority source
it was raised**: the translation unit, the line of the raise, and the enclosing
function. Those three strings are readable by any caller through
`ERR_get_error_all` / `ERR_peek_error_all`, and by `ERR_print_errors`. They are
therefore part of the observed contract, not private archaeology.

This tool derives them mechanically instead of transcribing them:

  * the `__FILE__` prefix is computed from the admitted build record
    (`relpath(source_tree, build_dir)`), because the authority was built
    out-of-tree and the compiler's `__FILE__` is the source path *as spelled on
    the command line*;
  * the line number is the line of the raise call in the pinned source;
  * the function name is the enclosing function, which is what `OPENSSL_FUNC`
    (`__func__`) expands to;
  * `lib` and `reason` are resolved by compiling a one-off C program against the
    authority's own headers, so the numbers are the authority's numbers and not
    a transcription of the header arithmetic.

Scope
-----
The file list below is the *subsystem set of the phase being closed*. Every
authority file that raises errors belongs in the obligation set; a phase adds
the files it implements. Sites in files not yet listed remain registered
obligations of a later phase, and `forensics/atlas/err-raise-sites.json`
records which files are covered so the uncovered remainder is visible rather
than implied.

Outputs
-------
  forensics/atlas/err-raise-sites.json   the machine-readable atlas document
  src/runtime/err_sites.rs               the Rust constants the runtime uses

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    authority_build_dir,
    envelope,
    rel,
    resolve_authority,
    run,
    write_json,
    write_text,
)

OUT_JSON = REPO_ROOT / "forensics" / "atlas" / "err-raise-sites.json"
OUT_RS = REPO_ROOT / "src" / "runtime" / "err_sites.rs"

# The authority files whose raise sites this phase reconstructs. Each entry is
# (path relative to the authority source tree, Rust-style stem for the
# generated constant names).
COVERED_FILES = [
    ("crypto/stack/stack.c", "STACK"),
    ("crypto/ex_data.c", "EX_DATA"),
    ("crypto/init.c", "INIT"),
]

# Raise macros, in the forms the authority actually spells them. `ERR_raise`
# and `ERR_raise_data` are the modern entry points; `<LIB>err(...)` are the
# per-library aliases defined in err.h and both route through `ERR_raise_data`.
RAISE_RE = re.compile(
    r"(?P<macro>ERR_raise_data|ERR_raise|[A-Z][A-Za-z0-9_]*err)\s*\("
)
# A function definition: a line starting at column 0 with an identifier-ish
# token, reaching an opening paren. Continuation lines of a multi-line
# signature start with whitespace, so anchoring at column 0 is enough.
FUNC_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_ \t*]*?([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def relpath_prefix(source: Path, build_dir: Path) -> str:
    """The `__FILE__` prefix the authority's compiler would have used."""
    return os.path.relpath(str(source.resolve()), str(build_dir.resolve())) + "/"


def enclosing_function(lines: list[str], lineno: int) -> str:
    """Name of the function whose body contains `lineno` (1-based)."""
    best = None
    for i in range(lineno - 1):
        m = FUNC_RE.match(lines[i])
        if m:
            best = m.group(1)
    if best is None:
        raise SystemExit(f"no enclosing function found for line {lineno}")
    # `if`/`while`/`for` at column 0 are not function definitions; the authority
    # never spells them at column 0, but guard anyway.
    if best in {"if", "while", "for", "switch", "return"}:
        raise SystemExit(f"refusing to treat `{best}` as a function at {lineno}")
    return best


def balanced_call(lines: list[str], start: int, open_paren_col: int) -> tuple[str, int]:
    """Return (call text, first line number) for the call beginning at `start`."""
    text = ""
    depth = 0
    first = start
    i = start
    col = open_paren_col
    while i < len(lines):
        line = lines[i]
        seg = line[col:] if i == start else line
        text += (" " if text else "") + seg
        for ch in seg:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return text, first
        i += 1
        col = 0
    raise SystemExit(f"unbalanced call starting at line {start + 1}")


def split_args(call: str) -> list[str]:
    """Split the macro argument list, respecting nesting and string literals."""
    inner = call[call.index("(") + 1 : call.rindex(")")]
    out, cur, depth, in_str, in_chr, esc = [], "", 0, False, False, False
    for ch in inner:
        if in_str:
            cur += ch
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if in_chr:
            cur += ch
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == "'":
                in_chr = False
            continue
        if ch == '"':
            in_str = True
            cur += ch
        elif ch == "'":
            in_chr = True
            cur += ch
        elif ch in "([{":
            depth += 1
            cur += ch
        elif ch in ")]}":
            depth -= 1
            cur += ch
        elif ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def scan(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    sites: list[dict] = []
    i = 0
    while i < len(lines):
        m = RAISE_RE.search(lines[i])
        if not m:
            i += 1
            continue
        call, _ = balanced_call(lines, i, m.start())
        args = split_args(call)
        if len(args) < 2:
            raise SystemExit(f"{path}:{i + 1}: unparsable raise call: {call!r}")
        macro = m.group("macro")
        # ERR_raise / <LIB>err carry an implicit library argument for the
        # per-library aliases; those are defined in err.h as
        # `#define X509err(f, r) ERR_raise_data(ERR_LIB_X509, (r), NULL)`,
        # so the explicit two-argument form only occurs for ERR_raise itself.
        if macro == "ERR_raise" or macro == "ERR_raise_data":
            lib_sym, reason_sym = args[0], args[1]
        else:
            lib_sym = "ERR_LIB_" + macro[: -len("err")]
            reason_sym = args[0]
        sites.append(
            {
                "file": rel(path),
                "line": i + 1,
                "function": enclosing_function(lines, i + 1),
                "macro": macro,
                "lib_symbol": lib_sym,
                "reason_symbol": reason_sym,
                "data_format": args[2] if len(args) > 2 and "NULL" not in args[2] else None,
            }
        )
        i += 1
    return sites


def resolve_symbols(authority, symbols: list[str], work: Path) -> dict[str, int]:
    """Ask the authority's own headers what each symbol evaluates to."""
    src = work / "resolve_err_symbols.c"
    body = ["#include <openssl/err.h>", "#include <openssl/cryptoerr.h>", "#include <stdio.h>", ""]
    body.append("int main(void) {")
    seen = []
    for s in symbols:
        if s in seen:
            continue
        seen.append(s)
        body.append(f'    printf("{s}=%lld\\n", (long long)({s}));')
    body.append("    return 0;")
    body.append("}")
    write_text(src, "\n".join(body) + "\n")

    binp = work / "resolve_err_symbols"
    include = authority.prefix / "include"
    libdir = authority.libdir
    res = run(
        [
            "clang",
            "-std=c11",
            "-I",
            str(include),
            "-o",
            str(binp),
            str(src),
        ]
    )
    if not res.ok:
        raise SystemExit("failed to build the symbol resolver:\n" + res.stderr)
    res = run([str(binp)])
    if not res.ok:
        raise SystemExit("failed to run the symbol resolver:\n" + res.stderr)
    out: dict[str, int] = {}
    for line in res.stdout.splitlines():
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = int(v.strip())
    missing = [s for s in seen if s not in out]
    if missing:
        raise SystemExit("symbols not resolved: " + ", ".join(missing))
    return out


def const_name(stem: str, line: int) -> str:
    return f"{stem}_{line}"


def c_literal(s: str) -> str:
    return 'c"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_rust(doc: dict, prefix: str) -> str:
    sites = doc["body"]["sites"]
    out = [
        "//! Authority `ERR_raise*` coordinates — GENERATED, do not edit.",
        "//!",
        "//! Regenerate with `forensics/tools/gen_err_raise_sites.py` inside the",
        "//! court container. See `forensics/atlas/err-raise-sites.json` for the",
        "//! machine-readable form and `docs/ERROR_MODEL.md` for why these strings",
        "//! are part of the contract rather than private archaeology.",
        "//!",
        f"//! Authority: `{doc['authority']}`; `__FILE__` prefix `{prefix}`.",
        "",
        "use core::ffi::{c_int, CStr};",
        "",
        "/// One recorded authority raise site: where `ERR_raise*` ran, and with what.",
        "#[derive(Clone, Copy, Debug)]",
        "pub(crate) struct ErrSite {",
        "    /// `OPENSSL_FILE` — the authority's translation unit, as the compiler",
        "    /// spelled it. Derived from the admitted build record, never hand-typed.",
        "    pub file: &'static CStr,",
        "    /// `OPENSSL_LINE`.",
        "    pub line: c_int,",
        "    /// `OPENSSL_FUNC`.",
        "    pub func: &'static CStr,",
        "    /// `ERR_GET_LIB` of the raised code.",
        "    pub lib: c_int,",
        "    /// The raised reason, including any `ERR_RFLAG_*` bits.",
        "    pub reason: c_int,",
        "}",
        "",
    ]
    for s in sites:
        out.append(
            f"/// `{s['function']}` at `{s['rel_source']}:{s['line']}` "
            f"({s['reason_symbol']})."
        )
        out.append(f"pub(crate) const {s['const_name']}: ErrSite = ErrSite {{")
        out.append(f"    file: {c_literal(s['file'])}, line: {s['line']},")
        out.append(f"    func: {c_literal(s['function'])},")
        out.append(f"    lib: {s['lib']}, reason: {s['reason']},")
        out.append("};")
        out.append("")

    out += [
        "/// Every recorded raise site, in authority source order.",
        "///",
        "/// This is the complete inventory for the covered files, including the",
        "/// allocation-failure arms that no runtime path in this crate can reach",
        "/// (`sk_reserve`'s growth overflow and the two `ex_data.c` stack-growth",
        "/// arms). It is kept so that coverage accounting, cross-checks and the",
        "/// court's negative controls can enumerate the authority's sites rather",
        "/// than a subset, which is also why it carries an `allow`: it is a",
        "/// reference table, not a call site.",
        "#[allow(dead_code)]",
        "pub(crate) static ALL: &[ErrSite] = &[",
    ]
    for s in sites:
        out.append(f"    {s['const_name']},")
    out += ["];", ""]
    return "\n".join(out)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    build_dir = authority_build_dir(auth.id)
    prefix = relpath_prefix(auth.source, build_dir)

    all_sites: list[dict] = []
    for rel_source, stem in COVERED_FILES:
        path = auth.source / rel_source
        if not path.is_file():
            raise SystemExit(f"authority file missing: {path}")
        for s in scan(path):
            s["rel_source"] = rel_source
            s["const_name"] = const_name(stem, s["line"])
            all_sites.append(s)

    symbols: list[str] = []
    for s in all_sites:
        symbols.append(s["lib_symbol"])
        symbols.append(s["reason_symbol"])
    symbols.append("ERR_LIB_SYS")

    work = REPO_ROOT / "court" / "err-sites"
    work.mkdir(parents=True, exist_ok=True)
    values = resolve_symbols(auth, symbols, work)

    for s in all_sites:
        s["lib"] = values[s["lib_symbol"]]
        s["reason"] = values[s["reason_symbol"]]
        # The `__FILE__` the authority's compiler saw.
        s["file"] = prefix + s["rel_source"]

    body = {
        "prefix": prefix,
        "covered_files": [f for f, _ in COVERED_FILES],
        "sites": all_sites,
        "counts": {"sites": len(all_sites)},
        "note": (
            "`file` is the authority's `__FILE__` string, derived from "
            "relpath(source_tree, build_dir) of the admitted build record. It is "
            "a build artifact of the forensic build, reproduced exactly rather "
            "than normalized away, so the candidate's ERR records compare "
            "byte-for-byte with the authority's."
        ),
    }

    inputs = [
        InputRef(name=f"authority:{rel_source}", path=auth.source / rel_source)
        for rel_source, _ in COVERED_FILES
    ]
    build_records = REPO_ROOT / "forensics" / "authorities" / "BUILD_RECORDS.json"
    if build_records.exists():
        inputs.append(InputRef(name="build-record", path=build_records))
    doc = envelope(
        kind="err-raise-sites",
        authority=auth.id,
        inputs=inputs,
        body=body,
        generator="forensics/tools/gen_err_raise_sites.py",
    )
    write_json(OUT_JSON, doc)
    write_text(OUT_RS, render_rust(doc, prefix))

    print(f"[err-raise-sites] authority={auth.id} prefix={prefix}")
    print(f"  sites: {len(all_sites)}")
    for s in all_sites:
        print(f"    {s['rel_source']}:{s['line']:<5} {s['function']} "
              f"({s['lib_symbol']}, {s['reason_symbol']} = {s['lib']}, {s['reason']})")
    print(f"  wrote {rel(OUT_JSON)}")
    print(f"  wrote {rel(OUT_RS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
