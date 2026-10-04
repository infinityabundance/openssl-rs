#!/usr/bin/env python3
"""openssl-rs — generate the `openssl` CLI dispatch and option tables (`src/apps/tables.rs`).

Why this generator exists
-------------------------
`apps/openssl.c`'s command dispatch is a `functions[]` table (`apps/progs.c`, emitted
by `apps/progs.pl`), and its option-list surface — `openssl list -options <cmd>` —
reads each command's `OPTIONS[]` table (`apps/include/opt.h`). Both are *data*: the
authority's own translation units define them, and they are large (163 `functions[]`
rows, 56 option tables). Transcribing them by hand is not an implementation, it is a
transcription error waiting to happen, exactly as `docs/PARITY_MODEL.md` §5 says of the
`obj_dat.h`/`obj_mac.h` tables `gen_nid_table.py` derives.

What is read, and how
---------------------
The authority's C is passed through the authority's own configured preprocessor
(`cc -E -P`, with the admitted build's include paths), so the `#ifndef OPENSSL_NO_*`
guards select the admitted profile exactly as the authority's own build did. Nothing is
re-derived from a hand-written list of what is enabled:

  * `forensics/authorities/build/openssl-3.6.4-production/apps/progs.c` gives the
    `FUNCTION functions[]` rows (`type`, `name`, `help` table pointer, deprecation);
  * every `forensics/authorities/src/openssl-3.6.4/apps/*.c` gives the `const OPTIONS
    <name>[]` arrays, whose rows are reduced to what the option-list reader reads:
    `name` and `valtype` (`apps/list.c:1151-1163`). The `OPT_HELP_STR`/`OPT_MORE_STR`/
    `OPT_SECTION_STR`/`OPT_PARAM_STR` markers are not options and are dropped here for
    the same reason `list_options_for_command` drops them.

Determinism
-----------
The output records the authority id and the SHA-256 of every input it read; it writes
nothing that depends on wall-clock time, PID, hostname or environment, so a re-run is
byte-identical (`docs/REPRODUCIBILITY.md` §2).

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    resolve_authority,
    sha256_file,
    write_text,
)

OUT = REPO_ROOT / "src" / "apps" / "tables.rs"
GENERATOR = "forensics/tools/gen_cli_tables.py"

SRC = REPO_ROOT / "forensics" / "authorities" / "src" / "openssl-3.6.4"
BUILD = REPO_ROOT / "forensics" / "authorities" / "build"

# The markers `apps/include/opt.h` defines as the pseudo-option names. A row whose
# first field is one of these is not an option.
MARKERS = ("OPT_HELP_STR", "OPT_MORE_STR", "OPT_SECTION_STR", "OPT_PARAM_STR")

_TABLE_DEF = re.compile(r"const\s+OPTIONS\s+([A-Za-z0-9_]+)\s*\[\]\s*=\s*\{")


def preprocess(path: Path, build: Path) -> str:
    """Run the authority's configured preprocessor over one C file.

    The include order is the authority's own: the build's generated headers first
    (`progs.h`, `opensslconf.h`), then the source tree's `include/` and the apps'
    private `apps/include/`.
    """
    argv = [
        "cc", "-E", "-P",
        "-I", str(build / "apps"),
        "-I", str(build / "include"),
        "-I", str(build),
        "-I", str(SRC),
        "-I", str(SRC / "include"),
        "-I", str(SRC / "apps" / "include"),
        str(path),
    ]
    p = subprocess.run(argv, capture_output=True, text=True)
    if p.returncode != 0:
        raise SystemExit(f"{GENERATOR}: preprocessing {path} failed:\n{p.stderr[:2000]}")
    return p.stdout


def brace_groups(body: str) -> list[str]:
    """Split an `{ ... }` array body into its top-level `{ ... }` element groups."""
    groups: list[str] = []
    i = 0
    while i < len(body):
        if body[i] == "{":
            depth = 1
            j = i + 1
            while j < len(body) and depth:
                if body[j] == "{":
                    depth += 1
                elif body[j] == "}":
                    depth -= 1
                j += 1
            groups.append(body[i + 1:j - 1])
            i = j
        else:
            i += 1
    return groups


def split_fields(group: str) -> list[str]:
    """Split an initializer group on top-level commas."""
    fields: list[str] = []
    depth = 0
    cur = []
    for ch in group:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            fields.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        fields.append("".join(cur).strip())
    return fields


def parse_options(text: str) -> dict[str, list[tuple[str, str]]]:
    """Every `const OPTIONS <name>[]` table -> its (name, valtype) rows, in table order."""
    tables: dict[str, list[tuple[str, str]]] = {}
    for m in _TABLE_DEF.finditer(text):
        name = m.group(1)
        i = text.find("{", m.end() - 1)
        depth = 1
        j = i + 1
        while j < len(text) and depth:
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
            j += 1
        body = text[i + 1:j - 1]
        rows: list[tuple[str, str]] = []
        for g in brace_groups(body):
            fields = split_fields(g)
            if not fields:
                continue
            first = fields[0].lstrip("{ ").strip()
            # `list_options_for_command` (apps/list.c:1154-1155) BREAKS at the
            # `OPT_PARAM_STR` marker: the rows after it are positional parameters,
            # not options, and are never listed.
            if first.startswith("OPT_PARAM_STR"):
                break
            if not first.startswith('"'):
                continue
            if any(first.startswith(mk) for mk in MARKERS):
                continue
            if len(fields) < 3:
                continue
            opt_name = first.strip('"')
            if opt_name == "":
                continue
            vt = fields[2].strip()
            m2 = re.match(r"'(\\.|[^'])'", vt)
            val = m2.group(1) if m2 else "-"
            rows.append((opt_name, val))
        tables[name] = rows
    return tables


def parse_functions(text: str) -> list[dict]:
    m = re.search(r"FUNCTION\s+functions\[\]\s*=\s*\{", text)
    if not m:
        raise SystemExit(f"{GENERATOR}: functions[] not found")
    i = text.find("{", m.end() - 1)
    depth = 1
    j = i + 1
    while j < len(text) and depth:
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
        j += 1
    body = text[i + 1:j - 1]
    out: list[dict] = []
    for g in brace_groups(body):
        fields = split_fields(g)
        if len(fields) < 4:
            continue
        kind = fields[0].strip()
        name_m = re.match(r'"([^"]*)"', fields[1].strip())
        if kind not in ("FT_general", "FT_md", "FT_cipher") or name_m is None:
            continue
        table = fields[3].strip()
        dep_alt = None
        dep_ver = None
        if len(fields) >= 5:
            dm = re.match(r'"([^"]*)"', fields[4].strip())
            if dm:
                dep_alt = dm.group(1)
        if len(fields) >= 6:
            dm = re.match(r'"([^"]*)"', fields[5].strip())
            if dm:
                dep_ver = dm.group(1)
        out.append({
            "kind": kind,
            "name": name_m.group(1),
            "table": None if table.startswith("(") else table,
            "dep_alt": dep_alt,
            "dep_ver": dep_ver,
        })
    return out


def rust_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def rust_char(c: str) -> str:
    if c == "\\":
        return "b'\\\\'"
    if c == "'":
        return "b'\\''"
    return f"b'{c}'"


def emit(authority_id: str, funcs: list[dict], tables: dict[str, list[tuple[str, str]]],
         input_hashes: list[str]) -> str:
    lines: list[str] = []
    lines.append("//! GENERATED by forensics/tools/gen_cli_tables.py — do not edit by hand.")
    lines.append("//!")
    lines.append("//! The `openssl` CLI's `functions[]` dispatch table and every command's")
    lines.append("//! `OPTIONS[]` option table, reduced to what `apps/list.c`'s option-list reader")
    lines.append("//! reads (`name` and `valtype`). Derived from the admitted authority's own C")
    lines.append("//! through its own configured preprocessor, so the `OPENSSL_NO_*` guards select")
    lines.append("//! the admitted profile; see the generator's header.")
    lines.append("//!")
    lines.append(f"//! Authority: `{authority_id}`")
    for h in input_hashes:
        lines.append(f"//! Input: `{h}`")
    lines.append("//!")
    lines.append("//! SPDX-License-Identifier: Apache-2.0")
    lines.append("")
    lines.append("/// One row of an authority `OPTIONS[]` table (`apps/include/opt.h`).")
    lines.append("#[derive(Clone, Copy)]")
    lines.append("pub struct Opt {")
    lines.append("    /// `OPTIONS.name`.")
    lines.append("    pub name: &'static str,")
    lines.append("    /// `OPTIONS.valtype`; `0` is rendered as `-` by the option-list reader.")
    lines.append("    pub valtype: u8,")
    lines.append("}")
    lines.append("")
    lines.append("/// `FUNC_TYPE` — `apps/include/function.h`.")
    lines.append("#[derive(Clone, Copy, PartialEq, Eq)]")
    lines.append("pub enum FuncKind {")
    lines.append("    /// `FT_general`.")
    lines.append("    General,")
    lines.append("    /// `FT_md`.")
    lines.append("    Md,")
    lines.append("    /// `FT_cipher`.")
    lines.append("    Cipher,")
    lines.append("}")
    lines.append("")
    lines.append("/// One row of the authority's `functions[]` table.")
    lines.append("#[derive(Clone, Copy)]")
    lines.append("pub struct Func {")
    lines.append("    /// `FUNCTION.name`.")
    lines.append("    pub name: &'static str,")
    lines.append("    /// `FUNCTION.type`.")
    lines.append("    pub kind: FuncKind,")
    lines.append("    /// `FUNCTION.help`, the command's `OPTIONS[]` table (`None` when the")
    lines.append("    /// authority row carries `NULL`).")
    lines.append("    pub options: Option<&'static [Opt]>,")
    lines.append("    /// `FUNCTION.deprecated_alternative`.")
    lines.append("    pub deprecated_alternative: Option<&'static str>,")
    lines.append("    /// `FUNCTION.deprecated_version`.")
    lines.append("    pub deprecated_version: Option<&'static str>,")
    lines.append("}")
    lines.append("")

    used_tables = sorted({f["table"] for f in funcs if f["table"]})
    for tname in used_tables:
        rows = tables.get(tname)
        if rows is None:
            raise SystemExit(f"{GENERATOR}: table {tname} referenced but not defined")
        const = tname.upper()
        lines.append(f"/// `const OPTIONS {tname}[]` — `apps/`.")
        lines.append("#[rustfmt::skip] // one row per authority table row, not rustfmt's struct_lit_width")
        lines.append(f"pub static {const}: &[Opt] = &[")
        for name, vt in rows:
            lines.append(f"    Opt {{ name: {rust_str(name)}, valtype: {rust_char(vt)} }},")
        lines.append("];")
        lines.append("")

    lines.append("/// `FUNCTION functions[]` — `apps/progs.c`, sorted as `prog_init` sorts it")
    lines.append("/// (`apps/openssl.c:543-546`).")
    lines.append("#[rustfmt::skip] // one row per authority table row, not rustfmt's struct_lit_width")
    lines.append("pub static FUNCTIONS: &[Func] = &[")
    order = {"FT_general": 0, "FT_md": 1, "FT_cipher": 2}
    for f in sorted(funcs, key=lambda f: (order[f["kind"]], f["name"])):
        kind = {"FT_general": "FuncKind::General", "FT_md": "FuncKind::Md",
                "FT_cipher": "FuncKind::Cipher"}[f["kind"]]
        opts = f"Some({f['table'].upper()})" if f["table"] else "None"
        alt = f"Some({rust_str(f['dep_alt'])})" if f["dep_alt"] else "None"
        ver = f"Some({rust_str(f['dep_ver'])})" if f["dep_ver"] else "None"
        lines.append(
            f"    Func {{ name: {rust_str(f['name'])}, kind: {kind}, options: {opts}, "
            f"deprecated_alternative: {alt}, deprecated_version: {ver} }},"
        )
    lines.append("];")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    build = BUILD / auth.id

    progs = preprocess(build / "apps" / "progs.c", build)
    funcs = parse_functions(progs)

    tables: dict[str, list[tuple[str, str]]] = {}
    input_hashes: list[str] = []
    for src in sorted((SRC / "apps").glob("*.c")):
        text = preprocess(src, build)
        found = parse_options(text)
        for k, v in found.items():
            tables.setdefault(k, v)
        input_hashes.append(f"{src.relative_to(REPO_ROOT).as_posix()} sha256 {sha256_file(src)}")
    input_hashes.append(
        f"{(build / 'apps' / 'progs.c').relative_to(REPO_ROOT).as_posix()} "
        f"sha256 {sha256_file(build / 'apps' / 'progs.c')}"
    )

    OUT.parent.mkdir(parents=True, exist_ok=True)
    write_text(OUT, emit(auth.id, funcs, tables, input_hashes))
    print(f"[gen_cli_tables] {OUT.relative_to(REPO_ROOT)} "
          f"functions={len(funcs)} tables={len({f['table'] for f in funcs if f['table']})}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
