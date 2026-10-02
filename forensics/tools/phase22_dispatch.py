#!/usr/bin/env python3
"""openssl-rs -- Phase 22.7 indirect dispatch, callback and registration graph.

`docs/PHASE-22-SUBPHASES.md` section 3 is the reason this subphase exists, and it names
the motivating example verbatim:

    static const OSSL_DISPATCH foo_functions[] = {
        { OSSL_FUNC_FOO_NEWCTX, (void (*)(void))foo_newctx },
    };

"There is no `foo()->foo_newctx()` edge anywhere in the source. The architecture *is* the
table." Section 6 then gives the rule: "**22.7** exists because the architecture of this
library is function-pointer tables." A call graph is not enough; this plane records the
**typed** indirect edges a header-only or call-graph view cannot see.

What is extracted
-----------------
The authority's source tree is scanned (lexically, with a real C tokenizer, not a regex
over lines) for the table families the plan names, and every `(slot, function)` pair that
bears a function pointer becomes an edge of one of the plan's typed kinds:

    DISPATCH_SLOT     OSSL_DISPATCH / OSSL_ALGORITHM / OSSL_ALGORITHM_CAPABLE /
                      OSSL_PARAM tables. The providers (base, default, legacy, null and
                      `providers/implementations/**`) and the `crypto/` built-in method
                      tables (digest, mac, kdf, keymgmt, signature, exchange, encoder,
                      decoder, store). A row is `{ OSSL_FUNC_x, (void (*)(void))f }`.
    CALLBACK_SLOT     `X509V3_EXT_METHOD *standard_exts[]`, the `EVP_PKEY_ASN1_METHOD
                      *standard_methods[]` legacy table, `X509V3_EXT_METHOD` and
                      `ASN1_AUX` struct initializers, and the `ASN1_SEQUENCE_ref/enc/cb`
                      item macros whose callback argument is an `ASN1_AUX` slot.
    REGISTRATION      provider `OSSL_provider_init` entrypoints, `X509_LOOKUP_METHOD`
                      rows, `X509_TRUST` rows (`trstandard[]`), `X509_PURPOSE` rows
                      (`xstandard[]`), and the engine's `ENGINE_set_*` bind calls.
    CLI_DISPATCH      the generated `apps/progs.c` `FUNCTION functions[]` table and the
                      `OPTIONS` tables under `apps/` (the plan names `apps/progs.h`).
    CONFIG_DISPATCH   the `CONF_METHOD` (`NCONF_default`/`NCONF_WIN32`) dispatch structs
                      and the `CONF_module_add` handler registrations.

The join, and what corroboration means
--------------------------------------
Two existing planes are joined in, because a dispatch row one sees and the other does
not is a finding rather than noise:

  * 22.3's `tu-ast.json` address-taken functions (`forensics/atlas/phase22/tu-ast.json`).
    A file-scope table initializer is not inside a function body, so the AST's
    address-taken census does **not** carry it; where an edge is nonetheless witnessed
    there it is recorded as `ast_witness`.
  * 22.6's `binary-reference-graph.json` relocations
    (`forensics/atlas/phase22/binary-reference-graph.json`). A function pointer stored in
    a table produces a data relocation (`R_X86_64_64`/`32`/`32S`), not a call relocation
    (`PLT32`/`PC32`), so those relocations are the binary witness of a dispatch slot.

Every edge carries a `corroboration` class:

    both          a source row and a matching binary data relocation from the same object;
    source_only   the source row has no binary witness;
    binary_only   the binary witnesses an address-taken function in a table-bearing file
                  that no source row claims -- exactly the macro-generated and
                  otherwise-hidden table slots.

The binary-only census is the interesting direction: OpenSSL writes a large fraction of
its `OSSL_DISPATCH` tables with `IMPLEMENT_*` macros, which a lexical scan cannot expand.
Those tables are named in `not_recovered` and their slots surface here as `binary_only`
edges rather than being silently dropped.

Reduction, recorded rather than silent
--------------------------------------
`#if`/`#else` branches are read *textually*: a row inside a disabled branch is still a row
the source contains, and deciding whether the branch is taken is 22.4's conditional plane,
not this one. Macro-generated tables are not expanded (named in `not_recovered`). The FIPS
provider is not part of the admitted production profile and is excluded. Every count is
derived from the table model; nothing is typed.

Output
------
    forensics/atlas/phase22/dispatch-graph.json

`forensics/tools/phase22_courts.py` discovers this module and calls `courts()`, which drives
the pure `build_body` over the committed artefact and over controlled in-memory mutations of
it. See `RT-PHASE22-DISPATCH` below.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
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

GENERATOR = "forensics/tools/phase22_dispatch.py"
ARTEFACT_REL = "forensics/atlas/phase22/dispatch-graph.json"
OUT_REL = ARTEFACT_REL
COURT = "RT-PHASE22-DISPATCH"
TU_AST_REL = "forensics/atlas/phase22/tu-ast.json"
BINARY_REL = "forensics/atlas/phase22/binary-reference-graph.json"
BUILD_DIR_REL = "forensics/authorities/build/openssl-3.6.4-production"

# Source roots scanned for tables. FIPS is excluded: it is not part of the admitted
# production profile (the production build produces no fips.so; 22.6 sees only legacy.so).
SCAN_DIRS = ("providers", "crypto", "apps", "engines", "ssl")
EXCLUDE_PREFIXES = ("providers/fips/",)
SOURCE_SUFFIXES = (".c", ".h", ".c.in", ".h.in")

# Relocation types that take an address into a data object (a table slot). A call is
# PLT32/PC32; a stored function pointer is an absolute data relocation.
ADDRESS_RELOC_TYPES = frozenset({"R_X86_64_64", "R_X86_64_32", "R_X86_64_32S"})

# Expression-level keywords that are never a slot target.
KEYWORDS = frozenset({
    "void", "const", "static", "unsigned", "signed", "int", "char", "long", "short",
    "float", "double", "struct", "union", "enum", "typedef", "return", "sizeof", "if",
    "else", "for", "while", "do", "switch", "case", "break", "continue", "goto",
    "default", "register", "volatile", "extern", "inline", "restrict", "NULL",
    "offsetof", "true", "false", "ossl_unused", "_Bool",
})

IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
NUMBER_RE = re.compile(r"[0-9][0-9A-Fa-fxX._]*")

# Expression-level keywords that are never a slot target.
# ---------------------------------------------------------------------------
# lexical layer (comment/directive stripping, tokenizer)
# ---------------------------------------------------------------------------

def strip_comments(text: str) -> str:
    """Blank comments, preserving every newline and byte offset."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == '"' or c == "'":
            quote = c
            out.append(c)
            i += 1
            while i < n:
                if text[i] == "\\":
                    out.append(text[i:i + 2])
                    i += 2
                    continue
                out.append(text[i])
                if text[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("".join(ch if ch == "\n" else " " for ch in text[i:j]))
            i = j
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
            continue
        out.append(c)
        i += 1
    return "".join(out)


def strip_directives(text: str) -> str:
    """Blank `#...` preprocessor lines, preserving newlines and offsets.

    A directive is never the table this plane inventories, and blanking it stops a
    `#define` body from being read as a declaration while leaving macro *invocations*
    (which are not directives) intact.
    """
    out: list[str] = []
    for line in text.splitlines(keepends=True):
        if line.lstrip().startswith("#"):
            out.append("".join(ch if ch == "\n" else " " for ch in line))
        else:
            out.append(line)
    return "".join(out)


def tokenize(text: str) -> list[tuple[str, str, int]]:
    """(kind, value, offset) tokens: kind in {id, str, char, num, p}."""
    toks: list[tuple[str, str, int]] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in " \t\r\n":
            i += 1
            continue
        if c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    break
                j += 1
            toks.append(("str", text[i + 1:j], i))
            i = j + 1
            continue
        if c == "'":
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == "'":
                    break
                j += 1
            toks.append(("char", text[i + 1:j], i))
            i = j + 1
            continue
        m = IDENT_RE.match(text, i)
        if m:
            toks.append(("id", m.group(0), i))
            i = m.end()
            continue
        m = NUMBER_RE.match(text, i)
        if m:
            toks.append(("num", m.group(0), i))
            i = m.end()
            continue
        toks.append(("p", c, i))
        i += 1
    return toks


def line_index(text: str) -> list[int]:
    return [i for i, ch in enumerate(text) if ch == "\n"]


def line_of(newlines: list[int], offset: int) -> int:
    import bisect
    return bisect.bisect_right(newlines, offset) + 1


def is_caps(ident: str) -> bool:
    return ident.upper() == ident and any(ch.isalpha() for ch in ident)


def symbol_like(ident: str) -> bool:
    """A likely function/table symbol: not a keyword, not NULL, not an ALL_CAPS constant."""
    return (ident not in KEYWORDS and ident != "NULL" and not is_caps(ident)
            and not ident.startswith("OSSL_FUNC_"))


# ---------------------------------------------------------------------------
# table declaration + initializer parsing
# ---------------------------------------------------------------------------

def decl_at(toks: list[tuple[str, str, int]], i: int, typ: str):
    """If `toks[i]` declares a table of type `typ`, return (name, brace_index, pointer).

    The shape is `<...> TYPE [*] NAME [[...]] = {`. A function whose return type is TYPE
    has `(` after the name instead of `=` and is rejected.
    """
    if toks[i][0] != "id" or toks[i][1] != typ:
        return None
    j = i + 1
    pointer = False
    while j < len(toks) and toks[j][0] == "p" and toks[j][1] == "*":
        pointer = True
        j += 1
    if j >= len(toks) or toks[j][0] != "id":
        return None
    name = toks[j][1]
    j += 1
    if j < len(toks) and toks[j][0] == "p" and toks[j][1] == "[":
        depth = 0
        while j < len(toks):
            t = toks[j]
            if t[0] == "p" and t[1] == "[":
                depth += 1
            elif t[0] == "p" and t[1] == "]":
                depth -= 1
                if depth == 0:
                    j += 1
                    break
            j += 1
    if j < len(toks) and toks[j][0] == "p" and toks[j][1] == "=":
        j += 1
        if j < len(toks) and toks[j][0] == "p" and toks[j][1] == "{":
            return name, j, pointer
    return None


def match_brace(toks: list[tuple[str, str, int]], open_i: int) -> int:
    depth = 0
    for k in range(open_i, len(toks)):
        t = toks[k]
        if t[0] == "p" and t[1] == "{":
            depth += 1
        elif t[0] == "p" and t[1] == "}":
            depth -= 1
            if depth == 0:
                return k
    return -1


def split_rows(body: list[tuple[str, str, int]]) -> list[list[tuple[str, str, int]]]:
    """Split an initializer body on commas at brace/paren depth zero."""
    rows: list[list[tuple[str, str, int]]] = []
    cur: list[tuple[str, str, int]] = []
    depth = 0
    for t in body:
        if t[0] == "p" and t[1] in "([{":
            depth += 1
        elif t[0] == "p" and t[1] in ")]}":
            depth -= 1
        if t[0] == "p" and t[1] == "," and depth == 0:
            rows.append(cur)
            cur = []
            continue
        cur.append(t)
    if cur:
        rows.append(cur)
    return [r for r in rows if r]


def has_top_level_brace(body: list[tuple[str, str, int]]) -> bool:
    """True when the initializer has brace-enclosed rows (an array of structs)."""
    return any(t[0] == "p" and t[1] == "{" for t in body)


def idents(part: list[tuple[str, str, int]]) -> list[str]:
    return [t[1] for t in part if t[0] == "id"]


def _symbols(part: list[tuple[str, str, int]]) -> list[str]:
    return [t[1] for t in part if t[0] == "id" and symbol_like(t[1])]


def slot_of(part: list[tuple[str, str, int]]) -> str | None:
    for t in part:
        if t[0] == "id" and (t[1].startswith("OSSL_FUNC_") or is_caps(t[1])):
            return t[1]
    return None


def rows_dispatch(body, known):
    out = []
    for part in split_rows(body):
        syms = _symbols(part)
        if syms:
            out.append({"slot": slot_of(part), "target": syms[-1]})
    return out


def rows_algorithm(body, known):
    out = []
    for part in split_rows(body):
        syms = _symbols(part)
        if syms:
            out.append({"slot": idents(part)[0] if idents(part) else None,
                        "target": syms[-1]})
    return out


def rows_ptr(body, known):
    out = []
    for n, part in enumerate(split_rows(body)):
        syms = _symbols(part)
        if syms:
            out.append({"slot": f"[{n}]", "target": syms[0]})
    return out


def rows_known_fn(body, known):
    """Struct-initializer callback slots: an identifier field that is a known function."""
    out = []
    if has_top_level_brace(body):
        parts = split_rows(body)
    else:
        parts = [body]
    for part in parts:
        for ident in idents(part):
            if ident in known and ident not in KEYWORDS:
                out.append({"slot": None, "target": ident})
    return out


def rows_cli(body, known):
    out = []
    for part in split_rows(body):
        name = next((t[1] for t in part if t[0] == "str"), None)
        for ident in idents(part):
            if ident.endswith("_main") or ident.endswith("_options"):
                out.append({"slot": name, "target": ident})
    return out


# family -> (edge_kind, row_mode). `mode` is a pure extractor over the initializer tokens.
FAMILIES: dict[str, tuple[str, str]] = {
    "OSSL_DISPATCH": ("DISPATCH_SLOT", "dispatch"),
    "OSSL_ALGORITHM": ("DISPATCH_SLOT", "algorithm"),
    "OSSL_ALGORITHM_CAPABLE": ("DISPATCH_SLOT", "algorithm"),
    "OSSL_PARAM": ("DISPATCH_SLOT", "param"),
    "X509_TRUST": ("REGISTRATION", "known_fn"),
    "X509_PURPOSE": ("REGISTRATION", "known_fn"),
    "X509_LOOKUP_METHOD": ("REGISTRATION", "known_fn"),
    "X509V3_EXT_METHOD": ("CALLBACK_SLOT", "known_fn"),
    "EVP_PKEY_ASN1_METHOD": ("CALLBACK_SLOT", "known_fn"),
    "ASN1_AUX": ("CALLBACK_SLOT", "known_fn"),
    "CONF_METHOD": ("CONFIG_DISPATCH", "known_fn"),
    "FUNCTION": ("CLI_DISPATCH", "cli"),
    "OPTIONS": ("CLI_DISPATCH", "data"),
}

MODE_FN = {
    "dispatch": rows_dispatch,
    "algorithm": rows_algorithm,
    "param": lambda body, known: [],
    "ptr": rows_ptr,
    "known_fn": rows_known_fn,
    "cli": rows_cli,
    "data": lambda body, known: [],
}

# Table families whose rows carry data descriptors rather than function slots. Their row
# totals are recorded, but a row without a target is not a `slot_without_target`.
DATA_FAMILIES = frozenset({"OSSL_PARAM", "OPTIONS"})


def extract_table(body, mode, known) -> list[dict]:
    fn = MODE_FN.get(mode)
    if fn is None:
        return []
    return fn(body, known)


# ---------------------------------------------------------------------------
# scanning whole files
# ---------------------------------------------------------------------------

def scan_text(text: str, file_key: str, known) -> list[dict]:
    """Every typed table this file declares, with its edge-bearing rows. A pure function."""
    pre = strip_directives(strip_comments(text))
    newlines = line_index(text)
    toks = tokenize(pre)
    tables: list[dict] = []
    i = 0
    while i < len(toks):
        t = toks[i]
        if t[0] == "id":
            typ = t[1]
            if typ in FAMILIES:
                kind, mode = FAMILIES[typ]
                res = decl_at(toks, i, typ)
                if res:
                    name, brace, pointer = res
                    close = match_brace(toks, brace)
                    if close > brace:
                        body = toks[brace + 1:close]
                        mode_eff = mode
                        if mode == "known_fn" and pointer:
                            mode_eff = "ptr"
                        rows = extract_table(body, mode_eff, known)
                        rows_total = len(split_rows(body)) if body else 0
                        tables.append({
                            "id": f"{kind}:{file_key}:{line_of(newlines, t[2])}:{name}",
                            "family": typ if not (mode == "known_fn" and pointer)
                            else typ + "_ARRAY",
                            "edge_kind": kind,
                            "symbol": name,
                            "file": file_key,
                            "line": line_of(newlines, t[2]),
                            "rows_total": rows_total,
                            "rows": [r for r in rows if r.get("target")],
                        })
                        i = close
        i += 1
    return tables


ASN1_RE = re.compile(
    r"\bASN1_(?:NDEF_)?SEQUENCE_(ref|enc|cb|const_cb|cb_const_cb)\s*\(([^)]*)\)\s*=")
ENGINE_RE = re.compile(r"\bENGINE_set_\w+\s*\(\s*\w+\s*,\s*(\w+)\s*\)")
CONF_MOD_RE = re.compile(r"\bCONF_module_add\s*\(\s*\"[^\"]*\"\s*,\s*(\w+)(?:\s*,\s*(\w+))?\s*\)")
PROV_INIT_RE = re.compile(r"\bOSSL_provider_init_fn\s+(\w+)\s*[;=]")
PROV_DEF_RE = re.compile(r"#\s*define\s+OSSL_provider_init\s+(\w+)")


def scan_call_sites(text: str, file_key: str, known) -> list[dict]:
    """Registration edges written as calls/macros rather than data tables."""
    pre = strip_comments(text)
    newlines = line_index(text)
    tables: list[dict] = []

    def add(family, kind, m, targets, label):
        rows = [{"slot": label, "target": g}
                for g in targets if g and g not in KEYWORDS and g in known]
        if rows:
            tables.append({
                "id": f"{kind}:{file_key}:{line_of(newlines, m.start())}:{label}",
                "family": family, "edge_kind": kind, "symbol": label,
                "file": file_key, "line": line_of(newlines, m.start()),
                "rows_total": len(rows), "rows": rows,
            })

    # (flavor -> indices of the callback arguments). `enc` puts the encoding field-name
    # second and the callback third; the others name the callback(s) after the item name.
    asn1_cb_args = {"ref": [1], "enc": [2], "cb": [1], "const_cb": [1],
                    "cb_const_cb": [1, 2]}
    for m in ASN1_RE.finditer(pre):
        flavor, args = m.group(1), [a.strip() for a in m.group(2).split(",")]
        targets = [args[k] for k in asn1_cb_args[flavor]
                   if k < len(args) and re.fullmatch(r"\w+", args[k])
                   and not is_caps(args[k]) and args[k] != "NULL"]
        add("ASN1_ITEM_CB", "CALLBACK_SLOT", m, targets, f"ASN1_SEQUENCE_{flavor}")

    for m in ENGINE_RE.finditer(pre):
        add("ENGINE_SET", "REGISTRATION", m, [m.group(1)], "ENGINE_set_function")

    for m in CONF_MOD_RE.finditer(pre):
        add("CONF_MODULE_ADD", "CONFIG_DISPATCH", m,
            [m.group(1), m.group(2)], "CONF_module_add")

    for m in PROV_INIT_RE.finditer(pre):
        add("PROVIDER_INIT", "REGISTRATION", m, [m.group(1)], "OSSL_provider_init")

    for m in PROV_DEF_RE.finditer(pre):
        add("PROVIDER_INIT", "REGISTRATION", m, [m.group(1)], "OSSL_provider_init")

    return tables


def iter_source_files(src_root: Path, build_dir: Path):
    """(file_key, path) for every scanned file, source and generated, deterministically."""
    seen: dict[str, Path] = {}
    for d in SCAN_DIRS:
        base = src_root / d
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file():
                continue
            if path.suffix not in SOURCE_SUFFIXES:
                continue
            key = path.relative_to(src_root).as_posix()
            if key.endswith(".in"):
                key = key[:-3]
            if key.startswith(EXCLUDE_PREFIXES):
                continue
            seen.setdefault(key, path)
    # The generated CLI tables live only in the build tree, not the source.
    for relp in ("apps/progs.c", "apps/progs.h"):
        p = build_dir / relp
        if p.is_file():
            seen.setdefault(relp, p)
    return [(k, seen[k]) for k in sorted(seen)]


# ---------------------------------------------------------------------------
# inputs: 22.3 address-taken, 22.6 relocations
# ---------------------------------------------------------------------------

def norm_source(s: str | None) -> str | None:
    if not s:
        return None
    marker = "openssl-3.6.4/"
    idx = s.find(marker)
    if idx >= 0:
        s = s[idx + len(marker):]
    if s.startswith("./"):
        s = s[2:]
    if s.endswith(".in"):
        s = s[:-3]
    return s


def load_known_functions(tu_ast: dict, binary: dict) -> set[str]:
    known: set[str] = set()
    for e in tu_ast.get("body", {}).get("entities", []):
        if e.get("kind") == "function":
            known.add(e["name"])
    for o in binary.get("body", {}).get("objects", []):
        for s in o.get("defined", []):
            if s.get("type") == "FUNC":
                known.add(s["name"])
    return known


def load_known_objects(binary: dict) -> set[str]:
    """Symbols the binary defines as data objects (dispatch tables, method structs)."""
    out: set[str] = set()
    for o in binary.get("body", {}).get("objects", []):
        for s in o.get("defined", []):
            if s.get("type") == "OBJECT":
                out.add(s["name"])
    return out


def load_ast_functions(tu_ast: dict) -> set[str]:
    return {r["function"] for r in tu_ast.get("body", {}).get("address_taken", [])}


def load_binary_address_taken(binary: dict, known: set[str]) -> dict[str, list[str]]:
    """file -> sorted function symbols that file's object takes the address of.

    A stored function pointer is an address-taking relocation (R_X86_64_64/32/32S), not a
    call (PLT32/PC32). Only symbols that are known functions are kept, so the binary-only
    census is a census of function slots rather than of every data address.
    """
    out: dict[str, set[str]] = {}
    for o in binary.get("body", {}).get("objects", []):
        f = norm_source(o.get("source"))
        if not f:
            continue
        for r in o.get("relocations", []):
            sym = r.get("symbol") or ""
            if not sym or sym.startswith(".") or sym not in known:
                continue
            if ADDRESS_RELOC_TYPES.intersection(r.get("types", [])):
                out.setdefault(f, set()).add(sym)
    return {k: sorted(v) for k, v in sorted(out.items())}


def load_binary_address_global(binary: dict, known: set[str]) -> list[str]:
    """Every function symbol the whole binary set takes the address of as data.

    Corroboration is judged against this set rather than a single object's file, because a
    table defined in a header (`standard_exts.h`, `standard_methods.h`) is materialised in
    the including translation unit and a table compiled into the `apps/openssl` executable
    has no archive-member source to attribute to.
    """
    out: set[str] = set()
    for o in binary.get("body", {}).get("objects", []):
        for r in o.get("relocations", []):
            sym = r.get("symbol") or ""
            if not sym or sym.startswith(".") or sym not in known:
                continue
            if ADDRESS_RELOC_TYPES.intersection(r.get("types", [])):
                out.add(sym)
    return sorted(out)


# ---------------------------------------------------------------------------
# body assembly (pure)
# ---------------------------------------------------------------------------

def _edge_sort_key(e: dict) -> tuple:
    return (e["file"] or "", e["line"] if e["line"] is not None else -1,
            e["kind"], e["target"] or "", e["slot"] or "")


def build_body(model: dict) -> dict:
    """The atlas body from the table model. A pure, deterministic function.

    `RT-PHASE22-DISPATCH` calls this on the committed artefact's own `tables` and on
    controlled in-memory mutations, so it must hold no I/O and no ambient state.
    """
    tables = sorted(model["tables"], key=lambda t: (t["file"], t["line"], t["id"]))
    ast = set(model.get("ast_functions", []))
    binary_global = set(model.get("binary_address_global", []))
    binary = {k: list(v) for k, v in model.get("binary_address_taken", {}).items()}

    edges: list[dict] = []
    for t in tables:
        for r in t["rows"]:
            edges.append({
                "kind": t["edge_kind"],
                "family": t["family"],
                "table": t["id"],
                "file": t["file"],
                "line": t["line"],
                "slot": r.get("slot"),
                "target": r.get("target"),
                "ast_witness": r.get("target") in ast,
                "binary_witness": r.get("target") in binary_global,
            })
    for e in edges:
        e["corroboration"] = "both" if e["binary_witness"] else "source_only"
        e.pop("binary_witness")

    claimed = {(e["file"], e["target"]) for e in edges}
    binary_only: list[dict] = []
    for file in sorted(binary):
        for sym in binary[file]:
            if (file, sym) in claimed:
                continue
            binary_only.append({
                "kind": "RELOCATION_REFERENCE", "family": "BINARY_ONLY", "table": None,
                "file": file, "line": None, "slot": None, "target": sym,
                "ast_witness": sym in ast, "corroboration": "binary_only",
            })

    edges.extend(binary_only)
    edges.sort(key=_edge_sort_key)

    by_kind: dict[str, int] = {}
    for e in edges:
        by_kind[e["kind"]] = by_kind.get(e["kind"], 0) + 1
    fam_tables: dict[str, int] = {}
    for t in tables:
        fam_tables[t["family"]] = fam_tables.get(t["family"], 0) + 1

    return {
        "tables": tables,
        "edges": edges,
        "counts": {
            "edges": len(edges),
            "edges_by_kind": dict(sorted(by_kind.items())),
            "tables": len(tables),
            "tables_by_family": dict(sorted(fam_tables.items())),
            "corroborated": sum(1 for e in edges if e["corroboration"] == "both"),
            "source_only": sum(1 for e in edges if e["corroboration"] == "source_only"),
            "binary_only": sum(1 for e in edges if e["corroboration"] == "binary_only"),
            "ast_corroborated": sum(1 for e in edges if e["ast_witness"]),
            "slots_without_target": sum(
                t["rows_total"] - len(t["rows"]) for t in tables
                if t["family"] not in DATA_FAMILIES),
        },
    }


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def collect(src_root: Path, build_dir: Path, known) -> list[dict]:
    tables: list[dict] = []
    for key, path in iter_source_files(src_root, build_dir):
        text = path.read_text(encoding="utf-8", errors="replace")
        tables.extend(scan_text(text, key, known))
        tables.extend(scan_call_sites(text, key, known))
    tables.sort(key=lambda t: (t["file"], t["line"], t["id"]))
    return tables


def not_recovered(src_root: Path) -> list[dict]:
    """Table families this extractor cannot recover mechanically, named rather than omitted."""
    counts: dict[str, int] = {}
    files_missing: list[str] = []
    macro_re = re.compile(r"\b((?:IMPLEMENT|PROV_DISPATCH)[A-Za-z0-9_]*)\s*\(")
    for key, path in iter_source_files(src_root, Path("/nonexistent")):
        if not key.endswith((".c", ".h")):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if "OSSL_DISPATCH" not in text:
            continue
        pre = strip_directives(strip_comments(text))
        if any(t["family"] == "OSSL_DISPATCH" for t in scan_text(text, key, set())):
            continue
        files_missing.append(key)
        for m in macro_re.finditer(pre):
            counts[m.group(1)] = counts.get(m.group(1), 0) + 1
    out = [{"family": "macro-generated dispatch tables",
            "files_referencing_dispatch_without_a_literal_table": sorted(files_missing),
            "macros": sorted(counts),
            "invocations": {k: counts[k] for k in sorted(counts)},
            "reason": ("the OSSL_DISPATCH initializer is produced by macro expansion and has no "
                       "literal row in the source; slots surface as binary_only edges")}]
    out.append({"family": "providers/fips/",
                "reason": "not part of the admitted production profile; excluded from the scan"})
    out.append({"family": "ossl_provider_add_* / OSSL_PROVIDER_add_builtin",
                "reason": ("a runtime registration API; the authority source contains no static "
                           "call site that names a provider init function, so no edge can be "
                           "recovered -- provider entry points are recovered instead from the "
                           "OSSL_provider_init_fn declarations and #define")})
    out.append({"family": "ASN1_ADB / ASN1_TEMPLATE embedded selectors",
                "reason": ("ADB/ADBENTRY selector function pointers are inside template macro "
                           "expansions and are not recovered by this lexical extractor")})
    out.append({"family": "OSSL_PARAM function-pointer slots",
                "reason": ("OSSL_PARAM arrays carry data descriptors; the few rows that name a "
                           "function are not distinguishable from data without type resolution")})
    out.append({"family": "EVP_PKEY_METHOD / EVP_PKEY_ASN1_METHOD struct initializers",
                "reason": ("built at run time through constructor calls, not static tables; the "
                           "pointer array `standard_methods[]` is recovered, the structs are not")})
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    src_root = auth.source
    build_dir = REPO_ROOT / BUILD_DIR_REL

    tu_path = REPO_ROOT / TU_AST_REL
    bin_path = REPO_ROOT / BINARY_REL
    if not tu_path.is_file() or not bin_path.is_file():
        raise SystemExit(
            "phase22-dispatch: 22.3's tu-ast.json and 22.6's binary-reference-graph.json are "
            "both required; run those planes first")

    tu_ast = json.loads(tu_path.read_text(encoding="utf-8"))
    binary = json.loads(bin_path.read_text(encoding="utf-8"))

    known = load_known_functions(tu_ast, binary)
    known_slots = known | load_known_objects(binary)
    ast_functions = sorted(load_ast_functions(tu_ast))
    binary_at = load_binary_address_taken(binary, known)
    binary_global = load_binary_address_global(binary, known_slots)

    tables = collect(src_root, build_dir, known)
    # Keep the file-attributed index only for table-bearing files (deterministic, bounded);
    # the global index is what decides corroboration, so headers and the executable join.
    table_files = {t["file"] for t in tables}
    binary_at = {k: [s for s in v if s in known] for k, v in binary_at.items()
                 if k in table_files}

    model = {"tables": tables, "ast_functions": ast_functions,
             "binary_address_taken": binary_at,
             "binary_address_global": binary_global}
    body = build_body(model)
    body["known_functions"] = len(known)
    body["known_slots"] = len(known_slots)
    # The corroboration inputs are carried in the body so the court re-derives from the
    # artefact's own rows, and so a reviewer can check the join without re-reading 22.3/22.6.
    body["ast_functions"] = ast_functions
    body["binary_address_taken"] = binary_at
    body["binary_address_global"] = binary_global
    body["sources"] = {
        "authority": auth.id,
        "source_root": rel(src_root),
        "scan_dirs": list(SCAN_DIRS),
        "tu_ast": rel(tu_path),
        "binary_reference_graph": rel(bin_path),
    }
    body["extraction"] = (
        "A real C tokenizer over comment-stripped, directive-blanked source. Tables are found "
        "by declaration shape (`TYPE [*] NAME [[...]] = {`), rows by comma at brace depth zero. "
        "DISPATCH_SLOT rows take the last symbol-like identifier (skipping OSSL_FUNC_* slots and "
        "NULL); OSSL_ALGORITHM rows take the implementation symbol; struct slots take identifier "
        "fields that are known functions (22.3 function entities plus 22.6 FUNC definitions); "
        "pointer-array rows take the pointee. Every count is derived from the table model."
    )
    body["join"] = (
        "Two corroboration witnesses. 22.3's address-taken functions are a weak witness because a "
        "file-scope table initializer is not inside a function body. 22.6's data relocations "
        "(R_X86_64_64/32/32S, the address-taking relocations, as opposed to PLT32/PC32 calls) are "
        "the binary witness of a stored pointer; corroboration is judged against the whole "
        "binary because a table in a header (`standard_exts.h`) is materialised in the including "
        "unit and the `apps/openssl` table has no archive-member source. The binary-only census "
        "is per archive-member source and restricted to function symbols."
    )
    body["reduction"] = {
        "conditionals": (
            "rows inside #if/#else branches are extracted textually; deciding whether a branch "
            "is taken is 22.4's conditional plane, not this one"),
        "macros": "macro-generated tables are not expanded; see not_recovered",
        "binary_only": (
            "binary_only edges are address-taken function symbols of a table-bearing file's "
            "object that no source row claims; they carry kind RELOCATION_REFERENCE because the "
            "slot's family is the thing the source extractor could not see"),
        "binary_witness_reach": (
            "22.6 sees an address-taken symbol only when the object references it by name; a "
            "pointer to a file-local (static) function is emitted as a section-relative "
            "relocation and carries no symbol name, so most static callbacks are source_only. "
            "A pointer internal to a linked DSO or the `apps/openssl` executable is resolved to "
            "an R_X86_64_RELATIVE relocation and is likewise unnamed, so the CLI table is "
            "source_only"),
        "extension_lookup": (
            "the extension-method lookup table the plan names under CONFIG_DISPATCH is "
            "`standard_exts[]`, recovered under CALLBACK_SLOT (X509V3_EXT_METHOD_ARRAY) and not "
            "counted twice"),
    }
    body["not_recovered"] = not_recovered(src_root)
    body["sort_key"] = ("(file, line, kind, target, slot); file is authority-relative and a "
                        "generated source keeps its source name")

    inputs = [
        InputRef(name="tu-ast", path=tu_path),
        InputRef(name="binary-reference-graph", path=bin_path),
    ]
    doc = envelope(kind="phase22-dispatch-graph", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(REPO_ROOT / OUT_REL, doc)

    c = body["counts"]
    print(f"[phase22-dispatch] tables={c['tables']} edges={c['edges']} "
          f"corroborated={c['corroborated']} source_only={c['source_only']} "
          f"binary_only={c['binary_only']} ast_witness={c['ast_corroborated']}")
    print(f"[phase22-dispatch] by kind: {c['edges_by_kind']}")
    print(f"[phase22-dispatch] -> {rel(REPO_ROOT / OUT_REL)}")
    return 0


# ---------------------------------------------------------------------------
# the court
# ---------------------------------------------------------------------------

def _model_from_body(body: dict) -> dict:
    return {
        "tables": json.loads(json.dumps(body["tables"])),
        "ast_functions": list(body["ast_functions"]),
        "binary_address_taken": {k: list(v) for k, v in body["binary_address_taken"].items()},
        "binary_address_global": list(body["binary_address_global"]),
    }


def _insensitive_build(model: dict) -> dict:
    """A deliberately insensitive classifier, for the court's negative controls.

    It ignores every table row, so any assertion that a mutation moves an edge count must
    fail against it. That is the in-memory proof the court's invariants are sensitive.
    """
    return build_body({"tables": [], "ast_functions": [], "binary_address_taken": {}})


def court_dispatch(body: dict) -> dict:
    """`RT-PHASE22-DISPATCH`: an FRF-style sensitivity challenge over `build_body`.

    Round-trips the committed body (re-derive tables, edges, corroboration and every count
    from the artefact's own rows and require equality), then drives it over controlled
    mutations: add a dispatch slot, add a callback slot, add a registration edge, move an
    edge between corroboration classes, and delete a table. Each is paired with a negative
    control against `_insensitive_build`, so the court fails if the classifier is
    insensitive.
    """
    checks: list[tuple[str, bool]] = []
    model = _model_from_body(body)
    base = build_body(json.loads(json.dumps(model)))

    checks.append(("baseline: tables and edges exist",
                   base["counts"]["tables"] > 0 and base["counts"]["edges"] > 0))
    checks.append(("baseline: every edge kind is present",
                   all(k in base["counts"]["edges_by_kind"]
                       for k in ("DISPATCH_SLOT", "CALLBACK_SLOT", "REGISTRATION",
                                 "CLI_DISPATCH", "CONFIG_DISPATCH"))))
    # Round trip: the committed body must be exactly what this logic derives from its model.
    checks.append(("round-trip: re-deriving from the artefact's own tables reproduces it",
                   base["edges"] == body["edges"]
                   and base["tables"] == body["tables"]
                   and base["counts"] == body["counts"]))

    def fresh() -> dict:
        return json.loads(json.dumps(model))

    def find_table(m: dict, kind: str) -> int:
        return next(i for i, t in enumerate(m["tables"]) if t["edge_kind"] == kind)

    def add_row(kind: str, label: str) -> None:
        m = fresh()
        i = find_table(m, kind)
        m["tables"][i]["rows"].append({"slot": label, "target": f"phase22_probe_{label}"})
        m["tables"][i]["rows_total"] += 1
        d = build_body(m)
        checks.append((f"add-{label}: `edges` rises by exactly one",
                       d["counts"]["edges"] == base["counts"]["edges"] + 1))
        checks.append((f"add-{label}: the kind's count rises by one",
                       d["counts"]["edges_by_kind"].get(kind, 0)
                       == base["counts"]["edges_by_kind"].get(kind, 0) + 1))
        found = next((e for e in d["edges"]
                      if e["target"] == f"phase22_probe_{label}"), None)
        checks.append((f"add-{label}: the new edge is present and source_only",
                       found is not None and found["corroboration"] == "source_only"))
        checks.append((f"add-{label}: negative control -- the insensitive build misses it",
                       _insensitive_build(m)["counts"]["edges"]
                       != base["counts"]["edges"] + 1))

    add_row("DISPATCH_SLOT", "dispatch")
    add_row("CALLBACK_SLOT", "callback")
    add_row("REGISTRATION", "registration")

    # CLI_DISPATCH add, for the apps table family.
    m = fresh()
    i = find_table(m, "CLI_DISPATCH")
    m["tables"][i]["rows"].append({"slot": "phase22", "target": "phase22_probe_main"})
    m["tables"][i]["rows_total"] += 1
    d = build_body(m)
    checks.append(("add-cli: `edges` and CLI_DISPATCH both rise by one",
                   d["counts"]["edges"] == base["counts"]["edges"] + 1
                   and d["counts"]["edges_by_kind"]["CLI_DISPATCH"]
                   == base["counts"]["edges_by_kind"]["CLI_DISPATCH"] + 1))

    # Delete a table: its own edges leave.
    m = fresh()
    victim = m["tables"][find_table(m, "DISPATCH_SLOT")]
    victim_edges = len(victim["rows"])
    m["tables"] = [t for t in m["tables"] if t["id"] != victim["id"]]
    d = build_body(m)
    checks.append(("delete-table: `tables` falls by one",
                   d["counts"]["tables"] == base["counts"]["tables"] - 1))
    checks.append(("delete-table: exactly the table's own edges leave",
                   d["counts"]["edges"] == base["counts"]["edges"] - victim_edges))
    checks.append(("delete-table: negative control -- the insensitive build is unchanged",
                   _insensitive_build(m)["counts"]["tables"] == 0
                   and _insensitive_build(m)["counts"]["tables"]
                   != base["counts"]["tables"] - 1))

    # Move an edge between corroboration classes: give a source_only edge a binary witness.
    from collections import Counter as _Counter
    target_counts = _Counter(e["target"] for e in base["edges"]
                             if e["corroboration"] == "source_only")
    source_only = [e for e in base["edges"]
                   if e["corroboration"] == "source_only"
                   and target_counts[e["target"]] == 1]
    checks.append(("move-corroboration: a uniquely-targeted source_only edge exists",
                   bool(source_only)))
    if source_only:
        victim = source_only[0]
        m = fresh()
        if victim["target"] not in m["binary_address_global"]:
            m["binary_address_global"].append(victim["target"])
        d = build_body(m)
        moved = next((e for e in d["edges"]
                      if e["file"] == victim["file"] and e["target"] == victim["target"]
                      and e["kind"] == victim["kind"]), None)
        checks.append(("move-corroboration: the edge is now `both`",
                       moved is not None and moved["corroboration"] == "both"))
        checks.append(("move-corroboration: `corroborated` rose and `source_only` fell",
                       d["counts"]["corroborated"] == base["counts"]["corroborated"] + 1
                       and d["counts"]["source_only"] == base["counts"]["source_only"] - 1))
        checks.append(("move-corroboration: total `edges` unchanged",
                       d["counts"]["edges"] == base["counts"]["edges"]))
        checks.append(("move-corroboration: negative control -- the insensitive build cannot "
                       "see the class move",
                       _insensitive_build(m)["counts"]["corroborated"]
                       != base["counts"]["corroborated"] + 1))

    # A binary_only edge leaves the moment the source claims it.
    binary_only = [e for e in base["edges"] if e["corroboration"] == "binary_only"]
    checks.append(("promote-binary-only: a binary_only edge exists to claim",
                   bool(binary_only)))
    if binary_only:
        victim = binary_only[0]
        m = fresh()
        # A synthetic table in the same object claims the binary-only symbol, so the
        # binary witness stops being unclaimed.
        m["tables"].append({
            "id": f"DISPATCH_SLOT:{victim['file']}:0:phase22_promote",
            "family": "OSSL_DISPATCH", "edge_kind": "DISPATCH_SLOT",
            "symbol": "phase22_promote", "file": victim["file"], "line": 0,
            "rows_total": 1, "rows": [{"slot": "OSSL_FUNC_PROBE",
                                         "target": victim["target"]}]})
        d = build_body(m)
        checks.append(("promote-binary-only: the symbol is no longer binary_only",
                       not any(e["corroboration"] == "binary_only"
                               and e["file"] == victim["file"]
                               and e["target"] == victim["target"] for e in d["edges"])))
        checks.append(("promote-binary-only: negative control -- the insensitive build sees none",
                       _insensitive_build(m)["counts"]["binary_only"]
                       != base["counts"]["binary_only"] - 1))

    failures = [desc for desc, ok in checks if not ok]
    c = base["counts"]
    return {
        "court": COURT,
        "artefact": ARTEFACT_REL,
        "tables": c["tables"],
        "edges": c["edges"],
        "edges_by_kind": c["edges_by_kind"],
        "corroborated": c["corroborated"],
        "source_only": c["source_only"],
        "binary_only": c["binary_only"],
        "summary": (f"{c['tables']} tables, {c['edges']} edges ({c['corroborated']} both, "
                    f"{c['source_only']} source-only, {c['binary_only']} binary-only)"),
        "mutations": ["round-trip", "add-dispatch-slot", "add-callback-slot",
                      "add-registration-edge", "add-cli-dispatch", "delete-table",
                      "move-corroboration", "promote-binary-only"],
        "observations": len(checks),
        "failures": failures,
        "verdict": "pass" if not failures else "fail",
    }


def courts() -> list[dict]:
    """`RT-PHASE22-DISPATCH`, or `[]` while the artefact has not landed."""
    path = REPO_ROOT / ARTEFACT_REL
    if not path.is_file():
        return []
    doc = json.loads(path.read_text(encoding="utf-8"))
    return [court_dispatch(doc["body"])]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
