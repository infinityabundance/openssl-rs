#!/usr/bin/env python3
"""openssl-rs — the provider algorithm-row census.

Why this exists
---------------
`forensics/atlas/openssl-3.6.4-production/symbols-*.json` and the six-and-a-half-thousand
export atlas enumerate *symbols*. A provider also publishes **algorithm registration rows**,
which are not symbols: `providers/defltprov.c`'s `deflt_ciphers[]` and its siblings are
arrays whose members name algorithms and point at internal dispatch tables, and no
`util/libcrypto.num` entry exists for any of them. So a row can be absent from the crate
and from every ledger list and still be a missing piece of the contract — which is exactly
what the review found with **`DES3-WRAP`**: `PROV_NAMES_DES3_WRAP ->
ossl_tdes_wrap_cbc_functions`, sitting between the EDE3 CFB rows and the EDE2 rows, in no
crate source, in no "provider half still open" list, and invisible to the export atlas
because it is a row and not a symbol.

This is the whole architectural class D49 recorded for `a2d_ASN1_OBJECT`: *the contract
exists in an observable surface outside the universe the primary ledger enumerates.* The
cure is the same one, one level down: generate the census from the pinned provider tables
and check the crate against it, so a row cannot be missing without the census saying so.

What it reads, and what it derives rather than types
---------------------------------------------------
    the provider tables   providers/{defltprov,legacyprov,baseprov,nullprov}.c, and the
                          `.inc` files the encoder, decoder and store tables include
    the profile's guards   build/include/openssl/configuration.h, which defines
                          `OPENSSL_NO_*` for every feature this build disabled, so a
                          `#ifndef OPENSSL_NO_OCB` row is included or excluded by
                          measurement and not by assumption
    the operation ids      the authority's own `OSSL_OP_*` defines
    the name strings       providers/implementations/include/prov/names.h
    the crate's rows       src/provider/cipher.rs's `DEFLT_CIPHERS` and
                          src/provider/digest.rs's `DEFLT_DIGESTS`, whose alias strings the
                          rows were transcribed from

Every row is emitted with the provider, the operation, its position in the table, the
primary name and aliases, the property definition, the dispatch-table symbol, the
capability predicate (for the `ALGC(...)` rows), the owning phase, the
`implementation_state` and the blocker, plus a derived `projection` block that says which
stratum each unlanded row is *open for* and which rows a stratum has *handed on*
(docs/DECISIONS.md D295). Only two things are authored, because they are policy rather than
measurement: `forensics/atlas/provider-algorithm-plans.json`'s per-operation default owner and
its per-row overrides. **A row the plan does not classify is a failure**, which is the
enforcement: a row the authority publishes and the crate does not cannot go unnoticed, because
it has to be classified before this tool will write its output.

The capability filter is a prerequisite, not a later repair
-----------------------------------------------------------
`deflt_query` does **not** return `deflt_ciphers[]`. It returns `exported_ciphers[]`, which
`ossl_default_provider_init` fills with `ossl_prov_cache_exported_algorithms(deflt_ciphers,
exported_ciphers)`: a row whose `capable()` predicate answers 0 is not published at all.
That is why a `capability_predicate` column exists here rather than a boolean, and why the
census records the filtering relation explicitly. The crate's `deflt_query` returns
`DEFLT_CIPHERS` directly, which is correct for every row landed so far because none of them
is capability-gated — and becomes wrong the moment one arrives. The census states that as a
prerequisite in its own body so the filtering is built before the first gated row lands, not
after it.

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
    ATLAS,
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    Authority,
    InputRef,
    authority_build_dir,
    envelope,
    rel,
    resolve_authority,
    write_json,
)

GENERATOR = "forensics/tools/gen_provider_algorithms.py"
OUT = ATLAS / "provider-algorithms.json"
PLANS = ATLAS / "provider-algorithm-plans.json"

# (provider name, translation unit). `base` and `null` publish no algorithm rows at all,
# and they are listed rather than omitted so the absence is a measured zero in the census
# instead of a provider nobody counted.
PROVIDER_FILES = [
    ("default", "providers/defltprov.c"),
    ("legacy", "providers/legacyprov.c"),
    ("base", "providers/baseprov.c"),
    ("null", "providers/nullprov.c"),
]

# Macros the tables use, and what each contributes. The `#define`s are in the translation
# units themselves; these are the forms the row parser recognises. A form that is not here
# is a hard failure rather than a silently skipped row.
ROW_FORMS = {
    "ALG": {"names": 0, "dispatch": 1, "capable": None},
    "ALGC": {"names": 0, "dispatch": 1, "capable": 2},
    "STORE": {"names": 0, "dispatch": 2},
    "ENCODER": {"names": 0, "dispatch": 1},
    "ENCODER_TEXT": {"names": 0, "dispatch": 1},
    "ENCODER_w_structure": {"names": 0, "dispatch": 1},
    "DECODER": {"names": 0, "dispatch": 2},
    "DECODER_w_structure": {"names": 0, "dispatch": 3},
}

# The `.inc` row macros build their dispatch symbol by `##`-concatenation, so the symbol is
# derived here from the same arguments the authority's `#define` uses. These patterns are a
# transcription of those five `#define` bodies (encoders.inc:32-45, decoders.inc:28-35,
# stores.inc:13) and are the only place a symbol is written rather than read.
INC_DISPATCH = {
    # STORE(name, _fips, func_table) -- the table symbol is already the third argument.
    "STORE": lambda a: a[2],
    # ENCODER_TEXT(_name, _sym, _fips)
    "ENCODER_TEXT": lambda a: f"ossl_{a[1]}_to_text_encoder_functions",
    # ENCODER(_name, _sym, _fips, _output)
    "ENCODER": lambda a: f"ossl_{a[1]}_to_{a[3]}_encoder_functions",
    # ENCODER_w_structure(_name, _sym, _fips, _output, _structure)
    "ENCODER_w_structure": lambda a: f"ossl_{a[1]}_to_{a[4]}_{a[3]}_encoder_functions",
    # DECODER(_name, _input, _output, _fips)
    "DECODER": lambda a: f"ossl_{a[1]}_to_{a[2]}_decoder_functions",
    # DECODER_w_structure(_name, _input, _structure, _output, _fips)
    "DECODER_w_structure": lambda a: f"ossl_{a[2]}_{a[1]}_to_{a[3]}_decoder_functions",
}

# Macros that are *defined* at the point the `.inc` is included, so an `#ifndef` on one of
# them is false and the `#error` behind it is not reached.
INC_TIME_DEFINED = {"STORE", "ENCODER_PROVIDER", "DECODER_PROVIDER", "OSSL_NELEM"}

CLAIM = (
    "One row per algorithm registration row of every admitted provider's tables. The row "
    "inventory, the names, the property definitions, the dispatch symbols, the capability "
    "predicates and the row order are generated from the pinned provider translation units "
    "with the profile's own `configuration.h` guards applied; the dispatch-table symbol is "
    "never typed. `implementation_state` is `implemented` when the crate publishes the row and "
    "`unimplemented` when it does not, which is a fact about the row alone; whether such a row "
    "is *open for* a stratum or *handed on by* it is the `projection` block, derived from "
    "`owning_phase` rather than stored, and is the same computation under every stratum "
    "(docs/DECISIONS.md D295). `owning_phase` and `blocked_by` are the only authored inputs, "
    "in `provider-algorithm-plans.json`; a row the plan does not classify is a failure and no "
    "output is written. A row here is NOT an exported symbol and carries no ABI obligation."
)


class CensusError(SystemExit):
    """The census cannot be derived, and says why."""


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def strip_comments(text: str) -> str:
    """Blank C comments, preserving newlines so guard line numbers stay meaningful."""
    out = []
    i, n = 0, len(text)
    state = "code"
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if state == "code":
            if c == "/" and nxt == "*":
                out.append("  ")
                i += 2
                state = "block"
                continue
            if c == "/" and nxt == "/":
                out.append("  ")
                i += 2
                state = "line"
                continue
            out.append(c)
            i += 1
        elif state == "block":
            if c == "*" and nxt == "/":
                out.append("  ")
                i += 2
                state = "code"
                continue
            out.append("\n" if c == "\n" else " ")
            i += 1
        else:
            if c == "\n":
                out.append("\n")
                state = "code"
            else:
                out.append(" ")
            i += 1
    return "".join(out)


def disabled_macros(build: Path) -> set[str]:
    """The `OPENSSL_NO_*` macros this profile defines, read from its own configuration.h."""
    cfg = build / "include" / "openssl" / "configuration.h"
    if not cfg.is_file():
        raise CensusError(f"[provider-algorithms] fatal: no configuration.h at {cfg}")
    return set(re.findall(r"^\s*#\s*define\s+(OPENSSL_NO_[A-Z0-9_]+)", read(cfg), re.M))


def operation_ids(prefix: Path) -> dict[str, int]:
    header = prefix / "include" / "openssl" / "core_dispatch.h"
    if not header.is_file():
        raise CensusError(f"[provider-algorithms] fatal: no core_dispatch.h at {header}")
    return {
        m.group(1): int(m.group(2))
        for m in re.finditer(r"^\s*#\s*define\s+(OSSL_OP_[A-Z_]+)\s+(\d+)", read(header), re.M)
    }


def prov_names(source: Path) -> dict[str, str]:
    path = source / "providers" / "implementations" / "include" / "prov" / "names.h"
    if not path.is_file():
        raise CensusError(f"[provider-algorithms] fatal: no names.h at {path}")
    return dict(re.findall(r'^\s*#\s*define\s+(PROV_NAMES_[A-Za-z0-9_]+)\s+"([^"]*)"', read(path), re.M))


def eval_guard(expr: str, defined: set[str]) -> bool:
    """Evaluate the guard forms the provider tables actually spell.

    Supported: `defined(X)`, `!defined(X)`, a bare identifier, `&&`, `||` and parentheses.
    Anything else is a hard failure -- a guard this tool cannot evaluate is a row it would
    otherwise guess about, and the census is supposed to be a measurement.
    """
    expr = expr.strip()
    expr = re.sub(r"defined\s*\(\s*([A-Za-z0-9_]+)\s*\)", lambda m: "1" if m.group(1) in defined else "0", expr)
    expr = re.sub(r"\b[A-Za-z_][A-Za-z0-9_]*\b", lambda m: "1" if m.group(0) in defined else "0", expr)
    if re.fullmatch(r"[01!&|() ]+", expr) is None:
        raise CensusError(f"[provider-algorithms] fatal: unevaluable guard: {expr!r}")
    py = expr.replace("&&", " and ").replace("||", " or ").replace("!", " not ")
    try:
        return bool(eval(py, {"__builtins__": {}}, {}))  # noqa: S307 -- the expression is [01!&|() ] only
    except SyntaxError as exc:
        raise CensusError(f"[provider-algorithms] fatal: unevaluable guard: {expr!r}") from exc


def evaluate_lines(
    lines: list[str], defined: set[str], src_label: str = "a preprocessed stream"
) -> list[tuple[int, str]]:
    """(line number, text) for every line the preprocessor would keep.

    `#include "x.inc"` is spliced in place, recursively, so a table that is assembled from
    an include is parsed as the authority compiles it. A `#define` and its backslash
    continuations are one preprocessor statement and are dropped whole. `src_label` exists so
    the `#elif` refusal can name the file it is in.
    """
    out: list[tuple[int, str]] = []
    stack: list[bool] = []

    def active() -> bool:
        return all(stack)

    i = 0
    while i < len(lines):
        raw = lines[i]
        i += 1
        m = re.match(r"\s*#\s*(ifdef|ifndef|if|elif|else|endif)\b(.*)$", raw)
        if m is None:
            if re.match(r"^\s*#", raw):
                if re.match(r'^\s*#\s*include\b', raw) and active():
                    out.append((i, raw))
                # A preprocessor directive: skip it together with its continuations.
                while raw.rstrip().endswith("\\") and i < len(lines):
                    raw = lines[i]
                    i += 1
                continue
            if active():
                out.append((i, raw))
            continue
        kind, rest = m.group(1), m.group(2).strip()
        if kind == "ifdef":
            stack.append(rest in defined)
        elif kind == "ifndef":
            stack.append(rest not in defined)
        elif kind == "if":
            stack.append(eval_guard(rest, defined))
        elif kind == "elif":
            # **Rejected rather than approximated** (D244). The previous arm was
            # `stack[-1] = stack[-1] or eval_guard(...)`, which keeps an `#elif` branch active
            # when an earlier branch was already true -- the opposite of what C does. It was
            # measured harmless on the admitted profile (all seven files this walks carry zero
            # `#elif`s), and that measurement is exactly why the arm is replaced by a refusal
            # instead of a fix: a branch-selection expression this file cannot get right is a
            # branch-selection expression it must not silently answer. The day an authority
            # update adds one, this fires and the arm gets written properly.
            raise CensusError(
                f"[provider-algorithms] fatal: {src_label}: unsupported `#elif` at line {i} "
                f"({rest!r}). This reader tracks a single boolean per nesting level, so it "
                f"cannot express `#elif`'s 'no earlier branch was taken' condition; refusing is "
                f"the fail-closed answer"
            )
        elif kind == "else":
            if not stack:
                raise CensusError("[provider-algorithms] fatal: #else without #if")
            stack[-1] = not stack[-1]
        else:
            if not stack:
                raise CensusError("[provider-algorithms] fatal: #endif without #if")
            stack.pop()
    if stack:
        raise CensusError("[provider-algorithms] fatal: unclosed #if")
    return out


def split_top(text: str, sep: str = ",") -> list[str]:
    """Split at `sep` occurrences that are not inside (), {} or a string/char literal."""
    out, cur, depth, in_str, in_chr, esc = [], "", 0, False, False, False
    for ch in text:
        if in_str or in_chr:
            cur += ch
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif in_str and ch == '"':
                in_str = False
            elif in_chr and ch == "'":
                in_chr = False
            continue
        if ch == '"':
            in_str = True
            cur += ch
        elif ch == "'":
            in_chr = True
            cur += ch
        elif ch in "({":
            depth += 1
            cur += ch
        elif ch in ")}":
            depth -= 1
            cur += ch
        elif ch == sep and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def table_bodies(text: str) -> dict[str, list[str]]:
    """`table name -> body lines` for every `const OSSL_ALGORITHM[...] NAME[] = { ... };`."""
    bodies: dict[str, list[str]] = {}
    for m in re.finditer(
        r"const\s+OSSL_ALGORITHM[A-Z_]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*\]\s*=\s*\{",
        text,
    ):
        name = m.group(1)
        i = m.end()
        depth = 1
        while i < len(text) and depth:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        if depth:
            raise CensusError(f"[provider-algorithms] fatal: unbalanced table {name}")
        bodies[name] = text[m.end(): i - 1].splitlines()
    return bodies


def query_switch(text: str) -> dict[str, str]:
    """`operation macro -> returned table`, from the provider's own `query` function."""
    out: dict[str, str] = {}
    for m in re.finditer(r"case\s+(OSSL_OP_[A-Z_]+)\s*:\s*return\s+([A-Za-z_][A-Za-z0-9_]*)\s*;", text):
        out[m.group(1)] = m.group(2)
    return out


def cache_relation(text: str) -> dict[str, str]:
    """`source table -> exported table` for every `ossl_prov_cache_exported_algorithms` call."""
    return {
        m.group(1): m.group(2)
        for m in re.finditer(
            r"ossl_prov_cache_exported_algorithms\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)",
            text,
        )
    }


def names_of(symbol: str, prov_names_map: dict[str, str], where: str) -> list[str]:
    """The alias list a row's name argument evaluates to."""
    if symbol.startswith('"'):
        literal = symbol.strip()
        if not (literal.startswith('"') and literal.endswith('"')):
            raise CensusError(f"[provider-algorithms] fatal: unparsable name literal {symbol!r} at {where}")
        value = literal[1:-1]
    elif symbol in prov_names_map:
        value = prov_names_map[symbol]
    else:
        raise CensusError(f"[provider-algorithms] fatal: unknown name symbol {symbol!r} at {where}")
    return [n for n in value.split(":") if n]


def property_for(form: str, args: list[str], provider: str) -> str:
    """The property definition a row carries."""
    if form == "ALG":
        return f"provider={provider}"
    if form == "ALGC":
        return f"provider={provider}"
    return ""


def parse_table(
    body: list[str],
    provider: str,
    source: Path,
    defined: set[str],
    prov_names_map: dict[str, str],
    table: str,
) -> list[dict]:
    """Every row of one table, guards applied and `.inc` includes spliced."""
    rows: list[dict] = []
    lines = evaluate_lines(body, defined, f"{source.name}:{table}")
    # Splice `.inc` includes in place; they are their own small preprocessor streams.
    spliced: list[tuple[int, str]] = []
    for lineno, text in lines:
        m = re.match(r'\s*#\s*include\s+"([^"]+\.inc)"', text)
        if m is None:
            spliced.append((lineno, text))
            continue
        inc = (source / "providers" / m.group(1))
        if not inc.is_file():
            raise CensusError(f"[provider-algorithms] fatal: missing include {inc}")
        inc_text = strip_comments(read(inc))
        for sm in re.finditer(
            r'^\s*#\s*define\s+((?:ENCODER|DECODER)_STRUCTURE_[A-Za-z0-9_]+)\s+"([^"]*)"',
            inc_text,
            re.M,
        ):
            symbol = sm.group(1)
            kind, token = symbol.split("_STRUCTURE_", 1)
            _STRUCTURE_CACHE[(kind, token)] = sm.group(2)
        spliced.extend(
            evaluate_lines(
                inc_text.splitlines(),
                defined | INC_TIME_DEFINED,
                f"{inc.name} (included by {source.name})",
            )
        )
        # The `.inc` files end their last row without a trailing comma, so the include site's
        # own terminator would be glued onto it. One comma keeps the row boundaries.
        spliced.append((-1, ","))

    joined = "\n".join(t for _l, t in spliced)
    for element in split_top(joined):
        element = element.strip()
        if not element:
            continue
        if element.startswith("{"):
            fields = split_top(element.strip()[1:-1].strip())
            if len(fields) < 3:
                # `OSSL_ALGORITHM_CAPABLE`'s terminator is `{ { NULL, NULL, NULL }, NULL }`,
                # which has two members. It is not a row.
                continue
            name_sym, prop, dispatch = fields[0], fields[1], fields[2]
            if name_sym.strip() == "NULL":
                continue
            capable = None
            form = "BRACES"
            if prop.startswith('"'):
                prop_value = prop.strip()[1:-1]
            else:
                prop_value = prop
        else:
            m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)\)\s*$", element, re.S)
            if m is None:
                raise CensusError(f"[provider-algorithms] fatal: unrecognised row in {table}: {element!r}")
            form = m.group(1)
            if form not in ROW_FORMS:
                raise CensusError(f"[provider-algorithms] fatal: unknown row macro {form} in {table}")
            args = split_top(m.group(2).strip())
            spec = ROW_FORMS[form]
            name_sym = args[spec["names"]]
            dispatch = args[spec["dispatch"]]
            capable = args[spec["capable"]] if spec.get("capable") is not None and len(args) > (spec["capable"] or 0) else None
            if form in INC_DISPATCH:
                dispatch = INC_DISPATCH[form](args)
                prop_value = inc_property(form, args, provider)
            else:
                prop_value = property_for(form, args, provider)
        if dispatch.strip().upper() == "NULL":
            continue
        name_sym = name_sym.strip()
        if form in ("ENCODER", "ENCODER_TEXT", "ENCODER_w_structure", "DECODER", "DECODER_w_structure", "STORE"):
            aliases = [name_sym.strip('"')]
        else:
            aliases = names_of(name_sym, prov_names_map, f"{table}:{name_sym}")
        rows.append(
            {
                "table": table,
                "algorithm_names": aliases[0],
                "aliases": aliases,
                "property_definition": prop_value,
                "dispatch_table_symbol": dispatch.strip().lstrip("(").rstrip(")"),
                "capability_predicate": None if capable is None or capable.strip() == "NULL" else capable.strip(),
            }
        )
    if not rows and not any(t.strip().startswith(("{", "ALG", "ENCODER", "DECODER", "STORE")) for _l, t in spliced):
        return []
    return rows


def inc_property(form: str, args: list[str], provider: str) -> str:
    """The literal property string the `.inc` macro builds, from the same `#`-stringification."""
    if form == "ENCODER_TEXT":
        return f"provider={provider},fips={args[2]},output=text"
    if form == "ENCODER":
        return f"provider={provider},fips={args[2]},output={args[3]}"
    if form == "ENCODER_w_structure":
        return f"provider={provider},fips={args[2]},output={args[3]},structure={structure_string('ENCODER', args[4], provider)}"
    if form == "DECODER":
        return f"provider={provider},fips={args[3]},input={args[1]}"
    if form == "DECODER_w_structure":
        return f"provider={provider},fips={args[4]},input={args[1]},structure={structure_string('DECODER', args[2], provider)}"
    if form == "STORE":
        return f"provider={provider},fips={args[1]}"
    raise CensusError(f"[provider-algorithms] fatal: no property rule for {form}")


_STRUCTURE_CACHE: dict[tuple[str, str], str] = {}


def structure_string(kind: str, token: str, provider: str) -> str:
    del provider
    try:
        return _STRUCTURE_CACHE[(kind, token)]
    except KeyError as exc:
        raise CensusError(
            f"[provider-algorithms] fatal: no {kind}_STRUCTURE_{token} define was read"
        ) from exc


# --- the crate's landed rows ------------------------------------------------------------------


def read_crate_table(path: Path, ident: str) -> list[tuple[str, str]]:
    """`(alias string, Rust dispatch expression)` for every row of one crate algorithm table.

    Two row forms exist in this crate and both are the authority's own: a table may carry the alias
    sequence inline (`DEFLT_DIGESTS`'s `algorithm_names: c"…"`, which is what `PROV_NAMES_*` expands
    to) or through the module's `alias!` map (`DEFLT_CIPHERS`'s `row(N_AES_128_CBC, …)`, which is what
    `defltprov.c`'s `ALG(PROV_NAMES_AES_128_CBC, …)` expands to). Reading both is what makes this a
    *reader* rather than three readers; the inline form is checked against the number of
    `algorithm_names:` fields so a row the regex missed cannot pass as a table with fewer rows.
    """
    text = read(path)
    start = text.index(f"static {ident}")
    end = text.index("];", start)
    body = text[start:end]

    # **Three spellings of one row, and the third was missing.** A row may carry its alias sequence
    # inline (`c"SEED-SRC".as_ptr()`, which is what `PROV_NAMES_*` expands to and what
    # `DEFLT_RANDS` writes) or through the module's `alias!` map (`row(N_AES_128_CBC, ...)`, which is
    # what `defltprov.c`'s `ALG(...)` expands to) -- and, as `src/provider/seed_src.rs`'s
    # `BASE_RANDS` does, through a `const … : *const c_char = c"…".as_ptr()` the module already
    # declares for that name. The third form is the *same* contract in a better spelling (the
    # literal appears once), so the reader resolves it rather than requiring the caller to repeat
    # the string; D420 is where the base provider's row needed it. Every form is checked against the
    # number of `algorithm_names:` fields, so a row the reader misses is an error and not a table
    # with fewer rows.
    consts = {
        m.group(1): m.group(2)
        for m in re.finditer(
            r'const\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*\*const c_char\s*=\s*c"([^"]*)"\s*\.as_ptr\(\)',
            text,
            re.S,
        )
    }
    spellings = [
        (m.start(), m.group(1) or consts.get(m.group(2)), m.group(3), m.group(2))
        for m in re.finditer(
            r'algorithm_names:\s*(?:c"([^"]*)"|([A-Za-z_][A-Za-z0-9_]*))\s*'
            r'(?:\.as_ptr\(\))?\s*,'
            r'.*?implementation:\s*([A-Za-z0-9_:]+)\.as_ptr\(\)',
            body,
            re.S,
        )
    ]
    unresolved = sorted({ident for _p, name, _d, ident in spellings if name is None})
    if unresolved:
        raise CensusError(
            f"[provider-algorithms] fatal: {rel(path)}'s {ident} names the algorithm_names "
            f"constant(s) {unresolved}, which this reader cannot resolve to a literal in the same "
            "module; a row it cannot read is a row it must not skip"
        )
    if spellings:
        # The field count is the number of rows **that spell a name**, so a terminator row's
        # `algorithm_names: ptr::null()` is not one of them -- counting every `algorithm_names:`
        # would report a table of N rows as having N+1 and fail on a correct table.
        aliased_fields = len(
            re.findall(
                r'algorithm_names:\s*(?:c"|[A-Za-z_][A-Za-z0-9_]*\s*(?:\.as_ptr\(\))?\s*,)',
                body,
            )
        )
        if len(spellings) != aliased_fields:
            raise CensusError(
                f"[provider-algorithms] fatal: {rel(path)}'s {ident} has {aliased_fields} "
                f"aliased row(s) and the reader found {len(spellings)}; a row it cannot read is a "
                f"row it must not skip"
            )
        return [(name, dispatch) for _p, name, dispatch, _ident in sorted(spellings)]

    aliases = {
        m.group(1): m.group(2)
        for m in re.finditer(r'alias!\(\s*([A-Za-z0-9_]+)\s*,\s*"([^"]*)"\s*\)', text, re.S)
    }
    rows: list[tuple[str, str]] = []
    for m in re.finditer(r"row\(\s*([A-Za-z0-9_]+)\s*,\s*([A-Za-z0-9_:]+)\.as_ptr\(", body):
        name = aliases.get(m.group(1))
        if name is None:
            raise CensusError(
                f"[provider-algorithms] fatal: {rel(path)}'s {ident} names the unknown alias "
                f"{m.group(1)}, so its alias sequence cannot be read"
            )
        rows.append((name, m.group(2)))
    # **The aliased form gets the same guard the inline form has above, and it did not have one.**
    # Its absence is D417: seven `AES`/`ARIA`/`SM4` GCM rows whose dispatch expression is a
    # *qualified path* (`cipher_gcm::AES128GCM_FUNCTIONS.as_ptr()`) were dropped in silence, because
    # the row pattern accepted only a bare identifier, so the census went on reading those rows
    # `unimplemented` while the crate had published them. A row this reader cannot read must be an
    # error rather than a table with one fewer row, which is what the inline branch already says.
    invocations = len(re.findall(r"(?m)^\s*(?:capable_)?row\(", body))
    if len(rows) != invocations:
        raise CensusError(
            f"[provider-algorithms] fatal: {rel(path)}'s {ident} has {invocations} row "
            f"invocation(s) and the reader found {len(rows)}; a row it cannot read is a row it "
            "must not skip"
        )
    if not rows:
        raise CensusError(
            f"[provider-algorithms] fatal: {rel(path)}'s {ident} yielded no rows in either form, "
            "so the census would lose a whole operation in silence"
        )
    return rows


# The crate's providers publish their algorithm tables through one query function each. The
# reader below is anchored on **those functions' arms** rather than on a table of per-operation
# readers, because a per-operation list is the failure mode this census exists to remove: a row
# landed under an operation nobody wrote a reader for would be invisible, which is `DES3-WRAP`'s
# class (D237) reached from the candidate side. Adding an operation to a provider's query is now
# enough for the census to see it (D246).
#
# **There is more than one provider, and D420 is what found that the reader knew only one.** It
# carried a single `CRATE_QUERY_UNIT`/`CRATE_QUERY_PROVIDER` pair, so a row the *base* provider
# publishes could never be read as `implemented` however the crate was shaped -- the base
# provider's `SEED-SRC` row was `unimplemented` by construction, not by measurement. Each entry is
# `(provider name, module, the query function's own definition line)`.
CRATE_QUERY_READERS: list[tuple[str, Path, str]] = [
    ("default", REPO_ROOT / "src" / "provider" / "digest.rs", 'unsafe extern "C" fn deflt_query('),
    ("base", REPO_ROOT / "src" / "provider" / "base.rs", 'unsafe extern "C" fn base_query('),
]
# An arm may return a table's `.as_ptr()` or call a function that answers the address. The second
# form exists because one arm answers a **filtered copy** rather than the source table. A `//`
# comment may sit between the brace and the `return`, which is how `src/provider/base.rs` documents
# each of its arms -- and a reader that could not see past one would report the base provider's
# whole table set as absent, silently. D420 found that the first time this reader met a commented
# arm; the per-reader guard below is what makes the next one a failure instead.
CRATE_QUERY_ARM = re.compile(
    r"if\s+operation_id\s*==\s*([A-Za-z0-9_:]+)\s*\{"
    r"(?:\s*//[^\n]*)*\s*return\s+([A-Za-z0-9_:]+)\s*(\(\)|\.as_ptr\(\))\s*;"
)
# An arm that answers `NULL` publishes nothing, which is the base provider's three unlanded
# operations (`src/provider/base.rs`'s `base_query`). It is not a table and must not be resolved as
# one; the alternative -- shaping the provider's code so the reader cannot see it -- is what this
# census is for. A *typo* in a table path is still an error, because it resolves to neither form.
CRATE_QUERY_ARM_NULL = "ptr::null"
# `OSSL_OP_CIPHER`'s arm answers `exported_ciphers`, which
# `ossl_prov_cache_exported_algorithms` fills from `DEFLT_CIPHERS` at provider init (D275). The
# census must read the **source** table: the filtered copy is a runtime projection of it, and a row
# the filter drops is still a row the crate published a capability predicate for. That is a fact
# about this crate's structure rather than a naming convention, so it is written down here rather
# than inferred from the call.
CRATE_QUERY_ARM_SOURCE = {
    "crate::provider::cipher::exported_ciphers": "DEFLT_CIPHERS",
}


def crate_query_tables(ops: dict[str, int]) -> dict[tuple[str, str], list[tuple[str, str]]]:
    """`(provider, operation)` -> `[(alias string, dispatch expression)]`, from the crate itself.

    Each arm names an `OSSL_OP_*` constant and the table it returns. The constant's final path
    segment is looked up in the authority's own operation ids, so an arm naming a constant the
    authority does not define is a failure rather than an unclassified row set; and the table's
    module is derived from the arm's own path, so where a table *lives* is read rather than typed.
    """
    text = None
    tables: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for provider, unit, fn_line in CRATE_QUERY_READERS:
        text = read(unit)
        start = text.index(fn_line)
        end = text.index("\n}", start)
        body = text[start:end]
        arms_seen = 0
        for arm in CRATE_QUERY_ARM.finditer(body):
            constant, table_path = arm.group(1), arm.group(2)
            arms_seen += 1
            if table_path == CRATE_QUERY_ARM_NULL:
                # This arm publishes nothing -- see `CRATE_QUERY_ARM_NULL`.
                continue
            source = CRATE_QUERY_ARM_SOURCE.get(table_path)
            if source is not None:
                # The arm answers a derived table; the census reads the one it derives from.
                table_path = f"crate::provider::cipher::{source}"
            operation = constant.split("::")[-1]
            if operation not in ops:
                raise CensusError(
                    f"[provider-algorithms] fatal: {rel(unit)}'s `{provider}` query answers "
                    f"{constant}, which the authority defines no operation id for"
                )
            segments = table_path.split("::")
            if len(segments) == 1:
                # A bare identifier is a table in the module the query itself lives in, which is
                # how the authority's `defltprov.c` spells its own `deflt_digests[]`.
                path = unit
                ident = segments[-1]
            else:
                if segments[0] != "crate":
                    raise CensusError(
                        f"[provider-algorithms] fatal: {rel(unit)}'s `{provider}` query returns "
                        f"{table_path}, which is not a path this reader can resolve to a module"
                    )
                module_segments = segments[1:-1]
                if not module_segments or module_segments[0] != "provider":
                    raise CensusError(
                        f"[provider-algorithms] fatal: {table_path} is not a provider module table"
                    )
                module = REPO_ROOT / "src" / Path(*module_segments)
                candidates = [module.with_suffix(".rs"), module / "mod.rs"]
                path = next((c for c in candidates if c.is_file()), None)
                if path is None:
                    raise CensusError(
                        f"[provider-algorithms] fatal: {table_path} names no module under src/ "
                        f"(tried {[rel(c) for c in candidates]})"
                    )
                ident = segments[-1]
            key = (provider, operation)
            if key in tables:
                raise CensusError(
                    f"[provider-algorithms] fatal: `{provider}`'s query answers {operation} twice, "
                    "so one arm's rows would be unreachable"
                )
            tables[key] = read_crate_table(path, ident)
        # **A reader that recognises no arm is a failure, not an empty result.** Without this the
        # base provider's four arms could go unread -- which is what happened the first time this
        # reader met a commented arm -- and the census would report the provider's rows unlanded
        # while the crate published them. That is D417's silent-drop class one level up.
        if arms_seen == 0:
            raise CensusError(
                f"[provider-algorithms] fatal: {rel(unit)}'s `{provider}` query has no arm this "
                "reader recognises, so the provider's rows would be read as unlanded in silence"
            )
    if not tables:
        raise CensusError(
            "[provider-algorithms] fatal: no crate query function in "
            f"{[rel(u) for _p, u, _f in CRATE_QUERY_READERS]} has an arm this reader recognises"
        )
    return tables


def primary(alias_string: str) -> str:
    return alias_string.split(":")[0]


def provider_projection(rows: list[dict]) -> dict:
    """`open` and `deferred` per stratum, **derived** from `owning_phase` (D295).

    This is the block that replaces a stored phase-relative state. `open[N]` is the number of rows
    the plan gives stratum N that the crate has not landed -- the row set that blocks N's
    completion. `handed_on[N]` is the number of unlanded rows the plan gives a *later* stratum,
    which are the rows N has handed on rather than left undone. Both are functions of the row set
    alone, so running this census while a different stratum is active cannot move them, which is
    exactly what the deleted `"open" if phase == 8 else "deferred"` could not promise.

    The strata are the ones the plan names, read from the rows, so a stratum added to
    `provider-algorithm-plans.json` appears here without an edit -- the same discovery rule the
    rest of this file follows.
    """
    phases = sorted({int(r["owning_phase"]) for r in rows})
    unlanded = [r for r in rows if r["implementation_state"] == "unimplemented"]
    return {
        "open": {str(p): sum(1 for r in unlanded if int(r["owning_phase"]) == p) for p in phases},
        "handed_on": {
            str(p): sum(1 for r in unlanded if int(r["owning_phase"]) > p) for p in phases
        },
        "what": (
            "`open[N]` are the rows the plan gives stratum N that the crate does not publish, and "
            "`handed_on[N]` are the unlanded rows the plan gives a later stratum. Both are derived "
            "from each row's `owning_phase` and `implementation_state` and are not stored on the "
            "row, because a stored `open`/`deferred` is a statement about which stratum was "
            "active on the day the census ran (docs/DECISIONS.md D295)."
        ),
    }


# --- plans ------------------------------------------------------------------------------------


def load_plans() -> dict:
    if not PLANS.is_file():
        raise CensusError(f"[provider-algorithms] fatal: no plans file at {rel(PLANS)}")
    plan = json.loads(read(PLANS))
    return plan


def plan_for(plan: dict, provider: str, operation: str, row: dict) -> tuple[int | None, str | None, str]:
    """`(owning_phase, blocked_by, matched_by)` for one row, most specific match first."""
    for ov in plan.get("overrides", []):
        if ov["provider"] != provider or ov["operation"] != operation:
            continue
        if "name" in ov and ov["name"] != row["algorithm_names"]:
            continue
        if "name_prefix" in ov and not row["algorithm_names"].startswith(ov["name_prefix"]):
            continue
        if "capability" in ov and ov["capability"] != bool(row["capability_predicate"]):
            continue
        return ov["phase"], ov.get("blocked_by"), f"override:{ov.get('name') or ov.get('name_prefix') or 'capability'}"
    for d in plan.get("operation_defaults", []):
        if d["provider"] == provider and d["operation"] == operation:
            return d["phase"], d.get("blocked_by"), "operation-default"
    return None, None, "none"


# --- the provider context, and the one thing it becomes load-bearing for ---------------------
#
# `ciphercommon.c.in`'s `ossl_cipher_generic_initkey` ends with
#
#     if (provctx != NULL)
#         ctx->libctx = PROV_LIBCTX_OF(provctx); /* used for rand */
#
# so a provider *cipher* context carries the library context of the provider that created it.
# That is the context `RAND_bytes_ex(ctx->libctx, ...)` resolves against in the GCM rows' no-IV
# arm and in `cipher_tdes_wrap.c`'s IV generation, and `EVP_CIPHER_fetch(ctx->libctx, ...)` and
# `EVP_MAC_fetch(libctx, ...)` resolve their sub-fetches against it too.
#
# **D241 discharged the plumbing, and this block is now the inverse measurement.** It used to
# *fail* when the crate grew the plumbing -- that was the obligation's stated retirement
# condition, and it is what fired -- and it now fails when the plumbing is *removed*. A
# certificate that fails when it stops being true is the shape that condition asked for.
#
# **D241 was also one row short, and the court arm is what found it.** The obligation was
# discharged at `ossl_cipher_generic_initkey` only, so `aes_siv_newctx` -- the *other* landed
# cipher unit that acquires the context -- kept `(*ctx).libctx = ptr::null_mut();`. Its own doc
# comment asserted the opposite was harmless, on the grounds that a NULL context and the default
# context are the same thing; that is true of the *values* and false of the *scope*, which is
# what this file is for. So the certificate below is no longer one needle in one file: it is the
# complete set of authority sites that acquire the context, each one checked **inside the crate
# function that owes it**, because a needle that is present somewhere in the file is exactly how
# the second site passed the first certificate.

# An *acquisition*: an object taking its library context from the provider context its provider
# was created with. Readers -- `OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);` locals, and the
# `RAND_*_ex(ctx->libctx, …)` / `EVP_*_fetch(ctx->libctx, …)` calls -- need no row of their own,
# because they read a field these assignments are what set.
LIBCTX_CARRY_RE = re.compile(r"\w+->libctx\s*=\s*PROV_LIBCTX_OF\(provctx\)")

# The land the enumeration walks. The `.c.in` templates are the authority's own source and are
# enumerated from the source tree; the build tree's expanded copies carry different line numbers
# and are deliberately not walked, so a site has exactly one row.
LIBCTX_CARRY_ROOT = "providers/implementations"

# Every acquisition site, with what discharges it.
#
#   state `landed`  the crate carries the context, and `crate_fn`'s **body** is checked for
#                   exactly one `.libctx` assignment, equal to `anchor`
#   state `open`    a named phase's own remaining work
#   state `later`   a family no current subphase has reached
#
# The set is compared for **exact equality** against the authority, so a site the authority has
# and this table does not classify fails the census instead of going unmentioned -- the `DES3-WRAP`
# failure class (D237), one level down.
LIBCTX_CARRY_SITES: list[dict] = [
    # The four cipher sites: the generic path (`ciphercommon.c.in`), the two AEAD rows that acquire
    # at `newctx` because their own `initkey` never reaches the generic one (`cipher_aes_siv.c`,
    # `cipher_aes_gcm_siv.c`), and GCM's.
    {
        "unit": "providers/implementations/ciphers/ciphercommon.c.in",
        "line": 759,
        "state": "landed",
        "owner": "8.3",
        "crate": "src/provider/cipher.rs",
        "crate_fn": "ossl_cipher_generic_initkey",
        "anchor": "(*ctx).libctx = crate::provider::ctx::prov_libctx_of(provctx);",
    },
    {
        "unit": "providers/implementations/ciphers/cipher_aes_siv.c",
        "line": 44,
        "state": "landed",
        "owner": "8.3",
        "crate": "src/provider/cipher.rs",
        "crate_fn": "aes_siv_newctx",
        "anchor": "(*ctx).libctx = crate::provider::ctx::prov_libctx_of(provctx);",
    },
    {
        "unit": "providers/implementations/ciphers/cipher_aes_gcm_siv.c",
        "line": 38,
        "state": "open",
        "owner": "8.3",
        "blocked_by": "the `AES-*-GCM-SIV` rows are 8.3's own remaining work",
    },
    {
        "unit": "providers/implementations/ciphers/ciphercommon_gcm.c.in",
        "line": 47,
        "state": "open",
        "owner": "9",
        "blocked_by": "the `AES-*-GCM` rows are handed to phase 9 on `RAND_bytes_ex`",
    },
    # The signature, asym-cipher, KEM, KDF and exchange families: none of them has reached the
    # crate, and the owner is the subphase the plan already names or `later` where it names none.
    {"unit": "providers/implementations/signature/rsa_sig.c.in", "line": 248, "state": "later", "owner": "8.4"},
    {"unit": "providers/implementations/asymciphers/rsa_enc.c.in", "line": 96, "state": "later", "owner": "8.4"},
    {"unit": "providers/implementations/kem/rsa_kem.c.in", "line": 100, "state": "later", "owner": "8.4"},
    {"unit": "providers/implementations/exchange/dh_exch.c.in", "line": 99, "state": "later", "owner": "8.5"},
    {"unit": "providers/implementations/signature/dsa_sig.c.in", "line": 144, "state": "later", "owner": "8.6"},
    {"unit": "providers/implementations/signature/ecdsa_sig.c.in", "line": 163, "state": "later", "owner": "8.7"},
    {"unit": "providers/implementations/signature/eddsa_sig.c.in", "line": 182, "state": "later", "owner": "8.7"},
    {"unit": "providers/implementations/signature/sm2_sig.c.in", "line": 132, "state": "later", "owner": "8.7"},
    {"unit": "providers/implementations/asymciphers/sm2_enc.c.in", "line": 61, "state": "later", "owner": "8.7"},
    {"unit": "providers/implementations/kem/ec_kem.c.in", "line": 205, "state": "later", "owner": "8.7"},
    {"unit": "providers/implementations/kem/ecx_kem.c.in", "line": 169, "state": "later", "owner": "8.7"},
    {"unit": "providers/implementations/signature/mac_legacy_sig.c", "line": 62, "state": "later", "owner": "8.8"},
    {"unit": "providers/implementations/keymgmt/kdf_legacy_kmgmt.c", "line": 44, "state": "later", "owner": "8.8"},
    {"unit": "providers/implementations/kdfs/argon2.c.in", "line": 944, "state": "later", "owner": None},
    {"unit": "providers/implementations/kdfs/argon2.c.in", "line": 963, "state": "later", "owner": None},
    {"unit": "providers/implementations/kdfs/argon2.c.in", "line": 982, "state": "later", "owner": None},
    {"unit": "providers/implementations/exchange/ecdh_exch.c.in", "line": 101, "state": "later", "owner": None},
    {"unit": "providers/implementations/kem/template_kem.c", "line": 67, "state": "later", "owner": None},
    {"unit": "providers/implementations/kem/mlx_kem.c", "line": 45, "state": "later", "owner": None},
    {"unit": "providers/implementations/signature/lms_signature.c", "line": 47, "state": "later", "owner": None},
    {"unit": "providers/implementations/signature/ml_dsa_sig.c.in", "line": 95, "state": "later", "owner": None},
    {"unit": "providers/implementations/signature/slh_dsa_sig.c.in", "line": 85, "state": "later", "owner": None},
]


def authority_libctx_carry_sites(auth: Authority) -> list[tuple[str, int]]:
    """Every acquisition site the pinned provider tree actually has, as `(unit, line)`.

    Walked rather than typed, which is what makes [`LIBCTX_CARRY_SITES`] a census instead of a
    list. `.c` and `.c.in` are both taken, in the source tree only.
    """
    root = auth.source / LIBCTX_CARRY_ROOT
    if not root.is_dir():
        raise CensusError(
            f"[provider-algorithms] fatal: {rel(root)} is missing, so the provider tree's "
            "library-context acquisition sites cannot be enumerated"
        )
    found: list[tuple[str, int]] = []
    for path in sorted(root.rglob("*")):
        if not (path.name.endswith(".c") or path.name.endswith(".c.in")):
            continue
        for number, line in enumerate(read(path).splitlines(), start=1):
            # A commented-out assignment is not an acquisition.
            if line.lstrip().startswith("//") or line.lstrip().startswith("*"):
                continue
            if LIBCTX_CARRY_RE.search(line):
                found.append((f"{LIBCTX_CARRY_ROOT}/{path.relative_to(root)}", number))
    return found


def rust_fn_body(text: str, name: str) -> str | None:
    """The source of the top-level Rust `fn name` body, `rustfmt`'s `^}` being its end.

    The certificate is anchored per *function* rather than per file because per file is what let
    `aes_siv_newctx` keep a NULL `libctx`: the needle was present, in
    `ossl_cipher_generic_initkey`. `None` means the function is absent, which is a failure for a
    site whose row says `landed`.
    """
    match = re.search(
        rf'^(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?(?:extern\s+"C"\s+)?fn {re.escape(name)}\s*[(<]',
        text,
        re.MULTILINE,
    )
    if match is None:
        return None
    end = text.find("\n}", match.end())
    if end == -1:
        return None
    return text[match.start():end + 2]


def check_libctx_carry_sites(auth: Authority) -> list[dict]:
    """The acquisition census: every authority site classified, every landed one anchored.

    Three failures are possible and all three are fatal:

      * the authority has an acquisition this table does not classify (the `DES3-WRAP` class);
      * a classified site is no longer at the recorded unit and line, so the row has drifted;
      * a `landed` row's crate function does not hold exactly the recorded `.libctx` assignment
        -- absent, doubled, or replaced by a NULL.

    The third is the one D241's first certificate could not see, so it is checked inside the
    function rather than anywhere in the file.
    """
    found = sorted(authority_libctx_carry_sites(auth))
    classified = sorted((row["unit"], row["line"]) for row in LIBCTX_CARRY_SITES)
    if len(set(classified)) != len(classified):
        raise CensusError("[provider-algorithms] fatal: LIBCTX_CARRY_SITES repeats a site")
    if found != classified:
        missing = [f"{u}:{n}" for u, n in found if (u, n) not in classified]
        stale = [f"{u}:{n}" for u, n in classified if (u, n) not in found]
        raise CensusError(
            "[provider-algorithms] fatal: the authority's library-context acquisition sites and "
            f"LIBCTX_CARRY_SITES disagree -- unclassified: {missing or 'none'}; no longer present: "
            f"{stale or 'none'}. A provider object that acquires the creating provider's library "
            "context must be classified where it is discharged, or the class goes missing the way "
            "`DES3-WRAP` did (D237, D241, D242)"
        )

    landed: list[dict] = []
    for row in LIBCTX_CARRY_SITES:
        if row["state"] != "landed":
            continue
        body = rust_fn_body(read(REPO_ROOT / row["crate"]), row["crate_fn"])
        if body is None:
            raise CensusError(
                f"[provider-algorithms] fatal: {row['crate']} has no fn {row['crate_fn']}, "
                f"which is the row that owes {row['unit']}:{row['line']}'s library context"
            )
        assignments = re.findall(r"\(\*\w+\)\.libctx\s*=\s*[^;]+;", body)
        if assignments != [row["anchor"]]:
            raise CensusError(
                f"[provider-algorithms] fatal: fn {row['crate_fn']} in {row['crate']} must hold "
                f"exactly one library-context assignment, {row['anchor']!r}, and holds {assignments}. "
                "A needle that is present elsewhere in the file is how `aes_siv_newctx` kept a NULL "
                "one while `ossl_cipher_generic_initkey` held the real one (D242)"
            )
        landed.append(dict(row))
    return landed


def provider_context(auth: Authority) -> dict:
    """The provider context's **discharge certificate**, and the rows whose plumbing it is.

    D240 recorded this as an obligation and gave it a retirement condition: an assignment to a
    `.libctx` field, or the disappearance of the NULL `provctx`, means the crate has grown the
    plumbing, and the block has to be re-derived in the same commit. That is what happened here,
    so what follows is the *inverse* measurement: every fact that used to hold is now asserted
    **not** to hold, and this generator fails if the plumbing is ever removed again. A certificate
    that fails when it stops being true is the shape D240's own message asked for, and the
    `court_arm` field names where the observation is taken.

    D242 widened it from one needle to the whole acquisition census, because the first version
    certified `ossl_cipher_generic_initkey` and nothing else -- and the site it left out was
    `aes_siv_newctx`.
    """
    digest_rs = read(REPO_ROOT / "src" / "provider" / "digest.rs")

    if "*provctx = ptr::null_mut();" in digest_rs:
        raise CensusError(
            "[provider-algorithms] fatal: src/provider/digest.rs publishes a NULL provctx again, "
            "so `PROV_LIBCTX_OF` has no argument and every provider sub-fetch in a private "
            "`OSSL_LIB_CTX` would silently reach the global one (D240, D241)"
        )
    if "*provctx = ctx.cast();" not in digest_rs:
        raise CensusError(
            "[provider-algorithms] fatal: src/provider/digest.rs no longer stores a `PROV_CTX` "
            "in `*provctx`, so this certificate has gone stale rather than been preserved"
        )
    landed = check_libctx_carry_sites(auth)
    ctx_rs = read(REPO_ROOT / "src" / "provider" / "ctx.rs")
    if "pub(crate) unsafe fn prov_libctx_of" not in ctx_rs:
        raise CensusError(
            "[provider-algorithms] fatal: src/provider/ctx.rs no longer publishes "
            "`prov_libctx_of`, which is the sites' `PROV_LIBCTX_OF`"
        )
    return {
        "state": "discharged",
        "what": (
            "Every provider object the crate builds acquires the library context of the provider "
            "that created it, so a row's sub-fetches and its `RAND_bytes_ex(ctx->libctx, …)` calls "
            "resolve in the creating provider's context rather than the global one. D240 recorded "
            "the gap as a measured obligation and made an assignment to a `.libctx` field its "
            "retirement condition; D241 landed the plumbing and D242 widened the measurement from "
            "one needle to the authority's whole acquisition census, so this block is the inverse "
            "measurement and fails if any landed site is removed or narrowed."
        ),
        "authority": {
            "unit": LIBCTX_CARRY_ROOT,
            "line": LIBCTX_CARRY_RE.pattern,
            "effect": (
                "a provider object stores the creating provider's library context, and the GCM "
                "no-IV arm and `cipher_tdes_wrap.c`'s IV generation call "
                "`RAND_bytes_ex(ctx->libctx, ...)` against it"
            ),
        },
        "crate": [
            {
                "path": "src/provider/digest.rs",
                "fact": "`ossl_default_provider_init` builds a `PROV_CTX` and stores it in `*provctx`",
            },
            {
                "path": "src/provider/cipher.rs",
                "fact": (
                    "the two landed sites assign "
                    f"{landed[0]['anchor']!r} inside {landed[0]['crate_fn']} and "
                    f"{landed[1]['crate_fn']}"
                ),
            },
            {
                "path": "src/provider/ctx.rs",
                "fact": "`prov_libctx_of` is `PROV_LIBCTX_OF`, and the accessors accept a NULL context",
            },
        ],
        "court_arm": (
            "`RT-CIPHER`'s `defltsiv.libctx*` observations, in two parts. The first is that a "
            "private `OSSL_LIB_CTX` is created, the default provider is loaded **in it**, "
            "AES-128-SIV is fetched there, and the tag matches both the same run in the global "
            "context and the published RFC 5297 A.1 value. The second is what catches a NULL "
            "context, because the first part cannot: the global context can always answer the "
            "row's sub-fetches, so the *values* are identical either way. So `fips=yes` is set as "
            "the private context's default properties -- a per-`OSSL_LIB_CTX` preference -- and "
            "`EVP_MAC_fetch(lc, \"CMAC\", NULL)` and a fresh `EVP_EncryptInit_ex2` on the "
            "already-fetched row are observed with it set, while the same `EVP_MAC_fetch(NULL, ...)` "
            "is observed unchanged. SIV is the row that makes scoping observable at all: "
            "`aes_siv_initkey` and `ossl_siv128_init` both sub-fetch through `PROV_LIBCTX_OF`, so "
            "with a NULL context the operation *succeeds* where the authority's fails."
        ),
        "libctx_carry_sites": [
            {
                "unit": row["unit"],
                "authority_line": row["line"],
                "state": row["state"],
                "owning_phase": row.get("owner"),
                "crate_fn": row.get("crate_fn"),
                "blocked_by": row.get("blocked_by"),
            }
            for row in LIBCTX_CARRY_SITES
        ],
        "libctx_carry_note": (
            f"All {len(LIBCTX_CARRY_SITES)} authority sites that acquire `PROV_LIBCTX_OF` into an "
            f"object are classified: {len(landed)} landed and anchored per crate function, "
            f"{sum(1 for r in LIBCTX_CARRY_SITES if r['state'] == 'open')} open on a named phase, "
            f"{sum(1 for r in LIBCTX_CARRY_SITES if r['state'] == 'later')} in a family no current "
            "subphase has reached. Readers of the field need no row: they read what these "
            "assignments set."
        ),
    }


def weak_tier() -> int:
    """Without the authority's tree, check the committed artefact against itself.

    The strong tier re-derives every row from the pinned provider tables. A runner that has
    only the repository cannot do that, so it checks what the artefact claims about itself:
    the recorded count is the number of rows, every row carries the documented fields with a
    legal state, no identity repeats, and the per-provider table counts sum to the rows. A
    hand-edited or truncated artefact fails here even though the authority is absent.
    """
    if not OUT.is_file():
        print(
            f"[provider-algorithms] neither the authority's provider tables nor {rel(OUT)} "
            f"is present; nothing can be checked",
            file=sys.stderr,
        )
        return 1
    body = json.loads(read(OUT))["body"]
    rows = body["rows"]
    required = {
        "provider", "operation", "operation_id", "row_order", "algorithm_names", "aliases",
        "property_definition", "dispatch_table_symbol", "capability_predicate", "source",
        "table_symbol", "implementation_state", "owning_phase", "blocked_by",
    }
    problems: list[str] = []
    if body.get("row_count") != len(rows):
        problems.append(f"row_count {body.get('row_count')} != {len(rows)} rows")
    identities = set()
    for r in rows:
        missing = required - set(r)
        if missing:
            problems.append(f"{r.get('algorithm_names')}: missing {sorted(missing)}")
        if r.get("implementation_state") not in ("implemented", "unimplemented"):
            problems.append(
                f"{r.get('algorithm_names')}: illegal implementation_state "
                f"{r.get('implementation_state')!r}"
            )
        ident = (r.get("provider"), r.get("operation"), r.get("table_symbol"), r.get("row_order"))
        if ident in identities:
            problems.append(f"double-counted row {ident}")
        identities.add(ident)
        # **The retired field name is rejected rather than ignored** (D295). A row carrying `state`
        # is either a stale artefact or a hand-edit that reintroduced the stratum-relative value
        # this change removed, and a reader that quietly used `implementation_state` beside it
        # would leave the stale one for every other consumer.
        if "state" in r:
            problems.append(
                f"{r.get('algorithm_names')}: carries the retired `state` field; the row state is "
                f"`implementation_state` and open/deferred are the `projection` block"
            )
    for p in body["providers"]:
        if sum(t["rows"] for t in p["tables"]) != len(
            [r for r in rows if r["provider"] == p["provider"]]
        ):
            problems.append(f"provider {p['provider']}: table counts do not sum to its rows")

    # The projection is derived, so it is checked against the rows it is derived from rather than
    # trusted. A hand-edited or one-generation-stale `projection` is a failure here, which is what
    # makes the block evidence instead of a summary (docs/DECISIONS.md D295).
    projection = body.get("projection")
    if not isinstance(projection, dict) or "open" not in projection or "handed_on" not in projection:
        problems.append("the `projection` block is absent or incomplete")
    else:
        unlanded = [r for r in rows if r["implementation_state"] == "unimplemented"]
        phases = sorted({int(r["owning_phase"]) for r in rows})
        want_open = {
            str(p): sum(1 for r in unlanded if int(r["owning_phase"]) == p) for p in phases
        }
        want_handed = {
            str(p): sum(1 for r in unlanded if int(r["owning_phase"]) > p) for p in phases
        }
        if projection.get("open") != want_open:
            problems.append(f"projection.open {projection.get('open')} != {want_open}")
        if projection.get("handed_on") != want_handed:
            problems.append(
                f"projection.handed_on {projection.get('handed_on')} != {want_handed}"
            )
    if problems:
        for p in problems[:20]:
            print(f"  {p}", file=sys.stderr)
        print(f"[provider-algorithms] {rel(OUT)} does not hold together", file=sys.stderr)
        return 1
    print(
        f"[provider-algorithms] ok (weak tier, provider tables absent): {rel(OUT)} "
        f"accounts for {len(rows)} row(s) over {len(body['providers'])} provider(s)"
    )
    return 0


def self_test(auth: Authority) -> int:
    """Provoke every way [`check_libctx_carry_sites`] can fail, and require the finding.

    A fail-closed check that cannot fail is indistinguishable from a passing check, so each
    failure mode is reconstructed here rather than argued for in prose: the site that regressed to
    a NULL, the same field write spelled with another local, the assignment doubled, an authority
    acquisition the table does not classify, a recorded line that has drifted, and the owing
    function renamed away. The crate-side cases are applied to copies of the real sources, so the
    tree is never touched.
    """
    real_read = read
    cipher = REPO_ROOT / "src" / "provider" / "cipher.rs"
    anchor = LIBCTX_CARRY_SITES[1]["anchor"]
    problems: list[str] = []

    def mutate_in_fn(text: str, fn: str, old: str, new: str) -> str:
        body = rust_fn_body(text, fn)
        if body is None or body.count(old) != 1:
            raise CensusError(f"self-test: cannot mutate {old!r} inside fn {fn}")
        return text.replace(body, body.replace(old, new))

    def expect(label: str, needle: str, *, sites=None, reader=real_read) -> None:
        global read
        saved = LIBCTX_CARRY_SITES[:]
        try:
            if sites is not None:
                LIBCTX_CARRY_SITES[:] = sites
            read = reader
            check_libctx_carry_sites(auth)
        except SystemExit as exc:
            if needle in str(exc):
                print(f"[provider-algorithms] ok   {label}")
                return
            problems.append(f"{label}: caught, but the message does not say {needle!r}: {exc}")
            return
        finally:
            LIBCTX_CARRY_SITES[:] = saved
            read = real_read
        problems.append(f"{label}: NOT caught, so the check is not fail-closed")

    def reader_with(fn_mutation):
        def _read(path: Path) -> str:
            text = real_read(path)
            return fn_mutation(text) if path == cipher else text

        return _read

    expect(
        "aes_siv_newctx regressed to a NULL libctx",
        "must hold exactly one library-context assignment",
        reader=reader_with(
            lambda t: mutate_in_fn(t, "aes_siv_newctx", anchor, "(*ctx).libctx = ptr::null_mut();")
        ),
    )
    expect(
        "the generic site respelled to a NULL",
        "must hold exactly one library-context assignment",
        reader=reader_with(
            lambda t: mutate_in_fn(
                t, "ossl_cipher_generic_initkey", anchor, "(*c).libctx = ptr::null_mut();"
            )
        ),
    )
    expect(
        "the site assigned twice",
        "must hold exactly one library-context assignment",
        reader=reader_with(
            lambda t: mutate_in_fn(
                t, "aes_siv_newctx", anchor, f"{anchor}\n            (*ctx).libctx = ptr::null_mut();"
            )
        ),
    )
    expect("an authority site the table does not classify", "unclassified", sites=LIBCTX_CARRY_SITES[1:])
    expect(
        "a recorded line that no longer matches",
        "no longer present",
        sites=[dict(r, line=r["line"] + 1) if r["state"] == "landed" else r for r in LIBCTX_CARRY_SITES],
    )
    expect(
        "the owing function renamed away",
        "has no fn",
        sites=[
            LIBCTX_CARRY_SITES[0],
            dict(LIBCTX_CARRY_SITES[1], crate_fn="aes_siv_newctx_renamed"),
            *LIBCTX_CARRY_SITES[2:],
        ],
    )

    # The weak tier's own checks, provoked the same way (D295). It reads the committed artefact
    # with the authority absent, so both new invariants are exercised against **mutated copies of
    # the real file**: a row that reintroduces the retired `state` field, and a `projection` block
    # that has drifted from the rows it is claimed to be derived from. A check nobody can make fail
    # is not evidence, and these two are the ones a later session would otherwise weaken.
    global OUT
    real_out = OUT
    committed = json.loads(real_out.read_text(encoding="utf-8"))

    def weak_tier_with(label: str, mutate) -> None:
        # `global OUT` is needed **here as well as in `self_test`**: the rebinding is what the check
        # under test reads, and a nested function that assigns it without the declaration
        # silences the check instead of provoking it -- which is how this self-test's first run
        # reported both invariants as "NOT caught" while the weak tier was reading the real file.
        global OUT
        broken = json.loads(json.dumps(committed))
        mutate(broken)
        probe = real_out.with_name("provider-algorithms.self-test.json")
        probe.write_text(json.dumps(broken), encoding="utf-8")
        OUT = probe
        try:
            caught = weak_tier() != 0
        finally:
            OUT = real_out
            probe.unlink(missing_ok=True)
        if not caught:
            problems.append(f"weak tier: {label} NOT caught, so the check is not fail-closed")
        else:
            print(f"[provider-algorithms] ok   weak tier caught {label}")

    weak_tier_with(
        "a row carrying the retired `state` field",
        lambda b: b["body"]["rows"][0].__setitem__("state", "open"),
    )

    def drift(b: dict) -> None:
        opens = b["body"]["projection"]["open"]
        opens[next(iter(opens))] = int(opens[next(iter(opens))]) + 1

    weak_tier_with("a `projection.open` that drifted from the rows", drift)

    if problems:
        print("[provider-algorithms] SELF-TEST FAILED:", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1
    print(
        "[provider-algorithms] self-test ok: all six ways to defeat the acquisition census, and "
        "both ways to defeat the weak-tier reader, are caught"
    )
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="provoke each way the library-context acquisition census can fail, and require it",
    )
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    if args.self_test:
        return self_test(auth)
    build = authority_build_dir(auth.id)
    first = auth.source / PROVIDER_FILES[0][1]
    if not first.is_file():
        return weak_tier()

    defined = disabled_macros(build)
    ops = operation_ids(auth.prefix)
    names = prov_names(auth.source)
    plan = load_plans()

    inputs = [InputRef(name="authority:configuration.h", path=build / "include" / "openssl" / "configuration.h")]
    providers: list[dict] = []
    census_rows: list[dict] = []
    total = 0
    for provider, rel_source in PROVIDER_FILES:
        path = auth.source / rel_source
        if not path.is_file():
            raise CensusError(f"[provider-algorithms] fatal: missing provider unit {path}")
        text = strip_comments(read(path))
        inputs.append(InputRef(name=f"authority:{rel_source}", path=path))
        tables = table_bodies(text)
        switch = query_switch(text)
        filtered = cache_relation(text)
        rows_here: list[dict] = []
        empty_tables: list[str] = []
        for table, body in tables.items():
            parsed = parse_table(body, provider, auth.source, defined, names, table)
            if not parsed:
                empty_tables.append(table)
                continue
            rows_here.append({"table": table, "rows": parsed})
        # **A table the parser saw no rows in is a fatal, not a skip.** The first version
        # `continue`d past it, and that left one hole in this file's `unknown = 0` invariant: a
        # table the query switch does not return -- and so is not caught by the check below --
        # could parse to nothing and vanish from the census without a word, which is the same
        # class of blind spot `DES3-WRAP` was before the table reader existed. It is also the
        # check that has to fail if the authority's `configuration.h` guards ever change which
        # rows a table carries.
        if empty_tables:
            raise CensusError(
                f"[provider-algorithms] fatal: {rel_source} declares "
                f"{', '.join(sorted(empty_tables))}, which the parser found no rows in"
            )
        # A table the query switch returns but the parser attributed to nothing is a fatal: the
        # census would silently drop a whole operation.
        for operation, table in sorted(switch.items()):
            if not any(t["table"] == table for t in rows_here) and table not in filtered.values():
                raise CensusError(
                    f"[provider-algorithms] fatal: {rel_source}'s {operation} returns {table}, "
                    f"which the parser found no rows in"
                )
        for t in rows_here:
            operation = next((op for op, tbl in switch.items() if tbl == t["table"] or filtered.get(t["table"]) == tbl), None)
            # A parsed table that no operation claims is a fatal rather than a skip: it would be
            # a row set the census knows about and never classifies, which is exactly the
            # `unknown = 0` invariant this file exists to hold.
            if operation is None:
                raise CensusError(
                    f"[provider-algorithms] fatal: {rel_source}'s {t['table']} parses to "
                    f"{len(t['rows'])} row(s) and no operation returns it or its filtered "
                    "target, so it has no operation to be classified under"
                )
            op_id = ops[operation]
            for order, row in enumerate(t["rows"]):
                entry = {
                    "provider": provider,
                    "operation": operation,
                    "operation_id": op_id,
                    "row_order": order,
                    "algorithm_names": row["algorithm_names"],
                    "aliases": row["aliases"],
                    "property_definition": row["property_definition"],
                    "dispatch_table_symbol": row["dispatch_table_symbol"],
                    "capability_predicate": row["capability_predicate"],
                    "source": rel_source,
                    "table_symbol": t["table"],
                    "capability_filtered": t["table"] in filtered,
                    # **The starting state is an assertion, not a default.** Every row of the
                    # authority's tables is unlanded until the join below proves the crate
                    # publishes it, so a row that never reaches the join is reported unlanded
                    # rather than silently missing a field (docs/DECISIONS.md D295).
                    "implementation_state": "unimplemented",
                }
                census_rows.append(entry)
        providers.append(
            {
                "provider": provider,
                "source": rel_source,
                "tables": [
                    {
                        "table_symbol": t["table"],
                        "rows": len(t["rows"]),
                        "operation": next(
                            (op for op, tbl in switch.items() if tbl == t["table"] or filtered.get(t["table"]) == tbl),
                            None,
                        ),
                        "capability_filtered_as": filtered.get(t["table"]),
                    }
                    for t in rows_here
                ],
            }
        )
        total += sum(len(t["rows"]) for t in rows_here)
        # Per-provider accounting, not only the global total: a row counted twice under one
        # provider and not at all under another used to close globally and lie locally.
        parsed_here = sum(len(t["rows"]) for t in rows_here)
        counted_here = sum(1 for r in census_rows if r["provider"] == provider)
        if counted_here != parsed_here:
            raise CensusError(
                f"[provider-algorithms] fatal: {provider}: {counted_here} census row(s) for "
                f"{parsed_here} parsed row(s)"
            )

    if total != len(census_rows):
        raise CensusError("[provider-algorithms] fatal: row accounting does not close")
    identities = [(r["provider"], r["operation"], r["table_symbol"], r["row_order"]) for r in census_rows]
    if len(set(identities)) != len(identities):
        raise CensusError("[provider-algorithms] fatal: a row is double-counted")

    # --- the crate's landed rows, and the exact join ---
    #
    # **The identity is the whole alias string, not the primary name** (D244). The authority's
    # `algorithm_names` field *is* the alias sequence, and for a provider compatibility port the
    # OIDs and spellings in it are part of the observable contract: `EVP_MD_fetch(NULL,
    # "SHA-256", NULL)` and a row published as `SHA2-256` alone are different rows even though
    # their primaries agree. The earlier join compared `primary(alias)` and would have accepted a
    # crate row that had dropped every alias and every OID.
    #
    # Two further facts are checked without a naming convention, because a convention would be a
    # guess: the crate's **dispatch association** — the relation "two matched rows share one
    # crate implementation" must equal the relation "two matched rows share one authority
    # dispatch symbol", so a crate table standing in for two authority tables is a failure even
    # though nothing is named differently; and the crate rows must be a **subsequence** of the
    # authority's rows for that operation in the authority's order, so an accidental reorder
    # cannot remain `implemented`.
    #
    # **The crate's landed rows are read from its own `deflt_query`**, one walk over that function's
    # arms, rather than from a table of per-operation readers. A per-operation list is the failure
    # mode this census exists to remove: a row landed under an operation nobody wrote a reader for
    # would be invisible from the candidate side, which is `DES3-WRAP`'s class (D237) reached from
    # the other direction. `crate_query_tables` resolves each arm's `OSSL_OP_*` constant through the
    # authority's own operation ids and each arm's table path to the module that declares it.
    landed = crate_query_tables(ops)

    # Every authority row keyed by its **full alias sequence**, so the join below cannot fall
    # back to a prefix match. `algorithm_names` is the primary and `aliases` is the sequence the
    # authority's `PROV_NAMES_*` macro expands to, so joining on the sequence is what compares
    # the whole contract rather than its first element.
    def full_alias(row: dict) -> str:
        return ":".join(row["aliases"])

    by_alias: dict[tuple[str, str, str], list[dict]] = {}
    for row in census_rows:
        by_alias.setdefault(
            (row["provider"], row["operation"], full_alias(row)), []
        ).append(row)

    matched: dict[tuple[str, str], list[tuple[dict, str]]] = {}
    for (provider, operation), names_ in landed.items():
        for alias, dispatch in names_:
            hits = by_alias.get((provider, operation, alias), [])
            if not hits:
                near = [
                    r for r in census_rows
                    if r["provider"] == provider
                    and r["operation"] == operation
                    and r["algorithm_names"] == alias.split(":")[0]
                ]
                detail = (
                    f" The authority's row of that primary name carries the alias sequence "
                    f"{full_alias(near[0])!r}."
                    if near
                    else ""
                )
                raise CensusError(
                    f"[provider-algorithms] fatal: the crate publishes {provider}/{operation} "
                    f"with the alias sequence {alias!r} ({dispatch}), which no authority row "
                    f"matches exactly. A row whose primaries agree but whose aliases differ is a "
                    f"different row: the alias sequence is the observable contract.{detail}"
                )
            if len(hits) > 1:
                raise CensusError(
                    f"[provider-algorithms] fatal: {provider}/{operation}/{alias} matches "
                    f"{len(hits)} authority rows, so the crate row is ambiguous"
                )
            hits[0]["implementation_state"] = "implemented"
            hits[0]["crate_dispatch"] = dispatch
            matched.setdefault((provider, operation), []).append((hits[0], dispatch))

    # --- the owning phase, and the one place this file used to be stratum-relative (D295) ---
    #
    # The plan classifies **every** row of every admitted provider's tables -- `operation_defaults`
    # covers a whole operation and `overrides` carve out the rows a subphase names differently -- so
    # `plan_for` answers for a row the crate has landed exactly as it answers for one it has not.
    # That is what makes `owning_phase` a fact about the row rather than about the day it was
    # written.
    #
    # The previous form derived the state directly:
    #
    #     row["state"] = "open" if phase == 8 else "deferred"
    #
    # which is a statement about stratum 8 rather than about the row. It was correct while exactly
    # one stratum's provider rows were being landed, and it was wrong the moment a second stratum
    # became active: phase 9's activation would have reclassified phase 8's eleven open cipher rows
    # as `deferred`, and `phase_state.py`'s rule -- "a stratum may not be complete while any row it
    # owns is open" -- would then have let phase 8 reach `open_in_this_stratum == 0` with eleven
    # rows never published. Whether a row is *open for* a stratum or *handed on by* it is a
    # projection over `owning_phase` and the stratum being judged, so `state` is gone and
    # `implementation_state` is a statement the row cannot lose.
    for row in census_rows:
        phase, blocker, matched_by = plan_for(plan, row["provider"], row["operation"], row)
        if phase is None:
            raise CensusError(
                "[provider-algorithms] fatal: no owning phase for "
                f"{row['provider']}/{row['operation']}/{row['algorithm_names']} "
                f"({row['dispatch_table_symbol']}, {row['source']}); a row the authority "
                "publishes must be classified, not dropped"
            )
        row["owning_phase"] = phase
        if row["implementation_state"] == "implemented":
            # An implemented row is blocked by nothing, and the plan's `blocked_by` for it is the
            # reason it *was* blocked. Recording a stale reason beside a landed row is a second
            # thing to keep true, and the census already refuses a `blocked_by` it cannot check.
            row["blocked_by"] = None
            row["plan_match"] = "crate-table"
        else:
            row["blocked_by"] = blocker
            row["plan_match"] = matched_by

    for (provider, operation), pairs in sorted(matched.items()):
        # The dispatch association, as a **partition equality** rather than a name comparison, and
        # in both directions (D386).
        #
        # The authority's own tables are many-to-one in places, and the census must describe them
        # rather than reject them: `deflt_keymgmt[]` publishes `HMAC`, `SIPHASH` and `POLY1305`
        # under the one `ossl_mac_legacy_keymgmt_functions`, and its three legacy-KDF rows
        # (`TLS1-PRF`, `HKDF`, `SCRYPT`) under the one `ossl_kdf_keymgmt_functions`. An earlier form
        # of this check required each authority dispatch symbol to name exactly one row, which is a
        # claim about this tool rather than about the authority it describes, and it refused those
        # two units outright. What is actually required is that the crate's dispatch symbols and
        # the authority's induce the **same partition** of the landed rows: rows the authority
        # dispatches together must be dispatched together by the crate, and rows the crate
        # dispatches together must be dispatched together by the authority. Either direction
        # failing is still fatal, so a miscarved transcription cannot pass.
        by_crate: dict[str, set[str]] = {}
        by_authority: dict[str, set[str]] = {}
        for row, dispatch in pairs:
            by_crate.setdefault(dispatch, set()).add(row["dispatch_table_symbol"])
            by_authority.setdefault(row["dispatch_table_symbol"], set()).add(dispatch)
        for dispatch, symbols in sorted(by_crate.items()):
            if len(symbols) > 1:
                raise CensusError(
                    f"[provider-algorithms] fatal: the crate implementation {dispatch} answers "
                    f"for {sorted(symbols)}, which the authority dispatches separately; the "
                    f"dispatch association is not one-to-one "
                    f"({provider}/{operation})"
                )
        for symbol, dispatches in sorted(by_authority.items()):
            if len(dispatches) > 1:
                raise CensusError(
                    f"[provider-algorithms] fatal: the authority dispatch symbol {symbol!r} "
                    f"reaches the crate's {sorted(dispatches)}, which dispatch it separately; the "
                    f"dispatch association is not one-to-one "
                    f"({provider}/{operation})"
                )

        # Subsequence order. The authority's rows for one operation are the concatenation of its
        # tables in declaration order, which is the order `deflt_query` publishes them in, and the
        # crate's rows must appear in that same relative order.
        authority_order = [
            r["algorithm_names"]
            for r in census_rows
            if r["provider"] == provider and r["operation"] == operation
        ]
        crate_order = [row["algorithm_names"] for row, _ in pairs]
        cursor = 0
        for position, name in enumerate(crate_order):
            while cursor < len(authority_order) and authority_order[cursor] != name:
                cursor += 1
            if cursor == len(authority_order):
                previous = crate_order[position - 1] if position else None
                raise CensusError(
                    f"[provider-algorithms] fatal: the crate's {provider}/{operation} rows are "
                    f"not a subsequence of the authority's order: {name!r} follows "
                    f"{previous!r} in the crate and precedes it in the authority"
                )
            cursor += 1

    # Every landed crate row's alias sequence matched exactly one authority row, and every
    # authority row matched at most once -- both are enforced by the join above, which is the
    # single place that can get it wrong. What is left here is the *accounting*: the crate's
    # landed row count for an operation is the census's `implemented` count for it. A missing row
    # and an invented one are both failures rather than a smaller or larger number nobody
    # compares.
    for (provider, operation), names_ in landed.items():
        implemented_here = [
            r for r in census_rows
            if r["provider"] == provider and r["operation"] == operation
            and r["implementation_state"] == "implemented"
        ]
        if len(implemented_here) != len(names_):
            raise CensusError(
                f"[provider-algorithms] fatal: {provider}/{operation}: the crate publishes "
                f"{len(names_)} rows and the census matched {len(implemented_here)}"
            )

    body = {
        "claim": CLAIM,
        "providers": providers,
        "row_count": len(census_rows),
        "operation_ids": ops,
        "disabled_in_profile": sorted(defined),
        "capability_filtering": {
            "relation": {
                src: dst for src, dst in sorted(cache_relation(strip_comments(read(auth.source / PROVIDER_FILES[0][1]))).items())
            },
            "state": "discharged",
            "what": (
                "`deflt_query` publishes `exported_ciphers[]` rather than `deflt_ciphers[]`: the "
                "capability-filtered copy `ossl_prov_cache_exported_algorithms` fills at provider "
                "init by evaluating each row's `capability_predicate` and dropping the rows whose "
                "predicate answers 0. The crate now does the same -- "
                "`src/provider/activate.rs`'s `ossl_prov_cache_exported_algorithms` and "
                "`src/provider/cipher.rs`'s `cache_exported_ciphers`, called from "
                "`ossl_default_provider_init` before the provider is published -- so a gated row "
                "can land without a later repair. D275 records the change and the test that proves "
                "the predicate is consulted. This paragraph replaces the earlier one that named "
                "the filtering as an outstanding prerequisite; the two tables it relates are "
                "equal while every landed row's `capable` is `None`, which a unit test asserts so "
                "that the day one is not, the difference is a failure rather than a silent one."
            ),
        },
        "provider_context": provider_context(auth),
        "projection": provider_projection(census_rows),
        "rows": census_rows,
    }
    doc = envelope(kind="provider-algorithms", authority=auth.id, inputs=inputs, body=body, generator=GENERATOR)
    write_json(OUT, doc)

    by_state: dict[str, int] = {}
    for row in census_rows:
        key = row["implementation_state"]
        by_state[key] = by_state.get(key, 0) + 1
    print(f"[provider-algorithms] authority={auth.id} providers={len(providers)}")
    for p in providers:
        print(f"  {p['provider']:<8} {sum(t['rows'] for t in p['tables']):>4} rows in {len(p['tables'])} table(s)")
    print(f"  implementation_state: {by_state}")
    print(f"  projection: {body['projection']['open']}")
    print(f"  wrote {rel(OUT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
