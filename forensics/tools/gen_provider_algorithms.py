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
capability predicate (for the `ALGC(...)` rows), the owning phase, the state and the
blocker. Only two things are authored, because they are policy rather than measurement:
`forensics/atlas/provider-algorithm-plans.json`'s per-operation default owner and its
per-row overrides. **A row with no owner is a failure**, which is the enforcement: a row
the authority publishes and the crate does not cannot go unnoticed, because it has to be
classified before this tool will write its output.

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
    "never typed. `state` is `implemented` when the crate publishes the row, `open` when it "
    "is this stratum's remaining work, and `deferred` when it is handed to a later phase, in "
    "which case `blocked_by` names the blocker. Only the owning phase and the blocker are "
    "authored, in `provider-algorithm-plans.json`; a row with neither is a failure and no "
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


def evaluate_lines(lines: list[str], defined: set[str]) -> list[tuple[int, str]]:
    """(line number, text) for every line the preprocessor would keep.

    `#include "x.inc"` is spliced in place, recursively, so a table that is assembled from
    an include is parsed as the authority compiles it. A `#define` and its backslash
    continuations are one preprocessor statement and are dropped whole.
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
            if not stack:
                raise CensusError("[provider-algorithms] fatal: #elif without #if")
            stack[-1] = stack[-1] or eval_guard(rest, defined)
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
    lines = evaluate_lines(body, defined)
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
        spliced.extend(evaluate_lines(inc_text.splitlines(), defined | INC_TIME_DEFINED))
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


def crate_cipher_rows() -> list[tuple[str, str]]:
    """`(alias string, authority dispatch table)` for every `DEFLT_CIPHERS` row, in order."""
    text = read(REPO_ROOT / "src" / "provider" / "cipher.rs")
    aliases = {
        m.group(1): m.group(2)
        for m in re.finditer(r'alias!\(\s*([A-Za-z0-9_]+)\s*,\s*"([^"]*)"\s*\)', text, re.S)
    }
    start = text.index("pub(crate) static DEFLT_CIPHERS")
    end = text.index("];", start)
    body = text[start:end]
    out = []
    for m in re.finditer(r"row\(\s*([A-Za-z0-9_]+)\s*,\s*([A-Za-z0-9_]+)\.as_ptr\(\)", body):
        name = aliases.get(m.group(1))
        if name is None:
            raise CensusError(f"[provider-algorithms] fatal: DEFLT_CIPHERS names unknown alias {m.group(1)}")
        out.append((name, m.group(2)))
    return out


def crate_digest_rows() -> list[str]:
    """The alias string of every `DEFLT_DIGESTS` row, in order."""
    text = read(REPO_ROOT / "src" / "provider" / "digest.rs")
    start = text.index("static DEFLT_DIGESTS")
    end = text.index("];", start)
    return [m.group(1) for m in re.finditer(r'algorithm_names:\s*c"([^"]*)"', text[start:end])]


def primary(alias_string: str) -> str:
    return alias_string.split(":")[0]


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
# arm and in `cipher_tdes_wrap.c`'s IV generation, and it is the one thing this crate's
# `ossl_default_provider_init` cannot supply: it publishes `*provctx = NULL`, so
# `PROV_LIBCTX_OF` has no argument at all.
#
# The consequence is not a wrong answer today -- every landed cipher row is deterministic -- it is
# a **library-context isolation** difference the moment a random-dependent row lands. An
# application that loads the default provider in a private `OSSL_LIB_CTX` A and fetches such a row
# in A gets the authority's A and the candidate's *global* context, and a test taken against the
# global default context cannot tell the two apart. That is why the obligation is recorded here
# as a **second blocker** beside `RAND_bytes_ex` rather than only in prose.
#
# It is measured rather than asserted, and every measurement is a fatal if it stops being true:
# the day the crate grows the plumbing this generator fails instead of the claim going stale, and
# a reviewer never has to re-derive which spelling is current.
CRATE_PROVIDER_CONTEXT_FACTS = [
    (
        "src/provider/digest.rs",
        "*provctx = ptr::null_mut();",
        "`ossl_default_provider_init` publishes a NULL provctx",
    ),
    (
        "src/provider/cipher.rs",
        "_provctx: *mut c_void,",
        "`ossl_cipher_generic_initkey` takes the provider context and ignores it",
    ),
]

# The point the authority's line makes, in one place so the check and the artefact cannot drift.
AUTHORITY_PROVIDER_CONTEXT_FACT = (
    "providers/implementations/ciphers/ciphercommon.c.in",
    "ctx->libctx = PROV_LIBCTX_OF(provctx);",
)


def provider_context(auth: Authority) -> dict:
    """The measured provider-context gap, and the rows whose blockers it joins.

    Reads the crate and the authority's template, and fails on any of the three facts moving:
    a crate fact disappears, the crate starts assigning `(*ctx).libctx` (the obligation is
    retired), or the authority's line moves. A `CensusError` rather than a warning, because a
    stale obligation here is exactly the class D237 exists to stop.
    """
    for rel, needle, what in CRATE_PROVIDER_CONTEXT_FACTS:
        if needle not in read(REPO_ROOT / rel):
            raise CensusError(
                f"[provider-algorithms] fatal: {rel} no longer contains {needle!r}, so the "
                f"provider-context fact recorded here ({what}) has moved: re-derive this block "
                "rather than trusting it"
            )
    # **The absence is the finding.** Nothing writes a provider cipher context's `libctx` from a
    # provider context; the field exists and is only ever NULL-initialised in a unit test. The
    # test is `any assignment to the field at all`, not one spelling of one: the first version
    # looked for the literal `(*ctx).libctx =` and a negative test with a differently-named
    # receiver (`(*c).libctx =`) sailed past it, which is precisely the false comfort this block
    # exists to prevent. Any assignment means the plumbing is arriving, so the obligation has to
    # be re-derived rather than trusted -- and its removal, not this check, is what retires it.
    cipher_rs = read(REPO_ROOT / "src" / "provider" / "cipher.rs")
    assignment = re.search(r"\.libctx\s*=", cipher_rs)
    if assignment is not None:
        line = cipher_rs.count("\n", 0, assignment.start()) + 1
        raise CensusError(
            "[provider-algorithms] fatal: src/provider/cipher.rs line "
            f"{line} assigns a `.libctx` field, so the provider context may now be plumbed: "
            "re-derive this obligation and the second blocker of the random-dependent rows with "
            "it. **This check failing is the obligation's retirement condition, not a bug in the "
            "generator**: delete this block and the `blocked_by` half in "
            "`provider-algorithm-plans.json` in the same commit that lands the plumbing, and "
            "replace both with the court arm the `court_requirement` below asks for."
        )
    auth_rel, auth_needle = AUTHORITY_PROVIDER_CONTEXT_FACT
    if auth_needle not in read(auth.source / auth_rel):
        raise CensusError(
            f"[provider-algorithms] fatal: the authority's {auth_rel} no longer contains "
            f"{auth_needle!r}, so a row's second blocker may no longer be what this says"
        )
    return {
        "obligation": (
            "The default provider's `provctx` is NULL in this crate, so `PROV_LIBCTX_OF(provctx)` "
            "-- and therefore a provider cipher context's `libctx` -- cannot be supplied. Counted "
            "as the **second** blocker of every provider row whose first blocker is randomness, "
            "because those are the rows where `ctx->libctx` is what the random call resolves "
            "against. It is the provider's own port of D117's residual."
        ),
        "authority": {
            "unit": auth_rel,
            "line": auth_needle,
            "effect": (
                "every provider cipher context stores the creating provider's library context, "
                "and the GCM no-IV arm and `cipher_tdes_wrap.c`'s IV generation call "
                "`RAND_bytes_ex(ctx->libctx, ...)` against it"
            ),
        },
        "crate": [
            {"path": rel, "fact": what} for rel, _needle, what in CRATE_PROVIDER_CONTEXT_FACTS
        ]
        + [
            {
                "path": "src/provider/cipher.rs",
                "fact": (
                    "no assignment from a provider context to `(*ctx).libctx` exists; the field "
                    "is only ever NULL-initialised in a unit test"
                ),
            }
        ],
        "blocked_rows": [],
        "court_requirement": (
            "Before Phase 9 retires a random-dependent row, the observation has to be taken in a "
            "**private `OSSL_LIB_CTX`**, not the global default context: with both providers "
            "loaded in the global context the isolation difference is invisible, so a passing "
            "test there would certify nothing about this obligation."
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
        "table_symbol", "state", "owning_phase", "blocked_by",
    }
    problems: list[str] = []
    if body.get("row_count") != len(rows):
        problems.append(f"row_count {body.get('row_count')} != {len(rows)} rows")
    identities = set()
    for r in rows:
        missing = required - set(r)
        if missing:
            problems.append(f"{r.get('algorithm_names')}: missing {sorted(missing)}")
        if r.get("state") not in ("implemented", "open", "deferred"):
            problems.append(f"{r.get('algorithm_names')}: illegal state {r.get('state')!r}")
        ident = (r.get("provider"), r.get("operation"), r.get("table_symbol"), r.get("row_order"))
        if ident in identities:
            problems.append(f"double-counted row {ident}")
        identities.add(ident)
    for p in body["providers"]:
        if sum(t["rows"] for t in p["tables"]) != len(
            [r for r in rows if r["provider"] == p["provider"]]
        ):
            problems.append(f"provider {p['provider']}: table counts do not sum to its rows")
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


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
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
    cipher_rows = crate_cipher_rows()
    digest_rows = crate_digest_rows()
    landed: dict[tuple[str, str], list[tuple[str, str]]] = {
        ("default", "OSSL_OP_CIPHER"): [(primary(a), d) for a, d in cipher_rows],
        ("default", "OSSL_OP_DIGEST"): [(primary(a), "") for a in digest_rows],
    }
    seen_landed: set[tuple[str, str, str]] = set()
    for row in census_rows:
        key = (row["provider"], row["operation"])
        match = None
        for name, dispatch in landed.get(key, []):
            if name == row["algorithm_names"]:
                match = dispatch
                break
        if match is not None:
            row["state"] = "implemented"
            seen_landed.add((row["provider"], row["operation"], row["algorithm_names"]))
            continue
        phase, blocker, matched_by = plan_for(plan, row["provider"], row["operation"], row)
        if phase is None:
            raise CensusError(
                "[provider-algorithms] fatal: no owning phase for "
                f"{row['provider']}/{row['operation']}/{row['algorithm_names']} "
                f"({row['dispatch_table_symbol']}, {row['source']}); a row the authority "
                "publishes and the crate does not must be classified, not dropped"
            )
        row["state"] = "open" if phase == 8 else "deferred"
        row["owning_phase"] = phase
        row["blocked_by"] = blocker
        row["plan_match"] = matched_by

    for row in census_rows:
        if row["state"] == "implemented":
            row.setdefault("owning_phase", 8)
            row.setdefault("blocked_by", None)
            row.setdefault("plan_match", "crate-table")

    # Every landed crate row must have an authority row behind it, and no more than one.
    for (provider, operation), names_ in landed.items():
        for name, dispatch in names_:
            hits = [r for r in census_rows if r["provider"] == provider and r["operation"] == operation and r["algorithm_names"] == name]
            if not hits:
                raise CensusError(
                    f"[provider-algorithms] fatal: the crate publishes {provider}/{operation}/{name} "
                    f"({dispatch or 'a digest row'}), which no authority row matches"
                )
            if len(hits) > 1:
                raise CensusError(
                    f"[provider-algorithms] fatal: {provider}/{operation}/{name} is double-counted "
                    "in the authority tables"
                )
    for (provider, operation, name) in seen_landed:
        hits = [r for r in census_rows if r["provider"] == provider and r["operation"] == operation and r["algorithm_names"] == name and r["state"] == "implemented"]
        if len(hits) != 1:
            raise CensusError(f"[provider-algorithms] fatal: {name} matched {len(hits)} authority rows")
    # Exact accounting, in both directions: the crate's landed row count for an operation is
    # the census's `implemented` count for it. A missing row and an invented one are both
    # failures rather than a smaller or larger number nobody compares.
    for (provider, operation), names_ in landed.items():
        implemented_here = [
            r for r in census_rows
            if r["provider"] == provider and r["operation"] == operation and r["state"] == "implemented"
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
            "prerequisite": (
                "`deflt_query` publishes `exported_ciphers[]`, which "
                "`ossl_prov_cache_exported_algorithms` fills by evaluating each row's "
                "`capability_predicate` and dropping the rows whose predicate answers 0. The "
                "crate's `deflt_query` returns `DEFLT_CIPHERS` directly, which is correct only "
                "while every landed row is unconditional; the filtering must be built before "
                "the first capability-gated row lands, not repaired after it."
            ),
        },
        "provider_context": provider_context(auth),
        "rows": census_rows,
    }
    body["provider_context"]["blocked_rows"] = [
        [r["provider"], r["operation"], r["algorithm_names"]]
        for r in census_rows
        if r["operation"] == "OSSL_OP_CIPHER" and r["blocked_by"] and "RAND" in r["blocked_by"]
    ]
    doc = envelope(kind="provider-algorithms", authority=auth.id, inputs=inputs, body=body, generator=GENERATOR)
    write_json(OUT, doc)

    by_state: dict[str, int] = {}
    for row in census_rows:
        by_state[row["state"]] = by_state.get(row["state"], 0) + 1
    print(f"[provider-algorithms] authority={auth.id} providers={len(providers)}")
    for p in providers:
        print(f"  {p['provider']:<8} {sum(t['rows'] for t in p['tables']):>4} rows in {len(p['tables'])} table(s)")
    print(f"  states: {by_state}")
    print(f"  wrote {rel(OUT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
