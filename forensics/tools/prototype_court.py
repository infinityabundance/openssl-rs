#!/usr/bin/env python3
"""openssl-rs — the prototype court: does each implemented export have the right *shape*?

Why this exists
---------------
The Phase 1 atlas records every authority export's full C prototype — its return type
and its parameter list. Nothing compared the candidate's Rust declaration against it,
and that gap produced a defect no differential probe was going to find cheaply:
`BN_signed_lebin2bn` was declared `-> c_int` while the authority declares
`BIGNUM *(const unsigned char *, int, BIGNUM *)`, and the implementation additionally
required a non-null `ret`, so every caller using the documented `NULL`-means-allocate
form got a failure where the authority returns a fresh object. That is a wrong *call
convention*, not a wrong value; a C caller compiles against it with at most a warning,
and only a probe that happens to call that one function notices.
See `docs/DECISIONS.md` D65.

What this court compares, and what it deliberately does not
----------------------------------------------------------
It compares the things a caller's compiler bakes into the call: the **return class**
(`void`, pointer, function pointer, integer, floating) and the **arity**. It does not
compare parameter *types*: the atlas gives C types and the source gives Rust types, and
mapping between them needs a per-parameter table that would itself be a transcription.
Class and arity catch the defect class above at every call site; parameter types remain
the probes' business.

Both sides are resolved through their typedef chains before classification —
`CRYPTO_THREAD_ID` is `unsigned long` and `BIO_callback_fn` is a function pointer — so
a difference in *spelling* is not reported as a difference in *shape*.

How a symbol is classified
--------------------------
  * `checked`            — a Rust declaration was parsed and agrees.
  * `mismatch`           — a Rust declaration was parsed and disagrees. **Fails.**
  * `unclassified`       — parsed, but a class this court cannot name. Never a pass.
  * `declaration_is_generated` — the symbol appears in `src/**/*.rs` but not as a
                          `pub extern "C" fn` this court can parse: the crate declares
                          several of these from a `macro_rules!`. Not checkable here,
                          and never counted as a pass.
  * `implementation_is_c` — a definition in `src/**/*.c` (the variadic and syscall
                          shims, which stable Rust cannot express).
  * `not_found`          — implemented, but no declaration found anywhere. **Fails**,
                          because an implemented export must be declared somewhere.

Scope
-----
Only `libcrypto` exports the candidate claims to implement, and only declarations found
in `src/`. A scaffold in the generated shell is not scored here: the shell is generated
*from* these prototypes, so comparing it with them would be circular.

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

OUT = REPO_ROOT / "forensics" / "atlas" / "prototype-court.json"
GENERATOR = "forensics/tools/prototype_court.py"
SRC = REPO_ROOT / "src"

C_INTEGER = re.compile(
    r"^(?:"
    r"(?:unsigned\s+)?(?:int|long|short|char)"
    r"|size_t|ssize_t|ptrdiff_t|intptr_t|uintptr_t|time_t|off_t"
    r"|u?int(?:8|16|32|64)_t"
    r"|BN_ULONG|BN_ULLONG"
    r")$"
)
# Types the authority's headers use but that come from the platform, so they are not
# in the atlas's typedef inventory. Each is named with what the authority's own build
# resolves it to on this profile (glibc, x86-64); the list is a declaration of the
# platform, not a guess about the API.
C_SYSTEM_TYPEDEFS = {
    "pthread_t": "unsigned long",
    "int32_t": "int",
    "uint32_t": "unsigned int",
    "int64_t": "long",
    "uint64_t": "unsigned long",
    "int16_t": "short",
    "uint16_t": "unsigned short",
    "int8_t": "signed char",
    "uint8_t": "unsigned char",
    "size_t": "unsigned long",
    "ssize_t": "long",
    "off_t": "long",
    "time_t": "long",
    "va_list": "struct __va_list_tag *",
}

R_INTEGER = re.compile(
    r"^(?:"
    r"c_int|c_uint|c_long|c_ulong|c_short|c_ushort|c_schar|c_uchar|c_char"
    r"|i8|i16|i32|i64|i128|isize|u8|u16|u32|u64|u128|usize|bool"
    r")$"
)

DECL_RE = re.compile(
    r"pub\s+(?:unsafe\s+)?extern\s+\"C\"\s+fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\("
)
RUST_ALIAS_RE = re.compile(
    r"^(?:pub(?:\s*\([a-z]+\s*\))?\s+)?type\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]+);",
    re.MULTILINE,
)
C_DEF_RE_TEMPLATE = r"(?m)^[A-Za-z_][A-Za-z0-9_ \t*]*\b{name}\s*\("


def strip_qualifiers(text: str) -> str:
    return " ".join(text.replace("const ", " ").replace("volatile ", " ").split())


def classify_c(text: str) -> str:
    t = strip_qualifiers(text)
    if t in ("void", ""):
        return "void"
    if "(*" in t or "(*)" in t:
        return "function_pointer"
    if t.endswith("*"):
        return "pointer"
    if t in ("float", "double"):
        return "floating"
    if C_INTEGER.match(t):
        return "integer"
    return "unclassified"


def resolve_c(text: str, typedefs: dict[str, str], depth: int = 0) -> str:
    t = strip_qualifiers(text)
    if depth > 8 or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", t):
        return t
    nxt = typedefs.get(t) or C_SYSTEM_TYPEDEFS.get(t)
    if nxt is None:
        return t
    return resolve_c(nxt, typedefs, depth + 1)


def classify_rust(text: str, aliases: dict[str, str], depth: int = 0) -> str:
    t = " ".join(text.split()).strip()
    if t in ("()", ""):
        return "void"
    if t.startswith("*mut ") or t.startswith("*const "):
        return "pointer"
    if t.startswith("Option<") and t.endswith(">"):
        inner = t[len("Option<"):-1].strip()
        # `Option<unsafe extern "C" fn ...>` is a nullable function pointer. An
        # `Option<integer>` has no niche and no ABI export returns one, so this is
        # safe to narrow — but the inner type is usually a local alias, and often an
        # alias *of* an alias (`BioRecvmmsgFn = BioSendmmsgFn`), so it goes back
        # through the same resolver rather than being string-matched once.
        inner_class = classify_rust(inner, aliases, depth + 1)
        return inner_class if inner_class in ("function_pointer", "pointer") else "unclassified"
    if t in ("f32", "f64"):
        return "floating"
    if R_INTEGER.match(t):
        return "integer"
    if depth < 8 and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_:]*", t):
        target = aliases.get(t) or aliases.get(t.split("::")[-1])
        if target is not None:
            return classify_rust(target, aliases, depth + 1)
    if re.search(r"\bfn\b", t):
        return "function_pointer"
    return "unclassified"


def split_top_level(text: str) -> list[str]:
    """Split on commas that are not nested, treating `->` as an arrow."""
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "-" and text[i + 1:i + 2] == ">":
            current.append("->")
            i += 2
            continue
        if ch in "(<[":
            depth += 1
        elif ch in ")>]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
        i += 1
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return [p.strip() for p in parts]


def _scan_balanced(text: str, open_at: int) -> int:
    """Index of the bracket closing the one at `open_at`, with `->` handled.

    The `>` of `->` would otherwise be read as closing a `<`, which truncated every
    declaration whose parameter list contains a function-pointer type — six of the
    first run's seven `mismatches` were that, in a court whose whole job is to
    distinguish a real mismatch from a spelling difference.
    """
    pairs = {"(": ")", "<": ">", "[": "]"}
    stack = [pairs[text[open_at]]]
    i = open_at + 1
    while i < len(text):
        ch = text[i]
        if ch == "-" and text[i + 1:i + 2] == ">":
            i += 2
            continue
        if ch in pairs:
            stack.append(pairs[ch])
        elif ch in ")>]":
            if not stack or ch != stack[-1]:
                return -1
            stack.pop()
            if not stack:
                return i
        i += 1
    return -1


def top_level_groups(text: str) -> list[tuple[int, int]]:
    """Every bracketed group at the top level of `text`, left to right."""
    groups: list[tuple[int, int]] = []
    i = 0
    while i < len(text):
        if text[i] == "(":
            end = _scan_balanced(text, i)
            if end < 0:
                return groups
            groups.append((i, end))
            i = end + 1
        else:
            i += 1
    return groups


def parse_c_prototype(proto: str, typedefs: dict[str, str]) -> tuple[str, int] | None:
    """`BIGNUM *(const unsigned char *, int, BIGNUM *)` -> (return, arity).

    A *function-pointer* return reads the other way round:
    `int (*(const BIO_METHOD *))(BIO *, char *, int)` is a function taking one
    `const BIO_METHOD *` whose result is an `int (*)(BIO *, char *, int)`. The first
    group is then the pointer declarator and the **last** is the parameter list, and
    getting that backwards reports the authority's own prototype as the mismatch.
    """
    text = proto.strip()
    groups = top_level_groups(text)
    if not groups:
        return None
    first = groups[0]
    content = text[first[0] + 1:first[1]]
    if content.strip().startswith("*"):
        # A function-pointer return, spelled without a function name:
        # `int (*(const BIO_METHOD *))(BIO *, char *, int)` declares a function
        # taking `const BIO_METHOD *` whose result is an
        # `int (*)(BIO *, char *, int)`. So the outer function's parameter list is
        # the first group nested inside the declarator, and the trailing group
        # belongs to the *returned* function — which is exactly the pair that must
        # not be swapped.
        nested = top_level_groups(content)
        if not nested:
            return "function_pointer", 0
        params = content[nested[0][0] + 1:nested[0][1]].strip()
        arity = 0 if params in ("", "void") else len(split_top_level(params))
        return "function_pointer", arity
    params = content.strip()
    arity = 0 if params in ("", "void") else len(split_top_level(params))
    return classify_c(resolve_c(text[:first[0]], typedefs)), arity


def parse_rust_declaration(
    text: str, open_at: int, aliases: dict[str, str]
) -> tuple[str, int] | None:
    close_at = _scan_balanced(text, open_at)
    if close_at < 0:
        return None
    params = text[open_at + 1:close_at]
    arity = 0 if not params.strip() else len(split_top_level(params))
    rest = text[close_at + 1:]
    m = re.match(r"\s*->\s*", rest)
    if not m:
        return "void", arity
    after = rest[m.end():]
    ret: list[str] = []
    i = 0
    stack: list[str] = []
    pairs = {"(": ")", "<": ">", "[": "]"}
    while i < len(after):
        ch = after[i]
        if ch == "-" and after[i + 1:i + 2] == ">":
            i += 2
            continue
        if ch in pairs:
            stack.append(pairs[ch])
        elif ch in ")>]":
            if stack and ch == stack[-1]:
                stack.pop()
            elif not stack:
                break
        elif ch in "{;" and not stack:
            break
        ret.append(ch)
        i += 1
    return classify_rust("".join(ret), aliases), arity


def read_sources() -> tuple[dict[str, tuple[str, int]], dict[str, str], str, str]:
    """Rust declarations, Rust type aliases, all Rust text, all C text.

    Two passes over the Rust sources, not one. An alias is often defined in a file
    that sorts *after* the one that returns it (`method.rs` returns `BioReadFn`, which
    `mod.rs` defines), and classifying during the scan made every such declaration
    `unclassified` — a court reporting its own traversal order as a property of the
    code. Phase 4 learned the same shape of lesson from the ERR coordinates (D60).
    """
    declarations: dict[str, tuple[str, int]] = {}
    aliases: dict[str, str] = {}
    rust_text: list[str] = []
    c_text: list[str] = []
    for path in sorted(SRC.rglob("*")):
        if path.suffix == ".rs":
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            rust_text.append(text)
            for m in RUST_ALIAS_RE.finditer(text):
                aliases.setdefault(m.group(1), m.group(2).strip())
        elif path.suffix == ".c":
            try:
                c_text.append(path.read_text(encoding="utf-8"))
            except UnicodeDecodeError:
                continue
    for text in rust_text:
        for m in DECL_RE.finditer(text):
            parsed = parse_rust_declaration(text, m.end() - 1, aliases)
            if parsed is not None:
                declarations.setdefault(m.group(1), parsed)
    return declarations, aliases, "\n".join(rust_text), "\n".join(c_text)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    atlas = REPO_ROOT / "forensics" / "atlas" / auth.id

    fn_doc = json.loads((atlas / "functions.json").read_text(encoding="utf-8"))["body"]
    prototypes = {r["name"]: r["type"] for r in fn_doc["records"] if r.get("type")}
    typedefs = {
        r["name"]: r["underlying_type"]
        for r in json.loads((atlas / "typedefs.json").read_text(encoding="utf-8"))["body"][
            "records"
        ]
        if r.get("underlying_type")
    }
    surface = json.loads(
        (REPO_ROOT / "forensics" / "atlas" / "implemented-surface.json").read_text(
            encoding="utf-8"
        )
    )["body"]["libraries"]["libcrypto"]

    declarations, _aliases, rust_text, c_text = read_sources()

    checked: list[dict] = []
    mismatches: list[dict] = []
    unclassified: list[dict] = []
    generated: list[str] = []
    in_c: list[str] = []
    not_found: list[str] = []
    no_prototype: list[str] = []

    for sym in sorted(surface["implemented_symbols"]):
        proto = prototypes.get(sym)
        if proto is None:
            no_prototype.append(sym)
            continue
        want = parse_c_prototype(proto, typedefs)
        if want is None:
            unclassified.append({"symbol": sym, "prototype": proto,
                                 "why": "the authority's prototype did not parse"})
            continue
        got = declarations.get(sym)
        if got is None:
            if re.search(C_DEF_RE_TEMPLATE.format(name=re.escape(sym)), c_text):
                in_c.append(sym)
            elif re.search(rf"\b{re.escape(sym)}\b", rust_text):
                generated.append(sym)
            else:
                not_found.append(sym)
            continue
        row = {
            "symbol": sym, "prototype": proto,
            "c_return": want[0], "c_arity": want[1],
            "rust_return": got[0], "rust_arity": got[1],
        }
        if want[0] == "unclassified" or got[0] == "unclassified":
            row["why"] = "a return type this court cannot classify"
            unclassified.append(row)
            continue
        checked.append(row)
        if want != got:
            row["class_mismatch"] = want[0] != got[0]
            row["arity_mismatch"] = want[1] != got[1]
            mismatches.append(row)

    body = {
        "what": (
            "every implemented libcrypto export's Rust declaration agrees with the "
            "authority's recorded prototype on return class and arity"
        ),
        "why": (
            "the atlas records the prototype and nothing compared it: a wrong return "
            "class or arity is a wrong call convention, which no value-level probe "
            "finds cheaply (docs/DECISIONS.md D65)"
        ),
        "counts": {
            "implemented": len(surface["implemented_symbols"]),
            "checked": len(checked),
            "mismatches": len(mismatches),
            "unclassified": len(unclassified),
            "declaration_is_generated": len(generated),
            "implementation_is_c": len(in_c),
            "not_found": len(not_found),
            "no_prototype_in_atlas": len(no_prototype),
        },
        "mismatches": mismatches,
        "unclassified": unclassified,
        "declaration_is_generated": generated,
        "implementation_is_c": in_c,
        "not_found": not_found,
        "no_prototype_in_atlas": no_prototype,
        "note": (
            "Return class and arity only. Parameter *types* are not compared: the atlas "
            "gives C types and the source gives Rust types, and a mapping between them "
            "would be a transcription rather than a check. A symbol this court cannot "
            "classify -- including one the crate declares from a `macro_rules!` -- is "
            "reported under its own heading and never counted as a pass, so `mismatches "
            "== 0` must be read together with `checked`, not instead of it."
        ),
    }

    inputs = [
        InputRef(name="authority-functions", path=atlas / "functions.json"),
        InputRef(name="authority-typedefs", path=atlas / "typedefs.json"),
        InputRef(name="implemented-surface",
                 path=REPO_ROOT / "forensics" / "atlas" / "implemented-surface.json"),
    ]
    write_json(OUT, envelope(kind="prototype-court", authority=auth.id, inputs=inputs,
                             body=body, generator=GENERATOR))

    c = body["counts"]
    print(f"[prototype-court] authority={auth.id}")
    print(f"  implemented={c['implemented']} checked={c['checked']} "
          f"mismatches={c['mismatches']} unclassified={c['unclassified']} "
          f"generated={c['declaration_is_generated']} in-c={c['implementation_is_c']} "
          f"not-found={c['not_found']} no-prototype={c['no_prototype_in_atlas']}")
    for row in mismatches:
        print(f"  MISMATCH {row['symbol']}: authority returns {row['c_return']} with "
              f"{row['c_arity']} parameter(s); the crate returns {row['rust_return']} "
              f"with {row['rust_arity']}")
    for row in unclassified:
        print(f"  unclassified {row['symbol']}: {row.get('why', '')} "
              f"({row.get('prototype', '')})")
    if not_found:
        print(f"  not found anywhere in src/: {', '.join(not_found[:10])}"
              + (f" (+{len(not_found) - 10} more)" if len(not_found) > 10 else ""))
    print(f"  -> {rel(OUT)}")

    return 1 if (mismatches or not_found) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
