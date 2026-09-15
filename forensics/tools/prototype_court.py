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
    "int8_t": "signed char",
    "uint8_t": "unsigned char",
    "int16_t": "short",
    "uint16_t": "unsigned short",
    "int32_t": "int",
    "uint32_t": "unsigned int",
    "int64_t": "long",
    "uint64_t": "unsigned long",
    "intptr_t": "long",
    "uintptr_t": "unsigned long",
    "ptrdiff_t": "long",
    "size_t": "unsigned long",
    "ssize_t": "long",
    "off_t": "long",
    "time_t": "long",
    "pthread_t": "unsigned long",
    "pthread_key_t": "unsigned int",
    "pthread_once_t": "int",
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


# C integer type -> (bytes, signed), after typedef resolution. `char` is signed on
# this profile (x86-64 Linux), which is what `c_char` is too.
C_INT_WIDTH = {
    "char": (1, True),
    "signed char": (1, True),
    "unsigned char": (1, False),
    "short": (2, True),
    "short int": (2, True),
    "unsigned short": (2, False),
    "unsigned short int": (2, False),
    "int": (4, True),
    "unsigned int": (4, False),
    "unsigned": (4, False),
    "long": (8, True),
    "long int": (8, True),
    "unsigned long": (8, False),
    "unsigned long int": (8, False),
    "long long": (8, True),
    "long long int": (8, True),
    "unsigned long long": (8, False),
    "unsigned long long int": (8, False),
    "BN_ULONG": (8, False),
    "BN_ULLONG": (16, False),
}

RUST_INT_WIDTH = {
    "c_char": (1, True),
    "c_schar": (1, True),
    "c_uchar": (1, False),
    "i8": (1, True),
    "u8": (1, False),
    "c_short": (2, True),
    "c_ushort": (2, False),
    "i16": (2, True),
    "u16": (2, False),
    "c_int": (4, True),
    "c_uint": (4, False),
    "i32": (4, True),
    "u32": (4, False),
    "c_long": (8, True),
    "c_ulong": (8, False),
    "c_longlong": (8, True),
    "c_ulonglong": (8, False),
    "i64": (8, True),
    "u64": (8, False),
    "isize": (8, True),
    "usize": (8, False),
    "i128": (16, True),
    "u128": (16, False),
    "bool": (1, False),
}


def canon_c_type(
    text: str, typedefs: dict[str, str], depth: int = 0, pointee: bool = False
) -> str | None:
    """A C type in the court's canonical form, or None when it cannot be read.

    The form keeps exactly what a *caller* can observe: the pointee chain, the
    constness of each pointee, the width and signedness of integer leaves, and the
    shape of function pointers. The *name* of a struct pointee is deliberately not
    kept -- `*mut Asn1String` and `*mut c_void` are the same to the ABI and the same
    to a caller passing its own pointer, so distinguishing them would report a
    spelling difference as a defect. What is kept is the depth, so `BIO **` cannot
    be mistaken for `BIO *`, and integer *width*, so `int *` cannot be mistaken for
    `long *`. Both of those are real defects a call-convention check should catch.

    `pointee` says whether the type being read is the target of a `*`. A top-level
    `const` on a *value* is not part of a function's type in C -- `const BN_ULONG w`
    and `BN_ULONG w` declare the same function -- so it is dropped there and kept
    only on a pointee, which is where a caller can observe it.
    """
    if depth > 8:
        return None
    t = " ".join(text.replace("volatile ", "").split())
    if t in ("void", ""):
        return "void"
    if "(*" in t:
        return canon_c_fnptr(t, typedefs, depth)
    if t.endswith("*"):
        inner = canon_c_type(t[:-1].strip(), typedefs, depth + 1, pointee=True)
        if inner is None:
            return None
        # A `void *` and a `T *` are the same to a caller: both are "a pointer".
        # The pointee's name is deliberately not part of this form, and `void` is
        # one of those names, so it is folded into `opaque` here rather than being
        # reported as a difference against `*mut c_void`.
        if inner == "void":
            inner = "opaque"
        elif inner == "const(void)":
            inner = "const(opaque)"
        elif inner.startswith("fn("):
            # A pointer to a function *type* is the function pointer: in C a function
            # type has no values, so `BIO_info_cb *` and `int (*)(BIO *, int, int)`
            # are the same type. A pointer to a function *pointer* is a real second
            # level and is left alone (`ptr(fptr(...))`), which is what makes
            # `CRYPTO_malloc_fn **` distinguishable from `CRYPTO_malloc_fn *`.
            return "fptr(" + inner[len("fn("):]
        elif inner.startswith("const(fn("):
            return "const(fptr(" + inner[len("const(fn("):]
        return f"ptr({inner})"
    fn_type = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_ ]*?)\s*\((.*)\)", t)
    if fn_type is not None:
        # A function *type*, not a pointer: `int (BIO *, int, int)`. The atlas
        # records `BIO_info_cb` this way (`typedef int BIO_info_cb(BIO *, int,
        # int);`), so a parameter spelled `BIO_info_cb *` is a pointer to one.
        ret = canon_c_type(fn_type.group(1), typedefs, depth + 1)
        if ret is None:
            return None
        args: list[str] = []
        for a in split_top_level(fn_type.group(2)):
            if a.strip() in ("", "void"):
                continue
            c = canon_c_type(a, typedefs, depth + 1)
            if c is None:
                return None
            args.append(c)
        return f"fn({ret}; {', '.join(args)})"
    const = False
    if t.startswith("const "):
        const = True
        t = t[len("const "):].strip()
    if t.startswith("enum ") or t.startswith("struct ") or t.startswith("union "):
        base = "int:4:s" if t.startswith("enum ") else "opaque"
        return f"const({base})" if (const and pointee) else base
    if t in ("float", "double"):
        base = "float:4" if t == "float" else "float:8"
        return f"const({base})" if (const and pointee) else base
    if t in C_INT_WIDTH:
        b, s = C_INT_WIDTH[t]
        base = f"int:{b}:{'s' if s else 'u'}"
        return f"const({base})" if (const and pointee) else base
    resolved = typedefs.get(t) or C_SYSTEM_TYPEDEFS.get(t)
    if resolved is not None:
        inner = canon_c_type(resolved, typedefs, depth + 1, pointee)
        if inner is None:
            return None
        # The `const` was read before the typedef was resolved, so it has to be
        # re-applied to the resolved type: `const BIO_ADDRINFO` reaches a struct
        # name only through `typedef struct bio_addrinfo_st BIO_ADDRINFO`, and the
        # qualifier would otherwise be dropped at the hand-off.
        if const and pointee and not inner.startswith("const("):
            return f"const({inner})"
        return inner
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", t):
        return "const(opaque)" if (const and pointee) else "opaque"
    return None


def canon_c_fnptr(t: str, typedefs: dict[str, str], depth: int) -> str | None:
    """A C function-pointer type: `int (*)(BIO *, char *, int)`."""
    groups = top_level_groups(t)
    if not groups:
        return None
    g0 = groups[0]
    content = t[g0[0] + 1:g0[1]]
    if not content.strip().startswith("*"):
        return None
    ret = canon_c_type(t[:g0[0]].strip(), typedefs, depth + 1)
    if ret is None:
        return None
    args_raw: list[str] = []
    if len(groups) > 1:
        g1 = groups[1]
        args_raw = split_top_level(t[g1[0] + 1:g1[1]])
    args = []
    for a in args_raw:
        if a.strip() in ("", "void"):
            continue
        if a.strip() == "...":
            args.append("...")
            continue
        c = canon_c_type(a, typedefs, depth + 1)
        if c is None:
            return None
        args.append(c)
    return f"fptr({ret}; {', '.join(args)})"


def canon_rust_type(text: str, aliases: dict[str, str], depth: int = 0) -> str | None:
    """A Rust type in the same canonical form as :func:`canon_c_type`."""
    if depth > 12:
        return None
    t = " ".join(text.split()).strip()
    if t in ("()", "void", ""):
        return "void"
    if t.startswith("Option<") and t.endswith(">"):
        # A nullable function pointer and a bare one are the same to the ABI.
        return canon_rust_type(t[len("Option<"):-1], aliases, depth + 1)
    if t.startswith("*mut "):
        inner = canon_rust_type(t[len("*mut "):], aliases, depth + 1)
        return None if inner is None else f"ptr({inner})"
    if t.startswith("*const "):
        inner = canon_rust_type(t[len("*const "):], aliases, depth + 1)
        return None if inner is None else f"ptr(const({inner}))"
    if t.startswith("unsafe extern \"C\" fn") or t.startswith("extern \"C\" fn"):
        return canon_rust_fnptr(t, aliases, depth)
    if t in ("f32", "f64"):
        return "float:4" if t == "f32" else "float:8"
    if t in RUST_INT_WIDTH:
        b, s = RUST_INT_WIDTH[t]
        return f"int:{b}:{'s' if s else 'u'}"
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_:]*", t):
        leaf = t.split("::")[-1]
        if leaf != t and leaf in RUST_INT_WIDTH:
            # `core::ffi::c_uint` and `c_uint` are the same type.
            b, s = RUST_INT_WIDTH[leaf]
            return f"int:{b}:{'s' if s else 'u'}"
        target = aliases.get(t) or aliases.get(leaf)
        if target is not None:
            return canon_rust_type(target, aliases, depth + 1)
        return "opaque"
    return None


def canon_rust_fnptr(t: str, aliases: dict[str, str], depth: int) -> str | None:
    body = t[t.index("fn") + 2:].strip()
    if not body.startswith("("):
        return None
    close = _scan_balanced(body, 0)
    if close < 0:
        return None
    args_raw = split_top_level(body[1:close])
    rest = body[close + 1:]
    m = re.match(r"\s*->\s*", rest)
    ret = canon_rust_type(rest[m.end():], aliases, depth + 1) if m else "void"
    if ret is None:
        return None
    args = []
    for a in args_raw:
        if a.strip() == "...":
            args.append("...")
            continue
        c = canon_rust_type(a, aliases, depth + 1)
        if c is None:
            return None
        args.append(c)
    return f"fptr({ret}; {', '.join(args)})"


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
        leaf = t.split("::")[-1]
        # A qualified path to a scalar (``core::ffi::c_ulong``) is the scalar. The
        # type plane already narrowed this; the class plane did not, and reported
        # `ASN1_tag2bit` as unclassified for that reason alone.
        if leaf != t and R_INTEGER.match(leaf):
            return "integer"
        target = aliases.get(t) or aliases.get(leaf)
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


def rust_signature_parts(text: str, open_at: int) -> tuple[str, list[str]] | None:
    """The declaration's return-type text and parameter-type texts.

    The same scan `parse_rust_declaration` classifies, kept in one place so the
    class/arity plane and the type plane cannot disagree about what was read.
    """
    close_at = _scan_balanced(text, open_at)
    if close_at < 0:
        return None
    params = text[open_at + 1:close_at]
    args = split_top_level(params) if params.strip() else []
    rest = text[close_at + 1:]
    m = re.match(r"\s*->\s*", rest)
    if not m:
        return "()", args
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
    return "".join(ret).strip(), args


def parse_rust_declaration(
    text: str, open_at: int, aliases: dict[str, str]
) -> tuple[str, int] | None:
    parts = rust_signature_parts(text, open_at)
    if parts is None:
        return None
    ret, args = parts
    return classify_rust(ret, aliases), len(args)


def read_sources() -> tuple[
    dict[str, tuple[str, int]],
    dict[str, tuple[str, list[str]]],
    dict[str, dict[str, str]],
    dict[str, str],
    str,
    str,
]:
    """Rust declarations, raw signatures, per-symbol alias scope, global unique
aliases, all Rust text, all C text.

    Two passes over the Rust sources, not one. An alias is often defined in a file
    that sorts *after* the one that returns it (`method.rs` returns `BioReadFn`, which
    `mod.rs` defines), and classifying during the scan made every such declaration
    `unclassified` -- a court reporting its own traversal order as a property of the
    code. Phase 4 learned the same shape of lesson from the ERR coordinates (D60).

    The alias scope is **per file**. `type FreeFn` is declared twice in this crate --
    `src/runtime/stack.rs` has the one-argument `OPENSSL_sk_freefunc` and
    `src/runtime/mem.rs` has the three-argument `CRYPTO_free_fn` -- and a single
    global table silently returned whichever file sorted first. That is a property of
    the court's traversal order, not of the declarations, so each declaration is now
    resolved against its own file's aliases first, with a name that is defined in
    exactly one file usable as a fallback. A name defined in more than one file and
    not present in the declaring file is deliberately left unresolved, so it is
    reported rather than guessed.
    """
    declarations: dict[str, tuple[str, int]] = {}
    signatures: dict[str, tuple[str, list[str]]] = {}
    scopes: dict[str, dict[str, str]] = {}
    aliases_by_file: dict[str, dict[str, str]] = {}
    rust_files: list[tuple[str, str]] = []
    c_text: list[str] = []
    for path in sorted(SRC.rglob("*")):
        if path.suffix == ".rs":
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            key = str(path)
            rust_files.append((key, text))
            file_aliases: dict[str, str] = {}
            for m in RUST_ALIAS_RE.finditer(text):
                file_aliases.setdefault(m.group(1), m.group(2).strip())
            aliases_by_file[key] = file_aliases
        elif path.suffix == ".c":
            try:
                c_text.append(path.read_text(encoding="utf-8"))
            except UnicodeDecodeError:
                continue
    seen: dict[str, int] = {}
    for file_aliases in aliases_by_file.values():
        for name in file_aliases:
            seen[name] = seen.get(name, 0) + 1
    unique_aliases: dict[str, str] = {}
    for file_aliases in aliases_by_file.values():
        for name, target in file_aliases.items():
            if seen[name] == 1:
                unique_aliases[name] = target
    for key, text in rust_files:
        scope = dict(unique_aliases)
        scope.update(aliases_by_file.get(key, {}))
        for m in DECL_RE.finditer(text):
            sym = m.group(1)
            parsed = parse_rust_declaration(text, m.end() - 1, scope)
            if parsed is not None:
                declarations.setdefault(sym, parsed)
            parts = rust_signature_parts(text, m.end() - 1)
            if parts is not None:
                signatures.setdefault(sym, parts)
                scopes.setdefault(sym, scope)
    return (
        declarations,
        signatures,
        scopes,
        unique_aliases,
        "\n".join(t for _, t in rust_files),
        "\n".join(c_text),
    )


def canon_c_return(proto: str, typedefs: dict[str, str]) -> str | None:
    """The authority's declared return type, in canonical form.

    A function-pointer return reads backwards from a normal prototype:
    `int (*(const BIO_METHOD *))(BIO *, char *, int)` is a function taking one
    `const BIO_METHOD *` whose *result* is an `int (*)(BIO *, char *, int)`. The
    returned function's parameter list is the trailing top-level group, and the
    outer function's parameters -- which the atlas already recorded separately --
    are the group inside the `(*...)` declarator. Swapping those two is the mistake
    the class/arity plane was written to avoid, so it is spelled out here too.
    """
    text = proto.strip()
    groups = top_level_groups(text)
    if not groups:
        return None
    g0 = groups[0]
    content = text[g0[0] + 1:g0[1]]
    if content.strip().startswith("*"):
        ret = canon_c_type(text[:g0[0]].strip(), typedefs)
        if ret is None:
            return None
        glast = groups[-1]
        args: list[str] = []
        if glast != g0:
            for a in split_top_level(text[glast[0] + 1:glast[1]]):
                if a.strip() in ("", "void"):
                    continue
                c = canon_c_type(a, typedefs)
                if c is None:
                    return None
                args.append(c)
        return f"fptr({ret}; {', '.join(args)})"
    return canon_c_type(text[:g0[0]].strip(), typedefs)


def c_signature_canon(
    rec: dict, typedefs: dict[str, str]
) -> tuple[str, tuple[str, ...]] | None:
    """The authority's whole prototype: canonical return and canonical parameters.

    The parameter list comes from the atlas's own parameter records rather than from
    re-splitting the prototype string, so the authority side is never re-parsed by
    this court -- only classified.
    """
    ret = canon_c_return(rec["type"], typedefs)
    if ret is None:
        return None
    args: list[str] = []
    for p in rec.get("params", []):
        c = canon_c_type(p["type"], typedefs)
        if c is None:
            return None
        args.append(c)
    return ret, tuple(args)


def canon_rust_param(raw: str, aliases: dict[str, str]) -> str | None:
    """A Rust parameter's *type*, with its binding name removed.

    `fn f(a: *mut T)` gives `a: *mut T` from the parameter split; the type is what
    follows the first top-level `:` that is not part of a `::` path. A parameter
    spelled without a binding (`_: T`) therefore still reads correctly, and one
    spelled without a type cannot occur in a valid declaration.
    """
    depth = 0
    i = 0
    t = " ".join(raw.split())
    while i < len(t):
        ch = t[i]
        if ch in "(<[":
            depth += 1
        elif ch in ")>]":
            depth -= 1
        elif ch == ":" and depth == 0:
            before = t[i - 1] if i > 0 else ""
            after = t[i + 1] if i + 1 < len(t) else ""
            if before != ":" and after != ":":
                return canon_rust_type(t[i + 1:].strip(), aliases)
            i += 1
            continue
        i += 1
    return None


def rust_signature_canon(
    parts: tuple[str, list[str]] | None, aliases: dict[str, str]
) -> tuple[str, tuple[str, ...]] | None:
    """The crate's declaration in the same canonical form."""
    if parts is None:
        return None
    ret_raw, args_raw = parts
    ret = canon_rust_type(ret_raw, aliases)
    if ret is None:
        return None
    args: list[str] = []
    for a in args_raw:
        c = canon_rust_param(a, aliases)
        if c is None:
            return None
        args.append(c)
    return ret, tuple(args)


def canon_render(sig: tuple[str, tuple[str, ...]]) -> str:
    """A canonical signature as one readable line for the artifact."""
    return f"{sig[0]} ({', '.join(sig[1])})"


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    atlas = REPO_ROOT / "forensics" / "atlas" / auth.id

    fn_doc = json.loads((atlas / "functions.json").read_text(encoding="utf-8"))["body"]
    records = {r["name"]: r for r in fn_doc["records"]}
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

    declarations, signatures, scopes, aliases, rust_text, c_text = read_sources()

    checked: list[dict] = []
    mismatches: list[dict] = []
    unclassified: list[dict] = []
    generated: list[str] = []
    in_c: list[str] = []
    not_found: list[str] = []
    no_prototype: list[str] = []
    type_checked: list[dict] = []
    type_mismatches: list[dict] = []
    type_unmapped: list[dict] = []

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

        # --- the type plane -------------------------------------------------
        # Class and arity say a call goes through; the type plane says each
        # argument is the right *kind* of thing. Both sides are canonicalised so
        # that a typedef spelling difference is not reported, while pointer
        # depth, pointee constness, integer width and function-pointer shape are.
        rec = records.get(sym)
        c_sig = c_signature_canon(rec, typedefs) if rec is not None else None
        r_sig = rust_signature_canon(signatures.get(sym), scopes.get(sym, aliases))
        if c_sig is None or r_sig is None:
            type_unmapped.append({
                "symbol": sym, "prototype": proto,
                "c_signature": None if c_sig is None else canon_render(c_sig),
                "rust_signature": None if r_sig is None else canon_render(r_sig),
                "why": "a parameter or return type this court cannot canonicalise",
            })
            continue
        type_row = {
            "symbol": sym,
            "c_signature": canon_render(c_sig),
            "rust_signature": canon_render(r_sig),
        }
        type_checked.append(type_row)
        if c_sig != r_sig:
            type_row["return_mismatch"] = c_sig[0] != r_sig[0]
            type_row["param_mismatches"] = [
                i for i, (a, b) in enumerate(zip(c_sig[1], r_sig[1])) if a != b
            ]
            if len(c_sig[1]) != len(r_sig[1]):
                type_row["arity_mismatch"] = True
            type_mismatches.append(type_row)

    body = {
        "what": (
            "every implemented libcrypto export's Rust declaration agrees with the "
            "authority's recorded prototype on return class and arity, and -- in the "
            "type plane -- on the canonical shape of its return and every parameter"
        ),
        "why": (
            "the atlas records the prototype and nothing compared it: a wrong return "
            "class or arity is a wrong call convention, which no value-level probe "
            "finds cheaply (docs/DECISIONS.md D65). Class and arity alone left the "
            "parameter list unchecked, so a `const` dropped, an extra pointer level, "
            "or an `int` widened to `long` was invisible until a probe happened to "
            "call that one function; the type plane closes that"
        ),
        "canonical_form": (
            "both sides are reduced to one grammar: `void`; `int:<bytes>:<s|u>`; "
            "`float:<bytes>`; `ptr(<inner>)`; `const(<inner>)`; `fn(<ret>; <args>)`; "
            "`opaque`. A struct pointee's *name* is deliberately discarded -- "
            "`*mut Asn1String` and `*mut c_void` are the same to a caller -- while "
            "pointer depth, pointee constness, integer width and signedness, and "
            "function-pointer argument shape are kept. A type the table cannot "
            "canonicalise is reported under `type_unmapped` and never counted as a "
            "pass"
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
            "type_checked": len(type_checked),
            "type_mismatches": len(type_mismatches),
            "type_unmapped": len(type_unmapped),
        },
        "mismatches": mismatches,
        "unclassified": unclassified,
        "declaration_is_generated": generated,
        "implementation_is_c": in_c,
        "not_found": not_found,
        "no_prototype_in_atlas": no_prototype,
        "type_mismatches": type_mismatches,
        "type_unmapped": type_unmapped,
        "note": (
            "A symbol this court cannot classify -- including one the crate declares "
            "from a `macro_rules!` -- is reported under its own heading and never "
            "counted as a pass, so `mismatches == 0` must be read together with "
            "`checked`, and `type_mismatches == 0` together with `type_checked`. The "
            "type plane's canonical form is what the court can defend; it does not "
            "claim two declarations are textually identical."
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
    print(f"  type plane: checked={c['type_checked']} "
          f"mismatches={c['type_mismatches']} unmapped={c['type_unmapped']}")
    for row in mismatches:
        print(f"  MISMATCH {row['symbol']}: authority returns {row['c_return']} with "
              f"{row['c_arity']} parameter(s); the crate returns {row['rust_return']} "
              f"with {row['rust_arity']}")
    for row in type_mismatches:
        print(f"  TYPE-MISMATCH {row['symbol']}: authority {row['c_signature']} != "
              f"crate {row['rust_signature']}")
    for row in type_unmapped:
        print(f"  TYPE-UNMAPPED {row['symbol']}: {row['prototype']}")
    for row in unclassified:
        print(f"  unclassified {row['symbol']}: {row.get('why', '')} "
              f"({row.get('prototype', '')})")
    if not_found:
        print(f"  not found anywhere in src/: {', '.join(not_found[:10])}"
              + (f" (+{len(not_found) - 10} more)" if len(not_found) > 10 else ""))
    print(f"  -> {rel(OUT)}")

    return 1 if (mismatches or type_mismatches or type_unmapped or not_found) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
