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
(`void`, pointer, function pointer, integer, floating) and the **arity**, and -- in
the type plane -- the canonical shape of the return type and of every parameter.
A struct pointee's *name* is deliberately discarded, because `*mut Asn1String` and
`*mut c_void` are the same to a caller; pointer depth, pointee constness, integer
width and signedness, and function-pointer shape are kept, because those are not.

Three declaration surfaces are read, and since D98 all three are *checked*:

  * a plain `pub`/`pub(crate)` `extern "C" fn` in `src/**/*.rs`;
  * a `macro_rules!` invocation, by reading the macro's declared parameter list and
the literal signature inside its body and substituting at each use;
  * a definition in `src/**/*.c`, for the variadic shims stable Rust cannot express.

Only three of the 932 implemented exports remain unjudged, and the reason is not a
gap in this court: they are declared in headers the authority does not install, so
the Phase 1 atlas -- whose universe is the installed public surface -- has no
prototype for them. Their ABI is proved by the Phase 2 loader court.

Sensitivity
-----------
A court that has only ever been seen to pass has not been shown to be able to fail,
so the artifact carries three **controls**: a macro body's return type perturbed, a
C definition's parameter perturbed, and a macro body that fills a type position (which
must be *refused* rather than read as `opaque`). Each asserts both halves -- that the
defective input is detected and the corrected one is not -- using the same parser and
the same canonical form as the real pass. `all_detected` is a failure condition.

How a symbol is classified
--------------------------
  * `checked`            — a Rust declaration was parsed and agrees.
  * `mismatch`           — a Rust declaration was parsed and disagrees. **Fails.**
  * `unclassified`       — parsed, but a class this court cannot name. Never a pass.
  * `declaration_is_generated` — the symbol appears in `src/**/*.rs` but not as a
                          declaration this court can read directly. This is the
                          `macro_rules!` surface, and since D98 it is **read** rather
                          than reported: `macro_defs` parses each macro's declared
                          parameter list and the literal signature inside its body, and
                          `expand_macro_invocations` substitutes each invocation's
                          arguments, so a macro-generated export is checked on the same
                          canonical form as every other. The heading now survives only
                          for a macro this court could not read, which is a hard failure.
  * `implementation_is_c` — a definition in `src/**/*.c` (the variadic and syscall
                          shims, which stable Rust cannot express). Since D98 their
                          **C** signature is read and canonicalised against the
                          authority's prototype, so they are checked rather than merely
                          counted.
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
from dataclasses import dataclass
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
    # `pub(crate)` was missing from this alternation until D98, and that single
    # omission hid twenty-six exports: `src/runtime/err_loaders.rs` declares every
    # `ERR_load_<LIB>_strings` as `pub(crate) extern "C" fn` with `#[no_mangle]`,
    # because the symbol has to be exported while the *Rust item* stays crate-private.
    # Twenty-six symbols were therefore reported as "the symbol appears in src but not
    # as a declaration this court can parse" -- the court's own regex was the defect,
    # not the declarations. The instrument is the suspect before the code, again.
    r"pub(?:\s*\([^)]*\))?\s+(?:unsafe\s+)?extern\s+\"C\"\s+fn\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*\("
)
RUST_ALIAS_RE = re.compile(
    r"^(?:pub(?:\s*\([a-z]+\s*\))?\s+)?type\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*",
    re.MULTILINE,
)
C_DEF_RE_TEMPLATE = r"(?m)^[A-Za-z_][A-Za-z0-9_ \t*]*\b{name}\s*\("

# A `macro_rules!` definition, and the `$param` names its body turns into exported
# symbols. See `macro_defs` and `expand_macro_invocations`.
MACRO_RULES_RE = re.compile(r"macro_rules!\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")
MACRO_FN_RE_TEMPLATE = r"\bfn\s+\${name}\s*\("
MACRO_BINDING_RE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")


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

# The C floating widths, which `core::ffi` spells `c_float`/`c_double`. They are kept apart from
# `RUST_INT_WIDTH` because the canonical form names the width and the class is `floating` rather
# than `integer`: `RAND_add`'s third parameter is the first export to carry one (`double`), and a
# court that could not read `c_double` would report an unreadable name against the authority's
# `float:8` instead of comparing two types.
RUST_FLOAT_WIDTH = {
    "c_float": 4,
    "f32": 4,
    "c_double": 8,
    "f64": 8,
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
    # A function *pointer* and a function *type with a pointer return* both spell `*(`, so
    # a substring test cannot tell `int (*)(BIO *, int)` from `void *(void **, long)`.
    # What separates them is where the `*` sits: in the first it is the declarator inside
    # the outermost group, and in the second it belongs to the return type in front of it.
    #
    # This was found by `d2i_of_void`, whose return is `void *`: it went down the
    # function-pointer path and failed, so every prototype mentioning it was reported
    # unmapped, while `i2d_of_void` — the same shape with an `int` return — mapped. The
    # instrument was the suspect before the declarations were, again.
    groups = top_level_groups(t)
    if groups:
        g0 = groups[0]
        inner = t[g0[0] + 1:g0[1]].strip()
        if inner.startswith("*"):
            tail = t[g0[1] + 1:].lstrip()
            if not tail.startswith("("):
                # `T (*)[N]` is a *pointer to an array*, and it shares the `(*` spelling
                # with a function pointer; what separates them is what follows the
                # declarator. Reading it as a function pointer made the authority's own
                # `ocb128_f` canonicalise `const unsigned char (*)[16]` to
                # `fptr(int:1:u; )` -- the argument list it never had. The instrument was
                # the suspect, not the declaration: see docs/DECISIONS.md D229.
                stars = 0
                for ch in inner:
                    if ch != "*":
                        break
                    stars += 1
                # `const` is read further down, after the group branches, so it is
                # recomputed here rather than reordered: moving the strip above them
                # would drop the pointee `const` of `const T *`.
                cst = t.startswith("const ")
                elem_src = t[:g0[0]].strip()
                if cst:
                    elem_src = elem_src[len("const "):].strip()
                elem = canon_c_type(elem_src, typedefs, depth + 1)
                if elem is None:
                    return None
                idx = t.rfind("[")
                base = f"arr({elem};{t[idx + 1:-1].strip()})"
                if cst:
                    base = f"const({base})"
                return "ptr(" * stars + base + ")" * stars
            return canon_c_fnptr(t, typedefs, depth)
        if "*" in t[:g0[0]] and not t[g0[1] + 1:].strip():
            # `RET *(...)`: a function type whose return is a pointer. The regex branch
            # below cannot match it, because its return-type group allows only letters,
            # digits and spaces.
            ret = canon_c_type(t[:g0[0]], typedefs, depth + 1)
            if ret is None:
                return None
            args: list[str] = []
            for a in split_top_level(inner):
                if a.strip() in ("", "void"):
                    continue
                c = canon_c_type(a, typedefs, depth + 1)
                if c is None:
                    return None
                args.append(c)
            return f"fn({ret}; {', '.join(args)})"
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
    if t.endswith("]") and "[" in t:
        # An *array* type, reached here almost always through a typedef -- `DES_cblock`
        # is `unsigned char[8]`, so `DES_cblock *` resolves to a pointer to an array.
        # Until this branch existed the type plane could not read it and reported a
        # *correct* declaration as `type_unmapped`, which is a failure, not a gap: the
        # first implementation whose prototype mentions `DES_cblock` was blocked by the
        # instrument rather than by the authority. The element type and the length are
        # both kept, so `DES_cblock *` and `unsigned char *` remain distinguishable.
        idx = t.rfind("[")
        elem = canon_c_type(t[:idx].strip(), typedefs, depth + 1, pointee)
        if elem is None:
            return None
        base = f"arr({elem};{t[idx + 1:-1].strip()})"
        return f"const({base})" if (const and pointee) else base
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
    """A C function-pointer type: `int (*)(BIO *, char *, int)`.

    The declarator may carry **more than one** `*`, and the count is the depth:
    `int (*)(...)` is a function pointer, `int (**pinit)(...)` is a pointer to one,
    `int (***)(...)` a pointer to two. All three are one pointer in the call
    convention, which is why collapsing them is easy to miss -- and why it was
    missed: `EVP_PKEY_meth_get_init`'s `int (**pinit)(EVP_PKEY_CTX *)` compared equal
    to `int (*)(EVP_PKEY_CTX *)`, so a crate that declared the output parameter as a
    bare function pointer instead of a pointer to one would have passed. Found when
    the forty `EVP_PKEY_meth_get_*` accessors landed (`docs/DECISIONS.md` D183).
    """
    groups = top_level_groups(t)
    if not groups:
        return None
    g0 = groups[0]
    content = t[g0[0] + 1:g0[1]].strip()
    stars = 0
    for ch in content:
        if ch != "*":
            break
        stars += 1
    if stars == 0:
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
    inner = f"fptr({ret}; {', '.join(args)})"
    return "ptr(" * (stars - 1) + inner + ")" * (stars - 1)


def canon_rust_type(text: str, aliases: dict[str, str], depth: int = 0) -> str | None:
    """A Rust type in the same canonical form as :func:`canon_c_type`."""
    if depth > 12:
        return None
    t = " ".join(text.split()).strip()
    # A type that sits in a comma-separated *list* may carry the list's trailing comma.
    # Rust allows it, and `cargo fmt` emits it for every multi-line generic argument
    # whose argument is itself long enough to wrap:
    #
    #     pub_print: Option<
    #         unsafe extern "C" fn(*mut Bio, *const EvpPkey, c_int, *mut Asn1Pctx) -> c_int,
    #     >,
    #
    # The comma belongs to `Option<...>`'s argument list, but `canon_rust_fnptr` reads
    # the text after the inner `->` as the return type, so it becomes `c_int,` and
    # canonicalises to None -- which reported five *correct* `EVP_PKEY_asn1_set_*`
    # mutators as `type_unmapped` and produced a false "the declarations need named
    # aliases" conclusion in docs/DECISIONS.md D178 (corrected by D179). Dropping a
    # trailing comma at the top level is a normalisation of the same kind as the
    # `Option<...>` unwrap above: the text is a type the compiler accepts.
    while t.endswith(","):
        t = t[:-1].strip()
    if t in ("()", "void", ""):
        return "void"
    if t.startswith("Option<") and t.endswith(">"):
        # A nullable function pointer and a bare one are the same to the ABI.
        return canon_rust_type(t[len("Option<"):-1], aliases, depth + 1)
    if t.startswith("[") and t.endswith("]") and ";" in t:
        # An array type. This is the Rust side of the array branch in `canon_c_type`:
        # `*mut [u8; 8]` and `DES_cblock *` must canonicalise alike, and the element
        # type and length are both kept so the two do not become a wildcard.
        elem_text, _, len_text = t[1:-1].rpartition(";")
        elem = canon_rust_type(elem_text.strip(), aliases, depth + 1)
        if elem is None:
            return None
        return f"arr({elem};{len_text.strip()})"
    if t.startswith("*mut "):
        inner = canon_rust_type(t[len("*mut "):], aliases, depth + 1)
        return None if inner is None else f"ptr({inner})"
    if t.startswith("*const "):
        inner = canon_rust_type(t[len("*const "):], aliases, depth + 1)
        return None if inner is None else f"ptr(const({inner}))"
    if t.startswith("unsafe extern \"C\" fn") or t.startswith("extern \"C\" fn"):
        return canon_rust_fnptr(t, aliases, depth)
    if t in RUST_FLOAT_WIDTH:
        return f"float:{RUST_FLOAT_WIDTH[t]}"
    if t in RUST_INT_WIDTH:
        b, s = RUST_INT_WIDTH[t]
        return f"int:{b}:{'s' if s else 'u'}"
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_:]*", t):
        leaf = t.split("::")[-1]
        if leaf != t and leaf in RUST_INT_WIDTH:
            # `core::ffi::c_uint` and `c_uint` are the same type.
            b, s = RUST_INT_WIDTH[leaf]
            return f"int:{b}:{'s' if s else 'u'}"
        if leaf != t and leaf in RUST_FLOAT_WIDTH:
            # `core::ffi::c_double` and `c_double` are the same type.
            return f"float:{RUST_FLOAT_WIDTH[leaf]}"
        target = aliases.get(t) or aliases.get(leaf)
        if target is not None:
            return canon_rust_type(target, aliases, depth + 1)
        return "opaque"
    return None


def strip_binding(raw: str) -> str:
    """A declared item's *type*, with a binding name removed if it has one.

    `a: *mut T` and `*mut T` are the same type; the name is not. A parameter of a
    function *declaration* always has one, an argument of a function-*pointer* type may
    (`unsafe extern "C" fn(provctx: *mut c_void) -> c_int` is legal Rust), and
    `canon_rust_fnptr` reads the second while `canon_rust_param` reads the first. They
    disagreed about it until D180: `GetReasonStringsFn` was the crate's one named
    fn-pointer argument and the dispatch plane reported it `unmapped`.

    The type follows the first top-level `:` that is not part of a `::` path.
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
                return t[i + 1:].strip()
            i += 1
            continue
        i += 1
    return t


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
        c = canon_rust_type(strip_binding(a), aliases, depth + 1)
        if c is None:
            return None
        args.append(c)
    return f"fptr({ret}; {', '.join(args)})"


def strip_qualifiers(text: str) -> str:
    return " ".join(text.replace("const ", " ").replace("volatile ", " ").split())


def classify_c(text: str, typedefs: dict[str, str] | None = None) -> str:
    t = strip_qualifiers(text)
    if t in ("void", ""):
        return "void"
    if "(*" in t or "(*)" in t:
        return "function_pointer"
    if t.endswith("*"):
        # A pointer to a **typedef that names a function type** is a function pointer, and the
        # syntactic test above cannot see it. `EVP_PKEY_gen_cb *EVP_PKEY_CTX_get_cb(EVP_PKEY_CTX *)`
        # resolves to `int (*)(EVP_PKEY_CTX *)`, while `BIO_meth_get_read` spells the same thing
        # `int (*(const BIO_METHOD *))(BIO *, char *, int)` and hits the test above. Those are one C
        # type spelled two ways, so they must classify alike and the canonicaliser decides. The
        # crate's side of that comparison is `Option<EvpPkeyGenCb>` against an alias, which
        # `classify_rust` resolves to `function_pointer` -- so without this the court reports a
        # mismatch between a type and itself.
        if typedefs is not None:
            canon = canon_c_type(t, typedefs)
            if canon is not None and canon.startswith("fptr("):
                return "function_pointer"
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
    if t in RUST_FLOAT_WIDTH:
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
        if leaf != t and leaf in RUST_FLOAT_WIDTH:
            return "floating"
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


def alias_target(text: str, start: int) -> str:
    """An alias body from `start` to the `;` that terminates it at bracket depth zero.

    The regex that used to capture this body was `[^;]+`, which stops at the *first*
    semicolon -- and an array type inside a function-pointer alias carries its own
    (`l_: *const [u8; 16]`). The alias was therefore truncated to `*const [u8`, the
    function-pointer canonicaliser answered None, and the two exports that take an
    `ocb128_f` were reported `type_unmapped` while their declarations were correct.
    The instrument dropped the detail, not the code: see docs/DECISIONS.md D229.
    """
    depth = 0
    i = start
    while i < len(text):
        ch = text[i]
        if ch == "-" and text[i + 1:i + 2] == ">":
            i += 2
            continue
        if ch in "(<[":
            depth += 1
        elif ch in ")>]":
            depth -= 1
        elif ch == ";" and depth == 0:
            return text[start:i]
        i += 1
    return text[start:]


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
    return classify_c(resolve_c(text[:first[0]], typedefs), typedefs), arity


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


def blank_comments(text: str) -> str:
    """Replace every comment's body with spaces, preserving length and line breaks.

    Length and line breaks are preserved so that every offset and line number derived
    from the original text still means the same thing.

    This exists because a Rust parameter list may legitimately contain a comment, and a
    comment may contain a comma or a parenthesis. Without blanking, ``split_top_level``
    counted the comment's comma as a parameter and ``_scan_balanced`` read the comment's
    parenthesis as structure. Both were observed, on ``ASN1_item_ex_d2i``: a two-line
    comment inside its parameter list made the class/arity plane report ten parameters
    for a declaration that has eight. The instrument was the suspect before the
    declaration was, as usual.

    String literals are skipped so a ``//`` inside one is not taken for a comment; that
    matters here because this crate writes C-string literals (``c"..."``) throughout.
    """
    out = list(text)
    n = len(text)
    i = 0
    while i < n:
        ch = text[i]
        if ch == "/" and text[i + 1:i + 2] == "/":
            while i < n and text[i] != "\n":
                out[i] = " "
                i += 1
        elif ch == "/" and text[i + 1:i + 2] == "*":
            depth = 0
            while i < n:
                if text[i] == "/" and text[i + 1:i + 2] == "*":
                    depth += 1
                    out[i] = out[i + 1] = " "
                    i += 2
                    continue
                if text[i] == "*" and text[i + 1:i + 2] == "/":
                    depth -= 1
                    out[i] = out[i + 1] = " "
                    i += 2
                    if depth == 0:
                        break
                    continue
                if text[i] != "\n":
                    out[i] = " "
                i += 1
        elif ch == '"':
            i += 1
            while i < n and text[i] != '"':
                if text[i] == "\\":
                    i += 1
                i += 1
            i += 1
        else:
            i += 1
    return "".join(out)


def _scan_delimited(text: str, open_at: int) -> int:
    """Index of the bracket closing the one at `open_at`, skipping literals.

    `_scan_balanced` is the right scanner for a declaration, where nothing can hold
    a bracket that is not structure. A *macro body* is different: `concat!("`BIGNUM *",
    stringify!($name), "(BIGNUM *bn)`")` contains parentheses inside a string
    literal, and `blank_comments` cannot blank them because they are not comments.
    Counting them as structure would end a body early and quietly attribute the next
    macro's declarations to this one, so string and char literals are skipped here.
    """
    pairs = {"(": ")", "{": "}", "[": "]"}
    if open_at >= len(text) or text[open_at] not in pairs:
        return -1
    depth = 0
    i = open_at
    while i < len(text):
        ch = text[i]
        if ch == '"':
            i += 1
            while i < len(text):
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == '"':
                    break
                i += 1
            i += 1
            continue
        if ch == "'":
            # A char literal closes within a few bytes; a lifetime never closes with
            # a second `'` before the next identifier ends, so this is safe.
            if text[i + 2:i + 3] == "'":
                i += 3
                continue
            if text[i + 1:i + 2] == "\\":
                j = text.find("'", i + 2)
                if 0 <= j <= i + 6:
                    i = j + 1
                    continue
            i += 1
            continue
        if ch in pairs:
            depth += 1
        elif ch in ")}]":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _split_delimited(text: str, start: int, end: int) -> list[tuple[int, int]]:
    """Top-level comma-separated spans of `text[start:end]`, as absolute offsets.

    Split on commas that are not inside a bracket of any kind and not inside a
    literal. Returns `[]` for an empty or whitespace-only region.
    """
    spans: list[tuple[int, int]] = []
    depth = 0
    i = start
    piece = start
    while i < end:
        ch = text[i]
        if ch == '"':
            i += 1
            while i < end:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == '"':
                    break
                i += 1
            i += 1
            continue
        if ch in "({[":
            depth += 1
        elif ch in ")}]":
            depth -= 1
        elif ch == "," and depth == 0:
            spans.append((piece, i))
            piece = i + 1
        i += 1
    spans.append((piece, end))
    return [s for s in spans if text[s[0]:s[1]].strip()]


@dataclass(frozen=True)
class MacroParam:
    """One top-level element of a `macro_rules!` matcher.

    `kind` is `simple` for `$name:kind` and `repeat` for `$( ... )sep*`. `binds`
    names every `$name` the element binds; `symbols` names those of them that the
    macro's body turns into an exported function, with that function's signature.
    """
    kind: str
    binds: tuple[str, ...]
    symbols: tuple[tuple[str, tuple[str, list[str]]], ...]


@dataclass(frozen=True)
class MacroDef:
    """A `macro_rules!` whose body declares at least one exported function."""
    name: str
    file: str
    params: tuple[MacroParam, ...]
    span: tuple[int, int]  # offsets of the whole definition, for skipping it

    @property
    def symbols(self) -> tuple[tuple[str, tuple[str, list[str]]], ...]:
        return tuple(s for p in self.params for s in p.symbols)


def macro_defs(
    text: str, source_key: str
) -> tuple[list[MacroDef], list[str]]:
    """Every `macro_rules!` in `text` that declares an exported function.

    The crate cannot build a `#[no_mangle]` symbol name from another token, so each
    of these macros writes both identifiers at every use and the *body* holds a
    literal signature with a `$param` where the name goes. The signature is
    therefore readable; only the substitution was missing.

    A macro with no `fn $param(` in its body -- `bail!`, the `macro_rules!` helper
    in `conf/def.rs` -- binds no symbol and is skipped, which is why this does not
    need to understand arbitrary macro syntax: it only has to understand the macros
    that produce symbols, and it fails loudly when one of those has a shape it cannot
    read. Returns `(defs, unreadable)`.
    """
    defs: list[MacroDef] = []
    unreadable: list[str] = []
    for m in MACRO_RULES_RE.finditer(text):
        name = m.group(1)
        body_open = m.end() - 1
        body_close = _scan_delimited(text, body_open)
        if body_close < 0:
            unreadable.append(f"{source_key}:{name}: the definition does not close")
            continue
        rule = text[body_open + 1:body_close]
        # The first rule: `(matcher) => { expansion }`. A macro with several rules
        # where more than one declares a symbol is not something this court can read
        # without implementing macro dispatch, so it is reported rather than guessed.
        paren = rule.find("(")
        if paren < 0:
            unreadable.append(f"{source_key}:{name}: no matcher")
            continue
        matcher_end = _scan_delimited(rule, paren)
        if matcher_end < 0:
            unreadable.append(f"{source_key}:{name}: the matcher does not close")
            continue
        matcher = rule[paren + 1:matcher_end]

        # The expansion body: the first `{` after the matcher. Everything after it is
        # where the `fn $param(` declarations live.
        brace = rule.find("{", matcher_end)
        if brace < 0:
            unreadable.append(f"{source_key}:{name}: no expansion body")
            continue
        expansion_end = _scan_delimited(rule, brace)
        if expansion_end < 0:
            unreadable.append(f"{source_key}:{name}: the body does not close")
            continue
        expansion = rule[brace + 1:expansion_end]

        params: list[MacroParam] = []
        for lo, hi in _split_delimited(matcher, 0, len(matcher)):
            element = matcher[lo:hi].strip()
            if element.startswith("$("):
                inner_end = _scan_delimited(element, 1)
                if inner_end < 0:
                    unreadable.append(
                        f"{source_key}:{name}: a repetition pattern does not close")
                    continue
                inner = element[2:inner_end]
                binds = tuple(dict.fromkeys(MACRO_BINDING_RE.findall(inner)))
                params.append(_macro_param("repeat", binds, expansion))
            elif element.startswith("$"):
                bm = MACRO_BINDING_RE.match(element)
                if bm is None:
                    continue
                params.append(_macro_param("simple", (bm.group(1),), expansion))
            # Anything else is a literal token (`,`, `=>`, a qualifier) and binds
            # nothing.
        if any(p.symbols for p in params):
            defs.append(MacroDef(name=name, file=source_key, params=tuple(params),
                                 span=(m.start(), body_close + 1)))
    return defs, unreadable


def _macro_param(kind: str, binds: tuple[str, ...], expansion: str) -> MacroParam:
    """The parameter, with the signature of every binding its body declares."""
    symbols: list[tuple[str, tuple[str, list[str]]]] = []
    for bind in binds:
        fn_re = re.compile(MACRO_FN_RE_TEMPLATE.format(name=re.escape(bind)))
        for m in fn_re.finditer(expansion):
            parts = rust_signature_parts(expansion, m.end() - 1)
            if parts is None:
                continue
            if "$" in parts[0] or any("$" in a for a in parts[1]):
                # A type position the macro fills in. This court cannot substitute
                # into a type, so it says so instead of reading half a signature.
                symbols.append((bind, ("unclassified", [])))
                continue
            symbols.append((bind, parts))
    return MacroParam(kind=kind, binds=binds, symbols=tuple(symbols))


def expand_macro_invocations(
    files: list[tuple[str, str]], defs: dict[str, MacroDef]
) -> tuple[dict[str, tuple[tuple[str, list[str]], str]], list[str]]:
    """Every exported symbol a `macro_rules!` invocation creates, by bare name.

    Answers `name -> (signature, invoking_file)`. The invoking file is what an alias in
    the macro body resolves against, since a macro body is expanded at its call site.

    Positional, in the order the matcher declares. A repetition parameter consumes
    every remaining comma-separated group, which is asserted rather than assumed: a
    matcher with a repetition that is not last is reported, because guessing where
    one ends is how a silent mis-substitution would start.

    **An invocation inside a `macro_rules!` definition is a template, not a call.** Its
    arguments are the defining macro's own `$` parameters, so reading them as names would
    report symbols that do not exist -- which is what a wrapper macro (`dec!`, `slh_pair!`)
    that forwards to a symbol-declaring macro (`make_decoder!`) looks like. Only a
    top-level invocation names anything, so every macro definition's span is skipped.
    """
    found: dict[str, tuple[tuple[str, list[str]], str]] = {}
    problems: list[str] = []
    for key, text in files:
        # Every `macro_rules!` body's span in this file. The defining macro's own span was
        # already skipped; this generalises it to a template argument in *any* macro.
        macro_spans: list[tuple[int, int]] = []
        for m in MACRO_RULES_RE.finditer(text):
            close = _scan_delimited(text, m.end() - 1)
            if close >= 0:
                macro_spans.append((m.start(), close + 1))
        for name, macro in defs.items():
            for m in re.finditer(rf"\b{re.escape(name)}\s*!", text):
                if any(lo <= m.start() < hi for lo, hi in macro_spans):
                    continue
                opener = m.end()
                while opener < len(text) and text[opener] in " \t\r\n":
                    opener += 1
                if opener >= len(text) or text[opener] not in "([{":
                    continue
                closer = _scan_delimited(text, opener)
                if closer < 0:
                    problems.append(f"{key}: `{name}!` invocation does not close")
                    continue
                groups = _split_delimited(text, opener + 1, closer)
                cursor = 0
                for index, param in enumerate(macro.params):
                    if not param.binds:
                        continue
                    if param.kind == "repeat":
                        if index != len(macro.params) - 1:
                            problems.append(
                                f"{key}: `{name}!` has a repetition that is not the "
                                "last matcher element, which this court cannot read")
                            cursor = len(groups)
                            break
                        take = groups[cursor:]
                        cursor = len(groups)
                    else:
                        take = groups[cursor:cursor + 1]
                        cursor += 1
                    for span in take:
                        if not param.symbols:
                            # A binder the body does not turn into a function -- a
                            # `$size`, a `$doc`, a `$flags`. Reading it as a name
                            # would report the crate's own literal arguments as
                            # unreadable invocations, which is how this check found
                            # itself before D98.
                            continue
                        group = text[span[0]:span[1]]
                        first = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)", group)
                        if first is None:
                            problems.append(
                                f"{key}: `{name}!` argument {group.strip()!r} does not "
                                "begin with an identifier, so the symbol it declares "
                                "cannot be named")
                            continue
                        for _bind, signature in param.symbols:
                            found.setdefault(first.group(1), (signature, key))
                if cursor < len(groups):
                    problems.append(
                        f"{key}: `{name}!` was given {len(groups)} argument group(s) "
                        f"and its matcher consumes {cursor}")
    return found, problems


def c_definition_signature(
    name: str, c_text: str, typedefs: dict[str, str]
) -> tuple[str, list[str]] | None:
    """The canonical signature of a C definition in `src/**/*.c`.

    The variadic shims (`BIO_printf`, `ERR_add_error_data`, ...) cannot be declared in
    stable Rust, so the crate implements them in C. Before D98 they were counted under
    `implementation_is_c` and therefore *unjudged*; their C signature is a perfectly
    readable comparison surface and is read here.

    A parameter's name is removed by trying the type as written first and, only when
    that does not canonicalise, stripping the trailing identifier. `int` keeps its
    spelling because it canonicalises; `const char *format` does not, so the name goes.
    """
    m = re.search(C_DEF_RE_TEMPLATE.format(name=re.escape(name)), c_text)
    if m is None:
        return None
    open_at = c_text.index("(", m.end() - 1)
    close_at = _scan_delimited(c_text, open_at)
    if close_at < 0:
        return None
    ret = c_text[m.start():open_at].strip()
    # The definition spells the return type *then* the name: `int BIO_printf`. The
    # name is a suffix, so it is the suffix that goes.
    if ret.endswith(name):
        ret = ret[:-len(name)].strip()
    c_ret = canon_c_type(ret, typedefs)
    if c_ret is None:
        return None
    args: list[str] = []
    for lo, hi in _split_delimited(c_text, open_at + 1, close_at):
        arg = c_text[lo:hi].strip()
        if arg in ("", "void"):
            continue
        if arg == "...":
            args.append("...")
            continue
        c = canon_c_type(arg, typedefs)
        if c is None:
            stripped = re.sub(r"[A-Za-z_][A-Za-z0-9_]*\s*$", "", arg).strip()
            c = canon_c_type(stripped, typedefs) if stripped else None
        if c is None:
            return None
        args.append(c)
    return c_ret, args


def read_sources() -> tuple[
    dict[str, tuple[str, int]],
    dict[str, tuple[str, list[str]]],
    dict[str, dict[str, str]],
    dict[str, str],
    str,
    str,
    list[str],
]:
    """Rust declarations, raw signatures, per-symbol alias scope, global unique
aliases, all Rust text, all C text, and every macro the court could not read.

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
                raw = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            key = str(path)
            text = blank_comments(raw)
            rust_files.append((key, text))
            file_aliases: dict[str, str] = {}
            for m in RUST_ALIAS_RE.finditer(text):
                file_aliases.setdefault(m.group(1), alias_target(text, m.end()).strip())
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

    # --- the `macro_rules!` plane -------------------------------------------
    # The crate cannot build a `#[no_mangle]` name from another token, so each macro
    # that exports a symbol writes both identifiers at every use and its body holds a
    # literal signature with `$param` where the name goes. That signature is readable;
    # only the substitution was missing, which is why 136 exports were reported as
    # unjudgeable rather than as wrong (docs/DECISIONS.md D96 recorded the gap and two
    # designs that did not need this; D98 records why this one is better).
    macro_table: dict[str, MacroDef] = {}
    unreadable: list[str] = []
    for key, text in rust_files:
        found, bad = macro_defs(text, key)
        unreadable.extend(bad)
        for found_def in found:
            macro_table.setdefault(found_def.name, found_def)
    expanded, expansion_problems = expand_macro_invocations(rust_files, macro_table)
    for sym, (signature, invoking_key) in expanded.items():
        if signature[0] == "unclassified":
            unreadable.append(
                f"{sym}: its macro fills a type position in the signature")
            continue
        scope = dict(unique_aliases)
        scope.update(aliases_by_file.get(invoking_key, {}))
        declarations.setdefault(sym, (classify_rust(signature[0], scope),
                                      len(signature[1])))
        signatures.setdefault(sym, signature)
        scopes.setdefault(sym, scope)

    return (
        declarations,
        signatures,
        scopes,
        unique_aliases,
        "\n".join(t for _, t in rust_files),
        "\n".join(c_text),
        unreadable + expansion_problems,
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
    if rec.get("variadic"):
        # The atlas's parameter *list* records only the named parameters -- Clang's
        # `ParmVarDecl`s -- so `int (BIO *, const char *, ...)` has two entries. The
        # varargs are as much a part of the call convention as the named arguments, and
        # leaving them out made these eight symbols compare against a two-argument
        # prototype and *fail*: the C definition was right and the court's reading of
        # the authority was wrong. Recorded because the same shape -- the instrument
        # dropping a detail rather than the code getting it wrong -- has now happened
        # five times in this stratum alone (docs/DECISIONS.md D98).
        args.append("...")
    return ret, tuple(args)


def canon_rust_param(raw: str, aliases: dict[str, str]) -> str | None:
    """A Rust parameter's *type*, with its binding name removed.

    `fn f(a: *mut T)` gives `a: *mut T` from the parameter split; the type is what
    follows the first top-level `:` that is not part of a `::` path. A parameter
    spelled without a binding (`_: T`) therefore still reads correctly, and one
    spelled without a type cannot occur in a valid declaration.
    """
    raw = " ".join(raw.split())
    stripped = strip_binding(raw)
    if stripped == raw:
        # No binding, and a parameter of a declaration must have one.
        return None
    return canon_rust_type(stripped, aliases)


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


SCALAR_PLANES = (
    "checked", "mismatches", "unclassified", "declaration_is_generated",
    "implementation_is_c", "implementation_is_c_mismatches", "not_found",
    "no_prototype_in_atlas", "type_checked", "type_mismatches", "type_unmapped",
    "unreadable_macros",
)


def compare_all(
    implemented: list[str],
    prototypes: dict[str, str],
    records: dict[str, dict],
    typedefs: dict[str, str],
    parsed: tuple,
) -> dict[str, list]:
    """Every implemented export, judged against the authority's prototype.

    Factored out of `main` so the **sensitivity control** can run the identical
    comparison over deliberately corrupted sources. A court that has only ever been
    seen to pass has not shown that it can fail, and this project treats a passing
    comparison with no sensitivity evidence as weak evidence rather than as a result.
    """
    (declarations, signatures, scopes, unique_aliases, rust_text, c_text,
     unreadable) = parsed
    out: dict[str, list] = {name: [] for name in SCALAR_PLANES}

    for sym in sorted(implemented):
        proto = prototypes.get(sym)
        if proto is None:
            out["no_prototype_in_atlas"].append(sym)
            continue
        want = parse_c_prototype(proto, typedefs)
        if want is None:
            out["unclassified"].append({
                "symbol": sym, "prototype": proto,
                "why": "the authority's prototype did not parse"})
            continue
        rec = records.get(sym)
        got = declarations.get(sym)
        if got is None:
            # Not a Rust declaration this court reads. Two cases, both now *checked*
            # rather than counted: a C definition in `src/**/*.c` (the variadic shims
            # stable Rust cannot express), and a symbol the crate declares from a
            # `macro_rules!` the expansion plane could not reach.
            c_sig = c_definition_signature(sym, c_text, typedefs)
            if c_sig is not None:
                out["implementation_is_c"].append(sym)
                c_want = c_signature_canon(rec, typedefs) if rec is not None else None
                if c_want is None:
                    out["type_unmapped"].append({
                        "symbol": sym, "prototype": proto,
                        "c_signature": canon_render(c_sig), "rust_signature": None,
                        "why": "the authority's own prototype did not canonicalise, "
                               "so the C definition has nothing to be compared with",
                    })
                elif (c_want[0], list(c_want[1])) != (c_sig[0], list(c_sig[1])):
                    out["implementation_is_c_mismatches"].append({
                        "symbol": sym, "prototype": proto,
                        "authority_signature": canon_render(c_want),
                        "definition_signature": canon_render(c_sig),
                    })
                continue
            if re.search(rf"\b{re.escape(sym)}\b", rust_text):
                out["declaration_is_generated"].append(sym)
            else:
                out["not_found"].append(sym)
            continue
        row = {
            "symbol": sym, "prototype": proto,
            "c_return": want[0], "c_arity": want[1],
            "rust_return": got[0], "rust_arity": got[1],
        }
        # The class plane is a coarse filter: return kind and arity. It has no notion of
        # a struct returned *by value*, because until Phase 6's `OSSL_PARAM_construct_*`
        # no export returned one -- `OSSL_PARAM` is a typedef of `struct ossl_param_st`,
        # and `classify_c` does not follow typedefs. Dropping such a symbol here used to
        # skip the type plane as well, which meant **fifteen exports whose return type is
        # a struct were checked by neither plane** (the D96 class a fourth time; see
        # docs/DECISIONS.md D103). The symbol is therefore only dropped when the type
        # plane cannot canonicalise it either.
        class_unknown = want[0] == "unclassified" or got[0] == "unclassified"
        if not class_unknown:
            out["checked"].append(row)
            if want != got:
                row["class_mismatch"] = want[0] != got[0]
                row["arity_mismatch"] = want[1] != got[1]
                out["mismatches"].append(row)

        # --- the type plane -------------------------------------------------
        # Class and arity say a call goes through; the type plane says each
        # argument is the right *kind* of thing. Both sides are canonicalised so
        # that a typedef spelling difference is not reported, while pointer
        # depth, pointee constness, integer width and function-pointer shape are.
        c_sig = c_signature_canon(rec, typedefs) if rec is not None else None
        r_sig = rust_signature_canon(signatures.get(sym),
                                     scopes.get(sym, unique_aliases))
        if c_sig is None or r_sig is None:
            if class_unknown:
                row["why"] = (
                    "neither plane could read it: the class plane does not follow a "
                    "typedef to a struct returned by value, and a parameter or return "
                    "type did not canonicalise"
                )
                out["unclassified"].append(row)
            else:
                out["type_unmapped"].append({
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
        out["type_checked"].append(type_row)
        if (c_sig[0], list(c_sig[1])) != (r_sig[0], list(r_sig[1])):
            type_row["return_mismatch"] = c_sig[0] != r_sig[0]
            type_row["param_mismatches"] = [
                i for i, (a, b) in enumerate(zip(c_sig[1], r_sig[1])) if a != b
            ]
            if len(c_sig[1]) != len(r_sig[1]):
                type_row["arity_mismatch"] = True
            out["type_mismatches"].append(type_row)

    out["unreadable_macros"] = list(unreadable)
    return out


def sensitivity_report() -> dict:
    """Demonstrate that this court can see the defect classes it claims to cover.

    The synthetic inputs below are parsed by the *same* functions the real pass uses,
    so a parser regression fails here first. Two of them are positive controls for the
    two planes that D98 added or repaired:

      * a `macro_rules!` body whose declared signature does not match the symbol's
        invocation -- the court must read the signature, and must produce a canonical
        form that differs from the authority's;
      * a C definition whose parameter differs in pointer depth -- the court must
        canonicalise both and see the difference.

    Each control asserts *both* halves: that the defective version is detected, and
    that the correct version is not. A control that only checks the first half would
    pass for a court that reports every symbol as a mismatch.
    """
    report: dict = {"what": (
        "the same comparison functions, run over deliberately defective inputs, must "
        "notice; and over the corrected inputs, must not"), "controls": []}
    aliases: dict[str, str] = {}

    macro_src = (
        "macro_rules! demo_fn {\n"
        "    ($name:ident) => {\n"
        "        #[no_mangle]\n"
        "        pub unsafe extern \"C\" fn $name(a: *mut c_void) -> c_int {\n"
        "            a as c_int\n"
        "        }\n"
        "    };\n"
        "}\n"
        "demo_fn!(demo_one);\n"
        "demo_fn!(demo_two);\n"
    )
    broken_src = macro_src.replace("fn $name(a: *mut c_void) -> c_int",
                                   "fn $name(a: *mut c_void) -> c_long")
    # A macro whose body puts a `$param` in a *type* position cannot be read, and the
    # court must say so rather than read half a signature. This is the control for the
    # refusal path, and it exists because the refusal is easy to get wrong in the
    # direction that matters: silently classifying the placeholder as `opaque` would
    # make every such symbol compare equal to something.
    type_placeholder_src = macro_src.replace("*mut c_void", "*mut $ty")

    def expand(text: str) -> dict[str, tuple[tuple[str, list[str]], str]]:
        defs: dict[str, MacroDef] = {}
        found, _bad = macro_defs(text, "<sensitivity>")
        for d in found:
            defs[d.name] = d
        out, _problems = expand_macro_invocations([("<sensitivity>", text)], defs)
        return out

    good = expand(macro_src)
    bad = expand(broken_src)
    refused = expand(type_placeholder_src)
    # The macro plane's control: the same invocations, read from the same parser.
    macro_ok = (
        set(good) == {"demo_one", "demo_two"}
        and good["demo_one"][0][0] == "c_int"
        and set(bad) == set(good)
        and bad["demo_one"][0][0] == "c_long"
        and set(refused) == {"demo_one", "demo_two"}
        and all(sig[0] == "unclassified" for sig, _key in refused.values())
        # The parameter *names* are in the macro body's text (`a: *mut c_void`), and
        # the same `canon_rust_param` the real pass uses must reduce both sides to
        # one parameter of the same shape.
        and rust_signature_canon(good["demo_one"][0], aliases)
        == ("int:4:s", ("ptr(opaque)",))
    )
    # ... and the canonical form must separate them, because that is the plane the
    # comparison actually uses.
    macro_ok = macro_ok and (
        canon_rust_type(good["demo_one"][0][0], aliases)
        != canon_rust_type(bad["demo_one"][0][0], aliases)
    )
    report["controls"].append({
        "control": "macro-plane",
        "what": "a `macro_rules!` return type perturbed from `c_int` to `c_long`, "
                "plus a body that fills a type position and must be refused rather "
                "than read",
        "detected": bool(macro_ok),
        "observed": {
            "correct": canon_rust_type(good["demo_one"][0][0], aliases),
            "perturbed": canon_rust_type(bad["demo_one"][0][0], aliases),
            "type_placeholder": refused["demo_one"][0][0],
        },
    })

    # The C plane's control.
    c_typedefs = dict(C_SYSTEM_TYPEDEFS)
    c_good = "void demo_c(const char *fmt, int n)\n{\n}\n"
    c_bad = "void demo_c(const char *fmt, long n)\n{\n}\n"
    sig_good = c_definition_signature("demo_c", c_good, c_typedefs)
    sig_bad = c_definition_signature("demo_c", c_bad, c_typedefs)
    c_ok = (
        sig_good is not None and sig_bad is not None
        and (sig_good[0], list(sig_good[1])) != (sig_bad[0], list(sig_bad[1]))
        and sig_good[1] == ["ptr(const(int:1:s))", "int:4:s"]
        and sig_bad[1] == ["ptr(const(int:1:s))", "int:8:s"]
    )
    report["controls"].append({
        "control": "c-definition-plane",
        "what": "a C definition's parameter perturbed from `int` to `long`",
        "detected": bool(c_ok),
        "observed": {
            "correct": None if sig_good is None else canon_render(sig_good),
            "perturbed": None if sig_bad is None else canon_render(sig_bad),
        },
    })

    # The trailing-comma reading, which D179 records: `cargo fmt` wraps a multi-line
    # generic argument and leaves the list's trailing comma inside it, and the court
    # read that comma as part of the inner function pointer's *return* type.
    comma_free = 'Option<unsafe extern "C" fn(*mut Bio, *const EvpPkey, c_int, *mut Asn1Pctx) -> c_int>'
    comma_wrapped = (
        'Option<\n        unsafe extern "C" fn(*mut Bio, *const EvpPkey, c_int, *mut Asn1Pctx) -> c_int,\n    >'
    )
    want_print = 'fptr(int:4:s; ptr(opaque), ptr(const(opaque)), int:4:s, ptr(opaque))'
    comma_ok = (
        canon_rust_type(comma_wrapped, aliases) == want_print
        and canon_rust_type(comma_free, aliases) == want_print
        and canon_rust_param("p: " + comma_wrapped, aliases) == want_print
        # ... and the same reading must still separate a *different* type, so this
        # control cannot pass for a court that ignores the comma by ignoring the type.
        and canon_rust_type(comma_wrapped.replace("*mut Asn1Pctx", "*const Asn1Pctx"), aliases)
        != want_print
    )
    report["controls"].append({
        "control": "generic-argument-trailing-comma",
        "what": "`cargo fmt`'s multi-line `Option<...,>` and its unwrapped spelling must "
                "canonicalise identically, while a pointee-constness change inside the "
                "same text must still differ",
        "detected": bool(comma_ok),
        "observed": {
            "comma_wrapped": canon_rust_type(comma_wrapped, aliases),
            "comma_free": canon_rust_type(comma_free, aliases),
            "perturbed": canon_rust_type(
                comma_wrapped.replace("*mut Asn1Pctx", "*const Asn1Pctx"), aliases),
        },
    })

    # The named fn-pointer argument, which D180 records: an argument of a function
    # *pointer* type may carry a binding name, and the reader used to canonicalise the
    # whole `name: T` text and fail.
    unnamed = 'unsafe extern "C" fn(*mut c_void) -> c_int'
    named = 'unsafe extern "C" fn(provctx: *mut c_void) -> c_int'
    named_ok = (canon_rust_type(named, aliases) == canon_rust_type(unnamed, aliases)
                and canon_rust_type(named, aliases) == "fptr(int:4:s; ptr(opaque))"
                # ... and the same reading must still separate a different type.
                and canon_rust_type('unsafe extern "C" fn(p: *const c_void) -> c_int',
                                    aliases) != canon_rust_type(unnamed, aliases))
    report["controls"].append({
        "control": "named-fn-pointer-argument",
        "what": "a function-pointer argument that carries a binding name must "
                "canonicalise identically to the unnamed form, while a pointee-constness "
                "change must still differ",
        "detected": bool(named_ok),
        "observed": {
            "named": canon_rust_type(named, aliases),
            "unnamed": canon_rust_type(unnamed, aliases),
            "perturbed": canon_rust_type('unsafe extern "C" fn(p: *const c_void) -> c_int',
                                         aliases),
        },
    })

    # The function-pointer declarator's *depth*, which D183 records: `int (*)(...)`,
    # `int (**)(...)` and `int (***)(...)` are one, two and three levels, and they are
    # all one pointer in the call convention, which is why collapsing them is easy to
    # miss.
    one = 'int (*)(EVP_PKEY_CTX *)'
    two = 'int (**)(EVP_PKEY_CTX *)'
    depth_ok = (
        canon_c_type(one, c_typedefs := dict(C_SYSTEM_TYPEDEFS))
        != canon_c_type(two, c_typedefs)
        and canon_c_type(one, c_typedefs) == "fptr(int:4:s; ptr(opaque))"
        and canon_c_type(two, c_typedefs) == "ptr(fptr(int:4:s; ptr(opaque)))"
        and canon_c_type('int (***)(void)', c_typedefs)
        == "ptr(ptr(fptr(int:4:s; )))"
        # ... and the Rust side must read the same two levels, or the plane would have
        # one side right and the other flattened.
        and canon_rust_type('*mut Option<unsafe extern "C" fn(*mut c_void) -> c_int>',
                            aliases) == "ptr(fptr(int:4:s; ptr(opaque)))"
    )
    report["controls"].append({
        "control": "function-pointer-declarator-depth",
        "what": "`int (*)(...)` and `int (**)(...)` must canonicalise to one and two "
                "pointer levels, and the Rust `*mut Option<fn ...>` spelling must read "
                "the same two",
        "detected": bool(depth_ok),
        "observed": {
            "one_star": canon_c_type(one, c_typedefs),
            "two_stars": canon_c_type(two, c_typedefs),
            "three_stars": canon_c_type('int (***)(void)', c_typedefs),
            "rust_pointer_to_fn_pointer": canon_rust_type(
                '*mut Option<unsafe extern "C" fn(*mut c_void) -> c_int>', aliases),
        },
    })

    # The variadic reading, which the C plane depends on and which the atlas's
    # parameter list omits.
    var_rec = {"type": "int (char *, ...)", "params": [{"type": "char *"}],
               "variadic": True}
    var_sig = c_signature_canon(var_rec, c_typedefs)
    var_ok = var_sig is not None and var_sig[1] == ("ptr(int:1:s)", "...")
    report["controls"].append({
        "control": "variadic-reading",
        "what": "`...` must be part of the authority's own canonical signature",
        "detected": bool(var_ok),
        "observed": None if var_sig is None else canon_render(var_sig),
    })

    report["all_detected"] = all(c["detected"] for c in report["controls"])
    return report


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

    result = compare_all(surface["implemented_symbols"], prototypes, records,
                         typedefs, read_sources())
    checked = result["checked"]
    mismatches = result["mismatches"]
    unclassified = result["unclassified"]
    generated = result["declaration_is_generated"]
    in_c = result["implementation_is_c"]
    in_c_mismatches = result["implementation_is_c_mismatches"]
    not_found = result["not_found"]
    no_prototype = result["no_prototype_in_atlas"]
    type_checked = result["type_checked"]
    type_mismatches = result["type_mismatches"]
    type_unmapped = result["type_unmapped"]
    unreadable = result["unreadable_macros"]

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
            "implementation_is_c_mismatches": len(in_c_mismatches),
            "not_found": len(not_found),
            "no_prototype_in_atlas": len(no_prototype),
            "type_checked": len(type_checked),
            "type_mismatches": len(type_mismatches),
            "type_unmapped": len(type_unmapped),
            "unreadable_macros": len(unreadable),
        },
        "sensitivity": sensitivity_report(),
        "mismatches": mismatches,
        "unclassified": unclassified,
        "declaration_is_generated": generated,
        "implementation_is_c": in_c,
        "implementation_is_c_mismatches": in_c_mismatches,
        "not_found": not_found,
        "no_prototype_in_atlas": no_prototype,
        "type_mismatches": type_mismatches,
        "type_unmapped": type_unmapped,
        "unreadable_macros": unreadable,
        "note": (
            "A symbol this court cannot classify is reported under its own heading and "
            "never counted as a pass, so `mismatches == 0` must be read together with "
            "`checked`, and `type_mismatches == 0` together with `type_checked`. The "
            "type plane's canonical form is what the court can defend; it does not "
            "claim two declarations are textually identical. Since D98 the "
            "`macro_rules!` surface and the C implementations are read rather than "
            "merely counted, and both are failures when they disagree: "
            "`declaration_is_generated` is now a defect rather than a gap. "
            "`no_prototype_in_atlas` is not a defect and cannot be closed here -- "
            "those exports are declared in headers the authority does not install "
            "(`crypto/o_dir.h`, `crypto/asn1/asn1_local.h`), so the Phase 1 atlas, "
            "whose universe is the installed public surface, has no prototype for "
            "them. Their ABI is still proved by the Phase 2 loader court, which "
            "resolves every one of them at its declared ELF version; what is missing "
            "is a *source* prototype to compare against."
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
          f"c-mismatches={c['implementation_is_c_mismatches']} "
          f"not-found={c['not_found']} no-prototype={c['no_prototype_in_atlas']} "
          f"unreadable={c['unreadable_macros']}")
    print(f"  type plane: checked={c['type_checked']} "
          f"mismatches={c['type_mismatches']} unmapped={c['type_unmapped']}")
    print(f"  C implementations: checked={c['implementation_is_c']} "
          f"mismatches={c['implementation_is_c_mismatches']}")
    sens = body["sensitivity"]
    print(f"  sensitivity: {len(sens['controls'])} control(s), "
          f"all_detected={sens['all_detected']}")
    for control in sens["controls"]:
        print(f"    {control['control']}: "
              f"{'detected' if control['detected'] else 'NOT DETECTED'} "
              f"({control['what']})")
    for row in mismatches:
        print(f"  MISMATCH {row['symbol']}: authority returns {row['c_return']} with "
              f"{row['c_arity']} parameter(s); the crate returns {row['rust_return']} "
              f"with {row['rust_arity']}")
    for row in in_c_mismatches:
        print(f"  C-MISMATCH {row['symbol']}: authority "
              f"{row['authority_signature']} != definition "
              f"{row['definition_signature']}")
    for row in type_mismatches:
        print(f"  TYPE-MISMATCH {row['symbol']}: authority {row['c_signature']} != "
              f"crate {row['rust_signature']}")
    for row in type_unmapped:
        print(f"  TYPE-UNMAPPED {row['symbol']}: {row['prototype']}")
    for row in unclassified:
        print(f"  unclassified {row['symbol']}: {row.get('why', '')} "
              f"({row.get('prototype', '')})")
    for problem in unreadable:
        print(f"  UNREADABLE {problem}")
    if generated:
        print(f"  UNREAD {len(generated)} symbol(s) appear in src/ but no declaration "
              "or definition could be read: "
              + ", ".join(generated[:10])
              + (f" (+{len(generated) - 10} more)" if len(generated) > 10 else ""))
    if not_found:
        print(f"  not found anywhere in src/: {', '.join(not_found[:10])}"
              + (f" (+{len(not_found) - 10} more)" if len(not_found) > 10 else ""))
    print(f"  -> {rel(OUT)}")

    return 1 if (mismatches or type_mismatches or type_unmapped or not_found
                 or in_c_mismatches or generated or unreadable
                 or not body["sensitivity"]["all_detected"]) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
