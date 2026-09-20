#!/usr/bin/env python3
"""openssl-rs — derive `crypto/ec/ec_curve.c`'s built-in curve parameters from the authority.

Why this exists
---------------
`crypto/ec/ec_curve.c` is 3,178 lines and almost all of it is `static const unsigned char`
arrays: eighty-two named curves, each a seed followed by `p || a || b || gx || gy || order`
zero-padded to one width per curve. Transcribing that by hand is the one thing this project
refuses to do with a constant another party defines, for the reason D329 and D332 record for
`crypto/bn/bn_dh.c`: **a typo in a 521-bit prime is invisible to every test that does not
compare against the authority itself**, and `EC_GROUP_new_by_curve_name` feeds such a prime
straight into a key agreement, where a wrong value silently changes every result. The
whole-table version of that argument is stronger than the single-constant one, because here
the *pairing* is also data: a curve whose `b` came from the row below it would round-trip
through every property test anyone would think to write.

So the **values** are *asked of the authority*: a C probe compiled against the admitted
prefix calls `EC_get_builtin_curves` to enumerate the table, builds each group with
`EC_GROUP_new_by_curve_name`, and prints `BN_bn2hex` of the six parameters, the cofactor, the
seed, the field degree and the group's own method identity. `src/ec/curve_data.rs` is the
emitted result.

The **inventory and the widths** come from the authority's own source instead — each
`EC_CURVE_DATA` initialiser's `{ field_type, seed_len, param_len, cofactor }` header, the
`data[N]` array each struct declares, and `curve_list[]`'s rows with their `#if`/`#elif`
method column resolved for this profile's macros. The two derivations are independent and the
generator **fails unless they agree**, per curve and per member: the read-back `p` must be
exactly `param_len` bytes, the read-back cofactor and field type must be the header's, the
seed must be the array's first `seed_len` bytes, and each of the six parameters must be the
array's own slice at its own offset. `forensics/atlas/ec-curves.json` records both sides, so
a reader can recheck the claim rather than believe it.

The method column is the one column this crate cannot yet carry
--------------------------------------------------------------
`curve_list[]` has four columns and the fourth is a `const EC_METHOD *(*)(void)`. On this
profile `ec_nistp_64_gcc_128` is disabled and `ECP_NISTZ256_ASM` is defined, so **exactly one
row** is non-NULL: `NID_X9_62_prime256v1` names `EC_GFp_nistz256_method`. That symbol is
**not** a DSO export (`nm -D` on the admitted prefix has no `EC_GFp_nistz256_method`, while
the four `EC_GFp_*_method`/`EC_GF2m_simple_method` are) — it is `ec_local.h`'s internal — and
its `EC_METHOD` table (`ecp_nistz256.c:1569-1630`) names `ossl_ec_key_simple_*`
(`ec_key.c`), `ossl_ecdh_simple_compute_key` (`ecdh_ossl.c`) and `ossl_ecdsa_simple_*`
(`ecdsa_ossl.c`), units this subphase does not own. So the column is **recorded here and not
transcribed into the crate**, and `src/ec/curve.rs` says so at the field it would occupy: a
row whose method wrote `NULL` where the authority's writes a function would be a fabricated
value, and this generator's whole job is to make that visible. The probe observes the
*consequence* — the method identity `EC_GROUP_method_of` answers for each group, printed as
which of the four exported constructors it equals and `other` for the nistz256 curve — so the
claim that the column has exactly one non-NULL row is a measurement, not a reading.

What is checked rather than assumed
-----------------------------------
* Every curve `curve_list[]` names is read back, and no other: the read-back NID set and the
  table's own must be equal in both directions, in the same order.
* Each curve's read-back agrees with its `data[]` array byte for byte, member for member.
* Each curve's `param_len` is the width of its own `p`, `seed_len` is the length of its own
  seed, and `field_type` and `cofactor` are the header's own numbers.
* The resolved method column is the profile's, and the probe's method observation confirms
  it — one non-NULL row, and it is `NID_X9_62_prime256v1`.
* `crypto/evp/ec_support.c`'s two tables — the name list `OSSL_EC_curve_nid2name` walks and
  the fifteen `nist_curves[]` rows — are read out of the source and checked against the
  crate's own transcription of them, in **both** tiers, so a hand edit to `src/ec/support.rs`
  fails on a runner with no authority.
* The NID set and the comment strings are the authority's, so `EC_get_builtin_curves`'s
  answer, which is `(nid, comment)` in `curve_list`'s own order, is checked rather than
  asserted.

Usage (inside the court, which is where the authority prefix lives):

    python3 forensics/tools/gen_ec_curves.py

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
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
    run,
    write_json,
    write_text,
)

OUT_RS = REPO_ROOT / "src" / "ec" / "curve_data.rs"
OUT_JSON = REPO_ROOT / "forensics" / "atlas" / "ec-curves.json"
SUPPORT_RS = REPO_ROOT / "src" / "ec" / "support.rs"
GENERATOR = "forensics/tools/gen_ec_curves.py"

EC_CURVE = "crypto/ec/ec_curve.c"
EC_SUPPORT = "crypto/evp/ec_support.c"
OBJ_MAC = "include/openssl/obj_mac.h"
FIPS_CURVE_LIST = "static const ec_list_element curve_list[] = {"

# The macros this profile sets, which are what decide every `#if` in `curve_list[]`'s
# fourth column. They are read out of the admitted build rather than typed here:
# `configdata.pm`'s `%disabled` holds `ec_nistp_64_gcc_128`, and the build's own compile
# line holds `-DECP_NISTZ256_ASM`. `profile_macros` re-reads both and fails if either
# moved, so a profile change is a failure rather than a stale resolution.
PROFILE_MACROS = {
    "ECP_NISTZ256_ASM": True,
    "S390X_EC_ASM": False,
    "ECP_SM2P256_ASM": False,
    "OPENSSL_NO_EC_NISTP_64_GCC_128": True,
}

# `rustfmt`'s default `max_width`. The renderer is `rustfmt`-stable because the file is a
# `COMPARED` entry in `evidence_determinism.py` and `pipeline.sh` runs `cargo fmt` between
# the generation and the comparison (D332's argument, and the reason `src/bn/dh_data.rs`
# can be compared at all).
MAX_WIDTH = 100
BYTES_PER_LINE = (MAX_WIDTH - 4 + 1) // 6

# `NID_X9_62_prime_field` and `NID_X9_62_characteristic_two_field` as the library reports
# them through `EC_GROUP_get_field_type`. The values are `src/runtime/obj_table.rs`'s own
# and are re-derived by the crate's unit test, not trusted from here.
FIELD_TYPE = {
    "NID_X9_62_prime_field": 406,
    "NID_X9_62_characteristic_two_field": 407,
}

_HEADER = re.compile(
    r"^\s*(\w+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(0[xX][0-9A-Fa-f]+|\d+)\s*$"
)
_STRUCT = re.compile(
    r"static const struct \{\s*"
    r"EC_CURVE_DATA h;\s*"
    r"unsigned char data\[([^\]]+)\];\s*"
    r"\}\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{\s*"
    r"\{([^}]*)\}\s*,\s*"
    r"\{(.*?)\}\s*\};",
    re.S,
)
# `curve_list[]`'s rows. The method column is matched up to the comment string, because
# the comment is the only part of a row that always ends the row and never contains a
# `}`; the method expression may span `#if`/`#elif`/`#else` lines and several of them do.
_LIST = re.compile(
    r"\{\s*(NID_[A-Za-z0-9_]+),\s*&([A-Za-z_][A-Za-z0-9_]*)\.h,\s*"
    r"(.*?)\s*((?:\"(?:[^\"\\]|\\.)*\"\s*)+)\s*\},",
    re.S,
)
_BYTE = re.compile(r"0x([0-9A-Fa-f]{2})")
_NAME2NID = re.compile(r"\{\s*(\"(?:[^\"\\]|\\.)*\")\s*,\s*(NID_[A-Za-z0-9_]+)\s*\}")
# `src/ec/support.rs`'s two tables are `[(&CStr, c_int); N]` arrays of `c"name", obj::NID_x`
# tuples; the order of the tuples in the file is the order this reads them in.
_SUPPORT_ROW = re.compile(r'\(\s*c"([^"]*)"\s*,\s*obj::(NID_[A-Za-z0-9_]+)\s*\)')


def strip_comments(text: str) -> str:
    """Block and line comments removed, string literals kept."""
    out = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            i = n if j < 0 else j
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
            out.append(text[i:j + 1])
            i = j + 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def line_of(text: str, offset: int) -> int:
    return text[:offset].count("\n") + 1


def eval_cond(expr: str, macros: dict[str, bool]) -> bool:
    """`#if` conditions in `curve_list[]`, evaluated against this profile's macros.

    Four shapes appear — `defined(X)`, `!defined(X)`, an integer, and `||`/`&&` over those
    — and a fifth is a failure rather than a false, because a silently-false condition
    would resolve a method column to NULL.
    """
    text = expr.strip()
    if "||" in text:
        return any(eval_cond(p, macros) for p in text.split("||"))
    if "&&" in text:
        return all(eval_cond(p, macros) for p in text.split("&&"))
    if text.startswith("!"):
        return not eval_cond(text[1:], macros)
    m = re.fullmatch(r"defined\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)", text)
    if m:
        return macros.get(m.group(1), False)
    if re.fullmatch(r"\d+", text):
        return int(text) != 0
    raise SystemExit(
        f"{GENERATOR}: cannot evaluate `#if {expr.strip()}` against this profile"
    )


def preprocess(text: str, macros: dict[str, bool]) -> tuple[list[bool], list[str]]:
    """The `#if`/`#elif`/`#else` walk `ec_curve.c` is written with.

    Returns, per line, whether the preprocessor keeps it, and the kept lines that are
    neither directives nor comments. One walk serves both uses: `curve_list[]`'s method
    column is a conditional *inside* a row, and one of its rows -- `secp224r1` -- is a pair
    of whole rows inside a `#ifndef`/`#else`, so the column's own text and the row's
    enclosing context both need the same state machine.
    """
    # Each frame is `[enclosing active, a clause of this chain is already taken, this
    # clause is active]`; a frame's third field already folds its enclosing condition in.
    stack: list[list[bool]] = []
    flags: list[bool] = []
    kept: list[str] = []
    for raw in text.splitlines():
        ln = raw.strip()
        parent = all(f[2] for f in stack)
        if ln.startswith("#ifdef"):
            v = macros.get(ln[6:].strip(), False)
            stack.append([parent, v, parent and v])
        elif ln.startswith("#ifndef"):
            v = not macros.get(ln[7:].strip(), False)
            stack.append([parent, v, parent and v])
        elif ln.startswith("#if"):
            v = eval_cond(ln[3:].strip(), macros)
            stack.append([parent, v, parent and v])
        elif ln.startswith("#elif"):
            if not stack:
                raise SystemExit(f"{GENERATOR}: `#elif` outside an `#if` in {EC_CURVE}")
            f = stack[-1]
            v = eval_cond(ln[5:].strip(), macros)
            take = f[0] and not f[1] and v
            f[1] = f[1] or v
            f[2] = take
        elif ln.startswith("#else"):
            if not stack:
                raise SystemExit(f"{GENERATOR}: `#else` outside an `#if` in {EC_CURVE}")
            f = stack[-1]
            take = f[0] and not f[1]
            f[1] = True
            f[2] = take
        elif ln.startswith("#endif"):
            if not stack:
                raise SystemExit(f"{GENERATOR}: `#endif` outside an `#if` in {EC_CURVE}")
            stack.pop()
        parent = all(f[2] for f in stack)
        flags.append(parent)
        if parent and ln and not ln.startswith(("/*", "*", "//", "#")):
            kept.append(ln.rstrip(",").strip())
    if stack:
        raise SystemExit(f"{GENERATOR}: an `#if` in {EC_CURVE} is never closed")
    return flags, kept


def resolve_method(text: str, macros: dict[str, bool]) -> str:
    """The fourth column of one `curve_list[]` row, as this profile compiles it.

    Returns the C expression verbatim (`0` when the column is NULL), so the atlas records
    the authority's own spelling and the checks below compare it with the probe's answer.
    """
    _, kept = preprocess(text, macros)
    if len(kept) != 1:
        raise SystemExit(
            f"{GENERATOR}: a `curve_list[]` row's method column resolved to {kept!r} for "
            f"this profile; exactly one clause must be active"
        )
    return kept[0]


def parse_ec_curve(text: str, macros: dict[str, bool]) -> tuple[list[dict], list[dict], int]:
    """The authority's own curve inventory and its compiled `curve_list[]`."""
    clean = strip_comments(text)
    structs: dict[str, dict] = {}
    curves: list[dict] = []
    for m in _STRUCT.finditer(clean):
        expr, name, header, body = m.groups()
        hm = _HEADER.fullmatch(header.strip())
        if hm is None:
            raise SystemExit(f"{GENERATOR}: {name}'s header is not an EC_CURVE_DATA")
        field_type, seed_len, param_len, cofactor_src = (
            hm.group(1), int(hm.group(2)), int(hm.group(3)), hm.group(4),
        )
        # The cofactor column is an `unsigned int` and three of its values are the
        # characteristic-two curves' own `0xFF6E`, `0x7FFFFFFE` and `0x1000000000000000`-
        # style literals rather than small decimals, so the source spelling is kept beside
        # the number it means.
        cofactor = int(cofactor_src, 0)
        declared = eval_size(expr)
        raw = bytes(int(b, 16) for b in _BYTE.findall(body))
        if len(raw) != declared:
            raise SystemExit(
                f"{GENERATOR}: {name} declares {declared} bytes and its initialiser has "
                f"{len(raw)}"
            )
        # The array is a seed followed by `nfields` `param_len`-wide fields. **Six is the
        # floor and not the rule**: `_EC_X9_62_PRIME_256V1` declares `20 + 32 * 8`, because
        # the nistz256 method's `ecp_nistz256group_full_init` reads a seventh and an eighth
        # field (`params + 6 * param_len` and `+ 7 * param_len`) that no public accessor
        # exposes -- the two Montgomery `RR` constants its `ossl_bn_mont_ctx_set` calls
        # take. They are still part of the array, so they are part of the table; see
        # `montgomery_fields` below for how they are obtained.
        if (declared - seed_len) % param_len != 0:
            raise SystemExit(
                f"{GENERATOR}: {name} declares data[{expr}] = {declared} and its header "
                f"says {seed_len} + n*{param_len} for no integer n"
            )
        nfields = (declared - seed_len) // param_len
        if nfields < 6:
            raise SystemExit(
                f"{GENERATOR}: {name} declares {nfields} field(s) after its seed; six are "
                f"`p || a || b || gx || gy || order`"
            )
        row = {
            "name": name,
            "source": f"{EC_CURVE}:{line_of(clean, m.start())}",
            "field_type": field_type,
            "field_type_number": FIELD_TYPE[field_type],
            "seed_len": seed_len,
            "param_len": param_len,
            "fields": nfields,
            "montgomery_fields": [
                raw[seed_len + i * param_len:seed_len + (i + 1) * param_len].hex().upper()
                for i in range(6, nfields)
            ],
            "cofactor": cofactor,
            "cofactor_source": cofactor_src,
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
        structs[name] = row
        curves.append(row)

    # **The non-FIPS `curve_list[]` is the one this profile compiles.** The file defines it
    # twice, once inside `#ifdef FIPS_MODULE` (fifteen rows) and once in the `#else` arm
    # (the eighty-two), and a finditer over the whole file would read both.
    starts = [m.start() for m in re.finditer(re.escape(FIPS_CURVE_LIST), clean)]
    if len(starts) != 2:
        raise SystemExit(
            f"{GENERATOR}: {EC_CURVE} has {len(starts)} `curve_list[]` definitions; this "
            f"tool models a `#ifdef FIPS_MODULE` pair"
        )
    fips_text = clean[starts[0]:clean.index("\n};", starts[0])]
    live_text = clean[starts[1]:clean.index("\n};", starts[1])]
    fips_rows = [m.group(1) for m in _LIST.finditer(fips_text)]
    if len(fips_rows) != 15:
        raise SystemExit(
            f"{GENERATOR}: the FIPS `curve_list[]` has {len(fips_rows)} rows, not 15"
        )

    rows: list[dict] = []
    flags, _ = preprocess(clean, macros)
    for m in _LIST.finditer(live_text):
        nid, name, method_text, comment = m.groups()
        line = line_of(clean, m.start() + starts[1])
        if not flags[line - 1]:
            # A whole row inside a conditional this profile does not take -- which is how
            # `secp224r1` is written twice, once under `OPENSSL_NO_EC_NISTP_64_GCC_128`'s
            # negation and once under its `#else`.
            continue
        if name not in structs:
            raise SystemExit(
                f"{GENERATOR}: `curve_list[]` names `&{name}.h`, which is not one of the "
                f"{len(structs)} EC_CURVE_DATA structs in this file"
            )
        rows.append({
            "nid": nid,
            "curve": name,
            "comment": decode_c_strings(comment),
            "method_source": method_text.strip(),
            "method": resolve_method(method_text, macros),
            "source": f"{EC_CURVE}:{line_of(clean, m.start() + starts[1])}",
        })
    if len(rows) != 82 or len(structs) != 75:
        raise SystemExit(
            f"{GENERATOR}: {EC_CURVE} yielded {len(rows)} rows over {len(structs)} "
            f"structs; the parser or the file is stale"
        )
    return curves, rows, len(fips_rows)


def eval_size(expr: str) -> int:
    """`20 + 24 * 6` as the compiler reads it."""
    if not re.fullmatch(r"[0-9+\-*/ ()]+", expr):
        raise SystemExit(f"{GENERATOR}: cannot evaluate `data[{expr}]`")
    return int(eval(expr, {"__builtins__": {}}, {}))  # noqa: S307 - the regex above


_LITERAL = re.compile(r'"(?:[^"\\]|\\.)*"')


def decode_c_strings(text: str) -> str:
    """Adjacent C string literals concatenated, which is how the three IPSec rows are
    written: `"...field.\n" "\tNot suitable for ECDSA.\n" "\tQuestionable extension
    field!"` is one comment in C and must be one row here."""
    return "".join(decode_c_string(lit) for lit in _LITERAL.findall(text))


def decode_c_string(literal: str) -> str:
    """A C string literal's value, for the comment column only."""
    body = literal[1:-1]
    out = []
    i = 0
    while i < len(body):
        if body[i] == "\\" and i + 1 < len(body):
            esc = body[i + 1]
            out.append({"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"'}.get(esc, esc))
            i += 2
            continue
        out.append(body[i])
        i += 1
    return "".join(out)


def parse_ec_support(text: str) -> dict:
    """`ec_support.c`'s two tables, which `src/ec/support.rs` transcribes by hand."""
    clean = strip_comments(text)
    name_start = clean.index("static const EC_NAME2NID curve_list[] = {")
    name_end = clean.index("};", name_start)
    names = [(decode_c_string(s), n) for s, n in
             _NAME2NID.findall(clean[name_start:name_end])]
    nist_start = clean.index("static const EC_NAME2NID nist_curves[] = {")
    nist_end = clean.index("};", nist_start)
    nist = [(decode_c_string(s), n) for s, n in
            _NAME2NID.findall(clean[nist_start:nist_end])]
    if len(names) != 82 or len(nist) != 15:
        raise SystemExit(
            f"{GENERATOR}: {EC_SUPPORT}'s tables are {len(names)} names and {len(nist)} "
            f"NIST rows; the parser or the reader is stale"
        )
    return {"names": names, "nist": nist}


def parse_short_names(text: str) -> dict[str, str]:
    """`obj_mac.h`'s `SN_<name>` strings, keyed by the name.

    `curve_list[]`'s NID column is a macro and the library's `OBJ_nid2sn` is the *object
    table*'s answer for the same number, so the two are independent derivations of one
    fact and the check below requires them to agree. The mapping is `NID_x` -> `SN_x`,
    which is the object table's own spelling rule and not always the obvious one:
    `NID_X9_62_prime192v1` is `prime192v1`, `NID_ipsec3` is `Oakley-EC2N-3`, and
    `NID_sm2` is `SM2`.
    """
    out: dict[str, str] = {}
    for m in re.finditer(r'^#\s*define\s+SN_([A-Za-z0-9_]+)\s+"((?:[^"\\]|\\.)*)"',
                         text, re.M):
        out[m.group(1)] = decode_c_string('"' + m.group(2) + '"')
    if not out:
        raise SystemExit(f"{GENERATOR}: {OBJ_MAC} yielded no `SN_` names")
    return out


def profile_macros(auth) -> dict[str, bool]:
    """This profile's macros, read from the admitted build rather than typed here."""
    build = REPO_ROOT / "forensics" / "authorities" / "build" / auth.id
    configdata = build / "configdata.pm"
    makefile = build / "Makefile"
    if not configdata.is_file() or not makefile.is_file():
        raise SystemExit(
            f"{GENERATOR}: {rel(configdata)} and {rel(makefile)} are both needed to read "
            f"this profile's macros; the admitted build is incomplete"
        )
    macros = dict(PROFILE_MACROS)
    macros["OPENSSL_NO_EC_NISTP_64_GCC_128"] = (
        '"ec_nistp_64_gcc_128" =>' in configdata.read_text(encoding="utf-8", errors="replace")
    )
    lines = makefile.read_text(encoding="utf-8", errors="replace").splitlines()
    rule = next((i for i, ln in enumerate(lines)
                 if ln.startswith("crypto/ec/libcrypto-shlib-ec_curve.o:")), None)
    if rule is None or rule + 1 >= len(lines):
        raise SystemExit(f"{GENERATOR}: the built Makefile has no rule for `ec_curve.o`")
    flags = set(re.findall(r"-D([A-Za-z0-9_]+)", lines[rule + 1]))
    for macro in ("ECP_NISTZ256_ASM", "S390X_EC_ASM", "ECP_SM2P256_ASM"):
        macros[macro] = macro in flags
    if macros["ECP_NISTZ256_ASM"] is not True or macros["S390X_EC_ASM"] is not False:
        raise SystemExit(
            f"{GENERATOR}: the admitted build's `ec_curve.o` flags are {sorted(flags)}; "
            f"this generator's method resolution is written for x86-64 with "
            f"`ECP_NISTZ256_ASM` set and `S390X_EC_ASM` clear"
        )
    return macros


def probe_source() -> str:
    """The C probe: one `key=value` line per observation, and never a bare pointer.

    The NID list is *not* typed here: the probe asks `EC_get_builtin_curves` for the table
    the authority actually publishes, which is both the enumeration and the first check.
    The order is then compared against `curve_list[]`'s own, so the values cannot be paired
    with the wrong rows.
    """
    return "\n".join([
        "/* Generated by forensics/tools/gen_ec_curves.py -- do not edit. */",
        "#define OPENSSL_SUPPRESS_DEPRECATED",
        "#include <openssl/ec.h>",
        "#include <openssl/bn.h>",
        "#include <openssl/objects.h>",
        "#include <stdio.h>",
        "#include <stdlib.h>",
        "#include <string.h>",
        "",
        "static void emit(const char *tag, const char *member, const BIGNUM *b)",
        "{",
        "    char *hex;",
        "    if (b == NULL) { printf(\"%s.%s=NONE\\n\", tag, member); return; }",
        "    hex = BN_bn2hex(b);",
        "    if (hex == NULL) { printf(\"%s.%s=ALLOCFAIL\\n\", tag, member); return; }",
        "    printf(\"%s.%s=%s\\n\", tag, member, hex);",
        "    OPENSSL_free(hex);",
        "}",
        "",
        "/* The comment column, with the two whitespace bytes the three IPSec rows carry",
        " * written as `|` and `/`, so the transcript is one line per observation. */",
        "static void emit_text(const char *tag, const char *member, const char *s)",
        "{",
        "    const char *p;",
        "    printf(\"%s.%s=\", tag, member);",
        "    if (s == NULL) { printf(\"NULL\\n\"); return; }",
        "    for (p = s; *p != '\\0'; p++)",
        "        putchar(*p == '\\n' ? '|' : (*p == '\\t' ? '/' : *p));",
        "    putchar('\\n');",
        "}",
        "",
        "/* Which of the profile's four *exported* method constructors a group's method is.",
        " * `EC_GFp_nistz256_method` is not a DSO export, so the one curve that uses it",
        " * answers `other` -- which is how the atlas's claim that exactly one row of",
        " * `curve_list[]` has a non-NULL method column becomes a measurement. */",
        "static const char *method_name(const EC_GROUP *g)",
        "{",
        "    const EC_METHOD *m = EC_GROUP_method_of(g);",
        "    if (m == EC_GFp_mont_method()) return \"EC_GFp_mont_method\";",
        "    if (m == EC_GFp_nist_method()) return \"EC_GFp_nist_method\";",
        "    if (m == EC_GFp_simple_method()) return \"EC_GFp_simple_method\";",
        "    if (m == EC_GF2m_simple_method()) return \"EC_GF2m_simple_method\";",
        "    return \"other\";",
        "}",
        "",
        "int main(void)",
        "{",
        "    size_t n, i;",
        "    EC_builtin_curve one[1];",
        "    EC_builtin_curve *table;",
        "    EC_GROUP *g;",
        "    const EC_POINT *G;",
        "    BN_CTX *ctx;",
        "    BIGNUM *pa = BN_new(), *pb = BN_new();",
        "    BIGNUM *x = BN_new(), *y = BN_new();",
        "    char tag[64];",
        "",
        "    n = EC_get_builtin_curves(NULL, 0);",
        "    printf(\"count=%zu\\n\", n);",
        "    printf(\"count_nitems0=%zu\\n\", EC_get_builtin_curves(one, 0));",
        "    printf(\"count_short=%zu\\n\", EC_get_builtin_curves(one, 1));",
        "    printf(\"short.nid=%d\\n\", one[0].nid);",
        "    emit_text(\"short\", \"comment\", one[0].comment);",
        "    table = malloc(n * sizeof(*table));",
        "    printf(\"count_filled=%zu\\n\", EC_get_builtin_curves(table, n));",
        "    ctx = BN_CTX_new();",
        "",
        "    for (i = 0; i < n; i++) {",
        "        const char *sn = OBJ_nid2sn(table[i].nid);",
        "        const BIGNUM *cof;",
        "        const unsigned char *seed;",
        "        size_t seed_len, k;",
        "",
        "        snprintf(tag, sizeof(tag), \"row%.3zu\", i);",
        "        printf(\"%s.nid=%d\\n\", tag, table[i].nid);",
        "        printf(\"%s.sn=%s\\n\", tag, sn != NULL ? sn : \"NULL\");",
        "        emit_text(tag, \"comment\", table[i].comment);",
        "        g = EC_GROUP_new_by_curve_name(table[i].nid);",
        "        if (g == NULL) { printf(\"%s.group=NULL\\n\", tag); continue; }",
        "        printf(\"%s.field_type=%d\\n\", tag, EC_GROUP_get_field_type(g));",
        "        printf(\"%s.degree=%d\\n\", tag, EC_GROUP_get_degree(g));",
        "        printf(\"%s.method=%s\\n\", tag, method_name(g));",
        "        EC_GROUP_get_curve(g, pa, pb, x, ctx);",
        "        emit(tag, \"p\", pa);",
        "        emit(tag, \"a\", pb);",
        "        emit(tag, \"b\", x);",
        "        G = EC_GROUP_get0_generator(g);",
        "        if (G != NULL && EC_POINT_get_affine_coordinates(g, G, x, y, ctx)) {",
        "            emit(tag, \"x\", x);",
        "            emit(tag, \"y\", y);",
        "        }",
        "        EC_GROUP_get_order(g, pa, ctx);",
        "        emit(tag, \"order\", pa);",
        "        cof = EC_GROUP_get0_cofactor(g);",
        "        emit(tag, \"cofactor\", cof);",
        "        seed = EC_GROUP_get0_seed(g);",
        "        seed_len = EC_GROUP_get_seed_len(g);",
        "        printf(\"%s.seed_len=%zu\\n\", tag, seed_len);",
        "        if (seed == NULL) {",
        "            printf(\"%s.seed=NULL\\n\", tag);",
        "        } else {",
        "            printf(\"%s.seed=\", tag);",
        "            for (k = 0; k < seed_len; k++) printf(\"%02X\", seed[k]);",
        "            printf(\"\\n\");",
        "        }",
        "        printf(\"%s.on_curve=%d\\n\", tag, EC_POINT_is_on_curve(g, G, ctx));",
        "        EC_GROUP_free(g);",
        "    }",
        "",
        "    /* The NIST-name pair and the curve-name lookup, over every row and over",
        "     * refusals. */",
        "    for (i = 0; i < n; i++) {",
        "        int nid = table[i].nid;",
        "        const char *nist = EC_curve_nid2nist(nid);",
        "        const char *name = OSSL_EC_curve_nid2name(nid);",
        "        printf(\"nid2nist.%d=%s\\n\", nid, nist != NULL ? nist : \"NULL\");",
        "        printf(\"nid2name.%d=%s\\n\", nid, name != NULL ? name : \"NULL\");",
        "        if (nist != NULL)",
        "            printf(\"nist2nid.%s=%d\\n\", nist, EC_curve_nist2nid(nist));",
        "    }",
        "    printf(\"nid2nist.0=%s\\n\", EC_curve_nid2nist(0) != NULL ? \"name\" : \"NULL\");",
        "    printf(\"nid2nist.-1=%s\\n\", EC_curve_nid2nist(-1) != NULL ? \"name\" : \"NULL\");",
        "    printf(\"nid2nist.999999=%s\\n\",",
        "           EC_curve_nid2nist(999999) != NULL ? \"name\" : \"NULL\");",
        "    printf(\"nist2nid.refusals=%d,%d,%d,%d\\n\",",
        "           EC_curve_nist2nid(\"P-999\"), EC_curve_nist2nid(\"p-256\"),",
        "           EC_curve_nist2nid(\"B-163 \"), EC_curve_nist2nid(\"\"));",
        "    printf(\"nid2name.0=%s\\n\",",
        "           OSSL_EC_curve_nid2name(0) != NULL ? \"name\" : \"NULL\");",
        "    printf(\"nid2name.-1=%s\\n\",",
        "           OSSL_EC_curve_nid2name(-1) != NULL ? \"name\" : \"NULL\");",
        "    printf(\"nid2name.999999=%s\\n\",",
        "           OSSL_EC_curve_nid2name(999999) != NULL ? \"name\" : \"NULL\");",
        "    printf(\"nid2name.rsa=%s\\n\",",
        "           OSSL_EC_curve_nid2name(NID_rsaEncryption) != NULL ? \"name\" : \"NULL\");",
        "",
        "    BN_free(pa); BN_free(pb); BN_free(x); BN_free(y);",
        "    BN_CTX_free(ctx);",
        "    free(table);",
        "    return 0;",
        "}",
        "",
    ])


def to_bytes(hexdigits: str, width: int, symbol: str) -> bytes:
    """Hex as the authority's own `data[]` slice width, big-endian.

    `BN_bn2hex` prints the minimal number of digits, so a value whose top byte clears —
    every `gx` and `gy`, and `b` on several curves — comes back shorter than its slice.
    Left-padding to the declared width is faithful to the array: the authority's own
    initialiser zero-pads every field to `param_len`. A read-back **wider** than the
    declared slice is a different thing entirely and fails.
    """
    text = hexdigits.strip()
    if text.startswith("-"):
        raise SystemExit(f"{GENERATOR}: {symbol} came back negative: {text!r}")
    if len(text) % 2:
        text = "0" + text
    raw = bytes.fromhex(text)
    if len(raw) > width:
        raise SystemExit(
            f"{GENERATOR}: {symbol} is {len(raw)} bytes and its slice is {width}; the "
            f"source and the library disagree"
        )
    return raw.rjust(width, b"\x00")


def sanitize(text: str) -> str:
    """The probe's own rendering of a comment column."""
    return text.replace("\n", "|").replace("\t", "/")


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


def render_rust(authority_id: str, curves: list[dict], rows: list[dict],
                values: dict[str, bytes]) -> str:
    """The generated file, as a pure function of the authority identity and the record."""
    body = [
        "//! The authority's built-in curve parameters — GENERATED, do not edit.",
        "//!",
        "//! Regenerate with `forensics/tools/gen_ec_curves.py` inside the court container.",
        "//! Each value is read back from the admitted authority rather than transcribed",
        "//! from `crypto/ec/ec_curve.c`: a typo in a 521-bit prime is invisible to",
        "//! everything except a comparison with the authority itself, and",
        "//! `EC_GROUP_new_by_curve_name` feeds these straight into a key agreement. The",
        "//! generator checks every read-back against the `data[]` array the authority's",
        "//! own struct declares, member for member and width for width, so the two",
        "//! derivations have to agree before this file is written.",
        "//!",
        "//! [`EcListElement`]'s rows carry `curve_list[]`'s `nid`, `data` and `comment`",
        "//! columns and **not** its fourth: see [`crate::ec::curve`] for why the method",
        "//! column has exactly one non-NULL value on this profile and why this crate does",
        "//! not carry it.",
        "//!",
        f"//! Authority: `{authority_id}`.",
        "",
        "use crate::ec::curve::{EcCurveData, EcListElement};",
        "use crate::runtime::obj;",
        "",
    ]
    for c in curves:
        body.append(render_curve(c, values[c["name"]]))
        body.append("")
    body.append(render_list(rows, len(rows)))
    body.append("")
    return "\n".join(body)


def needs_case_allow(name: str) -> bool:
    """Whether `non_upper_case_globals` fires for a name kept verbatim.

    The authority's own struct names are `_EC_NIST_PRIME_192` and
    `_EC_brainpoolP512t1`, and the second is not screaming snake case. **The name is kept
    verbatim anyway**, because it is what a reader pairs with `ec_curve.c` and what
    `forensics/atlas/ec-curves.json` records; the lint is silenced at the item rather than
    the module, which is this crate's rule for every `#[allow]`. The attribute is derived
    from the name rather than written out, so a new curve cannot be added without one.
    """
    return any(c.islower() for c in name)


def render_curve(c: dict, value: bytes) -> str:
    """One `static const struct` as the two items that carry it."""
    allow = "#[allow(non_upper_case_globals)] // the authority's own struct name\n" \
        if needs_case_allow(c["name"]) else ""
    lines = [
        f"/// `{c['name']}` — the authority's own `EC_CURVE_DATA` header and `data[]`,",
        f"/// `{c['source']}`.",
        allow + f"pub(crate) static {c['name']}: EcCurveData = EcCurveData {{",
        f"    field_type: obj::{c['field_type']},",
        f"    seed_len: {c['seed_len']},",
        f"    param_len: {c['param_len']},",
        f"    cofactor: {c['cofactor']},",
        f"    data: &{c['name']}_DATA,",
        "};",
        "",
        f"/// `{c['name']}`'s `data[]` — {len(value)} bytes: a {c['seed_len']}-byte seed",
        f"/// then {c['fields']} {c['param_len']}-byte fields,"
        + (" `p || a || b || gx || gy || order`." if c["fields"] == 6 else
           " `p || a || b || gx || gy || order || RR_p || RR_n` — the last two are the"
           " nistz256 method's own Montgomery constants and have no other reader."),
        allow + f"pub(crate) static {c['name']}_DATA: [u8; {len(value)}] = [",
    ]
    items = [f"0x{b:02X}" for b in value]
    for i in range(0, len(value), BYTES_PER_LINE):
        lines.append("    " + ", ".join(items[i:i + BYTES_PER_LINE]) + ",")
    lines.append("];")
    return "\n".join(lines)


def render_list(rows: list[dict], count: int) -> str:
    """`curve_list[]`'s three transcribed columns, in the authority's own row order."""
    lines = [
        "/// `static const ec_list_element curve_list[]` —",
        f"/// `{EC_CURVE}:2615-2837`, with its `nid`, `data` and `comment` columns. The",
        "/// fourth column is recorded in `forensics/atlas/ec-curves.json` and is not",
        "/// transcribed; [`crate::ec::curve`]'s module documentation says why.",
        f"pub(crate) static EC_LIST_ELEMENTS: [EcListElement; {count}] = [",
    ]
    for r in rows:
        lines.append("    EcListElement {")
        lines.append(f"        nid: obj::{r['nid']},")
        lines.append(f"        data: &{r['curve']},")
        lines.append(f"        comment: {rust_c_string(r['comment'])},")
        lines.append("    },")
    lines.append("];")
    return "\n".join(lines)


def rust_c_string(value: str) -> str:
    return ('c"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
            .replace("\t", "\\t").replace("\r", "\\r") + '"')


# ---------------------------------------------------------------------------
# the crate-side checks, which both tiers run
# ---------------------------------------------------------------------------


def check_support_table(support: dict) -> None:
    """`src/ec/support.rs`'s two tables are `ec_support.c`'s, in its order.

    The module is hand-written — it is where the unit's documentation and its tests live,
    so it cannot itself be generated — and this is the check that keeps it from drifting.
    """
    if not SUPPORT_RS.is_file():
        raise SystemExit(f"{GENERATOR}: {rel(SUPPORT_RS)} is absent")
    text = SUPPORT_RS.read_text(encoding="utf-8")
    # The two arrays by their own declarations, not every tuple that looks like a row: the
    # module's tests quote rows too, and a scan of the whole file would read them as
    # table members and fail on a module that is right.
    found: list[tuple[str, str]] = []
    for name, count in (("CURVE_NAME_ROWS", 82), ("NIST_CURVE_ROWS", 15)):
        m = re.search(
            rf"const {name}: \[\(&CStr, c_int\); {count}\] = \[(.*?)\n\];", text, re.S)
        if m is None:
            raise SystemExit(
                f"{GENERATOR}: {rel(SUPPORT_RS)} has no `{name}: [(&CStr, c_int); "
                f"{count}]` array"
            )
        found += [(a, b) for a, b in _SUPPORT_ROW.findall(m.group(1))]
    want = list(support["names"]) + list(support["nist"])
    if found != want:
        at = next((i for i, (a, b) in enumerate(zip(found, want)) if a != b),
                  min(len(found), len(want)))
        raise SystemExit(
            f"{GENERATOR}: {rel(SUPPORT_RS)}'s name tables are not {EC_SUPPORT}'s, in "
            f"order: it has {len(found)} rows, the authority {len(want)} "
            f"({len(support['names'])} curve names then {len(support['nist'])} NIST "
            f"names), and the first difference is at row {at}: "
            f"{found[at] if at < len(found) else '<none>'} against "
            f"{want[at] if at < len(want) else '<none>'}"
        )


def check_against_artefact() -> int:
    """The weak tier: rebuild the generated Rust from the committed artefact.

    Used when the authority is absent, which is the case on every runner that has only the
    repository. It catches a hand-edited `curve_data.rs` and a JSON that has drifted from
    it. It cannot catch the authority having changed — the authority is pinned by archive
    hash elsewhere, and the court, which has it, re-derives.
    """
    if not OUT_JSON.is_file() or not OUT_RS.is_file():
        print(
            f"[{GENERATOR}] neither the authority nor the pair "
            f"{rel(OUT_JSON)}/{rel(OUT_RS)} is present; nothing can be checked",
            file=sys.stderr,
        )
        return 1
    doc = json.loads(OUT_JSON.read_text(encoding="utf-8"))
    body = doc["body"]
    curves, rows = body["curves"], body["curve_list"]
    rust = OUT_RS.read_text(encoding="utf-8")

    values: dict[str, bytes] = {}
    for c in curves:
        m = re.search(
            rf"^pub\(crate\) static {re.escape(c['name'])}_DATA: \[u8; (\d+)\] = \[(.*?)^\];$",
            rust, re.M | re.S)
        if m is None:
            print(
                f"[{GENERATOR}] {rel(OUT_RS)} has no `{c['name']}_DATA` array, which "
                f"{rel(OUT_JSON)} records as one of {len(curves)} curves",
                file=sys.stderr,
            )
            return 1
        raw = bytes(int(b, 16) for b in _BYTE.findall(m.group(2)))
        if (int(m.group(1)) != c["bytes"] or len(raw) != c["bytes"]
                or hashlib.sha256(raw).hexdigest() != c["sha256"]):
            print(
                f"[{GENERATOR}] {c['name']}_DATA in {rel(OUT_RS)} does not hash to the "
                f"value {rel(OUT_JSON)} records; the generated file was edited by hand or "
                f"the artefact is stale",
                file=sys.stderr,
            )
            return 1
        values[c["name"]] = raw

    expected = render_rust(doc["authority"], curves, rows, values)
    if rust != expected:
        exp = expected.splitlines()
        act = rust.splitlines()
        at = next((i for i, (a, b) in enumerate(zip(act, exp)) if a != b),
                  min(len(act), len(exp)))
        print(
            f"[{GENERATOR}] {rel(OUT_RS)} does not match {rel(OUT_JSON)}; first "
            f"difference at line {at + 1}:\n"
            f"  committed: {act[at] if at < len(act) else '<eof>'}\n"
            f"  from json: {exp[at] if at < len(exp) else '<eof>'}",
            file=sys.stderr,
        )
        return 1

    check_support_table(body["ec_support"])
    print(
        f"[ec-curves] ok (weak tier, authority absent): {rel(OUT_RS)} matches "
        f"{rel(OUT_JSON)} over {len(curves)} curves and {len(rows)} rows"
    )
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    curve_c = auth.source / EC_CURVE
    support_c = auth.source / EC_SUPPORT
    if not curve_c.is_file() or not (auth.prefix / "include" / "openssl" / "ec.h").is_file():
        return check_against_artefact()

    macros = profile_macros(auth)
    source = curve_c.read_text(encoding="utf-8")
    short_names = parse_short_names((auth.source / OBJ_MAC).read_text(encoding="utf-8"))
    curves, rows, fips_rows = parse_ec_curve(source, macros)
    support = parse_ec_support(support_c.read_text(encoding="utf-8"))
    non_null = [r for r in rows if r["method"] != "0"]
    if len(non_null) != 1 or non_null[0]["nid"] != "NID_X9_62_prime256v1":
        raise SystemExit(
            f"{GENERATOR}: this profile resolves {len(non_null)} non-NULL method columns "
            f"({[r['nid'] for r in non_null]}); the crate's documentation says exactly "
            f"one, `NID_X9_62_prime256v1`"
        )
    by_name = {c["name"]: c for c in curves}
    used = {r["curve"] for r in rows}
    unused = sorted(set(by_name) - used)
    if unused:
        raise SystemExit(
            f"{GENERATOR}: {EC_CURVE} defines {len(unused)} EC_CURVE_DATA structs the "
            f"compiled `curve_list[]` does not name: {unused}"
        )

    work = REPO_ROOT / "court" / "ec-curves"
    work.mkdir(parents=True, exist_ok=True)
    src = work / "ec_curves_probe.c"
    write_text(src, probe_source())
    binp = work / "ec_curves_probe"
    res = run([
        "clang", "-std=c11", "-Wall", "-O1", "-D_GNU_SOURCE",
        "-I", str(auth.prefix / "include"),
        "-o", str(binp), str(src),
        "-L", str(auth.libdir), "-lcrypto",
        f"-Wl,-rpath,{auth.libdir}",
    ])
    if not res.ok:
        raise SystemExit(f"{GENERATOR}: the probe did not compile:\n{res.stderr}")
    res = run([str(binp)])
    if not res.ok:
        raise SystemExit(f"{GENERATOR}: the probe did not run:\n{res.stderr}")

    read: dict[str, str] = {}
    for line in res.stdout.splitlines():
        if "=" not in line:
            continue
        key, _, raw = line.partition("=")
        read[key] = raw

    count = len(rows)
    expect_common = {
        "count": str(count),
        "count_nitems0": str(count),
        "count_short": str(count),
        "count_filled": str(count),
        "short.nid": str(int(read.get("row000.nid", "0"))),
        "short.comment": sanitize(rows[0]["comment"]),
    }
    for key, expect in expect_common.items():
        if read.get(key) != expect:
            raise SystemExit(
                f"{GENERATOR}: `{key}` is {read.get(key)!r} on the authority and "
                f"{expect!r} from {EC_CURVE}"
            )

    values: dict[str, bytes] = {}
    for i, r in enumerate(rows):
        tag = f"row{i:03d}"
        c = by_name[r["curve"]]
        if read.get(f"{tag}.nid") != str(c_nid(read, i)):
            raise SystemExit(f"{GENERATOR}: {tag}'s NID is not the table's row {i}")
        if read.get(f"{tag}.sn") != short_names.get(r["nid"][4:], "<no SN_>"):
            raise SystemExit(
                f"{GENERATOR}: {tag} is `{read.get(f'{tag}.sn')}` and {OBJ_MAC}'s "
                f"`SN_{r['nid'][4:]}` is {short_names.get(r['nid'][4:], '<absent>')!r}"
            )
        if read.get(f"{tag}.comment") != sanitize(r["comment"]):
            raise SystemExit(
                f"{GENERATOR}: {tag}'s comment is not {EC_CURVE}'s:\n"
                f"  library: {read.get(f'{tag}.comment')!r}\n"
                f"  source:  {sanitize(r['comment'])!r}"
            )
        if read.get(f"{tag}.group") == "NULL":
            raise SystemExit(
                f"{GENERATOR}: the authority refused to build {r['nid']}, which "
                f"{EC_CURVE} has a row for"
            )
        if read.get(f"{tag}.field_type") != str(c["field_type_number"]):
            raise SystemExit(
                f"{GENERATOR}: {tag}'s field type is {read.get(f'{tag}.field_type')} and "
                f"{r['curve']} says {c['field_type']} = {c['field_type_number']}"
            )
        degree = field_degree(r, c, source)
        if read.get(f"{tag}.degree") != str(degree):
            raise SystemExit(
                f"{GENERATOR}: {tag}'s degree is {read.get(f'{tag}.degree')} and "
                f"{r['curve']}'s own `p` gives {degree}"
            )
        # The method column: the resolved source value names the symbol, and the probe
        # names which of the profile's four *exported* constructors the group's method is.
        observed = read.get(f"{tag}.method")
        if r["method"] != "0" and observed != "other":
            raise SystemExit(
                f"{GENERATOR}: {r['nid']} resolves its method column to `{r['method']}` "
                f"and its group's method is `{observed}`"
            )
        if r["method"] == "0" and observed == "other":
            raise SystemExit(
                f"{GENERATOR}: {r['nid']} resolves its method column to NULL and its "
                f"group's method is none of the four exported constructors"
            )

        raw = source_array(source, r["curve"])
        seed_len, param_len = c["seed_len"], c["param_len"]
        if read.get(f"{tag}.seed_len") != str(seed_len):
            raise SystemExit(
                f"{GENERATOR}: {tag}'s seed length is {read.get(f'{tag}.seed_len')} and "
                f"{r['curve']} says {seed_len}"
            )
        probe_seed = read.get(f"{tag}.seed", "")
        if seed_len == 0:
            if probe_seed != "NULL":
                raise SystemExit(
                    f"{GENERATOR}: {tag} has no seed in the source and one in the library"
                )
            seed_bytes = b""
        elif probe_seed != raw[:seed_len].hex().upper():
            raise SystemExit(
                f"{GENERATOR}: {tag}'s seed is not {r['curve']}'s first {seed_len} bytes"
            )
        else:
            seed_bytes = raw[:seed_len]
        value = bytearray(seed_bytes)
        for member, off in (("p", 0), ("a", 1), ("b", 2), ("x", 3), ("y", 4), ("order", 5)):
            got = read.get(f"{tag}.{member}")
            if got in (None, "NONE") or got == "ALLOCFAIL":
                raise SystemExit(
                    f"{GENERATOR}: the authority answered {got!r} for {tag}.{member}"
                )
            want = raw[seed_len + off * param_len:seed_len + (off + 1) * param_len]
            if to_bytes(got, param_len, f"{tag}.{member}") != want:
                raise SystemExit(
                    f"{GENERATOR}: {tag}.{member} does not match {r['curve']}'s own "
                    f"`data[]` slice:\n  library: {got}\n  source:  {want.hex().upper()}"
                )
            value += want
        # The seventh and eighth fields, where a curve has them, have no public accessor:
        # the nistz256 method's own `group_full_init` is the only reader, and it is
        # perlasm-backed on this profile, so the source's bytes are the only derivation
        # there is. The width is checked against the declared array either way.
        value += raw[seed_len + 6 * param_len:seed_len + c["fields"] * param_len]
        if len(value) != c["bytes"]:
            raise SystemExit(
                f"{GENERATOR}: {r['curve']}'s emitted width is {len(value)} and its "
                f"`data[]` is {c['bytes']} bytes"
            )
        cofactor = read.get(f"{tag}.cofactor")
        if cofactor in (None, "NONE"):
            raise SystemExit(f"{GENERATOR}: the authority answered {cofactor!r} for {tag}")
        if int(cofactor, 16) != c["cofactor"]:
            raise SystemExit(
                f"{GENERATOR}: {tag}'s cofactor is {cofactor} and {r['curve']} says "
                f"{c['cofactor']}"
            )
        if read.get(f"{tag}.on_curve") != "1":
            raise SystemExit(
                f"{GENERATOR}: the authority's {r['nid']} generator is not on its own curve"
            )
        values[r["curve"]] = bytes(value)

    for c in curves:
        value = values[c["name"]]
        if len(value) != c["seed_len"] + c["fields"] * c["param_len"]:
            raise SystemExit(f"{GENERATOR}: {c['name']}'s emitted width is wrong")
        c["emitted_bytes"] = len(value)
        c["emitted_sha256"] = hashlib.sha256(value).hexdigest()

    write_text(OUT_RS, render_rust(auth.id, curves, rows, values))

    doc = envelope(
        kind="ec-curves",
        authority=auth.id,
        inputs=[
            InputRef(name="authority-symbols",
                     path=REPO_ROOT / "forensics" / "atlas" / auth.id
                     / "symbols-libcrypto.json"),
            InputRef(name="authority-source-ec-curve", path=curve_c),
            InputRef(name="authority-source-ec-support", path=support_c),
        ],
        body={
            "curves": curves,
            "curve_list": rows,
            "ec_support": support,
            "profile_macros": macros,
            "checks": {
                "values_from": "a probe linked against the admitted prefix, walking "
                               "`EC_get_builtin_curves` and reading each group back with "
                               "`EC_GROUP_get_curve`, `EC_POINT_get_affine_coordinates`, "
                               "`EC_GROUP_get_order`, `EC_GROUP_get0_cofactor`, "
                               "`EC_GROUP_get0_seed` and `BN_bn2hex`",
                "inventory_from": f"{EC_CURVE}'s `EC_CURVE_DATA` initialisers and its "
                                  "compiled `curve_list[]`",
                "readback_is_the_source_arrays": True,
                "readback_width_is_the_declared_slice": True,
                "declared_size_is_seed_plus_n_fields": True,
                "montgomery_fields_from_the_source": [
                    c["name"] for c in curves if c["fields"] > 6
                ],
                "field_type_and_cofactor_are_the_headers": True,
                "table_order_is_the_probe_order": True,
                "nid_set_matches_both_directions": True,
                "comments_are_the_source_strings": True,
                "method_column_resolved_for_this_profile": True,
                "method_column_has_one_non_null_row": True,
                "ec_support_tables_match_the_crate": True,
                "fips_curve_list_rows": fips_rows,
            },
            "counts": {
                "curves": len(curves),
                "rows": len(rows),
                "bytes": sum(r["bytes"] for r in curves),
                "field_widths": len({r["param_len"] for r in curves}),
                "seed_lengths": sorted({r["seed_len"] for r in curves}),
                "prime_field": sum(1 for r in curves
                                   if r["field_type"] == "NID_X9_62_prime_field"),
                "characteristic_two_field": sum(
                    1 for r in curves
                    if r["field_type"] == "NID_X9_62_characteristic_two_field"),
                "non_null_method_rows": len(non_null),
            },
        },
        generator=GENERATOR,
    )
    write_json(OUT_JSON, doc)
    check_support_table(support)

    print(f"[ec-curves] authority={auth.id} curves={len(curves)} rows={len(rows)} "
          f"bytes={sum(r['bytes'] for r in curves)}")
    print(f"  prime field {sum(1 for r in curves if r['field_type'] == 'NID_X9_62_prime_field')}"
          f", characteristic two "
          f"{sum(1 for r in curves if r['field_type'] == 'NID_X9_62_characteristic_two_field')}"
          f", field widths {sorted({r['param_len'] for r in curves})}")
    print(f"  non-NULL method rows {len(non_null)}: {[r['nid'] for r in non_null]}")
    print(f"  -> {rel(OUT_RS)}")
    return 0


def c_nid(read: dict[str, str], index: int) -> int:
    """The NID the authority reported for row `index`, as the table's own must match it."""
    return int(read[f"row{index:03d}.nid"])


def field_degree(r: dict, c: dict, source: str) -> int:
    """`EC_GROUP_get_degree`'s answer, from the curve's own `p`.

    A prime field's degree is the bit width of `p`. A characteristic-two field's `p` is
    the reduction polynomial `x^m + (lower terms)`, so its degree — one less than its bit
    width — *is* `m`, which is what `EC_GROUP_get_degree` answers.
    """
    p = source_array(source, r["curve"])[
        c["seed_len"]:c["seed_len"] + c["param_len"]]
    width = int.from_bytes(p, "big").bit_length()
    if c["field_type"] == "NID_X9_62_prime_field":
        return width
    return width - 1


def source_token(source: str, name: str) -> str:
    """The initialiser body of one `EC_CURVE_DATA` struct."""
    m = re.search(
        rf"\}}\s*{re.escape(name)}\s*=\s*\{{\s*\{{[^}}]*\}}\s*,\s*\{{(.*?)\}}\s*\}};",
        strip_comments(source), re.S)
    if m is None:
        raise SystemExit(f"{GENERATOR}: {name}'s initialiser is no longer readable")
    return m.group(1)


def source_array(source: str, name: str) -> bytes:
    return bytes(int(b, 16) for b in _BYTE.findall(source_token(source, name)))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
