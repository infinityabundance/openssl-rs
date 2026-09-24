#!/usr/bin/env python3
"""openssl-rs — derive `crypto/bn/bn_dh.c`'s named-group constants from the authority.

Why this exists
---------------
`crypto/ffc/ffc_dh.c`'s `dh_named_groups[]` names thirty-two `ossl_bignum_*` objects,
and `crypto/dh/dh_rfc5114.c` duplicates three of them. Together they are 13,536 bytes
of limb data in a 1,423-line file. The alternative to generating them is transcribing
them out of `bn_dh.c`, which is the one thing this project refuses to do with a
constant another party defines: a typo in an 8192-bit prime is invisible to every test
that does not compare against the authority itself, and `DH_new_by_nid` feeds such a
prime straight into a key agreement, where a wrong value silently changes every result.

So the **values** are *asked of the authority*: a C probe compiled against the admitted
prefix calls `DH_new_by_nid` and `DH_get_1024_160`, prints `BN_bn2hex` of every group's
`p`, `q` and `g`, and this tool emits the byte arrays into `src/bn/dh_data.rs`.

The **inventory and the widths** come from the authority's own source instead —
`bn_dh.c`'s `make_dh_bn(x)` list, the line each is expanded at, and the number of limbs
each `x[]` array declares. The two derivations are independent, and the generator fails
unless they agree: `forensics/atlas/bn-dh.json` records both, so a reader can recheck
the claim rather than believe it.

What is checked rather than assumed
-----------------------------------
* Every one of the thirty-two symbols `bn_dh.c` defines through `make_dh_bn` (plus its
  `ossl_bignum_const_2`) is read back, and nothing else is: the read-back set and the
  source's own inventory must be equal **in both directions in meaning and in order**.
* `dh_named_groups[]` is read out of `ffc_dh.c` with its three macros expanded, and its
  rows must name exactly this inventory, **in the order the probe asks for the groups**
  -- so the values are the values those rows point at. Each row's `nbits` and the
  read-back's own width confirm each other.
* Each read-back value fits the limb count `bn_dh.c` declares for it. `BN_bn2hex` is
  minimal, so `dh1024_160_q`'s twenty bytes are left-padded to the twenty-four its
  `dh1024_160_q[3]` array occupies; a value that *exceeded* the declared array is a
  failure, not a pad.
* Every `_g` of the FFDHE and MODP families is 2 — the RFC 5114 groups have their own
  `g`, and the generator refuses to read the table as sharing `ossl_bignum_const_2` for
  anything else.
* `src/bn/dh.rs`'s accessor table is the same inventory, **in the same order**, with
  each accessor paired with the array its own uppercased name gives and citing the line
  `bn_dh.c` expands it at. That module is hand-written (it is where the unit's
  documentation and its tests live, so it cannot itself be generated) and this check is
  what stops it drifting from the authority in either tier.

Usage (inside the court, which is where the authority prefix lives):

    python3 forensics/tools/gen_bn_dh.py

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
    write_text,
    write_json,
)

OUT_RS = REPO_ROOT / "src" / "bn" / "dh_data.rs"
OUT_JSON = REPO_ROOT / "forensics" / "atlas" / "bn-dh.json"
ACCESSOR_RS = REPO_ROOT / "src" / "bn" / "dh.rs"
GENERATOR = "forensics/tools/gen_bn_dh.py"

BN_DH = "crypto/bn/bn_dh.c"
FFC_DH = "crypto/ffc/ffc_dh.c"

# How the probe obtains each named group through the authority's **public** API, in
# `dh_named_groups[]`'s order. `DH_new_by_nid` is the UID lookup, so this list is also
# what proves the NID-to-group mapping: the probe asks the authority's own dispatch for
# each NID rather than for each constant, and the values it gets back are the ones the
# constants must hold. The RFC 5114 rows are the three deprecated entry points, because
# their `uid`s are 1, 2 and 3 -- values no NID has.
#
# The generator checks this list against the table it reads out of `ffc_dh.c`, so a
# group added upstream is a failure here rather than a silently unread constant.
GROUPS: list[tuple[str, str]] = [
    ("ffdhe2048", "DH_new_by_nid(NID_ffdhe2048)"),
    ("ffdhe3072", "DH_new_by_nid(NID_ffdhe3072)"),
    ("ffdhe4096", "DH_new_by_nid(NID_ffdhe4096)"),
    ("ffdhe6144", "DH_new_by_nid(NID_ffdhe6144)"),
    ("ffdhe8192", "DH_new_by_nid(NID_ffdhe8192)"),
    ("modp_1536", "DH_new_by_nid(NID_modp_1536)"),
    ("modp_2048", "DH_new_by_nid(NID_modp_2048)"),
    ("modp_3072", "DH_new_by_nid(NID_modp_3072)"),
    ("modp_4096", "DH_new_by_nid(NID_modp_4096)"),
    ("modp_6144", "DH_new_by_nid(NID_modp_6144)"),
    ("modp_8192", "DH_new_by_nid(NID_modp_8192)"),
    ("dh1024_160", "DH_get_1024_160()"),
    ("dh2048_224", "DH_get_2048_224()"),
    ("dh2048_256", "DH_get_2048_256()"),
]

# The number of bytes `rustfmt` packs onto one line of a byte-array literal. Derived the
# same way `gen_bn_primes.py` derives it -- a byte token is `0xNN,`, five columns, joined
# by a space, indented four columns inside its declaration, and `rustfmt`'s default
# `max_width` is 100, so `4 + 6n - 1 <= 100` gives `n <= 16`.
BYTES_PER_LINE = (100 - 4 + 1) // 6

# `BN_DEF(lo, hi)` is `(BN_ULONG)hi << 32 | lo` when `BN_BITS2 == 64` and `lo, hi`
# otherwise (`bn_dh.c:16-20`), so one macro invocation is one limb on this profile and
# two otherwise. The probe's read-back is what decides which reading held; this is the
# profile's, and `to_bytes` fails loudly if the authority disagrees.
LIMB_BYTES = 8

_ARRAY = re.compile(r"^static const BN_ULONG ([A-Za-z0-9_]+)\[\] = \{(.*?)^\};", re.M | re.S)
_SCALAR = re.compile(r"^static const BN_ULONG ([A-Za-z0-9_]+) = (\d+);", re.M)
# `make_dh_bn(x)` is the whole block's spelling of `const BIGNUM ossl_bignum_x`; the
# expansion itself is indented inside the `#define` and so never matches this anchor.
_MAKE = re.compile(r"^make_dh_bn\(([A-Za-z0-9_]+)\)", re.M)
_CONST = re.compile(r"^const BIGNUM ([A-Za-z0-9_]+) = \{", re.M)


def parse_bn_dh(text: str) -> list[dict]:
    """The authority's own inventory, one row per `ossl_bignum_*`, in definition order.

    The order is the file's rather than a list typed here: `ossl_bignum_const_2` is
    defined first (`:1385`) and the `make_dh_bn` block follows it (`:1389-1423`). That
    is the order `src/bn/dh.rs`'s accessor table must be in, and the order the generated
    file is written in.
    """
    limbs: dict[str, int] = {}
    for name, body in _ARRAY.findall(text):
        # One limb per `BN_DEF(a, b)` and one per bare `(BN_ULONG)0x...` entry, which is
        # how the RFC 5114 `q` arrays spell their top limb (`dh1024_160_q[]`).
        limbs[name] = body.count("BN_DEF(") + body.count("(BN_ULONG)")

    scalars: dict[str, int] = {}
    for name, value in _SCALAR.findall(text):
        scalars[name] = int(value)
    if scalars.get("value_2") != 2:
        raise SystemExit(
            f"{GENERATOR}: {BN_DH} declares `value_2 = {scalars.get('value_2')}`, and "
            f"`ossl_bignum_const_2` is that object"
        )

    record: list[dict] = []
    for match in _CONST.finditer(text):
        if match.group(1) == "ossl_bignum_const_2":
            record.append({
                "symbol": "ossl_bignum_const_2",
                "limbs": 1,
                "source": f"{BN_DH}:{text[:match.start()].count(chr(10)) + 1}",
            })
    for match in _MAKE.finditer(text):
        array = match.group(1)
        if array not in limbs:
            raise SystemExit(
                f"{GENERATOR}: `make_dh_bn({array})` has no `static const BN_ULONG "
                f"{array}[]` in {BN_DH}; this tool no longer models the file"
            )
        record.append({
            "symbol": f"ossl_bignum_{array}",
            "limbs": limbs[array],
            "source": f"{BN_DH}:{text[:match.start()].count(chr(10)) + 1}",
        })
    return record


def expected_symbols(record: list[dict]) -> list[str]:
    return [r["symbol"] for r in record]


# The three macros `dh_named_groups[]` is written with, spelled out **whole**. They are
# modelled rather than expanded by a preprocessor, so each definition is matched after
# its line continuations are joined, and a macro whose body changed is a failure here
# rather than a quiet misreading of the table. Each shape ends before the closing brace,
# which is what distinguishes the real definition from the `#else` stub beside it.
_MACRO_SHAPES = {
    "FFDHE": (
        r"#define FFDHE\(sz, keylength\)\s*\{\s*SN_ffdhe##sz,\s*NID_ffdhe##sz,\s*sz,"
        r"\s*keylength,\s*&ossl_bignum_ffdhe##sz##_p,\s*&ossl_bignum_ffdhe##sz##_q,"
        r"\s*&ossl_bignum_const_2,"
    ),
    "MODP": (
        r"#define MODP\(sz, keylength\)\s*\{\s*SN_modp_##sz,\s*NID_modp_##sz,\s*sz,"
        r"\s*keylength,\s*&ossl_bignum_modp_##sz##_p,\s*&ossl_bignum_modp_##sz##_q,"
        r"\s*&ossl_bignum_const_2"
    ),
    "RFC5114": (
        r"#define RFC5114\(name, uid, sz, tag\)\s*\{\s*name,\s*uid,\s*sz,\s*0,"
        r"\s*&ossl_bignum_dh##tag##_p,\s*&ossl_bignum_dh##tag##_q,"
        r"\s*&ossl_bignum_dh##tag##_g"
    ),
}

_FFDHE_ROW = re.compile(r"FFDHE\((\d+), (\d+)\)")
_MODP_ROW = re.compile(r"MODP\((\d+), (\d+)\)")
_RFC5114_ROW = re.compile(r"RFC5114\(\"([^\"]+)\", (\d+), (\d+), ([0-9A-Za-z_]+)\)")


def parse_ffc_dh(text: str) -> list[dict]:
    """`dh_named_groups[]`, in table order, with the three macros expanded.

    A row is `(name, uid, nbits, keylength, p, q, g, family, group)`, where `group` is
    the tag the probe asks the authority's API for. The `#ifndef FIPS_MODULE` guards
    around `MODP(1536, 200)` and the RFC 5114 rows are *taken*, not skipped: this
    profile is not the FIPS module, so those rows are compiled and the table has
    fourteen entries.
    """
    joined = re.sub(r"\\\n", " ", text)
    for macro, shape in _MACRO_SHAPES.items():
        if not re.search(shape, joined):
            raise SystemExit(
                f"{GENERATOR}: {FFC_DH}'s `{macro}` definition is no longer the shape "
                f"this tool models; the table would be read wrongly"
            )
    rows: list[tuple[int, dict]] = []
    for m in _FFDHE_ROW.finditer(text):
        sz, keylength = m.group(1), m.group(2)
        rows.append((m.start(), {
            "name": f"SN_ffdhe{sz}", "uid": f"NID_ffdhe{sz}",
            "nbits": int(sz), "keylength": int(keylength),
            "p": f"ossl_bignum_ffdhe{sz}_p", "q": f"ossl_bignum_ffdhe{sz}_q",
            "g": "ossl_bignum_const_2", "family": "ffdhe", "group": f"ffdhe{sz}",
        }))
    for m in _MODP_ROW.finditer(text):
        sz, keylength = m.group(1), m.group(2)
        rows.append((m.start(), {
            "name": f"SN_modp_{sz}", "uid": f"NID_modp_{sz}",
            "nbits": int(sz), "keylength": int(keylength),
            "p": f"ossl_bignum_modp_{sz}_p", "q": f"ossl_bignum_modp_{sz}_q",
            "g": "ossl_bignum_const_2", "family": "modp", "group": f"modp_{sz}",
        }))
    for m in _RFC5114_ROW.finditer(text):
        name, uid, sz, tag = m.group(1), m.group(2), m.group(3), m.group(4)
        rows.append((m.start(), {
            "name": name, "uid": str(int(uid)),
            "nbits": int(sz), "keylength": 0,
            "p": f"ossl_bignum_dh{tag}_p", "q": f"ossl_bignum_dh{tag}_q",
            "g": f"ossl_bignum_dh{tag}_g", "family": "rfc5114", "group": f"dh{tag}",
        }))
    return [row for _at, row in sorted(rows, key=lambda r: r[0])]


def check_ffc_dh(auth_source: Path, record: list[dict]) -> list[dict]:
    """`dh_named_groups[]` and the inventory must confirm each other.

    Three things are checked rather than asserted: the table names exactly the constants
    `bn_dh.c` defines and no other `ossl_bignum_*` object; its order is the order the
    probe asks for the groups, so the values are the values those rows point at; and the
    only rows whose `g` is the shared `ossl_bignum_const_2` are the FFDHE and MODP ones.
    """
    path = auth_source / FFC_DH
    if not path.is_file():
        raise SystemExit(f"{GENERATOR}: {rel(path)} is absent")
    table = parse_ffc_dh(path.read_text(encoding="utf-8"))

    named = {row[member] for row in table for member in ("p", "q", "g")}
    expected = set(expected_symbols(record))
    if named != expected:
        raise SystemExit(
            f"{GENERATOR}: {FFC_DH}'s table and {BN_DH} disagree about the constants:\n"
            f"  only in {FFC_DH}: {sorted(named - expected)}\n"
            f"  only in {BN_DH}: {sorted(expected - named)}"
        )
    probe = [tag for tag, _acquire in GROUPS]
    if [row["group"] for row in table] != probe:
        raise SystemExit(
            f"{GENERATOR}: the probe asks for {probe}, and {FFC_DH}'s table is "
            f"{[row['group'] for row in table]}; the values would be paired with the "
            f"wrong rows"
        )
    for row in table:
        shared = row["family"] in ("ffdhe", "modp")
        if shared != (row["g"] == "ossl_bignum_const_2"):
            raise SystemExit(
                f"{GENERATOR}: {row['group']} has `g = {row['g']}`, which is not what "
                f"its family ({row['family']}) uses"
            )
    return table


def probe_source() -> str:
    """The C probe: one `key=value` line per group member, and never a bare pointer."""
    lines = [
        "/* Generated by forensics/tools/gen_bn_dh.py -- do not edit. */",
        "#define OPENSSL_SUPPRESS_DEPRECATED",
        "#include <openssl/bn.h>",
        "#include <openssl/dh.h>",
        "#include <openssl/objects.h>",
        "#include <stdio.h>",
        "",
        "static void emit(const char *key, const BIGNUM *b)",
        "{",
        "    char *hex;",
        "    if (b == NULL) { printf(\"%s=NONE\\n\", key); return; }",
        "    hex = BN_bn2hex(b);",
        "    if (hex == NULL) { printf(\"%s=ALLOCFAIL\\n\", key); return; }",
        "    printf(\"%s=%s\\n\", key, hex);",
        "    OPENSSL_free(hex);",
        "}",
        "",
        "static void group(const char *tag, DH *dh)",
        "{",
        "    const BIGNUM *p = NULL, *q = NULL, *g = NULL;",
        "    char key[64];",
        "",
        "    if (dh == NULL) { printf(\"%s_p=NONE\\n\", tag); return; }",
        "    DH_get0_pqg(dh, &p, &q, &g);",
        "    snprintf(key, sizeof(key), \"%s_p\", tag); emit(key, p);",
        "    snprintf(key, sizeof(key), \"%s_q\", tag); emit(key, q);",
        "    snprintf(key, sizeof(key), \"%s_g\", tag); emit(key, g);",
        "    DH_free(dh);",
        "}",
        "",
        "int main(void)",
        "{",
    ]
    for tag, acquire in GROUPS:
        lines.append(f"    group(\"{tag}\", {acquire});")
    lines += ["    return 0;", "}", ""]
    return "\n".join(lines)


def to_bytes(hexdigits: str, limbs: int, symbol: str) -> bytes:
    """Hex as the authority's own limb-array width, big-endian.

    `BN_bn2hex` prints the minimal number of digits, so a value whose top limb has a
    clear top bit -- `modp_1536_q`'s is `0x7FFF_FFFF_FFFF_FFFF` -- comes back a byte
    shorter than the array it lives in. Left-padding to the declared width is faithful to
    the object: the authority's `BIGNUM` reports `top == OSSL_NELEM(x)` either way, and
    `BN_num_bits` is a property of the *value*. A read-back **wider** than the declared
    array is a different thing entirely and fails.
    """
    text = hexdigits.strip()
    if text.startswith("-"):
        raise SystemExit(f"{GENERATOR}: {symbol} came back negative: {text!r}")
    if len(text) % 2:
        text = "0" + text
    raw = bytes.fromhex(text)
    width = limbs * LIMB_BYTES
    if len(raw) > width:
        raise SystemExit(
            f"{GENERATOR}: {symbol} is {len(raw)} bytes but {BN_DH} declares {limbs} "
            f"limb(s) = {width} bytes; the source and the library disagree"
        )
    return raw.rjust(width, b"\x00")


def rust_array(r: dict, value: bytes) -> str:
    """One `pub(crate) const` as a byte array, laid out the way `rustfmt` lays it out.

    Three cases, and all three are derived rather than guessed, because the file is in
    `evidence_determinism.py`'s `COMPARED` set and `pipeline.sh` runs `cargo fmt` between
    the generation and the comparison: a renderer that disagrees with `rustfmt` by one
    space fails the determinism gate on every run.

    * The whole declaration on one line, if it fits `rustfmt`'s 100 columns. (Eight bytes
       does: 100 columns exactly.)
    * Otherwise the initialiser alone on a continuation line, if *that* fits -- an array
      of up to fifteen bytes does, and sixteen does not by exactly one column.
    * Otherwise one item list per line, packed `BYTES_PER_LINE` to a line with a trailing
      comma, which is `prime_data.rs`'s shape.
    """
    name = r["symbol"].upper() + "_BYTES"
    items = [f"0x{b:02X}" for b in value]
    doc = f"/// `{r['symbol']}` — {r['bits']} bits over {r['limbs']} limb(s), `{r['source']}`."
    decl = f"pub(crate) const {name}: [u8; {len(value)}] = "

    one_line = decl + "[" + ", ".join(items) + "];"
    if len(one_line) <= 100:
        return "\n".join([doc, one_line])
    joined = ", ".join(items)
    if len(joined) + 8 <= 100:
        return "\n".join([doc, decl.rstrip(), f"    [{joined}];"])
    lines = [doc, decl + "["]
    for i in range(0, len(value), BYTES_PER_LINE):
        chunk = ", ".join(items[i:i + BYTES_PER_LINE])
        lines.append(f"    {chunk},")
    lines.append("];")
    return "\n".join(lines)


def render_rust(authority_id: str, record: list[dict], values: dict[str, bytes]) -> str:
    """The generated file, as a pure function of the authority identity and the record.

    Factored out so that the weak tier can rebuild it from the committed JSON alone.
    That is what makes the check exact rather than approximate: both tiers call this, so
    a difference is a difference in the *inputs* and never in the rendering.
    """
    body = [
        "//! The authority's named-group constants — GENERATED, do not edit.",
        "//!",
        "//! Regenerate with `forensics/tools/gen_bn_dh.py` inside the court container. Each",
        "//! value is read back from the admitted authority rather than transcribed from",
        "//! `crypto/bn/bn_dh.c`: a typo in an 8192-bit prime is invisible to everything",
        "//! except a comparison with the authority itself, and `DH_new_by_nid` feeds these",
        "//! straight into a key agreement.",
        "//!",
        "//! The arrays are named after the authority's own `ossl_bignum_*` objects, uppercased,",
        "//! so a reader can pair one with the object files without a mapping table; the object",
        "//! itself — the `*const BigNum` `dh_named_groups[]` points at — is the accessor of",
        "//! that name in [`crate::bn::dh`], which is where the unit's documentation and its",
        "//! tests live.",
        "//!",
        f"//! Authority: `{authority_id}`.",
        "",
    ]
    for r in record:
        body.append(rust_array(r, values[r["symbol"]]))
        body.append("")
    return "\n".join(body)


_ACCESSOR = re.compile(
    r"pub\(crate\) unsafe fn ([A-Za-z_][A-Za-z0-9_]*)\(\) -> \*const BigNum \{\s*"
    r"static CACHE: AtomicPtr<BigNum> = AtomicPtr::new\(core::ptr::null_mut\(\)\);\s*"
    r"static_data_bignum\(&CACHE, &data::([A-Za-z_][A-Za-z0-9_]*)\)"
)
_ACCESSOR_DOC = re.compile(r"/// `const BIGNUM ([A-Za-z_][A-Za-z0-9_]*)` — `([^`]*)`\.")


def check_accessor_table(record: list[dict]) -> None:
    """`src/bn/dh.rs`'s accessors are the authority's inventory, in the authority's order.

    The table there is hand-written — that module is where the unit's documentation and
    its unit tests live, so it cannot itself be generated — and this is the check that
    keeps it from drifting. It runs in **both** tiers: the weak tier runs it from the
    committed JSON, so a hand edit that reorders or drops a row fails even on a runner
    with no authority.

    Two passes, so that a reformat of the surrounding code cannot move the answer: the
    `/// `const BIGNUM x` — `coordinate`.` doc line and the accessor body are matched
    separately and then required to line up by index. Both are needed — a table whose
    names were right and whose every value came from the *next* array along would pass a
    name-only check.
    """
    if not ACCESSOR_RS.is_file():
        raise SystemExit(f"{GENERATOR}: {rel(ACCESSOR_RS)} is absent")
    text = ACCESSOR_RS.read_text(encoding="utf-8")
    docs = _ACCESSOR_DOC.findall(text)
    bodies = _ACCESSOR.findall(text)
    expected = expected_symbols(record)
    if [d[0] for d in docs] != expected:
        raise SystemExit(
            f"{GENERATOR}: {rel(ACCESSOR_RS)}'s documented inventory is not {BN_DH}'s, "
            f"in order:\n  expected: {expected}\n  found:    {[d[0] for d in docs]}"
        )
    if [b[0] for b in bodies] != expected:
        raise SystemExit(
            f"{GENERATOR}: {rel(ACCESSOR_RS)}'s accessor definitions are not {BN_DH}'s, "
            f"in order:\n  expected: {expected}\n  found:    {[b[0] for b in bodies]}"
        )
    for (doc_symbol, source), (symbol, array), r in zip(docs, bodies, record):
        if doc_symbol != symbol:
            raise SystemExit(
                f"{GENERATOR}: {rel(ACCESSOR_RS)} documents `{doc_symbol}` where it defines "
                f"`{symbol}`; the two lists have drifted out of step"
            )
        if array != symbol.upper() + "_BYTES":
            raise SystemExit(
                f"{GENERATOR}: {rel(ACCESSOR_RS)} pairs `{symbol}` with `{array}`, and the "
                f"generated array is `{symbol.upper()}_BYTES`"
            )
        if source != r["source"]:
            raise SystemExit(
                f"{GENERATOR}: {rel(ACCESSOR_RS)} cites `{source}` for `{symbol}`, and "
                f"{BN_DH} defines it at `{r['source']}`"
            )


def check_against_artefact() -> int:
    """The weak tier: rebuild the generated Rust from the committed artefact.

    Used when the authority is absent, which is the case on every runner that has only
    the repository. It catches a hand-edited `dh_data.rs` and a JSON that has drifted
    from it. It cannot catch the authority having changed -- the authority is pinned by
    archive hash elsewhere, and the court, which has it, re-derives. Which tier ran is
    printed, because a check that silently weakens is the thing this project exists not
    to have.

    The *values* are not in the JSON, only their SHA-256, so the rebuild takes the bytes
    out of the committed Rust and re-hashes them: a byte changed in `dh_data.rs` then
    changes the digest and fails, which is the property that matters.
    """
    if not OUT_JSON.is_file() or not OUT_RS.is_file():
        print(
            f"[{GENERATOR}] neither the authority nor the pair "
            f"{rel(OUT_JSON)}/{rel(OUT_RS)} is present; nothing can be checked",
            file=sys.stderr,
        )
        return 1
    doc = json.loads(OUT_JSON.read_text(encoding="utf-8"))
    record = doc["body"]["constants"]
    rust = OUT_RS.read_text(encoding="utf-8")

    values: dict[str, bytes] = {}
    for r in record:
        name = r["symbol"].upper() + "_BYTES"
        # The renderer emits three shapes -- the declaration on one line, the initialiser
        # on a continuation line, and the items wrapped -- so the body is taken from the
        # `=` to the terminating `;` rather than from a `[` to a `]` on their own lines.
        # The declared length is checked with the bytes: a hand edit that changed the
        # `[u8; N]` and not the items would otherwise be caught only by the hash.
        m = re.search(
            rf"^pub\(crate\) const {re.escape(name)}: \[u8; (\d+)\]\s*=\s*(.*?);$",
            rust, re.M | re.S)
        if m is None:
            print(
                f"[{GENERATOR}] {rel(OUT_RS)} has no `{name}` array, which "
                f"{rel(OUT_JSON)} records as one of {len(record)} constants",
                file=sys.stderr,
            )
            return 1
        declared = int(m.group(1))
        values[r["symbol"]] = bytes(
            int(b, 16) for b in re.findall(r"0x([0-9A-Fa-f]{2})", m.group(2)))
        if (declared != r["bytes"]
                or len(values[r["symbol"]]) != r["bytes"]
                or hashlib.sha256(values[r["symbol"]]).hexdigest() != r["sha256"]):
            print(
                f"[{GENERATOR}] {name} in {rel(OUT_RS)} does not hash to the value "
                f"{rel(OUT_JSON)} records; the generated file was edited by hand or the "
                f"artefact is stale",
                file=sys.stderr,
            )
            return 1

    expected = render_rust(doc["authority"], record, values)
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

    check_accessor_table(record)
    print(
        f"[bn-dh] ok (weak tier, authority absent): {rel(OUT_RS)} matches "
        f"{rel(OUT_JSON)} over {len(record)} constants"
    )
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    bn_dh = auth.source / BN_DH
    # Two tiers, exactly as `gen_bn_primes.py` and `gen_err_raise_sites.py`: re-derive
    # when the authority is present, and rebuild-and-compare from the committed pair
    # when it is not. Which tier ran is printed.
    if not bn_dh.is_file() or not (auth.prefix / "include" / "openssl" / "dh.h").is_file():
        return check_against_artefact()

    record = parse_bn_dh(bn_dh.read_text(encoding="utf-8"))
    if not record:
        raise SystemExit(f"{GENERATOR}: {BN_DH} yielded no constants; the parser is stale")
    table = check_ffc_dh(auth.source, record)

    work = REPO_ROOT / "court" / "bn-dh"
    work.mkdir(parents=True, exist_ok=True)
    src = work / "bn_dh_probe.c"
    write_text(src, probe_source())

    binp = work / "bn_dh_probe"
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

    readback: dict[str, str] = {}
    for line in res.stdout.splitlines():
        if "=" not in line:
            continue
        key, _, raw = line.partition("=")
        if raw in ("NONE", "ALLOCFAIL"):
            raise SystemExit(f"{GENERATOR}: the authority answered {raw} for {key}")
        readback[key] = raw

    # Pair the read-back with the *table's* rows rather than with a list typed here: the
    # row says which constant each member is, so a table that named the wrong constant
    # would put the wrong value under the wrong array.
    readback_hex: dict[str, str] = {}
    for row in table:
        group, family = row["group"], row["family"]
        readback_hex[row["p"]] = readback[f"{group}_p"]
        readback_hex[row["q"]] = readback[f"{group}_q"]
        if family == "rfc5114":
            readback_hex[row["g"]] = readback[f"{group}_g"]
        elif readback[f"{group}_g"].strip().lstrip("0") != "2":
            raise SystemExit(
                f"{GENERATOR}: `{group}_g` is {readback[f'{group}_g']}; {FFC_DH} "
                f"points the whole FFDHE and MODP families at "
                f"`ossl_bignum_const_2`, which is 2"
            )
    readback_hex["ossl_bignum_const_2"] = readback["ffdhe2048_g"]

    # The two directions of the inventory check, before any value is trusted: the source
    # says which symbols exist and how wide each is; the library is asked for exactly
    # those and no more.
    expected = expected_symbols(record)
    if set(readback_hex) != set(expected):
        raise SystemExit(
            f"{GENERATOR}: the probe and {BN_DH} disagree about the constants:\n"
            f"  only read back: {sorted(set(readback_hex) - set(expected))}\n"
            f"  never read back: {sorted(set(expected) - set(readback_hex))}"
        )

    values: dict[str, bytes] = {}
    for r in record:
        raw = to_bytes(readback_hex[r["symbol"]], r["limbs"], r["symbol"])
        values[r["symbol"]] = raw
        r["bytes"] = len(raw)
        # The *value's* width, which is what `BN_num_bits` answers and what the unit test
        # in `src/bn/dh.rs` asserts. It is not `len(raw) * 8`: the arrays are the
        # authority's limb arrays, so `modp_1536_q` occupies 192 bytes and is 1535 bits,
        # and `const_2` occupies one limb and is 2 bits.
        r["bits"] = int.from_bytes(raw, "big").bit_length()
        r["sha256"] = hashlib.sha256(raw).hexdigest()

    # The table's own numbers, cross-checked against the read-back: a row's `nbits` is
    # the width of its `p`, and the whole point of recording it is that a reader can
    # compare the two without the authority.
    found = {r["symbol"]: r["bits"] for r in record}
    acquire = dict(GROUPS)
    for row in table:
        row["acquired_by"] = acquire[row["group"]]
        row["bits_p"] = found[row["p"]]
        row["bits_q"] = found[row["q"]]
        row["bits_g"] = found[row["g"]]
        if row["bits_p"] != row["nbits"]:
            raise SystemExit(
                f"{GENERATOR}: {FFC_DH} says {row['group']} is {row['nbits']} bits and "
                f"its `p` reads back as {row['bits_p']}"
            )

    write_text(OUT_RS, render_rust(auth.id, record, values))

    doc = envelope(
        kind="bn-dh",
        authority=auth.id,
        inputs=[
            InputRef(name="authority-symbols",
                     path=REPO_ROOT / "forensics" / "atlas" / auth.id
                     / "symbols-libcrypto.json"),
            InputRef(name="authority-source-bn-dh", path=bn_dh),
            InputRef(name="authority-source-ffc-dh", path=auth.source / FFC_DH),
        ],
        body={
            "constants": record,
            "named_groups": table,
            "checks": {
                "inventory_from": f"{BN_DH}'s `make_dh_bn` list plus `ossl_bignum_const_2`",
                "table_from": f"{FFC_DH}'s `dh_named_groups[]`, macros expanded",
                "values_from": "a probe linked against the admitted prefix, calling "
                               "`DH_new_by_nid`/`DH_get_1024_160` and `BN_bn2hex`",
                "inventory_matches_both_directions": True,
                "table_names_only_these_constants": True,
                "table_order_is_the_probe_order": True,
                "readback_fits_declared_limbs": True,
                "nbits_is_the_readback_width": True,
                "ffdhe_and_modp_g_is_const_2": True,
                "accessor_table_in_bn_dh_rs_matches": True,
            },
            "counts": {
                "constants": len(record),
                "limbs": sum(r["limbs"] for r in record),
                "bytes": sum(r["bytes"] for r in record),
                "named_groups": len(table),
            },
        },
        generator=GENERATOR,
    )
    write_json(OUT_JSON, doc)

    check_accessor_table(record)

    print(f"[bn-dh] authority={auth.id} constants={len(record)} "
          f"bytes={sum(r['bytes'] for r in record)} groups={len(table)}")
    for r in record:
        print(f"  {r['symbol']:<28} {r['bits']:>5} bits  {r['limbs']:>4} limbs  "
              f"sha256={r['sha256'][:16]}")
    print(f"  -> {rel(OUT_RS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
