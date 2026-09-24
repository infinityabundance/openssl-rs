#!/usr/bin/env python3
"""openssl-rs — derive `crypto/ml_kem/ml_kem.c`'s three NTT root tables from the authority.

Why this exists
---------------
`ml_kem.c:261-668` is 410 lines of `static const uint16_t` literal data: `kNTTRoots`,
`kInverseNTTRoots` and `kModRoots`, 128 entries each. Their *definition* is written in the
file's own comments --

    kNTTRoots = [pow(17, bitreverse(i), p) for i in range(128)]
    InverseNTTRoots = [pow(17, -bitreverse(i), p) for i in range(128)]
    ModRoots = [pow(17, 2*bitreverse(i) + 1, p) for i in range(128)]

with `p = 3329` and the seven-bit `bitreverse` also written out in the file (`:243-255`) --
which is the one thing this project refuses to do with a constant another party defines (D33):
transcribe it. A wrong root is invisible to every test that does not compare against the
authority itself, and these roots are read by the NTT, the inverse NTT and the multiplication
in `R_q`, so a single wrong entry silently changes every public key, ciphertext and shared
secret. So the **values** are re-derived here from that definition, and the derivation is
checked against the literals the authority's own source carries: the generator fails unless
every one of the 384 entries agrees.

What is checked rather than assumed
-----------------------------------
* Each array's *definition line* is read out of `ml_kem.c`'s comments and evaluated, not
  restated. The regex pins the shape (`pow(17, <exponent>, p) for i in range(128)`), so a
  definition the generator does not understand is a failure rather than a silently different
  table.
* `bitreverse` is evaluated with the file's own seven-bit loop, transcribed from `:246-254`.
* `p` is taken from the file's `#define ML_KEM_PRIME (ML_KEM_DEGREE * 13 + 1)` with
  `ML_KEM_DEGREE` read from `crypto/ml_kem.h`, not typed.
* Every derived list is compared **element for element** with the array literal the authority
  emits, and the array's declared length must be 128.
* The three arrays are written in the order `ml_kem.c` declares them, with each entry's line
  `ml_kem.c` puts it on, so a reader can recheck a value against the file it came from.

Usage (inside the court, which is where the authority source lives):

    python3 forensics/tools/gen_ml_kem_tables.py

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import REPO_ROOT, InputRef, envelope, rel, resolve_authority, write_json  # noqa: E402

GENERATOR = "forensics/tools/gen_ml_kem_tables.py"
SOURCE = "crypto/ml_kem/ml_kem.c"
HEADER = "include/crypto/ml_kem.h"
OUT = REPO_ROOT / "src" / "ml_kem" / "tables.rs"
ATLAS = REPO_ROOT / "forensics" / "atlas" / "ml-kem-tables.json"

# The three arrays, in the order `ml_kem.c` declares them: the comment that defines each, and how
# its indices are ordered. `natural` means entry `i` is the root for the seven-bit bit-reversal of
# `i`; `use-order` means the array is listed in the order the inverse NTT's loop consumes it, which
# the file's own comment spells out (`ml_kem.c:392-396`): `0, 64, 65, ..., 127, 32, 33, ..., 63,
# 16, 17, ..., 31, 8, 9, ...` -- index 0 unused, then the halves `[64,128)`, `[32,64)`, `[16,32)`,
# `[8,16)`, `[4,8)`, `[2,4)` and finally the singleton `1`. That reconstruction is checked entry for
# entry against the literal below, so a wrong reading of the comment is a failure and not a table.
ARRAYS = [
    ("kNTTRoots", "KNTT_ROOTS", r"kNTTRoots\s*=\s*(\[.*?\])", "natural"),
    ("kInverseNTTRoots", "KINVERSE_NTT_ROOTS", r"InverseNTTRoots\s*=\s*(\[.*?\])", "use-order"),
    ("kModRoots", "KMOD_ROOTS", r"ModRoots\s*=\s*(\[.*?\])", "natural"),
]


def bitreverse(i: int) -> int:
    """The seven-bit reversal, transcribed from `ml_kem.c:246-254`."""
    ret = 0
    for _ in range(7):
        bit = i & 1
        ret <<= 1
        ret |= bit
        i >>= 1
    return ret


def read_u16_array(text: str, name: str) -> tuple[list[int], int]:
    """The `static const uint16_t <name>[128] = { ... };` initialiser, and its first line."""
    m = re.search(
        rf"static const uint16_t {name}\[128\] = \{{(.*?)\n\}};", text, re.S
    )
    if m is None:
        raise SystemExit(f"{SOURCE}: cannot find the {name} initialiser")
    first = text[: m.start()].count("\n") + 1
    values = [int(v, 10) for v in re.findall(r"\d+", m.group(1))]
    if len(values) != 128:
        raise SystemExit(f"{SOURCE}: {name} has {len(values)} entries, not 128")
    return values, first


def definition(text: str, pattern: str, name: str) -> str:
    """The comment-defined Python expression for one array, checked for the shape we evaluate."""
    m = re.search(pattern, text)
    if m is None:
        raise SystemExit(f"{SOURCE}: cannot find the definition comment for {name}")
    expr = m.group(1)
    if not re.fullmatch(
        r"\[pow\(17, (-)?(?:\d+\s*\*\s*)?bitreverse\(i\)(?:\s*\+\s*1)?, p\) for i in range\(128\)\]",
        expr,
    ):
        raise SystemExit(f"{SOURCE}: {name}'s definition is not the shape this tool evaluates: {expr}")
    return expr


def use_order_index(order: str, i: int, degree: int) -> int:
    """The root index array position `i` holds, for the two orderings the file uses.

    `natural` is the identity: entry `i` is the root for `bitreverse(i)`. `use-order` is the inverse
    NTT loop's own consumption order, reconstructed from the block pattern `ml_kem.c:392-396`
    states: `0`, then the halves `[DEGREE/4, DEGREE/2)`, `[DEGREE/8, DEGREE/4)`, ... down to
    `[2, 4)`, then `1`. It is checked against the authority's literals, so this reading being wrong
    is a failure rather than a silently different table.
    """
    if order == "natural":
        return i
    seq = [0]
    half = degree // 4
    while half >= 2:
        seq.extend(range(half, 2 * half))
        half //= 2
    seq.append(1)
    if len(seq) != 128:
        raise SystemExit(f"the use-order reconstruction gave {len(seq)} entries, not 128")
    return seq[i]


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.parse_args(argv)

    auth = resolve_authority("openssl-3.6.4-production")
    source = auth.source / SOURCE
    header = auth.source / HEADER
    text = source.read_text(encoding="utf-8")
    hdr = header.read_text(encoding="utf-8")

    # `p` is read, not typed: `ML_KEM_PRIME` is `(ML_KEM_DEGREE * 13 + 1)` and `ML_KEM_DEGREE`
    # is the header's own `256`.
    m = re.search(r"#define\s+ML_KEM_DEGREE\s+(\d+)", hdr)
    if m is None:
        raise SystemExit(f"{HEADER}: cannot find ML_KEM_DEGREE")
    degree = int(m.group(1))
    m = re.search(r"#define\s+ML_KEM_PRIME\s+\(ML_KEM_DEGREE \* (\d+) \+ 1\)", hdr)
    if m is None:
        raise SystemExit(f"{HEADER}: cannot find ML_KEM_PRIME")
    p = degree * int(m.group(1)) + 1
    if p != 3329:
        raise SystemExit(f"ML_KEM_PRIME resolved to {p}, not 3329")

    entries: list[tuple[str, str, list[int], str, int, str]] = []
    for name, rust_name, pattern, order in ARRAYS:
        expr = definition(text, pattern, name)
        fn = eval(expr, {"pow": pow, "bitreverse": bitreverse, "p": p, "range": range})  # noqa: S307
        if order == "natural":
            derived = fn
        else:
            # `fn[i]` is the root for the *i-th* natural index, and the array is that list read in
            # the loop's consumption order.
            derived = [fn[use_order_index(order, i, degree)] for i in range(128)]
        actual, first = read_u16_array(text, name)
        if derived != actual:
            bad = [(i, d, a) for i, (d, a) in enumerate(zip(derived, actual)) if d != a]
            raise SystemExit(
                f"{SOURCE}: {name} derived from `{expr}` ({order}) differs from the authority's "
                f"literal at {len(bad)} entr(ies), first {bad[0]}"
            )
        if order == "use-order" and sorted(fn) != sorted(derived):
            raise SystemExit(f"{SOURCE}: {name}'s use order is not a permutation of its roots")
        entries.append((name, rust_name, derived, expr, first, order))

    OUT.parent.mkdir(parents=True, exist_ok=True)
    body = [
        "//! Phase 8 — `crypto/ml_kem/ml_kem.c`'s three NTT root tables, **derived, not transcribed**.",
        "//!",
        "//! Generated by `forensics/tools/gen_ml_kem_tables.py` from that file's own definition",
        "//! comments, re-derived independently in Python and checked entry for entry against the",
        "//! literals the authority's source carries. **Do not edit by hand.** The definitions are",
        "//! ```text",
    ]
    for name, _rust, _values, expr, _first, order in entries:
        body.append(f"//! {name} ({order}) = {expr}")
    body += [
        f"//! ```",
        f"//! with `p = {p}` and the seven-bit `bitreverse` of the file's own loop. `kInverseNTTRoots`",
        "//! is listed in the order the inverse NTT consumes it, which the file's comments state.",
        "//!",
        "//! SPDX-License-Identifier: Apache-2.0",
        "",
        "/// `ML_KEM_PRIME` — `crypto/ml_kem.h`, `(ML_KEM_DEGREE * 13 + 1)`.",
        f"pub(crate) const ML_KEM_PRIME: u32 = {p};",
        "",
    ]
    for name, rust_name, values, expr, first, order in entries:
        rows = []
        for i in range(0, len(values), 8):
            rows.append("    " + " ".join(f"{v}," for v in values[i : i + 8]))
        body += [
            f"/// `{name}` — `{SOURCE}:{first}`, `{expr}` ({order}).",
            "#[rustfmt::skip]",
            f"pub(crate) static {rust_name}: [u16; {len(values)}] = [",
            "\n".join(rows),
            "];",
            "",
        ]
    OUT.write_text("\n".join(body), encoding="utf-8")

    inputs = [
        InputRef(name="source", path=source),
        InputRef(name="header", path=header),
    ]
    doc = envelope(
        kind="ml-kem-tables",
        generator=GENERATOR,
        inputs=inputs,
        body={
            "claim": (
                "Every entry of `ml_kem.c`'s three 128-entry NTT root tables is re-derived from the "
                "definition the file's own comments state and agrees with the literal the authority "
                "emits; nothing is transcribed."
            ),
            "prime": p,
            "degree": degree,
            "arrays": [
                {
                    "name": name,
                    "rust_name": rust_name,
                    "definition": expr,
                    "ordering": order,
                    "first_line": first,
                    "entries": len(values),
                    "matches_authority": True,
                }
                for name, rust_name, values, expr, first, order in entries
            ],
            "out": rel(OUT),
        },
        authority=auth.id,
    )
    write_json(ATLAS, doc)

    print(
        f"[ml-kem-tables] {len(entries)} array(s), "
        f"{sum(len(v) for _n, _r, v, _e, _f, _o in entries)} entries re-derived and checked; "
        f"p={p} -> {rel(OUT)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
