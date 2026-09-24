#!/usr/bin/env python3
"""openssl-rs — derive `crypto/ml_dsa/ml_dsa_ntt.c`'s Montgomery zeta table from the authority.

Why this exists
---------------
`ml_dsa_ntt.c:47-80` is 256 `static const uint32_t` literals: `zetas_montgomery`, the
Montgomery-form powers of the 256th root of unity the forward and inverse NTT both read. The
*definition* is written in the file's own comment (`:37-46`) --

    zeta[k] = 1753^bitrev(k) mod q             for k = 1..255 (the first value is not used)
    zetasMontgomery[k] = reduce_montgomery(zeta[k] * (2^32 * 2^32 mod(q)))

with `q = ML_DSA_Q = 8380417` (from `ml_dsa_local.h`), the eight-bit `bitrev`, and
`reduce_montgomery()` written out in the same file (`:93-100`). That is the one thing this
project refuses to do with a constant another party defines (D33): transcribe it. A wrong zeta
is invisible to every test that does not compare against the authority itself, and these entries
are read by the NTT, the inverse NTT and the pointwise multiply, so a single wrong one silently
changes every public key, signature and verification.

The **values** are therefore re-derived here from that definition -- `bitrev` is the file's own
eight-bit reversal and `reduce_montgomery` is the file's own Montgomery reduction with
`R = 2^32` and `q^-1` read from `ml_dsa_local.h` -- and every one of the 256 entries is checked
against the literal the authority's source carries. The generator fails unless all 256 agree.

What is checked rather than assumed
-----------------------------------
* The definition line is read out of the file's comment and the shape pinned, so a definition
  this tool does not understand is a failure rather than a silently different table.
* `q` is taken from `ml_dsa_local.h`'s `#define ML_DSA_Q 8380417`, not typed, and required to
  equal 8380417 (FIPS 204's `2^23 - 2^13 + 1`).
* `q^-1` (the negation of `q`'s inverse mod `2^32`) is taken from `ml_dsa_local.h`'s
  `ML_DSA_Q_NEG_INV`, not typed.
* `bitrev` is the eight-bit reversal; its width is *measured* against the authority's literals:
  the derivation is checked with the eight-bit reversal and the tool fails if that disagrees.
* The declared array length must be 256 and every derived entry must equal the literal.

Usage (inside the court, which is where the authority source lives):

    python3 forensics/tools/gen_ml_dsa_tables.py

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import REPO_ROOT, InputRef, envelope, rel, resolve_authority, write_json  # noqa: E402

GENERATOR = "forensics/tools/gen_ml_dsa_tables.py"
SOURCE = "crypto/ml_dsa/ml_dsa_ntt.c"
HEADER = "crypto/ml_dsa/ml_dsa_local.h"
OUT = REPO_ROOT / "src" / "ml_dsa" / "tables.rs"
ATLAS = REPO_ROOT / "forensics" / "atlas" / "ml-dsa-tables.json"

# The base the roots are powers of, from the file's own comment (`ml_dsa_ntt.c:39`).
ROOT_BASE = 1753
# The table's declared length.
ENTRIES = 256


def bitrev(i: int) -> int:
    """The *eight*-bit reversal. The forward NTT's `zetas_montgomery[step + i]` index is built
    from `step` in `1, 2, 4, ..., 128`, so the table index is eight bits wide (`0..255`), which is
    what pins the reversal width. A seven-bit reversal gives a table the authority's literals
    refute, so this is a checked reading and not a guess."""
    ret = 0
    for _ in range(8):
        ret = (ret << 1) | (i & 1)
        i >>= 1
    return ret


def reduce_montgomery(a: int, q: int, q_inv: int) -> int:
    """`reduce_montgomery()` of `ml_dsa_ntt.c:93-100`, transcribed from the file's own body.

    The file takes `a` in `0..(2**32)*q`, forms `t = (uint32_t)a * (uint32_t)ML_DSA_Q_NEG_INV`,
    `b = a + t*q`, shifts `b >> 32` and reduces once. `ML_DSA_Q_NEG_INV` is the authority's own
    literal (the negation of `q`'s inverse mod `2**32`)."""
    t = ((a & 0xFFFFFFFF) * q_inv) & 0xFFFFFFFF
    b = a + t * q
    c = b >> 32
    return c if c < q else c - q


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.parse_args(argv)

    auth = resolve_authority("openssl-3.6.4-production")
    source = auth.source / SOURCE
    header = auth.source / HEADER
    text = source.read_text(encoding="utf-8")
    hdr = header.read_text(encoding="utf-8")

    # `q` and `q^-1` are read, not typed.
    m = re.search(r"#define\s+ML_DSA_Q\s+(\d+)", hdr)
    if m is None:
        raise SystemExit(f"{HEADER}: cannot find ML_DSA_Q")
    q = int(m.group(1))
    if q != 8380417:
        raise SystemExit(f"ML_DSA_Q resolved to {q}, not 8380417")
    m = re.search(r"#define\s+ML_DSA_Q_NEG_INV\s+(\d+)", hdr)
    if m is None:
        raise SystemExit(f"{HEADER}: cannot find ML_DSA_Q_NEG_INV")
    q_neg_inv = int(m.group(1))

    # The definition line, shape-pinned.
    m = re.search(r"zeta\[k\]\s*=\s*(\d+)\^bitrev\(k\)\s*mod\s*q", text)
    if m is None:
        raise SystemExit(f"{SOURCE}: cannot find the zeta[k] definition comment")
    if int(m.group(1)) != ROOT_BASE:
        raise SystemExit(f"{SOURCE}: the zeta base is {m.group(1)}, not {ROOT_BASE}")
    if re.search(r"zetasMontgomery\[k\]\s*=\s*reduce_montgomery\(zeta\[k\]\s*\*\s*\(2\^32\s*\*\s*2\^32\s*mod\(q\)\)\)", text) is None:
        raise SystemExit(f"{SOURCE}: the zetasMontgomery definition is not the shape this tool evaluates")

    # The literal, and the line it starts on.
    m = re.search(r"static const uint32_t zetas_montgomery\[\d+\] = \{(.*?)\n\};", text, re.S)
    if m is None:
        raise SystemExit(f"{SOURCE}: cannot find the zetas_montgomery initialiser")
    first = text[: m.start()].count("\n") + 1
    declared = re.search(r"static const uint32_t zetas_montgomery\[(\d+)\]", text)
    if declared is None or int(declared.group(1)) != ENTRIES:
        raise SystemExit(f"{SOURCE}: zetas_montgomery is not declared as {ENTRIES} entries")
    actual = [int(v, 10) for v in re.findall(r"\d+", m.group(1))]
    if len(actual) != ENTRIES:
        raise SystemExit(f"{SOURCE}: zetas_montgomery has {len(actual)} entries, not {ENTRIES}")

    # The multiplier is `(2^32 * 2^32) mod q`, computed in Python's unbounded integers and then
    # reduced mod q -- which is what the C's `(2^32)*(2^32) mod(q)` means for a 64-bit product.
    mont_r2 = pow(2, 64, q)
    derived = [reduce_montgomery((pow(ROOT_BASE, bitrev(k), q) * mont_r2) % (1 << 64), q, q_neg_inv)
               for k in range(ENTRIES)]

    if derived != actual:
        bad = [(i, d, a) for i, (d, a) in enumerate(zip(derived, actual)) if d != a]
        raise SystemExit(
            f"{SOURCE}: zetas_montgomery derived from `{ROOT_BASE}^bitrev8(k) * (2^32*2^32 mod q)` "
            f"differs from the authority's literal at {len(bad)} entr(ies), first {bad[0]}"
        )

    OUT.parent.mkdir(parents=True, exist_ok=True)
    body = [
        "//! Phase 8 — `crypto/ml_dsa/ml_dsa_ntt.c`'s Montgomery zeta table, **derived, not transcribed**.",
        "//!",
        "//! Generated by `forensics/tools/gen_ml_dsa_tables.py` from that file's own definition",
        "//! comment, re-derived independently in Python with the file's own eight-bit `bitrev` and",
        "//! `reduce_montgomery`, and checked entry for entry against the literal the authority's",
        "//! source carries. **Do not edit by hand.** The definition is",
        "//! ```text",
        f"//! zeta[k] = {ROOT_BASE}^bitrev(k) mod q                   for k = 1..255 (the first is not used)",
        "//! zetasMontgomery[k] = reduce_montgomery(zeta[k] * (2^32 * 2^32 mod(q)))",
        "//! ```",
        f"//! with `q = {q}` (`ml_dsa_local.h`'s `ML_DSA_Q`), `bitrev` eight bits wide, and",
        f"//! `q^-1 mod 2^32`'s negation `{q_neg_inv}` (`ML_DSA_Q_NEG_INV`).",
        "//!",
        "//! SPDX-License-Identifier: Apache-2.0",
        "",
        f"/// `zetas_montgomery` — `{SOURCE}:{first}`, {ENTRIES} entries.",
        "///",
        "/// `zetas_montgomery[k] = reduce_montgomery(1753^bitrev8(k) * (2^32 * 2^32 mod q))`.",
        "#[rustfmt::skip]",
        f"pub(crate) static ZETAS_MONTGOMERY: [u32; {ENTRIES}] = [",
    ]
    rows = []
    for i in range(0, len(derived), 8):
        rows.append("    " + " ".join(f"{v}," for v in derived[i : i + 8]))
    body.append("\n".join(rows))
    body += ["];", ""]
    OUT.write_text("\n".join(body), encoding="utf-8")

    inputs = [
        InputRef(name="source", path=source),
        InputRef(name="header", path=header),
    ]
    doc = envelope(
        kind="ml-dsa-tables",
        generator=GENERATOR,
        inputs=inputs,
        body={
            "claim": (
                "Every entry of `ml_dsa_ntt.c`'s 256-entry `zetas_montgomery` table is re-derived "
                "from the definition the file's own comment states and agrees with the literal the "
                "authority emits; nothing is transcribed."
            ),
            "q": q,
            "q_neg_inv": q_neg_inv,
            "root_base": ROOT_BASE,
            "mont_r2": mont_r2,
            "first_line": first,
            "entries": ENTRIES,
            "matches_authority": True,
            "out": rel(OUT),
        },
        authority=auth.id,
    )
    write_json(ATLAS, doc)

    print(
        f"[ml-dsa-tables] {ENTRIES} zeta entries re-derived and checked; "
        f"q={q} -> {rel(OUT)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
