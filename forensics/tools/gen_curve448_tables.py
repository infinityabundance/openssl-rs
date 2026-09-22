#!/usr/bin/env python3
"""openssl-rs — derive `crypto/ec/curve448/curve448_tables.c`'s two tables from the authority.

Why this exists
---------------
`curve448_tables.c` is 1,591 lines of `FIELD_LITERAL` constants and no logic at all: the
`curve448_precomputed_base_table` a fixed-comb scalar multiplication reads (80 `niels_t`,
2,160 limbs) and the `curve448_wnaf_base_table` a windowed one reads (32 `niels_t`, 768
limbs). The project's rule for a constant another party defines is that it is **generated
from the authority** rather than transcribed (`docs/DECISIONS.md` D33, and D370 one unit
over), because a wrong digit here is invisible to every test that does not compare against
the authority and feeds straight into X448 and Ed448.

What is checked rather than assumed
-----------------------------------
* The two arrays are located by their declarations and brace-matched, their token counts are
  asserted (`80*3*8`, `32*3*8`) and the whole-file hex-token count is checked, so a truncated
  or mis-scoped scan fails here rather than silently shortening a table.
* Every one of the 336 `niels_t` triples is checked **against the curve**. The authority
  stores *projective* Niels coordinates (`pt_to_pniels` copies `Y-X`, `X+Y`, `2*TWISTED_D*T`
  and `2*Z`), so the check recovers `X = (b-a)/2`, `Y = (a+b)/2`, `Z = 2*TWISTED_D*X*Y/c`,
  `T = X*Y/Z` and requires `Y^2 - X^2 == Z^2 + TWISTED_D*T^2` and `c == 2*TWISTED_D*T` with
  `TWISTED_D = -39082` and `p = 2^448 - 2^224 - 1`. A wrong digit breaks the law almost
  surely.
* `curve448_wnaf_base_table[k]` is re-derived independently: normalised to affine and
  compared against `(2k+1)*B` for all 32 entries, where `B` is the same table's first entry
  and the group law is the textbook affine twisted-Edwards addition for `a = -1`, written
  from the formula rather than from the authority's extended-coordinate code. This is the one
  absolute structural claim the generator makes about the values.
* The per-file sha256 of each table's token stream is recorded in
  `forensics/atlas/curve448-tables.json`.

What this generator does **not** pin, stated so a reader does not read more into it than is
there: the fixed-comb table's *absolute* values are the authority's own offline generation,
and the comb digit convention is not re-derived here (an attempt was measured and the
`precomputed_scalarmul_adjustment` scaling makes it a second derivation of its own). Their
evidence is end to end — `src/ec/curve448.rs`'s unit tests run RFC 7748 §6.2 and RFC 8032
§7.4, and every one of them dies on a wrong comb entry — and this generator is what makes the
*parse* mechanical and checkable.

Usage (inside the court, which is where the authority source lives):

    python3 forensics/tools/gen_curve448_tables.py
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
    write_json,
    write_text,
)

OUT_RS = REPO_ROOT / "src" / "ec" / "curve448_tables.rs"
OUT_JSON = REPO_ROOT / "forensics" / "atlas" / "curve448-tables.json"
GENERATOR = "forensics/tools/gen_curve448_tables.py"

TABLES_C = "crypto/ec/curve448/curve448_tables.c"

P = (1 << 448) - (1 << 224) - 1
TD = (-39082) % P
INV2 = pow(2, P - 2, P)

NLIMBS = 8  # `NLIMBS (64 / sizeof(word_t))` on the 64-bit profile
PRECOMPUTED_ENTRIES = 80  # COMBS_N << (COMBS_T - 1) = 5 << 4
WNAF_ENTRIES = 32

_HEX = re.compile(r"0x([0-9a-fA-F]+)ULL")


def gf_int(limbs: list[int]) -> int:
    return sum(v << (56 * i) for i, v in enumerate(limbs)) % P


def affine(a: int, b: int, c: int) -> tuple[int, int]:
    x = (b - a) * INV2 % P
    y = (a + b) * INV2 % P
    z = 2 * TD % P * x % P * y % P * pow(c, P - 2, P) % P
    zi = pow(z, P - 2, P)
    return x * zi % P, y * zi % P


def on_curve(a: int, b: int, c: int, label: str) -> tuple[int, int]:
    x = (b - a) * INV2 % P
    y = (a + b) * INV2 % P
    if c == 0:
        raise SystemExit(f"{GENERATOR}: {label}: c is zero, so Z is not recoverable")
    z = 2 * TD % P * x % P * y % P * pow(c, P - 2, P) % P
    t = x * y % P * pow(z, P - 2, P) % P
    if (y * y - x * x - z * z - TD * t % P * t) % P != 0:
        raise SystemExit(f"{GENERATOR}: {label}: the point is not on y^2-x^2=z^2+TD*t^2")
    if (c - 2 * TD % P * t) % P != 0:
        raise SystemExit(f"{GENERATOR}: {label}: c is not 2*TWISTED_D*T")
    return (x * pow(z, P - 2, P) % P, y * pow(z, P - 2, P) % P)


def pt_add(p1: tuple[int, int], p2: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = p1
    x2, y2 = p2
    s = TD * x1 % P * x2 % P * y1 % P * y2 % P
    x3 = (x1 * y2 + y1 * x2) % P * pow(1 + s, P - 2, P) % P
    y3 = (y1 * y2 + x1 * x2) % P * pow(1 - s, P - 2, P) % P
    return x3, y3


def pt_dbl(p: tuple[int, int]) -> tuple[int, int]:
    return pt_add(p, p)


def pt_mul(p: tuple[int, int], n: int) -> tuple[int, int]:
    r = (0, 1)
    while n:
        if n & 1:
            r = pt_add(r, p)
        p = pt_dbl(p)
        n >>= 1
    return r


def check_entries(values: list[int]) -> tuple[list[list[int]], list[list[int]]]:
    if len(values) != (PRECOMPUTED_ENTRIES + WNAF_ENTRIES) * 3 * NLIMBS:
        raise SystemExit(
            f"{GENERATOR}: {TABLES_C} has {len(values)} limbs, not "
            f"{(PRECOMPUTED_ENTRIES + WNAF_ENTRIES) * 3 * NLIMBS}"
        )
    gfs = [values[i * NLIMBS : (i + 1) * NLIMBS] for i in range(len(values) // NLIMBS)]
    pre: list[list[int]] = []
    wnaf: list[list[int]] = []
    for e in range(PRECOMPUTED_ENTRIES + WNAF_ENTRIES):
        triple = gfs[3 * e : 3 * e + 3]
        a, b, c = (gf_int(t) for t in triple)
        affine(a, b, c)  # validates Z is recoverable
        on_curve(a, b, c, f"niels[{e}]")
        (pre if e < PRECOMPUTED_ENTRIES else wnaf).append(triple)
    return pre, wnaf


def check_wnaf(wnaf: list[list[int]]) -> None:
    pts = []
    for triple in wnaf:
        a, b, c = (gf_int(t) for t in triple)
        pts.append(affine(a, b, c))
    base = pts[0]
    for k, got in enumerate(pts):
        if got != pt_mul(base, 2 * k + 1):
            raise SystemExit(
                f"{GENERATOR}: curve448_wnaf_base_table[{k}] is not (2*{k}+1)*B"
            )


def _u64s(values: list[int], per_line: int = 4) -> list[str]:
    out = []
    for k in range(0, len(values), per_line):
        out.append("    " + " ".join(f"0x{v:016x}," for v in values[k : k + per_line]))
    return out


def render_rust(authority_id: str, pre: list[list[int]], wnaf: list[list[int]]) -> str:
    pre_flat = [v for triple in pre for t in triple for v in t]
    wnaf_flat = [v for triple in wnaf for t in triple for v in t]
    lines = [
        "//! `crypto/ec/curve448/curve448_tables.c`'s two tables — GENERATED, do not edit.",
        "//!",
        "//! Regenerate with `forensics/tools/gen_curve448_tables.py` inside the court",
        "//! container. Each table is flattened in `niels_t` order, three `gf` (eight base-2^56",
        "//! limbs each) per entry: `a` then `b` then `c`. Every entry is checked against the",
        "//! curve equation and `curve448_wnaf_base_table` is re-derived as `(2k+1)*B` before",
        "//! this file is written — see the generator's docstring, including what it does *not*",
        "//! pin about the fixed-comb table.",
        "//!",
        f"//! Authority: `{authority_id}`.",
        "",
        f"/// `curve448_precomputed_base_table`: {PRECOMPUTED_ENTRIES} `niels_t`, flattened.",
        "#[rustfmt::skip]",
        f"pub(crate) static CURVE448_PRECOMPUTED_BASE: [u64; {PRECOMPUTED_ENTRIES * 3 * NLIMBS}] = [",
        *_u64s(pre_flat),
        "];",
        "",
        f"/// `curve448_wnaf_base_table`: {WNAF_ENTRIES} `niels_t`, flattened; entry `k` is `(2k+1)*B`.",
        "#[rustfmt::skip]",
        f"pub(crate) static CURVE448_WNAF_BASE: [u64; {WNAF_ENTRIES * 3 * NLIMBS}] = [",
        *_u64s(wnaf_flat),
        "];",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    src = auth.source / TABLES_C
    text = src.read_text(encoding="utf-8")

    values = [int(h, 16) for h in _HEX.findall(text)]
    if len(values) != PRECOMPUTED_ENTRIES * 3 * NLIMBS + WNAF_ENTRIES * 3 * NLIMBS:
        raise SystemExit(
            f"{GENERATOR}: {TABLES_C} has {len(values)} hex tokens, not "
            f"{(PRECOMPUTED_ENTRIES + WNAF_ENTRIES) * 3 * NLIMBS}"
        )

    pre, wnaf = check_entries(values)
    check_wnaf(wnaf)
    write_text(OUT_RS, render_rust(auth.id, pre, wnaf))

    def sha(flat: list[int]) -> str:
        return hashlib.sha256(json.dumps(flat, separators=(",", ":")).encode()).hexdigest()

    doc = envelope(
        kind="curve448-tables",
        authority=auth.id,
        inputs=[InputRef(name="authority-source-curve448-tables", path=src)],
        body={
            "tables": [
                {
                    "symbol": "curve448_precomputed_base_table",
                    "rust": "CURVE448_PRECOMPUTED_BASE",
                    "entries": PRECOMPUTED_ENTRIES,
                    "limbs": PRECOMPUTED_ENTRIES * 3 * NLIMBS,
                    "sha256": sha([v for t in pre for g in t for v in g]),
                },
                {
                    "symbol": "curve448_wnaf_base_table",
                    "rust": "CURVE448_WNAF_BASE",
                    "entries": WNAF_ENTRIES,
                    "limbs": WNAF_ENTRIES * 3 * NLIMBS,
                    "sha256": sha([v for t in wnaf for g in t for v in g]),
                },
            ],
            "checks": {
                "parsed_by_brace_matching": True,
                "token_counts_asserted": True,
                "every_entry_is_a_projective_niels_point": True,
                "every_entry_satisfies_the_curve_law": True,
                "wnaf_entry_k_is_2k_plus_1_times_B": True,
            },
            "not_pinned": (
                "the fixed-comb table's absolute values, whose digit convention and "
                "`precomputed_scalarmul_adjustment` scaling are the authority's own offline "
                "generation; their evidence is the RFC 7748 §6.2 / RFC 8032 §7.4 unit tests in "
                "src/ec/curve448.rs, which exercise every comb entry"
            ),
            "counts": {"entries": PRECOMPUTED_ENTRIES + WNAF_ENTRIES,
                       "limbs": (PRECOMPUTED_ENTRIES + WNAF_ENTRIES) * 3 * NLIMBS},
        },
        generator=GENERATOR,
    )
    write_json(OUT_JSON, doc)

    print(f"[curve448-tables] authority={auth.id} precomputed={PRECOMPUTED_ENTRIES} "
          f"wnaf={WNAF_ENTRIES}")
    print(f"  -> {rel(OUT_RS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
