#!/usr/bin/env python3
"""openssl-rs — derive `crypto/ec/curve25519.c`'s two precomputed tables from the authority.

Why this exists
---------------
`crypto/ec/curve25519.c`'s `k25519Precomp[32][8]` is 7,680 limbs — the base-point
multiples `(j+1)*256^i*B` the Ed25519 base-point scalar multiplication reads — and its
`Bi[8]` is a further 240. Together they are 2,364 lines of a 5,879-line file. The project's
rule for a constant another party defines is that it is **generated from the authority**
rather than transcribed (`docs/DECISIONS.md` D33, and the generators that already do this:
`gen_bn_dh.py`, `gen_ec_curves.py`, `gen_phase8_tables.py`). A typo in one of these limbs is
invisible to every test that does not compare against the authority, and
`ge_scalarmult_base` feeds the table straight into an Ed25519 signing key.

What is checked rather than assumed
-----------------------------------
* The two arrays are located by their declarations and brace-matched, and the extracted
  token counts are asserted (`32*8*30` and `8*30`) so a truncated or mis-scoped scan fails
  here rather than silently shortening the table.
* Every one of the 264 `ge_precomp` entries is checked **against the curve**, in Python,
  from its own three field elements: with `d = -121665/121666 mod 2^255-19`, entry
  `(yplusx, yminusx, xy2d)` must satisfy `x = (yplusx-yminusx)/2`, `y = (yplusx+yminusx)/2`,
  `xy2d == 2*d*x*y`, and `-x^2 + y^2 == 1 + d*x^2*y^2`. A wrong digit breaks the equation
  almost surely, so this is what makes the parse trusted.
* `k25519Precomp[i][j]` is then checked **against the group itself**: `B` is the Ed25519
  base point with `y = 4/5` and the even `x`, and each entry must equal `(j+1)*256^i*B`
  computed independently in Python with Edwards extended-coordinate addition. `Bi[j]` must
  equal `(j+1)*B`. This is the independent derivation, not a re-reading of the source.

Usage (inside the court, which is where the authority source lives):

    python3 forensics/tools/gen_curve25519_tables.py
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

OUT_RS = REPO_ROOT / "src" / "ec" / "curve25519_data.rs"
OUT_JSON = REPO_ROOT / "forensics" / "atlas" / "curve25519-tables.json"
GENERATOR = "forensics/tools/gen_curve25519_tables.py"

CURVE25519 = "crypto/ec/curve25519.c"

# `p = 2^255 - 19`, and `d = -121665/121666 mod p`.
P = (1 << 255) - 19
D = (-121665 * pow(121666, P - 2, P)) % P
INV2 = pow(2, P - 2, P)

# The `fe` limbs are base 2^25.5: limb `i` carries weight `2^ceil(25.5*i)`, i.e. the
# exponents `0, 26, 51, 77, 102, 128, 153, 179, 204, 230`.
FE_OFFSETS = [0, 26, 51, 77, 102, 128, 153, 179, 204, 230]

_INT = re.compile(r"-?\d+")


def extract_array(text: str, decl: str) -> list[int]:
    """The integer tokens of the initializer of the array `decl` names."""
    m = re.search(
        r"^static const [A-Za-z0-9_ ]+ " + re.escape(decl) + r"(\[[^\]]*\])*\s*=\s*\{",
        text,
        re.M,
    )
    if m is None:
        raise SystemExit(f"{GENERATOR}: cannot find {decl} in {CURVE25519}")
    start = text.index("{", m.start())
    depth = 0
    end = None
    for i in range(start, len(text)):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end is None:
        raise SystemExit(f"{GENERATOR}: unbalanced braces for {decl}")
    return [int(t) for t in _INT.findall(text[start : end + 1])]


def limbs_to_int(limbs: list[int]) -> int:
    return sum(v << FE_OFFSETS[i] for i, v in enumerate(limbs)) % P


# --- the group, over the same field, in Python ------------------------------------------------
#
# Affine twisted Edwards arithmetic for `-x^2 + y^2 = 1 + d x^2 y^2` (`a = -1`), which is the
# textbook law and therefore *independent* of the authority's extended-coordinate formulas.


def affine_add(p1, p2):
    x1, y1 = p1
    x2, y2 = p2
    t = D * x1 % P * x2 % P * y1 % P * y2 % P
    x3 = (x1 * y2 + y1 * x2) % P * pow(1 + t, P - 2, P) % P
    y3 = (y1 * y2 + x1 * x2) % P * pow(1 - t, P - 2, P) % P
    return x3, y3


def affine_dbl(p1):
    return affine_add(p1, p1)


def base_point():
    """`B`: `y = 4/5` with the even `x` (the `fe_isnegative(x) == 0` root)."""
    y = 4 * pow(5, P - 2, P) % P
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = x * pow(2, (P - 1) // 4, P) % P
    if (x * x - xx) % P != 0:
        raise SystemExit(f"{GENERATOR}: the base point's x does not exist")
    if x & 1:
        x = (P - x) % P
    return x, y


B = base_point()


def check_entry(entry: list[int], label: str) -> tuple[int, int, int]:
    yplusx, yminusx, xy2d = (limbs_to_int(entry[i * 10 : i * 10 + 10]) for i in range(3))
    y = (yplusx + yminusx) * INV2 % P
    x = (yplusx - yminusx) * INV2 % P
    if (xy2d - 2 * D % P * x % P * y) % P != 0:
        raise SystemExit(f"{GENERATOR}: {label}: xy2d is not 2*d*x*y")
    if (-x * x + y * y - 1 - D * x * x % P * y % P * y) % P != 0:
        raise SystemExit(f"{GENERATOR}: {label}: the point is not on -x^2+y^2=1+d*x^2*y^2")
    return x, y


def check_precomp(values: list[int]) -> None:
    if len(values) != 32 * 8 * 30:
        raise SystemExit(
            f"{GENERATOR}: k25519Precomp has {len(values)} tokens, not {32 * 8 * 30}"
        )
    p = B
    for i in range(32):
        for j in range(8):
            entry = values[(i * 8 + j) * 30 : (i * 8 + j + 1) * 30]
            x, y = check_entry(entry, f"k25519Precomp[{i}][{j}]")
            # `(j+1)*p`, from `p` itself, by repeated affine addition.
            q = p
            for _ in range(j):
                q = affine_add(q, p)
            if (x, y) != q:
                raise SystemExit(
                    f"{GENERATOR}: k25519Precomp[{i}][{j}] is not (j+1)*256^{i}*B"
                )
        # `256*p` for the next table row: eight doublings.
        for _ in range(8):
            p = affine_dbl(p)


def check_bi(values: list[int]) -> None:
    if len(values) != 8 * 30:
        raise SystemExit(f"{GENERATOR}: Bi has {len(values)} tokens, not {8 * 30}")
    q = B
    for j in range(8):
        entry = values[j * 30 : (j + 1) * 30]
        x, y = check_entry(entry, f"Bi[{j}]")
        if (x, y) != q:
            raise SystemExit(f"{GENERATOR}: Bi[{j}] is not (2*{j}+1)*B")
        q = affine_add(q, affine_dbl(B))


def _ints(values: list[int], per_line: int = 10) -> list[str]:
    out = []
    for k in range(0, len(values), per_line):
        out.append("    " + " ".join(f"{v}," for v in values[k : k + per_line]))
    return out


def render_rust(authority_id: str, precomp: list[int], bi: list[int]) -> str:
    lines = [
        "//! `crypto/ec/curve25519.c`'s precomputed tables — GENERATED, do not edit.",
        "//!",
        "//! Regenerate with `forensics/tools/gen_curve25519_tables.py` inside the court",
        "//! container. `K25519_PRECOMP` is the authority's `k25519Precomp[32][8]` flattened",
        "//! (`256 * 30` field elements, entry `i*8+j` is `(j+1)*256^i*B`) and `BI` is its",
        "//! `Bi[8]` (`8 * 30`, entry `j` is `(2j+1)*B`); each entry is three `fe` values,",
        "//! `yplusx` then `yminusx` then `xy2d`, in the base-2^25.5 limb order (weights",
        "//! `2^ceil(25.5*i)`). Every entry is checked against the curve equation and against an",
        "//! independent Python scalar multiplication before this file is written — see the",
        "//! generator's docstring.",
        "//!",
        f"//! Authority: `{authority_id}`.",
        "",
        "/// `k25519Precomp[32][8]`, flattened: entry `i*8+j` is `(j+1)*256^i*B` — `curve25519.c:2206`.",
        "#[rustfmt::skip]",
        f"pub(crate) static K25519_PRECOMP: [i32; {32 * 8 * 30}] = [",
        *_ints(precomp),
        "];",
        "",
        "/// `Bi[8]`: entry `j` is `(2j+1)*B` — `curve25519.c:4618`.",
        "#[rustfmt::skip]",
        f"pub(crate) static BI: [i32; {8 * 30}] = [",
        *_ints(bi),
        "];",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    src = auth.source / CURVE25519
    text = src.read_text(encoding="utf-8")

    precomp = extract_array(text, "k25519Precomp")
    bi = extract_array(text, "Bi")

    check_precomp(precomp)
    check_bi(bi)

    write_text(OUT_RS, render_rust(auth.id, precomp, bi))

    doc = envelope(
        kind="curve25519-tables",
        authority=auth.id,
        inputs=[InputRef(name="authority-source-curve25519", path=src)],
        body={
            "tables": [
                {
                    "symbol": "k25519Precomp",
                    "rust": "K25519_PRECOMP",
                    "shape": [32, 8],
                    "entries": 256,
                    "limbs": len(precomp),
                    "definition": "(j+1)*256^i*B, three fe per entry",
                    "sha256": hashlib.sha256(
                        json.dumps(precomp, separators=(",", ":")).encode()
                    ).hexdigest(),
                },
                {
                    "symbol": "Bi",
                    "rust": "BI",
                    "shape": [8],
                    "entries": 8,
                    "limbs": len(bi),
                    "definition": "(2j+1)*B, three fe per entry",
                    "sha256": hashlib.sha256(
                        json.dumps(bi, separators=(",", ":")).encode()
                    ).hexdigest(),
                },
            ],
            "checks": {
                "parsed_by_brace_matching": True,
                "token_counts_asserted": True,
                "every_entry_on_the_curve": True,
                "every_entry_xy2d_is_2dxy": True,
                "every_entry_equals_independent_python_scalarmult": True,
            },
            "counts": {"entries": 264, "limbs": len(precomp) + len(bi)},
        },
        generator=GENERATOR,
    )
    write_json(OUT_JSON, doc)

    print(f"[curve25519-tables] authority={auth.id} precomp={len(precomp)} bi={len(bi)}")
    print(f"  -> {rel(OUT_RS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
