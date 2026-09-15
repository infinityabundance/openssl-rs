#!/usr/bin/env python3
"""openssl-rs — generate the character-class table from the authority's own source.

Why this is generated rather than written
-----------------------------------------
`crypto/ctype.c` carries a 128-entry `unsigned short ctype_char_map[]` in which each
entry is the sum of the `CTYPE_MASK_*` classes that byte belongs to. `docs/DECISIONS.md`
D33 refuses a constant that is recalled rather than read, and Phase 5's `ctype.rs` says
so explicitly: it implemented only the one class its parsers needed, as a range test, and
recorded that transcribing 128 masks by hand would be exactly that defect.

A *generated* table is the opposite of a hand-copied one: it is derived from the
authority on every run, its derivation is a committed generator, and
`evidence_determinism.py` recomputes it and fails if the committed copy drifts. So when a
third caller — the property grammar, which needs `alpha`, `alnum` and `print` on top of
the `digit`, `xdigit` and `space` already in use — the table becomes the right answer
rather than six more range tests reasoned out by hand.

What it does not replace
------------------------
`src/runtime/ctype.rs` keeps its range-test implementations of `ossl_isdigit`,
`ossl_isxdigit`, `ossl_isascii`, `ossl_isspace` and `ossl_isasn1print`, because those are
verified by courts and a Phase 5 seal did not name them as an obligation to change. The
generated table is used for the classes this stratum adds, and a unit test asserts the
range tests and the table **agree for every byte value**, which turns "the range test
equals the authority's table" from an assertion into a check.

    python3 forensics/tools/gen_ctype_table.py            # write
    python3 forensics/tools/gen_ctype_table.py --check    # fail on drift

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
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

OUT_RS = REPO_ROOT / "src" / "runtime" / "ctype_table.rs"
OUT_JSON = REPO_ROOT / "forensics" / "atlas" / "ctype-table.json"
GENERATOR = "forensics/tools/gen_ctype_table.py"
SOURCE_REL = "crypto/ctype.c"
# The `#define CTYPE_MASK_*` lines are in the header, not the translation unit: the
# table in `ctype.c` is written in terms of names the header defines.
MASKS_REL = "include/crypto/ctype.h"

# The table is `unsigned short ctype_char_map[128]`, so every entry must fit. A mask
# that did not would mean the source format changed rather than the content.
ENTRY_COUNT = 128
MASK_LIMIT = 0x10000


def mask_constants(text: str) -> dict[str, int]:
    """The `#define CTYPE_MASK_<name> 0x...` lines, resolved.

    `CTYPE_MASK_alpha` and `CTYPE_MASK_alnum` are defined in terms of two others, so the
    resolution is iterated to a fixed point rather than done in one pass.
    """
    raw: dict[str, str] = {}
    for name, value in re.findall(
        r"^#define\s+(CTYPE_MASK_\w+)\s+([0-9A-Za-z_ |()~]+)$", text, re.MULTILINE
    ):
        raw[name] = value.strip()

    resolved: dict[str, int] = {}
    for _ in range(len(raw) + 1):
        changed = False
        for name, expr in raw.items():
            if name in resolved:
                continue
            translated = expr
            for other in sorted(raw, key=len, reverse=True):
                translated = re.sub(rf"\b{other}\b", str(resolved.get(other, "?")), translated)
            if "?" in translated:
                continue
            try:
                # The masks are `unsigned int` in C, so a definition such as
                # `CTYPE_MASK_ascii (~0)` is `0xFFFFFFFF` rather than -1. Truncating
                # to 32 bits here is what makes that the value rather than a negative
                # number that cannot be a `u32`.
                resolved[name] = eval(translated, {"__builtins__": {}}, {}) & 0xFFFFFFFF  # noqa: S307
            except (SyntaxError, TypeError, NameError):
                continue
            changed = True
        if not changed:
            break
    unresolved = sorted(set(raw) - set(resolved))
    if unresolved:
        raise SystemExit(f"{GENERATOR}: unresolved mask constant(s): {unresolved}")
    return resolved


def table_entries(text: str, masks: dict[str, int]) -> list[int]:
    """The 128 initialiser entries, in source order.

    Each entry begins with a `/* NN xxx */` comment and then one or more lines of
    `|`-separated mask names — **an entry is not a line**: the authority wraps a long
    sum onto a continuation line, so the parser accumulates until the next comment.
    The first version of this generator read one line per entry, which silently
    dropped every mask after the first line: `'0'` came out as
    `digit | graph | print` with no `xdigit`, and the `xdigit` class looked empty.
    The comment is checked against the position, because a table whose comments
    disagree with its order is a table nobody can read.
    """
    body = text.split("ctype_char_map[128] = {", 1)
    if len(body) != 2:
        raise SystemExit(f"{GENERATOR}: the table initialiser is not where it was")
    body = body[1].split("};", 1)[0]

    entries: list[int] = []
    pending: list[str] = []

    def flush() -> None:
        if not pending:
            return
        index = len(entries)
        value = 0
        for name in pending:
            if name not in masks:
                raise SystemExit(f"{GENERATOR}: unknown mask `{name}` at entry {index:02X}")
            value |= masks[name]
        entries.append(value)

    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.match(r"/\*\s*([0-9A-Fa-f]{2})\s", line)
        if m is not None:
            # A new entry: the previous one is complete.
            flush()
            pending = []
            if int(m.group(1), 16) != len(entries):
                raise SystemExit(
                    f"{GENERATOR}: entry {len(entries)} is commented as "
                    f"{int(m.group(1), 16):02X}"
                )
            rhs = line.split("*/", 1)[1]
        else:
            # A continuation line, which starts with the separator.
            if not line.startswith("|"):
                continue
            rhs = line
        for name in rhs.strip().rstrip(",").split("|"):
            name = name.strip()
            if name:
                pending.append(name)
    flush()

    if len(entries) != ENTRY_COUNT:
        raise SystemExit(
            f"{GENERATOR}: {len(entries)} entries, expected {ENTRY_COUNT}"
        )
    for i, v in enumerate(entries):
        if not 0 <= v < MASK_LIMIT:
            raise SystemExit(f"{GENERATOR}: entry {i:02X} = {v} does not fit the type")
    return entries


def classes(masks: dict[str, int], entries: list[int]) -> dict[str, list[int]]:
    """For each class used in C, the byte values that satisfy it.

    This is the *observable* form of the table: `ossl_ctype_check(c, mask)` is true
    exactly for these values, which is what the unit test checks the range tests against.
    """
    used = ["digit", "xdigit", "space", "alpha", "alnum", "print", "cntrl", "punct",
            "graph", "blank", "lower", "upper", "base64", "asn1print"]
    out: dict[str, list[int]] = {}
    for name in used:
        mask = masks[f"CTYPE_MASK_{name}"]
        out[name] = [i for i, v in enumerate(entries) if v & mask]
    return out


def rust_source(masks: dict[str, int], entries: list[int]) -> str:
    lines = [
        "//! Generated by `forensics/tools/gen_ctype_table.py` — do not edit.",
        "//!",
        f"//! From `{SOURCE_REL}`: the authority's own `ctype_char_map[128]`, read out of",
        "//! its committed source on every run. `docs/DECISIONS.md` D33 refuses a",
        "//! constant that is recalled rather than derived; this is the derived form, and",
        "//! `evidence_determinism.py` recomputes it and fails on drift.",
        "//!",
        "//! SPDX-License-Identifier: Apache-2.0",
        "",
        "/// `CTYPE_MASK_*` — `include/crypto/ctype.h`.",
        "#[allow(dead_code)] // every class the profile's C uses is defined, not only the ones this crate calls",
        "pub(crate) mod mask {",
    ]
    for name in sorted(masks):
        short = name.replace("CTYPE_MASK_", "MASK_").upper()
        lines.append(f"    pub(crate) const {short}: u32 = {masks[name]:#x};")
    lines.append("}")
    lines.append("")
    lines.append("/// `static const unsigned short ctype_char_map[128]`.")
    lines.append(
        "#[allow(dead_code)] // read through `ossl_ctype_check`, which the property grammar calls"
    )
    lines.append("pub(crate) const CTYPE_CHAR_MAP: [u32; 128] = [")
    for i in range(0, ENTRY_COUNT, 8):
        row = ", ".join(f"{entries[j]:#06x}" for j in range(i, i + 8))
        lines.append(f"    {row}, // {i:02X}-{i + 7:02X}")
    lines.append("];")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument("--check", action="store_true", help="do not write; fail on drift")
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    src = auth.source / SOURCE_REL
    masks_src = auth.source / MASKS_REL
    for p in (src, masks_src):
        if not p.is_file():
            raise SystemExit(f"{GENERATOR}: missing {rel(p)}")

    masks = mask_constants(masks_src.read_text(encoding="utf-8"))
    text = src.read_text(encoding="utf-8")

    entries = table_entries(text, masks)
    by_class = classes(masks, entries)
    rust = rust_source(masks, entries)

    if args.check:
        if not OUT_RS.is_file() or OUT_RS.read_text(encoding="utf-8") != rust:
            print(f"[ctype-table] {rel(OUT_RS)} has drifted from the authority")
            return 1
        print(f"[ctype-table] ok: {rel(OUT_RS)} matches the authority's table")
        return 0

    OUT_RS.parent.mkdir(parents=True, exist_ok=True)
    OUT_RS.write_text(rust, encoding="utf-8")

    doc = envelope(
        kind="ctype-table",
        authority=auth.id,
        generator=GENERATOR,
        inputs=[
            InputRef(name="authority-source", path=src),
            InputRef(name="authority-header", path=masks_src),
        ],
        body={
            "source": SOURCE_REL,
            "entries": ENTRY_COUNT,
            "mask_constants": {k: v for k, v in sorted(masks.items())},
            "members": {k: v for k, v in sorted(by_class.items())},
            "claim": (
                "The table and the class memberships are read out of the authority's "
                "committed source. They are a transcription aid, not a parity claim: "
                "what is claimed is that this crate's character predicates agree with "
                "the authority's table, which the unit test checks for every byte value."
            ),
        },
    )
    write_json(OUT_JSON, doc)

    print(f"[ctype-table] {len(masks)} mask constants, {len(entries)} entries")
    for name in ("digit", "xdigit", "space", "alpha", "alnum", "print"):
        print(f"  {name:<9} {len(by_class[name]):>3} byte(s)")
    print(f"  -> {rel(OUT_RS)}")
    print(f"  -> {rel(OUT_JSON)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
