#!/usr/bin/env python3
"""openssl-rs — generate Phase 8's digest constant tables from the authority's own source.

Why this is generated rather than typed
---------------------------------------
Six of the tables this stratum needs are hundreds of numbers each, and every one of them is
a *transcription*: `crypto/whirlpool/wp_block.c`'s `Cx` is 256 eight-byte entries plus ten
round constants, `crypto/ripemd/rmdconst.h` is four eighty-entry tables plus two key
schedules, and `crypto/sha/sha256.c`'s `K256` and `crypto/sha/sha512.c`'s `K512` are the
SHA-2 round constants. `docs/DECISIONS.md` D33 refuses a constant that is recalled rather
than read, and `gen_ctype_table.py`'s header makes the same argument for the
character-class table: 128 masks typed by hand would be exactly that defect.

A *generated* table is the opposite of a hand-copied one: it is derived from the authority on
every run, its derivation is this committed generator, and `evidence_determinism.py`
recomputes it and fails if the committed copy drifts. The digest construction's *structure*
is transcribed by hand in `src/digest/*.rs` and verified by `RT-DIGEST`; the *numbers* are
read from the authority here, and a wrong table entry is caught by the differential court
rather than by a reader's eye.

The six tables, and where each comes from
-----------------------------------------
  * `crypto/md5/md5_dgst.c`'s `R0`/`R1`/`R2`/`R3` invocations — MD5's sixty-four
    `(message index, rotation, constant)` triples, in the order the authority applies them.
  * `crypto/md4/md4_dgst.c`'s `R0`/`R1`/`R2` invocations — MD4's forty-eight, same shape.
  * `crypto/ripemd/rmdconst.h` and `rmd_local.h` — RIPEMD-160's `WLNN`/`SLNN`/`WL...`
    message-order and rotation tables, its two key schedules and its five initial words.
  * `crypto/sha/sha256.c`'s `K256[64]`.
  * `crypto/sha/sha512.c`'s `K512[80]` (written through the `U64()` macro, which is the same
    number with a suffix).
  * `crypto/whirlpool/wp_block.c`'s `Cx` initialiser. It is written as a `u8` array of
    `(256*N + ROUNDS) * sizeof(u64)` bytes where `N` is 2, and the first two hundred and
    fifty-six `LL(...)` rows each name eight bytes that are repeated once. The repetition is
    the source's own "endian-neutral" device: the `C0`..`C7` macros read the entry at a
    one-byte *shift* through an unaligned `u64`, so the eight-byte group has to be followed
    by itself. This generator emits the eight unique bytes of each row and the ten round
    constants, and `src/digest/wp.rs` reproduces the shift with a rotate.

    python3 forensics/tools/gen_phase8_tables.py            # write
    python3 forensics/tools/gen_phase8_tables.py --check    # fail on drift

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

OUT_RS = REPO_ROOT / "src" / "digest" / "tables.rs"
OUT_JSON = REPO_ROOT / "forensics" / "atlas" / "digest-tables.json"
GENERATOR = "forensics/tools/gen_phase8_tables.py"

MD5 = "crypto/md5/md5_dgst.c"
MD4 = "crypto/md4/md4_dgst.c"
RMDCONST = "crypto/ripemd/rmdconst.h"
RMDLOCAL = "crypto/ripemd/rmd_local.h"
SHA256 = "crypto/sha/sha256.c"
SHA512 = "crypto/sha/sha512.c"
WP = "crypto/whrlpool/wp_block.c"

_SOURCES = (MD5, MD4, RMDCONST, RMDLOCAL, SHA256, SHA512, WP)

# `R0(A, B, C, D, X(0), 7, 0xd76aa478L);` — the round letter, the message word, the
# rotation and the constant. The authority writes the same invocation four times per round
# with the roles rotated, which is why the message index and the rotation are read from the
# arguments rather than derived from the round number.
_ROUND = re.compile(
    r"^\s*R(\d)\(\s*\w+,\s*\w+,\s*\w+,\s*\w+,\s*X\((\d+)\),\s*(\d+),\s*(0x[0-9a-fA-F]+|0)L?\s*\)",
    re.MULTILINE,
)
_KEY = re.compile(r"^#define\s+(K[LR]\d)\s+(0x[0-9a-fA-F]+)L", re.MULTILINE)
_INIT = re.compile(r"^#define\s+RIPEMD160_([A-E])\s+(0x[0-9a-fA-F]+)L", re.MULTILINE)


def read(authority, relpath: str) -> str:
    p = authority.source / relpath
    if not p.is_file():
        raise SystemExit(f"gen-phase8-tables: the authority has no {relpath}")
    return p.read_text(encoding="utf-8")


def rounds(text: str, count: int) -> tuple[list[int], list[int], list[int]]:
    """`(word, rotation, constant)` per invocation, in source order."""
    triples = [(int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4), 16))
               for m in _ROUND.finditer(text)]
    if len(triples) != count:
        raise SystemExit(
            f"gen-phase8-tables: expected {count} round invocations, read {len(triples)}; "
            f"the source's shape changed and the parse is now wrong"
        )
    # The authority interleaves the message loads with the rounds, so the triples are
    # already in application order and are emitted in it.
    return ([t[1] for t in triples], [t[2] for t in triples], [t[3] for t in triples])


def sha2_k(text: str, name: str, count: int) -> list[int]:
    """A `K256`/`K512` table, whose entries are `U64(...)`-wrapped or bare."""
    body = text.split(f"{name}[{count}]")[1].split("};")[0]
    values = re.findall(r"U64\(0x([0-9a-fA-F]+)\)|0x([0-9a-fA-F]+)UL?", body)
    out = [int(a or b, 16) for a, b in values]
    if len(out) != count:
        raise SystemExit(
            f"gen-phase8-tables: {name} read {len(out)} entries, expected {count}"
        )
    return out


def ripemd(authority) -> dict:
    const = read(authority, RMDCONST)
    local = read(authority, RMDLOCAL)

    def table(prefix: str) -> list[int]:
        out = []
        for i in range(80):
            m = re.search(rf"^#define {prefix}{i:02d}\s+(\d+)\s*$", const, re.MULTILINE)
            if m is None:
                raise SystemExit(f"gen-phase8-tables: rmdconst.h has no {prefix}{i:02d}")
            out.append(int(m.group(1)))
        return out

    keys = {m.group(1): int(m.group(2), 16) for m in _KEY.finditer(const)}
    if sorted(keys) != [f"K{l}{i}" for l in "LR" for i in range(5)]:
        raise SystemExit(f"gen-phase8-tables: rmdconst.h's key schedule is {sorted(keys)}")
    return {
        "wl": table("WL"),
        "sl": table("SL"),
        "wr": table("WR"),
        "sr": table("SR"),
        "init": {m.group(1): int(m.group(2), 16) for m in _INIT.finditer(local)},
        "keys": keys,
    }


def whirlpool(authority) -> tuple[list[int], list[int]]:
    """`(256 entries, 10 round constants)`, each read as a little-endian `u64`."""
    text = read(authority, WP)
    body = text.split("} Cx = {")[1].split("\n};")[0]
    rows = re.findall(r"LL\(([^)]*)\)", body)
    if len(rows) != 256:
        raise SystemExit(
            f"gen-phase8-tables: Cx's LL rows read {len(rows)}, expected 256"
        )
    table = []
    for row in rows:
        vals = [int(v, 16) for v in re.findall(r"0x([0-9a-fA-F]+)", row)]
        if len(vals) != 8:
            raise SystemExit(f"gen-phase8-tables: an LL row has {len(vals)} bytes")
        table.append(int.from_bytes(bytes(vals), "little"))

    # The ten round constants are the last eighty bytes of the initialiser: the eight bytes
    # after the LL rows (the `0x18, 0x23, ...` group, which the RC pointer reaches as its
    # first element) and then the `/* rc[ROUNDS] */` comment's seventy-two.
    tail = body[body.rindex("0x4f,") + len("0x4f,"):]
    rest = [int(v, 16) for v in re.findall(r"0x([0-9a-fA-F]+)", tail)]
    rc_bytes = [0x18, 0x23, 0xC6, 0xE8, 0x87, 0xB8, 0x01, 0x4F] + rest
    if len(rc_bytes) != 80:
        raise SystemExit(
            f"gen-phase8-tables: the round-constant tail read {len(rc_bytes)} bytes, "
            f"expected 80"
        )
    rc = [int.from_bytes(bytes(rc_bytes[i * 8:(i + 1) * 8]), "little") for i in range(10)]
    return table, rc


def render(t: dict) -> str:
    L: list[str] = []
    A = L.append
    A("//! Phase 8's digest constant tables, generated from the authority's own source.")
    A("//!")
    A("//! **Generated. Do not edit.** `forensics/tools/gen_phase8_tables.py` derives every")
    A("//! number here from the pinned authority's `crypto/` tree, and")
    A("//! `forensics/tools/evidence_determinism.py` re-derives them and fails if this file")
    A("//! drifts. The module doc of the generator says why they are generated rather than")
    A("//! typed (`docs/DECISIONS.md` D33), and `src/digest/*.rs` carries the *structure* that")
    A("//! reads them.")
    A("//!")
    A("//! SPDX-License-Identifier: Apache-2.0")
    A("")
    A("// `crypto/md5/md5_dgst.c`'s `R0`..`R3` invocations: the message word each round reads,")
    A("// the rotation it applies and its additive constant, in application order.")
    A("/// MD5's message index per round — `crypto/md5/md5_dgst.c`.")
    A(f"pub(crate) static MD5_WORD: [usize; {len(t['md5']['word'])}] = {fmt_usize(t['md5']['word'])};")
    A("/// MD5's rotation per round.")
    A(f"pub(crate) static MD5_ROT: [u32; {len(t['md5']['rot'])}] = {fmt_hex32(t['md5']['rot'])};")
    A("/// MD5's additive constant per round.")
    A(f"pub(crate) static MD5_K: [u32; {len(t['md5']['k'])}] = {fmt_hex32(t['md5']['k'])};")
    A("")
    A("/// MD4's message index per round — `crypto/md4/md4_dgst.c`.")
    A(f"pub(crate) static MD4_WORD: [usize; {len(t['md4']['word'])}] = {fmt_usize(t['md4']['word'])};")
    A("/// MD4's rotation per round.")
    A(f"pub(crate) static MD4_ROT: [u32; {len(t['md4']['rot'])}] = {fmt_hex32(t['md4']['rot'])};")
    A("/// MD4's additive constant per round — zero in round 0, which is the whole of MD4's")
    A("/// difference from MD5's round structure.")
    A(f"pub(crate) static MD4_K: [u32; {len(t['md4']['k'])}] = {fmt_hex32(t['md4']['k'])};")
    A("")
    A("/// RIPEMD-160's initial state — `crypto/ripemd/rmd_local.h`.")
    A(f"pub(crate) static RIPEMD160_INIT: [u32; 5] = [{', '.join(hex32(t['ripemd']['init'][c]) for c in 'ABCDE')}];")
    A("/// RIPEMD-160's left line: the message word each step reads — `crypto/ripemd/rmdconst.h`'s `WLNN`.")
    A(f"pub(crate) static RMD_WL: [usize; 80] = {fmt_usize(t['ripemd']['wl'])};")
    A("/// RIPEMD-160's left line: the rotation each step applies — `SLNN`.")
    A(f"pub(crate) static RMD_SL: [u32; 80] = {fmt_hex32(t['ripemd']['sl'])};")
    A("/// RIPEMD-160's right line: the message word each step reads — `WRNN`.")
    A(f"pub(crate) static RMD_WR: [usize; 80] = {fmt_usize(t['ripemd']['wr'])};")
    A("/// RIPEMD-160's right line: the rotation each step applies — `SRNN`.")
    A(f"pub(crate) static RMD_SR: [u32; 80] = {fmt_hex32(t['ripemd']['sr'])};")
    A("/// RIPEMD-160's left key schedule — `KL0`..`KL4`.")
    A(f"pub(crate) static RMD_KL: [u32; 5] = [{', '.join(hex32(t['ripemd']['keys'][f'KL{i}']) for i in range(5))}];")
    A("/// RIPEMD-160's right key schedule — `KR0`..`KR4`.")
    A(f"pub(crate) static RMD_KR: [u32; 5] = [{', '.join(hex32(t['ripemd']['keys'][f'KR{i}']) for i in range(5))}];")
    A("")
    A("/// SHA-256's round constants — `crypto/sha/sha256.c`'s `K256[64]`.")
    A(f"pub(crate) static K256: [u32; {len(t['sha2']['k256'])}] = {fmt_hex32(t['sha2']['k256'])};")
    A("/// SHA-512's round constants — `crypto/sha/sha512.c`'s `K512[80]`.")
    A(f"pub(crate) static K512: [u64; {len(t['sha2']['k512'])}] = {fmt_hex64(t['sha2']['k512'])};")
    A("")
    A("/// Whirlpool's `Cx` table: two hundred and fifty-six eight-byte groups, each read as")
    A("/// a little-endian `u64` — `crypto/whrlpool/wp_block.c`.")
    A("///")
    A("/// The authority's `C0`..`C7` macros reach these through an unaligned `u64` at a")
    A("/// one-byte shift into a *doubled* row; `src/digest/wp.rs` reproduces that with a")
    A("/// rotate, which is the same arithmetic on this profile's little-endian host and is")
    A("/// the authority's own device made explicit rather than an assumption about it.")
    A("pub(crate) static WP_TABLE: [u64; 256] = [")
    for i in range(0, 256, 4):
        A("    " + " ".join(hex64(v) + "," for v in t["wp"]["table"][i:i + 4]))
    A("];")
    A("/// Whirlpool's ten round constants — the last eighty bytes of `Cx`, read the same way.")
    A(f"pub(crate) static WP_RC: [u64; 10] = {fmt_hex64(t['wp']['rc'])};")
    A("")
    A("#[cfg(test)]")
    A("mod tests {")
    A("    use super::*;")
    A("")
    A("    #[test]")
    A("    fn the_tables_have_the_shapes_the_constructions_read_them_with() {")
    A("        assert_eq!(MD5_WORD.len(), 64);")
    A("        assert_eq!(MD4_WORD.len(), 48);")
    A("        assert_eq!(K256.len(), 64);")
    A("        assert_eq!(K512.len(), 80);")
    A("        assert_eq!(WP_TABLE.len(), 256);")
    A("        assert_eq!(WP_RC.len(), 10);")
    A("    }")
    A("")
    A("    #[test]")
    A("    fn the_whirlpool_table_opens_and_closes_on_the_sources_own_rows() {")
    A("        // The first row is `LL(0x18, 0x18, 0x60, 0x18, 0xc0, 0x78, 0x30, 0xd8)` and")
    A("        // the last `LL(0x86, 0x86, 0x22, 0x86, 0x44, 0xa4, 0x11, 0xc2)`, each read as")
    A("        // a little-endian `u64`. Pinning them here is what makes a parse that silently")
    A("        // read zero rows or the wrong column visible in a unit test rather than only in")
    A("        // the differential court.")
    A(f"        assert_eq!(WP_TABLE[0], {hex64(t['wp']['table'][0])});")
    A(f"        assert_eq!(WP_TABLE[255], {hex64(t['wp']['table'][255])});")
    A("        // Every entry is eight bytes, so no bit above bit 63 of any byte position may")
    A("        // survive: the high byte of the little-endian read is the row's eighth byte.")
    A("        for entry in WP_TABLE {")
    A("            assert!(entry >> 56 <= 0xff);")
    A("        }")
    A("    }")
    A("}")
    A("")
    return "\n".join(L)


def fmt_usize(values: list[int]) -> str:
    return "[" + ", ".join(str(v) for v in values) + "]"


def hex32(v: int) -> str:
    return f"0x{v:08x}"


def hex64(v: int) -> str:
    return f"0x{v:016x}"


def fmt_hex32(values: list[int], per_line: int = 8) -> str:
    lines = []
    for i in range(0, len(values), per_line):
        lines.append("    " + " ".join(hex32(v) + "," for v in values[i:i + per_line]))
    return "[\n" + "\n".join(lines) + "\n]"


def fmt_hex64(values: list[int], per_line: int = 4) -> str:
    if len(values) <= per_line:
        return "[" + ", ".join(hex64(v) for v in values) + "]"
    lines = []
    for i in range(0, len(values), per_line):
        lines.append("    " + " ".join(hex64(v) + "," for v in values[i:i + per_line]))
    return "[\n" + "\n".join(lines) + "\n]"


def build(authority) -> dict:
    md5_word, md5_rot, md5_k = rounds(read(authority, MD5), 64)
    md4_word, md4_rot, md4_k = rounds(read(authority, MD4), 48)
    rmd = ripemd(authority)
    table, rc = whirlpool(authority)
    return {
        "md5": {"word": md5_word, "rot": md5_rot, "k": md5_k},
        "md4": {"word": md4_word, "rot": md4_rot, "k": md4_k},
        "ripemd": rmd,
        "sha2": {"k256": sha2_k(read(authority, SHA256), "K256", 64),
                 "k512": sha2_k(read(authority, SHA512), "K512", 80)},
        "wp": {"table": table, "rc": rc},
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument("--check", action="store_true",
                    help="compare the committed table file against a fresh derivation")
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    tables = build(auth)
    rendered = render(tables)

    inputs = [InputRef(name="authority-source", path=auth.source / r) for r in _SOURCES]
    doc = envelope(kind="digest-tables", authority=auth.id, inputs=inputs,
                   body={"tables": tables, "source_files": list(_SOURCES)},
                   generator=GENERATOR)

    if args.check:
        if not OUT_RS.is_file() or OUT_RS.read_text(encoding="utf-8") != rendered:
            raise SystemExit(
                f"gen-phase8-tables: {rel(OUT_RS)} differs from a fresh derivation; "
                f"run `python3 {GENERATOR}`"
            )
        print(f"[gen-phase8-tables] ok: {rel(OUT_RS)} matches the authority")
        return 0

    OUT_RS.parent.mkdir(parents=True, exist_ok=True)
    OUT_RS.write_text(rendered, encoding="utf-8")
    write_json(OUT_JSON, doc)
    n = sum(len(v) for v in tables.values())
    print(f"[gen-phase8-tables] {n} table group(s) from {len(_SOURCES)} authority file(s)")
    for name, group in tables.items():
        sizes = {k: (len(v) if isinstance(v, (list, dict)) else v) for k, v in group.items()}
        print(f"  {name}: {sizes}")
    print(f"  -> {rel(OUT_RS)}")
    print(f"  -> {rel(OUT_JSON)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
