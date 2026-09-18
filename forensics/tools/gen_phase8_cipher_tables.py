#!/usr/bin/env python3
"""openssl-rs — generate Phase 8.2's cipher constant tables from the authority's own source.

Why this is generated rather than typed
---------------------------------------
Every table this stratum's symmetric ciphers need is a *transcription*: DES's eight
`DES_SPtrans` rows and eight `des_skb` rows (512 words each), Blowfish's 1042-word
π-derived initial state, CAST5's eight 256-word S-boxes, SEED's four 256-word `SS`
rows, Camellia's four 256-word `SBOX` rows, RC2's 256-byte `key_table`, and the small
schedules and key lists around them. `docs/DECISIONS.md` D33 refuses a constant that
is recalled rather than read, and `gen_phase8_tables.py`'s header makes the same
argument for the digest tables: a *generated* table is derived from the authority on
every run, its derivation is this committed generator, and `evidence_determinism.py`
recomputes it and fails if the committed copy drifts. The cipher construction's
*structure* is transcribed by hand in `src/*.rs` and verified by `RT-CIPHER`; the
*numbers* are read from the authority here.

Two sources are read rather than one, because two of the ciphers depend on a header:
`crypto/des/spr.h` is where `DES_SPtrans` lives (it is `#include`d by `des_enc.c`), and
Camellia's and SEED's tables are in the same `.c` as their round function.

Two tiers, because the authority's source is not committed
----------------------------------------------------------
The authority's source tree lives only in the court (it is ~100 MB). With it present,
this generator re-derives every table from the authority's `crypto/` tree — the strong
tier, which is what the court and the whole pipeline use. With it absent (CI's `static`
job), it re-renders `src/cipher_tables.rs` from the committed
`forensics/atlas/cipher-tables.json`'s own recorded tables, which still catches a
hand-edited Rust file. `gen_ctype_table.py` is the pattern, and the tier that ran is
printed.

    python3 forensics/tools/gen_phase8_cipher_tables.py            # write
    python3 forensics/tools/gen_phase8_cipher_tables.py --check    # fail on drift

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
    write_json,
)

OUT_RS = REPO_ROOT / "src" / "cipher_tables.rs"
OUT_JSON = REPO_ROOT / "forensics" / "atlas" / "cipher-tables.json"
GENERATOR = "forensics/tools/gen_phase8_cipher_tables.py"

DES_SPR = "crypto/des/spr.h"
DES_SETKEY = "crypto/des/set_key.c"
DES_FCRYPT = "crypto/des/fcrypt.c"
RC2_SKEY = "crypto/rc2/rc2_skey.c"
BF_PI = "crypto/bf/bf_pi.h"
CAST_S = "crypto/cast/cast_s.h"
SEED_C = "crypto/seed/seed.c"
CAMELLIA_C = "crypto/camellia/camellia.c"

_SOURCES = (DES_SPR, DES_SETKEY, DES_FCRYPT, RC2_SKEY, BF_PI, CAST_S, SEED_C, CAMELLIA_C)

# The families the generator emits. Each family's extraction is a function of the
# authority's source; extending this tuple is how a later family's tables join the file,
# and `evidence_determinism.py` recomputes the whole file.
FAMILIES = ("des", "rc2", "bf", "cast")


def read(authority, relpath: str) -> str:
    p = authority.source / relpath
    if not p.is_file():
        raise SystemExit(f"gen-phase8-cipher-tables: the authority has no {relpath}")
    return p.read_text(encoding="utf-8")


def _body(text: str, marker: str, closer: str = "};") -> str:
    """The initialiser between `marker` and the first `closer` after it."""
    if marker not in text:
        raise SystemExit(
            f"gen-phase8-cipher-tables: marker {marker!r} not found; the source's shape "
            f"changed and the parse is now wrong"
        )
    return text.split(marker, 1)[1].split(closer, 1)[0]


def hex_words(body: str) -> list[int]:
    return [int(v, 16) for v in re.findall(r"0x([0-9a-fA-F]+)", body)]


_INT_TOKEN = re.compile(r"0x([0-9a-fA-F]+)|\b(\d+)\b")


def ints(body: str) -> list[int]:
    """Every integer literal, hex (`0x..`) or decimal, in source order."""
    return [int(a, 16) if a else int(b) for a, b in _INT_TOKEN.findall(body)]


def dec_words(body: str) -> list[int]:
    return [int(v) for v in re.findall(r"\b(\d+)\b", body)]


def u32_rows(body: str, rows: int, cols: int) -> list[list[int]]:
    vals = hex_words(body)
    if len(vals) != rows * cols:
        raise SystemExit(
            f"gen-phase8-cipher-tables: expected {rows * cols} entries, read {len(vals)}"
        )
    return [vals[i * cols:(i + 1) * cols] for i in range(rows)]


def u8_table(body: str, count: int) -> list[int]:
    vals = [v for v in ints(body) if v <= 0xFF]
    if len(vals) != count:
        raise SystemExit(
            f"gen-phase8-cipher-tables: expected {count} byte entries, read {len(vals)}"
        )
    return vals


def des_tables(authority) -> dict:
    """`crypto/des/`'s tables, from `spr.h`, `set_key.c` and `fcrypt.c`.

    `DES_SPtrans` is the round's S-box/P-permutation folded into eight 64-word tables;
    `des_skb` is the key schedule's S-box/key-permutation fold, thirty-two words per
    round over eight tables; `odd_parity` and `weak_keys` are the two lists
    `DES_set_odd_parity` and `DES_is_weak_key` index. `con_salt` and `cov_2char` are
    `DES_fcrypt`'s `crypt(3)` salt and output alphabets.
    """
    spr = read(authority, DES_SPR)
    sk = read(authority, DES_SETKEY)
    fc = read(authority, DES_FCRYPT)

    weak = _body(sk, "weak_keys[] = {")
    weak_rows = [
        [int(v, 16) for v in re.findall(r"0x([0-9a-fA-F]+)", row)]
        for row in re.findall(r"\{([^{}]*)\}", weak)
    ]
    weak_rows = [r for r in weak_rows if len(r) == 8]
    if len(weak_rows) != 16:
        raise SystemExit(
            f"gen-phase8-cipher-tables: weak_keys read {len(weak_rows)} rows, expected 16"
        )
    shifts = ints(_body(sk, "shifts2[16] = {"))
    if len(shifts) != 16:
        raise SystemExit(
            f"gen-phase8-cipher-tables: shifts2 read {len(shifts)} entries, expected 16"
        )
    return {
        "sptrans": u32_rows(_body(spr, "DES_SPtrans[8][64] = {"), 8, 64),
        "skb": u32_rows(_body(sk, "des_skb[8][64] = {"), 8, 64),
        "odd_parity": u8_table(_body(sk, "odd_parity[256] = {"), 256),
        "weak_keys": weak_rows,
        "shifts2": shifts,
        "con_salt": u8_table(_body(fc, "con_salt[128] = {"), 128),
        "cov_2char": u8_table(_body(fc, "cov_2char[64] = {"), 64),
    }


def rc2_tables(authority) -> dict:
    """`crypto/rc2/rc2_skey.c`'s `key_table[256]` — the PITABLE expansion."""
    text = read(authority, RC2_SKEY)
    return {"key_table": u8_table(_body(text, "key_table[256] = {"), 256)}


def bf_tables(authority) -> dict:
    """`crypto/bf/bf_pi.h`'s `bf_init`: the P array (18 words) and the four S-boxes.

    The authority writes one `BF_KEY` initialiser, so the eighteen P words and the
    thousand-and-twenty-four S words are one flat list in source order; they are split
    at the key's own boundary.
    """
    text = read(authority, BF_PI)
    vals = hex_words(_body(text, "bf_init = {"))
    if len(vals) != 18 + 4 * 256:
        raise SystemExit(
            f"gen-phase8-cipher-tables: bf_init read {len(vals)} entries, expected 1042"
        )
    return {"p": vals[:18], "s": vals[18:]}


def cast_tables(authority) -> dict:
    """`crypto/cast/cast_s.h`'s `CAST_S_table0`..`7`, the sixteen-round S-boxes."""
    text = read(authority, CAST_S)
    return {
        f"s{i}": hex_words(_body(text, f"CAST_S_table{i}[256] = {{"))
        for i in range(8)
    }


def seed_tables(authority) -> dict:
    """`crypto/seed/seed.c`'s `SS[4][256]` and its sixteen golden-ratio `KC` constants."""
    text = read(authority, SEED_C)
    kc = [int(m, 16) for m in re.findall(r"^#define\s+KC\d+\s+(0x[0-9a-fA-F]+)", text, re.M)]
    if len(kc) != 16:
        raise SystemExit(
            f"gen-phase8-cipher-tables: SEED read {len(kc)} KC constants, expected 16"
        )
    return {"ss": u32_rows(_body(text, "SS[4][256] = {"), 4, 256), "kc": kc}


def camellia_tables(authority) -> dict:
    """`crypto/camellia/camellia.c`'s `Camellia_SBOX[4][256]` and `SIGMA[12]`."""
    text = read(authority, CAMELLIA_C)
    return {
        "sbox": u32_rows(_body(text, "Camellia_SBOX[][256] = {"), 4, 256),
        "sigma": hex_words(_body(text, "SIGMA[] = {")),
    }


_EXTRACTORS = {
    "des": des_tables,
    "rc2": rc2_tables,
    "bf": bf_tables,
    "cast": cast_tables,
    "seed": seed_tables,
    "camellia": camellia_tables,
}


def build(authority) -> dict:
    return {name: _EXTRACTORS[name](authority) for name in FAMILIES}


def fmt_u32(values: list[int], per_line: int = 8) -> str:
    lines = []
    for i in range(0, len(values), per_line):
        lines.append("    " + " ".join(f"0x{v:08x}," for v in values[i:i + per_line]))
    return "[\n" + "\n".join(lines) + "\n]"


def fmt_u32_matrix(rows: list[list[int]]) -> str:
    out = ["["]
    for row in rows:
        out.append("    [")
        for i in range(0, len(row), 8):
            out.append("        " + " ".join(f"0x{v:08x}," for v in row[i:i + 8]))
        out.append("    ],")
    out.append("]")
    return "\n".join(out)


def fmt_u8(values: list[int], per_line: int = 16) -> str:
    lines = []
    for i in range(0, len(values), per_line):
        lines.append("    " + " ".join(f"0x{v:02x}," for v in values[i:i + per_line]))
    return "[\n" + "\n".join(lines) + "\n]"


def render(t: dict) -> str:
    L: list[str] = []
    A = L.append
    A("//! Phase 8.2's cipher constant tables, generated from the authority's own source.")
    A("//!")
    A("//! **Generated. Do not edit.** `forensics/tools/gen_phase8_cipher_tables.py` derives")
    A("//! every number here from the pinned authority's `crypto/` tree, and")
    A("//! `forensics/tools/evidence_determinism.py` re-derives them and fails if this file")
    A("//! drifts. The generator's module doc says why they are generated rather than typed")
    A("//! (`docs/DECISIONS.md` D33); the *structure* that reads them is transcribed by hand in")
    A("//! `src/*.rs` and verified by `RT-CIPHER`.")
    A("//!")
    A("//! SPDX-License-Identifier: Apache-2.0")
    A("")

    if "des" in t:
        d = t["des"]
        A("/// DES's round tables — `crypto/des/spr.h`'s `DES_SPtrans[8][64]`.")
        A(f"pub(crate) static DES_SPTRANS: [[u32; 64]; 8] = {fmt_u32_matrix(d['sptrans'])};")
        A("/// DES's key-schedule tables — `crypto/des/set_key.c`'s `des_skb[8][64]`.")
        A(f"pub(crate) static DES_SKB: [[u32; 64]; 8] = {fmt_u32_matrix(d['skb'])};")
        A("/// `crypto/des/set_key.c`'s `odd_parity[256]` — `DES_set_odd_parity`'s map.")
        A(f"pub(crate) static DES_ODD_PARITY: [u8; 256] = {fmt_u8(d['odd_parity'])};")
        A("/// `crypto/des/set_key.c`'s `weak_keys[16][8]` — four weak and twelve semi-weak")
        A("/// keys, `DES_is_weak_key`'s list.")
        rows = "\n".join("    [" + ", ".join(f"0x{v:02x}" for v in r) + "]," for r in d["weak_keys"])
        A(f"pub(crate) static DES_WEAK_KEYS: [[u8; 8]; 16] = [\n{rows}\n];")
        A("/// `crypto/des/set_key.c`'s `shifts2[16]` — one bit or two per round.")
        A(f"pub(crate) static DES_SHIFTS2: [u8; 16] = {fmt_u8(d['shifts2'])};")
        A("/// `crypto/des/fcrypt.c`'s `con_salt[128]` — `DES_fcrypt`'s salt alphabet.")
        A(f"pub(crate) static DES_CON_SALT: [u8; 128] = {fmt_u8(d['con_salt'])};")
        A("/// `crypto/des/fcrypt.c`'s `cov_2char[64]` — `DES_fcrypt`'s output alphabet.")
        A(f"pub(crate) static DES_COV_2CHAR: [u8; 64] = {fmt_u8(d['cov_2char'])};")
        A("")

    if "rc2" in t:
        A("/// RC2's `PITABLE` — `crypto/rc2/rc2_skey.c`'s `key_table[256]`.")
        A(f"pub(crate) static RC2_KEY_TABLE: [u8; 256] = {fmt_u8(t['rc2']['key_table'])};")
        A("")

    if "bf" in t:
        b = t["bf"]
        A("/// Blowfish's P array — the first eighteen words of `crypto/bf/bf_pi.h`'s")
        A("/// `bf_init`, which is the fractional part of π.")
        A(f"pub(crate) static BF_P: [u32; 18] = {fmt_u32(b['p'])};")
        A("/// Blowfish's four S-boxes — the remaining thousand-and-twenty-four words of")
        A("/// `bf_init`, flat as the authority's `BF_LONG S[4 * 256]` is.")
        A(f"pub(crate) static BF_S: [u32; 1024] = {fmt_u32(b['s'])};")
        A("")

    if "cast" in t:
        c = t["cast"]
        A("/// CAST5's eight S-boxes — `crypto/cast/cast_s.h`'s `CAST_S_table0`..`7`.")
        A(f"pub(crate) static CAST_S: [[u32; 256]; 8] = {fmt_u32_matrix([c[f's{i}'] for i in range(8)])};")
        A("")

    if "seed" in t:
        s = t["seed"]
        A("/// SEED's S-box rows — `crypto/seed/seed.c`'s `SS[4][256]`.")
        A(f"pub(crate) static SEED_SS: [[u32; 256]; 4] = {fmt_u32_matrix(s['ss'])};")
        A("/// SEED's key-schedule constants — `seed.c`'s `KC0`..`KC15`, the golden ratio.")
        A(f"pub(crate) static SEED_KC: [u32; 16] = {fmt_u32(s['kc'])};")
        A("")

    if "camellia" in t:
        c = t["camellia"]
        A("/// Camellia's S-boxes — `crypto/camellia/camellia.c`'s `Camellia_SBOX[4][256]`.")
        A(f"pub(crate) static CAMELLIA_SBOX: [[u32; 256]; 4] = {fmt_u32_matrix(c['sbox'])};")
        A("/// Camellia's key-schedule constants — `camellia.c`'s `SIGMA[12]`.")
        A(f"pub(crate) static CAMELLIA_SIGMA: [u32; 12] = {fmt_u32(c['sigma'])};")
        A("")

    A("#[cfg(test)]")
    A("mod tests {")
    A("    use super::*;")
    A("")
    A("    #[test]")
    A("    fn the_tables_have_the_shapes_the_constructions_read_them_with() {")
    for name, (sym, shape) in {
        "des": ("DES_SPTRANS", "8"), "rc2": ("RC2_KEY_TABLE", "256"),
        "bf": ("BF_S", "1024"), "cast": ("CAST_S", "8"),
        "seed": ("SEED_SS", "4"), "camellia": ("CAMELLIA_SBOX", "4"),
    }.items():
        if name in t:
            A(f"        assert_eq!({sym}.len(), {shape});")
    if "des" in t:
        A("        assert_eq!(DES_SPTRANS[0][0], 0x02080800);")
    if "bf" in t:
        A("        assert_eq!(BF_P[0], 0x243f6a88);")
    if "camellia" in t:
        A("        assert_eq!(CAMELLIA_SIGMA[0], 0xa09e667f);")
    if "seed" in t:
        A("        assert_eq!(SEED_KC[0], 0x9e3779b9);")
    A("    }")
    A("}")
    A("")
    return "\n".join(L)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument("--check", action="store_true",
                    help="compare the committed table file against a fresh derivation")
    args = ap.parse_args(argv)

    from atlas_common import resolve_authority

    auth = resolve_authority(args.authority)
    strong = (auth.source / DES_SPR).is_file()

    if strong:
        tables = build(auth)
        rendered = render(tables)
        doc = envelope(kind="cipher-tables", authority=auth.id,
                       inputs=[InputRef(name="authority-source", path=auth.source / r)
                               for r in _SOURCES],
                       body={"tables": tables, "source_files": list(_SOURCES)},
                       generator=GENERATOR)
        tier = "strong (authority source present)"
    else:
        # Weak tier: the authority's source is not committed, so re-render the Rust from
        # the committed JSON's own recorded tables. This still catches a hand-edited
        # `src/cipher_tables.rs`; it cannot catch a wrong committed table, which is what
        # the court's strong tier is for.
        if not OUT_JSON.is_file():
            raise SystemExit(
                f"gen-phase8-cipher-tables: neither the authority source nor {rel(OUT_JSON)} "
                f"is present; cannot verify the tables"
            )
        doc = json.loads(OUT_JSON.read_text(encoding="utf-8"))
        rendered = render(doc["body"]["tables"])
        tier = "weak (authority source absent: re-rendered from the committed artefact)"

    if args.check:
        if not OUT_RS.is_file() or OUT_RS.read_text(encoding="utf-8") != rendered:
            raise SystemExit(
                f"gen-phase8-cipher-tables: {rel(OUT_RS)} differs from a fresh derivation; "
                f"run `python3 {GENERATOR}`"
            )
        print(f"[gen-phase8-cipher-tables] ok ({tier}): {rel(OUT_RS)} matches")
        return 0

    OUT_RS.parent.mkdir(parents=True, exist_ok=True)
    OUT_RS.write_text(rendered, encoding="utf-8")
    if strong:
        write_json(OUT_JSON, doc)
    print(f"[gen-phase8-cipher-tables] tier: {tier}")
    print(f"  -> {rel(OUT_RS)}")
    if strong:
        print(f"  -> {rel(OUT_JSON)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
