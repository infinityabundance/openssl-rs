#!/usr/bin/env python3
"""openssl-rs — generate the `OBJ`/NID static table (`src/runtime/obj_table.rs`).

Why this generator exists
-------------------------
`OBJ_*` is the one runtime subsystem whose *data* is enormous: the authority's
NID table has ~1500 named objects, a sorted short-name index, a sorted long-name
index, a sorted OID index, and several kilobytes of serialized OID content.
Typing that by hand is not an implementation, it is a transcription error
waiting to happen. So the table is *derived* from the authority, committed, and
regenerated deterministically by this tool.

`docs/PARITY_MODEL.md` §5 puts the rule plainly: derived evidence is never
hand-written, every record cites its provenance, and the original is preserved.
`docs/REPRODUCIBILITY.md` §2 requires the output to be byte-identical on
re-run. This generator therefore embeds the authority id, the content hash of
every input it read, and its own content hash into the generated header, and it
writes nothing that depends on wall-clock time, PID, hostname or environment.

Chosen inputs and why
---------------------
Three of the authority's own files, all under
`forensics/authorities/src/openssl-3.6.4/`:

  * `crypto/objects/obj_dat.h` — the authority's *generated, machine-readable*
    object table. It is produced by the authority's own `obj_dat.pl` from
    `objects.txt`, and it is exactly the data structure the built
    `libcrypto.so.3` initializes. It gives us, losslessly:
      - `so[]`           the serialized OID content octets;
      - `nid_objs[]`     sn / ln / nid / length / data for every NID;
      - `sn_objs[]`      the NID index list sorted by short name;
      - `ln_objs[]`      the NID index list sorted by long name;
      - `obj_objs[]`     the NID index list sorted by OID content;
      - the `NUM_*` counts.
    Preserving the authority's *sorted index lists* (rather than re-sorting by
    hand) is deliberate: three entries share the literal name `"NULL"`, and the
    authority's binary search for a duplicate key returns whichever element the
    *algorithm* lands on. Reproducing the authority's `ossl_bsearch` over the
    authority's own index order makes that tie-break identical by construction.

  * `crypto/objects/obj_mac.h` — the installed public header. It supplies the
    authoritative *names* and numeric values of the `NID_*` macros, including
    the aliases that `obj_dat.h` does not carry as table entries (e.g.
    `NID_grasshopper_ecb = NID_kuznyechik_ecb`). The generator cross-checks the
    numeric value against the table index and fails loudly on disagreement.

  `crypto/objects/obj_xref.h` — the authority's generated
    signature-algorithm cross-reference table (`sigoid_srt[]` and its
    hash/pkey-sorted index `sigoid_srt_xref[]`). `OBJ_find_sigid_algs` and
    `OBJ_find_sigid_by_algs` binary-search these arrays, so they are generated
    rather than transcribed: they are small, but they are still authority data,
    and hand-copying them would trade provenance for typo risk.

Why not `objects.txt`?
    `objects.txt` is the canonical human-maintained source, but consuming it
    means re-implementing `objects.pl`: aliases, `!Alias`/`!Cname`/`!module`
    directives, name elision and the short/long derivation rules. That would put
    a second, independently-buggy translation between the authority and this
    table, which is precisely the kind of layered divergence
    `docs/PARITY_MODEL.md` §5 exists to prevent. `obj_dat.h` is the authority's
    own translation of `objects.txt`, already content-addressed, already the
    literal initializer of the shipped DSO. We take it as the artifact of
    record and cross-check its names against `obj_mac.h`.

Failure policy
--------------
This generator never emits a partial table. A missing input, an unparsable
record, a count mismatch, a NID/index disagreement, an OID slice out of range,
or an unsorted index list all raise `SystemExit` with a diagnostic and leave the
previous output in place.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import REPO_ROOT, sha256_file, write_text  # noqa: E402

AUTHORITY = "openssl-3.6.4-production"
AUTH_SRC = REPO_ROOT / "forensics" / "authorities" / "src" / "openssl-3.6.4"
OBJ_DAT = AUTH_SRC / "crypto" / "objects" / "obj_dat.h"
OBJ_MAC = (
    REPO_ROOT
    / "forensics"
    / "authorities"
    / "prefix"
    / f"{AUTHORITY}"
    / "include"
    / "openssl"
    / "obj_mac.h"
)
OBJ_XREF = AUTH_SRC / "crypto" / "objects" / "obj_xref.h"

OUT_PATH = REPO_ROOT / "src" / "runtime" / "obj_table.rs"

GENERATOR = "forensics/tools/gen_nid_table.py"


class GenError(SystemExit):
    """A fatal condition: the generator refuses to emit a partial table."""


# ---------------------------------------------------------------------------
# parsing helpers
# ---------------------------------------------------------------------------

def read_required(path: Path) -> str:
    if not path.is_file():
        raise GenError(
            f"gen_nid_table: required input not found: {path}\n"
            "gen_nid_table: refusing to emit a partial table."
        )
    return path.read_text(encoding="utf-8")


def parse_so(text: str) -> tuple[int, bytes]:
    """Parse the `so[]` serialized-OID byte array."""
    m = re.search(
        r"static const unsigned char so\[(\d+)\] = \{(.*?)\n\};", text, re.S
    )
    if not m:
        raise GenError("gen_nid_table: could not find the `so[]` table")
    declared = int(m.group(1))
    body = m.group(2)
    for line in body.splitlines():
        stripped = re.sub(r"/\*.*?\*/", "", line).strip()
        if not stripped:
            continue
        for tok in stripped.strip(",").split(","):
            tok = tok.strip()
            if tok and not re.fullmatch(r"0x[0-9A-Fa-f]{2}", tok):
                raise GenError(f"gen_nid_table: malformed byte in so[]: {tok!r}")
    data = bytes(int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", body))
    if len(data) > declared:
        raise GenError(
            f"gen_nid_table: so[] declared {declared} but parsed {len(data)}"
        )
    # C zero-fills a partially-initialized array; mirror that exactly.
    if len(data) < declared:
        data = data + bytes(declared - len(data))
    return declared, data


_NID_OBJ_FULL = re.compile(
    r'^\s*"([^"]*)",\s*"([^"]*)",\s*(NID_\w+),\s*(\d+),\s*&so\[(\d+)\]\s*$'
)
_NID_OBJ_NAMEONLY = re.compile(
    r'^\s*"([^"]*)",\s*"([^"]*)",\s*(NID_\w+)\s*$'
)
_NID_OBJ_NULL = re.compile(r"^\s*NULL,\s*NULL,\s*(NID_\w+)\s*$")


class ObjEntry:
    __slots__ = ("sn", "ln", "nid_name", "length", "offset")

    def __init__(self, sn, ln, nid_name, length, offset):
        self.sn = sn
        self.ln = ln
        self.nid_name = nid_name
        self.length = length
        self.offset = offset


def parse_nid_objs(text: str) -> list[ObjEntry]:
    m = re.search(
        r"static const ASN1_OBJECT nid_objs\[NUM_NID\] = \{(.*?)\n\};", text, re.S
    )
    if not m:
        raise GenError("gen_nid_table: could not find the `nid_objs[]` table")
    raw = re.findall(r"\{([^{}]*)\}", m.group(1))
    entries: list[ObjEntry] = []
    for i, body in enumerate(raw):
        full = _NID_OBJ_FULL.match(body)
        if full:
            entries.append(
                ObjEntry(full.group(1), full.group(2), full.group(3),
                         int(full.group(4)), int(full.group(5)))
            )
            continue
        nameonly = _NID_OBJ_NAMEONLY.match(body)
        if nameonly:
            entries.append(
                ObjEntry(nameonly.group(1), nameonly.group(2),
                         nameonly.group(3), 0, None)
            )
            continue
        null = _NID_OBJ_NULL.match(body)
        if null:
            entries.append(ObjEntry(None, None, null.group(1), 0, None))
            continue
        raise GenError(
            f"gen_nid_table: unparsable nid_objs entry {i}: {body.strip()!r}"
        )
    return entries


def parse_count(text: str, name: str) -> int:
    m = re.search(rf"^#define {name} (\d+)$", text, re.M)
    if not m:
        raise GenError(f"gen_nid_table: could not find `#define {name}`")
    return int(m.group(1))


def parse_uint_array(text: str, name: str, count: int) -> list[int]:
    m = re.search(
        rf"static const unsigned int {name}\[NUM_\w+\] = \{{(.*?)\n\}};", text, re.S
    )
    if not m:
        raise GenError(f"gen_nid_table: could not find the `{name}[]` table")
    body = re.sub(r"/\*.*?\*/", "", m.group(1))
    values = [int(x) for x in re.findall(r"\d+", body)]
    if len(values) != count:
        raise GenError(
            f"gen_nid_table: {name}[] has {len(values)} entries, expected {count}"
        )
    return values


def parse_nid_macros(text: str) -> tuple[list[tuple[str, int]], list[tuple[str, str]]]:
    """Return (numeric NID defines in file order, alias NID defines)."""
    numeric: list[tuple[str, int]] = []
    aliases: list[tuple[str, str]] = []
    for name, value in re.findall(r"^#define (NID_\w+)\s+(.*)$", text, re.M):
        value = value.strip()
        if re.fullmatch(r"-?\d+", value):
            numeric.append((name, int(value)))
        else:
            aliases.append((name, value))
    if not numeric:
        raise GenError("gen_nid_table: no numeric NID_* macros found in obj_mac.h")
    return numeric, aliases


# ---------------------------------------------------------------------------
# C-string literal escaping
# ---------------------------------------------------------------------------

def c_literal(s: str) -> str:
    """A Rust `c"..."` literal for an ASCII/byte string, escaping safely."""
    if "\x00" in s:
        raise GenError("gen_nid_table: NUL byte inside an object name")
    out = []
    for byte in s.encode("utf-8"):
        ch = chr(byte)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif 0x20 <= byte < 0x7F:
            out.append(ch)
        else:
            out.append(f"\\x{byte:02x}")
    return 'c"' + "".join(out) + '"'


def chunked(items: list[str], per_line: int) -> list[str]:
    lines = []
    for i in range(0, len(items), per_line):
        lines.append("    " + ", ".join(items[i:i + per_line]) + ",")
    return lines


# ---------------------------------------------------------------------------
# signature cross-reference table
# ---------------------------------------------------------------------------

def parse_sigoid(text: str) -> tuple[list[tuple[str, str, str]], list[int]]:
    m = re.search(r"static const nid_triple sigoid_srt\[\] = \{(.*?)\n\};", text, re.S)
    if not m:
        raise GenError("gen_nid_table: could not find sigoid_srt[]")
    triples = [
        (a, b, c)
        for a, b, c in re.findall(r"\{(NID_\w+),\s*(NID_\w+),\s*(NID_\w+)\}", m.group(1))
    ]
    m2 = re.search(
        r"static const nid_triple \*const sigoid_srt_xref\[\] = \{(.*?)\n\};",
        text,
        re.S,
    )
    if not m2:
        raise GenError("gen_nid_table: could not find sigoid_srt_xref[]")
    xref = [int(x) for x in re.findall(r"&sigoid_srt\[(\d+)\]", m2.group(1))]
    return triples, xref


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> int:
    dat_text = read_required(OBJ_DAT)
    mac_text = read_required(OBJ_MAC)
    xref_text = read_required(OBJ_XREF)

    so_len, so = parse_so(dat_text)
    entries = parse_nid_objs(dat_text)
    num_nid = parse_count(dat_text, "NUM_NID")
    num_sn = parse_count(dat_text, "NUM_SN")
    num_ln = parse_count(dat_text, "NUM_LN")
    num_obj = parse_count(dat_text, "NUM_OBJ")
    sn_objs = parse_uint_array(dat_text, "sn_objs", num_sn)
    ln_objs = parse_uint_array(dat_text, "ln_objs", num_ln)
    obj_objs = parse_uint_array(dat_text, "obj_objs", num_obj)
    numeric, aliases = parse_nid_macros(mac_text)

    if len(entries) != num_nid:
        raise GenError(
            f"gen_nid_table: nid_objs has {len(entries)} entries, NUM_NID={num_nid}"
        )

    # NID name -> value, aliases resolved one level (obj_mac.h aliases do not
    # chain in this authority, but resolve defensively and fail if they do).
    value_of = {name: val for name, val in numeric}
    for name, target in aliases:
        if target not in value_of:
            raise GenError(
                f"gen_nid_table: NID alias {name} -> {target} is unresolved"
            )
        value_of[name] = value_of[target]

    # Every table slot's explicit NID must equal its index (except the deliberate
    # holes, which are `{NULL, NULL, NID_undef}` and must sit at a hole index).
    holes: list[int] = []
    for i, e in enumerate(entries):
        if e.sn is None:
            if e.nid_name != "NID_undef":
                raise GenError(
                    f"gen_nid_table: hole at index {i} names {e.nid_name}"
                )
            holes.append(i)
            continue
        if e.nid_name not in value_of:
            raise GenError(
                f"gen_nid_table: entry {i} names unknown macro {e.nid_name}"
            )
        if value_of[e.nid_name] != i:
            raise GenError(
                f"gen_nid_table: nid_objs[{i}] says {e.nid_name}="
                f"{value_of[e.nid_name]}, index disagrees"
            )

    # The numeric macro set must be exactly the non-hole slots; the difference is
    # what makes the emitted constant set faithful rather than a guess.
    slot_values = set(range(num_nid)) - set(holes)
    macro_values = {v for _, v in numeric}
    if macro_values != slot_values:
        raise GenError(
            "gen_nid_table: numeric NID_* macros and table slots disagree "
            f"(missing={sorted(slot_values - macro_values)}, "
            f"extra={sorted(macro_values - slot_values)})"
        )

    # Every OID slice must lie inside so[].
    for i, e in enumerate(entries):
        if e.offset is None:
            continue
        if e.offset + e.length > so_len:
            raise GenError(
                f"gen_nid_table: nid_objs[{i}] OID slice "
                f"[{e.offset},{e.offset + e.length}) exceeds so[{so_len}]"
            )

    # Name/OID index lists must be index-valid and sorted, or the binary search
    # we generate would not reproduce the authority's.
    def check_sorted(indices: list[int], key, label: str) -> None:
        keys = []
        for idx in indices:
            if not (0 <= idx < num_nid):
                raise GenError(f"gen_nid_table: {label} index {idx} out of range")
            keys.append(key(entries[idx]))
        for a, b in zip(keys, keys[1:]):
            if a > b:
                raise GenError(
                    f"gen_nid_table: {label} index list is not sorted at "
                    f"{a!r} > {b!r}"
                )

    check_sorted(sn_objs, lambda e: e.sn, "sn_objs")
    check_sorted(ln_objs, lambda e: e.ln, "ln_objs")
    check_sorted(
        obj_objs,
        lambda e: (e.length, so[e.offset:e.offset + e.length] if e.offset is not None else b""),
        "obj_objs",
    )

    sig_triples, sig_xref = parse_sigoid(xref_text)
    for sign, dig, pkey in sig_triples:
        for name in (sign, dig, pkey):
            if name != "NID_undef" and name not in value_of:
                raise GenError(f"gen_nid_table: sigid table names unknown {name}")
    for idx in sig_xref:
        if not (0 <= idx < len(sig_triples)):
            raise GenError(f"gen_nid_table: sigoid_srt_xref index {idx} out of range")
    # `sigoid_srt_xref` is *not* a permutation: it lists only the triples that are
    # addressable by (hash_id, pkey_id) and is ordered by the authority's
    # asymmetric `sigx_cmp`. It is emitted verbatim, in file order, so the binary
    # search over it is identical by construction.
    sig_srt = [
        (value_of[a], value_of[b], value_of[c]) for a, b, c in sig_triples
    ]
    # sigoid_srt is documented as sorted by sign_id; the authority binary-searches
    # it directly, so this must hold.
    for a, b in zip(sig_srt, sig_srt[1:]):
        if a[0] > b[0]:
            raise GenError("gen_nid_table: sigoid_srt is not sorted by sign_id")

    out: list[str] = []
    gen_hash = sha256_file(Path(__file__).resolve())
    out += [
        "//! GENERATED by forensics/tools/gen_nid_table.py — do not edit by hand.",
        "//!",
        "//! The authority's object/NID table as Rust data. Regenerate with:",
        "//!",
        "//! ```text",
        "//! python3 forensics/tools/gen_nid_table.py",
        "//! ```",
        "//!",
        f"//! Authority: `{AUTHORITY}`",
        "//!",
        "//! Content-addressed inputs (the authority's own generated tables; see the",
        "//! generator docstring for why these and not `objects.txt`):",
        f"//!   - `{OBJ_DAT.relative_to(REPO_ROOT).as_posix()}` sha256 `{sha256_file(OBJ_DAT)}`",
        f"//!   - `{OBJ_MAC.relative_to(REPO_ROOT).as_posix()}` sha256 `{sha256_file(OBJ_MAC)}`",
        f"//!   - `{OBJ_XREF.relative_to(REPO_ROOT).as_posix()}` sha256 `{sha256_file(OBJ_XREF)}`",
        "//!",
        f"//! Generator `{GENERATOR}` sha256 `{gen_hash}`",
        "//!",
        "//! The output is deterministic: it contains no wall-clock time, PID,",
        "//! hostname, absolute path or environment value (`docs/REPRODUCIBILITY.md`",
        "//! §2), and `python3 forensics/tools/gen_nid_table.py` re-run is byte-identical.",
        "//!",
        "//! `dead_code` is allowed because this is *data*: the whole authority constant",
        "//! set is emitted for completeness and for later subsystems, whether or not",
        "//! this module references every name yet.",
        "//!",
        "//! `non_upper_case_globals` is allowed for the same reason the names are kept:",
        "//! `NID_undef`, `NID_rsaEncryption` and the rest are the authority's own C",
        "//! identifiers. Renaming them to satisfy a Rust style lint would make this",
        "//! table harder to check against `obj_mac.h`, which is the whole point of",
        "//! generating it from the authority in the first place.",
        "#![allow(dead_code)]",
        "#![allow(non_upper_case_globals)]",
        "",
        "use core::ffi::c_int;",
        "",
        "use super::Asn1Object;",
        "",
        f"/// `NUM_NID` — number of NID slots in the authority's table (holes included).",
        f"pub(crate) const NUM_NID: usize = {num_nid};",
        f"/// `NUM_SN` — number of entries in the short-name index.",
        f"pub(crate) const NUM_SN: usize = {num_sn};",
        f"/// `NUM_LN` — number of entries in the long-name index.",
        f"pub(crate) const NUM_LN: usize = {num_ln};",
        f"/// `NUM_OBJ` — number of entries in the OID index.",
        f"pub(crate) const NUM_OBJ: usize = {num_obj};",
        f"/// Length of the serialized-OID byte pool.",
        f"pub(crate) const SO_LEN: usize = {so_len};",
        "",
    ]

    # NID constants: numeric in file order, then aliases (targets already bound).
    out.append("// --- NID_* constants (from the authority's installed obj_mac.h) ---")
    out.append("")
    for name, value in numeric:
        out.append(f"pub(crate) const {name}: c_int = {value};")
    out.append("")
    out.append("// Aliases: `obj_mac.h` defines these to another NID.")
    for name, target in aliases:
        out.append(f"pub(crate) const {name}: c_int = {target};")
    out.append("")

    # Serialized OID pool.
    out.append("// --- Serialized OID content octets (`so[]`) ---")
    out.append("")
    out.append(f"pub(crate) static SO: [u8; SO_LEN] = [")
    out += chunked([f"0x{b:02X}" for b in so], 12)
    out.append("];")
    out.append("")

    # The object table itself.
    out.append("// --- `nid_objs[]` as `Asn1Object` (layout of `struct asn1_object_st`) ---")
    out.append("")
    out.append(f"pub(crate) static NID_OBJS: [Asn1Object; NUM_NID] = [")
    for i, e in enumerate(entries):
        if e.sn is None:
            entry = (
                "    Asn1Object { sn: core::ptr::null(), ln: core::ptr::null(), "
                "nid: 0, length: 0, data: core::ptr::null(), flags: 0 },"
            )
        elif e.offset is None:
            entry = (
                f"    Asn1Object {{ sn: {c_literal(e.sn)}.as_ptr(), "
                f"ln: {c_literal(e.ln)}.as_ptr(), nid: {i}, length: 0, "
                f"data: core::ptr::null(), flags: 0 }},"
            )
        else:
            entry = (
                f"    Asn1Object {{ sn: {c_literal(e.sn)}.as_ptr(), "
                f"ln: {c_literal(e.ln)}.as_ptr(), nid: {i}, length: {e.length}, "
                f"data: &SO[{e.offset}] as *const u8, flags: 0 }},"
            )
        out.append(entry)
    out.append("];")
    out.append("")

    # Sorted index lists, preserved in the authority's order.
    out.append("// --- Index lists, in the authority's own sorted order ---")
    out.append("//")
    out.append("// Preserving the order (rather than re-sorting) reproduces the authority's")
    out.append("// binary-search tie-break for duplicate names such as the three `\"NULL\"`")
    out.append("// entries.")
    out.append("")
    out.append(f"pub(crate) static SN_ORDER: [u16; NUM_SN] = [")
    out += chunked([str(x) for x in sn_objs], 16)
    out.append("];")
    out.append("")
    out.append(f"pub(crate) static LN_ORDER: [u16; NUM_LN] = [")
    out += chunked([str(x) for x in ln_objs], 16)
    out.append("];")
    out.append("")
    out.append(f"pub(crate) static OBJ_ORDER: [u16; NUM_OBJ] = [")
    out += chunked([str(x) for x in obj_objs], 16)
    out.append("];")
    out.append("")

    # Signature-algorithm cross-reference.
    out.append("// --- Signature-algorithm cross reference (`obj_xref.h`) ---")
    out.append("//")
    out.append("// `SIGOID_SRT` is sorted by sign_id; `SIGOID_XREF` holds indices into it")
    out.append("// sorted by the `sigx_cmp` (hash_id, pkey_id) rule.")
    out.append("")
    out.append(
        f"pub(crate) static SIGOID_SRT: [(c_int, c_int, c_int); {len(sig_srt)}] = ["
    )
    for triple in sig_srt:
        out.append(f"    ({triple[0]}, {triple[1]}, {triple[2]}),")
    out.append("];")
    out.append("")
    out.append(f"pub(crate) static SIGOID_XREF: [u16; {len(sig_xref)}] = [")
    out += chunked([str(x) for x in sig_xref], 16)
    out.append("];")
    out.append("")

    text = "\n".join(out)
    digest = write_text(OUT_PATH, text)
    print(
        f"[gen_nid_table] {OUT_PATH.relative_to(REPO_ROOT)} "
        f"nid={num_nid} sn={num_sn} ln={num_ln} obj={num_obj} "
        f"so={so_len} sigid={len(sig_srt)} sha256={digest[:16]}…"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
